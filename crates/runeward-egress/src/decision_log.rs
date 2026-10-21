//! Per-sandbox, bounded, in-memory log of egress allow/deny outcomes for
//! dashboard inspection.

use std::collections::{HashMap, VecDeque};
use std::sync::{LazyLock, Mutex, MutexGuard};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize, Serializer};

/// How many decisions are retained per sandbox; older entries are evicted.
pub const MAX_DECISIONS_PER_SANDBOX: usize = 128;

/// One recorded egress allow/deny outcome.
///
/// The first five fields are the stable wire shape shared with the Go
/// implementation. The optional broker fields are only serialised when set,
/// so plain L4 decisions keep exactly the old JSON.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Decision {
    /// When the decision was made (UTC).
    #[serde(serialize_with = "rfc3339_nano")]
    pub timestamp: DateTime<Utc>,
    /// Hostname (or `ip:port` label) the decision was about.
    pub host: String,
    /// Destination IP that was (or would have been) dialled; may be empty.
    pub ip: String,
    /// Whether the connection or request was let through (true for audit
    /// mode would-denies, which are forwarded).
    pub allow: bool,
    /// Short human-readable reason.
    pub reason: String,
    /// Charter `[[endpoint]]` name the request matched.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    /// Endpoint protocol (`tcp`, `rest`, `websocket`, `mcp`, `json-rpc`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    /// HTTP method, or the JSON-RPC method for `mcp`/`json-rpc` endpoints
    /// (the same thing a request rule's `method` matches).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    /// Normalised request path (no query string).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// MCP tool name for `tools/call`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    /// Effect class of the matched rule (`read`, `write`, `irreversible`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub effect: Option<String>,
    /// The rule that decided, as `allow[i]` / `deny[i]` of the endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    /// The verdict, including `require-approval`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verdict: Option<Verdict>,
    /// Machine-readable reason class.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<ReasonCode>,
    /// Name of the `[[credential]]` attached (never its value).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential: Option<String>,
    /// The endpoint's `binaries` constraint (the executables allowed to use
    /// it).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binaries: Option<Vec<String>>,
    /// The executable the in-sandbox supervisor attributed the connection
    /// to (comma-separated when several processes hold it). Absent when the
    /// endpoint lists no `binaries` or the binary could not be identified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binary: Option<String>,
    /// Whether the endpoint's `binaries` were enforced on this decision:
    /// `true` in enforce mode (a binary that is not allowed, or cannot be
    /// identified, is refused), `false` in audit mode (recorded as
    /// `audit-would-deny` and forwarded). Absent when the endpoint lists no
    /// `binaries`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binary_enforced: Option<bool>,
}

/// A broker verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Verdict {
    /// Forwarded.
    Allow,
    /// Refused.
    Deny,
    /// Needs a human decision; the control plane routes it to its approval
    /// queue. Refused unless an approval hook approves it.
    RequireApproval,
}

impl Verdict {
    /// The wire spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::RequireApproval => "require-approval",
        }
    }
}

/// Why a broker decision came out the way it did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReasonCode {
    /// Allowed by policy.
    Allowed,
    /// Refused by policy (deny rule, no allow rule, malformed request).
    Denied,
    /// Refused because a `max_calls` budget is spent.
    Budget,
    /// Needs approval.
    Approval,
    /// An audit-mode endpoint would have refused this; it was forwarded.
    AuditWouldDeny,
    /// A credential placeholder was sent somewhere it does not belong.
    PlaceholderMisuse,
    /// Shed by the retry-storm breaker: the upstream answered 429/503 and
    /// its `Retry-After` window has not passed. Not a policy deny.
    Shed,
    /// Refused because the executable holding the connection is not one of
    /// the endpoint's `binaries`, or could not be identified.
    Binary,
}

impl ReasonCode {
    /// The wire spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allowed => "allowed",
            Self::Denied => "denied",
            Self::Budget => "budget",
            Self::Approval => "approval",
            Self::AuditWouldDeny => "audit-would-deny",
            Self::PlaceholderMisuse => "placeholder-misuse",
            Self::Shed => "shed",
            Self::Binary => "binary",
        }
    }
}

/// Serialises like Go's `time.RFC3339Nano` (fractional zeros trimmed).
fn rfc3339_nano<S: Serializer>(t: &DateTime<Utc>, s: S) -> Result<S::Ok, S::Error> {
    let mut out = t.format("%Y-%m-%dT%H:%M:%S").to_string();
    let nanos = t.timestamp_subsec_nanos();
    if nanos != 0 {
        let frac = format!("{nanos:09}");
        out.push('.');
        out.push_str(frac.trim_end_matches('0'));
    }
    out.push('Z');
    s.serialize_str(&out)
}

static DECISIONS: LazyLock<Mutex<HashMap<String, VecDeque<Decision>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn decisions() -> MutexGuard<'static, HashMap<String, VecDeque<Decision>>> {
    DECISIONS.lock().unwrap_or_else(|e| e.into_inner())
}

/// Appends one decision to the per-sandbox bounded log. A blank `sandbox_id`
/// is ignored.
pub fn record_decision(sandbox_id: &str, host: &str, ip: &str, allow: bool, reason: &str) {
    record_decision_entry(
        sandbox_id,
        Decision {
            timestamp: Utc::now(),
            host: host.to_string(),
            ip: ip.to_string(),
            allow,
            reason: reason.to_string(),
            ..Decision::default()
        },
    );
}

/// Appends a fully populated decision (broker fields included) to the
/// per-sandbox bounded log. `host`, `ip` and `reason` are trimmed; a blank
/// `sandbox_id` is ignored.
pub fn record_decision_entry(sandbox_id: &str, mut d: Decision) {
    let sandbox_id = sandbox_id.trim();
    if sandbox_id.is_empty() {
        return;
    }
    d.host = d.host.trim().to_string();
    d.ip = d.ip.trim().to_string();
    d.reason = d.reason.trim().to_string();
    let mut map = decisions();
    let ring = map
        .entry(sandbox_id.to_string())
        .or_insert_with(|| VecDeque::with_capacity(MAX_DECISIONS_PER_SANDBOX));
    if ring.len() == MAX_DECISIONS_PER_SANDBOX {
        ring.pop_front();
    }
    ring.push_back(d);
}

/// Returns the current per-sandbox decision log, oldest to newest.
pub fn list_decisions(sandbox_id: &str) -> Vec<Decision> {
    let sandbox_id = sandbox_id.trim();
    if sandbox_id.is_empty() {
        return Vec::new();
    }
    decisions()
        .get(sandbox_id)
        .map(|r| r.iter().cloned().collect())
        .unwrap_or_default()
}

/// Extracts the sandbox id from a log prefix of the form
/// `"runeward-egress <sandbox-id> ..."`; returns `""` if absent.
pub(crate) fn sandbox_id_from_log_prefix(prefix: &str) -> String {
    const MARKER: &str = "runeward-egress ";
    let prefix = prefix.trim();
    let Some(i) = prefix.find(MARKER) else {
        return String::new();
    };
    let rest = prefix[i + MARKER.len()..].trim();
    rest.split(' ').next().unwrap_or("").trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_per_sandbox() {
        let id = "decision-test-bounded";
        for i in 0..MAX_DECISIONS_PER_SANDBOX + 7 {
            record_decision(id, "example.com", "1.2.3.4", i % 2 == 0, &format!("r-{i}"));
        }
        let got = list_decisions(id);
        assert_eq!(got.len(), MAX_DECISIONS_PER_SANDBOX);
        assert_eq!(got[0].reason, "r-7");
        assert_eq!(
            got[got.len() - 1].reason,
            format!("r-{}", MAX_DECISIONS_PER_SANDBOX + 6)
        );
    }

    #[test]
    fn blank_sandbox_ignored_and_fields_trimmed() {
        record_decision("  ", "h", "", true, "r");
        assert!(list_decisions("").is_empty());
        record_decision(" decision-test-trim ", " h ", " 1.1.1.1 ", true, " ok ");
        let got = list_decisions("decision-test-trim");
        assert_eq!(got.len(), 1);
        assert_eq!(
            (
                got[0].host.as_str(),
                got[0].ip.as_str(),
                got[0].reason.as_str()
            ),
            ("h", "1.1.1.1", "ok")
        );
    }

    #[test]
    fn sandbox_id_from_prefix() {
        assert_eq!(
            sandbox_id_from_log_prefix("runeward-egress sb-123 2026/01/01"),
            "sb-123"
        );
        assert_eq!(sandbox_id_from_log_prefix("runeward-egress"), "");
        assert_eq!(sandbox_id_from_log_prefix(""), "");
    }

    #[test]
    fn decision_json_shape() {
        let d = Decision {
            timestamp: DateTime::parse_from_rfc3339("2026-01-02T03:04:05.120Z")
                .expect("ts")
                .with_timezone(&Utc),
            host: "h".into(),
            ip: "1.2.3.4".into(),
            allow: true,
            reason: "r".into(),
            ..Decision::default()
        };
        assert_eq!(
            serde_json::to_string(&d).expect("json"),
            r#"{"timestamp":"2026-01-02T03:04:05.12Z","host":"h","ip":"1.2.3.4","allow":true,"reason":"r"}"#
        );
    }

    #[test]
    fn broker_fields_are_optional_and_appended() {
        let d = Decision {
            timestamp: DateTime::parse_from_rfc3339("2026-01-02T03:04:05Z")
                .expect("ts")
                .with_timezone(&Utc),
            host: "h".into(),
            allow: false,
            reason: "r".into(),
            endpoint: Some("gh".into()),
            verdict: Some(Verdict::RequireApproval),
            reason_code: Some(ReasonCode::AuditWouldDeny),
            ..Decision::default()
        };
        assert_eq!(
            serde_json::to_string(&d).expect("json"),
            r#"{"timestamp":"2026-01-02T03:04:05Z","host":"h","ip":"","allow":false,"reason":"r","endpoint":"gh","verdict":"require-approval","reason_code":"audit-would-deny"}"#
        );
    }
}
