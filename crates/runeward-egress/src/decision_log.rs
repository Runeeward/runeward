//! Per-sandbox, bounded, in-memory log of egress allow/deny outcomes for
//! dashboard inspection.

use std::collections::{HashMap, VecDeque};
use std::sync::{LazyLock, Mutex, MutexGuard};

use chrono::{DateTime, Utc};
use serde::{Serialize, Serializer};

/// How many decisions are retained per sandbox; older entries are evicted.
pub const MAX_DECISIONS_PER_SANDBOX: usize = 128;

/// One recorded egress allow/deny outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Decision {
    /// When the decision was made (UTC).
    #[serde(serialize_with = "rfc3339_nano")]
    pub timestamp: DateTime<Utc>,
    /// Hostname (or `ip:port` label) the decision was about.
    pub host: String,
    /// Destination IP that was (or would have been) dialled; may be empty.
    pub ip: String,
    /// Whether the connection was allowed.
    pub allow: bool,
    /// Short human-readable reason.
    pub reason: String,
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
    let sandbox_id = sandbox_id.trim();
    if sandbox_id.is_empty() {
        return;
    }
    let d = Decision {
        timestamp: Utc::now(),
        host: host.trim().to_string(),
        ip: ip.trim().to_string(),
        allow,
        reason: reason.trim().to_string(),
    };
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
        };
        assert_eq!(
            serde_json::to_string(&d).expect("json"),
            r#"{"timestamp":"2026-01-02T03:04:05.12Z","host":"h","ip":"1.2.3.4","allow":true,"reason":"r"}"#
        );
    }
}
