//! The standard "nothing ran" refusal shared by the REST and MCP surfaces.
//!
//! Whenever a governed call is refused *before* it executed, the transport
//! adds one object describing why:
//!
//! ```json
//! {
//!   "refused": true,
//!   "reason": "policy",
//!   "retryable": false,
//!   "request_id": "5f0c9a7e21b4d3c8",
//!   "message": "denied by policy: no deletes"
//! }
//! ```
//!
//! Transports add it to the body they already send under one new key,
//! `refusal` ([`Refusal::attach`]): REST error bodies (`{"error", "code"}`),
//! denied or pending governed tool results, and MCP tool results. It is
//! nested rather than spread at the top level because those bodies already
//! use `reason` (and the dashboard and SDKs read `body.reason` first), so
//! every existing field keeps its meaning.
//!
//! `retryable` is only set when re-sending the identical request cannot
//! cause the work to run twice *and* waiting may change the answer (a rate
//! limit, a shed retry storm). A pending approval is never retryable: the
//! approval already queued may still release the original call.
//!
//! An error that does not prove nothing ran (an opaque internal failure, a
//! backend error mid-exec) gets no refusal object.

use std::future::Future;

use runeward_charter::Verdict;
use serde::{Deserialize, Serialize};

use crate::error::Error;
use crate::govern::ToolResult;

/// The header a caller may set to correlate a request; echoed (or
/// generated) on every REST response.
pub const REQUEST_ID_HEADER: &str = "x-request-id";

/// Longest caller-supplied request id that is echoed back.
pub const MAX_REQUEST_ID_LEN: usize = 128;

/// Why a governed call was refused before it ran.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RefusalReason {
    /// Malformed or unknown request (bad input, unknown resource, conflict).
    Request,
    /// The caller is not authenticated or not authorized.
    Permission,
    /// The Charter's policy denied the call.
    Policy,
    /// A human must approve (or denied) the call.
    Approval,
    /// A budget (execs, egress, tokens, cost, wall clock) is spent.
    Budget,
    /// The sandbox could not provide the Charter's isolation floor.
    Isolation,
    /// The environment cannot run the call (missing runtime, disabled
    /// feature).
    Environment,
    /// The server is at capacity (rate limited).
    Capacity,
    /// A retry storm was shed (the upstream asked callers to back off).
    Shed,
    /// The transport protocol was violated (bad MCP/JSON-RPC framing).
    Protocol,
}

impl RefusalReason {
    /// Every reason, in schema order.
    pub const ALL: [Self; 10] = [
        Self::Request,
        Self::Permission,
        Self::Policy,
        Self::Approval,
        Self::Budget,
        Self::Isolation,
        Self::Environment,
        Self::Capacity,
        Self::Shed,
        Self::Protocol,
    ];

    /// The wire spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Request => "request",
            Self::Permission => "permission",
            Self::Policy => "policy",
            Self::Approval => "approval",
            Self::Budget => "budget",
            Self::Isolation => "isolation",
            Self::Environment => "environment",
            Self::Capacity => "capacity",
            Self::Shed => "shed",
            Self::Protocol => "protocol",
        }
    }

    /// Whether re-sending the same request is safe and may succeed later.
    /// Only transient refusals that provably did not run qualify.
    pub fn retryable(self) -> bool {
        matches!(self, Self::Capacity | Self::Shed)
    }

    /// The refusal class of a REST error status, for error bodies built
    /// without a control-plane [`Error`]. 5xx statuses other than 503 are
    /// not refusals: an internal failure does not prove nothing ran.
    pub fn from_http_status(status: u16) -> Option<Self> {
        match status {
            400 | 404 | 405 | 409 | 411 | 413 | 415 | 422 => Some(Self::Request),
            401 | 403 => Some(Self::Permission),
            429 => Some(Self::Capacity),
            503 => Some(Self::Capacity),
            _ => None,
        }
    }
}

impl std::fmt::Display for RefusalReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A governed call that did not execute. See the module docs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Refusal {
    /// Always true; lets clients test one field.
    pub refused: bool,
    pub reason: RefusalReason,
    pub retryable: bool,
    /// The caller's `X-Request-Id`, or a generated id.
    pub request_id: String,
    pub message: String,
}

impl Refusal {
    /// A refusal with the reason's default retryability, correlated with
    /// the current request (or a fresh id).
    pub fn new(reason: RefusalReason, message: impl Into<String>) -> Self {
        Self {
            refused: true,
            reason,
            retryable: reason.retryable(),
            request_id: current_request_id().unwrap_or_else(new_request_id),
            message: message.into(),
        }
    }

    /// Overrides the request id.
    #[must_use]
    pub fn with_request_id(mut self, id: impl Into<String>) -> Self {
        self.request_id = id.into();
        self
    }

    /// The refusal for a control-plane error, or `None` when the error
    /// does not prove the call never ran. `message` is what the transport
    /// already shows the caller (opaque errors stay opaque).
    pub fn for_error(err: &Error, message: impl Into<String>) -> Option<Self> {
        reason_for_error(err).map(|r| Self::new(r, message))
    }

    /// The refusal for a governed result that did not run (deny or
    /// require-approval), or `None` when it ran.
    pub fn for_result(res: &ToolResult) -> Option<Self> {
        let reason = reason_for_result(res)?;
        let message = if res.reason.is_empty() {
            res.verdict.as_str().to_string()
        } else {
            res.reason.clone()
        };
        Some(Self::new(reason, message))
    }

    /// The fields as a JSON object (for merging into an existing body).
    pub fn to_json(&self) -> serde_json::Map<String, serde_json::Value> {
        match serde_json::to_value(self) {
            Ok(serde_json::Value::Object(m)) => m,
            _ => serde_json::Map::new(),
        }
    }

    /// Adds the refusal to a JSON object body under `refusal`, keeping
    /// every field already present. Non-object bodies are left alone.
    pub fn attach(&self, body: &mut serde_json::Value) {
        if let Some(obj) = body.as_object_mut() {
            obj.insert("refusal".into(), serde_json::Value::Object(self.to_json()));
        }
    }
}

/// Maps an [`Error`] to a refusal class. `Error::Other` is opaque (it may
/// have failed after work started), so it is not a refusal.
pub fn reason_for_error(err: &Error) -> Option<RefusalReason> {
    use runeward_fleet::FleetError;
    match err {
        Error::NotFound(_) | Error::BadInput(_) => Some(RefusalReason::Request),
        Error::Task(FleetError::NotFound(_) | FleetError::IllegalTransition(_)) => {
            Some(RefusalReason::Request)
        }
        Error::InvalidLease => Some(RefusalReason::Permission),
        Error::IsolationFloor { .. } => Some(RefusalReason::Isolation),
        _ => None,
    }
}

/// Maps a governed result to a refusal class, or `None` when it ran.
pub fn reason_for_result(res: &ToolResult) -> Option<RefusalReason> {
    match res.verdict {
        Verdict::Allow => None,
        Verdict::RequireApproval => Some(RefusalReason::Approval),
        _ => Some(classify_deny(&res.reason)),
    }
}

/// Classifies a deny reason produced by the governed path.
fn classify_deny(reason: &str) -> RefusalReason {
    use runeward_policy::GuardError;
    if reason == "denied by approver" {
        return RefusalReason::Approval;
    }
    let budget = [
        GuardError::WallClock,
        GuardError::MaxExecs,
        GuardError::EgressBudget,
    ]
    .iter()
    .any(|g| reason == g.to_string());
    if budget
        || reason.starts_with("token budget exhausted")
        || reason.starts_with("cost budget exhausted")
    {
        return RefusalReason::Budget;
    }
    RefusalReason::Policy
}

tokio::task_local! {
    static REQUEST_ID: String;
}

/// Runs `fut` with `id` as the current request id (see
/// [`current_request_id`]).
pub async fn with_request_id<F: Future>(id: String, fut: F) -> F::Output {
    REQUEST_ID.scope(id, fut).await
}

/// The request id of the request being served on this task, if a
/// transport set one with [`with_request_id`].
pub fn current_request_id() -> Option<String> {
    REQUEST_ID.try_with(Clone::clone).ok()
}

/// A fresh 64-bit hex request id.
pub fn new_request_id() -> String {
    hex::encode(rand::random::<[u8; 8]>())
}

/// Accepts a caller-supplied request id when it is short and made of
/// `[A-Za-z0-9._:-]`, so it is safe to echo in headers, bodies and logs.
pub fn sanitize_request_id(raw: &str) -> Option<String> {
    let id = raw.trim();
    let ok = !id.is_empty()
        && id.len() <= MAX_REQUEST_ID_LEN
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'));
    ok.then(|| id.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use runeward_fleet::FleetError;
    use serde_json::json;

    fn result(verdict: Verdict, reason: &str) -> ToolResult {
        ToolResult {
            verdict,
            reason: reason.into(),
            approval_id: String::new(),
            pending: false,
            exit_code: 0,
            stdout: String::new(),
            stderr: String::new(),
            duration_ms: 0,
        }
    }

    #[test]
    fn schema_spelling() {
        let r = Refusal::new(RefusalReason::Policy, "no").with_request_id("abc");
        assert_eq!(
            serde_json::to_value(&r).expect("json"),
            json!({"refused": true, "reason": "policy", "retryable": false, "request_id": "abc", "message": "no"})
        );
        let spelled: Vec<String> = RefusalReason::ALL
            .iter()
            .map(|r| {
                serde_json::to_value(r)
                    .expect("json")
                    .as_str()
                    .expect("s")
                    .to_string()
            })
            .collect();
        assert_eq!(
            spelled,
            [
                "request",
                "permission",
                "policy",
                "approval",
                "budget",
                "isolation",
                "environment",
                "capacity",
                "shed",
                "protocol"
            ]
        );
        for r in RefusalReason::ALL {
            assert_eq!(r.to_string(), r.as_str());
        }
    }

    #[test]
    fn only_transient_refusals_are_retryable() {
        let retryable: Vec<RefusalReason> = RefusalReason::ALL
            .into_iter()
            .filter(|r| r.retryable())
            .collect();
        assert_eq!(retryable, [RefusalReason::Capacity, RefusalReason::Shed]);
        assert!(Refusal::new(RefusalReason::Shed, "x").retryable);
        assert!(!Refusal::new(RefusalReason::Approval, "x").retryable);
    }

    #[test]
    fn errors_map_to_reasons() {
        let cases = [
            (Error::NotFound("x".into()), Some(RefusalReason::Request)),
            (Error::BadInput("x".into()), Some(RefusalReason::Request)),
            (
                Error::Task(FleetError::IllegalTransition("x".into())),
                Some(RefusalReason::Request),
            ),
            (Error::InvalidLease, Some(RefusalReason::Permission)),
            (
                Error::IsolationFloor {
                    charter: "c".into(),
                    required: "vm".into(),
                    actual: "container".into(),
                    backend: "docker".into(),
                },
                Some(RefusalReason::Isolation),
            ),
            (Error::Other("boom".into()), None),
        ];
        for (err, want) in cases {
            assert_eq!(reason_for_error(&err), want, "{err}");
            assert_eq!(Refusal::for_error(&err, "m").map(|r| r.reason), want);
        }
    }

    #[test]
    fn results_map_to_reasons() {
        let cases = [
            (Verdict::Allow, "", None),
            (
                Verdict::RequireApproval,
                "needs a human",
                Some(RefusalReason::Approval),
            ),
            (
                Verdict::Deny,
                "denied by approver",
                Some(RefusalReason::Approval),
            ),
            (
                Verdict::Deny,
                "policy: max execs exceeded",
                Some(RefusalReason::Budget),
            ),
            (
                Verdict::Deny,
                "policy: egress budget exceeded",
                Some(RefusalReason::Budget),
            ),
            (
                Verdict::Deny,
                "token budget exhausted: 10/10 tokens used",
                Some(RefusalReason::Budget),
            ),
            (
                Verdict::Deny,
                "cost budget exhausted: $1/$1 spent",
                Some(RefusalReason::Budget),
            ),
            (
                Verdict::Deny,
                "policy: runaway loop detected",
                Some(RefusalReason::Policy),
            ),
            (Verdict::Deny, "no deletes", Some(RefusalReason::Policy)),
        ];
        for (verdict, reason, want) in cases {
            let r = result(verdict, reason);
            assert_eq!(reason_for_result(&r), want, "{reason}");
            if let Some(refusal) = Refusal::for_result(&r) {
                assert_eq!(refusal.message, reason);
            }
        }
    }

    #[test]
    fn attach_keeps_existing_fields() {
        let r = Refusal::new(RefusalReason::Request, "bad").with_request_id("id-1");
        let mut body = json!({"error": "bad", "code": "invalid_request", "reason": "x"});
        r.attach(&mut body);
        assert_eq!(body["error"], "bad");
        assert_eq!(body["code"], "invalid_request");
        assert_eq!(body["reason"], "x", "a body's own reason keeps its meaning");
        assert_eq!(body["refusal"]["refused"], true);
        assert_eq!(body["refusal"]["reason"], "request");
        assert_eq!(body["refusal"]["request_id"], "id-1");
        let mut not_object = json!("x");
        r.attach(&mut not_object);
        assert_eq!(not_object, json!("x"));
    }

    #[test]
    fn http_statuses() {
        assert_eq!(
            RefusalReason::from_http_status(400),
            Some(RefusalReason::Request)
        );
        assert_eq!(
            RefusalReason::from_http_status(403),
            Some(RefusalReason::Permission)
        );
        assert_eq!(
            RefusalReason::from_http_status(429),
            Some(RefusalReason::Capacity)
        );
        assert_eq!(RefusalReason::from_http_status(500), None);
        assert_eq!(RefusalReason::from_http_status(200), None);
    }

    #[test]
    fn request_ids() {
        assert_eq!(
            sanitize_request_id(" abc-1.2_x:y "),
            Some("abc-1.2_x:y".into())
        );
        assert_eq!(sanitize_request_id(""), None);
        assert_eq!(sanitize_request_id("a b"), None);
        assert_eq!(sanitize_request_id("a\r\nX-Evil: 1"), None);
        assert_eq!(
            sanitize_request_id(&"a".repeat(MAX_REQUEST_ID_LEN + 1)),
            None
        );
        assert_eq!(new_request_id().len(), 16);
    }

    #[tokio::test]
    async fn request_id_scope() {
        assert_eq!(current_request_id(), None);
        let got = with_request_id("rid-7".into(), async {
            Refusal::new(RefusalReason::Policy, "x").request_id
        })
        .await;
        assert_eq!(got, "rid-7");
    }
}
