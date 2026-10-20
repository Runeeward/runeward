//! Tool result shapes, byte-compatible with the Go server's text content.
//!
//! Go marshals `map[string]any` with sorted keys and structs in field
//! order. Results here are serialized from typed values whose fields are
//! declared in that same order, so the text content matches Go regardless
//! of serde_json's map-ordering features; `structuredContent` carries the
//! same value.

use rmcp::model::{CallToolResult, ContentBlock as Content};
use runeward_charter::Verdict;
use runeward_controlplane::refusal::{Refusal, RefusalReason};
use runeward_controlplane::{Error as CpError, ToolResult};
use serde::{Serialize, Serializer};

/// A text-only success result.
pub(crate) fn text(s: impl Into<String>) -> CallToolResult {
    let mut r = CallToolResult::success(vec![Content::text(s.into())]);
    r.is_error = None;
    r
}

/// A success result whose text is the JSON of `v` and whose structured
/// content is `v`.
pub(crate) fn structured<T: Serialize + ?Sized>(v: &T) -> CallToolResult {
    let encoded = serde_json::to_string(v).and_then(|t| Ok((t, serde_json::to_value(v)?)));
    match encoded {
        Ok((body, value)) => {
            let mut r = text(body);
            r.structured_content = Some(value);
            r
        }
        Err(e) => {
            let mut r = text(format!("error: encode structured result: {e}"));
            r.is_error = Some(true);
            r
        }
    }
}

fn failed(mut r: CallToolResult) -> CallToolResult {
    r.is_error = Some(true);
    r
}

// Every body below keeps Go's fields (sorted, as Go marshals maps) and
// adds the standard refusal object under `refusal` when the call did not
// run (see `runeward_controlplane::refusal`).

#[derive(Serialize)]
struct ErrBody<'a> {
    code: &'a str,
    error: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    refusal: Option<Refusal>,
}

/// Go's `errText` classification: `authz_denied`, `not_found` or
/// `tool_error`.
fn classify(msg: &str) -> &'static str {
    let lower = msg.to_lowercase();
    if lower.contains("bearer token")
        || lower.contains("not authorized")
        || lower.contains("not allowed")
    {
        "authz_denied"
    } else if lower.contains("not found") {
        "not_found"
    } else {
        "tool_error"
    }
}

/// A classified tool error (Go's `errText`). Authorization and not-found
/// errors are refusals (nothing ran); other tool errors are not, since
/// they may have failed part way.
pub(crate) fn err_text(msg: &str) -> CallToolResult {
    let code = classify(msg);
    let reason = match code {
        "authz_denied" => Some(RefusalReason::Permission),
        "not_found" => Some(RefusalReason::Request),
        _ => None,
    };
    err_body(code, msg, reason.map(|r| Refusal::new(r, msg)))
}

fn err_body(code: &str, msg: &str, refusal: Option<Refusal>) -> CallToolResult {
    failed(structured(&ErrBody {
        code,
        error: msg,
        refusal,
    }))
}

/// A control-plane error as a tool error. The message is returned as the
/// Go server did; the refusal follows the error variant.
pub(crate) fn cp_err(e: &CpError) -> CallToolResult {
    let msg = e.to_string();
    let refusal = Refusal::for_error(e, &msg).or_else(|| {
        (classify(&msg) == "authz_denied").then(|| Refusal::new(RefusalReason::Permission, &msg))
    });
    err_body(classify(&msg), &msg, refusal)
}

#[derive(Serialize)]
struct Denied<'a> {
    code: &'a str,
    reason: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    refusal: Option<Refusal>,
    verdict: &'a str,
}

#[derive(Serialize)]
struct Pending<'a> {
    approval_id: &'a str,
    code: &'a str,
    reason: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    refusal: Option<Refusal>,
    verdict: &'a str,
}

/// A deny (tool error) or pending-approval result, or `None` when the call
/// ran and the caller formats success (Go's `blockedResult`).
pub(crate) fn blocked(res: &ToolResult) -> Option<CallToolResult> {
    if res.verdict == Verdict::Deny {
        return Some(failed(structured(&Denied {
            code: "policy_denied",
            reason: &res.reason,
            refusal: Refusal::for_result(res),
            verdict: "deny",
        })));
    }
    if res.verdict == Verdict::RequireApproval {
        return Some(structured(&Pending {
            approval_id: &res.approval_id,
            code: "approval_required",
            reason: &res.reason,
            refusal: Refusal::for_result(res),
            verdict: "require-approval",
        }));
    }
    None
}

#[derive(Serialize)]
struct Exec<'a> {
    duration_ms: i64,
    exit_code: i64,
    stderr: &'a str,
    stdout: &'a str,
    verdict: &'a str,
}

/// An exec-style result: exit code plus stdout/stderr.
pub(crate) fn exec(res: Result<ToolResult, CpError>) -> CallToolResult {
    let res = match res {
        Ok(r) => r,
        Err(e) => return cp_err(&e),
    };
    blocked(&res).unwrap_or_else(|| {
        structured(&Exec {
            duration_ms: res.duration_ms,
            exit_code: res.exit_code,
            stderr: &res.stderr,
            stdout: &res.stdout,
            verdict: res.verdict.as_str(),
        })
    })
}

#[derive(Serialize)]
struct Raw<'a> {
    output: &'a str,
    verdict: &'a str,
}

/// Just the stdout on success (read/list/search).
pub(crate) fn raw(res: Result<ToolResult, CpError>) -> CallToolResult {
    let res = match res {
        Ok(r) => r,
        Err(e) => return cp_err(&e),
    };
    blocked(&res).unwrap_or_else(|| {
        structured(&Raw {
            output: &res.stdout,
            verdict: res.verdict.as_str(),
        })
    })
}

/// Encodes an `f64` the way Go's `encoding/json` does for common values:
/// integral values without a fractional part (`1`, not `1.0`).
pub(crate) fn go_float<S: Serializer>(v: &f64, s: S) -> Result<S::Ok, S::Error> {
    const EXACT: f64 = 9_007_199_254_740_992.0; // 2^53
    if v.is_finite() && v.fract() == 0.0 && v.abs() < EXACT {
        // Lossless: |v| < 2^53 is an exact integer.
        #[allow(clippy::cast_possible_truncation)]
        let i = *v as i64;
        return s.serialize_i64(i);
    }
    s.serialize_f64(*v)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(r: &CallToolResult) -> String {
        r.content
            .iter()
            .filter_map(|c| c.as_text().map(|t| t.text.clone()))
            .collect()
    }

    #[test]
    fn error_codes_match_go() {
        for (msg, code) in [
            ("missing bearer token", "authz_denied"),
            ("not authorized to view conclave decisions", "authz_denied"),
            (
                "principal \"a\" is not allowed to launch charter \"b\"",
                "authz_denied",
            ),
            ("citadel not found", "not_found"),
            ("boom", "tool_error"),
        ] {
            let r = err_text(msg);
            assert_eq!(r.is_error, Some(true));
            let v: serde_json::Value = serde_json::from_str(&body(&r)).expect("json");
            assert_eq!(v["code"], code, "{msg}");
            assert_eq!(v["error"], msg);
            let want = match code {
                "authz_denied" => Some("permission"),
                "not_found" => Some("request"),
                _ => None,
            };
            assert_eq!(v["refusal"]["reason"].as_str(), want, "{msg}");
        }
        assert_eq!(body(&err_text("x")), r#"{"code":"tool_error","error":"x"}"#);
    }

    #[test]
    fn refusals_on_denied_and_pending_results() {
        let mut res = ToolResult {
            verdict: Verdict::Deny,
            reason: "no deletes".into(),
            approval_id: String::new(),
            pending: false,
            exit_code: 0,
            stdout: String::new(),
            stderr: String::new(),
            duration_ms: 0,
        };
        let r = blocked(&res).expect("blocked");
        let v: serde_json::Value = serde_json::from_str(&body(&r)).expect("json");
        assert_eq!(v["code"], "policy_denied");
        assert_eq!(v["reason"], "no deletes");
        assert_eq!(v["refusal"]["refused"], true);
        assert_eq!(v["refusal"]["reason"], "policy");
        assert_eq!(v["refusal"]["retryable"], false);
        assert_eq!(v["refusal"]["message"], "no deletes");
        // Keys stay sorted, as Go marshals them.
        let text = body(&r);
        assert!(text.find("\"reason\"") < text.find("\"refusal\""), "{text}");
        assert!(
            text.find("\"refusal\"") < text.find("\"verdict\""),
            "{text}"
        );

        res.verdict = Verdict::RequireApproval;
        res.approval_id = "ap-1".into();
        let v: serde_json::Value =
            serde_json::from_str(&body(&blocked(&res).expect("pending"))).expect("json");
        assert_eq!(v["refusal"]["reason"], "approval");
        assert_eq!(v["refusal"]["retryable"], false);

        let isolation = CpError::IsolationFloor {
            charter: "c".into(),
            required: "vm".into(),
            actual: "container".into(),
            backend: "docker".into(),
        };
        let v: serde_json::Value = serde_json::from_str(&body(&cp_err(&isolation))).expect("json");
        assert_eq!(v["refusal"]["reason"], "isolation");
        let v: serde_json::Value =
            serde_json::from_str(&body(&cp_err(&CpError::other("boom")))).expect("json");
        assert!(v.get("refusal").is_none(), "opaque errors are not refusals");
    }

    #[test]
    fn go_float_encoding() {
        #[derive(Serialize)]
        struct F {
            #[serde(serialize_with = "go_float")]
            v: f64,
        }
        let enc = |v| serde_json::to_string(&F { v }).expect("json");
        assert_eq!(enc(1.0), r#"{"v":1}"#);
        assert_eq!(enc(0.5), r#"{"v":0.5}"#);
        assert_eq!(enc(0.0), r#"{"v":0}"#);
    }
}
