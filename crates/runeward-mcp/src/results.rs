//! Tool result shapes, byte-compatible with the Go server's text content.
//!
//! Go marshals `map[string]any` with sorted keys and structs in field
//! order. Results here are serialized from typed values whose fields are
//! declared in that same order, so the text content matches Go regardless
//! of serde_json's map-ordering features; `structuredContent` carries the
//! same value.

use rmcp::model::{CallToolResult, ContentBlock as Content};
use runeward_charter::Verdict;
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

#[derive(Serialize)]
struct ErrBody<'a> {
    code: &'a str,
    error: &'a str,
}

/// A classified tool error (Go's `errText`): `authz_denied`, `not_found`
/// or `tool_error`.
pub(crate) fn err_text(msg: &str) -> CallToolResult {
    let lower = msg.to_lowercase();
    let code = if lower.contains("bearer token")
        || lower.contains("not authorized")
        || lower.contains("not allowed")
    {
        "authz_denied"
    } else if lower.contains("not found") {
        "not_found"
    } else {
        "tool_error"
    };
    failed(structured(&ErrBody { code, error: msg }))
}

/// A control-plane error as a tool error. The message is returned as the
/// Go server did.
pub(crate) fn cp_err(e: &CpError) -> CallToolResult {
    err_text(&e.to_string())
}

#[derive(Serialize)]
struct Denied<'a> {
    code: &'a str,
    reason: &'a str,
    verdict: &'a str,
}

#[derive(Serialize)]
struct Pending<'a> {
    approval_id: &'a str,
    code: &'a str,
    reason: &'a str,
    verdict: &'a str,
}

/// A deny (tool error) or pending-approval result, or `None` when the call
/// ran and the caller formats success (Go's `blockedResult`).
pub(crate) fn blocked(res: &ToolResult) -> Option<CallToolResult> {
    if res.verdict == Verdict::Deny {
        return Some(failed(structured(&Denied {
            code: "policy_denied",
            reason: &res.reason,
            verdict: "deny",
        })));
    }
    if res.verdict == Verdict::RequireApproval {
        return Some(structured(&Pending {
            approval_id: &res.approval_id,
            code: "approval_required",
            reason: &res.reason,
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
        }
        assert_eq!(body(&err_text("x")), r#"{"code":"tool_error","error":"x"}"#);
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
