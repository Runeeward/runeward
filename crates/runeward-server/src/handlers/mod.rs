//! Route handlers, one module per API area.

// Helpers return a ready response as their error so handlers can `?`-style
// bail out; boxing it would only add noise.
#![allow(clippy::result_large_err)]

use std::time::SystemTime;

use axum::http::StatusCode;
use axum::response::Response;
use runeward_backend::Sandbox;
use runeward_charter::Verdict;
use runeward_controlplane::{Result, ToolResult};
use serde_json::{Map, Value, json};

use crate::respond::{server_error, tool_json};
use crate::state::{AppState, Caller};

pub(crate) mod agents;
pub(crate) mod chronicle;
pub(crate) mod citadels;
pub(crate) mod conversation;
pub(crate) mod core;
pub(crate) mod fleet;
pub(crate) mod ide;
pub(crate) mod schedules;
pub(crate) mod simulate;
pub(crate) mod terminal;
pub(crate) mod tools;

/// Go's JSON encoding of a UTC `time.Time` (RFC 3339 with nanoseconds,
/// trailing zeros trimmed).
pub(crate) fn rfc3339(t: SystemTime) -> String {
    let t = chrono::DateTime::<chrono::Utc>::from(t).fixed_offset();
    runeward_ledger::gotime::format_rfc3339_nano(&t)
}

/// Whether the caller may see a Citadel: open/legacy mode and admins see
/// all; a tenant sees only its own.
pub(crate) fn sandbox_visible(s: &AppState, caller: &Caller, id: &str) -> bool {
    caller
        .scoped()
        .is_none_or(|p| s.mgr.sandbox_owner(id).is_some_and(|o| o == p.tenant_id()))
}

/// The JSON projection of a Citadel. `isolation` is new in the Rust port.
pub(crate) fn sandbox_view(sb: &Sandbox, owner: &str) -> Map<String, Value> {
    let mut v = Map::new();
    v.insert("id".into(), json!(sb.id));
    v.insert("profile".into(), json!(sb.profile));
    v.insert("backend".into(), json!(sb.backend));
    v.insert("image".into(), json!(sb.image));
    v.insert("status".into(), json!(sb.status));
    v.insert("isolation".into(), json!(sb.isolation.as_str()));
    if !owner.is_empty() {
        v.insert("owner".into(), json!(owner));
    }
    v
}

/// [`sandbox_view`] plus capabilities and the IDE hints.
pub(crate) fn sandbox_view_with_ide(s: &AppState, sb: &Sandbox, owner: &str) -> Map<String, Value> {
    let mut v = sandbox_view(sb, owner);
    let caps = s.mgr.sandbox_capabilities(&sb.id);
    if !caps.is_empty() {
        v.insert("capabilities".into(), json!(caps));
    }
    if s.mgr.ide_endpoint(&sb.id).is_some() {
        v.insert("ide".into(), json!(true));
        let agents = s.mgr.ide_agents(&sb.id);
        if !agents.is_empty() {
            v.insert("ide_agents".into(), json!(agents));
        }
    }
    v
}

/// Maps a governed result: 403 deny, 202 pending approval, 200 otherwise.
pub(crate) fn tool_result(res: Result<ToolResult>) -> Response {
    match res {
        Err(e) => server_error(&e),
        Ok(r) => tool_json(verdict_status(&r.verdict), &r),
    }
}

fn verdict_status(v: &Verdict) -> StatusCode {
    match v {
        Verdict::Deny => StatusCode::FORBIDDEN,
        Verdict::RequireApproval => StatusCode::ACCEPTED,
        _ => StatusCode::OK,
    }
}

/// The error/deny/pending cases shared by the file endpoints: `Err` holds
/// the response to send, `Ok` the allowed result.
pub(crate) fn unless_blocked(res: Result<ToolResult>) -> std::result::Result<ToolResult, Response> {
    match res {
        Err(e) => Err(server_error(&e)),
        Ok(r) if matches!(r.verdict, Verdict::Deny | Verdict::RequireApproval) => {
            Err(tool_json(verdict_status(&r.verdict), &r))
        }
        Ok(r) => Ok(r),
    }
}

/// Keeps `[A-Za-z0-9_-]` for a download file name; `export` when empty.
pub(crate) fn safe_filename(s: &str) -> String {
    let out: String = s
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
        .collect();
    if out.is_empty() { "export".into() } else { out }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filenames() {
        assert_eq!(safe_filename("ab/../c d"), "abcd");
        assert_eq!(safe_filename("../"), "export");
        assert_eq!(safe_filename("x-1_y"), "x-1_y");
    }
}
