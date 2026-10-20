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

/// The JSON projection of a Citadel. `isolation` and `isolation_evidence`
/// are new in the Rust port.
///
/// `isolation_evidence` says where the tier comes from: the backend that
/// reported it (backends report the tier they delivered, never the one
/// they were asked for). [`sandbox_view_with_floor`] adds the Charter's
/// floor.
pub(crate) fn sandbox_view(sb: &Sandbox, owner: &str) -> Map<String, Value> {
    let mut v = Map::new();
    v.insert("id".into(), json!(sb.id));
    v.insert("profile".into(), json!(sb.profile));
    v.insert("backend".into(), json!(sb.backend));
    v.insert("image".into(), json!(sb.image));
    v.insert("status".into(), json!(sb.status));
    v.insert("isolation".into(), json!(sb.isolation.as_str()));
    let mut evidence = json!({
        "tier": sb.isolation.as_str(),
        "backend": sb.backend,
        "source": "backend",
    });
    // The in-sandbox probe's observations (runtime, kernels, hypervisor),
    // when the backend collected them; the tier above is derived from these.
    if let (Some(probe), Value::Object(ev)) = (&sb.isolation_evidence, &mut evidence) {
        ev.insert("source".into(), json!("probe"));
        ev.insert("runtime".into(), json!(probe.runtime));
        ev.insert("guest_kernel".into(), json!(probe.guest_kernel));
        ev.insert("host_kernel".into(), json!(probe.host_kernel));
        ev.insert("hypervisor".into(), json!(probe.hypervisor));
        ev.insert("signals".into(), json!(probe.signals));
    }
    v.insert("isolation_evidence".into(), evidence);
    if !owner.is_empty() {
        v.insert("owner".into(), json!(owner));
    }
    v
}

/// The rank of an isolation tier or Charter floor name, weakest first.
fn tier_rank(name: &str) -> Option<usize> {
    ["process", "container", "kernel", "vm"]
        .iter()
        .position(|t| *t == name)
}

/// Adds the Charter's isolation floor (`[isolation] minimum`) to a view's
/// `isolation_evidence`: `floor` (empty when unset) and `meets_floor`.
pub(crate) fn add_isolation_floor(v: &mut Map<String, Value>, floor: &str) {
    let tier = v
        .get("isolation")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let meets = match (tier_rank(&tier), tier_rank(floor)) {
        (_, None) => true,
        (Some(t), Some(f)) => t >= f,
        (None, Some(_)) => false,
    };
    if let Some(Value::Object(ev)) = v.get_mut("isolation_evidence") {
        ev.insert("floor".into(), json!(floor));
        ev.insert("meets_floor".into(), json!(meets));
    }
}

/// [`sandbox_view`] plus capabilities, the supervisor's enforcement
/// evidence (`enforcement`, only for Charters run under the in-sandbox
/// supervisor) and the IDE hints.
pub(crate) fn sandbox_view_with_ide(s: &AppState, sb: &Sandbox, owner: &str) -> Map<String, Value> {
    let mut v = sandbox_view(sb, owner);
    if let Some(ev) = s
        .mgr
        .session_handle(&sb.id)
        .and_then(|sess| sess.enforcement().cloned())
    {
        v.insert("enforcement".into(), json!(ev));
    }
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
