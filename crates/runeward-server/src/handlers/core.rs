//! Health, metrics, identity, Charters, readiness, tickets and runs.

use std::time::Duration;

use axum::body::Body;
use axum::extract::{Path, Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::json;

use super::{rfc3339, sandbox_visible};
use crate::auth::query_get;
use crate::respond::{decode, error, json, not_found_text, server_error};
use crate::state::{Caller, SharedState, TicketKind, TicketScope};

pub(crate) async fn health() -> Response {
    json(StatusCode::OK, &json!({"status": "ok"}))
}

pub(crate) async fn metrics() -> Response {
    let (content_type, body) = runeward_obs::metrics_handler();
    let mut resp = body.into_response();
    if let Ok(v) = HeaderValue::from_str(content_type) {
        resp.headers_mut().insert(header::CONTENT_TYPE, v);
    }
    resp
}

/// The caller's identity and capabilities, so the dashboard can render its
/// login and gate controls. A 200 confirms the presented token is valid.
pub(crate) async fn whoami(State(s): State<SharedState>, caller: Caller) -> Response {
    let principal = match caller.get() {
        Some(p) => json!({
            "name": p.name,
            "tenant": p.tenant_id(),
            "admin": p.admin,
            "can_approve": p.may_approve(),
            "can_launch": p.may_launch(),
            "allowed_profiles": go_slice(&p.allowed_profiles),
            "approval_profiles": go_slice(&p.approval_profiles),
            "can_manage_all": p.admin,
            "can_export_audit": p.admin,
        }),
        // Legacy single-token or open mode: no named identity, full rights.
        None => json!({"name": "", "admin": true, "can_approve": true, "can_launch": true}),
    };
    json(
        StatusCode::OK,
        &json!({"authenticated": true, "rbac": s.authz.is_some(), "principal": principal}),
    )
}

/// An absent list in the principals file is `null` on the wire, as Go
/// encodes a nil slice (the store cannot tell absent from `[]`).
fn go_slice(v: &[String]) -> Option<&[String]> {
    (!v.is_empty()).then_some(v)
}

pub(crate) async fn list_profiles(State(s): State<SharedState>, caller: Caller) -> Response {
    let mut profiles = match s.mgr.list_profiles().await {
        Ok(p) => p,
        Err(e) => return server_error(&e),
    };
    // Non-admins only see Charters they may launch.
    if let Some(p) = caller.scoped() {
        profiles.retain(|info| p.can_launch(&info.name));
    }
    json(StatusCode::OK, &json!({"profiles": profiles}))
}

pub(crate) async fn readiness(
    State(s): State<SharedState>,
    caller: Caller,
    req: Request,
) -> Response {
    let name = query_get(req.uri(), "profile");
    let name = name.trim();
    if name.is_empty() {
        return error(StatusCode::BAD_REQUEST, "profile is required");
    }
    if caller.get().is_some_and(|p| !p.can_launch(name)) {
        return error(StatusCode::NOT_FOUND, "charter not found");
    }
    json(StatusCode::OK, &s.mgr.check_readiness(name).await)
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct TicketRequest {
    kind: String,
    sandbox_id: String,
    path: String,
    ttl_seconds: i64,
}

/// Mints a short-lived, single-use ticket for a WebSocket, the IDE or a
/// download, so long-lived credentials never appear in URLs.
pub(crate) async fn create_ticket(
    State(s): State<SharedState>,
    caller: Caller,
    body: Body,
) -> Response {
    let req: TicketRequest = match decode(body).await {
        Ok(r) => r,
        Err(e) => return e.into_response(),
    };
    let mut kind = req.kind.trim().to_lowercase();
    let sandbox_id = req.sandbox_id.trim().to_owned();
    let mut path = req.path.trim().to_owned();
    if kind.is_empty() {
        kind = if sandbox_id.is_empty() {
            "download"
        } else {
            "terminal"
        }
        .into();
    }
    for k in ["terminal", "conversation", "ide"] {
        if kind == k && sandbox_id.is_empty() {
            return error(
                StatusCode::BAD_REQUEST,
                format!("sandbox_id is required for {k} tickets"),
            );
        }
    }
    let Some(parsed) = TicketKind::parse(&kind) else {
        return error(StatusCode::BAD_REQUEST, "unsupported ticket kind");
    };
    if parsed.sandbox_scoped()
        && (s.mgr.sandbox(&sandbox_id).is_none() || !sandbox_visible(&s, &caller, &sandbox_id))
    {
        return error(StatusCode::NOT_FOUND, "sandbox not found");
    }
    if parsed == TicketKind::Ide {
        if !s.mgr.experimental_ide_enabled() {
            return error(StatusCode::NOT_FOUND, super::ide::IDE_DISABLED);
        }
        if s.mgr.ide_endpoint(&sandbox_id).is_none() {
            return error(StatusCode::NOT_FOUND, super::ide::IDE_UNAVAILABLE);
        }
    }
    if parsed == TicketKind::Download && path.is_empty() {
        path = "/v1/chronicle/export".into();
    }
    let secs = u64::try_from(req.ttl_seconds).unwrap_or(0);
    let ttl = if secs > 0 {
        Duration::from_secs(secs)
    } else {
        Duration::from_secs(30)
    }
    .min(Duration::from_secs(120));
    let scope = TicketScope {
        kind: parsed,
        sandbox_id: sandbox_id.clone(),
        path: path.clone(),
    };
    match s.issue_ticket(scope, caller.0.clone(), ttl) {
        Ok((ticket, expires_at)) => json(
            StatusCode::CREATED,
            &json!({
                "ticket": ticket,
                "expires_at": rfc3339(expires_at),
                "scope": {"kind": kind, "sandbox_id": sandbox_id, "path": path},
            }),
        ),
        Err(e) => error(StatusCode::BAD_REQUEST, e),
    }
}

pub(crate) async fn list_runs(State(s): State<SharedState>, caller: Caller) -> Response {
    let mut runs = s.mgr.list_runs();
    if let Some(p) = caller.scoped() {
        runs.retain(|r| r.tenant == p.tenant_id());
    }
    json(StatusCode::OK, &json!({"runs": runs}))
}

pub(crate) async fn get_run(
    State(s): State<SharedState>,
    caller: Caller,
    Path(id): Path<String>,
) -> Response {
    match s.mgr.run(&id) {
        Some(run) if caller.scoped().is_none_or(|p| run.tenant == p.tenant_id()) => {
            json(StatusCode::OK, &run)
        }
        _ => error(StatusCode::NOT_FOUND, "run not found"),
    }
}

/// `/` without the dashboard: a pointer to the API; anything else is 404.
pub(crate) async fn api_root(req: Request) -> Response {
    if req.uri().path() != "/" {
        return not_found_text();
    }
    json(
        StatusCode::OK,
        &json!({
            "service": "runeward control plane",
            "docs": "/v1/charters, /v1/citadels, /v1/conclave, /v1/chronicle/verify",
        }),
    )
}
