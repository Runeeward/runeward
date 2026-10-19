//! The Chronicle (audit ledger) and the Conclave (approval inbox).

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{ConnectInfo, Path, Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::json;

use crate::auth::query_get;
use crate::respond::{error, json, server_error};
use crate::state::{Caller, SharedState};

pub(crate) async fn replay(State(s): State<SharedState>, Path(id): Path<String>) -> Response {
    let ledger = Arc::clone(s.mgr.ledger());
    let events = tokio::task::spawn_blocking(move || ledger.replay(&id)).await;
    match events {
        Ok(Ok(events)) => json(StatusCode::OK, &json!({"events": events})),
        Ok(Err(e)) => server_error(&e.into()),
        Err(e) => server_error(&runeward_controlplane::Error::other(e)),
    }
}

pub(crate) async fn verify(State(s): State<SharedState>) -> Response {
    let signed = s.mgr.signed();
    match s.mgr.verify_ledger().await {
        Ok(()) => json(StatusCode::OK, &json!({"ok": true, "signed": signed})),
        Err(e) => json(
            StatusCode::OK,
            &json!({"ok": false, "signed": signed, "error": e.to_string()}),
        ),
    }
}

pub(crate) async fn pubkey(State(s): State<SharedState>) -> Response {
    match s.mgr.ledger_public_key() {
        None => json(StatusCode::OK, &json!({"signed": false})),
        Some((public_key, key_id)) => json(
            StatusCode::OK,
            &json!({"signed": true, "public_key": public_key, "key_id": key_id}),
        ),
    }
}

/// A verifiable transcript bundle; `?session=<id>` narrows it to one
/// session. Administrators only under RBAC.
pub(crate) async fn export(State(s): State<SharedState>, caller: Caller, req: Request) -> Response {
    if caller.scoped().is_some() {
        return error(
            StatusCode::FORBIDDEN,
            "not authorized to export audit bundle",
        );
    }
    let session = query_get(req.uri(), "session");
    let mut resp = match s.mgr.export_bundle(&session).await {
        Ok(bundle) => {
            let mut r = bundle.into_response();
            r.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            );
            r
        }
        Err(e) => error(StatusCode::BAD_REQUEST, e.to_string()),
    };
    resp.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_static("attachment; filename=runeward-audit-bundle.json"),
    );
    resp
}

pub(crate) async fn list_approvals(State(s): State<SharedState>, caller: Caller) -> Response {
    if caller.get().is_some_and(|p| !p.may_approve()) {
        return error(StatusCode::FORBIDDEN, "not authorized to view approvals");
    }
    let mut list = s.mgr.approvals().list();
    if let Some(p) = caller.scoped() {
        list.retain(|a| {
            s.mgr
                .sandbox(&a.sandbox)
                .is_some_and(|sb| p.can_approve_profile(&sb.profile))
        });
    }
    json(StatusCode::OK, &json!({"approvals": list}))
}

pub(crate) async fn approve(
    State(s): State<SharedState>,
    caller: Caller,
    Path(id): Path<String>,
    req: Request,
) -> Response {
    resolve(s, caller, id, req, true).await
}

pub(crate) async fn deny(
    State(s): State<SharedState>,
    caller: Caller,
    Path(id): Path<String>,
    req: Request,
) -> Response {
    resolve(s, caller, id, req, false).await
}

async fn resolve(
    s: SharedState,
    caller: Caller,
    id: String,
    req: Request,
    approve: bool,
) -> Response {
    const GONE: &str = "approval not found or already resolved";
    if caller.get().is_some_and(|p| !p.may_approve()) {
        return error(StatusCode::FORBIDDEN, "not authorized to resolve approvals");
    }
    if let Some(p) = caller.scoped() {
        let allowed = s
            .mgr
            .approvals()
            .get(&id)
            .and_then(|a| s.mgr.sandbox(&a.sandbox))
            .is_some_and(|sb| p.can_approve_profile(&sb.profile));
        if !allowed {
            return error(StatusCode::NOT_FOUND, GONE);
        }
    }
    let who = approver(&caller, &req);
    if !s.mgr.resolve_approval(&id, approve, &who).await {
        return error(StatusCode::NOT_FOUND, GONE);
    }
    json(StatusCode::OK, &json!({"ok": true}))
}

/// Who resolved an approval, for the audit record: the RBAC principal,
/// else `X-Runeward-Actor` or `?actor=`, else the peer address, so a
/// decision is never fully anonymous.
fn approver(caller: &Caller, req: &Request) -> String {
    if let Some(p) = caller.get()
        && !p.name.is_empty()
    {
        return p.name.clone();
    }
    if let Some(a) = req
        .headers()
        .get("x-runeward-actor")
        .and_then(|v| v.to_str().ok())
        .filter(|a| !a.is_empty())
    {
        return a.to_owned();
    }
    let a = query_get(req.uri(), "actor");
    if !a.is_empty() {
        return a;
    }
    req.extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0.ip().to_string())
        .unwrap_or_default()
}
