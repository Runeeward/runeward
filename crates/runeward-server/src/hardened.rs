//! Request correlation, per-principal rate limiting and the hardened-mode
//! startup gate.
//!
//! - Every response carries `X-Request-Id`: the caller's (when short and
//!   plain) or a generated one. The id is also the `request_id` of any
//!   refusal body (see [`runeward_controlplane::refusal`]).
//! - With `RUNEWARD_PRINCIPAL_RATE_LIMIT` set, each authenticated principal
//!   gets its own token bucket on top of the per-IP limit.
//! - In hardened mode [`crate::serve`] refuses to start unless
//!   [`runeward_controlplane::hardening`] passes.

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::Response;
use runeward_authz::Principal;
use runeward_controlplane::Manager;
use runeward_controlplane::hardening::{Listener, ServerChecks, Violation};
use runeward_controlplane::refusal::{
    REQUEST_ID_HEADER, new_request_id, sanitize_request_id, with_request_id,
};

use crate::ServerConfig;
use crate::respond::error;
use crate::state::SharedState;

/// Echoes (or generates) `X-Request-Id` and makes it the current request id
/// for every handler and refusal body below.
pub(crate) async fn request_id(req: Request, next: Next) -> Response {
    let id = req
        .headers()
        .get(REQUEST_ID_HEADER)
        .and_then(|v| v.to_str().ok())
        .and_then(sanitize_request_id)
        .unwrap_or_else(new_request_id);
    let mut resp = with_request_id(id.clone(), next.run(req)).await;
    if let Ok(v) = HeaderValue::from_str(&id) {
        resp.headers_mut().insert(REQUEST_ID_HEADER, v);
    }
    resp
}

/// Per-principal rate limiting, after authentication. Requests without a
/// principal (open or legacy-token mode) are left to the per-IP limit.
pub(crate) async fn principal_rate_limit(
    State(s): State<SharedState>,
    req: Request,
    next: Next,
) -> Response {
    if let (Some(l), Some(p)) = (
        &s.principal_limiter,
        req.extensions().get::<Arc<Principal>>(),
    ) && !l.allow(&p.name)
    {
        let wait = l.retry_after(&p.name).as_secs().max(1);
        let mut resp = error(
            StatusCode::TOO_MANY_REQUESTS,
            "rate limit exceeded for this principal",
        );
        if let Ok(v) = HeaderValue::from_str(&wait.to_string()) {
            resp.headers_mut().insert(header::RETRY_AFTER, v);
        }
        return resp;
    }
    next.run(req).await
}

/// What `config` tells the hardened-mode check about this server.
pub(crate) fn server_checks(config: &ServerConfig, principal_rate_limit: bool) -> ServerChecks {
    ServerChecks {
        listeners: vec![Listener {
            name: if config.mcp.is_some() {
                "rest+mcp".into()
            } else {
                "rest".into()
            },
            bind: config.bind.clone(),
            tls: config.tls.is_some(),
        }],
        per_principal_auth: config.authz.is_some(),
        shared_token: !config.token.is_empty(),
        principal_rate_limit,
        backend_tiers: Default::default(),
    }
}

/// Runs the hardened-mode check, printing every violation to stderr and
/// the log. Returns them all on failure.
pub(crate) async fn hardened_gate(
    config: &ServerConfig,
    mgr: &Manager,
    principal_rate_limit: bool,
) -> Result<(), Vec<Violation>> {
    let checks = server_checks(config, principal_rate_limit);
    let res = mgr.check_hardened(&checks).await;
    if let Err(violations) = &res {
        for v in violations {
            eprintln!("runeward: {v}");
            tracing::error!(rule = v.rule.as_str(), subject = %v.subject, "{}", v.message);
        }
    }
    res
}
