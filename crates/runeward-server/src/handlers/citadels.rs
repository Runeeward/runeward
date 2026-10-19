//! Citadel lifecycle, usage, perimeter, snapshots and exports.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use futures_util::stream;
use runeward_controlplane::{CreateOptions, with_actor};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::io::AsyncReadExt;

use super::{safe_filename, sandbox_view, sandbox_view_with_ide};
use crate::respond::{decode, decode_optional, error, json};
use crate::state::{Caller, SharedState};

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct CreateRequest {
    profile: String,
    copy_from: String,
    parent_citadel: String,
    run_id: String,
    agent: String,
    provider: String,
    model: String,
}

pub(crate) async fn create(State(s): State<SharedState>, caller: Caller, body: Body) -> Response {
    let req: CreateRequest = match decode(body).await {
        Ok(r) => r,
        Err(e) => return e.into_response(),
    };
    if req.profile.is_empty() {
        return error(StatusCode::BAD_REQUEST, "profile is required");
    }
    let copy_from = !req.copy_from.trim().is_empty();
    if copy_from && caller.scoped().is_some() {
        return error(
            StatusCode::FORBIDDEN,
            "copy_from overrides require an administrator",
        );
    }
    if s.authz.is_some()
        && copy_from
        && std::env::var("RUNEWARD_COPY_FROM_ROOTS")
            .unwrap_or_default()
            .trim()
            .is_empty()
    {
        return error(
            StatusCode::FORBIDDEN,
            "copy_from is disabled under RBAC until RUNEWARD_COPY_FROM_ROOTS is configured",
        );
    }
    if let Some(p) = caller.get()
        && !p.can_launch(&req.profile)
    {
        return error(
            StatusCode::FORBIDDEN,
            format!("not authorized to launch profile {}", req.profile),
        );
    }
    let (owner, actor) = caller.identity();
    let opts = CreateOptions {
        copy_from: req.copy_from,
        owner: owner.clone(),
        actor,
        parent_sandbox: req.parent_citadel,
        run_id: req.run_id,
        agent: req.agent,
        provider: req.provider,
        model: req.model,
    };
    match s.mgr.create_sandbox(&req.profile, opts).await {
        Ok(sb) => json(StatusCode::CREATED, &sandbox_view(&sb, &owner)),
        Err(e) => error(StatusCode::BAD_REQUEST, e.to_string()),
    }
}

pub(crate) async fn list(State(s): State<SharedState>, caller: Caller) -> Response {
    let views: Vec<Value> = s
        .mgr
        .list_sandbox_infos()
        .iter()
        .filter(|i| caller.scoped().is_none_or(|p| i.owner == p.tenant_id()))
        .map(|i| Value::Object(sandbox_view_with_ide(&s, &i.sandbox, &i.owner)))
        .collect();
    json(StatusCode::OK, &json!({"sandboxes": views}))
}

pub(crate) async fn get(State(s): State<SharedState>, Path(id): Path<String>) -> Response {
    let Some(sb) = s.mgr.sandbox(&id) else {
        return error(StatusCode::NOT_FOUND, "sandbox not found");
    };
    let owner = s.mgr.sandbox_owner(&id).unwrap_or_default();
    let mut view = sandbox_view_with_ide(&s, &sb, &owner);
    let u = s.mgr.sandbox_usage(&id);
    view.insert(
        "usage".into(),
        json!({"tokens": u.tokens, "cost_usd": u.cost_usd}),
    );
    if let Ok(c) = s.mgr.load_profile(&sb.profile).await {
        let l = &c.limits;
        view.insert(
            "limits".into(),
            json!({
                "max_tokens": l.max_tokens,
                "max_cost_usd": l.max_cost_usd,
                "max_execs": l.max_execs,
                "egress_requests": l.egress_requests,
                "wall_clock": l.wall_clock,
            }),
        );
    }
    json(StatusCode::OK, &view)
}

pub(crate) async fn kill(State(s): State<SharedState>, Path(id): Path<String>) -> Response {
    match s.mgr.kill_sandbox(&id).await {
        Ok(()) => json(StatusCode::OK, &json!({"ok": true})),
        Err(e) => error(StatusCode::NOT_FOUND, e.to_string()),
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct UsageRequest {
    tokens: i64,
    cost_usd: f64,
}

/// Records model usage the agent observed so it counts toward the budget.
pub(crate) async fn report_usage(
    State(s): State<SharedState>,
    Path(id): Path<String>,
    body: Body,
) -> Response {
    let req: UsageRequest = match decode(body).await {
        Ok(r) => r,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = s.mgr.record_usage(&id, req.tokens, req.cost_usd).await {
        return error(StatusCode::NOT_FOUND, e.to_string());
    }
    let u = s.mgr.sandbox_usage(&id);
    json(
        StatusCode::OK,
        &json!({"tokens": u.tokens, "cost_usd": u.cost_usd}),
    )
}

/// The bounded in-memory egress decision log. Broker decisions carry the
/// request-level fields (`endpoint`, `protocol`, `method`, `path`, `tool`,
/// `effect`, `verdict`, `reason_code`, ...) in addition to Go's five.
pub(crate) async fn perimeter(State(s): State<SharedState>, Path(id): Path<String>) -> Response {
    if s.mgr.sandbox(&id).is_none() {
        return error(StatusCode::NOT_FOUND, "sandbox not found");
    }
    let decisions = runeward_egress::list_decisions(&id);
    json(StatusCode::OK, &json!({"decisions": decisions}))
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct SnapshotRequest {
    name: String,
}

pub(crate) async fn snapshot(
    State(s): State<SharedState>,
    Path(id): Path<String>,
    body: Body,
) -> Response {
    let req: SnapshotRequest = match decode_optional(body).await {
        Ok(r) => r,
        Err(e) => return e.into_response(),
    };
    match s.mgr.snapshot(&id, &req.name).await {
        Ok(r) => json(StatusCode::CREATED, &r),
        Err(e) => error(StatusCode::BAD_REQUEST, e.to_string()),
    }
}

pub(crate) async fn list_snapshots(State(s): State<SharedState>, caller: Caller) -> Response {
    let mut snaps = s.mgr.list_snapshots();
    if let Some(p) = caller.scoped() {
        snaps.retain(|snap| {
            s.mgr
                .snapshot_owner(&snap.id)
                .is_some_and(|o| o == p.tenant_id())
        });
    }
    json(StatusCode::OK, &json!({"snapshots": snaps}))
}

pub(crate) async fn restore_snapshot(
    State(s): State<SharedState>,
    caller: Caller,
    Path(id): Path<String>,
) -> Response {
    if let Some(p) = caller.get() {
        if !p.admin && !s.snapshot_visible_to(p, &id) {
            return error(StatusCode::NOT_FOUND, "snapshot not found");
        }
        if s.mgr
            .snapshot_ref(&id)
            .is_none_or(|r| !p.can_launch(&r.profile))
        {
            return error(StatusCode::NOT_FOUND, "snapshot not found");
        }
    }
    let (owner, actor) = caller.identity();
    match s
        .mgr
        .restore_snapshot_for_identity(&id, &owner, &actor)
        .await
    {
        Ok(sb) => json(StatusCode::CREATED, &sandbox_view(&sb, &owner)),
        Err(e) => error(StatusCode::BAD_REQUEST, e.to_string()),
    }
}

/// Streams a point-in-time tar of the workspace. Failures after the
/// headers are sent are logged (the archive is cut short).
pub(crate) async fn workspace_export(
    State(s): State<SharedState>,
    caller: Caller,
    Path(id): Path<String>,
) -> Response {
    if s.mgr.sandbox(&id).is_none() {
        return error(StatusCode::NOT_FOUND, "sandbox not found");
    }
    let (mut writer, reader) = tokio::io::duplex(64 << 10);
    let mgr = Arc::clone(&s.mgr);
    let actor = caller.get().map(|p| p.name.clone()).unwrap_or_default();
    let sid = id.clone();
    tokio::spawn(async move {
        let export = async {
            if let Err(e) = mgr.export_workspace(&sid, &mut writer).await {
                tracing::error!(sandbox = %sid, error = %e, "workspace export failed");
            }
        };
        with_actor(&actor, export).await;
    });
    let body = Body::from_stream(stream::unfold(reader, |mut r| async move {
        let mut buf = vec![0u8; 32 << 10];
        match r.read(&mut buf).await {
            Ok(0) | Err(_) => None,
            Ok(n) => {
                buf.truncate(n);
                Some((Ok::<_, std::io::Error>(bytes::Bytes::from(buf)), r))
            }
        }
    }));
    let mut resp = body.into_response();
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/x-tar"),
    );
    if let Ok(v) = HeaderValue::from_str(&format!(
        "attachment; filename=runeward-workspace-{}.tar",
        safe_filename(&id)
    )) {
        h.insert(header::CONTENT_DISPOSITION, v);
    }
    resp
}

/// A portable, signed evidence document for the Citadel.
pub(crate) async fn evidence_export(
    State(s): State<SharedState>,
    Path(id): Path<String>,
) -> Response {
    let doc = match s.mgr.evidence(&id, &s.version).await {
        Ok(d) => d,
        Err(e) => return error(StatusCode::BAD_REQUEST, e.to_string()),
    };
    let mut body = Vec::new();
    if let Err(e) = runeward_ledger::evidence::write(&mut body, &doc) {
        tracing::error!(sandbox = %id, error = %e, "evidence export failed");
    }
    let mut resp = body.into_response();
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    if let Ok(v) = HeaderValue::from_str(&format!(
        "attachment; filename=runeward-evidence-{}.json",
        safe_filename(&id)
    )) {
        h.insert(header::CONTENT_DISPOSITION, v);
    }
    resp
}
