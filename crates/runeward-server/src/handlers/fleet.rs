//! Cohorts and their task boards.

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use runeward_controlplane::Error;
use runeward_fleet::FleetError;
use serde::Deserialize;
use serde_json::json;

use crate::respond::{decode, decode_optional, error, json};
use crate::state::{Caller, SharedState};

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct CreateRequest {
    profile: String,
}

pub(crate) async fn create(State(s): State<SharedState>, caller: Caller, body: Body) -> Response {
    let req: CreateRequest = match decode(body).await {
        Ok(r) => r,
        Err(e) => return e.into_response(),
    };
    if req.profile.is_empty() {
        return error(StatusCode::BAD_REQUEST, "profile is required");
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
    match s
        .mgr
        .create_fleet_for_identity(&req.profile, &owner, &actor)
        .await
    {
        Ok(v) => json(StatusCode::CREATED, &v),
        Err(e) => error(StatusCode::BAD_REQUEST, e.to_string()),
    }
}

pub(crate) async fn list(State(s): State<SharedState>, caller: Caller) -> Response {
    let mut fleets = s.mgr.list_fleets();
    if let Some(p) = caller.scoped() {
        fleets.retain(|v| s.fleet_owned_by(&v.id, p.tenant_id()));
    }
    json(StatusCode::OK, &json!({"fleets": fleets}))
}

pub(crate) async fn get(State(s): State<SharedState>, Path(id): Path<String>) -> Response {
    match s.mgr.fleet_view(&id) {
        Some(v) => json(StatusCode::OK, &v),
        None => error(StatusCode::NOT_FOUND, "fleet not found"),
    }
}

pub(crate) async fn kill(State(s): State<SharedState>, Path(id): Path<String>) -> Response {
    match s.mgr.kill_fleet(&id).await {
        Ok(()) => json(StatusCode::OK, &json!({"ok": true})),
        Err(e) => error(StatusCode::NOT_FOUND, e.to_string()),
    }
}

pub(crate) async fn list_tasks(State(s): State<SharedState>, Path(id): Path<String>) -> Response {
    match s.mgr.list_tasks(&id) {
        Ok(tasks) => json(StatusCode::OK, &json!({"tasks": tasks})),
        Err(e) => error(StatusCode::NOT_FOUND, e.to_string()),
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct AddTaskRequest {
    payload: String,
}

pub(crate) async fn add_task(
    State(s): State<SharedState>,
    Path(id): Path<String>,
    body: Body,
) -> Response {
    let req: AddTaskRequest = match decode(body).await {
        Ok(r) => r,
        Err(e) => return e.into_response(),
    };
    match s.mgr.add_task(&id, &req.payload).await {
        Ok(t) => json(StatusCode::CREATED, &t),
        Err(e) => error(StatusCode::NOT_FOUND, e.to_string()),
    }
}

/// The worker a task operation acts as: the authenticated principal under
/// RBAC (callers cannot impersonate), else the `owner` they name.
pub(crate) fn task_owner(caller: &Caller, requested: &str) -> Result<String, &'static str> {
    if let Some(p) = caller.get() {
        if p.name.trim().is_empty() {
            return Err("authenticated principal name is empty");
        }
        return Ok(p.name.clone());
    }
    let owner = requested.trim();
    if owner.is_empty() {
        return Err("owner is required");
    }
    Ok(owner.to_owned())
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct ClaimRequest {
    owner: String,
}

pub(crate) async fn claim(
    State(s): State<SharedState>,
    caller: Caller,
    Path(id): Path<String>,
    body: Body,
) -> Response {
    let req: ClaimRequest = match decode_optional(body).await {
        Ok(r) => r,
        Err(e) => return e.into_response(),
    };
    let owner = match task_owner(&caller, &req.owner) {
        Ok(o) => o,
        Err(e) => return error(StatusCode::BAD_REQUEST, e),
    };
    match s.mgr.claim_task(&id, &owner).await {
        Err(e) => error(StatusCode::NOT_FOUND, e.to_string()),
        Ok(None) => json(StatusCode::OK, &json!({"claimed": false})),
        Ok(Some(t)) => json(StatusCode::OK, &json!({"claimed": true, "task": t})),
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct CompleteRequest {
    owner: String,
    lease_token: String,
    result: String,
}

pub(crate) async fn complete(
    State(s): State<SharedState>,
    caller: Caller,
    Path((id, task_id)): Path<(String, String)>,
    body: Body,
) -> Response {
    let req: CompleteRequest = match decode_optional(body).await {
        Ok(r) => r,
        Err(e) => return e.into_response(),
    };
    let owner = match task_owner(&caller, &req.owner) {
        Ok(o) => o,
        Err(e) => return error(StatusCode::BAD_REQUEST, e),
    };
    match s
        .mgr
        .complete_task(&id, &task_id, &owner, &req.lease_token, &req.result)
        .await
    {
        Ok(()) => json(StatusCode::OK, &json!({"ok": true})),
        Err(e) => task_error(&e),
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct HeartbeatRequest {
    owner: String,
    lease_token: String,
}

pub(crate) async fn heartbeat(
    State(s): State<SharedState>,
    caller: Caller,
    Path((id, task_id)): Path<(String, String)>,
    body: Body,
) -> Response {
    let req: HeartbeatRequest = match decode_optional(body).await {
        Ok(r) => r,
        Err(e) => return e.into_response(),
    };
    let owner = match task_owner(&caller, &req.owner) {
        Ok(o) => o,
        Err(e) => return error(StatusCode::BAD_REQUEST, e),
    };
    match s
        .mgr
        .heartbeat_task(&id, &task_id, &owner, &req.lease_token)
        .await
    {
        Ok(t) => json(StatusCode::OK, &json!({"ok": true, "task": t})),
        Err(e) => task_error(&e),
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct FailRequest {
    owner: String,
    lease_token: String,
    error: String,
    requeue: bool,
}

pub(crate) async fn fail(
    State(s): State<SharedState>,
    caller: Caller,
    Path((id, task_id)): Path<(String, String)>,
    body: Body,
) -> Response {
    let req: FailRequest = match decode_optional(body).await {
        Ok(r) => r,
        Err(e) => return e.into_response(),
    };
    let owner = match task_owner(&caller, &req.owner) {
        Ok(o) => o,
        Err(e) => return error(StatusCode::BAD_REQUEST, e),
    };
    match s
        .mgr
        .fail_task(
            &id,
            &task_id,
            &owner,
            &req.lease_token,
            &req.error,
            req.requeue,
        )
        .await
    {
        Ok(()) => json(StatusCode::OK, &json!({"ok": true})),
        Err(e) => task_error(&e),
    }
}

/// Board errors: unknown task 404, illegal transition 409, bad lease 401,
/// anything else (including an unknown Cohort) 400.
fn task_error(e: &Error) -> Response {
    let status = match e {
        Error::Task(FleetError::NotFound(_)) => StatusCode::NOT_FOUND,
        Error::Task(FleetError::IllegalTransition(_)) => StatusCode::CONFLICT,
        Error::InvalidLease => StatusCode::UNAUTHORIZED,
        _ => StatusCode::BAD_REQUEST,
    };
    error(status, e.to_string())
}
