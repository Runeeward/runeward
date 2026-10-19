//! Cohorts and their task boards.

use axum::body::Body;
use axum::extract::{Path, Request, State};
use axum::http::StatusCode;
use axum::response::Response;
use runeward_controlplane::{Error, MemoryPut, MemoryQuery};
use runeward_fleet::FleetError;
use serde::Deserialize;
use serde_json::json;

use crate::auth::query_get;
use crate::respond::{decode, decode_optional, error, json, server_error};
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
    /// Also return the task's handoff notes, brief, parent and a ranked
    /// slice of the Cohort's shared memory.
    context: bool,
    /// Byte budget of the memory slice (default 8 KiB).
    memory_bytes: usize,
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
    if req.context {
        return match s
            .mgr
            .claim_task_with_context(&id, &owner, req.memory_bytes)
            .await
        {
            Err(e) => error(StatusCode::NOT_FOUND, e.to_string()),
            Ok(None) => json(StatusCode::OK, &json!({"claimed": false})),
            Ok(Some(c)) => json(
                StatusCode::OK,
                &json!({"claimed": true, "task": c.task, "context": c.context}),
            ),
        };
    }
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
    /// A note for whoever picks up the follow-up work.
    handoff: String,
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
        .complete_task_with_handoff(
            &id,
            &task_id,
            &owner,
            &req.lease_token,
            &req.result,
            &req.handoff,
        )
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
    /// A note for the next claimant (with `requeue`).
    handoff: String,
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
        .fail_task_with_handoff(
            &id,
            &task_id,
            &owner,
            &req.lease_token,
            &req.error,
            req.requeue,
            &req.handoff,
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

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct ChildRequest {
    payload: String,
}

/// Splits a task: adds a pending child linked to it.
pub(crate) async fn add_child(
    State(s): State<SharedState>,
    Path((id, task_id)): Path<(String, String)>,
    body: Body,
) -> Response {
    let req: ChildRequest = match decode(body).await {
        Ok(r) => r,
        Err(e) => return e.into_response(),
    };
    match s.mgr.add_child_task(&id, &task_id, &req.payload).await {
        Ok(t) => json(StatusCode::CREATED, &t),
        Err(e) => task_error(&e),
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct NoteRequest {
    text: String,
}

/// Adds a handoff note from the caller to a task.
pub(crate) async fn add_note(
    State(s): State<SharedState>,
    Path((id, task_id)): Path<(String, String)>,
    body: Body,
) -> Response {
    let req: NoteRequest = match decode(body).await {
        Ok(r) => r,
        Err(e) => return e.into_response(),
    };
    match s.mgr.add_task_note(&id, &task_id, &req.text).await {
        Ok(t) => json(StatusCode::CREATED, &t),
        Err(e) => task_error(&e),
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct BriefRequest {
    agent: String,
    brief: String,
}

/// Sets (or with an empty brief clears) the brief for an agent (`*`: every
/// agent) on a task.
pub(crate) async fn set_brief(
    State(s): State<SharedState>,
    Path((id, task_id)): Path<(String, String)>,
    body: Body,
) -> Response {
    let req: BriefRequest = match decode(body).await {
        Ok(r) => r,
        Err(e) => return e.into_response(),
    };
    match s
        .mgr
        .set_task_brief(&id, &task_id, &req.agent, &req.brief)
        .await
    {
        Ok(t) => json(StatusCode::OK, &t),
        Err(e) => task_error(&e),
    }
}

/// The context for working on a task (`?agent=` picks the brief, default
/// the caller).
pub(crate) async fn task_context(
    State(s): State<SharedState>,
    caller: Caller,
    Path((id, task_id)): Path<(String, String)>,
    req: Request,
) -> Response {
    let Some(task) = s
        .mgr
        .list_tasks(&id)
        .ok()
        .and_then(|ts| ts.into_iter().find(|t| t.id == task_id))
    else {
        return error(StatusCode::NOT_FOUND, "task not found");
    };
    let mut agent = query_get(req.uri(), "agent");
    if agent.trim().is_empty() {
        agent = caller.identity().1;
    }
    let bytes = query_get(req.uri(), "memory_bytes")
        .trim()
        .parse::<usize>()
        .unwrap_or(0);
    drop(req);
    match s.mgr.task_context(&id, &task, agent.trim(), bytes).await {
        Ok(c) => json(StatusCode::OK, &json!({"task": task, "context": c})),
        Err(e) => server_error(&e),
    }
}

/// Lists (no query) or searches (`query`, comma-separated `tags`,
/// `limit`, `max_bytes`) a Cohort's shared memory.
pub(crate) async fn memory_list(
    State(s): State<SharedState>,
    Path(id): Path<String>,
    req: Request,
) -> Response {
    let q = memory_query(req.uri());
    let res = match q {
        None => s.mgr.memory_list(&id).await,
        Some(q) => s.mgr.memory_search(&id, &q).await,
    };
    match res {
        Ok(entries) => json(StatusCode::OK, &json!({"entries": entries})),
        Err(e) => server_error(&e),
    }
}

/// The search in a memory listing's query string; `None` lists all.
fn memory_query(uri: &axum::http::Uri) -> Option<MemoryQuery> {
    let query = query_get(uri, "query");
    let tags: Vec<String> = query_get(uri, "tags")
        .split(',')
        .map(|t| t.trim().to_owned())
        .filter(|t| !t.is_empty())
        .collect();
    if query.trim().is_empty() && tags.is_empty() {
        return None;
    }
    let num = |k: &str| query_get(uri, k).trim().parse::<usize>().unwrap_or(0);
    Some(MemoryQuery {
        query,
        tags,
        limit: num("limit"),
        max_bytes: num("max_bytes"),
    })
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct MemoryRequest {
    key: String,
    text: String,
    tags: Vec<String>,
    /// `0`: the key must be new; `n`: the current version must be `n`.
    expected_version: Option<u64>,
}

/// Writes a shared memory entry (409 `version_conflict` on a stale
/// `expected_version`).
pub(crate) async fn memory_put(
    State(s): State<SharedState>,
    Path(id): Path<String>,
    body: Body,
) -> Response {
    let req: MemoryRequest = match decode(body).await {
        Ok(r) => r,
        Err(e) => return e.into_response(),
    };
    let put = MemoryPut {
        key: req.key,
        text: req.text,
        tags: req.tags,
        expected_version: req.expected_version,
    };
    match s.mgr.memory_put(&id, put).await {
        Ok(e) => json(StatusCode::OK, &e),
        Err(e) => server_error(&e),
    }
}

/// One memory entry.
pub(crate) async fn memory_get(
    State(s): State<SharedState>,
    Path((id, key)): Path<(String, String)>,
) -> Response {
    match s.mgr.memory_get(&id, &key).await {
        Ok(Some(e)) => json(StatusCode::OK, &e),
        Ok(None) => error(StatusCode::NOT_FOUND, "memory entry not found"),
        Err(e) => server_error(&e),
    }
}

/// Deletes a memory entry (`?version=` makes it conditional).
pub(crate) async fn memory_delete(
    State(s): State<SharedState>,
    Path((id, key)): Path<(String, String)>,
    req: Request,
) -> Response {
    let raw = query_get(req.uri(), "version");
    drop(req);
    let version = match raw.trim() {
        "" => None,
        v => match v.parse::<u64>() {
            Ok(n) => Some(n),
            Err(_) => return error(StatusCode::BAD_REQUEST, "version must be a number"),
        },
    };
    match s.mgr.memory_delete(&id, &key, version).await {
        Ok(deleted) => json(StatusCode::OK, &json!({"deleted": deleted})),
        Err(e) => server_error(&e),
    }
}
