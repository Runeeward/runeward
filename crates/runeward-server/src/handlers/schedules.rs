//! Scheduled agent runs for Cohorts and Citadels.

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use runeward_controlplane::{Schedule, ScheduleSpec};
use serde::Deserialize;
use serde_json::json;

use crate::respond::{decode, error, json, server_error};
use crate::state::{Caller, SharedState};

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct CreateRequest {
    cron: String,
    every: String,
    command: Vec<String>,
    prompt: String,
    agent: String,
    model: String,
    precheck: Vec<String>,
}

impl CreateRequest {
    fn spec(self, cohort_id: String, citadel_id: String) -> ScheduleSpec {
        ScheduleSpec {
            cohort_id,
            citadel_id,
            cron: self.cron,
            every: self.every,
            command: self.command,
            prompt: self.prompt,
            agent: self.agent,
            model: self.model,
            precheck: self.precheck,
        }
    }
}

fn visible(caller: &Caller, s: &Schedule) -> bool {
    caller.scoped().is_none_or(|p| s.owner == p.tenant_id())
}

async fn create(s: SharedState, spec: ScheduleSpec) -> Response {
    match s.mgr.create_schedule(spec).await {
        Ok(sched) => json(StatusCode::CREATED, &sched),
        Err(e) => server_error(&e),
    }
}

async fn decode_create(body: Body) -> Result<CreateRequest, Response> {
    decode(body).await.map_err(|e| e.into_response())
}

/// Schedules a run on a Citadel.
pub(crate) async fn create_for_citadel(
    State(s): State<SharedState>,
    Path(id): Path<String>,
    body: Body,
) -> Response {
    match decode_create(body).await {
        Ok(req) => create(s, req.spec(String::new(), id)).await,
        Err(resp) => resp,
    }
}

/// Schedules a run on a Cohort (it fires in the first member Citadel).
pub(crate) async fn create_for_cohort(
    State(s): State<SharedState>,
    Path(id): Path<String>,
    body: Body,
) -> Response {
    match decode_create(body).await {
        Ok(req) => create(s, req.spec(id, String::new())).await,
        Err(resp) => resp,
    }
}

/// A Citadel's schedules.
pub(crate) async fn list_for_citadel(
    State(s): State<SharedState>,
    Path(id): Path<String>,
) -> Response {
    json(
        StatusCode::OK,
        &json!({"schedules": s.mgr.schedules_for("", &id)}),
    )
}

/// A Cohort's schedules.
pub(crate) async fn list_for_cohort(
    State(s): State<SharedState>,
    Path(id): Path<String>,
) -> Response {
    json(
        StatusCode::OK,
        &json!({"schedules": s.mgr.schedules_for(&id, "")}),
    )
}

/// Every schedule the caller may see.
pub(crate) async fn list(State(s): State<SharedState>, caller: Caller) -> Response {
    let mut all = s.mgr.list_schedules();
    all.retain(|sched| visible(&caller, sched));
    json(StatusCode::OK, &json!({"schedules": all}))
}

fn find(s: &SharedState, caller: &Caller, id: &str) -> Result<Schedule, Response> {
    match s.mgr.schedule(id) {
        Some(sched) if visible(caller, &sched) => Ok(sched),
        _ => Err(error(StatusCode::NOT_FOUND, "schedule not found")),
    }
}

/// One schedule.
pub(crate) async fn get(
    State(s): State<SharedState>,
    caller: Caller,
    Path(id): Path<String>,
) -> Response {
    match find(&s, &caller, &id) {
        Ok(sched) => json(StatusCode::OK, &sched),
        Err(resp) => resp,
    }
}

/// Removes a schedule.
pub(crate) async fn delete(
    State(s): State<SharedState>,
    caller: Caller,
    Path(id): Path<String>,
) -> Response {
    if let Err(resp) = find(&s, &caller, &id) {
        return resp;
    }
    match s.mgr.delete_schedule(&id).await {
        Ok(_) => json(StatusCode::OK, &json!({"ok": true})),
        Err(e) => server_error(&e),
    }
}

/// Fires a schedule now (policy, precheck and budgets still apply).
pub(crate) async fn run(
    State(s): State<SharedState>,
    caller: Caller,
    Path(id): Path<String>,
) -> Response {
    if let Err(resp) = find(&s, &caller, &id) {
        return resp;
    }
    match s.mgr.run_schedule_now(&id).await {
        Ok(f) => json(StatusCode::OK, &f),
        Err(e) => server_error(&e),
    }
}
