//! Durable agent sessions: start, list, transcript and the SSE stream.

use std::time::Duration;

use axum::body::Body;
use axum::extract::{Path, Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use futures_util::stream;
use runeward_controlplane::{
    AgentEvent, AgentSession, AgentSubscription, StartAgentSessionOptions,
};
use serde::Deserialize;
use serde_json::json;
use tokio::time::{Interval, MissedTickBehavior};

use crate::auth::query_get;
use crate::respond::{decode, error, json};
use crate::state::{Caller, SharedState};

const KEEPALIVE: Duration = Duration::from_secs(15);

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct StartRequest {
    command: Vec<String>,
    agent: String,
    model: String,
    cohort_id: String,
    task_id: String,
}

pub(crate) async fn start(
    State(s): State<SharedState>,
    Path(id): Path<String>,
    body: Body,
) -> Response {
    let req: StartRequest = match decode(body).await {
        Ok(r) => r,
        Err(e) => return e.into_response(),
    };
    let opts = StartAgentSessionOptions {
        command: req.command,
        agent: req.agent,
        model: req.model,
        cohort_id: req.cohort_id,
        task_id: req.task_id,
    };
    match s.mgr.start_agent_session(&id, opts).await {
        Ok(a) => json(StatusCode::ACCEPTED, &a),
        Err(e) => error(StatusCode::BAD_REQUEST, e.to_string()),
    }
}

fn visible(caller: &Caller, a: &AgentSession) -> bool {
    caller.scoped().is_none_or(|p| a.tenant == p.tenant_id())
}

pub(crate) async fn list(State(s): State<SharedState>, caller: Caller, req: Request) -> Response {
    let cohort = query_get(req.uri(), "cohort_id");
    let mut sessions = s.mgr.agent_sessions(cohort.trim());
    sessions.retain(|a| visible(&caller, a));
    json(StatusCode::OK, &json!({"sessions": sessions}))
}

pub(crate) async fn get(
    State(s): State<SharedState>,
    caller: Caller,
    Path(id): Path<String>,
) -> Response {
    match s.mgr.agent_session(&id) {
        Some(a) if visible(&caller, &a) => json(StatusCode::OK, &a),
        _ => error(StatusCode::NOT_FOUND, "agent session not found"),
    }
}

fn cursor(req: &Request) -> Result<i64, Response> {
    let raw = query_get(req.uri(), "after");
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(0);
    }
    raw.parse::<i64>().ok().filter(|n| *n >= 0).ok_or_else(|| {
        error(
            StatusCode::BAD_REQUEST,
            "after must be a non-negative event sequence",
        )
    })
}

pub(crate) async fn events(
    State(s): State<SharedState>,
    caller: Caller,
    Path(id): Path<String>,
    req: Request,
) -> Response {
    let after = match cursor(&req) {
        Ok(a) => a,
        Err(resp) => return resp,
    };
    match s.mgr.agent_session_events(&id, after).await {
        Some((a, events)) if visible(&caller, &a) => {
            json(StatusCode::OK, &json!({"session": a, "events": events}))
        }
        _ => error(StatusCode::NOT_FOUND, "agent session not found"),
    }
}

fn sse_frame(ev: &AgentEvent) -> Bytes {
    let data = runeward_ledger::gojson::marshal(ev).unwrap_or_default();
    let mut out = format!("id: {}\nevent: agent-output\ndata: ", ev.seq).into_bytes();
    out.extend_from_slice(&data);
    out.extend_from_slice(b"\n\n");
    Bytes::from(out)
}

struct StreamState {
    sub: AgentSubscription,
    keepalive: Interval,
}

/// Server-sent events: the backlog after the cursor (or `Last-Event-ID`),
/// then live output until the session ends, with a keepalive comment every
/// 15 seconds.
pub(crate) async fn stream(
    State(s): State<SharedState>,
    caller: Caller,
    Path(id): Path<String>,
    req: Request,
) -> Response {
    let mut after = match cursor(&req) {
        Ok(a) => a,
        Err(resp) => return resp,
    };
    if let Some(last) = req
        .headers()
        .get("last-event-id")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<i64>().ok())
        && last > after
    {
        after = last;
    }
    let sub = match s.mgr.subscribe_agent_session(&id, after).await {
        Some(sub) if visible(&caller, &sub.session) => sub,
        _ => return error(StatusCode::NOT_FOUND, "agent session not found"),
    };
    let mut backlog: Vec<u8> = Vec::new();
    for ev in &sub.backlog {
        backlog.extend_from_slice(&sse_frame(ev));
    }
    let mut keepalive =
        tokio::time::interval_at(tokio::time::Instant::now() + KEEPALIVE, KEEPALIVE);
    keepalive.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let live = stream::unfold(StreamState { sub, keepalive }, |mut st| async move {
        let chunk = tokio::select! {
            ev = st.sub.recv() => sse_frame(&ev?),
            _ = st.keepalive.tick() => Bytes::from_static(b": keepalive\n\n"),
        };
        Some((Ok::<_, std::io::Error>(chunk), st))
    });
    let first = stream::iter([Ok::<_, std::io::Error>(Bytes::from(backlog))]);
    let mut resp = Body::from_stream(futures_util::StreamExt::chain(first, live)).into_response();
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/event-stream"),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    h.insert("x-accel-buffering", HeaderValue::from_static("no"));
    resp
}
