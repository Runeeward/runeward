//! Governed tool calls. Every call goes through the Manager's governed
//! path (policy, approval, guardrails, Chronicle).

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use runeward_browser::Command;
use runeward_charter::Verdict;
use serde::Deserialize;
use serde_json::json;

use super::{tool_result, unless_blocked};
use crate::respond::{
    decode, decode_bytes, error, json, read_body, reject_unknown_fields, server_error,
};
use crate::state::SharedState;

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct ShellRequest {
    command: Vec<String>,
    workdir: String,
}

pub(crate) async fn shell(
    State(s): State<SharedState>,
    Path(id): Path<String>,
    body: Body,
) -> Response {
    match decode::<ShellRequest>(body).await {
        Ok(r) => tool_result(s.mgr.shell(&id, &r.command, &r.workdir).await),
        Err(e) => e.into_response(),
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct BrowserRequest {
    url: String,
    mode: String,
}

pub(crate) async fn browser(
    State(s): State<SharedState>,
    Path(id): Path<String>,
    body: Body,
) -> Response {
    match decode::<BrowserRequest>(body).await {
        Ok(r) => tool_result(s.mgr.browser(&id, &r.url, &r.mode).await),
        Err(e) => e.into_response(),
    }
}

pub(crate) async fn browser_open(State(s): State<SharedState>, Path(id): Path<String>) -> Response {
    match s.mgr.browser_open(&id).await {
        Err(e) => server_error(&e),
        Ok((sid, res)) if res.verdict != Verdict::Allow || sid.is_none() => tool_result(Ok(res)),
        Ok((sid, _)) => json(StatusCode::CREATED, &json!({"session_id": sid})),
    }
}

const COMMAND_FIELDS: &[&str] = &[
    "action",
    "token",
    "url",
    "selector",
    "expr",
    "text",
    "timeout_ms",
];

pub(crate) async fn browser_act(
    State(s): State<SharedState>,
    Path((id, sid)): Path<(String, String)>,
    body: Body,
) -> Response {
    let cmd = match read_body(body).await.and_then(|b| {
        reject_unknown_fields(&b, COMMAND_FIELDS)?;
        decode_bytes::<Command>(&b)
    }) {
        Ok(c) => c,
        Err(e) => return e.into_response(),
    };
    tool_result(s.mgr.browser_act(&id, &sid, cmd).await)
}

pub(crate) async fn browser_close(
    State(s): State<SharedState>,
    Path((id, sid)): Path<(String, String)>,
) -> Response {
    match s.mgr.browser_close(&id, &sid).await {
        Ok(()) => json(StatusCode::OK, &json!({"ok": true})),
        Err(e) => error(StatusCode::NOT_FOUND, e.to_string()),
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct CodeRequest {
    code: String,
}

pub(crate) async fn python(
    State(s): State<SharedState>,
    Path(id): Path<String>,
    body: Body,
) -> Response {
    match decode::<CodeRequest>(body).await {
        Ok(r) => tool_result(s.mgr.python(&id, &r.code).await),
        Err(e) => e.into_response(),
    }
}

pub(crate) async fn node(
    State(s): State<SharedState>,
    Path(id): Path<String>,
    body: Body,
) -> Response {
    match decode::<CodeRequest>(body).await {
        Ok(r) => tool_result(s.mgr.node(&id, &r.code).await),
        Err(e) => e.into_response(),
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct PathRequest {
    path: String,
}

pub(crate) async fn file_read(
    State(s): State<SharedState>,
    Path(id): Path<String>,
    body: Body,
) -> Response {
    let req: PathRequest = match decode(body).await {
        Ok(r) => r,
        Err(e) => return e.into_response(),
    };
    match unless_blocked(s.mgr.file_read(&id, &req.path).await) {
        Ok(r) => json(
            StatusCode::OK,
            &json!({"content": r.stdout, "verdict": r.verdict}),
        ),
        Err(resp) => resp,
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct WriteRequest {
    path: String,
    content: String,
}

pub(crate) async fn file_write(
    State(s): State<SharedState>,
    Path(id): Path<String>,
    body: Body,
) -> Response {
    let req: WriteRequest = match decode(body).await {
        Ok(r) => r,
        Err(e) => return e.into_response(),
    };
    match unless_blocked(s.mgr.file_write(&id, &req.path, &req.content).await) {
        Ok(r) => json(
            StatusCode::OK,
            &json!({"bytes": req.content.len(), "verdict": r.verdict}),
        ),
        Err(resp) => resp,
    }
}

pub(crate) async fn file_list(
    State(s): State<SharedState>,
    Path(id): Path<String>,
    body: Body,
) -> Response {
    let req: PathRequest = match decode(body).await {
        Ok(r) => r,
        Err(e) => return e.into_response(),
    };
    match unless_blocked(s.mgr.file_list(&id, &req.path).await) {
        Ok(r) => json(
            StatusCode::OK,
            &json!({"output": r.stdout, "verdict": r.verdict}),
        ),
        Err(resp) => resp,
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct SearchRequest {
    query: String,
    path: String,
}

pub(crate) async fn file_search(
    State(s): State<SharedState>,
    Path(id): Path<String>,
    body: Body,
) -> Response {
    let req: SearchRequest = match decode(body).await {
        Ok(r) => r,
        Err(e) => return e.into_response(),
    };
    match unless_blocked(s.mgr.file_search(&id, &req.query, &req.path).await) {
        Ok(r) => json(
            StatusCode::OK,
            &json!({"output": r.stdout, "verdict": r.verdict}),
        ),
        Err(resp) => resp,
    }
}
