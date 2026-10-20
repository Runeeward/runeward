//! A Citadel's live conversation feed: publish, history and a read-only
//! WebSocket for observers.

use axum::body::Body;
use axum::extract::ws::{
    CloseFrame, Message, WebSocket, WebSocketUpgrade, rejection::WebSocketUpgradeRejection,
};
use axum::extract::{Path, Request, State};
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::Response;
use futures_util::{SinkExt, StreamExt};
use runeward_controlplane::ConversationSubscription;
use serde::Deserialize;
use serde_json::json;

use super::terminal::{check_ws_origin, ws_rejection};
use crate::auth::query_get;
use crate::respond::{decode, error, json, server_error};
use crate::state::SharedState;

/// WebSocket close codes.
const CLOSE_NORMAL: u16 = 1000;
const CLOSE_POLICY_VIOLATION: u16 = 1008;
const CLOSE_INTERNAL_ERROR: u16 = 1011;

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct PublishRequest {
    role: String,
    content: String,
    run_id: String,
}

pub(crate) async fn publish(
    State(s): State<SharedState>,
    Path(id): Path<String>,
    body: Body,
) -> Response {
    let req: PublishRequest = match decode(body).await {
        Ok(r) => r,
        Err(e) => return e.into_response(),
    };
    match s
        .mgr
        .publish_conversation(&id, &req.role, &req.content, &req.run_id)
        .await
    {
        Ok(msg) => json(StatusCode::CREATED, &msg),
        Err(e) => server_error(&e),
    }
}

pub(crate) async fn history(
    State(s): State<SharedState>,
    Path(id): Path<String>,
    req: Request,
) -> Response {
    let raw = query_get(req.uri(), "after_id");
    let after = match raw.trim() {
        "" => 0,
        v => match v.parse::<u64>() {
            Ok(n) => n,
            Err(_) => {
                return error(
                    StatusCode::BAD_REQUEST,
                    "after_id must be an unsigned integer",
                );
            }
        },
    };
    let raw = query_get(req.uri(), "limit");
    let limit = match raw.trim() {
        "" => 500,
        v => match v.parse::<i64>() {
            Ok(n) if (1..=500).contains(&n) => usize::try_from(n).unwrap_or(500),
            _ => return error(StatusCode::BAD_REQUEST, "limit must be between 1 and 500"),
        },
    };
    match s.mgr.conversation_history(&id, after, limit) {
        Ok(messages) => json(StatusCode::OK, &json!({"messages": messages})),
        Err(e) => server_error(&e),
    }
}

fn close(code: u16, reason: &'static str) -> Message {
    Message::Close(Some(CloseFrame {
        code,
        reason: reason.into(),
    }))
}

/// A read-only WebSocket. It subscribes before reading history so a turn
/// published during setup is not lost; message ids de-duplicate the
/// overlap. Any data from the client ends the stream.
pub(crate) async fn stream(
    State(s): State<SharedState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    uri: Uri,
    ws: Result<WebSocketUpgrade, WebSocketUpgradeRejection>,
) -> Response {
    let live = match s.mgr.subscribe_conversation(&id) {
        Ok(l) => l,
        Err(e) => return server_error(&e),
    };
    let ws = match ws {
        Ok(ws) => ws,
        Err(r) => return ws_rejection(&r),
    };
    if let Err(resp) = check_ws_origin(&headers, &uri) {
        return resp;
    }
    ws.on_upgrade(move |socket| run_stream(s, id, live, socket))
}

async fn run_stream(
    s: SharedState,
    id: String,
    mut live: ConversationSubscription,
    socket: WebSocket,
) {
    let (mut tx, mut rx) = socket.split();
    let Ok(history) = s.mgr.conversation_history(&id, 0, 500) else {
        let _ = tx
            .send(close(CLOSE_INTERNAL_ERROR, "history unavailable"))
            .await;
        return;
    };
    let mut last_id = 0;
    for msg in history {
        let Ok(payload) = serde_json::to_string(&msg) else {
            return;
        };
        if tx.send(Message::Text(payload.into())).await.is_err() {
            return;
        }
        last_id = msg.id;
    }
    loop {
        tokio::select! {
            incoming = rx.next() => match incoming {
                None | Some(Err(_)) | Some(Ok(Message::Close(_))) => return,
                Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
                Some(Ok(_)) => {
                    // Observer-only: application data never reaches an agent.
                    let _ = tx.send(close(CLOSE_POLICY_VIOLATION, "read-only stream")).await;
                    return;
                }
            },
            msg = live.recv() => {
                let Some(msg) = msg else {
                    let _ = tx.send(close(CLOSE_NORMAL, "citadel ended")).await;
                    return;
                };
                if msg.id <= last_id {
                    continue;
                }
                let Ok(payload) = serde_json::to_string(&msg) else { return };
                if tx.send(Message::Text(payload.into())).await.is_err() {
                    return;
                }
                last_id = msg.id;
            }
        }
    }
}
