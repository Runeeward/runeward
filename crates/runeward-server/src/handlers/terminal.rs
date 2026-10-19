//! The interactive terminal: a WebSocket bridged to a sandbox PTY, with
//! optional asciinema recording.

use std::io;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use axum::extract::ws::rejection::WebSocketUpgradeRejection;
use axum::extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use futures_util::{SinkExt, StreamExt};
use runeward_backend::{PtyStream, TermSize};
use runeward_controlplane::with_actor;
use runeward_termrec::Recorder;
use serde::Deserialize;
use serde_json::json;
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;

use super::rfc3339;
use crate::auth::{host_of, same_origin};
use crate::respond::{error, json, server_error, text};
use crate::state::{Caller, SharedState, TicketKind, TicketScope};

const TERMINAL_TICKET_TTL: Duration = Duration::from_secs(30);

pub(crate) async fn ticket(
    State(s): State<SharedState>,
    caller: Caller,
    Path(id): Path<String>,
) -> Response {
    match s.issue_ticket(
        TicketScope::sandbox(TicketKind::Terminal, &id),
        caller.0.clone(),
        TERMINAL_TICKET_TTL,
    ) {
        Ok((ticket, expires_at)) => json(
            StatusCode::CREATED,
            &json!({"ticket": ticket, "expires_at": rfc3339(expires_at)}),
        ),
        Err(e) => server_error(&runeward_controlplane::Error::other(e)),
    }
}

/// The response a failed WebSocket handshake gets (gorilla's plain-text
/// errors).
pub(crate) fn ws_rejection(r: &WebSocketUpgradeRejection) -> Response {
    if r.status() == StatusCode::METHOD_NOT_ALLOWED {
        return text(StatusCode::METHOD_NOT_ALLOWED, "Method Not Allowed\n");
    }
    text(StatusCode::BAD_REQUEST, "Bad Request\n")
}

/// Browser WebSockets must be same-origin, so another site cannot open a
/// shell into a sandbox.
pub(crate) fn check_ws_origin(headers: &HeaderMap, uri: &Uri) -> Result<(), Response> {
    if same_origin(headers, &host_of(headers, uri)) {
        Ok(())
    } else {
        Err(text(StatusCode::FORBIDDEN, "Forbidden\n"))
    }
}

/// A JSON control frame from the browser terminal (resize); anything else
/// is keystroke input.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct ControlMessage {
    #[serde(rename = "type")]
    kind: String,
    rows: u16,
    cols: u16,
}

pub(crate) async fn terminal(
    State(s): State<SharedState>,
    caller: Caller,
    Path(id): Path<String>,
    headers: HeaderMap,
    uri: Uri,
    ws: Result<WebSocketUpgrade, WebSocketUpgradeRejection>,
) -> Response {
    if s.mgr.sandbox(&id).is_none() {
        return error(StatusCode::NOT_FOUND, "sandbox not found");
    }
    let ws = match ws {
        Ok(ws) => ws,
        Err(r) => return ws_rejection(&r),
    };
    if let Err(resp) = check_ws_origin(&headers, &uri) {
        return resp;
    }
    let actor = caller.get().map(|p| p.name.clone()).unwrap_or_default();
    ws.on_upgrade(move |socket| async move {
        with_actor(&actor, bridge(s, id, socket)).await;
    })
    .into_response()
}

/// Forwards PTY output to the socket writer task.
struct ChannelWriter(mpsc::UnboundedSender<Vec<u8>>);

impl AsyncWrite for ChannelWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.0.send(buf.to_vec()) {
            Ok(()) => Poll::Ready(Ok(buf.len())),
            Err(_) => Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

async fn bridge(s: SharedState, id: String, socket: WebSocket) {
    let (mut tx, mut rx) = socket.split();
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let (resize_tx, resize_rx) = mpsc::channel::<TermSize>(1);
    let (mut stdin_w, stdin_r) = tokio::io::duplex(64 << 10);
    let recorder = start_recording(&s, &id).map(Arc::new);

    // Socket writer: PTY output (and the final status) in order.
    let (final_tx, final_rx) = tokio::sync::oneshot::channel::<Vec<Message>>();
    let rec = recorder.clone();
    let writer = tokio::spawn(async move {
        while let Some(chunk) = out_rx.recv().await {
            if let Some(r) = &rec {
                r.record(&chunk);
            }
            if tx.send(Message::Binary(chunk.into())).await.is_err() {
                return;
            }
        }
        if let Ok(msgs) = final_rx.await {
            for m in msgs {
                let _ = tx.send(m).await;
            }
        }
    });

    // Reader: demux resize control frames from raw input.
    let reader = tokio::spawn(async move {
        while let Some(Ok(msg)) = rx.next().await {
            let data: Vec<u8> = match msg {
                Message::Text(t) => {
                    if let Ok(cm) = serde_json::from_str::<ControlMessage>(t.as_str())
                        && cm.kind == "resize"
                    {
                        let _ = resize_tx.try_send(TermSize {
                            rows: cm.rows,
                            cols: cm.cols,
                        });
                        continue;
                    }
                    t.as_bytes().to_vec()
                }
                Message::Binary(b) => b.to_vec(),
                Message::Close(_) => break,
                Message::Ping(_) | Message::Pong(_) => continue,
            };
            if stdin_w.write_all(&data).await.is_err() {
                break;
            }
        }
        let _ = stdin_w.shutdown().await;
    });

    let stream = PtyStream {
        stdin: Some(Box::new(stdin_r)),
        stdout: Some(Box::new(ChannelWriter(out_tx.clone()))),
        tty: true,
        resize: Some(resize_rx),
        ..PtyStream::default()
    };
    let mut finals = Vec::new();
    if let Err(e) = s.mgr.attach_terminal(&id, stream).await {
        finals.push(Message::Text(
            format!("\r\n[runeward] terminal error: {e}\r\n").into(),
        ));
    }
    finals.push(Message::Close(Some(CloseFrame {
        code: 1000,
        reason: "session ended".into(),
    })));
    drop(out_tx);
    let _ = final_tx.send(finals);
    let _ = writer.await;
    reader.abort();
    if let Some(r) = recorder
        && let Err(e) = r.close()
    {
        tracing::warn!(sandbox = %id, error = %e, "close terminal recording");
    }
}

/// A terminal recorder when `RUNEWARD_RECORD_TERMINALS` is on, writing an
/// asciinema cast under `<state dir>/recordings`. Best effort: any setup
/// error disables recording rather than blocking the session.
fn start_recording(s: &SharedState, id: &str) -> Option<Recorder<std::fs::File>> {
    let on = std::env::var("RUNEWARD_RECORD_TERMINALS").unwrap_or_default();
    if !matches!(
        on.trim().to_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    ) {
        return None;
    }
    let dir: PathBuf = s.mgr.state_dir()?.join("recordings");
    if let Err(e) = create_private_dir(&dir) {
        tracing::warn!(error = %e, "terminal recording disabled: cannot create dir");
        return None;
    }
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default();
    let path = dir.join(format!("{id}-{secs}.cast"));
    match Recorder::create(&path, 80, 24) {
        Ok(r) => {
            tracing::info!(sandbox = %id, path = %path.display(), "recording terminal session");
            Some(r)
        }
        Err(e) => {
            tracing::warn!(error = %e, "terminal recording disabled: cannot open cast");
            None
        }
    }
}

fn create_private_dir(dir: &std::path::Path) -> io::Result<()> {
    let mut b = std::fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut b, 0o700);
    b.create(dir)
}
