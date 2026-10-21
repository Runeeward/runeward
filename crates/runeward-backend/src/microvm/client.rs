//! The host side of the guest agent protocol ([`runeward_vmagent::proto`]).
//!
//! Every operation opens its own stream; dropping a returned future closes
//! it, and the agent kills whatever the operation started.

use std::io;
use std::sync::Arc;
use std::time::Duration;

use runeward_vmagent::proto::{
    self, ErrorBody, ExecSpec, Exit, FileRequest, Kind, Request, Resize, Signal,
};
use serde::de::DeserializeOwned;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::{Mutex, mpsc};

use crate::error::{BackendError, Result};
use crate::types::{BoxReader, BoxWriter, TermSize};

/// Reads one frame; `None` at a clean end of stream.
pub(crate) async fn read_frame(
    r: &mut (impl AsyncRead + Unpin),
) -> io::Result<Option<(Kind, Vec<u8>)>> {
    let mut h = [0u8; 5];
    match r.read_exact(&mut h).await {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let (kind, len) = proto::parse_header(h)?;
    let mut payload = vec![0u8; len];
    r.read_exact(&mut payload).await?;
    Ok(Some((kind, payload)))
}

/// Writes one frame.
pub(crate) async fn write_frame(
    w: &mut (impl AsyncWrite + Unpin),
    kind: Kind,
    payload: &[u8],
) -> io::Result<()> {
    w.write_all(&proto::encode(kind, payload)).await?;
    w.flush().await
}

fn agent_err(context: &str, e: io::Error) -> BackendError {
    BackendError::io(format!("guest agent: {context}"), e)
}

fn error_body(p: &[u8]) -> BackendError {
    let msg = serde_json::from_slice::<ErrorBody>(p)
        .map(|b| b.message)
        .unwrap_or_else(|_| String::from_utf8_lossy(p).into_owned());
    BackendError::msg(msg)
}

/// Sends `req` on a fresh stream.
async fn open(stream: UnixStream, req: &Request) -> Result<(OwnedReadHalf, OwnedWriteHalf)> {
    let (r, mut w) = stream.into_split();
    let body = serde_json::to_vec(req).map_err(|e| BackendError::msg(e.to_string()))?;
    write_frame(&mut w, Kind::Request, &body)
        .await
        .map_err(|e| agent_err("send request", e))?;
    Ok((r, w))
}

/// Reads to the terminal frame, discarding output; `Result` bodies decode
/// as `T`, `Error` frames become errors.
async fn finish<T: DeserializeOwned>(r: &mut OwnedReadHalf) -> Result<T> {
    loop {
        match read_frame(r)
            .await
            .map_err(|e| agent_err("read reply", e))?
        {
            None => return Err(BackendError::msg("guest agent closed the stream")),
            Some((Kind::Result, p)) => {
                return serde_json::from_slice(&p)
                    .map_err(|e| BackendError::msg(format!("guest agent reply: {e}")));
            }
            Some((Kind::Error, p)) => return Err(error_body(&p)),
            Some(_) => {}
        }
    }
}

/// A simple request/reply.
pub(crate) async fn call<T: DeserializeOwned>(stream: UnixStream, req: &Request) -> Result<T> {
    let (mut r, _w) = open(stream, req).await?;
    finish(&mut r).await
}

/// Writes `body` to a file in the guest.
pub(crate) async fn file_write(
    stream: UnixStream,
    req: FileRequest,
    mut body: impl AsyncRead + Unpin,
) -> Result<()> {
    let (mut r, mut w) = open(stream, &Request::File(req)).await?;
    let send = async {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = body.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            write_frame(&mut w, Kind::Stdin, &buf[..n]).await?;
        }
        write_frame(&mut w, Kind::StdinEof, &[]).await
    };
    // The agent may answer (with an error) before the body is sent.
    let (sent, reply) = tokio::join!(send, finish::<serde_json::Value>(&mut r));
    reply?;
    sent.map_err(|e| agent_err("send file body", e))
}

/// Streams a file (or a tar) out of the guest into `sink`.
pub(crate) async fn file_read(
    stream: UnixStream,
    req: FileRequest,
    sink: &mut (dyn AsyncWrite + Send + Unpin),
) -> Result<serde_json::Value> {
    let (mut r, _w) = open(stream, &Request::File(req)).await?;
    loop {
        match read_frame(&mut r)
            .await
            .map_err(|e| agent_err("read file", e))?
        {
            None => return Err(BackendError::msg("guest agent closed the stream")),
            Some((Kind::Stdout, p)) => sink
                .write_all(&p)
                .await
                .map_err(|e| BackendError::io("write file data", e))?,
            Some((Kind::Result, p)) => {
                sink.flush()
                    .await
                    .map_err(|e| BackendError::io("write file data", e))?;
                return Ok(serde_json::from_slice(&p).unwrap_or_default());
            }
            Some((Kind::Error, p)) => return Err(error_body(&p)),
            Some(_) => {}
        }
    }
}

/// The I/O of one command.
#[derive(Default)]
pub(crate) struct ExecIo {
    pub(crate) stdin: Option<BoxReader>,
    pub(crate) stdout: Option<BoxWriter>,
    pub(crate) stderr: Option<BoxWriter>,
    /// Also keep stdout/stderr in memory.
    pub(crate) capture: bool,
    /// Sends stderr to the stdout sink (when there is no stderr sink).
    pub(crate) merge_stderr: bool,
    pub(crate) timeout: Option<Duration>,
    pub(crate) resize: Option<mpsc::Receiver<TermSize>>,
}

/// What a command produced.
#[derive(Debug, Default)]
pub(crate) struct ExecOutput {
    pub(crate) exit: Exit,
    pub(crate) stdout: Vec<u8>,
    pub(crate) stderr: Vec<u8>,
    pub(crate) timed_out: bool,
}

/// Runs a command in the guest.
pub(crate) async fn exec(stream: UnixStream, spec: ExecSpec, io: ExecIo) -> Result<ExecOutput> {
    let (mut r, w) = open(stream, &Request::Exec(spec)).await?;
    let w = Arc::new(Mutex::new(w));
    let ExecIo {
        stdin,
        mut stdout,
        mut stderr,
        capture,
        merge_stderr,
        timeout,
        resize,
    } = io;
    let feed = {
        let w = Arc::clone(&w);
        tokio::spawn(async move {
            if let Some(mut input) = stdin {
                let mut buf = vec![0u8; 32 * 1024];
                loop {
                    let n = match input.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => n,
                    };
                    if write_frame(&mut *w.lock().await, Kind::Stdin, &buf[..n])
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
            }
            let _ = write_frame(&mut *w.lock().await, Kind::StdinEof, &[]).await;
        })
    };
    let resizer = resize.map(|mut rx| {
        let w = Arc::clone(&w);
        tokio::spawn(async move {
            while let Some(sz) = rx.recv().await {
                let body = proto::encode_json(
                    Kind::Resize,
                    &Resize {
                        rows: sz.rows,
                        cols: sz.cols,
                    },
                );
                let mut g = w.lock().await;
                if g.write_all(&body).await.is_err() || g.flush().await.is_err() {
                    return;
                }
            }
        })
    });
    let mut out = ExecOutput::default();
    let deadline = async {
        match timeout {
            Some(t) if !t.is_zero() => tokio::time::sleep(t).await,
            _ => std::future::pending().await,
        }
    };
    tokio::pin!(deadline);
    let result = loop {
        let frame = tokio::select! {
            f = read_frame(&mut r) => f,
            () = &mut deadline, if !out.timed_out => {
                out.timed_out = true;
                let body = proto::encode_json(Kind::Signal, &Signal { signal: 9 });
                let mut g = w.lock().await;
                let _ = g.write_all(&body).await;
                let _ = g.flush().await;
                continue;
            }
        };
        match frame {
            Err(e) => break Err(agent_err("read output", e)),
            Ok(None) => break Err(BackendError::msg("guest agent closed the stream")),
            Ok(Some((Kind::Stdout, p))) => {
                if capture {
                    out.stdout.extend_from_slice(&p);
                }
                if let Some(s) = stdout.as_mut()
                    && (s.write_all(&p).await.is_err() || s.flush().await.is_err())
                {
                    stdout = None;
                }
            }
            Ok(Some((Kind::Stderr, p))) => {
                if capture {
                    out.stderr.extend_from_slice(&p);
                }
                let sink = match stderr.as_mut() {
                    Some(s) => Some(s),
                    None if merge_stderr => stdout.as_mut(),
                    None => None,
                };
                if let Some(s) = sink
                    && (s.write_all(&p).await.is_err() || s.flush().await.is_err())
                {
                    stderr = None;
                }
            }
            Ok(Some((Kind::Exit, p))) => {
                out.exit = serde_json::from_slice(&p).unwrap_or(Exit {
                    code: -1,
                    signal: None,
                });
                break Ok(());
            }
            Ok(Some((Kind::Error, p))) => break Err(error_body(&p)),
            Ok(Some(_)) => {}
        }
    };
    feed.abort();
    if let Some(t) = resizer {
        t.abort();
    }
    result?;
    if out.timed_out {
        // Like the container backends: a killed command reports -1.
        out.exit.code = -1;
    }
    Ok(out)
}
