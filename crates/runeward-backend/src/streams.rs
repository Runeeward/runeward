//! Async stream plumbing shared by the backends.

use std::process::ExitStatus;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::types::BoxWriter;

/// Go's `ExitError` text: `exit status N` or `signal: ...`.
pub(crate) fn exit_string(status: ExitStatus) -> String {
    if let Some(code) = status.code() {
        return format!("exit status {code}");
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(sig) = status.signal() {
            return match sig {
                9 => "signal: killed".into(),
                15 => "signal: terminated".into(),
                n => format!("signal: {n}"),
            };
        }
    }
    status.to_string()
}

pub(crate) type SharedWriter = Arc<tokio::sync::Mutex<BoxWriter>>;

pub(crate) fn shared(w: BoxWriter) -> SharedWriter {
    Arc::new(tokio::sync::Mutex::new(w))
}

/// Reads `r` to EOF, appending to `capture` and forwarding to `sink`. A sink
/// write failure stops forwarding but not capturing.
pub(crate) async fn drain<W: AsyncWrite + Unpin + ?Sized>(
    r: Option<impl AsyncRead + Unpin>,
    mut capture: Option<&mut Vec<u8>>,
    mut sink: Option<&mut W>,
) {
    let Some(mut r) = r else { return };
    let mut buf = vec![0u8; 32 * 1024];
    loop {
        let n = match r.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        if let Some(c) = capture.as_deref_mut() {
            c.extend_from_slice(&buf[..n]);
        }
        if let Some(s) = sink.as_deref_mut()
            && s.write_all(&buf[..n]).await.is_err()
        {
            sink = None;
        }
    }
    if let Some(s) = sink {
        let _ = s.flush().await;
    }
}

pub(crate) async fn drain_shared(r: Option<impl AsyncRead + Unpin>, sink: Option<SharedWriter>) {
    let Some(mut r) = r else { return };
    let mut buf = vec![0u8; 32 * 1024];
    loop {
        let n = match r.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        if let Some(s) = &sink {
            let mut w = s.lock().await;
            let _ = w.write_all(&buf[..n]).await;
            let _ = w.flush().await;
        }
    }
}

/// Folds a tar-into-container run into an error message: the CLI's exit
/// status wins, then a producer (archive) failure.
pub(crate) fn tar_in_error(
    status: std::io::Result<ExitStatus>,
    produced: std::io::Result<()>,
    stderr: &str,
) -> Option<String> {
    let stderr = stderr.trim();
    match status {
        Err(e) => Some(format!("{e}: {stderr}")),
        Ok(st) if !st.success() => Some(format!("{}: {stderr}", exit_string(st))),
        Ok(_) => produced.err().map(|e| format!("{e}: {stderr}")),
    }
}
