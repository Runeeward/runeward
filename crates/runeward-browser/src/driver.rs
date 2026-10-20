//! The driver side of the control socket: listening, the one-command-per-
//! connection exchange, and executing commands against the CDP client.

use std::env;
use std::io;
use std::path::PathBuf;
use std::time::Duration;

use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Mutex;

use crate::cdp::{Client, validate_navigate_url};
use crate::protocol::{Command, CommandResult, decode_object};

/// Set to `0`, `false`, `no` or `off` to keep Chromium's own sandbox.
pub const ENV_BROWSER_NO_SANDBOX: &str = "RUNEWARD_BROWSER_NO_SANDBOX";

/// The shared control secret when `--token` is not given.
pub const ENV_BROWSER_CONTROL_TOKEN: &str = "RUNEWARD_BROWSER_CONTROL_TOKEN";

/// Chromium binaries looked up on `PATH`, in order.
pub const CHROME_NAMES: [&str; 5] = [
    "chromium",
    "chromium-browser",
    "google-chrome",
    "google-chrome-stable",
    "headless-shell",
];

/// How long a client may take to send its command.
pub const COMMAND_READ_TIMEOUT: Duration = Duration::from_secs(60);

/// Whether Chromium should launch with `--no-sandbox`, from
/// `RUNEWARD_BROWSER_NO_SANDBOX`.
///
/// Chromium's sandbox needs user namespaces, which containers usually lack,
/// so `--no-sandbox` is the default. Under a runtime that provides isolation
/// (gVisor, Kata) or user namespaces, operators keep Chromium's sandbox by
/// setting the variable to `0`.
pub fn browser_no_sandbox_enabled() -> bool {
    no_sandbox_from(env::var(ENV_BROWSER_NO_SANDBOX).ok().as_deref())
}

/// [`browser_no_sandbox_enabled`] for an explicit variable value.
pub fn no_sandbox_from(v: Option<&str>) -> bool {
    !matches!(
        v.map(|v| v.trim().to_ascii_lowercase()).as_deref(),
        Some("0" | "false" | "no" | "off")
    )
}

/// Finds the first of [`CHROME_NAMES`] on `PATH`.
pub fn find_chrome() -> Result<PathBuf, String> {
    let path = env::var_os("PATH").unwrap_or_default();
    for name in CHROME_NAMES {
        for dir in env::split_paths(&path) {
            let dir = if dir.as_os_str().is_empty() {
                PathBuf::from(".")
            } else {
                dir
            };
            let candidate = dir.join(name);
            if is_executable(&candidate) {
                return Ok(candidate);
            }
        }
    }
    Err(format!(
        "no chromium binary found (looked for {})",
        CHROME_NAMES.join(", ")
    ))
}

#[cfg(unix)]
fn is_executable(p: &std::path::Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

#[cfg(not(unix))]
fn is_executable(p: &std::path::Path) -> bool {
    p.is_file()
}

/// The kind of control socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    /// A TCP socket (`tcp://host:port`); requires a control token.
    Tcp,
    /// A Unix domain socket (a path, or `unix://path`).
    Unix,
}

/// A connected control client.
pub trait ControlConn: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> ControlConn for T {}

/// A listening control socket.
#[derive(Debug)]
pub enum ControlListener {
    /// `tcp://` sockets.
    Tcp(TcpListener),
    /// Unix sockets, with the path to remove on shutdown.
    #[cfg(unix)]
    Unix(tokio::net::UnixListener, PathBuf),
}

impl ControlListener {
    /// Waits for the next client.
    pub async fn accept(&self) -> io::Result<Box<dyn ControlConn>> {
        match self {
            Self::Tcp(l) => Ok(Box::new(l.accept().await?.0)),
            #[cfg(unix)]
            Self::Unix(l, _) => Ok(Box::new(l.accept().await?.0)),
        }
    }

    /// The Unix socket path, if any.
    pub fn unix_path(&self) -> Option<&std::path::Path> {
        match self {
            Self::Tcp(_) => None,
            #[cfg(unix)]
            Self::Unix(_, p) => Some(p),
        }
    }
}

/// Listens on `socket`: `tcp://addr`, `unix://path`, or a bare Unix socket
/// path. A stale Unix socket file is removed first.
pub async fn listen_control(socket: &str) -> io::Result<(ControlListener, Network)> {
    let socket = socket.trim();
    if let Some(addr) = socket.strip_prefix("tcp://") {
        return Ok((
            ControlListener::Tcp(TcpListener::bind(addr).await?),
            Network::Tcp,
        ));
    }
    let path = socket.strip_prefix("unix://").unwrap_or(socket);
    listen_unix(path)
}

#[cfg(unix)]
fn listen_unix(path: &str) -> io::Result<(ControlListener, Network)> {
    let _ = std::fs::remove_file(path);
    let l = tokio::net::UnixListener::bind(path)?;
    Ok((ControlListener::Unix(l, PathBuf::from(path)), Network::Unix))
}

#[cfg(not(unix))]
fn listen_unix(_path: &str) -> io::Result<(ControlListener, Network)> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "unix control sockets are not supported on this platform; use tcp://",
    ))
}

/// Reads exactly one JSON value from `r`, like one Go `json.Decoder.Decode`:
/// leading whitespace is skipped, the value is returned as soon as it is
/// complete (without waiting for EOF), and anything sent after it is
/// ignored. Truncated input fails with Go's `EOF` / `unexpected EOF`
/// wording.
pub async fn read_json_value<R: AsyncRead + Unpin + ?Sized>(
    r: &mut R,
) -> Result<serde_json::Value, String> {
    let mut buf = Vec::with_capacity(512);
    let mut chunk = [0u8; 4096];
    loop {
        if !buf.is_empty() {
            match serde_json::Deserializer::from_slice(&buf)
                .into_iter::<serde_json::Value>()
                .next()
            {
                Some(Ok(v)) => return Ok(v),
                Some(Err(e)) if !e.is_eof() => return Err(e.to_string()),
                _ => {}
            }
        }
        let n = r.read(&mut chunk).await.map_err(|e| e.to_string())?;
        if n == 0 {
            return Err(if buf.iter().all(u8::is_ascii_whitespace) {
                "EOF".to_owned()
            } else {
                "unexpected EOF".to_owned()
            });
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

/// What the serve loop should do after a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    /// Keep serving.
    Continue,
    /// A `close` command was accepted: shut the driver down.
    Shutdown,
}

/// The long-lived browser session shared across control connections.
#[derive(Debug)]
pub struct Driver {
    client: Option<Client>,
    token: String,
    exec: Mutex<()>,
}

impl Driver {
    /// A driver for `client` that requires `token` on every command (an
    /// empty token disables the check, which only Unix sockets allow).
    pub fn new(client: Option<Client>, token: impl Into<String>) -> Self {
        Self {
            client,
            token: token.into(),
            exec: Mutex::new(()),
        }
    }

    /// Closes the CDP connection.
    pub async fn close(&self) {
        if let Some(c) = &self.client {
            c.close().await;
        }
    }

    /// Processes exactly one command/result exchange on `conn`.
    pub async fn handle_conn<S: AsyncRead + AsyncWrite + Unpin + ?Sized>(
        &self,
        conn: &mut S,
    ) -> Disposition {
        let decoded = match tokio::time::timeout(COMMAND_READ_TIMEOUT, read_json_value(conn)).await
        {
            Err(_) => Err("i/o timeout".to_owned()),
            Ok(Err(e)) => Err(e),
            Ok(Ok(v)) => decode_object::<Command>(v).map_err(|e| e.to_string()),
        };
        let cmd = match decoded {
            Ok(cmd) => cmd,
            Err(e) => {
                write_result(conn, &CommandResult::err(format!("decode command: {e}"))).await;
                return Disposition::Continue;
            }
        };
        if !self.token.is_empty() && !bool::from(cmd.token.as_bytes().ct_eq(self.token.as_bytes()))
        {
            write_result(conn, &CommandResult::err("unauthorized control token")).await;
            return Disposition::Continue;
        }
        if cmd.action == "close" {
            write_result(conn, &CommandResult::ok()).await;
            return Disposition::Shutdown;
        }
        let res = self.execute(&cmd).await;
        write_result(conn, &res).await;
        Disposition::Continue
    }

    /// Runs one command. Commands are serialized.
    pub async fn execute(&self, cmd: &Command) -> CommandResult {
        let _guard = self.exec.lock().await;
        let timeout = Duration::from_millis(u64::try_from(cmd.timeout_ms).unwrap_or(0));
        if cmd.action == "ping" {
            return CommandResult::ok();
        }
        let Some(c) = &self.client else {
            return CommandResult::err("browser is not attached");
        };
        let unit = |r: Result<(), crate::CdpError>| match r {
            Ok(()) => CommandResult::ok(),
            Err(e) => CommandResult::err(e.to_string()),
        };
        let value = |r: Result<String, crate::CdpError>| match r {
            Ok(v) => CommandResult::value(v),
            Err(e) => CommandResult::err(e.to_string()),
        };
        match cmd.action.as_str() {
            "navigate" => {
                if cmd.url.is_empty() {
                    return CommandResult::err("navigate: url is required");
                }
                if let Err(e) = validate_navigate_url(&cmd.url) {
                    return CommandResult::err(e.to_string());
                }
                unit(c.navigate(&cmd.url, timeout).await)
            }
            "eval" => value(c.eval(&cmd.expr).await),
            "text" => value(c.text().await),
            "html" => value(c.html().await),
            "title" => value(c.title().await),
            "url" => value(c.url().await),
            "screenshot" => match c.screenshot().await {
                Ok(b64) => CommandResult {
                    ok: true,
                    screenshot: b64,
                    ..CommandResult::default()
                },
                Err(e) => CommandResult::err(e.to_string()),
            },
            "click" => {
                if cmd.selector.is_empty() {
                    return CommandResult::err("click: selector is required");
                }
                unit(c.click(&cmd.selector).await)
            }
            "type" => {
                if cmd.selector.is_empty() {
                    return CommandResult::err("type: selector is required");
                }
                unit(c.type_text(&cmd.selector, &cmd.text).await)
            }
            "wait" => {
                if cmd.selector.is_empty() {
                    return CommandResult::err("wait: selector is required");
                }
                unit(c.wait_selector(&cmd.selector, timeout).await)
            }
            other => CommandResult::err(format!("unknown action: {other}")),
        }
    }
}

/// Writes one result as Go's `json.Encoder` does (JSON plus newline), then
/// closes the write side.
async fn write_result<S: AsyncWrite + Unpin + ?Sized>(conn: &mut S, res: &CommandResult) {
    let mut line = res.to_json();
    line.push(b'\n');
    let _ = conn.write_all(&line).await;
    let _ = conn.flush().await;
    let _ = conn.shutdown().await;
}
