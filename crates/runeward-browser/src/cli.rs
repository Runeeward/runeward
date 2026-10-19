//! The `runeward-browser` command.
//!
//! ```text
//! runeward-browser serve  --socket <path|tcp://addr> [--proxy <url>] [--token <secret>]
//! runeward-browser call   --socket <path|tcp://addr> [--token <secret>] [--json '<Command JSON>']
//! runeward-browser render [--mode text|screenshot] [--proxy <url>] <url>
//! ```
//!
//! `serve` runs a persistent headless Chromium behind a control socket; each
//! connection carries one JSON [`Command`] and one [`CommandResult`]. The
//! page lives across connections, so cookies and storage persist for the
//! session. `call` sends one command (from `--json` or stdin), prints the
//! result and exits 1 when it failed. `render` does a one-shot render of one
//! URL to stdout: the DOM (`text`) or a base64 PNG (`screenshot`).
//!
//! Flags follow Go's `flag` syntax (`-socket x`, `--socket=x`, ...).

use std::io::{Read, Write};
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper::{Method, Request};
use hyper_util::rt::TokioIo;
use serde::Deserialize;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::time::Instant;

use crate::cdp::Client;
use crate::driver::{
    ControlConn, Disposition, Driver, ENV_BROWSER_CONTROL_TOKEN, Network,
    browser_no_sandbox_enabled, find_chrome, listen_control, read_json_value,
};
use crate::goflag::{self, FlagError};
use crate::protocol::{Command, CommandResult, decode, decode_object};
use crate::proxyauth::{Forwarder, start_proxy_auth_forwarder};
use crate::util::go_duration;

const USAGE: &str = "runeward-browser — in-sandbox CDP browser driver

Usage:
  runeward-browser serve  --socket <path|tcp://addr> [--proxy <url>] [--token <secret>]
  runeward-browser call   --socket <path|tcp://addr> [--token <secret>] [--json '<Command JSON>']
  runeward-browser render [--mode text|screenshot] [--proxy <url>] <url>
";

fn log(msg: impl std::fmt::Display) {
    eprintln!("runeward-browser: {msg}");
}

/// Runs the command with `args` (without the program name) and returns the
/// process exit code.
pub fn main(args: Vec<String>) -> i32 {
    let Some(sub) = args.first() else {
        eprint!("{USAGE}");
        return 2;
    };
    let rest = &args[1..];
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            log(format!("start runtime: {e}"));
            return 1;
        }
    };
    match sub.as_str() {
        "serve" => rt.block_on(serve(rest)),
        "call" => rt.block_on(call(
            rest,
            std::io::stdin().lock(),
            &mut std::io::stdout().lock(),
            &mut std::io::stderr().lock(),
        )),
        "render" => rt.block_on(render(rest)),
        "-h" | "--help" | "help" => {
            eprint!("{USAGE}");
            0
        }
        other => {
            eprintln!("runeward-browser: unknown subcommand {other:?}");
            eprint!("{USAGE}");
            2
        }
    }
}

/// One flag of a subcommand, for usage output.
struct FlagDoc {
    name: &'static str,
    usage: &'static str,
}

/// Parses flags; on `-h` or a bad flag prints Go-style usage and returns the
/// exit code to use.
fn parse_flags(
    set: &str,
    docs: &[FlagDoc],
    args: &[String],
    stderr: &mut dyn Write,
) -> Result<goflag::Parsed, i32> {
    let names: Vec<&str> = docs.iter().map(|d| d.name).collect();
    let usage = |stderr: &mut dyn Write| {
        let _ = writeln!(stderr, "Usage of {set}:");
        for d in docs {
            let _ = writeln!(stderr, "  -{} string\n    \t{}", d.name, d.usage);
        }
    };
    match goflag::parse(&names, args) {
        Ok(p) => Ok(p),
        Err(FlagError::Help) => {
            usage(stderr);
            Err(0)
        }
        Err(FlagError::Bad(msg)) => {
            let _ = writeln!(stderr, "{msg}");
            usage(stderr);
            Err(2)
        }
    }
}

fn token_from_env() -> String {
    std::env::var(ENV_BROWSER_CONTROL_TOKEN)
        .map(|t| t.trim().to_owned())
        .unwrap_or_default()
}

/// The Chromium flags shared by `serve` and `render`.
fn base_chrome_args(udd: &Path) -> Vec<String> {
    let mut args = vec![
        "--headless=new".to_owned(),
        "--disable-gpu".to_owned(),
        "--disable-dev-shm-usage".to_owned(),
        "--hide-scrollbars".to_owned(),
    ];
    args.push(format!("--user-data-dir={}", udd.display()));
    if browser_no_sandbox_enabled() {
        args.push("--no-sandbox".to_owned());
    }
    args
}

/// Starts the proxy-auth forwarder for `proxy`, falling back to the raw URL
/// (unauthenticated proxies still work) when it cannot start.
async fn proxy_arg(proxy: &str) -> (String, Option<Forwarder>) {
    match start_proxy_auth_forwarder(proxy).await {
        Ok(f) => (format!("--proxy-server={}", f.url()), Some(f)),
        Err(e) => {
            log(format!("proxy-auth forwarder: {e} (using proxy as-is)"));
            (format!("--proxy-server={proxy}"), None)
        }
    }
}

/// Everything `serve` must tear down.
struct Session {
    chrome: Option<tokio::process::Child>,
    udd: Option<tempfile::TempDir>,
    forwarder: Option<Forwarder>,
    driver: Option<Driver>,
    socket_path: Option<std::path::PathBuf>,
}

impl Session {
    /// Tears everything down once and returns `code`.
    async fn shutdown(mut self, code: i32) -> i32 {
        if let Some(mut f) = self.forwarder.take() {
            f.stop();
        }
        if let Some(d) = self.driver.take() {
            d.close().await;
        }
        if let Some(mut c) = self.chrome.take() {
            let _ = c.kill().await;
        }
        if let Some(p) = self.socket_path.take() {
            let _ = std::fs::remove_file(p);
        }
        if let Some(d) = self.udd.take() {
            let _ = d.close();
        }
        code
    }
}

async fn serve(args: &[String]) -> i32 {
    let docs = [
        FlagDoc {
            name: "socket",
            usage: "path to the Unix domain control socket to listen on",
        },
        FlagDoc {
            name: "proxy",
            usage: "HTTP(S) proxy passed to Chromium via --proxy-server",
        },
        FlagDoc {
            name: "token",
            usage: "shared secret required on control requests (or RUNEWARD_BROWSER_CONTROL_TOKEN)",
        },
    ];
    let flags = match parse_flags("serve", &docs, args, &mut std::io::stderr()) {
        Ok(f) => f,
        Err(code) => return code,
    };
    let socket = flags.get("socket");
    if socket.is_empty() {
        eprintln!("serve: --socket is required");
        return 2;
    }
    let mut token = flags.get("token");
    if token.is_empty() {
        token = token_from_env();
    }

    let chrome = match find_chrome() {
        Ok(c) => c,
        Err(e) => {
            log(e);
            return 1;
        }
    };
    let udd = match tempfile::Builder::new()
        .prefix("runeward-browser-")
        .tempdir()
    {
        Ok(d) => d,
        Err(e) => {
            log(format!("create user-data-dir: {e}"));
            return 1;
        }
    };
    let mut chrome_args = base_chrome_args(udd.path());
    chrome_args.insert(4, "--remote-debugging-port=0".to_owned());
    let mut session = Session {
        chrome: None,
        udd: None,
        forwarder: None,
        driver: None,
        socket_path: None,
    };
    let proxy = flags.get("proxy");
    if !proxy.is_empty() {
        let (arg, fwd) = proxy_arg(&proxy).await;
        chrome_args.push(arg);
        session.forwarder = fwd;
    }

    let child = tokio::process::Command::new(&chrome)
        .args(&chrome_args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn();
    let udd_path = udd.path().to_path_buf();
    session.udd = Some(udd);
    let child = match child {
        Ok(c) => c,
        Err(e) => {
            log(format!("launch chromium: {e}"));
            return session.shutdown(1).await;
        }
    };
    let pid = child.id().unwrap_or_default();
    session.chrome = Some(child);

    let port = match wait_for_devtools_port(&udd_path, Duration::from_secs(15)).await {
        Ok(p) => p,
        Err(e) => {
            log(e);
            return session.shutdown(1).await;
        }
    };
    let ws_url = match attach_page(port, Duration::from_secs(10)).await {
        Ok(u) => u,
        Err(e) => {
            log(format!("attach page: {e}"));
            return session.shutdown(1).await;
        }
    };
    let client = match Client::dial(&ws_url).await {
        Ok(c) => c,
        Err(e) => {
            log(format!("cdp dial: {e}"));
            return session.shutdown(1).await;
        }
    };
    session.driver = Some(Driver::new(Some(client), token.clone()));

    let (ln, network) = match listen_control(&socket).await {
        Ok(v) => v,
        Err(e) => {
            log(format!("listen {socket}: {e}"));
            return session.shutdown(1).await;
        }
    };
    session.socket_path = ln.unix_path().map(Path::to_path_buf);
    if network != Network::Unix && token.is_empty() {
        log(format!(
            "listen {socket}: --token (or {ENV_BROWSER_CONTROL_TOKEN}) is required for network sockets"
        ));
        return session.shutdown(2).await;
    }

    log(format!(
        "serving on {socket} (chrome pid {pid}, devtools port {port})"
    ));
    let signal = shutdown_signal();
    tokio::pin!(signal);
    loop {
        let conn = tokio::select! {
            sig = &mut signal => {
                log(format!("received {sig}, shutting down"));
                return session.shutdown(0).await;
            }
            r = ln.accept() => r,
        };
        let mut conn: Box<dyn ControlConn> = match conn {
            Ok(c) => c,
            Err(e) => {
                log(format!("accept: {e}"));
                continue;
            }
        };
        let Some(driver) = session.driver.as_ref() else {
            return session.shutdown(1).await;
        };
        if driver.handle_conn(&mut *conn).await == Disposition::Shutdown {
            drop(conn);
            log("close requested, shutting down");
            return session.shutdown(0).await;
        }
    }
}

/// Resolves with the signal name on SIGINT or SIGTERM.
async fn shutdown_signal() -> &'static str {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let Ok(mut term) = signal(SignalKind::terminate()) else {
            let _ = tokio::signal::ctrl_c().await;
            return "interrupt";
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => "interrupt",
            _ = term.recv() => "terminated",
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
        "interrupt"
    }
}

/// Polls for the `DevToolsActivePort` file Chromium writes after launch and
/// returns the port on its first line.
pub(crate) async fn wait_for_devtools_port(udd: &Path, timeout: Duration) -> Result<u16, String> {
    let path = udd.join("DevToolsActivePort");
    let deadline = Instant::now() + timeout;
    loop {
        if let Ok(data) = tokio::fs::read_to_string(&path).await {
            let first = data.trim().lines().next().unwrap_or_default().trim();
            if let Ok(p) = first.parse::<u16>()
                && p > 0
            {
                return Ok(p);
            }
        }
        if Instant::now() > deadline {
            return Err(format!(
                "DevToolsActivePort not ready within {}",
                go_duration(timeout)
            ));
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// A DevTools target descriptor.
#[derive(Debug, Default, Deserialize)]
struct Target {
    #[serde(default, rename = "type")]
    typ: String,
    #[serde(default, rename = "webSocketDebuggerUrl")]
    web_socket_debugger_url: String,
}

/// Returns a page-level DevTools WebSocket URL, retrying until `timeout`.
pub(crate) async fn attach_page(port: u16, timeout: Duration) -> Result<String, String> {
    let deadline = Instant::now() + timeout;
    let mut last_err = None;
    loop {
        match new_page_ws(port).await {
            Ok(ws) if !ws.is_empty() => return Ok(ws),
            Ok(_) => {}
            Err(e) => last_err = Some(e),
        }
        if Instant::now() > deadline {
            return Err(last_err.unwrap_or_else(|| "no page target available".to_owned()));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn new_page_ws(port: u16) -> Result<String, String> {
    for method in [Method::PUT, Method::GET] {
        let (status, body) = http_do(port, method, "/json/new?about:blank").await?;
        if status == 200
            && let Ok(t) = serde_json::from_slice::<Target>(&body)
            && !t.web_socket_debugger_url.is_empty()
        {
            return Ok(t.web_socket_debugger_url);
        }
    }
    let (_, body) = http_do(port, Method::GET, "/json").await?;
    let targets: Vec<Target> = serde_json::from_slice(&body).map_err(|e| e.to_string())?;
    targets
        .into_iter()
        .find(|t| t.typ == "page" && !t.web_socket_debugger_url.is_empty())
        .map(|t| t.web_socket_debugger_url)
        .ok_or_else(|| "no page target found".to_owned())
}

/// One HTTP/1.1 request to the local DevTools endpoint, with a 5 s limit.
async fn http_do(port: u16, method: Method, path: &str) -> Result<(u16, Bytes), String> {
    let fut = async {
        let stream = TcpStream::connect(("127.0.0.1", port))
            .await
            .map_err(|e| e.to_string())?;
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .map_err(|e| e.to_string())?;
        tokio::spawn(conn);
        let req = Request::builder()
            .method(method)
            .uri(path)
            .header(hyper::header::HOST, format!("127.0.0.1:{port}"))
            .body(Empty::<Bytes>::new())
            .map_err(|e| e.to_string())?;
        let resp = sender.send_request(req).await.map_err(|e| e.to_string())?;
        let status = resp.status().as_u16();
        let body = resp
            .into_body()
            .collect()
            .await
            .map_err(|e| e.to_string())?
            .to_bytes();
        Ok::<_, String>((status, body))
    };
    tokio::time::timeout(Duration::from_secs(5), fut)
        .await
        .map_err(|_| "Client.Timeout exceeded while awaiting headers".to_owned())?
}

async fn render(args: &[String]) -> i32 {
    let docs = [
        FlagDoc {
            name: "mode",
            usage: "\"text\" (rendered DOM) or \"screenshot\" (base64 PNG) (default \"text\")",
        },
        FlagDoc {
            name: "proxy",
            usage: "HTTP(S) proxy (embedded credentials are honored)",
        },
    ];
    let flags = match parse_flags("render", &docs, args, &mut std::io::stderr()) {
        Ok(f) => f,
        Err(code) => return code,
    };
    // Any mode other than "screenshot" renders text, so the "text"
    // default needs no special casing.
    let mode = flags.get("mode");
    let Some(target) = flags.args.first().filter(|t| !t.is_empty()).cloned() else {
        eprintln!("render: a url argument is required");
        return 2;
    };

    let chrome = match find_chrome() {
        Ok(c) => c,
        Err(e) => {
            log(e);
            return 1;
        }
    };
    let udd = match tempfile::Builder::new()
        .prefix("runeward-render-")
        .tempdir()
    {
        Ok(d) => d,
        Err(e) => {
            log(format!("create user-data-dir: {e}"));
            return 1;
        }
    };
    let mut chrome_args = base_chrome_args(udd.path());
    let mut _forwarder = None;
    let proxy = flags.get("proxy");
    if !proxy.is_empty() {
        let (arg, fwd) = proxy_arg(&proxy).await;
        chrome_args.push(arg);
        _forwarder = fwd;
    }

    if mode == "screenshot" {
        let shot = udd.path().join("shot.png");
        chrome_args.push(format!("--screenshot={}", shot.display()));
        chrome_args.push(target);
        let status = tokio::process::Command::new(&chrome)
            .args(&chrome_args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await;
        if let Err(e) = exit_ok(status) {
            log(format!("chromium: {e}"));
            return 1;
        }
        let data = match std::fs::read(&shot) {
            Ok(d) => d,
            Err(e) => {
                log(format!("read screenshot: {e}"));
                return 1;
            }
        };
        let mut out = std::io::stdout().lock();
        let _ = out.write_all(STANDARD.encode(data).as_bytes());
        let _ = out.flush();
        return 0;
    }

    chrome_args.push("--dump-dom".to_owned());
    chrome_args.push(target);
    let status = tokio::process::Command::new(&chrome)
        .args(&chrome_args)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::null())
        .status()
        .await;
    if let Err(e) = exit_ok(status) {
        log(format!("chromium: {e}"));
        return 1;
    }
    0
}

fn exit_ok(status: std::io::Result<std::process::ExitStatus>) -> Result<(), String> {
    match status {
        Ok(s) if s.success() => Ok(()),
        Ok(s) => Err(s.to_string()),
        Err(e) => Err(e.to_string()),
    }
}

/// `call`: sends one command to a driver and prints the result. Returns the
/// exit code (0 ok, 1 when the result is not ok, 2 on usage or transport
/// errors).
pub async fn call<I: Read>(
    args: &[String],
    mut stdin: I,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> i32 {
    let docs = [
        FlagDoc {
            name: "socket",
            usage: "path to the driver's Unix domain control socket",
        },
        FlagDoc {
            name: "token",
            usage: "shared secret for control requests (or RUNEWARD_BROWSER_CONTROL_TOKEN)",
        },
        FlagDoc {
            name: "json",
            usage: "Command JSON; if empty, read from stdin",
        },
    ];
    let flags = match parse_flags("call", &docs, args, stderr) {
        Ok(f) => f,
        Err(code) => return code,
    };
    let socket = flags.get("socket");
    if socket.is_empty() {
        let _ = writeln!(stderr, "call: --socket is required");
        return 2;
    }
    let raw = match flags.get("json") {
        j if !j.is_empty() => j.into_bytes(),
        _ => {
            let mut b = Vec::new();
            if let Err(e) = stdin.read_to_end(&mut b) {
                let _ = writeln!(stderr, "call: read stdin: {e}");
                return 2;
            }
            b
        }
    };
    let mut cmd: Command = match decode(&raw) {
        Ok(c) => c,
        Err(e) => {
            let _ = writeln!(stderr, "call: invalid command JSON: {e}");
            return 2;
        }
    };
    if cmd.token.is_empty() {
        let mut token = flags.get("token");
        if token.is_empty() {
            token = token_from_env();
        }
        cmd.token = token;
    }

    let mut conn = match dial_control(&socket).await {
        Ok(c) => c,
        Err(e) => {
            let _ = writeln!(stderr, "call: dial {socket}: {e}");
            return 2;
        }
    };
    let mut line = cmd.to_json();
    line.push(b'\n');
    if let Err(e) = conn.write_all(&line).await {
        let _ = writeln!(stderr, "call: send command: {e}");
        return 2;
    }
    let _ = conn.shutdown().await;

    let res: CommandResult = match read_json_value(&mut *conn)
        .await
        .and_then(|v| decode_object(v).map_err(|e| e.to_string()))
    {
        Ok(r) => r,
        Err(e) => {
            let _ = writeln!(stderr, "call: read result: {e}");
            return 2;
        }
    };
    let mut out = res.to_json();
    out.push(b'\n');
    let _ = stdout.write_all(&out);
    let _ = stdout.flush();
    if !res.ok {
        let _ = writeln!(stderr, "{}", res.error);
        return 1;
    }
    0
}

/// Connects to a control socket: a Unix path (optionally `unix://`) or
/// `tcp://host:port`.
async fn dial_control(socket: &str) -> std::io::Result<Box<dyn ControlConn>> {
    if let Some(addr) = socket.strip_prefix("tcp://") {
        return Ok(Box::new(TcpStream::connect(addr).await?));
    }
    let path = socket.strip_prefix("unix://").unwrap_or(socket);
    dial_unix(path).await
}

#[cfg(unix)]
async fn dial_unix(path: &str) -> std::io::Result<Box<dyn ControlConn>> {
    Ok(Box::new(tokio::net::UnixStream::connect(path).await?))
}

#[cfg(not(unix))]
async fn dial_unix(_path: &str) -> std::io::Result<Box<dyn ControlConn>> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "unix control sockets are not supported on this platform; use tcp://",
    ))
}
