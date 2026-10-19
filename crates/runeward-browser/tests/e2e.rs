//! End-to-end runs of the `runeward-browser` binary with a fake `chromium`
//! on PATH and an in-test fake DevTools endpoint.
#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command as Proc, Stdio};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;

const BIN: &str = env!("CARGO_BIN_EXE_runeward-browser");

const FAKE_CHROMIUM: &str = r#"#!/bin/sh
printf '%s\n' "$@" > "$FAKE_ARGS_FILE"
d=""; shot=""; dump=""
for a in "$@"; do
  case "$a" in
    --user-data-dir=*) d="${a#--user-data-dir=}" ;;
    --screenshot=*) shot="${a#--screenshot=}" ;;
    --dump-dom) dump=1 ;;
  esac
done
if [ -n "$shot" ]; then printf 'PNGDATA' > "$shot"; exit 0; fi
if [ -n "$dump" ]; then printf '<html>fake dom</html>\n'; exit 0; fi
printf '%s\n/devtools/browser/fake\n' "$FAKE_DEVTOOLS_PORT" > "$d/DevToolsActivePort"
exec sleep 60
"#;

fn fake_bin(dir: &Path) -> PathBuf {
    let bin = dir.join("bin");
    std::fs::create_dir_all(&bin).expect("mkdir");
    let chromium = bin.join("chromium");
    std::fs::write(&chromium, FAKE_CHROMIUM).expect("write script");
    std::fs::set_permissions(&chromium, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    bin
}

fn path_with(bin: &Path) -> String {
    format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    )
}

/// Fake DevTools: an HTTP endpoint answering /json/new and a CDP WebSocket.
async fn fake_devtools() -> u16 {
    let ws = TcpListener::bind("127.0.0.1:0").await.expect("bind ws");
    let ws_addr = ws.local_addr().expect("addr");
    tokio::spawn(async move {
        while let Ok((s, _)) = ws.accept().await {
            tokio::spawn(async move {
                let Ok(mut ws) = tokio_tungstenite::accept_async(s).await else {
                    return;
                };
                while let Some(Ok(Message::Text(t))) = ws.next().await {
                    let req: Value = serde_json::from_str(t.as_str()).expect("json");
                    let id = &req["id"];
                    let mut frames = vec![];
                    match req["method"].as_str().unwrap_or_default() {
                        "Runtime.evaluate" => frames.push(json!({"id": id, "result": {"result": {"type": "string", "value": "Fake Title"}}})),
                        "Page.navigate" => {
                            frames.push(json!({"id": id, "result": {}}));
                            frames.push(json!({"method": "Page.loadEventFired", "params": {}}));
                        }
                        _ => frames.push(json!({"id": id, "result": {}})),
                    }
                    for f in frames {
                        if ws.send(Message::text(f.to_string())).await.is_err() {
                            return;
                        }
                    }
                }
            });
        }
    });
    let http = TcpListener::bind("127.0.0.1:0").await.expect("bind http");
    let port = http.local_addr().expect("addr").port();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = http.accept().await {
            let mut buf = vec![0u8; 4096];
            let n = s.read(&mut buf).await.unwrap_or(0);
            let head = String::from_utf8_lossy(&buf[..n]).to_string();
            let body = if head.starts_with("PUT /json/new?about:blank") {
                json!({"type": "page", "webSocketDebuggerUrl": format!("ws://{ws_addr}/devtools/page/1")}).to_string()
            } else {
                "[]".to_owned()
            };
            let _ = s
                .write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes())
                .await;
        }
    });
    port
}

fn call(path: &str, socket: &Path, json: &str) -> (i32, String) {
    let out = Proc::new(BIN)
        .env("PATH", path)
        .args([
            "call",
            "--socket",
            &socket.display().to_string(),
            "--token",
            "t",
            "--json",
            json,
        ])
        .output()
        .expect("run call");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).to_string(),
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn serve_call_close() {
    let dir = tempfile::tempdir().expect("tempdir");
    let bin = fake_bin(dir.path());
    let path = path_with(&bin);
    let port = fake_devtools().await;
    let socket = dir.path().join("ctl.sock");
    let args_file = dir.path().join("args.txt");

    let mut serve = Proc::new(BIN)
        .env("PATH", &path)
        .env("FAKE_DEVTOOLS_PORT", port.to_string())
        .env("FAKE_ARGS_FILE", &args_file)
        .env_remove("RUNEWARD_BROWSER_NO_SANDBOX")
        .args([
            "serve",
            "-socket",
            &socket.display().to_string(),
            "-token",
            "t",
            "-proxy",
            "http://u:p@127.0.0.1:9",
        ])
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn serve");

    for _ in 0..200 {
        if socket.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(socket.exists(), "control socket never appeared");

    let chrome_args = std::fs::read_to_string(&args_file).expect("args");
    assert!(
        chrome_args.contains("--remote-debugging-port=0\n"),
        "{chrome_args}"
    );
    assert!(chrome_args.contains("--no-sandbox\n"), "{chrome_args}");
    // Chromium gets the credential-free loopback forwarder, not u:p@.
    assert!(
        chrome_args.contains("--proxy-server=http://127.0.0.1:"),
        "{chrome_args}"
    );
    assert!(!chrome_args.contains("u:p@"), "{chrome_args}");

    let p = path.clone();
    let s = socket.clone();
    let results = tokio::task::spawn_blocking(move || {
        vec![
            call(&p, &s, r#"{"action":"ping"}"#),
            call(
                &p,
                &s,
                r#"{"action":"navigate","url":"https://example.com/"}"#,
            ),
            call(&p, &s, r#"{"action":"navigate","url":"http://127.0.0.1/"}"#),
            call(&p, &s, r#"{"action":"title"}"#),
            call(&p, &s, r#"{"action":"close"}"#),
        ]
    })
    .await
    .expect("calls");
    assert_eq!(results[0], (0, "{\"ok\":true}\n".to_owned()));
    assert_eq!(results[1], (0, "{\"ok\":true}\n".to_owned()));
    assert_eq!(results[2].0, 1);
    assert!(results[2].1.contains("is blocked"), "{}", results[2].1);
    assert_eq!(
        results[3],
        (0, "{\"ok\":true,\"value\":\"Fake Title\"}\n".to_owned())
    );
    assert_eq!(results[4], (0, "{\"ok\":true}\n".to_owned()));

    let status = tokio::task::spawn_blocking(move || serve.wait())
        .await
        .expect("join")
        .expect("wait");
    assert!(status.success(), "serve exit: {status}");
    assert!(!socket.exists(), "socket removed on shutdown");
}

#[test]
fn render_text_and_screenshot() {
    let dir = tempfile::tempdir().expect("tempdir");
    let bin = fake_bin(dir.path());
    let path = path_with(&bin);
    let args_file = dir.path().join("args.txt");
    let run = |extra: &[&str]| {
        Proc::new(BIN)
            .env("PATH", &path)
            .env("FAKE_ARGS_FILE", &args_file)
            .env("RUNEWARD_BROWSER_NO_SANDBOX", "0")
            .arg("render")
            .args(extra)
            .output()
            .expect("run render")
    };

    let out = run(&["https://example.com/"]);
    assert!(out.status.success());
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "<html>fake dom</html>\n"
    );
    let args = std::fs::read_to_string(&args_file).expect("args");
    assert!(
        args.ends_with("--dump-dom\nhttps://example.com/\n"),
        "{args}"
    );
    assert!(!args.contains("--no-sandbox"), "{args}");

    let out = run(&["--mode", "screenshot", "https://example.com/"]);
    assert!(out.status.success());
    assert_eq!(String::from_utf8_lossy(&out.stdout), "UE5HREFUQQ==");

    let out = run(&[]);
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(
        String::from_utf8_lossy(&out.stderr),
        "render: a url argument is required\n"
    );
}

#[test]
fn usage_and_unknown_subcommand() {
    let out = Proc::new(BIN).output().expect("run");
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("Usage:"));
    let out = Proc::new(BIN).arg("help").output().expect("run");
    assert_eq!(out.status.code(), Some(0));
    let out = Proc::new(BIN).arg("frobnicate").output().expect("run");
    assert_eq!(out.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&out.stderr)
            .starts_with("runeward-browser: unknown subcommand \"frobnicate\"\n")
    );
    let out = Proc::new(BIN).args(["serve"]).output().expect("run");
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(
        String::from_utf8_lossy(&out.stderr),
        "serve: --socket is required\n"
    );
}
