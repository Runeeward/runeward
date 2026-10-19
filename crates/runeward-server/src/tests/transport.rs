//! Loopback tests over real sockets: WebSockets, SSE, TLS and `serve`.

use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use runeward_controlplane::{Manager, StartAgentSessionOptions};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;

use super::support::*;
use crate::{ServeError, Server, ServerConfig, TlsPaths, is_loopback_host};

/// Serves a configured router on a loopback port; returns `host:port`.
pub(crate) async fn spawn_server(
    mgr: Arc<Manager>,
    configure: impl FnOnce(Server) -> Server,
) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr").to_string();
    let router = configure(Server::new(mgr).rate_limit(None)).router();
    tokio::spawn(crate::listen::run(
        listener,
        router,
        None,
        std::future::pending(),
    ));
    addr
}

/// Sends a raw HTTP/1.1 request and returns (status, headers+body text).
async fn raw<S: AsyncRead + AsyncWrite + Unpin>(mut s: S, request: String) -> (u16, String) {
    s.write_all(request.as_bytes()).await.expect("write");
    let mut out = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(30), s.read_to_end(&mut out)).await;
    let text = String::from_utf8_lossy(&out).into_owned();
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    (status, text)
}

async fn http(addr: &str, method: &str, path: &str, headers: &str, body: &str) -> (u16, String) {
    let s = tokio::net::TcpStream::connect(addr).await.expect("connect");
    raw(
        s,
        format!(
            "{method} {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\nContent-Length: {}\r\n{headers}\r\n{body}",
            body.len()
        ),
    )
    .await
}

fn body_json(text: &str) -> serde_json::Value {
    let body = text
        .split_once("\r\n\r\n")
        .map(|(_, b)| b)
        .unwrap_or_default();
    serde_json::from_str(body).unwrap_or(serde_json::Value::Null)
}

/// Mints a ticket on a live server.
pub(crate) async fn mint(addr: &str, token: &str, body: &str) -> String {
    let (status, text) = http(
        addr,
        "POST",
        "/v1/tickets",
        &format!("Authorization: Bearer {token}\r\nContent-Type: application/json\r\n"),
        body,
    )
    .await;
    assert_eq!(status, 201, "{text}");
    body_json(&text)["ticket"]
        .as_str()
        .unwrap_or_default()
        .to_owned()
}

fn ws_request(
    url: &str,
    origin: Option<&str>,
) -> tokio_tungstenite::tungstenite::handshake::client::Request {
    let mut r = url.into_client_request().expect("request");
    if let Some(o) = origin {
        r.headers_mut().insert("origin", o.parse().expect("origin"));
    }
    r
}

#[tokio::test]
async fn terminal_websocket_bridges_the_pty() {
    let h = harness().await;
    h.inject("cit-1", "parity", "").await;
    let addr = spawn_server(Arc::clone(&h.mgr), |s| s.token("s3cret")).await;

    // Long-lived tokens never work in the URL; tickets do, once.
    let url = format!("ws://{addr}/v1/citadels/cit-1/terminal?token=s3cret");
    assert!(
        tokio_tungstenite::connect_async(ws_request(&url, None))
            .await
            .is_err()
    );

    let ticket = mint(&addr, "s3cret", r#"{"sandbox_id":"cit-1"}"#).await;
    let url = format!("ws://{addr}/v1/citadels/cit-1/terminal?ticket={ticket}");
    let origin = format!("http://{addr}");
    let (mut ws, _) = tokio_tungstenite::connect_async(ws_request(&url, Some(&origin)))
        .await
        .expect("dial");
    ws.send(WsMessage::Text(
        r#"{"type":"resize","rows":40,"cols":120}"#.into(),
    ))
    .await
    .expect("resize");
    ws.send(WsMessage::Text("echo hi\n".into()))
        .await
        .expect("send");
    let echoed = tokio::time::timeout(Duration::from_secs(30), ws.next())
        .await
        .expect("timely")
        .expect("frame")
        .expect("message");
    assert_eq!(
        echoed.into_data().as_ref(),
        b"echo hi\n",
        "resize frames are not input"
    );
    ws.close(None).await.expect("close");

    let events = {
        let ledger = h.mgr.ledger().clone();
        tokio::task::spawn_blocking(move || ledger.replay("cit-1"))
            .await
            .expect("join")
            .expect("replay")
    };
    assert!(
        events
            .iter()
            .any(|e| e.tool == "terminal" && e.action == "attach"),
        "terminal attach is audited"
    );

    // The used ticket is gone.
    let reused = tokio_tungstenite::connect_async(ws_request(&url, Some(&origin))).await;
    assert!(reused.is_err());
}

#[tokio::test]
async fn terminal_websocket_refuses_cross_origin() {
    let h = harness().await;
    h.inject("cit-1", "parity", "").await;
    let addr = spawn_server(Arc::clone(&h.mgr), |s| s).await;
    let url = format!("ws://{addr}/v1/citadels/cit-1/terminal");
    let err = tokio_tungstenite::connect_async(ws_request(&url, Some("https://evil.example")))
        .await
        .expect_err("cross-origin");
    match err {
        tokio_tungstenite::tungstenite::Error::Http(resp) => assert_eq!(resp.status(), 403),
        e => panic!("unexpected error {e}"),
    }
}

async fn next_msg<S>(ws: &mut tokio_tungstenite::WebSocketStream<S>) -> WsMessage
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    tokio::time::timeout(Duration::from_secs(30), ws.next())
        .await
        .expect("timely")
        .expect("frame")
        .expect("message")
}

#[tokio::test]
async fn conversation_stream_is_read_only() {
    let h = harness().await;
    h.inject("cit-1", "parity", "").await;
    h.mgr
        .publish_conversation("cit-1", "assistant", "earlier", "")
        .await
        .expect("publish");
    let addr = spawn_server(Arc::clone(&h.mgr), |s| s).await;
    let url = format!("ws://{addr}/v1/citadels/cit-1/conversation/stream");
    let (mut ws, _) = tokio_tungstenite::connect_async(ws_request(&url, None))
        .await
        .expect("dial");
    let first: serde_json::Value =
        serde_json::from_str(next_msg(&mut ws).await.to_text().expect("text")).expect("json");
    assert_eq!(first["content"], "earlier");
    assert_eq!(first["id"], 1);
    h.mgr
        .publish_conversation("cit-1", "assistant", "live", "")
        .await
        .expect("publish");
    let live: serde_json::Value =
        serde_json::from_str(next_msg(&mut ws).await.to_text().expect("text")).expect("json");
    assert_eq!(live["content"], "live");
    ws.send(WsMessage::Text("hijack".into()))
        .await
        .expect("send");
    match next_msg(&mut ws).await {
        WsMessage::Close(Some(f)) => {
            assert_eq!(f.code, CloseCode::Policy);
            assert_eq!(f.reason.as_str(), "read-only stream");
        }
        m => panic!("expected close, got {m:?}"),
    }
}

#[tokio::test]
async fn agent_session_events_and_stream() {
    let h = harness().await;
    h.inject("cit-1", "parity", "").await;
    let started = h
        .mgr
        .start_agent_session(
            "cit-1",
            StartAgentSessionOptions {
                command: vec!["echo".into(), "hi".into()],
                ..StartAgentSessionOptions::default()
            },
        )
        .await
        .expect("start");
    for _ in 0..600 {
        if h.mgr
            .agent_session(&started.id)
            .is_some_and(|a| a.status.is_terminal())
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let addr = spawn_server(Arc::clone(&h.mgr), |s| s).await;
    let (status, text) = http(
        &addr,
        "GET",
        &format!("/v1/agent-sessions/{}/events", started.id),
        "",
        "",
    )
    .await;
    assert_eq!(status, 200, "{text}");
    let v = body_json(&text);
    assert_eq!(v["session"]["id"], started.id.as_str());
    assert!(v["events"].as_array().is_some_and(|e| !e.is_empty()), "{v}");

    let (status, text) = http(
        &addr,
        "GET",
        &format!("/v1/agent-sessions/{}/stream", started.id),
        "",
        "",
    )
    .await;
    assert_eq!(status, 200, "{text}");
    assert!(
        text.to_ascii_lowercase()
            .contains("content-type: text/event-stream")
    );
    assert!(text.contains("event: agent-output\ndata: {"), "{text}");
    assert!(text.contains("id: 1\n"), "{text}");

    // Last-Event-ID resumes after the given sequence.
    let (_, resumed) = http(
        &addr,
        "GET",
        &format!("/v1/agent-sessions/{}/stream", started.id),
        "Last-Event-ID: 1\r\n",
        "",
    )
    .await;
    assert!(!resumed.contains("id: 1\n"), "{resumed}");
}

#[tokio::test]
async fn tls_serves_https_with_ring() {
    let dir = tempfile::tempdir().expect("tempdir");
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".into()]).expect("cert");
    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");
    std::fs::write(&cert_path, ck.cert.pem()).expect("write cert");
    std::fs::write(&key_path, ck.signing_key.serialize_pem()).expect("write key");

    let h = harness().await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let acceptor = crate::tls_acceptor(&cert_path, &key_path).expect("acceptor");
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let cfg = ServerConfig {
        no_ui: true,
        ..ServerConfig::default()
    };
    let server = tokio::spawn(crate::serve_listener(
        cfg,
        Arc::clone(&h.mgr),
        listener,
        Some(acceptor),
        async move {
            let _ = stop_rx.await;
        },
    ));

    let mut roots = rustls::RootCertStore::empty();
    roots.add(ck.cert.der().clone()).expect("root");
    let client = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("versions")
    .with_root_certificates(roots)
    .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client));
    let tcp = tokio::net::TcpStream::connect(addr).await.expect("connect");
    let name = rustls::pki_types::ServerName::try_from("localhost").expect("name");
    let tls = connector.connect(name, tcp).await.expect("handshake");
    let (status, text) = raw(
        tls,
        "GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".into(),
    )
    .await;
    assert_eq!(status, 200, "{text}");
    assert!(text.contains(r#"{"status":"ok"}"#));

    // Plain HTTP on the TLS port fails the handshake.
    let (status, _) = http(&addr.to_string(), "GET", "/healthz", "", "").await;
    assert_eq!(status, 0);

    let _ = stop_tx.send(());
    tokio::time::timeout(Duration::from_secs(30), server)
        .await
        .expect("graceful shutdown")
        .expect("join");
}

#[tokio::test]
async fn serve_binds_and_shuts_down() {
    let h = harness().await;
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let cfg = ServerConfig {
        port: 0,
        ..ServerConfig::default()
    };
    let task = tokio::spawn(crate::serve(cfg, Arc::clone(&h.mgr), async move {
        let _ = stop_rx.await;
    }));
    tokio::time::sleep(Duration::from_millis(100)).await;
    let _ = stop_tx.send(());
    let res = tokio::time::timeout(Duration::from_secs(30), task)
        .await
        .expect("timely")
        .expect("join");
    assert!(res.is_ok(), "{res:?}");

    let bad = ServerConfig {
        tls: Some(TlsPaths {
            cert: "/nonexistent/cert.pem".into(),
            key: "/nonexistent/key.pem".into(),
        }),
        ..ServerConfig::default()
    };
    let err = crate::serve(bad, Arc::clone(&h.mgr), async {})
        .await
        .expect_err("tls");
    assert!(matches!(err, ServeError::Tls(_)), "{err}");
}

#[test]
fn exposure_rules_match_go() {
    let base = ServerConfig::default();
    assert!(base.validate().is_ok(), "loopback without auth");
    for host in ["127.0.0.1", "::1", "localhost"] {
        assert!(is_loopback_host(host), "{host}");
    }
    for host in ["", "0.0.0.0", "10.0.0.1", "example.com"] {
        assert!(!is_loopback_host(host), "{host}");
    }

    let open = ServerConfig {
        bind: "0.0.0.0".into(),
        ..ServerConfig::default()
    };
    assert_eq!(
        open.validate().expect_err("no auth").to_string(),
        "refusing to bind 0.0.0.0 without authentication: set --token / RUNEWARD_API_TOKEN, configure RUNEWARD_AUTHZ_FILE, or bind 127.0.0.1"
    );
    let short = ServerConfig {
        token: "short".into(),
        ..open.clone()
    };
    assert_eq!(
        short.validate().expect_err("short").to_string(),
        "refusing network bind with an API token shorter than 32 characters"
    );
    let plain = ServerConfig {
        token: "x".repeat(32),
        ..open.clone()
    };
    assert_eq!(
        plain.validate().expect_err("plaintext").to_string(),
        "refusing plaintext HTTP on non-loopback bind 0.0.0.0: configure --tls-cert/--tls-key or explicitly pass --allow-insecure-http behind a trusted TLS proxy"
    );
    let insecure = ServerConfig {
        allow_insecure_http: true,
        ..plain.clone()
    };
    assert!(insecure.validate().is_ok());
    let tls = ServerConfig {
        tls: Some(TlsPaths {
            cert: "c".into(),
            key: "k".into(),
        }),
        ..plain
    };
    assert!(tls.validate().is_ok());

    let weak = runeward_authz::Store::from_principals(vec![runeward_authz::Principal {
        name: "a".into(),
        token: "short-token".into(),
        ..runeward_authz::Principal::default()
    }])
    .expect("store");
    let rbac = ServerConfig {
        authz: Some(Arc::new(weak)),
        allow_insecure_http: true,
        ..open
    };
    assert!(
        rbac.validate().is_err(),
        "RBAC tokens must be long on a network bind"
    );

    assert!(TlsPaths::from_flags(Some("c".into()), None).is_err());
    assert_eq!(TlsPaths::from_flags(None, None).expect("none"), None);
    assert_eq!(
        ServerConfig {
            bind: "::1".into(),
            port: 80,
            ..ServerConfig::default()
        }
        .addr(),
        "[::1]:80"
    );
}
