//! The streamable-HTTP transport, in process: the mountable router driven
//! through tower, and `serve_http_on` over loopback TCP (plain and TLS).

#![allow(clippy::unwrap_used)]

mod support;

use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use http::{HeaderMap, Request, StatusCode};
use http_body_util::BodyExt;
use runeward_authz::Store;
use runeward_mcp::{Error, HttpConfig, McpConfig, router, serve_http, serve_http_on};
use serde_json::{Value, json};
use support::{Harness, principal, store};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tower::ServiceExt;

const PROTOCOL: &str = "2025-06-18";

fn team_store() -> Arc<Store> {
    store(vec![
        principal("alice", "team-alpha", "token-alice", &["dev"]),
        principal("eve", "team-other", "token-eve", &["dev"]),
    ])
}

struct Reply {
    status: StatusCode,
    headers: HeaderMap,
    body: String,
}

impl Reply {
    /// The JSON-RPC message with `id` from a JSON or SSE body.
    fn message(&self, id: i64) -> Value {
        let candidates: Vec<&str> = if self.body.trim_start().starts_with('{') {
            vec![self.body.as_str()]
        } else {
            self.body
                .lines()
                .filter_map(|l| l.strip_prefix("data:"))
                .map(str::trim)
                .collect()
        };
        candidates
            .into_iter()
            .filter_map(|c| serde_json::from_str::<Value>(c).ok())
            .find(|v| v["id"] == id)
            .unwrap_or_else(|| panic!("no message {id} in {:?}", self.body))
    }
}

async fn post(app: &Router, body: Value, headers: &[(&str, &str)]) -> Reply {
    let mut req = Request::post("/mcp")
        .header("host", "localhost")
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream");
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    let req = req.body(Body::from(body.to_string())).unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let headers = res.headers().clone();
    let body = tokio::time::timeout(Duration::from_secs(10), res.into_body().collect())
        .await
        .expect("body completes")
        .unwrap()
        .to_bytes();
    Reply {
        status,
        headers,
        body: String::from_utf8_lossy(&body).into_owned(),
    }
}

fn initialize() -> Value {
    json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": PROTOCOL,
        "capabilities": {},
        "clientInfo": {"name": "test", "version": "0"}
    }})
}

/// Initializes a session and calls one tool, returning the tool result.
async fn call_tool(app: &Router, auth: &[(&str, &str)], tool: &str, args: Value) -> Value {
    let init = post(app, initialize(), auth).await;
    assert_eq!(init.status, StatusCode::OK, "{}", init.body);
    assert_eq!(init.message(1)["result"]["serverInfo"]["name"], "runeward");
    let session = init
        .headers
        .get("mcp-session-id")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    let mut headers = auth.to_vec();
    headers.push(("mcp-session-id", &session));
    headers.push(("mcp-protocol-version", PROTOCOL));
    let ack = post(
        app,
        json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        &headers,
    )
    .await;
    assert_eq!(ack.status, StatusCode::ACCEPTED, "{}", ack.body);
    let res = post(
        app,
        json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
               "params": {"name": tool, "arguments": args}}),
        &headers,
    )
    .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    res.message(2)["result"].clone()
}

fn result_json(result: &Value) -> Value {
    serde_json::from_str(result["content"][0]["text"].as_str().unwrap()).unwrap()
}

#[tokio::test]
async fn rbac_router_identifies_each_request() {
    let h = Harness::new().await;
    h.inject("cit-a", "team-alpha", vec![]);
    let app = router(h.mgr.clone(), Some(team_store()), McpConfig::default());

    let res = post(&app, initialize(), &[]).await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED);
    assert_eq!(res.headers["www-authenticate"], "Bearer");
    let res = post(&app, initialize(), &[("authorization", "Bearer nope")]).await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED);

    let alice = [("authorization", "Bearer token-alice")];
    let who = result_json(&call_tool(&app, &alice, "runeward_whoami", json!({})).await);
    assert_eq!(who["principal"]["name"], "alice");
    assert_eq!(who["principal"]["tenant"], "team-alpha");

    let listed = result_json(&call_tool(&app, &alice, "runeward_list_citadels", json!({})).await);
    assert_eq!(listed["citadels"][0]["id"], "cit-a");
    assert_eq!(listed["citadels"][0]["isolation"], "container");

    let eve = [("authorization", "Bearer token-eve")];
    let res = call_tool(
        &app,
        &eve,
        "runeward_shell",
        json!({"sandbox": "cit-a", "command": ["id"]}),
    )
    .await;
    assert_eq!(res["isError"], true);
    assert_eq!(result_json(&res)["error"], "citadel not found");
    let last = h.records().await;
    assert!(last.iter().all(|e| e.tool != "shell"), "nothing executed");

    let res = call_tool(
        &app,
        &alice,
        "runeward_shell",
        json!({"sandbox": "cit-a", "command": ["echo", "hi"]}),
    )
    .await;
    assert_eq!(result_json(&res)["stdout"], "echo hi");
    let ev = h.records().await.pop().unwrap();
    assert_eq!(ev.meta["actor"], "alice");
}

#[tokio::test]
async fn legacy_shared_token_gates_the_endpoint() {
    let h = Harness::new().await;
    let token = "t".repeat(40);
    let config = McpConfig {
        token: token.clone(),
        ..McpConfig::default()
    };
    let app = router(h.mgr.clone(), None, config);
    let res = post(&app, initialize(), &[]).await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED);
    let res = post(&app, initialize(), &[("x-runeward-token", "wrong")]).await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED);

    let bearer = format!("Bearer {token}");
    let auth = [("authorization", bearer.as_str())];
    let who = result_json(&call_tool(&app, &auth, "runeward_whoami", json!({})).await);
    assert_eq!(who["principal"]["name"], "mcp-http");
    assert_eq!(who["rbac"], false);

    // As in Go, X-Runeward-Token passes the gate but tool calls still need
    // a bearer header.
    let alt = [("x-runeward-token", token.as_str())];
    let res = call_tool(&app, &alt, "runeward_whoami", json!({})).await;
    assert_eq!(
        result_json(&res),
        json!({"code": "authz_denied", "error": "missing bearer token"})
    );
}

#[tokio::test]
async fn host_header_is_validated_by_default() {
    let h = Harness::new().await;
    let app = router(h.mgr.clone(), None, McpConfig::default());
    let req = Request::post("/mcp")
        .header("host", "evil.example")
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .body(Body::from(initialize().to_string()))
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert!(res.status().is_client_error(), "{}", res.status());

    let open = router(
        h.mgr.clone(),
        None,
        McpConfig {
            allowed_hosts: None,
            ..McpConfig::default()
        },
    );
    let req = Request::post("/mcp")
        .header("host", "evil.example")
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .body(Body::from(initialize().to_string()))
        .unwrap();
    assert_eq!(open.oneshot(req).await.unwrap().status(), StatusCode::OK);
}

#[tokio::test]
async fn serve_http_refuses_unsafe_binds_before_binding() {
    let h = Harness::new().await;
    let config = HttpConfig {
        bind: "0.0.0.0".into(),
        port: 1,
        token: Some("short".into()),
        ..HttpConfig::default()
    };
    let err = serve_http(config, h.mgr.clone(), async {})
        .await
        .expect_err("refused");
    assert!(matches!(err, Error::Config(_)), "{err}");
    assert_eq!(
        err.to_string(),
        "refusing network bind with an API token shorter than 32 characters"
    );
}

/// Sends an initialize over a raw HTTP/1.1 connection and returns the
/// response head and body seen before the result arrives.
async fn raw_initialize<S: AsyncRead + AsyncWrite + Unpin>(mut io: S, port: u16) -> String {
    let body = initialize().to_string();
    let req = format!(
        "POST /mcp HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/json\r\nAccept: application/json, text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    io.write_all(req.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let read = async {
        loop {
            let n = io.read(&mut chunk).await.unwrap_or(0);
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
            if String::from_utf8_lossy(&buf).contains("serverInfo") {
                break;
            }
        }
    };
    tokio::time::timeout(Duration::from_secs(10), read)
        .await
        .expect("response");
    String::from_utf8_lossy(&buf).into_owned()
}

#[tokio::test]
async fn serve_http_on_loopback_and_shuts_down() {
    let h = Harness::new().await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(serve_http_on(
        listener,
        HttpConfig::default(),
        h.mgr.clone(),
        async {
            let _ = stopped.await;
        },
    ));
    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    let resp = raw_initialize(tcp, port).await;
    assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
    assert!(resp.contains("\"name\":\"runeward\""), "{resp}");
    stop.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(10), server)
        .await
        .expect("server stops")
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn serve_http_on_tls() {
    use rustls::pki_types::{CertificateDer, ServerName};

    let h = Harness::new().await;
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let (cert_path, key_path) = (dir.path().join("cert.pem"), dir.path().join("key.pem"));
    std::fs::write(&cert_path, cert.cert.pem()).unwrap();
    std::fs::write(&key_path, cert.signing_key.serialize_pem()).unwrap();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let config = HttpConfig {
        tls_cert: Some(cert_path),
        tls_key: Some(key_path),
        ..HttpConfig::default()
    };
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(serve_http_on(listener, config, h.mgr.clone(), async {
        let _ = stopped.await;
    }));

    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from(cert.cert.der().to_vec()))
        .unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let client = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client));
    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    let tls = connector
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await
        .unwrap();
    let resp = raw_initialize(tls, port).await;
    assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
    stop.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(10), server)
        .await
        .expect("server stops")
        .unwrap()
        .unwrap();

    let bad = HttpConfig {
        tls_cert: Some(dir.path().join("missing.pem")),
        tls_key: Some(dir.path().join("missing.pem")),
        ..HttpConfig::default()
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let err = serve_http_on(listener, bad, h.mgr.clone(), async {})
        .await
        .expect_err("bad tls");
    assert!(matches!(err, Error::Tls(_)), "{err}");
}
