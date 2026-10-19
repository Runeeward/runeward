//! Ports of Go `internal/server/ide_test.go`.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::extract::ConnectInfo;
use axum::extract::ws::{Message, WebSocketUpgrade};
use axum::http::{Extensions, HeaderMap, HeaderValue};
use axum::routing::get as get_route;
use futures_util::StreamExt;
use runeward_charter::{Charter, Ide};

use super::support::*;
use crate::auth::TlsConnection;
use crate::state::AppState;

async fn ide_harness() -> Harness {
    harness_with(|c| c.experimental_ide = true, |_| {}).await
}

fn inject_ide(h: &Harness, id: &str, endpoint: &str, owner: &str) {
    let charter = Charter {
        name: "ide-demo".into(),
        ide: Ide {
            enabled: true,
            port: 8080,
            ..Ide::default()
        },
        ..Charter::default()
    };
    h.inject_charter(id, charter, owner);
    h.mgr.set_ide_endpoint_for_test(id, endpoint);
}

/// Serves `router` on a loopback port and returns `host:port`.
async fn spawn_upstream(router: Router) -> String {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = l.local_addr().expect("addr");
    tokio::spawn(async move {
        let _ = axum::serve(l, router).await;
    });
    addr.to_string()
}

fn http_upstream() -> Router {
    Router::new().route(
        "/",
        get_route(|headers: HeaderMap| async move {
            // Outer credentials never reach code-server.
            assert!(headers.get("authorization").is_none());
            assert!(
                headers
                    .get("cookie")
                    .and_then(|c| c.to_str().ok())
                    .is_none_or(|c| !c.contains("rw_ide_sess"))
            );
            (
                [
                    ("content-type", "text/plain"),
                    ("set-cookie", "cs=1; Path=/"),
                ],
                "ide-ok",
            )
        }),
    )
}

#[tokio::test]
async fn ide_ticket_single_use_and_proxy() {
    let host = spawn_upstream(http_upstream()).await;
    let h = ide_harness().await;
    inject_ide(&h, "ide1", &host, "");
    let r = router_with_token(&h, "s3cret");

    let mint = post(
        &r,
        "/v1/tickets",
        Some("s3cret"),
        r#"{"kind":"ide","sandbox_id":"ide1"}"#,
    )
    .await;
    assert_eq!(mint.status, 201, "{}", mint.text());
    let ticket = mint.json()["ticket"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    assert!(!ticket.is_empty());

    let uri = format!("/v1/citadels/ide1/ide/?ticket={ticket}");
    let first = get(&r, &uri, None).await;
    assert_eq!(first.status, 200, "{}", first.text());
    assert!(first.text().contains("ide-ok"));
    let cookies: Vec<String> = first
        .headers
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok().map(str::to_owned))
        .collect();
    let session = cookies
        .iter()
        .find(|c| c.starts_with("rw_ide_sess="))
        .cloned()
        .unwrap_or_else(|| panic!("expected IDE session cookie, got {cookies:?}"));
    assert!(
        cookies
            .iter()
            .any(|c| c == "cs=1; Path=/v1/citadels/ide1/ide/"),
        "upstream cookie re-rooted: {cookies:?}"
    );

    assert_eq!(get(&r, &uri, None).await.status, 401, "ticket reuse");

    let pair = session.split(';').next().unwrap_or_default().to_owned();
    let by_cookie = send(
        &r,
        req("GET", "/v1/citadels/ide1/ide/", &[("cookie", &pair)], None),
    )
    .await;
    assert_eq!(by_cookie.status, 200, "{}", by_cookie.text());

    // The cookie is bound to its Citadel.
    inject_ide(&h, "ide2", &host, "");
    let other = send(
        &r,
        req("GET", "/v1/citadels/ide2/ide/", &[("cookie", &pair)], None),
    )
    .await;
    assert_eq!(other.status, 401);

    // A bearer token works too; an upstream 404 is passed through.
    let missing = get(&r, "/v1/citadels/ide1/ide/missing", Some("s3cret")).await;
    assert_eq!(missing.status, 404);
}

#[tokio::test]
async fn ide_proxy_redirect_and_secure_cookie() {
    let h = ide_harness().await;
    inject_ide(&h, "ide1", "127.0.0.1:8080", "");
    let r = router_with_token(&h, "s3cret");
    let resp = send(
        &r,
        req(
            "GET",
            "/v1/citadels/ide1/ide",
            &[
                ("authorization", "Bearer s3cret"),
                ("host", "runeward.example"),
            ],
            None,
        ),
    )
    .await;
    assert_eq!(resp.status, 307);
    assert_eq!(resp.header("location"), "/v1/citadels/ide1/ide/");

    let state = test_state(&h);
    let cookie = |headers: &HeaderMap, ext: &Extensions, host: &str| {
        state
            .attach_ide_session(headers, ext, host, "ide1", None)
            .and_then(|v| v.to_str().ok().map(str::to_owned))
            .unwrap_or_default()
    };
    let hardened = |c: &str| c.contains("; HttpOnly") && c.contains("; SameSite=Strict");

    // TLS keeps the session cookie Secure.
    let mut tls = Extensions::new();
    tls.insert(TlsConnection);
    let c = cookie(&HeaderMap::new(), &tls, "runeward.example");
    assert!(c.contains("; Secure") && hardened(&c), "{c}");
    assert!(c.contains("; Path=/v1/citadels/ide1/ide;"), "{c}");

    // Loopback HTTP omits Secure, or browsers reject the cookie.
    let mut loopback = Extensions::new();
    loopback.insert(ConnectInfo(
        "127.0.0.1:43210".parse::<SocketAddr>().expect("addr"),
    ));
    let c = cookie(&HeaderMap::new(), &loopback, "127.0.0.1:8080");
    assert!(!c.contains("Secure") && hardened(&c), "{c}");

    // A remote peer cannot get a non-Secure cookie by spoofing Host.
    let mut remote = Extensions::new();
    remote.insert(ConnectInfo(
        "198.51.100.25:43210".parse::<SocketAddr>().expect("addr"),
    ));
    let c = cookie(&HeaderMap::new(), &remote, "127.0.0.1:8080");
    assert!(c.contains("; Secure"), "{c}");

    // Forwarded HTTPS stays Secure.
    let mut fwd = HeaderMap::new();
    fwd.insert("x-forwarded-proto", HeaderValue::from_static("https"));
    let c = cookie(&fwd, &loopback, "127.0.0.1:8080");
    assert!(c.contains("; Secure"), "{c}");
}

fn test_state(h: &Harness) -> AppState {
    AppState {
        mgr: h.mgr.clone(),
        token: String::new(),
        authz: None,
        dashboard: false,
        version: String::new(),
        limiter: None,
        principal_limiter: None,
        tickets: Default::default(),
        ide_sessions: Default::default(),
        ide_client: crate::handlers::ide::proxy_client(),
    }
}

#[tokio::test]
async fn ide_disabled_without_flag() {
    let h = harness().await;
    inject_ide(&h, "ide1", "127.0.0.1:9", "");
    let r = router_with_token(&h, "s3cret");
    let resp = post(&r, "/v1/citadels/ide1/ide-ticket", Some("s3cret"), "").await;
    assert_eq!(resp.status, 404);
    let resp = get(&r, "/v1/citadels/ide1/ide/", Some("s3cret")).await;
    assert_eq!(resp.status, 404);
}

#[tokio::test]
async fn ide_ticket_endpoint_and_unavailable_upstream() {
    let h = ide_harness().await;
    // Nothing listens on the discard port: the proxy answers 502.
    inject_ide(&h, "ide1", "127.0.0.1:9", "");
    let r = router_with_token(&h, "s3cret");
    let mint = post(&r, "/v1/citadels/ide1/ide-ticket", Some("s3cret"), "").await;
    assert_eq!(mint.status, 201, "{}", mint.text());
    let ticket = mint.json()["ticket"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    let resp = get(&r, &format!("/v1/citadels/ide1/ide/?ticket={ticket}"), None).await;
    assert_eq!(resp.status, 502);
    assert_eq!(resp.json()["error"], "ide upstream unavailable");
    let missing = post(&r, "/v1/citadels/nope/ide-ticket", Some("s3cret"), "").await;
    assert_eq!(missing.status, 404);
}

#[tokio::test]
async fn ide_proxy_rejects_foreign_owner() {
    let host = spawn_upstream(Router::new().route("/", get_route(|| async { "secret" }))).await;
    let h = ide_harness().await;
    inject_ide(&h, "ide-alice", &host, "alice");
    let store = authz_store(
        h.dir.path(),
        r#"{"principals":[
            {"name":"alice","token":"tok-alice","allowed_profiles":["*"]},
            {"name":"bob","token":"tok-bob","allowed_profiles":["*"]}
        ]}"#,
    );
    let r = server(&h).authz(Some(store)).router();
    let body = r#"{"kind":"ide","sandbox_id":"ide-alice"}"#;
    assert_eq!(
        post(&r, "/v1/tickets", Some("tok-bob"), body).await.status,
        404
    );
    let mint = post(&r, "/v1/tickets", Some("tok-alice"), body).await;
    assert_eq!(mint.status, 201, "{}", mint.text());
    let ticket = mint.json()["ticket"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    let used = get(
        &r,
        &format!("/v1/citadels/ide-alice/ide/?ticket={ticket}"),
        None,
    )
    .await;
    assert_eq!(used.status, 200, "{}", used.text());
    let bob = get(&r, "/v1/citadels/ide-alice/ide/", Some("tok-bob")).await;
    assert_eq!(bob.status, 404);
}

#[tokio::test]
async fn ide_websocket_upgrade() {
    let upstream = Router::new().route(
        "/",
        get_route(|ws: WebSocketUpgrade| async move {
            ws.on_upgrade(|mut socket| async move {
                let _ = socket.send(Message::Text("pong".into())).await;
            })
        }),
    );
    let host = spawn_upstream(upstream).await;
    let h = ide_harness().await;
    inject_ide(&h, "ide-ws", &host, "");
    let addr = super::transport::spawn_server(Arc::clone(&h.mgr), |s| s.token("s3cret")).await;
    let ticket =
        super::transport::mint(&addr, "s3cret", r#"{"kind":"ide","sandbox_id":"ide-ws"}"#).await;
    let url = format!("ws://{addr}/v1/citadels/ide-ws/ide/?ticket={ticket}");
    let mut request =
        tokio_tungstenite::tungstenite::client::IntoClientRequest::into_client_request(url)
            .expect("request");
    request.headers_mut().insert(
        "origin",
        HeaderValue::from_str(&format!("http://{addr}")).expect("origin"),
    );
    let (mut ws, _) = tokio_tungstenite::connect_async(request)
        .await
        .expect("dial");
    let msg = ws.next().await.expect("message").expect("frame");
    assert_eq!(msg.into_text().expect("text").as_str(), "pong");
}
