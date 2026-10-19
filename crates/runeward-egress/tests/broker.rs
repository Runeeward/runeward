//! Request broker behaviour against loopback upstreams: TLS interception with
//! the per-sandbox CA, request rules, budgets, audit mode, approval, and
//! credential placeholders. No network beyond 127.0.0.1.

mod common;

use std::collections::HashMap;
use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use bytes::Bytes;
use common::{policy, rule, start_proxy};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::header::HeaderValue;
use hyper::{HeaderMap, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use runeward_charter::{Credential, Endpoint, RequestRule};
use runeward_egress::resolve::StaticResolver;
use runeward_egress::{
    ApprovalFuture, ApprovalHook, ApprovalOutcome, ApprovalRequest, Broker, Decision, Proxy,
    ReasonCode, TransparentProxy, Verdict, list_decisions,
};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

const SECRET: &str = "s3cr3t-value";
const NAMES: [&str; 9] = [
    "api.test",
    "h.test",
    "q.test",
    "b.test",
    "mcp.test",
    "ws.test",
    "audit.test",
    "other.test",
    "raw.test",
];

// ---------------------------------------------------------------- upstreams

/// What an origin saw.
#[derive(Debug)]
struct Seen {
    method: String,
    uri: String,
    headers: HeaderMap,
    body: String,
}

struct TestCa {
    server: Arc<rustls::ServerConfig>,
    client: Arc<rustls::ClientConfig>,
}

/// A self-signed upstream certificate for every test hostname, plus a
/// client config (for the broker's upstream side) trusting it.
fn test_ca() -> TestCa {
    let names: Vec<String> = NAMES.iter().map(|s| s.to_string()).collect();
    let cert = rcgen::generate_simple_self_signed(names).expect("cert");
    let der = CertificateDer::from(cert.cert.der().to_vec());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let server = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("versions")
        .with_no_client_auth()
        .with_single_cert(vec![der.clone()], key)
        .expect("server config");
    let mut roots = rustls::RootCertStore::empty();
    roots.add(der).expect("root");
    TestCa {
        server: Arc::new(server),
        client: Arc::new(runeward_egress::proxy::tls_client_config(roots)),
    }
}

async fn origin_service(
    mut req: Request<Incoming>,
    tx: mpsc::UnboundedSender<Seen>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    if req.headers().contains_key(hyper::header::UPGRADE) {
        let up = hyper::upgrade::on(&mut req);
        tokio::spawn(async move {
            if let Ok(u) = up.await {
                let mut io = TokioIo::new(u);
                let mut buf = [0u8; 64];
                if let Ok(n) = io.read(&mut buf).await {
                    let _ = io.write_all(&buf[..n]).await;
                }
            }
        });
        let mut resp = Response::new(Full::new(Bytes::new()));
        *resp.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
        resp.headers_mut()
            .insert("upgrade", HeaderValue::from_static("websocket"));
        resp.headers_mut()
            .insert("connection", HeaderValue::from_static("upgrade"));
        return Ok(resp);
    }
    let (parts, body) = req.into_parts();
    let body = body
        .collect()
        .await
        .map(|c| c.to_bytes())
        .unwrap_or_default();
    let auth = parts
        .headers
        .get("authorization")
        .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned())
        .unwrap_or_default();
    let _ = tx.send(Seen {
        method: parts.method.to_string(),
        uri: parts.uri.to_string(),
        headers: parts.headers.clone(),
        body: String::from_utf8_lossy(&body).into_owned(),
    });
    // Echo the credential back, as a careless API or error page might.
    let mut resp = Response::new(Full::new(Bytes::from(format!(
        "{{\"uri\":\"{}\",\"auth\":\"{auth}\"}}",
        parts.uri
    ))));
    if let Ok(v) = HeaderValue::from_str(&auth) {
        resp.headers_mut().insert("x-echo-auth", v);
    }
    Ok(resp)
}

/// An HTTP/1.1 origin (TLS when `tls` is set) recording every request.
async fn start_origin(
    tls: Option<Arc<rustls::ServerConfig>>,
) -> (SocketAddr, mpsc::UnboundedReceiver<Seen>) {
    let ln = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = ln.local_addr().expect("addr");
    let (tx, rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = ln.accept().await {
            let tx = tx.clone();
            let tls = tls.clone();
            tokio::spawn(async move {
                let svc = hyper::service::service_fn(move |req| origin_service(req, tx.clone()));
                let b = hyper::server::conn::http1::Builder::new();
                match tls {
                    Some(cfg) => {
                        if let Ok(s) = tokio_rustls::TlsAcceptor::from(cfg).accept(tcp).await {
                            let _ = b
                                .serve_connection(TokioIo::new(s), svc)
                                .with_upgrades()
                                .await;
                        }
                    }
                    None => {
                        let _ = b
                            .serve_connection(TokioIo::new(tcp), svc)
                            .with_upgrades()
                            .await;
                    }
                }
            });
        }
    });
    (addr, rx)
}

// ------------------------------------------------------------------ charter

fn endpoint(name: &str, host: &str, port: u16, protocol: &str) -> Endpoint {
    Endpoint {
        name: name.into(),
        host: host.into(),
        port,
        protocol: protocol.into(),
        ..Endpoint::default()
    }
}

fn allow(method: &str, path: &str, tool: &str, effect: &str) -> RequestRule {
    RequestRule {
        method: method.into(),
        path: path.into(),
        tool: tool.into(),
        effect: effect.into(),
        ..RequestRule::default()
    }
}

fn credential(name: &str, inject: &str) -> Credential {
    Credential {
        name: name.into(),
        source: format!("env://{}", name.to_uppercase()),
        placeholder_env: format!("{}_TOKEN", name.to_uppercase()),
        inject: inject.into(),
    }
}

fn broker(
    sandbox: &str,
    endpoints: Vec<Endpoint>,
    creds: Vec<Credential>,
    ca: &TestCa,
) -> Arc<Broker> {
    let values: HashMap<String, String> = creds
        .iter()
        .map(|c| (c.name.clone(), format!("{SECRET}-{}", c.name)))
        .collect();
    Arc::new(
        Broker::with_secret_values(sandbox, endpoints, creds, values)
            .expect("broker")
            .with_upstream_tls(Arc::clone(&ca.client)),
    )
}

fn loopback() -> Arc<StaticResolver> {
    Arc::new(StaticResolver::new(vec![
        "127.0.0.1".parse::<IpAddr>().expect("ip"),
    ]))
}

/// A default-deny proxy whose only reachable destinations are endpoints
/// (plus `extra` network rules).
async fn proxy_with(b: &Arc<Broker>, extra: Vec<runeward_egress::Rule>) -> SocketAddr {
    let p = Proxy::new(policy("deny", extra))
        .with_resolver(loopback())
        .with_broker(Arc::clone(b));
    let (addr, stop) = start_proxy(p).await;
    // Keep serving for the rest of the test.
    std::mem::forget(stop);
    addr
}

// ------------------------------------------------------------------- client

/// Opens a CONNECT tunnel; returns the status and the raw stream.
async fn connect(proxy: SocketAddr, authority: &str) -> (u16, TcpStream) {
    let mut s = TcpStream::connect(proxy).await.expect("connect");
    s.write_all(format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n").as_bytes())
        .await
        .expect("write");
    let mut br = BufReader::new(s);
    let head = common::read_head(&mut br).await.expect("head");
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .expect("status");
    (status, br.into_inner())
}

fn trusting(ca_pem: &str) -> Arc<rustls::ClientConfig> {
    let ca = CertificateDer::from_pem_slice(ca_pem.as_bytes()).expect("broker CA PEM");
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca).expect("root");
    Arc::new(runeward_egress::proxy::tls_client_config(roots))
}

struct Client {
    sender: hyper::client::conn::http1::SendRequest<Full<Bytes>>,
    host: String,
}

struct Resp {
    status: StatusCode,
    headers: HeaderMap,
    body: String,
}

impl Resp {
    fn json(&self) -> serde_json::Value {
        serde_json::from_str(&self.body).unwrap_or_else(|_| panic!("json: {}", self.body))
    }
}

impl Client {
    async fn over<IO>(io: IO, host: &str) -> Self
    where
        IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let (sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(io))
            .await
            .expect("handshake");
        tokio::spawn(async move {
            let _ = conn.with_upgrades().await;
        });
        Self {
            sender,
            host: host.into(),
        }
    }

    /// CONNECT through `proxy`, then TLS trusting the broker CA.
    async fn tls(proxy: SocketAddr, b: &Broker, host: &str, port: u16) -> Self {
        let authority = format!("{host}:{port}");
        let (status, tcp) = connect(proxy, &authority).await;
        assert_eq!(status, 200, "CONNECT {authority}");
        let tls = tokio_rustls::TlsConnector::from(trusting(b.ca_cert_pem()))
            .connect(ServerName::try_from(host.to_string()).expect("name"), tcp)
            .await
            .expect("client trusts the per-sandbox CA");
        Self::over(tls, &authority).await
    }

    async fn send(
        &mut self,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: &str,
    ) -> Resp {
        let mut req = Request::builder()
            .method(method)
            .uri(path)
            .header("host", &self.host);
        for (k, v) in headers {
            req = req.header(*k, *v);
        }
        let req = req
            .body(Full::new(Bytes::from(body.to_string())))
            .expect("request");
        self.sender.ready().await.expect("ready");
        let resp = self.sender.send_request(req).await.expect("response");
        let (parts, body) = resp.into_parts();
        let body = body.collect().await.expect("body").to_bytes();
        Resp {
            status: parts.status,
            headers: parts.headers,
            body: String::from_utf8_lossy(&body).into_owned(),
        }
    }

    async fn get(&mut self, path: &str) -> Resp {
        self.send("GET", path, &[], "").await
    }
}

fn last(sandbox: &str) -> Decision {
    list_decisions(sandbox).pop().expect("a decision")
}

fn assert_no_secret(sandbox: &str) {
    let all = serde_json::to_string(&list_decisions(sandbox)).expect("json");
    assert!(!all.contains(SECRET), "secret leaked into decisions: {all}");
}

fn mcp(method: &str, tool: Option<&str>) -> String {
    match tool {
        Some(t) => format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"{method}","params":{{"name":"{t}","arguments":{{}}}}}}"#
        ),
        None => format!(r#"{{"jsonrpc":"2.0","id":1,"method":"{method}"}}"#),
    }
}

// -------------------------------------------------------------------- tests

#[tokio::test]
async fn rest_rules_deny_wins_and_bearer_injection() {
    let ca = test_ca();
    let (origin, mut seen) = start_origin(Some(Arc::clone(&ca.server))).await;
    let port = origin.port();
    let mut ep = endpoint("github", "api.test", port, "rest");
    ep.credential = "gh".into();
    ep.binaries = vec!["/usr/bin/gh".into()];
    ep.allow = vec![
        allow("GET", "/repos/**", "", "read"),
        allow("POST", "/repos/*/issues", "", "write"),
    ];
    ep.deny = vec![RequestRule {
        path: "/repos/*/hooks/**".into(),
        reason: "webhooks are off limits".into(),
        ..RequestRule::default()
    }];
    let sb = "sb-broker-rest";
    let b = broker(sb, vec![ep], vec![credential("gh", "")], &ca);
    let placeholder = b.placeholder_env()["GH_TOKEN"].clone();
    let proxy = proxy_with(&b, vec![]).await;
    let mut c = Client::tls(proxy, &b, "api.test", port).await;

    // Allowed, with the placeholder swapped for the secret upstream and the
    // secret swapped back out of the response.
    let auth = format!("Bearer {placeholder}");
    let r = c
        .send(
            "GET",
            "/repos/acme/x?per_page=1",
            &[("authorization", &auth)],
            "",
        )
        .await;
    assert_eq!(r.status, 200, "{}", r.body);
    let s = seen.recv().await.expect("origin saw it");
    assert_eq!(s.uri, "/repos/acme/x?per_page=1");
    assert_eq!(
        s.headers.get("authorization").expect("auth"),
        &format!("Bearer {SECRET}-gh")
    );
    assert!(!r.body.contains(SECRET), "{}", r.body);
    assert!(r.body.contains(&placeholder), "{}", r.body);
    assert_eq!(
        r.headers.get("x-echo-auth").expect("echo"),
        &format!("Bearer {placeholder}")
    );
    let d = last(sb);
    assert_eq!(d.endpoint.as_deref(), Some("github"));
    assert_eq!(d.protocol.as_deref(), Some("rest"));
    assert_eq!(d.method.as_deref(), Some("GET"));
    assert_eq!(d.path.as_deref(), Some("/repos/acme/x"));
    assert_eq!(d.rule.as_deref(), Some("allow[0]"));
    assert_eq!(d.effect.as_deref(), Some("read"));
    assert_eq!(d.verdict, Some(Verdict::Allow));
    assert_eq!(d.reason_code, Some(ReasonCode::Allowed));
    assert_eq!(d.credential.as_deref(), Some("gh"));
    assert_eq!(d.binaries, Some(vec!["/usr/bin/gh".to_string()]));

    // No placeholder at all: the secret is attached anyway (same connection).
    let r = c.send("POST", "/repos/acme/issues", &[], "{}").await;
    assert_eq!(r.status, 200);
    let s = seen.recv().await.expect("seen");
    assert_eq!(s.method, "POST");
    assert_eq!(s.body, "{}");
    assert_eq!(
        s.headers.get("authorization").expect("auth"),
        &format!("Bearer {SECRET}-gh")
    );
    assert_eq!(last(sb).effect.as_deref(), Some("write"));

    // Deny wins over the matching allow rule.
    let r = c.get("/repos/acme/hooks/1").await;
    assert_eq!(r.status, 403);
    let j = r.json();
    assert_eq!(j["code"], "denied");
    assert_eq!(j["rule"], "deny[0]");
    assert_eq!(r.headers.get("x-runeward-decision").expect("hdr"), "denied");
    let d = last(sb);
    assert_eq!(d.reason, "webhooks are off limits");
    assert!(!d.allow);

    // No allow rule matched.
    let r = c.send("DELETE", "/repos/acme", &[], "").await;
    assert_eq!(r.status, 403);
    assert_eq!(last(sb).reason, "no allow rule matched");

    assert!(
        seen.try_recv().is_err(),
        "denied requests never reach upstream"
    );
    assert_no_secret(sb);
}

#[tokio::test]
async fn path_normalisation_attacks_are_refused() {
    let ca = test_ca();
    let (origin, mut seen) = start_origin(Some(Arc::clone(&ca.server))).await;
    let mut ep = endpoint("api", "api.test", origin.port(), "rest");
    ep.allow = vec![allow("GET", "/public/**", "", "read")];
    ep.deny = vec![allow("", "/public/admin/**", "", "")];
    let sb = "sb-broker-paths";
    let b = broker(sb, vec![ep], vec![], &ca);
    let proxy = proxy_with(&b, vec![]).await;
    let mut c = Client::tls(proxy, &b, "api.test", origin.port()).await;

    for path in [
        "/public/../admin/x",
        "/public/%2e%2e/admin",
        "/public%2Fadmin/x",
        "/public/admin%2fx",
        "/public//admin/x",
        "/public/./admin/x",
        "/public/%5c..%5cadmin",
    ] {
        let r = c.get(path).await;
        assert_eq!(r.status, 400, "{path}: {}", r.body);
        assert_eq!(r.json()["code"], "denied", "{path}");
    }
    // Percent-encoded ordinary characters are decoded before matching, so
    // the deny rule still applies.
    let r = c.get("/public/%61dmin/x").await;
    assert_eq!(r.status, 403, "{}", r.body);
    let r = c.get("/public/ok").await;
    assert_eq!(r.status, 200);
    assert_eq!(seen.recv().await.expect("seen").uri, "/public/ok");
    assert!(seen.try_recv().is_err());

    // Host header must match the tunnel's destination.
    let mut evil = Client::tls(proxy, &b, "api.test", origin.port()).await;
    evil.host = "other.test".into();
    let r = evil.get("/public/ok").await;
    assert_eq!(r.status, 400);
    assert!(last(sb).reason.contains("host header"), "{:?}", last(sb));
}

#[tokio::test]
async fn header_query_and_basic_injection() {
    let ca = test_ca();
    let (origin, mut seen) = start_origin(Some(Arc::clone(&ca.server))).await;
    let port = origin.port();
    let mk = |name: &str, host: &str, cred: &str| {
        let mut e = endpoint(name, host, port, "rest");
        e.credential = cred.into();
        e
    };
    let sb = "sb-broker-inject";
    let b = broker(
        sb,
        vec![
            mk("hdr", "h.test", "hk"),
            mk("qry", "q.test", "qk"),
            mk("bas", "b.test", "bk"),
        ],
        vec![
            credential("hk", "header:X-Api-Key"),
            credential("qk", "query:key"),
            credential("bk", "basic"),
        ],
        &ca,
    );
    let ph = b.placeholders();
    let proxy = proxy_with(&b, vec![]).await;

    let mut c = Client::tls(proxy, &b, "h.test", port).await;
    let r = c.send("GET", "/x", &[("x-api-key", &ph["hk"])], "").await;
    assert_eq!(r.status, 200);
    let s = seen.recv().await.expect("seen");
    assert_eq!(
        s.headers.get("x-api-key").expect("key"),
        &format!("{SECRET}-hk")
    );
    assert!(s.headers.get("authorization").is_none());

    let mut c = Client::tls(proxy, &b, "q.test", port).await;
    assert_eq!(c.get(&format!("/x?a=1&key={}", ph["qk"])).await.status, 200);
    assert_eq!(
        seen.recv().await.expect("seen").uri,
        format!("/x?a=1&key={SECRET}-qk")
    );
    assert_eq!(c.get("/y").await.status, 200);
    assert_eq!(
        seen.recv().await.expect("seen").uri,
        format!("/y?key={SECRET}-qk")
    );
    // The query secret never shows up in the recorded path.
    assert_eq!(last(sb).path.as_deref(), Some("/y"));

    use base64::Engine as _;
    let b64 = |s: &str| base64::engine::general_purpose::STANDARD.encode(s);
    let mut c = Client::tls(proxy, &b, "b.test", port).await;
    let auth = format!("Basic {}", b64(&format!("x-access-token:{}", ph["bk"])));
    assert_eq!(
        c.send("GET", "/", &[("authorization", &auth)], "")
            .await
            .status,
        200
    );
    assert_eq!(
        seen.recv()
            .await
            .expect("seen")
            .headers
            .get("authorization")
            .expect("auth"),
        &format!("Basic {}", b64(&format!("x-access-token:{SECRET}-bk")))
    );
    assert_no_secret(sb);
}

#[tokio::test]
async fn placeholder_exfiltration_is_refused_everywhere_else() {
    let ca = test_ca();
    let (origin, mut seen) = start_origin(Some(Arc::clone(&ca.server))).await;
    let (plain, mut plain_seen) = start_origin(None).await;
    let port = origin.port();
    let mut gh = endpoint("github", "api.test", port, "rest");
    gh.credential = "gh".into();
    let other = endpoint("other", "other.test", port, "rest");
    let sb = "sb-broker-exfil";
    let b = broker(sb, vec![gh, other], vec![credential("gh", "")], &ca);
    let ph = b.placeholders()["gh"].clone();
    let mut events = b.subscribe();
    // A plain origin the network policy allows by IP.
    let proxy = proxy_with(&b, vec![rule("allow", "", "127.0.0.0/8")]).await;

    // To a different inspected endpoint, in a header, query or body.
    let mut c = Client::tls(proxy, &b, "other.test", port).await;
    let bearer = format!("Bearer {ph}");
    for (path, hdrs, body) in [
        (
            "/a",
            vec![("authorization", bearer.as_str())],
            String::new(),
        ),
        ("/a", vec![("x-custom", ph.as_str())], String::new()),
        (&*format!("/a?t={ph}"), vec![], String::new()),
        ("/a", vec![], format!("{{\"token\":\"{ph}\"}}")),
    ] {
        let r = c.send("POST", path, &hdrs, &body).await;
        assert_eq!(r.status, 403, "{path} {hdrs:?}");
        assert_eq!(r.json()["code"], "placeholder-misuse");
        let d = last(sb);
        assert_eq!(d.reason_code, Some(ReasonCode::PlaceholderMisuse));
        assert_eq!(d.credential.as_deref(), Some("gh"));
        assert_eq!(d.endpoint.as_deref(), Some("other"));
    }
    assert!(seen.try_recv().is_err());

    // To a plain HTTP destination outside any endpoint.
    let resp = common::roundtrip(
        proxy,
        &format!("GET http://{plain}/leak?x={ph} HTTP/1.1\r\nHost: {plain}\r\n\r\n"),
    )
    .await;
    assert_eq!(resp.status, 403);
    assert!(resp.body.contains("placeholder-misuse"), "{}", resp.body);
    assert!(plain_seen.try_recv().is_err());
    // A clean request there still works.
    let resp = common::roundtrip(
        proxy,
        &format!("GET http://{plain}/fine HTTP/1.1\r\nHost: {plain}\r\n\r\n"),
    )
    .await;
    assert_eq!(resp.status, 200);
    assert_eq!(plain_seen.recv().await.expect("seen").uri, "/fine");

    // Through a plaintext CONNECT tunnel: the tunnel is cut.
    let (status, mut tunnel) = connect(proxy, &plain.to_string()).await;
    assert_eq!(status, 200);
    tunnel
        .write_all(format!("GET /t HTTP/1.1\r\nHost: x\r\nAuthorization: {}", &ph[..10]).as_bytes())
        .await
        .expect("write");
    tunnel
        .write_all(format!("{}\r\n\r\n", &ph[10..]).as_bytes())
        .await
        .expect("write");
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        tunnel.read_to_end(&mut buf),
    )
    .await
    .expect("tunnel closed");
    assert!(buf.is_empty(), "{}", String::from_utf8_lossy(&buf));
    let d = last(sb);
    assert_eq!(d.reason_code, Some(ReasonCode::PlaceholderMisuse));
    assert!(d.reason.contains("opaque tunnel"), "{d:?}");

    // The stream saw the misuse too.
    let mut saw = false;
    while let Ok(d) = events.try_recv() {
        saw |= d.reason_code == Some(ReasonCode::PlaceholderMisuse);
    }
    assert!(saw, "decision stream carried the misuse");
    assert_no_secret(sb);
}

#[derive(Debug)]
struct Approver(ApprovalOutcome, mpsc::UnboundedSender<ApprovalRequest>);

impl ApprovalHook for Approver {
    fn request_approval(&self, req: ApprovalRequest) -> ApprovalFuture {
        let _ = self.1.send(req);
        let out = self.0.clone();
        Box::pin(async move { out })
    }
}

fn mcp_endpoint(port: u16) -> Endpoint {
    let mut ep = endpoint("tools", "mcp.test", port, "mcp");
    ep.allow = vec![
        allow("tools/list", "", "", ""),
        allow("", "", "search_*", "read"),
        allow("", "", "deploy", ""),
        allow("", "", "drop_*", "irreversible"),
    ];
    ep.deny = vec![allow("", "", "search_secrets", "")];
    ep
}

#[tokio::test]
async fn mcp_tool_rules_and_require_approval() {
    let ca = test_ca();
    let (origin, mut seen) = start_origin(Some(Arc::clone(&ca.server))).await;
    let port = origin.port();
    let sb = "sb-broker-mcp";
    let b = broker(sb, vec![mcp_endpoint(port)], vec![], &ca);
    let proxy = proxy_with(&b, vec![]).await;
    let mut c = Client::tls(proxy, &b, "mcp.test", port).await;
    let json = [("content-type", "application/json")];

    assert_eq!(
        c.send("POST", "/mcp", &json, &mcp("initialize", None))
            .await
            .status,
        200
    );
    assert_eq!(
        c.send("POST", "/mcp", &json, &mcp("tools/list", None))
            .await
            .status,
        200
    );
    let r = c
        .send(
            "POST",
            "/mcp",
            &json,
            &mcp("tools/call", Some("search_code")),
        )
        .await;
    assert_eq!(r.status, 200);
    let d = last(sb);
    assert_eq!(
        (d.method.as_deref(), d.tool.as_deref(), d.effect.as_deref()),
        (Some("tools/call"), Some("search_code"), Some("read"))
    );
    for _ in 0..3 {
        seen.recv().await.expect("forwarded");
    }

    let r = c
        .send(
            "POST",
            "/mcp",
            &json,
            &mcp("tools/call", Some("search_secrets")),
        )
        .await;
    assert_eq!(r.status, 403);
    assert_eq!(r.json()["code"], "denied");

    // Untagged tool: require-approval, refused with a clear JSON error.
    let r = c
        .send("POST", "/mcp", &json, &mcp("tools/call", Some("deploy")))
        .await;
    assert_eq!(r.status, 403);
    let j = r.json();
    assert_eq!(j["code"], "approval");
    assert_eq!(j["verdict"], "require-approval");
    assert_eq!(j["tool"], "deploy");
    assert!(
        j["error"].as_str().expect("msg").contains("approval"),
        "{j}"
    );
    let d = last(sb);
    assert_eq!(d.verdict, Some(Verdict::RequireApproval));
    assert_eq!(d.reason_code, Some(ReasonCode::Approval));
    assert_eq!(d.effect.as_deref(), Some("irreversible"));
    assert!(d.reason.contains("untagged"), "{d:?}");

    // Explicitly irreversible: also approval.
    let r = c
        .send(
            "POST",
            "/mcp",
            &json,
            &mcp("tools/call", Some("drop_table")),
        )
        .await;
    assert_eq!(r.json()["verdict"], "require-approval");

    // Unknown tool, unknown method, broken body: denied.
    for body in [
        mcp("tools/call", Some("rm_rf")),
        mcp("resources/read", None),
        "not json".to_string(),
    ] {
        let r = c.send("POST", "/mcp", &json, &body).await;
        assert_eq!(r.status, 403, "{body}");
        assert_eq!(r.json()["code"], "denied", "{body}");
    }
    // A batch is as strict as its strictest member.
    let batch = format!(
        "[{},{}]",
        mcp("tools/call", Some("search_code")),
        mcp("tools/call", Some("deploy"))
    );
    assert_eq!(
        c.send("POST", "/mcp", &json, &batch).await.json()["code"],
        "approval"
    );
    assert!(seen.try_recv().is_err());
}

#[tokio::test]
async fn approval_hook_routes_require_approval() {
    let ca = test_ca();
    let (origin, mut seen) = start_origin(Some(Arc::clone(&ca.server))).await;
    let port = origin.port();
    let json = [("content-type", "application/json")];

    let (tx, mut asked) = mpsc::unbounded_channel();
    let sb = "sb-broker-approve";
    let b = Broker::with_secret_values(sb, vec![mcp_endpoint(port)], vec![], HashMap::new())
        .expect("broker")
        .with_upstream_tls(Arc::clone(&ca.client))
        .with_approval_hook(Arc::new(Approver(ApprovalOutcome::Approved, tx)));
    let b = Arc::new(b);
    let proxy = proxy_with(&b, vec![]).await;
    let mut c = Client::tls(proxy, &b, "mcp.test", port).await;
    let r = c
        .send("POST", "/mcp", &json, &mcp("tools/call", Some("deploy")))
        .await;
    assert_eq!(r.status, 200, "{}", r.body);
    seen.recv().await.expect("forwarded after approval");
    let req = asked.recv().await.expect("hook asked");
    assert_eq!(req.sandbox_id, sb);
    assert_eq!(req.decision.verdict, Some(Verdict::RequireApproval));
    assert_eq!(req.decision.tool.as_deref(), Some("deploy"));
    let d = last(sb);
    assert_eq!(d.verdict, Some(Verdict::Allow));
    assert!(d.reason.starts_with("approved"), "{d:?}");

    let (tx, _asked) = mpsc::unbounded_channel();
    let sb = "sb-broker-reject";
    let b = Broker::with_secret_values(sb, vec![mcp_endpoint(port)], vec![], HashMap::new())
        .expect("broker")
        .with_upstream_tls(Arc::clone(&ca.client))
        .with_approval_hook(Arc::new(Approver(
            ApprovalOutcome::Denied("not today".into()),
            tx,
        )));
    let b = Arc::new(b);
    let proxy = proxy_with(&b, vec![]).await;
    let mut c = Client::tls(proxy, &b, "mcp.test", port).await;
    let r = c
        .send("POST", "/mcp", &json, &mcp("tools/call", Some("deploy")))
        .await;
    assert_eq!(r.status, 403);
    assert!(r.json()["error"].as_str().expect("e").contains("not today"));
    assert!(seen.try_recv().is_err());
}

#[tokio::test]
async fn json_rpc_over_plain_http() {
    let ca = test_ca();
    let (origin, mut seen) = start_origin(None).await;
    let mut ep = endpoint("chain", "rpc.test", origin.port(), "json-rpc");
    ep.allow = vec![allow("eth_get*", "", "", "read")];
    ep.deny = vec![allow("eth_getLogs", "", "", "")];
    let sb = "sb-broker-jsonrpc";
    let b = broker(sb, vec![ep], vec![], &ca);
    let proxy = proxy_with(&b, vec![]).await;
    let authority = format!("rpc.test:{}", origin.port());
    let call = |m: &str| {
        let body = mcp(m, None);
        format!(
            "POST http://{authority}/ HTTP/1.1\r\nHost: {authority}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
    };
    assert_eq!(
        common::roundtrip(proxy, &call("eth_getBalance"))
            .await
            .status,
        200
    );
    assert_eq!(seen.recv().await.expect("seen").method, "POST");
    assert_eq!(last(sb).method.as_deref(), Some("eth_getBalance"));
    assert_eq!(
        common::roundtrip(proxy, &call("eth_getLogs")).await.status,
        403
    );
    assert_eq!(
        common::roundtrip(proxy, &call("eth_sendTransaction"))
            .await
            .status,
        403
    );
    assert!(seen.try_recv().is_err());
}

#[tokio::test]
async fn budgets_refuse_with_429() {
    let ca = test_ca();
    let (origin, _seen) = start_origin(Some(Arc::clone(&ca.server))).await;
    let mut ep = endpoint("api", "api.test", origin.port(), "rest");
    ep.max_calls = 3;
    ep.allow = vec![
        RequestRule {
            path: "/once".into(),
            max_calls: 1,
            ..RequestRule::default()
        },
        allow("", "/**", "", ""),
    ];
    let sb = "sb-broker-budget";
    let b = broker(sb, vec![ep], vec![], &ca);
    let proxy = proxy_with(&b, vec![]).await;
    let mut c = Client::tls(proxy, &b, "api.test", origin.port()).await;

    assert_eq!(c.get("/once").await.status, 200);
    let r = c.get("/once").await;
    assert_eq!(r.status, 429);
    assert_eq!(r.json()["code"], "budget");
    let d = last(sb);
    assert_eq!(d.reason_code, Some(ReasonCode::Budget));
    assert_eq!(d.verdict, Some(Verdict::Deny));
    assert_eq!(c.get("/a").await.status, 200);
    assert_eq!(c.get("/b").await.status, 200);
    let r = c.get("/c").await;
    assert_eq!(r.status, 429);
    assert!(
        last(sb).reason.contains("endpoint budget"),
        "{:?}",
        last(sb)
    );
}

#[tokio::test]
async fn audit_mode_forwards_and_records_would_deny() {
    let ca = test_ca();
    let (origin, mut seen) = start_origin(Some(Arc::clone(&ca.server))).await;
    let mut ep = endpoint("audited", "audit.test", origin.port(), "rest");
    ep.mode = "audit".into();
    ep.allow = vec![allow("GET", "/ok/**", "", "read")];
    ep.deny = vec![allow("", "/danger/**", "", "")];
    let sb = "sb-broker-audit";
    let b = broker(sb, vec![ep], vec![], &ca);
    let proxy = proxy_with(&b, vec![]).await;
    let mut c = Client::tls(proxy, &b, "audit.test", origin.port()).await;

    let r = c.get("/danger/zone").await;
    assert_eq!(r.status, 200);
    assert_eq!(seen.recv().await.expect("forwarded").uri, "/danger/zone");
    let d = last(sb);
    assert!(d.allow);
    assert_eq!(d.verdict, Some(Verdict::Allow));
    assert_eq!(d.reason_code, Some(ReasonCode::AuditWouldDeny));
    assert_eq!(d.rule.as_deref(), Some("deny[0]"));

    assert_eq!(c.send("PUT", "/ok/x", &[], "").await.status, 200);
    assert_eq!(last(sb).reason_code, Some(ReasonCode::AuditWouldDeny));
    assert_eq!(c.get("/ok/x").await.status, 200);
    assert_eq!(last(sb).reason_code, Some(ReasonCode::Allowed));
}

#[tokio::test]
async fn websocket_upgrade_is_checked_then_spliced() {
    let ca = test_ca();
    let (origin, _seen) = start_origin(Some(Arc::clone(&ca.server))).await;
    let mut ep = endpoint("ws", "ws.test", origin.port(), "websocket");
    ep.credential = "wk".into();
    ep.allow = vec![allow("GET", "/socket", "", "read")];
    let sb = "sb-broker-ws";
    let b = broker(sb, vec![ep], vec![credential("wk", "")], &ca);
    let proxy = proxy_with(&b, vec![]).await;
    let upgrade = [
        ("connection", "Upgrade"),
        ("upgrade", "websocket"),
        ("sec-websocket-version", "13"),
        ("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ=="),
    ];

    let mut c = Client::tls(proxy, &b, "ws.test", origin.port()).await;
    assert_eq!(c.send("GET", "/other", &upgrade, "").await.status, 403);

    let mut c = Client::tls(proxy, &b, "ws.test", origin.port()).await;
    let mut req = Request::builder()
        .method("GET")
        .uri("/socket")
        .header("host", &c.host);
    for (k, v) in upgrade {
        req = req.header(k, v);
    }
    let req = req.body(Full::new(Bytes::new())).expect("req");
    c.sender.ready().await.expect("ready");
    let mut resp = c.sender.send_request(req).await.expect("resp");
    assert_eq!(resp.status(), StatusCode::SWITCHING_PROTOCOLS);
    let up = hyper::upgrade::on(&mut resp).await.expect("upgraded");
    let mut io = TokioIo::new(up);
    io.write_all(b"frame").await.expect("write");
    let mut buf = [0u8; 5];
    io.read_exact(&mut buf).await.expect("echo");
    assert_eq!(&buf, b"frame");
    assert_eq!(last(sb).credential.as_deref(), Some("wk"));
}

#[tokio::test]
async fn tcp_endpoint_is_a_tunnel_with_sni_check() {
    let ca = test_ca();
    // A line server that answers every connection.
    let ln = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let target = ln.local_addr().expect("addr");
    tokio::spawn(async move {
        while let Ok((conn, _)) = ln.accept().await {
            tokio::spawn(async move {
                let mut br = BufReader::new(conn);
                let mut line = String::new();
                let _ = br.read_line(&mut line).await;
                let _ = br.get_mut().write_all(b"pong\n").await;
            });
        }
    });
    let sb = "sb-broker-tcp";
    let mut tcp_ep = endpoint("raw", "raw.test", target.port(), "tcp");
    tcp_ep.binaries = vec!["/usr/bin/psql".into()];
    let b = broker(sb, vec![tcp_ep], vec![], &ca);
    let proxy = proxy_with(&b, vec![]).await;

    // Reachable under default deny; plaintext passes through.
    let (status, tunnel) = connect(proxy, &format!("raw.test:{}", target.port())).await;
    assert_eq!(status, 200);
    let mut br = BufReader::new(tunnel);
    br.get_mut().write_all(b"ping\n").await.expect("write");
    let mut line = String::new();
    br.read_line(&mut line).await.expect("read");
    assert_eq!(line.trim(), "pong");
    let d = list_decisions(sb)
        .into_iter()
        .find(|d| d.endpoint.is_some())
        .expect("endpoint decision");
    assert_eq!(d.protocol.as_deref(), Some("tcp"));
    assert_eq!(d.binaries, Some(vec!["/usr/bin/psql".to_string()]));

    // A ClientHello naming another host is cut off.
    let (status, tunnel) = connect(proxy, &format!("raw.test:{}", target.port())).await;
    assert_eq!(status, 200);
    let res = tokio_rustls::TlsConnector::from(Arc::clone(&ca.client))
        .connect(ServerName::try_from("other.test").expect("name"), tunnel)
        .await;
    assert!(res.is_err());
    let d = last(sb);
    assert_eq!(d.reason_code, Some(ReasonCode::Denied));
    assert!(d.reason.contains("sni"), "{d:?}");

    // Non-endpoint hosts are still denied by the default.
    let (status, _) = connect(proxy, "nope.test:443").await;
    assert_eq!(status, 403);
}

#[tokio::test]
async fn transparent_mode_intercepts_endpoints() {
    let ca = test_ca();
    let (origin, mut seen) = start_origin(Some(Arc::clone(&ca.server))).await;
    let mut ep = endpoint("github", "api.test", origin.port(), "rest");
    ep.credential = "gh".into();
    ep.allow = vec![allow("GET", "/**", "", "read")];
    let sb = "sb-broker-transparent";
    let b = broker(sb, vec![ep], vec![credential("gh", "")], &ca);
    let tp = Arc::new(
        TransparentProxy::new(policy("deny", vec![]))
            .with_resolver(loopback())
            .with_broker(Arc::clone(&b)),
    );
    let ln = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let client = TcpStream::connect(ln.local_addr().expect("addr"))
        .await
        .expect("connect");
    let (server, _) = ln.accept().await.expect("accept");
    tokio::spawn(async move { tp.handle_redirected(server, origin).await });

    let tls = tokio_rustls::TlsConnector::from(trusting(b.ca_cert_pem()))
        .connect(ServerName::try_from("api.test").expect("name"), client)
        .await
        .expect("tls via sandbox CA");
    let mut c = Client::over(tls, &format!("api.test:{}", origin.port())).await;
    let r = c.get("/x").await;
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(
        seen.recv()
            .await
            .expect("seen")
            .headers
            .get("authorization")
            .expect("auth"),
        &format!("Bearer {SECRET}-gh")
    );
    assert_eq!(c.send("POST", "/x", &[], "").await.status, 403);
    assert_eq!(last(sb).reason, "no allow rule matched");
}
