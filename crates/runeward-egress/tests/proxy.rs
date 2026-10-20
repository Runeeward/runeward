//! Forward-proxy behaviour against loopback upstreams.

mod common;

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use common::*;
use runeward_egress::resolve::StaticResolver;
use runeward_egress::{Proxy, list_decisions};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

fn loopback_resolver() -> Arc<StaticResolver> {
    Arc::new(StaticResolver::new(vec![
        "127.0.0.1".parse::<IpAddr>().expect("ip"),
    ]))
}

#[tokio::test]
async fn connect_allowed() {
    let target = start_line_target("pong\n").await;
    let p = Proxy::new(policy(
        "deny",
        vec![rule("allow", &target.ip().to_string(), "")],
    ));
    let (proxy, _stop) = start_proxy(p).await;

    let (resp, mut tunnel) = connect_via(proxy, &target.to_string()).await;
    assert_eq!(resp.status, 200, "{}", resp.head);
    assert!(
        resp.head.starts_with("HTTP/1.1 200 Connection Established"),
        "{}",
        resp.head
    );

    tunnel.get_mut().write_all(b"ping\n").await.expect("write");
    let mut line = String::new();
    tunnel.read_line(&mut line).await.expect("read");
    assert_eq!(line.trim(), "pong");
}

#[tokio::test]
async fn connect_denied() {
    let p = Proxy::new(policy("deny", vec![])).with_sandbox_id("sb-connect-denied");
    let (proxy, _stop) = start_proxy(p).await;
    let (resp, _) = connect_via(proxy, "blocked.example.com:443").await;
    assert_eq!(resp.status, 403);

    let d = list_decisions("sb-connect-denied");
    assert_eq!(d.len(), 1);
    assert_eq!(d[0].host, "blocked.example.com");
    assert!(!d[0].allow);
    assert_eq!(d[0].reason, "hostname not allowlisted");
}

#[tokio::test]
async fn connect_hostname_with_default_allow_is_still_denied() {
    // Hostnames must be explicitly allowlisted; the default only governs IPs.
    let p = Proxy::new(policy("allow", vec![])).with_resolver(loopback_resolver());
    let (proxy, _stop) = start_proxy(p).await;
    let (resp, _) = connect_via(proxy, "anything.test:443").await;
    assert_eq!(resp.status, 403);
}

#[tokio::test]
async fn connect_ip_denied_by_cidr_records_ip() {
    let p = Proxy::new(policy("allow", vec![rule("deny", "", "127.0.0.0/8")]))
        .with_sandbox_id("sb-connect-cidr");
    let (proxy, _stop) = start_proxy(p).await;
    let (resp, _) = connect_via(proxy, "127.0.0.1:9").await;
    assert_eq!(resp.status, 403);
    let d = list_decisions("sb-connect-cidr");
    assert_eq!(d[0].ip, "127.0.0.1");
    assert_eq!(d[0].reason, "blocked by egress policy");
}

#[tokio::test]
async fn connect_resolution_failure_denies() {
    let p = Proxy::new(policy("deny", vec![rule("allow", "api.example.test", "")]))
        .with_resolver(Arc::new(StaticResolver::new(vec![])))
        .with_sandbox_id("sb-connect-resolve");
    let (proxy, _stop) = start_proxy(p).await;
    let (resp, _) = connect_via(proxy, "api.example.test:443").await;
    assert_eq!(resp.status, 403);
    assert_eq!(
        list_decisions("sb-connect-resolve")[0].reason,
        "hostname resolution failed"
    );
}

#[tokio::test]
async fn connect_dial_failure_is_bad_gateway() {
    // Reserve a port, then close it so the dial is refused.
    let ln = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let closed = ln.local_addr().expect("addr");
    drop(ln);
    let p = Proxy::new(policy("deny", vec![rule("allow", "", "127.0.0.0/8")]))
        .with_sandbox_id("sb-connect-dialfail");
    let (proxy, _stop) = start_proxy(p).await;
    let (resp, _) = connect_via(proxy, &closed.to_string()).await;
    assert_eq!(resp.status, 502);
    let d = list_decisions("sb-connect-dialfail");
    assert!(d[0].allow);
    assert_eq!(d[0].reason, "allowed by policy (dial failed)");
}

#[tokio::test]
async fn connect_pins_resolved_ip() {
    let target = start_line_target("pong\n").await;
    let p = Proxy::new(policy("deny", vec![rule("allow", "api.example.test", "")]))
        .with_resolver(loopback_resolver())
        .with_sandbox_id("sb-connect-pin");
    let (proxy, _stop) = start_proxy(p).await;

    let (resp, mut tunnel) =
        connect_via(proxy, &format!("api.example.test:{}", target.port())).await;
    assert_eq!(resp.status, 200, "{}", resp.head);
    tunnel.get_mut().write_all(b"ping\n").await.expect("write");
    let mut line = String::new();
    tunnel.read_line(&mut line).await.expect("read");
    assert_eq!(line.trim(), "pong");

    // The decision is recorded once the tunnel is established.
    let d = list_decisions("sb-connect-pin");
    assert_eq!(d.len(), 1);
    assert_eq!(
        (d[0].host.as_str(), d[0].ip.as_str()),
        ("api.example.test", "127.0.0.1")
    );
    assert_eq!(d[0].reason, "allowed by egress policy");
}

#[tokio::test]
async fn http_denied() {
    let p = Proxy::new(policy("deny", vec![])).with_sandbox_id("sb-http-denied");
    let (proxy, _stop) = start_proxy(p).await;
    let resp = roundtrip(
        proxy,
        "GET http://denied.example.com/path HTTP/1.1\r\nHost: denied.example.com\r\n\r\n",
    )
    .await;
    assert_eq!(resp.status, 403);
    assert_eq!(resp.body, "Forbidden\n");
    assert_eq!(
        resp.header("content-type").as_deref(),
        Some("text/plain; charset=utf-8")
    );
    let d = list_decisions("sb-http-denied");
    assert_eq!(d[0].reason, "blocked by egress policy");
}

#[tokio::test]
async fn http_allowed_forwards() {
    let (origin, mut heads) = start_origin("hello-from-origin").await;
    let p = Proxy::new(policy(
        "deny",
        vec![rule("allow", &origin.ip().to_string(), "")],
    ));
    let (proxy, _stop) = start_proxy(p).await;

    let resp = roundtrip(
        proxy,
        &format!("GET http://{origin}/x?y=1 HTTP/1.1\r\nHost: {origin}\r\nX-Test: 1\r\n\r\n"),
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.head);
    assert_eq!(resp.body, "hello-from-origin");
    assert_eq!(resp.header("x-origin").as_deref(), Some("yes"));

    let head = heads.recv().await.expect("origin saw request");
    assert!(head.starts_with("GET /x?y=1 HTTP/1.1\r\n"), "{head}");
    assert!(
        head.to_ascii_lowercase()
            .contains(&format!("host: {origin}")),
        "{head}"
    );
    assert!(head.to_ascii_lowercase().contains("x-test: 1"), "{head}");
}

#[tokio::test]
async fn http_hostname_is_pinned() {
    let (origin, mut heads) = start_origin("pinned").await;
    let p = Proxy::new(policy("deny", vec![rule("allow", "origin.test", "")]))
        .with_resolver(loopback_resolver());
    let (proxy, _stop) = start_proxy(p).await;
    let authority = format!("origin.test:{}", origin.port());
    let resp = roundtrip(
        proxy,
        &format!("GET http://{authority}/ HTTP/1.1\r\nHost: {authority}\r\n\r\n"),
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.head);
    assert_eq!(resp.body, "pinned");
    let head = heads.recv().await.expect("head");
    assert!(
        head.to_ascii_lowercase()
            .contains(&format!("host: {authority}")),
        "{head}"
    );
}

#[tokio::test]
async fn proxy_auth_required() {
    let (origin, mut heads) = start_origin("ok").await;
    let p = Proxy::new(policy(
        "deny",
        vec![rule("allow", &origin.ip().to_string(), "")],
    ))
    .with_auth("runeward", "s3cret");
    let (proxy, _stop) = start_proxy(p).await;

    // No credentials -> 407.
    let req = format!("GET http://{origin}/ HTTP/1.1\r\nHost: {origin}\r\n\r\n");
    let resp = roundtrip(proxy, &req).await;
    assert_eq!(resp.status, 407);
    assert_eq!(
        resp.header("proxy-authenticate").as_deref(),
        Some(r#"Basic realm="runeward-egress""#)
    );

    // Wrong credentials -> 407, also for CONNECT.
    let bad = base64::engine::general_purpose::STANDARD.encode("runeward:nope");
    let resp = roundtrip(
        proxy,
        &format!("CONNECT {origin} HTTP/1.1\r\nHost: {origin}\r\nProxy-Authorization: Basic {bad}\r\n\r\n"),
    )
    .await;
    assert_eq!(resp.status, 407);

    // Correct credentials -> forwarded, and not leaked upstream.
    let good = base64::engine::general_purpose::STANDARD.encode("runeward:s3cret");
    let resp = roundtrip(
        proxy,
        &format!("GET http://{origin}/ HTTP/1.1\r\nHost: {origin}\r\nProxy-Authorization: Basic {good}\r\n\r\n"),
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.head);
    let head = heads.recv().await.expect("head");
    assert!(
        !head.to_ascii_lowercase().contains("proxy-authorization"),
        "{head}"
    );
}

#[tokio::test]
async fn https_absolute_uri_uses_pinned_ip_and_sni() {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

    let cert = rcgen::generate_simple_self_signed(vec!["origin.test".to_string()]).expect("cert");
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let server_cfg = rustls::ServerConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()
        .expect("versions")
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key)
        .expect("server config");
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_cfg));

    let ln = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let origin = ln.local_addr().expect("addr");
    let (tx, mut heads) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        let Ok((tcp, _)) = ln.accept().await else {
            return;
        };
        let Ok(tls) = acceptor.accept(tcp).await else {
            return;
        };
        let sni = tls.get_ref().1.server_name().map(str::to_string);
        let _ = tx.send(format!("sni={sni:?}"));
        let _ = serve_origin_conn(tls, "tls-ok", tx).await;
    });

    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert_der).expect("root");
    let p = Proxy::new(policy("deny", vec![rule("allow", "origin.test", "")]))
        .with_resolver(loopback_resolver())
        .with_tls_config(Arc::new(runeward_egress::proxy::tls_client_config(roots)));
    let (proxy, _stop) = start_proxy(p).await;

    let authority = format!("origin.test:{}", origin.port());
    let resp = roundtrip(
        proxy,
        &format!("GET https://{authority}/secure HTTP/1.1\r\nHost: {authority}\r\n\r\n"),
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.head);
    assert_eq!(resp.body, "tls-ok");
    assert_eq!(
        heads.recv().await.as_deref(),
        Some(r#"sni=Some("origin.test")"#)
    );
    let head = heads.recv().await.expect("head");
    assert!(head.starts_with("GET /secure HTTP/1.1"), "{head}");
}

#[tokio::test]
async fn graceful_shutdown_stops_accepting() {
    let p = Proxy::new(policy("deny", vec![]));
    let ln = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = ln.local_addr().expect("addr");
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(Arc::new(p).serve_with_shutdown(ln, async move {
        let _ = rx.await;
    }));
    // An idle keep-alive connection must not block shutdown.
    let resp_conn = tokio::net::TcpStream::connect(addr).await.expect("connect");
    let _ = tx.send(());
    let res = tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .expect("shutdown finished")
        .expect("join");
    assert!(res.is_ok());
    drop(resp_conn);
    assert!(tokio::net::TcpStream::connect(addr).await.is_err());
}
