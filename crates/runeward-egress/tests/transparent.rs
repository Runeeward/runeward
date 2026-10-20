//! Transparent-proxy connection handling with a supplied original
//! destination (no iptables or root needed).

mod common;

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use common::*;
use runeward_egress::resolve::StaticResolver;
use runeward_egress::{Policy, TransparentProxy, list_decisions};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

/// Returns a client stream whose server side is handled by `tp` as if it had
/// been redirected from `dst`.
async fn redirected_client(tp: Arc<TransparentProxy>, dst: SocketAddr) -> TcpStream {
    let ln = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = ln.local_addr().expect("addr");
    let client = TcpStream::connect(addr).await.expect("connect");
    let (server, _) = ln.accept().await.expect("accept");
    tokio::spawn(async move { tp.handle_redirected(server, dst).await });
    client
}

fn tp(policy: Policy, sandbox: &str) -> Arc<TransparentProxy> {
    Arc::new(
        TransparentProxy::new(policy)
            .with_sandbox_id(sandbox)
            .with_resolver(Arc::new(StaticResolver::new(vec![
                "127.0.0.1".parse::<IpAddr>().expect("ip"),
            ]))),
    )
}

#[tokio::test]
async fn http_host_allowlisted_is_spliced() {
    let (origin, mut heads) = start_origin("via-transparent").await;
    let t = tp(
        policy("deny", vec![rule("allow", "origin.test", "")]),
        "sb-tp-http",
    );
    let client = redirected_client(t, origin).await;
    let mut br = BufReader::new(client);
    br.get_mut()
        .write_all(b"GET /t HTTP/1.1\r\nHost: origin.test\r\n\r\n")
        .await
        .expect("write");
    let resp = read_response(&mut br).await;
    assert_eq!(resp.status, 200);
    assert_eq!(resp.body, "via-transparent");
    // The sniffed bytes were replayed verbatim.
    let head = heads.recv().await.expect("head");
    assert!(
        head.starts_with("GET /t HTTP/1.1\r\nHost: origin.test\r\n"),
        "{head}"
    );

    let d = list_decisions("sb-tp-http");
    assert_eq!(d.len(), 1);
    assert_eq!(
        (d[0].host.as_str(), d[0].ip.as_str(), d[0].allow),
        ("origin.test", "127.0.0.1", true)
    );
}

#[tokio::test]
async fn host_not_allowlisted_is_dropped() {
    // A default-allow policy still requires presented hostnames be listed.
    let dst: SocketAddr = "192.0.2.10:80".parse().expect("addr");
    let t = tp(policy("allow", vec![]), "sb-tp-deny");
    let mut client = redirected_client(t, dst).await;
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: evil.test\r\n\r\n")
        .await
        .expect("write");
    let mut buf = Vec::new();
    let n = tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut buf))
        .await
        .expect("closed")
        .unwrap_or(0);
    assert_eq!(n, 0, "denied connection must be closed without data");

    let d = list_decisions("sb-tp-deny");
    assert_eq!(d.len(), 1);
    assert_eq!(
        (
            d[0].host.as_str(),
            d[0].ip.as_str(),
            d[0].allow,
            d[0].reason.as_str()
        ),
        ("evil.test", "192.0.2.10", false, "blocked by egress policy")
    );
}

#[tokio::test]
async fn sni_is_used_as_hostname() {
    let dst: SocketAddr = "192.0.2.11:443".parse().expect("addr");
    let t = tp(policy("deny", vec![]), "sb-tp-sni");
    let mut client = redirected_client(t, dst).await;

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("versions")
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
    let name = rustls::pki_types::ServerName::try_from("Api.Example.com").expect("name");
    let mut conn = rustls::ClientConnection::new(Arc::new(cfg), name).expect("client");
    let mut hello = Vec::new();
    conn.write_tls(&mut hello).expect("hello");
    client.write_all(&hello).await.expect("write");
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut buf)).await;

    let d = list_decisions("sb-tp-sni");
    assert_eq!(d.len(), 1);
    assert_eq!(d[0].host, "api.example.com");
    assert!(!d[0].allow);
}

#[tokio::test]
async fn no_hostname_falls_back_to_cidr() {
    let target = start_line_target("pong\n").await;
    let t = tp(
        policy("deny", vec![rule("allow", "", "127.0.0.0/8")]),
        "sb-tp-cidr",
    );
    let client = redirected_client(t, target).await;
    let mut br = BufReader::new(client);
    br.get_mut().write_all(b"ping\n").await.expect("write");
    let mut line = String::new();
    br.read_line(&mut line).await.expect("read");
    assert_eq!(line.trim(), "pong");

    let d = list_decisions("sb-tp-cidr");
    assert_eq!(d[0].host, target.to_string());
    assert_eq!(d[0].ip, "127.0.0.1");
    assert!(d[0].allow);
}

#[tokio::test]
async fn no_hostname_outside_cidr_is_denied() {
    let dst: SocketAddr = "198.51.100.1:5432".parse().expect("addr");
    let t = tp(
        policy("deny", vec![rule("allow", "", "127.0.0.0/8")]),
        "sb-tp-cidr-deny",
    );
    let mut client = redirected_client(t, dst).await;
    client.write_all(b"\x00\x01binary").await.expect("write");
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut buf)).await;
    let d = list_decisions("sb-tp-cidr-deny");
    assert_eq!(
        (d[0].host.as_str(), d[0].ip.as_str(), d[0].allow),
        ("198.51.100.1:5432", "198.51.100.1", false)
    );
}

#[tokio::test]
async fn resolution_failure_records_twice_like_go() {
    let dst: SocketAddr = "192.0.2.12:80".parse().expect("addr");
    let t = Arc::new(
        TransparentProxy::new(policy("deny", vec![rule("allow", "origin.test", "")]))
            .with_sandbox_id("sb-tp-resolve")
            .with_resolver(Arc::new(StaticResolver::new(vec![]))),
    );
    let mut client = redirected_client(t, dst).await;
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: origin.test\r\n\r\n")
        .await
        .expect("write");
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut buf)).await;
    let reasons: Vec<_> = list_decisions("sb-tp-resolve")
        .into_iter()
        .map(|d| d.reason)
        .collect();
    assert_eq!(
        reasons,
        ["hostname resolution failed", "blocked by egress policy"]
    );
}

#[cfg(not(target_os = "linux"))]
#[tokio::test]
async fn serve_is_unsupported_off_linux() {
    let err = Arc::new(TransparentProxy::new(Policy::default()))
        .serve("127.0.0.1:0")
        .await
        .expect_err("unsupported");
    assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
}
