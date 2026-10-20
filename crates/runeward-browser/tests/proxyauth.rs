//! Ports of Go `cmd/runeward-browser/proxyauth_test.go`.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use runeward_browser::proxyauth::start_proxy_auth_forwarder;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

const USER: &str = "runeward";
const PASS: &str = "s3cret";

fn want_auth() -> String {
    format!("Basic {}", STANDARD.encode(format!("{USER}:{PASS}")))
}

/// Reads a request head; returns its request line and Proxy-Authorization.
async fn read_head(r: &mut BufReader<TcpStream>) -> (String, String) {
    let mut first = String::new();
    r.read_line(&mut first).await.expect("request line");
    let mut auth = String::new();
    loop {
        let mut line = String::new();
        r.read_line(&mut line).await.expect("header");
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':')
            && k.eq_ignore_ascii_case("proxy-authorization")
        {
            auth = v.trim().to_owned();
        }
    }
    (first.trim_end().to_owned(), auth)
}

/// Reads a whole response (the forwarder closes the connection after it).
async fn read_all(s: &mut TcpStream) -> String {
    let mut out = Vec::new();
    s.read_to_end(&mut out).await.expect("read");
    String::from_utf8(out).expect("utf8")
}

#[tokio::test]
async fn no_credentials_returns_url_unchanged() {
    let f = start_proxy_auth_forwarder("http://proxy.local:3128")
        .await
        .expect("start");
    assert_eq!(f.url(), "http://proxy.local:3128");
    assert!(start_proxy_auth_forwarder("not a url").await.is_err());
}

/// A plain-HTTP proxied request is forwarded with Proxy-Authorization added.
#[tokio::test]
async fn injects_http() {
    let upstream = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = upstream.local_addr().expect("addr");
    let seen = tokio::spawn(async move {
        let (s, _) = upstream.accept().await.expect("accept");
        let mut r = BufReader::new(s);
        let (line, auth) = read_head(&mut r).await;
        let body = if auth == want_auth() {
            "OK BODY"
        } else {
            "NO AUTH"
        };
        let status = if auth == want_auth() {
            "200 OK"
        } else {
            "407 Proxy Authentication Required"
        };
        r.get_mut()
            .write_all(
                format!(
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .as_bytes(),
            )
            .await
            .expect("respond");
        line
    });

    let f = start_proxy_auth_forwarder(&format!("http://{USER}:{PASS}@{addr}"))
        .await
        .expect("start");
    assert!(f.url().starts_with("http://127.0.0.1:"), "{}", f.url());
    let mut c = TcpStream::connect(f.url().trim_start_matches("http://"))
        .await
        .expect("dial");
    c.write_all(b"GET http://example.invalid/ HTTP/1.1\r\nHost: example.invalid\r\nConnection: close\r\n\r\n")
        .await
        .expect("send");
    let resp = read_all(&mut c).await;
    assert!(resp.starts_with("HTTP/1.1 200 OK\r\n"), "{resp}");
    assert!(resp.ends_with("OK BODY"), "{resp}");
    // The absolute-form request target reaches the upstream proxy.
    assert_eq!(
        seen.await.expect("upstream"),
        "GET http://example.invalid/ HTTP/1.1"
    );
}

/// The CONNECT path authenticates upstream and relays bytes the upstream
/// sent right after its handshake response.
#[tokio::test]
async fn injects_connect() {
    let upstream = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = upstream.local_addr().expect("addr");
    tokio::spawn(async move {
        while let Ok((s, _)) = upstream.accept().await {
            tokio::spawn(async move {
                let mut r = BufReader::new(s);
                let (line, auth) = read_head(&mut r).await;
                let s = r.get_mut();
                if auth != want_auth() {
                    let _ = s.write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"t\"\r\n\r\n").await;
                    return;
                }
                assert_eq!(line, "CONNECT example.invalid:443 HTTP/1.1");
                let _ = s
                    .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\nTUNNEL-OK")
                    .await;
            });
        }
    });

    let f = start_proxy_auth_forwarder(&format!("http://{USER}:{PASS}@{addr}"))
        .await
        .expect("start");
    let mut c = TcpStream::connect(f.url().trim_start_matches("http://"))
        .await
        .expect("dial");
    c.write_all(b"CONNECT example.invalid:443 HTTP/1.1\r\nHost: example.invalid:443\r\n\r\n")
        .await
        .expect("send");
    let resp = read_all(&mut c).await;
    assert!(
        resp.starts_with("HTTP/1.1 200 Connection Established\r\n"),
        "{resp}"
    );
    assert!(resp.ends_with("\r\n\r\nTUNNEL-OK"), "{resp}");

    // Wrong credentials surface as 502 with the upstream status.
    let wrong = start_proxy_auth_forwarder(&format!("http://{USER}:nope@{addr}"))
        .await
        .expect("start");
    let mut c = TcpStream::connect(wrong.url().trim_start_matches("http://"))
        .await
        .expect("dial");
    c.write_all(b"CONNECT example.invalid:443 HTTP/1.1\r\nHost: example.invalid:443\r\n\r\n")
        .await
        .expect("send");
    let mut buf = vec![0u8; 512];
    let n = c.read(&mut buf).await.expect("read");
    let resp = String::from_utf8_lossy(&buf[..n]).to_string();
    assert!(resp.starts_with("HTTP/1.1 502 Bad Gateway\r\n"), "{resp}");
    assert!(
        resp.contains("upstream proxy: 407 Proxy Authentication Required\n"),
        "{resp}"
    );
}

#[tokio::test]
async fn percent_encoded_credentials_are_decoded() {
    let upstream = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = upstream.local_addr().expect("addr");
    let got = tokio::spawn(async move {
        let (s, _) = upstream.accept().await.expect("accept");
        let mut r = BufReader::new(s);
        let (_, auth) = read_head(&mut r).await;
        let _ = r
            .get_mut()
            .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
            .await;
        auth
    });
    let f = start_proxy_auth_forwarder(&format!("http://a%40b:p%3Ass@{addr}"))
        .await
        .expect("start");
    let mut c = TcpStream::connect(f.url().trim_start_matches("http://"))
        .await
        .expect("dial");
    c.write_all(b"GET http://x.invalid/ HTTP/1.1\r\nHost: x.invalid\r\n\r\n")
        .await
        .expect("send");
    let _ = read_all(&mut c).await;
    assert_eq!(
        got.await.expect("upstream"),
        format!("Basic {}", STANDARD.encode("a@b:p:ss"))
    );
}
