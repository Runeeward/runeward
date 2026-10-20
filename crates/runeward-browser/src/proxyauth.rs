//! A loopback forwarding proxy that adds proxy Basic auth for Chromium.
//!
//! Chromium's `--proxy-server` flag cannot carry credentials, so an upstream
//! proxy that requires Basic auth (like Runeward's egress proxy) rejects it
//! and pages render blank. When the proxy URL embeds `user:pass@`,
//! [`start_proxy_auth_forwarder`] listens on `127.0.0.1` and relays each
//! request to the upstream proxy with `Proxy-Authorization` added. The
//! forwarder's own URL carries no credentials and is what Chromium is given.
//! The listener is bound to loopback only, so it is no more exposed than the
//! credentials already are in the sandbox environment.

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::header::{CONNECTION, CONTENT_TYPE, HeaderValue, PROXY_AUTHORIZATION};
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::{JoinHandle, JoinSet};

/// How long dialing the upstream proxy may take.
const DIAL_TIMEOUT: Duration = Duration::from_secs(30);
/// How long a client may take to send its request head.
const READ_HEADER_TIMEOUT: Duration = Duration::from_secs(10);
/// The largest upstream CONNECT response head accepted.
const MAX_HEAD: usize = 64 * 1024;

type Body = BoxBody<Bytes, Box<dyn std::error::Error + Send + Sync>>;

/// A proxy URL that could not be forwarded.
#[derive(Debug, thiserror::Error)]
pub enum ProxyAuthError {
    /// The URL does not parse.
    #[error("parse proxy url: {0}")]
    Parse(#[from] url::ParseError),
    /// The loopback listener could not be opened.
    #[error("listen loopback proxy: {0}")]
    Listen(std::io::Error),
}

/// A running forwarder (or the unchanged proxy URL when no credentials were
/// embedded). Dropping it stops the forwarder.
#[derive(Debug)]
pub struct Forwarder {
    url: String,
    task: Option<JoinHandle<()>>,
}

impl Forwarder {
    /// The proxy URL to hand to Chromium.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Stops accepting and closes the forwarder's open connections
    /// (established CONNECT tunnels finish on their own, as in Go).
    pub fn stop(&mut self) {
        if let Some(t) = self.task.take() {
            t.abort();
        }
    }
}

impl Drop for Forwarder {
    fn drop(&mut self) {
        self.stop();
    }
}

struct Upstream {
    /// `host:port` of the credentialed upstream proxy.
    addr: String,
    /// `Basic <base64(user:pass)>`.
    auth: HeaderValue,
}

/// Starts the forwarder for `raw_proxy`. Without embedded credentials the
/// URL is returned unchanged and nothing is started.
pub async fn start_proxy_auth_forwarder(raw_proxy: &str) -> Result<Forwarder, ProxyAuthError> {
    let u = url::Url::parse(raw_proxy)?;
    let (user, pass) = (u.username(), u.password());
    let host = u.host_str().unwrap_or_default();
    if (user.is_empty() && pass.is_none()) || host.is_empty() {
        return Ok(Forwarder {
            url: raw_proxy.to_owned(),
            task: None,
        });
    }
    let mut creds = percent_decode(user);
    creds.push(b':');
    creds.extend(percent_decode(pass.unwrap_or_default()));
    let auth = HeaderValue::from_str(&format!("Basic {}", STANDARD.encode(creds)))
        .unwrap_or_else(|_| HeaderValue::from_static("Basic"));
    let addr = match u.port_or_known_default() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_owned(),
    };

    let ln = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(ProxyAuthError::Listen)?;
    let local = ln.local_addr().map_err(ProxyAuthError::Listen)?;
    let upstream = Arc::new(Upstream { addr, auth });
    let task = tokio::spawn(serve(ln, upstream));
    Ok(Forwarder {
        url: format!("http://{local}"),
        task: Some(task),
    })
}

async fn serve(ln: TcpListener, upstream: Arc<Upstream>) {
    let mut conns = JoinSet::new();
    loop {
        let stream = tokio::select! {
            r = ln.accept() => match r {
                Ok((s, _)) => s,
                Err(e) => {
                    eprintln!("runeward-browser: proxy-auth forwarder: {e}");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            },
            Some(_) = conns.join_next(), if !conns.is_empty() => continue,
        };
        let upstream = Arc::clone(&upstream);
        conns.spawn(async move {
            let svc = hyper::service::service_fn(move |req| handle(Arc::clone(&upstream), req));
            let _ = hyper::server::conn::http1::Builder::new()
                .timer(TokioTimer::new())
                .header_read_timeout(READ_HEADER_TIMEOUT)
                .serve_connection(TokioIo::new(stream), svc)
                .with_upgrades()
                .await;
        });
    }
}

async fn handle(up: Arc<Upstream>, req: Request<Incoming>) -> Result<Response<Body>, Infallible> {
    Ok(if req.method() == Method::CONNECT {
        handle_connect(&up, req).await
    } else {
        handle_http(&up, req).await
    })
}

/// Go's `http.Error`: a plain-text body ending in a newline.
fn http_error(status: StatusCode, msg: &str) -> Response<Body> {
    let mut resp = Response::new(full(format!("{msg}\n")));
    *resp.status_mut() = status;
    let h = resp.headers_mut();
    h.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    h.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    resp
}

fn full(s: impl Into<Bytes>) -> Body {
    Full::new(s.into()).map_err(|never| match never {}).boxed()
}

async fn dial(addr: &str) -> std::io::Result<TcpStream> {
    tokio::time::timeout(DIAL_TIMEOUT, TcpStream::connect(addr))
        .await
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("dial tcp {addr}: i/o timeout"),
            )
        })?
}

/// Tunnels HTTPS: performs the CONNECT handshake with the upstream (adding
/// auth), answers the client, then splices the two connections.
async fn handle_connect(up: &Upstream, req: Request<Incoming>) -> Response<Body> {
    let target = req
        .uri()
        .authority()
        .map(ToString::to_string)
        .unwrap_or_default();
    let mut upstream = match dial(&up.addr).await {
        Ok(s) => s,
        Err(e) => return http_error(StatusCode::BAD_GATEWAY, &e.to_string()),
    };
    let head = format!(
        "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nProxy-Authorization: {}\r\nProxy-Connection: Keep-Alive\r\n\r\n",
        up.auth.to_str().unwrap_or_default()
    );
    if let Err(e) = upstream.write_all(head.as_bytes()).await {
        return http_error(StatusCode::BAD_GATEWAY, &e.to_string());
    }
    let (status, leftover) = match read_response_head(&mut upstream).await {
        Ok(v) => v,
        Err(e) => {
            return http_error(
                StatusCode::BAD_GATEWAY,
                &format!("upstream proxy handshake: {e}"),
            );
        }
    };
    if !status.starts_with("200") {
        return http_error(
            StatusCode::BAD_GATEWAY,
            &format!("upstream proxy: {status}"),
        );
    }

    tokio::spawn(async move {
        let Ok(upgraded) = hyper::upgrade::on(req).await else {
            return;
        };
        let mut client = TokioIo::new(upgraded);
        // Bytes the upstream sent past its response head belong to the
        // tunnel.
        if !leftover.is_empty() && client.write_all(&leftover).await.is_err() {
            return;
        }
        let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
    });

    let mut resp = Response::new(full(Bytes::new()));
    resp.extensions_mut()
        .insert(hyper::ext::ReasonPhrase::from_static(
            b"Connection Established",
        ));
    resp
}

/// Reads an HTTP response head, returning its status (`"200 OK"`) and any
/// bytes read past it.
async fn read_response_head(s: &mut TcpStream) -> Result<(String, Vec<u8>), String> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 4096];
    loop {
        let n = s.read(&mut chunk).await.map_err(|e| e.to_string())?;
        if n == 0 {
            return Err(if buf.is_empty() {
                "EOF".to_owned()
            } else {
                "unexpected EOF".to_owned()
            });
        }
        buf.extend_from_slice(&chunk[..n]);
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut resp = httparse::Response::new(&mut headers);
        match resp.parse(&buf) {
            Ok(httparse::Status::Complete(len)) => {
                let code = resp.code.unwrap_or_default();
                let reason = resp.reason.unwrap_or_default();
                let status = if reason.is_empty() {
                    code.to_string()
                } else {
                    format!("{code} {reason}")
                };
                return Ok((status, buf[len..].to_vec()));
            }
            Ok(httparse::Status::Partial) if buf.len() < MAX_HEAD => {}
            Ok(httparse::Status::Partial) => return Err("response head too large".to_owned()),
            Err(e) => return Err(format!("malformed HTTP response: {e}")),
        }
    }
}

/// Forwards a plain-HTTP proxied request (absolute-form URL) to the upstream
/// with auth added and relays the response.
async fn handle_http(up: &Upstream, mut req: Request<Incoming>) -> Response<Body> {
    let stream = match dial(&up.addr).await {
        Ok(s) => s,
        Err(e) => return http_error(StatusCode::BAD_GATEWAY, &e.to_string()),
    };
    let (mut sender, conn) =
        match hyper::client::conn::http1::handshake::<_, Incoming>(TokioIo::new(stream)).await {
            Ok(v) => v,
            Err(e) => return http_error(StatusCode::BAD_GATEWAY, &e.to_string()),
        };
    tokio::spawn(conn);
    let h = req.headers_mut();
    h.insert(PROXY_AUTHORIZATION, up.auth.clone());
    h.insert(CONNECTION, HeaderValue::from_static("close"));
    match sender.send_request(req).await {
        Ok(resp) => resp.map(|b| b.map_err(Into::into).boxed()),
        Err(e) => http_error(StatusCode::BAD_GATEWAY, &e.to_string()),
    }
}

/// Decodes `%XX` escapes, as Go's URL user info accessors do.
fn percent_decode(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && i + 2 < b.len()
            && let (Some(h), Some(l)) = (hex_val(b[i + 1]), hex_val(b[i + 2]))
        {
            out.push(h << 4 | l);
            i += 3;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    out
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::percent_decode;

    #[test]
    fn decodes_user_info() {
        assert_eq!(percent_decode("a%40b%3Ac"), b"a@b:c");
        assert_eq!(percent_decode("100%"), b"100%");
        assert_eq!(percent_decode("%zz%4"), b"%zz%4");
    }
}
