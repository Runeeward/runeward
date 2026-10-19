//! The experimental browser IDE: ticket minting and an authenticated
//! reverse proxy (HTTP and WebSocket) to code-server inside the Citadel.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use axum::body::Body;
use axum::extract::{Path, Request, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use http_body_util::{BodyExt, Limited};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::{TokioExecutor, TokioIo};

use super::rfc3339;
use crate::auth::{IDE_COOKIE_NAME, TlsConnection, peer_addr, request_host};
use crate::respond::{MAX_REQUEST_BODY_BYTES, error, json, server_error};
use crate::state::{Caller, SharedState, TicketKind, TicketScope};

pub(crate) const IDE_DISABLED: &str =
    "experimental IDE is disabled; set RUNEWARD_ENABLE_EXPERIMENTAL_IDE=1";
pub(crate) const IDE_UNAVAILABLE: &str = "ide not available for this citadel";
const IDE_TICKET_TTL: Duration = Duration::from_secs(30);

/// The upstream HTTP client for the IDE proxy.
pub(crate) type ProxyClient = Client<HttpConnector, Limited<Body>>;

pub(crate) fn proxy_client() -> ProxyClient {
    Client::builder(TokioExecutor::new()).build_http()
}

pub(crate) async fn ticket(
    State(s): State<SharedState>,
    caller: Caller,
    Path(id): Path<String>,
) -> Response {
    if !s.mgr.experimental_ide_enabled() {
        return error(StatusCode::NOT_FOUND, IDE_DISABLED);
    }
    if s.mgr.sandbox(&id).is_none() {
        return error(StatusCode::NOT_FOUND, "sandbox not found");
    }
    if s.mgr.ide_endpoint(&id).is_none() {
        return error(StatusCode::NOT_FOUND, IDE_UNAVAILABLE);
    }
    match s.issue_ticket(
        TicketScope::sandbox(TicketKind::Ide, &id),
        caller.0.clone(),
        IDE_TICKET_TTL,
    ) {
        Ok((ticket, expires_at)) => json(
            StatusCode::CREATED,
            &serde_json::json!({"ticket": ticket, "expires_at": rfc3339(expires_at)}),
        ),
        Err(e) => server_error(&runeward_controlplane::Error::other(e)),
    }
}

/// Validates the in-cell endpoint: a literal, non-unspecified, non-multicast
/// IP and a port in 1..=65535 (no hostnames, so nothing is resolved).
pub(crate) fn parse_ide_proxy_target(endpoint: &str) -> Result<SocketAddr, String> {
    let addr: SocketAddr = endpoint
        .parse()
        .map_err(|e| format!("invalid ide endpoint {endpoint:?}: {e}"))?;
    let ip: IpAddr = addr.ip();
    if ip.is_unspecified() || ip.is_multicast() {
        return Err(format!("invalid ide endpoint IP {:?}", ip.to_string()));
    }
    if addr.port() == 0 {
        return Err(format!("invalid ide endpoint port {:?}", "0"));
    }
    Ok(addr)
}

/// Hop-by-hop headers a proxy must not forward.
const HOP_HEADERS: &[&str] = &[
    "connection",
    "proxy-connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

fn is_upgrade(h: &HeaderMap) -> Option<HeaderValue> {
    let conn_upgrade = h
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .any(|t| t.trim().eq_ignore_ascii_case("upgrade"));
    if conn_upgrade {
        h.get(header::UPGRADE).cloned()
    } else {
        None
    }
}

fn remove_hop_headers(h: &mut HeaderMap) {
    let listed: Vec<HeaderName> = h
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .filter_map(|t| HeaderName::from_bytes(t.trim().as_bytes()).ok())
        .collect();
    for n in listed {
        h.remove(n);
    }
    for n in HOP_HEADERS {
        h.remove(*n);
    }
}

/// Drops one cookie from the `Cookie` headers.
fn strip_cookie(h: &mut HeaderMap, name: &str) {
    let kept: Vec<String> = h
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .map(str::trim)
        .filter(|kv| !kv.is_empty() && kv.split_once('=').is_none_or(|(k, _)| k != name))
        .map(str::to_owned)
        .collect();
    h.remove(header::COOKIE);
    if !kept.is_empty()
        && let Ok(v) = HeaderValue::from_str(&kept.join("; "))
    {
        h.insert(header::COOKIE, v);
    }
}

/// Re-roots upstream redirects and cookies under the Citadel's IDE prefix.
fn rewrite_response_headers(h: &mut HeaderMap, prefix: &str) {
    if let Some(loc) = h.get(header::LOCATION).and_then(|v| v.to_str().ok())
        && loc.starts_with('/')
        && !loc.starts_with("//")
        && !loc.starts_with(prefix)
        && let Ok(v) = HeaderValue::from_str(&format!("{prefix}{loc}"))
    {
        h.insert(header::LOCATION, v);
    }
    let cookies: Vec<HeaderValue> = h.get_all(header::SET_COOKIE).iter().cloned().collect();
    if cookies.is_empty() {
        return;
    }
    h.remove(header::SET_COOKIE);
    for c in cookies {
        let Ok(s) = c.to_str() else { continue };
        let mut parts: Vec<String> = s.split(';').map(|p| p.trim().to_owned()).collect();
        let path_at = parts.iter().position(|p| {
            p.split_once('=')
                .is_some_and(|(k, _)| k.trim().eq_ignore_ascii_case("path"))
        });
        let new_path = format!("Path={prefix}/");
        match path_at {
            Some(i) => {
                let v = parts[i]
                    .split_once('=')
                    .map(|(_, v)| v.trim())
                    .unwrap_or("");
                if v.is_empty() || v == "/" {
                    parts[i] = new_path;
                }
            }
            None => parts.insert(1.min(parts.len()), new_path),
        }
        if let Ok(v) = HeaderValue::from_str(&parts.join("; ")) {
            h.append(header::SET_COOKIE, v);
        }
    }
}

/// Reverse-proxies HTTP and WebSocket traffic to the in-cell code-server
/// after ticket, cookie or bearer authentication.
pub(crate) async fn proxy(
    State(s): State<SharedState>,
    Path(params): Path<Vec<(String, String)>>,
    mut req: Request,
) -> Response {
    if !s.mgr.experimental_ide_enabled() {
        return error(StatusCode::NOT_FOUND, IDE_DISABLED);
    }
    let id = params
        .iter()
        .find(|(k, _)| k == "id")
        .map(|(_, v)| v.clone())
        .unwrap_or_default();
    let Some(endpoint) = s.mgr.ide_endpoint(&id) else {
        return error(StatusCode::NOT_FOUND, IDE_UNAVAILABLE);
    };
    let prefix = format!("/v1/citadels/{id}/ide");
    if req.uri().path() == prefix {
        // Prefer a trailing slash so relative asset URLs resolve; the
        // consumed ?ticket= is not replayed.
        let mut resp = StatusCode::TEMPORARY_REDIRECT.into_response();
        if let Ok(v) = HeaderValue::from_str(&format!("{prefix}/")) {
            resp.headers_mut().insert(header::LOCATION, v);
        }
        return resp;
    }
    let target = match parse_ide_proxy_target(&endpoint) {
        Ok(t) => t,
        Err(e) => return server_error(&runeward_controlplane::Error::other(e)),
    };

    let host = request_host(&req);
    let tls = req.extensions().get::<TlsConnection>().is_some();
    let client_ip = peer_addr(req.extensions()).map(|a| a.ip().to_string());
    let upgrade = is_upgrade(req.headers());
    let path = req.uri().path().strip_prefix(&prefix).unwrap_or("/");
    let path = if path.is_empty() { "/" } else { path };
    let pq = match req.uri().query() {
        Some(q) => format!("{path}?{q}"),
        None => path.to_owned(),
    };
    let Ok(uri) = format!("http://{target}{pq}").parse::<Uri>() else {
        return error(StatusCode::BAD_GATEWAY, "ide upstream unavailable");
    };

    let client_upgrade = upgrade.is_some().then(|| hyper::upgrade::on(&mut req));
    let (parts, body) = req.into_parts();
    let mut out = http::Request::builder()
        .method(parts.method.clone())
        .uri(uri)
        .version(http::Version::HTTP_11);
    let Some(h) = out.headers_mut() else {
        return error(StatusCode::BAD_GATEWAY, "ide upstream unavailable");
    };
    *h = parts.headers.clone();
    remove_hop_headers(h);
    if let Some(proto) = &upgrade {
        h.insert(header::CONNECTION, HeaderValue::from_static("Upgrade"));
        h.insert(header::UPGRADE, proto.clone());
    }
    // Keep the browser-facing Host: code-server rejects WebSocket upgrades
    // whose Origin does not match it.
    if let Ok(v) = HeaderValue::from_str(&host) {
        h.insert(header::HOST, v);
    }
    if let Some(ip) = client_ip {
        let xff = match h.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
            Some(prior) => format!("{prior}, {ip}"),
            None => ip,
        };
        if let Ok(v) = HeaderValue::from_str(&xff) {
            h.insert("x-forwarded-for", v);
        }
    }
    if !h.contains_key("x-forwarded-host")
        && let Ok(v) = HeaderValue::from_str(&host)
    {
        h.insert("x-forwarded-host", v);
    }
    if !h.contains_key("x-forwarded-proto") {
        h.insert(
            "x-forwarded-proto",
            HeaderValue::from_static(if tls { "https" } else { "http" }),
        );
    }
    if let Ok(v) = HeaderValue::from_str(&prefix) {
        h.insert("x-forwarded-prefix", v);
    }
    // code-server runs with --auth none on the container network; outer
    // credentials never reach it.
    h.remove(header::AUTHORIZATION);
    strip_cookie(h, IDE_COOKIE_NAME);
    let Ok(out) = out.body(Limited::new(body, MAX_REQUEST_BODY_BYTES)) else {
        return error(StatusCode::BAD_GATEWAY, "ide upstream unavailable");
    };

    let mut resp = match s.ide_client.request(out).await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(sandbox = %id, error = %e, "ide proxy error");
            return error(StatusCode::BAD_GATEWAY, "ide upstream unavailable");
        }
    };
    if resp.status() == StatusCode::SWITCHING_PROTOCOLS {
        let Some(client_upgrade) = client_upgrade else {
            return error(StatusCode::BAD_GATEWAY, "ide upstream unavailable");
        };
        let upstream = hyper::upgrade::on(&mut resp);
        tokio::spawn(async move {
            match tokio::try_join!(client_upgrade, upstream) {
                Ok((c, u)) => {
                    let mut c = TokioIo::new(c);
                    let mut u = TokioIo::new(u);
                    let _ = tokio::io::copy_bidirectional(&mut c, &mut u).await;
                }
                Err(e) => {
                    tracing::error!(sandbox = %id, error = %e, "ide websocket upgrade failed")
                }
            }
        });
        let (parts, _) = resp.into_parts();
        return http::Response::from_parts(parts, Body::empty());
    }
    let (mut parts, body) = resp.into_parts();
    remove_hop_headers(&mut parts.headers);
    rewrite_response_headers(&mut parts.headers, &prefix);
    let body = body.map_err(axum::Error::new).boxed_unsync();
    http::Response::from_parts(parts, Body::new(body))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_targets() {
        for ok in ["127.0.0.1:8080", "[::1]:8080", "10.0.0.5:65535"] {
            assert!(parse_ide_proxy_target(ok).is_ok(), "{ok}");
        }
        for bad in [
            "example.com:8080",
            "127.0.0.1",
            "0.0.0.0:8080",
            "127.0.0.1:65536",
            "224.0.0.1:80",
            "127.0.0.1:0",
        ] {
            assert!(parse_ide_proxy_target(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn header_rewrites() {
        let prefix = "/v1/citadels/x/ide";
        let mut h = HeaderMap::new();
        h.insert(header::LOCATION, HeaderValue::from_static("/login?to=/"));
        h.append(
            header::SET_COOKIE,
            HeaderValue::from_static("a=1; Path=/; HttpOnly"),
        );
        h.append(header::SET_COOKIE, HeaderValue::from_static("b=2"));
        h.append(
            header::SET_COOKIE,
            HeaderValue::from_static("c=3; Path=/deep"),
        );
        rewrite_response_headers(&mut h, prefix);
        assert_eq!(h[header::LOCATION], "/v1/citadels/x/ide/login?to=/");
        let cookies: Vec<_> = h.get_all(header::SET_COOKIE).iter().collect();
        assert_eq!(cookies[0], "a=1; Path=/v1/citadels/x/ide/; HttpOnly");
        assert_eq!(cookies[1], "b=2; Path=/v1/citadels/x/ide/");
        assert_eq!(cookies[2], "c=3; Path=/deep");

        let mut h = HeaderMap::new();
        h.insert(
            header::COOKIE,
            HeaderValue::from_static("rw_ide_sess=s; other=1"),
        );
        strip_cookie(&mut h, IDE_COOKIE_NAME);
        assert_eq!(h[header::COOKIE], "other=1");
        h.insert(
            header::CONNECTION,
            HeaderValue::from_static("keep-alive, x-custom"),
        );
        h.insert("x-custom", HeaderValue::from_static("1"));
        remove_hop_headers(&mut h);
        assert!(!h.contains_key("x-custom") && !h.contains_key(header::CONNECTION));
    }
}
