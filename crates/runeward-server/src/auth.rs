//! Authentication, tenancy guards, CSRF and the other request middleware,
//! in the order Go's `Handler` chains them.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::Response;
use runeward_authz::Principal;
use runeward_controlplane::with_actor;
use subtle::ConstantTimeEq;

use crate::respond::error;
use crate::state::{IdeCookieSession, SharedState, TicketKind, TicketScope, lock, random_id};

/// The IDE session cookie.
pub(crate) const IDE_COOKIE_NAME: &str = "rw_ide_sess";
/// How long an IDE cookie session lasts.
pub(crate) const IDE_SESSION_TTL: Duration = Duration::from_secs(2 * 60 * 60);

/// Marks a request that arrived over TLS (Go's `r.TLS != nil`).
#[derive(Debug, Clone, Copy)]
pub(crate) struct TlsConnection;

const CITADELS_PREFIX: &str = "/v1/citadels/";

// ---------------------------------------------------------------------------
// Request helpers.

/// The first value of query parameter `name`, URL-decoded (Go's
/// `r.URL.Query().Get`).
pub(crate) fn query_get(req_uri: &axum::http::Uri, name: &str) -> String {
    req_uri
        .query()
        .and_then(|q| {
            url::form_urlencoded::parse(q.as_bytes())
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.into_owned())
        })
        .unwrap_or_default()
}

/// The caller's token from `Authorization` (an optional `Bearer ` prefix is
/// stripped) or `X-Runeward-Token`. Query-string tokens are never accepted.
pub(crate) fn presented_token(headers: &HeaderMap) -> String {
    if let Some(h) = header_str(headers, header::AUTHORIZATION.as_str())
        && !h.is_empty()
    {
        return h.strip_prefix("Bearer ").unwrap_or(h).trim().to_owned();
    }
    header_str(headers, "x-runeward-token")
        .map(|h| h.trim().to_owned())
        .unwrap_or_default()
}

fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

/// The browser-facing host (Go's `r.Host`): the `Host` header, else the
/// request target's authority.
pub(crate) fn request_host(req: &Request) -> String {
    host_of(req.headers(), req.uri())
}

pub(crate) fn host_of(headers: &HeaderMap, uri: &axum::http::Uri) -> String {
    header_str(headers, header::HOST.as_str())
        .map(str::to_owned)
        .or_else(|| uri.authority().map(|a| a.as_str().to_owned()))
        .unwrap_or_default()
}

/// The peer address, when the transport recorded one.
pub(crate) fn peer_addr(ext: &axum::http::Extensions) -> Option<SocketAddr> {
    ext.get::<ConnectInfo<SocketAddr>>().map(|c| c.0)
}

/// Go's `url.Parse(origin).Host`: the authority of `scheme://host[:port]`,
/// without user info. `None` when the origin is not a hierarchical URL.
pub(crate) fn origin_host(origin: &str) -> Option<String> {
    let (scheme, rest) = origin.split_once(':')?;
    if scheme.is_empty()
        || !scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
        || !scheme.starts_with(|c: char| c.is_ascii_alphabetic())
    {
        return None;
    }
    let Some(rest) = rest.strip_prefix("//") else {
        return Some(String::new());
    };
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..end];
    let host = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    Some(host.to_owned())
}

/// Same-origin check for browser WebSockets: no Origin (native tooling) is
/// allowed; otherwise its host must equal the request Host.
pub(crate) fn same_origin(headers: &HeaderMap, host: &str) -> bool {
    let Some(origin) = headers.get(header::ORIGIN).filter(|v| !v.is_empty()) else {
        return true;
    };
    origin
        .to_str()
        .ok()
        .and_then(origin_host)
        .is_some_and(|h| h == host)
}

/// Splits `/v1/citadels/{id}{suffix}` into the id, when it has no slash.
fn citadel_id_with_suffix<'a>(path: &'a str, suffix: &str) -> Option<&'a str> {
    let id = path.strip_prefix(CITADELS_PREFIX)?.strip_suffix(suffix)?;
    (!id.is_empty()).then_some(id)
}

/// The Citadel of a terminal WebSocket path.
pub(crate) fn terminal_sandbox_id(path: &str) -> Option<&str> {
    citadel_id_with_suffix(path, "/terminal")
}

/// The Citadel of a conversation-stream path.
pub(crate) fn conversation_stream_sandbox_id(path: &str) -> Option<&str> {
    citadel_id_with_suffix(path, "/conversation/stream").filter(|id| !id.contains('/'))
}

/// Whether `path` is the IDE reverse proxy (`/v1/citadels/{id}/ide[/...]`).
pub(crate) fn is_ide_path(path: &str) -> bool {
    ide_sandbox_id(path).is_some()
}

/// The Citadel of an IDE proxy path.
pub(crate) fn ide_sandbox_id(path: &str) -> Option<&str> {
    let rest = path.strip_prefix(CITADELS_PREFIX)?;
    let i = rest.find('/')?;
    let after = &rest[i..];
    if i == 0 || !(after == "/ide" || after.starts_with("/ide/")) {
        return None;
    }
    Some(&rest[..i])
}

/// The first path segment after `prefix`, when the path has that prefix.
fn segment_after<'a>(path: &'a str, prefix: &str) -> Option<&'a str> {
    let rest = path.strip_prefix(prefix)?;
    Some(rest.split('/').next().unwrap_or_default())
}

// ---------------------------------------------------------------------------
// Tickets and IDE cookie sessions.

enum TicketOutcome {
    NotPresented,
    Invalid,
    Valid(Option<Arc<Principal>>),
}

impl crate::state::AppState {
    /// Consumes a `?ticket=` scoped to the request path's kind.
    fn consume_request_ticket(&self, req: &Request) -> TicketOutcome {
        let ticket = query_get(req.uri(), "ticket");
        let ticket = ticket.trim();
        if ticket.is_empty() {
            return TicketOutcome::NotPresented;
        }
        let path = req.uri().path();
        let want = if let Some(id) = conversation_stream_sandbox_id(path) {
            TicketScope::sandbox(TicketKind::Conversation, id)
        } else if let Some(id) = terminal_sandbox_id(path) {
            TicketScope::sandbox(TicketKind::Terminal, id)
        } else if let Some(id) = ide_sandbox_id(path) {
            TicketScope::sandbox(TicketKind::Ide, id)
        } else {
            TicketScope {
                kind: TicketKind::Download,
                sandbox_id: String::new(),
                path: String::new(),
            }
        };
        match self.consume_ticket(ticket, &want, req.method(), path) {
            Some(p) => TicketOutcome::Valid(p),
            None => TicketOutcome::Invalid,
        }
    }

    /// Records an IDE cookie session for a consumed ticket and returns the
    /// `Set-Cookie` value.
    pub(crate) fn attach_ide_session(
        &self,
        req_headers: &HeaderMap,
        req_ext: &axum::http::Extensions,
        host: &str,
        sandbox_id: &str,
        principal: Option<Arc<Principal>>,
    ) -> Option<HeaderValue> {
        let sid = random_id();
        let now = SystemTime::now();
        let expires_at = now + IDE_SESSION_TTL;
        {
            let mut sessions = lock(&self.ide_sessions);
            sessions.retain(|_, s| now < s.expires_at);
            sessions.insert(
                sid.clone(),
                IdeCookieSession {
                    sandbox_id: sandbox_id.to_owned(),
                    principal,
                    expires_at,
                },
            );
        }
        let expires = chrono::DateTime::<chrono::Utc>::from(expires_at)
            .format("%a, %d %b %Y %H:%M:%S GMT")
            .to_string();
        let mut cookie = format!(
            "{IDE_COOKIE_NAME}={sid}; Path=/v1/citadels/{sandbox_id}/ide; Expires={expires}; HttpOnly"
        );
        // Loopback HTTP is the local-development exception: browsers reject
        // Secure cookies from http://127.0.0.1. Both the Host and the peer
        // must be loopback, so a spoofed Host cannot relax it.
        if ide_cookie_secure(req_headers, req_ext, host) {
            cookie.push_str("; Secure");
        }
        cookie.push_str("; SameSite=Strict");
        HeaderValue::from_str(&cookie).ok()
    }

    fn ide_session_from_cookie(
        &self,
        headers: &HeaderMap,
        sandbox_id: &str,
    ) -> Option<Option<Arc<Principal>>> {
        let value = cookie_value(headers, IDE_COOKIE_NAME)?;
        if value.trim().is_empty() {
            return None;
        }
        let now = SystemTime::now();
        let mut sessions = lock(&self.ide_sessions);
        sessions.retain(|_, s| now < s.expires_at);
        let sess = sessions.get(&value)?;
        if sess.sandbox_id != sandbox_id {
            return None;
        }
        Some(sess.principal.clone())
    }

    /// Whether `r` targets a static dashboard file that must load before the
    /// login screen. An allowlist, so new GET endpoints are authenticated
    /// by default.
    fn public_dashboard_asset(&self, method: &Method, path: &str) -> bool {
        self.dashboard
            && (method == Method::GET || method == Method::HEAD)
            && matches!(
                path,
                "/" | "/index.html" | "/app.js" | "/style.css" | "/logo.png"
            )
    }
}

/// Whether the IDE cookie must carry `Secure`: always, except plain HTTP
/// where both the Host and the connected peer are loopback.
pub(crate) fn ide_cookie_secure(
    headers: &HeaderMap,
    ext: &axum::http::Extensions,
    host: &str,
) -> bool {
    if ext.get::<TlsConnection>().is_some()
        || header_str(headers, "x-forwarded-proto")
            .is_some_and(|p| p.trim().eq_ignore_ascii_case("https"))
    {
        return true;
    }
    let peer = peer_addr(ext).map(|a| a.to_string()).unwrap_or_default();
    !(is_loopback_address(host) && is_loopback_address(&peer))
}

/// Whether `address` (`host`, `host:port` or `[v6]:port`) is loopback.
pub(crate) fn is_loopback_address(address: &str) -> bool {
    let mut host = address.trim();
    if let Some((h, port)) = split_host_port(host)
        && !port.is_empty()
    {
        host = h;
    }
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

/// Go's `net.SplitHostPort` for the forms that matter here.
fn split_host_port(s: &str) -> Option<(&str, &str)> {
    if let Some(rest) = s.strip_prefix('[') {
        let (h, p) = rest.split_once("]:")?;
        return Some((h, p));
    }
    let (h, p) = s.rsplit_once(':')?;
    (!h.contains(':')).then_some((h, p))
}

/// The value of cookie `name` from the request's `Cookie` headers.
pub(crate) fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|kv| kv.trim().split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v.trim_matches('"').to_owned())
}

// ---------------------------------------------------------------------------
// Middleware.

fn unauthorized(msg: &str) -> Response {
    let mut resp = error(StatusCode::UNAUTHORIZED, msg);
    resp.headers_mut()
        .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    resp
}

/// Runs the rest of the chain as `principal` (attached for handlers and
/// the MCP router, and as the Chronicle actor).
async fn run_as(principal: Option<Arc<Principal>>, mut req: Request, next: Next) -> Response {
    match principal {
        Some(p) => {
            let name = p.name.clone();
            req.extensions_mut().insert(p);
            with_actor(&name, next.run(req)).await
        }
        None => next.run(req).await,
    }
}

/// Selects the active scheme: RBAC (each token, or OIDC JWT, maps to a
/// named principal), else the legacy single token, else open mode.
/// `/healthz` and the dashboard shell are always public; WebSockets and
/// downloads may present a single-use `?ticket=`; the IDE proxy also
/// accepts its cookie session.
pub(crate) async fn authenticate(
    State(s): State<SharedState>,
    req: Request,
    next: Next,
) -> Response {
    if s.authz.is_none() && s.token.is_empty() {
        return next.run(req).await;
    }
    let path = req.uri().path().to_owned();
    if path == "/healthz" || s.public_dashboard_asset(req.method(), &path) {
        return next.run(req).await;
    }
    match s.consume_request_ticket(&req) {
        TicketOutcome::Invalid => return unauthorized("unauthorized: invalid or expired ticket"),
        TicketOutcome::Valid(p) => {
            let cookie = ide_sandbox_id(&path).and_then(|sid| {
                let host = request_host(&req);
                s.attach_ide_session(req.headers(), req.extensions(), &host, sid, p.clone())
            });
            let principal = if s.authz.is_some() { p } else { None };
            let mut resp = run_as(principal, req, next).await;
            if let Some(c) = cookie {
                resp.headers_mut().append(header::SET_COOKIE, c);
            }
            return resp;
        }
        TicketOutcome::NotPresented => {}
    }
    if let Some(sid) = ide_sandbox_id(&path)
        && let Some(p) = s.ide_session_from_cookie(req.headers(), sid)
    {
        let principal = if s.authz.is_some() { p } else { None };
        return run_as(principal, req, next).await;
    }
    let token = presented_token(req.headers());
    if let Some(store) = &s.authz {
        return match store.identify(&token).await {
            Some(p) => run_as(Some(p), req, next).await,
            None => unauthorized("unauthorized: unknown or missing API token"),
        };
    }
    if token.is_empty() || !bool::from(token.as_bytes().ct_eq(s.token.as_bytes())) {
        return unauthorized("unauthorized: missing or invalid API token");
    }
    next.run(req).await
}

/// Per-tenant resource access under RBAC: unknown or other-tenant Citadels,
/// Cohorts and snapshots are 404 (no existence probing), the bundle export
/// is admin-only and the approval inbox needs approval rights. Open/legacy
/// mode and admins are unrestricted.
pub(crate) async fn ownership_guard(
    State(s): State<SharedState>,
    req: Request,
    next: Next,
) -> Response {
    let Some(p) = req.extensions().get::<Arc<Principal>>().cloned() else {
        return next.run(req).await;
    };
    if p.admin {
        return next.run(req).await;
    }
    let path = req.uri().path();
    if let Some(id) = segment_after(path, CITADELS_PREFIX)
        && !id.is_empty()
        && s.mgr.sandbox_owner(id).is_none_or(|o| o != p.tenant_id())
    {
        return error(StatusCode::NOT_FOUND, "sandbox not found");
    }
    if let Some(id) = segment_after(path, "/v1/cohorts/")
        && !id.is_empty()
        && !s.fleet_owned_by(id, p.tenant_id())
    {
        return error(StatusCode::NOT_FOUND, "fleet not found");
    }
    if let Some(id) = path
        .strip_prefix("/v1/snapshots/")
        .and_then(|r| r.strip_suffix("/restore"))
        && !s.snapshot_visible_to(&p, id)
    {
        return error(StatusCode::NOT_FOUND, "snapshot not found");
    }
    if path == "/v1/chronicle/export" {
        return error(
            StatusCode::FORBIDDEN,
            "not authorized to export audit bundle",
        );
    }
    if path.starts_with("/v1/conclave") && !p.may_approve() {
        return error(StatusCode::FORBIDDEN, "not authorized to view approvals");
    }
    next.run(req).await
}

/// Refuses state-changing requests whose Origin (when present) does not
/// match the Host. Non-browser clients send no Origin and pass.
pub(crate) async fn csrf_guard(req: Request, next: Next) -> Response {
    let safe = matches!(*req.method(), Method::GET | Method::HEAD | Method::OPTIONS);
    if !safe && !same_origin(req.headers(), &request_host(&req)) {
        return error(StatusCode::FORBIDDEN, "cross-origin request refused");
    }
    next.run(req).await
}

/// Per-client-IP rate limiting.
pub(crate) async fn rate_limit(State(s): State<SharedState>, req: Request, next: Next) -> Response {
    if let Some(l) = &s.limiter {
        let ip = peer_addr(req.extensions())
            .map(|a| a.ip().to_string())
            .unwrap_or_default();
        if !l.allow(&ip) {
            return error(StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded");
        }
    }
    next.run(req).await
}

const API_CSP: &str = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'";
const DASHBOARD_CSP: &str = "default-src 'self'; script-src 'self' https://cdn.jsdelivr.net; style-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; img-src 'self' data:; font-src 'self' https://cdn.jsdelivr.net; connect-src 'self' ws: wss:; base-uri 'self'; object-src 'none'; frame-ancestors 'none'";

/// Go's `securityHeaders`. Handler-set values win (Go sets these before
/// the handler runs). The IDE proxy keeps upstream CSP and framing.
pub(crate) async fn security_headers(req: Request, next: Next) -> Response {
    let path = req.uri().path().to_owned();
    let mut resp = next.run(req).await;
    let h = resp.headers_mut();
    let ide = is_ide_path(&path);
    let mut set = |name: header::HeaderName, value: &'static str| {
        if !h.contains_key(&name) {
            h.insert(name, HeaderValue::from_static(value));
        }
    };
    set(header::X_CONTENT_TYPE_OPTIONS, "nosniff");
    set(header::REFERRER_POLICY, "no-referrer");
    if ide {
        // Upstream may set its own Cache-Control; Go adds no-store beside it.
        if h.get_all(header::CACHE_CONTROL)
            .iter()
            .all(|v| v != "no-store")
        {
            h.append(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        }
        return resp;
    }
    set(
        header::HeaderName::from_static("permissions-policy"),
        "camera=(), microphone=(), geolocation=()",
    );
    set(header::X_FRAME_OPTIONS, "DENY");
    if path.starts_with("/v1/") || path == "/mcp" || path.starts_with("/mcp/") {
        set(header::CONTENT_SECURITY_POLICY, API_CSP);
        set(header::CACHE_CONTROL, "no-store");
    } else {
        set(header::CONTENT_SECURITY_POLICY, DASHBOARD_CSP);
    }
    resp
}

/// Structured access log; `/metrics` and `/healthz` are not logged.
pub(crate) async fn log_requests(req: Request, next: Next) -> Response {
    let start = Instant::now();
    let method = req.method().clone();
    let path = req.uri().path().to_owned();
    let resp = next.run(req).await;
    if path != "/metrics" && path != "/healthz" {
        tracing::info!(
            method = %method,
            path = %path,
            status = resp.status().as_u16(),
            duration_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX),
            "request"
        );
    }
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_classifiers() {
        assert_eq!(terminal_sandbox_id("/v1/citadels/a/terminal"), Some("a"));
        assert_eq!(terminal_sandbox_id("/v1/citadels//terminal"), None);
        for (path, id) in [
            ("/v1/citadels/cit-1/conversation/stream", Some("cit-1")),
            ("/v1/citadels/cit-1/conversation", None),
            ("/v1/citadels/a/b/conversation/stream", None),
        ] {
            assert_eq!(conversation_stream_sandbox_id(path), id, "{path}");
        }
        assert_eq!(ide_sandbox_id("/v1/citadels/x/ide"), Some("x"));
        assert_eq!(ide_sandbox_id("/v1/citadels/x/ide/static/a.js"), Some("x"));
        assert_eq!(ide_sandbox_id("/v1/citadels/x/ide-ticket"), None);
        assert_eq!(ide_sandbox_id("/v1/citadels/x"), None);
        assert!(!is_ide_path("/v1/citadels/x/idea"));
    }

    #[test]
    fn origins_parse_like_go() {
        assert_eq!(
            origin_host("http://a.example:8080").as_deref(),
            Some("a.example:8080")
        );
        assert_eq!(origin_host("https://u:p@h/x?y").as_deref(), Some("h"));
        assert_eq!(origin_host("null").as_deref(), None);
        assert_eq!(origin_host("mailto:x").as_deref(), Some(""));
        let mut h = HeaderMap::new();
        assert!(same_origin(&h, "a:1"));
        h.insert(header::ORIGIN, HeaderValue::from_static("http://a:1"));
        assert!(same_origin(&h, "a:1"));
        assert!(!same_origin(&h, "b:1"));
    }

    #[test]
    fn loopback_addresses() {
        for a in [
            "127.0.0.1:8080",
            "[::1]:1",
            "localhost",
            "LOCALHOST:80",
            "::1",
            "127.0.0.2",
        ] {
            assert!(is_loopback_address(a), "{a}");
        }
        for a in ["198.51.100.25:43210", "runeward.example", "", "10.0.0.1"] {
            assert!(!is_loopback_address(a), "{a}");
        }
    }

    #[test]
    fn tokens_and_cookies() {
        let mut h = HeaderMap::new();
        assert_eq!(presented_token(&h), "");
        h.insert("x-runeward-token", HeaderValue::from_static(" t2 "));
        assert_eq!(presented_token(&h), "t2");
        h.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer t1 "),
        );
        assert_eq!(presented_token(&h), "t1");
        h.insert(
            header::COOKIE,
            HeaderValue::from_static("a=1; rw_ide_sess=abc"),
        );
        assert_eq!(cookie_value(&h, IDE_COOKIE_NAME).as_deref(), Some("abc"));
        assert_eq!(cookie_value(&h, "zz"), None);
    }
}
