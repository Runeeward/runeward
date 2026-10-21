//! Cooperative forward proxy (sandboxes point `HTTP(S)_PROXY` at it). It
//! enforces the policy on `CONNECT` tunnels and on plain absolute-URI HTTP
//! requests, optionally behind HTTP Basic proxy authentication.

use std::convert::Infallible;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use base64::Engine as _;
use bytes::Bytes;
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use hyper::body::Incoming;
use hyper::header::{self, HeaderValue};
use hyper::{Method, Request, Response, StatusCode, Uri, Version};
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinSet;

use crate::broker::{Broker, Target};
use crate::decision_log::Decision;
use crate::gate::{DenyReason, EgressRequest, Frontend, Gate, GateDecision, HostSource};
use crate::logger::{Logger, Sink};
use crate::netutil::parse_ip;
use crate::policy::Policy;
use crate::resolve::{PinnedTarget, Resolver, host_with_default_port, system_resolver};

/// Bounds dials to origins and CONNECT targets.
pub const DIAL_TIMEOUT: Duration = Duration::from_secs(30);

/// Bounds how long a client may take to send request headers.
pub const READ_HEADER_TIMEOUT: Duration = Duration::from_secs(10);

/// Response body type produced by [`Proxy::handle`].
pub type ProxyBody = BoxBody<Bytes, hyper::Error>;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// A forward proxy enforcing a [`Policy`] on CONNECT tunnels (HTTPS) and
/// plain absolute-URI HTTP requests.
pub struct Proxy {
    gate: Gate,
    sink: Sink,
    broker: Option<Arc<Broker>>,
    auth_user: String,
    auth_pass: String,
    tls: Arc<rustls::ClientConfig>,
}

impl std::fmt::Debug for Proxy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Proxy")
            .field("gate", &self.gate)
            .field("sink", &self.sink)
            .field("broker", &self.broker.is_some())
            .field(
                "auth",
                &(!self.auth_user.is_empty() || !self.auth_pass.is_empty()),
            )
            .finish_non_exhaustive()
    }
}

static DEFAULT_TLS: LazyLock<Arc<rustls::ClientConfig>> = LazyLock::new(|| {
    let roots = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    Arc::new(tls_client_config(roots))
});

/// The shared client config trusting the bundled Mozilla roots.
pub(crate) fn default_tls() -> Arc<rustls::ClientConfig> {
    DEFAULT_TLS.clone()
}

/// Builds a rustls client config (ring provider, safe defaults) trusting
/// `roots`.
pub fn tls_client_config(roots: rustls::RootCertStore) -> rustls::ClientConfig {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    match rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
    {
        Ok(b) => b.with_root_certificates(roots).with_no_client_auth(),
        // The ring provider always supports the safe defaults.
        Err(_) => unreachable!("ring provider lacks default protocol versions"),
    }
}

impl Proxy {
    /// Creates a proxy enforcing `policy` with the system resolver, no
    /// logger, no sandbox id and no proxy authentication.
    pub fn new(policy: Policy) -> Self {
        Self {
            gate: Gate::new(policy, system_resolver()),
            sink: Sink::default(),
            broker: None,
            auth_user: String::new(),
            auth_pass: String::new(),
            tls: DEFAULT_TLS.clone(),
        }
    }

    /// Associates decisions with a sandbox for dashboard egress logs.
    #[must_use]
    pub fn with_sandbox_id(mut self, id: impl Into<String>) -> Self {
        self.sink.sandbox_id = id.into();
        self
    }

    /// Sends allow/deny lines to `logger`.
    #[must_use]
    pub fn with_logger(mut self, logger: Logger) -> Self {
        self.sink.logger = Some(logger);
        self
    }

    /// Requires `Proxy-Authorization: Basic` with these credentials on every
    /// request (when either is non-empty). This keeps a proxy bound on a
    /// shared interface from being used by other local/LAN processes.
    #[must_use]
    pub fn with_auth(mut self, user: impl Into<String>, pass: impl Into<String>) -> Self {
        self.auth_user = user.into();
        self.auth_pass = pass.into();
        self
    }

    /// Replaces the hostname resolver used for pinning.
    #[must_use]
    pub fn with_resolver(mut self, resolver: Arc<dyn Resolver>) -> Self {
        self.gate = self.gate.with_resolver(resolver);
        self
    }

    /// Attaches a request [`Broker`]: its endpoints become reachable,
    /// inspected endpoints are terminated and checked per request, and every
    /// decision is also published on [`Broker::subscribe`]. Adopts the
    /// broker's sandbox id when none is set.
    #[must_use]
    pub fn with_broker(mut self, broker: Arc<Broker>) -> Self {
        self.gate = self.gate.with_broker(Arc::clone(&broker));
        self.sink.events = Some(broker.events.clone());
        if self.sink.sandbox_id.trim().is_empty() {
            self.sink.sandbox_id = broker.sandbox_id().to_string();
        }
        self.broker = Some(broker);
        self
    }

    /// Replaces the TLS client config used for absolute `https://` requests
    /// (the default trusts the bundled Mozilla roots).
    #[must_use]
    pub fn with_tls_config(mut self, config: Arc<rustls::ClientConfig>) -> Self {
        self.tls = config;
        self
    }

    /// The enforced policy.
    pub fn policy(&self) -> &Policy {
        self.gate.policy()
    }

    /// Whether `req` satisfies the configured proxy credentials. Always true
    /// when none are configured.
    fn auth_ok<B>(&self, req: &Request<B>) -> bool {
        if self.auth_user.is_empty() && self.auth_pass.is_empty() {
            return true;
        }
        let Some(value) = req
            .headers()
            .get(header::PROXY_AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
        else {
            return false;
        };
        let Some((user, pass)) = parse_proxy_basic_auth(value) else {
            return false;
        };
        let user_ok = constant_time_eq(&user, self.auth_user.as_bytes());
        let pass_ok = constant_time_eq(&pass, self.auth_pass.as_bytes());
        user_ok && pass_ok
    }

    /// Handles one proxy request. Mount this in any hyper server built with
    /// `.with_upgrades()` (CONNECT needs the connection upgrade).
    pub async fn handle(self: Arc<Self>, req: Request<Incoming>) -> Response<ProxyBody> {
        if !self.auth_ok(&req) {
            let mut resp = http_error(
                StatusCode::PROXY_AUTHENTICATION_REQUIRED,
                "Proxy Authentication Required",
            );
            resp.headers_mut().insert(
                header::PROXY_AUTHENTICATE,
                HeaderValue::from_static(r#"Basic realm="runeward-egress""#),
            );
            return resp;
        }
        if req.method() == Method::CONNECT {
            self.handle_connect(req).await
        } else {
            self.handle_http(req).await
        }
    }

    /// Checks a CONNECT target against the policy, dials the pinned IP, then
    /// upgrades the client connection and splices it to the target.
    async fn handle_connect(self: Arc<Self>, req: Request<Incoming>) -> Response<ProxyBody> {
        let target = request_authority(&req);
        let Ok((host, port)) = host_with_default_port(&target, "443") else {
            return http_error(StatusCode::BAD_REQUEST, "Bad Request");
        };
        let ereq = EgressRequest {
            frontend: Frontend::Connect,
            host: host.clone(),
            port,
            source: HostSource::Authority,
            dst_hint: None,
            method: Some(Method::CONNECT.to_string()),
            path: None,
        };
        let pinned = match self.gate.evaluate(&ereq).await {
            GateDecision::Allow(t) => t,
            GateDecision::Deny(reason) => {
                self.deny_connect(&target, &host, reason);
                return http_error(StatusCode::FORBIDDEN, "Forbidden");
            }
        };
        let pinned_ip = pinned.ip.to_string();
        if let Some(b) = &self.broker
            && let Some(i) = b.endpoint_index(&host, &ereq.port)
        {
            let b = Arc::clone(b);
            return self
                .connect_endpoint(req, b, i, target, host, ereq.port, pinned)
                .await;
        }

        let upstream = match dial(&pinned).await {
            Ok(s) => s,
            Err(e) => {
                self.sink.logf(format_args!(
                    "egress: ALLOW CONNECT {target} (dial={pinned} failed: {e})"
                ));
                self.sink
                    .record(&host, &pinned_ip, true, "allowed by policy (dial failed)");
                return http_error(StatusCode::BAD_GATEWAY, "Bad Gateway");
            }
        };

        let this = Arc::clone(&self);
        tokio::spawn(async move {
            let Ok(upgraded) = hyper::upgrade::on(req).await else {
                return;
            };
            this.sink.logf(format_args!(
                "egress: ALLOW CONNECT {target} (dial={pinned})"
            ));
            this.sink
                .record(&host, &pinned_ip, true, "allowed by egress policy");
            let mut client = TokioIo::new(upgraded);
            let mut upstream = upstream;
            match &this.broker {
                // Plaintext tunnels are scanned for credential placeholders.
                Some(b) if b.has_placeholders() => {
                    let base = Decision {
                        host: host.clone(),
                        ip: pinned_ip.clone(),
                        ..Decision::default()
                    };
                    b.guarded_splice(client, upstream, Vec::new(), None, base, &this.sink)
                        .await;
                }
                _ => {
                    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
                }
            }
        });

        let mut resp = Response::new(empty_body());
        resp.extensions_mut()
            .insert(hyper::ext::ReasonPhrase::from_static(
                b"Connection Established",
            ));
        resp
    }

    /// CONNECT to a broker endpoint: inspected protocols are terminated with
    /// the sandbox CA; `tcp` endpoints are spliced with an SNI check.
    #[allow(clippy::too_many_arguments)]
    async fn connect_endpoint(
        self: Arc<Self>,
        req: Request<Incoming>,
        broker: Arc<Broker>,
        i: usize,
        target: String,
        host: String,
        port: String,
        pinned: PinnedTarget,
    ) -> Response<ProxyBody> {
        let pinned_ip = pinned.ip.to_string();
        let mut decision = broker.connect_decision(i, &host, &pinned_ip);
        let conn = client_conn(&req);
        let binary = broker.check_binary(i, conn.peer, conn.local).await;
        if !Broker::apply_binary(&mut decision, binary.as_ref()) {
            self.sink.logf(format_args!(
                "egress: DENY CONNECT {target} (endpoint {}, binary)",
                broker.endpoints[i].label()
            ));
            broker.record(&self.sink, decision);
            return http_error(StatusCode::FORBIDDEN, "Forbidden");
        }
        if broker.endpoints[i].protocol.inspected() {
            self.sink.logf(format_args!(
                "egress: ALLOW CONNECT {target} (endpoint {}, inspecting)",
                broker.endpoints[i].label()
            ));
            broker.record(&self.sink, decision);
            let sink = self.sink.clone();
            tokio::spawn(async move {
                let Ok(upgraded) = hyper::upgrade::on(req).await else {
                    return;
                };
                let t = Target {
                    host,
                    port,
                    pinned,
                    upstream_tls: None,
                    endpoint: Some(i),
                    binary,
                };
                broker
                    .serve_intercepted(TokioIo::new(upgraded), Vec::new(), t, sink)
                    .await;
            });
        } else {
            let upstream = match dial(&pinned).await {
                Ok(s) => s,
                Err(e) => {
                    self.sink.logf(format_args!(
                        "egress: ALLOW CONNECT {target} (dial={pinned} failed: {e})"
                    ));
                    let mut d = decision;
                    d.reason = "allowed: endpoint (dial failed)".into();
                    broker.record(&self.sink, d);
                    return http_error(StatusCode::BAD_GATEWAY, "Bad Gateway");
                }
            };
            let this = Arc::clone(&self);
            tokio::spawn(async move {
                let Ok(upgraded) = hyper::upgrade::on(req).await else {
                    return;
                };
                this.sink.logf(format_args!(
                    "egress: ALLOW CONNECT {target} (dial={pinned}, endpoint {})",
                    broker.endpoints[i].label()
                ));
                let base = broker.record(&this.sink, decision);
                broker
                    .guarded_splice(
                        TokioIo::new(upgraded),
                        upstream,
                        Vec::new(),
                        Some(host),
                        base,
                        &this.sink,
                    )
                    .await;
            });
        }
        let mut resp = Response::new(empty_body());
        resp.extensions_mut()
            .insert(hyper::ext::ReasonPhrase::from_static(
                b"Connection Established",
            ));
        resp
    }

    fn deny_connect(&self, target: &str, host: &str, reason: DenyReason) {
        match reason {
            DenyReason::Policy => {
                self.sink
                    .logf(format_args!("egress: DENY CONNECT {target}"));
                let ip = parse_ip(host).map(|i| i.to_string()).unwrap_or_default();
                self.sink
                    .record(host, &ip, false, "blocked by egress policy");
            }
            DenyReason::NotAllowlisted => {
                self.sink
                    .logf(format_args!("egress: DENY CONNECT {target}"));
                self.sink
                    .record(host, "", false, "hostname not allowlisted");
            }
            DenyReason::Resolution(e) => {
                self.sink.logf(format_args!(
                    "egress: DENY CONNECT {target} (resolve failed: {e})"
                ));
                self.sink
                    .record(host, "", false, "hostname resolution failed");
            }
        }
    }

    /// Checks a plain forward-proxy request against the policy and, if
    /// allowed, forwards it to the pinned origin.
    async fn handle_http(self: Arc<Self>, req: Request<Incoming>) -> Response<ProxyBody> {
        let authority = request_authority(&req);
        let https = req
            .uri()
            .scheme_str()
            .is_some_and(|s| s.eq_ignore_ascii_case("https"));
        let default_port = if https { "443" } else { "80" };
        let Ok((host, port)) = host_with_default_port(&authority, default_port) else {
            return http_error(StatusCode::BAD_REQUEST, "Bad Request");
        };
        let method = req.method().clone();
        let ereq = EgressRequest {
            frontend: Frontend::Http,
            host: host.clone(),
            port,
            source: HostSource::Authority,
            dst_hint: None,
            method: Some(method.to_string()),
            path: req.uri().path_and_query().map(|p| p.as_str().to_string()),
        };
        let pinned = match self.gate.evaluate(&ereq).await {
            GateDecision::Allow(t) => t,
            GateDecision::Deny(_) => {
                self.sink
                    .logf(format_args!("egress: DENY HTTP {method} {authority}"));
                self.sink
                    .record(&host, "", false, "blocked by egress policy");
                return http_error(StatusCode::FORBIDDEN, "Forbidden");
            }
        };
        let mut binary = None;
        if let Some(b) = &self.broker
            && let Some(i) = b.endpoint_index(&host, &ereq.port)
        {
            // Endpoint binaries apply to plain HTTP too, inspected or not.
            let conn = client_conn(&req);
            binary = b.check_binary(i, conn.peer, conn.local).await;
            let mut d = b.connect_decision(i, &host, &pinned.ip.to_string());
            d.method = Some(method.to_string());
            if !Broker::apply_binary(&mut d, binary.as_ref()) {
                b.record(&self.sink, d);
                return http_error(StatusCode::FORBIDDEN, "Forbidden");
            }
            if binary.is_some() && !b.endpoints[i].protocol.inspected() {
                // Inspected endpoints record per request below; record the
                // attribution for the others here.
                b.record(&self.sink, d);
            }
        }
        if let Some(b) = &self.broker {
            let ep = b
                .endpoint_index(&host, &ereq.port)
                .filter(|&i| b.endpoints[i].protocol.inspected());
            if ep.is_some() || b.has_placeholders() {
                if ep.is_none() {
                    self.sink.logf(format_args!(
                        "egress: ALLOW HTTP {method} {authority} (dial={pinned})"
                    ));
                    self.sink.record(
                        &host,
                        &pinned.ip.to_string(),
                        true,
                        "allowed by egress policy",
                    );
                }
                let upstream_tls = https.then(|| {
                    if ep.is_some() {
                        Arc::clone(&b.upstream_tls)
                    } else {
                        Arc::clone(&self.tls)
                    }
                });
                let t = Target {
                    host,
                    port: ereq.port,
                    pinned,
                    upstream_tls,
                    endpoint: ep,
                    binary,
                };
                return b.handle(req, &t, &self.sink).await;
            }
        }
        self.sink.logf(format_args!(
            "egress: ALLOW HTTP {method} {authority} (dial={pinned})"
        ));
        self.sink.record(
            &host,
            &pinned.ip.to_string(),
            true,
            "allowed by egress policy",
        );

        match self.forward(req, &pinned, &host, &authority, https).await {
            Ok(resp) => resp.map(BodyExt::boxed),
            Err(_) => http_error(StatusCode::BAD_GATEWAY, "Bad Gateway"),
        }
    }

    /// Sends `req` to `pinned` (TLS with SNI `host` when `https`), keeping
    /// `authority` as the `Host` header.
    async fn forward(
        &self,
        req: Request<Incoming>,
        pinned: &PinnedTarget,
        host: &str,
        authority: &str,
        https: bool,
    ) -> Result<Response<Incoming>, BoxError> {
        let (mut parts, body) = req.into_parts();
        let path = parts
            .uri
            .path_and_query()
            .map_or("/", |p| p.as_str())
            .to_string();
        parts.uri = path.parse::<Uri>()?;
        parts.version = Version::HTTP_11;
        // Proxy credentials are for this hop only.
        parts.headers.remove(header::PROXY_AUTHORIZATION);
        parts
            .headers
            .insert(header::HOST, HeaderValue::from_str(authority)?);
        let out = Request::from_parts(parts, body);

        let stream = dial(pinned).await?;
        if https {
            let name = rustls::pki_types::ServerName::try_from(host.to_string())?;
            let tls = tokio_rustls::TlsConnector::from(Arc::clone(&self.tls))
                .connect(name, stream)
                .await?;
            send_http1(tls, out).await
        } else {
            send_http1(stream, out).await
        }
    }

    /// Serves the proxy on `listener` until an unrecoverable error.
    pub async fn serve(self: Arc<Self>, listener: TcpListener) -> io::Result<()> {
        self.serve_with_shutdown(listener, std::future::pending())
            .await
    }

    /// Binds `addr` and serves the proxy on it.
    pub async fn listen_and_serve(self: Arc<Self>, addr: &str) -> io::Result<()> {
        let listener = TcpListener::bind(addr).await?;
        self.serve(listener).await
    }

    /// Serves the proxy on `listener` until `shutdown` resolves, then stops
    /// accepting, asks open HTTP connections to finish their in-flight
    /// request, and waits for them. Established CONNECT tunnels are detached
    /// and not waited for.
    pub async fn serve_with_shutdown<F>(
        self: Arc<Self>,
        listener: TcpListener,
        shutdown: F,
    ) -> io::Result<()>
    where
        F: Future<Output = ()> + Send,
    {
        let (stop_tx, stop_rx) = watch::channel(false);
        let mut conns = JoinSet::new();
        let mut backoff = Duration::ZERO;
        tokio::pin!(shutdown);
        loop {
            tokio::select! {
                () = &mut shutdown => break,
                Some(_) = conns.join_next(), if !conns.is_empty() => {}
                accepted = listener.accept() => match accepted {
                    Ok((stream, _)) => {
                        backoff = Duration::ZERO;
                        conns.spawn(Arc::clone(&self).serve_conn(stream, stop_rx.clone()));
                    }
                    Err(e) => {
                        // Like Go's http.Server: back off and retry.
                        backoff = (backoff * 2).clamp(Duration::from_millis(5), Duration::from_secs(1));
                        tracing::warn!(target: "runeward_egress", "accept error: {e}; retrying in {backoff:?}");
                        tokio::time::sleep(backoff).await;
                    }
                },
            }
        }
        drop(listener);
        let _ = stop_tx.send(true);
        while conns.join_next().await.is_some() {}
        Ok(())
    }

    async fn serve_conn(self: Arc<Self>, stream: TcpStream, mut stop: watch::Receiver<bool>) {
        let conn_info = ClientConn {
            peer: stream.peer_addr().ok(),
            local: stream.local_addr().ok(),
        };
        let svc = hyper::service::service_fn(move |mut req: Request<Incoming>| {
            let this = Arc::clone(&self);
            req.extensions_mut().insert(conn_info);
            async move { Ok::<_, Infallible>(this.handle(req).await) }
        });
        let mut builder = hyper::server::conn::http1::Builder::new();
        builder
            .timer(TokioTimer::new())
            .header_read_timeout(READ_HEADER_TIMEOUT);
        let conn = builder
            .serve_connection(TokioIo::new(stream), svc)
            .with_upgrades();
        tokio::pin!(conn);
        tokio::select! {
            _ = conn.as_mut() => {}
            _ = async { stop.wait_for(|s| *s).await.is_ok() } => {
                conn.as_mut().graceful_shutdown();
                let _ = conn.await;
            }
        }
    }
}

/// The client connection a request arrived on: the client's address and
/// the proxy address it dialled. Binary attribution looks the client's
/// socket up by these when the proxy shares the sandbox's network
/// namespace.
#[derive(Debug, Clone, Copy, Default)]
struct ClientConn {
    peer: Option<SocketAddr>,
    local: Option<SocketAddr>,
}

fn client_conn<B>(req: &Request<B>) -> ClientConn {
    req.extensions()
        .get::<ClientConn>()
        .copied()
        .unwrap_or_default()
}

/// Sends one HTTP/1.1 request over `io`, driving the connection in the
/// background.
async fn send_http1<IO>(io: IO, req: Request<Incoming>) -> Result<Response<Incoming>, BoxError>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(io)).await?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    Ok(sender.send_request(req).await?)
}

/// Dials `pinned` within [`DIAL_TIMEOUT`].
pub(crate) async fn dial(pinned: &PinnedTarget) -> io::Result<TcpStream> {
    let addr = pinned.socket_addr()?;
    tokio::time::timeout(DIAL_TIMEOUT, TcpStream::connect(addr))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, format!("dial {addr}: timeout")))?
}

/// The request's target authority: the URI authority (CONNECT target or
/// absolute-URI host), else the `Host` header.
fn request_authority<B>(req: &Request<B>) -> String {
    if let Some(a) = req.uri().authority() {
        return a.as_str().to_string();
    }
    req.headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string()
}

fn empty_body() -> ProxyBody {
    Full::new(Bytes::new())
        .map_err(|never| match never {})
        .boxed()
}

/// A plain-text error response shaped like Go's `http.Error`.
pub(crate) fn http_error(status: StatusCode, msg: &str) -> Response<ProxyBody> {
    let body = Full::new(Bytes::from(format!("{msg}\n")))
        .map_err(|never| match never {})
        .boxed();
    let mut resp = Response::new(body);
    *resp.status_mut() = status;
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    resp
}

/// Parses a `Basic base64(user:pass)` Proxy-Authorization value.
fn parse_proxy_basic_auth(value: &str) -> Option<(Vec<u8>, Vec<u8>)> {
    const PREFIX: &str = "Basic ";
    let head = value.get(..PREFIX.len())?;
    if !head.eq_ignore_ascii_case(PREFIX) {
        return None;
    }
    let dec = base64::engine::general_purpose::STANDARD
        .decode(&value[PREFIX.len()..])
        .ok()?;
    let i = dec.iter().position(|&b| b == b':')?;
    Some((dec[..i].to_vec(), dec[i + 1..].to_vec()))
}

/// Length-revealing constant-time comparison (as Go's
/// `subtle.ConstantTimeCompare`).
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let diff = a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y));
    std::hint::black_box(diff) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_auth_parsing() {
        let enc = base64::engine::general_purpose::STANDARD.encode("u:p:x");
        assert_eq!(
            parse_proxy_basic_auth(&format!("basic {enc}")),
            Some((b"u".to_vec(), b"p:x".to_vec()))
        );
        let nocolon = base64::engine::general_purpose::STANDARD.encode("up");
        assert_eq!(parse_proxy_basic_auth(&format!("Basic {nocolon}")), None);
        assert_eq!(parse_proxy_basic_auth("Bearer abc"), None);
        assert_eq!(parse_proxy_basic_auth("Basic !!!"), None);
        assert_eq!(parse_proxy_basic_auth("Bas"), None);
    }

    #[test]
    fn constant_time_eq_cases() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
        assert!(constant_time_eq(b"", b""));
    }
}
