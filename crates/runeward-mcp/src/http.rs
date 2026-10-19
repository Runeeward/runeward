//! The streamable-HTTP transport: the mountable [`router`], the
//! `runeward mcp --http` server ([`serve_http`]) and its flags.

use std::future::Future;
use std::net::IpAddr;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::extract::{Request, State};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto;
use hyper_util::server::graceful::GracefulShutdown;
use hyper_util::service::TowerToHyperService;
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::{StreamableHttpServerConfig, StreamableHttpService};
use runeward_authz::{ENV_FILE, Store};
use runeward_controlplane::hardening::{Listener, ServerChecks};
use runeward_controlplane::refusal::{Refusal, RefusalReason};
use runeward_controlplane::{Manager, PrincipalLimiter};
use rustls::ServerConfig;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;

use crate::auth::{Authenticated, parse_bearer_token};
use crate::server::{McpConfig, McpServer, serve_stdio};
use crate::{ENV_API_TOKEN, Error};

/// Bound on reading request headers (and the TLS handshake).
const READ_HEADER_TIMEOUT: Duration = Duration::from_secs(10);
/// Budget for draining in-flight requests on shutdown (Go's 5s).
const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);
/// Minimum shared-token length for a network bind.
const MIN_NETWORK_TOKEN_LEN: usize = 32;

/// A boxed shutdown future for [`run`].
pub type ShutdownSignal = Pin<Box<dyn Future<Output = ()> + Send>>;

/// Reports whether `host` is a loopback interface. `localhost` is; an
/// empty host means all interfaces and is not (Go's `isLoopbackHost`).
pub fn is_loopback_host(host: &str) -> bool {
    match host {
        "localhost" => true,
        "" => false,
        h => h.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback()),
    }
}

/// The MCP streamable-HTTP endpoint, routed at `/mcp` (and `/mcp/...`),
/// for mounting into the REST server or serving on its own.
///
/// Authentication: with `authz`, every request must carry
/// `Authorization: Bearer <token>` naming a principal (401 otherwise) and
/// each tool call runs as that principal. Without `authz`, a non-empty
/// `config.token` must be presented (bearer or `X-Runeward-Token`), as the
/// Go `TokenAuth` middleware required; tool calls then share the `mcp-http`
/// boundary.
pub fn router(manager: Arc<Manager>, authz: Option<Arc<Store>>, config: McpConfig) -> Router {
    router_with_cancel(manager, authz, &config, CancellationToken::new())
}

fn router_with_cancel(
    manager: Arc<Manager>,
    authz: Option<Arc<Store>>,
    config: &McpConfig,
    cancel: CancellationToken,
) -> Router {
    let server = McpServer::for_http(manager, authz.clone(), config);
    let mut http_cfg = StreamableHttpServerConfig::default().with_cancellation_token(cancel);
    http_cfg = match &config.allowed_hosts {
        Some(hosts) => http_cfg.with_allowed_hosts(hosts.clone()),
        None => http_cfg.disable_allowed_hosts(),
    };
    let service = StreamableHttpService::new(
        move || Ok(server.clone()),
        Arc::new(LocalSessionManager::default()),
        http_cfg,
    );
    let gate = AuthGate {
        store: authz,
        token: (!config.token.is_empty()).then(|| Arc::from(config.token.as_bytes())),
        limiter: config
            .principal_rate_limit
            .and_then(PrincipalLimiter::new)
            .map(Arc::new),
    };
    Router::new()
        .route_service("/mcp", service.clone())
        .route_service("/mcp/", service.clone())
        .route_service("/mcp/{*rest}", service)
        .layer(middleware::from_fn_with_state(gate, authenticate))
}

#[derive(Clone)]
struct AuthGate {
    store: Option<Arc<Store>>,
    token: Option<Arc<[u8]>>,
    /// Per-principal limiting (`RUNEWARD_PRINCIPAL_RATE_LIMIT`).
    limiter: Option<Arc<PrincipalLimiter>>,
}

/// `{"error": msg}` plus the standard refusal object.
fn refused(status: http::StatusCode, msg: &str, reason: RefusalReason) -> Response {
    let mut body = serde_json::json!({ "error": msg });
    Refusal::new(reason, msg).attach(&mut body);
    (status, axum::Json(body)).into_response()
}

fn unauthorized(msg: &str) -> Response {
    let mut res = refused(
        http::StatusCode::UNAUTHORIZED,
        msg,
        RefusalReason::Permission,
    );
    res.headers_mut().insert(
        http::header::WWW_AUTHENTICATE,
        http::HeaderValue::from_static("Bearer"),
    );
    res
}

/// The token a caller presented: the `Authorization` value without a
/// `Bearer ` prefix, else `X-Runeward-Token` (Go's `presentedToken`).
fn presented_token(headers: &http::HeaderMap) -> String {
    if let Some(h) = headers.get(http::header::AUTHORIZATION) {
        let h = h.to_str().unwrap_or_default();
        return h.strip_prefix("Bearer ").unwrap_or(h).trim().to_owned();
    }
    headers
        .get("X-Runeward-Token")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.trim().to_owned())
        .unwrap_or_default()
}

async fn authenticate(State(gate): State<AuthGate>, mut req: Request, next: Next) -> Response {
    if let Some(store) = &gate.store {
        let token = req
            .headers()
            .get(http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(parse_bearer_token)
            .map(str::to_owned);
        let principal = match token {
            Some(t) => store.identify(&t).await,
            None => None,
        };
        match principal {
            Some(p) => {
                if let Some(l) = &gate.limiter
                    && !l.allow(&p.name)
                {
                    let mut res = refused(
                        http::StatusCode::TOO_MANY_REQUESTS,
                        "rate limit exceeded for this principal",
                        RefusalReason::Capacity,
                    );
                    let wait = l.retry_after(&p.name).as_secs().max(1);
                    if let Ok(v) = http::HeaderValue::from_str(&wait.to_string()) {
                        res.headers_mut().insert(http::header::RETRY_AFTER, v);
                    }
                    return res;
                }
                req.extensions_mut().insert(Authenticated(p));
            }
            None => return unauthorized("unauthorized: missing or invalid bearer token"),
        }
    } else if let Some(want) = &gate.token {
        let got = presented_token(req.headers());
        if got.is_empty() || !bool::from(got.as_bytes().ct_eq(want)) {
            return unauthorized("unauthorized: missing or invalid API token");
        }
    }
    next.run(req).await
}

/// Settings for `runeward mcp --http`.
#[derive(Clone)]
pub struct HttpConfig {
    /// Interface to bind (default `127.0.0.1`).
    pub bind: String,
    /// Listen port (default 8081).
    pub port: u16,
    /// Shared token required on every request when there is no authz
    /// store; `None` falls back to `RUNEWARD_API_TOKEN`.
    pub token: Option<String>,
    /// PEM certificate chain (enables HTTPS; requires `tls_key`).
    pub tls_cert: Option<PathBuf>,
    /// PEM private key (requires `tls_cert`).
    pub tls_key: Option<PathBuf>,
    /// Allows plaintext HTTP on a non-loopback bind (behind a trusted TLS
    /// proxy).
    pub allow_insecure_http: bool,
    /// The RBAC store (`RUNEWARD_AUTHZ_FILE`), if configured.
    pub authz: Option<Arc<Store>>,
    /// Server settings. `token` is overwritten from [`HttpConfig::token`]
    /// and `allowed_hosts` is derived from the bind (loopback names on a
    /// loopback bind, any host otherwise).
    pub mcp: McpConfig,
    /// Refuses to start unless every hardened-mode rule holds (see
    /// [`runeward_controlplane::hardening`]). Also on when
    /// `RUNEWARD_HARDENED=1`.
    pub hardened: bool,
}

impl std::fmt::Debug for HttpConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpConfig")
            .field("bind", &self.bind)
            .field("port", &self.port)
            .field("token", &self.token.as_ref().map(|_| "<redacted>"))
            .field("tls_cert", &self.tls_cert)
            .field("tls_key", &self.tls_key)
            .field("allow_insecure_http", &self.allow_insecure_http)
            .field("authz", &self.authz.is_some())
            .field("mcp", &self.mcp)
            .field("hardened", &self.hardened)
            .finish()
    }
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            bind: "127.0.0.1".into(),
            port: 8081,
            token: None,
            tls_cert: None,
            tls_key: None,
            allow_insecure_http: false,
            authz: None,
            mcp: McpConfig::default(),
            hardened: false,
        }
    }
}

impl HttpConfig {
    fn token(&self) -> &str {
        self.token.as_deref().unwrap_or_default()
    }

    /// Applies the Go CLI's refusal rules: a non-loopback bind needs
    /// authentication (a token of at least 32 characters or a
    /// network-safe authz store) and TLS unless `allow_insecure_http`;
    /// the certificate and key go together.
    pub fn validate(&self) -> Result<(), Error> {
        let loopback = is_loopback_host(&self.bind);
        let token = self.token();
        if !loopback && token.is_empty() && self.authz.is_none() {
            return Err(Error::Config(format!(
                "refusing to bind {} without authentication: set --token, configure {ENV_FILE}, or bind 127.0.0.1",
                self.bind
            )));
        }
        if !loopback {
            if !token.is_empty() && token.len() < MIN_NETWORK_TOKEN_LEN {
                return Err(Error::Config(
                    "refusing network bind with an API token shorter than 32 characters".into(),
                ));
            }
            if let Some(store) = &self.authz {
                store.validate_for_network()?;
            }
        }
        if self.tls_cert.is_some() != self.tls_key.is_some() {
            return Err(Error::Config(
                "--tls-cert and --tls-key must be set together".into(),
            ));
        }
        if !loopback && self.tls_cert.is_none() && !self.allow_insecure_http {
            return Err(Error::Config(format!(
                "refusing plaintext MCP HTTP on non-loopback bind {}: configure --tls-cert/--tls-key or explicitly pass --allow-insecure-http behind a trusted TLS proxy",
                self.bind
            )));
        }
        Ok(())
    }
}

/// The `runeward mcp` flags.
#[derive(Debug, Clone, clap::Args)]
pub struct McpArgs {
    /// Serve over streamable HTTP instead of stdio.
    #[arg(long)]
    pub http: bool,
    /// Listen port for --http.
    #[arg(long, default_value_t = 8081)]
    pub port: u16,
    /// Interface to bind for --http (0.0.0.0 requires --token).
    #[arg(long, default_value = "127.0.0.1")]
    pub bind: String,
    /// API token required on every --http request (falls back to
    /// RUNEWARD_API_TOKEN).
    #[arg(long, env = ENV_API_TOKEN, hide_env_values = true)]
    pub token: Option<String>,
    /// Path to a TLS certificate for --http.
    #[arg(long)]
    pub tls_cert: Option<PathBuf>,
    /// Path to the TLS private key for --http.
    #[arg(long)]
    pub tls_key: Option<PathBuf>,
    /// Allow plaintext MCP HTTP on a non-loopback bind behind a trusted TLS
    /// proxy.
    #[arg(long)]
    pub allow_insecure_http: bool,
}

impl McpArgs {
    /// The HTTP settings these flags describe.
    pub fn http_config(&self, authz: Option<Arc<Store>>, mcp: McpConfig) -> HttpConfig {
        HttpConfig {
            bind: self.bind.clone(),
            port: self.port,
            token: self.token.clone().filter(|t| !t.is_empty()),
            tls_cert: self.tls_cert.clone(),
            tls_key: self.tls_key.clone(),
            allow_insecure_http: self.allow_insecure_http,
            authz,
            mcp,
            hardened: false,
        }
    }
}

/// Runs `runeward mcp`: stdio by default, streamable HTTP with `--http`
/// until `shutdown` resolves.
pub async fn run(
    args: &McpArgs,
    manager: Arc<Manager>,
    authz: Option<Arc<Store>>,
    config: McpConfig,
    shutdown: ShutdownSignal,
) -> Result<(), Error> {
    if args.http {
        serve_http(args.http_config(authz, config), manager, shutdown).await
    } else {
        serve_stdio(manager, authz, config).await
    }
}

/// Validates `config` (see [`HttpConfig::validate`]), binds it and serves
/// `/mcp` until `shutdown` resolves, then drains in-flight requests for up
/// to five seconds.
pub async fn serve_http(
    mut config: HttpConfig,
    manager: Arc<Manager>,
    shutdown: impl Future<Output = ()> + Send,
) -> Result<(), Error> {
    if config.token.as_deref().unwrap_or_default().is_empty() {
        config.token = std::env::var(ENV_API_TOKEN).ok().filter(|t| !t.is_empty());
    }
    config.validate()?;
    if config.hardened || runeward_controlplane::hardening::hardened_from_env() {
        hardened_gate(&config, &manager).await?;
    }
    let listener = TcpListener::bind((config.bind.as_str(), config.port)).await?;
    serve_http_on(listener, config, manager, shutdown).await
}

/// Runs the hardened-mode check for `runeward mcp --http`, printing every
/// violation.
async fn hardened_gate(config: &HttpConfig, manager: &Manager) -> Result<(), Error> {
    let checks = ServerChecks {
        listeners: vec![Listener {
            name: "mcp".into(),
            bind: config.bind.clone(),
            tls: config.tls_cert.is_some() && config.tls_key.is_some(),
        }],
        per_principal_auth: config.authz.is_some(),
        shared_token: !config.token().is_empty(),
        principal_rate_limit: config.mcp.principal_rate_limit.is_some(),
        backend_tiers: Default::default(),
    };
    manager.check_hardened(&checks).await.map_err(|violations| {
        for v in &violations {
            eprintln!("runeward: {v}");
        }
        Error::Hardened(violations)
    })
}

/// Serves `/mcp` on an already bound listener (no validation; see
/// [`serve_http`]).
pub async fn serve_http_on(
    listener: TcpListener,
    config: HttpConfig,
    manager: Arc<Manager>,
    shutdown: impl Future<Output = ()> + Send,
) -> Result<(), Error> {
    let tls = match (&config.tls_cert, &config.tls_key) {
        (Some(cert), Some(key)) => Some(tls_config(cert, key)?),
        (None, None) => None,
        _ => {
            return Err(Error::Config(
                "--tls-cert and --tls-key must be set together".into(),
            ));
        }
    };
    let mut mcp = config.mcp.clone();
    mcp.token = config.token.clone().unwrap_or_default();
    if !is_loopback_host(&config.bind) {
        mcp.allowed_hosts = None;
    }
    let cancel = CancellationToken::new();
    let app = router_with_cancel(manager, config.authz.clone(), &mcp, cancel.clone());

    let addr = listener.local_addr()?;
    let scheme = if tls.is_some() { "https" } else { "http" };
    let auth = !mcp.token.is_empty() || config.authz.is_some();
    eprintln!("runeward: MCP (streamable HTTP) at {scheme}://{addr}/mcp (auth={auth})");

    let acceptor = tls.map(TlsAcceptor::from);
    let graceful = GracefulShutdown::new();
    tokio::pin!(shutdown);
    loop {
        let (stream, peer) = tokio::select! {
            () = &mut shutdown => break,
            res = listener.accept() => match res {
                Ok(conn) => conn,
                Err(e) => {
                    tracing::warn!(error = %e, "mcp: accept failed");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            },
        };
        let app = app.clone();
        let watcher = graceful.watcher();
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            match acceptor {
                None => serve_conn(stream, app, watcher, peer).await,
                Some(acceptor) => {
                    match tokio::time::timeout(READ_HEADER_TIMEOUT, acceptor.accept(stream)).await {
                        Ok(Ok(tls)) => serve_conn(tls, app, watcher, peer).await,
                        Ok(Err(e)) => {
                            tracing::debug!(%peer, error = %e, "mcp: TLS handshake failed");
                        }
                        Err(_) => tracing::debug!(%peer, "mcp: TLS handshake timed out"),
                    }
                }
            }
        });
    }
    drop(listener);
    // Ends open SSE streams and sessions so connections can drain.
    cancel.cancel();
    if tokio::time::timeout(SHUTDOWN_GRACE, graceful.shutdown())
        .await
        .is_err()
    {
        tracing::warn!("mcp: shutdown grace period elapsed with connections open");
    }
    Ok(())
}

async fn serve_conn<S>(
    io: S,
    app: Router,
    watcher: hyper_util::server::graceful::Watcher,
    peer: std::net::SocketAddr,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut builder = auto::Builder::new(TokioExecutor::new());
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(READ_HEADER_TIMEOUT);
    let conn = builder.serve_connection(TokioIo::new(io), TowerToHyperService::new(app));
    if let Err(e) = watcher.watch(conn).await {
        tracing::debug!(%peer, error = %e, "mcp: connection error");
    }
}

/// A ring-backed rustls server config (TLS 1.2+, ALPN h2 and http/1.1).
fn tls_config(cert: &PathBuf, key: &PathBuf) -> Result<Arc<ServerConfig>, Error> {
    let certs = CertificateDer::pem_file_iter(cert)
        .and_then(Iterator::collect::<Result<Vec<_>, _>>)
        .map_err(|e| Error::Tls(format!("parse certificate {}: {e}", cert.display())))?;
    if certs.is_empty() {
        return Err(Error::Tls(format!(
            "no certificate found in {}",
            cert.display()
        )));
    }
    let key = PrivateKeyDer::from_pem_file(key)
        .map_err(|e| Error::Tls(format!("parse private key {}: {e}", key.display())))?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut cfg = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|e| Error::Tls(e.to_string()))?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| Error::Tls(e.to_string()))?;
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(cfg))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_hosts_match_go() {
        for h in ["localhost", "127.0.0.1", "127.1.2.3", "::1"] {
            assert!(is_loopback_host(h), "{h}");
        }
        for h in ["", "0.0.0.0", "::", "10.0.0.1", "example.com", "[::1]"] {
            assert!(!is_loopback_host(h), "{h}");
        }
    }

    fn cfg(bind: &str) -> HttpConfig {
        HttpConfig {
            bind: bind.into(),
            ..HttpConfig::default()
        }
    }

    fn err(c: &HttpConfig) -> String {
        c.validate().expect_err("refused").to_string()
    }

    #[test]
    fn refusal_rules_match_go() {
        cfg("127.0.0.1").validate().expect("loopback without auth");
        assert_eq!(
            err(&cfg("0.0.0.0")),
            "refusing to bind 0.0.0.0 without authentication: set --token, configure RUNEWARD_AUTHZ_FILE, or bind 127.0.0.1"
        );
        let mut c = cfg("0.0.0.0");
        c.token = Some("short".into());
        assert_eq!(
            err(&c),
            "refusing network bind with an API token shorter than 32 characters"
        );
        c.token = Some("x".repeat(32));
        assert_eq!(
            err(&c),
            "refusing plaintext MCP HTTP on non-loopback bind 0.0.0.0: configure --tls-cert/--tls-key or explicitly pass --allow-insecure-http behind a trusted TLS proxy"
        );
        c.allow_insecure_http = true;
        c.validate().expect("explicit insecure opt-in");
        c.allow_insecure_http = false;
        c.tls_cert = Some("cert.pem".into());
        assert_eq!(err(&c), "--tls-cert and --tls-key must be set together");
        c.tls_key = Some("key.pem".into());
        c.validate().expect("tls");
        let mut c = cfg("localhost");
        c.tls_key = Some("key.pem".into());
        assert_eq!(err(&c), "--tls-cert and --tls-key must be set together");
    }

    #[test]
    fn network_bind_requires_network_safe_store() {
        let weak = Store::from_principals(vec![runeward_authz::Principal {
            name: "a".into(),
            token: "short".into(),
            allowed_profiles: vec!["*".into()],
            ..runeward_authz::Principal::default()
        }])
        .expect("store");
        let mut c = cfg("0.0.0.0");
        c.authz = Some(Arc::new(weak));
        c.allow_insecure_http = true;
        assert!(c.validate().is_err());
    }

    #[test]
    fn presented_token_matches_go() {
        let mut h = http::HeaderMap::new();
        assert_eq!(presented_token(&h), "");
        h.insert("X-Runeward-Token", http::HeaderValue::from_static(" t1 "));
        assert_eq!(presented_token(&h), "t1");
        h.insert(
            http::header::AUTHORIZATION,
            http::HeaderValue::from_static("Bearer t2"),
        );
        assert_eq!(presented_token(&h), "t2");
    }

    #[test]
    fn flags_parse_with_go_defaults() {
        use clap::Parser;
        #[derive(Parser)]
        struct Cli {
            #[command(flatten)]
            mcp: McpArgs,
        }
        let cli = Cli::parse_from(["runeward"]);
        assert!(!cli.mcp.http);
        assert_eq!((cli.mcp.port, cli.mcp.bind.as_str()), (8081, "127.0.0.1"));
        let cli = Cli::parse_from([
            "runeward",
            "--http",
            "--port",
            "9000",
            "--bind",
            "0.0.0.0",
            "--token",
            "t",
            "--tls-cert",
            "c.pem",
            "--tls-key",
            "k.pem",
            "--allow-insecure-http",
        ]);
        let c = cli.mcp.http_config(None, McpConfig::default());
        assert_eq!(
            (c.port, c.bind.as_str(), c.token.as_deref()),
            (9000, "0.0.0.0", Some("t"))
        );
        assert!(c.allow_insecure_http && c.tls_cert.is_some() && c.tls_key.is_some());
    }
}
