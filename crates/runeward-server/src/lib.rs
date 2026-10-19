//! The Rune Box control plane over HTTP: Citadel lifecycle, governed tool
//! calls, Cohorts and their task boards, snapshots, agent sessions, the
//! conversation feed, approvals (Conclave), the audit ledger (Chronicle),
//! a terminal WebSocket, the experimental IDE reverse proxy and, unless
//! disabled, the embedded web dashboard.
//!
//! Every tool call goes through [`runeward_controlplane::Manager`], so
//! governance is always enforced; this crate is a thin transport.
//!
//! # Wire compatibility
//!
//! Routes, status codes, error bodies (`{"error", "code"}`) and JSON field
//! names match the Go server, because the dashboard and the Python and
//! TypeScript SDKs consume them. Additions are new fields only: Citadel
//! views carry `isolation` (the tier the backend delivered), and egress
//! decisions in `/perimeter` carry the request broker's fields (`endpoint`,
//! `protocol`, `method`, `path`, `tool`, `effect`, `verdict`,
//! `reason_code`, ...) when set.
//!
//! # Security
//!
//! - Authentication: RBAC principals (`RUNEWARD_AUTHZ_FILE`, optionally
//!   OIDC), else a static bearer token (`RUNEWARD_API_TOKEN`), else open on
//!   loopback only. Browser WebSockets, the IDE and downloads use
//!   short-lived single-use tickets (and an IDE cookie session), so
//!   long-lived credentials never appear in URLs.
//! - Tenancy: non-admin principals only see their tenant's Citadels,
//!   Cohorts, snapshots, runs and agent sessions; others are 404.
//! - Per-IP rate limiting (`RUNEWARD_RATE_LIMIT`, default 50 req/s),
//!   same-origin checks on state-changing requests and WebSockets, a 16 MiB
//!   body cap, security headers, and panic recovery.
//! - [`ServerConfig::validate`] refuses a non-loopback bind without
//!   authentication, with short tokens, or over plain HTTP without
//!   `allow_insecure_http`. TLS uses rustls with the ring provider.

mod auth;
mod handlers;
mod limit;
mod listen;
mod respond;
mod router;
mod state;
pub mod web;

#[cfg(test)]
mod tests;

use std::future::Future;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;

use axum::Router;
use runeward_authz::Store;
use runeward_controlplane::Manager;

pub use limit::{DEFAULT_RATE_LIMIT, RATE_LIMIT_ENV, parse_rate_limit};
pub use listen::tls_acceptor;
pub use router::Server;

/// The static API token variable the CLI reads when `--token` is empty.
pub const API_TOKEN_ENV: &str = "RUNEWARD_API_TOKEN";

/// A PEM certificate chain and private key for HTTPS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsPaths {
    /// `--tls-cert`.
    pub cert: PathBuf,
    /// `--tls-key`.
    pub key: PathBuf,
}

impl TlsPaths {
    /// Pairs `--tls-cert` and `--tls-key`, which must be set together.
    pub fn from_flags(
        cert: Option<PathBuf>,
        key: Option<PathBuf>,
    ) -> Result<Option<Self>, ServeError> {
        let cert = cert.filter(|p| !p.as_os_str().is_empty());
        let key = key.filter(|p| !p.as_os_str().is_empty());
        match (cert, key) {
            (None, None) => Ok(None),
            (Some(cert), Some(key)) => Ok(Some(Self { cert, key })),
            _ => Err(ServeError::Config(
                "--tls-cert and --tls-key must be set together".into(),
            )),
        }
    }
}

/// Settings for [`serve`] (the CLI's `serve` command).
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Interface to bind (default `127.0.0.1`).
    pub bind: String,
    /// Listen port (default 8080).
    pub port: u16,
    /// Legacy single API token; see [`ServerConfig::with_env_token`].
    pub token: String,
    /// RBAC principals and OIDC (`runeward_authz::Store::from_env`).
    pub authz: Option<Arc<Store>>,
    /// Serves HTTPS when set.
    pub tls: Option<TlsPaths>,
    /// Permits plain HTTP on a non-loopback bind (behind a TLS proxy).
    pub allow_insecure_http: bool,
    /// Serves the REST API only, without the dashboard.
    pub no_ui: bool,
    /// An MCP router mounted at `/mcp` (see [`Server::mcp`]).
    pub mcp: Option<Router>,
    /// Embedded in evidence exports.
    pub version: String,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind: "127.0.0.1".into(),
            port: 8080,
            token: String::new(),
            authz: None,
            tls: None,
            allow_insecure_http: false,
            no_ui: false,
            mcp: None,
            version: String::new(),
        }
    }
}

/// Why the server could not start.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ServeError {
    /// An unsafe or inconsistent configuration (message matches Go's).
    #[error("{0}")]
    Config(String),
    /// The certificate or key could not be loaded.
    #[error("tls: {0}")]
    Tls(String),
    /// Binding the listener failed.
    #[error("listen {addr}: {source}")]
    Bind {
        /// The address.
        addr: String,
        /// The failure.
        #[source]
        source: std::io::Error,
    },
}

/// Whether `host` is a loopback interface. Empty means all interfaces, so
/// it is not loopback.
pub fn is_loopback_host(host: &str) -> bool {
    match host {
        "localhost" => true,
        "" => false,
        h => h.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback()),
    }
}

impl ServerConfig {
    /// Falls back to `RUNEWARD_API_TOKEN` when no token was given.
    #[must_use]
    pub fn with_env_token(mut self) -> Self {
        if self.token.is_empty() {
            self.token = std::env::var(API_TOKEN_ENV).unwrap_or_default();
        }
        self
    }

    /// Whether any authentication is configured.
    pub fn auth_enabled(&self) -> bool {
        !self.token.is_empty() || self.authz.is_some()
    }

    /// Go's exposure rules: a non-loopback bind needs authentication, tokens
    /// of at least 32 characters, and TLS unless `allow_insecure_http`.
    pub fn validate(&self) -> Result<(), ServeError> {
        let loopback = is_loopback_host(&self.bind);
        if !loopback && !self.auth_enabled() {
            return Err(ServeError::Config(format!(
                "refusing to bind {} without authentication: set --token / {API_TOKEN_ENV}, configure {}, or bind 127.0.0.1",
                self.bind,
                runeward_authz::ENV_FILE
            )));
        }
        if !loopback {
            if !self.token.is_empty() && self.token.len() < 32 {
                return Err(ServeError::Config(
                    "refusing network bind with an API token shorter than 32 characters".into(),
                ));
            }
            if let Some(store) = &self.authz {
                store
                    .validate_for_network()
                    .map_err(|e| ServeError::Config(e.to_string()))?;
            }
        }
        if !loopback && self.tls.is_none() && !self.allow_insecure_http {
            return Err(ServeError::Config(format!(
                "refusing plaintext HTTP on non-loopback bind {}: configure --tls-cert/--tls-key or explicitly pass --allow-insecure-http behind a trusted TLS proxy",
                self.bind
            )));
        }
        Ok(())
    }

    /// `host:port` to listen on (IPv6 literals bracketed, as Go's
    /// `net.JoinHostPort`).
    pub fn addr(&self) -> String {
        if self.bind.contains(':') {
            format!("[{}]:{}", self.bind, self.port)
        } else {
            format!("{}:{}", self.bind, self.port)
        }
    }
}

/// Validates `config`, binds, and serves the control plane until
/// `shutdown` resolves (then drains in-flight requests for up to 5 s).
pub async fn serve(
    config: ServerConfig,
    mgr: Arc<Manager>,
    shutdown: impl Future<Output = ()> + Send,
) -> Result<(), ServeError> {
    config.validate()?;
    let tls = match &config.tls {
        Some(p) => Some(tls_acceptor(&p.cert, &p.key)?),
        None => None,
    };
    let addr = config.addr();
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .map_err(|source| ServeError::Bind {
            addr: addr.clone(),
            source,
        })?;
    serve_listener(config, mgr, listener, tls, shutdown).await;
    Ok(())
}

/// Serves on an already bound listener (tests, socket activation). The
/// configuration is not re-validated.
pub(crate) async fn serve_listener(
    config: ServerConfig,
    mgr: Arc<Manager>,
    listener: tokio::net::TcpListener,
    tls: Option<tokio_rustls::TlsAcceptor>,
    shutdown: impl Future<Output = ()> + Send,
) {
    let auth = config.auth_enabled();
    let addr = listener
        .local_addr()
        .map_or_else(|_| config.addr(), |a| a.to_string());
    let router = Server::new(mgr)
        .token(config.token)
        .authz(config.authz)
        .dashboard(!config.no_ui)
        .mcp(config.mcp)
        .version(config.version)
        .router();
    let scheme = if tls.is_some() { "https" } else { "http" };
    tracing::info!(
        addr = %format!("{scheme}://{addr}"),
        ui = !config.no_ui,
        metrics = "/metrics",
        auth,
        tls = tls.is_some(),
        "control plane listening"
    );
    if !auth {
        tracing::warn!(
            "control plane is UNAUTHENTICATED (bound to loopback); set --token or RUNEWARD_AUTHZ_FILE before exposing it"
        );
    }
    listen::run(listener, router, tls, shutdown).await;
    tracing::info!("control plane stopped");
}
