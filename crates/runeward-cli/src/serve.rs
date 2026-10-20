//! `runeward serve` (the control plane: REST API, dashboard and `/mcp`) and
//! `runeward mcp` (the MCP server over stdio or streamable HTTP).

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Result, anyhow};
use runeward_authz::Store;
use runeward_controlplane::Manager;
use runeward_mcp::{McpArgs, McpConfig};
use runeward_server::{ServerConfig, TlsPaths};

use crate::common::{manager_config_dir, resolve_config_dir, shutdown_signal};
use crate::version::VERSION;

/// `runeward serve` flags.
#[derive(Debug, Clone, clap::Args)]
pub struct ServeArgs {
    /// listen port
    #[arg(long, default_value_t = 8080)]
    pub port: u16,
    /// interface to bind (use 0.0.0.0 to expose on the network; requires --token)
    #[arg(long, default_value = "127.0.0.1")]
    pub bind: String,
    /// API token required on every request (falls back to RUNEWARD_API_TOKEN)
    #[arg(long, default_value = "")]
    pub token: String,
    /// path to a TLS certificate (enables HTTPS; requires --tls-key)
    #[arg(long)]
    pub tls_cert: Option<PathBuf>,
    /// path to the TLS private key (requires --tls-cert)
    #[arg(long)]
    pub tls_key: Option<PathBuf>,
    /// allow plaintext HTTP on a non-loopback bind behind a trusted TLS proxy
    #[arg(long)]
    pub allow_insecure_http: bool,
    /// serve the REST API only, without the web dashboard
    #[arg(long)]
    pub no_ui: bool,
    /// refuse to start unless every hardened-mode check passes (also RUNEWARD_HARDENED=1)
    #[arg(long)]
    pub hardened: bool,
}

/// The RBAC store from `RUNEWARD_AUTHZ_FILE` (and OIDC settings), if any.
async fn authz_from_env() -> Result<Option<Arc<Store>>> {
    Store::from_env()
        .await
        .map(|s| s.map(Arc::new))
        .map_err(|e| anyhow!("load {}: {e}", runeward_authz::ENV_FILE))
}

/// Builds and validates the server configuration (no side effects), so an
/// unsafe exposure is refused before any state is opened.
pub async fn server_config(args: &ServeArgs) -> Result<ServerConfig> {
    let authz = authz_from_env().await?;
    let config = ServerConfig {
        bind: args.bind.clone(),
        port: args.port,
        token: args.token.clone(),
        authz,
        tls: TlsPaths::from_flags(args.tls_cert.clone(), args.tls_key.clone())?,
        allow_insecure_http: args.allow_insecure_http,
        no_ui: args.no_ui,
        mcp: None,
        version: VERSION.to_owned(),
        hardened: args.hardened,
    }
    .with_env_token();
    config.validate()?;
    Ok(config)
}

/// `runeward serve`.
pub async fn serve(args: &ServeArgs, config_dir: &str) -> Result<()> {
    let mut config = server_config(args).await?;
    let mgr = Manager::open(manager_config_dir(&resolve_config_dir(config_dir))).await?;
    runeward_obs::init_logging();
    runeward_obs::set_build_info(VERSION);

    // MCP shares the REST server's authentication (it is mounted behind it)
    // and its per-request principal and ownership checks.
    let mut mcp = McpConfig::from_env();
    mcp.token = config.token.clone();
    if !runeward_server::is_loopback_host(&config.bind) {
        mcp.allowed_hosts = None;
    }
    config.mcp = Some(runeward_mcp::router(mgr.clone(), config.authz.clone(), mcp));

    tracing::info!("{}", runeward_obs::telemetry::notice());
    let props = BTreeMap::from([
        ("ui".to_owned(), (!config.no_ui).to_string()),
        ("auth".to_owned(), config.auth_enabled().to_string()),
    ]);
    let _ = runeward_obs::telemetry::report(VERSION, "serve_start", props);

    let shutdown = async {
        shutdown_signal().await;
        tracing::info!("shutting down control plane");
    };
    let result = runeward_server::serve(config, mgr.clone(), shutdown).await;
    let _ = mgr.close().await;
    Ok(result?)
}

/// `runeward mcp`.
pub async fn mcp(args: &McpArgs, config_dir: &str) -> Result<()> {
    let authz = authz_from_env().await?;
    let config = McpConfig::from_env();
    if args.http {
        args.http_config(authz.clone(), config.clone()).validate()?;
        runeward_obs::init_logging();
    }
    let mgr = Manager::open(manager_config_dir(&resolve_config_dir(config_dir))).await?;
    let result = runeward_mcp::run(
        args,
        mgr.clone(),
        authz,
        config,
        Box::pin(shutdown_signal()),
    )
    .await;
    let _ = mgr.close().await;
    Ok(result?)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use clap::Parser;

    use super::*;

    #[derive(Debug, Parser)]
    struct Serve {
        #[command(flatten)]
        args: ServeArgs,
    }

    #[derive(Debug, Parser)]
    struct Mcp {
        #[command(flatten)]
        args: McpArgs,
    }

    /// Both network listeners refuse plaintext on a non-loopback bind.
    #[tokio::test]
    async fn network_listeners_require_tls() {
        let token = "x".repeat(32);
        let serve = Serve::parse_from(["serve", "--bind", "0.0.0.0", "--token", &token]);
        let err = server_config(&serve.args).await.unwrap_err();
        assert!(err.to_string().contains("plaintext"), "serve: {err}");

        let mcp = Mcp::parse_from(["mcp", "--http", "--bind", "0.0.0.0", "--token", &token]);
        let err = mcp
            .args
            .http_config(None, McpConfig::default())
            .validate()
            .unwrap_err();
        assert!(err.to_string().contains("plaintext"), "mcp: {err}");
    }
}
