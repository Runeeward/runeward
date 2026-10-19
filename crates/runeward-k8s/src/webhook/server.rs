//! HTTPS serving (axum over tokio-rustls with the ring provider) and the
//! full webhook startup sequence.

use super::{CertBundle, Error, KubePolicySource, Server, load_or_create_cert, register};
use axum::Router;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto;
use hyper_util::server::graceful::GracefulShutdown;
use hyper_util::service::TowerToHyperService;
use rustls::ServerConfig;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::future::Future;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

/// Bound on reading request headers (and the TLS handshake).
const READ_HEADER_TIMEOUT: Duration = Duration::from_secs(10);
/// Budget for draining in-flight connections on shutdown.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

/// Builds a ring-backed rustls server config (TLS 1.2+, ALPN h2 and
/// http/1.1) from a PEM certificate chain and key.
pub fn tls_config(bundle: &CertBundle) -> Result<Arc<ServerConfig>, Error> {
    let certs = CertificateDer::pem_slice_iter(&bundle.cert_pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| Error::Tls(format!("parse certificate: {e}")))?;
    if certs.is_empty() {
        return Err(Error::Tls("no certificate found".to_owned()));
    }
    let key = PrivateKeyDer::from_pem_slice(&bundle.key_pem)
        .map_err(|e| Error::Tls(format!("parse private key: {e}")))?;
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

/// Serves `app` over TLS on `listener` until `shutdown` resolves, then drains
/// in-flight connections for up to five seconds.
pub async fn serve_tls<F>(
    listener: TcpListener,
    tls: Arc<ServerConfig>,
    app: Router,
    shutdown: F,
) -> std::io::Result<()>
where
    F: Future<Output = ()> + Send,
{
    let acceptor = TlsAcceptor::from(tls);
    let graceful = GracefulShutdown::new();
    tokio::pin!(shutdown);
    loop {
        let (stream, peer) = tokio::select! {
            () = &mut shutdown => break,
            res = listener.accept() => match res {
                Ok(conn) => conn,
                Err(e) => {
                    tracing::warn!(error = %e, "webhook: accept failed");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            },
        };
        let acceptor = acceptor.clone();
        let app = app.clone();
        let watcher = graceful.watcher();
        tokio::spawn(async move {
            let tls = match tokio::time::timeout(READ_HEADER_TIMEOUT, acceptor.accept(stream)).await
            {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => {
                    tracing::debug!(%peer, error = %e, "webhook: TLS handshake failed");
                    return;
                }
                Err(_) => {
                    tracing::debug!(%peer, "webhook: TLS handshake timed out");
                    return;
                }
            };
            let mut builder = auto::Builder::new(TokioExecutor::new());
            builder
                .http1()
                .timer(TokioTimer::new())
                .header_read_timeout(READ_HEADER_TIMEOUT);
            let conn = builder.serve_connection(TokioIo::new(tls), TowerToHyperService::new(app));
            if let Err(e) = watcher.watch(conn).await {
                tracing::debug!(%peer, error = %e, "webhook: connection error");
            }
        });
    }
    drop(listener);
    if tokio::time::timeout(SHUTDOWN_GRACE, graceful.shutdown())
        .await
        .is_err()
    {
        tracing::warn!("webhook: shutdown grace period elapsed with connections open");
    }
    Ok(())
}

/// Resolves on SIGINT or SIGTERM.
pub async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! {
        () = ctrl_c => {},
        () = term => {},
    }
}

/// Startup options for [`run`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunOptions {
    /// HTTPS port to serve admission requests on.
    pub port: u16,
    /// Name of the Service fronting the webhook (empty: `runeward-webhook`).
    pub service: String,
    /// Secret persisting the serving cert (empty: `<service>-cert`).
    pub cert_secret: String,
    /// Namespace the webhook runs in.
    pub namespace: String,
}

impl Default for RunOptions {
    fn default() -> Self {
        Self {
            port: 8443,
            service: String::new(),
            cert_secret: String::new(),
            namespace: "runeward".to_owned(),
        }
    }
}

impl RunOptions {
    /// Defaults overlaid with `RUNEWARD_WEBHOOK_SERVICE`,
    /// `RUNEWARD_WEBHOOK_CERT_SECRET` and `RUNEWARD_K8S_NAMESPACE`.
    pub fn from_env() -> Self {
        let env = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
        let d = Self::default();
        Self {
            service: env("RUNEWARD_WEBHOOK_SERVICE").unwrap_or(d.service),
            cert_secret: env("RUNEWARD_WEBHOOK_CERT_SECRET").unwrap_or(d.cert_secret),
            namespace: env("RUNEWARD_K8S_NAMESPACE").unwrap_or(d.namespace),
            ..d
        }
    }

    /// The service name with its default applied.
    pub fn service_name(&self) -> String {
        if self.service.is_empty() {
            "runeward-webhook".to_owned()
        } else {
            self.service.clone()
        }
    }

    /// The cert Secret name with its default applied.
    pub fn cert_secret_name(&self) -> String {
        if self.cert_secret.is_empty() {
            format!("{}-cert", self.service_name())
        } else {
            self.cert_secret.clone()
        }
    }

    /// The DNS names the serving certificate covers.
    pub fn dns_names(&self) -> Vec<String> {
        let (svc, ns) = (self.service_name(), &self.namespace);
        vec![
            format!("{svc}.{ns}.svc"),
            format!("{svc}.{ns}.svc.cluster.local"),
        ]
    }
}

/// Runs the webhook: obtains the serving certificate (persisted in a Secret
/// so restarts and replicas share one CA), self-registers the webhook
/// configurations, then serves HTTPS until `shutdown` resolves.
pub async fn run<F>(client: kube::Client, opts: RunOptions, shutdown: F) -> Result<(), Error>
where
    F: Future<Output = ()> + Send,
{
    let service = opts.service_name();
    let bundle = load_or_create_cert(
        Some(client.clone()),
        &opts.namespace,
        &opts.cert_secret_name(),
        &opts.dns_names(),
    )
    .await?;
    let tls = tls_config(&bundle)?;

    register(client.clone(), &bundle.ca_pem, &service, &opts.namespace).await?;

    let server = Arc::new(Server::new(KubePolicySource::new(client)));
    let listener = bind(opts.port).await?;
    tracing::info!(service = %service, namespace = %opts.namespace, port = opts.port, "starting webhook");
    serve_tls(listener, tls, server.router(), shutdown).await?;
    tracing::info!("webhook: shut down");
    Ok(())
}

/// Binds every interface, preferring a dual-stack IPv6 socket.
async fn bind(port: u16) -> std::io::Result<TcpListener> {
    match TcpListener::bind(SocketAddr::from((Ipv6Addr::UNSPECIFIED, port))).await {
        Ok(l) => Ok(l),
        Err(_) => TcpListener::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, port))).await,
    }
}
