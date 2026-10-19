//! The accept loop: plain HTTP/1.1 or TLS (rustls with the ring provider),
//! WebSocket upgrades, a 10 s header timeout and graceful shutdown.

use std::future::Future;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::ConnectInfo;
use hyper::body::Incoming;
use hyper_util::rt::{TokioIo, TokioTimer};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;
use tower::ServiceExt;

use crate::ServeError;
use crate::auth::TlsConnection;

const READ_HEADER_TIMEOUT: Duration = Duration::from_secs(10);
const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Loads a PEM certificate chain and private key into a ring-backed rustls
/// server configuration (TLS 1.2 and 1.3, HTTP/1.1).
pub fn tls_acceptor(cert: &Path, key: &Path) -> Result<TlsAcceptor, ServeError> {
    let tls_err = |m: String| ServeError::Tls(m);
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(cert)
        .map_err(|e| tls_err(format!("read {}: {e}", cert.display())))?
        .collect::<Result<_, _>>()
        .map_err(|e| tls_err(format!("parse {}: {e}", cert.display())))?;
    if certs.is_empty() {
        return Err(tls_err(format!(
            "{}: no certificates found",
            cert.display()
        )));
    }
    let key = PrivateKeyDer::from_pem_file(key)
        .map_err(|e| tls_err(format!("read {}: {e}", key.display())))?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut cfg = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| tls_err(e.to_string()))?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| tls_err(e.to_string()))?;
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(TlsAcceptor::from(Arc::new(cfg)))
}

/// Serves `router` on `listener` until `shutdown` resolves, then lets open
/// requests finish for up to five seconds.
pub(crate) async fn run(
    listener: TcpListener,
    router: Router,
    tls: Option<TlsAcceptor>,
    shutdown: impl Future<Output = ()> + Send,
) {
    let (stop_tx, stop_rx) = watch::channel(false);
    let mut conns = JoinSet::new();
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            () = &mut shutdown => break,
            accepted = listener.accept() => {
                let (stream, peer) = match accepted {
                    Ok(a) => a,
                    Err(e) => {
                        tracing::warn!(error = %e, "accept failed");
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        continue;
                    }
                };
                let _ = stream.set_nodelay(true);
                let (router, tls, stop) = (router.clone(), tls.clone(), stop_rx.clone());
                conns.spawn(async move {
                    match tls {
                        None => serve_conn(stream, peer, router, false, stop).await,
                        Some(acceptor) => {
                            match tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await {
                                Ok(Ok(s)) => serve_conn(s, peer, router, true, stop).await,
                                Ok(Err(e)) => tracing::debug!(%peer, error = %e, "TLS handshake failed"),
                                Err(_) => tracing::debug!(%peer, "TLS handshake timed out"),
                            }
                        }
                    }
                });
            }
            Some(_) = conns.join_next(), if !conns.is_empty() => {}
        }
    }
    drop(listener);
    let _ = stop_tx.send(true);
    let drain = async { while conns.join_next().await.is_some() {} };
    if tokio::time::timeout(SHUTDOWN_GRACE, drain).await.is_err() {
        conns.abort_all();
    }
}

async fn serve_conn<S>(
    stream: S,
    peer: SocketAddr,
    router: Router,
    tls: bool,
    mut stop: watch::Receiver<bool>,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let svc = hyper::service::service_fn(move |mut req: hyper::Request<Incoming>| {
        req.extensions_mut().insert(ConnectInfo(peer));
        if tls {
            req.extensions_mut().insert(TlsConnection);
        }
        router.clone().oneshot(req.map(Body::new))
    });
    let conn = hyper::server::conn::http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(READ_HEADER_TIMEOUT)
        .serve_connection(TokioIo::new(stream), svc)
        .with_upgrades();
    tokio::pin!(conn);
    tokio::select! {
        res = conn.as_mut() => {
            if let Err(e) = res {
                tracing::debug!(%peer, error = %e, "connection error");
            }
            return;
        }
        _ = stop.wait_for(|s| *s) => conn.as_mut().graceful_shutdown(),
    }
    let _ = conn.await;
}
