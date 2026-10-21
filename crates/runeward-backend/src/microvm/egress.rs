//! The host end of a microVM's only way out.
//!
//! The guest has no network device. Its agent forwards each connection
//! made to the in-guest proxy address over vsock to the host, where the
//! VMM hands it to this Unix socket; here the Charter's [`Policy`] (and
//! the request broker, when there is one) decides, exactly as the
//! cooperative proxy of the container backends does. A connection that
//! does not speak HTTP proxy protocol is refused by the proxy, and nothing
//! else leaves the guest, so deny-by-default cannot be bypassed from
//! inside: there is no route to bypass it with.

use std::convert::Infallible;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use hyper_util::rt::{TokioIo, TokioTimer};
use runeward_egress::{Broker, Logger, Policy, Proxy};
use tokio::net::UnixListener;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use crate::error::{BackendError, Result};

/// Serves the egress proxy on a Unix socket until dropped.
#[derive(Debug)]
pub(crate) struct EgressServer {
    path: PathBuf,
    stop: Option<oneshot::Sender<()>>,
    task: JoinHandle<()>,
}

impl EgressServer {
    /// Binds `path` (replacing a stale socket) and serves `policy` for
    /// sandbox `id`, with `broker` handling the Charter's endpoints.
    pub(crate) async fn start(
        path: &Path,
        policy: Policy,
        id: &str,
        broker: Option<Arc<Broker>>,
    ) -> Result<Self> {
        let _ = std::fs::remove_file(path);
        let listener = UnixListener::bind(path)
            .map_err(|e| BackendError::io(format!("bind egress socket {}", path.display()), e))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        }
        let mut proxy = Proxy::new(policy)
            .with_sandbox_id(id)
            .with_logger(Logger::new(format!("runeward-egress {id} ")));
        if let Some(b) = broker {
            proxy = proxy.with_broker(b);
        }
        let proxy = Arc::new(proxy);
        let (tx, mut rx) = oneshot::channel::<()>();
        let task = tokio::spawn(async move {
            let mut conns = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    _ = &mut rx => break,
                    Some(_) = conns.join_next(), if !conns.is_empty() => {}
                    accepted = listener.accept() => {
                        let Ok((stream, _)) = accepted else { continue };
                        let proxy = Arc::clone(&proxy);
                        conns.spawn(async move {
                            let svc = hyper::service::service_fn(move |req| {
                                let p = Arc::clone(&proxy);
                                async move { Ok::<_, Infallible>(p.handle(req).await) }
                            });
                            let mut b = hyper::server::conn::http1::Builder::new();
                            b.timer(TokioTimer::new());
                            let _ = b
                                .serve_connection(TokioIo::new(stream), svc)
                                .with_upgrades()
                                .await;
                        });
                    }
                }
            }
            conns.abort_all();
        });
        Ok(Self {
            path: path.to_path_buf(),
            stop: Some(tx),
            task,
        })
    }
}

impl Drop for EgressServer {
    fn drop(&mut self) {
        if let Some(tx) = self.stop.take() {
            let _ = tx.send(());
        }
        self.task.abort();
        let _ = std::fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use runeward_charter::{Network, NetworkRule};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;
    use crate::egress::policy_from_network;

    async fn connect_status(path: &Path, target: &str) -> String {
        let mut s = tokio::net::UnixStream::connect(path)
            .await
            .expect("connect");
        s.write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
            .await
            .expect("write");
        let mut buf = vec![0u8; 256];
        let n = s.read(&mut buf).await.expect("read");
        String::from_utf8_lossy(&buf[..n]).into_owned()
    }

    #[tokio::test]
    async fn deny_by_default_is_enforced_on_the_socket() {
        let d = tempfile::tempdir().expect("tempdir");
        let path = d.path().join("egress.sock");
        let net = Network {
            default: "deny".into(),
            rules: vec![NetworkRule {
                hostname: "allowed.example".into(),
                ..NetworkRule::default()
            }],
            enforce: String::new(),
        };
        let srv = EgressServer::start(&path, policy_from_network(&net), "sb-egress", None)
            .await
            .expect("start");
        let head = connect_status(&path, "denied.example:443").await;
        assert!(head.starts_with("HTTP/1.1 403"), "{head}");
        drop(srv);
        assert!(!path.exists(), "socket removed on drop");
    }
}
