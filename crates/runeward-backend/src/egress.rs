//! Egress wiring shared by the backends.

use std::sync::Arc;

use runeward_charter::Network;
use runeward_egress::{Logger, Policy, Proxy, Rule};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use crate::error::{BackendError, Result};

/// Translates a Charter's network block into an egress [`Policy`]. Unset
/// verdicts mean allow.
pub fn policy_from_network(n: &Network) -> Policy {
    let default = if n.default.is_empty() {
        "allow".to_owned()
    } else {
        n.default.clone()
    };
    let rules = n
        .rules
        .iter()
        .map(|r| Rule {
            verdict: if r.verdict.is_empty() {
                "allow".to_owned()
            } else {
                r.verdict.clone()
            },
            hostname: r.hostname.clone(),
            cidr: r.cidr.clone(),
        })
        .collect();
    Policy { default, rules }
}

/// The policy JSON handed to the egress sidecar, byte-identical to Go's
/// `json.Marshal(egress.Policy)`.
pub(crate) fn policy_json(n: &Network) -> Result<String> {
    serde_json::to_string(&policy_from_network(n))
        .map_err(|e| BackendError::msg(format!("marshal egress policy: {e}")))
}

/// The `HTTP(S)_PROXY` variables pointing a sandbox at `proxy_url`, in a
/// fixed order.
pub fn proxy_env(proxy_url: &str) -> Vec<(String, String)> {
    const NO_PROXY: &str = "localhost,127.0.0.1,::1";
    [
        ("HTTP_PROXY", proxy_url),
        ("HTTPS_PROXY", proxy_url),
        ("http_proxy", proxy_url),
        ("https_proxy", proxy_url),
        ("NO_PROXY", NO_PROXY),
        ("no_proxy", NO_PROXY),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_owned(), v.to_owned()))
    .collect()
}

/// An in-process egress proxy on an ephemeral host port, reached from a
/// container via `host.docker.internal:<port>`. It binds all interfaces
/// (the host gateway is not loopback), so it is gated by freshly generated
/// Basic credentials only the sandbox receives.
#[derive(Debug)]
pub(crate) struct HostProxy {
    pub(crate) port: u16,
    pub(crate) user: String,
    pub(crate) pass: String,
    stop: Option<oneshot::Sender<()>>,
    task: JoinHandle<()>,
}

impl HostProxy {
    /// Serves `policy` on `0.0.0.0:0`.
    pub(crate) async fn start(policy: Policy, sandbox_id: &str) -> Result<Self> {
        let listener = TcpListener::bind("0.0.0.0:0")
            .await
            .map_err(|e| BackendError::io("start egress proxy", e))?;
        let port = listener
            .local_addr()
            .map_err(|e| BackendError::io("start egress proxy", e))?
            .port();
        let user = "runeward".to_owned();
        let pass = crate::random_hex();
        let proxy = Arc::new(
            Proxy::new(policy)
                .with_sandbox_id(sandbox_id)
                .with_logger(Logger::new(format!("runeward-egress {sandbox_id} ")))
                .with_auth(user.clone(), pass.clone()),
        );
        let (tx, rx) = oneshot::channel::<()>();
        let task = tokio::spawn(async move {
            let shutdown = async {
                let _ = rx.await;
            };
            if let Err(e) = proxy.serve_with_shutdown(listener, shutdown).await {
                tracing::warn!(target: "runeward_backend", "egress proxy stopped: {e}");
            }
        });
        Ok(Self {
            port,
            user,
            pass,
            stop: Some(tx),
            task,
        })
    }

    /// The proxy URL as seen from a container that resolves `gateway` to
    /// the host.
    pub(crate) fn url(&self, gateway: &str) -> String {
        format!("http://{}:{}@{gateway}:{}", self.user, self.pass, self.port)
    }

    /// Stops accepting and tears the proxy down.
    pub(crate) fn stop(mut self) {
        if let Some(tx) = self.stop.take() {
            let _ = tx.send(());
        }
        self.task.abort();
    }
}

impl Drop for HostProxy {
    fn drop(&mut self) {
        if let Some(tx) = self.stop.take() {
            let _ = tx.send(());
        }
        self.task.abort();
    }
}

#[cfg(test)]
mod tests {
    use runeward_charter::NetworkRule;

    use super::*;

    #[test]
    fn policy_defaults_and_json() {
        let n = Network {
            default: "deny".into(),
            rules: vec![
                NetworkRule {
                    hostname: "example.com".into(),
                    ..NetworkRule::default()
                },
                NetworkRule {
                    verdict: "deny".into(),
                    cidr: "10.0.0.0/8".into(),
                    ..NetworkRule::default()
                },
            ],
            enforce: String::new(),
        };
        assert_eq!(
            policy_json(&n).expect("json"),
            r#"{"default":"deny","rules":[{"verdict":"allow","hostname":"example.com","cidr":""},{"verdict":"deny","hostname":"","cidr":"10.0.0.0/8"}]}"#
        );
        let open = policy_from_network(&Network::default());
        assert_eq!(open.default, "allow");
        assert_eq!(
            policy_json(&Network::default()).expect("json"),
            r#"{"default":"allow","rules":[]}"#
        );
    }

    #[test]
    fn proxy_env_vars() {
        let env = proxy_env("http://p:1");
        assert_eq!(env.len(), 6);
        assert!(env.contains(&("https_proxy".into(), "http://p:1".into())));
        assert!(env.contains(&("NO_PROXY".into(), "localhost,127.0.0.1,::1".into())));
    }

    #[tokio::test]
    async fn host_proxy_requires_credentials() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let hp = HostProxy::start(policy_from_network(&Network::default()), "sb-test")
            .await
            .expect("start");
        assert_eq!(hp.pass.len(), 32);
        assert!(
            hp.url("host.docker.internal")
                .starts_with("http://runeward:")
        );
        let mut s = tokio::net::TcpStream::connect(("127.0.0.1", hp.port))
            .await
            .expect("connect");
        s.write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
            .await
            .expect("write");
        let mut buf = [0u8; 64];
        let n = s.read(&mut buf).await.expect("read");
        let head = String::from_utf8_lossy(&buf[..n]);
        assert!(head.contains("407"), "{head}");
        hp.stop();
    }
}
