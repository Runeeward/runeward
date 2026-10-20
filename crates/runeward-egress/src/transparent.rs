//! Transparent proxy for iptables-redirected connections (strict mode).
//!
//! Unlike [`crate::Proxy`] it needs no `HTTP(S)_PROXY` cooperation: the
//! original destination comes from `SO_ORIGINAL_DST` and the hostname is
//! sniffed from TLS SNI or the HTTP `Host` header. Accepting redirected
//! connections is Linux-only; the per-connection logic is portable.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::broker::{Broker, Target};
use crate::decision_log::Decision;
use crate::gate::{DenyReason, EgressRequest, Frontend, Gate, GateDecision, HostSource};
use crate::logger::{Logger, Sink};
use crate::policy::Policy;
use crate::proxy::dial;
use crate::resolve::{Resolver, system_resolver};
use crate::sni::{extract_sni, http_host_from_peek};

/// How many leading bytes are read to sniff the hostname.
pub const PEEK_LIMIT: usize = 4096;

/// How long to wait for the client's first bytes.
pub const PEEK_TIMEOUT: Duration = Duration::from_secs(5);

/// Enforces a [`Policy`] on connections redirected to it by iptables.
pub struct TransparentProxy {
    gate: Gate,
    sink: Sink,
    broker: Option<Arc<Broker>>,
}

impl std::fmt::Debug for TransparentProxy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransparentProxy")
            .field("gate", &self.gate)
            .field("sink", &self.sink)
            .field("broker", &self.broker.is_some())
            .finish()
    }
}

impl TransparentProxy {
    /// Creates a transparent proxy enforcing `policy` with the system
    /// resolver.
    pub fn new(policy: Policy) -> Self {
        Self {
            gate: Gate::new(policy, system_resolver()),
            sink: Sink::default(),
            broker: None,
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

    /// Replaces the hostname resolver used for pinning.
    #[must_use]
    pub fn with_resolver(mut self, resolver: Arc<dyn Resolver>) -> Self {
        self.gate = self.gate.with_resolver(resolver);
        self
    }

    /// Attaches a request [`Broker`] (see [`crate::Proxy::with_broker`]).
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

    /// The enforced policy.
    pub fn policy(&self) -> &Policy {
        self.gate.policy()
    }

    /// Binds `addr` and serves redirected connections until an accept error.
    pub async fn serve(self: Arc<Self>, addr: &str) -> io::Result<()> {
        if !cfg!(target_os = "linux") {
            return Err(unsupported());
        }
        let listener = tokio::net::TcpListener::bind(addr).await?;
        self.serve_listener(listener).await
    }

    /// Serves redirected connections from `listener` until an accept error.
    #[cfg(target_os = "linux")]
    pub async fn serve_listener(
        self: Arc<Self>,
        listener: tokio::net::TcpListener,
    ) -> io::Result<()> {
        loop {
            let (stream, _) = listener.accept().await?;
            let this = Arc::clone(&self);
            tokio::spawn(async move {
                match original_dst(&stream) {
                    Ok(dst) => this.handle_redirected(stream, dst).await,
                    Err(e) => this
                        .sink
                        .logf(format_args!("egress: drop (no original dst: {e})")),
                }
            });
        }
    }

    /// Unsupported off Linux (`SO_ORIGINAL_DST` is a netfilter feature).
    #[cfg(not(target_os = "linux"))]
    pub async fn serve_listener(
        self: Arc<Self>,
        _listener: tokio::net::TcpListener,
    ) -> io::Result<()> {
        Err(unsupported())
    }

    /// Handles one redirected connection whose pre-redirect destination was
    /// `dst`: sniffs the hostname, applies the policy, and on allow dials
    /// the pinned upstream, replays the sniffed bytes and splices.
    pub async fn handle_redirected(&self, mut client: TcpStream, dst: SocketAddr) {
        let mut peek = vec![0u8; PEEK_LIMIT];
        let n = match tokio::time::timeout(PEEK_TIMEOUT, client.read(&mut peek)).await {
            Ok(Ok(n)) => n,
            _ => 0,
        };
        peek.truncate(n);

        let host = extract_sni(&peek)
            .or_else(|| http_host_from_peek(&peek))
            .unwrap_or_default();
        let dst_label = dst.to_string();

        let ereq = if host.is_empty() {
            // No hostname; fall back to the raw IP against CIDR rules.
            EgressRequest {
                frontend: Frontend::Transparent,
                host: dst.ip().to_string(),
                port: dst.port().to_string(),
                source: HostSource::OriginalDst,
                dst_hint: Some(dst.ip()),
                method: None,
                path: None,
            }
        } else {
            // In strict mode a presented hostname must be explicitly
            // allowlisted.
            EgressRequest {
                frontend: Frontend::Transparent,
                host: host.clone(),
                port: dst.port().to_string(),
                source: HostSource::Sniffed,
                dst_hint: Some(dst.ip()),
                method: None,
                path: None,
            }
        };

        let label = if host.is_empty() {
            dst_label.clone()
        } else {
            host.clone()
        };
        let pinned = match self.gate.evaluate(&ereq).await {
            GateDecision::Allow(t) => t,
            GateDecision::Deny(reason) => {
                if let DenyReason::Resolution(e) = reason {
                    self.sink
                        .logf(format_args!("egress: DENY {host} (resolve failed: {e})"));
                    self.sink
                        .record(&host, "", false, "hostname resolution failed");
                }
                self.sink
                    .logf(format_args!("egress: DENY {label} (dst={dst_label})"));
                self.sink.record(
                    &label,
                    &dst.ip().to_string(),
                    false,
                    "blocked by egress policy",
                );
                return;
            }
        };
        self.sink.logf(format_args!(
            "egress: ALLOW {label} (dst={dst_label} pinned={pinned})"
        ));
        let endpoint = self
            .broker
            .as_ref()
            .and_then(|b| b.endpoint_index(&ereq.host, &ereq.port).map(|i| (b, i)));
        let base = match endpoint {
            Some((b, i)) => b.record(
                &self.sink,
                b.connect_decision(i, &label, &pinned.ip.to_string()),
            ),
            None => {
                self.sink.record(
                    &label,
                    &pinned.ip.to_string(),
                    true,
                    "allowed by egress policy",
                );
                Decision {
                    host: label.clone(),
                    ip: pinned.ip.to_string(),
                    ..Decision::default()
                }
            }
        };
        if let Some((b, i)) = endpoint
            && b.endpoints[i].protocol.inspected()
        {
            let t = Target {
                host: ereq.host.clone(),
                port: ereq.port.clone(),
                pinned,
                upstream_tls: None,
                endpoint: Some(i),
            };
            Arc::clone(b)
                .serve_intercepted(client, peek, t, self.sink.clone())
                .await;
            return;
        }

        let mut upstream = match dial(&pinned).await {
            Ok(s) => s,
            Err(e) => {
                self.sink
                    .logf(format_args!("egress: dial {pinned} failed: {e}"));
                return;
            }
        };
        if let Some(b) = &self.broker
            && (endpoint.is_some() || b.has_placeholders())
        {
            b.guarded_splice(client, upstream, peek, None, base, &self.sink)
                .await;
            return;
        }
        // Replay the sniffed bytes, then splice bidirectionally.
        if !peek.is_empty() && upstream.write_all(&peek).await.is_err() {
            return;
        }
        let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
    }
}

fn unsupported() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "transparent egress proxy is only supported on linux",
    )
}

/// The pre-DNAT destination of an iptables-REDIRECTed IPv4 connection.
#[cfg(target_os = "linux")]
fn original_dst(stream: &TcpStream) -> io::Result<SocketAddr> {
    use nix::sys::socket::{getsockopt, sockopt::OriginalDst};
    let sa = getsockopt(stream, OriginalDst).map_err(io::Error::from)?;
    let ip = std::net::Ipv4Addr::from(u32::from_be(sa.sin_addr.s_addr));
    Ok(SocketAddr::new(ip.into(), u16::from_be(sa.sin_port)))
}
