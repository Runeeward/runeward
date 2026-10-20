//! The decision seam between "request parsed" and "connect upstream".
//!
//! Every front end (forward-proxy CONNECT, forward-proxy plain HTTP,
//! transparent redirect) parses its input into an [`EgressRequest`] and asks
//! the [`Gate`] for a [`GateDecision`]. Only an [`GateDecision::Allow`]
//! carries a [`PinnedTarget`], so nothing can be dialled without passing the
//! gate, and the IP that is dialled is the one the policy approved.
//!
//! The gate is deliberately the only place that interprets the policy, so
//! later L7 brokering (per-endpoint method/path rules, MCP tool names,
//! credential placeholder substitution, audit-vs-enforce mode) extends
//! [`EgressRequest`] / [`GateDecision`] here instead of touching the
//! transport code in the front ends.

use std::io;
use std::net::IpAddr;
use std::sync::Arc;

use crate::broker::Broker;
use crate::netutil::{join_host_port, parse_ip};
use crate::policy::Policy;
use crate::resolve::{PinnedTarget, Resolver, pinned_addr_for_host};

/// Where the host in an [`EgressRequest`] came from; this selects which
/// policy check applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostSource {
    /// The client named the destination (CONNECT target or absolute-URI
    /// authority). IP literals are checked with [`Policy::allow_addr`];
    /// hostnames must be explicitly allowlisted and are then pinned.
    Authority,
    /// The hostname was sniffed from TLS SNI or an HTTP `Host` header on a
    /// redirected connection. It must be explicitly allowlisted, and is
    /// pinned preferring the original destination IP.
    Sniffed,
    /// Only the original destination IP is known; `host` is that IP and is
    /// checked with [`Policy::allow_addr`] (CIDR rules, then the default).
    OriginalDst,
}

/// Which front end produced the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Frontend {
    /// Forward proxy `CONNECT` tunnel.
    Connect,
    /// Forward proxy plain HTTP request.
    Http,
    /// Transparent (iptables-redirected) connection.
    Transparent,
}

/// A parsed egress attempt, before any upstream connection exists.
#[derive(Debug, Clone)]
pub struct EgressRequest {
    /// Front end that parsed this request.
    pub frontend: Frontend,
    /// Destination host (hostname or IP literal, no brackets).
    pub host: String,
    /// Destination port as given (not yet validated).
    pub port: String,
    /// Provenance of `host`.
    pub source: HostSource,
    /// Original destination IP of a redirected connection, if known.
    pub dst_hint: Option<IpAddr>,
    /// HTTP method, when the front end has seen one (plain HTTP only today).
    pub method: Option<String>,
    /// HTTP path and query, when the front end has seen one.
    pub path: Option<String>,
}

/// Why the gate refused a request.
#[derive(Debug)]
pub enum DenyReason {
    /// An IP destination was rejected by CIDR/hostname rules or the default.
    Policy,
    /// A hostname was not explicitly allowlisted (or its first match denies).
    NotAllowlisted,
    /// The hostname was allowlisted but could not be resolved for pinning.
    Resolution(io::Error),
}

/// The gate's verdict.
#[derive(Debug)]
pub enum GateDecision {
    /// Connect to exactly this target.
    Allow(PinnedTarget),
    /// Refuse the request.
    Deny(DenyReason),
}

/// Applies a [`Policy`] to [`EgressRequest`]s and pins approved hostnames.
/// With a [`Broker`] attached, its `[[endpoint]]` host:ports are allowed
/// too (unless the first matching network hostname rule denies them).
#[derive(Clone)]
pub struct Gate {
    policy: Policy,
    resolver: Arc<dyn Resolver>,
    broker: Option<Arc<Broker>>,
}

impl std::fmt::Debug for Gate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Gate")
            .field("policy", &self.policy)
            .field("broker", &self.broker)
            .finish_non_exhaustive()
    }
}

impl Gate {
    /// Creates a gate for `policy` resolving with `resolver`.
    pub fn new(policy: Policy, resolver: Arc<dyn Resolver>) -> Self {
        Self {
            policy,
            resolver,
            broker: None,
        }
    }

    /// Replaces the resolver, keeping the policy and broker.
    #[must_use]
    pub fn with_resolver(mut self, resolver: Arc<dyn Resolver>) -> Self {
        self.resolver = resolver;
        self
    }

    /// Lets `broker`'s endpoints through at L4.
    #[must_use]
    pub fn with_broker(mut self, broker: Arc<Broker>) -> Self {
        self.broker = Some(broker);
        self
    }

    /// The attached broker, if any.
    pub fn broker(&self) -> Option<&Arc<Broker>> {
        self.broker.as_ref()
    }

    /// The policy this gate enforces.
    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    /// Decides `req`. On allow, the returned target is the only address the
    /// caller may dial.
    pub async fn evaluate(&self, req: &EgressRequest) -> GateDecision {
        let ip_literal = parse_ip(&req.host);
        if let Some(b) = &self.broker
            && b.endpoint_index(&req.host, &req.port).is_some()
        {
            // A listed endpoint is reachable even under default deny, but an
            // explicit network deny for the hostname still wins.
            if ip_literal.is_none() && self.policy.first_hostname_verdict(&req.host) == Some(false)
            {
                return GateDecision::Deny(DenyReason::Policy);
            }
            return match pinned_addr_for_host(&*self.resolver, &req.host, &req.port, req.dst_hint)
                .await
            {
                Ok(t) => GateDecision::Allow(t),
                Err(e) => GateDecision::Deny(DenyReason::Resolution(e)),
            };
        }
        match (req.source, ip_literal) {
            (HostSource::Authority | HostSource::OriginalDst, Some(ip)) => {
                if self
                    .policy
                    .allow_addr(&join_host_port(&req.host, &req.port))
                {
                    GateDecision::Allow(PinnedTarget {
                        ip,
                        port: req.port.clone(),
                    })
                } else {
                    GateDecision::Deny(DenyReason::Policy)
                }
            }
            (HostSource::OriginalDst, None) => GateDecision::Deny(DenyReason::Policy),
            (HostSource::Authority | HostSource::Sniffed, _) => {
                if !self.policy.allow_listed_hostname(&req.host) {
                    return GateDecision::Deny(DenyReason::NotAllowlisted);
                }
                match pinned_addr_for_host(&*self.resolver, &req.host, &req.port, req.dst_hint)
                    .await
                {
                    Ok(t) => GateDecision::Allow(t),
                    Err(e) => GateDecision::Deny(DenyReason::Resolution(e)),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::Rule;
    use crate::resolve::StaticResolver;

    fn gate(default: &str, rules: Vec<Rule>, answers: Vec<IpAddr>) -> Gate {
        Gate::new(
            Policy {
                default: default.into(),
                rules,
            },
            Arc::new(StaticResolver::new(answers)),
        )
    }

    fn req(host: &str, source: HostSource) -> EgressRequest {
        EgressRequest {
            frontend: Frontend::Connect,
            host: host.into(),
            port: "443".into(),
            source,
            dst_hint: None,
            method: None,
            path: None,
        }
    }

    #[tokio::test]
    async fn hostname_needs_explicit_allow_even_with_default_allow() {
        let g = gate("allow", vec![], vec!["127.0.0.1".parse().expect("ip")]);
        let d = g.evaluate(&req("x.test", HostSource::Authority)).await;
        assert!(matches!(d, GateDecision::Deny(DenyReason::NotAllowlisted)));
        // IP literals fall back to the default.
        let d = g.evaluate(&req("10.0.0.1", HostSource::Authority)).await;
        assert!(matches!(d, GateDecision::Allow(_)));
    }

    #[tokio::test]
    async fn sniffed_ip_literal_uses_allowlist() {
        let g = gate("allow", vec![], vec![]);
        let d = g.evaluate(&req("10.0.0.1", HostSource::Sniffed)).await;
        assert!(matches!(d, GateDecision::Deny(DenyReason::NotAllowlisted)));
    }

    #[tokio::test]
    async fn endpoints_pass_default_deny_unless_network_denies() {
        let endpoints = ["api.test", "blocked.test", "10.9.9.9"]
            .into_iter()
            .map(|h| runeward_charter::Endpoint {
                host: h.into(),
                ..runeward_charter::Endpoint::default()
            })
            .collect();
        let broker = Broker::with_secret_values("sb-gate", endpoints, vec![], Default::default())
            .expect("broker");
        let rules = vec![Rule {
            verdict: "deny".into(),
            hostname: "blocked.test".into(),
            cidr: String::new(),
        }];
        let g = gate("deny", rules, vec!["127.0.0.1".parse().expect("ip")])
            .with_broker(Arc::new(broker));
        let d = g.evaluate(&req("api.test", HostSource::Authority)).await;
        assert!(matches!(d, GateDecision::Allow(_)));
        let d = g.evaluate(&req("10.9.9.9", HostSource::Authority)).await;
        assert!(matches!(d, GateDecision::Allow(_)));
        let d = g
            .evaluate(&req("blocked.test", HostSource::Authority))
            .await;
        assert!(matches!(d, GateDecision::Deny(DenyReason::Policy)));
        // Wrong port: not an endpoint, so the policy applies.
        let mut other = req("api.test", HostSource::Authority);
        other.port = "8443".into();
        let d = g.evaluate(&other).await;
        assert!(matches!(d, GateDecision::Deny(DenyReason::NotAllowlisted)));
    }

    #[tokio::test]
    async fn resolution_failure_denies() {
        let rules = vec![Rule {
            verdict: "allow".into(),
            hostname: "x.test".into(),
            cidr: String::new(),
        }];
        let g = gate("deny", rules, vec![]);
        let d = g.evaluate(&req("x.test", HostSource::Authority)).await;
        assert!(matches!(d, GateDecision::Deny(DenyReason::Resolution(_))));
    }
}
