//! The credential-injecting request broker.
//!
//! A [`Broker`] is built per sandbox from the Charter's `[[endpoint]]` and
//! `[[credential]]` sections and attached to a [`crate::Proxy`] or
//! [`crate::TransparentProxy`] with `with_broker`. It adds, on top of the L4
//! policy:
//!
//! - **Endpoints at L4.** A listed `host:port` is reachable even under a
//!   deny-by-default network policy (an explicit network deny rule for the
//!   hostname still wins). An endpoint's `binaries` list is copied onto
//!   every decision but is *advisory*: the broker cannot yet tell which
//!   executable opened a connection, so it is recorded, not enforced.
//! - **TLS inspection.** For `rest`, `websocket`, `mcp` and `json-rpc`
//!   endpoints the broker terminates TLS with a per-sandbox CA
//!   ([`Broker::ca_cert_pem`] is what the control plane mounts into the
//!   sandbox trust store), evaluates every request, and originates TLS to
//!   the real upstream against the Mozilla roots. `tcp` endpoints stay
//!   opaque tunnels with an SNI check.
//! - **Request rules.** REST method and path globs, JSON-RPC methods and MCP
//!   `tools/call` tool globs; deny rules win, and when allow rules exist one
//!   must match (see [`rules`]). MCP tool calls that are untagged or tagged
//!   `irreversible` produce a distinct `require-approval` verdict.
//! - **Budgets.** `max_calls` per endpoint and per allow rule, per broker
//!   (one broker per sandbox session); a spent budget answers 429.
//! - **Audit mode.** `mode = "audit"` records what would have been refused
//!   and forwards it anyway.
//! - **Credential placeholders.** Each credential gets a random
//!   `rwph_<hex>` placeholder ([`Broker::placeholder_env`] is the env map to
//!   set in the sandbox). Requests to the owning endpoint have it swapped for
//!   the real secret (headers, `Basic` credentials and query) and the secret
//!   attached per `inject`; the secret is scrubbed back out of responses.
//!   A placeholder seen on the way to any other destination is refused and
//!   recorded as `placeholder-misuse`.
//!
//! Every decision goes to the per-sandbox ring ([`crate::list_decisions`])
//! and to the live stream from [`Broker::subscribe`]. Secrets never appear
//! in decisions or log lines.

pub mod ca;
mod credentials;
mod intercept;
pub mod rules;

use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use runeward_charter::{Charter, Credential, Endpoint};
use tokio::sync::broadcast;

pub use ca::{CaError, SandboxCa};
pub use credentials::{PLACEHOLDER_PREFIX, SCRUBBED};
pub use rules::{Effect, Protocol};

use crate::decision_log::Decision;
use crate::policy::hostname_matches;
use credentials::{Inject, Secret, Slot, Vault};

pub(crate) use intercept::Target;

/// Largest request body the broker buffers for inspection; bigger bodies to
/// inspected endpoints are refused with 413.
pub const MAX_INSPECT_BODY: usize = 8 << 20;

/// How many decisions the live stream buffers per subscriber before the
/// slowest one starts missing events.
pub const DECISION_STREAM_CAPACITY: usize = 1024;

/// Errors building a [`Broker`].
#[derive(Debug, thiserror::Error)]
pub enum BrokerError {
    /// A credential's secret reference could not be resolved. The message
    /// names the reference, never a value.
    #[error("credential {name:?}: {source}")]
    Secret {
        /// Credential name.
        name: String,
        /// Resolver error.
        source: runeward_secrets::Error,
    },
    /// A credential was referenced but no value was supplied.
    #[error("credential {0:?}: no secret value supplied")]
    MissingSecret(String),
    /// A resolved secret cannot be sent in a header (control characters).
    #[error("credential {0:?}: secret contains characters not allowed in a header")]
    InvalidSecret(String),
    /// A credential's `inject` is not understood.
    #[error("credential {0:?}: unsupported inject {1:?}")]
    Inject(String, String),
    /// An endpoint names an undeclared credential.
    #[error("endpoint {0:?}: credential {1:?} is not declared")]
    UnknownCredential(String, String),
    /// An endpoint's protocol is not understood.
    #[error("endpoint {0:?}: unsupported protocol {1:?}")]
    Protocol(String, String),
    /// The per-sandbox CA could not be created.
    #[error("broker CA: {0}")]
    Ca(#[from] CaError),
}

/// A request the control plane must approve before the broker forwards it.
#[derive(Debug, Clone)]
pub struct ApprovalRequest {
    /// Sandbox the request came from.
    pub sandbox_id: String,
    /// The `require-approval` decision as recorded (no secrets).
    pub decision: Decision,
}

/// The control plane's answer to an [`ApprovalRequest`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApprovalOutcome {
    /// Forward the request.
    Approved,
    /// Refuse it, with a reason for the agent.
    Denied(String),
    /// No decision could be obtained (queue offline, timed out).
    Unavailable,
}

/// Future returned by [`ApprovalHook::request_approval`].
pub type ApprovalFuture = Pin<Box<dyn Future<Output = ApprovalOutcome> + Send>>;

/// Routes `require-approval` decisions to a human. Without a hook the
/// broker refuses such requests with 403 and an `approval` reason code.
/// Implementations should bound how long they wait; the agent's request is
/// held open meanwhile.
pub trait ApprovalHook: Send + Sync {
    /// Asks for approval of one request.
    fn request_approval(&self, req: ApprovalRequest) -> ApprovalFuture;
}

/// An endpoint with its parsed settings.
#[derive(Debug)]
pub(crate) struct EndpointSpec {
    pub(crate) ep: Endpoint,
    pub(crate) protocol: Protocol,
    pub(crate) port: u16,
    pub(crate) credential: Option<usize>,
    pub(crate) audit: bool,
}

impl EndpointSpec {
    pub(crate) fn label(&self) -> &str {
        if self.ep.name.is_empty() {
            &self.ep.host
        } else {
            &self.ep.name
        }
    }
}

/// The per-sandbox request broker. See the module docs.
pub struct Broker {
    sandbox_id: String,
    pub(crate) endpoints: Vec<EndpointSpec>,
    pub(crate) vault: Vault,
    pub(crate) ca: SandboxCa,
    budgets: Mutex<HashMap<(usize, Option<usize>), u64>>,
    pub(crate) events: broadcast::Sender<Decision>,
    pub(crate) approval: Option<Arc<dyn ApprovalHook>>,
    pub(crate) upstream_tls: Arc<rustls::ClientConfig>,
}

impl std::fmt::Debug for Broker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Broker")
            .field("sandbox_id", &self.sandbox_id)
            .field(
                "endpoints",
                &self.endpoints.iter().map(|e| e.label()).collect::<Vec<_>>(),
            )
            .field(
                "credentials",
                &self.vault.slots.iter().map(|s| &s.name).collect::<Vec<_>>(),
            )
            .finish_non_exhaustive()
    }
}

impl Broker {
    /// Builds a broker for a Charter, resolving every credential an endpoint
    /// uses through `secrets` (fail closed: any resolution error aborts).
    pub async fn from_charter(
        sandbox_id: &str,
        charter: &Charter,
        secrets: &dyn runeward_secrets::Resolver,
    ) -> Result<Self, BrokerError> {
        Self::resolve(
            sandbox_id,
            charter.endpoints.clone(),
            charter.credentials.clone(),
            secrets,
        )
        .await
    }

    /// Like [`Broker::from_charter`] with explicit sections.
    pub async fn resolve(
        sandbox_id: &str,
        endpoints: Vec<Endpoint>,
        credentials: Vec<Credential>,
        secrets: &dyn runeward_secrets::Resolver,
    ) -> Result<Self, BrokerError> {
        let mut values = HashMap::new();
        for c in &credentials {
            if endpoints.iter().any(|e| e.credential == c.name) {
                let v = secrets
                    .resolve(&c.source)
                    .await
                    .map_err(|source| BrokerError::Secret {
                        name: c.name.clone(),
                        source,
                    })?;
                values.insert(c.name.clone(), v);
            }
        }
        Self::with_secret_values(sandbox_id, endpoints, credentials, values)
    }

    /// Builds a broker from already-resolved secret values keyed by
    /// credential name. Values for credentials no endpoint uses are dropped.
    pub fn with_secret_values(
        sandbox_id: &str,
        endpoints: Vec<Endpoint>,
        credentials: Vec<Credential>,
        mut values: HashMap<String, String>,
    ) -> Result<Self, BrokerError> {
        let mut slots = Vec::with_capacity(credentials.len());
        for c in credentials {
            let inject = Inject::parse(&c.inject)
                .ok_or_else(|| BrokerError::Inject(c.name.clone(), c.inject.clone()))?;
            let used = endpoints.iter().any(|e| e.credential == c.name);
            let secret = if used {
                let v = values
                    .remove(&c.name)
                    .filter(|v| !v.is_empty())
                    .ok_or_else(|| BrokerError::MissingSecret(c.name.clone()))?;
                if v.chars().any(char::is_control) {
                    return Err(BrokerError::InvalidSecret(c.name));
                }
                Some(Secret::new(v))
            } else {
                None
            };
            slots.push(Slot {
                placeholder: credentials::new_placeholder(),
                placeholder_env: c.placeholder_env,
                inject,
                secret,
                name: c.name,
            });
        }
        // Wipe any unused values handed to us.
        drop(values.into_values().map(Secret::new).collect::<Vec<_>>());

        let mut specs = Vec::with_capacity(endpoints.len());
        for ep in endpoints {
            let label = if ep.name.is_empty() {
                ep.host.clone()
            } else {
                ep.name.clone()
            };
            let protocol = Protocol::parse(&ep.protocol)
                .ok_or_else(|| BrokerError::Protocol(label.clone(), ep.protocol.clone()))?;
            let credential = if ep.credential.is_empty() {
                None
            } else {
                Some(
                    slots
                        .iter()
                        .position(|s| s.name == ep.credential)
                        .ok_or_else(|| {
                            BrokerError::UnknownCredential(label.clone(), ep.credential.clone())
                        })?,
                )
            };
            specs.push(EndpointSpec {
                protocol,
                port: if ep.port == 0 { 443 } else { ep.port },
                credential,
                audit: ep.mode == "audit",
                ep,
            });
        }

        let (events, _) = broadcast::channel(DECISION_STREAM_CAPACITY);
        Ok(Self {
            ca: SandboxCa::generate(sandbox_id)?,
            sandbox_id: sandbox_id.trim().to_string(),
            endpoints: specs,
            vault: Vault { slots },
            budgets: Mutex::new(HashMap::new()),
            events,
            approval: None,
            upstream_tls: crate::proxy::default_tls(),
        })
    }

    /// Replaces the TLS client config used towards inspected upstreams (the
    /// default trusts the bundled Mozilla roots).
    #[must_use]
    pub fn with_upstream_tls(mut self, config: Arc<rustls::ClientConfig>) -> Self {
        self.upstream_tls = config;
        self
    }

    /// Routes `require-approval` decisions to `hook`.
    #[must_use]
    pub fn with_approval_hook(mut self, hook: Arc<dyn ApprovalHook>) -> Self {
        self.approval = Some(hook);
        self
    }

    /// The sandbox this broker serves.
    pub fn sandbox_id(&self) -> &str {
        &self.sandbox_id
    }

    /// PEM of the per-sandbox CA; mount it into the sandbox trust store
    /// (and point `SSL_CERT_FILE`/`NODE_EXTRA_CA_CERTS`/`REQUESTS_CA_BUNDLE`
    /// at it) so inspected endpoints validate.
    pub fn ca_cert_pem(&self) -> &str {
        self.ca.cert_pem()
    }

    /// The per-sandbox CA.
    pub fn ca(&self) -> &SandboxCa {
        &self.ca
    }

    /// Env var name → placeholder, for every credential with a
    /// `placeholder_env`. The control plane sets these in the sandbox.
    pub fn placeholder_env(&self) -> BTreeMap<String, String> {
        self.vault
            .slots
            .iter()
            .filter(|s| !s.placeholder_env.is_empty())
            .map(|s| (s.placeholder_env.clone(), s.placeholder.clone()))
            .collect()
    }

    /// Credential name → placeholder, for every credential.
    pub fn placeholders(&self) -> BTreeMap<String, String> {
        self.vault
            .slots
            .iter()
            .map(|s| (s.name.clone(), s.placeholder.clone()))
            .collect()
    }

    /// Subscribes to the live decision stream (L4 and L7, every front end
    /// this broker is attached to). Slow subscribers miss events rather than
    /// stall traffic.
    pub fn subscribe(&self) -> broadcast::Receiver<Decision> {
        self.events.subscribe()
    }

    /// The endpoint (by Charter name, or host when unnamed) that governs
    /// `host:port`, if any.
    pub fn endpoint_for(&self, host: &str, port: u16) -> Option<&str> {
        self.endpoint_index(host, &port.to_string())
            .map(|i| self.endpoints[i].label())
    }

    /// First endpoint matching `host` (exactly or by `*.` wildcard,
    /// case-insensitively) and `port`.
    pub(crate) fn endpoint_index(&self, host: &str, port: &str) -> Option<usize> {
        let port: u16 = port.parse().ok()?;
        self.endpoints
            .iter()
            .position(|e| e.port == port && hostname_matches(&e.ep.host, host))
    }

    /// Whether any credential placeholder exists (so plaintext traffic must
    /// be scanned for misuse).
    pub(crate) fn has_placeholders(&self) -> bool {
        !self.vault.slots.is_empty()
    }

    /// Takes one call from the endpoint budget and from each matched allow
    /// rule's budget, all or nothing.
    pub(crate) fn take_budget(&self, ep: usize, rules: &[usize]) -> Result<(), String> {
        let spec = &self.endpoints[ep];
        let mut counts = self.budgets.lock().unwrap_or_else(|e| e.into_inner());
        let mut keys = Vec::new();
        if spec.ep.max_calls > 0 {
            keys.push(((ep, None), spec.ep.max_calls, "endpoint".to_string()));
        }
        for &r in rules {
            if let Some(rule) = spec.ep.allow.get(r)
                && rule.max_calls > 0
            {
                keys.push(((ep, Some(r)), rule.max_calls, format!("allow[{r}]")));
            }
        }
        for (key, max, what) in &keys {
            if counts.get(key).copied().unwrap_or(0) >= *max {
                return Err(format!("{what} budget of {max} calls is spent"));
            }
        }
        for (key, _, _) in keys {
            *counts.entry(key).or_insert(0) += 1;
        }
        Ok(())
    }

    /// Removes every resolved secret from `s`.
    pub(crate) fn scrub(&self, s: &str) -> String {
        self.vault.scrub(s)
    }

    /// Base decision fields for an endpoint.
    pub(crate) fn endpoint_decision(&self, ep: Option<usize>) -> Decision {
        let Some(spec) = ep.map(|i| &self.endpoints[i]) else {
            return Decision::default();
        };
        Decision {
            endpoint: Some(spec.label().to_string()),
            protocol: Some(spec.protocol.as_str().to_string()),
            binaries: (!spec.ep.binaries.is_empty()).then(|| spec.ep.binaries.clone()),
            ..Decision::default()
        }
    }

    /// The L4 allow decision for a connection to endpoint `i`.
    pub(crate) fn connect_decision(&self, i: usize, host: &str, ip: &str) -> Decision {
        let mut d = self.endpoint_decision(Some(i));
        d.host = host.to_string();
        d.ip = ip.to_string();
        d.allow = true;
        d.verdict = Some(crate::decision_log::Verdict::Allow);
        d.reason_code = Some(crate::decision_log::ReasonCode::Allowed);
        d.reason = if self.endpoints[i].protocol.inspected() {
            "allowed: endpoint (requests inspected)".into()
        } else {
            "allowed: endpoint".into()
        };
        d
    }

    /// Scrubs every string field of a decision.
    pub(crate) fn scrub_decision(&self, mut d: Decision) -> Decision {
        let s = |v: &mut String| *v = self.scrub(v);
        s(&mut d.host);
        s(&mut d.reason);
        for v in [&mut d.method, &mut d.path, &mut d.tool]
            .into_iter()
            .flatten()
        {
            s(v);
        }
        d
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use runeward_charter::RequestRule;

    fn ep(host: &str, port: u16) -> Endpoint {
        Endpoint {
            name: format!("{host}-ep"),
            host: host.into(),
            port,
            protocol: "rest".into(),
            ..Endpoint::default()
        }
    }

    #[test]
    fn builds_placeholders_and_env() {
        let creds = vec![
            Credential {
                name: "gh".into(),
                source: "env://GH".into(),
                placeholder_env: "GITHUB_TOKEN".into(),
                inject: String::new(),
            },
            Credential {
                name: "idle".into(),
                source: "env://IDLE".into(),
                ..Credential::default()
            },
        ];
        let mut e = ep("api.test", 0);
        e.credential = "gh".into();
        let b = Broker::with_secret_values(
            "sb",
            vec![e],
            creds,
            HashMap::from([("gh".to_string(), "tok".to_string())]),
        )
        .expect("broker");
        let env = b.placeholder_env();
        assert_eq!(env.len(), 1);
        assert!(env["GITHUB_TOKEN"].starts_with(PLACEHOLDER_PREFIX));
        assert_eq!(b.placeholders().len(), 2);
        assert_eq!(b.endpoint_for("API.test", 443), Some("api.test-ep"));
        assert_eq!(b.endpoint_for("api.test", 80), None);
        assert!(!format!("{b:?}").contains("tok\""));
    }

    #[test]
    fn missing_or_bad_secret_fails_closed() {
        let creds = vec![Credential {
            name: "gh".into(),
            source: "env://GH".into(),
            ..Credential::default()
        }];
        let mut e = ep("api.test", 0);
        e.credential = "gh".into();
        let err = Broker::with_secret_values("sb", vec![e.clone()], creds.clone(), HashMap::new())
            .expect_err("missing");
        assert!(matches!(err, BrokerError::MissingSecret(_)));
        let err = Broker::with_secret_values(
            "sb",
            vec![e],
            creds,
            HashMap::from([("gh".to_string(), "a\nb".to_string())]),
        )
        .expect_err("newline");
        assert!(matches!(err, BrokerError::InvalidSecret(_)));
    }

    #[test]
    fn budgets_per_endpoint_and_rule() {
        let mut e = ep("api.test", 0);
        e.max_calls = 3;
        e.allow = vec![RequestRule {
            max_calls: 1,
            ..RequestRule::default()
        }];
        let b = Broker::with_secret_values("sb", vec![e], vec![], HashMap::new()).expect("b");
        assert!(b.take_budget(0, &[0]).is_ok());
        let err = b.take_budget(0, &[0]).expect_err("rule spent");
        assert!(err.contains("allow[0]"), "{err}");
        assert!(b.take_budget(0, &[]).is_ok());
        assert!(b.take_budget(0, &[]).is_ok());
        let err = b.take_budget(0, &[]).expect_err("endpoint spent");
        assert!(err.contains("endpoint"), "{err}");
    }

    #[derive(Debug)]
    struct Fixed;
    impl runeward_secrets::Resolver for Fixed {
        fn resolve<'a>(&'a self, reference: &'a str) -> runeward_secrets::ResolveFuture<'a> {
            Box::pin(async move {
                if reference == "env://OK" {
                    Ok("v".to_string())
                } else {
                    Err(runeward_secrets::Dispatcher::default()
                        .resolve(reference)
                        .await
                        .expect_err("unconfigured"))
                }
            })
        }
    }

    #[tokio::test]
    async fn resolves_through_secret_resolver() {
        let mut e = ep("api.test", 0);
        e.credential = "c".into();
        let ok = Credential {
            name: "c".into(),
            source: "env://OK".into(),
            ..Credential::default()
        };
        Broker::resolve("sb", vec![e.clone()], vec![ok], &Fixed)
            .await
            .expect("resolved");
        let bad = Credential {
            name: "c".into(),
            source: "vault://kv/x#y".into(),
            ..Credential::default()
        };
        let err = Broker::resolve("sb", vec![e], vec![bad], &Fixed)
            .await
            .expect_err("fails closed");
        assert!(err.to_string().contains("credential \"c\""), "{err}");
    }
}
