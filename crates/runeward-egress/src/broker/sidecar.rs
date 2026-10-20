//! Handing a broker to an out-of-process egress sidecar.
//!
//! In strict (transparent) mode and on Kubernetes the proxy runs in a
//! sidecar container, not in the control plane. The control plane still
//! builds the [`Broker`] (it resolves the secrets and owns the sandbox's
//! placeholders and CA), then exports it with [`Broker::sidecar_config`] as
//! a [`BrokerConfig`] document (`runeward.egress.broker.v1`). The sidecar
//! loads it with `runeward-egress --broker-config <file>`
//! ([`Broker::from_sidecar_config`]) and serves exactly the same
//! placeholders and CA the sandbox was given.
//!
//! # Threat model
//!
//! The document carries **resolved secret values** and the **CA private
//! key**, so it is as sensitive as the secrets themselves:
//!
//! - It is only ever written to a file readable by the sidecar: a `0600`
//!   root-owned file copied into the sidecar container before it starts
//!   (Docker/Podman), or a Kubernetes Secret mounted into the egress
//!   container alone. It is never put on a command line (visible in `ps`
//!   and `docker inspect`) or in an environment variable (inherited by
//!   children, visible in `/proc/<pid>/environ` and `docker inspect`).
//! - The sandbox container never mounts it. In Docker strict mode the sandbox
//!   shares the sidecar's network namespace but not its filesystem or PID
//!   namespace; on Kubernetes the Secret volume is mounted into the egress
//!   container only, and only the CA certificate key of it is projected into
//!   the sandbox.
//! - The sidecar reads the file once at startup, while still privileged,
//!   and then removes it where it can (Docker); afterwards the secrets live
//!   only in the proxy's memory and are wiped on drop.
//! - Anyone who can read the sidecar's filesystem or memory (the container
//!   engine, the node's root, Kubernetes users allowed to read Secrets or
//!   exec into the pod) can read the secrets. That is the same trust the
//!   control plane already places in the container engine; a Charter whose
//!   secrets must never leave the control plane host should use the
//!   cooperative mode, where the broker runs in-process.
//! - The CA key lets its holder mint certificates the *sandbox* trusts, and
//!   nothing else trusts it; it is per sandbox and dies with it.
//!
//! The sidecar reports each decision as one [`DecisionLine`] JSON object
//! per line on stdout (logs go to stderr), which the control plane feeds
//! back into its own broker with [`Broker::publish`].

use std::collections::HashMap;

use runeward_charter::{Credential, Endpoint};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use super::{Broker, BrokerError, SandboxCa};
use crate::decision_log::Decision;

/// The `schema` of a [`BrokerConfig`] document.
pub const BROKER_CONFIG_SCHEMA: &str = "runeward.egress.broker.v1";

/// The `schema` of a [`DecisionLine`].
pub const DECISION_LINE_SCHEMA: &str = "runeward.egress.decision.v1";

/// A string holding secret material: never printed by `Debug`, wiped on
/// drop.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SecretText(String);

impl SecretText {
    /// Wraps a secret.
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    /// The secret.
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Reports whether it is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl std::fmt::Debug for SecretText {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("«redacted»")
    }
}

impl Drop for SecretText {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// One credential in a [`BrokerConfig`]: its Charter settings, the
/// placeholder already set in the sandbox, and the resolved value.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SidecarCredential {
    pub name: String,
    pub placeholder_env: String,
    pub inject: String,
    pub placeholder: String,
    /// The resolved secret; empty when no endpoint uses the credential.
    pub value: SecretText,
}

impl std::fmt::Debug for SidecarCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SidecarCredential")
            .field("name", &self.name)
            .field("placeholder_env", &self.placeholder_env)
            .field("inject", &self.inject)
            .finish_non_exhaustive()
    }
}

/// The per-sandbox CA as a certificate and private key.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SidecarCa {
    pub cert_pem: String,
    pub key_pem: SecretText,
}

impl std::fmt::Debug for SidecarCa {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SidecarCa").finish_non_exhaustive()
    }
}

/// Everything an egress sidecar needs to act as a sandbox's broker
/// (`runeward.egress.broker.v1`). Contains secrets; see the module docs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BrokerConfig {
    pub schema: String,
    pub sandbox_id: String,
    pub endpoints: Vec<Endpoint>,
    pub credentials: Vec<SidecarCredential>,
    pub ca: SidecarCa,
    /// Extra PEM roots trusted towards inspected upstreams.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub upstream_ca_pem: String,
}

impl Default for BrokerConfig {
    fn default() -> Self {
        Self {
            schema: BROKER_CONFIG_SCHEMA.into(),
            sandbox_id: String::new(),
            endpoints: Vec::new(),
            credentials: Vec::new(),
            ca: SidecarCa::default(),
            upstream_ca_pem: String::new(),
        }
    }
}

impl BrokerConfig {
    /// Parses a document, rejecting unknown fields and other schemas.
    pub fn from_json(src: &[u8]) -> Result<Self, BrokerError> {
        let cfg: Self =
            serde_json::from_slice(src).map_err(|e| BrokerError::Config(e.to_string()))?;
        if cfg.schema != BROKER_CONFIG_SCHEMA {
            return Err(BrokerError::Config(format!(
                "schema must be {BROKER_CONFIG_SCHEMA:?}, got {:?}",
                cfg.schema
            )));
        }
        Ok(cfg)
    }

    /// The document as JSON. The returned buffer holds secrets and is wiped
    /// on drop.
    pub fn to_json(&self) -> zeroize::Zeroizing<Vec<u8>> {
        // Serialising strings and plain structs cannot fail.
        zeroize::Zeroizing::new(serde_json::to_vec(self).unwrap_or_default())
    }
}

/// One decision as a sidecar reports it on stdout. `decision` has the same
/// JSON shape as the perimeter list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionLine {
    pub schema: String,
    pub sandbox_id: String,
    pub decision: Decision,
}

impl DecisionLine {
    /// Wraps a decision for the log stream.
    pub fn new(sandbox_id: &str, d: &Decision) -> Self {
        Self {
            schema: DECISION_LINE_SCHEMA.into(),
            sandbox_id: sandbox_id.to_string(),
            decision: d.clone(),
        }
    }

    /// The line as JSON (no trailing newline).
    pub fn to_line(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }

    /// Parses one stdout line; `None` for anything that is not a decision
    /// line (other output is ignored, never trusted).
    pub fn parse(line: &str) -> Option<Self> {
        let l: Self = serde_json::from_str(line.trim()).ok()?;
        (l.schema == DECISION_LINE_SCHEMA).then_some(l)
    }
}

impl Broker {
    /// Exports this broker for an egress sidecar: endpoints, credentials
    /// with their placeholders and **resolved values**, and the CA with its
    /// **private key**. Write it only where the threat model in
    /// [`crate::broker::sidecar`] allows.
    pub fn sidecar_config(&self) -> BrokerConfig {
        BrokerConfig {
            schema: BROKER_CONFIG_SCHEMA.into(),
            sandbox_id: self.sandbox_id.clone(),
            endpoints: self.endpoints.iter().map(|e| e.ep.clone()).collect(),
            credentials: self
                .vault
                .slots
                .iter()
                .map(|s| SidecarCredential {
                    name: s.name.clone(),
                    placeholder_env: s.placeholder_env.clone(),
                    inject: s.inject_src.clone(),
                    placeholder: s.placeholder.clone(),
                    value: SecretText::new(
                        s.secret
                            .as_ref()
                            .map(|v| v.expose().to_string())
                            .unwrap_or_default(),
                    ),
                })
                .collect(),
            ca: SidecarCa {
                cert_pem: self.ca.cert_pem().to_string(),
                key_pem: SecretText::new(self.ca.key_pem().as_str()),
            },
            upstream_ca_pem: self.upstream_ca_pem.clone(),
        }
    }

    /// Rebuilds a broker from a [`BrokerConfig`], keeping its placeholders
    /// and CA. Fails closed on any inconsistency (missing secret, foreign
    /// CA key, malformed placeholder).
    pub fn from_sidecar_config(cfg: &BrokerConfig) -> Result<Self, BrokerError> {
        if cfg.schema != BROKER_CONFIG_SCHEMA {
            return Err(BrokerError::Config(format!(
                "schema must be {BROKER_CONFIG_SCHEMA:?}, got {:?}",
                cfg.schema
            )));
        }
        let ca = SandboxCa::from_pem(&cfg.sandbox_id, &cfg.ca.cert_pem, cfg.ca.key_pem.expose())?;
        let mut values = HashMap::new();
        let mut placeholders = HashMap::new();
        let mut credentials = Vec::with_capacity(cfg.credentials.len());
        for c in &cfg.credentials {
            if !c.value.is_empty() {
                values.insert(c.name.clone(), c.value.expose().to_string());
            }
            placeholders.insert(c.name.clone(), c.placeholder.clone());
            credentials.push(Credential {
                name: c.name.clone(),
                source: String::new(),
                placeholder_env: c.placeholder_env.clone(),
                inject: c.inject.clone(),
            });
        }
        let b = Self::assemble(
            &cfg.sandbox_id,
            cfg.endpoints.clone(),
            credentials,
            values,
            &placeholders,
            ca,
        )?;
        b.with_upstream_roots_pem(&cfg.upstream_ca_pem)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn broker() -> Broker {
        let creds = vec![
            Credential {
                name: "gh".into(),
                source: "env://GH".into(),
                placeholder_env: "GITHUB_TOKEN".into(),
                inject: "header:X-Api-Key".into(),
            },
            Credential {
                name: "idle".into(),
                ..Credential::default()
            },
        ];
        let ep = Endpoint {
            name: "gh-api".into(),
            host: "api.example.test".into(),
            protocol: "rest".into(),
            credential: "gh".into(),
            ..Endpoint::default()
        };
        Broker::with_secret_values(
            "0123456789abcdef0123456789abcdef",
            vec![ep],
            creds,
            HashMap::from([("gh".to_string(), "s3cr3t-value".to_string())]),
        )
        .expect("broker")
    }

    #[test]
    fn round_trips_placeholders_secrets_and_ca() {
        let b = broker();
        let cfg = b.sidecar_config();
        assert_eq!(cfg.schema, BROKER_CONFIG_SCHEMA);
        let json = cfg.to_json();
        let back = BrokerConfig::from_json(&json).expect("parse");
        assert_eq!(back, cfg);
        // Debug output never carries the secret or the key.
        let dbg = format!("{back:?}");
        assert!(!dbg.contains("s3cr3t") && !dbg.contains("PRIVATE"), "{dbg}");

        let side = Broker::from_sidecar_config(&back).expect("rebuild");
        assert_eq!(side.placeholder_env(), b.placeholder_env());
        assert_eq!(side.placeholders(), b.placeholders());
        assert_eq!(side.ca_cert_pem(), b.ca_cert_pem());
        assert_eq!(side.sandbox_id(), b.sandbox_id());
        assert_eq!(
            side.endpoint_for("api.example.test", 443),
            Some("gh-api"),
            "endpoints survive"
        );
        assert_eq!(side.scrub("x s3cr3t-value y"), "x «redacted» y");
    }

    #[test]
    fn rejects_bad_documents() {
        assert!(BrokerConfig::from_json(b"{}").is_ok_and(|c| c.schema == BROKER_CONFIG_SCHEMA));
        assert!(BrokerConfig::from_json(br#"{"schema":"other"}"#).is_err());
        assert!(BrokerConfig::from_json(br#"{"bogus":1}"#).is_err());

        let b = broker();
        let mut cfg = b.sidecar_config();
        cfg.credentials[0].placeholder = "guessable".into();
        assert!(matches!(
            Broker::from_sidecar_config(&cfg),
            Err(BrokerError::Placeholder(_))
        ));
        let mut cfg = b.sidecar_config();
        cfg.credentials[0].value = SecretText::default();
        assert!(matches!(
            Broker::from_sidecar_config(&cfg),
            Err(BrokerError::MissingSecret(_))
        ));
        let mut cfg = b.sidecar_config();
        cfg.ca.key_pem = broker().sidecar_config().ca.key_pem.clone();
        assert!(matches!(
            Broker::from_sidecar_config(&cfg),
            Err(BrokerError::Ca(_))
        ));
    }

    #[test]
    fn decision_lines_round_trip_and_ignore_noise() {
        let d = Decision {
            host: "api.example.test".into(),
            allow: false,
            reason: "denied".into(),
            endpoint: Some("gh-api".into()),
            verdict: Some(crate::Verdict::Deny),
            reason_code: Some(crate::ReasonCode::PlaceholderMisuse),
            ..Decision::default()
        };
        let line = DecisionLine::new("sb", &d).to_line();
        let back = DecisionLine::parse(&line).expect("line");
        assert_eq!(back.sandbox_id, "sb");
        let got = back.decision;
        assert_eq!(got.host, d.host);
        assert_eq!(got.reason_code, d.reason_code);
        assert_eq!(got.endpoint, d.endpoint);
        assert!(DecisionLine::parse("egress: ALLOW CONNECT x").is_none());
        assert!(DecisionLine::parse(r#"{"schema":"x","sandbox_id":"","decision":{}}"#).is_none());
    }

    #[test]
    fn extra_upstream_roots() {
        let ca = SandboxCa::generate("roots").expect("ca");
        assert!(super::super::upstream_tls_with_roots(ca.cert_pem()).is_ok());
        assert!(super::super::upstream_tls_with_roots("nope").is_err());
        let b = broker()
            .with_upstream_roots_pem(ca.cert_pem())
            .expect("roots");
        assert_eq!(b.sidecar_config().upstream_ca_pem, ca.cert_pem());
    }
}
