//! Hard cross-field invariants checked after parsing.
//!
//! Validation rejects a Charter outright; the softer "probably not what you
//! meant" checks live in [`crate::lint`].

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

use crate::STRICT_PROXY_UID;
use crate::schema::{Charter, HostType};

/// A Charter violates a hard invariant.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ValidationError {
    #[error("unsupported host.type {0:?} (want \"container\" or \"k8s\")")]
    UnsupportedHostType(String),
    #[error("network.default must be \"allow\" or \"deny\", got {0:?}")]
    NetworkDefault(String),
    #[error("host.user uid {STRICT_PROXY_UID} is reserved for strict egress interception")]
    ReservedUid,
    #[error("env[{0}]: missing name")]
    EnvMissingName(usize),
    #[error("env[{index}] ({name}): set only one of value/file/op")]
    EnvMultipleSources { index: usize, name: String },
    #[error("policy[{index}]: invalid verdict {verdict:?}")]
    PolicyVerdict { index: usize, verdict: String },
    #[error("policy_engine must be \"builtin\", \"cel\", or \"rego\", got {0:?}")]
    PolicyEngine(String),
    #[error("rego: set exactly one of module/file")]
    RegoSource,
    #[error("cel[{index}]: invalid verdict {verdict:?}")]
    CelVerdict { index: usize, verdict: String },
    #[error("policy_bundle.verify_key: not valid base64: {0}")]
    BundleKeyBase64(String),
    #[error("policy_bundle.verify_key: wrong ed25519 public key size {0} (want 32)")]
    BundleKeySize(usize),
    #[error("{0}")]
    Governance(String),
    #[error("fleet.replicas must be >= 0")]
    FleetReplicas,
    #[error("ide.port must be between 1 and 65535, got {0}")]
    IdePort(i64),
}

impl Charter {
    /// Fills the loader defaults (host type, workdir and image) for fields the
    /// author left empty.
    pub fn apply_defaults(&mut self) {
        if self.host.host_type == HostType::Unset {
            self.host.host_type = HostType::Container;
        }
        if self.host.workdir.is_empty() {
            self.host.workdir = "/workspace".to_owned();
        }
        if self.host.image.is_empty() {
            self.host.image = "ghcr.io/runewardd/runeward-sandbox:latest".to_owned();
        }
    }

    /// Checks cross-field invariants. Like the Go loader it also fills the IDE
    /// port and path defaults when the IDE is enabled, hence `&mut self`.
    pub fn validate(&mut self) -> Result<(), ValidationError> {
        if !matches!(self.host.host_type, HostType::Container | HostType::K8s) {
            return Err(ValidationError::UnsupportedHostType(
                self.host.host_type.as_str().to_owned(),
            ));
        }
        let default = self.network.default.as_str();
        if !matches!(default, "" | "allow" | "deny") {
            return Err(ValidationError::NetworkDefault(default.to_owned()));
        }
        if self.network.strict_egress()
            && numeric_uid(&self.host.user) == Some(STRICT_PROXY_UID.into())
        {
            return Err(ValidationError::ReservedUid);
        }
        for (index, e) in self.env.iter().enumerate() {
            if e.name.is_empty() {
                return Err(ValidationError::EnvMissingName(index));
            }
            let set = [&e.value, &e.file, &e.op]
                .iter()
                .filter(|v| !v.is_empty())
                .count();
            if set > 1 {
                return Err(ValidationError::EnvMultipleSources {
                    index,
                    name: e.name.clone(),
                });
            }
        }
        for (index, r) in self.policy.iter().enumerate() {
            if !r.verdict.is_valid() {
                return Err(ValidationError::PolicyVerdict {
                    index,
                    verdict: r.verdict.as_str().to_owned(),
                });
            }
        }
        if !matches!(self.policy_engine.as_str(), "" | "builtin" | "cel" | "rego") {
            return Err(ValidationError::PolicyEngine(self.policy_engine.clone()));
        }
        if self.uses_rego() && self.rego.module.is_empty() == self.rego.file.is_empty() {
            return Err(ValidationError::RegoSource);
        }
        for (index, r) in self.cel.iter().enumerate() {
            if !(r.verdict.is_valid() || r.verdict.as_str().is_empty()) {
                return Err(ValidationError::CelVerdict {
                    index,
                    verdict: r.verdict.as_str().to_owned(),
                });
            }
        }
        if let Some(bundle) = self.policy_bundle.as_ref().filter(|b| !b.r#ref.is_empty())
            && !bundle.verify_key.is_empty()
        {
            let raw = STANDARD
                .decode(&bundle.verify_key)
                .map_err(|e| ValidationError::BundleKeyBase64(e.to_string()))?;
            if raw.len() != runeward_keys::PUBLIC_KEY_LEN {
                return Err(ValidationError::BundleKeySize(raw.len()));
            }
        }
        if self.fleet.as_ref().is_some_and(|f| f.replicas < 0) {
            return Err(ValidationError::FleetReplicas);
        }
        if self.ide.enabled {
            if self.ide.port == 0 {
                self.ide.port = 8080;
            }
            if !(1..=65535).contains(&self.ide.port) {
                return Err(ValidationError::IdePort(self.ide.port));
            }
            if self.ide.path.trim().is_empty() {
                self.ide.path = "/".to_owned();
            }
        }
        crate::governance::validate(
            &self.isolation,
            self.filesystem.as_ref(),
            self.process.as_ref(),
            &self.credentials,
            &self.endpoints,
        )
        .map_err(ValidationError::Governance)?;
        Ok(())
    }
}

/// Parses the numeric uid from a `uid` or `uid:gid` user spec; names and
/// out-of-range numbers yield `None`.
pub(crate) fn numeric_uid(user: &str) -> Option<i64> {
    let u = user.trim();
    let u = u.split_once(':').map_or(u, |(uid, _)| uid);
    if u.is_empty() || !u.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    u.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{Host, Network};

    #[test]
    fn rejects_strict_egress_proxy_uid() {
        let mut p = Charter {
            host: Host {
                host_type: HostType::Container,
                image: "img".into(),
                user: "1337".into(),
                ..Host::default()
            },
            network: Network {
                default: "deny".into(),
                enforce: "strict".into(),
                ..Network::default()
            },
            ..Charter::default()
        };
        assert_eq!(p.validate(), Err(ValidationError::ReservedUid));
        p.host.user = "1337:1337".into();
        assert!(p.validate().is_err());
        p.network.enforce.clear();
        assert!(p.validate().is_ok());
    }

    #[test]
    fn numeric_uid_matches_go() {
        assert_eq!(numeric_uid(" 1000:1000 "), Some(1000));
        assert_eq!(numeric_uid("0"), Some(0));
        assert_eq!(numeric_uid("root"), None);
        assert_eq!(numeric_uid(":1"), None);
        assert_eq!(numeric_uid("-1"), None);
        assert_eq!(numeric_uid("99999999999999999999"), None);
    }

    #[test]
    fn ide_defaults_and_bounds() {
        let mut p = Charter::default();
        p.apply_defaults();
        p.ide.enabled = true;
        p.validate().expect("valid");
        assert_eq!((p.ide.port, p.ide.path.as_str()), (8080, "/"));
        p.ide.port = 70000;
        assert_eq!(p.validate(), Err(ValidationError::IdePort(70000)));
    }

    #[test]
    fn messages_match_go() {
        let mut p = Charter::default();
        p.apply_defaults();
        p.host.host_type = HostType::parse("vm");
        assert_eq!(
            p.validate().expect_err("must fail").to_string(),
            r#"unsupported host.type "vm" (want "container" or "k8s")"#
        );
        p.host.host_type = HostType::K8s;
        p.policy_engine = "rego".into();
        assert_eq!(
            p.validate().expect_err("must fail").to_string(),
            "rego: set exactly one of module/file"
        );
        p.policy_engine = "opa".into();
        assert_eq!(
            p.validate().expect_err("must fail").to_string(),
            r#"policy_engine must be "builtin", "cel", or "rego", got "opa""#
        );
    }
}
