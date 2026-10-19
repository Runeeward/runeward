//! Hardened mode: refuse to start unless every production safeguard is on.
//!
//! `RUNEWARD_HARDENED=1` (or `hardened = true` in the server or MCP HTTP
//! config) makes `runeward serve`, `runeward mcp --http` and the control
//! plane check, before binding anything, that ALL of these hold:
//!
//! | rule             | requirement                                                        |
//! |------------------|--------------------------------------------------------------------|
//! | `tls`            | TLS on every non-loopback listener (no `--allow-insecure-http`)    |
//! | `auth`           | per-principal auth (authz file or OIDC), no shared static token    |
//! | `signed-charters`| `RUNEWARD_REQUIRE_SIGNED_PROFILES` on, with a verify key           |
//! | `ledger-signing` | Chronicle signing on (`RUNEWARD_LEDGER_SIGN` not `off`)            |
//! | `isolation`      | every Charter's floor ≥ kernel, or the tier it runs on ≥ kernel    |
//! | `egress`         | every Charter's `[network] default = "deny"`                       |
//! | `image-digest`   | every Charter's `host.image` pinned as `name@sha256:<64 hex>`      |
//! | `rate-limit`     | per-principal rate limiting on (`RUNEWARD_PRINCIPAL_RATE_LIMIT`)   |
//! | `seccomp`        | no Charter sets `host.seccomp = "unconfined"`                      |
//! | `charter`        | every resolvable Charter loads (and verifies)                      |
//!
//! [`check`] is the pure rule set; [`Manager::check_hardened`] loads every
//! resolvable Charter and asks the backends for their default tier first.
//! Every violation is reported, not just the first.

use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

use runeward_backend::{IsolationTier, classify_runtime};
use runeward_charter::{Charter, IsolationLevel, SignedCharters};

use crate::config::ManagerConfig;
use crate::manager::{Manager, blocking};

/// `1`/`true`/`yes`/`on` turns hardened mode on.
pub const HARDENED_ENV: &str = "RUNEWARD_HARDENED";

/// How long a backend may take to report its default tier.
const BACKEND_PROBE_TIMEOUT: Duration = Duration::from_secs(15);

/// Whether [`HARDENED_ENV`] asks for hardened mode.
pub fn hardened_from_env() -> bool {
    hardened_from_lookup(|k| std::env::var(k).ok())
}

/// [`hardened_from_env`] through an explicit lookup.
pub fn hardened_from_lookup(lookup: impl Fn(&str) -> Option<String>) -> bool {
    lookup(HARDENED_ENV).is_some_and(|v| {
        matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        )
    })
}

/// One network listener the process is about to open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listener {
    /// What it serves (`rest`, `mcp`).
    pub name: String,
    /// Bind host.
    pub bind: String,
    /// Whether it terminates TLS itself.
    pub tls: bool,
}

/// What the transport knows about itself, for [`check`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ServerChecks {
    /// Every listener about to be opened.
    pub listeners: Vec<Listener>,
    /// An authz store (principal file or OIDC) authenticates callers.
    pub per_principal_auth: bool,
    /// A shared static token (`--token` / `RUNEWARD_API_TOKEN`) is set.
    pub shared_token: bool,
    /// Per-principal rate limiting is on.
    pub principal_rate_limit: bool,
    /// The tier each backend (by `host.type`) gives a sandbox that does not
    /// request a runtime. Missing entries are unknown.
    pub backend_tiers: BTreeMap<String, IsolationTier>,
}

/// A hardened-mode rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Rule {
    Tls,
    Auth,
    SignedCharters,
    LedgerSigning,
    Isolation,
    Egress,
    ImageDigest,
    RateLimit,
    Seccomp,
    Charter,
}

impl Rule {
    /// The rule's short name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tls => "tls",
            Self::Auth => "auth",
            Self::SignedCharters => "signed-charters",
            Self::LedgerSigning => "ledger-signing",
            Self::Isolation => "isolation",
            Self::Egress => "egress",
            Self::ImageDigest => "image-digest",
            Self::RateLimit => "rate-limit",
            Self::Seccomp => "seccomp",
            Self::Charter => "charter",
        }
    }
}

/// One failed requirement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    pub rule: Rule,
    /// What failed: a listener, a Charter name, or `server`.
    pub subject: String,
    /// What to change.
    pub message: String,
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "hardened: [{}] {}: {}",
            self.rule.as_str(),
            self.subject,
            self.message
        )
    }
}

fn v(rule: Rule, subject: impl Into<String>, message: impl Into<String>) -> Violation {
    Violation {
        rule,
        subject: subject.into(),
        message: message.into(),
    }
}

/// Whether `host` is a loopback interface (empty means all interfaces).
fn is_loopback(host: &str) -> bool {
    let h = host.trim_start_matches('[').trim_end_matches(']');
    match h {
        "localhost" => true,
        "" => false,
        h => h
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback()),
    }
}

/// Whether `image` is pinned to a content digest (`name@sha256:<64 hex>`).
pub fn image_pinned(image: &str) -> bool {
    let Some((name, digest)) = image.rsplit_once("@sha256:") else {
        return false;
    };
    !name.is_empty()
        && digest.len() == 64
        && digest
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn tier_of(level: IsolationLevel) -> IsolationTier {
    match level {
        IsolationLevel::Process => IsolationTier::Process,
        IsolationLevel::Container => IsolationTier::Container,
        IsolationLevel::Kernel => IsolationTier::Kernel,
        IsolationLevel::Vm => IsolationTier::Vm,
    }
}

/// The tier a Charter's sandbox runs on without a floor: its requested
/// runtime when set, else its backend's default, else unknown.
fn runtime_tier(c: &Charter, server: &ServerChecks) -> Option<IsolationTier> {
    if !c.host.runtime_class.trim().is_empty() {
        return Some(classify_runtime(&c.host.runtime_class));
    }
    server.backend_tiers.get(c.host.host_type.as_str()).copied()
}

fn floor_proves_kernel(c: &Charter) -> bool {
    c.isolation
        .minimum_level()
        .is_some_and(|l| tier_of(l) >= IsolationTier::Kernel)
}

/// Checks every hardened-mode rule. `charters` are all Charters the
/// process may launch. Returns every violation, sorted by rule.
pub fn check(
    cfg: &ManagerConfig,
    charters: &[Charter],
    server: &ServerChecks,
) -> Result<(), Vec<Violation>> {
    let mut out = Vec::new();

    for l in &server.listeners {
        if !l.tls && !is_loopback(&l.bind) {
            out.push(v(
                Rule::Tls,
                format!("{} listener {}", l.name, l.bind),
                "serves plaintext on a non-loopback address; configure --tls-cert/--tls-key (--allow-insecure-http is not allowed)",
            ));
        }
    }
    if !server.per_principal_auth {
        out.push(v(
            Rule::Auth,
            "server",
            format!(
                "no per-principal authentication; configure {} (static principals or OIDC)",
                runeward_authz_env()
            ),
        ));
    }
    if server.shared_token {
        out.push(v(
            Rule::Auth,
            "server",
            "a shared static API token is set (--token / RUNEWARD_API_TOKEN); remove it and authenticate principals instead",
        ));
    }
    if !server.principal_rate_limit {
        out.push(v(
            Rule::RateLimit,
            "server",
            format!(
                "per-principal rate limiting is off; set {}",
                crate::principal_limit::PRINCIPAL_RATE_LIMIT_ENV
            ),
        ));
    }

    let signed = match &cfg.signed_charters {
        SignedCharters::FromEnv => SignedCharters::from_lookup(|k| std::env::var(k).ok()),
        other => other.clone(),
    };
    match signed {
        SignedCharters::Required { verify_key } if !verify_key.trim().is_empty() => {}
        SignedCharters::Required { .. } => out.push(v(
            Rule::SignedCharters,
            "server",
            format!(
                "signed Charters are required but no verify key is configured; set {}",
                runeward_charter::VERIFY_KEY_ENV
            ),
        )),
        _ => out.push(v(
            Rule::SignedCharters,
            "server",
            format!(
                "unsigned Charters are accepted; set {}=1 and {}",
                runeward_charter::REQUIRE_SIGNED_ENV,
                runeward_charter::VERIFY_KEY_ENV
            ),
        )),
    }
    if !cfg.sign_ledger {
        out.push(v(
            Rule::LedgerSigning,
            "server",
            format!(
                "Chronicle signing is off; unset {}",
                crate::config::LEDGER_SIGN_ENV
            ),
        ));
    }

    for c in charters {
        let name = if c.name.is_empty() {
            "<unnamed>"
        } else {
            &c.name
        };
        if !floor_proves_kernel(c) {
            match runtime_tier(c, server) {
                Some(t) if t >= IsolationTier::Kernel => {}
                Some(t) => out.push(v(
                    Rule::Isolation,
                    name,
                    format!(
                        "runs on a {t} boundary; set [isolation] minimum = \"kernel\" (or \"vm\") or a kernel-grade host.runtime_class"
                    ),
                )),
                None => out.push(v(
                    Rule::Isolation,
                    name,
                    "the isolation tier cannot be proven; set [isolation] minimum = \"kernel\" (or \"vm\")",
                )),
            }
        }
        if !c.network.deny_by_default() {
            out.push(v(
                Rule::Egress,
                name,
                "egress is open by default; set [network] default = \"deny\"",
            ));
        }
        if !image_pinned(&c.host.image) {
            out.push(v(
                Rule::ImageDigest,
                name,
                format!(
                    "host.image {:?} is not pinned; use name@sha256:<digest>",
                    c.host.image
                ),
            ));
        }
        if c.host.seccomp.trim().eq_ignore_ascii_case("unconfined") {
            out.push(v(
                Rule::Seccomp,
                name,
                "host.seccomp = \"unconfined\" disables syscall filtering",
            ));
        }
    }

    if out.is_empty() {
        Ok(())
    } else {
        out.sort_by_key(|v| v.rule);
        Err(out)
    }
}

fn runeward_authz_env() -> &'static str {
    "RUNEWARD_AUTHZ_FILE"
}

impl Manager {
    /// Hardened-mode check against every resolvable Charter. Charters that
    /// fail to load (or verify) are violations. Backend default tiers not
    /// supplied in `server` are probed for Charters whose floor and runtime
    /// do not settle the isolation rule.
    pub async fn check_hardened(&self, server: &ServerChecks) -> Result<(), Vec<Violation>> {
        let opts = self.config.charter_options();
        let loaded = blocking(move || {
            let mut ok = Vec::new();
            let mut bad = Vec::new();
            for name in runeward_charter::list(&opts) {
                match runeward_charter::load(&name, &opts) {
                    Ok(c) => ok.push(c),
                    Err(e) => bad.push(v(Rule::Charter, name, format!("does not load: {e}"))),
                }
            }
            Ok((ok, bad))
        })
        .await;
        let (charters, mut violations) = match loaded {
            Ok(x) => x,
            Err(e) => (
                Vec::new(),
                vec![v(Rule::Charter, "server", format!("listing Charters: {e}"))],
            ),
        };

        let mut server = server.clone();
        for c in &charters {
            let host_type = c.host.host_type.as_str().to_owned();
            if floor_proves_kernel(c)
                || !c.host.runtime_class.trim().is_empty()
                || server.backend_tiers.contains_key(&host_type)
            {
                continue;
            }
            let opened = tokio::time::timeout(
                BACKEND_PROBE_TIMEOUT,
                self.registry.open(c, &self.backend_config),
            )
            .await;
            if let Ok(Ok(be)) = opened {
                server.backend_tiers.insert(host_type, be.isolation_tier());
            }
        }

        if let Err(mut more) = check(&self.config, &charters, &server) {
            violations.append(&mut more);
        }
        if violations.is_empty() {
            Ok(())
        } else {
            violations.sort_by_key(|v| v.rule);
            Err(violations)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn good_cfg() -> ManagerConfig {
        ManagerConfig {
            sign_ledger: true,
            signed_charters: SignedCharters::Required {
                verify_key: "key".into(),
            },
            ..ManagerConfig::default()
        }
    }

    fn good_server() -> ServerChecks {
        ServerChecks {
            listeners: vec![
                Listener {
                    name: "rest".into(),
                    bind: "0.0.0.0".into(),
                    tls: true,
                },
                Listener {
                    name: "mcp".into(),
                    bind: "127.0.0.1".into(),
                    tls: false,
                },
            ],
            per_principal_auth: true,
            shared_token: false,
            principal_rate_limit: true,
            backend_tiers: BTreeMap::new(),
        }
    }

    fn good_charter(name: &str) -> Charter {
        let mut c = Charter {
            name: name.into(),
            ..Charter::default()
        };
        c.host.image = format!("ghcr.io/acme/agent@sha256:{DIGEST}");
        c.isolation.minimum = "kernel".into();
        c.network.default = "deny".into();
        c
    }

    fn rules(r: Result<(), Vec<Violation>>) -> Vec<(Rule, String)> {
        r.err()
            .unwrap_or_default()
            .into_iter()
            .map(|v| (v.rule, v.subject))
            .collect()
    }

    #[test]
    fn a_fully_hardened_setup_passes() {
        check(&good_cfg(), &[good_charter("a")], &good_server()).expect("hardened");
    }

    #[test]
    fn env_flag() {
        assert!(hardened_from_lookup(|_| Some(" ON ".into())));
        assert!(hardened_from_lookup(|_| Some("1".into())));
        assert!(!hardened_from_lookup(|_| Some("0".into())));
        assert!(!hardened_from_lookup(|_| None));
    }

    #[test]
    fn tls_on_every_non_loopback_listener() {
        let mut s = good_server();
        s.listeners[0].tls = false;
        s.listeners.push(Listener {
            name: "mcp".into(),
            bind: "::1".into(),
            tls: false,
        });
        s.listeners.push(Listener {
            name: "mcp".into(),
            bind: "".into(),
            tls: false,
        });
        let got = rules(check(&good_cfg(), &[], &s));
        assert_eq!(
            got,
            vec![
                (Rule::Tls, "rest listener 0.0.0.0".to_string()),
                (Rule::Tls, "mcp listener ".to_string()),
            ]
        );
    }

    #[test]
    fn per_principal_auth_and_no_shared_token() {
        let mut s = good_server();
        s.per_principal_auth = false;
        assert_eq!(
            rules(check(&good_cfg(), &[], &s)),
            vec![(Rule::Auth, "server".to_string())]
        );
        let mut s = good_server();
        s.shared_token = true;
        let err = check(&good_cfg(), &[], &s).expect_err("shared token");
        assert_eq!(err.len(), 1);
        assert!(
            err[0].message.contains("shared static API token"),
            "{}",
            err[0]
        );
    }

    #[test]
    fn signed_charters_required_with_a_key() {
        let mut cfg = good_cfg();
        cfg.signed_charters = SignedCharters::Disabled;
        assert_eq!(
            rules(check(&cfg, &[], &good_server())),
            vec![(Rule::SignedCharters, "server".to_string())]
        );
        cfg.signed_charters = SignedCharters::Required {
            verify_key: " ".into(),
        };
        let err = check(&cfg, &[], &good_server()).expect_err("no key");
        assert!(err[0].message.contains("verify key"), "{}", err[0]);
    }

    #[test]
    fn ledger_signing_on() {
        let mut cfg = good_cfg();
        cfg.sign_ledger = false;
        assert_eq!(
            rules(check(&cfg, &[], &good_server())),
            vec![(Rule::LedgerSigning, "server".to_string())]
        );
    }

    #[test]
    fn isolation_floor_or_tier_at_least_kernel() {
        let s = good_server();
        let mut weak = good_charter("weak");
        weak.isolation.minimum = "container".into();
        let mut unset = good_charter("unset");
        unset.isolation.minimum.clear();
        let mut gvisor = good_charter("gvisor");
        gvisor.isolation.minimum.clear();
        gvisor.host.runtime_class = "runsc".into();
        let mut vm = good_charter("vm");
        vm.isolation.minimum = "vm".into();
        let got = rules(check(
            &good_cfg(),
            &[weak.clone(), unset.clone(), gvisor, vm],
            &s,
        ));
        assert_eq!(
            got,
            vec![
                (Rule::Isolation, "weak".to_string()),
                (Rule::Isolation, "unset".to_string()),
            ]
        );

        // A backend whose default tier is kernel-grade satisfies the rule
        // for Charters without a floor; a container default does not.
        let mut s = good_server();
        s.backend_tiers
            .insert(unset.host.host_type.as_str().into(), IsolationTier::Kernel);
        check(&good_cfg(), &[unset.clone(), weak.clone()], &s).expect("kernel default");
        s.backend_tiers.insert(
            unset.host.host_type.as_str().into(),
            IsolationTier::Container,
        );
        let err = check(&good_cfg(), &[unset], &s).expect_err("container default");
        assert!(err[0].message.contains("container"), "{}", err[0]);
    }

    #[test]
    fn egress_default_deny() {
        let mut c = good_charter("open");
        c.network.default = "allow".into();
        assert_eq!(
            rules(check(&good_cfg(), &[c], &good_server())),
            vec![(Rule::Egress, "open".to_string())]
        );
    }

    #[test]
    fn images_pinned_by_digest() {
        assert!(image_pinned(&format!("alpine@sha256:{DIGEST}")));
        assert!(image_pinned(&format!(
            "registry:5000/a/b:1.2@sha256:{DIGEST}"
        )));
        assert!(!image_pinned("alpine:3.20"));
        assert!(!image_pinned("alpine"));
        assert!(!image_pinned(""));
        assert!(!image_pinned(&format!("@sha256:{DIGEST}")));
        assert!(!image_pinned("alpine@sha256:abc"));
        assert!(!image_pinned(&format!(
            "alpine@sha256:{}",
            DIGEST.to_uppercase()
        )));
        let mut c = good_charter("tagged");
        c.host.image = "alpine:3.20".into();
        assert_eq!(
            rules(check(&good_cfg(), &[c], &good_server())),
            vec![(Rule::ImageDigest, "tagged".to_string())]
        );
    }

    #[test]
    fn principal_rate_limit_on() {
        let mut s = good_server();
        s.principal_rate_limit = false;
        assert_eq!(
            rules(check(&good_cfg(), &[], &s)),
            vec![(Rule::RateLimit, "server".to_string())]
        );
    }

    #[test]
    fn no_unconfined_seccomp() {
        let mut c = good_charter("loose");
        c.host.seccomp = "Unconfined".into();
        assert_eq!(
            rules(check(&good_cfg(), &[c], &good_server())),
            vec![(Rule::Seccomp, "loose".to_string())]
        );
        let mut c = good_charter("profile");
        c.host.seccomp = "/etc/seccomp.json".into();
        check(&good_cfg(), &[c], &good_server()).expect("a profile is fine");
    }

    #[test]
    fn every_violation_is_reported_in_rule_order() {
        let cfg = ManagerConfig {
            sign_ledger: false,
            signed_charters: SignedCharters::Disabled,
            ..ManagerConfig::default()
        };
        let s = ServerChecks {
            listeners: vec![Listener {
                name: "rest".into(),
                bind: "0.0.0.0".into(),
                tls: false,
            }],
            shared_token: true,
            ..ServerChecks::default()
        };
        let mut c = Charter {
            name: "bad".into(),
            ..Charter::default()
        };
        c.host.seccomp = "unconfined".into();
        let err = check(&cfg, &[c], &s).expect_err("everything wrong");
        let got: Vec<Rule> = err.iter().map(|v| v.rule).collect();
        assert_eq!(
            got,
            vec![
                Rule::Tls,
                Rule::Auth,
                Rule::Auth,
                Rule::SignedCharters,
                Rule::LedgerSigning,
                Rule::Isolation,
                Rule::Egress,
                Rule::ImageDigest,
                Rule::RateLimit,
                Rule::Seccomp,
            ]
        );
        assert!(
            err[0]
                .to_string()
                .starts_with("hardened: [tls] rest listener 0.0.0.0: ")
        );
    }
}
