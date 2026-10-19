//! Egress policy: an ordered allow/deny rule list with a default verdict.

use std::path::Path;

use serde::{Deserialize, Deserializer, Serialize};

use crate::netutil::{net_contains, parse_ip, split_host_port};

/// A single allow/deny entry in a [`Policy`]. Set exactly one of `hostname`
/// or `cidr`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    /// `"allow"` or `"deny"`; anything but `"allow"` denies.
    #[serde(default, alias = "Verdict", deserialize_with = "nullable")]
    pub verdict: String,
    /// Matches exactly or by a leading `*.` wildcard.
    #[serde(default, alias = "Hostname", deserialize_with = "nullable")]
    pub hostname: String,
    /// Matches a destination IP (e.g. `10.0.0.0/8`).
    #[serde(default, alias = "CIDR", alias = "Cidr", deserialize_with = "nullable")]
    pub cidr: String,
}

/// An ordered list of [`Rule`]s; the first match wins, otherwise `default`
/// applies.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy {
    /// `"allow"` or `"deny"`; empty means `"allow"`.
    #[serde(default, alias = "Default", deserialize_with = "nullable")]
    pub default: String,
    /// Rules evaluated in order.
    #[serde(default, alias = "Rules", deserialize_with = "nullable")]
    pub rules: Vec<Rule>,
}

/// Treats JSON `null` as the zero value, as Go's decoder does.
fn nullable<'de, D, T>(d: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Default + Deserialize<'de>,
{
    Ok(Option::<T>::deserialize(d)?.unwrap_or_default())
}

/// Errors from [`load_policy`].
#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    /// The policy file could not be read.
    #[error("read policy: {0}")]
    Io(#[from] std::io::Error),
    /// The policy is not valid JSON for a [`Policy`].
    #[error("decode policy: {0}")]
    Json(#[from] serde_json::Error),
}

/// Whether a verdict permits the connection. Only `"allow"`
/// (case-insensitive, surrounding whitespace ignored) permits.
fn verdict_allows(verdict: &str) -> bool {
    verdict.trim().eq_ignore_ascii_case("allow")
}

/// Whether `pattern` matches `host`, case-insensitively. A `*.` pattern
/// matches subdomains at any depth but not the bare domain; anything else
/// matches by equality.
pub(crate) fn hostname_matches(pattern: &str, host: &str) -> bool {
    let pattern = pattern.trim().to_lowercase();
    let host = host.trim().to_lowercase();
    if pattern.is_empty() {
        return false;
    }
    if let Some(suffix) = pattern.strip_prefix("*.") {
        // Require a label before the suffix so the bare domain doesn't match.
        return host.ends_with(&format!(".{suffix}")) && host.len() > suffix.len() + 1;
    }
    pattern == host
}

impl Policy {
    /// The fallback when no rule matches; empty means allow.
    fn default_allows(&self) -> bool {
        if self.default.trim().is_empty() {
            return true;
        }
        verdict_allows(&self.default)
    }

    /// The verdict of the first hostname rule matching `host`, if any.
    fn first_hostname_verdict(&self, host: &str) -> Option<bool> {
        let host = host.trim().to_lowercase();
        self.rules
            .iter()
            .filter(|r| !r.hostname.is_empty())
            .find(|r| hostname_matches(&r.hostname, &host))
            .map(|r| verdict_allows(&r.verdict))
    }

    /// Whether `host` is permitted. Only hostname rules are considered; the
    /// first match decides, otherwise `default` applies.
    pub fn allow(&self, host: &str) -> bool {
        self.first_hostname_verdict(host)
            .unwrap_or_else(|| self.default_allows())
    }

    /// Whether `host` matches an explicit hostname rule whose first matching
    /// verdict is allow. Unlike [`Policy::allow`], it does not fall back to
    /// the policy default.
    pub fn allow_listed_hostname(&self, host: &str) -> bool {
        self.first_hostname_verdict(host).unwrap_or(false)
    }

    /// Whether the destination `host:port` is permitted. The host is checked
    /// against hostname rules, and against CIDR rules when it parses as an
    /// IP; the first match decides, otherwise `default` applies.
    pub fn allow_addr(&self, hostport: &str) -> bool {
        let host = match split_host_port(hostport) {
            Ok((h, _)) => h,
            // No port; treat the whole value as the host.
            Err(_) => hostport.to_string(),
        };
        let host = host.trim().to_lowercase();
        let ip = parse_ip(&host);

        for r in &self.rules {
            if !r.hostname.is_empty() && hostname_matches(&r.hostname, &host) {
                return verdict_allows(&r.verdict);
            }
            if let Some(ip) = ip
                && !r.cidr.is_empty()
                && let Ok(net) = r.cidr.parse::<ipnet::IpNet>()
                && net_contains(&net, ip)
            {
                return verdict_allows(&r.verdict);
            }
        }
        self.default_allows()
    }

    /// Decodes a policy from JSON text.
    pub fn from_json(raw: &str) -> Result<Self, PolicyError> {
        Ok(serde_json::from_str(raw)?)
    }
}

/// Reads and decodes a JSON [`Policy`] from the file at `path`.
pub fn load_policy(path: impl AsRef<Path>) -> Result<Policy, PolicyError> {
    let data = std::fs::read_to_string(path)?;
    Policy::from_json(&data)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(verdict: &str, hostname: &str, cidr: &str) -> Rule {
        Rule {
            verdict: verdict.into(),
            hostname: hostname.into(),
            cidr: cidr.into(),
        }
    }

    fn policy(default: &str, rules: Vec<Rule>) -> Policy {
        Policy {
            default: default.into(),
            rules,
        }
    }

    #[test]
    fn allow_exact_match() {
        let p = policy("deny", vec![rule("allow", "example.com", "")]);
        assert!(p.allow("example.com"));
        assert!(p.allow("EXAMPLE.COM"), "case-insensitive match");
        assert!(!p.allow("other.com"));
    }

    #[test]
    fn allow_wildcard() {
        let p = policy("deny", vec![rule("allow", "*.example.com", "")]);
        for (host, want) in [
            ("api.example.com", true),
            ("a.b.example.com", true),
            ("evil.com", false),
            ("notexample.com", false),
            ("example.com", false), // wildcard matches subdomains only
        ] {
            assert_eq!(p.allow(host), want, "allow({host})");
        }
    }

    #[test]
    fn default_deny() {
        assert!(!policy("deny", vec![]).allow("anything.com"));
    }

    #[test]
    fn default_allow() {
        assert!(policy("allow", vec![]).allow("anything.com"));
        // Empty default is treated as allow.
        assert!(Policy::default().allow("anything.com"));
    }

    #[test]
    fn first_match_wins() {
        let p = policy(
            "allow",
            vec![
                rule("deny", "blocked.example.com", ""),
                rule("allow", "*.example.com", ""),
            ],
        );
        assert!(!p.allow("blocked.example.com"));
        assert!(p.allow("ok.example.com"));
    }

    #[test]
    fn allow_addr_cidr() {
        let p = policy("deny", vec![rule("allow", "", "10.0.0.0/8")]);
        assert!(p.allow_addr("10.1.2.3:443"));
        assert!(!p.allow_addr("192.168.1.1:443"));
    }

    #[test]
    fn allow_addr_hostname() {
        let p = policy("deny", vec![rule("allow", "api.example.com", "")]);
        assert!(p.allow_addr("api.example.com:443"));
        assert!(!p.allow_addr("evil.com:443"));
    }

    #[test]
    fn allow_addr_without_port_and_ipv6() {
        let p = policy(
            "deny",
            vec![
                rule("allow", "", "10.0.0.0/8"),
                rule("allow", "", "fd00::/8"),
            ],
        );
        assert!(p.allow_addr("10.0.0.1"));
        assert!(p.allow_addr("[fd00::1]:443"));
        assert!(p.allow_addr("fd00::1"));
        assert!(!p.allow_addr("[fe80::1]:443"));
    }

    #[test]
    fn allow_listed_hostname() {
        let p = policy(
            "allow",
            vec![
                rule("deny", "blocked.example.com", ""),
                rule("allow", "*.example.com", ""),
            ],
        );
        assert!(!p.allow_listed_hostname("unknown.test"));
        assert!(!p.allow_listed_hostname("blocked.example.com"));
        assert!(p.allow_listed_hostname("api.example.com"));
    }

    #[test]
    fn verdict_is_case_and_space_insensitive() {
        let p = policy(" DENY ", vec![rule(" Allow ", "a.test", "")]);
        assert!(p.allow("a.test"));
        assert!(!p.allow("b.test"));
        // Unknown verdicts deny.
        assert!(!policy("permit", vec![]).allow("x.test"));
    }

    #[test]
    fn load_policy_from_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("policy.json");
        let data = r#"{"default":"deny","rules":[{"verdict":"allow","hostname":"*.example.com"},{"verdict":"allow","cidr":"10.0.0.0/8"}]}"#;
        std::fs::write(&path, data).expect("write");
        let p = load_policy(&path).expect("load");
        assert_eq!(p.default, "deny");
        assert_eq!(p.rules.len(), 2);
        assert!(p.allow("api.example.com"));
        assert!(p.allow_addr("10.0.0.1:80"));
    }

    #[test]
    fn load_policy_errors() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert!(load_policy(dir.path().join("missing.json")).is_err());
        let bad = dir.path().join("bad.json");
        std::fs::write(&bad, "{not json").expect("write");
        assert!(load_policy(&bad).is_err());
    }

    #[test]
    fn json_null_and_go_field_names() {
        let p = Policy::from_json(r#"{"default":null,"rules":null}"#).expect("null");
        assert_eq!(p, Policy::default());
        let p = Policy::from_json(
            r#"{"Default":"deny","Rules":[{"Verdict":"allow","CIDR":"10.0.0.0/8"}]}"#,
        )
        .expect("go names");
        assert!(p.allow_addr("10.0.0.1:1"));
        assert!(!p.allow_addr("11.0.0.1:1"));
    }

    #[test]
    fn json_round_trip_keeps_wire_shape() {
        let p = policy("deny", vec![rule("allow", "a.test", "")]);
        let s = serde_json::to_string(&p).expect("encode");
        assert_eq!(
            s,
            r#"{"default":"deny","rules":[{"verdict":"allow","hostname":"a.test","cidr":""}]}"#
        );
    }
}
