//! Static lint of a resolved Charter.
//!
//! Validation enforces the hard invariants that make a Charter loadable; lint
//! surfaces the softer "this probably isn't what you meant" problems on top of
//! an already-valid Charter. It works on the struct directly, so Charters
//! built in memory can be linted too.

use std::fmt;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::STRICT_PROXY_UID;
use crate::load::home_dir;
use crate::schema::{Charter, NetworkRule, PolicyRule};
use crate::validate::numeric_uid;

/// How serious a [`Finding`] is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Fails validation: the Charter will not behave as intended (or will
    /// refuse to run) if shipped as-is.
    Error,
    /// A likely footgun that still lets the Charter run.
    Warn,
}

impl Severity {
    /// The wire spelling (`"error"` or `"warn"`).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warn => "warn",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One lint result. `field` is a dotted/indexed path into the Charter (such
/// as `host.image`, `env[2].op` or `policy[1]`) locating the stanza.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct Finding {
    pub severity: Severity,
    pub field: String,
    pub message: String,
}

/// Lints a Charter, returning findings in a stable order: host fields first,
/// then capabilities, env, network and policy stanzas in declaration order.
///
/// It performs no network I/O; the only side effect is stat-ing local paths
/// (env files and `host.copy_from`) to warn about missing ones.
pub fn lint(p: &Charter) -> Vec<Finding> {
    lint_with_home(p, home_dir(|k| std::env::var(k).ok()))
}

/// Lints with an explicit home directory for `~/` expansion, so tests do not
/// depend on the machine's home.
pub(crate) fn lint_with_home(p: &Charter, home: Option<PathBuf>) -> Vec<Finding> {
    Linter {
        home,
        out: Vec::new(),
    }
    .run(p)
}

struct Linter {
    home: Option<PathBuf>,
    out: Vec<Finding>,
}

impl Linter {
    fn add(&mut self, severity: Severity, field: impl Into<String>, message: impl Into<String>) {
        self.out.push(Finding {
            severity,
            field: field.into(),
            message: message.into(),
        });
    }

    fn run(mut self, p: &Charter) -> Vec<Finding> {
        // The loader defaults the image, so this only fires for Charters built
        // in memory, but callers linting pre-default structs still want it.
        if p.host.image.trim().is_empty() {
            self.add(
                Severity::Warn,
                "host.image",
                "no image set; an image is usually required to launch a sandbox",
            );
        }
        let cf = &p.host.copy_from;
        if !cf.is_empty() && !self.path_exists(cf) {
            self.add(
                Severity::Warn,
                "host.copy_from",
                format!("copy_from path {cf:?} does not exist"),
            );
        }
        self.host_footguns(p);
        self.capabilities(p);
        self.env(p);
        self.network(p);
        self.policy(p);
        self.out
    }

    fn capabilities(&mut self, p: &Charter) {
        if p.host.command.first().is_some_and(|c| c.trim().is_empty()) {
            self.add(
                Severity::Error,
                "host.command[0]",
                "command executable cannot be empty",
            );
        }
        let mut seen = Vec::new();
        for (i, raw) in p.capabilities.iter().enumerate() {
            let capability = raw.trim().to_lowercase();
            let field = format!("capabilities[{i}]");
            if !matches!(capability.as_str(), "python" | "node" | "browser") {
                self.add(
                    Severity::Error,
                    field,
                    format!("unsupported capability {raw:?} (want python, node, or browser)"),
                );
                continue;
            }
            if seen.contains(&capability) {
                self.add(
                    Severity::Warn,
                    field,
                    format!("duplicate capability {capability:?}"),
                );
            } else {
                seen.push(capability);
            }
        }
    }

    /// Flags unresolved secret references, missing files and duplicate names.
    fn env(&mut self, p: &Charter) {
        let mut seen: Vec<(&str, usize)> = Vec::new();
        for (i, e) in p.env.iter().enumerate() {
            let field = format!("env[{i}]");
            if !e.name.is_empty() {
                if let Some((_, first)) = seen.iter().find(|(n, _)| *n == e.name) {
                    self.add(
                        Severity::Error,
                        format!("{field}.name"),
                        format!(
                            "duplicate env name {:?} (first defined at env[{first}]); the later value silently wins",
                            e.name
                        ),
                    );
                } else {
                    seen.push((&e.name, i));
                }
            }

            // env:// and vault:// are built in and resolve when the source is
            // present (warn); other schemes always fail closed (error).
            if !e.op.is_empty() {
                let scheme = e.op.split_once("://").map_or(e.op.as_str(), |(s, _)| s);
                if matches!(scheme, "env" | "vault") {
                    self.add(
                        Severity::Warn,
                        format!("{field}.op"),
                        format!(
                            "env {:?} resolves {:?} at sandbox creation; it is fail-closed and cannot be validated statically",
                            e.name, e.op
                        ),
                    );
                } else {
                    self.add(
                        Severity::Error,
                        format!("{field}.op"),
                        format!(
                            "env {:?} uses an external secret reference ({}) that is not built in; it always fails closed at runtime and cannot be validated statically",
                            e.name, e.op
                        ),
                    );
                }
            }

            if !e.file.is_empty() && !self.path_exists(&e.file) {
                self.add(
                    Severity::Warn,
                    format!("{field}.file"),
                    format!(
                        "env {:?} reads from file {:?} which does not exist",
                        e.name, e.file
                    ),
                );
            }
        }
    }

    fn host_footguns(&mut self, p: &Charter) {
        let strict = p.network.strict_egress();
        if strict && numeric_uid(&p.host.user) == Some(STRICT_PROXY_UID.into()) {
            self.add(
                Severity::Error,
                "host.user",
                format!(
                    "host.user uid {STRICT_PROXY_UID} is reserved for strict egress interception; choose a different uid"
                ),
            );
        }
        if !p.host.read_only && (strict || !p.host.runtime_class.is_empty()) {
            self.add(
                Severity::Warn,
                "host.read_only",
                "host.read_only is false while stricter isolation settings are enabled; writable rootfs increases tamper surface",
            );
        }
        if !is_root_user(&p.host.user) {
            return;
        }
        for (i, f) in p.files.iter().enumerate() {
            // path.Clean never turns a relative path absolute, so checking the
            // trimmed prefix is equivalent to Go's Clean + IsAbs.
            if f.path.trim().starts_with('/') {
                self.add(
                    Severity::Warn,
                    format!("file[{i}].path"),
                    format!(
                        "running as root with broad file projection target {:?} increases write blast radius",
                        f.path
                    ),
                );
            }
        }
    }

    /// Flags egress policies that cannot do anything useful.
    fn network(&mut self, p: &Charter) {
        let rules = &p.network.rules;
        if p.network.deny_by_default() && !rules.iter().any(|r| is_allow_verdict(&r.verdict)) {
            if p.network.strict_egress() {
                self.add(
                    Severity::Warn,
                    "network.enforce",
                    "strict egress is enabled but there are no allow rules; all outbound traffic is blocked",
                );
            } else {
                self.add(
                    Severity::Warn,
                    "network.default",
                    "network.default is \"deny\" but there are no allow rules; nothing can egress",
                );
            }
        }

        // A hostname matches one host (or one wildcard); a comma or space
        // means the author meant a list that can never match.
        for (i, r) in rules.iter().enumerate() {
            let h = r.hostname.trim();
            if !h.is_empty() && h.contains([',', ' ', '\t']) {
                self.add(
                    Severity::Error,
                    format!("network.rule[{i}].hostname"),
                    format!(
                        "hostname {:?} contains a comma or space; a rule matches exactly one host — use a separate [[network.rule]] per host (wildcards like *.example.com are allowed)",
                        r.hostname
                    ),
                );
            }
        }

        for (j, later) in rules.iter().enumerate() {
            if let Some(i) = rules[..j]
                .iter()
                .position(|earlier| network_rule_shadows(earlier, later))
            {
                self.add(
                    Severity::Warn,
                    format!("network.rule[{j}]"),
                    format!(
                        "unreachable: network.rule[{i}] already matches these targets (first match wins)"
                    ),
                );
            }
        }
    }

    /// Flags invalid verdicts and rules an earlier catch-all already decides.
    fn policy(&mut self, p: &Charter) {
        let rules = &p.policy;
        if rules.is_empty() && matches!(p.policy_engine.as_str(), "" | "builtin") {
            self.add(
                Severity::Warn,
                "policy",
                "no [[policy]] rules configured; this relies on implicit allow-by-default behavior",
            );
        }
        for (i, r) in rules.iter().enumerate() {
            if r.verdict.is_valid() {
                continue;
            }
            let msg = if r.verdict.as_str().is_empty() {
                "policy rule has no verdict (want allow, deny, or require-approval)".to_owned()
            } else {
                format!(
                    "policy rule has invalid verdict {:?} (want allow, deny, or require-approval)",
                    r.verdict.as_str()
                )
            };
            self.add(Severity::Error, format!("policy[{i}]"), msg);
        }
        for (j, later) in rules.iter().enumerate() {
            if let Some(i) = rules[..j]
                .iter()
                .position(|earlier| policy_rule_shadows(earlier, later))
            {
                let tool = &rules[i].tool;
                let label = if tool == "*" { "* (any)" } else { tool };
                self.add(
                    Severity::Error,
                    format!("policy[{j}]"),
                    format!(
                        "unreachable: policy[{i}] is a catch-all for tool {label:?} and decides first (first match wins)"
                    ),
                );
            }
        }
    }

    /// Reports whether a path (with a leading `~/` expanded) exists.
    fn path_exists(&self, path: &str) -> bool {
        if path.is_empty() {
            return false;
        }
        let expanded = match (path.strip_prefix("~/"), &self.home) {
            (Some(rest), Some(home)) => home.join(rest),
            _ => PathBuf::from(path),
        };
        Path::new(&expanded).metadata().is_ok()
    }
}

/// Reports whether earlier rule `a` matches every action later rule `b`
/// could. Deliberately conservative: only a genuine catch-all (no match and
/// no argv constraint) for a covering tool shadows, so it never reports a
/// false "unreachable".
fn policy_rule_shadows(a: &PolicyRule, b: &PolicyRule) -> bool {
    (a.tool == "*" || a.tool == b.tool)
        && is_catch_all_glob(&a.match_glob)
        && is_catch_all_glob(&a.match_argv)
}

fn is_catch_all_glob(s: &str) -> bool {
    s.is_empty() || s == "*"
}

/// Reports whether earlier rule `a` matches a superset of `b`'s targets.
/// Hostname and CIDR selectors are compared independently.
fn network_rule_shadows(a: &NetworkRule, b: &NetworkRule) -> bool {
    (!b.hostname.is_empty()
        && !a.hostname.is_empty()
        && hostname_pattern_covers(&a.hostname, &b.hostname))
        || (!b.cidr.is_empty() && !a.cidr.is_empty() && cidr_covers(&a.cidr, &b.cidr))
}

/// Reports whether hostname pattern `a` matches every host `b` matches, using
/// the egress matcher's semantics: exact hosts or one leading `*.` wildcard.
fn hostname_pattern_covers(a: &str, b: &str) -> bool {
    let a = a.trim().to_lowercase();
    let b = b.trim().to_lowercase();
    if a.is_empty() || b.is_empty() {
        return false;
    }
    if a == b {
        return true;
    }
    let Some(suffix) = a.strip_prefix("*.") else {
        return false;
    };
    let dotted = format!(".{suffix}");
    match b.strip_prefix("*.") {
        Some(b_suffix) => b_suffix == suffix || b_suffix.ends_with(&dotted),
        None => b.ends_with(&dotted) && b.len() > suffix.len() + 1,
    }
}

/// Parses a CIDR the way Go's `net.ParseCIDR` does, returning the address as
/// written and its prefix length.
fn parse_cidr(s: &str) -> Option<(IpAddr, u32)> {
    let (addr, prefix) = s.trim().split_once('/')?;
    let addr: IpAddr = addr.parse().ok()?;
    if prefix.is_empty() || !prefix.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let bits = if addr.is_ipv4() { 32 } else { 128 };
    let prefix: u32 = prefix.parse().ok().filter(|&p| p <= bits)?;
    Some((addr, prefix))
}

/// Reports whether CIDR `a` fully contains CIDR `b`.
fn cidr_covers(a: &str, b: &str) -> bool {
    let (Some((a_ip, a_len)), Some((b_ip, b_len))) = (parse_cidr(a), parse_cidr(b)) else {
        return false;
    };
    if a_len > b_len {
        return false;
    }
    let mask = |bits: u32, total: u32| -> u128 {
        if bits == 0 {
            0
        } else {
            (u128::MAX << (total - bits)) & (u128::MAX >> (128 - total))
        }
    };
    match (a_ip, b_ip) {
        (IpAddr::V4(a), IpAddr::V4(b)) => {
            let m = mask(a_len, 32);
            u128::from(u32::from(a)) & m == u128::from(u32::from(b)) & m
        }
        (IpAddr::V6(a), IpAddr::V6(b)) => {
            let m = mask(a_len, 128);
            u128::from(a) & m == u128::from(b) & m
        }
        _ => false,
    }
}

/// An empty network verdict defaults to allow, matching backend translation.
fn is_allow_verdict(v: &str) -> bool {
    let v = v.trim().to_lowercase();
    v.is_empty() || v == "allow"
}

fn is_root_user(user: &str) -> bool {
    let u = user.trim().to_lowercase();
    u.is_empty() || u == "root" || numeric_uid(&u) == Some(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{EnvVar, File, Host, Network, Verdict};

    fn has(findings: &[Finding], severity: Severity, field: &str) -> bool {
        findings
            .iter()
            .any(|f| f.severity == severity && f.field == field)
    }

    fn img() -> Host {
        Host {
            image: "img".into(),
            ..Host::default()
        }
    }

    fn rule(verdict: &str, hostname: &str, cidr: &str) -> NetworkRule {
        NetworkRule {
            verdict: verdict.into(),
            hostname: hostname.into(),
            cidr: cidr.into(),
        }
    }

    fn prule(tool: &str, m: &str, verdict: Verdict) -> PolicyRule {
        PolicyRule {
            tool: tool.into(),
            match_glob: m.into(),
            verdict,
            ..PolicyRule::default()
        }
    }

    fn env_op(name: &str, op: &str) -> EnvVar {
        EnvVar {
            name: name.into(),
            op: op.into(),
            ..EnvVar::default()
        }
    }

    fn env_val(name: &str, value: &str) -> EnvVar {
        EnvVar {
            name: name.into(),
            value: value.into(),
            ..EnvVar::default()
        }
    }

    fn deny_net(rules: Vec<NetworkRule>) -> Network {
        Network {
            default: "deny".into(),
            rules,
            ..Network::default()
        }
    }

    fn allow_all() -> Vec<PolicyRule> {
        vec![prule("shell", "*", Verdict::Allow)]
    }

    #[test]
    fn table_of_findings() {
        let cases: Vec<(&str, Charter, Severity, &str)> = vec![
            (
                "missing image warns",
                Charter::default(),
                Severity::Warn,
                "host.image",
            ),
            (
                "op reference errors",
                Charter {
                    host: img(),
                    env: vec![env_op("TOKEN", "op://vault/item/field")],
                    ..Charter::default()
                },
                Severity::Error,
                "env[0].op",
            ),
            (
                "env reference warns",
                Charter {
                    host: img(),
                    env: vec![env_op("TOKEN", "env://TOKEN")],
                    ..Charter::default()
                },
                Severity::Warn,
                "env[0].op",
            ),
            (
                "duplicate env name errors",
                Charter {
                    host: img(),
                    env: vec![env_val("API", "a"), env_val("API", "b")],
                    ..Charter::default()
                },
                Severity::Error,
                "env[1].name",
            ),
            (
                "deny default with no allow rules warns",
                Charter {
                    host: img(),
                    network: deny_net(vec![]),
                    ..Charter::default()
                },
                Severity::Warn,
                "network.default",
            ),
            (
                "unreachable hostname rule warns",
                Charter {
                    host: img(),
                    network: deny_net(vec![
                        rule("allow", "*.example.com", ""),
                        rule("deny", "api.example.com", ""),
                    ]),
                    ..Charter::default()
                },
                Severity::Warn,
                "network.rule[1]",
            ),
            (
                "unreachable cidr rule warns",
                Charter {
                    host: img(),
                    network: deny_net(vec![
                        rule("allow", "", "10.0.0.0/8"),
                        rule("deny", "", "10.1.0.0/16"),
                    ]),
                    ..Charter::default()
                },
                Severity::Warn,
                "network.rule[1]",
            ),
            (
                "invalid policy verdict errors",
                Charter {
                    host: img(),
                    policy: vec![prule("shell", "rm*", Verdict::parse("nope"))],
                    ..Charter::default()
                },
                Severity::Error,
                "policy[0]",
            ),
            (
                "empty policy verdict errors",
                Charter {
                    host: img(),
                    policy: vec![prule("shell", "rm*", Verdict::Unset)],
                    ..Charter::default()
                },
                Severity::Error,
                "policy[0]",
            ),
            (
                "shadowed policy rule errors on same tool catch-all",
                Charter {
                    host: img(),
                    policy: vec![
                        prule("shell", "*", Verdict::Allow),
                        prule("shell", "rm -rf*", Verdict::Deny),
                    ],
                    ..Charter::default()
                },
                Severity::Error,
                "policy[1]",
            ),
            (
                "shadowed policy rule errors on wildcard tool catch-all",
                Charter {
                    host: img(),
                    policy: vec![
                        prule("*", "", Verdict::Deny),
                        prule("shell", "ls", Verdict::Allow),
                    ],
                    ..Charter::default()
                },
                Severity::Error,
                "policy[1]",
            ),
        ];
        for (name, charter, severity, field) in cases {
            let findings = lint(&charter);
            assert!(
                has(&findings, severity, field),
                "{name}: missing {severity} {field}; got {findings:?}"
            );
        }
    }

    #[test]
    fn env_file_missing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let present = dir.path().join("present.txt");
        std::fs::write(&present, "v").expect("write");
        let missing = dir.path().join("missing.txt");
        let p = Charter {
            host: img(),
            env: vec![
                EnvVar {
                    name: "OK".into(),
                    file: present.display().to_string(),
                    ..EnvVar::default()
                },
                EnvVar {
                    name: "BAD".into(),
                    file: missing.display().to_string(),
                    ..EnvVar::default()
                },
            ],
            ..Charter::default()
        };
        let findings = lint(&p);
        assert!(!has(&findings, Severity::Warn, "env[0].file"));
        assert!(has(&findings, Severity::Warn, "env[1].file"));
    }

    #[test]
    fn tilde_expands_against_home() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("k.key"), "v").expect("write");
        let mut p = Charter {
            host: img(),
            ..Charter::default()
        };
        p.host.copy_from = "~/k.key".into();
        let home = Some(dir.path().to_owned());
        assert!(!has(
            &lint_with_home(&p, home),
            Severity::Warn,
            "host.copy_from"
        ));
        assert!(has(
            &lint_with_home(&p, None),
            Severity::Warn,
            "host.copy_from"
        ));
    }

    #[test]
    fn copy_from_missing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut p = Charter {
            host: img(),
            ..Charter::default()
        };
        p.host.copy_from = dir.path().join("nope").display().to_string();
        assert!(has(&lint(&p), Severity::Warn, "host.copy_from"));
        p.host.copy_from = dir.path().display().to_string();
        assert!(!has(&lint(&p), Severity::Warn, "host.copy_from"));
    }

    #[test]
    fn clean_charter_has_no_findings() {
        let p = Charter {
            host: img(),
            env: vec![env_val("A", "1"), env_val("B", "2")],
            network: deny_net(vec![
                rule("allow", "api.example.com", ""),
                rule("allow", "*.internal", ""),
            ]),
            policy: vec![
                prule("shell", "rm -rf*", Verdict::Deny),
                prule("shell", "*", Verdict::Allow),
            ],
            ..Charter::default()
        };
        assert_eq!(lint(&p), []);
    }

    #[test]
    fn stable_order() {
        let p = Charter {
            env: vec![env_op("X", "op://a/b/c")],
            network: deny_net(vec![
                rule("allow", "*.example.com", ""),
                rule("deny", "a.example.com", ""),
            ]),
            policy: vec![prule("shell", "", Verdict::parse("bogus"))],
            ..Charter::default()
        };
        let first = lint(&p);
        let fields: Vec<_> = first.iter().map(|f| f.field.as_str()).collect();
        assert_eq!(
            fields,
            ["host.image", "env[0].op", "network.rule[1]", "policy[0]"]
        );
        for _ in 0..5 {
            assert_eq!(lint(&p), first);
        }
    }

    #[test]
    fn strict_egress_rejects_exempt_uid() {
        let p = Charter {
            host: Host {
                user: "1337".into(),
                ..img()
            },
            network: Network {
                enforce: "strict".into(),
                ..deny_net(vec![rule("allow", "api.example.com", "")])
            },
            policy: allow_all(),
            ..Charter::default()
        };
        assert!(has(&lint(&p), Severity::Error, "host.user"));
    }

    #[test]
    fn warns_on_implicit_allow_policy() {
        let p = Charter {
            host: img(),
            network: Network {
                default: "allow".into(),
                ..Network::default()
            },
            ..Charter::default()
        };
        assert!(has(&lint(&p), Severity::Warn, "policy"));
    }

    #[test]
    fn warns_on_root_broad_file_projection() {
        let p = Charter {
            host: Host {
                user: "root".into(),
                ..img()
            },
            files: vec![File {
                path: "/etc/profile".into(),
                ..File::default()
            }],
            policy: allow_all(),
            ..Charter::default()
        };
        assert!(has(&lint(&p), Severity::Warn, "file[0].path"));
    }

    #[test]
    fn warns_on_strict_egress_without_allow_rules() {
        let p = Charter {
            host: img(),
            network: Network {
                enforce: "strict".into(),
                ..deny_net(vec![])
            },
            policy: allow_all(),
            ..Charter::default()
        };
        assert!(has(&lint(&p), Severity::Warn, "network.enforce"));
    }

    #[test]
    fn errors_on_multi_host_hostname() {
        let p = Charter {
            host: img(),
            network: deny_net(vec![rule("allow", "example.com, *.github.com", "")]),
            policy: allow_all(),
            ..Charter::default()
        };
        assert!(has(&lint(&p), Severity::Error, "network.rule[0].hostname"));
    }

    #[test]
    fn warns_writable_rootfs_with_isolation_settings() {
        let p = Charter {
            host: img(),
            network: Network {
                enforce: "strict".into(),
                ..deny_net(vec![rule("allow", "", "10.0.0.0/8")])
            },
            policy: allow_all(),
            ..Charter::default()
        };
        assert!(has(&lint(&p), Severity::Warn, "host.read_only"));
    }

    #[test]
    fn capabilities_and_command() {
        let p = Charter {
            host: Host {
                command: vec![String::new()],
                ..img()
            },
            capabilities: vec!["python".into(), "python".into(), "ruby".into()],
            policy: allow_all(),
            ..Charter::default()
        };
        let findings = lint(&p);
        assert!(has(&findings, Severity::Error, "host.command[0]"));
        assert!(has(&findings, Severity::Warn, "capabilities[1]"));
        assert!(has(&findings, Severity::Error, "capabilities[2]"));
    }

    #[test]
    fn hostname_and_cidr_coverage() {
        assert!(hostname_pattern_covers("*.Example.com", "a.b.example.com"));
        assert!(hostname_pattern_covers("*.example.com", "*.b.example.com"));
        assert!(!hostname_pattern_covers("*.example.com", "example.com"));
        assert!(!hostname_pattern_covers("api.example.com", "*.example.com"));
        assert!(cidr_covers("0.0.0.0/0", "192.168.1.0/24"));
        assert!(cidr_covers("10.0.0.0/8", "10.1.2.3/32"));
        assert!(!cidr_covers("10.1.0.0/16", "10.0.0.0/8"));
        assert!(!cidr_covers("10.0.0.0/8", "fd00::/8"));
        assert!(cidr_covers("fd00::/8", "fd12::/16"));
        assert!(cidr_covers("10.0.0.0/08", "10.0.0.0/8"));
        assert!(!cidr_covers("010.0.0.0/8", "10.0.0.0/8"));
        assert!(!cidr_covers("10.0.0.0/33", "10.0.0.0/8"));
    }
}
