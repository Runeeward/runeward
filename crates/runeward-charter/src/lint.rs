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
use crate::governance::IsolationLevel;
use crate::governance::{Endpoint, RequestRule};
use crate::load::home_dir;
use crate::runtimes::{FIRECRACKER_NO_SHARED_FS, KRUN_NO_EXEC, RuntimeFamily, is_engine_name};
use crate::schema::{Charter, NetworkRule, PolicyRule};
use crate::validate::numeric_uid;

/// Reports whether `path` names an interpreter or a launcher that runs
/// other programs, by its file name.
fn is_interpreter(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path);
    let base = name.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.');
    matches!(
        base,
        "python"
            | "pypy"
            | "node"
            | "nodejs"
            | "deno"
            | "bun"
            | "ruby"
            | "perl"
            | "php"
            | "lua"
            | "java"
            | "sh"
            | "bash"
            | "dash"
            | "zsh"
            | "ash"
            | "ksh"
            | "fish"
            | "env"
            | "busybox"
            | "xargs"
            | "nohup"
            | "timeout"
            | "sudo"
            | "osascript"
            | "pwsh"
    )
}

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
    lint_for(p, home, std::env::consts::OS)
}

/// Lints as if running on `os` (a `std::env::consts::OS` value): some
/// runtime hints depend on where the container engine runs.
pub(crate) fn lint_for(p: &Charter, home: Option<PathBuf>, os: &'static str) -> Vec<Finding> {
    Linter {
        home,
        os,
        out: Vec::new(),
    }
    .run(p)
}

struct Linter {
    home: Option<PathBuf>,
    os: &'static str,
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
        self.broker(p);
        lint_host_runtime(p, self.os, &mut self.out);
        lint_governance_isolation(p, &mut self.out);
        lint_governance_filesystem(p, &mut self.out);
        lint_governance_process(p, &mut self.out);
        lint_workspace(p, &mut self.out);
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
        if !p.host.read_only && (strict || !p.host.oci_runtime().is_empty()) {
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
        if p.network.deny_by_default()
            && !rules.iter().any(|r| is_allow_verdict(&r.verdict))
            && p.endpoints.is_empty()
        {
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

// ---------------------------------------------------------------------------
// [[credential]] / [[endpoint]] (egress broker) lint.
// ---------------------------------------------------------------------------

impl Linter {
    /// Flags credential and endpoint stanzas that validate but will not do
    /// what the author probably meant.
    fn broker(&mut self, p: &Charter) {
        for (i, c) in p.credentials.iter().enumerate() {
            if !p.endpoints.iter().any(|e| e.credential == c.name) {
                self.add(
                    Severity::Warn,
                    format!("credential[{i}]"),
                    format!(
                        "credential {:?} is not referenced by any [[endpoint]]; it is never injected",
                        c.name
                    ),
                );
            }
        }
        for (i, e) in p.endpoints.iter().enumerate() {
            self.endpoint(p, i, e);
        }
    }

    /// Endpoint `binaries` are enforced by the in-sandbox supervisor
    /// attributing each connection to the executable holding it, so they
    /// need what that takes, and they fail closed without it: a Charter that
    /// cannot get attribution is refused at create, like `landlock =
    /// "required"` on a kernel without Landlock.
    fn binaries(&mut self, p: &Charter, field: &str, label: &str, e: &Endpoint) {
        let f = format!("{field}.binaries");
        if !p.network.strict_egress() {
            self.add(
                Severity::Error,
                f.clone(),
                format!(
                    "endpoint {label:?} lists binaries, which are only enforced with strict egress ([network] default = \"deny\", enforce = \"strict\"): the broker must share the Citadel's network namespace to ask the in-sandbox supervisor which executable opened each connection. Without it the Citadel is refused at create"
                ),
            );
        }
        for b in &e.binaries {
            if !b.starts_with('/') {
                self.add(
                    Severity::Error,
                    f.clone(),
                    format!(
                        "endpoint {label:?} binary {b:?} must be an absolute path (it is matched by file identity, not looked up on PATH)"
                    ),
                );
            } else if is_interpreter(b) {
                self.add(
                    Severity::Warn,
                    f.clone(),
                    format!(
                        "endpoint {label:?} allows {b:?}, an interpreter or launcher: every program it runs (any script, `{b} -c ...`) counts as {b:?} and can use the endpoint"
                    ),
                );
            }
        }
        let oci = p.host.oci_runtime();
        if !oci.is_empty() && RuntimeFamily::of(oci) != RuntimeFamily::Container {
            self.add(
                Severity::Warn,
                f.clone(),
                format!(
                    "endpoint {label:?} lists binaries but the runtime is {oci:?}: Docker and Podman refuse that (the egress sidecar cannot see a gVisor or VM sandbox's sockets); it can work on Kubernetes once the supervisor runs there, where the sidecar shares the Pod"
                ),
            );
        }
        let has_identity = !p.host.user.trim().is_empty()
            || p.process
                .as_ref()
                .is_some_and(|pr| !pr.run_as_user.trim().is_empty());
        if !has_identity {
            self.add(
                Severity::Warn,
                f,
                format!(
                    "endpoint {label:?} lists binaries, which run the in-sandbox supervisor; it needs a non-root agent identity: set [process] run_as_user or host.user, or use an image whose USER is not root"
                ),
            );
        }
    }

    fn endpoint(&mut self, p: &Charter, i: usize, e: &Endpoint) {
        let field = format!("endpoint[{i}]");
        let label = endpoint_label(e);
        let port = endpoint_port(e);
        let inspected = !matches!(e.protocol.as_str(), "" | "tcp");

        if let Some(j) = p.endpoints[..i].iter().position(|earlier| {
            endpoint_port(earlier) == port && earlier.host.eq_ignore_ascii_case(&e.host)
        }) {
            self.add(
                Severity::Warn,
                field.clone(),
                format!(
                    "unreachable: endpoint[{j}] already covers {}:{port} (first match wins)",
                    e.host
                ),
            );
        }
        if !e.credential.is_empty() && !inspected {
            self.add(
                Severity::Error,
                format!("{field}.credential"),
                format!(
                    "endpoint {label:?} injects credential {:?} but protocol is tcp; credentials are only attached to inspected protocols (rest, websocket, mcp, json-rpc)",
                    e.credential
                ),
            );
        }
        if !e.binaries.is_empty() {
            self.binaries(p, &field, label, e);
        }
        if e.mode == "audit" {
            self.add(
                Severity::Warn,
                format!("{field}.mode"),
                format!(
                    "endpoint {label:?} is in audit mode; requests that would be denied are recorded and still forwarded"
                ),
            );
        }
        // The egress gate lets the first matching hostname rule veto an
        // endpoint, mirroring how it decides plain hostnames.
        if p.network
            .rules
            .iter()
            .find(|r| hostname_pattern_covers(&r.hostname, &e.host))
            .is_some_and(|r| !is_allow_verdict(&r.verdict))
        {
            self.add(
                Severity::Warn,
                field.clone(),
                format!(
                    "endpoint {label:?}: host {:?} is denied by a [[network.rule]]; the explicit network deny wins and the endpoint is unreachable",
                    e.host
                ),
            );
        }
        if e.health_path.contains("..") || e.health_path.to_ascii_lowercase().contains("%2f") {
            self.add(
                Severity::Error,
                format!("{field}.health_path"),
                format!(
                    "health_path {:?} contains \"..\" or an encoded \"/\"; the broker refuses such paths, so the breaker never closes early",
                    e.health_path
                ),
            );
        } else if !e.health_path.is_empty() && e.health_path.contains('?') {
            self.add(
                Severity::Warn,
                format!("{field}.health_path"),
                "health_path carries a query string; it is sent verbatim on every probe",
            );
        }
        for (kind, rules) in [("allow", &e.allow), ("deny", &e.deny)] {
            for (j, r) in rules.iter().enumerate() {
                self.request_rule(e, &format!("{field}.{kind}[{j}]"), kind, r);
            }
        }
    }

    fn request_rule(&mut self, e: &Endpoint, field: &str, kind: &str, r: &RequestRule) {
        if r.path.contains("..") || r.path.to_ascii_lowercase().contains("%2f") {
            self.add(
                Severity::Error,
                format!("{field}.path"),
                format!(
                    "path {:?} contains \"..\" or an encoded \"/\"; such requests are always refused, so this rule never matches",
                    r.path
                ),
            );
        }
        if kind == "deny" {
            if r.method.is_empty() && r.path.is_empty() && r.tool.is_empty() {
                self.add(
                    Severity::Warn,
                    field.to_owned(),
                    "deny rule sets no method, path or tool; it matches every request to this endpoint",
                );
            }
            if r.max_calls > 0 {
                self.add(
                    Severity::Warn,
                    format!("{field}.max_calls"),
                    "max_calls on a deny rule has no effect; budgets apply to allow rules",
                );
            }
            return;
        }
        if e.protocol == "mcp" {
            if !r.tool.is_empty() && !r.method.is_empty() && r.method != "tools/call" {
                self.add(
                    Severity::Warn,
                    format!("{field}.tool"),
                    format!(
                        "tool {:?} only matches method \"tools/call\", but the rule's method is {:?}; it never matches",
                        r.tool, r.method
                    ),
                );
            }
            let calls_tools = !r.tool.is_empty() || r.method == "tools/call";
            if calls_tools && matches!(r.effect.as_str(), "" | "irreversible") {
                self.add(
                    Severity::Warn,
                    format!("{field}.effect"),
                    "MCP tool calls matched by this rule are untagged or irreversible and require approval; tag effect = \"read\" or \"write\" to allow them directly",
                );
            }
        }
    }
}

fn endpoint_label(e: &Endpoint) -> &str {
    if e.name.is_empty() { &e.host } else { &e.name }
}

fn endpoint_port(e: &Endpoint) -> u16 {
    if e.port == 0 { 443 } else { e.port }
}

#[cfg(test)]
mod broker_tests {
    use super::*;
    use crate::governance::Credential;
    use crate::schema::{Host, Network};

    fn base() -> Charter {
        Charter {
            host: Host {
                image: "img".into(),
                ..Host::default()
            },
            ..Charter::default()
        }
    }

    fn fields(c: &Charter) -> Vec<(Severity, String)> {
        lint_with_home(c, None)
            .into_iter()
            .filter(|f| f.field.starts_with("credential") || f.field.starts_with("endpoint"))
            .map(|f| (f.severity, f.field))
            .collect()
    }

    #[test]
    fn binaries_need_strict_egress_and_absolute_paths() {
        let lint_of = |c: &Charter| -> Vec<Finding> {
            lint_with_home(c, None)
                .into_iter()
                .filter(|f| f.field == "endpoint[0].binaries")
                .collect()
        };
        let mut c = base();
        c.host.user = "1500".into();
        c.endpoints = vec![Endpoint {
            host: "api.github.com".into(),
            binaries: vec!["/usr/bin/gh".into()],
            ..Endpoint::default()
        }];
        // Cooperative egress cannot attribute: an error that says why.
        let got = lint_of(&c);
        assert_eq!(got.len(), 1, "{got:?}");
        assert_eq!(got[0].severity, Severity::Error);
        assert!(
            got[0].message.contains("strict egress"),
            "{}",
            got[0].message
        );

        // Strict egress, an absolute non-interpreter path and an identity:
        // nothing to say.
        c.network = Network {
            default: "deny".into(),
            enforce: "strict".into(),
            ..Network::default()
        };
        assert!(lint_of(&c).is_empty(), "{:?}", lint_of(&c));

        // A relative path, an interpreter, a VM runtime and no identity.
        c.endpoints[0].binaries = vec!["gh".into(), "/usr/bin/python3.11".into()];
        c.host.runtime_class = "kata-qemu".into();
        c.host.user.clear();
        let got = lint_of(&c);
        let has = |sev: Severity, needle: &str| {
            got.iter()
                .any(|f| f.severity == sev && f.message.contains(needle))
        };
        assert!(has(Severity::Error, "absolute path"), "{got:?}");
        assert!(has(Severity::Warn, "interpreter"), "{got:?}");
        assert!(has(Severity::Warn, "kata-qemu"), "{got:?}");
        assert!(has(Severity::Warn, "non-root agent identity"), "{got:?}");
        assert!(!has(Severity::Error, "strict egress"), "{got:?}");
    }

    #[test]
    fn interpreters_are_recognised_by_name() {
        for p in [
            "/usr/bin/python3",
            "/usr/bin/python3.11",
            "/bin/sh",
            "/usr/bin/env",
            "/usr/local/bin/node",
        ] {
            assert!(is_interpreter(p), "{p}");
        }
        for p in [
            "/usr/bin/gh",
            "/usr/bin/curl",
            "/usr/bin/git",
            "/usr/bin/shellcheck",
        ] {
            assert!(!is_interpreter(p), "{p}");
        }
    }

    #[test]
    fn flags_broker_footguns() {
        let mut c = base();
        c.credentials = vec![
            Credential {
                name: "used".into(),
                source: "env://A".into(),
                ..Credential::default()
            },
            Credential {
                name: "unused".into(),
                source: "env://B".into(),
                ..Credential::default()
            },
        ];
        c.network = Network {
            rules: vec![NetworkRule {
                verdict: "deny".into(),
                hostname: "blocked.test".into(),
                cidr: String::new(),
            }],
            ..Network::default()
        };
        c.endpoints = vec![
            Endpoint {
                host: "api.test".into(),
                protocol: "mcp".into(),
                credential: "used".into(),
                mode: "audit".into(),
                binaries: vec!["/usr/bin/x".into()],
                allow: vec![RequestRule {
                    tool: "deploy_*".into(),
                    ..RequestRule::default()
                }],
                deny: vec![RequestRule {
                    max_calls: 3,
                    path: "/a/../b".into(),
                    ..RequestRule::default()
                }],
                ..Endpoint::default()
            },
            Endpoint {
                host: "API.test".into(),
                port: 443,
                credential: "used".into(),
                ..Endpoint::default()
            },
            Endpoint {
                host: "blocked.test".into(),
                ..Endpoint::default()
            },
            Endpoint {
                host: "probe.test".into(),
                protocol: "rest".into(),
                health_path: "/a/../health".into(),
                ..Endpoint::default()
            },
            Endpoint {
                host: "probe2.test".into(),
                protocol: "rest".into(),
                health_path: "/health?deep=1".into(),
                ..Endpoint::default()
            },
        ];
        let got = fields(&c);
        for want in [
            (Severity::Warn, "credential[1]"),
            (Severity::Error, "endpoint[0].binaries"),
            (Severity::Warn, "endpoint[0].mode"),
            (Severity::Warn, "endpoint[0].allow[0].effect"),
            (Severity::Error, "endpoint[0].deny[0].path"),
            (Severity::Warn, "endpoint[0].deny[0].max_calls"),
            (Severity::Warn, "endpoint[1]"),
            (Severity::Error, "endpoint[1].credential"),
            (Severity::Warn, "endpoint[2]"),
            (Severity::Error, "endpoint[3].health_path"),
            (Severity::Warn, "endpoint[4].health_path"),
        ] {
            assert!(
                got.iter().any(|(s, f)| *s == want.0 && f == want.1),
                "missing {want:?} in {got:?}"
            );
        }
        assert!(!got.iter().any(|(_, f)| f == "credential[0]"), "{got:?}");
    }

    #[test]
    fn endpoints_satisfy_deny_by_default() {
        let mut c = base();
        c.network.default = "deny".into();
        assert!(
            lint_with_home(&c, None)
                .iter()
                .any(|f| f.field == "network.default")
        );
        c.endpoints = vec![Endpoint {
            host: "api.test".into(),
            ..Endpoint::default()
        }];
        let got = lint_with_home(&c, None);
        assert!(!got.iter().any(|f| f.field == "network.default"), "{got:?}");
        assert!(fields(&c).is_empty(), "{:?}", fields(&c));
    }
}

// Governance sections: [isolation], [filesystem], [process]. Each lint only
// fires when its section is present, so older Charters lint unchanged.

/// The in-sandbox supervisor's state directory; it refuses any allowed
/// filesystem path that exposes it.
const SUPERVISOR_STATE_DIR: &str = "/run/runeward";

fn finding(out: &mut Vec<Finding>, severity: Severity, field: &str, message: String) {
    out.push(Finding {
        severity,
        field: field.to_owned(),
        message,
    });
}

/// Flags OCI runtime settings that will not do what they say: two
/// different runtimes named, an OCI runtime in the engine hint, or a
/// microVM runtime on a desktop engine that has no nested virtualisation.
fn lint_host_runtime(p: &Charter, os: &str, out: &mut Vec<Finding>) {
    let rt = p.host.runtime.trim();
    let rc = p.host.runtime_class.trim();
    if !is_engine_name(rt) {
        if rc.is_empty() {
            finding(
                out,
                Severity::Warn,
                "host.runtime",
                format!(
                    "host.runtime {rt:?} is used as the sandbox OCI runtime; prefer host.runtime_class = {rt:?} (host.runtime is the engine hint)"
                ),
            );
        } else if !rt.eq_ignore_ascii_case(rc) {
            finding(
                out,
                Severity::Error,
                "host.runtime",
                format!(
                    "host.runtime {rt:?} and host.runtime_class {rc:?} name different OCI runtimes; set only host.runtime_class"
                ),
            );
        }
    }
    let oci = p.host.oci_runtime();
    let family = RuntimeFamily::of(oci);
    let container_host = matches!(p.host.host_type.as_str(), "" | "container");
    if !family.supports_exec() {
        finding(
            out,
            Severity::Error,
            "host.runtime_class",
            format!("runtime {oci:?} cannot run a Rune Box sandbox: {KRUN_NO_EXEC}"),
        );
    }
    if p.host.host_type == crate::HostType::K8s
        && !family.shares_filesystem()
        && p.persists_workspace()
    {
        // Only the cluster knows whether a direct-volume StorageClass is
        // configured; without one the backend refuses the sandbox.
        finding(
            out,
            Severity::Warn,
            "workspace.persist",
            format!(
                "runtime {oci:?} keeps a persistent workspace only with a Kata direct-volume StorageClass: {FIRECRACKER_NO_SHARED_FS}"
            ),
        );
        // Firecracker has five drives per Pod: pause, the strict-egress
        // init container, the broker's trust-bundle init container, the
        // sandbox, the egress sidecar and the workspace would need six.
        if p.network.strict_egress() && (!p.endpoints.is_empty() || !p.credentials.is_empty()) {
            finding(
                out,
                Severity::Error,
                "workspace.persist",
                format!(
                    "runtime {oci:?} cannot combine a persistent workspace with strict egress and the egress broker ([[credential]] or [[endpoint]]): the Pod would need six drives and Firecracker has five; drop one of them or use kata-qemu or kata-clh"
                ),
            );
        }
    }
    if container_host
        && matches!(
            family,
            RuntimeFamily::KataFirecracker | RuntimeFamily::Firecracker
        )
    {
        finding(
            out,
            Severity::Error,
            "host.runtime_class",
            format!(
                "runtime {oci:?} cannot run under Docker or Podman: Firecracker has no shared filesystem and no device hot-plug, so it needs containerd with the devmapper snapshotter (host.type = \"k8s\" with a kata-fc RuntimeClass) or a native Firecracker driver; use kata-qemu or kata-clh on a container host"
            ),
        );
    }
    if container_host && family.needs_kvm() && matches!(os, "macos" | "windows") {
        finding(
            out,
            Severity::Warn,
            "host.runtime_class",
            format!(
                "runtime {oci:?} starts a VM per sandbox and needs /dev/kvm; container engines on {os} (Docker Desktop, OrbStack, Podman machine) run inside a VM without nested virtualisation, so it is unavailable there. Run this Charter on a Linux host with KVM or a Kubernetes node pool that has the runtime"
            ),
        );
    }
}

/// Flags an `[isolation] minimum` the configured runtime cannot meet.
fn lint_governance_isolation(p: &Charter, out: &mut Vec<Finding>) {
    let Some(min) = p.isolation.minimum_level() else {
        return;
    };
    if min <= IsolationLevel::Container {
        return;
    }
    let rc = p.host.oci_runtime();
    if rc.is_empty() {
        finding(
            out,
            Severity::Warn,
            "isolation.minimum",
            format!(
                "isolation.minimum is {:?} but host.runtime_class is empty; the sandbox is refused unless the engine's default runtime provides that boundary",
                min.as_str()
            ),
        );
        return;
    }
    let family = RuntimeFamily::of(rc);
    if family.ceiling() < min {
        finding(
            out,
            Severity::Error,
            "isolation.minimum",
            format!(
                "isolation.minimum is {:?} but host.runtime_class {rc:?} only provides {:?} at most; the sandbox will be refused",
                min.as_str(),
                family.ceiling().as_str()
            ),
        );
    } else if family.claim() < min {
        finding(
            out,
            Severity::Warn,
            "isolation.minimum",
            format!(
                "isolation.minimum is {:?}: host.runtime_class {rc:?} reaches it only when the sandbox evidence shows a hardware-virtualised guest kernel; otherwise the sandbox is refused",
                min.as_str()
            ),
        );
    }
}

/// Reports whether `path` is the supervisor state directory or one of its
/// ancestors (so allowing it would expose the supervisor's files).
fn exposes_supervisor_state(path: &str) -> bool {
    let mut parts: Vec<&str> = Vec::new();
    for c in path.split('/') {
        match c {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            c => parts.push(c),
        }
    }
    let state: Vec<&str> = SUPERVISOR_STATE_DIR
        .split('/')
        .filter(|c| !c.is_empty())
        .collect();
    let n = parts.len().min(state.len());
    parts[..n] == state[..n]
}

/// Flags `[filesystem]` rules that are ignored, contradictory or refused.
fn lint_governance_filesystem(p: &Charter, out: &mut Vec<Finding>) {
    let Some(fs) = &p.filesystem else {
        return;
    };
    let listed = !fs.read_only.is_empty() || !fs.read_write.is_empty();
    if fs.landlock == "off" {
        if listed {
            finding(
                out,
                Severity::Warn,
                "filesystem.landlock",
                "filesystem.landlock is \"off\"; read_only and read_write are not enforced".into(),
            );
        }
        return;
    }
    if !listed && !fs.include_workdir {
        finding(
            out,
            Severity::Error,
            "filesystem",
            "no paths are allowed (read_only, read_write empty and include_workdir false); the agent cannot even load its own executable".into(),
        );
    }
    for (kind, paths) in [("read_only", &fs.read_only), ("read_write", &fs.read_write)] {
        for (i, path) in paths.iter().enumerate() {
            let field = format!("filesystem.{kind}[{i}]");
            if paths[..i].contains(path) {
                finding(
                    out,
                    Severity::Warn,
                    &field,
                    format!("duplicate path {path:?}"),
                );
            } else if exposes_supervisor_state(path) {
                finding(
                    out,
                    Severity::Error,
                    &field,
                    format!(
                        "{path:?} contains the supervisor's state directory {SUPERVISOR_STATE_DIR}; the supervisor refuses to start (allow narrower paths)"
                    ),
                );
            }
        }
    }
    for (i, path) in fs.read_only.iter().enumerate() {
        if fs.read_write.contains(path) && !fs.read_only[..i].contains(path) {
            finding(
                out,
                Severity::Warn,
                &format!("filesystem.read_only[{i}]"),
                format!("{path:?} is also in read_write; read-write access wins"),
            );
        }
    }
}

/// Flags `[workspace]` settings whose effect is easy to misread.
fn lint_workspace(p: &Charter, out: &mut Vec<Finding>) {
    let Some(ws) = &p.workspace else {
        return;
    };
    if !ws.persist {
        return;
    }
    if ws.idle_timeout.trim().is_empty() {
        finding(
            out,
            Severity::Warn,
            "workspace.idle_timeout",
            "workspace.persist is set without workspace.idle_timeout; the Citadel keeps running until it is put to sleep or killed".into(),
        );
    } else if p.ide.enabled {
        finding(
            out,
            Severity::Warn,
            "workspace.idle_timeout",
            "Citadels with the browser IDE enabled never sleep on idle; workspace.idle_timeout has no effect".into(),
        );
    }
    if p.host.read_only {
        finding(
            out,
            Severity::Warn,
            "workspace.persist",
            "host.read_only mounts /tmp as tmpfs; only the workspace directory survives a sleep"
                .into(),
        );
    }
}

/// Flags `[process]` identities (falling back to `host.user`) the supervisor
/// refuses or that collide with reserved uids.
fn lint_governance_process(p: &Charter, out: &mut Vec<Finding>) {
    // The supervisor runs whenever either section is present.
    if p.process.is_none() && p.filesystem.is_none() {
        return;
    }
    let proc_ = p.process.clone().unwrap_or_default();
    let user = if proc_.run_as_user.is_empty() {
        if !proc_.run_as_group.is_empty() {
            finding(
                out,
                Severity::Warn,
                "process.run_as_group",
                "process.run_as_group is set without process.run_as_user; the agent's user falls back to host.user".into(),
            );
        }
        p.host.user.split(':').next().unwrap_or_default().to_owned()
    } else {
        proc_.run_as_user.clone()
    };
    if is_root_user(&user) {
        finding(
            out,
            Severity::Error,
            "process.run_as_user",
            "the agent would run as root (process.run_as_user and host.user are unset or root); the supervisor refuses to start — set process.run_as_user".into(),
        );
    }
    if p.network.strict_egress() && numeric_uid(&proc_.run_as_user) == Some(STRICT_PROXY_UID.into())
    {
        finding(
            out,
            Severity::Error,
            "process.run_as_user",
            format!(
                "uid {STRICT_PROXY_UID} is reserved for strict egress interception; choose a different uid"
            ),
        );
    }
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

    fn governed(f: impl FnOnce(&mut Charter)) -> Vec<Finding> {
        let mut p = Charter {
            host: Host {
                user: "1000".into(),
                ..img()
            },
            policy: allow_all(),
            ..Charter::default()
        };
        f(&mut p);
        lint_for(&p, None, "linux")
    }

    #[test]
    fn governance_sections_absent_add_nothing() {
        assert!(governed(|_| {}).is_empty());
    }

    #[test]
    fn workspace_findings() {
        use crate::Workspace;
        let f = governed(|p| {
            p.workspace = Some(Workspace {
                persist: true,
                idle_timeout: String::new(),
            });
        });
        assert!(has(&f, Severity::Warn, "workspace.idle_timeout"), "{f:?}");
        let f = governed(|p| {
            p.workspace = Some(Workspace {
                persist: true,
                idle_timeout: "15m".into(),
            });
        });
        assert!(f.is_empty(), "{f:?}");
        let f = governed(|p| {
            p.host.read_only = true;
            p.workspace = Some(Workspace {
                persist: true,
                idle_timeout: "15m".into(),
            });
        });
        assert!(has(&f, Severity::Warn, "workspace.persist"), "{f:?}");
        let f = governed(|p| {
            p.workspace = Some(Workspace::default());
        });
        assert!(f.is_empty(), "persist off adds nothing: {f:?}");
    }

    #[test]
    fn isolation_minimum_vs_runtime_class() {
        let f = governed(|p| p.isolation.minimum = "kernel".into());
        assert!(has(&f, Severity::Warn, "isolation.minimum"), "{f:?}");
        for rc in ["runsc", "gvisor", "runc", "crun"] {
            let f = governed(|p| {
                p.isolation.minimum = "vm".into();
                p.host.runtime_class = rc.into();
                p.host.read_only = true;
            });
            assert!(has(&f, Severity::Error, "isolation.minimum"), "{rc}: {f:?}");
        }
        // Kata always boots a hardware VM, so it claims vm (the evidence
        // still confirms it at create).
        for rc in ["kata", "kata-qemu", "kata-clh"] {
            let f = governed(|p| {
                p.isolation.minimum = "vm".into();
                p.host.runtime_class = rc.into();
                p.host.read_only = true;
            });
            assert!(f.is_empty(), "{rc}: {f:?}");
        }
        for (min, rc) in [
            ("kernel", "runsc"),
            ("kernel", "kata-qemu"),
            ("vm", "kata-clh"),
            ("container", ""),
            ("process", ""),
        ] {
            let f = governed(|p| {
                p.isolation.minimum = min.into();
                p.host.runtime_class = rc.into();
                p.host.read_only = true;
            });
            assert!(f.is_empty(), "{min} {rc}: {f:?}");
        }
    }

    #[test]
    fn host_runtime_as_oci_runtime() {
        // An OCI runtime in host.runtime is honoured, with a nudge.
        let f = governed(|p| {
            p.isolation.minimum = "vm".into();
            p.host.runtime = "kata-qemu".into();
            p.host.read_only = true;
        });
        assert!(has(&f, Severity::Warn, "host.runtime"), "{f:?}");
        assert!(!has(&f, Severity::Error, "isolation.minimum"), "{f:?}");
        let f = governed(|p| {
            p.isolation.minimum = "vm".into();
            p.host.runtime = "runsc".into();
            p.host.read_only = true;
        });
        assert!(has(&f, Severity::Error, "isolation.minimum"), "{f:?}");
        // Engine names stay the backend hint.
        let f = governed(|p| {
            p.host.runtime = "podman".into();
        });
        assert!(f.is_empty(), "{f:?}");
        // Two different runtimes is an error; the same one twice is fine.
        let f = governed(|p| {
            p.host.runtime = "kata-qemu".into();
            p.host.runtime_class = "kata-clh".into();
            p.host.read_only = true;
        });
        assert!(has(&f, Severity::Error, "host.runtime"), "{f:?}");
        let f = governed(|p| {
            p.host.runtime = "KATA-QEMU".into();
            p.host.runtime_class = "kata-qemu".into();
            p.host.read_only = true;
        });
        assert!(f.is_empty(), "{f:?}");
    }

    #[test]
    fn kata_fc_needs_kubernetes() {
        for rc in ["kata-fc", "io.containerd.kata-fc.v2", "aws.firecracker"] {
            let f = governed(|p| {
                p.isolation.minimum = "vm".into();
                p.host.runtime_class = rc.into();
                p.host.read_only = true;
            });
            assert!(
                has(&f, Severity::Error, "host.runtime_class"),
                "{rc}: {f:?}"
            );
            assert!(
                !has(&f, Severity::Error, "isolation.minimum"),
                "{rc}: {f:?}"
            );
            let f = governed(|p| {
                p.isolation.minimum = "vm".into();
                p.host.host_type = "k8s".into();
                p.host.runtime_class = rc.into();
                p.host.read_only = true;
            });
            assert!(f.is_empty(), "{rc}: {f:?}");
        }
    }

    #[test]
    fn microvm_runtime_on_desktop_engine_warns() {
        let charter = |rc: &str, host_type: &str| Charter {
            host: Host {
                user: "1000".into(),
                runtime_class: rc.into(),
                read_only: true,
                host_type: host_type.into(),
                ..img()
            },
            policy: allow_all(),
            ..Charter::default()
        };
        for os in ["macos", "windows"] {
            for rc in ["kata", "kata-qemu", "io.containerd.kata-clh.v2"] {
                let f = lint_for(&charter(rc, "container"), None, os);
                assert!(
                    has(&f, Severity::Warn, "host.runtime_class"),
                    "{os} {rc}: {f:?}"
                );
            }
            // gVisor needs no KVM; Kubernetes runs elsewhere.
            assert!(lint_for(&charter("runsc", "container"), None, os).is_empty());
            assert!(lint_for(&charter("kata-qemu", "k8s"), None, os).is_empty());
        }
        assert!(lint_for(&charter("kata-qemu", "container"), None, "linux").is_empty());
    }

    #[test]
    fn krun_is_refused_on_every_host() {
        for (host_type, rc) in [("container", "krun"), ("", "crun-krun"), ("k8s", "krun")] {
            let f = governed(|p| {
                p.isolation.minimum = "vm".into();
                p.host.host_type = host_type.into();
                p.host.runtime_class = rc.into();
                p.host.read_only = true;
            });
            assert!(
                f.iter().any(|x| x.severity == Severity::Error
                    && x.field == "host.runtime_class"
                    && x.message.contains("does not support exec")),
                "{host_type} {rc}: {f:?}"
            );
        }
    }

    #[test]
    fn firecracker_workspace_persist_warns_on_k8s() {
        let ws = || {
            Some(crate::Workspace {
                persist: true,
                idle_timeout: "15m".into(),
            })
        };
        let f = governed(|p| {
            p.host.host_type = "k8s".into();
            p.host.runtime_class = "kata-fc".into();
            p.host.read_only = true;
            p.workspace = ws();
        });
        // A warning: only the cluster knows whether a direct-volume
        // StorageClass makes it work; the backend refuses it otherwise.
        assert!(has(&f, Severity::Warn, "workspace.persist"), "{f:?}");
        assert!(!has(&f, Severity::Error, "workspace.persist"), "{f:?}");
        // With strict egress and the broker the Pod needs six drives.
        let f = governed(|p| {
            p.host.host_type = "k8s".into();
            p.host.runtime_class = "kata-fc".into();
            p.host.read_only = true;
            p.workspace = ws();
            p.network = crate::Network {
                default: "deny".into(),
                enforce: "strict".into(),
                ..crate::Network::default()
            };
            p.credentials.push(crate::Credential {
                name: "gh".into(),
                ..crate::Credential::default()
            });
        });
        assert!(has(&f, Severity::Error, "workspace.persist"), "{f:?}");
        // A non-persistent workspace and a shared-filesystem runtime are fine.
        let f = governed(|p| {
            p.host.host_type = "k8s".into();
            p.host.runtime_class = "kata-fc".into();
            p.host.read_only = true;
        });
        assert!(!has(&f, Severity::Error, "workspace.persist"), "{f:?}");
        let f = governed(|p| {
            p.host.host_type = "k8s".into();
            p.host.runtime_class = "kata-qemu".into();
            p.host.read_only = true;
            p.workspace = ws();
        });
        assert!(!has(&f, Severity::Error, "workspace.persist"), "{f:?}");
    }

    #[test]
    fn filesystem_findings() {
        use crate::Filesystem;
        let fs = |ro: &[&str], rw: &[&str], landlock: &str, workdir: bool| Filesystem {
            read_only: ro.iter().map(|s| (*s).to_owned()).collect(),
            read_write: rw.iter().map(|s| (*s).to_owned()).collect(),
            include_workdir: workdir,
            landlock: landlock.into(),
        };
        let cases = [
            (fs(&["/usr"], &["/tmp"], "", true), None),
            (
                fs(&["/usr"], &[], "off", true),
                Some((Severity::Warn, "filesystem.landlock")),
            ),
            (fs(&[], &[], "off", false), None),
            (
                fs(&[], &[], "required", false),
                Some((Severity::Error, "filesystem")),
            ),
            (
                fs(&["/"], &[], "", true),
                Some((Severity::Error, "filesystem.read_only[0]")),
            ),
            (
                fs(&["/usr"], &["/run/./x/.."], "", true),
                Some((Severity::Error, "filesystem.read_write[0]")),
            ),
            (
                fs(&["/usr", "/usr"], &[], "", true),
                Some((Severity::Warn, "filesystem.read_only[1]")),
            ),
            (
                fs(&["/srv"], &["/srv"], "", true),
                Some((Severity::Warn, "filesystem.read_only[0]")),
            ),
            (fs(&["/run/user"], &[], "", true), None),
        ];
        for (f, want) in cases {
            let label = format!("{f:?}");
            let got = governed(|p| p.filesystem = Some(f));
            match want {
                None => assert!(got.is_empty(), "{label}: {got:?}"),
                Some((sev, field)) => {
                    assert_eq!(got.len(), 1, "{label}: {got:?}");
                    assert!(has(&got, sev, field), "{label}: {got:?}");
                }
            }
        }
    }

    #[test]
    fn process_findings() {
        use crate::Process;
        let f = governed(|p| {
            p.host.user = String::new();
            p.filesystem = Some(crate::Filesystem::default());
        });
        assert!(has(&f, Severity::Error, "process.run_as_user"), "{f:?}");

        let f = governed(|p| {
            p.process = Some(Process {
                run_as_user: String::new(),
                run_as_group: "1500".into(),
            });
        });
        assert!(has(&f, Severity::Warn, "process.run_as_group"), "{f:?}");
        assert!(
            !has(&f, Severity::Error, "process.run_as_user"),
            "host.user 1000 is used"
        );

        let f = governed(|p| {
            p.network = Network {
                enforce: "strict".into(),
                ..deny_net(vec![rule("allow", "example.com", "")])
            };
            p.process = Some(Process {
                run_as_user: STRICT_PROXY_UID.to_string(),
                run_as_group: String::new(),
            });
        });
        assert!(has(&f, Severity::Error, "process.run_as_user"), "{f:?}");

        let f = governed(|p| {
            p.process = Some(Process {
                run_as_user: "1500".into(),
                run_as_group: String::new(),
            });
        });
        assert!(f.is_empty(), "{f:?}");
    }
}
