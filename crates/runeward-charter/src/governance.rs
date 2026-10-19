//! Charter sections that govern what happens *inside* the boundary:
//! filesystem and process confinement, an isolation floor, per-endpoint
//! request rules, and credentials that never enter the sandbox.
//!
//! Every section is optional and defaults to "not configured", so Charters
//! written before these sections existed load, lint and print unchanged.
//!
//! ```toml
//! [isolation]
//! minimum = "kernel"            # refuse to start on a weaker boundary
//!
//! [filesystem]
//! read_only = ["/usr", "/lib", "/etc"]
//! read_write = ["/tmp"]
//! landlock = "required"
//!
//! [process]
//! run_as_user = "1500"
//!
//! [[credential]]
//! name = "github"
//! source = "vault://kv/data/github#token"
//! placeholder_env = "GITHUB_TOKEN"
//! inject = "bearer"
//!
//! [[endpoint]]
//! name = "github-api"
//! host = "api.github.com"
//! protocol = "rest"
//! credential = "github"
//! binaries = ["/usr/bin/gh"]
//!   [[endpoint.allow]]
//!   method = "GET"
//!   path = "/repos/acme/**"
//!   effect = "read"
//!   [[endpoint.deny]]
//!   path = "/repos/acme/*/hooks/**"
//! ```

use serde::{Deserialize, Serialize};

/// Isolation boundaries, weakest first. The ordering is what a
/// [`Isolation::minimum`] floor compares against.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum IsolationLevel {
    /// A host process with in-process confinement only.
    Process,
    /// A shared-kernel container (runc, crun).
    Container,
    /// A user-space or dedicated kernel boundary (gVisor, Kata).
    Kernel,
    /// A hardware-virtualised microVM (libkrun, Firecracker).
    Vm,
}

impl IsolationLevel {
    /// Every level, weakest first.
    pub const ALL: [Self; 4] = [Self::Process, Self::Container, Self::Kernel, Self::Vm];

    /// The Charter spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Process => "process",
            Self::Container => "container",
            Self::Kernel => "kernel",
            Self::Vm => "vm",
        }
    }

    /// Parses the Charter spelling.
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|l| l.as_str() == s)
    }
}

/// `[isolation]`: the weakest boundary this Charter may run on.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Isolation {
    /// `process`, `container`, `kernel` or `vm`. A sandbox whose backend
    /// cannot prove at least this level is refused before anything runs.
    pub minimum: String,
}

impl Isolation {
    /// Reports whether no floor is configured.
    pub fn is_unset(&self) -> bool {
        self.minimum.is_empty()
    }

    /// The parsed floor, or `None` when unset.
    pub fn minimum_level(&self) -> Option<IsolationLevel> {
        IsolationLevel::parse(&self.minimum)
    }
}

/// `[filesystem]`: paths the agent may read or write, enforced with Landlock
/// inside the sandbox. Everything not listed is inaccessible.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Filesystem {
    pub read_only: Vec<String>,
    pub read_write: Vec<String>,
    /// Grants read-write on `host.workdir`. Defaults to true.
    pub include_workdir: bool,
    /// `best-effort` (default) degrades to the kernel's Landlock ABI;
    /// `required` refuses to start without full enforcement; `off` skips it.
    pub landlock: String,
}

impl Default for Filesystem {
    fn default() -> Self {
        Self {
            read_only: Vec::new(),
            read_write: Vec::new(),
            include_workdir: true,
            landlock: String::new(),
        }
    }
}

/// `[process]`: the identity the agent process runs as. Root is refused.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Process {
    pub run_as_user: String,
    pub run_as_group: String,
}

/// `[[credential]]`: a secret the egress broker attaches to matching requests.
/// The sandbox only ever sees an opaque placeholder.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Credential {
    pub name: String,
    /// A secret reference (`env://`, `vault://`, `aws://`, `gcp://`).
    pub source: String,
    /// Env var set inside the sandbox to the placeholder, so tools that
    /// expect a token find one.
    pub placeholder_env: String,
    /// `bearer` (default), `basic`, `header:<Name>` or `query:<param>`.
    pub inject: String,
}

/// `[[endpoint]]`: an upstream the agent may reach, with optional
/// request-level rules. Listing an endpoint also allows its host:port at the
/// network layer.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Endpoint {
    pub name: String,
    pub host: String,
    /// Defaults to 443.
    pub port: u16,
    /// `tcp` (default, no request inspection), `rest`, `websocket`, `mcp` or
    /// `json-rpc`.
    pub protocol: String,
    /// `enforce` (default) blocks; `audit` records what would be blocked.
    pub mode: String,
    /// Executables allowed to open this connection. Empty allows any.
    pub binaries: Vec<String>,
    /// Name of a `[[credential]]` to inject.
    pub credential: String,
    /// Calls allowed per session across all rules; 0 is unlimited.
    pub max_calls: u64,
    pub allow: Vec<RequestRule>,
    /// Deny rules always win over allow rules.
    pub deny: Vec<RequestRule>,
}

/// One request matcher on an [`Endpoint`]. Unset fields match anything.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RequestRule {
    /// HTTP method, or the JSON-RPC method for `mcp`/`json-rpc`.
    pub method: String,
    /// Path glob: `*` matches one segment, `**` any number.
    pub path: String,
    /// MCP tool name glob, for `tools/call`.
    pub tool: String,
    /// `read`, `write` or `irreversible`. Untagged MCP tools count as
    /// irreversible, which requires approval.
    pub effect: String,
    /// Calls allowed per session for this rule; 0 is unlimited.
    pub max_calls: u64,
    pub reason: String,
}

const PROTOCOLS: [&str; 5] = ["tcp", "rest", "websocket", "mcp", "json-rpc"];
const EFFECTS: [&str; 3] = ["read", "write", "irreversible"];

/// Checks the governance sections, returning the first problem as a message
/// in the same `field: problem` style as the rest of validation.
pub(crate) fn validate(
    isolation: &Isolation,
    filesystem: Option<&Filesystem>,
    process: Option<&Process>,
    credentials: &[Credential],
    endpoints: &[Endpoint],
) -> Result<(), String> {
    if !isolation.minimum.is_empty() && isolation.minimum_level().is_none() {
        return Err(format!(
            "isolation.minimum must be one of process, container, kernel, vm; got {:?}",
            isolation.minimum
        ));
    }
    if let Some(fs) = filesystem {
        if !matches!(
            fs.landlock.as_str(),
            "" | "best-effort" | "required" | "off"
        ) {
            return Err(format!(
                "filesystem.landlock must be \"best-effort\", \"required\" or \"off\", got {:?}",
                fs.landlock
            ));
        }
        for (field, paths) in [("read_only", &fs.read_only), ("read_write", &fs.read_write)] {
            if let Some(p) = paths.iter().find(|p| !p.starts_with('/')) {
                return Err(format!("filesystem.{field}: path {p:?} must be absolute"));
            }
        }
    }
    if let Some(p) = process {
        for (field, v) in [
            ("run_as_user", &p.run_as_user),
            ("run_as_group", &p.run_as_group),
        ] {
            if v == "0" || v == "root" {
                return Err(format!("process.{field}: running as root is not allowed"));
            }
        }
    }

    let mut names = std::collections::BTreeSet::new();
    for (i, c) in credentials.iter().enumerate() {
        if c.name.is_empty() {
            return Err(format!("credential[{i}]: missing name"));
        }
        if !names.insert(c.name.as_str()) {
            return Err(format!("credential[{i}]: duplicate name {:?}", c.name));
        }
        if !c.source.contains("://") {
            return Err(format!(
                "credential[{i}] ({}): source must be a secret reference such as env://NAME",
                c.name
            ));
        }
        let inject = c.inject.as_str();
        let ok = matches!(inject, "" | "bearer" | "basic")
            || inject
                .strip_prefix("header:")
                .is_some_and(|h| !h.is_empty())
            || inject.strip_prefix("query:").is_some_and(|q| !q.is_empty());
        if !ok {
            return Err(format!(
                "credential[{i}] ({}): inject must be bearer, basic, header:<Name> or query:<param>, got {inject:?}",
                c.name
            ));
        }
    }

    for (i, e) in endpoints.iter().enumerate() {
        let label = if e.name.is_empty() { &e.host } else { &e.name };
        if e.host.is_empty() {
            return Err(format!("endpoint[{i}]: missing host"));
        }
        if !e.protocol.is_empty() && !PROTOCOLS.contains(&e.protocol.as_str()) {
            return Err(format!(
                "endpoint[{i}] ({label}): protocol must be one of {}, got {:?}",
                PROTOCOLS.join(", "),
                e.protocol
            ));
        }
        if !matches!(e.mode.as_str(), "" | "enforce" | "audit") {
            return Err(format!(
                "endpoint[{i}] ({label}): mode must be \"enforce\" or \"audit\", got {:?}",
                e.mode
            ));
        }
        if !e.credential.is_empty() && !names.contains(e.credential.as_str()) {
            return Err(format!(
                "endpoint[{i}] ({label}): credential {:?} is not declared in [[credential]]",
                e.credential
            ));
        }
        let inspects = !matches!(e.protocol.as_str(), "" | "tcp");
        if !inspects && (!e.allow.is_empty() || !e.deny.is_empty()) {
            return Err(format!(
                "endpoint[{i}] ({label}): allow/deny rules need a protocol other than tcp"
            ));
        }
        for (kind, rules) in [("allow", &e.allow), ("deny", &e.deny)] {
            for (j, r) in rules.iter().enumerate() {
                if !r.effect.is_empty() && !EFFECTS.contains(&r.effect.as_str()) {
                    return Err(format!(
                        "endpoint[{i}].{kind}[{j}]: effect must be read, write or irreversible, got {:?}",
                        r.effect
                    ));
                }
                if !r.tool.is_empty() && e.protocol != "mcp" {
                    return Err(format!(
                        "endpoint[{i}].{kind}[{j}]: tool rules apply only to protocol \"mcp\""
                    ));
                }
                if !r.path.is_empty() && !r.path.starts_with('/') {
                    return Err(format!(
                        "endpoint[{i}].{kind}[{j}]: path {:?} must start with /",
                        r.path
                    ));
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse_bytes;

    const FULL: &str = r#"
[host]
type = "container"
image = "alpine"

[isolation]
minimum = "kernel"

[filesystem]
read_only = ["/usr"]
read_write = ["/tmp"]
landlock = "required"

[process]
run_as_user = "1500"

[[credential]]
name = "github"
source = "vault://kv/data/github#token"
placeholder_env = "GITHUB_TOKEN"

[[endpoint]]
name = "github-api"
host = "api.github.com"
protocol = "rest"
credential = "github"
binaries = ["/usr/bin/gh"]
  [[endpoint.allow]]
  method = "GET"
  path = "/repos/acme/**"
  effect = "read"
  [[endpoint.deny]]
  path = "/repos/acme/*/hooks/**"
"#;

    fn check(src: &str) -> Result<(), String> {
        let mut c = parse_bytes(src.as_bytes(), true).expect("parse");
        c.validate().map_err(|e| e.to_string())
    }

    #[test]
    fn parses_and_validates_every_section() {
        let mut c = parse_bytes(FULL.as_bytes(), true).expect("parse");
        c.validate().expect("valid");
        assert_eq!(c.isolation.minimum_level(), Some(IsolationLevel::Kernel));
        let fs = c.filesystem.as_ref().expect("filesystem");
        assert!(fs.include_workdir, "include_workdir defaults to true");
        assert_eq!(c.endpoints[0].allow[0].effect, "read");
        assert_eq!(c.credentials[0].placeholder_env, "GITHUB_TOKEN");
    }

    #[test]
    fn levels_order_weakest_first() {
        assert!(IsolationLevel::Process < IsolationLevel::Container);
        assert!(IsolationLevel::Kernel < IsolationLevel::Vm);
        assert_eq!(IsolationLevel::parse("vm"), Some(IsolationLevel::Vm));
        assert_eq!(IsolationLevel::parse("VM"), None);
    }

    #[test]
    fn rejects_bad_values() {
        let cases = [
            ("[isolation]\nminimum = \"strong\"", "isolation.minimum"),
            ("[filesystem]\nread_only = [\"usr\"]", "must be absolute"),
            ("[filesystem]\nlandlock = \"maybe\"", "filesystem.landlock"),
            ("[process]\nrun_as_user = \"0\"", "root"),
            (
                "[[credential]]\nname = \"x\"\nsource = \"plain\"",
                "secret reference",
            ),
            (
                "[[credential]]\nname = \"x\"\nsource = \"env://X\"\ninject = \"header:\"",
                "inject",
            ),
            ("[[endpoint]]\nhost = \"h\"\nprotocol = \"ftp\"", "protocol"),
            (
                "[[endpoint]]\nhost = \"h\"\ncredential = \"nope\"",
                "not declared",
            ),
            (
                "[[endpoint]]\nhost = \"h\"\n[[endpoint.allow]]\nmethod = \"GET\"",
                "need a protocol",
            ),
            (
                "[[endpoint]]\nhost = \"h\"\nprotocol = \"rest\"\n[[endpoint.allow]]\ntool = \"x\"",
                "only to protocol \"mcp\"",
            ),
            (
                "[[endpoint]]\nhost = \"h\"\nprotocol = \"mcp\"\n[[endpoint.deny]]\neffect = \"big\"",
                "effect",
            ),
        ];
        for (section, want) in cases {
            let src = format!("[host]\ntype = \"container\"\nimage = \"alpine\"\n{section}\n");
            let err = check(&src).expect_err(section);
            assert!(err.contains(want), "{section}: {err}");
        }
    }

    #[test]
    fn rejects_unknown_fields() {
        let src = "[host]\ntype = \"container\"\nimage = \"a\"\n[filesystem]\nreadonly = []\n";
        assert!(parse_bytes(src.as_bytes(), true).is_err());
    }
}
