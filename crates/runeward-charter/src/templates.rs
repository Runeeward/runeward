//! Ready-made Charter snippets for common security controls.
//!
//! Each template is a complete, valid slice of Charter TOML (policy rules,
//! network allowlists or host hardening) that decodes strictly into a
//! [`Charter`](crate::Charter), so it can be pasted straight into a Charter
//! file instead of authoring policy from scratch.

/// A named, ready-to-paste Charter snippet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Template {
    /// Short, stable identifier used for lookup.
    pub name: &'static str,
    /// One-line human label.
    pub title: &'static str,
    /// What the snippet enforces and when to reach for it.
    pub description: &'static str,
    /// The Charter body, with explanatory comments.
    pub toml: &'static str,
}

/// An unknown template name was requested.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("policytemplates: unknown template {0:?}")]
pub struct UnknownTemplate(pub String);

/// The registry, kept sorted by name so lookups and listings are
/// deterministic.
const TEMPLATES: &[Template] = &[
    Template {
        name: "block-prod",
        title: "Block production-mutating actions",
        description: "Deny terraform/kubectl commands that mutate production, refuse egress to prod-looking hosts, and require approval for recursive force deletes.",
        toml: r#"# block-prod — refuse production-mutating commands and egress to prod hosts.
# Paste these rules into a profile. They use match_argv (a glob on argv[0], the
# executable) so wrappers like `sh -c 'terraform ...'` or an absolute
# path such as /usr/local/bin/terraform cannot slip past a match on the joined
# command line. Builtin rules are first-match, so the specific denials below win.

# Terraform state mutations are blocked outright; run plans, not applies.
[[policy]]
tool       = "shell"
match_argv = "*terraform"
match      = "*apply*"
verdict    = "deny"
reason     = "terraform apply is blocked by policy; use plan only"

[[policy]]
tool       = "shell"
match_argv = "*terraform"
match      = "*destroy*"
verdict    = "deny"
reason     = "terraform destroy is blocked by policy"

# kubectl against a prod context or namespace is denied.
[[policy]]
tool       = "shell"
match_argv = "*kubectl"
match      = "*prod*"
verdict    = "deny"
reason     = "kubectl against prod contexts is blocked"

# Recursive force deletes always need a human in the loop.
[[policy]]
tool       = "shell"
match_argv = "*rm"
match      = "*-rf*"
verdict    = "require-approval"
reason     = "recursive force delete must be reviewed"

# Egress to production-looking hosts is refused. Egress rules are first-match,
# so keep this deny rule before any allowlist entries you add later.
[network]
default = "deny"

[[network.rule]]
verdict  = "deny"
hostname = "*.prod.internal"

[[network.rule]]
verdict  = "deny"
hostname = "*.prod.svc"

[[network.rule]]
verdict  = "deny"
hostname = "prod.*"
"#,
    },
    Template {
        name: "least-privilege-egress",
        title: "Least-privilege egress allowlist",
        description: "Deny-by-default egress with a couple of example allow rules and comments showing how to extend the allowlist.",
        toml: r#"# least-privilege-egress — start from deny-by-default egress and open only what
# the task needs. Add one [[network.rule]] per destination. Hostnames support
# *.wildcards; use one rule per hostname and cidr for IP ranges.

[network]
default = "deny"

# enforce = "strict" adds kernel-level iptables redirection on the k8s backend
# (the default cooperative HTTP(S)_PROXY is bypassable). Ignored by docker.
enforce = "strict"

# Example: reach a model API.
[[network.rule]]
verdict  = "allow"
hostname = "api.openai.com"

# Example: allow a whole CDN via wildcard.
[[network.rule]]
verdict  = "allow"
hostname = "*.githubusercontent.com"

# Example: allow an internal IP range by CIDR (uncomment and edit).
# [[network.rule]]
# verdict = "allow"
# cidr    = "10.0.0.0/8"
"#,
    },
    Template {
        name: "package-approval",
        title: "Require approval for package installs",
        description: "Require a human to approve apt/apt-get/npm/pip/pipx/go install commands, and allow everything else to run.",
        toml: r#"# package-approval — let commands run freely but require a human to approve any
# package installation. match_argv pins the executable (argv[0]) so wrappers and
# absolute paths still match; the trailing allow rule lets everything else run.
# Builtin rules are first-match, so keep the broad allow rule last.

[[policy]]
tool       = "shell"
match_argv = "*apt-get"
match      = "*install*"
verdict    = "require-approval"
reason     = "apt-get install must be approved"

[[policy]]
tool       = "shell"
match_argv = "*apt"
match      = "*install*"
verdict    = "require-approval"
reason     = "apt install must be approved"

[[policy]]
tool       = "shell"
match_argv = "*npm"
match      = "*install*"
verdict    = "require-approval"
reason     = "npm install must be approved"

[[policy]]
tool       = "shell"
match_argv = "*pip"
match      = "*install*"
verdict    = "require-approval"
reason     = "pip install must be approved"

[[policy]]
tool       = "shell"
match_argv = "*pipx"
match      = "*install*"
verdict    = "require-approval"
reason     = "pipx install must be approved"

[[policy]]
tool       = "shell"
match_argv = "*go"
match      = "install*"
verdict    = "require-approval"
reason     = "go install must be approved"

# Anything that is not a package install is allowed through.
[[policy]]
tool    = "shell"
match   = "*"
verdict = "allow"
"#,
    },
    Template {
        name: "pii-egress",
        title: "Lock down egress and sensitive writes for PII tasks",
        description: "Deny-by-default network with a tiny allowlist, plus require-approval on writes to credential and key-material paths.",
        toml: r#"# pii-egress — lock egress to a tiny allowlist and gate writes to sensitive
# paths. Use for tasks that touch PII: nothing leaves the sandbox except the
# hosts you name, and any write to secret or credential material pauses for a
# human to approve.

[network]
default = "deny"

# Only these destinations are reachable; everything else is dropped.
[[network.rule]]
verdict  = "allow"
hostname = "api.openai.com"

[[network.rule]]
verdict  = "allow"
hostname = "api.anthropic.com"

[[network.rule]]
verdict  = "allow"
hostname = "*.githubusercontent.com"

# Writes to key material and cloud credentials must be approved.
[[policy]]
tool    = "file.write"
match   = "**/.ssh/*"
verdict = "require-approval"
reason  = "write to SSH key material must be reviewed"

[[policy]]
tool    = "file.write"
match   = "**/.aws/*"
verdict = "require-approval"
reason  = "write to AWS credentials must be reviewed"

[[policy]]
tool    = "file.write"
match   = "/etc/*"
verdict = "require-approval"
reason  = "write outside the workspace must be reviewed"
"#,
    },
    Template {
        name: "read-only-fs",
        title: "Read-only root filesystem",
        description: "Mount the root filesystem read-only, deny writes outside the workspace, and block chmod/chown escalation.",
        toml: r#"# read-only-fs — mount the root filesystem read-only and keep writes confined to
# the workspace. Only /workspace (and the runtime's writable /tmp) may be
# written; permission and ownership escalation is refused. Builtin rules are
# first-match, so the explicit workspace allow comes before the broad deny.

[host]
# Mount the container root filesystem read-only. /tmp and /workspace stay
# writable; workloads that must write elsewhere have to opt out.
read_only = true

# The workspace is the only writable tree; allow it explicitly first.
[[policy]]
tool    = "file.write"
match   = "/workspace/**"
verdict = "allow"
reason  = "the workspace is the only writable location"

# Any other write is refused on a read-only filesystem.
[[policy]]
tool    = "file.write"
match   = "*"
verdict = "deny"
reason  = "root filesystem is read-only; write inside /workspace"

# Permission and ownership escalation is blocked regardless of wrapper or path.
[[policy]]
tool       = "shell"
match_argv = "*chmod"
match      = "*"
verdict    = "deny"
reason     = "chmod escalation is blocked on a read-only filesystem"

[[policy]]
tool       = "shell"
match_argv = "*chown"
match      = "*"
verdict    = "deny"
reason     = "chown escalation is blocked on a read-only filesystem"
"#,
    },
];

/// Returns the template names in sorted order.
pub fn names() -> Vec<&'static str> {
    TEMPLATES.iter().map(|t| t.name).collect()
}

/// Returns the template registered under `name`.
pub fn get(name: &str) -> Option<&'static Template> {
    TEMPLATES.iter().find(|t| t.name == name)
}

/// Returns the TOML body for the named template.
pub fn render(name: &str) -> Result<&'static str, UnknownTemplate> {
    get(name)
        .map(|t| t.toml)
        .ok_or_else(|| UnknownTemplate(name.to_owned()))
}

/// Returns every template, sorted by name.
pub fn all() -> &'static [Template] {
    TEMPLATES
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every template is valid Charter TOML with no typo'd keys.
    #[test]
    fn render_unmarshals_strict() {
        for name in names() {
            let body = render(name).expect("render");
            assert!(!body.trim().is_empty(), "{name} is empty");
            if let Err(e) = crate::parse_bytes(body.as_bytes(), true) {
                panic!("template {name} does not decode strictly: {e}\n---\n{body}");
            }
        }
    }

    #[test]
    fn get_matches_render() {
        for name in names() {
            let t = get(name).expect("registered");
            assert_eq!(t.name, name);
            assert!(!t.title.is_empty() && !t.description.is_empty());
            assert_eq!(render(name), Ok(t.toml));
        }
    }

    #[test]
    fn names_sorted() {
        let n = names();
        assert!(n.len() >= 5);
        assert!(n.is_sorted(), "{n:?}");
    }

    #[test]
    fn unknown_name() {
        assert!(get("does-not-exist").is_none());
        assert_eq!(
            render("does-not-exist").expect_err("must fail").to_string(),
            r#"policytemplates: unknown template "does-not-exist""#
        );
    }

    #[test]
    fn all_covers_registry() {
        assert!(all().windows(2).all(|w| w[0].name < w[1].name));
        assert_eq!(
            names(),
            [
                "block-prod",
                "least-privilege-egress",
                "package-approval",
                "pii-egress",
                "read-only-fs",
            ]
        );
    }

    #[test]
    fn block_prod_documents_first_match_egress() {
        let body = render("block-prod").expect("render");
        assert!(!body.contains("Deny rules are evaluated\n# before any allow rules"));
        assert!(body.contains("Egress rules are first-match"));
    }
}
