//! Operator configuration read from `RUNEWARD_*` environment variables.
//!
//! The Go implementation reads these variables at the point of use. Here they
//! are captured once into a [`BackendConfig`] when a backend is built, which
//! keeps backends deterministic and lets tests inject values without mutating
//! the process environment.

use std::collections::BTreeMap;

/// Selects `docker` or `podman` (auto-detected when unset).
pub const CONTAINER_RUNTIME_ENV: &str = "RUNEWARD_CONTAINER_RUNTIME";
/// Default CPU cap (float cores; `0`/`off`/`none` disables).
pub const SANDBOX_CPUS_ENV: &str = "RUNEWARD_SANDBOX_CPUS";
/// Default memory cap (bytes or k/m/g/t suffix; `0`/`off`/`none` disables).
pub const SANDBOX_MEMORY_ENV: &str = "RUNEWARD_SANDBOX_MEMORY";
/// Default process cap (`0`/`off`/`none` disables).
pub const SANDBOX_PIDS_ENV: &str = "RUNEWARD_SANDBOX_PIDS";
/// Egress sidecar image.
pub const EGRESS_IMAGE_ENV: &str = "RUNEWARD_EGRESS_IMAGE";
/// Kubernetes pull policy for the egress sidecar (Always|Never|IfNotPresent).
pub const EGRESS_PULL_POLICY_ENV: &str = "RUNEWARD_EGRESS_PULL_POLICY";
/// DNS resolvers pinned inside the strict egress sidecar.
pub const DNS_RESOLVERS_ENV: &str = "RUNEWARD_DNS_RESOLVERS";
/// kubeconfig context to use.
pub const KUBE_CONTEXT_ENV: &str = "RUNEWARD_KUBE_CONTEXT";
/// Namespace for sandbox pods (default `runeward`).
pub const K8S_NAMESPACE_ENV: &str = "RUNEWARD_K8S_NAMESPACE";
/// Installs a default-deny NetworkPolicy when truthy.
pub const K8S_NETWORK_POLICY_ENV: &str = "RUNEWARD_K8S_NETWORK_POLICY";
/// Pod Security Admission enforce level (privileged|baseline|restricted).
pub const K8S_PSA_ENFORCE_ENV: &str = "RUNEWARD_K8S_PSA_ENFORCE";
/// Colon-separated allowlist of roots `copy_from` must live under.
pub const COPY_FROM_ROOTS_ENV: &str = "RUNEWARD_COPY_FROM_ROOTS";
/// Refuses absolute `[[file]]` projection targets when truthy.
pub const CONFINE_FILES_ENV: &str = "RUNEWARD_CONFINE_FILES";
/// `off` (or `0`/`false`/`no`) skips the in-sandbox isolation probe and
/// trusts runtime names; the evidence records `probe:disabled`.
pub const ISOLATION_PROBE_ENV: &str = "RUNEWARD_ISOLATION_PROBE";

const ALL_ENV: &[&str] = &[
    CONTAINER_RUNTIME_ENV,
    SANDBOX_CPUS_ENV,
    SANDBOX_MEMORY_ENV,
    SANDBOX_PIDS_ENV,
    EGRESS_IMAGE_ENV,
    EGRESS_PULL_POLICY_ENV,
    DNS_RESOLVERS_ENV,
    KUBE_CONTEXT_ENV,
    K8S_NAMESPACE_ENV,
    K8S_NETWORK_POLICY_ENV,
    K8S_PSA_ENFORCE_ENV,
    COPY_FROM_ROOTS_ENV,
    CONFINE_FILES_ENV,
    ISOLATION_PROBE_ENV,
];

/// The image used when neither the Charter nor the operator picks one.
pub const DEFAULT_IMAGE: &str = "debian:stable-slim";
/// The egress sidecar image used when `RUNEWARD_EGRESS_IMAGE` is unset.
pub const DEFAULT_EGRESS_IMAGE: &str = "runeward-egress:latest";
/// The Kubernetes namespace used when `RUNEWARD_K8S_NAMESPACE` is unset.
pub const DEFAULT_K8S_NAMESPACE: &str = "runeward";

/// Secure-by-default memory ceiling for a sandbox (4 GiB).
pub const FALLBACK_MEMORY_BYTES: i64 = 4 << 30;
/// Secure-by-default CPU ceiling for a sandbox (2 cores, in nano-CPUs).
pub const FALLBACK_NANO_CPUS: i64 = 2_000_000_000;
/// Secure-by-default process ceiling for a sandbox.
pub const FALLBACK_PIDS_LIMIT: i64 = 1024;

/// A snapshot of the `RUNEWARD_*` variables the backends honour.
///
/// Values are stored raw (as the operator wrote them); accessor methods apply
/// the same defaulting and parsing rules as the Go implementation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BackendConfig {
    vars: BTreeMap<String, String>,
}

impl BackendConfig {
    /// Reads the configuration from the process environment.
    pub fn from_env() -> Self {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    /// Builds a configuration from an arbitrary lookup (tests, embedding).
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Self {
        let vars = ALL_ENV
            .iter()
            .filter_map(|k| lookup(k).map(|v| ((*k).to_owned(), v)))
            .collect();
        Self { vars }
    }

    /// Builds a configuration from `(name, value)` pairs.
    pub fn from_pairs<'a>(pairs: impl IntoIterator<Item = (&'a str, &'a str)>) -> Self {
        let vars = pairs
            .into_iter()
            .map(|(k, v)| (k.to_owned(), v.to_owned()))
            .collect();
        Self { vars }
    }

    /// Returns a copy with `name` set to `value`.
    pub fn with(mut self, name: &str, value: &str) -> Self {
        self.vars.insert(name.to_owned(), value.to_owned());
        self
    }

    /// The raw value of `name`, or `""` when unset.
    pub fn raw(&self, name: &str) -> &str {
        self.vars.get(name).map(String::as_str).unwrap_or("")
    }

    /// `RUNEWARD_CONTAINER_RUNTIME`, trimmed and lowercased.
    pub fn container_runtime(&self) -> String {
        self.raw(CONTAINER_RUNTIME_ENV).trim().to_lowercase()
    }

    /// The default memory cap in bytes (0 = uncapped).
    pub fn default_memory_bytes(&self) -> i64 {
        limit_from_env(
            self.raw(SANDBOX_MEMORY_ENV),
            FALLBACK_MEMORY_BYTES,
            parse_size,
        )
    }

    /// The default CPU cap in nano-CPUs (0 = uncapped).
    pub fn default_nano_cpus(&self) -> i64 {
        limit_from_env(
            self.raw(SANDBOX_CPUS_ENV),
            FALLBACK_NANO_CPUS,
            |s| match s.parse::<f64>() {
                Ok(f) if f >= 0.0 => Some((f * 1e9) as i64),
                _ => None,
            },
        )
    }

    /// The default process cap (0 = uncapped).
    pub fn default_pids_limit(&self) -> i64 {
        limit_from_env(
            self.raw(SANDBOX_PIDS_ENV),
            FALLBACK_PIDS_LIMIT,
            |s| match s.parse::<i64>() {
                Ok(n) if n >= 0 => Some(n),
                _ => None,
            },
        )
    }

    /// The egress sidecar image.
    pub fn egress_image(&self) -> String {
        non_empty(self.raw(EGRESS_IMAGE_ENV), DEFAULT_EGRESS_IMAGE)
    }

    /// The Kubernetes pull policy for the egress sidecar.
    pub fn egress_pull_policy(&self) -> &'static str {
        match self.raw(EGRESS_PULL_POLICY_ENV) {
            "Always" => "Always",
            "Never" => "Never",
            _ => "IfNotPresent",
        }
    }

    /// The trimmed DNS resolver pin list (may be empty).
    pub fn dns_resolvers(&self) -> String {
        self.raw(DNS_RESOLVERS_ENV).trim().to_owned()
    }

    /// The kubeconfig context override, if any.
    pub fn kube_context(&self) -> Option<String> {
        let v = self.raw(KUBE_CONTEXT_ENV);
        (!v.is_empty()).then(|| v.to_owned())
    }

    /// The namespace sandbox pods live in.
    pub fn k8s_namespace(&self) -> String {
        non_empty(self.raw(K8S_NAMESPACE_ENV), DEFAULT_K8S_NAMESPACE)
    }

    /// Whether the default-deny NetworkPolicy is installed.
    pub fn k8s_network_policy(&self) -> bool {
        env_truthy(self.raw(K8S_NETWORK_POLICY_ENV))
    }

    /// The Pod Security Admission enforce level.
    pub fn psa_enforce_level(&self) -> &'static str {
        match self.raw(K8S_PSA_ENFORCE_ENV) {
            "restricted" => "restricted",
            "baseline" => "baseline",
            _ => "privileged",
        }
    }

    /// The trimmed `copy_from` root allowlist (empty = unrestricted).
    pub fn copy_from_roots(&self) -> &str {
        self.raw(COPY_FROM_ROOTS_ENV).trim()
    }

    /// Whether absolute `[[file]]` projections are refused.
    pub fn confine_files(&self) -> bool {
        env_truthy(self.raw(CONFINE_FILES_ENV))
    }

    /// Whether backends probe new sandboxes for isolation evidence (on
    /// unless `RUNEWARD_ISOLATION_PROBE` is `off`, `0`, `false` or `no`).
    pub fn isolation_probe(&self) -> bool {
        !matches!(
            self.raw(ISOLATION_PROBE_ENV)
                .trim()
                .to_ascii_lowercase()
                .as_str(),
            "off" | "0" | "false" | "no"
        )
    }
}

fn non_empty(v: &str, fallback: &str) -> String {
    if v.is_empty() { fallback } else { v }.to_owned()
}

/// Reports whether an env value should be treated as "on".
pub fn env_truthy(v: &str) -> bool {
    matches!(
        v.trim().to_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

/// Resolves a resource limit: `fallback` when unset, 0 (disabled) for
/// `0`/`off`/`none`, otherwise the parsed value; an unparseable value keeps
/// the fallback.
pub fn limit_from_env(raw: &str, fallback: i64, parse: impl Fn(&str) -> Option<i64>) -> i64 {
    let v = raw.trim();
    match v.to_lowercase().as_str() {
        "" => return fallback,
        "0" | "off" | "none" => return 0,
        _ => {}
    }
    parse(v).unwrap_or(fallback)
}

/// Parses a byte size with an optional base-2 k/m/g/t suffix (case
/// insensitive); a bare number is bytes.
pub fn parse_size(s: &str) -> Option<i64> {
    let s = s.trim();
    let last = s.chars().last()?;
    let (mult, num): (i64, &str) = match last {
        'k' | 'K' => (1 << 10, &s[..s.len() - 1]),
        'm' | 'M' => (1 << 20, &s[..s.len() - 1]),
        'g' | 'G' => (1 << 30, &s[..s.len() - 1]),
        't' | 'T' => (1 << 40, &s[..s.len() - 1]),
        _ => (1, s),
    };
    let n: i64 = num.trim().parse().ok()?;
    if n < 0 {
        return None;
    }
    n.checked_mul(mult)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_size_suffixes() {
        assert_eq!(parse_size("512"), Some(512));
        assert_eq!(parse_size("1k"), Some(1024));
        assert_eq!(parse_size("512m"), Some(512 << 20));
        assert_eq!(parse_size("2G"), Some(2 << 30));
        assert_eq!(parse_size(" 1t "), Some(1 << 40));
        assert_eq!(parse_size(""), None);
        assert_eq!(parse_size("-1"), None);
        assert_eq!(parse_size("lots"), None);
        assert_eq!(parse_size("1.5g"), None);
    }

    #[test]
    fn resource_defaults() {
        let c = BackendConfig::default();
        assert_eq!(c.default_memory_bytes(), 4 << 30);
        assert_eq!(c.default_nano_cpus(), 2_000_000_000);
        assert_eq!(c.default_pids_limit(), 1024);

        let off = BackendConfig::from_pairs([
            (SANDBOX_MEMORY_ENV, "off"),
            (SANDBOX_CPUS_ENV, "0"),
            (SANDBOX_PIDS_ENV, "NONE"),
        ]);
        assert_eq!(off.default_memory_bytes(), 0);
        assert_eq!(off.default_nano_cpus(), 0);
        assert_eq!(off.default_pids_limit(), 0);

        let set = BackendConfig::from_pairs([
            (SANDBOX_MEMORY_ENV, "1g"),
            (SANDBOX_CPUS_ENV, "0.5"),
            (SANDBOX_PIDS_ENV, "256"),
        ]);
        assert_eq!(set.default_memory_bytes(), 1 << 30);
        assert_eq!(set.default_nano_cpus(), 500_000_000);
        assert_eq!(set.default_pids_limit(), 256);

        let bad = BackendConfig::from_pairs([
            (SANDBOX_MEMORY_ENV, "lots"),
            (SANDBOX_CPUS_ENV, "-1"),
            (SANDBOX_PIDS_ENV, "-3"),
        ]);
        assert_eq!(bad.default_memory_bytes(), 4 << 30);
        assert_eq!(bad.default_nano_cpus(), 2_000_000_000);
        assert_eq!(bad.default_pids_limit(), 1024);
    }

    #[test]
    fn isolation_probe_toggle() {
        assert!(BackendConfig::default().isolation_probe());
        for v in ["off", "OFF", "0", "false", "no"] {
            let c = BackendConfig::from_pairs([(ISOLATION_PROBE_ENV, v)]);
            assert!(!c.isolation_probe(), "{v}");
        }
        let c = BackendConfig::from_pairs([(ISOLATION_PROBE_ENV, "on")]);
        assert!(c.isolation_probe());
    }

    #[test]
    fn k8s_settings() {
        let c = BackendConfig::default();
        assert_eq!(c.k8s_namespace(), "runeward");
        assert_eq!(c.psa_enforce_level(), "privileged");
        assert_eq!(c.egress_pull_policy(), "IfNotPresent");
        assert_eq!(c.egress_image(), "runeward-egress:latest");
        assert!(!c.k8s_network_policy());
        assert!(c.kube_context().is_none());

        let c = BackendConfig::from_pairs([
            (K8S_NAMESPACE_ENV, "sbx"),
            (K8S_PSA_ENFORCE_ENV, "restricted"),
            (EGRESS_PULL_POLICY_ENV, "Never"),
            (K8S_NETWORK_POLICY_ENV, " Yes "),
            (KUBE_CONTEXT_ENV, "kind"),
        ]);
        assert_eq!(c.k8s_namespace(), "sbx");
        assert_eq!(c.psa_enforce_level(), "restricted");
        assert_eq!(c.egress_pull_policy(), "Never");
        assert!(c.k8s_network_policy());
        assert_eq!(c.kube_context().as_deref(), Some("kind"));
        // Pull policy and PSA level are case-sensitive, as in Go.
        let c = BackendConfig::from_pairs([
            (EGRESS_PULL_POLICY_ENV, "never"),
            (K8S_PSA_ENFORCE_ENV, "Baseline"),
        ]);
        assert_eq!(c.egress_pull_policy(), "IfNotPresent");
        assert_eq!(c.psa_enforce_level(), "privileged");
    }

    #[test]
    fn from_lookup_reads_only_known_names() {
        let c = BackendConfig::from_lookup(|k| Some(format!("v-{k}")));
        assert_eq!(c.raw(EGRESS_IMAGE_ENV), "v-RUNEWARD_EGRESS_IMAGE");
        assert_eq!(c.raw("PATH"), "");
    }
}
