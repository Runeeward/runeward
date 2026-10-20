//! The pure admission decision over a ClusterPolicy snapshot.

use serde_json::Value;
use std::collections::BTreeMap;

/// The enforceable fields of a ClusterPolicy spec as a plain value type, so
/// the decision logic can be tested without a cluster. The profile/namespace
/// lists are glob patterns; empty means no constraint.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Policy {
    /// If non-empty, the effective profile must match at least one pattern.
    pub allowed_profiles: Vec<String>,
    /// If any pattern matches the effective profile the request is rejected.
    pub denied_profiles: Vec<String>,
    /// If non-empty, a namespaced resource's namespace must match one pattern.
    pub allowed_namespaces: Vec<String>,
    /// Label keys that must be present on the resource.
    pub required_labels: Vec<String>,
    /// Applied (mutating) when `spec.profile` is empty.
    pub default_profile: String,
}

impl Policy {
    /// Extracts a [`Policy`] from a ClusterPolicy object (as JSON) with the
    /// same leniency as the unstructured accessors the Go webhook used: a list
    /// holding any non-string element, or a non-string `defaultProfile`, is
    /// treated as absent rather than failing the whole snapshot.
    pub fn from_object(obj: &Value) -> Self {
        let spec = obj.get("spec");
        let list = |key: &str| nested_string_slice(spec.and_then(|s| s.get(key)));
        Self {
            allowed_profiles: list("allowedProfiles"),
            denied_profiles: list("deniedProfiles"),
            allowed_namespaces: list("allowedNamespaces"),
            required_labels: list("requiredLabels"),
            default_profile: spec
                .and_then(|s| s.get("defaultProfile"))
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
        }
    }
}

fn nested_string_slice(v: Option<&Value>) -> Vec<String> {
    let Some(Value::Array(items)) = v else {
        return Vec::new();
    };
    items
        .iter()
        .map(|i| i.as_str().map(str::to_owned))
        .collect::<Option<Vec<_>>>()
        .unwrap_or_default()
}

/// The outcome of [`decide`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    /// Whether the request is admitted.
    pub allowed: bool,
    /// The effective profile (the incoming one, or the applied default). The
    /// caller patches it in when it differs from the incoming profile.
    pub profile: String,
    /// Why the request was denied; empty when allowed.
    pub reason: String,
}

/// Evaluates an admission request against every policy. If `profile` is
/// empty, the first policy with a default profile supplies it; the effective
/// profile, namespace and labels are then validated, first violation wins.
pub fn decide(
    policies: &[Policy],
    namespace: &str,
    labels: &BTreeMap<String, String>,
    profile: &str,
) -> Decision {
    let mut effective = profile.to_owned();
    if effective.is_empty()
        && let Some(p) = policies.iter().find(|p| !p.default_profile.is_empty())
    {
        effective = p.default_profile.clone();
    }
    let deny = |reason: String, effective: String| Decision {
        allowed: false,
        profile: effective,
        reason,
    };

    for p in policies {
        // Denied profiles take precedence over allowed.
        if let Some(pat) = p
            .denied_profiles
            .iter()
            .find(|pat| match_glob(pat, &effective))
        {
            let reason = format!(
                "profile {} is denied by cluster policy (matched {})",
                quote(&effective),
                quote(pat)
            );
            return deny(reason, effective);
        }
        if !p.allowed_profiles.is_empty() && !match_any(&p.allowed_profiles, &effective) {
            let reason = format!(
                "profile {} is not in the cluster policy allowed list",
                quote(&effective)
            );
            return deny(reason, effective);
        }
        // Cluster-scoped resources (empty namespace) skip the namespace
        // allowlist.
        if !namespace.is_empty()
            && !p.allowed_namespaces.is_empty()
            && !match_any(&p.allowed_namespaces, namespace)
        {
            let reason = format!(
                "namespace {} is not permitted by cluster policy",
                quote(namespace)
            );
            return deny(reason, effective);
        }
        if let Some(key) = p.required_labels.iter().find(|k| !labels.contains_key(*k)) {
            let reason = format!("required label {} is missing (cluster policy)", quote(key));
            return deny(reason, effective);
        }
    }

    Decision {
        allowed: true,
        profile: effective,
        reason: String::new(),
    }
}

fn match_any(patterns: &[String], s: &str) -> bool {
    patterns.iter().any(|p| match_glob(p, s))
}

fn quote(s: &str) -> String {
    format!("\"{s}\"")
}

/// Reports whether `s` matches `pattern` as an anchored, full-string glob.
/// `*` matches any run of bytes and `?` exactly one byte, both including `/`.
/// Matching is byte-wise, as in the Go original, so `?` does not match a
/// multi-byte UTF-8 character.
pub fn match_glob(pattern: &str, s: &str) -> bool {
    let (p, s) = (pattern.as_bytes(), s.as_bytes());
    let (mut si, mut pi) = (0usize, 0usize);
    let mut star: Option<usize> = None;
    let mut star_mark = 0usize;
    while si < s.len() {
        if pi < p.len() && (p[pi] == b'?' || p[pi] == s[si]) {
            si += 1;
            pi += 1;
        } else if pi < p.len() && p[pi] == b'*' {
            star = Some(pi);
            star_mark = si;
            pi += 1;
        } else if let Some(st) = star {
            pi = st + 1;
            star_mark += 1;
            si = star_mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == b'*' {
        pi += 1;
    }
    pi == p.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| (*x).to_owned()).collect()
    }

    fn labels(kv: &[(&str, &str)]) -> BTreeMap<String, String> {
        kv.iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    #[test]
    fn decide_table() {
        struct Case {
            name: &'static str,
            policies: Vec<Policy>,
            namespace: &'static str,
            labels: BTreeMap<String, String>,
            profile: &'static str,
            want_allowed: bool,
            want_profile: &'static str,
        }
        let p = Policy::default;
        let cases = vec![
            Case {
                name: "no policies allows anything",
                policies: vec![],
                namespace: "",
                labels: labels(&[]),
                profile: "anything",
                want_allowed: true,
                want_profile: "anything",
            },
            Case {
                name: "allowed profile matches glob",
                policies: vec![Policy {
                    allowed_profiles: s(&["team-*"]),
                    ..p()
                }],
                namespace: "",
                labels: labels(&[]),
                profile: "team-web",
                want_allowed: true,
                want_profile: "team-web",
            },
            Case {
                name: "deny by denied profile",
                policies: vec![Policy {
                    denied_profiles: s(&["*-root"]),
                    ..p()
                }],
                namespace: "",
                labels: labels(&[]),
                profile: "prod-root",
                want_allowed: false,
                want_profile: "prod-root",
            },
            Case {
                name: "deny when not in allowed list",
                policies: vec![Policy {
                    allowed_profiles: s(&["team-*"]),
                    ..p()
                }],
                namespace: "",
                labels: labels(&[]),
                profile: "rogue",
                want_allowed: false,
                want_profile: "rogue",
            },
            Case {
                name: "namespace restriction rejects",
                policies: vec![Policy {
                    allowed_namespaces: s(&["apps-*"]),
                    ..p()
                }],
                namespace: "kube-system",
                labels: labels(&[]),
                profile: "p",
                want_allowed: false,
                want_profile: "p",
            },
            Case {
                name: "namespace restriction allows match",
                policies: vec![Policy {
                    allowed_namespaces: s(&["apps-*"]),
                    ..p()
                }],
                namespace: "apps-prod",
                labels: labels(&[]),
                profile: "p",
                want_allowed: true,
                want_profile: "p",
            },
            Case {
                name: "required label missing rejects",
                policies: vec![Policy {
                    required_labels: s(&["team"]),
                    ..p()
                }],
                namespace: "",
                labels: labels(&[("env", "prod")]),
                profile: "p",
                want_allowed: false,
                want_profile: "p",
            },
            Case {
                name: "required label present allows",
                policies: vec![Policy {
                    required_labels: s(&["team"]),
                    ..p()
                }],
                namespace: "",
                labels: labels(&[("team", "web")]),
                profile: "p",
                want_allowed: true,
                want_profile: "p",
            },
            Case {
                name: "defaulting sets profile",
                policies: vec![Policy {
                    default_profile: "baseline".into(),
                    ..p()
                }],
                namespace: "",
                labels: labels(&[]),
                profile: "",
                want_allowed: true,
                want_profile: "baseline",
            },
            Case {
                name: "defaulting then validated against allowed list",
                policies: vec![Policy {
                    default_profile: "baseline".into(),
                    allowed_profiles: s(&["baseline", "team-*"]),
                    ..p()
                }],
                namespace: "",
                labels: labels(&[]),
                profile: "",
                want_allowed: true,
                want_profile: "baseline",
            },
            Case {
                name: "first default wins across policies",
                policies: vec![
                    p(),
                    Policy {
                        default_profile: "second".into(),
                        ..p()
                    },
                ],
                namespace: "",
                labels: labels(&[]),
                profile: "",
                want_allowed: true,
                want_profile: "second",
            },
            Case {
                name: "denied wins over allowed in same policy",
                policies: vec![Policy {
                    allowed_profiles: s(&["team-*"]),
                    denied_profiles: s(&["team-secret"]),
                    ..p()
                }],
                namespace: "",
                labels: labels(&[]),
                profile: "team-secret",
                want_allowed: false,
                want_profile: "team-secret",
            },
            Case {
                name: "must satisfy every policy",
                policies: vec![
                    Policy {
                        allowed_profiles: s(&["team-*"]),
                        ..p()
                    },
                    Policy {
                        denied_profiles: s(&["team-legacy"]),
                        ..p()
                    },
                ],
                namespace: "",
                labels: labels(&[]),
                profile: "team-legacy",
                want_allowed: false,
                want_profile: "team-legacy",
            },
        ];
        for c in cases {
            let d = decide(&c.policies, c.namespace, &c.labels, c.profile);
            assert_eq!(
                d.allowed, c.want_allowed,
                "{}: allowed (reason={:?})",
                c.name, d.reason
            );
            assert_eq!(d.profile, c.want_profile, "{}: profile", c.name);
            if !d.allowed {
                assert!(
                    !d.reason.is_empty(),
                    "{}: denied decision must include a reason",
                    c.name
                );
            }
        }
    }

    #[test]
    fn glob() {
        for (pattern, s, want) in [
            ("*", "anything", true),
            ("team-*", "team-web", true),
            ("team-*", "other", false),
            ("prod-?", "prod-1", true),
            ("prod-?", "prod-12", false),
            ("exact", "exact", true),
            ("exact", "exactly", false),
            ("a/*/c", "a/b/c", true),
            ("prod-?", "prod-\u{e9}", false),
            ("prod-??", "prod-\u{e9}", true),
            ("*a*b", "xaxxb", true),
            ("", "", true),
            ("", "x", false),
            ("**", "", true),
        ] {
            assert_eq!(
                match_glob(pattern, s),
                want,
                "match_glob({pattern:?}, {s:?})"
            );
        }
    }

    #[test]
    fn policy_from_object_is_lenient() {
        let p = Policy::from_object(&serde_json::json!({
            "spec": {
                "allowedProfiles": ["a", 3],
                "deniedProfiles": ["d"],
                "allowedNamespaces": "not-a-list",
                "requiredLabels": ["team"],
                "defaultProfile": 7
            }
        }));
        assert_eq!(
            p,
            Policy {
                allowed_profiles: vec![],
                denied_profiles: s(&["d"]),
                allowed_namespaces: vec![],
                required_labels: s(&["team"]),
                default_profile: String::new(),
            }
        );
        assert_eq!(
            Policy::from_object(&serde_json::json!({})),
            Policy::default()
        );
    }
}
