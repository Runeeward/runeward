//! Building the authority engine a Charter selects.

use std::path::PathBuf;

use runeward_charter::{CelRule, Charter, Verdict};
use runeward_policybundle::{self as policybundle, Bundle, Engine as BundleEngine, PullOptions};
use serde::Deserialize;

use crate::cel::{CelEngine, CelError};
use crate::decision::Evaluator;
use crate::rego::{RegoEngine, RegoError};
use crate::rules::RuleEngine;

/// Environment variable consulted for the no-match verdict when a Charter
/// leaves `policy_default` unset.
pub const POLICY_DEFAULT_ENV: &str = "RUNEWARD_POLICY_DEFAULT";

/// An engine could not be built from a Charter.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BuildError {
    /// CEL rules failed to compile.
    #[error(transparent)]
    Cel(#[from] CelError),
    /// The Rego module failed to prepare.
    #[error(transparent)]
    Rego(#[from] RegoError),
    /// `rego.file` could not be read.
    #[error("read rego policy {path:?}: {source}")]
    ReadRego {
        /// The path as written in the Charter.
        path: String,
        /// The I/O failure.
        #[source]
        source: std::io::Error,
    },
    /// The Charter sources its policy from an OCI bundle, which needs
    /// [`engine_for_charter_with_bundle`] (a network pull).
    #[error(
        "profile {name:?} sources its policy from an OCI policy bundle ({reference}); use the bundle-aware constructor"
    )]
    BundleRequiresPull {
        /// The Charter name.
        name: String,
        /// The bundle reference.
        reference: String,
    },
    /// The bundle has no verify key and `insecure_skip_verify` is not set.
    #[error(
        "policy bundle {reference:?}: verify_key is required; set policy_bundle.verify_key, or set insecure_skip_verify=true to explicitly accept an unsigned bundle"
    )]
    BundleVerifyKeyRequired {
        /// The bundle reference.
        reference: String,
    },
    /// The bundle's verify key is malformed.
    #[error("policy bundle: {0}")]
    BundleKey(#[source] policybundle::Error),
    /// Pulling or verifying the bundle failed.
    #[error("policy bundle {reference:?}: {source}")]
    BundlePull {
        /// The bundle reference.
        reference: String,
        /// The pull failure.
        #[source]
        source: policybundle::Error,
    },
    /// A CEL bundle's TOML fragment did not parse.
    #[error("policy bundle {reference:?}: parse cel fragment: {message}")]
    BundleCelFragment {
        /// The bundle reference.
        reference: String,
        /// The TOML error.
        message: String,
    },
}

/// The verdict for actions no rule matches: the Charter's `policy_default`
/// (`allow`/`deny`, case-insensitive), else the `env_default` value (normally
/// [`POLICY_DEFAULT_ENV`]), else allow.
pub fn no_match_verdict(charter: Option<&Charter>, env_default: Option<&str>) -> Verdict {
    let pick = |s: &str| match s.trim().to_ascii_lowercase().as_str() {
        "deny" => Some(Verdict::Deny),
        "allow" => Some(Verdict::Allow),
        _ => None,
    };
    charter
        .and_then(|c| pick(c.policy_default.as_str()))
        .or_else(|| env_default.and_then(pick))
        .unwrap_or(Verdict::Allow)
}

/// [`no_match_verdict`] reading [`POLICY_DEFAULT_ENV`] from the process
/// environment.
pub fn no_match_verdict_from_env(charter: Option<&Charter>) -> Verdict {
    no_match_verdict(charter, std::env::var(POLICY_DEFAULT_ENV).ok().as_deref())
}

/// Builds the inline engine a Charter selects: Rego or CEL when requested,
/// otherwise the built-in rules, with `default` as the no-match verdict.
///
/// A Charter that uses a policy bundle is refused with
/// [`BuildError::BundleRequiresPull`]; offline tools (simulation, `policy
/// test`) surface that, and the control plane calls
/// [`engine_for_charter_with_bundle`] instead.
pub fn engine_for_charter(
    charter: &Charter,
    default: Verdict,
) -> Result<Box<dyn Evaluator>, BuildError> {
    if charter.uses_policy_bundle() {
        return Err(BuildError::BundleRequiresPull {
            name: charter.name.clone(),
            reference: charter
                .policy_bundle
                .as_ref()
                .map(|b| b.r#ref.clone())
                .unwrap_or_default(),
        });
    }
    if charter.uses_rego() {
        let mut module = charter.rego.module.clone();
        if module.is_empty() && !charter.rego.file.is_empty() {
            let path = expand_home(&charter.rego.file);
            module = std::fs::read_to_string(&path).map_err(|source| BuildError::ReadRego {
                path: charter.rego.file.clone(),
                source,
            })?;
        }
        return Ok(Box::new(RegoEngine::new(
            &module,
            &charter.rego.query,
            default,
        )?));
    }
    if charter.uses_cel() {
        return Ok(Box::new(CelEngine::new(&charter.cel, default)?));
    }
    Ok(Box::new(RuleEngine::new(charter.policy.clone(), default)))
}

/// Like [`engine_for_charter`], but pulls a Charter's OCI policy bundle.
///
/// With `verify_key` set the bundle's ed25519 signature is required before
/// its policy is trusted. Without one the Charter must explicitly set
/// `insecure_skip_verify` (logged as a warning); otherwise this fails closed.
pub async fn engine_for_charter_with_bundle(
    charter: &Charter,
    default: Verdict,
) -> Result<Box<dyn Evaluator>, BuildError> {
    let Some(pb) = charter
        .policy_bundle
        .as_ref()
        .filter(|_| charter.uses_policy_bundle())
    else {
        return engine_for_charter(charter, default);
    };
    let key = if !pb.verify_key.is_empty() {
        Some(policybundle::decode_public_key(&pb.verify_key).map_err(BuildError::BundleKey)?)
    } else if pb.insecure {
        tracing::warn!(
            reference = %pb.r#ref,
            "runeward: WARNING: policy bundle pulled WITHOUT signature verification (insecure_skip_verify=true)"
        );
        None
    } else {
        return Err(BuildError::BundleVerifyKeyRequired {
            reference: pb.r#ref.clone(),
        });
    };
    let bundle = policybundle::pull(
        &pb.r#ref,
        key.as_ref(),
        PullOptions {
            plain_http: pb.plain_http,
        },
    )
    .await
    .map_err(|source| BuildError::BundlePull {
        reference: pb.r#ref.clone(),
        source,
    })?;
    engine_for_bundle(&bundle, &pb.r#ref, default)
}

/// Builds the engine for an already pulled (and verified) bundle. `reference`
/// is used only in error messages.
pub fn engine_for_bundle(
    bundle: &Bundle,
    reference: &str,
    default: Verdict,
) -> Result<Box<dyn Evaluator>, BuildError> {
    match bundle.engine {
        BundleEngine::Rego => {
            let module = String::from_utf8_lossy(&bundle.policy);
            Ok(Box::new(RegoEngine::new(
                &module,
                bundle.query.as_deref().unwrap_or_default(),
                default,
            )?))
        }
        BundleEngine::Cel => {
            let rules = parse_cel_fragment(&bundle.policy).map_err(|message| {
                BuildError::BundleCelFragment {
                    reference: reference.to_owned(),
                    message,
                }
            })?;
            Ok(Box::new(CelEngine::new(&rules, default)?))
        }
    }
}

/// A bundle's `[[cel]]` fragment. Decoded leniently (unknown keys ignored),
/// as the Go control plane does.
#[derive(Deserialize, Default)]
#[serde(default)]
struct CelFragment {
    cel: Vec<LenientCelRule>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct LenientCelRule {
    expr: String,
    verdict: String,
    reason: String,
}

fn parse_cel_fragment(policy: &[u8]) -> Result<Vec<CelRule>, String> {
    let text = std::str::from_utf8(policy).map_err(|e| e.to_string())?;
    let frag: CelFragment =
        toml::from_str(text).map_err(|e| e.to_string().trim_end().to_owned())?;
    Ok(frag
        .cel
        .into_iter()
        .map(|r| CelRule {
            expr: r.expr,
            verdict: Verdict::parse(&r.verdict),
            reason: r.reason,
        })
        .collect())
}

fn expand_home(p: &str) -> PathBuf {
    if let Some(rest) = p.strip_prefix("~/")
        && let Some(home) = std::env::var_os("HOME").filter(|h| !h.is_empty())
    {
        return PathBuf::from(home).join(rest);
    }
    PathBuf::from(p)
}

#[cfg(test)]
mod tests {
    use runeward_charter::{PolicyBundle, PolicyRule, RegoPolicy};

    use super::*;
    use crate::{Action, EngineKind};

    #[test]
    fn no_match_verdict_precedence() {
        let mut c = Charter::default();
        assert_eq!(no_match_verdict(Some(&c), None), Verdict::Allow);
        assert_eq!(no_match_verdict(Some(&c), Some(" DENY ")), Verdict::Deny);
        assert_eq!(no_match_verdict(None, Some("deny")), Verdict::Deny);
        assert_eq!(no_match_verdict(Some(&c), Some("bogus")), Verdict::Allow);
        c.policy_default = Verdict::parse("Allow");
        assert_eq!(no_match_verdict(Some(&c), Some("deny")), Verdict::Allow);
        c.policy_default = Verdict::Deny;
        assert_eq!(no_match_verdict(Some(&c), Some("allow")), Verdict::Deny);
        // require-approval is not a valid no-match verdict.
        c.policy_default = Verdict::RequireApproval;
        assert_eq!(no_match_verdict(Some(&c), None), Verdict::Allow);
    }

    #[test]
    fn selects_engine_by_policy_engine() {
        let mut c = Charter {
            policy: vec![PolicyRule {
                tool: "shell".into(),
                match_glob: "rm *".into(),
                verdict: Verdict::Deny,
                ..PolicyRule::default()
            }],
            ..Charter::default()
        };
        let e = engine_for_charter(&c, Verdict::Allow).expect("builtin");
        assert_eq!(e.kind(), EngineKind::Builtin);
        assert_eq!(
            e.evaluate(&Action::new("shell", "rm x")).verdict,
            Verdict::Deny
        );

        c.policy_engine = "cel".into();
        c.cel = vec![CelRule {
            expr: r#"tool == "net""#.into(),
            verdict: Verdict::Deny,
            reason: String::new(),
        }];
        let e = engine_for_charter(&c, Verdict::Allow).expect("cel");
        assert_eq!(e.kind(), EngineKind::Cel);
        // [[policy]] rules are ignored once cel is selected.
        assert_eq!(
            e.evaluate(&Action::new("shell", "rm x")).verdict,
            Verdict::Allow
        );

        c.policy_engine = "rego".into();
        c.rego = RegoPolicy {
            module: "package runeward\n\ndecision := \"require-approval\"\n".into(),
            ..RegoPolicy::default()
        };
        let e = engine_for_charter(&c, Verdict::Allow).expect("rego");
        assert_eq!(e.kind(), EngineKind::Rego);
        assert_eq!(
            e.evaluate(&Action::new("shell", "ls")).verdict,
            Verdict::RequireApproval
        );
    }

    #[test]
    fn rego_file_is_read() {
        let dir = std::env::temp_dir().join(format!("runeward-policy-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("p.rego");
        std::fs::write(&path, "package runeward\n\ndecision := \"deny\"\n").expect("write");
        let c = Charter {
            policy_engine: "rego".into(),
            rego: RegoPolicy {
                file: path.to_string_lossy().into_owned(),
                ..RegoPolicy::default()
            },
            ..Charter::default()
        };
        let e = engine_for_charter(&c, Verdict::Allow).expect("rego file");
        assert_eq!(e.evaluate(&Action::new("x", "y")).verdict, Verdict::Deny);
        let _ = std::fs::remove_dir_all(&dir);

        let missing = Charter {
            policy_engine: "rego".into(),
            rego: RegoPolicy {
                file: "/nonexistent/runeward/p.rego".into(),
                ..RegoPolicy::default()
            },
            ..Charter::default()
        };
        assert!(matches!(
            engine_for_charter(&missing, Verdict::Allow),
            Err(BuildError::ReadRego { .. })
        ));
    }

    #[test]
    fn bundle_charter_refused_offline() {
        let c = Charter {
            name: "b".into(),
            policy_bundle: Some(PolicyBundle {
                r#ref: "oci://example.test/p:v1".into(),
                ..PolicyBundle::default()
            }),
            ..Charter::default()
        };
        assert!(matches!(
            engine_for_charter(&c, Verdict::Allow),
            Err(BuildError::BundleRequiresPull { .. })
        ));
    }

    #[test]
    fn bundle_without_key_fails_closed() {
        let c = Charter {
            policy_bundle: Some(PolicyBundle {
                r#ref: "oci://example.test/p:v1".into(),
                ..PolicyBundle::default()
            }),
            ..Charter::default()
        };
        let fut = engine_for_charter_with_bundle(&c, Verdict::Allow);
        // The verify-key check happens before any await point that touches
        // the network, so a no-op executor suffices.
        let res = block_on(fut);
        assert!(matches!(
            res,
            Err(BuildError::BundleVerifyKeyRequired { .. })
        ));
    }

    #[test]
    fn bundle_engines() {
        let rego = Bundle::new(
            BundleEngine::Rego,
            "package runeward\n\ndecision := \"deny\"\n",
        );
        let e = engine_for_bundle(&rego, "r", Verdict::Allow).expect("rego bundle");
        assert_eq!(e.evaluate(&Action::new("x", "y")).verdict, Verdict::Deny);

        let custom =
            Bundle::new(BundleEngine::Rego, "package p\n\nd := \"deny\"\n").with_query("data.p.d");
        let e = engine_for_bundle(&custom, "r", Verdict::Allow).expect("query bundle");
        assert_eq!(e.evaluate(&Action::new("x", "y")).verdict, Verdict::Deny);

        let cel = Bundle::new(
            BundleEngine::Cel,
            "[[cel]]\nexpr = 'tool == \"shell\"'\nverdict = \"require-approval\"\nextra = 1\n",
        );
        let e = engine_for_bundle(&cel, "r", Verdict::Allow).expect("cel bundle");
        assert_eq!(
            e.evaluate(&Action::new("shell", "ls")).verdict,
            Verdict::RequireApproval
        );

        let bad = Bundle::new(BundleEngine::Cel, "[[cel]\n");
        assert!(matches!(
            engine_for_bundle(&bad, "r", Verdict::Allow),
            Err(BuildError::BundleCelFragment { .. })
        ));
    }

    /// Polls a future that must complete without waking.
    fn block_on<F: std::future::Future>(fut: F) -> F::Output {
        use std::pin::pin;
        use std::task::{Context, Poll, Waker};
        let mut fut = pin!(fut);
        let mut cx = Context::from_waker(Waker::noop());
        match fut.as_mut().poll(&mut cx) {
            Poll::Ready(v) => v,
            Poll::Pending => panic!("future unexpectedly pending"),
        }
    }
}
