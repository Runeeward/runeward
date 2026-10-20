//! Resolving a Charter into what a session needs: literal environment and
//! secrets, the authority engine, and custom scrub patterns.

use std::collections::BTreeMap;
use std::time::Duration;

use regex::Regex;
use runeward_charter::{Charter, Verdict};
use runeward_policy::Evaluator;
use runeward_secrets::Dispatcher;

use crate::error::{Error, Result};

/// Bounds an OCI policy-bundle pull.
const BUNDLE_PULL_TIMEOUT: Duration = Duration::from_secs(30);

/// Turns a Charter's `[[env]]` entries into literals and returns the secret
/// values for redaction. Fails closed: a source that cannot be resolved
/// (unreadable file, unresolvable `env://`/`vault://`/`op://` reference) is
/// an error, so a sandbox never starts believing it holds a credential it
/// does not.
pub(crate) async fn resolve_env(
    c: &Charter,
    resolver: &Dispatcher,
) -> Result<(BTreeMap<String, String>, Vec<String>)> {
    let mut out = BTreeMap::new();
    let mut secrets = Vec::new();
    for e in &c.env {
        let val = if !e.op.is_empty() {
            resolver.resolve(&e.op).await.map_err(|err| {
                Error::other(format!("env {:?}: resolve {:?}: {err}", e.name, e.op))
            })?
        } else if !e.file.is_empty() {
            let path = runeward_backend::expand_home(&e.file);
            let b = tokio::fs::read(&path).await.map_err(|err| {
                Error::other(format!("env {:?}: read file {:?}: {err}", e.name, e.file))
            })?;
            String::from_utf8_lossy(&b)
                .trim_end_matches(['\r', '\n'])
                .to_owned()
        } else if !e.value.is_empty() {
            e.value.clone()
        } else {
            continue;
        };
        if e.is_secret() && !val.is_empty() {
            secrets.push(val.clone());
        }
        out.insert(e.name.clone(), val);
    }
    Ok((out, secrets))
}

/// The no-match verdict: the Charter's `policy_default`, else the
/// operator's `RUNEWARD_POLICY_DEFAULT`, else allow.
pub(crate) fn no_match_verdict(c: &Charter, env_default: Option<&str>) -> Verdict {
    runeward_policy::no_match_verdict(Some(c), env_default)
}

/// Builds the authority engine a Charter selects: a signed OCI bundle, Rego,
/// CEL or the built-in first-match rules.
pub(crate) async fn new_engine(
    c: &Charter,
    env_default: Option<&str>,
) -> Result<Box<dyn Evaluator>> {
    let default = no_match_verdict(c, env_default);
    if c.uses_policy_bundle() {
        return tokio::time::timeout(
            BUNDLE_PULL_TIMEOUT,
            runeward_policy::engine_for_charter_with_bundle(c, default),
        )
        .await
        .map_err(|_| Error::other("policy bundle: pull timed out"))?
        .map_err(Error::other);
    }
    runeward_policy::engine_for_charter(c, default).map_err(Error::other)
}

/// Compiles `[chronicle] scrub_patterns`.
pub(crate) fn compile_scrub_patterns(patterns: &[String]) -> Result<Vec<Regex>> {
    patterns
        .iter()
        .map(|raw| raw.trim())
        .filter(|p| !p.is_empty())
        .map(|p| {
            Regex::new(p).map_err(|e| Error::other(format!("chronicle.scrub_patterns {p:?}: {e}")))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use runeward_charter::EnvVar;
    use runeward_policy::Action;

    use super::*;

    #[tokio::test]
    async fn resolves_literals_files_and_fails_closed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let f = dir.path().join("tok");
        std::fs::write(&f, "s3cret\r\n").expect("write");
        let c = Charter {
            env: vec![
                EnvVar {
                    name: "PLAIN".into(),
                    value: "v".into(),
                    ..EnvVar::default()
                },
                EnvVar {
                    name: "TOKEN".into(),
                    file: f.display().to_string(),
                    ..EnvVar::default()
                },
                EnvVar {
                    name: "EMPTY".into(),
                    ..EnvVar::default()
                },
            ],
            ..Charter::default()
        };
        let (env, secrets) = resolve_env(&c, &Dispatcher::from_env())
            .await
            .expect("resolve");
        assert_eq!(env["PLAIN"], "v");
        assert_eq!(env["TOKEN"], "s3cret");
        assert!(!env.contains_key("EMPTY"));
        assert_eq!(secrets, ["s3cret"]);

        let name = "RUNEWARD_TEST_MISSING_PREREQUISITE_7F3A";
        let c = Charter {
            env: vec![EnvVar {
                name: "TOKEN".into(),
                op: format!("env://{name}"),
                ..EnvVar::default()
            }],
            ..Charter::default()
        };
        let err = resolve_env(&c, &Dispatcher::from_env())
            .await
            .expect_err("missing env");
        assert!(err.to_string().contains(name), "{err}");
    }

    #[tokio::test]
    async fn no_match_default_and_precedence() {
        let allow = Charter::default();
        let e = new_engine(&allow, None).await.expect("engine");
        assert_eq!(
            e.evaluate(&Action::new("shell", "echo hi")).verdict,
            Verdict::Allow
        );
        let deny = Charter {
            policy_default: Verdict::Deny,
            ..Charter::default()
        };
        let e = new_engine(&deny, None).await.expect("engine");
        assert_eq!(
            e.evaluate(&Action::new("shell", "echo hi")).verdict,
            Verdict::Deny
        );

        // Operator default applies only when the Charter is silent.
        assert_eq!(no_match_verdict(&allow, Some("deny")), Verdict::Deny);
        let explicit_allow = Charter {
            policy_default: Verdict::Allow,
            ..Charter::default()
        };
        assert_eq!(
            no_match_verdict(&explicit_allow, Some("deny")),
            Verdict::Allow
        );
        assert_eq!(no_match_verdict(&deny, Some("allow")), Verdict::Deny);
        assert_eq!(no_match_verdict(&allow, None), Verdict::Allow);
    }

    #[test]
    fn scrub_patterns() {
        assert_eq!(
            compile_scrub_patterns(&[" ".into(), "a+".into()])
                .expect("ok")
                .len(),
            1
        );
        let err = compile_scrub_patterns(&["(".into()]).expect_err("bad");
        assert!(
            err.to_string().contains("chronicle.scrub_patterns"),
            "{err}"
        );
    }
}
