//! `env://NAME` references.

use crate::resolver::{Error, ResolveFuture, Resolver, split_scheme};

/// Resolves `env://NAME` references from the operator's process environment.
/// It is fail-closed: an unset or empty variable is an error.
#[derive(Debug, Clone, Copy, Default)]
pub struct EnvResolver;

impl EnvResolver {
    /// Reads the environment variable named in an `env://NAME` reference.
    pub async fn resolve(&self, reference: &str) -> Result<String, Error> {
        resolve_env(reference)
    }
}

fn resolve_env(reference: &str) -> Result<String, Error> {
    let name = match split_scheme(reference) {
        Some((scheme, name)) if scheme == "env" => name,
        _ => {
            return Err(Error::new(format!(
                "secret reference {reference:?} is not an env:// reference"
            )));
        }
    };
    if name.is_empty() {
        return Err(Error::new(format!(
            "secret reference {reference:?}: missing variable name (expected env://NAME)"
        )));
    }
    match std::env::var_os(name) {
        Some(v) if !v.is_empty() => Ok(v.to_string_lossy().into_owned()),
        _ => Err(Error::new(format!(
            "secret reference {reference:?}: environment variable {name:?} is unset or empty"
        ))),
    }
}

impl Resolver for EnvResolver {
    fn resolve<'a>(&'a self, reference: &'a str) -> ResolveFuture<'a> {
        Box::pin(EnvResolver::resolve(self, reference))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{child_test_name, is_child, run_child};

    #[tokio::test]
    async fn env_resolver_set() {
        let name = child_test_name(module_path!(), "env_resolver_set");
        if !is_child(&name) {
            run_child(&name, &[("RUNEWARD_TEST_SECRET", "hunter2")], &[]);
            return;
        }
        let got = EnvResolver
            .resolve("env://RUNEWARD_TEST_SECRET")
            .await
            .expect("resolve");
        assert_eq!(got, "hunter2");
    }

    #[tokio::test]
    async fn env_resolver_unset() {
        let name = child_test_name(module_path!(), "env_resolver_unset");
        if !is_child(&name) {
            run_child(&name, &[("RUNEWARD_TEST_SECRET", "")], &[]);
            return;
        }
        assert!(
            EnvResolver
                .resolve("env://RUNEWARD_TEST_SECRET")
                .await
                .is_err(),
            "expected error for unset/empty variable"
        );
    }

    #[tokio::test]
    async fn env_resolver_missing_name() {
        assert!(EnvResolver.resolve("env://").await.is_err());
    }

    #[tokio::test]
    async fn env_resolver_wrong_scheme() {
        assert!(EnvResolver.resolve("vault://a/b#c").await.is_err());
    }
}
