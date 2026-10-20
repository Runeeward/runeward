//! The [`Resolver`] trait and the scheme-routing [`Dispatcher`].

use std::fmt;
use std::future::Future;
use std::pin::Pin;

use crate::{AwsResolver, EnvResolver, GcpResolver, VaultResolver};

/// A secret reference could not be resolved.
///
/// The message matches the Go implementation's error text and always names
/// the offending reference.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct Error(String);

impl Error {
    pub(crate) fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }

    /// The human-readable error message.
    pub fn message(&self) -> &str {
        &self.0
    }
}

/// The boxed future returned by [`Resolver::resolve`].
pub type ResolveFuture<'a> = Pin<Box<dyn Future<Output = Result<String, Error>> + Send + 'a>>;

/// Turns a scheme-qualified secret reference into its literal value.
pub trait Resolver: Send + Sync + fmt::Debug {
    /// Returns the secret value named by `reference`, or an error if the
    /// reference is malformed, the backend is unreachable, or the value is
    /// unset. Implementations must never resolve to an empty string.
    ///
    /// Cancellation is by dropping the returned future.
    fn resolve<'a>(&'a self, reference: &'a str) -> ResolveFuture<'a>;
}

/// Routes a reference to a backend [`Resolver`] by its URI scheme.
///
/// A backend left as `None` is "not configured" and references to it error.
#[derive(Debug, Default)]
pub struct Dispatcher {
    pub env: Option<Box<dyn Resolver>>,
    pub vault: Option<Box<dyn Resolver>>,
    pub aws: Option<Box<dyn Resolver>>,
    pub gcp: Option<Box<dyn Resolver>>,
}

impl Dispatcher {
    /// Returns the standard dispatcher, wiring each backend resolver from the
    /// process environment (Vault: `VAULT_ADDR` / `VAULT_TOKEN`; AWS:
    /// `AWS_REGION` / `AWS_ACCESS_KEY_ID` / ...; GCP: `GOOGLE_CLOUD_PROJECT` /
    /// `GOOGLE_OAUTH_ACCESS_TOKEN`).
    pub fn from_env() -> Self {
        Self {
            env: Some(Box::new(EnvResolver)),
            vault: Some(Box::new(VaultResolver::from_env())),
            aws: Some(Box::new(AwsResolver::from_env())),
            gcp: Some(Box::new(GcpResolver::from_env())),
        }
    }

    /// Dispatches `reference` to the resolver for its scheme. Supported
    /// schemes are `env://`, `vault://`, `aws://`, `gcp://` and `op://` (the
    /// last always errors, by design).
    pub async fn resolve(&self, reference: &str) -> Result<String, Error> {
        let Some((scheme, _)) = split_scheme(reference) else {
            return Err(Error::new(format!(
                "secret reference {reference:?} has no scheme; expected one of env://, vault://, aws://, gcp://, op://"
            )));
        };
        let backend = match scheme.as_str() {
            "env" => &self.env,
            "vault" => &self.vault,
            "aws" => &self.aws,
            "gcp" => &self.gcp,
            "op" => {
                return Err(Error::new(format!(
                    "secret reference {reference:?}: 1Password (op://) resolution is not built in; provide the value another way"
                )));
            }
            _ => {
                return Err(Error::new(format!(
                    "secret reference {reference:?}: unsupported scheme {scheme:?}; expected one of env://, vault://, aws://, gcp://, op://"
                )));
            }
        };
        match backend {
            Some(resolver) => resolver.resolve(reference).await,
            None => Err(Error::new(format!(
                "secret reference {reference:?}: {scheme} resolver not configured"
            ))),
        }
    }
}

impl Resolver for Dispatcher {
    fn resolve<'a>(&'a self, reference: &'a str) -> ResolveFuture<'a> {
        Box::pin(Dispatcher::resolve(self, reference))
    }
}

/// Separates `scheme://rest` without requiring the rest to be a valid URL
/// (`env://NAME` and vault paths are not strict URLs). The scheme is
/// lower-cased. Returns `None` when no plausible `scheme://` prefix is present.
pub(crate) fn split_scheme(reference: &str) -> Option<(String, &str)> {
    let i = reference.find("://")?;
    if i == 0 {
        return None;
    }
    let scheme = reference[..i].to_lowercase();
    // A scheme must be a plausible URI scheme; reject anything with a space so
    // a stray value isn't misread as a reference.
    if scheme.contains([' ', '\t', '/']) {
        return None;
    }
    Some((scheme, &reference[i + "://".len()..]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{child_test_name, is_child, run_child};

    #[test]
    fn split_scheme_cases() {
        assert_eq!(split_scheme("env://X"), Some(("env".to_owned(), "X")));
        assert_eq!(
            split_scheme("VAULT://a/b#c"),
            Some(("vault".to_owned(), "a/b#c"))
        );
        assert_eq!(split_scheme("://x"), None);
        assert_eq!(split_scheme("just-a-literal"), None);
        assert_eq!(split_scheme("a b://x"), None);
        assert_eq!(split_scheme("a/b://x"), None);
    }

    #[tokio::test]
    async fn dispatcher_routes_env() {
        let name = child_test_name(module_path!(), "dispatcher_routes_env");
        if !is_child(&name) {
            run_child(&name, &[("RUNEWARD_TEST_SECRET", "routed")], &[]);
            return;
        }
        let got = Dispatcher::from_env()
            .resolve("env://RUNEWARD_TEST_SECRET")
            .await
            .expect("resolve");
        assert_eq!(got, "routed");
    }

    #[tokio::test]
    async fn dispatcher_op_is_not_built_in() {
        let err = Dispatcher::from_env()
            .resolve("op://vault/item/field")
            .await
            .expect_err("op:// must error");
        assert!(err.to_string().contains("1Password"), "{err}");
    }

    #[tokio::test]
    async fn dispatcher_unknown_scheme() {
        assert!(
            Dispatcher::from_env()
                .resolve("gopher://x/y")
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn dispatcher_no_scheme() {
        assert!(
            Dispatcher::from_env()
                .resolve("just-a-literal")
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn dispatcher_unconfigured_backend() {
        let err = Dispatcher::default()
            .resolve("vault://kv/a#b")
            .await
            .expect_err("unconfigured");
        assert!(
            err.to_string().contains("vault resolver not configured"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn dispatcher_as_trait_object() {
        let d: Box<dyn Resolver> = Box::new(Dispatcher::from_env());
        assert!(d.resolve("op://x").await.is_err());
    }
}
