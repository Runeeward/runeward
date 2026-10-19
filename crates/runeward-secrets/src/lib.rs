//! Resolves secret references from multiple backends so a profile's `[[env]]`
//! entries can pull values from more than literals and files.
//!
//! A reference is a URI whose scheme selects the backend:
//!
//! ```text
//! env://NAME                       read from the operator's environment
//! vault://<mount>/<path>#<field>   read a HashiCorp Vault KV v2 field
//! aws://<secretId>[#<jsonKey>]     read an AWS Secrets Manager secret
//! gcp://<name>[#<version>]         read a GCP Secret Manager secret version
//! op://vault/item/field            1Password (not built in; errors)
//! ```
//!
//! The [`Dispatcher`] returned by [`Dispatcher::from_env`] routes a reference
//! by scheme. It is fail-closed: an unknown scheme, a missing value, or a
//! backend error is returned as an error rather than resolving to an empty
//! string, so a sandbox never starts believing it holds a credential it does
//! not.

mod aws;
mod env;
mod gcp;
mod http;
mod resolver;
mod vault;

#[cfg(test)]
mod test_support;

pub use aws::AwsResolver;
pub use env::EnvResolver;
pub use gcp::GcpResolver;
pub use resolver::{Dispatcher, Error, ResolveFuture, Resolver};
pub use vault::VaultResolver;
