//! Multi-principal, RBAC-style access control for the control plane.
//!
//! It generalizes the legacy single static bearer token into a set of named
//! [`Principal`]s, each with its own token, an allowed-profile glob list, and
//! permission flags, loaded from the JSON file named by `RUNEWARD_AUTHZ_FILE`.
//! Optionally, RS256 OIDC bearer tokens are verified against a JWKS and mapped
//! onto the same principal model ([`OidcVerifier`]).
//!
//! [`Store::from_env`] returning `None` means "RBAC not configured", allowing
//! the caller to fall back to legacy single-token behaviour.

mod authz;
mod oidc;
mod pathmatch;

#[cfg(test)]
mod test_support;

pub use authz::{ENV_FILE, Principal, Store};
pub use oidc::{ENV_OIDC_AUDIENCE, ENV_OIDC_ISSUER, ENV_OIDC_JWKS_URL, OidcVerifier};

/// An authorization configuration or credential could not be used.
///
/// The messages match the Go implementation's error text.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// Returned by helpers that require a configured store.
    #[error("authz: store not configured")]
    Empty,
    /// The principals file is unreadable, insecure or invalid.
    #[error("{0}")]
    Config(String),
    /// OIDC configuration failed or a token did not verify.
    #[error("{0}")]
    Oidc(String),
}

/// Decodes the first JSON value in `bytes`, ignoring anything after it, as
/// Go's `json.Decoder.Decode` does.
pub(crate) fn decode_first_value(bytes: &[u8]) -> Result<serde_json::Value, String> {
    match serde_json::Deserializer::from_slice(bytes)
        .into_iter::<serde_json::Value>()
        .next()
    {
        Some(Ok(v)) => Ok(v),
        Some(Err(e)) => Err(e.to_string()),
        None => Err("EOF".to_owned()),
    }
}
