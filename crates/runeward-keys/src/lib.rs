//! Ed25519 key encoding shared by the ledger, Charter signatures and policy
//! bundles.
//!
//! Formats match the Go implementation byte for byte: keys are standard
//! base64, a private key is the 64-byte `seed || public` form, and a key id is
//! the hex of the first 8 bytes of `SHA-256(public key)`.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::{SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

/// Length of an encoded public key.
pub const PUBLIC_KEY_LEN: usize = 32;
/// Length of an encoded private key (`seed || public`).
pub const PRIVATE_KEY_LEN: usize = 64;

/// A key could not be decoded.
#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("decode {kind} key: {source}")]
    Base64 {
        kind: &'static str,
        source: base64::DecodeError,
    },
    #[error("{kind} key wrong size {got} (want {want})")]
    Size {
        kind: &'static str,
        got: usize,
        want: usize,
    },
    #[error("invalid {kind} key: {0}", kind = "ed25519")]
    Invalid(ed25519_dalek::SignatureError),
}

/// Returns the short fingerprint of a public key.
pub fn key_id(public: &VerifyingKey) -> String {
    let sum = Sha256::digest(public.as_bytes());
    hex::encode(&sum[..8])
}

/// Base64-encodes raw key bytes.
pub fn encode(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

/// Base64-encodes a public key.
pub fn encode_public(public: &VerifyingKey) -> String {
    encode(public.as_bytes())
}

/// Base64-encodes a private key in the 64-byte `seed || public` form.
pub fn encode_private(signing: &SigningKey) -> String {
    encode(&signing.to_keypair_bytes())
}

/// Parses a base64 public key; surrounding whitespace is ignored.
pub fn decode_public(s: &str) -> Result<VerifyingKey, KeyError> {
    let raw = decode_b64("public", s)?;
    public_from_bytes(&raw)
}

/// Parses a base64 private key in the 64-byte `seed || public` form.
pub fn decode_private(s: &str) -> Result<SigningKey, KeyError> {
    let raw = decode_b64("private", s)?;
    private_from_bytes(&raw)
}

/// Builds a public key from its raw 32 bytes.
pub fn public_from_bytes(raw: &[u8]) -> Result<VerifyingKey, KeyError> {
    let bytes: [u8; PUBLIC_KEY_LEN] = raw.try_into().map_err(|_| KeyError::Size {
        kind: "public",
        got: raw.len(),
        want: PUBLIC_KEY_LEN,
    })?;
    VerifyingKey::from_bytes(&bytes).map_err(KeyError::Invalid)
}

/// Builds a private key from the raw 64-byte `seed || public` form, rejecting
/// a public half that does not match the seed.
pub fn private_from_bytes(raw: &[u8]) -> Result<SigningKey, KeyError> {
    let bytes: [u8; PRIVATE_KEY_LEN] = raw.try_into().map_err(|_| KeyError::Size {
        kind: "private",
        got: raw.len(),
        want: PRIVATE_KEY_LEN,
    })?;
    SigningKey::from_keypair_bytes(&bytes).map_err(KeyError::Invalid)
}

fn decode_b64(kind: &'static str, s: &str) -> Result<Vec<u8>, KeyError> {
    STANDARD
        .decode(s.trim())
        .map_err(|source| KeyError::Base64 { kind, source })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn golden(path: &str) -> String {
        let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../testdata/golden/");
        std::fs::read_to_string(format!("{root}{path}")).expect("read golden fixture")
    }

    #[test]
    fn matches_go_policy_bundle_keys() {
        let fx: serde_json::Value =
            serde_json::from_str(&golden("policy-bundle.json")).expect("parse fixture");
        let s = |k: &str| fx[k].as_str().expect("string field").to_owned();
        let signing = decode_private(&s("private_key")).expect("private key");
        let public = decode_public(&s("public_key")).expect("public key");
        assert_eq!(signing.verifying_key(), public);
        assert_eq!(key_id(&public), s("key_id"));
        assert_eq!(encode_private(&signing), s("private_key"));
        assert_eq!(encode_public(&public), s("public_key"));
    }

    #[test]
    fn rejects_wrong_sizes_and_mismatched_halves() {
        assert!(matches!(
            decode_public(&encode(&[0; 31])),
            Err(KeyError::Size { got: 31, .. })
        ));
        let mut raw = SigningKey::from_bytes(&[7; 32]).to_keypair_bytes();
        raw[63] ^= 1;
        assert!(private_from_bytes(&raw).is_err());
        assert!(decode_public("not base64!").is_err());
    }
}
