//! Detached Charter signatures (`<charter>.sig`).
//!
//! The signed message is the exact on-disk Charter bytes: signing raw bytes
//! keeps the scheme canonical (no re-serialisation) and mirrors how policy
//! bundles cover their raw policy layer. The envelope is a small JSON document
//! that the Go implementation writes and reads, so its encoding is byte-exact.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

/// Schema tag written into detached signature files so a reader can tell a
/// Charter signature apart from other JSON.
pub const SIGNATURE_FORMAT: &str = "runeward.profile.sig.v1";

/// A signature failed to decode or verify.
#[derive(Debug, thiserror::Error)]
pub enum SignatureError {
    #[error("profile: decode signature file: {0}")]
    Decode(#[source] serde_json::Error),
    #[error("profile: signature file missing sig field")]
    MissingSig,
    #[error("profile: decode signature: {0}")]
    Base64(#[source] base64::DecodeError),
    #[error("profile: signature key id {got:?} does not match verify key {want:?}")]
    KeyIdMismatch { got: String, want: String },
    #[error("profile: signature does not verify against the supplied key")]
    BadSignature,
}

/// The JSON envelope stored in a detached `.sig` file.
///
/// Field order is the serialised order and must stay `format, key_id, sig`
/// for byte compatibility with Go.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Signature {
    /// Envelope schema tag; see [`SIGNATURE_FORMAT`].
    pub format: String,
    /// Short fingerprint of the signing public key ([`runeward_keys::key_id`]).
    pub key_id: String,
    /// Standard base64 ed25519 signature over the Charter bytes.
    pub sig: String,
}

/// Returns the raw ed25519 signature over the exact Charter bytes.
pub fn sign(content: &[u8], key: &SigningKey) -> [u8; 64] {
    key.sign(content).to_bytes()
}

/// Verifies a raw ed25519 signature over `content`.
pub fn verify(content: &[u8], sig: &[u8], public: &VerifyingKey) -> Result<(), SignatureError> {
    let sig =
        ed25519_dalek::Signature::from_slice(sig).map_err(|_| SignatureError::BadSignature)?;
    // The non-strict check matches Go's cofactorless crypto/ed25519 verifier,
    // so both implementations accept the same signatures.
    ed25519_dalek::Verifier::verify(public, content, &sig).map_err(|_| SignatureError::BadSignature)
}

impl Signature {
    /// Signs `content` and wraps the result in an envelope tagged with the
    /// signer's key id.
    pub fn new(content: &[u8], key: &SigningKey) -> Self {
        Self {
            format: SIGNATURE_FORMAT.to_owned(),
            key_id: runeward_keys::key_id(&key.verifying_key()),
            sig: STANDARD.encode(sign(content, key)),
        }
    }

    /// Encodes the envelope as two-space indented JSON with a trailing
    /// newline, byte-identical to Go's `json.MarshalIndent` output.
    pub fn marshal(&self) -> Vec<u8> {
        // Serialising three plain strings cannot fail.
        let mut out = serde_json::to_vec_pretty(self).unwrap_or_default();
        out.push(b'\n');
        out
    }

    /// Decodes a detached signature file, requiring a non-empty `sig`.
    pub fn parse(bytes: &[u8]) -> Result<Self, SignatureError> {
        let s: Self = serde_json::from_slice(bytes).map_err(SignatureError::Decode)?;
        if s.sig.is_empty() {
            return Err(SignatureError::MissingSig);
        }
        Ok(s)
    }

    /// Checks the envelope against `content` and `public`, failing closed on a
    /// key id that names a different key, and returns the verified key id.
    pub fn verify(&self, content: &[u8], public: &VerifyingKey) -> Result<String, SignatureError> {
        let sig = STANDARD.decode(&self.sig).map_err(SignatureError::Base64)?;
        let want = runeward_keys::key_id(public);
        if !self.key_id.is_empty() && self.key_id != want {
            return Err(SignatureError::KeyIdMismatch {
                got: self.key_id.clone(),
                want,
            });
        }
        verify(content, &sig, public)?;
        Ok(want)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    #[test]
    fn sign_verify_round_trip() {
        let k = key(1);
        let content = b"name = \"demo\"\n[network]\nallow = [\"example.com\"]\n";
        let sig = sign(content, &k);
        verify(content, &sig, &k.verifying_key()).expect("valid signature");
    }

    #[test]
    fn verify_tampered_content_fails() {
        let k = key(1);
        let content = b"name = \"demo\"\n".to_vec();
        let sig = sign(&content, &k);
        let mut tampered = content.clone();
        tampered[0] ^= 0xff;
        assert!(verify(&tampered, &sig, &k.verifying_key()).is_err());
    }

    #[test]
    fn verify_wrong_key_fails() {
        let content = b"name = \"demo\"\n";
        let sig = sign(content, &key(1));
        assert!(verify(content, &sig, &key(2).verifying_key()).is_err());
        assert!(verify(content, &sig[..10], &key(1).verifying_key()).is_err());
    }

    #[test]
    fn envelope_round_trip() {
        let k = key(3);
        let content = b"name = \"demo\"\nreadonly = true\n";
        let env = Signature::new(content, &k);
        assert_eq!(env.format, SIGNATURE_FORMAT);
        let parsed = Signature::parse(&env.marshal()).expect("parse");
        let id = parsed
            .verify(content, &k.verifying_key())
            .expect("envelope verifies");
        assert_eq!(id, env.key_id);
    }

    #[test]
    fn envelope_tampered_fails() {
        let k = key(3);
        let env = Signature::new(b"name = \"demo\"\n", &k);
        assert!(
            env.verify(b"name = \"evil\"\n", &k.verifying_key())
                .is_err()
        );
    }

    #[test]
    fn envelope_wrong_key_fails() {
        let env = Signature::new(b"name = \"demo\"\n", &key(3));
        assert!(matches!(
            env.verify(b"name = \"demo\"\n", &key(4).verifying_key()),
            Err(SignatureError::KeyIdMismatch { .. })
        ));
    }

    #[test]
    fn parse_rejects_empty_sig() {
        assert!(matches!(
            Signature::parse(br#"{"format":"runeward.profile.sig.v1","key_id":"abcd"}"#),
            Err(SignatureError::MissingSig)
        ));
        assert!(Signature::parse(b"not json").is_err());
    }
}
