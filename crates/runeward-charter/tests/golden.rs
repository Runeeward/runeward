//! Interoperability with detached Charter signatures written by the Go
//! implementation (`tools/golden`).

use std::path::{Path, PathBuf};

use ed25519_dalek::SigningKey;
use runeward_charter::{Options, Signature, SignedCharters, load};
use sha2::{Digest, Sha256};

fn golden_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../testdata/golden/charter")
}

fn golden(name: &str) -> Vec<u8> {
    std::fs::read(golden_dir().join(name)).expect("read golden fixture")
}

/// The Go generator's key: seed = SHA-256("runeward-golden:charter").
fn golden_key() -> SigningKey {
    let seed: [u8; 32] = Sha256::digest(b"runeward-golden:charter").into();
    SigningKey::from_bytes(&seed)
}

fn verify_key() -> ed25519_dalek::VerifyingKey {
    let text = String::from_utf8(golden("charter.pub")).expect("utf8 key");
    runeward_keys::decode_public(&text).expect("decode charter.pub")
}

#[test]
fn go_signature_verifies() {
    let sig = Signature::parse(&golden("signed.toml.sig")).expect("parse sig");
    let id = sig
        .verify(&golden("signed.toml"), &verify_key())
        .expect("Go signature verifies");
    assert_eq!(id, sig.key_id);
    assert_eq!(verify_key(), golden_key().verifying_key());
}

#[test]
fn flipped_byte_fails() {
    let sig = Signature::parse(&golden("signed.toml.sig")).expect("parse sig");
    let content = golden("signed.toml");
    for i in [0, content.len() / 2, content.len() - 1] {
        let mut tampered = content.clone();
        tampered[i] ^= 0x01;
        assert!(sig.verify(&tampered, &verify_key()).is_err(), "byte {i}");
    }
}

#[test]
fn marshal_matches_go_bytes() {
    let ours = Signature::new(&golden("signed.toml"), &golden_key()).marshal();
    assert_eq!(
        String::from_utf8(ours).expect("utf8"),
        String::from_utf8(golden("signed.toml.sig")).expect("utf8")
    );
}

#[test]
fn signed_load_accepts_go_signature() {
    let opts = Options {
        config_dir: Some(golden_dir()),
        signed: SignedCharters::Required {
            verify_key: golden_dir().join("charter.pub").display().to_string(),
        },
        ..Options::default()
    };
    let charter = load("signed", &opts).expect("signed load");
    assert_eq!(charter.host.image, "alpine:3.20");
    assert_eq!(charter.policy.len(), 1);
}
