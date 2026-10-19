//! Ports of the Go `policybundle` tests plus golden-fixture checks.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use super::*;
use crate::store::MemoryStore;

fn new_key() -> (VerifyingKey, SigningKey) {
    let key = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
    (key.verifying_key(), key)
}

fn rego_bundle() -> Bundle {
    Bundle::new(Engine::Rego, "package runeward\n\ndecision := \"allow\"\n")
        .with_query("data.runeward.decision")
}

fn cel_bundle() -> Bundle {
    Bundle::new(
        Engine::Cel,
        "[[cel]]\nexpr = 'tool == \"shell\"'\nverdict = \"deny\"\nreason = \"no shell\"\n",
    )
}

async fn round_trip(
    b: &Bundle,
    key: &SigningKey,
    verify: Option<&VerifyingKey>,
) -> Result<Bundle, Error> {
    let store = MemoryStore::default();
    push_to(&store, "v1", b, key).await.expect("push");
    pull_from(&store, "v1", verify).await
}

#[tokio::test]
async fn round_trip_rego() {
    let (public, key) = new_key();
    let src = rego_bundle();
    let got = round_trip(&src, &key, Some(&public)).await.expect("pull");
    assert_eq!(got.engine, Engine::Rego);
    assert_eq!(got.query, src.query);
    assert_eq!(got.policy, src.policy);
    assert_eq!(got.annotations[ANNOTATION_KEY_ID], key_id(&public));
    assert_eq!(
        got.annotations[ANNOTATION_SIGNING_KEY],
        encode_key(public.as_bytes())
    );
    assert!(got.annotations.contains_key(manifest::ANNOTATION_CREATED));
}

#[tokio::test]
async fn round_trip_cel() {
    let (public, key) = new_key();
    let src = cel_bundle();
    let got = round_trip(&src, &key, Some(&public)).await.expect("pull");
    assert_eq!(got.engine, Engine::Cel);
    assert_eq!(got.query, None);
    assert_eq!(got.policy, src.policy);
}

#[tokio::test]
async fn pull_without_verify_key_succeeds() {
    let (_, key) = new_key();
    let got = round_trip(&rego_bundle(), &key, None).await.expect("pull");
    assert_eq!(got.engine, Engine::Rego);
}

#[tokio::test]
async fn pull_wrong_key_fails() {
    let (_, key) = new_key();
    let (wrong, _) = new_key();
    let err = round_trip(&rego_bundle(), &key, Some(&wrong))
        .await
        .expect_err("wrong key must fail");
    assert!(matches!(err, Error::BadSignature), "{err}");
}

/// Repoints the manifest's layer at a tampered blob; the signature covers the
/// original digest, so a verifying pull must fail closed.
#[tokio::test]
async fn tampered_policy_fails() {
    let (public, key) = new_key();
    let store = MemoryStore::default();
    push_to(&store, "v1", &rego_bundle(), &key)
        .await
        .expect("push");

    let (_, bytes) = store.fetch_manifest("v1").await.expect("fetch manifest");
    let orig: Manifest = serde_json::from_slice(&bytes).expect("decode manifest");

    let tampered = b"package runeward\n\ndecision := \"deny\"\n".to_vec();
    let layer = Descriptor::of(MEDIA_TYPE_LAYER_REGO, &tampered);
    store
        .push_blob(&layer, tampered)
        .await
        .expect("push tampered");
    let forged = Manifest::pack_v1_1(
        ARTIFACT_TYPE,
        orig.config.clone(),
        vec![layer],
        orig.annotations.clone(),
    );
    push_manifest(&store, &forged, "forged")
        .await
        .expect("push forged");

    let err = pull_from(&store, "forged", Some(&public))
        .await
        .expect_err("tampered layer must fail");
    assert!(matches!(err, Error::BadSignature), "{err}");
}

#[tokio::test]
async fn unsigned_bundle_fails_with_verify_key() {
    let (public, key) = new_key();
    let store = MemoryStore::default();
    push_to(&store, "v1", &cel_bundle(), &key)
        .await
        .expect("push");
    let (_, bytes) = store.fetch_manifest("v1").await.expect("fetch");
    let mut m: Manifest = serde_json::from_slice(&bytes).expect("decode");
    m.annotations.remove(ANNOTATION_SIGNATURE);
    push_manifest(&store, &m, "unsigned").await.expect("push");

    let err = pull_from(&store, "unsigned", Some(&public))
        .await
        .expect_err("unsigned must fail");
    assert!(matches!(err, Error::Unsigned), "{err}");
    assert!(pull_from(&store, "unsigned", None).await.is_ok());
}

/// A store that serves different bytes for the policy layer than were pushed.
struct Hostile(MemoryStore);

impl Target for Hostile {
    async fn push_blob(&self, desc: &Descriptor, data: Vec<u8>) -> Result<(), StoreError> {
        self.0.push_blob(desc, data).await
    }

    async fn push_manifest(
        &self,
        desc: &Descriptor,
        data: Vec<u8>,
        tag: Option<&str>,
    ) -> Result<(), StoreError> {
        self.0.push_manifest(desc, data, tag).await
    }

    async fn fetch_manifest(&self, reference: &str) -> Result<(String, Vec<u8>), StoreError> {
        self.0.fetch_manifest(reference).await
    }

    async fn fetch_blob(&self, desc: &Descriptor) -> Result<Vec<u8>, StoreError> {
        let mut data = self.0.fetch_blob(desc).await?;
        if desc.media_type == MEDIA_TYPE_LAYER_REGO {
            data[0] ^= 1;
        }
        Ok(data)
    }
}

/// Blob bytes are checked against their descriptors even without a verify
/// key, as oras-go's `content.FetchAll` does.
#[tokio::test]
async fn swapped_blob_bytes_fail_without_verify_key() {
    let (_, key) = new_key();
    let store = Hostile(MemoryStore::default());
    push_to(&store, "v1", &rego_bundle(), &key)
        .await
        .expect("push");
    let err = pull_from(&store, "v1", None)
        .await
        .expect_err("swapped bytes must fail");
    assert!(
        matches!(
            &err,
            Error::Store {
                source: StoreError::DigestMismatch { .. },
                ..
            }
        ),
        "{err}"
    );
    assert!(
        err.to_string()
            .starts_with("policybundle: fetch policy layer: ")
    );
}

#[tokio::test]
async fn rejects_manifest_without_single_layer() {
    let (_, key) = new_key();
    let store = MemoryStore::default();
    push_to(&store, "v1", &rego_bundle(), &key)
        .await
        .expect("push");
    let (_, bytes) = store.fetch_manifest("v1").await.expect("fetch");
    let mut m: Manifest = serde_json::from_slice(&bytes).expect("decode");
    m.layers.push(m.layers[0].clone());
    push_manifest(&store, &m, "two").await.expect("push");
    let err = pull_from(&store, "two", None)
        .await
        .expect_err("two layers");
    assert!(matches!(err, Error::LayerCount(2)), "{err}");
}

#[tokio::test]
async fn digest_reference_pushes_untagged_and_pulls_by_digest() {
    let (public, key) = new_key();
    let store = MemoryStore::default();
    let digest = push_to(&store, "", &cel_bundle(), &key)
        .await
        .expect("push");
    assert!(pull_from(&store, "", None).await.is_err(), "no latest tag");
    let got = pull_from(&store, &digest, Some(&public))
        .await
        .expect("pull by digest");
    assert_eq!(got.engine, Engine::Cel);
    store.tag(&digest, "latest");
    assert!(pull_from(&store, "", Some(&public)).await.is_ok());
}

/// The config blob, signing payload and signature are byte-identical to the
/// Go golden fixture.
#[tokio::test]
async fn matches_go_golden_signature() {
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../testdata/golden/");
    let raw = fs::read_to_string(format!("{root}policy-bundle.json")).expect("fixture");
    let fx: HashMap<String, String> = serde_json::from_str(&raw).expect("parse fixture");

    let key = decode_private_key(&fx["private_key"]).expect("private key");
    let public = decode_public_key(&fx["public_key"]).expect("public key");
    assert_eq!(key.verifying_key(), public);
    assert_eq!(key_id(&public), fx["key_id"]);

    let bundle =
        Bundle::new(Engine::Rego, "package runeward\n").with_query("data.runeward.decision");
    let config = Descriptor::of(MEDIA_TYPE_CONFIG, &bundle.config_bytes().expect("config"));
    let layer = Descriptor::of(MEDIA_TYPE_LAYER_REGO, &bundle.policy);
    let payload = signing_payload(&config, &layer);
    assert_eq!(String::from_utf8_lossy(&payload), fx["payload"]);

    let sig = key.sign(&payload);
    assert_eq!(STANDARD.encode(sig.to_bytes()), fx["signature"]);

    // A manifest carrying the Go signature verifies, and a full push with the
    // golden key produces the same signature annotation.
    let store = MemoryStore::default();
    push_to(&store, "golden", &bundle, &key)
        .await
        .expect("push");
    let got = pull_from(&store, "golden", Some(&public))
        .await
        .expect("pull");
    assert_eq!(got.annotations[ANNOTATION_SIGNATURE], fx["signature"]);
    assert_eq!(got.annotations[ANNOTATION_SIGNING_KEY], fx["public_key"]);
    assert_eq!(got.annotations[ANNOTATION_KEY_ID], fx["key_id"]);
}

#[test]
fn config_blob_matches_go_json() {
    let b = rego_bundle();
    assert_eq!(
        b.config_bytes().expect("config"),
        br#"{"engine":"rego","query":"data.runeward.decision"}"#
    );
    assert_eq!(
        cel_bundle().config_bytes().expect("config"),
        br#"{"engine":"cel"}"#
    );
    let html = Bundle::new(Engine::Rego, "").with_query("a<b");
    assert_eq!(
        html.config_bytes().expect("config"),
        br#"{"engine":"rego","query":"a\u003cb"}"#
    );
}

#[test]
fn engines_and_media_types() {
    assert_eq!("rego".parse::<Engine>().expect("rego"), Engine::Rego);
    assert_eq!("cel".parse::<Engine>().expect("cel"), Engine::Cel);
    let err = "wasm".parse::<Engine>().expect_err("unknown");
    assert_eq!(
        err.to_string(),
        r#"policybundle: unknown engine "wasm" (want "rego" or "cel")"#
    );
    for e in [Engine::Rego, Engine::Cel] {
        assert_eq!(
            Engine::from_layer_media_type(e.layer_media_type()).expect("round trip"),
            e
        );
    }
    assert!(Engine::from_layer_media_type("text/plain").is_err());
}

#[test]
fn strips_scheme_and_parses_references() {
    assert_eq!(strip_scheme("oci://r.io/a:v1"), "r.io/a:v1");
    assert_eq!(strip_scheme("r.io/a:v1"), "r.io/a:v1");
    let r = parse_reference("oci://localhost:5000/runeward/policy:v1").expect("parse");
    assert_eq!(r.reference, "v1");
    let err = parse_reference("oci://nohost").expect_err("invalid");
    assert!(
        err.to_string()
            .starts_with(r#"policybundle: parse reference "oci://nohost""#)
    );
}

#[test]
fn key_helpers_match_go_formats() {
    let (public, key) = new_key();
    let priv_b64 = encode_key(&key.to_keypair_bytes());
    let pub_b64 = encode_key(public.as_bytes());
    assert_eq!(
        decode_private_key(&format!(" {priv_b64}\n")).expect("private"),
        key
    );
    assert_eq!(decode_public_key(&pub_b64).expect("public"), public);
    assert_eq!(key_id(&public).len(), 16);
    let err = decode_public_key(&encode_key(&[1; 31])).expect_err("short");
    assert_eq!(
        err.to_string(),
        "policybundle: public key wrong size 31 (want 32)"
    );
}

/// A minimal OCI image layout store, the equivalent of oras-go's `oci.Store`.
struct OciLayout {
    root: PathBuf,
}

impl OciLayout {
    fn new(root: &Path) -> Self {
        fs::write(
            root.join("oci-layout"),
            br#"{"imageLayoutVersion":"1.0.0"}"#,
        )
        .expect("oci-layout");
        fs::write(
            root.join("index.json"),
            br#"{"schemaVersion":2,"manifests":[]}"#,
        )
        .expect("index.json");
        Self {
            root: root.to_owned(),
        }
    }

    fn blob_path(&self, digest: &str) -> PathBuf {
        let (alg, hex) = digest.split_once(':').expect("digest");
        self.root.join("blobs").join(alg).join(hex)
    }

    fn write_blob(&self, desc: &Descriptor, data: &[u8]) -> Result<(), StoreError> {
        verify_content(desc, data)?;
        let path = self.blob_path(&desc.digest);
        fs::create_dir_all(path.parent().expect("parent"))?;
        fs::write(path, data)?;
        Ok(())
    }

    fn index(&self) -> serde_json::Value {
        serde_json::from_slice(&fs::read(self.root.join("index.json")).expect("read index"))
            .expect("parse index")
    }
}

impl Target for OciLayout {
    async fn push_blob(&self, desc: &Descriptor, data: Vec<u8>) -> Result<(), StoreError> {
        self.write_blob(desc, &data)
    }

    async fn push_manifest(
        &self,
        desc: &Descriptor,
        data: Vec<u8>,
        tag: Option<&str>,
    ) -> Result<(), StoreError> {
        self.write_blob(desc, &data)?;
        let mut index = self.index();
        let mut entry = serde_json::to_value(desc).expect("descriptor json");
        if let Some(tag) = tag {
            entry["annotations"] = serde_json::json!({"org.opencontainers.image.ref.name": tag});
        }
        index["manifests"]
            .as_array_mut()
            .expect("manifests")
            .push(entry);
        fs::write(
            self.root.join("index.json"),
            serde_json::to_vec(&index).expect("index json"),
        )?;
        Ok(())
    }

    async fn fetch_manifest(&self, reference: &str) -> Result<(String, Vec<u8>), StoreError> {
        let index = self.index();
        let digest = index["manifests"]
            .as_array()
            .expect("manifests")
            .iter()
            .rev()
            .find(|m| {
                m["annotations"]["org.opencontainers.image.ref.name"] == reference
                    || m["digest"] == reference
            })
            .and_then(|m| m["digest"].as_str())
            .ok_or_else(|| StoreError::NotFound(reference.to_owned()))?
            .to_owned();
        let data = fs::read(self.blob_path(&digest))?;
        Ok((digest, data))
    }

    async fn fetch_blob(&self, desc: &Descriptor) -> Result<Vec<u8>, StoreError> {
        Ok(fs::read(self.blob_path(&desc.digest))?)
    }
}

#[tokio::test]
async fn oci_layout_round_trip() {
    let (public, key) = new_key();
    let dir = tempfile::tempdir().expect("tempdir");
    let store = OciLayout::new(dir.path());
    let src = cel_bundle();
    push_to(&store, "v2", &src, &key).await.expect("push");
    let got = pull_from(&store, "v2", Some(&public)).await.expect("pull");
    assert_eq!(got.engine, Engine::Cel);
    assert_eq!(got.policy, src.policy);
}

/// Building the HTTPS client (ring provider) works and an unreachable
/// registry surfaces as an error rather than a panic.
#[tokio::test]
async fn unreachable_registry_is_an_error() {
    let err = pull(
        "127.0.0.1:1/runeward/policy:v1",
        None,
        PullOptions::default(),
    )
    .await
    .expect_err("nothing listens on port 1");
    assert!(
        err.to_string()
            .starts_with(r#"policybundle: fetch manifest "v1": "#),
        "{err}"
    );
}
