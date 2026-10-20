//! Distributes runeward policies as signed OCI artifacts.
//!
//! A bundle is a single-layer image manifest (v1.1, artifact type
//! [`ARTIFACT_TYPE`]): the layer is the raw policy (`.rego` or a TOML
//! `[[cel]]` fragment) and the config blob records the engine and optional
//! Rego query.
//!
//! Signing the manifest digest would be circular (the signature lives in the
//! manifest annotations), so the signature instead covers a canonical payload
//! built from the config and layer blob digests:
//!
//! ```text
//! runeward.policy.bundle.v1
//! config=<config-blob-digest>
//! layer=<layer-blob-digest>
//! ```
//!
//! That transitively covers the policy bytes and metadata. On pull, blob bytes
//! are checked against their descriptor digests and the payload is recomputed
//! and verified, so a tampered blob or manifest fails closed. The signature,
//! public key and key id are stored as manifest annotations.
//!
//! Everything on the wire matches the Go implementation, so bundles pushed by
//! either side pull and verify on the other.

mod digest;
mod manifest;
mod reference;
mod remote;
mod store;

use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::manifest::{Descriptor, Manifest, go_json};
use crate::reference::Reference;
use crate::store::{MAX_MANIFEST_BYTES, Target, verify_content, verify_digest};

pub use runeward_keys::KeyError;
pub use store::StoreError;

/// Media type of the bundle config blob (engine + query).
pub const MEDIA_TYPE_CONFIG: &str = "application/vnd.runeward.policy.config.v1+json";
/// Layer media type for a Rego module.
pub const MEDIA_TYPE_LAYER_REGO: &str = "application/vnd.runeward.policy.layer.v1.rego";
/// Layer media type for a CEL TOML fragment.
pub const MEDIA_TYPE_LAYER_CEL: &str = "application/vnd.runeward.policy.layer.v1.cel+toml";
/// Artifact type identifying runeward policy bundle manifests.
pub const ARTIFACT_TYPE: &str = "application/vnd.runeward.policy.v1";

/// Annotation holding the base64 signature over the signing payload.
pub const ANNOTATION_SIGNATURE: &str = "runeward.dev/signature";
/// Annotation holding the signer's base64 public key.
pub const ANNOTATION_SIGNING_KEY: &str = "runeward.dev/signing-key";
/// Annotation holding the signer's short key fingerprint.
pub const ANNOTATION_KEY_ID: &str = "runeward.dev/key-id";

/// Domain-separation tag of the v1 signing payload.
const SIGNING_PAYLOAD_PREFIX: &str = "runeward.policy.bundle.v1";

/// Policy engine a bundle targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Engine {
    /// A Rego module.
    Rego,
    /// A TOML fragment of `[[cel]]` rules.
    Cel,
}

impl Engine {
    /// The identifier carried in the bundle config (`"rego"` or `"cel"`).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Rego => "rego",
            Self::Cel => "cel",
        }
    }

    /// The layer media type for this engine.
    pub fn layer_media_type(self) -> &'static str {
        match self {
            Self::Rego => MEDIA_TYPE_LAYER_REGO,
            Self::Cel => MEDIA_TYPE_LAYER_CEL,
        }
    }

    /// Maps a layer media type back to its engine.
    pub fn from_layer_media_type(media_type: &str) -> Result<Self, Error> {
        match media_type {
            MEDIA_TYPE_LAYER_REGO => Ok(Self::Rego),
            MEDIA_TYPE_LAYER_CEL => Ok(Self::Cel),
            other => Err(Error::UnknownLayerMediaType(other.to_owned())),
        }
    }
}

impl fmt::Display for Engine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Engine {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        match s {
            "rego" => Ok(Self::Rego),
            "cel" => Ok(Self::Cel),
            other => Err(Error::UnknownEngine(other.to_owned())),
        }
    }
}

/// The decoded content of a policy bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bundle {
    /// Policy engine.
    pub engine: Engine,
    /// Optional Rego decision entrypoint (ignored for CEL); an empty string
    /// is treated as absent.
    pub query: Option<String>,
    /// Raw policy bytes.
    pub policy: Vec<u8>,
    /// Manifest annotations returned on pull; ignored on push.
    pub annotations: BTreeMap<String, String>,
}

impl Bundle {
    /// A bundle with no query and no annotations.
    pub fn new(engine: Engine, policy: impl Into<Vec<u8>>) -> Self {
        Self {
            engine,
            query: None,
            policy: policy.into(),
            annotations: BTreeMap::new(),
        }
    }

    /// Sets the Rego decision query.
    #[must_use]
    pub fn with_query(mut self, query: impl Into<String>) -> Self {
        self.query = Some(query.into());
        self
    }

    /// The exact config blob bytes Go's `json.Marshal` produces.
    fn config_bytes(&self) -> Result<Vec<u8>, Error> {
        go_json(&ConfigOut {
            engine: self.engine.as_str(),
            query: self.query.as_deref().unwrap_or_default(),
        })
        .map_err(Error::EncodeConfig)
    }
}

/// Options for [`push`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PushOptions {
    /// Talk plain HTTP instead of HTTPS (local or insecure registries).
    pub plain_http: bool,
}

/// Options for [`pull`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PullOptions {
    /// Talk plain HTTP instead of HTTPS.
    pub plain_http: bool,
}

/// A policy bundle error. Messages match the Go implementation.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The OCI reference is malformed.
    #[error("policybundle: parse reference {reference:?}: invalid reference: {reason}")]
    InvalidReference {
        /// The reference as given.
        reference: String,
        /// Why it was rejected.
        reason: String,
    },
    /// The engine name is neither `rego` nor `cel`.
    #[error("policybundle: unknown engine {0:?} (want \"rego\" or \"cel\")")]
    UnknownEngine(String),
    /// The policy layer has an unrecognised media type.
    #[error("policybundle: unrecognized policy layer media type {0:?}")]
    UnknownLayerMediaType(String),
    /// The config blob could not be encoded.
    #[error("policybundle: marshal config: {0}")]
    EncodeConfig(#[source] serde_json::Error),
    /// The manifest could not be encoded.
    #[error("policybundle: pack manifest: {0}")]
    EncodeManifest(#[source] serde_json::Error),
    /// A store or registry operation failed.
    #[error("policybundle: {op}: {source}")]
    Store {
        /// The operation, e.g. `push config blob`.
        op: String,
        /// The underlying failure.
        #[source]
        source: StoreError,
    },
    /// The manifest is not valid JSON.
    #[error("policybundle: decode manifest: {0}")]
    DecodeManifest(#[source] serde_json::Error),
    /// The config blob is not valid JSON.
    #[error("policybundle: decode config: {0}")]
    DecodeConfig(#[source] serde_json::Error),
    /// The manifest does not have exactly one layer.
    #[error("policybundle: expected exactly 1 policy layer, got {0}")]
    LayerCount(usize),
    /// A verify key was supplied but the bundle carries no signature.
    #[error("policybundle: bundle is unsigned but a verify key was supplied")]
    Unsigned,
    /// The signature annotation is not valid base64.
    #[error("policybundle: decode signature: {0}")]
    DecodeSignature(#[source] base64::DecodeError),
    /// The signature does not verify against the supplied key.
    #[error("policybundle: signature does not verify against the supplied key")]
    BadSignature,
    /// A key could not be decoded.
    #[error("policybundle: {0}")]
    Key(#[from] KeyError),
}

impl Error {
    fn store(op: impl Into<String>) -> impl FnOnce(StoreError) -> Self {
        let op = op.into();
        move |source| Self::Store { op, source }
    }
}

/// JSON body of the config blob, as written.
#[derive(Serialize)]
struct ConfigOut<'a> {
    engine: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    query: &'a str,
}

/// JSON body of the config blob, as read (the engine comes from the layer).
#[derive(Deserialize)]
struct ConfigIn {
    #[serde(default)]
    query: String,
}

/// Builds the canonical signed bytes from the config and layer digests.
fn signing_payload(config: &Descriptor, layer: &Descriptor) -> Vec<u8> {
    format!(
        "{SIGNING_PAYLOAD_PREFIX}\nconfig={}\nlayer={}",
        config.digest, layer.digest
    )
    .into_bytes()
}

/// Removes an optional `oci://` prefix from a reference.
pub fn strip_scheme(reference: &str) -> &str {
    reference.strip_prefix("oci://").unwrap_or(reference)
}

fn parse_reference(reference: &str) -> Result<Reference, Error> {
    Reference::parse(strip_scheme(reference)).map_err(|reason| Error::InvalidReference {
        reference: reference.to_owned(),
        reason,
    })
}

/// Signs `bundle` with `key` and pushes it to the OCI reference `reference`
/// (an optional `oci://` prefix is stripped), returning the manifest digest.
///
/// The manifest is tagged when the reference carries a tag; a digest
/// reference or a bare repository pushes it untagged. Registry access is
/// anonymous, as with the Go implementation.
pub async fn push(
    reference: &str,
    bundle: &Bundle,
    key: &SigningKey,
    opts: PushOptions,
) -> Result<String, Error> {
    let parsed = parse_reference(reference)?;
    let repo = remote::Repository::new(&parsed, opts.plain_http).await;
    push_to(&repo, &parsed.reference, bundle, key).await
}

/// Network-free core of [`push`]; tags the manifest when `tag` is a
/// non-empty, non-digest reference.
async fn push_to<T: Target>(
    target: &T,
    tag: &str,
    bundle: &Bundle,
    key: &SigningKey,
) -> Result<String, Error> {
    let config_bytes = bundle.config_bytes()?;
    let config = Descriptor::of(MEDIA_TYPE_CONFIG, &config_bytes);
    target
        .push_blob(&config, config_bytes)
        .await
        .map_err(Error::store("push config blob"))?;
    let layer = Descriptor::of(bundle.engine.layer_media_type(), &bundle.policy);
    target
        .push_blob(&layer, bundle.policy.clone())
        .await
        .map_err(Error::store("push policy layer"))?;

    let public = key.verifying_key();
    let signature = key.sign(&signing_payload(&config, &layer));
    let annotations = BTreeMap::from([
        (
            ANNOTATION_SIGNATURE.to_owned(),
            STANDARD.encode(signature.to_bytes()),
        ),
        (
            ANNOTATION_SIGNING_KEY.to_owned(),
            runeward_keys::encode_public(&public),
        ),
        (ANNOTATION_KEY_ID.to_owned(), runeward_keys::key_id(&public)),
    ]);
    let manifest = Manifest::pack_v1_1(ARTIFACT_TYPE, config, vec![layer], annotations);
    push_manifest(target, &manifest, tag).await
}

/// Serialises and stores `manifest`, tagging it when `tag` is a tag.
async fn push_manifest<T: Target>(
    target: &T,
    manifest: &Manifest,
    tag: &str,
) -> Result<String, Error> {
    let bytes = go_json(manifest).map_err(Error::EncodeManifest)?;
    let desc = Descriptor::of(&manifest.media_type, &bytes);
    let tag = (!tag.is_empty() && !tag.contains(':')).then_some(tag);
    let op = match tag {
        Some(tag) => format!("tag {tag:?}"),
        None => "pack manifest".to_owned(),
    };
    target
        .push_manifest(&desc, bytes, tag)
        .await
        .map_err(Error::store(op))?;
    Ok(desc.digest)
}

/// Fetches a policy bundle from the OCI reference `reference` (an optional
/// `oci://` prefix is stripped; no tag means `latest`).
///
/// With `verify` set a valid ed25519 signature is required and a missing or
/// invalid one fails closed. With `verify` unset no signature check is done
/// (the `insecure_skip_verify` path); blob digests are still enforced.
pub async fn pull(
    reference: &str,
    verify: Option<&VerifyingKey>,
    opts: PullOptions,
) -> Result<Bundle, Error> {
    let parsed = parse_reference(reference)?;
    let repo = remote::Repository::new(&parsed, opts.plain_http).await;
    pull_from(&repo, &parsed.reference, verify).await
}

/// Network-free core of [`pull`]; `reference` is the tag or digest to resolve.
async fn pull_from<T: Target>(
    target: &T,
    reference: &str,
    verify: Option<&VerifyingKey>,
) -> Result<Bundle, Error> {
    let reference = if reference.is_empty() {
        "latest"
    } else {
        reference
    };
    let fetch_op = || format!("fetch manifest {reference:?}");
    let (manifest_digest, manifest_bytes) = target
        .fetch_manifest(reference)
        .await
        .map_err(Error::store(fetch_op()))?;
    if manifest_bytes.len() > MAX_MANIFEST_BYTES {
        return Err(Error::store(fetch_op())(StoreError::TooLarge {
            limit: MAX_MANIFEST_BYTES,
        }));
    }
    verify_digest(&manifest_digest, &manifest_bytes).map_err(Error::store(fetch_op()))?;

    let manifest: Manifest =
        serde_json::from_slice(&manifest_bytes).map_err(Error::DecodeManifest)?;
    let [layer] = manifest.layers.as_slice() else {
        return Err(Error::LayerCount(manifest.layers.len()));
    };

    // Verify the signature (if required) before trusting any blob bytes.
    if let Some(key) = verify {
        verify_signature(&manifest, layer, key)?;
    }

    let engine = Engine::from_layer_media_type(&layer.media_type)?;

    let config_bytes = fetch_verified(target, &manifest.config, "fetch config blob").await?;
    let config: ConfigIn = serde_json::from_slice(&config_bytes).map_err(Error::DecodeConfig)?;
    let policy = fetch_verified(target, layer, "fetch policy layer").await?;

    Ok(Bundle {
        engine,
        query: Some(config.query).filter(|q| !q.is_empty()),
        policy,
        annotations: manifest.annotations,
    })
}

/// Fetches a blob and checks it against its descriptor's size and digest.
async fn fetch_verified<T: Target>(
    target: &T,
    desc: &Descriptor,
    op: &'static str,
) -> Result<Vec<u8>, Error> {
    let data = target.fetch_blob(desc).await.map_err(Error::store(op))?;
    verify_content(desc, &data).map_err(Error::store(op))?;
    Ok(data)
}

/// Checks the manifest's ed25519 signature against `key`, failing closed when
/// the annotation is missing or malformed.
fn verify_signature(
    manifest: &Manifest,
    layer: &Descriptor,
    key: &VerifyingKey,
) -> Result<(), Error> {
    let sig_b64 = manifest
        .annotations
        .get(ANNOTATION_SIGNATURE)
        .filter(|s| !s.is_empty())
        .ok_or(Error::Unsigned)?;
    let raw = STANDARD.decode(sig_b64).map_err(Error::DecodeSignature)?;
    let signature = Signature::from_slice(&raw).map_err(|_| Error::BadSignature)?;
    key.verify(&signing_payload(&manifest.config, layer), &signature)
        .map_err(|_| Error::BadSignature)
}

/// Parses a base64 ed25519 public key; surrounding whitespace is ignored.
pub fn decode_public_key(s: &str) -> Result<VerifyingKey, Error> {
    Ok(runeward_keys::decode_public(s)?)
}

/// Parses a base64 ed25519 private key in the 64-byte `seed || public` form.
pub fn decode_private_key(s: &str) -> Result<SigningKey, Error> {
    Ok(runeward_keys::decode_private(s)?)
}

/// Base64-encodes raw key bytes.
pub fn encode_key(bytes: &[u8]) -> String {
    runeward_keys::encode(bytes)
}

/// Returns the short fingerprint of a public key.
pub fn key_id(public: &VerifyingKey) -> String {
    runeward_keys::key_id(public)
}

#[cfg(test)]
mod tests;
