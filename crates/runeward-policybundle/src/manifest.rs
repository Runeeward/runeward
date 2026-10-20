//! OCI image manifest and descriptor types, serialised exactly as Go's
//! `encoding/json` serialises `ocispec.Manifest` (field order, `omitempty`,
//! sorted annotation keys and HTML-safe escaping).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::digest;

/// The OCI image manifest media type.
pub(crate) const MEDIA_TYPE_IMAGE_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";

/// Annotation oras-go adds with the manifest creation time (RFC 3339).
pub(crate) const ANNOTATION_CREATED: &str = "org.opencontainers.image.created";

/// Manifest media types requested on pull, as oras-go's remote repository
/// sends in its `Accept` header.
pub(crate) const MANIFEST_ACCEPT: &[&str] = &[
    "application/vnd.docker.distribution.manifest.v2+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.index.v1+json",
    MEDIA_TYPE_IMAGE_MANIFEST,
    "application/vnd.oci.artifact.manifest.v1+json",
];

/// An OCI content descriptor.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub(crate) struct Descriptor {
    pub media_type: String,
    pub digest: String,
    pub size: i64,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub urls: Vec<String>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub annotations: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub artifact_type: String,
}

impl Descriptor {
    /// Describes `data` with the given media type and its sha256 digest.
    pub fn of(media_type: &str, data: &[u8]) -> Self {
        Self {
            media_type: media_type.to_owned(),
            digest: digest::sha256(data),
            size: i64::try_from(data.len()).unwrap_or(i64::MAX),
            ..Self::default()
        }
    }
}

/// An OCI image manifest.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub(crate) struct Manifest {
    pub schema_version: i64,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub media_type: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub artifact_type: String,
    pub config: Descriptor,
    pub layers: Vec<Descriptor>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<Descriptor>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub annotations: BTreeMap<String, String>,
}

impl Manifest {
    /// Builds an image manifest v1.1 the way oras-go's `PackManifest` does,
    /// adding the creation-time annotation when absent.
    pub fn pack_v1_1(
        artifact_type: &str,
        config: Descriptor,
        layers: Vec<Descriptor>,
        mut annotations: BTreeMap<String, String>,
    ) -> Self {
        annotations
            .entry(ANNOTATION_CREATED.to_owned())
            .or_insert_with(|| chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string());
        Self {
            schema_version: 2,
            media_type: MEDIA_TYPE_IMAGE_MANIFEST.to_owned(),
            artifact_type: artifact_type.to_owned(),
            config,
            layers,
            subject: None,
            annotations,
        }
    }
}

/// Serialises `value` to JSON byte-identical to Go's `json.Marshal`, which
/// escapes `<`, `>`, `&`, U+2028 and U+2029 inside strings.
pub(crate) fn go_json<T: Serialize>(value: &T) -> serde_json::Result<Vec<u8>> {
    let s = serde_json::to_string(value)?;
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '<' => out.push_str("\\u003c"),
            '>' => out.push_str("\\u003e"),
            '&' => out.push_str("\\u0026"),
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            c => out.push(c),
        }
    }
    Ok(out.into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn go_json_escapes_html_characters() {
        let got = go_json(&BTreeMap::from([("q", "a<b>&c\u{2028}\n")])).expect("marshal");
        assert_eq!(
            String::from_utf8(got).expect("utf8"),
            r#"{"q":"a\u003cb\u003e\u0026c\u2028\n"}"#
        );
    }

    #[test]
    fn manifest_matches_go_layout() {
        let m = Manifest::pack_v1_1(
            "application/x.test",
            Descriptor::of("application/x.cfg", b"{}"),
            vec![Descriptor::of("application/x.layer", b"x")],
            BTreeMap::from([
                ("b".to_owned(), "2".to_owned()),
                (
                    ANNOTATION_CREATED.to_owned(),
                    "2026-01-02T03:04:05Z".to_owned(),
                ),
            ]),
        );
        let got = String::from_utf8(go_json(&m).expect("marshal")).expect("utf8");
        let want = concat!(
            r#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","#,
            r#""artifactType":"application/x.test","config":{"mediaType":"application/x.cfg","#,
            r#""digest":"sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a","size":2},"#,
            r#""layers":[{"mediaType":"application/x.layer","#,
            r#""digest":"sha256:2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881","size":1}],"#,
            r#""annotations":{"b":"2","org.opencontainers.image.created":"2026-01-02T03:04:05Z"}}"#
        );
        assert_eq!(got, want);
    }
}
