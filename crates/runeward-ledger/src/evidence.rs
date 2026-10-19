//! The portable, independently verifiable artifact produced after an agent
//! run: the resolved policy plus the signed audit bundle.

use std::io::{self, Read};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::LedgerError;
use crate::gojson::{self, go_struct};
use crate::gotime::{self, Time};
use crate::sign::Bundle;

/// Format identifier written into every document.
pub const FORMAT: &str = "runeward-evidence/v1";

/// A portable policy-lint finding captured at export time.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Finding {
    pub severity: String,
    pub field: String,
    pub message: String,
}

go_struct!(Finding {
    "severity" => severity: Str,
    "field" => field: Str,
    "message" => message: Str,
});

/// The resolved, secret-redacted policy that governed a run. `sha256` makes
/// accidental or malicious edits independently detectable.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct PolicySnapshot {
    pub name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub source: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub image: String,
    pub resolved: String,
    pub sha256: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub findings: Vec<Finding>,
}

go_struct!(PolicySnapshot {
    "name" => name: Str,
    "source" => source: Str,
    "image" => image: Str,
    "resolved" => resolved: Str,
    "sha256" => sha256: Str,
    "findings" => findings: Findings,
});

/// Policy context combined with the signed Chronicle audit bundle. The
/// embedded ledger public key verifies event integrity; organizations can pin
/// that key out of band when they need identity assurance as well.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Document {
    pub format: String,
    #[serde(serialize_with = "gotime::serialize")]
    pub generated_at: Time,
    pub runeward_version: String,
    pub policy: PolicySnapshot,
    pub chronicle: Bundle,
}

impl Default for Document {
    fn default() -> Self {
        Self {
            format: String::new(),
            generated_at: gotime::zero(),
            runeward_version: String::new(),
            policy: PolicySnapshot::default(),
            chronicle: Bundle::default(),
        }
    }
}

go_struct!(Document {
    "format" => format: Str,
    "generated_at" => generated_at: Time,
    "runeward_version" => runeward_version: Str,
    "policy" => policy: Policy,
    "chronicle" => chronicle: Bundle,
});

/// Evidence encoding, decoding and verification failures.
#[derive(Debug, thiserror::Error)]
pub enum EvidenceError {
    #[error("evidence: encode: {0}")]
    Encode(io::Error),
    #[error("evidence: decode: {0}")]
    Decode(serde_json::Error),
    #[error("evidence: unsupported format {0:?}")]
    UnsupportedFormat(String),
    #[error("evidence: policy snapshot hash mismatch")]
    PolicyHashMismatch,
    #[error(transparent)]
    Ledger(#[from] LedgerError),
}

/// Creates an evidence document stamped now and hashes the resolved policy
/// snapshot.
pub fn new(
    version: &str,
    name: &str,
    source: &str,
    image: &str,
    resolved: &str,
    findings: Vec<Finding>,
    chronicle: Bundle,
) -> Document {
    Document {
        format: FORMAT.to_owned(),
        generated_at: gotime::now(),
        runeward_version: version.to_owned(),
        policy: PolicySnapshot {
            name: name.to_owned(),
            source: source.to_owned(),
            image: image.to_owned(),
            resolved: resolved.to_owned(),
            sha256: sha256_hex(resolved),
            findings,
        },
        chronicle,
    }
}

/// Serializes a document as stable, human-inspectable JSON (two-space
/// indent, trailing newline).
pub fn write<W: io::Write>(w: W, doc: &Document) -> Result<(), EvidenceError> {
    gojson::encode_indent(w, doc).map_err(EvidenceError::Encode)
}

/// Decodes an evidence document (the first JSON value in r).
pub fn read<R: Read>(r: R) -> Result<Document, EvidenceError> {
    let mut de = serde_json::Deserializer::from_reader(r);
    Document::deserialize(&mut de).map_err(EvidenceError::Decode)
}

/// Checks the document format, policy digest, event hash chain, and every
/// event signature. Returns the number of verified events.
pub fn verify(doc: &Document) -> Result<usize, EvidenceError> {
    if doc.format != FORMAT {
        return Err(EvidenceError::UnsupportedFormat(doc.format.clone()));
    }
    if sha256_hex(&doc.policy.resolved) != doc.policy.sha256 {
        return Err(EvidenceError::PolicyHashMismatch);
    }
    Ok(doc.chronicle.verify()?)
}

fn sha256_hex(s: &str) -> String {
    hex::encode(Sha256::digest(s.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Event, Ledger, Signer};

    #[test]
    fn verify_detects_policy_and_event_tampering() {
        let dir = tempfile::tempdir().expect("tempdir");
        let l = Ledger::open(dir.path().join("ledger.jsonl")).expect("open");
        let signer = Signer::load_or_create(dir.path()).expect("signer");
        l.set_signer(Some(signer.clone()));
        l.append(Event {
            session_id: "s1".into(),
            tool: "shell".into(),
            action: "echo ok".into(),
            verdict: "allow".into(),
            ..Event::default()
        })
        .expect("append");
        let mut exported = Vec::new();
        l.export_bundle(&mut exported, "s1", &signer.public())
            .expect("export");
        l.close();
        let bundle: Bundle = serde_json::from_slice(&exported).expect("decode bundle");

        let mut doc = new(
            "test",
            "quickstart",
            "test.toml",
            "image",
            "resolved policy",
            Vec::new(),
            bundle,
        );
        assert_eq!(verify(&doc).expect("verify"), 1);

        let mut buf = Vec::new();
        write(&mut buf, &doc).expect("write");
        assert_eq!(read(buf.as_slice()).expect("read"), doc);

        let mut tampered = doc.clone();
        tampered.chronicle.events[0].action = "echo pwned".into();
        assert!(matches!(verify(&tampered), Err(EvidenceError::Ledger(_))));

        doc.policy.resolved = "tampered".into();
        assert!(matches!(
            verify(&doc),
            Err(EvidenceError::PolicyHashMismatch)
        ));
        doc.format = "other".into();
        assert!(matches!(
            verify(&doc),
            Err(EvidenceError::UnsupportedFormat(_))
        ));
    }
}
