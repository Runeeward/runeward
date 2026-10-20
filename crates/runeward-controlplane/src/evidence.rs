//! Portable, signed evidence documents for a Citadel.

use runeward_ledger::Bundle;
use runeward_ledger::evidence::{self, Document, Finding};

use crate::error::{Error, Result};
use crate::manager::Manager;

impl Manager {
    /// Pairs the Citadel's signed Chronicle bundle with the redacted,
    /// resolved Charter that governed it and its lint findings.
    pub async fn evidence(&self, id: &str, version: &str) -> Result<Document> {
        let sess = self.session(id)?;
        let mut portable = sess.charter.clone();
        let source = portable
            .source
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        portable.source = source.clone().into();
        let policy_view = runeward_charter::render(&portable);
        let bundle_json = self.export_bundle(id).await?;
        let bundle: Bundle = serde_json::from_slice(&bundle_json)
            .map_err(|e| Error::other(format!("decode Chronicle bundle: {e}")))?;
        let findings = runeward_charter::lint(&sess.charter)
            .into_iter()
            .map(|f| Finding {
                severity: f.severity.as_str().into(),
                field: f.field,
                message: f.message,
            })
            .collect();
        Ok(evidence::new(
            version,
            &sess.charter.name,
            &source,
            &sess.charter.host.image,
            &policy_view,
            findings,
            bundle,
        ))
    }
}
