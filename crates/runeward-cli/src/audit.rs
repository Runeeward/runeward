//! Offline audit tools: `chronicle verify` and `evidence export|verify`.

use std::fs::File;
use std::io::Write;

use anyhow::{Result, anyhow, bail};
use runeward_charter::Charter;
use runeward_controlplane::Manager;
use runeward_ledger::Bundle;
use runeward_ledger::evidence::{self, Document, Finding};

use crate::common::{go_io_error, go_quote, load_profile, manager_config_dir, resolve_config_dir};
use crate::version::VERSION;

fn open(path: &str) -> Result<File> {
    File::open(path).map_err(|e| anyhow!(go_io_error("open", path, &e)))
}

/// `runeward chronicle verify <bundle.json>`.
pub fn chronicle_verify(path: &str) -> Result<()> {
    let n = runeward_ledger::verify_bundle(open(path)?)?;
    println!("ok: {n} events verified (hash chain + signatures intact)");
    Ok(())
}

/// `runeward evidence verify <evidence.json>`.
pub fn evidence_verify(path: &str) -> Result<()> {
    let doc = evidence::read(open(path)?)?;
    let count = evidence::verify(&doc)?;
    println!(
        "verified: policy digest and {count} signed audit event(s); key {}",
        doc.chronicle.key_id.trim()
    );
    Ok(())
}

/// `runeward evidence export <charter>`.
pub async fn evidence_export(
    name: &str,
    session: &str,
    output: &str,
    force: bool,
    config_dir: &str,
) -> Result<()> {
    let p = load_profile(name, config_dir)?;
    let mgr = Manager::open(manager_config_dir(&resolve_config_dir(config_dir)))
        .await
        .map_err(|e| {
            anyhow!(
                "open local audit state: {e} (stop a running server first, or download evidence from its dashboard)"
            )
        })?;
    let result = export_to(&mgr, &p, session, output, force).await;
    let _ = mgr.close().await;
    result
}

async fn export_to(
    mgr: &Manager,
    p: &Charter,
    session: &str,
    output: &str,
    force: bool,
) -> Result<()> {
    let doc = build_evidence_document(mgr, p, session).await?;
    let mut buf = Vec::new();
    evidence::write(&mut buf, &doc)?;
    if output.is_empty() || output == "-" {
        std::io::stdout().write_all(&buf)?;
        return Ok(());
    }
    let mut f = create_output(output, force)?;
    f.write_all(&buf)?;
    eprintln!("evidence package: {output}");
    Ok(())
}

/// Pairs the redacted, resolved Charter with the signed audit bundle.
async fn build_evidence_document(mgr: &Manager, p: &Charter, session: &str) -> Result<Document> {
    let source = p
        .source
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let mut portable = p.clone();
    portable.source = source.clone().into();
    let policy_view = runeward_charter::render(&portable);
    let bundle_json = mgr.export_bundle(session).await?;
    let bundle: Bundle = serde_json::from_slice(&bundle_json)
        .map_err(|e| anyhow!("decode signed audit bundle: {e}"))?;
    let findings = runeward_charter::lint(p)
        .into_iter()
        .map(|f| Finding {
            severity: f.severity.as_str().into(),
            field: f.field,
            message: f.message,
        })
        .collect();
    Ok(evidence::new(
        VERSION,
        &p.name,
        &source,
        &p.host.image,
        &policy_view,
        findings,
        bundle,
    ))
}

/// Opens the output exclusively (0600) unless `force` replaces it.
fn create_output(output: &str, force: bool) -> Result<File> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true);
    if force {
        opts.create(true).truncate(true);
    } else {
        opts.create_new(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    match opts.open(output) {
        Ok(f) => Ok(f),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            bail!(
                "output {} already exists; pass --force to replace it",
                go_quote(output)
            )
        }
        Err(e) => Err(anyhow!(go_io_error("open", output, &e))),
    }
}
