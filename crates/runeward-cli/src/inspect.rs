//! Read-only Charter commands: `list`, `print` and `validate`.

use std::io::Write;

use anyhow::{Result, bail};
use runeward_charter::{Finding, Severity};

use crate::common::{charter_options, load_profile, resolve_config_dir};
use crate::tabwriter::TabWriter;

/// `runeward list`: every reachable Charter with its host and egress mode.
pub fn list(config_dir: &str) -> Result<()> {
    let dir = resolve_config_dir(config_dir);
    let opts = charter_options(&dir);
    let names = runeward_charter::list(&opts);
    if names.is_empty() {
        eprintln!("no charters found");
        return Ok(());
    }
    let mut tw = TabWriter::default();
    for n in &names {
        match runeward_charter::load(n, &opts) {
            Err(e) => tw.push(&format!("{n}\t(error: {e})\n")),
            Ok(p) => {
                let egress = if p.network.deny_by_default() {
                    format!("deny+{}", p.network.rules.len())
                } else {
                    "open".to_owned()
                };
                tw.push(&format!(
                    "{n}\thost={}\tegress={egress}\n",
                    p.host.host_type
                ));
            }
        }
    }
    let mut out = String::new();
    tw.flush(&mut out);
    std::io::stdout().write_all(out.as_bytes())?;
    Ok(())
}

/// `runeward print <charter>`: the resolved, redacted controls.
pub fn print(name: &str, config_dir: &str) -> Result<()> {
    let p = load_profile(name, config_dir)?;
    let mut stdout = std::io::stdout().lock();
    runeward_charter::print(&mut stdout, &p)?;
    Ok(())
}

/// `runeward validate [charter...]`: lints Charters without launching
/// anything. Fails on any error finding, and on warnings under `--strict`.
pub fn validate(names: &[String], strict: bool, config_dir: &str) -> Result<()> {
    let dir = resolve_config_dir(config_dir);
    let names: Vec<String> = if names.is_empty() {
        runeward_charter::list(&charter_options(&dir))
    } else {
        names.to_vec()
    };
    let mut out = String::new();
    if names.is_empty() {
        out.push_str("no charters found\n");
        std::io::stdout().write_all(out.as_bytes())?;
        return Ok(());
    }
    let (mut errors, mut warnings) = (0usize, 0usize);
    for name in &names {
        let findings = validate_one(name, &dir);
        for f in &findings {
            match f.severity {
                Severity::Error => errors += 1,
                Severity::Warn => warnings += 1,
            }
        }
        render_findings(&mut out, name, &findings);
    }
    std::io::stdout().write_all(out.as_bytes())?;
    if errors > 0 || (strict && warnings > 0) {
        bail!("validation failed: {errors} error(s), {warnings} warning(s)");
    }
    Ok(())
}

/// Resolves and lints one Charter, folding a load failure into an error
/// finding so it groups with the Charter's other output.
fn validate_one(name: &str, dir: &str) -> Vec<Finding> {
    match runeward_charter::load(name, &charter_options(dir)) {
        Ok(p) => runeward_charter::lint(&p),
        Err(e) => vec![Finding {
            severity: Severity::Error,
            field: "load".into(),
            message: e.to_string(),
        }],
    }
}

/// One Charter's findings under its name, or an `ok` line.
fn render_findings(out: &mut String, name: &str, findings: &[Finding]) {
    out.push_str(name);
    out.push('\n');
    if findings.is_empty() {
        out.push_str("  ok\n");
        return;
    }
    let mut tw = TabWriter::default();
    for f in findings {
        tw.push(&format!(
            "  {}\t{}\t{}\n",
            severity_marker(f.severity),
            f.field,
            f.message
        ));
    }
    tw.flush(out);
}

/// A fixed-width label for a finding severity.
fn severity_marker(sev: Severity) -> &'static str {
    match sev {
        Severity::Error => "[error]",
        Severity::Warn => "[warn] ",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn findings_align_like_go() {
        let mut out = String::new();
        render_findings(
            &mut out,
            "dev",
            &[
                Finding {
                    severity: Severity::Warn,
                    field: "host.image".into(),
                    message: "mutable tag".into(),
                },
                Finding {
                    severity: Severity::Error,
                    field: "env[0].op".into(),
                    message: "unresolved".into(),
                },
            ],
        );
        assert_eq!(
            out,
            "dev\n  [warn]   host.image  mutable tag\n  [error]  env[0].op   unresolved\n"
        );
        let mut ok = String::new();
        render_findings(&mut ok, "x", &[]);
        assert_eq!(ok, "x\n  ok\n");
    }
}
