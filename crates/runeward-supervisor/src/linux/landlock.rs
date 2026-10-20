//! Landlock filesystem confinement.

use std::path::Path;

use landlock::{
    ABI, Access, AccessFs, CompatLevel, Compatible, RestrictionStatus, Ruleset, RulesetAttr,
    RulesetCreatedAttr, RulesetStatus, path_beneath_rules,
};

use crate::config::{FilesystemConfig, LandlockMode, REQUIRED_MIN_ABI};
use crate::report::LandlockReport;

/// Debug builds only: caps the detected Landlock ABI, so tests can simulate
/// an older or Landlock-less kernel. It can only lower the ABI. Release
/// builds ignore it.
pub const TEST_ABI_ENV: &str = "RUNEWARD_SUPERVISOR_TEST_LANDLOCK_ABI";

/// Every ABI this build knows, newest first, with its number.
const KNOWN: [(ABI, u32); 9] = [
    (ABI::V9, 9),
    (ABI::V8, 8),
    (ABI::V7, 7),
    (ABI::V6, 6),
    (ABI::V5, 5),
    (ABI::V4, 4),
    (ABI::V3, 3),
    (ABI::V2, 2),
    (ABI::V1, 1),
];

fn abi_for(n: u32) -> Option<ABI> {
    KNOWN.iter().find(|(_, v)| *v == n).map(|(a, _)| *a)
}

/// Finds the newest ABI the running kernel fully supports by creating (and
/// discarding) a ruleset that hard-requires each one. Returns 0 when the
/// kernel has no usable Landlock.
pub fn detect_abi() -> u32 {
    let detected = KNOWN
        .iter()
        .find(|(abi, _)| {
            Ruleset::default()
                .set_compatibility(CompatLevel::HardRequirement)
                .handle_access(AccessFs::from_all(*abi))
                .and_then(|r| r.create())
                .is_ok()
        })
        .map_or(0, |(_, n)| *n);
    test_cap(detected)
}

#[cfg(debug_assertions)]
fn test_cap(detected: u32) -> u32 {
    match std::env::var(TEST_ABI_ENV)
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
    {
        Some(cap) => detected.min(cap),
        None => detected,
    }
}

#[cfg(not(debug_assertions))]
fn test_cap(detected: u32) -> u32 {
    detected
}

/// Applies the filesystem rules to the calling thread (and so to every
/// process it later spawns). Returns what was enforced, or an error when the
/// supervisor must not start.
pub fn apply(fs: &FilesystemConfig) -> Result<LandlockReport, String> {
    let mut report = LandlockReport {
        requested: fs.landlock.as_str().to_owned(),
        ..LandlockReport::default()
    };
    if fs.landlock == LandlockMode::Off {
        report.status = "off".into();
        return Ok(report);
    }

    let abi_n = detect_abi();
    report.abi = abi_n;
    let Some(abi) = abi_for(abi_n) else {
        if fs.landlock == LandlockMode::Required {
            report.status = "refused".into();
            return Err("filesystem.landlock is \"required\" but this kernel has no usable Landlock support".into());
        }
        report.status = "unsupported".into();
        return Ok(report);
    };
    if fs.landlock == LandlockMode::Required && abi_n < REQUIRED_MIN_ABI {
        return Err(format!(
            "filesystem.landlock is \"required\" but the kernel offers Landlock ABI {abi_n}; at least ABI {REQUIRED_MIN_ABI} (Linux 6.2) is needed to enforce read-only paths"
        ));
    }

    let mut ruleset = Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(AccessFs::from_all(abi))
        .and_then(|r| r.create())
        .map_err(|e| format!("landlock: create ruleset: {e}"))?;

    for (paths, access, applied) in [
        (
            &fs.read_only,
            AccessFs::from_read(abi),
            &mut report.read_only,
        ),
        (
            &fs.read_write,
            AccessFs::from_all(abi),
            &mut report.read_write,
        ),
    ] {
        for p in paths {
            // path_beneath_rules skips paths it cannot open and narrows the
            // rights to those valid for a regular file.
            match path_beneath_rules([Path::new(p)], access).next() {
                Some(rule) => {
                    let rule = rule.map_err(|e| format!("landlock: rule for {p}: {e}"))?;
                    ruleset = ruleset
                        .add_rule(rule)
                        .map_err(|e| format!("landlock: rule for {p}: {e}"))?;
                    applied.push(p.clone());
                }
                None => report.skipped.push(p.clone()),
            }
        }
    }

    let status: RestrictionStatus = ruleset
        .restrict_self()
        .map_err(|e| format!("landlock: restrict: {e}"))?;
    match status.ruleset {
        RulesetStatus::FullyEnforced => report.status = "enforced".into(),
        RulesetStatus::PartiallyEnforced | RulesetStatus::NotEnforced => {
            // A hard-required ruleset at the detected ABI cannot degrade;
            // treat it as a failure rather than trust it.
            return Err(format!(
                "landlock: kernel reported {:?} for an ABI {abi_n} ruleset",
                status.ruleset
            ));
        }
    }
    Ok(report)
}
