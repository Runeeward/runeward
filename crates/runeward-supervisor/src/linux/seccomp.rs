//! The self-protection seccomp filters.
//!
//! Two filters are stacked:
//!
//! 1. Every syscall in [`DENIED`] (plus x32 aliases on x86_64), and `clone`
//!    with any namespace flag, returns `EPERM`.
//! 2. `clone3` returns `ENOSYS`: its flags sit behind a pointer the filter
//!    cannot inspect, and libc falls back to `clone` on `ENOSYS`, which the
//!    first filter does inspect.
//!
//! Everything else is allowed. A syscall made through a foreign ABI (such as
//! 32-bit `int 0x80` on x86_64) fails the filter's architecture check and
//! kills the process, so the deny list cannot be bypassed that way.

use std::collections::BTreeMap;

use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule, TargetArch,
};

use crate::report::SeccompReport;
use crate::syscalls::{Arch, CLONE, CLONE_NAMESPACE_FLAGS, CLONE3, DENIED, denied_numbers};

const EPERM: u32 = 1;
const ENOSYS: u32 = 38;

fn target(arch: Arch) -> TargetArch {
    match arch {
        Arch::X86_64 => TargetArch::x86_64,
        Arch::Aarch64 => TargetArch::aarch64,
    }
}

/// Builds both BPF programs for `arch`: the `EPERM` deny filter and the
/// `clone3` `ENOSYS` filter.
pub fn build(arch: Arch) -> Result<(BpfProgram, BpfProgram), String> {
    let err = |e: seccompiler::BackendError| format!("seccomp: build filter: {e}");

    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = denied_numbers(arch)
        .into_iter()
        .map(|(_, nr)| (nr, Vec::new()))
        .collect();
    let mut clone_rules = Vec::new();
    for (_, flag) in CLONE_NAMESPACE_FLAGS {
        let cond = SeccompCondition::new(
            0,
            SeccompCmpArgLen::Dword,
            SeccompCmpOp::MaskedEq(*flag),
            *flag,
        )
        .map_err(err)?;
        clone_rules.push(SeccompRule::new(vec![cond]).map_err(err)?);
    }
    rules.insert(CLONE.nr(arch), clone_rules);

    let deny = SeccompFilter::new(
        rules,
        SeccompAction::Allow,
        SeccompAction::Errno(EPERM),
        target(arch),
    )
    .map_err(err)?;
    let clone3 = SeccompFilter::new(
        BTreeMap::from([(CLONE3.nr(arch), Vec::new())]),
        SeccompAction::Allow,
        SeccompAction::Errno(ENOSYS),
        target(arch),
    )
    .map_err(err)?;
    Ok((
        BpfProgram::try_from(deny).map_err(err)?,
        BpfProgram::try_from(clone3).map_err(err)?,
    ))
}

/// Installs both filters on the calling thread (inherited by everything it
/// spawns). Sets `no_new_privs` as a side effect.
pub fn apply() -> Result<SeccompReport, String> {
    let arch = Arch::native().ok_or("seccomp: unsupported CPU architecture")?;
    let (deny, clone3) = build(arch)?;
    seccompiler::apply_filter(&deny).map_err(|e| format!("seccomp: install: {e}"))?;
    seccompiler::apply_filter(&clone3).map_err(|e| format!("seccomp: install: {e}"))?;
    Ok(SeccompReport {
        enabled: true,
        arch: arch.as_str().to_owned(),
        action: "errno:EPERM".into(),
        denied: DENIED.iter().map(|d| d.name.to_owned()).collect(),
        clone_flags_denied: CLONE_NAMESPACE_FLAGS
            .iter()
            .map(|(n, _)| (*n).to_owned())
            .collect(),
        clone3: "errno:ENOSYS".into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_for_both_arches() {
        for arch in Arch::ALL {
            let (deny, clone3) = build(arch).expect("build");
            // Arch check, syscall load, one jump per rule and a default.
            assert!(deny.len() > denied_numbers(arch).len(), "{arch:?}");
            assert!(!clone3.is_empty());
        }
    }
}
