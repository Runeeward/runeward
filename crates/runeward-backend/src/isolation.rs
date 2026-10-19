//! Isolation tiers: how strong the boundary around a sandbox is.

use std::fmt;

use serde::{Deserialize, Serialize};

/// The isolation boundary a sandbox runs behind, weakest first.
///
/// Tiers are ordered, so policy can require a minimum
/// (`sandbox.isolation >= IsolationTier::Kernel`). A backend must report the
/// tier it actually delivered, never the one it was asked for: when a check
/// cannot confirm a stronger boundary the weaker tier is reported.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum IsolationTier {
    /// An ordinary host process, possibly confined by an in-sandbox
    /// supervisor (Landlock, seccomp). Shares the host kernel directly.
    Process,
    /// A Linux container (namespaces, cgroups, dropped capabilities) on the
    /// host kernel, e.g. runc or crun.
    #[default]
    Container,
    /// A container behind a separate or user-space kernel: gVisor (runsc)
    /// or Kata Containers.
    Kernel,
    /// A dedicated virtual machine, e.g. a libkrun or Firecracker microVM.
    Vm,
}

impl IsolationTier {
    /// The lowercase name used on the wire.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Process => "process",
            Self::Container => "container",
            Self::Kernel => "kernel",
            Self::Vm => "vm",
        }
    }
}

impl fmt::Display for IsolationTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Classifies an OCI runtime name (Docker `--runtime`, a Kubernetes
/// RuntimeClass handler, a containerd shim name) into the tier it provides.
///
/// - `runsc`, `gvisor`, `kata*` (and their containerd shims) are
///   [`IsolationTier::Kernel`];
/// - `krun`/`libkrun` and Firecracker runtimes are [`IsolationTier::Vm`];
/// - anything else (`runc`, `crun`, `youki`, unknown names, empty) is
///   [`IsolationTier::Container`], so an unrecognised runtime never
///   over-claims.
pub fn classify_runtime(name: &str) -> IsolationTier {
    let n = name.trim().to_ascii_lowercase();
    if n.contains("krun") || n.contains("firecracker") {
        IsolationTier::Vm
    } else if n.contains("runsc") || n.contains("gvisor") || n.contains("kata") {
        IsolationTier::Kernel
    } else {
        IsolationTier::Container
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tiers_are_ordered() {
        assert!(IsolationTier::Process < IsolationTier::Container);
        assert!(IsolationTier::Container < IsolationTier::Kernel);
        assert!(IsolationTier::Kernel < IsolationTier::Vm);
        assert_eq!(IsolationTier::default(), IsolationTier::Container);
    }

    #[test]
    fn classify_known_runtimes() {
        for (name, want) in [
            ("", IsolationTier::Container),
            ("runc", IsolationTier::Container),
            ("crun", IsolationTier::Container),
            ("io.containerd.runc.v2", IsolationTier::Container),
            ("runsc", IsolationTier::Kernel),
            ("runsc-kvm", IsolationTier::Kernel),
            ("gVisor", IsolationTier::Kernel),
            ("io.containerd.runsc.v1", IsolationTier::Kernel),
            ("kata", IsolationTier::Kernel),
            ("kata-qemu", IsolationTier::Kernel),
            ("io.containerd.kata.v2", IsolationTier::Kernel),
            ("krun", IsolationTier::Vm),
            ("crun-krun", IsolationTier::Vm),
            ("aws.firecracker", IsolationTier::Vm),
        ] {
            assert_eq!(classify_runtime(name), want, "{name}");
        }
    }

    #[test]
    fn serializes_lowercase() {
        assert_eq!(
            serde_json::to_string(&IsolationTier::Kernel).expect("serialize"),
            "\"kernel\""
        );
        assert_eq!(IsolationTier::Vm.to_string(), "vm");
    }
}
