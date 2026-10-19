//! What an OCI runtime name can deliver.
//!
//! `host.runtime_class` (or an OCI runtime written in `host.runtime`) names
//! the runtime a sandbox runs under: a Docker/Podman `--runtime`, or the
//! handler of a Kubernetes RuntimeClass. A name is only a claim. Backends
//! confirm the boundary from evidence collected inside the sandbox, and a
//! name bounds what that evidence may establish: a runtime that cannot be a
//! VM never reports `vm`, whatever the sandbox says about itself.

use crate::governance::IsolationLevel;

/// The runtime families Rune Box knows how to reason about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RuntimeFamily {
    /// runc, crun, youki, an unknown name, or the engine default: a
    /// shared-kernel container.
    Container,
    /// gVisor (`runsc`): a user-space kernel.
    Gvisor,
    /// Kata Containers with QEMU, Cloud Hypervisor or another hypervisor:
    /// a guest kernel in a VM, confirmed as `vm` only from evidence.
    Kata,
    /// Kata Containers configured with the Firecracker hypervisor
    /// (`kata-fc`, `io.containerd.kata-fc.v2`).
    KataFirecracker,
    /// Firecracker through another integration (`aws.firecracker`).
    Firecracker,
    /// crun built with libkrun (`krun`): a libkrun microVM per container.
    Krun,
}

impl RuntimeFamily {
    /// Classifies a runtime name, RuntimeClass handler or containerd shim
    /// name (case-insensitive).
    pub fn of(name: &str) -> Self {
        let n = name.trim().to_ascii_lowercase();
        let tokens: Vec<&str> = n
            .split(|c: char| !c.is_ascii_alphanumeric())
            .filter(|t| !t.is_empty())
            .collect();
        let has = |t: &str| tokens.contains(&t);
        if n.contains("krun") {
            Self::Krun
        } else if n.contains("kata") && (has("fc") || n.contains("firecracker")) {
            Self::KataFirecracker
        } else if n.contains("firecracker") {
            Self::Firecracker
        } else if n.contains("kata") {
            Self::Kata
        } else if n.contains("runsc") || n.contains("gvisor") {
            Self::Gvisor
        } else {
            Self::Container
        }
    }

    /// The level the name alone claims (what a backend reports when it is
    /// told not to probe).
    pub fn claim(self) -> IsolationLevel {
        match self {
            Self::Container => IsolationLevel::Container,
            Self::Gvisor | Self::Kata => IsolationLevel::Kernel,
            Self::KataFirecracker | Self::Firecracker | Self::Krun => IsolationLevel::Vm,
        }
    }

    /// The strongest level this runtime can deliver; evidence never raises a
    /// sandbox above it.
    pub fn ceiling(self) -> IsolationLevel {
        match self {
            Self::Container => IsolationLevel::Container,
            Self::Gvisor => IsolationLevel::Kernel,
            Self::Kata | Self::KataFirecracker | Self::Firecracker | Self::Krun => {
                IsolationLevel::Vm
            }
        }
    }

    /// Reports whether the runtime needs hardware virtualisation (`/dev/kvm`)
    /// on the node that runs the sandbox.
    pub fn needs_kvm(self) -> bool {
        self.ceiling() == IsolationLevel::Vm
    }
}

/// Engine names `host.runtime` historically carries (the backend hint).
const ENGINE_NAMES: &[&str] = &["docker", "podman"];

/// Reports whether `host.runtime` holds an engine name (or nothing) rather
/// than an OCI runtime.
pub fn is_engine_name(runtime: &str) -> bool {
    let r = runtime.trim().to_ascii_lowercase();
    r.is_empty() || ENGINE_NAMES.contains(&r.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn families() {
        for (name, want) in [
            ("", RuntimeFamily::Container),
            ("runc", RuntimeFamily::Container),
            ("crun", RuntimeFamily::Container),
            ("io.containerd.runc.v2", RuntimeFamily::Container),
            ("runsc", RuntimeFamily::Gvisor),
            ("runsc-kvm", RuntimeFamily::Gvisor),
            ("gVisor", RuntimeFamily::Gvisor),
            ("kata", RuntimeFamily::Kata),
            ("kata-qemu", RuntimeFamily::Kata),
            ("kata-clh", RuntimeFamily::Kata),
            ("io.containerd.kata.v2", RuntimeFamily::Kata),
            ("kata-fc", RuntimeFamily::KataFirecracker),
            ("io.containerd.kata-fc.v2", RuntimeFamily::KataFirecracker),
            ("kata-firecracker", RuntimeFamily::KataFirecracker),
            ("aws.firecracker", RuntimeFamily::Firecracker),
            ("krun", RuntimeFamily::Krun),
            ("crun-krun", RuntimeFamily::Krun),
            ("libkrun", RuntimeFamily::Krun),
            // "fc" only counts as a token of a Kata name.
            ("fcrun", RuntimeFamily::Container),
        ] {
            assert_eq!(RuntimeFamily::of(name), want, "{name}");
        }
    }

    #[test]
    fn claims_never_exceed_ceilings() {
        for f in [
            RuntimeFamily::Container,
            RuntimeFamily::Gvisor,
            RuntimeFamily::Kata,
            RuntimeFamily::KataFirecracker,
            RuntimeFamily::Firecracker,
            RuntimeFamily::Krun,
        ] {
            assert!(f.claim() <= f.ceiling(), "{f:?}");
        }
        assert_eq!(RuntimeFamily::Kata.claim(), IsolationLevel::Kernel);
        assert_eq!(RuntimeFamily::Kata.ceiling(), IsolationLevel::Vm);
        assert!(!RuntimeFamily::Gvisor.needs_kvm());
        assert!(RuntimeFamily::Krun.needs_kvm());
    }

    #[test]
    fn engine_names() {
        assert!(is_engine_name(""));
        assert!(is_engine_name("Docker"));
        assert!(is_engine_name("podman"));
        assert!(!is_engine_name("krun"));
        assert!(!is_engine_name("kata-fc"));
    }
}
