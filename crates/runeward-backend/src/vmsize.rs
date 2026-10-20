//! Sizing VM sandboxes against the engine host, and explaining VM start
//! failures.
//!
//! A VM runtime turns the sandbox's container limits into a guest: Kata
//! sizes it as its configured default memory and vCPUs **plus** the
//! container's memory and CPU limits. When the guest cannot fit on the
//! engine host the hypervisor never starts, and the engine only reports an
//! opaque shim timeout, so the backend checks the size before it asks the
//! engine and names the likely causes when a VM fails to start anyway.
//! See docs/isolation.md.

use runeward_charter::RuntimeFamily;

use crate::config::{
    BackendConfig, SANDBOX_CPUS_ENV, SANDBOX_MEMORY_ENV, VM_OVERHEAD_CPUS_ENV,
    VM_OVERHEAD_MEMORY_ENV,
};
use crate::types::Spec;

const MIB: i64 = 1 << 20;
const NANO: i64 = 1_000_000_000;

/// The engine host's total memory and CPUs (`docker info` MemTotal/NCPU,
/// `podman info` Host.MemTotal/Host.CPUs); 0 when unknown.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EngineCapacity {
    /// Total memory in bytes.
    pub memory_bytes: i64,
    /// Logical CPUs.
    pub cpus: i64,
}

/// The guest a VM runtime boots for a sandbox.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GuestSize {
    /// The sandbox's memory limit in bytes (0 = none).
    pub limit_memory_bytes: i64,
    /// The sandbox's CPU limit in nano-CPUs (0 = none).
    pub limit_nano_cpus: i64,
    /// The VM overhead memory in bytes.
    pub overhead_memory_bytes: i64,
    /// The VM overhead CPUs in nano-CPUs.
    pub overhead_nano_cpus: i64,
}

impl GuestSize {
    /// The size of the guest for `spec` under `cfg`.
    pub fn of(spec: &Spec, cfg: &BackendConfig) -> Self {
        Self {
            limit_memory_bytes: cfg.sandbox_memory_bytes(spec.resources.memory_bytes),
            limit_nano_cpus: cfg.sandbox_nano_cpus(spec.resources.nano_cpus),
            overhead_memory_bytes: cfg.vm_overhead_memory_bytes(),
            overhead_nano_cpus: cfg.vm_overhead_nano_cpus(),
        }
    }

    /// Guest memory: the overhead plus the limit.
    pub fn memory_bytes(&self) -> i64 {
        self.overhead_memory_bytes
            .saturating_add(self.limit_memory_bytes)
    }

    /// Guest vCPUs: the overhead plus the limit, each rounded up to whole
    /// vCPUs (a VM cannot have a fraction of one).
    pub fn vcpus(&self) -> i64 {
        ceil_cpus(self.overhead_nano_cpus).saturating_add(ceil_cpus(self.limit_nano_cpus))
    }

    fn describe(&self) -> String {
        format!(
            "about {} MiB and {} vCPUs (sandbox limits {} / {} plus VM overhead {} MiB / {} vCPUs)",
            self.memory_bytes() / MIB,
            self.vcpus(),
            if self.limit_memory_bytes > 0 {
                format!("{} MiB", self.limit_memory_bytes / MIB)
            } else {
                "no memory limit".to_owned()
            },
            if self.limit_nano_cpus > 0 {
                format!("{} CPUs", fmt_cpus(self.limit_nano_cpus))
            } else {
                "no CPU limit".to_owned()
            },
            self.overhead_memory_bytes / MIB,
            fmt_cpus(self.overhead_nano_cpus),
        )
    }
}

fn ceil_cpus(nano: i64) -> i64 {
    if nano <= 0 {
        0
    } else {
        (nano + NANO - 1) / NANO
    }
}

fn fmt_cpus(nano: i64) -> String {
    let s = format!("{:.3}", nano as f64 / 1e9);
    s.trim_end_matches('0').trim_end_matches('.').to_owned()
}

/// Whether `runtime` boots a hardware VM per sandbox (Kata, krun,
/// Firecracker), so its limits size a guest.
pub fn is_vm_runtime(runtime: &str) -> bool {
    RuntimeFamily::of(runtime).needs_kvm()
}

/// How to bring the guest size down.
fn remedy() -> String {
    format!(
        "lower [rationing] memory / cpus in the Charter, or {SANDBOX_MEMORY_ENV} / {SANDBOX_CPUS_ENV} for the default limits ({VM_OVERHEAD_MEMORY_ENV} / {VM_OVERHEAD_CPUS_ENV} when the runtime's own VM size differs from the 2048 MiB / 1 vCPU default)"
    )
}

/// Refuses a sandbox whose VM cannot fit on the engine host. A non-VM
/// runtime, or a capacity the engine did not report, is never refused.
pub fn check_fits(
    runtime: &str,
    engine: &str,
    size: &GuestSize,
    cap: EngineCapacity,
) -> Result<(), String> {
    if !is_vm_runtime(runtime) {
        return Ok(());
    }
    let mem_short = cap.memory_bytes > 0 && size.memory_bytes() > cap.memory_bytes;
    let cpu_short = cap.cpus > 0 && size.vcpus() > cap.cpus;
    if !mem_short && !cpu_short {
        return Ok(());
    }
    Err(format!(
        "runtime {runtime:?} would boot a VM of {} but the {engine} engine host has {} MiB and {} CPUs, so the hypervisor could not start; {} (see docs/isolation.md)",
        size.describe(),
        cap.memory_bytes / MIB,
        cap.cpus,
        remedy(),
    ))
}

/// Engine errors that mean a VM runtime's hypervisor never came up.
const VM_START_FAILURES: &[&str] = &[
    "timed out waiting for qmp ready",
    "start vm",
    "failed to create shim task",
];

/// Explains an engine error from starting a sandbox under a VM runtime,
/// when it is one of the known VM start failures.
pub fn explain_start_failure(
    runtime: &str,
    engine_error: &str,
    size: &GuestSize,
    cap: EngineCapacity,
) -> Option<String> {
    if !is_vm_runtime(runtime) {
        return None;
    }
    let e = engine_error.to_ascii_lowercase();
    if !VM_START_FAILURES.iter().any(|m| e.contains(m)) {
        return None;
    }
    let host = if cap.memory_bytes > 0 {
        format!("{} MiB and {} CPUs", cap.memory_bytes / MIB, cap.cpus)
    } else {
        "an unknown amount of memory".to_owned()
    };
    Some(format!(
        "the {runtime:?} VM did not start. Likely causes: (1) the guest ({}) does not fit next to everything else on the engine host ({host}): {}; (2) the runtime cannot use /dev/kvm (KVM permissions, or no nested virtualisation); (3) a broken hypervisor configuration (Kata runtime-rs reads the first existing runtime-rs/configuration.toml, normally /etc/kata-containers/runtime-rs/configuration.toml). See docs/isolation.md. Engine error: {engine_error}",
        size.describe(),
        remedy(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Resources;

    /// The KVM host the bug was found on: 3.8 GiB, 2 CPUs.
    const HOST: EngineCapacity = EngineCapacity {
        memory_bytes: 4_014_825_472,
        cpus: 2,
    };

    fn size(pairs: &[(&str, &str)], resources: Resources) -> GuestSize {
        let cfg = BackendConfig::from_pairs(pairs.iter().copied());
        GuestSize::of(
            &Spec {
                resources,
                ..Spec::default()
            },
            &cfg,
        )
    }

    #[test]
    fn default_limits_do_not_fit_a_small_host() {
        let s = size(&[], Resources::default());
        assert_eq!(s.memory_bytes(), 6144 * MIB);
        assert_eq!(s.vcpus(), 3);
        let err =
            check_fits("io.containerd.kata-qemu.v2", "docker", &s, HOST).expect_err("refused");
        assert!(err.contains("6144 MiB and 3 vCPUs"), "{err}");
        assert!(err.contains("4096 MiB / 2 CPUs"), "{err}");
        assert!(err.contains("3828 MiB and 2 CPUs"), "{err}");
        assert!(err.contains("[rationing] memory / cpus"), "{err}");
        assert!(err.contains("RUNEWARD_SANDBOX_MEMORY"), "{err}");
        // Not a VM: never refused.
        assert!(check_fits("runc", "docker", &s, HOST).is_ok());
        assert!(check_fits("", "docker", &s, HOST).is_ok());
        assert!(check_fits("runsc", "docker", &s, HOST).is_ok());
        // Unknown capacity: never refused.
        let unknown = EngineCapacity::default();
        assert!(check_fits("kata-qemu", "docker", &s, unknown).is_ok());
    }

    #[test]
    fn the_size_that_worked_fits() {
        // RUNEWARD_SANDBOX_MEMORY=512m RUNEWARD_SANDBOX_CPUS=1 booted.
        let s = size(
            &[(SANDBOX_MEMORY_ENV, "512m"), (SANDBOX_CPUS_ENV, "1")],
            Resources::default(),
        );
        assert_eq!(s.memory_bytes(), 2560 * MIB);
        assert_eq!(s.vcpus(), 2);
        assert!(check_fits("kata-clh", "docker", &s, HOST).is_ok());
        // Charter limits take precedence over the defaults.
        let s = size(
            &[],
            Resources {
                memory_bytes: 1 << 30,
                nano_cpus: 500_000_000,
            },
        );
        assert_eq!((s.memory_bytes(), s.vcpus()), (3072 * MIB, 2));
        assert!(check_fits("krun", "podman", &s, HOST).is_ok());
    }

    #[test]
    fn cpus_alone_can_refuse_and_overhead_is_configurable() {
        let s = size(
            &[(SANDBOX_MEMORY_ENV, "256m"), (SANDBOX_CPUS_ENV, "2")],
            Resources::default(),
        );
        let err = check_fits("kata", "docker", &s, HOST).expect_err("3 vCPUs on 2");
        assert!(err.contains("3 vCPUs"), "{err}");
        let s = size(
            &[
                (VM_OVERHEAD_MEMORY_ENV, "128m"),
                (VM_OVERHEAD_CPUS_ENV, "0"),
            ],
            Resources::default(),
        );
        assert_eq!((s.memory_bytes(), s.vcpus()), (4224 * MIB, 2));
        // Without limits the guest is just the overhead.
        let s = size(
            &[(SANDBOX_MEMORY_ENV, "off"), (SANDBOX_CPUS_ENV, "off")],
            Resources::default(),
        );
        assert_eq!((s.memory_bytes(), s.vcpus()), (2048 * MIB, 1));
        assert!(s.describe().contains("no memory limit / no CPU limit"));
    }

    #[test]
    fn known_vm_start_failures_are_explained() {
        let s = size(&[], Resources::default());
        let observed = "docker run: exit status 125: docker: Error response from daemon: failed to create task for container: failed to create shim task: Others(\"failed to handle message start vm: timed out waiting for QMP ready\"): unknown.";
        let m = explain_start_failure("io.containerd.kata-qemu.v2", observed, &s, HOST)
            .expect("explained");
        for want in [
            "did not start",
            "6144 MiB and 3 vCPUs",
            "3828 MiB and 2 CPUs",
            "/dev/kvm",
            "runtime-rs/configuration.toml",
            "docs/isolation.md",
            "timed out waiting for QMP ready",
        ] {
            assert!(m.contains(want), "{want}: {m}");
        }
        assert!(
            explain_start_failure("kata-clh", "Failed to create shim task: x", &s, HOST).is_some()
        );
        // Other errors, and non-VM runtimes, are left alone.
        assert!(explain_start_failure("kata-qemu", "no such image", &s, HOST).is_none());
        assert!(explain_start_failure("runc", observed, &s, HOST).is_none());
        let m = explain_start_failure("krun", "start vm", &s, EngineCapacity::default())
            .expect("explained");
        assert!(m.contains("unknown amount of memory"), "{m}");
    }
}
