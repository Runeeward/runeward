//! Isolation evidence: deriving a sandbox's tier from what it can observe.
//!
//! A runtime name is a claim. Right after a sandbox starts, the backend runs
//! [`probe_command`] inside it and compares the result with what the engine
//! says about the host ([`assess`]):
//!
//! - a gVisor signature (`/proc/version`, `dmesg`, `/proc/cmdline`) means a
//!   user-space kernel: [`IsolationTier::Kernel`];
//! - a guest kernel release different from the engine host's kernel, plus a
//!   hypervisor marker (the x86 `hypervisor` CPU flag, a hypervisor DMI
//!   vendor, `/sys/hypervisor/type`, a `linux,dummy-virt` device tree or
//!   virtio-mmio devices on the kernel command line) means a hardware VM:
//!   [`IsolationTier::Vm`];
//! - a different kernel without a hypervisor marker is a separate kernel
//!   that is not confirmed as a VM: [`IsolationTier::Kernel`];
//! - the same kernel as the host, or anything unconfirmed (probe failed,
//!   host kernel unknown), is [`IsolationTier::Container`].
//!
//! The result is then capped at the runtime's ceiling
//! ([`crate::runtime_ceiling`]), so output forged by the sandbox's own
//! userland can never lift a runc or gVisor sandbox to `vm`. When the name
//! claims more than the evidence shows, the weaker tier is reported and a
//! warning is logged.
//!
//! Evidence is collected through the sandbox's own `/bin/sh` and `cat`, so it
//! detects misconfiguration (a runtime name mapped to runc, a VM runtime that
//! silently fell back) rather than a hostile image. Images without a shell
//! report `container`; operators can trust names instead with
//! `RUNEWARD_ISOLATION_PROBE=off`, which the evidence records.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use runeward_charter::RuntimeFamily;

use crate::isolation::{IsolationTier, classify_runtime, runtime_ceiling};

/// Marker carried in the probe's argv, so it is recognisable in logs and
/// test fakes.
pub const PROBE_MARKER: &str = "runeward-isolation-probe";

/// The POSIX shell script that prints the probe sections, on one line so
/// engine logs and audit trails keep it intact. Each section starts with a
/// `@@name` line; missing files print nothing.
pub const PROBE_SCRIPT: &str = concat!(
    ": runeward-isolation-probe; ",
    "s() { printf '\\n@@%s\\n' \"$1\"; }; ",
    "s osrelease; cat /proc/sys/kernel/osrelease 2>/dev/null || uname -r 2>/dev/null; ",
    "s version; cat /proc/version 2>/dev/null; ",
    "s cpuflags; while IFS= read -r l; do case \"$l\" in flags*) printf '%s\\n' \"$l\"; break;; esac; done 2>/dev/null </proc/cpuinfo; ",
    "s dmi; cat /sys/class/dmi/id/sys_vendor /sys/class/dmi/id/product_name 2>/dev/null; ",
    "s hypervisor; cat /sys/hypervisor/type 2>/dev/null; ",
    "s devicetree; cat /proc/device-tree/compatible 2>/dev/null; ",
    "s cmdline; cat /proc/cmdline 2>/dev/null; ",
    "s dmesg; dmesg 2>/dev/null | head -n 20 2>/dev/null; ",
    "exit 0",
);

/// The argv that runs [`PROBE_SCRIPT`] inside a sandbox.
pub fn probe_command() -> Vec<String> {
    vec!["/bin/sh".into(), "-c".into(), PROBE_SCRIPT.into()]
}

/// What a backend observed about one sandbox's isolation boundary, recorded
/// on the [`crate::Sandbox`] so the control plane can put it in the ledger.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct IsolationEvidence {
    /// The OCI runtime (or RuntimeClass handler) the sandbox runs under;
    /// the engine default's name when the Spec picked none.
    pub runtime: String,
    /// Kernel release seen inside the sandbox (empty when unknown).
    pub guest_kernel: String,
    /// Kernel release of the engine host or Kubernetes node (empty when
    /// unknown).
    pub host_kernel: String,
    /// What was observed and concluded, e.g. `kernel:separate`,
    /// `hypervisor:cpu-flag`, `gvisor:proc-version`, `claim:vm`,
    /// `verdict:vm`.
    pub signals: Vec<String>,
    /// The hypervisor actually running a `vm` sandbox, found from the host
    /// side (`qemu`, `cloud-hypervisor`, `firecracker`); `unknown` when the
    /// control plane cannot see the engine host's processes; empty below
    /// `vm`.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub hypervisor: String,
}

impl IsolationEvidence {
    /// The evidence as flat `meta` entries for a ledger event.
    pub fn ledger_meta(&self) -> BTreeMap<String, String> {
        let mut m = BTreeMap::new();
        for (k, v) in [
            ("isolation_runtime", self.runtime.clone()),
            ("isolation_guest_kernel", self.guest_kernel.clone()),
            ("isolation_host_kernel", self.host_kernel.clone()),
            ("isolation_signals", self.signals.join(",")),
            ("isolation_hypervisor", self.hypervisor.clone()),
        ] {
            if !v.is_empty() {
                m.insert(k.to_owned(), v);
            }
        }
        m
    }
}

/// A derived tier with the evidence behind it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assessment {
    /// The tier to report: the evidence's, capped at the runtime ceiling.
    pub tier: IsolationTier,
    /// The tier the runtime name claims.
    pub claimed: IsolationTier,
    /// What was observed.
    pub evidence: IsolationEvidence,
}

impl Assessment {
    /// Records which hypervisor the host shows running the sandbox. A runtime
    /// name says nothing reliable about it (Kata's runtime-rs shim, for one,
    /// picks the hypervisor from its configuration file whatever the shim is
    /// called), so a `vm` sandbox reports `unknown` unless the host-side
    /// process was found, and a mismatch with the name is flagged.
    pub fn attach_host_hypervisor(&mut self, found: Option<&str>) {
        if self.tier != IsolationTier::Vm {
            return;
        }
        let hv = found.unwrap_or("unknown").to_owned();
        let mut extra = vec![format!("host:hypervisor={hv}")];
        if let (Some(want), Some(got)) = (expected_hypervisor(&self.evidence.runtime), found)
            && want != got
        {
            extra.push(format!("host:hypervisor-mismatch={want}->{got}"));
            tracing::warn!(
                target: "runeward_backend",
                "runtime {:?} is named for {want} but the sandbox runs under {got}; check the runtime's configuration (Kata runtime-rs reads runtime-rs/configuration.toml, not the shim name)",
                self.evidence.runtime,
            );
        }
        let at = self.evidence.signals.len().saturating_sub(1);
        for (i, sig) in extra.into_iter().enumerate() {
            self.evidence.signals.insert(at + i, sig);
        }
        self.evidence.hypervisor = hv;
    }

    /// Reports whether the name claimed more than the evidence confirmed.
    pub fn downgraded(&self) -> bool {
        self.tier < self.claimed
    }

    /// Logs the outcome; a downgrade is a warning, since it means the
    /// runtime is not what its name says (or could not be confirmed).
    pub(crate) fn log(&self, backend: &str, id: &str) {
        let signals = self.evidence.signals.join(",");
        if self.downgraded() {
            tracing::warn!(
                target: "runeward_backend",
                "ISOLATION DOWNGRADE: sandbox {id} on {backend}: runtime {:?} claims {} but the evidence shows {}; reporting {} (guest kernel {:?}, host kernel {:?}, signals {signals})",
                self.evidence.runtime,
                self.claimed,
                self.tier,
                self.tier,
                self.evidence.guest_kernel,
                self.evidence.host_kernel,
            );
        } else {
            tracing::info!(
                target: "runeward_backend",
                "sandbox {id} on {backend}: isolation {} confirmed for runtime {:?} ({signals})",
                self.tier,
                self.evidence.runtime,
            );
        }
    }
}

/// The parsed sections of the probe's output.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProbeOutput {
    /// `/proc/sys/kernel/osrelease` (or `uname -r`).
    pub osrelease: String,
    /// `/proc/version`.
    pub version: String,
    /// The first x86 `flags` line of `/proc/cpuinfo`.
    pub cpu_flags: String,
    /// DMI system vendor and product name, one per line.
    pub dmi: String,
    /// `/sys/hypervisor/type`.
    pub hypervisor: String,
    /// `/proc/device-tree/compatible` (NUL-separated strings).
    pub devicetree: String,
    /// `/proc/cmdline`.
    pub cmdline: String,
    /// The first lines of `dmesg`.
    pub dmesg: String,
}

impl ProbeOutput {
    /// Parses the probe's stdout. Unknown sections are ignored.
    pub fn parse(stdout: &str) -> Self {
        let mut out = Self::default();
        let mut current: Option<&mut String> = None;
        for line in stdout.lines() {
            if let Some(name) = line.strip_prefix("@@") {
                current = match name.trim() {
                    "osrelease" => Some(&mut out.osrelease),
                    "version" => Some(&mut out.version),
                    "cpuflags" => Some(&mut out.cpu_flags),
                    "dmi" => Some(&mut out.dmi),
                    "hypervisor" => Some(&mut out.hypervisor),
                    "devicetree" => Some(&mut out.devicetree),
                    "cmdline" => Some(&mut out.cmdline),
                    "dmesg" => Some(&mut out.dmesg),
                    _ => None,
                };
                continue;
            }
            if let Some(buf) = current.as_deref_mut() {
                if !buf.is_empty() {
                    buf.push('\n');
                }
                buf.push_str(line);
            }
        }
        for s in [
            &mut out.osrelease,
            &mut out.version,
            &mut out.cpu_flags,
            &mut out.dmi,
            &mut out.hypervisor,
            &mut out.devicetree,
            &mut out.cmdline,
            &mut out.dmesg,
        ] {
            *s = s.trim().to_owned();
        }
        out
    }

    /// The guest kernel release: `osrelease`, else the third word of
    /// `/proc/version` (`Linux version <release> ...`).
    pub fn guest_kernel(&self) -> String {
        let first = self.osrelease.lines().next().unwrap_or("").trim();
        if !first.is_empty() {
            return first.to_owned();
        }
        self.version
            .split_whitespace()
            .nth(2)
            .unwrap_or("")
            .to_owned()
    }

    /// gVisor's documented signatures: its fixed `/proc/version` build
    /// string, `Starting gVisor...` in `dmesg`, and a gVisor kernel image
    /// on the command line.
    fn gvisor_signals(&self) -> Vec<&'static str> {
        let mut s = Vec::new();
        if self.version.contains("#1 SMP Sun Jan 10 15:06:54 PST 2016") {
            s.push("gvisor:proc-version");
        }
        if self.dmesg.contains("Starting gVisor") {
            s.push("gvisor:dmesg");
        }
        if self.cmdline.contains("gvisor") {
            s.push("gvisor:cmdline");
        }
        s
    }

    /// Markers of a hardware-virtualised guest.
    fn hypervisor_signals(&self) -> Vec<String> {
        let mut s = Vec::new();
        if self.cpu_flags.split_whitespace().any(|f| f == "hypervisor") {
            s.push("hypervisor:cpu-flag".to_owned());
        }
        for line in self.dmi.lines() {
            let l = line.trim();
            if HYPERVISOR_DMI
                .iter()
                .any(|v| l.to_ascii_lowercase().contains(&v.to_ascii_lowercase()))
            {
                s.push(format!("hypervisor:dmi={}", sanitize(l)));
                break;
            }
        }
        let hv = self.hypervisor.trim();
        if !hv.is_empty() {
            s.push(format!("hypervisor:sysfs={}", sanitize(hv)));
        }
        if self
            .devicetree
            .split(['\0', '\n'])
            .any(|c| c.trim() == "linux,dummy-virt")
        {
            s.push("hypervisor:devicetree=linux,dummy-virt".to_owned());
        }
        if self.cmdline.contains("virtio_mmio.device=") {
            s.push("hypervisor:cmdline=virtio_mmio".to_owned());
        }
        s
    }
}

/// The hypervisor a runtime name implies, if any.
pub fn expected_hypervisor(runtime: &str) -> Option<&'static str> {
    let n = runtime.to_ascii_lowercase();
    match RuntimeFamily::of(&n) {
        RuntimeFamily::KataFirecracker | RuntimeFamily::Firecracker => Some("firecracker"),
        RuntimeFamily::Kata if n.contains("clh") || n.contains("cloud-hypervisor") => {
            Some("cloud-hypervisor")
        }
        RuntimeFamily::Kata if n.contains("qemu") => Some("qemu"),
        _ => None,
    }
}

/// Names a hypervisor from a process's argv[0].
fn hypervisor_of(argv0: &str) -> Option<&'static str> {
    let base = argv0.rsplit('/').next().unwrap_or(argv0);
    if base.starts_with("qemu-system") || base.starts_with("qemu-kvm") {
        Some("qemu")
    } else if base.starts_with("cloud-hypervisor") {
        Some("cloud-hypervisor")
    } else if base.starts_with("firecracker") {
        Some("firecracker")
    } else {
        None
    }
}

/// Scans `proc_root` (normally `/proc` on the engine host) for a hypervisor
/// process whose command line mentions `needle` (the container or sandbox
/// id: Kata puts it in the VM name and socket paths) and names it.
pub fn find_hypervisor(proc_root: &std::path::Path, needle: &str) -> Option<String> {
    if needle.len() < 12 {
        return None;
    }
    let entries = std::fs::read_dir(proc_root).ok()?;
    for e in entries.flatten() {
        let name = e.file_name();
        if !name.to_string_lossy().bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let Ok(raw) = std::fs::read(e.path().join("cmdline")) else {
            continue;
        };
        let raw = String::from_utf8_lossy(&raw);
        let mut args = raw.split('\0').filter(|a| !a.is_empty());
        let Some(hv) = args.next().and_then(hypervisor_of) else {
            continue;
        };
        if raw.contains(needle) {
            return Some(hv.to_owned());
        }
    }
    None
}

/// DMI vendor/product substrings that identify a hypervisor.
const HYPERVISOR_DMI: &[&str] = &[
    "QEMU",
    "KVM",
    "Firecracker",
    "Cloud Hypervisor",
    "cloud-hypervisor",
    "Amazon EC2",
    "Virtual Machine",
    "VMware",
    "Xen",
    "innotek",
    "Google Compute Engine",
    "Parallels",
    "BHYVE",
];

/// Keeps a value safe for a comma-separated signal list.
fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| if c == ',' || c.is_control() { ' ' } else { c })
        .collect::<String>()
        .trim()
        .chars()
        .take(64)
        .collect()
}

/// Derives the tier of a sandbox running under `runtime` on a host whose
/// kernel release is `host_kernel` (empty when unknown), from the probe's
/// stdout or the reason it could not run.
pub fn assess(runtime: &str, host_kernel: &str, probe: Result<&str, &str>) -> Assessment {
    let claimed = classify_runtime(runtime);
    let ceiling = runtime_ceiling(runtime);
    let host_kernel = host_kernel.trim().to_owned();
    let mut signals: Vec<String> = Vec::new();
    let mut guest_kernel = String::new();

    let evidence_tier = match probe {
        Err(e) => {
            signals.push(format!("probe:failed={}", sanitize(e)));
            IsolationTier::Container
        }
        Ok(stdout) => {
            let p = ProbeOutput::parse(stdout);
            guest_kernel = p.guest_kernel();
            let gvisor = p.gvisor_signals();
            let hyper = p.hypervisor_signals();
            signals.push("probe:ok".into());
            signals.extend(gvisor.iter().map(|s| (*s).to_owned()));
            let kernel = if guest_kernel.is_empty() {
                "kernel:unknown-guest"
            } else if host_kernel.is_empty() {
                "kernel:unknown-host"
            } else if guest_kernel == host_kernel {
                "kernel:shared"
            } else {
                "kernel:separate"
            };
            signals.push(kernel.into());
            signals.extend(hyper.iter().cloned());
            if !gvisor.is_empty() {
                IsolationTier::Kernel
            } else if kernel == "kernel:separate" {
                if hyper.is_empty() {
                    IsolationTier::Kernel
                } else {
                    IsolationTier::Vm
                }
            } else {
                IsolationTier::Container
            }
        }
    };
    let tier = evidence_tier.min(ceiling);
    signals.push(format!("claim:{claimed}"));
    if tier < evidence_tier {
        signals.push(format!("capped:{evidence_tier}->{tier}"));
    }
    signals.push(format!("verdict:{tier}"));
    Assessment {
        tier,
        claimed,
        evidence: IsolationEvidence {
            runtime: runtime.to_owned(),
            guest_kernel,
            host_kernel,
            signals,
            hypervisor: String::new(),
        },
    }
}

/// The assessment when probing is disabled by the operator: the name's
/// claim, recorded as unverified.
pub fn assess_unprobed(runtime: &str, host_kernel: &str) -> Assessment {
    let claimed = classify_runtime(runtime);
    Assessment {
        tier: claimed,
        claimed,
        evidence: IsolationEvidence {
            runtime: runtime.to_owned(),
            guest_kernel: String::new(),
            host_kernel: host_kernel.trim().to_owned(),
            signals: vec![
                "probe:disabled".into(),
                format!("claim:{claimed}"),
                format!("verdict:{claimed}"),
            ],
            hypervisor: String::new(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Probe outputs marked SYNTHETIC below are assembled by hand in the
    // probe's section format from the documented behaviour of a runtime
    // (gVisor's fixed /proc/version and dmesg banner, a QEMU SMBIOS vendor,
    // the aarch64 `linux,dummy-virt` device tree, Firecracker's virtio-mmio
    // command line). The OBSERVED and CAPTURED ones come from real hosts;
    // the opt-in `vm_runtime` integration test records them on a KVM
    // machine.

    /// runc on an x86 cloud VM: the container shares the host kernel, and
    /// the host itself is virtualised, so the hypervisor flag is present.
    const RUNC_ON_CLOUD_VM: &str = "
@@osrelease
6.8.0-45-generic
@@version
Linux version 6.8.0-45-generic (buildd@lcy02-amd64-075) (x86_64-linux-gnu-gcc-13 (Ubuntu 13.2.0-23ubuntu4) 13.2.0) #45-Ubuntu SMP PREEMPT_DYNAMIC Fri Aug 30 12:02:04 UTC 2024
@@cpuflags
flags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge hypervisor lahf_lm
@@dmi
Hetzner
vServer
@@hypervisor
@@devicetree
@@cmdline
BOOT_IMAGE=/boot/vmlinuz-6.8.0-45-generic root=UUID=0b6e ro consoleblank=0
@@dmesg
";

    /// gVisor (runsc): fixed 4.4.0 kernel, documented /proc/version and
    /// dmesg banner; cpuinfo passes the host's CPUID through.
    const RUNSC: &str = "
@@osrelease
4.4.0
@@version
Linux version 4.4.0 #1 SMP Sun Jan 10 15:06:54 PST 2016
@@cpuflags
flags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep hypervisor
@@dmi
@@hypervisor
@@devicetree
@@cmdline
BOOT_IMAGE=/vmlinuz-4.4.0-gvisor quiet
@@dmesg
[   0.000000] Starting gVisor...
[   0.512345] Reticulating splines...
";

    /// OBSERVED on a KVM host (Debian 13, Docker 29, Kata 4.2.0 runtime-rs,
    /// 2026-10-19): kata-qemu and kata-clh both showed this guest kernel,
    /// the `hypervisor` CPU flag and an empty DMI sys_vendor, with host
    /// kernel [`KVM_HOST`]. Only those values were recorded; the remaining
    /// sections are left empty rather than invented.
    const KATA_OBSERVED: &str = "
@@osrelease
6.18.35
@@version
@@cpuflags
flags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep vmx hypervisor
@@dmi

@@hypervisor
@@devicetree
@@cmdline
@@dmesg
";

    /// The host kernel of the KVM host the Kata values were observed on.
    const KVM_HOST: &str = "6.12.100+deb13-cloud-amd64";

    /// OBSERVED on the same KVM host: runc shares the host kernel, and the
    /// host is itself a VM, so the `hypervisor` CPU flag is present.
    const RUNC_KVM_HOST_OBSERVED: &str = "
@@osrelease
6.12.100+deb13-cloud-amd64
@@version
@@cpuflags
flags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep vmx hypervisor
@@dmi

@@hypervisor
@@devicetree
@@cmdline
@@dmesg
";

    /// SYNTHETIC. A QEMU guest that exposes SMBIOS (a q35 machine), to
    /// cover the DMI signal. Not what Kata showed on the tested host: its
    /// guests had an empty DMI vendor (see [`KATA_OBSERVED`]).
    const QEMU_SMBIOS: &str = "
@@osrelease
6.1.62
@@version
Linux version 6.1.62 (root@kata-builder) (gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0) #1 SMP Thu Nov 30 10:12:04 UTC 2023
@@cpuflags
flags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep pge hypervisor
@@dmi
QEMU
Standard PC (Q35 + ICH9, 2009)
@@hypervisor
@@devicetree
@@cmdline
tsc=reliable no_timer_check rcupdate.rcu_expedited=1 i8042.direct=1 root=/dev/pmem0p1 systemd.unit=kata-containers.target agent.log_vport=1025
@@dmesg
";

    /// SYNTHETIC. Kata Containers with Firecracker on x86: no SMBIOS,
    /// devices passed as virtio-mmio on the command line, hypervisor CPU
    /// flag. (On the KVM host, kata-fc under Docker never started; see
    /// docs/isolation.md.)
    const KATA_FC: &str = "
@@osrelease
6.1.62
@@version
Linux version 6.1.62 (root@kata-builder) #1 SMP Thu Nov 30 10:12:04 UTC 2023
@@cpuflags
flags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep hypervisor
@@dmi
@@hypervisor
@@devicetree
@@cmdline
console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda1 virtio_mmio.device=4K@0xd0000000:5 virtio_mmio.device=4K@0xd0001000:6 systemd.unit=kata-containers.target
@@dmesg
";

    /// SYNTHETIC, untested on a real host (libkrun is not packaged for the
    /// KVM host's distribution). crun with libkrun on aarch64: libkrunfw's
    /// kernel, no CPU flag on arm64, the `linux,dummy-virt` device tree.
    const KRUN_ARM64: &str = "
@@osrelease
6.6.59
@@version
Linux version 6.6.59 (mockbuild@libkrunfw) (gcc 14.2.1) #1 SMP PREEMPT_DYNAMIC
@@cpuflags
@@dmi
@@hypervisor
@@devicetree
linux,dummy-virt\0
@@cmdline
reboot=k panic=-1 panic_print=0 nomodule console=hvc0 rootfstype=virtiofs rw quiet no-kvmapf
@@dmesg
";

    const HOST: &str = "6.8.0-45-generic";

    /// CAPTURED (not synthetic): alpine under runc on OrbStack (arm64),
    /// 2026-10-19; `docker info` KernelVersion was the same release.
    const RUNC_ORBSTACK_CAPTURED: &str = "
@@osrelease
7.2.9-orbstack-00391-g2b298d05fbd4

@@version
Linux version 7.2.9-orbstack-00391-g2b298d05fbd4 (orbstack@builder) (ClangBuiltLinux clang version 22.1.3) #1 SMP PREEMPT Mon Oct 12 05:39:36 UTC 2026

@@cpuflags

@@dmi

@@hypervisor

@@devicetree

@@cmdline
init=/opt/orb/vinit workqueue.power_efficient=1 root=/dev/vda rootfstype=erofs ro console=hvc0 quiet

@@dmesg
";

    #[test]
    fn captured_runc_on_orbstack_is_container() {
        let host = "7.2.9-orbstack-00391-g2b298d05fbd4";
        let a = assess("runc", host, Ok(RUNC_ORBSTACK_CAPTURED));
        assert_eq!(a.tier, IsolationTier::Container);
        assert_eq!(a.evidence.guest_kernel, host);
        assert!(a.evidence.signals.contains(&"kernel:shared".to_owned()));
        // Even under a VM runtime name, a shared kernel is a container.
        assert_eq!(
            assess("krun", host, Ok(RUNC_ORBSTACK_CAPTURED)).tier,
            IsolationTier::Container
        );
    }

    #[test]
    fn parses_sections() {
        let p = ProbeOutput::parse(QEMU_SMBIOS);
        assert_eq!(p.osrelease, "6.1.62");
        assert_eq!(p.guest_kernel(), "6.1.62");
        assert_eq!(p.dmi, "QEMU\nStandard PC (Q35 + ICH9, 2009)");
        assert!(p.cpu_flags.contains("hypervisor"));
        assert!(p.dmesg.is_empty());
        // Falls back to /proc/version when osrelease is missing.
        let p = ProbeOutput::parse("@@version\nLinux version 5.15.0-1 (x) #1\n");
        assert_eq!(p.guest_kernel(), "5.15.0-1");
        assert_eq!(ProbeOutput::parse("garbage"), ProbeOutput::default());
    }

    #[test]
    fn runc_is_container_even_on_a_virtualised_host() {
        let a = assess("runc", HOST, Ok(RUNC_ON_CLOUD_VM));
        assert_eq!(a.tier, IsolationTier::Container);
        assert!(!a.downgraded());
        let s = &a.evidence.signals;
        assert!(s.contains(&"kernel:shared".to_owned()), "{s:?}");
        assert!(s.contains(&"hypervisor:cpu-flag".to_owned()), "{s:?}");
        assert_eq!(a.evidence.guest_kernel, HOST);
        assert_eq!(a.evidence.host_kernel, HOST);
    }

    #[test]
    fn runsc_is_kernel() {
        let a = assess("runsc", HOST, Ok(RUNSC));
        assert_eq!(a.tier, IsolationTier::Kernel);
        assert!(!a.downgraded());
        for want in ["gvisor:proc-version", "gvisor:dmesg", "gvisor:cmdline"] {
            assert!(a.evidence.signals.contains(&want.to_owned()), "{want}");
        }
        // A gVisor signature is enough without the host kernel.
        assert_eq!(assess("runsc", "", Ok(RUNSC)).tier, IsolationTier::Kernel);
    }

    #[test]
    fn observed_kata_is_vm_by_evidence() {
        for rt in ["kata-qemu", "kata-clh", "io.containerd.kata-qemu.v2"] {
            let a = assess(rt, KVM_HOST, Ok(KATA_OBSERVED));
            assert_eq!(a.claimed, IsolationTier::Vm, "{rt}");
            assert_eq!(a.tier, IsolationTier::Vm, "{rt}");
            assert_eq!(a.evidence.guest_kernel, "6.18.35");
            assert!(
                a.evidence
                    .signals
                    .contains(&"hypervisor:cpu-flag".to_owned())
            );
            assert!(a.evidence.signals.contains(&"kernel:separate".to_owned()));
            assert!(
                !a.evidence
                    .signals
                    .iter()
                    .any(|s| s.starts_with("hypervisor:dmi"))
            );
        }
        // runc on the same host: the guest kernel is the host's.
        let runc = "@@osrelease\n6.12.100+deb13-cloud-amd64\n@@cpuflags\nflags : vmx hypervisor\n";
        assert_eq!(
            assess("runc", KVM_HOST, Ok(runc)).tier,
            IsolationTier::Container
        );
    }

    /// The evidence recorded on the KVM host, field for field. The host
    /// recorded `claim:kernel` for Kata, from before Kata's name claimed
    /// `vm`; the rest is unchanged.
    #[test]
    fn observed_kvm_host_evidence_is_reproduced() {
        let signals = |v: &[&str]| v.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        let a = assess("runc", KVM_HOST, Ok(RUNC_KVM_HOST_OBSERVED));
        assert_eq!(a.tier, IsolationTier::Container);
        assert_eq!(
            a.evidence,
            IsolationEvidence {
                runtime: "runc".into(),
                guest_kernel: KVM_HOST.into(),
                host_kernel: KVM_HOST.into(),
                signals: signals(&[
                    "probe:ok",
                    "kernel:shared",
                    "hypervisor:cpu-flag",
                    "claim:container",
                    "verdict:container",
                ]),
                hypervisor: String::new(),
            }
        );
        for (runtime, hv) in [
            ("io.containerd.kata-qemu.v2", "qemu"),
            ("io.containerd.kata-clh.v2", "cloud-hypervisor"),
        ] {
            let mut a = assess(runtime, KVM_HOST, Ok(KATA_OBSERVED));
            a.attach_host_hypervisor(Some(hv));
            assert_eq!(a.tier, IsolationTier::Vm, "{runtime}");
            assert!(!a.downgraded(), "{runtime}");
            assert_eq!(
                a.evidence,
                IsolationEvidence {
                    runtime: runtime.into(),
                    guest_kernel: "6.18.35".into(),
                    host_kernel: KVM_HOST.into(),
                    signals: signals(&[
                        "probe:ok",
                        "kernel:separate",
                        "hypervisor:cpu-flag",
                        "claim:vm",
                        &format!("host:hypervisor={hv}"),
                        "verdict:vm",
                    ]),
                    hypervisor: hv.into(),
                },
                "{runtime}"
            );
        }
    }

    #[test]
    fn host_hypervisor_is_recorded_and_mismatches_flagged() {
        // Observed: a runtime named kata-clh that really ran QEMU.
        let mut a = assess("kata-clh", KVM_HOST, Ok(KATA_OBSERVED));
        a.attach_host_hypervisor(Some("qemu"));
        assert_eq!(a.tier, IsolationTier::Vm);
        assert_eq!(a.evidence.hypervisor, "qemu");
        let s = &a.evidence.signals;
        assert!(s.contains(&"host:hypervisor=qemu".to_owned()), "{s:?}");
        assert!(
            s.contains(&"host:hypervisor-mismatch=cloud-hypervisor->qemu".to_owned()),
            "{s:?}"
        );
        assert_eq!(s.last().map(String::as_str), Some("verdict:vm"));
        // Host processes not visible: vm, hypervisor unknown.
        let mut a = assess("kata-qemu", KVM_HOST, Ok(KATA_OBSERVED));
        a.attach_host_hypervisor(None);
        assert_eq!(a.evidence.hypervisor, "unknown");
        assert_eq!(a.evidence.ledger_meta()["isolation_hypervisor"], "unknown");
        // Below vm nothing is attached.
        let mut a = assess("runc", HOST, Ok(RUNC_ON_CLOUD_VM));
        a.attach_host_hypervisor(Some("qemu"));
        assert!(a.evidence.hypervisor.is_empty());
        assert_eq!(
            expected_hypervisor("io.containerd.kata-fc.v2"),
            Some("firecracker")
        );
        assert_eq!(expected_hypervisor("kata"), None);
    }

    #[test]
    fn finds_hypervisor_processes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let id = "0123456789abcdef0123456789abcdef";
        let proc_ = |pid: &str, argv: &[&str]| {
            let d = dir.path().join(pid);
            std::fs::create_dir_all(&d).expect("mkdir");
            std::fs::write(d.join("cmdline"), argv.join("\0")).expect("write");
        };
        let sandbox = format!("sandbox-{id}");
        proc_("10", &["/usr/bin/containerd-shim-kata-v2", "-id", id]);
        proc_(
            "11",
            &[
                "/opt/kata/bin/qemu-system-x86_64",
                "-name",
                "sandbox-other0000000000",
            ],
        );
        proc_(
            "12",
            &["/opt/kata/bin/qemu-system-x86_64", "-name", &sandbox],
        );
        proc_("self", &["/opt/kata/bin/firecracker", id]);
        assert_eq!(find_hypervisor(dir.path(), id).as_deref(), Some("qemu"));
        let sock = format!("/run/kata/{id}x/clh.sock");
        proc_(
            "13",
            &["/opt/kata/bin/cloud-hypervisor", "--api-socket", &sock],
        );
        let found = find_hypervisor(dir.path(), &format!("{id}x"));
        assert_eq!(found.as_deref(), Some("cloud-hypervisor"));
        assert_eq!(find_hypervisor(dir.path(), "nope-nope-nope"), None);
        assert_eq!(find_hypervisor(dir.path(), "short"), None);
    }

    #[test]
    fn smbios_qemu_is_vm_by_evidence() {
        let a = assess("kata-qemu", HOST, Ok(QEMU_SMBIOS));
        assert_eq!(a.claimed, IsolationTier::Vm);
        assert_eq!(a.tier, IsolationTier::Vm);
        assert!(
            a.evidence
                .signals
                .contains(&"hypervisor:dmi=QEMU".to_owned())
        );
        assert!(a.evidence.signals.contains(&"kernel:separate".to_owned()));
    }

    #[test]
    fn kata_fc_is_vm() {
        let a = assess("kata-fc", HOST, Ok(KATA_FC));
        assert_eq!(a.tier, IsolationTier::Vm);
        assert!(!a.downgraded());
        assert!(
            a.evidence
                .signals
                .contains(&"hypervisor:cmdline=virtio_mmio".to_owned())
        );
    }

    #[test]
    fn krun_on_arm64_is_vm_from_the_device_tree() {
        let a = assess("krun", HOST, Ok(KRUN_ARM64));
        assert_eq!(a.tier, IsolationTier::Vm);
        assert!(
            a.evidence
                .signals
                .contains(&"hypervisor:devicetree=linux,dummy-virt".to_owned())
        );
    }

    #[test]
    fn vm_name_with_shared_kernel_is_downgraded() {
        // A runtime called kata-fc that is really runc (mis-registered in
        // daemon.json): the kernel is the host's.
        let a = assess("kata-fc", HOST, Ok(RUNC_ON_CLOUD_VM));
        assert_eq!(a.tier, IsolationTier::Container);
        assert!(a.downgraded());
        assert!(a.evidence.signals.contains(&"verdict:container".to_owned()));
    }

    #[test]
    fn forged_vm_output_cannot_exceed_the_ceiling() {
        let a = assess("runc", HOST, Ok(QEMU_SMBIOS));
        assert_eq!(a.tier, IsolationTier::Container);
        assert!(
            a.evidence
                .signals
                .contains(&"capped:vm->container".to_owned())
        );
        let a = assess("runsc", HOST, Ok(KATA_FC));
        assert_eq!(a.tier, IsolationTier::Kernel);
    }

    #[test]
    fn separate_kernel_without_hypervisor_marker_is_kernel() {
        // Kata claims vm; without a hardware marker only kernel is proven.
        let p = "@@osrelease\n6.1.62\n@@cpuflags\nflags : fpu vme\n";
        let a = assess("kata-clh", HOST, Ok(p));
        assert_eq!(a.tier, IsolationTier::Kernel);
        assert!(a.downgraded());
    }

    #[test]
    fn unconfirmed_is_container() {
        // Probe failed (no shell in the image).
        let a = assess("krun", HOST, Err("exec: \"/bin/sh\": not found"));
        assert_eq!(a.tier, IsolationTier::Container);
        assert!(a.downgraded());
        assert!(a.evidence.signals[0].starts_with("probe:failed="));
        // Host kernel unknown: a different kernel cannot be established.
        let a = assess("kata-fc", "", Ok(KATA_FC));
        assert_eq!(a.tier, IsolationTier::Container);
        assert!(
            a.evidence
                .signals
                .contains(&"kernel:unknown-host".to_owned())
        );
        // Empty output.
        assert_eq!(assess("krun", HOST, Ok("")).tier, IsolationTier::Container);
    }

    #[test]
    fn unprobed_trusts_the_name_and_says_so() {
        let a = assess_unprobed("kata-fc", HOST);
        assert_eq!(a.tier, IsolationTier::Vm);
        assert_eq!(a.evidence.signals[0], "probe:disabled");
    }

    #[test]
    fn ledger_meta_and_serde() {
        let a = assess("kata-fc", HOST, Ok(KATA_FC));
        let m = a.evidence.ledger_meta();
        assert_eq!(m["isolation_runtime"], "kata-fc");
        assert_eq!(m["isolation_guest_kernel"], "6.1.62");
        assert!(m["isolation_signals"].ends_with("verdict:vm"));
        let j = serde_json::to_value(&a.evidence).expect("json");
        assert_eq!(j["guest_kernel"], "6.1.62");
        assert!(j["signals"].is_array());
    }

    #[test]
    fn probe_script_is_marked_and_avoids_tar_flags() {
        let argv = probe_command();
        assert!(argv[2].contains(PROBE_MARKER));
        // The Docker test fake routes tar streams on these substrings.
        assert!(!argv[2].contains("-xf -") && !argv[2].contains("-cf -"));
        assert!(!argv[2].contains('\n'), "one line");
    }
}
