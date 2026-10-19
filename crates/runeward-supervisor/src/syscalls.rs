//! The self-protection syscall deny list, with numbers for each supported
//! architecture.
//!
//! The numbers are spelled out rather than taken from `libc` so a filter can
//! be built and inspected for either architecture on any host; a Linux test
//! cross-checks them against `libc::SYS_*` for the native one.

/// A supported filter architecture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arch {
    X86_64,
    Aarch64,
}

impl Arch {
    /// Both architectures.
    pub const ALL: [Self; 2] = [Self::X86_64, Self::Aarch64];

    /// The architecture this binary was built for, if supported.
    pub fn native() -> Option<Self> {
        if cfg!(target_arch = "x86_64") {
            Some(Self::X86_64)
        } else if cfg!(target_arch = "aarch64") {
            Some(Self::Aarch64)
        } else {
            None
        }
    }

    /// The report spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::X86_64 => "x86_64",
            Self::Aarch64 => "aarch64",
        }
    }
}

/// Bit the x86_64 kernel sets on x32-ABI syscall numbers.
pub const X32_SYSCALL_BIT: i64 = 0x4000_0000;

/// One denied syscall: its name and number on x86_64 and aarch64.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Denied {
    pub name: &'static str,
    pub x86_64: i64,
    pub aarch64: i64,
}

impl Denied {
    /// The number on `arch`.
    pub fn nr(&self, arch: Arch) -> i64 {
        match arch {
            Arch::X86_64 => self.x86_64,
            Arch::Aarch64 => self.aarch64,
        }
    }
}

macro_rules! denied {
    ($($name:ident = $x:expr, $a:expr;)*) => {
        /// Syscalls that let a process escape or tamper with its sandbox.
        /// The filter answers them with `EPERM`.
        pub const DENIED: &[Denied] = &[
            $(Denied { name: stringify!($name), x86_64: $x, aarch64: $a },)*
        ];
    };
}

denied! {
    // Inspecting or writing other processes.
    ptrace = 101, 117;
    process_vm_readv = 310, 270;
    process_vm_writev = 311, 271;
    pidfd_getfd = 438, 438;
    // Namespaces and mounts.
    unshare = 272, 97;
    setns = 308, 268;
    mount = 165, 40;
    umount2 = 166, 39;
    pivot_root = 155, 41;
    chroot = 161, 51;
    open_tree = 428, 428;
    move_mount = 429, 429;
    fsopen = 430, 430;
    fsconfig = 431, 431;
    fsmount = 432, 432;
    fspick = 433, 433;
    mount_setattr = 442, 442;
    open_tree_attr = 467, 467;
    // Kernel attack surface.
    bpf = 321, 280;
    perf_event_open = 298, 241;
    userfaultfd = 323, 282;
    io_uring_setup = 425, 425;
    io_uring_enter = 426, 426;
    io_uring_register = 427, 427;
    kexec_load = 246, 104;
    kexec_file_load = 320, 294;
    init_module = 175, 105;
    finit_module = 313, 273;
    delete_module = 176, 106;
    // Kernel keyrings.
    keyctl = 250, 219;
    add_key = 248, 217;
    request_key = 249, 218;
    // Capabilities.
    capset = 126, 91;
}

/// x32-ABI numbers that differ from `x86_64 | X32_SYSCALL_BIT` for denied
/// syscalls (ptrace, process_vm_readv/writev, kexec_load), already with the
/// x32 bit set.
pub const X32_EXTRA: &[(&str, i64)] = &[
    ("ptrace", X32_SYSCALL_BIT | 521),
    ("process_vm_readv", X32_SYSCALL_BIT | 539),
    ("process_vm_writev", X32_SYSCALL_BIT | 540),
    ("kexec_load", X32_SYSCALL_BIT | 528),
];

/// `clone(2)`, whose namespace flags the filter rejects with `EPERM`.
pub const CLONE: Denied = Denied {
    name: "clone",
    x86_64: 56,
    aarch64: 220,
};

/// `clone3(2)`, answered with `ENOSYS` because its flags live behind a
/// pointer seccomp cannot read; libc then falls back to `clone(2)`.
pub const CLONE3: Denied = Denied {
    name: "clone3",
    x86_64: 435,
    aarch64: 435,
};

/// `clone(2)` flags that create namespaces.
pub const CLONE_NAMESPACE_FLAGS: &[(&str, u64)] = &[
    ("CLONE_NEWNS", 0x0002_0000),
    ("CLONE_NEWCGROUP", 0x0200_0000),
    ("CLONE_NEWUTS", 0x0400_0000),
    ("CLONE_NEWIPC", 0x0800_0000),
    ("CLONE_NEWUSER", 0x1000_0000),
    ("CLONE_NEWPID", 0x2000_0000),
    ("CLONE_NEWNET", 0x4000_0000),
];

/// Every number the `EPERM` filter matches unconditionally on `arch`,
/// including the x32 aliases on x86_64.
pub fn denied_numbers(arch: Arch) -> Vec<(&'static str, i64)> {
    let mut out: Vec<_> = DENIED.iter().map(|d| (d.name, d.nr(arch))).collect();
    if arch == Arch::X86_64 {
        out.extend(DENIED.iter().map(|d| (d.name, d.x86_64 | X32_SYSCALL_BIT)));
        out.extend(X32_EXTRA.iter().copied());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn covers_the_required_list() {
        let required = [
            "ptrace",
            "process_vm_readv",
            "process_vm_writev",
            "pidfd_getfd",
            "unshare",
            "setns",
            "mount",
            "umount2",
            "pivot_root",
            "chroot",
            "fsopen",
            "fsmount",
            "move_mount",
            "open_tree",
            "fsconfig",
            "fspick",
            "mount_setattr",
            "bpf",
            "perf_event_open",
            "userfaultfd",
            "io_uring_setup",
            "io_uring_enter",
            "io_uring_register",
            "kexec_load",
            "kexec_file_load",
            "init_module",
            "finit_module",
            "delete_module",
            "keyctl",
            "add_key",
            "request_key",
            "capset",
        ];
        for name in required {
            assert!(DENIED.iter().any(|d| d.name == name), "{name} missing");
        }
    }

    #[test]
    fn numbers_are_unique_per_arch() {
        for arch in Arch::ALL {
            let mut nrs: Vec<i64> = denied_numbers(arch).iter().map(|(_, n)| *n).collect();
            nrs.push(CLONE.nr(arch));
            nrs.push(CLONE3.nr(arch));
            let len = nrs.len();
            nrs.sort_unstable();
            nrs.dedup();
            assert_eq!(nrs.len(), len, "{arch:?} has a duplicate number");
        }
    }

    #[test]
    fn x32_aliases_only_on_x86_64() {
        assert_eq!(denied_numbers(Arch::Aarch64).len(), DENIED.len());
        assert_eq!(
            denied_numbers(Arch::X86_64).len(),
            DENIED.len() * 2 + X32_EXTRA.len()
        );
    }

    /// The hand-written numbers match the C library's for the native arch.
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[test]
    fn numbers_match_libc() {
        let arch = Arch::native().expect("supported arch");
        let libc_nr: &[(&str, i64)] = &[
            ("ptrace", libc::SYS_ptrace),
            ("process_vm_readv", libc::SYS_process_vm_readv),
            ("process_vm_writev", libc::SYS_process_vm_writev),
            ("pidfd_getfd", libc::SYS_pidfd_getfd),
            ("unshare", libc::SYS_unshare),
            ("setns", libc::SYS_setns),
            ("mount", libc::SYS_mount),
            ("umount2", libc::SYS_umount2),
            ("pivot_root", libc::SYS_pivot_root),
            ("chroot", libc::SYS_chroot),
            ("open_tree", libc::SYS_open_tree),
            ("move_mount", libc::SYS_move_mount),
            ("fsopen", libc::SYS_fsopen),
            ("fsconfig", libc::SYS_fsconfig),
            ("fsmount", libc::SYS_fsmount),
            ("fspick", libc::SYS_fspick),
            ("mount_setattr", libc::SYS_mount_setattr),
            ("bpf", libc::SYS_bpf),
            ("perf_event_open", libc::SYS_perf_event_open),
            ("userfaultfd", libc::SYS_userfaultfd),
            ("io_uring_setup", libc::SYS_io_uring_setup),
            ("io_uring_enter", libc::SYS_io_uring_enter),
            ("io_uring_register", libc::SYS_io_uring_register),
            ("kexec_load", libc::SYS_kexec_load),
            ("kexec_file_load", libc::SYS_kexec_file_load),
            ("init_module", libc::SYS_init_module),
            ("finit_module", libc::SYS_finit_module),
            ("delete_module", libc::SYS_delete_module),
            ("keyctl", libc::SYS_keyctl),
            ("add_key", libc::SYS_add_key),
            ("request_key", libc::SYS_request_key),
            ("capset", libc::SYS_capset),
            ("clone", libc::SYS_clone),
            ("clone3", libc::SYS_clone3),
        ];
        for (name, nr) in libc_nr {
            let d = DENIED
                .iter()
                .chain([&CLONE, &CLONE3])
                .find(|d| d.name == *name)
                .expect(name);
            assert_eq!(d.nr(arch), *nr, "{name} on {arch:?}");
        }
    }
}
