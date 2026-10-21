//! The isolation probe, collected by the agent itself.
//!
//! The output uses the same `@@section` format as the shell probe the
//! container backends run (`runeward_backend::evidence::PROBE_SCRIPT`), so
//! the host assesses it with the same code. Collecting it natively means an
//! image without `/bin/sh` still produces evidence.

use std::fs;
use std::io::Read;
use std::path::Path;

fn read(root: &Path, p: &str) -> String {
    fs::read_to_string(root.join(p.trim_start_matches('/'))).unwrap_or_default()
}

/// The first `flags` line of `/proc/cpuinfo` (x86).
fn cpu_flags(root: &Path) -> String {
    read(root, "/proc/cpuinfo")
        .lines()
        .find(|l| l.starts_with("flags"))
        .unwrap_or("")
        .to_owned()
}

/// The first `n` kernel log records, formatted like `dmesg`.
fn dmesg(root: &Path, n: usize) -> String {
    let path = root.join("dev/kmsg");
    let mut out = Vec::new();
    #[cfg(unix)]
    let opened = {
        use std::os::unix::fs::OpenOptionsExt;
        fs::OpenOptions::new()
            .read(true)
            .custom_flags(nix::fcntl::OFlag::O_NONBLOCK.bits())
            .open(&path)
    };
    #[cfg(not(unix))]
    let opened = fs::File::open(&path);
    let Ok(mut f) = opened else {
        return String::new();
    };
    let mut buf = vec![0u8; 8192];
    while out.len() < n {
        // Each read returns one record; EAGAIN at the end of the buffer.
        match f.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(len) => {
                let rec = String::from_utf8_lossy(&buf[..len]).into_owned();
                if let Some(line) = format_kmsg(&rec) {
                    out.push(line);
                }
            }
        }
    }
    out.join("\n")
}

/// Formats one `/dev/kmsg` record (`prio,seq,usec,flags;message`) as
/// `[seconds.micros] message`.
pub fn format_kmsg(rec: &str) -> Option<String> {
    let (head, msg) = rec.split_once(';')?;
    let usec: u64 = head.split(',').nth(2)?.parse().ok()?;
    let msg = msg.lines().next().unwrap_or("");
    Some(format!(
        "[{:5}.{:06}] {msg}",
        usec / 1_000_000,
        usec % 1_000_000
    ))
}

/// Collects the probe sections from the filesystem rooted at `root`
/// (normally `/`).
pub fn collect(root: &Path) -> String {
    let mut s = String::from(": runeward-isolation-probe (agent)\n");
    let mut section = |name: &str, body: String| {
        s.push_str("\n@@");
        s.push_str(name);
        s.push('\n');
        s.push_str(body.trim_end());
        s.push('\n');
    };
    section("osrelease", read(root, "/proc/sys/kernel/osrelease"));
    section("version", read(root, "/proc/version"));
    section("cpuflags", cpu_flags(root));
    section(
        "dmi",
        format!(
            "{}{}",
            read(root, "/sys/class/dmi/id/sys_vendor"),
            read(root, "/sys/class/dmi/id/product_name")
        ),
    );
    section("hypervisor", read(root, "/sys/hypervisor/type"));
    section(
        "devicetree",
        fs::read(root.join("proc/device-tree/compatible"))
            .map(|b| String::from_utf8_lossy(&b).into_owned())
            .unwrap_or_default(),
    );
    section("cmdline", read(root, "/proc/cmdline"));
    section("mounts", read(root, "/proc/self/mounts"));
    section("dmesg", dmesg(root, 20));
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sections_from_a_fake_root() {
        let d = tempfile::tempdir().expect("tempdir");
        let w = |p: &str, c: &str| {
            let full = d.path().join(p);
            std::fs::create_dir_all(full.parent().expect("parent")).expect("mkdir");
            std::fs::write(full, c).expect("write");
        };
        w("proc/sys/kernel/osrelease", "6.1.141\n");
        w(
            "proc/cpuinfo",
            "processor\t: 0\nflags\t\t: fpu hypervisor\n",
        );
        w(
            "proc/cmdline",
            "console=ttyS0 virtio_mmio.device=4K@0xd0000000:5\n",
        );
        w("proc/self/mounts", "/dev/vdb /workspace ext4 rw 0 0\n");
        let out = collect(d.path());
        assert!(out.contains("@@osrelease\n6.1.141\n"), "{out}");
        assert!(
            out.contains("@@cpuflags\nflags\t\t: fpu hypervisor\n"),
            "{out}"
        );
        assert!(
            out.contains("@@mounts\n/dev/vdb /workspace ext4 rw 0 0\n"),
            "{out}"
        );
        assert!(out.contains("@@dmesg\n"), "{out}");
    }

    #[test]
    fn kmsg_records() {
        assert_eq!(
            format_kmsg("6,0,0,-;Linux version 6.1.141\n SUBSYSTEM=x").as_deref(),
            Some("[    0.000000] Linux version 6.1.141")
        );
        assert_eq!(
            format_kmsg("4,12,1512345,-;Hypervisor detected: KVM").as_deref(),
            Some("[    1.512345] Hypervisor detected: KVM")
        );
        assert!(format_kmsg("garbage").is_none());
    }
}
