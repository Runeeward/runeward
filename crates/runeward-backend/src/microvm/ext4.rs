//! Building ext4 disk images with e2fsprogs, without root.
//!
//! `mkfs.ext4 -d DIR` copies a directory tree into a new filesystem, but
//! takes ownership and permissions from the host files, and an unprivileged
//! extraction cannot reproduce an image's owners (or unreadable modes).
//! The real owner and mode of every entry are therefore recorded while the
//! layers are extracted and written into the image afterwards with
//! `debugfs -w` (`set_inode_field`), so the build never needs root.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use tokio::process::Command;

use crate::config::{BackendConfig, MICROVM_MKFS_ENV};
use crate::error::{BackendError, Result};
use crate::factory::look_path;

/// An entry's owner and full `st_mode` (file type bits included).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Meta {
    pub(crate) uid: u64,
    pub(crate) gid: u64,
    pub(crate) mode: u32,
}

/// `S_IFDIR`.
pub(crate) const S_IFDIR: u32 = 0o040_000;
/// `S_IFREG`.
pub(crate) const S_IFREG: u32 = 0o100_000;
/// `S_IFLNK`.
pub(crate) const S_IFLNK: u32 = 0o120_000;

/// `mkfs.ext4` and `debugfs`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Tools {
    pub(crate) mkfs: PathBuf,
    pub(crate) debugfs: PathBuf,
}

impl Tools {
    /// Finds the tools: `RUNEWARD_MICROVM_MKFS`, else `mkfs.ext4` on
    /// `PATH`, `/sbin`, `/usr/sbin` or Homebrew's e2fsprogs; `debugfs`
    /// from the same directory.
    pub(crate) fn find(cfg: &BackendConfig) -> Result<Self> {
        let set = cfg.raw(MICROVM_MKFS_ENV).trim();
        let mkfs = if set.is_empty() {
            look_path("mkfs.ext4").or_else(|| {
                [
                    "/sbin/mkfs.ext4",
                    "/usr/sbin/mkfs.ext4",
                    "/opt/homebrew/opt/e2fsprogs/sbin/mkfs.ext4",
                    "/usr/local/opt/e2fsprogs/sbin/mkfs.ext4",
                ]
                .iter()
                .map(PathBuf::from)
                .find(|p| p.is_file())
            })
        } else {
            Some(PathBuf::from(set))
        };
        let Some(mkfs) = mkfs.filter(|p| p.is_file()) else {
            return Err(BackendError::Unsupported(format!(
                "the microvm backend builds ext4 disks with mkfs.ext4 and debugfs (e2fsprogs 1.43 or later); install e2fsprogs or set {MICROVM_MKFS_ENV}"
            )));
        };
        let debugfs = mkfs.with_file_name("debugfs");
        if !debugfs.is_file() {
            return Err(BackendError::Unsupported(format!(
                "debugfs not found next to {} (e2fsprogs)",
                mkfs.display()
            )));
        }
        Ok(Self { mkfs, debugfs })
    }

    async fn run(&self, bin: &Path, args: &[&str]) -> Result<String> {
        let out = Command::new(bin)
            .args(args)
            .stdin(Stdio::null())
            .output()
            .await
            .map_err(|e| BackendError::io(format!("run {}", bin.display()), e))?;
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        if !out.status.success() {
            return Err(BackendError::msg(format!(
                "{} {}: {}",
                bin.display(),
                args.join(" "),
                stderr.trim()
            )));
        }
        Ok(stderr)
    }

    /// Creates an empty ext4 filesystem in a sparse file of `size` bytes,
    /// its root directory owned by root.
    pub(crate) async fn make_empty(&self, out: &Path, size: u64, label: &str) -> Result<()> {
        let f = std::fs::File::create(out)
            .map_err(|e| BackendError::io(format!("create {}", out.display()), e))?;
        f.set_len(size)
            .map_err(|e| BackendError::io(format!("size {}", out.display()), e))?;
        drop(f);
        let path = out.to_string_lossy();
        self.run(
            &self.mkfs,
            &[
                "-F",
                "-q",
                "-m",
                "0",
                "-L",
                label,
                "-E",
                "root_owner=0:0,nodiscard",
                &path,
            ],
        )
        .await
        .map(drop)
    }

    /// Builds a read-only image filesystem from `dir`, then applies the
    /// recorded owners and modes.
    pub(crate) async fn make_from_dir(
        &self,
        dir: &Path,
        meta: &BTreeMap<String, Meta>,
        out: &Path,
        size: u64,
    ) -> Result<()> {
        let f = std::fs::File::create(out)
            .map_err(|e| BackendError::io(format!("create {}", out.display()), e))?;
        f.set_len(size)
            .map_err(|e| BackendError::io(format!("size {}", out.display()), e))?;
        drop(f);
        let inodes = (meta.len() as u64 + 4096).to_string();
        let (src, path) = (dir.to_string_lossy(), out.to_string_lossy());
        self.run(
            &self.mkfs,
            &[
                "-F",
                "-q",
                "-m",
                "0",
                "-N",
                &inodes,
                "-O",
                "^has_journal",
                "-L",
                "rw-image",
                "-E",
                "root_owner=0:0,nodiscard",
                "-d",
                &src,
                &path,
            ],
        )
        .await?;
        let (script, skipped) = fixup_script(meta);
        if skipped > 0 {
            tracing::warn!(target: "runeward_backend", "{skipped} image entries have names debugfs cannot address; they keep the extracting user's owner");
        }
        let script_path = out.with_extension("debugfs");
        std::fs::write(&script_path, script)
            .map_err(|e| BackendError::io("write debugfs script", e))?;
        let res = self
            .run(
                &self.debugfs,
                &["-w", "-f", &script_path.to_string_lossy(), &path],
            )
            .await;
        let _ = std::fs::remove_file(&script_path);
        let stderr = res?;
        // debugfs exits 0 even when a command fails; anything besides its
        // banner on stderr is a failure.
        let errors: Vec<&str> = stderr
            .lines()
            .filter(|l| !l.trim().is_empty() && !l.starts_with("debugfs "))
            .take(5)
            .collect();
        if !errors.is_empty() {
            return Err(BackendError::msg(format!(
                "apply image owners with debugfs: {}",
                errors.join("; ")
            )));
        }
        Ok(())
    }
}

/// Reports whether debugfs can address `p` inside double quotes.
fn quotable(p: &str) -> bool {
    !p.chars().any(|c| c == '"' || c == '\\' || c.is_control())
}

/// The debugfs commands setting every entry's owner and mode. Returns the
/// script and how many entries had to be skipped.
pub(crate) fn fixup_script(meta: &BTreeMap<String, Meta>) -> (String, usize) {
    let mut s = String::new();
    let mut skipped = 0;
    for (p, m) in meta {
        if !quotable(p) {
            skipped += 1;
            continue;
        }
        let path = format!("/{}", p.trim_start_matches('/'));
        let _ = writeln!(s, "sif \"{path}\" uid {}", m.uid);
        let _ = writeln!(s, "sif \"{path}\" gid {}", m.gid);
        let _ = writeln!(s, "sif \"{path}\" mode 0{:o}", m.mode);
    }
    (s, skipped)
}

/// The image size for `bytes` of file data in `entries` entries: room for
/// one block per entry, metadata and slack, at least 64 MiB, rounded to
/// MiB.
pub(crate) fn image_size(bytes: u64, entries: u64) -> u64 {
    let raw = bytes + entries * 4096 + bytes / 8 + (48 << 20);
    let mib = 1 << 20;
    raw.max(64 << 20).div_ceil(mib) * mib
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn script_sets_owner_and_full_mode() {
        let meta = BTreeMap::from([
            (
                "etc/shadow".to_owned(),
                Meta {
                    uid: 0,
                    gid: 42,
                    mode: S_IFREG | 0o640,
                },
            ),
            (
                "usr/bin/sudo".to_owned(),
                Meta {
                    uid: 0,
                    gid: 0,
                    mode: S_IFREG | 0o4755,
                },
            ),
            (
                "home/a dir".to_owned(),
                Meta {
                    uid: 1000,
                    gid: 1000,
                    mode: S_IFDIR | 0o700,
                },
            ),
            (
                "bad\"name".to_owned(),
                Meta {
                    uid: 0,
                    gid: 0,
                    mode: S_IFREG | 0o644,
                },
            ),
        ]);
        // The assertions do not print the script: CodeQL treats the
        // owners in it as sensitive data written to a log.
        let (s, skipped) = fixup_script(&meta);
        assert_eq!(skipped, 1);
        assert!(s.contains("sif \"/etc/shadow\" gid 42\n"));
        assert!(s.contains("sif \"/etc/shadow\" mode 0100640\n"));
        assert!(s.contains("sif \"/usr/bin/sudo\" mode 0104755\n"));
        assert!(s.contains("sif \"/home/a dir\" uid 1000\n"));
        assert!(!s.contains("bad"));
    }

    #[test]
    fn sizes() {
        assert_eq!(image_size(0, 0), 64 << 20);
        let s = image_size(100 << 20, 5000);
        assert!(s > (100 << 20) + 5000 * 4096, "{s}");
        assert_eq!(s % (1 << 20), 0);
    }
}
