//! File operations, run with the caller's identity already in effect (in
//! the agent's helper process, after it dropped to the sandbox user).

use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

use crate::proto::{DirEntry, FileAction, FileStat};

/// The JSON result of an action that has one (`None` for streamed ones).
pub type Outcome = Result<Option<serde_json::Value>, String>;

/// Runs `action` on `path`, reading a body from `input` (write, tar-in) and
/// streaming output to `output` (read, tar-out).
pub fn run(
    action: FileAction,
    path: &Path,
    mode: u32,
    input: &mut dyn Read,
    output: &mut dyn Write,
) -> Outcome {
    let ctx = |what: &str, e: io::Error| format!("{what} {}: {e}", path.display());
    match action {
        FileAction::Write => {
            if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
                fs::create_dir_all(parent).map_err(|e| ctx("create parent of", e))?;
            }
            let mode = if mode == 0 { 0o644 } else { mode & 0o7777 };
            // Never write through a link the sandbox planted at the target.
            let mut f = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(mode)
                .custom_flags(nix::fcntl::OFlag::O_NOFOLLOW.bits())
                .open(path)
                .map_err(|e| ctx("open", e))?;
            io::copy(input, &mut f).map_err(|e| ctx("write", e))?;
            f.flush().map_err(|e| ctx("flush", e))?;
            // The umask may have narrowed the creation mode.
            f.set_permissions(fs::Permissions::from_mode(mode))
                .map_err(|e| ctx("chmod", e))?;
            f.sync_all().map_err(|e| ctx("sync", e))?;
            Ok(Some(serde_json::json!({})))
        }
        FileAction::Read => {
            let mut f = fs::File::open(path).map_err(|e| ctx("open", e))?;
            io::copy(&mut f, output).map_err(|e| ctx("read", e))?;
            output.flush().map_err(|e| ctx("read", e))?;
            Ok(None)
        }
        FileAction::Mkdir => {
            fs::create_dir_all(path).map_err(|e| ctx("mkdir", e))?;
            if mode != 0 {
                fs::set_permissions(path, fs::Permissions::from_mode(mode & 0o7777))
                    .map_err(|e| ctx("chmod", e))?;
            }
            Ok(Some(serde_json::json!({})))
        }
        FileAction::Stat => {
            let md = fs::symlink_metadata(path).map_err(|e| ctx("stat", e))?;
            Ok(Some(
                serde_json::to_value(stat_of(&md)).map_err(|e| e.to_string())?,
            ))
        }
        FileAction::List => {
            let mut out = Vec::new();
            for e in fs::read_dir(path).map_err(|e| ctx("list", e))? {
                let e = e.map_err(|e| ctx("list", e))?;
                let md = e.metadata().map_err(|e| ctx("stat entry in", e))?;
                out.push(DirEntry {
                    name: e.file_name().to_string_lossy().into_owned(),
                    stat: stat_of(&md),
                });
            }
            out.sort_by(|a, b| a.name.cmp(&b.name));
            Ok(Some(serde_json::to_value(out).map_err(|e| e.to_string())?))
        }
        FileAction::TarIn => {
            fs::create_dir_all(path).map_err(|e| ctx("create", e))?;
            let mut a = tar::Archive::new(input);
            a.set_preserve_permissions(true);
            a.set_preserve_ownerships(false);
            a.set_unpack_xattrs(false);
            a.set_overwrite(true);
            // `unpack` refuses entries that would land outside `path`,
            // including through links already in the directory.
            a.unpack(path).map_err(|e| ctx("extract into", e))?;
            Ok(Some(serde_json::json!({})))
        }
        FileAction::TarOut => {
            let mut b = tar::Builder::new(output);
            b.follow_symlinks(false);
            b.mode(tar::HeaderMode::Complete);
            b.append_dir_all(".", path).map_err(|e| ctx("archive", e))?;
            let w = b.into_inner().map_err(|e| ctx("archive", e))?;
            w.flush().map_err(|e| ctx("archive", e))?;
            Ok(None)
        }
    }
}

/// The protocol view of a file's metadata.
pub fn stat_of(md: &fs::Metadata) -> FileStat {
    let ft = md.file_type();
    FileStat {
        kind: if ft.is_symlink() {
            "symlink"
        } else if ft.is_dir() {
            "dir"
        } else if ft.is_file() {
            "file"
        } else {
            "other"
        }
        .into(),
        size: md.len(),
        mode: md.mode() & 0o7777,
        uid: md.uid(),
        gid: md.gid(),
        mtime: md.mtime(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run_on(action: FileAction, path: &Path, mode: u32, input: &[u8]) -> (Outcome, Vec<u8>) {
        let mut out = Vec::new();
        let mut inp = input;
        let r = run(action, path, mode, &mut inp, &mut out);
        (r, out)
    }

    #[test]
    fn write_read_stat_list() {
        let d = tempfile::tempdir().expect("tempdir");
        let f = d.path().join("a/b/c.txt");
        run_on(FileAction::Write, &f, 0o600, b"hi")
            .0
            .expect("write");
        let (r, out) = run_on(FileAction::Read, &f, 0, b"");
        assert!(r.expect("read").is_none());
        assert_eq!(out, b"hi");
        let st: FileStat = serde_json::from_value(
            run_on(FileAction::Stat, &f, 0, b"")
                .0
                .expect("stat")
                .expect("value"),
        )
        .expect("json");
        assert_eq!((st.kind.as_str(), st.size, st.mode), ("file", 2, 0o600));
        let ls: Vec<DirEntry> = serde_json::from_value(
            run_on(FileAction::List, &d.path().join("a/b"), 0, b"")
                .0
                .expect("list")
                .expect("value"),
        )
        .expect("json");
        assert_eq!(ls.len(), 1);
        assert_eq!(ls[0].name, "c.txt");
    }

    #[test]
    fn write_refuses_a_planted_symlink() {
        let d = tempfile::tempdir().expect("tempdir");
        let victim = d.path().join("victim");
        std::fs::write(&victim, "keep").expect("victim");
        let link = d.path().join("link");
        std::os::unix::fs::symlink(&victim, &link).expect("symlink");
        let (r, _) = run_on(FileAction::Write, &link, 0o644, b"pwned");
        assert!(r.is_err());
        assert_eq!(std::fs::read_to_string(&victim).expect("read"), "keep");
    }

    #[test]
    fn tar_round_trip() {
        let src = tempfile::tempdir().expect("src");
        std::fs::create_dir_all(src.path().join("dir")).expect("dir");
        std::fs::write(src.path().join("dir/f"), "data").expect("f");
        let (r, tar) = run_on(FileAction::TarOut, src.path(), 0, b"");
        assert!(r.expect("tar out").is_none());
        let dst = tempfile::tempdir().expect("dst");
        run_on(FileAction::TarIn, dst.path(), 0, &tar)
            .0
            .expect("tar in");
        assert_eq!(
            std::fs::read_to_string(dst.path().join("dir/f")).expect("read"),
            "data"
        );
    }
}
