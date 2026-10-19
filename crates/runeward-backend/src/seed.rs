//! Workspace tar streams: seeding, sanitizing, extracting and hashing.
//!
//! Host-side filesystem access goes through [`cap_std::fs::Dir`], which (like
//! Go's `os.Root`) resolves every path beneath an opened directory and
//! refuses to follow a symlink out of it, even if a path component is swapped
//! concurrently.

use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use cap_std::ambient_authority;
use cap_std::fs::{Dir, DirBuilder, OpenOptions};
use sha2::{Digest, Sha256};
use tar::{Archive, Builder, EntryType, Header};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, DuplexStream};
use tokio::runtime::Handle;
use tokio::task::JoinHandle;

use crate::error::{BackendError, Result};
use crate::pathutil;
use crate::types::SnapshotRef;

const STREAM_BUF: usize = 64 * 1024;

/// Reports whether a tar entry name (and, for links, its target) stays
/// within the extraction root: no absolute paths and no `..` escape.
pub fn tar_entry_safe(name: &str, linkname: &str) -> bool {
    rel_within_root(name) && (linkname.is_empty() || rel_within_root(linkname))
}

fn rel_within_root(p: &str) -> bool {
    if p.is_empty() {
        return true;
    }
    if p.starts_with('/') {
        return false;
    }
    let clean = pathutil::clean(p);
    clean != ".." && !clean.starts_with("../")
}

/// Copies a tar stream from `src` to `dst`, passing through only entries
/// whose paths stay within the extraction root and failing on the first
/// unsafe entry. Used to sanitize archives host-side before they reach a
/// sandbox's `tar -x`.
pub fn filter_tar_safe(dst: impl Write, src: impl Read) -> io::Result<()> {
    let mut archive = Archive::new(src);
    let mut out = Builder::new(dst);
    out.mode(tar::HeaderMode::Complete);
    let entries = archive
        .entries()
        .map_err(|e| io::Error::other(format!("restore: read archive: {e}")))?;
    for entry in entries {
        let mut entry =
            entry.map_err(|e| io::Error::other(format!("restore: read archive: {e}")))?;
        let name = String::from_utf8_lossy(&entry.path_bytes()).into_owned();
        let link = entry
            .link_name_bytes()
            .map(|b| String::from_utf8_lossy(&b).into_owned())
            .unwrap_or_default();
        if !tar_entry_safe(&name, &link) {
            let _ = out.finish();
            return Err(io::Error::other(format!(
                "restore: unsafe archive entry {name:?} -> {link:?}"
            )));
        }
        let mut header = entry.header().clone();
        let kind = header.entry_type();
        if kind.is_symlink() || kind.is_hard_link() {
            out.append_link(&mut header, &name, &link)?;
        } else if kind == EntryType::Regular {
            out.append_data(&mut header, &name, &mut entry)?;
        } else {
            header.set_size(0);
            out.append_data(&mut header, &name, io::empty())?;
        }
    }
    out.into_inner()?.flush()
}

/// Checks that a snapshot tarball still matches the digest recorded at
/// capture time. Snapshots without a digest are accepted.
pub fn verify_snapshot(snapshot: &SnapshotRef) -> Result<()> {
    if snapshot.sha256.is_empty() {
        return Ok(());
    }
    let sum = hash_file(Path::new(&snapshot.location))
        .map_err(|e| BackendError::io("restore: hash snapshot", e))?;
    if sum != snapshot.sha256 {
        return Err(BackendError::msg(format!(
            "restore: snapshot integrity check failed (tarball digest {sum} != recorded {})",
            snapshot.sha256
        )));
    }
    Ok(())
}

/// The hex SHA-256 of a file.
pub fn hash_file(path: &Path) -> io::Result<String> {
    let mut f = fs::File::open(path)?;
    let mut h = Sha256::new();
    io::copy(&mut f, &mut h)?;
    Ok(hex::encode(h.finalize()))
}

/// Tars the contents of `src_dir` into `w` with paths relative to it.
/// Regular files, directories and symlinks only (sockets, devices and fifos
/// are skipped), in lexical order. The source is never modified.
pub fn write_dir_tar(w: impl Write, src_dir: &Path) -> io::Result<()> {
    let meta = fs::metadata(src_dir).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("seed source {:?}: {e}", src_dir.display().to_string()),
        )
    })?;
    if !meta.is_dir() {
        return Err(io::Error::other(format!(
            "seed source {:?} is not a directory",
            src_dir.display().to_string()
        )));
    }
    let root = Dir::open_ambient_dir(src_dir, ambient_authority()).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("seed source root {:?}: {e}", src_dir.display().to_string()),
        )
    })?;
    let mut tw = Builder::new(w);
    tw.mode(tar::HeaderMode::Complete);
    walk(&root, Path::new(""), &mut tw)?;
    tw.into_inner()?.flush()
}

fn walk<W: Write>(root: &Dir, rel: &Path, tw: &mut Builder<W>) -> io::Result<()> {
    let dir = if rel.as_os_str().is_empty() {
        root.try_clone()?
    } else {
        root.open_dir(rel)?
    };
    let mut names: Vec<_> = dir
        .entries()?
        .map(|e| e.map(|e| e.file_name()))
        .collect::<io::Result<_>>()?;
    names.sort();
    for file_name in names {
        let child = rel.join(&file_name);
        let name = child.to_string_lossy().replace('\\', "/");
        let meta = root.symlink_metadata(&child)?;
        let mode = permissions(&meta);
        let ft = meta.file_type();
        if ft.is_dir() {
            let mut h = Header::new_ustar();
            h.set_entry_type(EntryType::Directory);
            h.set_mode(mode);
            h.set_mtime(0);
            h.set_size(0);
            tw.append_data(&mut h, format!("{name}/"), io::empty())?;
            walk(root, &child, tw)?;
        } else if ft.is_symlink() {
            let target = root.read_link_contents(&child)?;
            let mut h = Header::new_ustar();
            h.set_entry_type(EntryType::Symlink);
            h.set_mode(mode);
            h.set_mtime(0);
            h.set_size(0);
            tw.append_link(&mut h, &name, target)?;
        } else if ft.is_file() {
            let f = root.open(&child)?;
            let mut h = Header::new_ustar();
            h.set_entry_type(EntryType::Regular);
            h.set_mode(mode);
            h.set_mtime(0);
            h.set_size(meta.len());
            tw.append_data(&mut h, &name, f)?;
        }
    }
    Ok(())
}

#[cfg(unix)]
fn permissions(meta: &cap_std::fs::Metadata) -> u32 {
    use cap_std::fs::PermissionsExt;
    meta.permissions().mode() & 0o777
}

#[cfg(not(unix))]
fn permissions(meta: &cap_std::fs::Metadata) -> u32 {
    if meta.permissions().readonly() {
        0o555
    } else {
        0o755
    }
}

/// Writes a tar stream's files, directories and symlinks into `dest_dir`.
/// Entry names are contained at the root (absolute and `..` names land
/// inside it), symlinks whose target would resolve outside are refused, and
/// nothing is ever written through a symlink that points out of `dest_dir`.
pub fn extract_tar(r: impl Read, dest_dir: &Path) -> Result<()> {
    create_dir_all_mode(dest_dir, 0o700)
        .map_err(|e| BackendError::io("export: create destination root", e))?;
    let root = Dir::open_ambient_dir(dest_dir, ambient_authority())
        .map_err(|e| BackendError::io("export: open destination root", e))?;
    let mut archive = Archive::new(r);
    let entries = archive
        .entries()
        .map_err(|e| BackendError::io("export: read archive", e))?;
    for entry in entries {
        let mut entry = entry.map_err(|e| BackendError::io("export: read archive", e))?;
        let raw_name = String::from_utf8_lossy(&entry.path_bytes()).into_owned();
        let target = archive_entry_path(&raw_name);
        let mode = entry.header().mode().unwrap_or(0) & 0o777;
        let kind = entry.header().entry_type();
        let io_err = |e: io::Error| BackendError::io(format!("export: {raw_name}"), e);
        match kind {
            EntryType::Directory => {
                mkdir_all(&root, &target, mode | 0o700).map_err(io_err)?;
            }
            EntryType::Regular => {
                mkdir_all(&root, &parent(&target), 0o755).map_err(io_err)?;
                let mut opts = OpenOptions::new();
                opts.write(true).create(true).truncate(true);
                set_open_mode(&mut opts, mode | 0o600);
                let mut f = root.open_with(&target, &opts).map_err(io_err)?;
                io::copy(&mut entry, &mut f).map_err(io_err)?;
                f.flush().map_err(io_err)?;
            }
            EntryType::Symlink => {
                let link = entry
                    .link_name_bytes()
                    .map(|b| String::from_utf8_lossy(&b).into_owned())
                    .unwrap_or_default();
                if !symlink_within_archive(&target, &link) {
                    return Err(BackendError::msg(format!(
                        "export: unsafe symlink {raw_name:?} -> {link:?} in archive"
                    )));
                }
                mkdir_all(&root, &parent(&target), 0o755).map_err(io_err)?;
                match root.remove_file(&target) {
                    Ok(()) => {}
                    Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                    Err(e) => {
                        // os.Remove also removes an empty directory.
                        if root.remove_dir(&target).is_err() {
                            return Err(io_err(e));
                        }
                    }
                }
                symlink(&root, &link, &target).map_err(io_err)?;
            }
            _ => {}
        }
    }
    Ok(())
}

/// Maps an archive name to a root-relative path: prefixing `/` before
/// cleaning contains absolute names and parent traversal at the root.
fn archive_entry_path(name: &str) -> PathBuf {
    let clean = pathutil::clean(&format!("/{}", name.replace('\\', "/")));
    let clean = clean.trim_start_matches('/');
    if clean.is_empty() {
        PathBuf::from(".")
    } else {
        PathBuf::from(clean)
    }
}

/// Reports whether a link target resolves inside the archive root.
fn symlink_within_archive(entry: &Path, linkname: &str) -> bool {
    if linkname.starts_with('/') || Path::new(linkname).is_absolute() {
        return false;
    }
    let entry = entry.to_string_lossy().replace('\\', "/");
    let joined = format!("{}/{}", pathutil::dir(&entry), linkname.replace('\\', "/"));
    let resolved = pathutil::clean(&joined);
    resolved != ".." && !resolved.starts_with("../") && !resolved.starts_with('/')
}

fn parent(p: &Path) -> PathBuf {
    match p.parent() {
        Some(d) if !d.as_os_str().is_empty() => d.to_path_buf(),
        _ => PathBuf::from("."),
    }
}

fn mkdir_all(root: &Dir, p: &Path, mode: u32) -> io::Result<()> {
    if p == Path::new(".") {
        return Ok(());
    }
    let mut b = DirBuilder::new();
    b.recursive(true);
    set_dir_mode(&mut b, mode);
    root.create_dir_with(p, &b)
}

fn create_dir_all_mode(p: &Path, mode: u32) -> io::Result<()> {
    let mut b = fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(mode);
    }
    #[cfg(not(unix))]
    let _ = mode;
    b.create(p)
}

#[cfg(unix)]
fn set_dir_mode(b: &mut DirBuilder, mode: u32) {
    use cap_std::fs::DirBuilderExt;
    b.mode(mode);
}

#[cfg(not(unix))]
fn set_dir_mode(_: &mut DirBuilder, _: u32) {}

#[cfg(unix)]
fn set_open_mode(o: &mut OpenOptions, mode: u32) {
    use cap_std::fs::OpenOptionsExt;
    o.mode(mode);
}

#[cfg(not(unix))]
fn set_open_mode(_: &mut OpenOptions, _: u32) {}

#[cfg(unix)]
fn symlink(root: &Dir, original: &str, link: &Path) -> io::Result<()> {
    root.symlink(original, link)
}

#[cfg(not(unix))]
fn symlink(root: &Dir, original: &str, link: &Path) -> io::Result<()> {
    root.symlink_file(original, link)
}

/// A blocking [`Read`]/[`Write`] view of an async stream, for driving the
/// synchronous `tar` crate from a blocking thread.
pub(crate) struct SyncBridge<T> {
    handle: Handle,
    inner: T,
}

impl<T> SyncBridge<T> {
    pub(crate) fn new(handle: Handle, inner: T) -> Self {
        Self { handle, inner }
    }
}

impl<T: AsyncRead + Unpin> Read for SyncBridge<T> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        use tokio::io::AsyncReadExt;
        self.handle.block_on(self.inner.read(buf))
    }
}

impl<T: AsyncWrite + Unpin> Write for SyncBridge<T> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.handle.block_on(self.inner.write(buf))
    }

    fn flush(&mut self) -> io::Result<()> {
        self.handle.block_on(self.inner.flush())
    }
}

/// Streams a sanitized tar of `src_dir`: [`write_dir_tar`] feeds
/// [`filter_tar_safe`], whose output is readable from the returned stream.
/// The task resolves to the producer's result once the stream is finished.
pub(crate) fn seed_tar_stream(src_dir: PathBuf) -> (DuplexStream, JoinHandle<io::Result<()>>) {
    let (w, r) = tokio::io::duplex(STREAM_BUF);
    let handle = Handle::current();
    let task = tokio::task::spawn_blocking(move || {
        let (pr, pw) = io::pipe()?;
        let producer = std::thread::spawn(move || write_dir_tar(pw, &src_dir));
        let res = filter_tar_safe(SyncBridge::new(handle, w), pr);
        let produced = producer
            .join()
            .unwrap_or_else(|_| Err(io::Error::other("seed tar producer panicked")));
        res.and(produced)
    });
    (r, task)
}

/// Streams a sanitized copy of the tarball at `path`.
pub(crate) fn filtered_file_stream(path: PathBuf) -> (DuplexStream, JoinHandle<io::Result<()>>) {
    let (w, r) = tokio::io::duplex(STREAM_BUF);
    let handle = Handle::current();
    let task = tokio::task::spawn_blocking(move || {
        let f = fs::File::open(&path)?;
        filter_tar_safe(SyncBridge::new(handle, w), io::BufReader::new(f))
    });
    (r, task)
}

/// Joins a producer task, flattening panics into I/O errors.
pub(crate) async fn join_producer(task: JoinHandle<io::Result<()>>) -> io::Result<()> {
    task.await
        .unwrap_or_else(|e| Err(io::Error::other(format!("tar producer failed: {e}"))))
}

/// Copies `r` into `w` and shuts `w` down (signalling EOF).
pub(crate) async fn pump(
    mut r: impl AsyncRead + Unpin,
    mut w: impl AsyncWrite + Unpin,
) -> io::Result<u64> {
    let n = tokio::io::copy(&mut r, &mut w).await?;
    w.shutdown().await?;
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds an in-memory tar from raw headers (name, type, link, body).
    fn tarball(entries: &[(&str, EntryType, &str, &str)]) -> Vec<u8> {
        let mut b = Builder::new(Vec::new());
        for (name, kind, link, body) in entries {
            let mut h = Header::new_gnu();
            h.set_entry_type(*kind);
            h.set_mode(if *kind == EntryType::Symlink {
                0o777
            } else {
                0o644
            });
            h.set_size(body.len() as u64);
            // Write the raw name so unsafe names survive (the builder's
            // path helpers would reject them).
            raw_name(&mut h, name);
            if !link.is_empty() {
                raw_link(&mut h, link);
            }
            h.set_cksum();
            b.append(&h, body.as_bytes()).expect("append");
        }
        b.into_inner().expect("finish")
    }

    fn raw_name(h: &mut Header, name: &str) {
        let gnu = h.as_gnu_mut().expect("gnu header");
        gnu.name = [0; 100];
        gnu.name[..name.len()].copy_from_slice(name.as_bytes());
    }

    fn raw_link(h: &mut Header, link: &str) {
        let gnu = h.as_gnu_mut().expect("gnu header");
        gnu.linkname = [0; 100];
        gnu.linkname[..link.len()].copy_from_slice(link.as_bytes());
    }

    fn file(name: &str) -> (&str, EntryType, &'static str, &'static str) {
        (name, EntryType::Regular, "", "x")
    }

    #[test]
    fn entry_safety() {
        assert!(tar_entry_safe("a.txt", ""));
        assert!(tar_entry_safe("sub/../a.txt", "b"));
        assert!(!tar_entry_safe("../a", ""));
        assert!(!tar_entry_safe("/abs", ""));
        assert!(!tar_entry_safe("ok", "../../etc/passwd"));
        assert!(!tar_entry_safe("ok", "/etc/passwd"));
    }

    #[test]
    fn filter_tar_safe_accepts_and_rejects() {
        let good = tarball(&[
            file("a.txt"),
            file("sub/b.txt"),
            ("link", EntryType::Symlink, "a.txt", ""),
        ]);
        filter_tar_safe(io::sink(), good.as_slice()).expect("good archive");

        let bad: Vec<Vec<(&str, EntryType, &str, &str)>> = vec![
            vec![file("../escape.txt")],
            vec![file("/abs.txt")],
            vec![file("ok.txt"), file("a/../../evil")],
            vec![("link", EntryType::Symlink, "../../etc/passwd", "")],
        ];
        for (i, entries) in bad.iter().enumerate() {
            let data = tarball(entries);
            assert!(
                filter_tar_safe(io::sink(), data.as_slice()).is_err(),
                "case {i}"
            );
        }
    }

    #[test]
    fn filter_tar_safe_round_trips() {
        let src = tarball(&[file("keep.txt")]);
        let mut out = Vec::new();
        filter_tar_safe(&mut out, src.as_slice()).expect("filter");
        let mut ar = Archive::new(out.as_slice());
        let mut entries = ar.entries().expect("entries");
        let mut e = entries.next().expect("one entry").expect("entry");
        assert_eq!(e.path().expect("path").to_string_lossy(), "keep.txt");
        let mut body = String::new();
        e.read_to_string(&mut body).expect("body");
        assert_eq!(body.trim(), "x");
    }

    #[cfg(unix)]
    #[test]
    fn filter_tar_safe_rejects_unsafe_seed_symlink() {
        let src = tempfile::tempdir().expect("tempdir");
        std::os::unix::fs::symlink("../../etc/passwd", src.path().join("escape")).expect("symlink");
        let mut raw = Vec::new();
        write_dir_tar(&mut raw, src.path()).expect("write tar");
        let err = filter_tar_safe(io::sink(), raw.as_slice()).expect_err("must reject");
        assert!(err.to_string().contains("unsafe archive entry"), "{err}");
    }

    #[test]
    fn extract_contains_parent_traversal() {
        let base = tempfile::tempdir().expect("tempdir");
        let dest = base.path().join("out");
        let data = tarball(&[("../escape.txt", EntryType::Regular, "", "pwn")]);
        extract_tar(data.as_slice(), &dest).expect("extract");
        assert!(!base.path().join("escape.txt").exists());
        assert!(dest.join("escape.txt").exists());
    }

    #[test]
    fn extract_rejects_symlink_escape() {
        let base = tempfile::tempdir().expect("tempdir");
        let dest = base.path().join("out");
        let outside = base.path().join("outside");
        fs::create_dir_all(&outside).expect("mkdir");
        let outside_s = outside.to_string_lossy().to_string();
        let data = tarball(&[
            ("link", EntryType::Symlink, &outside_s, ""),
            ("link/loot.txt", EntryType::Regular, "", "loot"),
        ]);
        let _ = extract_tar(data.as_slice(), &dest);
        assert!(!outside.join("loot.txt").exists());
    }

    #[cfg(unix)]
    #[test]
    fn extract_rejects_preexisting_symlink_escape() {
        let base = tempfile::tempdir().expect("tempdir");
        let dest = base.path().join("out");
        let outside = base.path().join("outside");
        fs::create_dir_all(&dest).expect("mkdir");
        fs::create_dir_all(&outside).expect("mkdir");
        std::os::unix::fs::symlink(&outside, dest.join("link")).expect("symlink");
        let data = tarball(&[("link/loot.txt", EntryType::Regular, "", "loot")]);
        assert!(extract_tar(data.as_slice(), &dest).is_err());
        assert!(!outside.join("loot.txt").exists());
    }

    #[test]
    fn extract_happy_path() {
        let dest = tempfile::tempdir().expect("tempdir");
        let data = tarball(&[
            ("sub/", EntryType::Directory, "", ""),
            ("sub/a.txt", EntryType::Regular, "", "hello"),
            ("rel", EntryType::Symlink, "sub/a.txt", ""),
        ]);
        extract_tar(data.as_slice(), dest.path()).expect("extract");
        let got = fs::read_to_string(dest.path().join("sub/a.txt")).expect("read");
        assert_eq!(got, "hello");
        let via_link = fs::read_to_string(dest.path().join("rel")).expect("read link");
        assert_eq!(via_link, "hello");
    }

    #[test]
    fn symlink_containment() {
        assert!(symlink_within_archive(Path::new("rel"), "sub/a.txt"));
        assert!(symlink_within_archive(Path::new("sub/l"), "../a.txt"));
        assert!(!symlink_within_archive(Path::new("sub/l"), "../../a.txt"));
        assert!(!symlink_within_archive(Path::new("l"), "/etc/passwd"));
        assert_eq!(archive_entry_path("../x"), PathBuf::from("x"));
        assert_eq!(archive_entry_path("/abs/y"), PathBuf::from("abs/y"));
        assert_eq!(archive_entry_path("./"), PathBuf::from("."));
    }

    #[test]
    fn snapshot_verification() {
        let dir = tempfile::tempdir().expect("tempdir");
        let loc = dir.path().join("s.tar");
        fs::write(&loc, b"data").expect("write");
        let sum = hash_file(&loc).expect("hash");
        let mut r = SnapshotRef {
            id: "i".into(),
            name: "n".into(),
            profile: String::new(),
            backend: "docker".into(),
            location: loc.to_string_lossy().into(),
            sha256: sum,
            created: crate::types::go_zero_time(),
        };
        verify_snapshot(&r).expect("matches");
        fs::write(&loc, b"tampered").expect("write");
        assert!(verify_snapshot(&r).is_err());
        r.sha256.clear();
        verify_snapshot(&r).expect("no digest is accepted");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn seed_stream_produces_sanitized_tar() {
        let src = tempfile::tempdir().expect("tempdir");
        fs::write(src.path().join("a.txt"), "alpha").expect("write");
        fs::create_dir(src.path().join("d")).expect("mkdir");
        fs::write(src.path().join("d/b.txt"), "bravo").expect("write");
        let (r, task) = seed_tar_stream(src.path().to_path_buf());
        let mut buf = Vec::new();
        pump(r, &mut buf).await.expect("pump");
        join_producer(task).await.expect("producer");
        let names: Vec<String> = Archive::new(buf.as_slice())
            .entries()
            .expect("entries")
            .map(|e| {
                e.expect("entry")
                    .path()
                    .expect("path")
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        assert_eq!(names, ["a.txt", "d/", "d/b.txt"]);
    }
}
