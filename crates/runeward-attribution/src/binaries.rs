//! The Charter's binaries, pinned by file identity when the sandbox starts.
//!
//! Each listed path is resolved (following symlinks) to the file it names,
//! and that file's device and inode are recorded. A running process matches
//! a listed binary when its executable (`/proc/<pid>/exe`) is the same file.
//! So:
//!
//! - a listed symlink matches its target (`/usr/bin/python3` matches a
//!   process running `/usr/bin/python3.11`), and a hard link matches too;
//! - a copy of an allowed binary under another path does not match;
//! - a file put at a listed path after the snapshot (a replaced binary) does
//!   not match, because it is a different inode;
//! - a listed path that does not exist at snapshot time never matches and is
//!   reported as missing.

use std::collections::BTreeMap;
use std::fs::Metadata;
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;

/// File identity: device and inode.
pub type FileId = (u64, u64);

/// The pinned binaries. See the module docs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BinarySet {
    by_id: BTreeMap<FileId, Vec<String>>,
    missing: Vec<String>,
}

impl BinarySet {
    /// Resolves every path in `paths` now. Relative paths, paths that do not
    /// exist and paths that are not regular files are recorded as missing.
    pub fn snapshot<S: AsRef<str>>(paths: &[S]) -> Self {
        let mut out = Self::default();
        for p in paths {
            let p = p.as_ref();
            let md = Path::new(p)
                .is_absolute()
                .then(|| std::fs::metadata(p).ok())
                .flatten()
                .filter(Metadata::is_file);
            match md {
                Some(md) => {
                    let v = out.by_id.entry(id(&md)).or_default();
                    if !v.iter().any(|x| x == p) {
                        v.push(p.to_owned());
                    }
                }
                None => {
                    if !out.missing.iter().any(|x| x == p) {
                        out.missing.push(p.to_owned());
                    }
                }
            }
        }
        out
    }

    /// The listed paths that are the same file as `md`.
    pub fn matches(&self, md: &Metadata) -> Vec<String> {
        self.by_id.get(&id(md)).cloned().unwrap_or_default()
    }

    /// Listed paths that resolved to a file.
    pub fn pinned(&self) -> Vec<String> {
        let mut v: Vec<String> = self.by_id.values().flatten().cloned().collect();
        v.sort();
        v
    }

    /// Listed paths that did not resolve to a regular file.
    pub fn missing(&self) -> &[String] {
        &self.missing
    }
}

/// The identity of the file `md` describes.
pub fn id(md: &Metadata) -> FileId {
    (md.dev(), md.ino())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn file(dir: &Path, name: &str, body: &str) -> String {
        let p = dir.join(name);
        std::fs::write(&p, body).expect("write");
        p.display().to_string()
    }

    #[test]
    fn symlinks_and_hard_links_match_their_file() {
        let dir = tempfile::tempdir().expect("tmp");
        let real = file(dir.path(), "python3.11", "interp");
        let link = dir.path().join("python3");
        symlink(&real, &link).expect("symlink");
        let link = link.display().to_string();
        let hard = dir.path().join("python-hard");
        std::fs::hard_link(&real, &hard).expect("hard link");

        // Only the symlink is listed; the process runs the real file.
        let set = BinarySet::snapshot(std::slice::from_ref(&link));
        let md = std::fs::metadata(&real).expect("md");
        assert_eq!(set.matches(&md), vec![link.clone()]);
        // A hard link is the same file.
        assert_eq!(
            set.matches(&std::fs::metadata(&hard).expect("md")),
            vec![link.clone()]
        );
        assert_eq!(set.pinned(), vec![link.clone()]);

        // Listing both names of one file reports both.
        let set = BinarySet::snapshot(&[link.clone(), real.clone(), real.clone()]);
        let mut got = set.matches(&md);
        got.sort();
        let mut want = vec![link, real];
        want.sort();
        assert_eq!(got, want);
    }

    #[test]
    fn copies_and_replacements_do_not_match() {
        let dir = tempfile::tempdir().expect("tmp");
        let curl = file(dir.path(), "curl", "the real curl");
        let set = BinarySet::snapshot(std::slice::from_ref(&curl));

        // A byte-identical copy elsewhere is a different file.
        let copy = file(dir.path(), "copy-of-curl", "the real curl");
        assert!(
            set.matches(&std::fs::metadata(&copy).expect("md"))
                .is_empty()
        );

        // Replacing the listed path after the snapshot does not carry the
        // permission over to the new file.
        let staged = file(dir.path(), "evil", "something else");
        std::fs::rename(&staged, &curl).expect("replace");
        assert!(
            set.matches(&std::fs::metadata(&curl).expect("md"))
                .is_empty()
        );
    }

    #[test]
    fn missing_relative_and_non_files_are_reported() {
        let dir = tempfile::tempdir().expect("tmp");
        let gone = dir.path().join("gone").display().to_string();
        let dir_path = dir.path().display().to_string();
        let set = BinarySet::snapshot(&[gone.clone(), "curl".into(), dir_path.clone()]);
        assert_eq!(set.missing(), [gone, "curl".into(), dir_path]);
        assert!(set.pinned().is_empty());
        let md = std::fs::metadata(dir.path()).expect("md");
        assert!(set.matches(&md).is_empty());
    }
}
