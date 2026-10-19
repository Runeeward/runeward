//! Durable state files: atomic, private replacement of JSON documents in the
//! state directory, plus Go-compatible JSON encoding.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use serde::Serialize;

use crate::error::{Error, Result};

/// The state directory and the lock serializing every replacement in it, so
/// concurrent Cohort, snapshot, run and agent-session updates cannot trample
/// one another. Without a directory nothing is persisted.
#[derive(Debug, Default)]
pub(crate) struct StateDir {
    dir: Option<PathBuf>,
    lock: Mutex<()>,
}

impl StateDir {
    pub(crate) fn new(dir: Option<PathBuf>) -> Arc<Self> {
        Arc::new(Self {
            dir: dir.filter(|d| !d.as_os_str().is_empty()),
            lock: Mutex::new(()),
        })
    }

    pub(crate) fn dir(&self) -> Option<&Path> {
        self.dir.as_deref()
    }

    pub(crate) fn path(&self, name: &str) -> Option<PathBuf> {
        self.dir.as_ref().map(|d| d.join(name))
    }

    /// Reads `name`; a missing file (or no state dir) is `None`.
    pub(crate) fn read(&self, name: &str) -> io::Result<Option<Vec<u8>>> {
        let Some(path) = self.path(name) else {
            return Ok(None);
        };
        match fs::read(path) {
            Ok(b) => Ok(Some(b)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Reads `<sub>/<name>`; a missing file (or no state dir) is `None`.
    pub(crate) fn read_in(&self, sub: &str, name: &str) -> io::Result<Option<Vec<u8>>> {
        let Some(dir) = &self.dir else {
            return Ok(None);
        };
        match fs::read(dir.join(sub).join(name)) {
            Ok(b) => Ok(Some(b)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Removes `<sub>/<name>` if it exists.
    pub(crate) fn remove_in(&self, sub: &str, name: &str) -> io::Result<()> {
        let Some(dir) = &self.dir else {
            return Ok(());
        };
        match fs::remove_file(dir.join(sub).join(name)) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        }
    }

    /// [`StateDir::write`] into the private subdirectory `sub`.
    pub(crate) fn write_in(&self, sub: &str, name: &str, data: &[u8]) -> Result<()> {
        let Some(dir) = &self.dir else {
            return Ok(());
        };
        self.write_at(&dir.join(sub), name, data)
    }

    /// Replaces `name` atomically: a unique 0600 temporary file in the state
    /// directory is written, fsynced and renamed over the target, then the
    /// directory is fsynced. A no-op without a state directory.
    pub(crate) fn write(&self, name: &str, data: &[u8]) -> Result<()> {
        let Some(dir) = &self.dir else {
            return Ok(());
        };
        self.write_at(dir, name, data)
    }

    fn write_at(&self, dir: &Path, name: &str, data: &[u8]) -> Result<()> {
        let _guard = self
            .lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        create_private_dir(dir)
            .map_err(|e| Error::other(format!("create state directory: {e}")))?;
        let mut tmp = tempfile::Builder::new()
            .prefix(&format!(".{name}.tmp-"))
            .tempfile_in(dir)
            .map_err(|e| Error::other(format!("create temporary state file: {e}")))?;
        set_private(tmp.as_file())
            .map_err(|e| Error::other(format!("protect temporary state file: {e}")))?;
        tmp.write_all(data)
            .map_err(|e| Error::other(format!("write temporary state file: {e}")))?;
        tmp.as_file()
            .sync_all()
            .map_err(|e| Error::other(format!("sync temporary state file: {e}")))?;
        tmp.persist(dir.join(name))
            .map_err(|e| Error::other(format!("replace state file: {}", e.error)))?;
        if let Ok(d) = fs::File::open(dir) {
            let _ = d.sync_all();
        }
        Ok(())
    }
}

/// Encodes `v` like Go's `json.MarshalIndent(v, "", "  ")`: two-space
/// indent, Go's HTML-safe string escaping, no trailing newline.
pub(crate) fn marshal_indent<T: Serialize + ?Sized>(v: &T) -> Result<Vec<u8>> {
    let mut out = runeward_ledger::gojson::marshal_indent(v).map_err(Error::other)?;
    if out.last() == Some(&b'\n') {
        out.pop();
    }
    Ok(out)
}

pub(crate) fn create_private_dir(dir: &Path) -> io::Result<()> {
    let mut b = fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
    }
    b.create(dir)
}

#[cfg(unix)]
fn set_private(f: &fs::File) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    f.set_permissions(fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn set_private(_: &fs::File) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_atomically_and_privately() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sd = StateDir::new(Some(dir.path().join("state")));
        sd.write("x.json", b"[]").expect("write");
        sd.write("x.json", b"[1]").expect("rewrite");
        assert_eq!(
            sd.read("x.json").expect("read").as_deref(),
            Some(&b"[1]"[..])
        );
        assert_eq!(sd.read("missing.json").expect("read"), None);
        let names: Vec<_> = fs::read_dir(dir.path().join("state"))
            .expect("ls")
            .map(|e| e.expect("entry").file_name())
            .collect();
        assert_eq!(names, ["x.json"], "no temporary files left behind");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |p: &Path| fs::metadata(p).expect("stat").permissions().mode() & 0o777;
            assert_eq!(mode(&dir.path().join("state/x.json")), 0o600);
            assert_eq!(mode(&dir.path().join("state")), 0o700);
        }
        let none = StateDir::new(None);
        none.write("x.json", b"[]").expect("no-op");
        assert_eq!(none.read("x.json").expect("read"), None);
    }

    #[test]
    fn marshal_indent_matches_go() {
        #[derive(Serialize)]
        struct S<'a> {
            a: &'a str,
            b: Vec<i64>,
        }
        let got = marshal_indent(&[S {
            a: "<&>",
            b: vec![],
        }])
        .expect("encode");
        assert_eq!(
            String::from_utf8(got).expect("utf8"),
            "[\n  {\n    \"a\": \"\\u003c\\u0026\\u003e\",\n    \"b\": []\n  }\n]"
        );
        assert_eq!(marshal_indent(&Vec::<i64>::new()).expect("encode"), b"[]");
    }
}
