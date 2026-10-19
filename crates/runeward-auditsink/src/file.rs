//! A sink that appends each event as one JSON line to a local file.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use runeward_ledger::Event;

use crate::queue::lock;
use crate::{Error, Sink};

/// Appends each event as one JSON line. Local disk writes are fast, so they
/// happen synchronously under a mutex; `emit` still never fails the caller
/// (write errors are logged once, not returned).
#[derive(Debug)]
pub struct FileSink {
    path: PathBuf,
    state: Mutex<FileState>,
}

#[derive(Debug)]
struct FileState {
    file: Option<File>,
    /// Avoids spamming identical write errors.
    logged_err: bool,
}

impl FileSink {
    /// Opens (creating if needed) the JSON Lines file at `path` for
    /// appending, with mode 0o600 on Unix.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, Error> {
        let path = path.as_ref();
        let mut opts = OpenOptions::new();
        opts.append(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let file = opts.open(path).map_err(|source| Error::OpenFile {
            path: path.display().to_string(),
            source,
        })?;
        Ok(Self {
            path: path.to_path_buf(),
            state: Mutex::new(FileState {
                file: Some(file),
                logged_err: false,
            }),
        })
    }
}

impl Sink for FileSink {
    fn emit(&self, ev: &Event) {
        let mut line = match ev.to_json() {
            Ok(l) => l,
            Err(err) => {
                tracing::warn!(%err, seq = ev.seq, "auditsink: marshal event failed");
                return;
            }
        };
        line.push(b'\n');

        let mut st = lock(&self.state);
        let Some(f) = st.file.as_mut() else {
            return;
        };
        if let Err(err) = f.write_all(&line)
            && !st.logged_err
        {
            tracing::warn!(path = %self.path.display(), %err, "auditsink: write to audit file failed");
            st.logged_err = true;
        }
    }

    fn close(&self) -> Result<(), Error> {
        // Writes are unbuffered, so dropping the handle is the whole close.
        drop(lock(&self.state).file.take());
        Ok(())
    }

    fn kind(&self) -> &'static str {
        "file"
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::io::BufRead;

    use super::*;
    use crate::testutil::sample_event;

    #[test]
    fn file_sink_appends_json_lines() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");

        let s = FileSink::open(&path).unwrap();
        let ev1 = sample_event();
        let mut ev2 = sample_event();
        ev2.seq = 8;
        ev2.session_id = "sess-def".into();
        s.emit(&ev1);
        s.emit(&ev2);
        s.close().unwrap();
        // A second close and an emit after close are harmless.
        s.close().unwrap();
        s.emit(&ev1);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "file mode = {mode:o}, want 600");
        }

        let f = File::open(&path).unwrap();
        let lines: Vec<String> = std::io::BufReader::new(f)
            .lines()
            .map(Result::unwrap)
            .collect();
        assert_eq!(lines.len(), 2);

        let events: Vec<Event> = lines
            .iter()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(events[0].seq, 7);
        assert_eq!(events[1].seq, 8);
        assert_eq!(events[1].session_id, "sess-def");

        // The line is the ledger's Go-compatible encoding, byte for byte.
        assert_eq!(lines[0].as_bytes(), ev1.to_json().unwrap().as_slice());
        assert_eq!(
            lines[0],
            r#"{"seq":7,"time":"2026-07-04T17:00:00Z","session_id":"sess-abc","sandbox":"sbx-1","profile":"default","tool":"shell","action":"rm -rf /tmp/x","args":["-rf","/tmp/x"],"verdict":"allow","exit_code":0,"duration_ms":0,"redacted":false,"prev_hash":"","hash":"deadbeef"}"#
        );
    }

    #[test]
    fn file_sink_appends_to_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        std::fs::write(&path, "existing\n").unwrap();
        let s = FileSink::open(&path).unwrap();
        s.emit(&sample_event());
        s.close().unwrap();
        let body = std::fs::read_to_string(&path).unwrap();
        assert!(body.starts_with("existing\n{\"seq\":7"));
    }

    #[test]
    fn file_sink_open_error() {
        let dir = tempfile::tempdir().unwrap();
        let err = FileSink::open(dir.path().join("missing").join("audit.jsonl")).unwrap_err();
        assert!(matches!(err, Error::OpenFile { .. }));
    }
}
