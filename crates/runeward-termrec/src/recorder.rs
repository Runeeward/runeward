//! The asciinema v2 recorder.

use std::collections::BTreeMap;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use chrono::{DateTime, Utc};
use runeward_ledger::gojson;
use serde::{Deserialize, Deserializer, Serialize};

use crate::encode::{go_float, go_json_string};

/// Go's `bufio.NewWriter` default size; keeps flush points identical.
const BUF_SIZE: usize = 4096;

/// The clock that stamps the header and frames. The default is
/// [`Utc::now`]; tests inject a fixed sequence.
pub type Clock = Box<dyn FnMut() -> DateTime<Utc> + Send>;

/// The first line of an asciinema v2 cast file.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Header {
    /// Always 2.
    #[serde(default, deserialize_with = "nullable")]
    pub version: i64,
    /// Terminal columns.
    #[serde(default, deserialize_with = "nullable")]
    pub width: i64,
    /// Terminal rows.
    #[serde(default, deserialize_with = "nullable")]
    pub height: i64,
    /// Recording start, Unix seconds.
    #[serde(default, deserialize_with = "nullable")]
    pub timestamp: i64,
    /// Captured environment; omitted when empty.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env: Option<BTreeMap<String, String>>,
}

fn nullable<'de, D: Deserializer<'de>>(d: D) -> Result<i64, D::Error> {
    Ok(Option::<i64>::deserialize(d)?.unwrap_or_default())
}

struct State<W: Write> {
    bw: BufWriter<W>,
    /// The first write error; like Go's `bufio.Writer`, every later write and
    /// the final flush fail with it.
    broken: Option<(io::ErrorKind, String)>,
    width: i64,
    height: i64,
    start: Option<DateTime<Utc>>,
    now: Clock,
}

impl<W: Write> State<W> {
    fn put(&mut self, data: &[u8]) -> io::Result<()> {
        if let Some((kind, msg)) = &self.broken {
            return Err(io::Error::new(*kind, msg.clone()));
        }
        self.bw.write_all(data).inspect_err(|e| {
            self.broken = Some((e.kind(), e.to_string()));
        })
    }

    /// Writes the header exactly once, anchoring the recording clock.
    fn start(&mut self) -> io::Result<DateTime<Utc>> {
        if let Some(start) = self.start {
            return Ok(start);
        }
        let start = (self.now)();
        self.start = Some(start);
        let header = Header {
            version: 2,
            width: self.width,
            height: self.height,
            timestamp: start.timestamp(),
            env: Some(BTreeMap::from([(
                "TERM".to_owned(),
                "xterm-256color".to_owned(),
            )])),
        };
        let mut line = gojson::marshal(&header).map_err(io::Error::other)?;
        line.push(b'\n');
        self.put(&line)?;
        Ok(start)
    }

    fn frame(&mut self, p: &[u8]) -> io::Result<()> {
        let start = self.start()?;
        let elapsed = seconds((self.now)() - start).max(0.0);
        let data = go_json_string(p).map_err(io::Error::other)?;
        let mut line = Vec::with_capacity(data.len() + 32);
        line.push(b'[');
        line.extend_from_slice(go_float(elapsed).as_bytes());
        line.extend_from_slice(b",\"o\",");
        line.extend_from_slice(&data);
        line.extend_from_slice(b"]\n");
        self.put(&line)
    }

    fn flush(&mut self) -> io::Result<()> {
        if let Some((kind, msg)) = &self.broken {
            return Err(io::Error::new(*kind, msg.clone()));
        }
        self.bw.flush().inspect_err(|e| {
            self.broken = Some((e.kind(), e.to_string()));
        })
    }
}

/// Go's `Duration.Seconds()` for a nanosecond count (saturating like Go's
/// `Time.Sub`).
fn seconds(d: chrono::TimeDelta) -> f64 {
    let ns = d
        .num_nanoseconds()
        .unwrap_or(if d < chrono::TimeDelta::zero() {
            i64::MIN
        } else {
            i64::MAX
        });
    let sec = ns / 1_000_000_000;
    let nsec = ns % 1_000_000_000;
    sec as f64 + nsec as f64 / 1e9
}

/// Captures every write as an asciinema v2 output frame. Safe for concurrent
/// use: `&Recorder` implements [`Write`] too.
///
/// A recorder is meant to sit in a tee beside the real terminal stream, so
/// writes always report the full length and never fail, even when encoding
/// or the underlying writer fails; a recording problem can never stall or
/// corrupt the session. [`close`](Self::close) reports such failures.
pub struct Recorder<W: Write> {
    state: Mutex<State<W>>,
}

impl<W: Write> fmt::Debug for Recorder<W> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = self.lock();
        f.debug_struct("Recorder")
            .field("width", &s.width)
            .field("height", &s.height)
            .field("started", &s.start.is_some())
            .finish_non_exhaustive()
    }
}

impl<W: Write> Recorder<W> {
    /// Wraps `w` and records writes with the given terminal size.
    pub fn new(w: W, width: i64, height: i64) -> Self {
        Self {
            state: Mutex::new(State {
                bw: BufWriter::with_capacity(BUF_SIZE, w),
                broken: None,
                width,
                height,
                start: None,
                now: Box::new(Utc::now),
            }),
        }
    }

    /// Replaces the clock used for the header timestamp and frame offsets.
    pub fn with_clock(self, clock: Clock) -> Self {
        self.lock().now = clock;
        self
    }

    fn lock(&self) -> MutexGuard<'_, State<W>> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Writes the cast header if it has not been written yet, anchoring the
    /// recording clock. Only the first call has an effect; writes start the
    /// recording implicitly.
    pub fn start(&self) -> io::Result<()> {
        self.lock().start().map(drop)
    }

    /// Records `p` as one output frame and returns `p.len()`; failures are
    /// swallowed (see the type docs).
    pub fn record(&self, p: &[u8]) -> usize {
        let _ = self.lock().frame(p);
        p.len()
    }

    /// Writes the header if no frame was recorded (so an empty session is
    /// still a valid cast) and flushes buffered frames.
    pub fn close(&self) -> io::Result<()> {
        let mut s = self.lock();
        s.start()?;
        s.flush()
    }

    /// Closes the recording and returns the underlying writer.
    pub fn finish(self) -> io::Result<W> {
        self.close()?;
        let state = self.state.into_inner().unwrap_or_else(|e| e.into_inner());
        state.bw.into_inner().map_err(|e| e.into_error())
    }
}

impl Recorder<File> {
    /// Creates (truncating) the cast file at `path`, with 0600 permissions
    /// on Unix. The file closes when the recorder is dropped or finished.
    pub fn create(path: impl AsRef<Path>, width: i64, height: i64) -> io::Result<Self> {
        let mut opts = OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        Ok(Self::new(opts.open(path)?, width, height))
    }
}

impl<W: Write> Write for &Recorder<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        Ok(self.record(buf))
    }

    /// Flushes buffered frames, swallowing errors like writes do.
    fn flush(&mut self) -> io::Result<()> {
        let _ = self.lock().flush();
        Ok(())
    }
}

impl<W: Write> Write for Recorder<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        Ok(self.record(buf))
    }

    fn flush(&mut self) -> io::Result<()> {
        (&*self).flush()
    }
}
