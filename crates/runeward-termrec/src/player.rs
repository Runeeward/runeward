//! Cast file playback.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::thread;
use std::time::Duration;

use serde_json::value::RawValue;

use crate::recorder::Header;

/// The longest pause [`replay`] sleeps between two frames in real time, so
/// idle stretches of a session do not stall playback.
pub const MAX_GAP: Duration = Duration::from_secs(2);

/// The longest line the player accepts, as Go's scanner buffer limit.
const MAX_LINE: usize = 16 * 1024 * 1024;

/// A cast that could not be replayed. Messages match the Go player.
#[derive(Debug, thiserror::Error)]
pub enum ReplayError {
    /// The first non-empty line is not a valid header.
    #[error("termrec: invalid cast header: {0}")]
    InvalidHeader(serde_json::Error),
    /// The header names a version other than 2.
    #[error("termrec: unsupported cast version {0}")]
    UnsupportedVersion(i64),
    /// The input has no non-empty line.
    #[error("termrec: empty cast: missing header")]
    MissingHeader,
    /// A frame line is not a JSON array.
    #[error("termrec: invalid frame: {0}")]
    InvalidFrame(serde_json::Error),
    /// A frame's first element is not a number.
    #[error("termrec: invalid frame timestamp: {0}")]
    InvalidTimestamp(serde_json::Error),
    /// A frame's second element is not a string.
    #[error("termrec: invalid frame type: {0}")]
    InvalidType(serde_json::Error),
    /// An output frame's data is not a string.
    #[error("termrec: invalid frame data: {0}")]
    InvalidData(serde_json::Error),
    /// A line exceeds 16 MiB.
    #[error("bufio.Scanner: token too long")]
    LineTooLong,
    /// Reading the cast or writing the output failed.
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// Parses a cast from `r` and writes its output frames to `w`. With
/// `realtime`, it sleeps between frames to honor their timestamps (each gap
/// capped at [`MAX_GAP`]); otherwise frames are written back to back.
///
/// The header is validated as asciinema v2. Only `"o"` (output) frames are
/// replayed; frames that are not three elements long, input frames and
/// other event types are skipped.
pub fn replay<R: Read, W: Write>(r: R, w: W, realtime: bool) -> Result<(), ReplayError> {
    if realtime {
        replay_with_sleep(r, w, Some(&mut thread::sleep))
    } else {
        replay_with_sleep(r, w, None)
    }
}

/// [`replay`] with an injectable sleep; `None` disables pacing.
pub fn replay_with_sleep<R: Read, W: Write>(
    r: R,
    mut w: W,
    mut sleep: Option<&mut dyn FnMut(Duration)>,
) -> Result<(), ReplayError> {
    let mut lines = Lines {
        r: BufReader::with_capacity(64 * 1024, r),
        buf: Vec::new(),
    };

    let mut have_header = false;
    while let Some(line) = lines.next_line()? {
        if line.is_empty() {
            continue;
        }
        let header = decode_header(line)?;
        if header.version != 2 {
            return Err(ReplayError::UnsupportedVersion(header.version));
        }
        have_header = true;
        break;
    }
    if !have_header {
        return Err(ReplayError::MissingHeader);
    }

    let mut last = 0.0f64;
    while let Some(line) = lines.next_line()? {
        if line.is_empty() {
            continue;
        }
        // null decodes to an empty frame in Go, which is skipped.
        let frame: Option<Vec<&RawValue>> =
            serde_json::from_slice(line).map_err(ReplayError::InvalidFrame)?;
        let Some([t, kind, data]) = frame.as_deref() else {
            continue;
        };
        // A null element leaves Go's zero value in place.
        let t = serde_json::from_str::<Option<f64>>(t.get())
            .map_err(ReplayError::InvalidTimestamp)?
            .unwrap_or_default();
        let kind = serde_json::from_str::<Option<String>>(kind.get())
            .map_err(ReplayError::InvalidType)?
            .unwrap_or_default();
        if kind != "o" {
            continue;
        }
        let data = serde_json::from_str::<Option<String>>(data.get())
            .map_err(ReplayError::InvalidData)?
            .unwrap_or_default();

        if let Some(sleep) = sleep.as_deref_mut() {
            let gap = (t - last) * 1e9;
            if gap >= MAX_GAP.as_nanos() as f64 {
                sleep(MAX_GAP);
            } else if gap >= 1.0 {
                // Go converts to an integer Duration, truncating.
                sleep(Duration::from_nanos(gap as u64));
            }
        }
        last = t;

        w.write_all(data.as_bytes())?;
    }
    Ok(())
}

/// Decodes the header like Go's `json.Unmarshal` into the header struct,
/// which requires a JSON object (or null).
fn decode_header(line: &[u8]) -> Result<Header, ReplayError> {
    let v: serde_json::Value = serde_json::from_slice(line).map_err(ReplayError::InvalidHeader)?;
    if !(v.is_object() || v.is_null()) {
        let err = <serde_json::Error as serde::de::Error>::custom(format!(
            "cannot unmarshal {} into Go value of type termrec.header",
            json_kind(&v)
        ));
        return Err(ReplayError::InvalidHeader(err));
    }
    if v.is_null() {
        return Ok(Header::default());
    }
    serde_json::from_value(v).map_err(ReplayError::InvalidHeader)
}

fn json_kind(v: &serde_json::Value) -> &'static str {
    match v {
        serde_json::Value::Array(_) => "array",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::Bool(_) => "bool",
        serde_json::Value::Object(_) => "object",
        serde_json::Value::Null => "null",
    }
}

/// Splits input like Go's `bufio.ScanLines`: on `\n`, dropping one trailing
/// `\r`, with a final unterminated line included.
struct Lines<R> {
    r: BufReader<R>,
    buf: Vec<u8>,
}

impl<R: Read> Lines<R> {
    fn next_line(&mut self) -> Result<Option<&[u8]>, ReplayError> {
        self.buf.clear();
        loop {
            let chunk = self.r.fill_buf()?;
            if chunk.is_empty() {
                if self.buf.is_empty() {
                    return Ok(None);
                }
                break;
            }
            if let Some(i) = chunk.iter().position(|&b| b == b'\n') {
                if self.buf.len() + i > MAX_LINE {
                    return Err(ReplayError::LineTooLong);
                }
                self.buf.extend_from_slice(&chunk[..i]);
                self.r.consume(i + 1);
                break;
            }
            let n = chunk.len();
            if self.buf.len() + n > MAX_LINE {
                return Err(ReplayError::LineTooLong);
            }
            self.buf.extend_from_slice(chunk);
            self.r.consume(n);
        }
        if self.buf.last() == Some(&b'\r') {
            self.buf.pop();
        }
        Ok(Some(&self.buf))
    }
}
