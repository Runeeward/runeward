//! Records governed terminal sessions as asciinema v2 "cast" files and
//! replays them. Rust port of the Go `internal/termrec` package.
//!
//! A cast file is one JSON header line followed by one JSON array per output
//! frame: `[elapsedSeconds, "o", "data"]`. For the same input and clock the
//! [`Recorder`] writes byte-identical output to the Go recorder, including
//! Go's number formatting (`1`, `0.5`, `1e-9`), its HTML-safe string escapes
//! and its per-byte replacement of invalid UTF-8.

mod encode;
mod player;
mod recorder;

pub use player::{MAX_GAP, ReplayError, replay, replay_with_sleep};
pub use recorder::{Clock, Header, Recorder};
