//! Append-only audit ledger stored as JSON Lines.
//!
//! Each record embeds the SHA-256 hash of the previous record, so any edit,
//! insertion or reorder breaks the chain and is caught by
//! [`Ledger::verify`]. Records can be signed with ed25519 and exported as
//! self-contained [`Bundle`]s, and [`evidence`] documents pair a bundle with
//! the policy that governed the run.
//!
//! The on-disk and export formats are byte-compatible with the Go
//! implementation: the same events produce the same lines, hashes and
//! signatures, so ledgers written by either build verify with the other.

mod error;
pub mod evidence;
pub mod gojson;
pub mod gotime;
mod ledger;
mod scrub;
mod sign;

#[cfg(test)]
mod golden_tests;

pub use error::{BundleProblem, LedgerError};
pub use ledger::{Event, Ledger, redact};
pub use scrub::{REDACT_MASK, Scrubber, scrub, scrub_string};
pub use sign::{Bundle, KEY_FILE_NAME, PUB_FILE_NAME, Signer, decode_public_key, verify_bundle};
