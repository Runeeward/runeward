//! Ledger errors. Messages follow the Go implementation so operators see the
//! same diagnostics from either build.

use std::io;
use std::path::PathBuf;

/// Everything that can go wrong opening, writing or verifying a ledger.
#[derive(Debug, thiserror::Error)]
pub enum LedgerError {
    #[error("ledger: open {path:?}: {source}")]
    Open { path: PathBuf, source: io::Error },

    #[error(
        "ledger: {path:?} is already in use by another runeward process (only one writer per ledger; set a distinct $RUNEWARD_STATE_DIR): {source}"
    )]
    Locked { path: PathBuf, source: io::Error },

    #[error("ledger: append on closed ledger")]
    Closed,

    #[error("ledger: marshal seq {seq}: {source}")]
    Marshal { seq: i64, source: serde_json::Error },

    #[error("ledger: write seq {seq}: {source}")]
    Write { seq: i64, source: io::Error },

    #[error("ledger: sync seq {seq}: {source}")]
    Sync { seq: i64, source: io::Error },

    #[error("ledger: read {path:?}: {source}")]
    Read { path: PathBuf, source: io::Error },

    #[error("ledger: parse {path:?} line {line}: {source}")]
    Parse {
        path: PathBuf,
        line: usize,
        source: serde_json::Error,
    },

    #[error("ledger: record {index}: out-of-order seq {seq} (expected {index})")]
    OutOfOrder { index: usize, seq: i64 },

    #[error(
        "ledger: record seq {seq}: broken chain, prev_hash {prev_hash:?} does not link to previous hash {expected:?}"
    )]
    BrokenChain {
        seq: i64,
        prev_hash: String,
        expected: String,
    },

    #[error(
        "ledger: record seq {seq}: tampered, stored hash {stored:?} != recomputed {recomputed:?}"
    )]
    Tampered {
        seq: i64,
        stored: String,
        recomputed: String,
    },

    #[error("ledger: signatures required but no public key provided")]
    SignaturesRequired,

    #[error("ledger: record seq {seq}: missing signature")]
    MissingSignature { seq: i64 },

    #[error("ledger: record seq {seq}: bad signature encoding: {source}")]
    SignatureEncoding {
        seq: i64,
        source: base64::DecodeError,
    },

    #[error("ledger: record seq {seq}: signature does not verify")]
    BadSignature { seq: i64 },

    #[error("ledger: export: {0}")]
    Export(io::Error),

    #[error("ledger: export bundle: {0}")]
    ExportBundle(io::Error),

    #[error("ledger: signer dir: {0}")]
    SignerDir(io::Error),

    #[error("ledger: read signing key: {0}")]
    ReadKey(io::Error),

    #[error("ledger: signing key {path:?} has wrong size {size}")]
    KeySize { path: PathBuf, size: usize },

    #[error("ledger: signing key {path:?}: {source}")]
    InvalidKey {
        path: PathBuf,
        source: runeward_keys::KeyError,
    },

    #[error("ledger: write signing key: {0}")]
    WriteKey(io::Error),

    #[error("ledger: write public key: {0}")]
    WritePublicKey(io::Error),

    #[error("ledger: decode public key: {0}")]
    DecodePublicKey(base64::DecodeError),

    #[error("ledger: public key wrong size {0}")]
    PublicKeySize(usize),

    #[error("ledger: public key: {0}")]
    InvalidPublicKey(runeward_keys::KeyError),

    #[error("ledger: decode bundle: {0}")]
    DecodeBundle(serde_json::Error),

    #[error("ledger: bundle key_id {declared:?} does not match public key ({actual:?})")]
    BundleKeyId { declared: String, actual: String },

    #[error("ledger: bundle event {index} (seq {seq}): {problem}")]
    BundleEvent {
        index: usize,
        seq: i64,
        problem: BundleProblem,
    },

    #[error("ledger: bundle event {index}: bad signature encoding: {source}")]
    BundleSignatureEncoding {
        index: usize,
        source: base64::DecodeError,
    },
}

/// Why a bundle event failed verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum BundleProblem {
    #[error("hash mismatch")]
    HashMismatch,
    #[error("events are not in sequence order")]
    OutOfOrder,
    #[error("broken chain")]
    BrokenChain,
    #[error("event is outside declared session scope")]
    OutsideScope,
    #[error("missing signature")]
    MissingSignature,
    #[error("signature does not verify")]
    BadSignature,
}
