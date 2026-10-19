//! Cohort task board: an in-memory FIFO queue of tasks that the agents of a
//! Cohort pull from, plus the signed, short-lived lease tokens that prove a
//! worker currently holds a claim.
//!
//! This is the Rust port of the Go `internal/fleet` package and of the lease
//! token half of `internal/controlplane/leasetoken.go`.
//!
//! * [`Board`] serves claims first-in-first-out under a single mutex, so a
//!   task is held by at most one worker at a time. Leases expire unless the
//!   holder heartbeats; [`Board::sweep`] returns expired claims to the pending
//!   pool. Every claim and heartbeat rotates [`Task::lease_version`], which a
//!   signed lease is bound to, so an old token cannot be replayed.
//! * [`Task`] serializes to exactly the JSON the Go control plane writes to
//!   `fleets.json` (see [`Task`] for the encoding rules), so state files stay
//!   readable in both directions.
//! * [`LeaseSigner`] mints and verifies `b64url(JSON claims).b64url(HMAC)`
//!   tokens that are interchangeable with the Go implementation.
//!
//! # Multi-agent context
//!
//! Beyond the Go fields, a task can carry context for multi-agent work: a
//! parent/child link ([`Task::parent`], [`Task::children`]), handoff notes
//! left by one agent for the next ([`Task::notes`]) and per-agent briefs
//! ([`Task::briefs`]). These fields are omitted from the JSON while empty, so
//! a board that does not use them encodes byte for byte like Go, and Go
//! ignores them when it reads a file that has them (it drops them if it
//! rewrites the file).
//!
//! The durable result of a task is still the Go `result` string, which is
//! kept across requeues and persisted with the board. A structured result
//! (artifacts, typed outputs) is deliberately not added yet: it would need a
//! size limit and a storage decision (inline in `fleets.json` or by
//! reference), so it is left for when the control plane gains a consumer.

mod board;
mod gotime_serde;
mod lease;
mod task;

pub use board::{Board, FleetError};
pub use lease::{
    InvalidLease, LEASE_KEY_FILE_NAME, LEASE_KEY_LEN, LeaseClaims, LeaseKeyError, LeaseSigner,
};
pub use task::{HandoffNote, Stats, Task, TaskState};

/// Go's time type as this crate stores it (an instant plus its offset).
pub use runeward_ledger::gotime::Time;
