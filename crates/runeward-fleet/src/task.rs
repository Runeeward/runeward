//! Task, state and stats types with Go-compatible JSON.

use std::collections::BTreeMap;
use std::fmt;

use runeward_ledger::gotime::{self, Time};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::gotime_serde::{self, nullable};

/// The lifecycle state of a [`Task`].
///
/// A task starts [`Pending`](TaskState::Pending), becomes
/// [`Claimed`](TaskState::Claimed) when a worker takes it, and finishes
/// [`Done`](TaskState::Done) or [`Failed`](TaskState::Failed). A failed task
/// may be requeued back to pending. Like Go's string-typed state, any other
/// value read from a state file is kept verbatim in
/// [`Other`](TaskState::Other) so it survives a rewrite.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub enum TaskState {
    /// Waiting to be claimed.
    Pending,
    /// Held by a worker.
    Claimed,
    /// Finished successfully.
    Done,
    /// Finished unsuccessfully (not requeued).
    Failed,
    /// Any other non-empty value.
    Other(String),
    /// Go's zero state: the empty string.
    #[default]
    Empty,
}

impl TaskState {
    /// The wire spelling, as in Go.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Pending => "pending",
            Self::Claimed => "claimed",
            Self::Done => "done",
            Self::Failed => "failed",
            Self::Other(s) => s,
            Self::Empty => "",
        }
    }

    fn parse(s: &str) -> Self {
        match s {
            "pending" => Self::Pending,
            "claimed" => Self::Claimed,
            "done" => Self::Done,
            "failed" => Self::Failed,
            "" => Self::Empty,
            other => Self::Other(other.to_owned()),
        }
    }
}

impl fmt::Display for TaskState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for TaskState {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for TaskState {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s: String = nullable(d)?;
        Ok(Self::parse(&s))
    }
}

/// A note one agent leaves on a task for whoever picks it up next.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandoffNote {
    /// The actor that wrote the note.
    #[serde(default, deserialize_with = "nullable")]
    pub from: String,
    /// Free-form note text.
    #[serde(default, deserialize_with = "nullable")]
    pub text: String,
    /// When the note was added.
    #[serde(with = "gotime_serde", default = "gotime::zero")]
    pub at: Time,
}

/// A unit of work on the board. [`Board`](crate::Board) methods hand out
/// copies, so callers can never mutate board state through a returned value.
///
/// # JSON
///
/// The encoding matches Go's `fleet.Task`: fields in Go's order, times as
/// RFC 3339 with trailing fraction zeros trimmed, `lease_expiry` always
/// present (the zero time `0001-01-01T00:00:00Z` when unset, since Go's
/// `omitempty` never omits a struct), `lease_version` omitted when 0 and
/// `lease_token` omitted when empty. Encode with
/// [`runeward_ledger::gojson::marshal`] to also get Go's HTML-safe string
/// escaping. The multi-agent fields after `lease_token` are omitted while
/// empty.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Task {
    /// Random 16-hex-digit identifier.
    #[serde(default, deserialize_with = "nullable")]
    pub id: String,
    /// Opaque work description.
    #[serde(default, deserialize_with = "nullable")]
    pub payload: String,
    /// Lifecycle state.
    #[serde(default)]
    pub state: TaskState,
    /// The worker that last claimed the task; cleared on requeue.
    #[serde(default, deserialize_with = "nullable")]
    pub owner: String,
    /// Counts claims, not completions.
    #[serde(default, deserialize_with = "nullable")]
    pub attempts: i64,
    /// When the task was added.
    #[serde(with = "gotime_serde", default = "gotime::zero")]
    pub created_at: Time,
    /// When the task last changed.
    #[serde(with = "gotime_serde", default = "gotime::zero")]
    pub updated_at: Time,
    /// The durable result of a completed task.
    #[serde(default, deserialize_with = "nullable")]
    pub result: String,
    /// The last failure message.
    #[serde(default, deserialize_with = "nullable")]
    pub error: String,
    /// When the current claim expires; [`Board::sweep`](crate::Board::sweep)
    /// requeues claimed tasks past it. `None` means no lease (the claim never
    /// expires).
    #[serde(with = "gotime_serde::opt", default)]
    pub lease_expiry: Option<Time>,
    /// Rotates on every claim and heartbeat. It is persisted so an older
    /// signed lease cannot be replayed after renewal or requeue.
    #[serde(
        default,
        deserialize_with = "nullable",
        skip_serializing_if = "is_zero_i64"
    )]
    pub lease_version: i64,
    /// Returned only with a successful claim. It is a signed, short-lived
    /// capability and is never stored on the board or returned by list
    /// operations.
    #[serde(
        default,
        deserialize_with = "nullable",
        skip_serializing_if = "String::is_empty"
    )]
    pub lease_token: String,
    /// The task this one was split from, if any.
    #[serde(
        default,
        deserialize_with = "nullable",
        skip_serializing_if = "String::is_empty"
    )]
    pub parent: String,
    /// Tasks split from this one, in creation order.
    #[serde(
        default,
        deserialize_with = "nullable",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub children: Vec<String>,
    /// Handoff notes, oldest first.
    #[serde(
        default,
        deserialize_with = "nullable",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub notes: Vec<HandoffNote>,
    /// Per-agent briefs keyed by actor.
    #[serde(
        default,
        deserialize_with = "nullable",
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    pub briefs: BTreeMap<String, String>,
}

fn is_zero_i64(v: &i64) -> bool {
    *v == 0
}

impl Default for Task {
    /// Go's zero `Task`: empty strings, zero counters and zero times.
    fn default() -> Self {
        Self {
            id: String::new(),
            payload: String::new(),
            state: TaskState::Empty,
            owner: String::new(),
            attempts: 0,
            created_at: gotime::zero(),
            updated_at: gotime::zero(),
            result: String::new(),
            error: String::new(),
            lease_expiry: None,
            lease_version: 0,
            lease_token: String::new(),
            parent: String::new(),
            children: Vec::new(),
            notes: Vec::new(),
            briefs: BTreeMap::new(),
        }
    }
}

/// A point-in-time count of tasks by state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Stats {
    /// All tasks.
    #[serde(default)]
    pub total: i64,
    /// Waiting to be claimed.
    #[serde(default)]
    pub pending: i64,
    /// Held by a worker.
    #[serde(default)]
    pub claimed: i64,
    /// Finished successfully.
    #[serde(default)]
    pub done: i64,
    /// Finished unsuccessfully.
    #[serde(default)]
    pub failed: i64,
}
