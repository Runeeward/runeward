//! The in-memory task board.

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use chrono::TimeDelta;
use rand::RngCore;
use runeward_ledger::gotime::{self, Time};

use crate::task::{HandoffNote, Stats, Task, TaskState};

/// Errors returned by [`Board`] methods. The messages match Go's wrapped
/// sentinel errors (`fleet: task not found: "id"` and
/// `fleet: illegal state transition: ...`).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FleetError {
    /// No task has the given ID (Go's `ErrNotFound`).
    #[error("fleet: task not found: {}", quote(.0))]
    NotFound(String),
    /// The task is not in a state that allows the operation, or is held by a
    /// different worker (Go's `ErrIllegalTransition`).
    #[error("fleet: illegal state transition: {0}")]
    IllegalTransition(String),
}

/// Quotes s roughly like Go's `%q`.
fn quote(s: &str) -> String {
    format!("{s:?}")
}

#[derive(Debug, Default)]
struct Inner {
    tasks: HashMap<String, Task>,
    /// IDs in insertion order; defines FIFO claim order.
    order: Vec<String>,
    /// How long a claim is valid without a heartbeat; zero disables expiry.
    lease: Duration,
}

/// An in-memory task board. All methods are safe for concurrent use; share
/// it behind an `Arc`.
#[derive(Debug, Default)]
pub struct Board {
    inner: Mutex<Inner>,
}

impl Board {
    /// Returns an empty board with lease expiry disabled.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns a new board with one pending task per payload, in order.
    pub fn seed<I, S>(payloads: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let b = Self::new();
        for p in payloads {
            b.add(p);
        }
        b
    }

    /// Reconstructs a board from an [`export`](Self::export) snapshot,
    /// preserving IDs, states and insertion order.
    pub fn load(tasks: Vec<Task>, lease: Duration) -> Self {
        let mut inner = Inner {
            tasks: HashMap::with_capacity(tasks.len()),
            order: Vec::with_capacity(tasks.len()),
            lease,
        };
        for t in tasks {
            inner.order.push(t.id.clone());
            inner.tasks.insert(t.id.clone(), t);
        }
        Self {
            inner: Mutex::new(inner),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        // A panic while holding the lock cannot leave a task half-updated in a
        // way later calls depend on, so keep serving after poisoning.
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Sets the claim lease duration. When non-zero, claims stamp a deadline
    /// of now + `lease`, heartbeats extend it, and [`sweep`](Self::sweep)
    /// requeues tasks whose lease has passed. Zero disables lease expiry.
    pub fn set_lease(&self, lease: Duration) {
        self.lock().lease = lease;
    }

    /// Returns a copy of every task in insertion order, for serialization.
    pub fn export(&self) -> Vec<Task> {
        self.list()
    }

    /// Enqueues a new pending task and returns a copy.
    pub fn add(&self, payload: impl Into<String>) -> Task {
        let mut inner = self.lock();
        let t = new_task(payload.into(), String::new());
        insert(&mut inner, t)
    }

    /// Enqueues a new pending task split from `parent` and records the link
    /// on both tasks. Children are claimed in the same FIFO order as any
    /// other task.
    pub fn add_child(&self, parent: &str, payload: impl Into<String>) -> Result<Task, FleetError> {
        let mut inner = self.lock();
        if !inner.tasks.contains_key(parent) {
            return Err(FleetError::NotFound(parent.to_owned()));
        }
        let child = insert(&mut inner, new_task(payload.into(), parent.to_owned()));
        if let Some(p) = inner.tasks.get_mut(parent) {
            p.children.push(child.id.clone());
            p.updated_at = gotime::now();
        }
        Ok(child)
    }

    /// Appends a handoff note from `from` to task `id` and returns a copy.
    /// Notes can be added in any state.
    pub fn add_note(&self, id: &str, from: &str, text: &str) -> Result<Task, FleetError> {
        let mut inner = self.lock();
        let t = get_mut(&mut inner, id)?;
        let now = gotime::now();
        t.notes.push(HandoffNote {
            from: from.to_owned(),
            text: text.to_owned(),
            at: now,
        });
        t.updated_at = now;
        Ok(t.clone())
    }

    /// Sets (or, with an empty brief, clears) the brief for `actor` on task
    /// `id` and returns a copy.
    pub fn set_brief(&self, id: &str, actor: &str, brief: &str) -> Result<Task, FleetError> {
        let mut inner = self.lock();
        let t = get_mut(&mut inner, id)?;
        if brief.is_empty() {
            t.briefs.remove(actor);
        } else {
            t.briefs.insert(actor.to_owned(), brief.to_owned());
        }
        t.updated_at = gotime::now();
        Ok(t.clone())
    }

    /// Takes the oldest pending task, marks it claimed by `owner` and returns
    /// a copy, or `None` when nothing is pending. The scan and update run
    /// under the board lock, so two callers never get the same task.
    pub fn claim(&self, owner: &str) -> Option<Task> {
        let mut guard = self.lock();
        let inner = &mut *guard;
        let lease = inner.lease;
        let id = inner
            .order
            .iter()
            .find(|id| {
                inner
                    .tasks
                    .get(*id)
                    .is_some_and(|t| t.state == TaskState::Pending)
            })?
            .clone();
        let t = inner.tasks.get_mut(&id)?;
        let now = gotime::now();
        t.state = TaskState::Claimed;
        t.owner = owner.to_owned();
        t.attempts += 1;
        t.lease_version += 1;
        t.updated_at = now;
        if let Some(exp) = expiry(now, lease) {
            t.lease_expiry = Some(exp);
        }
        Some(t.clone())
    }

    /// Extends the lease on a task claimed by `owner` and rotates its lease
    /// version. Fails if the task does not exist, is not claimed, or is held
    /// by someone else.
    pub fn heartbeat(&self, id: &str, owner: &str) -> Result<Task, FleetError> {
        let mut inner = self.lock();
        let lease = inner.lease;
        let t = get_mut(&mut inner, id)?;
        if t.state != TaskState::Claimed {
            return Err(FleetError::IllegalTransition(format!(
                "heartbeat requires claimed, task {} is {}",
                quote(id),
                t.state
            )));
        }
        if t.owner != owner {
            return Err(wrong_owner(id, &t.owner, owner));
        }
        let now = gotime::now();
        t.lease_version += 1;
        t.updated_at = now;
        if let Some(exp) = expiry(now, lease) {
            t.lease_expiry = Some(exp);
        }
        Ok(t.clone())
    }

    /// Requeues every claimed task whose lease expired before `now`, so a dead
    /// worker's task returns to the pending pool. Attempts are retained.
    /// Returns copies of the requeued tasks; tasks without a lease are never
    /// swept.
    pub fn sweep(&self, now: Time) -> Vec<Task> {
        let mut guard = self.lock();
        let inner = &mut *guard;
        let mut requeued = Vec::new();
        for id in &inner.order {
            let Some(t) = inner.tasks.get_mut(id) else {
                continue;
            };
            if t.state != TaskState::Claimed {
                continue;
            }
            let Some(exp) = t.lease_expiry else {
                continue;
            };
            if now > exp {
                t.state = TaskState::Pending;
                t.owner.clear();
                t.lease_expiry = None;
                t.error = "lease expired; requeued".to_owned();
                t.updated_at = now.to_utc().fixed_offset();
                requeued.push(t.clone());
            }
        }
        requeued
    }

    /// Marks the claimed task `id` done with `result`. `owner` must match the
    /// claiming worker; an empty `owner` skips the check, for trusted local
    /// callers.
    pub fn complete(&self, id: &str, owner: &str, result: &str) -> Result<(), FleetError> {
        let mut inner = self.lock();
        let t = claimed_by(&mut inner, id, owner, "complete")?;
        t.state = TaskState::Done;
        t.result = result.to_owned();
        t.error.clear();
        t.lease_expiry = None;
        t.updated_at = gotime::now();
        Ok(())
    }

    /// Marks the claimed task `id` failed with `err`. With `requeue` the task
    /// instead goes back to the pending pool (owner cleared, attempts kept) so
    /// another worker can retry it. `owner` must match the claiming worker;
    /// an empty `owner` skips the check.
    pub fn fail(&self, id: &str, owner: &str, err: &str, requeue: bool) -> Result<(), FleetError> {
        let mut inner = self.lock();
        let t = claimed_by(&mut inner, id, owner, "fail")?;
        t.error = err.to_owned();
        t.updated_at = gotime::now();
        t.lease_expiry = None;
        if requeue {
            t.state = TaskState::Pending;
            t.owner.clear();
        } else {
            t.state = TaskState::Failed;
        }
        Ok(())
    }

    /// Returns a copy of the task with the given ID.
    pub fn get(&self, id: &str) -> Option<Task> {
        self.lock().tasks.get(id).cloned()
    }

    /// Replaces one existing task with a previously captured copy (its lease
    /// token is dropped). The control plane uses this only to roll back an
    /// in-memory transition when its durable state write fails. Returns false
    /// when no task has that ID.
    pub fn restore(&self, mut task: Task) -> bool {
        let mut inner = self.lock();
        let Some(slot) = inner.tasks.get_mut(&task.id) else {
            return false;
        };
        task.lease_token.clear();
        *slot = task;
        true
    }

    /// Deletes one task while preserving FIFO order, unlinking it from its
    /// parent. Used to roll back an add whose durable state update failed.
    pub fn remove(&self, id: &str) -> bool {
        let mut inner = self.lock();
        let Some(t) = inner.tasks.remove(id) else {
            return false;
        };
        if let Some(pos) = inner.order.iter().position(|o| o == id) {
            inner.order.remove(pos);
        }
        if !t.parent.is_empty()
            && let Some(p) = inner.tasks.get_mut(&t.parent)
        {
            p.children.retain(|c| c != id);
        }
        true
    }

    /// Returns a snapshot copy of every task in insertion order.
    pub fn list(&self) -> Vec<Task> {
        let inner = self.lock();
        inner
            .order
            .iter()
            .filter_map(|id| inner.tasks.get(id).cloned())
            .collect()
    }

    /// Returns a point-in-time count of tasks by state.
    pub fn stats(&self) -> Stats {
        let inner = self.lock();
        let mut s = Stats {
            total: count(inner.order.len()),
            ..Stats::default()
        };
        for t in inner.order.iter().filter_map(|id| inner.tasks.get(id)) {
            match t.state {
                TaskState::Pending => s.pending += 1,
                TaskState::Claimed => s.claimed += 1,
                TaskState::Done => s.done += 1,
                TaskState::Failed => s.failed += 1,
                TaskState::Other(_) | TaskState::Empty => {}
            }
        }
        s
    }

    /// Returns the number of tasks still in flight: pending plus claimed.
    pub fn remaining(&self) -> usize {
        let inner = self.lock();
        inner
            .order
            .iter()
            .filter_map(|id| inner.tasks.get(id))
            .filter(|t| matches!(t.state, TaskState::Pending | TaskState::Claimed))
            .count()
    }
}

fn count(n: usize) -> i64 {
    i64::try_from(n).unwrap_or(i64::MAX)
}

fn new_task(payload: String, parent: String) -> Task {
    let now = gotime::now();
    Task {
        id: new_id(),
        payload,
        state: TaskState::Pending,
        created_at: now,
        updated_at: now,
        parent,
        ..Task::default()
    }
}

fn insert(inner: &mut Inner, t: Task) -> Task {
    inner.order.push(t.id.clone());
    inner.tasks.insert(t.id.clone(), t.clone());
    t
}

fn get_mut<'a>(inner: &'a mut Inner, id: &str) -> Result<&'a mut Task, FleetError> {
    inner
        .tasks
        .get_mut(id)
        .ok_or_else(|| FleetError::NotFound(id.to_owned()))
}

fn claimed_by<'a>(
    inner: &'a mut Inner,
    id: &str,
    owner: &str,
    op: &str,
) -> Result<&'a mut Task, FleetError> {
    let t = get_mut(inner, id)?;
    if t.state != TaskState::Claimed {
        return Err(FleetError::IllegalTransition(format!(
            "{op} requires claimed, task {} is {}",
            quote(id),
            t.state
        )));
    }
    if !owner.is_empty() && t.owner != owner {
        return Err(wrong_owner(id, &t.owner, owner));
    }
    Ok(t)
}

fn wrong_owner(id: &str, holder: &str, caller: &str) -> FleetError {
    FleetError::IllegalTransition(format!(
        "task {} is owned by {}, not {}",
        quote(id),
        quote(holder),
        quote(caller)
    ))
}

/// The lease deadline for a claim or heartbeat at `now`, or `None` when
/// leases are disabled.
fn expiry(now: Time, lease: Duration) -> Option<Time> {
    if lease.is_zero() {
        return None;
    }
    let d = TimeDelta::from_std(lease).unwrap_or(TimeDelta::MAX);
    Some(now.checked_add_signed(d).unwrap_or(now))
}

/// A random 16-hex-digit ID, with a timestamp fallback so ID generation can
/// never fail.
fn new_id() -> String {
    let mut b = [0u8; 8];
    if rand::rngs::OsRng.try_fill_bytes(&mut b).is_err() {
        let nanos = gotime::now().timestamp_nanos_opt().unwrap_or_default();
        return format!("t{nanos:x}");
    }
    hex::encode(b)
}
