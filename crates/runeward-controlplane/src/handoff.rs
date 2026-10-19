//! Cohort handoffs: notes, briefs and child tasks on the board, and the
//! context a claimant gets with a task.
//!
//! An agent that finishes or gives up a task can leave a handoff note for
//! whoever works on it (or its children) next; operators and agents can
//! set per-agent briefs on a task; work splits into child tasks. A claim
//! with context returns the task together with the relevant handoff notes
//! (the parent's, then the task's), the brief meant for the claimant, a
//! summary of the parent, and a ranked, byte-capped slice of the Cohort's
//! shared memory, so an agent starting fresh has what it needs without
//! replaying transcripts. Every write is attributed, size-capped and
//! Chronicled (hashed when the Charter redacts).

use runeward_fleet::{HandoffNote, Task, TaskState};
use serde::Serialize;

use crate::actor::actor_or;
use crate::error::{Error, Result};
use crate::manager::Manager;
use crate::memory::{DEFAULT_MEMORY_SLICE_BYTES, MemoryEntry, MemoryQuery, rank};

/// Largest handoff note, in bytes.
pub const MAX_NOTE_BYTES: usize = 8 << 10;
/// Most notes per task.
pub const MAX_NOTES_PER_TASK: usize = 100;
/// Largest brief, in bytes.
pub const MAX_BRIEF_BYTES: usize = 8 << 10;
/// Most briefs per task.
pub const MAX_BRIEFS_PER_TASK: usize = 64;
/// Largest child task payload, in bytes.
pub const MAX_CHILD_PAYLOAD_BYTES: usize = 64 << 10;
/// Most children per task.
pub const MAX_CHILDREN_PER_TASK: usize = 256;
/// The brief key that applies to every agent.
pub const ANY_AGENT: &str = "*";

/// The parent of a claimed child task.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ParentSummary {
    pub id: String,
    pub payload: String,
    pub state: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub result: String,
}

/// What a claimant needs to start on a task cold.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct ClaimContext {
    /// The brief for the claimant (or for every agent), from the task, else
    /// from its parent.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub brief: String,
    /// Handoff notes from the parent, then the task, oldest first.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub handoff: Vec<HandoffNote>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent: Option<ParentSummary>,
    /// The most relevant shared memory, ranked against the task.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub memory: Vec<MemoryEntry>,
}

impl ClaimContext {
    /// Reports whether there is nothing to hand over.
    pub fn is_empty(&self) -> bool {
        self.brief.is_empty()
            && self.handoff.is_empty()
            && self.parent.is_none()
            && self.memory.is_empty()
    }
}

/// A claimed task (with its signed lease) and its context.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ClaimedTask {
    pub task: Task,
    pub context: ClaimContext,
}

fn check_note(text: &str) -> Result<()> {
    if text.trim().is_empty() {
        return Err(Error::bad_input("note text is required"));
    }
    if text.len() > MAX_NOTE_BYTES {
        return Err(Error::bad_input(format!(
            "note exceeds {MAX_NOTE_BYTES} bytes"
        )));
    }
    Ok(())
}

fn author() -> String {
    let a = actor_or("");
    if a.is_empty() { "anonymous".into() } else { a }
}

fn brief_for(t: &Task, who: &str) -> Option<String> {
    t.briefs
        .get(who)
        .or_else(|| t.briefs.get(ANY_AGENT))
        .cloned()
}

impl Manager {
    fn fleet_or_not_found(&self, id: &str) -> Result<std::sync::Arc<crate::fleet::Fleet>> {
        self.fleet(id)
            .ok_or_else(|| Error::not_found(format!("fleet {id:?} not found")))
    }

    fn task_of(f: &crate::fleet::Fleet, task_id: &str) -> Result<Task> {
        f.board
            .get(task_id)
            .ok_or_else(|| Error::Task(runeward_fleet::FleetError::NotFound(task_id.to_owned())))
    }

    /// Adds a task split from `parent`.
    pub async fn add_child_task(
        &self,
        fleet_id: &str,
        parent: &str,
        payload: &str,
    ) -> Result<Task> {
        if payload.len() > MAX_CHILD_PAYLOAD_BYTES {
            return Err(Error::bad_input(format!(
                "task payload exceeds {MAX_CHILD_PAYLOAD_BYTES} bytes"
            )));
        }
        let child = {
            let _op = self.fleet_op.lock().await;
            let f = self.fleet_or_not_found(fleet_id)?;
            let before = Self::task_of(&f, parent)?;
            if before.children.len() >= MAX_CHILDREN_PER_TASK {
                return Err(Error::bad_input(format!(
                    "a task has at most {MAX_CHILDREN_PER_TASK} children"
                )));
            }
            let child = f.board.add_child(parent, payload)?;
            if let Err(e) = self.save_fleets().await {
                f.board.remove(&child.id);
                f.board.restore(before);
                return Err(Error::other(format!("persist child task: {e}")));
            }
            child
        };
        let f = self.fleet_or_not_found(fleet_id)?;
        self.record_context(
            &f,
            "fleet",
            "task.child",
            vec![child.id.clone(), parent.to_owned()],
            payload,
            &[],
        )
        .await;
        Ok(child)
    }

    /// Appends a handoff note from the acting principal to a task (in any
    /// state).
    pub async fn add_task_note(&self, fleet_id: &str, task_id: &str, text: &str) -> Result<Task> {
        check_note(text)?;
        let from = author();
        let t = {
            let _op = self.fleet_op.lock().await;
            let f = self.fleet_or_not_found(fleet_id)?;
            let before = Self::task_of(&f, task_id)?;
            if before.notes.len() >= MAX_NOTES_PER_TASK {
                return Err(Error::bad_input(format!(
                    "a task holds at most {MAX_NOTES_PER_TASK} notes"
                )));
            }
            let t = f.board.add_note(task_id, &from, text)?;
            if let Err(e) = self.save_fleets().await {
                f.board.restore(before);
                return Err(Error::other(format!("persist task note: {e}")));
            }
            t
        };
        let f = self.fleet_or_not_found(fleet_id)?;
        self.record_context(
            &f,
            "fleet",
            "task.note",
            vec![task_id.to_owned()],
            text,
            &[],
        )
        .await;
        Ok(t)
    }

    /// Sets (or with an empty brief clears) the brief for `agent` (`*`:
    /// every agent) on a task.
    pub async fn set_task_brief(
        &self,
        fleet_id: &str,
        task_id: &str,
        agent: &str,
        brief: &str,
    ) -> Result<Task> {
        let agent = agent.trim();
        if agent.is_empty() || agent.len() > 128 || agent.chars().any(char::is_control) {
            return Err(Error::bad_input(
                "agent is required (at most 128 bytes; \"*\" for every agent)",
            ));
        }
        if brief.len() > MAX_BRIEF_BYTES {
            return Err(Error::bad_input(format!(
                "brief exceeds {MAX_BRIEF_BYTES} bytes"
            )));
        }
        let t = {
            let _op = self.fleet_op.lock().await;
            let f = self.fleet_or_not_found(fleet_id)?;
            let before = Self::task_of(&f, task_id)?;
            if !brief.is_empty()
                && !before.briefs.contains_key(agent)
                && before.briefs.len() >= MAX_BRIEFS_PER_TASK
            {
                return Err(Error::bad_input(format!(
                    "a task holds at most {MAX_BRIEFS_PER_TASK} briefs"
                )));
            }
            let t = f.board.set_brief(task_id, agent, brief)?;
            if let Err(e) = self.save_fleets().await {
                f.board.restore(before);
                return Err(Error::other(format!("persist task brief: {e}")));
            }
            t
        };
        let f = self.fleet_or_not_found(fleet_id)?;
        let action = if brief.is_empty() {
            "task.brief.clear"
        } else {
            "task.brief"
        };
        self.record_context(
            &f,
            "fleet",
            action,
            vec![task_id.to_owned(), agent.to_owned()],
            brief,
            &[],
        )
        .await;
        Ok(t)
    }

    /// Completes a claimed task like [`Manager::complete_task`] and leaves a
    /// handoff note (when non-empty) for whoever picks up its follow-up
    /// work: its children, or anything that reads the task.
    pub async fn complete_task_with_handoff(
        &self,
        fleet_id: &str,
        task_id: &str,
        owner: &str,
        lease_token: &str,
        result: &str,
        handoff: &str,
    ) -> Result<()> {
        self.finish_with_handoff(fleet_id, task_id, owner, lease_token, handoff, |f| {
            f.board.complete(task_id, owner, result)
        })
        .await
    }

    /// Fails a claimed task like [`Manager::fail_task`] (with `requeue`, it
    /// goes back to the board) and leaves a handoff note for the next
    /// claimant.
    #[allow(clippy::too_many_arguments)]
    pub async fn fail_task_with_handoff(
        &self,
        fleet_id: &str,
        task_id: &str,
        owner: &str,
        lease_token: &str,
        message: &str,
        requeue: bool,
        handoff: &str,
    ) -> Result<()> {
        self.finish_with_handoff(fleet_id, task_id, owner, lease_token, handoff, |f| {
            f.board.fail(task_id, owner, message, requeue)
        })
        .await
    }

    async fn finish_with_handoff(
        &self,
        fleet_id: &str,
        task_id: &str,
        owner: &str,
        lease_token: &str,
        handoff: &str,
        finish: impl FnOnce(&crate::fleet::Fleet) -> std::result::Result<(), runeward_fleet::FleetError>,
    ) -> Result<()> {
        if !handoff.is_empty() {
            check_note(handoff)?;
        }
        {
            let _op = self.fleet_op.lock().await;
            let f = self.fleet_or_not_found(fleet_id)?;
            let current = Self::task_of(&f, task_id)?;
            self.verify_task_lease(lease_token, fleet_id, &current, owner)?;
            if !handoff.is_empty() && current.notes.len() >= MAX_NOTES_PER_TASK {
                return Err(Error::bad_input(format!(
                    "a task holds at most {MAX_NOTES_PER_TASK} notes"
                )));
            }
            finish(&f)?;
            if !handoff.is_empty() {
                f.board.add_note(task_id, owner, handoff)?;
            }
            if let Err(e) = self.save_fleets().await {
                f.board.restore(current);
                return Err(Error::other(format!("persist task handoff: {e}")));
            }
        }
        if !handoff.is_empty() {
            let f = self.fleet_or_not_found(fleet_id)?;
            self.record_context(
                &f,
                "fleet",
                "task.handoff",
                vec![task_id.to_owned()],
                handoff,
                &[("worker", owner.to_owned())],
            )
            .await;
        }
        Ok(())
    }

    /// Claims the next pending task like [`Manager::claim_task`] and
    /// returns it with its [`ClaimContext`]; `memory_bytes` caps the memory
    /// slice (0: 8 KiB).
    pub async fn claim_task_with_context(
        &self,
        fleet_id: &str,
        owner: &str,
        memory_bytes: usize,
    ) -> Result<Option<ClaimedTask>> {
        let Some(task) = self.claim_task(fleet_id, owner).await? else {
            return Ok(None);
        };
        let context = self
            .task_context(fleet_id, &task, owner, memory_bytes)
            .await?;
        Ok(Some(ClaimedTask { task, context }))
    }

    /// The context for `who` working on `task` (see [`ClaimContext`]).
    pub async fn task_context(
        &self,
        fleet_id: &str,
        task: &Task,
        who: &str,
        memory_bytes: usize,
    ) -> Result<ClaimContext> {
        let f = self.fleet_or_not_found(fleet_id)?;
        let parent = (!task.parent.is_empty())
            .then(|| f.board.get(&task.parent))
            .flatten();
        let mut handoff = Vec::new();
        if let Some(p) = &parent {
            handoff.extend(p.notes.iter().cloned());
        }
        handoff.extend(task.notes.iter().cloned());
        let brief = brief_for(task, who)
            .or_else(|| parent.as_ref().and_then(|p| brief_for(p, who)))
            .unwrap_or_default();
        let mut query = task.payload.clone();
        if let Some(p) = &parent {
            query.push(' ');
            query.push_str(&p.payload);
        }
        let memory = rank(
            self.memory_entries(fleet_id).await?,
            &MemoryQuery {
                query,
                max_bytes: if memory_bytes == 0 {
                    DEFAULT_MEMORY_SLICE_BYTES
                } else {
                    memory_bytes
                },
                ..MemoryQuery::default()
            },
            false,
        );
        Ok(ClaimContext {
            brief,
            handoff,
            parent: parent.map(|p| ParentSummary {
                id: p.id,
                payload: p.payload,
                state: match p.state {
                    TaskState::Empty => String::new(),
                    s => s.as_str().to_owned(),
                },
                result: p.result,
            }),
            memory,
        })
    }
}
