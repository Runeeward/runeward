//! Rune Box's governed execution core.
//!
//! Every tool call takes one path: the Charter's authority engine, the
//! approval gate (Conclave), guardrails and budgets, backend exec, then the
//! signed, hash-chained ledger (Chronicle). The [`Manager`] owns sandbox
//! sessions (Citadels), Cohorts with their task boards, snapshots, durable
//! run records and agent sessions; the REST, MCP and CLI layers are thin
//! adapters over it.
//!
//! - Secrets declared in `[[env]]` are resolved fail-closed and scrubbed
//!   (with built-in and `[chronicle] scrub_patterns`) from ledger payloads,
//!   tool output, agent transcripts and the conversation feed.
//! - Lineage: each Citadel belongs to a run (`run_id`, `parent_run_id` for
//!   delegated children), attributed to a tenant (`owner`) and the acting
//!   principal (see [`with_actor`]).
//! - Isolation: the Charter's `[isolation] minimum` is enforced at create
//!   and restore. The backend's reported tier is compared before anything
//!   executes; a weaker sandbox is torn down and refused
//!   ([`Error::IsolationFloor`]). The tier is kept in the run record, in
//!   every Chronicle event's `meta.isolation`, and in [`SandboxInfo`].
//! - In-sandbox governance: Charters with `[[endpoint]]`/`[[credential]]`
//!   get a request broker (secrets resolved here, placeholders in the
//!   sandbox, approvals through Conclave, every decision Chronicled as tool
//!   `egress` and listed by [`Manager::perimeter`]); Charters with
//!   `[filesystem]`/`[process]` run under `runeward-supervisor`, whose
//!   enforcement report is Chronicled, checked (fail closed) and surfaced
//!   as [`IsolationEvidence`] on [`SandboxInfo`].
//! - Cohort task claims carry HMAC-signed lease tokens bound to the
//!   Cohort, task, worker and lease version (`cohort-lease.key`).
//!
//! # State files
//!
//! The state directory holds `ledger.jsonl` (+ signing key),
//! `cohort-lease.key`, `runs.json`, `fleets.json`, `snapshots.json`,
//! `agent-sessions.json` and `agent-sessions/<id>.jsonl`, all in the exact
//! format the Go control plane reads and writes, so either implementation
//! can take over a state directory. Rust-only state lives in files Go never
//! reads: `workspaces.json` (persistent Citadels), `schedules.json` and
//! `cohort-memory/<cohort id>.json`; fields added to shared files are
//! optional and omitted while empty. Every JSON file is replaced atomically
//! (private temp file, fsync, rename, directory fsync).
//!
//! # Concurrency
//!
//! [`Manager`] is `Send + Sync` and shared as `Arc<Manager>`. Ledger and
//! state-file I/O run on `spawn_blocking`; locks are never held across an
//! await except the per-resource operation locks that make a mutation plus
//! its persistence one transaction.
//!
//! # Keeping context over long runs
//!
//! - **Persistent workspaces:** with `[workspace] persist = true` a Citadel
//!   sleeps after `idle_timeout` ([`SessionState::Sleeping`]) and any
//!   governed call, terminal or agent turn wakes it under the same id
//!   ([`Manager::sleep_citadel`], [`Manager::wake_citadel`],
//!   [`Manager::workspace_status`]); a restarted Manager rediscovers
//!   sleeping workspaces. Only what is on disk survives a sleep.
//! - **Fork:** [`Manager::fork_citadel`] copies a workspace into a new,
//!   independent Citadel with `forked_from` lineage.
//! - **Resumable agent turns:** [`Manager::start_agent_turn`] (one active
//!   turn per session), [`Manager::subscribe_agent_session`] (gap-free
//!   replay plus live events) and [`Manager::cancel_agent_session`].
//! - **Shared Cohort memory and handoffs:** [`Manager::memory_put`] and
//!   friends, task notes/briefs/children and
//!   [`Manager::claim_task_with_context`].
//! - **Scheduled runs:** [`Manager::create_schedule`] (and
//!   [`Manager::create_self_schedule`] for agents when the Charter allows).
//!
//! # Seams for upcoming features
//!
//! - **Effect classes and per-route budgets:** every policy input is built
//!   in one place (the crate-private `GovernCall`), where an effect class
//!   and the egress broker's route would be added to the policy `Action`
//!   and budget checks run alongside the existing guardrails.

mod actor;
mod agent_sessions;
mod approvals;
mod browser;
mod citadels;
pub mod config;
mod conversation;
mod env;
mod error;
mod evidence;
mod fleet;
mod fork;
mod govern;
mod governance;
mod handoff;
mod ide;
mod manager;
mod memory;
mod runs;
mod schedules;
mod sessions;
mod snapshots;
mod statefile;
mod timefmt;
mod workspaces;

#[cfg(test)]
mod tests;

pub use actor::{current_actor, with_actor};
pub use agent_sessions::{
    AgentEvent, AgentSession, AgentStatus, AgentSubscription, AgentTurnOptions,
    MAX_AGENT_EVENT_BYTES, MAX_AGENT_EVENTS_MEMORY, MAX_AGENT_TRANSCRIPT_BYTES,
    StartAgentSessionOptions,
};
pub use approvals::{ApprovalStore, ApprovalView};
pub use citadels::{CreateOptions, ProfileInfo, ReadinessCheck, ReadinessReport, SandboxInfo};
pub use config::ManagerConfig;
pub use conversation::{ConversationMessage, ConversationSubscription};
pub use error::{Error, Result};
pub use fleet::{Fleet, FleetView};
pub use fork::ForkOptions;
pub use govern::ToolResult;
pub use governance::IsolationEvidence;
pub use handoff::{
    ANY_AGENT, ClaimContext, ClaimedTask, MAX_BRIEF_BYTES, MAX_CHILD_PAYLOAD_BYTES, MAX_NOTE_BYTES,
    ParentSummary,
};
pub use manager::{LEDGER_FILE_NAME, Manager, ManagerBuilder};
pub use memory::{
    DEFAULT_MEMORY_SLICE_BYTES, MAX_MEMORY_ENTRIES, MAX_MEMORY_KEY_BYTES, MAX_MEMORY_TEXT_BYTES,
    MAX_MEMORY_TOTAL_BYTES, MemoryEntry, MemoryPut, MemoryQuery,
};
pub use runs::Run;
pub use schedules::{
    MAX_SCHEDULES_PER_TARGET, MIN_SCHEDULE_INTERVAL, Schedule, ScheduleFiring, ScheduleSpec,
};
pub use sessions::{Session, SessionBuilder, SessionState};
pub use workspaces::{WorkspaceRecord, WorkspaceStatus};

/// A fresh 128-bit hex id (approvals, runs, Cohorts, agent sessions):
/// unguessable even without authentication.
pub(crate) fn new_id() -> String {
    hex::encode(rand::random::<[u8; 16]>())
}
