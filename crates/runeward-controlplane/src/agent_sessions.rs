//! Agent sessions: observable, durable agent commands with reconnectable
//! transcripts.
//!
//! Metadata lives in `agent-sessions.json`; each session's transcript is
//! appended to `agent-sessions/<id>.jsonl` (one Go-encoded event per line,
//! capped at 64 MiB, after which the session is marked
//! `transcript_truncated`). Output is split into events of at most 32 KiB,
//! scrubbed before storage, and the newest 2048 events are kept in memory;
//! older backlog is read back from the transcript on demand.
//!
//! # Lifecycle
//!
//! ```text
//!  queued ──▶ running ──▶ completed | failed | denied | canceled
//!     └──────────┴──────▶ interrupted   (control plane restarted)
//! ```
//!
//! Resumable sessions build on this: [`Manager::subscribe_agent_session`]
//! already replays the backlog and attaches to live events without a gap,
//! and [`Manager::cancel_agent_session`] stops a running command. Multi-turn
//! sessions will add an idle state between turns, with at most one active
//! turn per session.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::io::{BufRead, Write};
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll};

use runeward_backend::ExecRequest;
use runeward_charter::Verdict;
use runeward_ledger::gotime::{self, Time};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use tokio::io::AsyncWrite;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;

use crate::actor::{actor_or, with_actor};
use crate::error::{Error, Result};
use crate::govern::GovernCall;
use crate::manager::{Manager, blocking};
use crate::sessions::Session;
use crate::statefile::{StateDir, create_private_dir, marshal_indent};
use crate::timefmt::nullable;

pub(crate) const AGENT_SESSIONS_FILE_NAME: &str = "agent-sessions.json";
pub(crate) const AGENT_SESSION_DIR_NAME: &str = "agent-sessions";
/// Largest single event payload.
pub const MAX_AGENT_EVENT_BYTES: usize = 32 << 10;
/// Events kept in memory per session.
pub const MAX_AGENT_EVENTS_MEMORY: usize = 2_048;
/// Transcript size cap.
pub const MAX_AGENT_TRANSCRIPT_BYTES: u64 = 64 << 20;
/// Longest transcript line read back (Go's scanner limit).
const MAX_TRANSCRIPT_LINE: usize = 256 << 10;
/// Live events buffered per subscriber before it starts missing them.
const SUBSCRIBER_BUFFER: usize = 256;

/// Where an agent session is in its lifecycle. Values read from disk that
/// are not recognised are kept verbatim.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub enum AgentStatus {
    #[default]
    Queued,
    Running,
    Completed,
    Failed,
    Denied,
    Canceled,
    Interrupted,
    Other(String),
}

impl AgentStatus {
    /// The wire spelling.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Queued => "queued",
            Self::Running => "running",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Denied => "denied",
            Self::Canceled => "canceled",
            Self::Interrupted => "interrupted",
            Self::Other(s) => s,
        }
    }

    /// Parses the wire spelling.
    pub fn parse(s: &str) -> Self {
        match s {
            "queued" => Self::Queued,
            "running" => Self::Running,
            "completed" => Self::Completed,
            "failed" => Self::Failed,
            "denied" => Self::Denied,
            "canceled" => Self::Canceled,
            "interrupted" => Self::Interrupted,
            other => Self::Other(other.to_owned()),
        }
    }

    /// Reports whether the session is finished.
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Completed | Self::Failed | Self::Denied | Self::Canceled | Self::Interrupted
        )
    }

    /// Reports whether `self -> next` is a legal transition.
    pub fn can_transition(&self, next: &Self) -> bool {
        match self {
            Self::Queued => matches!(next, Self::Running) || next.is_terminal(),
            Self::Running => next.is_terminal(),
            _ => false,
        }
    }
}

impl fmt::Display for AgentStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for AgentStatus {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for AgentStatus {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s: String = nullable(d)?;
        Ok(Self::parse(&s))
    }
}

/// One durable agent command. Field order and `omitempty` rules match Go.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentSession {
    #[serde(default, deserialize_with = "nullable")]
    pub id: String,
    #[serde(default, deserialize_with = "nullable")]
    pub citadel_id: String,
    #[serde(
        default,
        deserialize_with = "nullable",
        skip_serializing_if = "String::is_empty"
    )]
    pub tenant: String,
    #[serde(
        default,
        deserialize_with = "nullable",
        skip_serializing_if = "String::is_empty"
    )]
    pub actor: String,
    #[serde(
        default,
        deserialize_with = "nullable",
        skip_serializing_if = "String::is_empty"
    )]
    pub agent: String,
    #[serde(
        default,
        deserialize_with = "nullable",
        skip_serializing_if = "String::is_empty"
    )]
    pub model: String,
    #[serde(
        default,
        deserialize_with = "nullable",
        skip_serializing_if = "String::is_empty"
    )]
    pub cohort_id: String,
    #[serde(
        default,
        deserialize_with = "nullable",
        skip_serializing_if = "String::is_empty"
    )]
    pub task_id: String,
    #[serde(
        default,
        deserialize_with = "nullable",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub command: Vec<String>,
    #[serde(default)]
    pub status: AgentStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i64>,
    #[serde(
        default,
        deserialize_with = "nullable",
        skip_serializing_if = "String::is_empty"
    )]
    pub error: String,
    #[serde(with = "crate::timefmt", default = "gotime::zero")]
    pub created_at: Time,
    #[serde(
        with = "crate::timefmt::opt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub started_at: Option<Time>,
    #[serde(
        with = "crate::timefmt::opt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub finished_at: Option<Time>,
    #[serde(default, deserialize_with = "nullable")]
    pub last_seq: i64,
    #[serde(
        default,
        deserialize_with = "nullable",
        skip_serializing_if = "std::ops::Not::not"
    )]
    pub transcript_truncated: bool,
}

/// A reconnectable transcript record. `stream` is `stdout`, `stderr` or
/// `status`; `data` has already been scrubbed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentEvent {
    #[serde(default, deserialize_with = "nullable")]
    pub seq: i64,
    #[serde(with = "crate::timefmt", default = "gotime::zero")]
    pub time: Time,
    #[serde(default, deserialize_with = "nullable")]
    pub stream: String,
    #[serde(default, deserialize_with = "nullable")]
    pub data: String,
}

/// What to run in a new agent session.
#[derive(Debug, Clone, Default)]
pub struct StartAgentSessionOptions {
    pub command: Vec<String>,
    pub agent: String,
    pub model: String,
    /// Scopes the session to a Cohort the Citadel belongs to.
    pub cohort_id: String,
    /// A task on that Cohort's board.
    pub task_id: String,
}

/// A backlog plus live events, registered atomically so nothing falls in
/// between. Dropping it unsubscribes.
#[derive(Debug)]
pub struct AgentSubscription {
    /// The session as of subscribing.
    pub session: AgentSession,
    /// Events after the requested sequence number.
    pub backlog: Vec<AgentEvent>,
    events: mpsc::Receiver<AgentEvent>,
    store: Arc<AgentStore>,
    session_id: String,
    sub_id: u64,
}

impl AgentSubscription {
    /// The next live event; `None` once the session finished (or this
    /// subscriber fell too far behind to keep up).
    pub async fn recv(&mut self) -> Option<AgentEvent> {
        self.events.recv().await
    }
}

impl Drop for AgentSubscription {
    fn drop(&mut self) {
        let mut inner = self.store.lock();
        if let Some(e) = inner.sessions.get_mut(&self.session_id) {
            e.subscribers.remove(&self.sub_id);
        }
    }
}

#[derive(Debug)]
struct Entry {
    meta: AgentSession,
    events: VecDeque<AgentEvent>,
    subscribers: HashMap<u64, mpsc::Sender<AgentEvent>>,
    cancel: Option<watch::Sender<bool>>,
}

#[derive(Debug, Default)]
struct Inner {
    sessions: HashMap<String, Entry>,
    next_sub: u64,
}

/// Agent session state shared with the blocking threads that persist
/// transcripts. Every method may do file I/O.
#[derive(Debug)]
pub(crate) struct AgentStore {
    state: Arc<StateDir>,
    inner: Mutex<Inner>,
    tasks: Mutex<Vec<JoinHandle<()>>>,
}

pub(crate) fn valid_agent_session_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit())
}

fn events_after<'a>(
    events: impl IntoIterator<Item = &'a AgentEvent>,
    after: i64,
) -> Vec<AgentEvent> {
    events
        .into_iter()
        .filter(|e| e.seq > after)
        .cloned()
        .collect()
}

impl AgentStore {
    pub(crate) fn new(state: Arc<StateDir>) -> Arc<Self> {
        Arc::new(Self {
            state,
            inner: Mutex::new(Inner::default()),
            tasks: Mutex::new(Vec::new()),
        })
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn transcript_dir(&self) -> Option<std::path::PathBuf> {
        self.state.path(AGENT_SESSION_DIR_NAME)
    }

    /// Appends one event (split into ≤32 KiB pieces at char boundaries),
    /// persists it unless the transcript is already truncated, and fans it
    /// out to live subscribers without blocking.
    pub(crate) fn append(&self, id: &str, stream: &str, data: &str) {
        if data.is_empty() {
            return;
        }
        let mut rest = data;
        while rest.len() > MAX_AGENT_EVENT_BYTES {
            let mut cut = MAX_AGENT_EVENT_BYTES;
            while !rest.is_char_boundary(cut) {
                cut -= 1;
            }
            self.append_one(id, stream, &rest[..cut]);
            rest = &rest[cut..];
        }
        self.append_one(id, stream, rest);
    }

    fn append_one(&self, id: &str, stream: &str, data: &str) {
        let mut inner = self.lock();
        let Some(e) = inner.sessions.get_mut(id) else {
            return;
        };
        e.meta.last_seq += 1;
        let ev = AgentEvent {
            seq: e.meta.last_seq,
            time: gotime::now(),
            stream: stream.to_owned(),
            data: data.to_owned(),
        };
        e.events.push_back(ev.clone());
        while e.events.len() > MAX_AGENT_EVENTS_MEMORY {
            e.events.pop_front();
        }
        if !e.meta.transcript_truncated && self.persist_event(id, &ev).is_err() {
            e.meta.transcript_truncated = true;
        }
        for tx in e.subscribers.values() {
            let _ = tx.try_send(ev.clone());
        }
    }

    fn persist_event(&self, id: &str, ev: &AgentEvent) -> std::io::Result<()> {
        let Some(dir) = self.transcript_dir() else {
            return Ok(());
        };
        if !valid_agent_session_id(id) {
            return Ok(());
        }
        create_private_dir(&dir)?;
        let root = cap_std::fs::Dir::open_ambient_dir(&dir, cap_std::ambient_authority())?;
        let mut opts = cap_std::fs::OpenOptions::new();
        opts.create(true).append(true);
        #[cfg(unix)]
        {
            use cap_std::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = root.open_with(format!("{id}.jsonl"), &opts)?;
        let mut line = runeward_ledger::gojson::marshal(ev).map_err(std::io::Error::other)?;
        line.push(b'\n');
        let size = f.metadata()?.len();
        if size + line.len() as u64 > MAX_AGENT_TRANSCRIPT_BYTES {
            return Err(std::io::Error::other(format!(
                "agent transcript exceeds {MAX_AGENT_TRANSCRIPT_BYTES} bytes"
            )));
        }
        f.write_all(&line)
    }

    /// Every event in a session's transcript.
    fn load_all_events(&self, id: &str) -> std::io::Result<Vec<AgentEvent>> {
        let Some(dir) = self.transcript_dir() else {
            return Ok(Vec::new());
        };
        let root = match cap_std::fs::Dir::open_ambient_dir(&dir, cap_std::ambient_authority()) {
            Ok(r) => r,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e),
        };
        let f = match root.open(format!("{id}.jsonl")) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e),
        };
        let mut events = Vec::new();
        let mut r = std::io::BufReader::new(f.into_std());
        let mut line = Vec::new();
        loop {
            line.clear();
            if r.read_until(b'\n', &mut line)? == 0 {
                break;
            }
            if line.len() > MAX_TRANSCRIPT_LINE {
                return Err(std::io::Error::other("transcript line too long"));
            }
            if let Ok(ev) = serde_json::from_slice::<AgentEvent>(&line) {
                events.push(ev);
            }
        }
        Ok(events)
    }

    fn load_recent_events(&self, id: &str) -> VecDeque<AgentEvent> {
        let mut events = self.load_all_events(id).unwrap_or_default();
        if events.len() > MAX_AGENT_EVENTS_MEMORY {
            events.drain(..events.len() - MAX_AGENT_EVENTS_MEMORY);
        }
        events.into()
    }

    /// Events after `after`, reading the transcript when the in-memory
    /// window does not reach back far enough.
    fn events_after(&self, e: &Entry, after: i64) -> Vec<AgentEvent> {
        let Some(first) = e.events.front() else {
            return Vec::new();
        };
        if after >= first.seq - 1 || self.state.dir().is_none() {
            return events_after(&e.events, after);
        }
        match self.load_all_events(&e.meta.id) {
            Ok(mut persisted) if !persisted.is_empty() => {
                let last = persisted.last().map_or(0, |ev| ev.seq);
                persisted.extend(e.events.iter().filter(|ev| ev.seq > last).cloned());
                events_after(&persisted, after)
            }
            _ => events_after(&e.events, after),
        }
    }

    fn snapshot(&self) -> Vec<AgentSession> {
        let mut out: Vec<AgentSession> = self
            .lock()
            .sessions
            .values()
            .map(|e| e.meta.clone())
            .collect();
        out.sort_by_key(|s| s.created_at);
        out
    }

    pub(crate) fn save(&self) -> Result<()> {
        if self.state.dir().is_none() {
            return Ok(());
        }
        self.state
            .write(AGENT_SESSIONS_FILE_NAME, &marshal_indent(&self.snapshot())?)
    }

    /// Restores sessions; one left queued or running is finished from the
    /// last status event in its transcript, else marked interrupted.
    pub(crate) fn load(&self) -> Result<()> {
        let Some(data) = self.state.read(AGENT_SESSIONS_FILE_NAME)? else {
            return Ok(());
        };
        let sessions: Vec<AgentSession> =
            serde_json::from_slice::<Option<Vec<AgentSession>>>(&data)
                .map_err(|e| Error::other(format!("decode {AGENT_SESSIONS_FILE_NAME}: {e}")))?
                .unwrap_or_default();
        let now = gotime::now();
        let mut interrupted = false;
        for mut meta in sessions {
            if !valid_agent_session_id(&meta.id) {
                continue;
            }
            let events = self.load_recent_events(&meta.id);
            if matches!(meta.status, AgentStatus::Queued | AgentStatus::Running) {
                let last = events
                    .back()
                    .filter(|e| e.stream == "status")
                    .map(|e| AgentStatus::parse(&e.data));
                match last {
                    Some(s) if s.is_terminal() => meta.status = s,
                    _ => {
                        meta.status = AgentStatus::Interrupted;
                        meta.error =
                            "control plane restarted before the agent session completed".into();
                    }
                }
                meta.finished_at = Some(now);
                interrupted = true;
            }
            if let Some(last) = events.back()
                && last.seq > meta.last_seq
            {
                meta.last_seq = last.seq;
            }
            self.lock().sessions.insert(
                meta.id.clone(),
                Entry {
                    meta,
                    events,
                    subscribers: HashMap::new(),
                    cancel: None,
                },
            );
        }
        if interrupted {
            self.save()?;
        }
        Ok(())
    }

    fn get(&self, id: &str) -> Option<AgentSession> {
        self.lock().sessions.get(id).map(|e| e.meta.clone())
    }

    fn update(&self, id: &str, f: impl FnOnce(&mut AgentSession)) {
        if let Some(e) = self.lock().sessions.get_mut(id) {
            f(&mut e.meta);
        }
    }

    /// Commits the final status event before exposing a terminal status, so
    /// a client that observes completion can fetch a complete backlog.
    fn finish(&self, id: &str, status: AgentStatus, exit_code: Option<i64>, message: String) {
        self.append(id, "status", status.as_str());
        let now = gotime::now();
        if let Some(e) = self.lock().sessions.get_mut(id) {
            e.meta.status = status;
            e.meta.exit_code = exit_code;
            e.meta.error = message;
            e.meta.finished_at = Some(now);
            e.cancel = None;
        }
        if let Err(e) = self.save() {
            tracing::warn!(error = %e, "runeward: persist agent session");
        }
        if let Some(e) = self.lock().sessions.get_mut(id) {
            e.subscribers.clear();
        }
    }

    /// Cancels running sessions on `citadel` (every Citadel when `None`).
    fn cancel_where(&self, citadel: Option<&str>) {
        for e in self.lock().sessions.values() {
            if citadel.is_none_or(|c| e.meta.citadel_id == c)
                && let Some(tx) = &e.cancel
            {
                let _ = tx.send(true);
            }
        }
    }

    pub(crate) fn cancel_for(&self, citadel: &str) {
        self.cancel_where(Some(citadel));
    }

    pub(crate) fn cancel_all(&self) {
        self.cancel_where(None);
    }

    pub(crate) async fn wait_all(&self) {
        let handles: Vec<_> = std::mem::take(
            &mut *self
                .tasks
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        for h in handles {
            let _ = h.await;
        }
    }

    fn track(&self, h: JoinHandle<()>) {
        let mut tasks = self
            .tasks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        tasks.retain(|t| !t.is_finished());
        tasks.push(h);
    }
}

/// Output streams an agent command writes to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stream {
    Stdout,
    Stderr,
}

impl Stream {
    fn as_str(self) -> &'static str {
        match self {
            Self::Stdout => "stdout",
            Self::Stderr => "stderr",
        }
    }
}

#[derive(Debug)]
enum PumpMsg {
    Data(Stream, Vec<u8>),
    Flush(oneshot::Sender<()>),
}

/// Hands exec output to the transcript pump; never blocks the backend.
struct EventWriter {
    tx: mpsc::UnboundedSender<PumpMsg>,
    stream: Stream,
}

impl AsyncWrite for EventWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        // A gone pump means the session already finished; drop the output.
        let _ = self.tx.send(PumpMsg::Data(self.stream, buf.to_vec()));
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// Splits buffered output into events: at each newline, or every 32 KiB
/// without one, exactly as the Go writer does.
fn drain_lines(pending: &mut Vec<u8>, mut emit: impl FnMut(&[u8])) {
    loop {
        let idx = pending.iter().position(|&b| b == b'\n');
        if idx.is_none() && pending.len() <= MAX_AGENT_EVENT_BYTES {
            return;
        }
        let end = match idx {
            Some(i) if i < MAX_AGENT_EVENT_BYTES => i + 1,
            _ => MAX_AGENT_EVENT_BYTES,
        };
        emit(&pending[..end]);
        pending.drain(..end);
    }
}

/// Runs on a blocking thread: turns raw output into scrubbed, persisted
/// events until every writer is gone.
fn pump(store: &AgentStore, sess: &Session, id: &str, mut rx: mpsc::UnboundedReceiver<PumpMsg>) {
    let mut out = Vec::new();
    let mut err = Vec::new();
    let emit = |stream: Stream, bytes: &[u8]| {
        let data = String::from_utf8_lossy(bytes);
        store.append(id, stream.as_str(), &sess.scrub(&data));
    };
    while let Some(msg) = rx.blocking_recv() {
        match msg {
            PumpMsg::Data(stream, bytes) => {
                let buf = match stream {
                    Stream::Stdout => &mut out,
                    Stream::Stderr => &mut err,
                };
                buf.extend_from_slice(&bytes);
                drain_lines(buf, |b| emit(stream, b));
            }
            PumpMsg::Flush(ack) => {
                for (stream, buf) in [(Stream::Stdout, &mut out), (Stream::Stderr, &mut err)] {
                    if !buf.is_empty() {
                        emit(stream, buf);
                        buf.clear();
                    }
                }
                let _ = ack.send(());
            }
        }
    }
}

async fn cancelled(rx: &mut watch::Receiver<bool>) {
    loop {
        if *rx.borrow_and_update() {
            return;
        }
        if rx.changed().await.is_err() {
            std::future::pending::<()>().await;
        }
    }
}

impl Manager {
    /// Launches a governed command asynchronously and returns as soon as its
    /// durable record exists. Arguments are scrubbed before they are stored.
    pub async fn start_agent_session(
        self: &Arc<Self>,
        citadel_id: &str,
        opts: StartAgentSessionOptions,
    ) -> Result<AgentSession> {
        let sess = self.session(citadel_id)?;
        if opts.command.is_empty() {
            return Err(Error::other("command is required"));
        }
        if !opts.cohort_id.is_empty() {
            let f = self
                .fleet(&opts.cohort_id)
                .ok_or_else(|| Error::other(format!("cohort {:?} not found", opts.cohort_id)))?;
            if !f.members().iter().any(|id| id == citadel_id) {
                return Err(Error::other(format!(
                    "citadel {citadel_id:?} is not a member of cohort {:?}",
                    opts.cohort_id
                )));
            }
            if !opts.task_id.is_empty() && f.board.get(&opts.task_id).is_none() {
                return Err(Error::other(format!(
                    "task {:?} not found in cohort {:?}",
                    opts.task_id, opts.cohort_id
                )));
            }
        }
        let actor = actor_or(&sess.actor);
        let meta = AgentSession {
            id: crate::new_id(),
            citadel_id: citadel_id.to_owned(),
            tenant: sess.owner.clone(),
            actor: actor.clone(),
            agent: opts.agent.trim().to_owned(),
            model: opts.model.trim().to_owned(),
            cohort_id: opts.cohort_id.trim().to_owned(),
            task_id: opts.task_id.trim().to_owned(),
            command: opts.command.iter().map(|a| sess.scrub(a)).collect(),
            status: AgentStatus::Queued,
            exit_code: None,
            error: String::new(),
            created_at: gotime::now(),
            started_at: None,
            finished_at: None,
            last_seq: 0,
            transcript_truncated: false,
        };
        let (cancel_tx, cancel_rx) = watch::channel(false);
        let id = meta.id.clone();
        self.agents.lock().sessions.insert(
            id.clone(),
            Entry {
                meta: meta.clone(),
                events: VecDeque::new(),
                subscribers: HashMap::new(),
                cancel: Some(cancel_tx),
            },
        );
        let store = Arc::clone(&self.agents);
        if let Err(e) = blocking(move || store.save()).await {
            self.agents.lock().sessions.remove(&id);
            return Err(Error::other(format!("persist agent session: {e}")));
        }
        let mgr = Arc::clone(self);
        let command = opts.command;
        let handle = tokio::spawn(async move {
            with_actor(&actor, mgr.run_agent_session(sess, id, command, cancel_rx)).await;
        });
        self.agents.track(handle);
        Ok(meta)
    }

    async fn run_agent_session(
        &self,
        sess: Arc<Session>,
        id: String,
        command: Vec<String>,
        mut cancel: watch::Receiver<bool>,
    ) {
        let store = Arc::clone(&self.agents);
        let sid = id.clone();
        let _ = blocking(move || {
            store.update(&sid, |m| {
                m.status = AgentStatus::Running;
                m.started_at = Some(gotime::now());
            });
            let _ = store.save();
            store.append(&sid, "status", AgentStatus::Running.as_str());
            Ok(())
        })
        .await;

        let (tx, rx) = mpsc::unbounded_channel();
        {
            let (store, sess, id) = (Arc::clone(&self.agents), Arc::clone(&sess), id.clone());
            // Detached: it ends when the last writer is dropped.
            drop(tokio::task::spawn_blocking(move || {
                pump(&store, &sess, &id, rx)
            }));
        }
        let req = ExecRequest {
            command: command.clone(),
            workdir: sess.workdir.clone(),
            env: sess.env.clone(),
            stdout: Some(Box::new(EventWriter {
                tx: tx.clone(),
                stream: Stream::Stdout,
            })),
            stderr: Some(Box::new(EventWriter {
                tx: tx.clone(),
                stream: Stream::Stderr,
            })),
            stream_only: true,
            ..ExecRequest::default()
        };
        let arg = command.join(" ");
        let call = GovernCall::new("shell", &arg, command.clone());
        let citadel = sess.sandbox.id.clone();
        // Cancellation wins over a result that is ready at the same time.
        let outcome = tokio::select! {
            biased;
            () = cancelled(&mut cancel) => None,
            r = self.govern(&sess, call, || sess.backend.exec(&citadel, req)) => Some(r),
        };
        // Drain buffered partial lines before the terminal status.
        let (ack_tx, ack_rx) = oneshot::channel();
        if tx.send(PumpMsg::Flush(ack_tx)).is_ok() {
            let _ = ack_rx.await;
        }
        drop(tx);

        let (status, exit_code, message) = match outcome {
            None => {
                self.record(
                    &sess,
                    "shell",
                    &arg,
                    &command,
                    "error",
                    -1,
                    0,
                    "context canceled",
                )
                .await;
                (
                    AgentStatus::Canceled,
                    None,
                    "agent session canceled".to_owned(),
                )
            }
            Some(Err(e)) => (AgentStatus::Failed, None, e.to_string()),
            Some(Ok(res)) if res.verdict != Verdict::Allow => {
                (AgentStatus::Denied, None, res.reason)
            }
            Some(Ok(res)) if res.exit_code != 0 => (
                AgentStatus::Failed,
                Some(res.exit_code),
                format!("agent exited with status {}", res.exit_code),
            ),
            Some(Ok(res)) => (AgentStatus::Completed, Some(res.exit_code), String::new()),
        };
        let store = Arc::clone(&self.agents);
        let _ = blocking(move || {
            store.finish(&id, status, exit_code, message);
            Ok(())
        })
        .await;
    }

    /// Stops a running agent session; reports whether one was running.
    pub fn cancel_agent_session(&self, id: &str) -> bool {
        let inner = self.agents.lock();
        match inner.sessions.get(id).and_then(|e| e.cancel.as_ref()) {
            Some(tx) => tx.send(true).is_ok(),
            None => false,
        }
    }

    /// Sessions in creation order, optionally scoped to one Cohort. Tenant
    /// filtering is the transport's job.
    pub fn agent_sessions(&self, cohort_id: &str) -> Vec<AgentSession> {
        self.agents
            .snapshot()
            .into_iter()
            .filter(|s| cohort_id.is_empty() || s.cohort_id == cohort_id)
            .collect()
    }

    /// One session's metadata.
    pub fn agent_session(&self, id: &str) -> Option<AgentSession> {
        self.agents.get(id)
    }

    /// A session with its events after sequence number `after`.
    pub async fn agent_session_events(
        &self,
        id: &str,
        after: i64,
    ) -> Option<(AgentSession, Vec<AgentEvent>)> {
        let store = Arc::clone(&self.agents);
        let id = id.to_owned();
        blocking(move || {
            let inner = store.lock();
            Ok(inner
                .sessions
                .get(&id)
                .map(|e| (e.meta.clone(), store.events_after(e, after))))
        })
        .await
        .ok()
        .flatten()
    }

    /// Returns the backlog after `after` and registers a live subscription
    /// in one step, so replay and follow mode leave no gap. A finished
    /// session's subscription ends immediately after the backlog.
    pub async fn subscribe_agent_session(&self, id: &str, after: i64) -> Option<AgentSubscription> {
        let store = Arc::clone(&self.agents);
        let sid = id.to_owned();
        blocking(move || {
            let mut inner = store.lock();
            inner.next_sub += 1;
            let sub_id = inner.next_sub;
            let Some(e) = inner.sessions.get_mut(&sid) else {
                return Ok(None);
            };
            let (tx, rx) = mpsc::channel(SUBSCRIBER_BUFFER);
            if !e.meta.status.is_terminal() {
                e.subscribers.insert(sub_id, tx);
            }
            let session = e.meta.clone();
            let backlog = store.events_after(e, after);
            drop(inner);
            Ok(Some(AgentSubscription {
                session,
                backlog,
                events: rx,
                store: Arc::clone(&store),
                session_id: sid,
                sub_id,
            }))
        })
        .await
        .ok()
        .flatten()
    }

    pub(crate) async fn load_agent_sessions(&self) -> Result<()> {
        let store = Arc::clone(&self.agents);
        blocking(move || store.load()).await
    }

    /// Test hook: appends an event as the transcript pump would.
    #[cfg(test)]
    pub(crate) async fn append_agent_event(&self, id: &str, stream: &str, data: &str) {
        let (store, id, stream, data) = (
            Arc::clone(&self.agents),
            id.to_owned(),
            stream.to_owned(),
            data.to_owned(),
        );
        let _ = blocking(move || {
            store.append(&id, &stream, &data);
            Ok(())
        })
        .await;
    }

    /// Test hook: registers a session record without running anything.
    #[cfg(test)]
    pub(crate) fn insert_agent_session(&self, meta: AgentSession) {
        self.agents.lock().sessions.insert(
            meta.id.clone(),
            Entry {
                meta,
                events: VecDeque::new(),
                subscribers: HashMap::new(),
                cancel: None,
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_like_the_go_writer() {
        let mut got = Vec::new();
        let mut pending = b"a\nbc\nrest".to_vec();
        drain_lines(&mut pending, |b| got.push(b.to_vec()));
        assert_eq!(got, [b"a\n".to_vec(), b"bc\n".to_vec()]);
        assert_eq!(pending, b"rest");

        let mut got = Vec::new();
        let mut pending = vec![b'x'; MAX_AGENT_EVENT_BYTES * 2 + 3];
        drain_lines(&mut pending, |b| got.push(b.len()));
        assert_eq!(got, [MAX_AGENT_EVENT_BYTES, MAX_AGENT_EVENT_BYTES]);
        assert_eq!(pending.len(), 3);

        // A newline past the 32 KiB mark still cuts at 32 KiB first.
        let mut pending = vec![b'y'; MAX_AGENT_EVENT_BYTES + 10];
        pending.push(b'\n');
        let mut got = Vec::new();
        drain_lines(&mut pending, |b| got.push(b.len()));
        assert_eq!(got, [MAX_AGENT_EVENT_BYTES, 11]);
        assert!(pending.is_empty());
    }

    #[test]
    fn status_machine() {
        use AgentStatus::*;
        assert!(Queued.can_transition(&Running));
        assert!(Running.can_transition(&Completed));
        assert!(Queued.can_transition(&Canceled));
        assert!(!Completed.can_transition(&Running));
        assert!(!Running.can_transition(&Queued));
        assert!(Interrupted.is_terminal() && !Running.is_terminal());
        assert_eq!(AgentStatus::parse("weird"), Other("weird".into()));
        assert!(valid_agent_session_id(&crate::new_id()));
        assert!(!valid_agent_session_id("../../etc/passwd"));
    }
}
