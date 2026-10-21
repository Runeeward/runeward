//! Governed sandbox sessions and their lifecycle.
//!
//! A [`Session`] is the per-sandbox governed state: the backend handle, the
//! Charter, its authority engine and guardrails, resolved environment and
//! secrets, and the run lineage every Chronicle event carries.
//!
//! # Lifecycle
//!
//! ```text
//!   Creating ──▶ Running ──▶ Terminating ──▶ Terminated
//!                 │   ▲
//!                 ▼   │          (persistent workspaces)
//!               Sleeping ──▶ Waking ──▶ Running
//! ```
//!
//! Only `Running` sessions accept tool calls. `Sleeping` and `Waking` are
//! for Charters with `[workspace] persist = true`: a sleep stops the
//! sandbox (keeping its disk) while the session and its run stay alive, and
//! the next governed call, terminal attach or agent turn wakes it under the
//! same id (see the crate's `workspaces` module).

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::ops::Deref;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use runeward_backend::{Backend, IsolationTier, Sandbox};
use runeward_charter::Charter;
use runeward_egress::Broker;
use runeward_ledger::Scrubber;
use runeward_policy::{Evaluator, Guard, RuleEngine};
use serde::Serialize;
use tokio::task::JoinHandle;

use crate::error::{Error, Result};
use crate::governance::IsolationEvidence;

/// Where a session is in its lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SessionState {
    /// The sandbox is being provisioned and verified.
    Creating,
    /// Ready for governed tool calls.
    Running,
    /// The workspace is persisted and the sandbox's compute released.
    Sleeping,
    /// The sandbox is being resumed from its sleeping workspace.
    Waking,
    /// Being torn down; no new calls are accepted.
    Terminating,
    /// Gone. Only the run record and Chronicle remain.
    Terminated,
}

impl SessionState {
    /// Reports whether `self -> next` is a legal transition.
    pub fn can_transition(self, next: Self) -> bool {
        use SessionState::*;
        matches!(
            (self, next),
            (Creating, Running | Terminating)
                | (Running, Sleeping | Terminating)
                | (Sleeping, Waking | Terminating)
                | (Waking, Running | Terminating)
                | (Terminating, Terminated)
        )
    }

    /// Reports whether tool calls may run.
    pub fn accepts_calls(self) -> bool {
        self == Self::Running
    }

    /// The lowercase name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Creating => "creating",
            Self::Running => "running",
            Self::Sleeping => "sleeping",
            Self::Waking => "waking",
            Self::Terminating => "terminating",
            Self::Terminated => "terminated",
        }
    }
}

impl fmt::Display for SessionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// When a session last did something, and how many governed operations
/// (calls, terminals, agent turns) are in flight. Drives idle sleep.
#[derive(Debug)]
pub(crate) struct Activity {
    last: Mutex<tokio::time::Instant>,
    inflight: AtomicUsize,
}

impl Default for Activity {
    fn default() -> Self {
        Self {
            last: Mutex::new(tokio::time::Instant::now()),
            inflight: AtomicUsize::new(0),
        }
    }
}

impl Activity {
    pub(crate) fn touch(&self) {
        *lock(&self.last) = tokio::time::Instant::now();
    }

    pub(crate) fn idle_for(&self) -> Duration {
        lock(&self.last).elapsed()
    }

    pub(crate) fn inflight(&self) -> usize {
        self.inflight.load(Ordering::SeqCst)
    }

    /// Test hook: pretends the last activity was `by` ago.
    #[cfg(test)]
    pub(crate) fn backdate(&self, by: Duration) {
        let mut last = lock(&self.last);
        *last = tokio::time::Instant::now().checked_sub(by).unwrap_or(*last);
    }
}

/// A session held awake: while it lives the session counts as busy and
/// cannot be put to sleep. Dropping it records the activity.
#[derive(Debug)]
pub(crate) struct Busy(Arc<Session>);

impl Busy {
    pub(crate) fn enter(sess: Arc<Session>) -> Self {
        sess.activity.inflight.fetch_add(1, Ordering::SeqCst);
        sess.activity.touch();
        Self(sess)
    }

    pub(crate) fn arc(&self) -> &Arc<Session> {
        &self.0
    }
}

impl Deref for Busy {
    type Target = Session;

    fn deref(&self) -> &Session {
        &self.0
    }
}

impl Drop for Busy {
    fn drop(&mut self) {
        self.0.activity.touch();
        self.0.activity.inflight.fetch_sub(1, Ordering::SeqCst);
    }
}

/// One live in-sandbox browser driver.
#[derive(Debug, Clone)]
pub(crate) struct BrowserSession {
    pub(crate) socket: String,
    pub(crate) token: String,
}

/// The per-sandbox governed state.
pub struct Session {
    pub(crate) sandbox: Sandbox,
    pub(crate) backend: Arc<dyn Backend>,
    pub(crate) charter: Charter,
    pub(crate) engine: Box<dyn Evaluator>,
    pub(crate) guard: Guard,
    pub(crate) env: BTreeMap<String, String>,
    pub(crate) workdir: String,
    /// Tenant boundary for visibility and access control; empty without RBAC.
    pub(crate) owner: String,
    /// The principal that created the session (events default to it).
    pub(crate) actor: String,
    pub(crate) run_id: String,
    pub(crate) parent_run_id: String,
    /// The run this session's workspace was forked from.
    pub(crate) forked_from: String,
    /// How a delegated child's or fork's Charter was admitted against its
    /// parent's (`exact`, `subsumed`, `admin-override`); empty otherwise.
    pub(crate) charter_lineage: String,
    /// The parent (or fork source) Charter the lineage check compared to.
    pub(crate) parent_charter: String,
    /// What the subsumption check proved (or, for an admin override, why
    /// it refused).
    pub(crate) charter_proof: String,
    pub(crate) agent: String,
    pub(crate) provider: String,
    pub(crate) model: String,
    /// Resolved secret values, redacted from every payload.
    pub(crate) secrets: Vec<String>,
    pub(crate) scrubber: Scrubber,
    pub(crate) state: Mutex<SessionState>,
    pub(crate) browsers: Mutex<HashMap<String, BrowserSession>>,
    pub(crate) ide_endpoint: Mutex<String>,
    /// The request broker for `[[endpoint]]`/`[[credential]]` Charters.
    pub(crate) broker: Option<Arc<Broker>>,
    /// What the in-sandbox supervisor reported enforcing.
    pub(crate) enforcement: Option<IsolationEvidence>,
    /// Background work tied to the session (the broker decision pump),
    /// aborted when it ends.
    pub(crate) tasks: Mutex<Vec<JoinHandle<()>>>,
    /// Idle tracking for persistent workspaces.
    pub(crate) activity: Activity,
    /// Serializes sleep and wake.
    pub(crate) lifecycle: tokio::sync::Mutex<()>,
}

impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session")
            .field("sandbox", &self.sandbox.id)
            .field("backend", &self.backend.name())
            .field("charter", &self.charter.name)
            .field("owner", &self.owner)
            .field("actor", &self.actor)
            .field("run_id", &self.run_id)
            .field("state", &self.state())
            .finish_non_exhaustive()
    }
}

pub(crate) fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl Session {
    /// Starts building a session around an existing sandbox. Used by the
    /// control plane itself and by transports' tests to inject a session
    /// without a backend create (Go's `InjectSession`).
    pub fn builder(
        sandbox: Sandbox,
        backend: Arc<dyn Backend>,
        charter: Charter,
    ) -> SessionBuilder {
        SessionBuilder {
            workdir: charter.host.workdir.clone(),
            sandbox,
            backend,
            charter,
            engine: None,
            guard: None,
            env: BTreeMap::new(),
            owner: String::new(),
            actor: String::new(),
            run_id: String::new(),
            parent_run_id: String::new(),
            forked_from: String::new(),
            charter_lineage: String::new(),
            parent_charter: String::new(),
            charter_proof: String::new(),
            agent: String::new(),
            provider: String::new(),
            model: String::new(),
            secrets: Vec::new(),
            scrubber: None,
            broker: None,
            enforcement: None,
        }
    }

    /// The sandbox handle.
    pub fn sandbox(&self) -> &Sandbox {
        &self.sandbox
    }

    /// The governing Charter.
    pub fn charter(&self) -> &Charter {
        &self.charter
    }

    /// The tenant that owns the session.
    pub fn owner(&self) -> &str {
        &self.owner
    }

    /// The principal that created the session.
    pub fn actor(&self) -> &str {
        &self.actor
    }

    /// The run this session belongs to.
    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    /// The run this session's workspace was forked from (empty if none).
    pub fn forked_from(&self) -> &str {
        &self.forked_from
    }

    /// Moves straight to `next`, bypassing the transition table (used to
    /// roll a failed sleep or wake back).
    pub(crate) fn force_state(&self, next: SessionState) {
        *lock(&self.state) = next;
    }

    /// The isolation tier the backend reported for this sandbox.
    pub fn isolation(&self) -> IsolationTier {
        self.sandbox.isolation
    }

    /// What the in-sandbox supervisor reported enforcing, when the sandbox
    /// was asked to run under it.
    pub fn enforcement(&self) -> Option<&IsolationEvidence> {
        self.enforcement.as_ref()
    }

    /// The request broker, for Charters with endpoints or credentials.
    pub fn broker(&self) -> Option<&Arc<Broker>> {
        self.broker.as_ref()
    }

    /// Stops the session's background work.
    pub(crate) fn stop_tasks(&self) {
        for t in lock(&self.tasks).drain(..) {
            t.abort();
        }
    }

    /// The current lifecycle state.
    pub fn state(&self) -> SessionState {
        *lock(&self.state)
    }

    /// Moves to `next` when the transition is legal.
    pub(crate) fn transition(&self, next: SessionState) -> Result<()> {
        let mut s = lock(&self.state);
        if !s.can_transition(next) {
            return Err(Error::bad_input(format!(
                "citadel {:?} cannot go from {} to {next}",
                self.sandbox.id, *s
            )));
        }
        *s = next;
        Ok(())
    }

    pub(crate) fn ensure_running(&self) -> Result<()> {
        let s = self.state();
        if s.accepts_calls() {
            Ok(())
        } else {
            Err(Error::bad_input(format!(
                "citadel {:?} is {s}",
                self.sandbox.id
            )))
        }
    }

    pub(crate) fn scrub(&self, s: &str) -> String {
        self.scrubber.scrub_string(s, &self.secrets)
    }
}

/// Builds a [`Session`].
pub struct SessionBuilder {
    sandbox: Sandbox,
    backend: Arc<dyn Backend>,
    charter: Charter,
    engine: Option<Box<dyn Evaluator>>,
    guard: Option<Guard>,
    env: BTreeMap<String, String>,
    workdir: String,
    owner: String,
    actor: String,
    run_id: String,
    parent_run_id: String,
    forked_from: String,
    charter_lineage: String,
    parent_charter: String,
    charter_proof: String,
    agent: String,
    provider: String,
    model: String,
    secrets: Vec<String>,
    scrubber: Option<Scrubber>,
    broker: Option<Arc<Broker>>,
    enforcement: Option<IsolationEvidence>,
}

impl fmt::Debug for SessionBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionBuilder")
            .field("sandbox", &self.sandbox.id)
            .finish_non_exhaustive()
    }
}

macro_rules! setters {
    ($($(#[$m:meta])* $name:ident),* $(,)?) => {
        $(
            $(#[$m])*
            #[must_use]
            pub fn $name(mut self, v: impl Into<String>) -> Self {
                self.$name = v.into();
                self
            }
        )*
    };
}

impl SessionBuilder {
    setters!(
        /// Working directory for tool calls (default `host.workdir`).
        workdir,
        /// Tenant owner.
        owner,
        /// Creating principal.
        actor,
        /// Run id (default: a fresh id).
        run_id,
        /// Parent run for delegated children.
        parent_run_id,
        /// The run a forked workspace was copied from.
        forked_from,
        /// How the Charter was admitted against its parent's.
        charter_lineage,
        /// The parent Charter the lineage check compared to.
        parent_charter,
        /// The lineage check's proof summary.
        charter_proof,
        /// Agent name.
        agent,
        /// Model provider.
        provider,
        /// Model name.
        model,
    );

    /// The authority engine (default: the Charter's `[[policy]]` rules with
    /// an allow default).
    #[must_use]
    pub fn engine(mut self, engine: Box<dyn Evaluator>) -> Self {
        self.engine = Some(engine);
        self
    }

    /// The guardrails (default: built from the Charter's limits).
    #[must_use]
    pub fn guard(mut self, guard: Guard) -> Self {
        self.guard = Some(guard);
        self
    }

    /// Resolved environment passed to every exec.
    #[must_use]
    pub fn env(mut self, env: BTreeMap<String, String>) -> Self {
        self.env = env;
        self
    }

    /// Secret values to redact.
    #[must_use]
    pub fn secrets(mut self, secrets: Vec<String>) -> Self {
        self.secrets = secrets;
        self
    }

    /// The scrubber (default: built-in patterns only).
    #[must_use]
    pub fn scrubber(mut self, scrubber: Scrubber) -> Self {
        self.scrubber = Some(scrubber);
        self
    }

    /// The sandbox's request broker.
    #[must_use]
    pub fn broker(mut self, broker: Arc<Broker>) -> Self {
        self.broker = Some(broker);
        self
    }

    /// The supervisor's reported enforcement.
    #[must_use]
    pub fn enforcement(mut self, evidence: IsolationEvidence) -> Self {
        self.enforcement = Some(evidence);
        self
    }

    /// Builds a running session.
    pub fn build(self) -> Result<Session> {
        let guard = match self.guard {
            Some(g) => g,
            None => {
                let g = Guard::new(&self.charter.limits).map_err(Error::other)?;
                g.start();
                g
            }
        };
        let engine = self.engine.unwrap_or_else(|| {
            Box::new(RuleEngine::new(
                self.charter.policy.clone(),
                runeward_charter::Verdict::Allow,
            ))
        });
        let run_id = if self.run_id.trim().is_empty() {
            crate::new_id()
        } else {
            self.run_id
        };
        Ok(Session {
            sandbox: self.sandbox,
            backend: self.backend,
            charter: self.charter,
            engine,
            guard,
            env: self.env,
            workdir: self.workdir,
            owner: self.owner,
            actor: self.actor,
            run_id,
            parent_run_id: self.parent_run_id,
            forked_from: self.forked_from,
            charter_lineage: self.charter_lineage,
            parent_charter: self.parent_charter,
            charter_proof: self.charter_proof,
            agent: self.agent,
            provider: self.provider,
            model: self.model,
            secrets: self.secrets,
            scrubber: self.scrubber.unwrap_or_default(),
            state: Mutex::new(SessionState::Running),
            browsers: Mutex::new(HashMap::new()),
            ide_endpoint: Mutex::new(String::new()),
            broker: self.broker,
            enforcement: self.enforcement,
            tasks: Mutex::new(Vec::new()),
            activity: Activity::default(),
            lifecycle: tokio::sync::Mutex::new(()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transitions() {
        use SessionState::*;
        assert!(Creating.can_transition(Running));
        assert!(Running.can_transition(Terminating));
        assert!(Running.can_transition(Sleeping));
        assert!(Sleeping.can_transition(Waking));
        assert!(Waking.can_transition(Running));
        assert!(Terminating.can_transition(Terminated));
        assert!(!Terminated.can_transition(Running));
        assert!(!Running.can_transition(Creating));
        assert!(
            !Sleeping.can_transition(Running),
            "a wake goes through Waking"
        );
        assert!(Running.accepts_calls());
        for s in [Creating, Sleeping, Waking, Terminating, Terminated] {
            assert!(!s.accepts_calls(), "{s}");
        }
    }
}
