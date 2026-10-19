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
//!                 ▼   │          (reserved: persistent workspaces)
//!               Sleeping ──▶ Waking ──▶ Running
//! ```
//!
//! Only `Running` sessions accept tool calls. `Sleeping` and `Waking` are
//! reserved for workspaces that persist across idle periods: a sleep will
//! snapshot or stop the sandbox and keep the session (and its run) alive, a
//! wake will restore it. No transition into them exists yet, but the guard
//! in [`SessionState::accepts_calls`] and the transition table are where
//! that feature plugs in.

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard};

use runeward_backend::{Backend, IsolationTier, Sandbox};
use runeward_charter::Charter;
use runeward_ledger::Scrubber;
use runeward_policy::{Evaluator, Guard, RuleEngine};
use serde::Serialize;

use crate::error::{Error, Result};

/// Where a session is in its lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SessionState {
    /// The sandbox is being provisioned and verified.
    Creating,
    /// Ready for governed tool calls.
    Running,
    /// Reserved: the workspace is persisted and the sandbox released.
    Sleeping,
    /// Reserved: the sandbox is being restored from its sleeping workspace.
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
    pub(crate) agent: String,
    pub(crate) provider: String,
    pub(crate) model: String,
    /// Resolved secret values, redacted from every payload.
    pub(crate) secrets: Vec<String>,
    pub(crate) scrubber: Scrubber,
    pub(crate) state: Mutex<SessionState>,
    pub(crate) browsers: Mutex<HashMap<String, BrowserSession>>,
    pub(crate) ide_endpoint: Mutex<String>,
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
            agent: String::new(),
            provider: String::new(),
            model: String::new(),
            secrets: Vec::new(),
            scrubber: None,
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

    /// The isolation tier the backend reported for this sandbox.
    pub fn isolation(&self) -> IsolationTier {
        self.sandbox.isolation
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
    agent: String,
    provider: String,
    model: String,
    secrets: Vec<String>,
    scrubber: Option<Scrubber>,
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
            agent: self.agent,
            provider: self.provider,
            model: self.model,
            secrets: self.secrets,
            scrubber: self.scrubber.unwrap_or_default(),
            state: Mutex::new(SessionState::Running),
            browsers: Mutex::new(HashMap::new()),
            ide_endpoint: Mutex::new(String::new()),
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
