//! The [`Manager`]: construction, shared state and the Chronicle path.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use base64::Engine as _;
use runeward_auditsink::Sink;
use runeward_backend::{BackendConfig, Registry};
use runeward_charter::Verdict;
use runeward_fleet::LeaseSigner;
use runeward_ledger::{Event, Ledger, Signer};
use runeward_policy::accounting::{Tracker, Usage};
use runeward_secrets::Dispatcher;
use tokio::task::JoinHandle;

use crate::actor::actor_or;
use crate::agent_sessions::AgentStore;
use crate::approvals::ApprovalStore;
use crate::config::ManagerConfig;
use crate::conversation::ConversationHub;
use crate::error::{Error, Result};
use crate::fleet::Fleet;
use crate::runs::Run;
use crate::sessions::{Session, lock};
use crate::snapshots::SnapshotState;
use crate::statefile::StateDir;

/// The ledger file name inside the state directory.
pub const LEDGER_FILE_NAME: &str = "ledger.jsonl";

/// The control-plane core. Every tool call runs through one path: policy,
/// approval gate, guardrails, backend exec, audit ledger. The Manager owns
/// sandbox sessions and the shared ledger; the REST, MCP and CLI layers are
/// thin adapters over it.
///
/// Share it as `Arc<Manager>`; it is `Send + Sync`. Methods that spawn work
/// (agent sessions, the lease sweeper) take `self: &Arc<Self>`.
pub struct Manager {
    pub(crate) config: ManagerConfig,
    pub(crate) registry: Registry,
    pub(crate) backend_config: BackendConfig,
    pub(crate) resolver: Arc<Dispatcher>,
    pub(crate) ledger: Arc<Ledger>,
    pub(crate) signer: Option<Signer>,
    pub(crate) approvals: ApprovalStore,
    /// Real-time audit fan-out; never blocks.
    pub(crate) sink: Arc<dyn Sink>,
    pub(crate) accounting: Tracker,
    pub(crate) sessions: Mutex<HashMap<String, Arc<Session>>>,
    pub(crate) snapshots: Mutex<SnapshotState>,
    pub(crate) snap_op: tokio::sync::Mutex<()>,
    pub(crate) fleets: Mutex<HashMap<String, Arc<Fleet>>>,
    /// Makes each board mutation plus durable replacement one transaction,
    /// including rollback on write failure.
    pub(crate) fleet_op: tokio::sync::Mutex<()>,
    pub(crate) runs: Mutex<HashMap<String, Run>>,
    pub(crate) run_op: tokio::sync::Mutex<()>,
    pub(crate) conversation: ConversationHub,
    pub(crate) agents: Arc<AgentStore>,
    pub(crate) state: Arc<StateDir>,
    pub(crate) lease: LeaseSigner,
    sweeper: Mutex<Option<JoinHandle<()>>>,
}

impl std::fmt::Debug for Manager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Manager")
            .field("state_dir", &self.state.dir())
            .field("ledger", &self.ledger.path())
            .field("signed", &self.signer.is_some())
            .field("registry", &self.registry)
            .finish_non_exhaustive()
    }
}

/// Builds a [`Manager`] with explicit dependencies; [`Manager::open`] wires
/// everything from the environment.
pub struct ManagerBuilder {
    config: ManagerConfig,
    registry: Registry,
    backend_config: BackendConfig,
    resolver: Option<Dispatcher>,
    sink: Option<Arc<dyn Sink>>,
    ledger_path: Option<PathBuf>,
}

impl std::fmt::Debug for ManagerBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ManagerBuilder")
            .field("config", &self.config)
            .field("ledger_path", &self.ledger_path)
            .finish_non_exhaustive()
    }
}

impl ManagerBuilder {
    /// The sandbox drivers (default: Docker/Podman and Kubernetes).
    #[must_use]
    pub fn registry(mut self, registry: Registry) -> Self {
        self.registry = registry;
        self
    }

    /// Backend operator settings (default: empty, i.e. built-in defaults).
    #[must_use]
    pub fn backend_config(mut self, config: BackendConfig) -> Self {
        self.backend_config = config;
        self
    }

    /// The secret resolver for `[[env]]` references (default: from env).
    #[must_use]
    pub fn resolver(mut self, resolver: Dispatcher) -> Self {
        self.resolver = Some(resolver);
        self
    }

    /// The audit fan-out (default: none).
    #[must_use]
    pub fn sink(mut self, sink: Arc<dyn Sink>) -> Self {
        self.sink = Some(sink);
        self
    }

    /// The ledger file (default: `<state_dir>/ledger.jsonl`). Required when
    /// the config has no state directory.
    #[must_use]
    pub fn ledger_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.ledger_path = Some(path.into());
        self
    }

    /// Opens the ledger (and signing key), restores Cohorts, snapshots,
    /// runs and agent sessions from the state directory, and starts the
    /// lease sweeper.
    pub async fn build(self) -> Result<Arc<Manager>> {
        let ManagerBuilder {
            config,
            registry,
            backend_config,
            resolver,
            sink,
            ledger_path,
        } = self;
        let state = StateDir::new(config.state_dir.clone());
        let ledger_path = match (ledger_path, state.dir()) {
            (Some(p), _) => p,
            (None, Some(d)) => d.join(LEDGER_FILE_NAME),
            (None, None) => {
                return Err(Error::other(
                    "control plane needs a state directory or a ledger path",
                ));
            }
        };
        let sign = config.sign_ledger;
        let state_dir = state.dir().map(Path::to_path_buf);
        let (ledger, signer, lease) = tokio::task::spawn_blocking(move || {
            open_ledger(&ledger_path, sign, state_dir.as_deref())
        })
        .await
        .map_err(Error::other)??;

        let mgr = Arc::new(Manager {
            agents: AgentStore::new(Arc::clone(&state)),
            config,
            registry,
            backend_config,
            resolver: Arc::new(resolver.unwrap_or_else(Dispatcher::from_env)),
            ledger: Arc::new(ledger),
            signer,
            approvals: ApprovalStore::new(),
            sink: sink.unwrap_or_else(|| Arc::new(runeward_auditsink::Multi::default())),
            accounting: Tracker::new(),
            sessions: Mutex::new(HashMap::new()),
            snapshots: Mutex::new(SnapshotState::default()),
            snap_op: tokio::sync::Mutex::new(()),
            fleets: Mutex::new(HashMap::new()),
            fleet_op: tokio::sync::Mutex::new(()),
            runs: Mutex::new(HashMap::new()),
            run_op: tokio::sync::Mutex::new(()),
            conversation: ConversationHub::default(),
            state,
            lease,
            sweeper: Mutex::new(None),
        });
        mgr.load_fleets().await?;
        mgr.load_snapshots().await?;
        mgr.load_runs().await?;
        mgr.load_agent_sessions().await?;
        if let Some(every) = mgr.config.sweep_interval {
            mgr.start_sweeper(every);
        }
        Ok(mgr)
    }
}

/// Opens the ledger, attaches the signer when enabled, and loads (or
/// creates) the Cohort lease key. Without a state directory the lease key
/// is ephemeral.
fn open_ledger(
    path: &Path,
    sign: bool,
    state_dir: Option<&Path>,
) -> Result<(Ledger, Option<Signer>, LeaseSigner)> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        crate::statefile::create_private_dir(parent)?;
    }
    let ledger = Ledger::open(path)?;
    let signer = if sign {
        let dir = path.parent().unwrap_or_else(|| Path::new("."));
        let s = Signer::load_or_create(dir)?;
        ledger.set_signer(Some(s.clone()));
        Some(s)
    } else {
        None
    };
    let lease = match state_dir {
        Some(d) => LeaseSigner::load_or_create(d).map_err(Error::other)?,
        None => LeaseSigner::new(rand::random::<[u8; 32]>().to_vec()),
    };
    Ok((ledger, signer, lease))
}

impl Manager {
    /// Wires a Manager from the process environment like the Go `New`:
    /// state under `$RUNEWARD_STATE_DIR` (or the user cache dir), signing
    /// unless `RUNEWARD_LEDGER_SIGN=off`, audit sinks from
    /// `RUNEWARD_AUDIT_*` plus the anomaly detector, and the built-in
    /// backend drivers.
    pub async fn open(config_dir: Option<PathBuf>) -> Result<Arc<Self>> {
        let mut config = ManagerConfig::from_env();
        config.config_dir = config_dir.filter(|d| !d.as_os_str().is_empty());
        let env_sink = runeward_auditsink::from_env()
            .map_err(|e| Error::other(format!("configure audit sink: {e}")))?;
        let sink = runeward_auditsink::Multi::new(vec![
            Box::new(env_sink),
            Box::new(runeward_auditsink::anomaly::Detector::new()),
        ]);
        Self::builder(config)
            .backend_config(BackendConfig::from_env())
            .sink(Arc::new(sink))
            .build()
            .await
    }

    /// Starts a [`ManagerBuilder`].
    pub fn builder(config: ManagerConfig) -> ManagerBuilder {
        ManagerBuilder {
            config,
            registry: Registry::with_defaults(),
            backend_config: BackendConfig::default(),
            resolver: None,
            sink: None,
            ledger_path: None,
        }
    }

    /// The active configuration.
    pub fn config(&self) -> &ManagerConfig {
        &self.config
    }

    /// Reports whether the ledger is signed.
    pub fn signed(&self) -> bool {
        self.signer.is_some()
    }

    /// The shared ledger. Its methods block; call them from
    /// `spawn_blocking` in async code.
    pub fn ledger(&self) -> &Arc<Ledger> {
        &self.ledger
    }

    /// The state directory (ledger, keys, recordings, state files).
    pub fn state_dir(&self) -> Option<&Path> {
        self.state.dir()
    }

    /// The approval inbox.
    pub fn approvals(&self) -> &ApprovalStore {
        &self.approvals
    }

    /// The base64 signing key and key id, or `None` when signing is off.
    pub fn ledger_public_key(&self) -> Option<(String, String)> {
        let s = self.signer.as_ref()?;
        Some((
            base64::engine::general_purpose::STANDARD.encode(s.public().as_bytes()),
            s.key_id().to_owned(),
        ))
    }

    /// A verifiable transcript of a session's events (every event when
    /// `session_id` is empty). Fails when signing is disabled.
    pub async fn export_bundle(&self, session_id: &str) -> Result<Vec<u8>> {
        let Some(signer) = self.signer.clone() else {
            return Err(Error::other(
                "ledger signing is disabled; no verifiable transcript to export",
            ));
        };
        let ledger = Arc::clone(&self.ledger);
        let session_id = session_id.to_owned();
        blocking(move || {
            let mut out = Vec::new();
            ledger.export_bundle(&mut out, &session_id, &signer.public())?;
            Ok(out)
        })
        .await
    }

    /// Checks the hash chain and, when signing is on, every signature.
    pub async fn verify_ledger(&self) -> Result<()> {
        let ledger = Arc::clone(&self.ledger);
        let signer = self.signer.clone();
        blocking(move || match signer {
            Some(s) => Ok(ledger.verify_signatures(Some(&s.public()), false)?),
            None => Ok(ledger.verify()?),
        })
        .await
    }

    /// Stops the sweeper, cancels and waits for agent sessions, flushes the
    /// audit sinks and releases the ledger.
    pub async fn close(&self) -> Result<()> {
        let sweeper = lock(&self.sweeper).take();
        if let Some(h) = sweeper {
            h.abort();
            let _ = h.await;
        }
        self.agents.cancel_all();
        self.agents.wait_all().await;
        let sink = Arc::clone(&self.sink);
        let ledger = Arc::clone(&self.ledger);
        blocking(move || {
            let _ = sink.close();
            ledger.close();
            Ok(())
        })
        .await
    }

    /// Resolves a pending approval and records who decided it, so every
    /// human-in-the-loop decision is attributed. Reports whether it was
    /// pending.
    pub async fn resolve_approval(&self, id: &str, approve: bool, actor: &str) -> bool {
        let Some(view) = self.approvals.resolve_view(id, approve) else {
            return false;
        };
        let actor = if actor.trim().is_empty() {
            "unknown"
        } else {
            actor
        };
        let (decision, verdict) = if approve {
            ("approved", Verdict::Allow)
        } else {
            ("denied", Verdict::Deny)
        };
        let mut ev = Event {
            session_id: view.sandbox.clone(),
            sandbox: view.sandbox.clone(),
            tool: "approval".into(),
            action: view.action.clone(),
            args: vec![view.tool.clone()],
            verdict: verdict.as_str().to_owned(),
            ..Event::default()
        };
        ev.meta.insert("decision".into(), decision.into());
        ev.meta.insert("approver".into(), actor.into());
        ev.meta.insert("approval_id".into(), view.id.clone());
        if !view.reason.is_empty() {
            ev.meta.insert("reason".into(), view.reason.clone());
        }
        let ev = match self.session_opt(&view.sandbox) {
            Some(sess) => {
                ev.profile.clone_from(&sess.charter.name);
                if sess.charter.audit.redact_enabled() {
                    sess.scrubber.scrub(ev, &sess.secrets)
                } else {
                    ev
                }
            }
            None => runeward_ledger::scrub::<&str>(ev, &[]),
        };
        runeward_obs::record_action("approval", verdict.as_str(), 0);
        self.append_audit(ev).await;
        true
    }

    /// Writes an event to the ledger (logging, not dropping, a failure so a
    /// broken audit trail is visible) and fans it out to the sinks.
    pub(crate) async fn append_audit(&self, ev: Event) {
        let ledger = Arc::clone(&self.ledger);
        let (tool, verdict) = (ev.tool.clone(), ev.verdict.clone());
        let stored = tokio::task::spawn_blocking(move || {
            let res = ledger.append(ev.clone());
            (ev, res)
        })
        .await;
        match stored {
            Ok((ev, res)) => {
                if let Err(e) = res {
                    tracing::error!(%tool, %verdict, error = %e, "runeward: audit ledger append failed");
                }
                self.sink.emit(&ev);
            }
            Err(e) => {
                tracing::error!(%tool, %verdict, error = %e, "runeward: audit ledger append task failed");
            }
        }
    }

    /// Appends one session event with run lineage, tenant, actor and the
    /// sandbox's isolation tier in `meta`, scrubbed when the Charter redacts.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn record(
        &self,
        sess: &Session,
        tool: &str,
        action: &str,
        args: &[String],
        verdict: &str,
        exit: i64,
        dur_ms: i64,
        reason: &str,
    ) {
        let mut ev = Event {
            session_id: sess.sandbox.id.clone(),
            sandbox: sess.sandbox.id.clone(),
            profile: sess.charter.name.clone(),
            tool: tool.to_owned(),
            action: action.to_owned(),
            args: args.to_vec(),
            verdict: verdict.to_owned(),
            exit_code: exit,
            duration_ms: dur_ms,
            ..Event::default()
        };
        let meta = &mut ev.meta;
        meta.insert("run_id".into(), sess.run_id.clone());
        meta.insert("isolation".into(), sess.isolation().as_str().into());
        let actor = actor_or(&sess.actor);
        for (k, v) in [
            ("tenant", sess.owner.as_str()),
            ("actor", actor.as_str()),
            ("parent_run_id", sess.parent_run_id.as_str()),
            ("agent", sess.agent.as_str()),
            ("provider", sess.provider.as_str()),
            ("model", sess.model.as_str()),
            ("reason", reason),
        ] {
            if !v.is_empty() {
                meta.insert(k.into(), v.into());
            }
        }
        runeward_obs::record_action(tool, verdict, dur_ms);
        // Declared secrets are hashed and credential-shaped substrings
        // masked, keeping the trail readable.
        if sess.charter.audit.redact_enabled() {
            ev = sess.scrubber.scrub(ev, &sess.secrets);
        }
        self.append_audit(ev).await;
    }

    /// Cumulative reported usage for a sandbox.
    pub fn sandbox_usage(&self, id: &str) -> Usage {
        self.accounting.usage(id)
    }

    pub(crate) fn session(&self, id: &str) -> Result<Arc<Session>> {
        self.session_opt(id)
            .ok_or_else(|| Error::not_found(format!("sandbox {id:?} not found")))
    }

    pub(crate) fn session_opt(&self, id: &str) -> Option<Arc<Session>> {
        lock(&self.sessions).get(id).cloned()
    }

    /// Persists `data` as state file `name` off the async runtime.
    pub(crate) async fn write_state(&self, name: &'static str, data: Vec<u8>) -> Result<()> {
        let state = Arc::clone(&self.state);
        blocking(move || state.write(name, &data)).await
    }

    /// Reads state file `name` off the async runtime.
    pub(crate) async fn read_state(&self, name: &'static str) -> Result<Option<Vec<u8>>> {
        let state = Arc::clone(&self.state);
        blocking(move || Ok(state.read(name)?)).await
    }

    fn start_sweeper(self: &Arc<Self>, every: Duration) {
        if every.is_zero() {
            return;
        }
        let weak: Weak<Self> = Arc::downgrade(self);
        let handle = tokio::spawn(async move {
            let mut tick = tokio::time::interval(every);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            tick.tick().await;
            loop {
                tick.tick().await;
                let Some(m) = weak.upgrade() else { return };
                m.sweep_once().await;
            }
        });
        *lock(&self.sweeper) = Some(handle);
    }
}

/// Runs blocking work (ledger and state-file I/O) off the async runtime.
pub(crate) async fn blocking<T, F>(f: F) -> Result<T>
where
    F: FnOnce() -> Result<T> + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| Error::other(format!("blocking task: {e}")))?
}
