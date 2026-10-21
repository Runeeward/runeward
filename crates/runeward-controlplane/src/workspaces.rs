//! Persistent workspaces: idle sleep, transparent wake and restart recovery
//! (`workspaces.json`).
//!
//! A Citadel whose Charter sets `[workspace] persist = true` keeps its disk
//! across stop/start. After `idle_timeout` with no governed calls, attached
//! terminals or running agent turns it goes `Sleeping`: the backend stops
//! the sandbox (Docker/Podman keep the container and its volumes;
//! Kubernetes deletes the Pod and keeps the PVC) while the session, its
//! run, broker and supervisor plan stay in the control plane. The next
//! governed call, terminal attach or agent turn wakes it (`Waking` →
//! `Running`) under the same id and environment. Every sleep and wake is
//! Chronicled as tool `workspace`.
//!
//! Only what is on disk survives a sleep. Processes, open browser
//! sessions, `/tmp` on a read-only root and anything in memory are gone
//! after a wake.
//!
//! # Restart recovery
//!
//! Each persistent Citadel has a record in `workspaces.json` (identity,
//! lineage, Charter and state). When the Manager starts it rediscovers
//! them as sleeping workspaces: they are listed, owned and addressable,
//! their runs stay `running`, and the first call rebuilds the governed
//! session (Charter, secrets, broker, supervisor, policy) and asks the
//! backend to resume the sandbox around its kept workspace. A workspace
//! that was running when the control plane stopped is put to sleep in the
//! background, since its broker and proxy died with the old process.

use std::collections::HashMap;
use std::sync::Arc;

use runeward_backend::{IsolationTier, Sandbox, spec_from_charter, verify_runtime_capabilities};
use runeward_charter::Verdict;
use runeward_ledger::gotime::{self, Time};
use runeward_ledger::{Event, Scrubber};
use runeward_policy::Guard;
use serde::{Deserialize, Serialize};

use crate::actor::actor_or;
use crate::citadels::check_isolation_floor;
use crate::env::{compile_scrub_patterns, new_engine, resolve_env};
use crate::error::{Error, Result};
use crate::governance::supervisor_spec;
use crate::manager::Manager;
use crate::sessions::{Busy, Session, SessionState, lock};
use crate::statefile::marshal_indent;
use crate::timefmt::nullable;

pub(crate) const WORKSPACES_FILE_NAME: &str = "workspaces.json";

/// How many times a call retries waking a workspace that went back to
/// sleep under it before giving up.
const WAKE_ATTEMPTS: usize = 3;

/// The durable record of one persistent Citadel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceRecord {
    #[serde(default, deserialize_with = "nullable")]
    pub citadel_id: String,
    #[serde(default, deserialize_with = "nullable")]
    pub profile: String,
    #[serde(default, deserialize_with = "nullable")]
    pub backend: String,
    #[serde(
        default,
        deserialize_with = "nullable",
        skip_serializing_if = "String::is_empty"
    )]
    pub image: String,
    #[serde(default)]
    pub isolation: IsolationTier,
    /// `running` or `sleeping`.
    #[serde(default, deserialize_with = "nullable")]
    pub state: String,
    #[serde(
        default,
        deserialize_with = "nullable",
        skip_serializing_if = "String::is_empty"
    )]
    pub owner: String,
    #[serde(
        default,
        deserialize_with = "nullable",
        skip_serializing_if = "String::is_empty"
    )]
    pub actor: String,
    #[serde(default, deserialize_with = "nullable")]
    pub run_id: String,
    #[serde(
        default,
        deserialize_with = "nullable",
        skip_serializing_if = "String::is_empty"
    )]
    pub parent_run_id: String,
    #[serde(
        default,
        deserialize_with = "nullable",
        skip_serializing_if = "String::is_empty"
    )]
    pub forked_from: String,
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
    pub provider: String,
    #[serde(
        default,
        deserialize_with = "nullable",
        skip_serializing_if = "String::is_empty"
    )]
    pub model: String,
    #[serde(with = "crate::timefmt", default = "gotime::zero")]
    pub created_at: Time,
    #[serde(
        with = "crate::timefmt::opt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub slept_at: Option<Time>,
    #[serde(
        with = "crate::timefmt::opt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub woke_at: Option<Time>,
}

impl WorkspaceRecord {
    pub(crate) fn sandbox(&self) -> Sandbox {
        Sandbox {
            id: self.citadel_id.clone(),
            profile: self.profile.clone(),
            backend: self.backend.clone(),
            image: self.image.clone(),
            status: SessionState::Sleeping.as_str().into(),
            created_at: self.created_at.with_timezone(&chrono::Utc),
            endpoint: String::new(),
            isolation: self.isolation,
            // A sleeping workspace has no live evidence; wake re-probes.
            isolation_evidence: None,
        }
    }
}

/// A persistent Citadel's workspace status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WorkspaceStatus {
    pub citadel_id: String,
    /// The session state (`running`, `sleeping`, `waking`, ...).
    pub state: String,
    /// The Charter's idle timeout in seconds (0: never sleeps on idle).
    pub idle_timeout_secs: u64,
    /// Seconds since the last governed activity (0 while asleep).
    pub idle_secs: u64,
    #[serde(with = "crate::timefmt::opt", skip_serializing_if = "Option::is_none")]
    pub slept_at: Option<Time>,
    #[serde(with = "crate::timefmt::opt", skip_serializing_if = "Option::is_none")]
    pub woke_at: Option<Time>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub forked_from: String,
}

/// A sandbox handle whose status reflects a sleeping or waking session.
pub(crate) fn live_sandbox(sess: &Session) -> Sandbox {
    let mut sb = sess.sandbox.clone();
    if let s @ (SessionState::Sleeping | SessionState::Waking) = sess.state() {
        s.as_str().clone_into(&mut sb.status);
    }
    sb
}

impl Manager {
    /// Reports whether `id` is a persistent Citadel the control plane
    /// tracks (live or asleep).
    pub(crate) fn is_workspace(&self, id: &str) -> bool {
        lock(&self.workspaces).contains_key(id)
    }

    /// A workspace known only from `workspaces.json` (rediscovered after a
    /// restart and not woken yet).
    pub(crate) fn dormant(&self, id: &str) -> Option<WorkspaceRecord> {
        if self.session_opt(id).is_some() {
            return None;
        }
        lock(&self.workspaces).get(id).cloned()
    }

    /// Every rediscovered, not yet woken workspace.
    pub(crate) fn dormant_records(&self) -> Vec<WorkspaceRecord> {
        let sessions = lock(&self.sessions);
        lock(&self.workspaces)
            .values()
            .filter(|r| !sessions.contains_key(&r.citadel_id))
            .cloned()
            .collect()
    }

    /// The workspace status of a persistent Citadel, or `None` for an
    /// unknown or non-persistent one.
    pub fn workspace_status(&self, id: &str) -> Option<WorkspaceStatus> {
        let rec = lock(&self.workspaces).get(id).cloned()?;
        let sess = self.session_opt(id);
        let state = sess.as_ref().map_or(SessionState::Sleeping, |s| s.state());
        let idle_timeout_secs = sess
            .as_ref()
            .and_then(|s| s.charter.idle_timeout())
            .map_or(0, |d| d.as_secs());
        let idle_secs = match &sess {
            Some(s) if state == SessionState::Running => s.activity.idle_for().as_secs(),
            _ => 0,
        };
        Some(WorkspaceStatus {
            citadel_id: rec.citadel_id,
            state: state.as_str().into(),
            idle_timeout_secs,
            idle_secs,
            slept_at: rec.slept_at,
            woke_at: rec.woke_at,
            forked_from: rec.forked_from,
        })
    }

    /// Records (or refreshes) a live persistent session in
    /// `workspaces.json`.
    pub(crate) async fn track_workspace(&self, sess: &Session) -> Result<()> {
        let state = match sess.state() {
            SessionState::Sleeping => "sleeping",
            _ => "running",
        };
        self.update_workspace(sess, |r| state.clone_into(&mut r.state))
            .await
    }

    /// Applies `f` to a session's workspace record (creating it) and
    /// persists the file.
    async fn update_workspace(
        &self,
        sess: &Session,
        f: impl FnOnce(&mut WorkspaceRecord),
    ) -> Result<()> {
        let _op = self.workspace_op.lock().await;
        let previous = {
            let mut map = lock(&self.workspaces);
            let prev = map.get(&sess.sandbox.id).cloned();
            let mut rec = prev.clone().unwrap_or_else(|| WorkspaceRecord {
                citadel_id: sess.sandbox.id.clone(),
                profile: sess.charter.name.clone(),
                backend: sess.sandbox.backend.clone(),
                image: sess.sandbox.image.clone(),
                isolation: sess.isolation(),
                state: "running".into(),
                owner: sess.owner.clone(),
                actor: sess.actor.clone(),
                run_id: sess.run_id.clone(),
                parent_run_id: sess.parent_run_id.clone(),
                forked_from: sess.forked_from.clone(),
                agent: sess.agent.clone(),
                provider: sess.provider.clone(),
                model: sess.model.clone(),
                created_at: gotime::now(),
                slept_at: None,
                woke_at: None,
            });
            f(&mut rec);
            map.insert(rec.citadel_id.clone(), rec);
            prev
        };
        if let Err(e) = self.save_workspaces().await {
            let mut map = lock(&self.workspaces);
            match previous {
                Some(p) => map.insert(p.citadel_id.clone(), p),
                None => map.remove(&sess.sandbox.id),
            };
            return Err(Error::other(format!("persist workspace: {e}")));
        }
        Ok(())
    }

    /// Forgets a workspace (its Citadel was killed).
    pub(crate) async fn untrack_workspace(&self, id: &str) {
        let _op = self.workspace_op.lock().await;
        if lock(&self.workspaces).remove(id).is_some()
            && let Err(e) = self.save_workspaces().await
        {
            tracing::error!(citadel = %id, error = %e, "runeward: persist workspace removal");
        }
    }

    async fn save_workspaces(&self) -> Result<()> {
        if self.state.dir().is_none() {
            return Ok(());
        }
        let mut recs: Vec<WorkspaceRecord> = lock(&self.workspaces).values().cloned().collect();
        recs.sort_by(|a, b| (a.created_at, &a.citadel_id).cmp(&(b.created_at, &b.citadel_id)));
        self.write_state(WORKSPACES_FILE_NAME, marshal_indent(&recs)?)
            .await
    }

    /// Rediscovers persistent workspaces. Any that was running when the
    /// control plane stopped is marked sleeping (its in-process broker and
    /// proxy are gone) and returned so the caller can stop it.
    pub(crate) async fn load_workspaces(&self) -> Result<Vec<WorkspaceRecord>> {
        let Some(data) = self.read_state(WORKSPACES_FILE_NAME).await? else {
            return Ok(Vec::new());
        };
        let recs: Vec<WorkspaceRecord> =
            serde_json::from_slice::<Option<Vec<WorkspaceRecord>>>(&data)
                .map_err(|e| Error::other(format!("decode {WORKSPACES_FILE_NAME}: {e}")))?
                .unwrap_or_default();
        let mut was_running = Vec::new();
        {
            let mut map = lock(&self.workspaces);
            for mut r in recs {
                if r.citadel_id.is_empty() {
                    continue;
                }
                if r.state != "sleeping" {
                    r.state = "sleeping".into();
                    r.slept_at = Some(gotime::now());
                    was_running.push(r.clone());
                }
                map.insert(r.citadel_id.clone(), r);
            }
        }
        if !was_running.is_empty() {
            self.save_workspaces().await?;
        }
        Ok(was_running)
    }

    /// Stops sandboxes left running by a previous control-plane process,
    /// keeping their workspaces. Best effort: a failure is logged and the
    /// next wake rebuilds the sandbox anyway.
    pub(crate) async fn stop_orphaned(&self, recs: Vec<WorkspaceRecord>) {
        for r in recs {
            let stopped = async {
                let c = self.load_profile(&r.profile).await?;
                let be = self.registry.open(&c, &self.backend_config).await?;
                be.stop(&r.citadel_id).await.map_err(Error::from)
            }
            .await;
            if let Err(e) = stopped {
                tracing::warn!(citadel = %r.citadel_id, error = %e, "runeward: stop workspace left running by a previous control plane");
            }
        }
    }

    /// The governed session for `id`, woken if it sleeps (rebuilt first if
    /// it was rediscovered after a restart), held busy so it cannot fall
    /// asleep while the caller uses it.
    pub(crate) async fn awake_session(&self, id: &str) -> Result<Busy> {
        for _ in 0..WAKE_ATTEMPTS {
            if let Some(sess) = self.session_opt(id) {
                let busy = Busy::enter(sess);
                match busy.state() {
                    SessionState::Running => return Ok(busy),
                    SessionState::Sleeping | SessionState::Waking => {
                        let sess = Arc::clone(busy.arc());
                        drop(busy);
                        self.wake_session(&sess, "activity").await?;
                    }
                    s => {
                        return Err(Error::bad_input(format!("citadel {id:?} is {s}")));
                    }
                }
            } else if self.dormant(id).is_some() {
                self.recover_workspace(id).await?;
            } else {
                return Err(Error::not_found(format!("sandbox {id:?} not found")));
            }
        }
        Err(Error::conflict(
            "citadel_busy",
            format!("citadel {id:?} kept going back to sleep while waking"),
        ))
    }

    /// Wakes a sleeping persistent Citadel (a no-op when it is running).
    pub async fn wake_citadel(&self, id: &str) -> Result<()> {
        drop(self.awake_session(id).await?);
        Ok(())
    }

    /// Puts a persistent Citadel to sleep now. Refused while governed
    /// calls, terminals or agent turns are active (`citadel_busy`).
    /// Reports whether it was running.
    pub async fn sleep_citadel(&self, id: &str) -> Result<bool> {
        if self.session_opt(id).is_none() && self.dormant(id).is_some() {
            return Ok(false);
        }
        self.sleep_session(id, "manual").await
    }

    async fn sleep_session(&self, id: &str, reason: &str) -> Result<bool> {
        let sess = self.session(id)?;
        if !sess.charter.persists_workspace() {
            return Err(Error::bad_input(format!(
                "citadel {id:?} does not persist its workspace (set [workspace] persist = true)"
            )));
        }
        if !sess.backend.supports_sleep() {
            return Err(Error::bad_input(format!(
                "the {} backend cannot put citadels to sleep",
                sess.backend.name()
            )));
        }
        let _l = sess.lifecycle.lock().await;
        match sess.state() {
            SessionState::Running => {}
            SessionState::Sleeping => return Ok(false),
            s => return Err(Error::bad_input(format!("citadel {id:?} is {s}"))),
        }
        let busy = || {
            Error::conflict(
                "citadel_busy",
                format!("citadel {id:?} has active calls, terminals or agent turns"),
            )
        };
        if self.agents.running_on(id) {
            return Err(busy());
        }
        // Block new calls first, then look for ones already inside: a call
        // enters before it checks the state, so one of the two sides sees
        // the other.
        sess.transition(SessionState::Sleeping)?;
        if sess.activity.inflight() > 0 {
            sess.force_state(SessionState::Running);
            return Err(busy());
        }
        if let Err(e) = sess.backend.stop(id).await {
            sess.force_state(SessionState::Running);
            self.record(
                &sess,
                "workspace",
                "sleep",
                &[],
                "error",
                -1,
                0,
                &e.to_string(),
            )
            .await;
            return Err(e.into());
        }
        // In-sandbox browser drivers died with the processes.
        lock(&sess.browsers).clear();
        self.record(
            &sess,
            "workspace",
            "sleep",
            &[],
            Verdict::Allow.as_str(),
            0,
            0,
            reason,
        )
        .await;
        if let Err(e) = self
            .update_workspace(&sess, |r| {
                r.state = "sleeping".into();
                r.slept_at = Some(gotime::now());
            })
            .await
        {
            tracing::error!(citadel = %id, error = %e, "runeward: persist workspace sleep");
        }
        Ok(true)
    }

    /// Resumes a sleeping in-memory session through its backend.
    async fn wake_session(&self, sess: &Arc<Session>, reason: &str) -> Result<()> {
        let _l = sess.lifecycle.lock().await;
        match sess.state() {
            SessionState::Sleeping => {}
            SessionState::Running => return Ok(()),
            s => {
                return Err(Error::bad_input(format!(
                    "citadel {:?} is {s}",
                    sess.sandbox.id
                )));
            }
        }
        sess.transition(SessionState::Waking)?;
        let mut spec = spec_from_charter(&sess.charter, sess.env.clone());
        spec.id.clone_from(&sess.sandbox.id);
        spec.broker = sess.broker.clone().map(runeward_backend::BrokerHandle::new);
        spec.supervisor = supervisor_spec(&sess.charter, sess.broker.is_some())?;
        if let Err(e) = sess.backend.start(&sess.sandbox.id, spec).await {
            sess.force_state(SessionState::Sleeping);
            self.record(
                sess,
                "workspace",
                "wake",
                &[],
                "error",
                -1,
                0,
                &e.to_string(),
            )
            .await;
            return Err(Error::other(format!("wake citadel: {e}")));
        }
        sess.transition(SessionState::Running)?;
        sess.activity.touch();
        self.record(
            sess,
            "workspace",
            "wake",
            &[],
            Verdict::Allow.as_str(),
            0,
            0,
            reason,
        )
        .await;
        if let Err(e) = self
            .update_workspace(sess, |r| {
                r.state = "running".into();
                r.woke_at = Some(gotime::now());
            })
            .await
        {
            tracing::error!(citadel = %sess.sandbox.id, error = %e, "runeward: persist workspace wake");
        }
        Ok(())
    }

    /// Rebuilds the governed session of a workspace rediscovered after a
    /// restart and resumes its sandbox around the kept workspace.
    async fn recover_workspace(&self, id: &str) -> Result<()> {
        let gate = {
            let mut locks = lock(&self.recover_locks);
            Arc::clone(locks.entry(id.to_owned()).or_default())
        };
        let _g = gate.lock().await;
        let Some(rec) = self.dormant(id) else {
            // Someone else rebuilt (or killed) it while we waited.
            return Ok(());
        };
        let res = self.rebuild_session(&rec).await;
        lock(&self.recover_locks).remove(id);
        res
    }

    async fn rebuild_session(&self, rec: &WorkspaceRecord) -> Result<()> {
        let id = rec.citadel_id.as_str();
        let mut c = self.load_profile(&rec.profile).await?;
        let extra = compile_scrub_patterns(&c.audit.scrub_patterns)?;
        let (mut env, mut secrets) = resolve_env(&c, &self.resolver).await?;
        let gov = self
            .prepare_governance_for(&c, &mut env, &mut secrets, Some(id))
            .await?;
        let be = self.registry.open(&c, &self.backend_config).await?;
        let mut spec = spec_from_charter(&c, env.clone());
        gov.apply(&mut spec);
        spec.id = id.to_owned();
        let mut sb = be
            .start(id, spec)
            .await
            .map_err(|e| Error::other(format!("wake citadel: {e}")))?;
        sb.created_at = rec.created_at.with_timezone(&chrono::Utc);
        // From here on a failure puts the sandbox back to sleep: the
        // workspace must survive a refused wake.
        let back_to_sleep = || async {
            let _ = be.stop(id).await;
        };
        if let Err(e) =
            check_isolation_floor(&c, be.name(), sb.isolation, sb.isolation_evidence.as_ref())
        {
            back_to_sleep().await;
            return Err(e);
        }
        let (evidence, report_line) = match self.verify_governance(be.as_ref(), &sb, &gov).await {
            Ok(Some((ev, line))) => (Some(ev), line),
            Ok(None) => (None, String::new()),
            Err(e) => {
                back_to_sleep().await;
                return Err(e);
            }
        };
        if let Err(e) = verify_runtime_capabilities(be.as_ref(), id, &mut c).await {
            back_to_sleep().await;
            return Err(e.into());
        }
        let guard = match Guard::new(&c.limits) {
            Ok(g) => g,
            Err(e) => {
                back_to_sleep().await;
                return Err(Error::other(e));
            }
        };
        guard.start();
        let engine = match new_engine(&c, self.config.policy_default.as_deref()).await {
            Ok(e) => e,
            Err(e) => {
                back_to_sleep().await;
                return Err(e);
            }
        };
        let actor = if rec.actor.is_empty() {
            &rec.owner
        } else {
            &rec.actor
        };
        let mut builder = Session::builder(sb, Arc::clone(&be), c)
            .engine(engine)
            .guard(guard)
            .env(env)
            .owner(rec.owner.clone())
            .actor(actor.clone())
            .run_id(rec.run_id.clone())
            .parent_run_id(rec.parent_run_id.clone())
            .forked_from(rec.forked_from.clone())
            .agent(rec.agent.clone())
            .provider(rec.provider.clone())
            .model(rec.model.clone())
            .secrets(secrets)
            .scrubber(Scrubber::new(extra));
        if let Some(b) = &gov.broker {
            builder = builder.broker(Arc::clone(b));
        }
        if let Some(ev) = evidence {
            builder = builder.enforcement(ev);
        }
        let sess = match builder.build() {
            Ok(s) => Arc::new(s),
            Err(e) => {
                back_to_sleep().await;
                return Err(e);
            }
        };
        lock(&self.sessions).insert(id.to_owned(), Arc::clone(&sess));
        self.attach_governance(&sess, gov, &report_line).await;
        if let Err(e) = self.start_ide(&sess).await {
            tracing::warn!(citadel = %id, error = %e, "runeward: restart ide after wake");
        }
        self.record(
            &sess,
            "workspace",
            "wake",
            &[],
            Verdict::Allow.as_str(),
            0,
            0,
            "recovered after control-plane restart",
        )
        .await;
        if let Err(e) = self
            .update_workspace(&sess, |r| {
                r.state = "running".into();
                r.woke_at = Some(gotime::now());
            })
            .await
        {
            tracing::error!(citadel = %id, error = %e, "runeward: persist workspace wake");
        }
        Ok(())
    }

    /// Tears down a workspace that is only known from `workspaces.json`.
    pub(crate) async fn kill_dormant(&self, rec: WorkspaceRecord) -> Result<()> {
        let id = rec.citadel_id.clone();
        let killed = async {
            let c = self.load_profile(&rec.profile).await?;
            let be = self.registry.open(&c, &self.backend_config).await?;
            be.kill(&id).await.map_err(Error::from)
        }
        .await;
        let mut ev = Event {
            session_id: id.clone(),
            sandbox: id.clone(),
            profile: rec.profile.clone(),
            tool: "sandbox".into(),
            action: "kill".into(),
            verdict: Verdict::Allow.as_str().into(),
            ..Event::default()
        };
        ev.meta.insert("run_id".into(), rec.run_id.clone());
        ev.meta
            .insert("isolation".into(), rec.isolation.as_str().into());
        let actor = actor_or(&rec.actor);
        for (k, v) in [("tenant", rec.owner.as_str()), ("actor", actor.as_str())] {
            if !v.is_empty() {
                ev.meta.insert(k.into(), v.into());
            }
        }
        self.append_audit(ev).await;
        self.untrack_workspace(&id).await;
        let run = self
            .finish_run(
                &rec.run_id,
                killed.as_ref().err().map(ToString::to_string).as_deref(),
            )
            .await;
        killed?;
        run
    }

    /// Puts every persistent Citadel that has been idle past its Charter's
    /// `idle_timeout` to sleep. Returns the ids that went to sleep.
    pub async fn sleep_idle_once(&self) -> Vec<String> {
        let candidates: Vec<Arc<Session>> = lock(&self.sessions).values().cloned().collect();
        let mut slept = Vec::new();
        for sess in candidates {
            let Some(timeout) = sess.charter.idle_timeout() else {
                continue;
            };
            let id = sess.sandbox.id.clone();
            if sess.state() != SessionState::Running
                || !sess.backend.supports_sleep()
                || sess.activity.inflight() > 0
                || sess.activity.idle_for() < timeout
                || !lock(&sess.ide_endpoint).is_empty()
                || self.agents.running_on(&id)
            {
                continue;
            }
            match self.sleep_session(&id, "idle").await {
                Ok(true) => slept.push(id),
                Ok(false) => {}
                Err(e) if e.code() == Some("citadel_busy") => {}
                Err(e) => {
                    tracing::warn!(citadel = %id, error = %e, "runeward: idle sleep failed");
                }
            }
        }
        slept
    }
}

/// Per-workspace locks serializing restart recovery.
pub(crate) type RecoverLocks = HashMap<String, Arc<tokio::sync::Mutex<()>>>;
