//! Cohorts: sandboxes from one Charter sharing an atomic task board with
//! signed task leases, persisted in `fleets.json`.

use std::sync::Arc;

use runeward_charter::Verdict;
use runeward_fleet::{Board, Stats, Task, TaskState};
use runeward_ledger::Event;
use runeward_ledger::gotime::{self, Time};
use serde::{Deserialize, Serialize};

use crate::citadels::CreateOptions;
use crate::error::{Error, Result};
use crate::manager::Manager;
use crate::sessions::lock;
use crate::statefile::marshal_indent;
use crate::timefmt::nullable;

pub(crate) const FLEETS_FILE_NAME: &str = "fleets.json";

/// A set of sandboxes from one Charter sharing a task board.
#[derive(Debug)]
pub struct Fleet {
    pub(crate) id: String,
    pub(crate) profile: String,
    pub(crate) owner: String,
    pub(crate) board: Board,
    /// `None` preserves a Go `null` from disk.
    pub(crate) sandboxes: Option<Vec<String>>,
    pub(crate) created: Time,
    /// Loaded from disk: the board survived but the sandboxes were not
    /// recreated.
    pub(crate) restored: bool,
}

impl Fleet {
    fn view(&self) -> FleetView {
        FleetView {
            id: self.id.clone(),
            profile: self.profile.clone(),
            owner: self.owner.clone(),
            sandboxes: self.sandboxes.clone(),
            stats: self.board.stats(),
            created: self.created,
        }
    }

    pub(crate) fn members(&self) -> &[String] {
        self.sandboxes.as_deref().unwrap_or_default()
    }

    /// Reports whether the Cohort was restored from disk (its sandboxes are
    /// not running).
    pub fn restored(&self) -> bool {
        self.restored
    }
}

/// The JSON projection of a Cohort.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct FleetView {
    pub id: String,
    pub profile: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub owner: String,
    pub sandboxes: Option<Vec<String>>,
    pub stats: Stats,
    #[serde(with = "crate::timefmt")]
    pub created: Time,
}

/// The on-disk projection of a Cohort (Go's `persistedFleet`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct PersistedFleet {
    #[serde(default, deserialize_with = "nullable")]
    pub(crate) id: String,
    #[serde(default, deserialize_with = "nullable")]
    pub(crate) profile: String,
    #[serde(
        default,
        deserialize_with = "nullable",
        skip_serializing_if = "String::is_empty"
    )]
    pub(crate) owner: String,
    #[serde(default)]
    pub(crate) sandboxes: Option<Vec<String>>,
    #[serde(with = "crate::timefmt", default = "gotime::zero")]
    pub(crate) created: Time,
    #[serde(default)]
    pub(crate) tasks: Option<Vec<Task>>,
}

fn not_found(id: &str) -> Error {
    Error::not_found(format!("fleet {id:?} not found"))
}

impl Manager {
    /// Provisions a Charter's replicas with a shared board seeded from its
    /// `[cohort] task_board`.
    pub async fn create_fleet(&self, profile: &str) -> Result<FleetView> {
        self.create_fleet_for_identity(profile, "", "").await
    }

    /// Creates a tenant-owned Cohort whose member Citadels are attributed
    /// to the requesting actor.
    pub async fn create_fleet_for_identity(
        &self,
        profile: &str,
        owner: &str,
        actor: &str,
    ) -> Result<FleetView> {
        let c = self.load_profile(profile).await?;
        let (replicas, seed) = match &c.fleet {
            Some(f) => (f.replicas.max(1), f.task_board.clone()),
            None => (1, Vec::new()),
        };
        let board = Board::seed(seed);
        board.set_lease(self.config.fleet_lease);
        let mut sandboxes = Vec::new();
        for i in 0..replicas {
            let opts = CreateOptions {
                owner: owner.to_owned(),
                actor: if actor.is_empty() { owner } else { actor }.to_owned(),
                ..CreateOptions::default()
            };
            match self.create_sandbox(profile, opts).await {
                Ok(sb) => sandboxes.push(sb.id),
                Err(e) => {
                    for id in &sandboxes {
                        let _ = self.kill_sandbox(id).await;
                    }
                    return Err(Error::other(format!(
                        "provision fleet replica {}/{replicas}: {e}",
                        i + 1
                    )));
                }
            }
        }
        let f = Arc::new(Fleet {
            id: crate::new_id(),
            profile: profile.to_owned(),
            owner: owner.to_owned(),
            board,
            sandboxes: Some(sandboxes),
            created: gotime::now(),
            restored: false,
        });
        let _op = self.fleet_op.lock().await;
        lock(&self.fleets).insert(f.id.clone(), Arc::clone(&f));
        if let Err(e) = self.save_fleets().await {
            lock(&self.fleets).remove(&f.id);
            for id in f.members() {
                let _ = self.kill_sandbox(id).await;
            }
            return Err(Error::other(format!("persist cohort: {e}")));
        }
        Ok(f.view())
    }

    /// Every Cohort.
    pub fn list_fleets(&self) -> Vec<FleetView> {
        lock(&self.fleets).values().map(|f| f.view()).collect()
    }

    /// One Cohort's projection.
    pub fn fleet_view(&self, id: &str) -> Option<FleetView> {
        self.fleet(id).map(|f| f.view())
    }

    /// The owner of a Cohort: `None` when unknown, `Some("")` when unowned.
    pub fn fleet_owner(&self, id: &str) -> Option<String> {
        self.fleet(id).map(|f| f.owner.clone())
    }

    /// Tears down every member sandbox and removes the Cohort.
    pub async fn kill_fleet(&self, id: &str) -> Result<()> {
        let _op = self.fleet_op.lock().await;
        let f = self.fleet(id).ok_or_else(|| not_found(id))?;
        lock(&self.fleets).remove(id);
        if let Err(e) = self.save_fleets().await {
            lock(&self.fleets).insert(id.to_owned(), Arc::clone(&f));
            return Err(Error::other(format!("persist cohort removal: {e}")));
        }
        for sid in f.members() {
            let _ = self.kill_sandbox(sid).await;
        }
        Ok(())
    }

    /// Appends a task to a Cohort's board.
    pub async fn add_task(&self, fleet_id: &str, payload: &str) -> Result<Task> {
        let _op = self.fleet_op.lock().await;
        let f = self.fleet(fleet_id).ok_or_else(|| not_found(fleet_id))?;
        let t = f.board.add(payload);
        if let Err(e) = self.save_fleets().await {
            f.board.remove(&t.id);
            return Err(Error::other(format!("persist task: {e}")));
        }
        Ok(t)
    }

    /// Atomically claims the next pending task for `owner`, returning it
    /// with a signed lease token (`None` when nothing is pending).
    pub async fn claim_task(&self, fleet_id: &str, owner: &str) -> Result<Option<Task>> {
        let _op = self.fleet_op.lock().await;
        let f = self.fleet(fleet_id).ok_or_else(|| not_found(fleet_id))?;
        let Some(mut t) = f.board.claim(owner) else {
            return Ok(None);
        };
        match self.lease.issue(fleet_id, &t) {
            Ok(token) => t.lease_token = token,
            Err(e) => {
                let _ = f.board.fail(&t.id, owner, "lease signing failed", true);
                return Err(Error::other(format!("sign task lease: {e}")));
            }
        }
        if let Err(e) = self.save_fleets().await {
            let _ = f.board.fail(&t.id, owner, "persistence failed", true);
            return Err(Error::other(format!("persist task claim: {e}")));
        }
        Ok(Some(t))
    }

    fn verify_lease(&self, token: &str, fleet_id: &str, t: &Task, owner: &str) -> Result<()> {
        self.lease
            .verify(token, fleet_id, &t.id, owner, t.lease_version)
            .map(drop)
            .map_err(|_| Error::InvalidLease)
    }

    fn current_task(f: &Fleet, task_id: &str) -> Result<Task> {
        f.board
            .get(task_id)
            .ok_or_else(|| Error::Task(runeward_fleet::FleetError::NotFound(task_id.to_owned())))
    }

    /// Extends a worker's lease so the sweeper will not requeue the task,
    /// returning a refreshed token.
    pub async fn heartbeat_task(
        &self,
        fleet_id: &str,
        task_id: &str,
        owner: &str,
        lease_token: &str,
    ) -> Result<Task> {
        let _op = self.fleet_op.lock().await;
        let f = self.fleet(fleet_id).ok_or_else(|| not_found(fleet_id))?;
        let current = Self::current_task(&f, task_id)?;
        self.verify_lease(lease_token, fleet_id, &current, owner)?;
        let mut t = f.board.heartbeat(task_id, owner)?;
        match self.lease.issue(fleet_id, &t) {
            Ok(token) => t.lease_token = token,
            Err(e) => {
                f.board.restore(current);
                return Err(Error::other(format!("refresh task lease: {e}")));
            }
        }
        if let Err(e) = self.save_fleets().await {
            f.board.restore(current);
            return Err(Error::other(format!("persist task heartbeat: {e}")));
        }
        Ok(t)
    }

    /// Marks a claimed task done; `owner` and the lease must match.
    pub async fn complete_task(
        &self,
        fleet_id: &str,
        task_id: &str,
        owner: &str,
        lease_token: &str,
        result: &str,
    ) -> Result<()> {
        let _op = self.fleet_op.lock().await;
        let f = self.fleet(fleet_id).ok_or_else(|| not_found(fleet_id))?;
        let current = Self::current_task(&f, task_id)?;
        self.verify_lease(lease_token, fleet_id, &current, owner)?;
        f.board.complete(task_id, owner, result)?;
        if let Err(e) = self.save_fleets().await {
            f.board.restore(current);
            return Err(Error::other(format!("persist task completion: {e}")));
        }
        Ok(())
    }

    /// Marks a claimed task failed, optionally requeuing it; `owner` and the
    /// lease must match.
    pub async fn fail_task(
        &self,
        fleet_id: &str,
        task_id: &str,
        owner: &str,
        lease_token: &str,
        message: &str,
        requeue: bool,
    ) -> Result<()> {
        let _op = self.fleet_op.lock().await;
        let f = self.fleet(fleet_id).ok_or_else(|| not_found(fleet_id))?;
        let current = Self::current_task(&f, task_id)?;
        self.verify_lease(lease_token, fleet_id, &current, owner)?;
        f.board.fail(task_id, owner, message, requeue)?;
        if let Err(e) = self.save_fleets().await {
            f.board.restore(current);
            return Err(Error::other(format!("persist task failure: {e}")));
        }
        Ok(())
    }

    /// A snapshot of a Cohort's tasks.
    pub fn list_tasks(&self, fleet_id: &str) -> Result<Vec<Task>> {
        let f = self.fleet(fleet_id).ok_or_else(|| not_found(fleet_id))?;
        Ok(f.board.list())
    }

    pub(crate) fn fleet(&self, id: &str) -> Option<Arc<Fleet>> {
        lock(&self.fleets).get(id).cloned()
    }

    /// Restores persisted Cohorts. Pre-v1 claims without a lease version
    /// cannot be heartbeated or finished by any worker, so only those are
    /// requeued (durably); signed claims keep their state.
    pub(crate) async fn load_fleets(&self) -> Result<()> {
        let Some(data) = self.read_state(FLEETS_FILE_NAME).await? else {
            return Ok(());
        };
        let pfs: Vec<PersistedFleet> = serde_json::from_slice::<Option<Vec<PersistedFleet>>>(&data)
            .map_err(|e| Error::other(format!("decode {FLEETS_FILE_NAME}: {e}")))?
            .unwrap_or_default();
        let mut migrated = false;
        {
            let mut fleets = lock(&self.fleets);
            for pf in pfs {
                let mut tasks = pf.tasks.unwrap_or_default();
                for t in &mut tasks {
                    if t.state == TaskState::Claimed && t.lease_version == 0 {
                        t.state = TaskState::Pending;
                        t.owner.clear();
                        t.lease_expiry = None;
                        t.error = "legacy unsigned lease requeued during v1 upgrade".into();
                        t.updated_at = gotime::now();
                        migrated = true;
                    }
                }
                fleets.insert(
                    pf.id.clone(),
                    Arc::new(Fleet {
                        id: pf.id,
                        profile: pf.profile,
                        owner: pf.owner,
                        board: Board::load(tasks, self.config.fleet_lease),
                        sandboxes: pf.sandboxes,
                        created: pf.created,
                        restored: true,
                    }),
                );
            }
        }
        if migrated {
            self.save_fleets().await?;
        }
        Ok(())
    }

    /// Writes every Cohort (snapshot under the lock, write outside it).
    pub(crate) async fn save_fleets(&self) -> Result<()> {
        if self.state.dir().is_none() {
            return Ok(());
        }
        let pfs: Vec<PersistedFleet> = lock(&self.fleets)
            .values()
            .map(|f| PersistedFleet {
                id: f.id.clone(),
                profile: f.profile.clone(),
                owner: f.owner.clone(),
                sandboxes: f.sandboxes.clone(),
                created: f.created,
                tasks: Some(f.board.export()),
            })
            .collect();
        self.write_state(FLEETS_FILE_NAME, marshal_indent(&pfs)?)
            .await
    }

    /// Requeues tasks whose worker lease expired and Chronicles each.
    pub(crate) async fn sweep_once(&self) {
        let _op = self.fleet_op.lock().await;
        let now = gotime::now();
        let fleets: Vec<Arc<Fleet>> = lock(&self.fleets).values().cloned().collect();
        let mut changed = false;
        for f in fleets {
            for t in f.board.sweep(now) {
                changed = true;
                self.record_fleet(
                    &f,
                    "task.requeue",
                    &t.id,
                    &format!("lease expired (worker {})", t.owner),
                )
                .await;
            }
        }
        if changed && let Err(e) = self.save_fleets().await {
            tracing::error!(error = %e, "runeward: persist requeued cohort tasks");
        }
    }

    pub(crate) async fn record_fleet(&self, f: &Fleet, action: &str, task_id: &str, reason: &str) {
        let mut ev = Event {
            session_id: format!("fleet:{}", f.id),
            profile: f.profile.clone(),
            tool: "fleet".into(),
            action: action.into(),
            verdict: Verdict::Allow.as_str().into(),
            ..Event::default()
        };
        if !task_id.is_empty() {
            ev.args = vec![task_id.to_owned()];
        }
        if !reason.is_empty() {
            ev.meta.insert("reason".into(), reason.into());
        }
        self.append_audit(ev).await;
    }
}
