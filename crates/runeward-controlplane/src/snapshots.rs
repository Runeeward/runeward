//! Workspace snapshots (`snapshots.json`), export and restore.
//!
//! Fork ([`Manager::fork_citadel`]) builds on the same pieces: a snapshot
//! of the source, restored into a new, independent sandbox with fresh
//! lineage.

use std::collections::HashMap;
use std::sync::Arc;

use runeward_backend::{Resources, Sandbox, SnapshotRef, restore_snapshot, spec_from_charter};
use runeward_charter::{Charter, Verdict};
use runeward_ledger::Scrubber;
use runeward_policy::Guard;
use serde::{Deserialize, Serialize};
use tokio::io::AsyncWrite;

use crate::citadels::{check_isolation_floor, first_non_empty};
use crate::env::{compile_scrub_patterns, new_engine, resolve_env};
use crate::error::{Error, Result};
use crate::manager::Manager;
use crate::sessions::{Session, lock};
use crate::statefile::marshal_indent;
use crate::timefmt::nullable;

pub(crate) const SNAPSHOTS_FILE_NAME: &str = "snapshots.json";

/// Who a sandbox restored from a snapshot belongs to, and its lineage.
#[derive(Debug, Clone, Default)]
pub(crate) struct LaunchIdentity {
    pub(crate) owner: String,
    pub(crate) actor: String,
    /// Empty picks a fresh run id.
    pub(crate) run_id: String,
    pub(crate) forked_from: String,
    pub(crate) agent: String,
    pub(crate) provider: String,
    pub(crate) model: String,
    /// Overrides the Charter's resource caps.
    pub(crate) resources: Option<Resources>,
}

/// Registered snapshots and the tenant that owns each.
#[derive(Debug, Default)]
pub(crate) struct SnapshotState {
    pub(crate) refs: HashMap<String, SnapshotRef>,
    pub(crate) owners: HashMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct PersistedSnapshot {
    #[serde(rename = "ref")]
    pub(crate) snapshot: SnapshotRef,
    #[serde(
        default,
        deserialize_with = "nullable",
        skip_serializing_if = "String::is_empty"
    )]
    pub(crate) owner: String,
}

impl Manager {
    /// Captures a sandbox's workspace and registers it, carrying the
    /// Charter name so a restore re-derives governance.
    pub async fn snapshot(&self, id: &str, name: &str) -> Result<SnapshotRef> {
        let sess = self.awake_session(id).await?;
        let mut snap = sess.backend.snapshot(id, name).await?;
        snap.profile.clone_from(&sess.charter.name);
        {
            let _op = self.snap_op.lock().await;
            {
                let mut st = lock(&self.snapshots);
                st.refs.insert(snap.id.clone(), snap.clone());
                st.owners.insert(snap.id.clone(), sess.owner.clone());
            }
            if let Err(e) = self.save_snapshots().await {
                let mut st = lock(&self.snapshots);
                st.refs.remove(&snap.id);
                st.owners.remove(&snap.id);
                return Err(Error::other(format!("persist snapshot reference: {e}")));
            }
        }
        self.record(
            &sess,
            "snapshot",
            name,
            &[],
            Verdict::Allow.as_str(),
            0,
            0,
            &format!("snapshot {}", snap.id),
        )
        .await;
        Ok(snap)
    }

    /// The tenant that created a snapshot.
    pub fn snapshot_owner(&self, id: &str) -> Option<String> {
        lock(&self.snapshots).owners.get(id).cloned()
    }

    /// One registered snapshot.
    pub fn snapshot_ref(&self, id: &str) -> Option<SnapshotRef> {
        lock(&self.snapshots).refs.get(id).cloned()
    }

    /// Every registered snapshot.
    pub fn list_snapshots(&self) -> Vec<SnapshotRef> {
        lock(&self.snapshots).refs.values().cloned().collect()
    }

    /// Streams a point-in-time tar of a sandbox's workspace to `w`.
    pub async fn export_workspace(
        &self,
        id: &str,
        w: &mut (dyn AsyncWrite + Send + Unpin),
    ) -> Result<()> {
        let sess = self.awake_session(id).await?;
        Ok(sess.backend.export_workspace(id, w).await?)
    }

    /// Recreates a governed sandbox from a snapshot.
    pub async fn restore_snapshot(&self, snapshot_id: &str, owner: &str) -> Result<Sandbox> {
        self.restore_snapshot_for_identity(snapshot_id, owner, owner)
            .await
    }

    /// Restores a tenant-owned snapshot into a new sandbox, re-deriving
    /// policy, guardrails and the isolation floor from the snapshot's
    /// Charter, with a fresh run attributed to `actor`.
    pub async fn restore_snapshot_for_identity(
        &self,
        snapshot_id: &str,
        owner: &str,
        actor: &str,
    ) -> Result<Sandbox> {
        let snap = self
            .snapshot_ref(snapshot_id)
            .ok_or_else(|| Error::other(format!("snapshot {snapshot_id:?} not found")))?;
        let c = self
            .load_profile(&snap.profile)
            .await
            .map_err(|e| Error::other(format!("load snapshot profile {:?}: {e}", snap.profile)))?;
        let ident = LaunchIdentity {
            owner: owner.to_owned(),
            actor: first_non_empty(actor, owner).to_owned(),
            ..LaunchIdentity::default()
        };
        let sess = self.restore_into(c, &snap, ident).await?;
        self.record(
            &sess,
            "snapshot",
            "restore",
            &[],
            Verdict::Allow.as_str(),
            0,
            0,
            &format!("from {snapshot_id}"),
        )
        .await;
        Ok(sess.sandbox.clone())
    }

    /// Creates a new governed sandbox under Charter `c` holding the
    /// snapshot's workspace: policy, guardrails, secrets, broker,
    /// supervisor and the isolation floor all come from `c`, and the
    /// session gets a fresh (or the given) run with `ident`'s lineage.
    pub(crate) async fn restore_into(
        &self,
        c: Charter,
        snap: &SnapshotRef,
        ident: LaunchIdentity,
    ) -> Result<Arc<Session>> {
        let extra = compile_scrub_patterns(&c.audit.scrub_patterns)?;
        let (mut env, mut secrets) = resolve_env(&c, &self.resolver).await?;
        let gov = self.prepare_governance(&c, &mut env, &mut secrets).await?;
        let mut spec = spec_from_charter(&c, env.clone());
        gov.apply(&mut spec);
        if let Some(r) = ident.resources {
            spec.resources = r;
        }
        let be = self.registry.open(&c, &self.backend_config).await?;
        let sb = restore_snapshot(be.as_ref(), snap, spec).await?;
        let kill = || async {
            let _ = be.kill(&sb.id).await;
        };
        if let Err(e) = check_isolation_floor(&c, be.name(), sb.isolation) {
            kill().await;
            return Err(e);
        }
        let (evidence, report_line) = match self.verify_governance(be.as_ref(), &sb, &gov).await {
            Ok(Some((ev, line))) => (Some(ev), line),
            Ok(None) => (None, String::new()),
            Err(e) => {
                kill().await;
                return Err(e);
            }
        };
        let guard = match Guard::new(&c.limits) {
            Ok(g) => g,
            Err(e) => {
                kill().await;
                return Err(Error::other(e));
            }
        };
        guard.start();
        let engine = match new_engine(&c, self.config.policy_default.as_deref()).await {
            Ok(e) => e,
            Err(e) => {
                kill().await;
                return Err(e);
            }
        };
        let mut builder = Session::builder(sb.clone(), Arc::clone(&be), c)
            .engine(engine)
            .guard(guard)
            .env(env)
            .owner(ident.owner.clone())
            .actor(first_non_empty(&ident.actor, &ident.owner))
            .run_id(ident.run_id)
            .forked_from(ident.forked_from)
            .agent(ident.agent.trim())
            .provider(ident.provider.trim())
            .model(ident.model.trim())
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
                kill().await;
                return Err(e);
            }
        };
        lock(&self.sessions).insert(sb.id.clone(), Arc::clone(&sess));
        self.attach_governance(&sess, gov, &report_line).await;
        if let Err(e) = self.register_run(&sess).await {
            sess.stop_tasks();
            kill().await;
            lock(&self.sessions).remove(&sb.id);
            return Err(Error::other(format!("persist restored run: {e}")));
        }
        Ok(sess)
    }

    pub(crate) async fn load_snapshots(&self) -> Result<()> {
        let Some(data) = self.read_state(SNAPSHOTS_FILE_NAME).await? else {
            return Ok(());
        };
        let items: Vec<PersistedSnapshot> =
            serde_json::from_slice::<Option<Vec<PersistedSnapshot>>>(&data)
                .map_err(|e| Error::other(format!("decode {SNAPSHOTS_FILE_NAME}: {e}")))?
                .unwrap_or_default();
        let mut st = lock(&self.snapshots);
        for item in items {
            st.owners.insert(item.snapshot.id.clone(), item.owner);
            st.refs.insert(item.snapshot.id.clone(), item.snapshot);
        }
        Ok(())
    }

    pub(crate) async fn save_snapshots(&self) -> Result<()> {
        if self.state.dir().is_none() {
            return Ok(());
        }
        let items: Vec<PersistedSnapshot> = {
            let st = lock(&self.snapshots);
            st.refs
                .iter()
                .map(|(id, r)| PersistedSnapshot {
                    snapshot: r.clone(),
                    owner: st.owners.get(id).cloned().unwrap_or_default(),
                })
                .collect()
        };
        self.write_state(SNAPSHOTS_FILE_NAME, marshal_indent(&items)?)
            .await
    }
}
