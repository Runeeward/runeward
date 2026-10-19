//! Workspace snapshots (`snapshots.json`), export and restore.
//!
//! Fork (copying a sandbox's disk into a new, independent sandbox) builds on
//! the same pieces: a snapshot of the source, then
//! [`Manager::restore_snapshot_for_identity`] with fresh lineage. It is not
//! exposed yet; see the crate docs.

use std::collections::HashMap;
use std::sync::Arc;

use runeward_backend::{Sandbox, SnapshotRef, restore_snapshot, spec_from_charter};
use runeward_charter::Verdict;
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
        let sess = self.session(id)?;
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
        let sess = self.session(id)?;
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
        let extra = compile_scrub_patterns(&c.audit.scrub_patterns)?;
        let (env, secrets) = resolve_env(&c, &self.resolver).await?;
        let spec = spec_from_charter(&c, env.clone());
        let be = self.registry.open(&c, &self.backend_config).await?;
        let sb = restore_snapshot(be.as_ref(), &snap, spec).await?;
        let kill = || async {
            let _ = be.kill(&sb.id).await;
        };
        if let Err(e) = check_isolation_floor(&c, be.name(), sb.isolation) {
            kill().await;
            return Err(e);
        }
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
        let sess = Arc::new(
            Session::builder(sb.clone(), Arc::clone(&be), c)
                .engine(engine)
                .guard(guard)
                .env(env)
                .owner(owner)
                .actor(first_non_empty(actor, owner))
                .secrets(secrets)
                .scrubber(Scrubber::new(extra))
                .build()?,
        );
        lock(&self.sessions).insert(sb.id.clone(), Arc::clone(&sess));
        if let Err(e) = self.register_run(&sess).await {
            kill().await;
            lock(&self.sessions).remove(&sb.id);
            return Err(Error::other(format!("persist restored run: {e}")));
        }
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
        Ok(sb)
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
