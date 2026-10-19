//! Durable run records (`runs.json`): one lineage node per agent execution,
//! queryable after the sandbox is gone.

use runeward_ledger::gotime::{self, Time};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::manager::Manager;
use crate::sessions::{Session, lock};
use crate::statefile::marshal_indent;
use crate::timefmt::nullable;

pub(crate) const RUNS_FILE_NAME: &str = "runs.json";

/// A provider-neutral run record. Field order and `omitempty` rules match
/// the Go `Run`, so `runs.json` round-trips byte for byte.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Run {
    #[serde(default, deserialize_with = "nullable")]
    pub id: String,
    #[serde(
        default,
        deserialize_with = "nullable",
        skip_serializing_if = "String::is_empty"
    )]
    pub parent_run_id: String,
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
    #[serde(default, deserialize_with = "nullable")]
    pub charter: String,
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
    /// `running`, `completed`, `failed` or `interrupted`.
    #[serde(default, deserialize_with = "nullable")]
    pub status: String,
    #[serde(with = "crate::timefmt", default = "gotime::zero")]
    pub created_at: Time,
    #[serde(
        with = "crate::timefmt::opt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub finished_at: Option<Time>,
    #[serde(
        default,
        deserialize_with = "nullable",
        skip_serializing_if = "String::is_empty"
    )]
    pub error: String,
    /// The isolation tier the sandbox ran behind (new in the Rust port;
    /// omitted when empty so Go-written records rewrite unchanged).
    #[serde(
        default,
        deserialize_with = "nullable",
        skip_serializing_if = "String::is_empty"
    )]
    pub isolation: String,
    /// The run whose workspace this run's Citadel was forked from (new in
    /// the Rust port; omitted when empty).
    #[serde(
        default,
        deserialize_with = "nullable",
        skip_serializing_if = "String::is_empty"
    )]
    pub forked_from: String,
}

impl Run {
    fn sort_key(&self) -> Time {
        self.created_at
    }
}

impl Manager {
    pub(crate) async fn load_runs(&self) -> Result<()> {
        let Some(data) = self.read_state(RUNS_FILE_NAME).await? else {
            return Ok(());
        };
        let runs: Vec<Run> = serde_json::from_slice::<Option<Vec<Run>>>(&data)
            .map_err(|e| Error::other(format!("decode {RUNS_FILE_NAME}: {e}")))?
            .unwrap_or_default();
        let now = gotime::now();
        let mut interrupted = false;
        {
            let mut map = lock(&self.runs);
            for mut run in runs {
                // A runtime session cannot survive a restart: keep the
                // lineage but make the terminal state truthful. Persistent
                // workspaces survive (asleep), and so do their runs.
                if run.status == "running" && !self.is_workspace(&run.citadel_id) {
                    run.status = "interrupted".into();
                    run.error = "control plane restarted before the run completed".into();
                    run.finished_at = Some(now);
                    interrupted = true;
                }
                map.insert(run.id.clone(), run);
            }
        }
        if interrupted {
            self.save_runs().await?;
        }
        Ok(())
    }

    pub(crate) async fn save_runs(&self) -> Result<()> {
        let data = marshal_indent(&self.list_runs())?;
        self.write_state(RUNS_FILE_NAME, data).await
    }

    pub(crate) async fn register_run(&self, sess: &Session) -> Result<()> {
        let _op = self.run_op.lock().await;
        let run = Run {
            id: sess.run_id.clone(),
            parent_run_id: sess.parent_run_id.clone(),
            citadel_id: sess.sandbox.id.clone(),
            tenant: sess.owner.clone(),
            actor: sess.actor.clone(),
            charter: sess.charter.name.clone(),
            agent: sess.agent.clone(),
            provider: sess.provider.clone(),
            model: sess.model.clone(),
            status: "running".into(),
            created_at: gotime::now(),
            finished_at: None,
            error: String::new(),
            isolation: sess.isolation().as_str().into(),
            forked_from: sess.forked_from.clone(),
        };
        {
            let mut map = lock(&self.runs);
            if map
                .get(&run.id)
                .is_some_and(|existing| existing.citadel_id != run.citadel_id)
            {
                return Err(Error::other(format!("run {} already exists", run.id)));
            }
            map.insert(run.id.clone(), run.clone());
        }
        if let Err(e) = self.save_runs().await {
            lock(&self.runs).remove(&run.id);
            return Err(e);
        }
        drop(_op);
        if sess.charter.persists_workspace() {
            self.track_workspace(sess).await?;
        }
        Ok(())
    }

    pub(crate) async fn finish_run(&self, id: &str, run_err: Option<&str>) -> Result<()> {
        if id.is_empty() {
            return Ok(());
        }
        let _op = self.run_op.lock().await;
        {
            let mut map = lock(&self.runs);
            let Some(run) = map.get_mut(id) else {
                return Ok(());
            };
            run.finished_at = Some(gotime::now());
            match run_err {
                None => run.status = "completed".into(),
                Some(e) => {
                    run.status = "failed".into();
                    run.error = e.to_owned();
                }
            }
        }
        self.save_runs().await
    }

    /// Every run record in creation order.
    pub fn list_runs(&self) -> Vec<Run> {
        let mut out: Vec<Run> = lock(&self.runs).values().cloned().collect();
        out.sort_by_key(Run::sort_key);
        out
    }

    /// One run record.
    pub fn run(&self, id: &str) -> Option<Run> {
        lock(&self.runs).get(id).cloned()
    }
}
