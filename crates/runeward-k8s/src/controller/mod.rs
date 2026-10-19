//! Reconciles `runeward.dev` Citadel and Cohort custom resources onto the
//! control-plane [`Manager`] running in the same process.
//!
//! - [`Citadel`]/[`ClusterCitadel`] map to [`Manager::create_sandbox`]; the
//!   status records `phase`, `citadelId`, `backend`, `image`, `isolation`
//!   (the tier the sandbox actually runs behind), `message` and
//!   `observedGeneration`.
//! - [`Cohort`]/[`ClusterCohort`] map to [`Manager::create_fleet`]; the
//!   status records the cohort id, member citadels and task-board counts.
//! - The [`FINALIZER`] blocks deletion until the backing citadel or cohort is
//!   torn down.
//!
//! Backing ids live in status, so a resource whose citadel or cohort is gone
//! (for example after a controller restart) is reprovisioned. Namespaced
//! kinds are watched in one namespace (or all of them with
//! [`ControllerOptions::all_namespaces`]); the cluster-scoped kinds are
//! always watched cluster-wide.

use std::collections::HashMap;
use std::fmt::Debug;
use std::future::Future;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use futures_util::StreamExt as _;
use kube::api::{Api, Patch, PatchParams};
use kube::runtime::controller::{self, Action, Controller};
use kube::runtime::watcher;
use kube::{Client, Resource, ResourceExt as _};
use runeward_controlplane::{CreateOptions, FleetView, Manager};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Map, Value, json};
use tokio::sync::{Semaphore, watch};

use crate::crd::{Citadel, ClusterCitadel, ClusterCohort, Cohort};

#[cfg(test)]
mod tests;

/// Blocks custom-resource deletion until the backing citadel or cohort is
/// torn down.
pub const FINALIZER: &str = "runeward.dev/finalizer";

/// How often a reconciled resource is revisited without a change (the Go
/// informers' resync period). Cohort task counts refresh at least this often.
pub const RESYNC_PERIOD: Duration = Duration::from_secs(10 * 60);

/// First retry delay after a failed reconcile; doubles per consecutive
/// failure of the same resource.
const BACKOFF_BASE: Duration = Duration::from_millis(5);
/// Retry delay ceiling.
const BACKOFF_MAX: Duration = Duration::from_secs(1000);

/// Startup options for [`run`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControllerOptions {
    /// Reconciles allowed to run at once, across every kind (minimum 1).
    pub workers: usize,
    /// Watch namespaced kinds in every namespace instead of [`namespace`].
    ///
    /// [`namespace`]: ControllerOptions::namespace
    pub all_namespaces: bool,
    /// Namespace watched for Citadels and Cohorts (empty: all namespaces).
    pub namespace: String,
}

impl Default for ControllerOptions {
    fn default() -> Self {
        Self {
            workers: 2,
            all_namespaces: false,
            namespace: "runeward".to_owned(),
        }
    }
}

impl ControllerOptions {
    /// Defaults with `namespace` taken from `RUNEWARD_K8S_NAMESPACE`.
    pub fn from_env() -> Self {
        let d = Self::default();
        Self {
            namespace: std::env::var("RUNEWARD_K8S_NAMESPACE")
                .ok()
                .filter(|v| !v.is_empty())
                .unwrap_or(d.namespace),
            ..d
        }
    }

    /// The namespace namespaced kinds are watched in; `None` means all.
    pub fn watch_namespace(&self) -> Option<&str> {
        if self.all_namespaces || self.namespace.is_empty() {
            None
        } else {
            Some(&self.namespace)
        }
    }
}

/// A reconcile failure. The resource is retried with per-resource
/// exponential backoff.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A Kubernetes API call failed.
    #[error("kubernetes api: {0}")]
    Kube(#[from] kube::Error),
    /// The control plane could not provision the backing citadel or cohort;
    /// the message is also recorded in the resource status.
    #[error("provision: {0}")]
    Provision(String),
}

/// Watches Citadel, ClusterCitadel, Cohort and ClusterCohort resources and
/// reconciles them onto `manager` until `shutdown` resolves, then lets
/// in-flight reconciles finish and returns.
pub async fn run<F>(
    client: Client,
    manager: Arc<Manager>,
    opts: ControllerOptions,
    shutdown: F,
) -> Result<(), Error>
where
    F: Future<Output = ()> + Send,
{
    let workers = opts.workers.max(1);
    let ctx = Arc::new(Context::new(client.clone(), manager, workers));
    let (stop_tx, stop_rx) = watch::channel(false);
    let ns = opts.watch_namespace();
    tracing::info!(
        group = crate::crd::GROUP,
        scope = ns.unwrap_or("all namespaces"),
        workers,
        "starting controller"
    );
    let stop = async move {
        shutdown.await;
        tracing::info!("controller: shutting down");
        let _ = stop_tx.send(true);
    };
    tokio::join!(
        stop,
        drive(Citadel::watch_api(&client, ns), &ctx, &stop_rx, workers),
        drive(
            ClusterCitadel::watch_api(&client, ns),
            &ctx,
            &stop_rx,
            workers
        ),
        drive(Cohort::watch_api(&client, ns), &ctx, &stop_rx, workers),
        drive(
            ClusterCohort::watch_api(&client, ns),
            &ctx,
            &stop_rx,
            workers
        ),
    );
    Ok(())
}

/// Runs one kind's controller until the stop signal fires.
async fn drive<K: Governed>(
    api: Api<K>,
    ctx: &Arc<Context>,
    stop: &watch::Receiver<bool>,
    workers: usize,
) {
    let mut stop = stop.clone();
    let trigger = async move {
        let _ = stop.wait_for(|s| *s).await;
    };
    let concurrency = u16::try_from(workers).unwrap_or(u16::MAX);
    Controller::new(api, watcher::Config::default())
        .with_config(controller::Config::default().concurrency(concurrency))
        .graceful_shutdown_on(trigger)
        .run(reconcile::<K>, error_policy::<K>, Arc::clone(ctx))
        .for_each(|res| async move {
            match res {
                Ok((obj, _)) => tracing::debug!(object = %obj, "reconciled"),
                // Reconcile failures are logged by the error policy.
                Err(controller::Error::ReconcilerFailed(..)) => {}
                Err(e) => tracing::warn!(error = %e, "controller error"),
            }
        })
        .await;
}

/// Shared reconcile state.
struct Context {
    client: Client,
    manager: Arc<Manager>,
    /// Bounds concurrent reconciles across all kinds to the worker count.
    permits: Semaphore,
    /// Consecutive failures per resource key, for retry backoff.
    failures: Mutex<HashMap<String, u32>>,
}

impl Context {
    fn new(client: Client, manager: Arc<Manager>, workers: usize) -> Self {
        Self {
            client,
            manager,
            permits: Semaphore::new(workers.max(1)),
            failures: Mutex::default(),
        }
    }

    /// Records one more failure for `key` and returns the retry delay.
    fn fail(&self, key: &str) -> Duration {
        let mut f = self.failures.lock().unwrap_or_else(PoisonError::into_inner);
        let n = f.entry(key.to_owned()).or_default();
        *n = n.saturating_add(1);
        backoff(*n)
    }

    /// Clears the failure history of `key` after a successful reconcile.
    fn forget(&self, key: &str) {
        self.failures
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(key);
    }
}

/// The retry delay after `failures` consecutive failures: 5ms doubling up
/// to 1000s, as Go's default controller rate limiter.
fn backoff(failures: u32) -> Duration {
    let exp = failures.saturating_sub(1).min(31);
    BACKOFF_BASE
        .checked_mul(1u32 << exp)
        .map_or(BACKOFF_MAX, |d| d.min(BACKOFF_MAX))
}

/// What a custom resource is backed by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Backing {
    Citadel,
    Cohort,
}

/// The four reconciled kinds.
trait Governed:
    Resource<DynamicType = ()> + Clone + Debug + DeserializeOwned + Serialize + Send + Sync + 'static
{
    const BACKING: Backing;

    /// `spec.profile`.
    fn profile(&self) -> &str;

    /// `status.citadelId` or `status.cohortId`, if recorded.
    fn backing_id(&self) -> Option<&str>;

    /// The API for one object: namespaced kinds in `ns`, cluster kinds
    /// cluster-wide.
    fn object_api(client: &Client, ns: Option<&str>) -> Api<Self>;

    /// The API to watch: namespaced kinds in `ns` (all when `None`), cluster
    /// kinds cluster-wide.
    fn watch_api(client: &Client, ns: Option<&str>) -> Api<Self>;
}

macro_rules! namespaced {
    ($kind:ty, $backing:expr, $field:ident) => {
        impl Governed for $kind {
            const BACKING: Backing = $backing;
            fn profile(&self) -> &str {
                &self.spec.profile
            }
            fn backing_id(&self) -> Option<&str> {
                self.status.as_ref()?.$field.as_deref()
            }
            fn object_api(client: &Client, ns: Option<&str>) -> Api<Self> {
                match ns {
                    Some(ns) => Api::namespaced(client.clone(), ns),
                    None => Api::all(client.clone()),
                }
            }
            fn watch_api(client: &Client, ns: Option<&str>) -> Api<Self> {
                Self::object_api(client, ns)
            }
        }
    };
}

macro_rules! cluster {
    ($kind:ty, $backing:expr, $field:ident) => {
        impl Governed for $kind {
            const BACKING: Backing = $backing;
            fn profile(&self) -> &str {
                &self.spec.profile
            }
            fn backing_id(&self) -> Option<&str> {
                self.status.as_ref()?.$field.as_deref()
            }
            fn object_api(client: &Client, _: Option<&str>) -> Api<Self> {
                Api::all(client.clone())
            }
            fn watch_api(client: &Client, _: Option<&str>) -> Api<Self> {
                Api::all(client.clone())
            }
        }
    };
}

namespaced!(Citadel, Backing::Citadel, citadel_id);
cluster!(ClusterCitadel, Backing::Citadel, citadel_id);
namespaced!(Cohort, Backing::Cohort, cohort_id);
cluster!(ClusterCohort, Backing::Cohort, cohort_id);

/// `kind/namespace/name`, identifying a resource across kinds.
fn key_of<K: Governed>(obj: &K) -> String {
    format!(
        "{}/{}/{}",
        K::kind(&()),
        obj.namespace().unwrap_or_default(),
        obj.name_any()
    )
}

fn has_finalizer<K: Resource>(obj: &K) -> bool {
    obj.finalizers().iter().any(|f| f == FINALIZER)
}

async fn reconcile<K: Governed>(obj: Arc<K>, ctx: Arc<Context>) -> Result<Action, Error> {
    // The semaphore is never closed, so acquiring cannot fail.
    let _permit = ctx.permits.acquire().await.ok();
    let res = reconcile_one(obj.as_ref(), &ctx).await;
    if res.is_ok() {
        ctx.forget(&key_of(obj.as_ref()));
    }
    res
}

fn error_policy<K: Governed>(obj: Arc<K>, err: &Error, ctx: Arc<Context>) -> Action {
    let key = key_of(obj.as_ref());
    let delay = ctx.fail(&key);
    tracing::error!(resource = %key, error = %err, retry_in = ?delay, "reconcile failed, requeueing");
    Action::requeue(delay)
}

/// One reconcile pass: finalizer bookkeeping, then the kind's provisioning.
async fn reconcile_one<K: Governed>(cached: &K, ctx: &Context) -> Result<Action, Error> {
    let ns = cached.namespace();
    let api = K::object_api(&ctx.client, ns.as_deref());
    let name = cached.name_any();

    // Read the live object, as Go does: the watch cache can lag behind our
    // own status write, and acting on a copy without the recorded backing id
    // would provision a second citadel or cohort.
    let Some(live) = api.get_opt(&name).await? else {
        // Deleted and already finalized; nothing to do.
        return Ok(Action::await_change());
    };
    let obj = &live;

    if obj.meta().deletion_timestamp.is_some() {
        if !has_finalizer(obj) {
            return Ok(Action::await_change());
        }
        teardown(&ctx.manager, obj).await;
        let rest: Vec<&String> = obj
            .finalizers()
            .iter()
            .filter(|f| *f != FINALIZER)
            .collect();
        patch_finalizers(&api, obj, &name, &rest).await?;
        tracing::info!(resource = %key_of(obj), "finalizer removed");
        return Ok(Action::await_change());
    }

    // Ensure the finalizer is present before anything is created.
    let added;
    let obj = if has_finalizer(obj) {
        obj
    } else {
        let mut all: Vec<&String> = obj.finalizers().iter().collect();
        let f = FINALIZER.to_owned();
        all.push(&f);
        added = patch_finalizers(&api, obj, &name, &all).await?;
        &added
    };

    match K::BACKING {
        Backing::Citadel => reconcile_citadel(&api, obj, &ctx.manager).await,
        Backing::Cohort => reconcile_cohort(&api, obj, &ctx.manager).await,
    }
}

/// Replaces `metadata.finalizers`, guarded by the observed resourceVersion
/// so a concurrent writer causes a conflict (and a retry) rather than a
/// lost update.
async fn patch_finalizers<K: Governed>(
    api: &Api<K>,
    obj: &K,
    name: &str,
    finalizers: &[&String],
) -> Result<K, Error> {
    let mut meta = Map::new();
    meta.insert("finalizers".into(), json!(finalizers));
    if let Some(rv) = obj.resource_version() {
        meta.insert("resourceVersion".into(), json!(rv));
    }
    let patch = json!({ "metadata": meta });
    Ok(api
        .patch(name, &PatchParams::default(), &Patch::Merge(&patch))
        .await?)
}

async fn reconcile_citadel<K: Governed>(
    api: &Api<K>,
    obj: &K,
    manager: &Manager,
) -> Result<Action, Error> {
    if let Some(id) = obj.backing_id().filter(|id| !id.is_empty()) {
        // Already provisioned; nothing to do while it still exists.
        if manager.sandbox(id).is_some() {
            return Ok(Action::requeue(RESYNC_PERIOD));
        }
        // The backing citadel vanished (e.g. controller restart);
        // reprovision.
    }

    let profile = obj.profile();
    if profile.is_empty() {
        set_status(
            api,
            obj,
            json!({"phase": "Failed", "message": "spec.profile is required"}),
        )
        .await?;
        return Ok(Action::requeue(RESYNC_PERIOD));
    }

    let sb = match manager
        .create_sandbox(profile, CreateOptions::default())
        .await
    {
        Ok(sb) => sb,
        Err(e) => {
            let msg = e.to_string();
            set_status(api, obj, json!({"phase": "Failed", "message": msg})).await?;
            return Err(Error::Provision(msg));
        }
    };
    tracing::info!(resource = %key_of(obj), citadel_id = %sb.id, isolation = %sb.isolation, "citadel reconciled");
    let status = json!({
        "phase": "Running",
        "citadelId": sb.id,
        "backend": sb.backend,
        "image": sb.image,
        "isolation": sb.isolation.as_str(),
        "message": "",
    });
    if let Err(e) = set_status(api, obj, status).await {
        // The id was never recorded, so a retry would provision a second
        // citadel; tear this one down first.
        if let Err(kill) = manager.kill_sandbox(&sb.id).await {
            tracing::error!(citadel_id = %sb.id, error = %kill, "kill unrecorded citadel failed");
        }
        return Err(e);
    }
    Ok(Action::requeue(RESYNC_PERIOD))
}

async fn reconcile_cohort<K: Governed>(
    api: &Api<K>,
    obj: &K,
    manager: &Manager,
) -> Result<Action, Error> {
    // A recorded cohort that is gone (e.g. controller restart) is recreated
    // below.
    if let Some(v) = obj
        .backing_id()
        .filter(|id| !id.is_empty())
        .and_then(|id| manager.fleet_view(id))
    {
        set_status(api, obj, cohort_status(&v)).await?;
        return Ok(Action::requeue(RESYNC_PERIOD));
    }

    let profile = obj.profile();
    if profile.is_empty() {
        set_status(
            api,
            obj,
            json!({"phase": "Failed", "message": "spec.profile is required"}),
        )
        .await?;
        return Ok(Action::requeue(RESYNC_PERIOD));
    }

    let v = match manager.create_fleet(profile).await {
        Ok(v) => v,
        Err(e) => {
            let msg = e.to_string();
            set_status(api, obj, json!({"phase": "Failed", "message": msg})).await?;
            return Err(Error::Provision(msg));
        }
    };
    tracing::info!(
        resource = %key_of(obj),
        cohort_id = %v.id,
        citadels = v.sandboxes.as_ref().map_or(0, Vec::len),
        "cohort reconciled"
    );
    if let Err(e) = set_status(api, obj, cohort_status(&v)).await {
        // As for citadels: never leave an unrecorded cohort behind.
        if let Err(kill) = manager.kill_fleet(&v.id).await {
            tracing::error!(cohort_id = %v.id, error = %kill, "kill unrecorded cohort failed");
        }
        return Err(e);
    }
    Ok(Action::requeue(RESYNC_PERIOD))
}

/// Tears down the backing citadel or cohort of a resource being deleted.
/// Failures are logged and do not block finalizer removal.
async fn teardown<K: Governed>(manager: &Manager, obj: &K) {
    let Some(id) = obj.backing_id().filter(|id| !id.is_empty()) else {
        return;
    };
    match K::BACKING {
        Backing::Citadel => {
            if let Err(e) = manager.kill_sandbox(id).await {
                tracing::error!(citadel_id = %id, error = %e, "kill citadel failed, continuing");
            }
        }
        Backing::Cohort => {
            if let Err(e) = manager.kill_fleet(id).await {
                tracing::error!(cohort_id = %id, error = %e, "kill cohort failed, continuing");
            }
        }
    }
}

/// Merges `fields` into the status subresource, stamping
/// `observedGeneration`.
async fn set_status<K: Governed>(api: &Api<K>, obj: &K, fields: Value) -> Result<(), Error> {
    let mut status = match fields {
        Value::Object(m) => m,
        _ => Map::new(),
    };
    status.insert(
        "observedGeneration".into(),
        json!(obj.meta().generation.unwrap_or_default()),
    );
    let patch = json!({ "status": status });
    api.patch_status(
        &obj.name_any(),
        &PatchParams::default(),
        &Patch::Merge(&patch),
    )
    .await?;
    Ok(())
}

/// The Running status of a cohort.
fn cohort_status(v: &FleetView) -> Value {
    json!({
        "phase": "Running",
        "cohortId": v.id,
        "citadels": v.sandboxes.clone().unwrap_or_default(),
        "tasksTotal": v.stats.total,
        "tasksPending": v.stats.pending,
        "tasksClaimed": v.stats.claimed,
        "tasksDone": v.stats.done,
        "tasksFailed": v.stats.failed,
        "message": "",
    })
}
