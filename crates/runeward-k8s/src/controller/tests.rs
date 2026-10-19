//! Controller tests: reconcile passes against a stateful mock API server
//! (built on the shared mock client) with a Manager driving a fake backend,
//! plus an end-to-end [`run`] over list responses.

use super::*;
use crate::testutil::{Log, mock_client_with_body, recorded, status};
use async_trait::async_trait;
use http::Method;
use runeward_backend::{
    Backend, BackendConfig, BackendError, Driver, ExecRequest, ExecResult, IsolationTier,
    PtyStream, Registry, Result as BResult, Sandbox, SnapshotRef, Spec,
};
use runeward_charter::{Charter, File, SignedCharters};
use runeward_controlplane::ManagerConfig;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::io::AsyncWrite;

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

// ---------------------------------------------------------------------------
// Fake backend and Manager harness.

#[derive(Debug)]
struct FakeBackend {
    tier: IsolationTier,
    creates: AtomicUsize,
    killed: Mutex<Vec<String>>,
    /// When set, `create` fails with this message.
    fail_create: Mutex<Option<String>>,
}

impl FakeBackend {
    fn new(tier: IsolationTier) -> Self {
        Self {
            tier,
            creates: AtomicUsize::new(0),
            killed: Mutex::default(),
            fail_create: Mutex::default(),
        }
    }
}

#[async_trait]
impl Backend for FakeBackend {
    fn name(&self) -> &str {
        "fake"
    }

    fn isolation_tier(&self) -> IsolationTier {
        self.tier
    }

    async fn create(&self, spec: Spec) -> BResult<Sandbox> {
        if let Some(msg) = lock(&self.fail_create).clone() {
            return Err(BackendError::Message(msg));
        }
        let n = self.creates.fetch_add(1, Ordering::SeqCst) + 1;
        Ok(Sandbox {
            id: format!("fake-{n}"),
            profile: spec.profile,
            backend: "fake".into(),
            image: spec.image,
            status: "running".into(),
            isolation: self.tier,
            ..Sandbox::default()
        })
    }

    async fn exec(&self, _: &str, _: ExecRequest) -> BResult<ExecResult> {
        Ok(ExecResult::default())
    }

    async fn attach_pty(&self, _: &str, _: PtyStream) -> BResult<()> {
        Ok(())
    }

    async fn copy_files(&self, _: &str, _: &[File]) -> BResult<()> {
        Ok(())
    }

    async fn export_workspace(
        &self,
        _: &str,
        _: &mut (dyn AsyncWrite + Send + Unpin),
    ) -> BResult<()> {
        Ok(())
    }

    async fn snapshot(&self, _: &str, _: &str) -> BResult<SnapshotRef> {
        Err(BackendError::Message("unsupported".into()))
    }

    async fn restore(&self, _: &SnapshotRef) -> BResult<Sandbox> {
        Err(BackendError::Message("unsupported".into()))
    }

    async fn kill(&self, id: &str) -> BResult<()> {
        lock(&self.killed).push(id.to_owned());
        Ok(())
    }

    async fn list(&self) -> BResult<Vec<Sandbox>> {
        Ok(Vec::new())
    }

    async fn exists(&self, _: &str) -> bool {
        true
    }
}

struct FakeDriver(Arc<FakeBackend>);

#[async_trait]
impl Driver for FakeDriver {
    async fn open(&self, _: &Charter, _: &BackendConfig) -> BResult<Arc<dyn Backend>> {
        Ok(self.0.clone())
    }
}

const IMAGE: &str = "ghcr.io/example/agent:1";

struct Harness {
    mgr: Arc<Manager>,
    fake: Arc<FakeBackend>,
    _dir: tempfile::TempDir,
}

async fn harness(tier: IsolationTier) -> Harness {
    let dir = tempfile::tempdir().expect("tempdir");
    let charters = dir.path().join("charters");
    std::fs::create_dir_all(&charters).expect("mkdir");
    std::fs::write(
        charters.join("basic.toml"),
        format!("[host]\nimage = \"{IMAGE}\"\n"),
    )
    .expect("write charter");
    std::fs::write(
        charters.join("crew.toml"),
        format!(
            "[host]\nimage = \"{IMAGE}\"\n\n[cohort]\nreplicas = 2\ntask_board = [\"a\", \"b\"]\n"
        ),
    )
    .expect("write charter");
    let cfg = ManagerConfig {
        config_dir: Some(charters),
        state_dir: Some(dir.path().join("state")),
        approval_wait: None,
        sweep_interval: None,
        signed_charters: SignedCharters::Disabled,
        policy_default: None,
        ..ManagerConfig::default()
    };
    let fake = Arc::new(FakeBackend::new(tier));
    let mut registry = Registry::new();
    for host in ["", "container", "k8s"] {
        registry.register(host, Arc::new(FakeDriver(fake.clone())));
    }
    let mgr = Manager::builder(cfg)
        .registry(registry)
        .build()
        .await
        .expect("manager");
    Harness {
        mgr,
        fake,
        _dir: dir,
    }
}

// ---------------------------------------------------------------------------
// Stateful mock API server.

const PREFIX: &str = "/apis/runeward.dev/v1alpha1/";

/// Splits an API path below [`PREFIX`] into (namespace, plural, name).
fn parse(path: &str) -> Option<(Option<String>, String, Option<String>)> {
    let rest = path.strip_prefix(PREFIX)?;
    let parts: Vec<&str> = rest.split('/').collect();
    let (ns, tail) = match parts.as_slice() {
        ["namespaces", ns, tail @ ..] => (Some((*ns).to_owned()), tail),
        tail => (None, tail),
    };
    match tail {
        [plural] => Some((ns, (*plural).to_owned(), None)),
        [plural, name] | [plural, name, "status"] => {
            Some((ns, (*plural).to_owned(), Some((*name).to_owned())))
        }
        _ => None,
    }
}

/// RFC 7386 JSON merge patch.
fn merge(target: &mut Value, patch: &Value) {
    let Value::Object(p) = patch else {
        *target = patch.clone();
        return;
    };
    if !target.is_object() {
        *target = json!({});
    }
    if let Value::Object(t) = target {
        for (k, v) in p {
            if v.is_null() {
                t.remove(k);
            } else {
                merge(t.entry(k.clone()).or_insert(Value::Null), v);
            }
        }
    }
}

/// Failure injected for requests whose path ends with `suffix`.
#[derive(Clone)]
struct Fault {
    method: Method,
    suffix: &'static str,
    code: u16,
}

#[derive(Default)]
struct FakeApi {
    /// (namespace, plural, name) -> object.
    objects: Mutex<BTreeMap<(String, String, String), Value>>,
    rv: AtomicUsize,
    fault: Mutex<Option<Fault>>,
}

impl FakeApi {
    fn put(&self, mut obj: Value, plural: &str) {
        let ns = obj["metadata"]["namespace"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        let name = obj["metadata"]["name"].as_str().expect("name").to_owned();
        let rv = self.rv.fetch_add(1, Ordering::SeqCst) + 1;
        obj["metadata"]["resourceVersion"] = json!(rv.to_string());
        lock(&self.objects).insert((ns, plural.to_owned(), name), obj);
    }

    fn get(&self, ns: &str, plural: &str, name: &str) -> Option<Value> {
        lock(&self.objects)
            .get(&(ns.to_owned(), plural.to_owned(), name.to_owned()))
            .cloned()
    }

    fn respond(&self, method: &Method, target: &str, body: Option<&Value>) -> (u16, Value) {
        let (path, query) = target.split_once('?').unwrap_or((target, ""));
        if let Some(f) = lock(&self.fault).clone()
            && f.method == method
            && path.ends_with(f.suffix)
        {
            return status(f.code, "Injected");
        }
        if query.contains("watch=true") {
            // No change stream: the controllers work from the initial list.
            return status(500, "NoWatch");
        }
        let Some((ns, plural, name)) = parse(path) else {
            return status(404, "NotFound");
        };
        let mut objects = lock(&self.objects);
        let Some(name) = name else {
            let items: Vec<Value> = objects
                .iter()
                .filter(|((ons, op, _), _)| *op == plural && ns.as_ref().is_none_or(|n| n == ons))
                .map(|(_, v)| v.clone())
                .collect();
            return (
                200,
                json!({"apiVersion": "runeward.dev/v1alpha1", "kind": "List", "metadata": {"resourceVersion": self.rv.load(Ordering::SeqCst).to_string()}, "items": items}),
            );
        };
        let key = (ns.unwrap_or_default(), plural, name);
        let Some(cur) = objects.get(&key).cloned() else {
            return status(404, "NotFound");
        };
        match *method {
            Method::GET => (200, cur),
            Method::PATCH => {
                let patch = body.cloned().unwrap_or_default();
                let want_rv = &patch["metadata"]["resourceVersion"];
                if !want_rv.is_null() && *want_rv != cur["metadata"]["resourceVersion"] {
                    return status(409, "Conflict");
                }
                let mut next = cur;
                if path.ends_with("/status") {
                    merge(&mut next["status"], &patch["status"]);
                } else {
                    merge(&mut next["metadata"], &patch["metadata"]);
                }
                let rv = self.rv.fetch_add(1, Ordering::SeqCst) + 1;
                next["metadata"]["resourceVersion"] = json!(rv.to_string());
                let finalized = next["metadata"]["finalizers"]
                    .as_array()
                    .is_none_or(Vec::is_empty);
                if finalized && !next["metadata"]["deletionTimestamp"].is_null() {
                    objects.remove(&key);
                } else {
                    objects.insert(key, next.clone());
                }
                (200, next)
            }
            _ => status(405, "MethodNotAllowed"),
        }
    }
}

fn fake_client(api: &Arc<FakeApi>) -> (Client, Log) {
    let api = Arc::clone(api);
    mock_client_with_body(Arc::new(move |m, target, body, _| {
        api.respond(m, target, body)
    }))
}

fn citadel(ns: &str, name: &str, profile: &str) -> Value {
    json!({
        "apiVersion": "runeward.dev/v1alpha1",
        "kind": "Citadel",
        "metadata": {"name": name, "namespace": ns, "generation": 1, "uid": format!("uid-{name}")},
        "spec": {"profile": profile},
    })
}

fn cohort(ns: &str, name: &str, profile: &str) -> Value {
    json!({
        "apiVersion": "runeward.dev/v1alpha1",
        "kind": "Cohort",
        "metadata": {"name": name, "namespace": ns, "generation": 1, "uid": format!("uid-{name}")},
        "spec": {"profile": profile},
    })
}

fn decode<K: DeserializeOwned>(v: Value) -> K {
    serde_json::from_value(v).expect("decode")
}

fn ctx(client: Client, h: &Harness) -> Arc<Context> {
    Arc::new(Context::new(client, Arc::clone(&h.mgr), 2))
}

/// Requests other than the controller's own reads.
fn writes(log: &Log) -> Vec<(Method, String, Option<Value>)> {
    recorded(log)
        .into_iter()
        .filter(|r| r.method != Method::GET)
        .map(|r| (r.method, r.path, r.body))
        .collect()
}

const CITADEL_PATH: &str = "/apis/runeward.dev/v1alpha1/namespaces/apps/citadels/c1";

// ---------------------------------------------------------------------------
// Tests.

#[tokio::test]
async fn citadel_create_sets_finalizer_then_running_status() {
    let h = harness(IsolationTier::Kernel).await;
    let api = Arc::new(FakeApi::default());
    api.put(citadel("apps", "c1", "basic"), "citadels");
    let (client, log) = fake_client(&api);
    let c = ctx(client, &h);

    let obj: Citadel = decode(api.get("apps", "citadels", "c1").expect("obj"));
    let action = reconcile(Arc::new(obj), Arc::clone(&c))
        .await
        .expect("reconcile");
    assert_eq!(action, Action::requeue(RESYNC_PERIOD));

    let w = writes(&log);
    assert_eq!(w.len(), 2, "{w:?}");
    assert_eq!(w[0].0, Method::PATCH);
    assert_eq!(w[0].1, CITADEL_PATH);
    assert_eq!(
        w[0].2,
        Some(json!({"metadata": {"finalizers": [FINALIZER], "resourceVersion": "1"}}))
    );
    assert_eq!(w[1].1, format!("{CITADEL_PATH}/status"));

    let stored = api.get("apps", "citadels", "c1").expect("stored");
    assert_eq!(
        stored["status"],
        json!({
            "phase": "Running",
            "citadelId": "fake-1",
            "backend": "fake",
            "image": IMAGE,
            "isolation": "kernel",
            "message": "",
            "observedGeneration": 1,
        })
    );
    let typed: Citadel = decode(stored);
    let st = typed.status.expect("status");
    assert_eq!(st.isolation.as_deref(), Some("kernel"));
    assert_eq!(st.citadel_id.as_deref(), Some("fake-1"));
    assert!(h.mgr.sandbox("fake-1").is_some());
}

#[tokio::test]
async fn citadel_reconcile_is_idempotent_and_ignores_generation_bumps() {
    let h = harness(IsolationTier::Container).await;
    let api = Arc::new(FakeApi::default());
    api.put(citadel("apps", "c1", "basic"), "citadels");
    let (client, log) = fake_client(&api);
    let c = ctx(client, &h);
    let first: Citadel = decode(api.get("apps", "citadels", "c1").expect("obj"));
    reconcile(Arc::new(first), Arc::clone(&c))
        .await
        .expect("first");
    let before = writes(&log).len();

    // A spec edit bumps the generation. As in Go, a live citadel is left
    // alone: no reprovision and no status write (observedGeneration stays).
    let mut edited = api.get("apps", "citadels", "c1").expect("obj");
    edited["metadata"]["generation"] = json!(2);
    edited["spec"]["profile"] = json!("other");
    api.put(edited, "citadels");
    let obj: Citadel = decode(api.get("apps", "citadels", "c1").expect("obj"));
    let action = reconcile(Arc::new(obj), Arc::clone(&c))
        .await
        .expect("second");
    assert_eq!(action, Action::requeue(RESYNC_PERIOD));
    assert_eq!(writes(&log).len(), before, "no writes for a live citadel");
    assert_eq!(h.fake.creates.load(Ordering::SeqCst), 1);
    let stored = api.get("apps", "citadels", "c1").expect("stored");
    assert_eq!(stored["status"]["observedGeneration"], json!(1));
}

#[tokio::test]
async fn citadel_reprovisions_when_backing_sandbox_is_gone() {
    let h = harness(IsolationTier::Container).await;
    let api = Arc::new(FakeApi::default());
    let mut obj = citadel("apps", "c1", "basic");
    obj["metadata"]["finalizers"] = json!([FINALIZER]);
    obj["metadata"]["generation"] = json!(3);
    obj["status"] = json!({"phase": "Running", "citadelId": "gone", "observedGeneration": 2});
    api.put(obj, "citadels");
    let (client, log) = fake_client(&api);
    let c = ctx(client, &h);

    let obj: Citadel = decode(api.get("apps", "citadels", "c1").expect("obj"));
    reconcile(Arc::new(obj), c).await.expect("reconcile");
    let w = writes(&log);
    assert_eq!(w.len(), 1, "finalizer already present: status only");
    let stored = api.get("apps", "citadels", "c1").expect("stored");
    assert_eq!(stored["status"]["citadelId"], json!("fake-1"));
    assert_eq!(stored["status"]["observedGeneration"], json!(3));
}

#[tokio::test]
async fn citadel_delete_tears_down_then_removes_finalizer() {
    let h = harness(IsolationTier::Container).await;
    let api = Arc::new(FakeApi::default());
    let mut obj = citadel("apps", "c1", "basic");
    obj["metadata"]["finalizers"] = json!(["example.com/keep", FINALIZER]);
    api.put(obj, "citadels");
    let (client, log) = fake_client(&api);
    let c = ctx(client, &h);
    let live: Citadel = decode(api.get("apps", "citadels", "c1").expect("obj"));
    reconcile(Arc::new(live), Arc::clone(&c))
        .await
        .expect("create");
    assert!(h.mgr.sandbox("fake-1").is_some());

    let mut deleting = api.get("apps", "citadels", "c1").expect("obj");
    deleting["metadata"]["deletionTimestamp"] = json!("2026-10-19T00:00:00Z");
    api.put(deleting, "citadels");
    let before = writes(&log).len();
    let obj: Citadel = decode(api.get("apps", "citadels", "c1").expect("obj"));
    let action = reconcile(Arc::new(obj), Arc::clone(&c))
        .await
        .expect("delete");
    assert_eq!(action, Action::await_change());

    assert!(h.mgr.sandbox("fake-1").is_none(), "sandbox killed");
    assert_eq!(*lock(&h.fake.killed), vec!["fake-1".to_owned()]);
    let w = writes(&log);
    assert_eq!(w.len(), before + 1);
    let last = w.last().expect("finalizer patch");
    assert_eq!(last.1, CITADEL_PATH);
    assert_eq!(
        last.2.as_ref().expect("body")["metadata"]["finalizers"],
        json!(["example.com/keep"]),
        "only our finalizer is removed"
    );

    // Once our finalizer is gone a further pass is a no-op.
    let obj: Citadel = decode(api.get("apps", "citadels", "c1").expect("obj"));
    reconcile(Arc::new(obj), c).await.expect("noop");
    assert_eq!(writes(&log).len(), before + 1);
}

#[tokio::test]
async fn delete_without_backing_id_only_drops_finalizer() {
    let h = harness(IsolationTier::Container).await;
    let api = Arc::new(FakeApi::default());
    let mut obj = citadel("apps", "c1", "basic");
    obj["metadata"]["finalizers"] = json!([FINALIZER]);
    obj["metadata"]["deletionTimestamp"] = json!("2026-10-19T00:00:00Z");
    api.put(obj, "citadels");
    let (client, _) = fake_client(&api);
    let obj: Citadel = decode(api.get("apps", "citadels", "c1").expect("obj"));
    reconcile(Arc::new(obj), ctx(client, &h))
        .await
        .expect("delete");
    assert!(
        api.get("apps", "citadels", "c1").is_none(),
        "object released"
    );
    assert!(lock(&h.fake.killed).is_empty());
}

#[tokio::test]
async fn provision_error_records_message_and_requeues_with_backoff() {
    let h = harness(IsolationTier::Container).await;
    *lock(&h.fake.fail_create) = Some("runtime unavailable".into());
    let api = Arc::new(FakeApi::default());
    api.put(citadel("apps", "c1", "basic"), "citadels");
    let (client, _) = fake_client(&api);
    let c = ctx(client, &h);

    let obj = Arc::new(decode::<Citadel>(
        api.get("apps", "citadels", "c1").expect("obj"),
    ));
    let err = reconcile(Arc::clone(&obj), Arc::clone(&c))
        .await
        .expect_err("provision fails");
    assert!(matches!(err, Error::Provision(_)), "{err}");
    let stored = api.get("apps", "citadels", "c1").expect("stored");
    assert_eq!(stored["status"]["phase"], json!("Failed"));
    let msg = stored["status"]["message"].as_str().expect("message");
    assert!(msg.contains("runtime unavailable"), "{msg}");
    assert_eq!(stored["status"]["observedGeneration"], json!(1));
    assert!(stored["status"]["citadelId"].is_null());

    // The error policy requeues with growing per-resource backoff.
    let a1 = error_policy(Arc::clone(&obj), &err, Arc::clone(&c));
    let a2 = error_policy(Arc::clone(&obj), &err, Arc::clone(&c));
    assert_eq!(a1, Action::requeue(Duration::from_millis(5)));
    assert_eq!(a2, Action::requeue(Duration::from_millis(10)));

    // Recovery clears the backoff and records Running.
    *lock(&h.fake.fail_create) = None;
    let obj = Arc::new(decode::<Citadel>(
        api.get("apps", "citadels", "c1").expect("obj"),
    ));
    reconcile(Arc::clone(&obj), Arc::clone(&c))
        .await
        .expect("recovers");
    let stored = api.get("apps", "citadels", "c1").expect("stored");
    assert_eq!(stored["status"]["phase"], json!("Running"));
    assert_eq!(stored["status"]["message"], json!(""));
    assert_eq!(
        error_policy(obj, &err, c),
        Action::requeue(Duration::from_millis(5))
    );
}

#[tokio::test]
async fn empty_profile_is_failed_without_provisioning() {
    let h = harness(IsolationTier::Container).await;
    let api = Arc::new(FakeApi::default());
    api.put(citadel("apps", "c1", ""), "citadels");
    let (client, _) = fake_client(&api);
    let obj: Citadel = decode(api.get("apps", "citadels", "c1").expect("obj"));
    reconcile(Arc::new(obj), ctx(client, &h))
        .await
        .expect("reconcile");
    let stored = api.get("apps", "citadels", "c1").expect("stored");
    assert_eq!(stored["status"]["phase"], json!("Failed"));
    assert_eq!(
        stored["status"]["message"],
        json!("spec.profile is required")
    );
    assert_eq!(h.fake.creates.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn kube_errors_propagate_for_requeue() {
    let h = harness(IsolationTier::Container).await;
    let api = Arc::new(FakeApi::default());
    api.put(citadel("apps", "c1", "basic"), "citadels");
    *lock(&api.fault) = Some(Fault {
        method: Method::PATCH,
        suffix: "/c1",
        code: 500,
    });
    let (client, _) = fake_client(&api);
    let obj: Citadel = decode(api.get("apps", "citadels", "c1").expect("obj"));
    let err = reconcile(Arc::new(obj), ctx(client, &h))
        .await
        .expect_err("finalizer patch fails");
    assert!(matches!(err, Error::Kube(_)), "{err}");
    assert_eq!(h.fake.creates.load(Ordering::SeqCst), 0, "nothing created");
}

#[tokio::test]
async fn unrecorded_citadel_is_torn_down() {
    let h = harness(IsolationTier::Container).await;
    let api = Arc::new(FakeApi::default());
    let mut obj = citadel("apps", "c1", "basic");
    obj["metadata"]["finalizers"] = json!([FINALIZER]);
    api.put(obj, "citadels");
    *lock(&api.fault) = Some(Fault {
        method: Method::PATCH,
        suffix: "/status",
        code: 500,
    });
    let (client, _) = fake_client(&api);
    let obj: Citadel = decode(api.get("apps", "citadels", "c1").expect("obj"));
    reconcile(Arc::new(obj), ctx(client, &h))
        .await
        .expect_err("status write fails");
    assert_eq!(*lock(&h.fake.killed), vec!["fake-1".to_owned()]);
    assert!(h.mgr.list_sandboxes().is_empty());
}

#[tokio::test]
async fn stale_object_conflicts_on_finalizer_patch() {
    let h = harness(IsolationTier::Container).await;
    let api = Arc::new(FakeApi::default());
    api.put(citadel("apps", "c1", "basic"), "citadels");
    let stale: Citadel = decode(api.get("apps", "citadels", "c1").expect("obj"));
    // Someone else writes in between.
    api.put(api.get("apps", "citadels", "c1").expect("obj"), "citadels");
    let (client, _) = fake_client(&api);
    let err = reconcile(Arc::new(stale), ctx(client, &h))
        .await
        .expect_err("conflict");
    assert!(matches!(err, Error::Kube(_)), "{err}");
    assert_eq!(h.fake.creates.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn cohort_lifecycle() {
    let h = harness(IsolationTier::Container).await;
    let api = Arc::new(FakeApi::default());
    api.put(cohort("apps", "k1", "crew"), "cohorts");
    let (client, log) = fake_client(&api);
    let c = ctx(client, &h);

    let obj: Cohort = decode(api.get("apps", "cohorts", "k1").expect("obj"));
    reconcile(Arc::new(obj), Arc::clone(&c))
        .await
        .expect("create");
    let stored = api.get("apps", "cohorts", "k1").expect("stored");
    let st = &stored["status"];
    let id = st["cohortId"].as_str().expect("cohortId").to_owned();
    assert_eq!(st["phase"], json!("Running"));
    assert_eq!(st["citadels"], json!(["fake-1", "fake-2"]));
    assert_eq!(
        (
            &st["tasksTotal"],
            &st["tasksPending"],
            &st["tasksClaimed"],
            &st["tasksDone"],
            &st["tasksFailed"]
        ),
        (&json!(2), &json!(2), &json!(0), &json!(0), &json!(0))
    );
    assert_eq!(st["message"], json!(""));
    assert_eq!(st["observedGeneration"], json!(1));

    // Progress on the board plus a generation bump: as in Go the existing
    // cohort is kept and its status refreshed with the new generation.
    let task = h
        .mgr
        .claim_task(&id, "w1")
        .await
        .expect("claim")
        .expect("task");
    h.mgr
        .complete_task(&id, &task.id, "w1", &task.lease_token, "ok")
        .await
        .expect("complete");
    let mut edited = stored.clone();
    edited["metadata"]["generation"] = json!(2);
    api.put(edited, "cohorts");
    let obj: Cohort = decode(api.get("apps", "cohorts", "k1").expect("obj"));
    reconcile(Arc::new(obj), Arc::clone(&c))
        .await
        .expect("refresh");
    let st = api.get("apps", "cohorts", "k1").expect("stored")["status"].clone();
    assert_eq!(st["cohortId"], json!(id));
    assert_eq!(
        (&st["tasksDone"], &st["tasksPending"]),
        (&json!(1), &json!(1))
    );
    assert_eq!(st["observedGeneration"], json!(2));
    assert_eq!(h.fake.creates.load(Ordering::SeqCst), 2, "no new members");

    // Deletion kills the cohort and its members, then releases the object.
    let mut deleting = api.get("apps", "cohorts", "k1").expect("obj");
    deleting["metadata"]["deletionTimestamp"] = json!("2026-10-19T00:00:00Z");
    api.put(deleting, "cohorts");
    let obj: Cohort = decode(api.get("apps", "cohorts", "k1").expect("obj"));
    reconcile(Arc::new(obj), c).await.expect("delete");
    assert!(h.mgr.fleet_view(&id).is_none());
    assert_eq!(lock(&h.fake.killed).len(), 2);
    assert!(api.get("apps", "cohorts", "k1").is_none());
    assert!(
        writes(&log).iter().all(
            |(_, p, _)| p.starts_with("/apis/runeward.dev/v1alpha1/namespaces/apps/cohorts/k1")
        )
    );
}

#[tokio::test]
async fn cluster_citadel_uses_cluster_scoped_paths() {
    let h = harness(IsolationTier::Container).await;
    let api = Arc::new(FakeApi::default());
    let mut obj = citadel("", "g1", "basic");
    obj["kind"] = json!("ClusterCitadel");
    obj["metadata"]
        .as_object_mut()
        .expect("meta")
        .remove("namespace");
    api.put(obj, "clustercitadels");
    let (client, log) = fake_client(&api);
    let obj: ClusterCitadel = decode(api.get("", "clustercitadels", "g1").expect("obj"));
    reconcile(Arc::new(obj), ctx(client, &h))
        .await
        .expect("reconcile");
    let paths: Vec<String> = writes(&log).into_iter().map(|w| w.1).collect();
    assert_eq!(
        paths,
        [
            "/apis/runeward.dev/v1alpha1/clustercitadels/g1",
            "/apis/runeward.dev/v1alpha1/clustercitadels/g1/status"
        ]
    );
    let stored = api.get("", "clustercitadels", "g1").expect("stored");
    assert_eq!(stored["status"]["citadelId"], json!("fake-1"));
}

#[test]
fn backoff_doubles_and_caps() {
    assert_eq!(backoff(1), Duration::from_millis(5));
    assert_eq!(backoff(2), Duration::from_millis(10));
    assert_eq!(backoff(10), Duration::from_millis(5 * 512));
    assert_eq!(backoff(40), BACKOFF_MAX);
    assert_eq!(backoff(u32::MAX), BACKOFF_MAX);
}

#[test]
fn options_scope() {
    let d = ControllerOptions::default();
    assert_eq!(d.workers, 2);
    assert_eq!(d.watch_namespace(), Some("runeward"));
    let all = ControllerOptions {
        all_namespaces: true,
        ..d.clone()
    };
    assert_eq!(all.watch_namespace(), None);
    let empty = ControllerOptions {
        namespace: String::new(),
        ..d
    };
    assert_eq!(empty.watch_namespace(), None);
}

/// Polls until `f` holds or the deadline passes.
async fn eventually(mut f: impl FnMut() -> bool) -> bool {
    for _ in 0..400 {
        if f() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    false
}

/// Starts [`run`] over a namespaced citadel in `apps` and `other`, a cohort
/// in `apps` and a cluster citadel, waits until every `(namespace, plural,
/// name)` in `expect` is Running, then shuts the controller down.
async fn run_scoped(
    opts: ControllerOptions,
    expect: &[(&str, &str, &str)],
) -> (Arc<FakeApi>, Log, Harness) {
    let h = harness(IsolationTier::Container).await;
    let api = Arc::new(FakeApi::default());
    api.put(citadel("apps", "a", "basic"), "citadels");
    api.put(citadel("other", "b", "basic"), "citadels");
    api.put(cohort("apps", "k", "crew"), "cohorts");
    let mut g = citadel("", "g", "basic");
    g["kind"] = json!("ClusterCitadel");
    g["metadata"]
        .as_object_mut()
        .expect("meta")
        .remove("namespace");
    api.put(g, "clustercitadels");
    let (client, log) = fake_client(&api);
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let task = tokio::spawn(run(client, Arc::clone(&h.mgr), opts, async move {
        let _ = rx.await;
    }));
    let api2 = Arc::clone(&api);
    assert!(
        eventually(|| expect.iter().all(|(ns, plural, name)| {
            api2.get(ns, plural, name)
                .is_some_and(|o| o["status"]["phase"] == "Running")
        }))
        .await,
        "reconciled {expect:?}"
    );
    let _ = tx.send(());
    tokio::time::timeout(Duration::from_secs(10), task)
        .await
        .expect("shuts down")
        .expect("join")
        .expect("run");
    let watches = recorded(&log)
        .iter()
        .filter(|r| r.query.contains("watch=true"))
        .count();
    assert!(watches < 40, "watch retries back off: {watches}");
    (api, log, h)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn run_watches_one_namespace() {
    let (api, log, h) = run_scoped(
        ControllerOptions {
            namespace: "apps".into(),
            ..ControllerOptions::default()
        },
        &[
            ("apps", "citadels", "a"),
            ("apps", "cohorts", "k"),
            ("", "clustercitadels", "g"),
        ],
    )
    .await;
    assert!(
        api.get("other", "citadels", "b").expect("b")["status"].is_null(),
        "other namespace untouched"
    );
    let lists: Vec<String> = recorded(&log)
        .into_iter()
        .filter(|r| r.method == Method::GET && !r.query.contains("watch=true"))
        .map(|r| r.path)
        .collect();
    for p in [
        "/apis/runeward.dev/v1alpha1/namespaces/apps/citadels",
        "/apis/runeward.dev/v1alpha1/namespaces/apps/cohorts",
        "/apis/runeward.dev/v1alpha1/clustercitadels",
        "/apis/runeward.dev/v1alpha1/clustercohorts",
    ] {
        assert!(lists.iter().any(|l| l == p), "listed {p}: {lists:?}");
    }
    // One citadel, one cluster citadel and two cohort members.
    assert_eq!(h.mgr.list_sandboxes().len(), 4);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn run_all_namespaces() {
    let (_, log, h) = run_scoped(
        ControllerOptions {
            all_namespaces: true,
            ..ControllerOptions::default()
        },
        &[
            ("apps", "citadels", "a"),
            ("other", "citadels", "b"),
            ("apps", "cohorts", "k"),
            ("", "clustercitadels", "g"),
        ],
    )
    .await;
    assert!(
        recorded(&log)
            .iter()
            .any(|r| r.path == "/apis/runeward.dev/v1alpha1/citadels"),
        "citadels listed cluster-wide"
    );
    // Three citadels plus two cohort members.
    assert_eq!(h.mgr.list_sandboxes().len(), 5);
}
