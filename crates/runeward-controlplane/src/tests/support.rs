//! A scriptable in-memory backend and a manager harness around it.

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use chrono::TimeZone;
use runeward_backend::{
    Backend, BackendConfig, Driver, ExecRequest, ExecResult, IsolationTier, PtyStream, Registry,
    Result as BResult, Sandbox, SnapshotRef, Spec,
};
use runeward_charter::{Charter, File, PolicyRule, SignedCharters, Verdict};
use runeward_ledger::Event;
use runeward_policy::RuleEngine;
use tokio::io::{AsyncWrite, AsyncWriteExt};

use crate::{Manager, ManagerConfig, Session};

pub(crate) fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Echoes commands (stdout = argv joined) so tests run without a runtime.
#[derive(Debug)]
pub(crate) struct FakeBackend {
    pub(crate) tier: Mutex<IsolationTier>,
    pub(crate) execs: AtomicUsize,
    pub(crate) creates: AtomicUsize,
    pub(crate) calls: Mutex<Vec<Vec<String>>>,
    pub(crate) killed: Mutex<Vec<String>>,
    /// Fixed result for every exec.
    pub(crate) result: Mutex<Option<ExecResult>>,
    /// Writes canned output to the stream writers.
    pub(crate) streaming: Mutex<bool>,
    /// Sleeps before answering an exec.
    pub(crate) delay: Mutex<Option<Duration>>,
    /// The last Spec handed to create.
    pub(crate) last_spec: Mutex<Option<Spec>>,
    /// Whether a requested supervisor runs (an image with the binary).
    pub(crate) supervisor_present: Mutex<bool>,
    /// The report a running supervisor returns.
    pub(crate) report: Mutex<String>,
}

impl Default for FakeBackend {
    fn default() -> Self {
        Self {
            tier: Mutex::new(IsolationTier::Container),
            execs: AtomicUsize::new(0),
            creates: AtomicUsize::new(0),
            calls: Mutex::new(Vec::new()),
            killed: Mutex::new(Vec::new()),
            result: Mutex::new(None),
            streaming: Mutex::new(false),
            delay: Mutex::new(None),
            last_spec: Mutex::new(None),
            supervisor_present: Mutex::new(true),
            report: Mutex::new(String::new()),
        }
    }
}

impl FakeBackend {
    pub(crate) fn execs(&self) -> usize {
        self.execs.load(Ordering::SeqCst)
    }

    pub(crate) fn set_result(&self, r: ExecResult) {
        *lock(&self.result) = Some(r);
    }
}

async fn write_to(w: &mut Option<runeward_backend::BoxWriter>, data: &str) {
    if let Some(w) = w.as_mut() {
        let _ = w.write_all(data.as_bytes()).await;
    }
}

#[async_trait]
impl Backend for FakeBackend {
    fn name(&self) -> &str {
        "fake"
    }

    fn isolation_tier(&self) -> IsolationTier {
        *lock(&self.tier)
    }

    async fn create(&self, spec: Spec) -> BResult<Sandbox> {
        let n = self.creates.fetch_add(1, Ordering::SeqCst) + 1;
        if let Some(s) = &spec.supervisor
            && s.required
            && !*lock(&self.supervisor_present)
        {
            return Err(runeward_backend::BackendError::Unsupported(
                "image lacks the supervisor".into(),
            ));
        }
        let id = if spec.id.is_empty() {
            format!("fake-{n}")
        } else {
            spec.id.clone()
        };
        *lock(&self.last_spec) = Some(spec.clone());
        Ok(Sandbox {
            id,
            profile: spec.profile,
            backend: "fake".into(),
            status: "running".into(),
            isolation: *lock(&self.tier),
            ..Sandbox::default()
        })
    }

    async fn exec(&self, _: &str, mut req: ExecRequest) -> BResult<ExecResult> {
        self.execs.fetch_add(1, Ordering::SeqCst);
        lock(&self.calls).push(req.command.clone());
        let delay = *lock(&self.delay);
        if let Some(d) = delay {
            tokio::time::sleep(d).await;
        }
        if *lock(&self.streaming) {
            write_to(
                &mut req.stdout,
                "hello\nsecret=sk-ant-abcdefghijklmnopqrstuvwxyz\npartial",
            )
            .await;
            write_to(&mut req.stderr, "warning\n").await;
            return Ok(ExecResult {
                duration: Duration::from_millis(1),
                ..ExecResult::default()
            });
        }
        if let Some(r) = lock(&self.result).clone() {
            return Ok(r);
        }
        if req.command.first().is_some_and(|c| c == "false") {
            return Ok(ExecResult {
                exit_code: 1,
                stderr: "failed".into(),
                duration: Duration::from_millis(1),
                ..ExecResult::default()
            });
        }
        Ok(ExecResult {
            stdout: req.command.join(" "),
            duration: Duration::from_millis(1),
            ..ExecResult::default()
        })
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
        w: &mut (dyn AsyncWrite + Send + Unpin),
    ) -> BResult<()> {
        let _ = w.write_all(b"tar").await;
        Ok(())
    }

    async fn snapshot(&self, id: &str, name: &str) -> BResult<SnapshotRef> {
        Ok(SnapshotRef {
            id: "snapshot-1".into(),
            name: name.into(),
            profile: String::new(),
            backend: "fake".into(),
            location: format!("snapshots/{id}"),
            sha256: String::new(),
            created: chrono::Utc
                .timestamp_opt(1_700_000_000, 0)
                .single()
                .unwrap_or_default(),
        })
    }

    async fn restore(&self, s: &SnapshotRef) -> BResult<Sandbox> {
        self.create(Spec {
            profile: s.profile.clone(),
            ..Spec::default()
        })
        .await
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

    async fn supervisor_report(&self, _: &str) -> BResult<Option<String>> {
        let supervised = lock(&self.last_spec)
            .as_ref()
            .is_some_and(|s| s.supervisor.is_some());
        if !supervised || !*lock(&self.supervisor_present) {
            return Ok(None);
        }
        Ok(Some(lock(&self.report).clone()))
    }
}

/// The value `env://RW_TEST_API_TOKEN` resolves to in the harness.
pub(crate) const TEST_TOKEN: &str = "tok-0123-real-secret";

/// Resolves `env://RW_TEST_API_TOKEN` without touching the process
/// environment; every other reference goes to the real env resolver.
#[derive(Debug)]
struct TestEnv;

impl runeward_secrets::Resolver for TestEnv {
    fn resolve<'a>(&'a self, reference: &'a str) -> runeward_secrets::ResolveFuture<'a> {
        Box::pin(async move {
            if reference == "env://RW_TEST_API_TOKEN" {
                Ok(TEST_TOKEN.to_owned())
            } else {
                runeward_secrets::Resolver::resolve(&runeward_secrets::EnvResolver, reference).await
            }
        })
    }
}

/// Hands out the shared fake for every Charter.
struct FakeDriver(Arc<FakeBackend>);

#[async_trait]
impl Driver for FakeDriver {
    async fn open(&self, _: &Charter, _: &BackendConfig) -> BResult<Arc<dyn Backend>> {
        Ok(self.0.clone())
    }
}

pub(crate) struct Harness {
    pub(crate) mgr: Arc<Manager>,
    pub(crate) fake: Arc<FakeBackend>,
    pub(crate) dir: tempfile::TempDir,
}

impl Harness {
    pub(crate) fn state_dir(&self) -> PathBuf {
        self.dir.path().join("state")
    }

    pub(crate) fn charter_dir(&self) -> PathBuf {
        self.dir.path().join("charters")
    }

    /// Writes `<name>.toml` into the Charter directory.
    pub(crate) fn write_charter(&self, name: &str, body: &str) {
        std::fs::create_dir_all(self.charter_dir()).expect("mkdir");
        std::fs::write(self.charter_dir().join(format!("{name}.toml")), body)
            .expect("write charter");
    }

    /// Registers session `fake-1` (Charter `test`) like the Go tests did.
    pub(crate) fn inject(&self, charter: Charter, rules: Vec<PolicyRule>) -> Arc<Session> {
        self.inject_with(charter, rules, |b| b)
    }

    pub(crate) fn inject_with(
        &self,
        mut charter: Charter,
        rules: Vec<PolicyRule>,
        f: impl FnOnce(crate::SessionBuilder) -> crate::SessionBuilder,
    ) -> Arc<Session> {
        if charter.name.is_empty() {
            charter.name = "test".into();
        }
        let sb = Sandbox {
            id: "fake-1".into(),
            profile: charter.name.clone(),
            backend: "fake".into(),
            status: "running".into(),
            ..Sandbox::default()
        };
        let b = Session::builder(sb, self.fake.clone(), charter)
            .engine(Box::new(RuleEngine::new(rules, Verdict::Allow)));
        self.mgr.inject_session(f(b).build().expect("session"))
    }

    pub(crate) async fn records(&self) -> Vec<Event> {
        let ledger = self.mgr.ledger().clone();
        tokio::task::spawn_blocking(move || ledger.records().expect("records"))
            .await
            .expect("join")
    }
}

/// Test configuration: state under the temp dir, no sweeper, unsigned
/// Charters accepted.
pub(crate) fn config(dir: &std::path::Path, approval_wait: Option<Duration>) -> ManagerConfig {
    ManagerConfig {
        config_dir: Some(dir.join("charters")),
        state_dir: Some(dir.join("state")),
        approval_wait,
        sweep_interval: None,
        signed_charters: SignedCharters::Disabled,
        policy_default: None,
        ..ManagerConfig::default()
    }
}

pub(crate) async fn harness_with(
    approval_wait: Option<Duration>,
    tweak: impl FnOnce(&mut ManagerConfig),
) -> Harness {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut cfg = config(dir.path(), approval_wait);
    tweak(&mut cfg);
    let fake = Arc::new(FakeBackend::default());
    let mut registry = Registry::new();
    for host in ["", "container", "k8s"] {
        registry.register(host, Arc::new(FakeDriver(fake.clone())));
    }
    let resolver = runeward_secrets::Dispatcher {
        env: Some(Box::new(TestEnv)),
        ..runeward_secrets::Dispatcher::default()
    };
    let mgr = Manager::builder(cfg)
        .registry(registry)
        .resolver(resolver)
        .build()
        .await
        .expect("manager");
    Harness { mgr, fake, dir }
}

pub(crate) async fn harness(approval_wait: Option<Duration>) -> Harness {
    harness_with(approval_wait, |_| {}).await
}

pub(crate) fn rule(tool: &str, glob: &str, verdict: Verdict, reason: &str) -> PolicyRule {
    PolicyRule {
        tool: tool.into(),
        match_glob: glob.into(),
        match_argv: String::new(),
        verdict,
        reason: reason.into(),
    }
}

pub(crate) fn argv(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|s| (*s).to_owned()).collect()
}
