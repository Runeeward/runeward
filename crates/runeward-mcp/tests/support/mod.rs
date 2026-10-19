//! An in-memory backend, a manager harness and an in-process MCP client.
//! No Docker, Kubernetes or network.

#![allow(dead_code, clippy::unwrap_used)]

use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use rmcp::model::{CallToolRequestParams, CallToolResult, JsonObject};
use rmcp::service::RunningService;
use rmcp::{RoleClient, ServiceExt};
use runeward_authz::{Principal, Store};
use runeward_backend::{
    Backend, BackendConfig, Driver, ExecRequest, ExecResult, IsolationTier, PtyStream, Registry,
    Result as BResult, Sandbox, SnapshotRef, Spec,
};
use runeward_charter::{Charter, File, PolicyRule, SignedCharters, Verdict};
use runeward_controlplane::{Manager, ManagerConfig, Session};
use runeward_mcp::{McpConfig, McpServer};
use runeward_policy::RuleEngine;
use serde_json::Value;
use tokio::io::{AsyncWrite, AsyncWriteExt};

/// Echoes argv as stdout (`false` exits 1), like the Go test backend.
#[derive(Debug, Default)]
pub struct FakeBackend {
    pub creates: AtomicUsize,
    pub killed: Mutex<Vec<String>>,
}

#[async_trait]
impl Backend for FakeBackend {
    fn name(&self) -> &str {
        "fake"
    }

    fn isolation_tier(&self) -> IsolationTier {
        IsolationTier::Container
    }

    async fn create(&self, spec: Spec) -> BResult<Sandbox> {
        let n = self.creates.fetch_add(1, Ordering::SeqCst) + 1;
        Ok(Sandbox {
            id: format!("created-{n}"),
            profile: spec.profile,
            backend: "fake".into(),
            image: spec.image,
            status: "running".into(),
            ..Sandbox::default()
        })
    }

    async fn exec(&self, _: &str, req: ExecRequest) -> BResult<ExecResult> {
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
            id: format!("snap-{id}"),
            name: name.into(),
            backend: "fake".into(),
            profile: String::new(),
            location: format!("snapshots/{id}"),
            sha256: String::new(),
            created: chrono::DateTime::UNIX_EPOCH,
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
        self.killed.lock().unwrap().push(id.to_owned());
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

pub struct Harness {
    pub mgr: Arc<Manager>,
    pub fake: Arc<FakeBackend>,
    pub dir: tempfile::TempDir,
}

pub const BASIC_CHARTER: &str =
    "[host]\ntype = \"container\"\nimage = \"ghcr.io/example/agent:1\"\n";

impl Harness {
    pub async fn new() -> Self {
        Self::with(|_| {}, |_| {}).await
    }

    /// `seed` runs on the temp dir before the manager loads state.
    pub async fn with(seed: impl FnOnce(&Path), tweak: impl FnOnce(&mut ManagerConfig)) -> Self {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("state")).unwrap();
        std::fs::create_dir_all(dir.path().join("charters")).unwrap();
        seed(dir.path());
        let mut cfg = ManagerConfig {
            config_dir: Some(dir.path().join("charters")),
            state_dir: Some(dir.path().join("state")),
            approval_wait: Some(Duration::from_millis(20)),
            sweep_interval: None,
            sign_ledger: false,
            signed_charters: SignedCharters::Disabled,
            policy_default: None,
            ..ManagerConfig::default()
        };
        tweak(&mut cfg);
        let fake = Arc::new(FakeBackend::default());
        let mut registry = Registry::new();
        for host in ["", "container", "k8s"] {
            registry.register(host, Arc::new(FakeDriver(fake.clone())));
        }
        let mgr = Manager::builder(cfg)
            .registry(registry)
            .build()
            .await
            .unwrap();
        Self { mgr, fake, dir }
    }

    pub fn write_charter(&self, name: &str, body: &str) {
        std::fs::write(
            self.dir
                .path()
                .join("charters")
                .join(format!("{name}.toml")),
            body,
        )
        .unwrap();
    }

    /// Registers Citadel `id` (Charter `test`, python and node declared)
    /// owned by `owner`, with `rules` over an allow default.
    pub fn inject(&self, id: &str, owner: &str, rules: Vec<PolicyRule>) {
        let charter = Charter {
            name: "test".into(),
            capabilities: vec!["python".into(), "node".into()],
            ..Charter::default()
        };
        let sb = Sandbox {
            id: id.into(),
            profile: "test".into(),
            backend: "fake".into(),
            status: "running".into(),
            ..Sandbox::default()
        };
        let sess = Session::builder(sb, self.fake.clone(), charter)
            .owner(owner)
            .engine(Box::new(RuleEngine::new(rules, Verdict::Allow)))
            .build()
            .unwrap();
        self.mgr.inject_session(sess);
    }

    pub async fn records(&self) -> Vec<runeward_ledger::Event> {
        let ledger = self.mgr.ledger().clone();
        tokio::task::spawn_blocking(move || ledger.records().unwrap())
            .await
            .unwrap()
    }
}

pub fn rule(tool: &str, glob: &str, verdict: Verdict, reason: &str) -> PolicyRule {
    PolicyRule {
        tool: tool.into(),
        match_glob: glob.into(),
        match_argv: String::new(),
        verdict,
        reason: reason.into(),
    }
}

pub fn principal(name: &str, tenant: &str, token: &str, profiles: &[&str]) -> Principal {
    Principal {
        name: name.into(),
        tenant: tenant.into(),
        token: token.into(),
        allowed_profiles: profiles.iter().map(|s| (*s).to_owned()).collect(),
        ..Principal::default()
    }
}

pub fn store(principals: Vec<Principal>) -> Arc<Store> {
    Arc::new(Store::from_principals(principals).unwrap())
}

/// An rmcp client connected in-process (stdio semantics: no HTTP parts).
pub struct Client {
    pub service: RunningService<RoleClient, ()>,
}

impl Client {
    pub async fn connect(server: McpServer) -> Self {
        let (server_io, client_io) = tokio::io::duplex(1 << 20);
        tokio::spawn(async move {
            if let Ok(running) = server.serve(server_io).await {
                let _ = running.waiting().await;
            }
        });
        let service = ().serve(client_io).await.unwrap();
        Self { service }
    }

    pub async fn stdio(mgr: &Arc<Manager>, authz: Option<Arc<Store>>, config: McpConfig) -> Self {
        Self::connect(McpServer::new(mgr.clone(), authz, &config).await).await
    }

    pub async fn call(&self, name: &str, args: Value) -> CallToolResult {
        let mut params = CallToolRequestParams::new(name.to_owned());
        if let Value::Object(map) = args {
            params = params.with_arguments(map);
        }
        self.service.call_tool(params).await.unwrap()
    }

    pub async fn call_raw(&self, name: &str, args: JsonObject) -> Result<CallToolResult, String> {
        let params = CallToolRequestParams::new(name.to_owned()).with_arguments(args);
        self.service
            .call_tool(params)
            .await
            .map_err(|e| e.to_string())
    }
}

/// The concatenated text content of a result.
pub fn text(r: &CallToolResult) -> String {
    r.content
        .iter()
        .filter_map(|c| c.as_text().map(|t| t.text.clone()))
        .collect()
}

/// The text content parsed as JSON.
pub fn json(r: &CallToolResult) -> Value {
    serde_json::from_str(&text(r)).unwrap_or(Value::Null)
}

pub fn is_error(r: &CallToolResult) -> bool {
    r.is_error == Some(true)
}
