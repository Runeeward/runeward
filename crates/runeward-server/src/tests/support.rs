//! An in-memory backend, a Manager harness and request helpers.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{HeaderMap, Request, StatusCode};
use runeward_authz::Store;
use runeward_backend::{
    Backend, BackendConfig, Driver, ExecRequest, ExecResult, IsolationTier, PtyStream, Registry,
    Result as BResult, Sandbox, SnapshotRef, Spec,
};
use runeward_charter::{Charter, File, SignedCharters};
use runeward_controlplane::{Manager, ManagerConfig, Session};
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tower::ServiceExt;

use crate::Server;

/// Echoes exec argv; the terminal echoes stdin back to stdout.
#[derive(Debug, Default)]
pub(crate) struct FakeBackend;

#[async_trait]
impl Backend for FakeBackend {
    fn name(&self) -> &str {
        "fake"
    }

    fn isolation_tier(&self) -> IsolationTier {
        IsolationTier::Container
    }

    async fn create(&self, spec: Spec) -> BResult<Sandbox> {
        Ok(Sandbox {
            id: "fake-1".into(),
            profile: spec.profile,
            backend: "fake".into(),
            status: "running".into(),
            ..Sandbox::default()
        })
    }

    async fn exec(&self, _: &str, req: ExecRequest) -> BResult<ExecResult> {
        Ok(ExecResult {
            stdout: req.command.join(" "),
            duration: Duration::from_millis(1),
            ..ExecResult::default()
        })
    }

    async fn attach_pty(&self, _: &str, mut stream: PtyStream) -> BResult<()> {
        let (Some(mut stdin), Some(mut stdout)) = (stream.stdin.take(), stream.stdout.take())
        else {
            return Ok(());
        };
        let mut buf = [0u8; 1024];
        loop {
            match stdin.read(&mut buf).await {
                Ok(0) | Err(_) => return Ok(()),
                Ok(n) => {
                    if stdout.write_all(&buf[..n]).await.is_err() {
                        return Ok(());
                    }
                }
            }
        }
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
            created: chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap_or_default(),
        })
    }

    async fn restore(&self, _: &SnapshotRef) -> BResult<Sandbox> {
        Ok(Sandbox::default())
    }

    async fn kill(&self, _: &str) -> BResult<()> {
        Ok(())
    }

    async fn list(&self) -> BResult<Vec<Sandbox>> {
        Ok(Vec::new())
    }

    async fn exists(&self, _: &str) -> bool {
        true
    }
}

struct FakeDriver;

#[async_trait]
impl Driver for FakeDriver {
    async fn open(&self, _: &Charter, _: &BackendConfig) -> BResult<Arc<dyn Backend>> {
        Ok(Arc::new(FakeBackend))
    }
}

/// A Manager over the fake backend with state and Charters in a temp dir.
pub(crate) struct Harness {
    pub(crate) mgr: Arc<Manager>,
    pub(crate) dir: tempfile::TempDir,
}

impl Harness {
    /// Registers a running Citadel `id` with a Charter `profile` (loaded
    /// from the Charter dir when present).
    pub(crate) async fn inject(&self, id: &str, profile: &str, owner: &str) {
        let charter = self
            .mgr
            .load_profile(profile)
            .await
            .unwrap_or_else(|_| Charter {
                name: profile.into(),
                ..Charter::default()
            });
        self.inject_charter(id, charter, owner);
    }

    pub(crate) fn inject_charter(&self, id: &str, charter: Charter, owner: &str) {
        let sb = Sandbox {
            id: id.into(),
            profile: charter.name.clone(),
            backend: "fake".into(),
            image: "debian:stable-slim".into(),
            status: "running".into(),
            ..Sandbox::default()
        };
        let sess = Session::builder(sb, Arc::new(FakeBackend), charter)
            .workdir("/workspace")
            .owner(owner)
            .build()
            .expect("session");
        self.mgr.inject_session(sess);
    }
}

/// Builds a harness; `tweak` adjusts the config, `before` prepares the
/// directory (state files, Charters) before the Manager loads it.
pub(crate) async fn harness_with(
    tweak: impl FnOnce(&mut ManagerConfig),
    before: impl FnOnce(&Path),
) -> Harness {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(dir.path().join("charters")).expect("mkdir charters");
    std::fs::create_dir_all(dir.path().join("state")).expect("mkdir state");
    before(dir.path());
    let mut cfg = ManagerConfig {
        config_dir: Some(dir.path().join("charters")),
        state_dir: Some(dir.path().join("state")),
        sweep_interval: None,
        context_tick: None,
        signed_charters: SignedCharters::Disabled,
        policy_default: None,
        ..ManagerConfig::default()
    };
    tweak(&mut cfg);
    let mut registry = Registry::new();
    for host in ["", "container", "k8s"] {
        registry.register(host, Arc::new(FakeDriver));
    }
    let mgr = Manager::builder(cfg)
        .registry(registry)
        .build()
        .await
        .expect("manager");
    Harness { mgr, dir }
}

pub(crate) async fn harness() -> Harness {
    harness_with(|_| {}, |_| {}).await
}

/// Writes a principals file (mode 0600) and loads it.
pub(crate) fn authz_store(dir: &Path, json: &str) -> Arc<Store> {
    let path = dir.join("authz.json");
    std::fs::write(&path, json).expect("write authz");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
    }
    Arc::new(Store::load(&path).expect("load authz"))
}

pub(crate) const RBAC_PRINCIPALS: &str = r#"{
    "principals":[
        {"name":"admin","token":"tok-admin","admin":true},
        {"name":"alice","tenant":"team-alpha","token":"tok-alice","allowed_profiles":["team-*"]},
        {"name":"bob","tenant":"team-alpha","token":"tok-bob","allowed_profiles":["team-*"]},
        {"name":"eve","tenant":"team-other","token":"tok-eve","allowed_profiles":["team-*"]},
        {"name":"reviewer","tenant":"team-alpha","token":"tok-reviewer","can_approve":true,"allowed_profiles":["team-*"]}
    ]
}"#;

/// The server under test, without rate limiting.
pub(crate) fn server(h: &Harness) -> Server {
    Server::new(Arc::clone(&h.mgr)).rate_limit(None)
}

pub(crate) fn router_with_token(h: &Harness, token: &str) -> Router {
    server(h).token(token).router()
}

pub(crate) fn router_with_rbac(h: &Harness) -> Router {
    server(h)
        .authz(Some(authz_store(h.dir.path(), RBAC_PRINCIPALS)))
        .router()
}

/// A response with its body collected.
#[derive(Debug)]
pub(crate) struct Reply {
    pub(crate) status: StatusCode,
    pub(crate) headers: HeaderMap,
    pub(crate) body: bytes::Bytes,
}

impl Reply {
    pub(crate) fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).unwrap_or(serde_json::Value::Null)
    }

    pub(crate) fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    pub(crate) fn header(&self, name: &str) -> String {
        self.headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_owned()
    }
}

/// Sends one request in-process.
pub(crate) async fn send(r: &Router, req: Request<Body>) -> Reply {
    let resp = r.clone().oneshot(req).await.expect("infallible");
    let (parts, body) = resp.into_parts();
    let body = to_bytes(body, usize::MAX).await.expect("body");
    Reply {
        status: parts.status,
        headers: parts.headers,
        body,
    }
}

/// Builds a request; `headers` are `(name, value)` pairs.
pub(crate) fn req(
    method: &str,
    uri: &str,
    headers: &[(&str, &str)],
    body: Option<&str>,
) -> Request<Body> {
    let mut b = Request::builder().method(method).uri(uri);
    for (k, v) in headers {
        b = b.header(*k, *v);
    }
    b.body(body.map_or_else(Body::empty, |s| Body::from(s.to_owned())))
        .expect("request")
}

pub(crate) async fn get(r: &Router, uri: &str, token: Option<&str>) -> Reply {
    let auth = token.map(|t| format!("Bearer {t}"));
    let headers: Vec<(&str, &str)> = auth.iter().map(|a| ("authorization", a.as_str())).collect();
    send(r, req("GET", uri, &headers, None)).await
}

pub(crate) async fn post(r: &Router, uri: &str, token: Option<&str>, body: &str) -> Reply {
    let auth = token.map(|t| format!("Bearer {t}"));
    let mut headers: Vec<(&str, &str)> = vec![("content-type", "application/json")];
    if let Some(a) = &auth {
        headers.push(("authorization", a.as_str()));
    }
    send(r, req("POST", uri, &headers, Some(body))).await
}
