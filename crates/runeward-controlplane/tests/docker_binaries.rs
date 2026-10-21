//! Opt-in end-to-end test of endpoint `binaries` on a real Docker engine.
//!
//! Runs only with `RUNEWARD_TEST_DOCKER=1`. It builds:
//!
//! - a sandbox image holding `runeward-supervisor` (compiled in a
//!   `rust:1.95-bookworm` builder), `curl` and `python3`;
//! - the egress sidecar image from `deploy/Dockerfile.egress`.
//!
//! Set `RW_IT_SANDBOX_IMAGE` / `RW_IT_EGRESS_IMAGE` to reuse images built
//! from this tree instead (they are then not removed).
//!
//! It starts a plain-HTTP upstream on the host, reachable from containers as
//! `host.docker.internal`, and creates a Citadel from a Charter with strict
//! egress and one `tcp` endpoint that allows only `/usr/bin/curl`. It then
//! proves that:
//!
//! - `curl` reaches the upstream through the transparent sidecar;
//! - `python3` asking for the same URL is refused before the upstream sees
//!   anything, as is `curl` copied to another path;
//! - the perimeter list and the signed ledger record the attributed binary,
//!   `binary_enforced`, and reason code `binary` for the refusals;
//! - the supervisor reported binary attribution `enforced`.
//!
//! Everything the test creates (containers with their anonymous volumes,
//! the workspace volume, the sidecar, the image tags it built) is removed on
//! the way out.
#![cfg(unix)]

use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use runeward_backend::{BackendConfig, container_name, volume_name};
use runeward_charter::SignedCharters;
use runeward_controlplane::{CreateOptions, Manager, ManagerConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const AGENT_UID: &str = "1500";
const BODY: &str = "hello-from-upstream";

fn enabled() -> bool {
    std::env::var("RUNEWARD_TEST_DOCKER").is_ok_and(|v| v == "1")
}

/// Removes image tags this test built, on drop.
struct ImageGuard(Vec<String>);

impl Drop for ImageGuard {
    fn drop(&mut self) {
        for t in &self.0 {
            let _ = Command::new("docker").args(["rmi", "-f", t]).output();
        }
    }
}

/// Removes every sandbox the test created (and its sidecar), on drop.
#[derive(Default)]
struct SandboxGuard(Mutex<Vec<String>>);

impl SandboxGuard {
    fn track(&self, id: &str) {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(id.to_owned());
    }
}

impl Drop for SandboxGuard {
    fn drop(&mut self) {
        let ids = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for id in ids.iter() {
            for name in [container_name(id), format!("runeward-egress-{id}")] {
                let _ = Command::new("docker")
                    .args(["rm", "-f", "-v", &name])
                    .output();
            }
            let _ = Command::new("docker")
                .args(["volume", "rm", "-f", &volume_name(id)])
                .output();
        }
    }
}

/// Copies the Rust workspace (manifests and crates, no build output) into
/// a fresh build context.
fn build_context(dst: &Path) {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    for f in ["Cargo.toml", "Cargo.lock"] {
        std::fs::copy(root.join(f), dst.join(f)).expect("copy manifest");
    }
    fn copy_dir(src: &Path, dst: &Path) {
        std::fs::create_dir_all(dst).expect("mkdir");
        for e in std::fs::read_dir(src).expect("read dir") {
            let e = e.expect("entry");
            let name = e.file_name();
            if name == "target" {
                continue;
            }
            let ty = e.file_type().expect("type");
            if ty.is_dir() {
                copy_dir(&e.path(), &dst.join(&name));
            } else if ty.is_file() {
                std::fs::copy(e.path(), dst.join(&name)).expect("copy");
            }
        }
    }
    copy_dir(&root.join("crates"), &dst.join("crates"));
    std::fs::copy(
        root.join("deploy/Dockerfile.egress"),
        dst.join("Dockerfile.egress"),
    )
    .expect("copy egress Dockerfile");
    std::fs::write(
        dst.join("Dockerfile.sandbox"),
        r#"FROM rust:1.95-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN --mount=type=cache,id=runeward-it-cargo-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=runeward-it-supervisor-target,target=/src/target \
    cargo build --release --locked -p runeward-supervisor \
    && install -D -m 0755 target/release/runeward-supervisor /out/runeward-supervisor

# The builder image already carries curl and python3.
FROM rust:1.95-bookworm
COPY --from=build /out/runeward-supervisor /usr/local/bin/runeward-supervisor
RUN useradd -m -u 1500 agent && mkdir -p /workspace && chown agent /workspace
WORKDIR /workspace
"#,
    )
    .expect("write Dockerfile");
}

fn build(ctx: &Path, dockerfile: &str, tag: &str) {
    let status = Command::new("docker")
        .args(["build", "-q", "-f"])
        .arg(ctx.join(dockerfile))
        .args(["-t", tag])
        .arg(ctx)
        .env("DOCKER_BUILDKIT", "1")
        .status()
        .expect("docker build");
    assert!(status.success(), "building {tag} from {dockerfile} failed");
}

fn suffix() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    format!("{:x}{nanos:x}", std::process::id())
}

/// A plain-HTTP origin on every host interface that counts requests.
async fn start_upstream() -> (u16, Arc<AtomicUsize>) {
    let ln = TcpListener::bind("0.0.0.0:0").await.expect("bind");
    let port = ln.local_addr().expect("addr").port();
    let hits = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&hits);
    tokio::spawn(async move {
        while let Ok((mut tcp, _)) = ln.accept().await {
            let count = Arc::clone(&count);
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 2048];
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    match tcp.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                }
                count.fetch_add(1, Ordering::SeqCst);
                let resp = format!(
                    "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{BODY}",
                    BODY.len()
                );
                let _ = tcp.write_all(resp.as_bytes()).await;
                let _ = tcp.shutdown().await;
            });
        }
    });
    (port, hits)
}

fn charter(image: &str, port: u16) -> String {
    format!(
        r#"
[host]
type = "container"
image = "{image}"
workdir = "/workspace"

[process]
run_as_user = "{AGENT_UID}"

[network]
default = "deny"
enforce = "strict"

[[endpoint]]
name = "upstream"
host = "host.docker.internal"
port = {port}
protocol = "tcp"
binaries = ["/usr/bin/curl"]
"#
    )
}

#[test]
fn endpoint_binaries_enforced_on_docker() {
    if !enabled() {
        eprintln!("skipping: set RUNEWARD_TEST_DOCKER=1 to run");
        return;
    }
    let tag = suffix();
    let ctx = tempfile::tempdir().expect("context");
    build_context(ctx.path());
    let mut built = Vec::new();
    let sandbox_image = std::env::var("RW_IT_SANDBOX_IMAGE").unwrap_or_else(|_| {
        let t = format!("runeward-it-binaries-sandbox:{tag}");
        build(ctx.path(), "Dockerfile.sandbox", &t);
        built.push(t.clone());
        t
    });
    let egress_image = std::env::var("RW_IT_EGRESS_IMAGE").unwrap_or_else(|_| {
        let t = format!("runeward-it-binaries-egress:{tag}");
        build(ctx.path(), "Dockerfile.egress", &t);
        built.push(t.clone());
        t
    });
    let _images = ImageGuard(built);
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    rt.block_on(run(&sandbox_image, &egress_image));
}

async fn run(image: &str, egress_image: &str) {
    let guard = SandboxGuard::default();
    let (port, hits) = start_upstream().await;
    let dir = tempfile::tempdir().expect("tmp");
    let charters = dir.path().join("charters");
    std::fs::create_dir_all(&charters).expect("mkdir");
    std::fs::write(charters.join("binaries.toml"), charter(image, port)).expect("charter");

    let mut cfg = ManagerConfig::from_lookup(|_| None);
    cfg.config_dir = Some(charters);
    cfg.state_dir = Some(dir.path().join("state"));
    cfg.signed_charters = SignedCharters::Disabled;
    cfg.sweep_interval = None;
    cfg.supervisor_report_wait = Duration::from_secs(60);
    let backend = BackendConfig::from_pairs([
        ("RUNEWARD_CONTAINER_RUNTIME", "docker"),
        ("RUNEWARD_EGRESS_IMAGE", egress_image),
        ("RUNEWARD_SANDBOX_MEMORY", "512m"),
        ("RUNEWARD_SANDBOX_CPUS", "1"),
    ]);
    let mgr: Arc<Manager> = Manager::builder(cfg)
        .backend_config(backend)
        .build()
        .await
        .expect("manager");

    let sb = mgr
        .create_sandbox("binaries", CreateOptions::default())
        .await
        .expect("create the Citadel");
    guard.track(&sb.id);
    println!("created {} ({})", sb.id, sb.image);
    let sh = |script: String| {
        let mgr = Arc::clone(&mgr);
        let id = sb.id.clone();
        async move {
            let r = mgr
                .shell(&id, &["sh".into(), "-c".into(), script.clone()], "")
                .await
                .expect("shell");
            println!(
                "$ {script}\n  exit={} stdout={:?} stderr={:?}",
                r.exit_code, r.stdout, r.stderr
            );
            r
        }
    };
    let url = format!("http://host.docker.internal:{port}/hello");

    // The allowed binary reaches the endpoint.
    let r = sh(format!("curl -sS --max-time 20 {url}")).await;
    assert_eq!(r.exit_code, 0, "curl: {}", r.stderr);
    assert_eq!(r.stdout.trim(), BODY);
    assert_eq!(hits.load(Ordering::SeqCst), 1);

    // Another binary is refused, and nothing reaches the upstream.
    let py = format!(
        "python3 -c \"import urllib.request,sys\ntry:\n  print(urllib.request.urlopen('{url}', timeout=20).read().decode())\nexcept Exception as e:\n  print('refused:', e); sys.exit(3)\""
    );
    let r = sh(py).await;
    assert_eq!(r.exit_code, 3, "python3 must be refused: {}", r.stdout);
    assert!(!r.stdout.contains(BODY), "{}", r.stdout);

    // So is curl copied somewhere else: a binary is a file, not a name.
    let r = sh(format!(
        "cp /usr/bin/curl /tmp/curl && /tmp/curl -sS --max-time 20 {url}"
    ))
    .await;
    assert_ne!(r.exit_code, 0, "a copy of curl is not curl: {}", r.stdout);
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "only the allowed call landed"
    );

    // Evidence: the supervisor ran the helper.
    let info = mgr
        .list_sandbox_infos()
        .into_iter()
        .find(|i| i.sandbox.id == sb.id)
        .expect("info");
    let ev = info.enforcement.expect("enforcement evidence");
    println!("enforcement: {ev:?}");
    assert_eq!(ev.binary_attribution, "enforced");
    assert_eq!(ev.uid, Some(1500));

    // Decisions come back from the sidecar's log stream; wait for them.
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    let perimeter = loop {
        let p = mgr.perimeter(&sb.id).expect("perimeter");
        let refused = p
            .iter()
            .filter(|d| d.reason_code == Some(runeward_egress::ReasonCode::Binary))
            .count();
        if refused >= 2 || std::time::Instant::now() > deadline {
            break p;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    };
    for d in &perimeter {
        println!(
            "perimeter: allow={} binary={:?} enforced={:?} code={:?} reason={}",
            d.allow, d.binary, d.binary_enforced, d.reason_code, d.reason
        );
    }
    let allowed = perimeter
        .iter()
        .find(|d| d.allow && d.endpoint.as_deref() == Some("upstream"))
        .expect("allowed decision");
    assert_eq!(allowed.binary.as_deref(), Some("/usr/bin/curl"));
    assert_eq!(allowed.binary_enforced, Some(true));
    let refused: Vec<_> = perimeter
        .iter()
        .filter(|d| d.reason_code == Some(runeward_egress::ReasonCode::Binary))
        .collect();
    assert!(
        refused
            .iter()
            .any(|d| d.binary.as_deref().is_some_and(|b| b.contains("python3"))),
        "{refused:?}"
    );
    assert!(
        refused
            .iter()
            .any(|d| d.binary.as_deref() == Some("/tmp/curl")),
        "{refused:?}"
    );
    assert!(
        refused
            .iter()
            .all(|d| !d.allow && d.binary_enforced == Some(true))
    );

    // And the signed ledger has them.
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    let records = loop {
        let ledger = Arc::clone(mgr.ledger());
        let records = tokio::task::spawn_blocking(move || ledger.records().expect("records"))
            .await
            .expect("join");
        let n = records
            .iter()
            .filter(|e| {
                e.tool == "egress"
                    && e.meta.get("reason_code").map(String::as_str) == Some("binary")
            })
            .count();
        if n >= 2 || std::time::Instant::now() > deadline {
            break records;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    };
    let denied = records
        .iter()
        .find(|e| e.tool == "egress" && e.meta.get("binary").is_some_and(|b| b.contains("python3")))
        .expect("python3 refusal chronicled");
    assert_eq!(denied.verdict, "deny");
    assert_eq!(denied.meta["binary_enforced"], "true");
    assert_eq!(denied.meta["reason_code"], "binary");
    let report = records
        .iter()
        .find(|e| e.tool == "supervisor" && e.action == "report")
        .expect("supervisor report chronicled");
    assert_eq!(report.meta["binary_attribution"], "enforced");
    mgr.verify_ledger().await.expect("signed ledger verifies");

    mgr.kill_sandbox(&sb.id).await.expect("kill");
}
