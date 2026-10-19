//! Opt-in end-to-end test of in-sandbox governance on a real Docker engine.
//!
//! Runs only with `RUNEWARD_TEST_DOCKER=1`. It builds a small test image
//! holding `runeward-supervisor` (compiled for Linux in a `rust:1.95-bookworm`
//! builder with `docker build`), starts an HTTPS upstream on the host's
//! loopback, and creates a Citadel from a Charter with `[filesystem]`,
//! `[process]`, an `[[endpoint]]` and an `env://` `[[credential]]`. It then
//! proves that:
//!
//! - the agent only ever sees the credential placeholder;
//! - a request to the endpoint reaches the upstream with the real secret
//!   injected (through the cooperative proxy at `host.docker.internal`,
//!   with TLS terminated by the broker CA the sandbox trusts);
//! - a path the endpoint denies is refused before it leaves the host;
//! - a read outside the allowed filesystem paths fails (Landlock), and the
//!   agent runs as the Charter's uid;
//! - the signed ledger holds the broker decisions and the supervisor's
//!   enforcement report, and never the secret.
//!
//! The `env://` secret is set for a child copy of this test process (the
//! parent never mutates its own environment). Everything the test creates
//! (containers with their anonymous volumes, the workspace volume, the test
//! image tag) is removed on the way out, and nothing else is touched.
#![cfg(unix)]

use std::io::{BufRead, BufReader};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use runeward_backend::{BackendConfig, container_name, volume_name};
use runeward_charter::SignedCharters;
use runeward_controlplane::{CreateOptions, Manager, ManagerConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const TEST_NAME: &str = "supervised_brokered_sandbox_end_to_end";
const CHILD_ENV: &str = "RW_IT_CHILD";
const IMAGE_ENV: &str = "RW_IT_IMAGE";
const SECRET_ENV: &str = "RW_IT_API_TOKEN";
const SECRET: &str = "rw-it-real-secret-6f1d0c";
const AGENT_UID: &str = "1500";

fn enabled() -> bool {
    std::env::var("RUNEWARD_TEST_DOCKER").is_ok_and(|v| v == "1")
}

fn docker(args: &[&str]) -> std::process::Output {
    Command::new("docker")
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("docker {args:?}: {e}"))
}

/// Removes the test image tag on drop.
struct ImageGuard(String);

impl Drop for ImageGuard {
    fn drop(&mut self) {
        let _ = Command::new("docker").args(["rmi", "-f", &self.0]).output();
    }
}

/// Removes every sandbox the child created (container with its anonymous
/// volumes, and the workspace volume) on drop.
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
            let _ = Command::new("docker")
                .args(["rm", "-f", "-v", &container_name(id)])
                .output();
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
    std::fs::write(
        dst.join("Dockerfile"),
        r#"FROM rust:1.95-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN --mount=type=cache,id=runeward-it-cargo-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=runeward-it-supervisor-target,target=/src/target \
    cargo build --release --locked -p runeward-supervisor \
    && install -D -m 0755 target/release/runeward-supervisor /out/runeward-supervisor

# The builder image already carries curl and CA roots.
FROM rust:1.95-bookworm
COPY --from=build /out/runeward-supervisor /usr/local/bin/runeward-supervisor
RUN useradd -m -u 1500 agent \
    && mkdir -p /workspace /opt/outside \
    && echo "outside the allowed paths" > /opt/outside/data \
    && chmod 0644 /opt/outside/data
WORKDIR /workspace
"#,
    )
    .expect("write Dockerfile");
}

/// The parent: builds the image, then runs the real test in a child with
/// the `env://` secret set.
#[test]
fn supervised_brokered_sandbox_end_to_end() {
    if !enabled() {
        eprintln!("skipping: set RUNEWARD_TEST_DOCKER=1 to run");
        return;
    }
    if std::env::var(CHILD_ENV).is_ok_and(|v| v == "1") {
        child();
        return;
    }
    let tag = format!("runeward-it-supervised:{}", hex_suffix(std::process::id()));
    let _image = ImageGuard(tag.clone());
    let ctx = tempfile::tempdir().expect("context");
    build_context(ctx.path());
    let ctx_path = ctx.path().display().to_string();
    let status = Command::new("docker")
        .args(["build", "-q", "-t", &tag, &ctx_path])
        .env("DOCKER_BUILDKIT", "1")
        .status()
        .expect("docker build");
    assert!(status.success(), "building the test image failed");

    let exe = std::env::current_exe().expect("exe");
    let mut child = Command::new(exe)
        .args(["--exact", TEST_NAME, "--nocapture", "--test-threads=1"])
        .env(CHILD_ENV, "1")
        .env(IMAGE_ENV, &tag)
        .env(SECRET_ENV, SECRET)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn child");
    let out = child.stdout.take().expect("stdout");
    let mut passed = false;
    for line in BufReader::new(out).lines().map_while(Result::ok) {
        println!("{line}");
        if line.contains("CHILD-OK") {
            passed = true;
        }
    }
    let status = child.wait().expect("wait child");
    assert!(status.success() && passed, "child run failed");
}

fn hex_suffix(n: u32) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    format!("{n:x}{nanos:x}")
}

/// What the upstream saw.
#[derive(Debug, Clone)]
struct Seen {
    path: String,
    authorization: String,
}

/// An HTTPS origin on 127.0.0.1 with a private CA, recording requests and
/// echoing the Authorization header back (as a careless API might).
async fn start_upstream() -> (SocketAddr, String, Arc<Mutex<Vec<Seen>>>) {
    let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_owned()]).expect("cert");
    let pem = cert.cert.pem();
    let der = rustls::pki_types::CertificateDer::from(cert.cert.der().to_vec());
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
        cert.signing_key.serialize_der(),
    ));
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let server = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("versions")
        .with_no_client_auth()
        .with_single_cert(vec![der], key)
        .expect("server config");
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server));
    let ln = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = ln.local_addr().expect("addr");
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&seen);
    tokio::spawn(async move {
        while let Ok((tcp, _)) = ln.accept().await {
            let acceptor = acceptor.clone();
            let log = Arc::clone(&log);
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    match tls.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                }
                let head = String::from_utf8_lossy(&buf).into_owned();
                let path = head
                    .lines()
                    .next()
                    .and_then(|l| l.split_whitespace().nth(1))
                    .unwrap_or_default()
                    .to_owned();
                let authorization = head
                    .lines()
                    .find_map(|l| {
                        l.split_once(':')
                            .filter(|(k, _)| k.eq_ignore_ascii_case("authorization"))
                            .map(|(_, v)| v.trim().to_owned())
                    })
                    .unwrap_or_default();
                log.lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(Seen {
                        path: path.clone(),
                        authorization: authorization.clone(),
                    });
                let body = format!("{{\"path\":\"{path}\",\"auth\":\"{authorization}\"}}");
                let resp = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = tls.write_all(resp.as_bytes()).await;
                let _ = tls.shutdown().await;
            });
        }
    });
    (addr, pem, seen)
}

fn charter(image: &str, port: u16) -> String {
    format!(
        r#"
[host]
type = "container"
image = "{image}"
workdir = "/workspace"

[filesystem]
read_only = ["/usr", "/lib", "/bin", "/etc"]
read_write = ["/tmp"]
landlock = "required"

[process]
run_as_user = "{AGENT_UID}"

[network]
default = "deny"

[[credential]]
name = "api"
source = "env://{SECRET_ENV}"
placeholder_env = "API_TOKEN"
inject = "bearer"

[[endpoint]]
name = "upstream"
host = "127.0.0.1"
port = {port}
protocol = "rest"
credential = "api"
  [[endpoint.allow]]
  method = "GET"
  path = "/v1/**"
  effect = "read"
  [[endpoint.deny]]
  path = "/v1/admin/**"
  reason = "admin is off limits"
"#
    )
}

fn child() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    rt.block_on(child_async());
    println!("CHILD-OK");
}

async fn child_async() {
    let image = std::env::var(IMAGE_ENV).expect("image");
    let guard = SandboxGuard::default();
    let (upstream, upstream_ca, seen) = start_upstream().await;
    let dir = tempfile::tempdir().expect("tmp");
    let charters = dir.path().join("charters");
    std::fs::create_dir_all(&charters).expect("mkdir");
    std::fs::write(
        charters.join("governed.toml"),
        charter(&image, upstream.port()),
    )
    .expect("charter");
    let ca_path: PathBuf = dir.path().join("upstream-ca.pem");
    std::fs::write(&ca_path, &upstream_ca).expect("ca");

    let mut cfg = ManagerConfig::from_lookup(|_| None);
    cfg.config_dir = Some(charters);
    cfg.state_dir = Some(dir.path().join("state"));
    cfg.signed_charters = SignedCharters::Disabled;
    cfg.sweep_interval = None;
    cfg.approval_wait = Some(Duration::from_secs(5));
    cfg.broker_upstream_ca = Some(ca_path);
    cfg.supervisor_report_wait = Duration::from_secs(60);
    let backend = BackendConfig::from_pairs([
        ("RUNEWARD_CONTAINER_RUNTIME", "docker"),
        ("RUNEWARD_SANDBOX_MEMORY", "512m"),
        ("RUNEWARD_SANDBOX_CPUS", "1"),
    ]);
    let mgr: Arc<Manager> = Manager::builder(cfg)
        .backend_config(backend)
        .build()
        .await
        .expect("manager");

    let sb = mgr
        .create_sandbox("governed", CreateOptions::default())
        .await
        .expect("create the governed Citadel");
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

    // The agent runs as the Charter's uid and only sees the placeholder.
    let r = sh("id -u".into()).await;
    assert_eq!(r.stdout.trim(), AGENT_UID);
    let r = sh("printenv API_TOKEN; env | grep -c rw-it-real-secret || true".into()).await;
    let mut lines = r.stdout.lines();
    let placeholder = lines.next().unwrap_or_default().to_owned();
    assert!(placeholder.starts_with("rwph_"), "{placeholder:?}");
    assert_eq!(lines.next(), Some("0"), "no secret anywhere in the env");

    // A governed request gets the real secret injected upstream; the
    // response echo comes back with the placeholder, never the secret.
    let port = upstream.port();
    let curl = |path: &str| {
        format!(
            "curl -sS --noproxy '' --max-time 30 -H \"Authorization: Bearer $API_TOKEN\" -w '\\n%{{http_code}}' https://127.0.0.1:{port}{path}"
        )
    };
    let r = sh(curl("/v1/data")).await;
    assert_eq!(r.exit_code, 0, "curl through the broker: {}", r.stderr);
    assert!(r.stdout.trim_end().ends_with("200"), "{}", r.stdout);
    assert!(
        !r.stdout.contains(SECRET),
        "secret scrubbed from the response"
    );
    // The echoed header is scrubbed twice: the broker swaps the secret back
    // to the placeholder, and governed tool output masks bearer tokens.
    assert!(r.stdout.contains("\"auth\""), "{}", r.stdout);
    let got = seen
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    assert_eq!(got.len(), 1, "{got:?}");
    assert_eq!(got[0].path, "/v1/data");
    assert_eq!(got[0].authorization, format!("Bearer {SECRET}"));

    // A denied path is refused at the broker and never reaches upstream.
    let r = sh(curl("/v1/admin/keys")).await;
    assert!(r.stdout.trim_end().ends_with("403"), "{}", r.stdout);
    assert_eq!(
        seen.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len(),
        1
    );

    // Landlock: reads outside the allowed paths fail, allowed ones work.
    let r = sh("cat /opt/outside/data".into()).await;
    assert_ne!(r.exit_code, 0, "read outside the allowed paths must fail");
    assert!(
        r.stderr.contains("Permission denied"),
        "Landlock refusal: {}",
        r.stderr
    );
    let r = sh("cat /etc/hostname >/dev/null && echo readable".into()).await;
    assert_eq!(r.stdout.trim(), "readable");
    let r = sh("touch /usr/x 2>&1; echo $?".into()).await;
    assert_ne!(r.stdout.trim().lines().last(), Some("0"), "{}", r.stdout);

    // Evidence: the supervisor report and every broker decision are in the
    // signed ledger, on SandboxInfo and on the perimeter list.
    let info = mgr
        .list_sandbox_infos()
        .into_iter()
        .find(|i| i.sandbox.id == sb.id)
        .expect("info");
    let ev = info.enforcement.expect("enforcement evidence");
    println!("enforcement: {ev:?}");
    assert_eq!(ev.landlock, "enforced");
    assert_eq!(ev.uid, Some(1500));
    assert!(ev.seccomp && ev.no_new_privs && ev.capabilities_dropped);

    let perimeter = mgr.perimeter(&sb.id).expect("perimeter");
    assert!(
        perimeter
            .iter()
            .any(|d| d.path.as_deref() == Some("/v1/data") && d.allow),
        "{perimeter:#?}"
    );
    assert!(
        perimeter
            .iter()
            .any(|d| d.path.as_deref() == Some("/v1/admin/keys") && !d.allow)
    );

    // The pump records asynchronously; give it a moment.
    let mut records = Vec::new();
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    while std::time::Instant::now() < deadline {
        let ledger = Arc::clone(mgr.ledger());
        records = tokio::task::spawn_blocking(move || ledger.records().expect("records"))
            .await
            .expect("join");
        if records
            .iter()
            .filter(|e| e.tool == "egress" && e.meta.contains_key("path"))
            .count()
            >= 2
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let egress: Vec<_> = records.iter().filter(|e| e.tool == "egress").collect();
    for e in &egress {
        println!(
            "ledger egress: {} {} {:?}",
            e.verdict,
            e.action,
            e.meta.get("reason_code")
        );
    }
    let allowed = egress
        .iter()
        .find(|e| e.meta.get("path").map(String::as_str) == Some("/v1/data"))
        .expect("allowed request chronicled");
    assert_eq!(allowed.verdict, "allow");
    assert_eq!(allowed.meta["credential"], "api");
    assert_eq!(allowed.meta["endpoint"], "upstream");
    let denied = egress
        .iter()
        .find(|e| e.meta.get("path").map(String::as_str) == Some("/v1/admin/keys"))
        .expect("denied request chronicled");
    assert_eq!(denied.verdict, "deny");
    assert_eq!(denied.meta["reason_code"], "denied");
    let report = records
        .iter()
        .find(|e| e.tool == "supervisor" && e.action == "report")
        .expect("supervisor report chronicled");
    assert_eq!(report.meta["landlock"], "enforced");
    assert!(report.meta["report"].contains("runeward.supervisor.report.v1"));
    mgr.verify_ledger().await.expect("signed ledger verifies");
    let ledger_text =
        std::fs::read_to_string(dir.path().join("state/ledger.jsonl")).expect("ledger file");
    assert!(
        !ledger_text.contains(SECRET),
        "the secret never reaches the ledger"
    );

    mgr.kill_sandbox(&sb.id).await.expect("kill");
    let gone = docker(&["inspect", &container_name(&sb.id)]);
    assert!(!gone.status.success(), "container removed");
    mgr.close().await.expect("close");
}
