//! Drives the Docker/Podman backend against a fake CLI and compares every
//! invocation with the argv the Go implementation produced for the same
//! scenarios (`fixtures/go-docker-argv.json`).
#![cfg(unix)]

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use regex::Regex;
use runeward_backend::config::{
    DNS_RESOLVERS_ENV, EGRESS_IMAGE_ENV, ISOLATION_PROBE_ENV, SANDBOX_CPUS_ENV, SANDBOX_MEMORY_ENV,
    SANDBOX_PIDS_ENV,
};
use runeward_backend::evidence::PROBE_MARKER;
use runeward_backend::{
    Backend, BackendConfig, Docker, ExecRequest, IsolationTier, LABEL_PROFILE, PtyStream,
    Resources, Spec,
};
use runeward_charter::{File, Network, NetworkRule};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Fixture {
    calls: Vec<Vec<String>>,
    #[serde(default)]
    tars: Vec<Vec<TarEntry>>,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
struct TarEntry {
    name: String,
    #[serde(rename = "type")]
    kind: String,
    size: u64,
    #[serde(default)]
    linkname: String,
    mode: u32,
}

fn fixtures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn go_fixtures() -> HashMap<String, Fixture> {
    let raw = std::fs::read_to_string(fixtures_dir().join("go-docker-argv.json"))
        .expect("read go fixture");
    serde_json::from_str(&raw).expect("parse go fixture")
}

static HEX_ID: LazyLock<Regex> = LazyLock::new(|| Regex::new("[0-9a-f]{32}").expect("re"));
static PROXY_URL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"http://runeward:<ID>@(host\.docker\.internal|host\.containers\.internal):[0-9]+")
        .expect("re")
});
static PROJ_TMP: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^.*/runeward-proj-[^/]+$").expect("re"));

/// Applies the same normalisation as the Go fixture generator.
fn norm(s: &str) -> String {
    let s = HEX_ID.replace_all(s, "<ID>");
    let s = PROXY_URL.replace_all(&s, "http://runeward:<ID>@$1:<PORT>");
    PROJ_TMP.replace_all(&s, "<TMP>").into_owned()
}

/// Sorts each run of consecutive `-e NAME=value` pairs: Go iterates maps in
/// random order, so only the set of variables in a run is significant.
fn canon(calls: &[Vec<String>]) -> Vec<Vec<String>> {
    calls
        .iter()
        .map(|call| {
            let mut out = Vec::with_capacity(call.len());
            let mut i = 0;
            while i < call.len() {
                if call[i] == "-e" && i + 1 < call.len() {
                    let mut run = Vec::new();
                    while i + 1 < call.len() && call[i] == "-e" {
                        run.push(call[i + 1].clone());
                        i += 2;
                    }
                    run.sort();
                    for v in run {
                        out.push("-e".to_owned());
                        out.push(v);
                    }
                } else {
                    out.push(call[i].clone());
                    i += 1;
                }
            }
            out
        })
        .collect()
}

/// A temp dir holding `docker`/`podman` symlinks to the fake CLI; the fake
/// logs to `calls.log` beside them.
struct FakeCli {
    dir: tempfile::TempDir,
}

impl FakeCli {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let script = fixtures_dir().join("fake-docker.sh");
        for name in ["docker", "podman"] {
            std::os::unix::fs::symlink(&script, dir.path().join(name)).expect("symlink");
        }
        Self { dir }
    }

    fn bin(&self, runtime: &str) -> PathBuf {
        self.dir.path().join(runtime)
    }

    fn log(&self) -> PathBuf {
        self.dir.path().join("calls.log")
    }

    fn reset(&self) {
        let _ = std::fs::remove_file(self.log());
    }

    /// Every invocation except the isolation probe, which the Go
    /// implementation never made (see [`FakeCli::probes`]).
    fn calls(&self) -> Vec<Vec<String>> {
        self.all_calls()
            .into_iter()
            .filter(|c| !is_probe(c))
            .collect()
    }

    /// The isolation probe invocations.
    fn probes(&self) -> Vec<Vec<String>> {
        self.all_calls()
            .into_iter()
            .filter(|c| is_probe(c))
            .collect()
    }

    fn all_calls(&self) -> Vec<Vec<String>> {
        let raw = std::fs::read_to_string(self.log()).unwrap_or_default();
        raw.lines()
            .filter(|l| !l.is_empty())
            .map(|l| {
                l.trim_end_matches('\u{1f}')
                    .split('\u{1f}')
                    .map(norm)
                    .collect()
            })
            .collect()
    }

    /// Makes the fake answer `info` and the isolation probe.
    fn set_engine(&self, info: &str, probe: &str) {
        std::fs::write(self.dir.path().join("info"), info).expect("write info");
        std::fs::write(self.dir.path().join("probe"), probe).expect("write probe");
    }

    fn tars(&self) -> Vec<Vec<TarEntry>> {
        (0..)
            .map(|n| self.dir.path().join(format!("calls.log.tar.{n}")))
            .take_while(|p| p.exists())
            .map(|p| list_tar(&p))
            .collect()
    }
}

fn is_probe(call: &[String]) -> bool {
    call.iter().any(|a| a.contains(PROBE_MARKER))
}

fn list_tar(p: &Path) -> Vec<TarEntry> {
    let f = std::fs::File::open(p).expect("open tar");
    let mut ar = tar::Archive::new(f);
    ar.entries()
        .expect("entries")
        .map(|e| {
            let e = e.expect("entry");
            let h = e.header();
            TarEntry {
                name: String::from_utf8_lossy(&e.path_bytes()).into_owned(),
                kind: String::from(char::from(h.entry_type().as_byte())),
                size: h.size().expect("size"),
                linkname: e
                    .link_name_bytes()
                    .map(|b| String::from_utf8_lossy(&b).into_owned())
                    .unwrap_or_default(),
                mode: h.mode().expect("mode"),
            }
        })
        .collect()
}

fn labels(profile: &str) -> BTreeMap<String, String> {
    BTreeMap::from([(LABEL_PROFILE.to_owned(), profile.to_owned())])
}

fn deny_network(enforce: &str) -> Network {
    Network {
        default: "deny".into(),
        rules: vec![
            NetworkRule {
                hostname: "example.com".into(),
                ..NetworkRule::default()
            },
            NetworkRule {
                verdict: "deny".into(),
                cidr: "10.0.0.0/8".into(),
                ..NetworkRule::default()
            },
        ],
        enforce: enforce.into(),
    }
}

fn demo(profile: &str) -> Spec {
    Spec {
        profile: profile.into(),
        labels: labels(profile),
        ..Spec::default()
    }
}

async fn backend(cli: &FakeCli, runtime: &str, cfg: BackendConfig) -> Docker {
    let d = Docker::with_cli(runtime, cli.bin(runtime), cfg)
        .await
        .expect("backend");
    cli.reset();
    d
}

fn assert_matches_go(name: &str, cli: &FakeCli, go: &HashMap<String, Fixture>) {
    let want = &go[name];
    let got = cli.calls();
    let (got_c, want_c) = (canon(&got), canon(&want.calls));
    for (i, (g, w)) in got_c.iter().zip(&want_c).enumerate() {
        assert_eq!(g, w, "{name}: call {i} differs");
    }
    assert_eq!(got_c.len(), want_c.len(), "{name}: call count\n{got:#?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn create_scenarios_match_go() {
    let go = go_fixtures();
    let cli = FakeCli::new();

    // minimal + kill
    let d = backend(&cli, "docker", BackendConfig::default()).await;
    assert_eq!(d.default_runtime(), "runc");
    assert_eq!(d.isolation_tier(), IsolationTier::Container);
    let sb = d.create(demo("demo")).await.expect("create");
    assert_eq!(sb.backend, "docker");
    assert_eq!(sb.status, "running");
    assert_eq!(sb.image, "debian:stable-slim");
    assert_eq!(sb.isolation, IsolationTier::Container);
    let ev = sb.isolation_evidence.as_ref().expect("evidence");
    assert_eq!(ev.runtime, "runc");
    assert!(
        ev.signals.contains(&"verdict:container".to_owned()),
        "{ev:?}"
    );
    let probes = cli.probes();
    assert_eq!(probes.len(), 1, "{probes:?}");
    assert_eq!(probes[0][..3], ["exec", "runeward-<ID>", "/bin/sh"]);
    d.kill(&sb.id).await.expect("kill");
    assert_matches_go("minimal", &cli, &go);

    // hardened: the engine has gVisor and the sandbox shows its signature.
    cli.set_engine(
        "runc|6.8.0-45-generic|Ubuntu 24.04 LTS",
        "@@osrelease\n4.4.0\n@@version\nLinux version 4.4.0 #1 SMP Sun Jan 10 15:06:54 PST 2016\n",
    );
    let d = backend(&cli, "docker", BackendConfig::default()).await;
    assert_eq!(d.host_kernel(), "6.8.0-45-generic");
    let spec = Spec {
        image: "example/img:1".into(),
        workdir: "/work".into(),
        user: "1000:1000".into(),
        command: ["/bin/sh", "-c", "sleep infinity"]
            .map(String::from)
            .to_vec(),
        env: BTreeMap::from([("FOO".into(), "bar baz".into())]),
        runtime_class: "runsc".into(),
        read_only: true,
        seccomp: "/etc/seccomp.json".into(),
        apparmor: "runeward-default".into(),
        resources: Resources {
            memory_bytes: 512 << 20,
            nano_cpus: 1_500_000_000,
        },
        ..demo("hard")
    };
    let sb = d.create(spec).await.expect("create");
    assert_eq!(sb.isolation, IsolationTier::Kernel);
    let ev = sb.isolation_evidence.as_ref().expect("evidence");
    assert_eq!(ev.guest_kernel, "4.4.0");
    assert_eq!(ev.host_kernel, "6.8.0-45-generic");
    assert!(
        ev.signals.contains(&"gvisor:proc-version".to_owned()),
        "{ev:?}"
    );
    assert_matches_go("hardened", &cli, &go);
    std::fs::remove_file(cli.dir.path().join("info")).expect("rm info");
    std::fs::remove_file(cli.dir.path().join("probe")).expect("rm probe");

    for (name, pids, mem, cpus) in [
        ("limits-off", "off", "0", "none"),
        ("limits-env", "256", "1g", "0.5"),
        ("limits-bad-env", "-3", "lots", "x"),
    ] {
        let cfg = BackendConfig::from_pairs([
            (SANDBOX_PIDS_ENV, pids),
            (SANDBOX_MEMORY_ENV, mem),
            (SANDBOX_CPUS_ENV, cpus),
        ]);
        let d = backend(&cli, "docker", cfg).await;
        d.create(demo("demo")).await.expect("create");
        assert_matches_go(name, &cli, &go);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn egress_scenarios_match_go() {
    let go = go_fixtures();
    let cli = FakeCli::new();

    let d = backend(&cli, "docker", BackendConfig::default()).await;
    let spec = Spec {
        network: deny_network(""),
        ..demo("net")
    };
    let sb = d.create(spec.clone()).await.expect("create");
    d.kill(&sb.id).await.expect("kill");
    assert_matches_go("cooperative-docker", &cli, &go);

    let d = backend(&cli, "podman", BackendConfig::default()).await;
    assert_eq!(d.name(), "podman");
    d.create(spec).await.expect("create");
    assert_matches_go("cooperative-podman", &cli, &go);

    let cfg = BackendConfig::from_pairs([
        (EGRESS_IMAGE_ENV, "registry.example/egress:2"),
        (DNS_RESOLVERS_ENV, "1.1.1.1,8.8.8.8"),
    ]);
    let d = backend(&cli, "docker", cfg).await;
    let spec = Spec {
        network: deny_network("strict"),
        user: "1000".into(),
        ..demo("strict")
    };
    let sb = d.create(spec).await.expect("create");
    let ip = d
        .reachable()
        .expect("reachable")
        .container_ip(&sb.id)
        .await
        .expect("ip");
    assert_eq!(ip, "172.17.0.9");
    d.kill(&sb.id).await.expect("kill");
    assert_matches_go("strict", &cli, &go);
}

#[tokio::test(flavor = "multi_thread")]
async fn seed_and_files_match_go() {
    let go = go_fixtures();
    let cli = FakeCli::new();
    let d = backend(&cli, "docker", BackendConfig::default()).await;
    let file = |path: &str, content: &str, mode: &str| File {
        path: path.into(),
        content: content.into(),
        mode: mode.into(),
        ..File::default()
    };
    let spec = Spec {
        seed_dir: Some(fixtures_dir().join("seed")),
        files: vec![
            file("/root/.gitconfig", "[user]\n", "0600"),
            file("notes/a.txt", "hi", ""),
            file("top.txt", "x", ""),
        ],
        ..demo("seed")
    };
    d.create(spec).await.expect("create");

    // Up to and including the seed the argv is Go's. File projection then
    // deliberately differs: Go ran `docker cp` (which resolves a relative
    // target from `/` and keeps the host owner) followed by chmod/chown
    // calls that fail under --cap-drop ALL. Rust resolves relative targets
    // against the workdir and streams a tar into `tar -x --no-same-owner`.
    let got = canon(&cli.calls());
    let want = canon(&go["seed-and-files"].calls);
    let seed_calls = want
        .iter()
        .position(|c| c.iter().any(|a| a == "-xf"))
        .expect("go seed call")
        + 1;
    assert_eq!(got[..seed_calls], want[..seed_calls], "create and seed");
    let ctr = "runeward-<ID>";
    let extract = |dir: &str| {
        [
            "exec",
            "-i",
            ctr,
            "tar",
            "--no-same-owner",
            "-p",
            "-C",
            dir,
            "-xf",
            "-",
        ]
        .map(String::from)
        .to_vec()
    };
    let mkdir = |dir: &str| ["exec", ctr, "mkdir", "-p", dir].map(String::from).to_vec();
    let workdir_query = ["inspect", "-f", "{{.Config.WorkingDir}}", ctr]
        .map(String::from)
        .to_vec();
    let files_want = [
        mkdir("/root"),
        extract("/root"),
        workdir_query,
        mkdir("/workspace/notes"),
        extract("/workspace/notes"),
        mkdir("/workspace"),
        extract("/workspace"),
    ];
    assert_eq!(got[seed_calls..], files_want[..], "file projection");

    // One archive per projected file, each a single entry at its mode.
    let tars = cli.tars();
    assert_eq!(tars.len(), 4, "seed plus three projections");
    let entry = |t: &[TarEntry]| (t[0].name.clone(), t[0].mode, t[0].size, t.len());
    assert_eq!(entry(&tars[1]), (".gitconfig".to_owned(), 0o600, 7, 1));
    assert_eq!(entry(&tars[2]), ("a.txt".to_owned(), 0o444, 2, 1));
    assert_eq!(entry(&tars[3]), ("top.txt".to_owned(), 0o444, 1, 1));

    // The seeded tar carries the same entries Go streams. Modes come from
    // the checkout (and symlink modes differ by OS), so compare those with
    // the source tree instead of the Go fixture.
    let got = tars;
    let want = &go["seed-and-files"].tars;
    assert_eq!(want.len(), 1);
    for (g, w) in got[0].iter().zip(&want[0]) {
        assert_eq!(
            (&g.name, &g.kind, g.size, &g.linkname),
            (&w.name, &w.kind, w.size, &w.linkname)
        );
        let src = fixtures_dir()
            .join("seed")
            .join(g.name.trim_end_matches('/'));
        let meta = std::fs::symlink_metadata(&src).expect("source entry");
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(g.mode, meta.permissions().mode() & 0o777, "{}", g.name);
    }
    assert_eq!(got[0].len(), want[0].len());
}

#[tokio::test(flavor = "multi_thread")]
async fn operations_match_go() {
    let go = go_fixtures();
    let cli = FakeCli::new();
    let d = backend(&cli, "docker", BackendConfig::default()).await;
    let sb = d.create(demo("ops")).await.expect("create");

    let res = d
        .exec(&sb.id, ExecRequest::new(["ls", "-la"]))
        .await
        .expect("exec");
    assert_eq!(res.exit_code, 0);
    let req = ExecRequest {
        command: vec!["env".into()],
        workdir: "/tmp".into(),
        env: BTreeMap::from([("A".into(), "1".into())]),
        ..ExecRequest::default()
    };
    d.exec(&sb.id, req).await.expect("exec env");
    let stream = || PtyStream {
        stdin: Some(Box::new(tokio::io::empty())),
        stdout: Some(Box::new(tokio::io::sink())),
        ..PtyStream::default()
    };
    d.attach_pty(&sb.id, stream()).await.expect("attach");
    let s = PtyStream {
        command: vec!["bash".into(), "-l".into()],
        ..stream()
    };
    d.attach_pty(&sb.id, s).await.expect("attach bash");
    d.export_workspace(&sb.id, &mut tokio::io::sink())
        .await
        .expect("export");
    let snap = d.snapshot(&sb.id, "snap1").await.expect("snapshot");
    let _ = std::fs::remove_file(&snap.location);
    assert_eq!(snap.name, "snap1");
    assert_eq!(snap.sha256.len(), 64);
    let listed = d.list().await.expect("list");
    assert!(listed.is_empty());
    d.kill(&sb.id).await.expect("kill");
    assert_matches_go("ops", &cli, &go);
}

/// Not a Go scenario: the supervisor and broker are new. A supervised,
/// brokered sandbox is created stopped, gets its root-only files copied
/// in, starts under the supervisor, hands the workspace to the agent, and
/// confines governed execs while the backend's own tar streams run as the
/// agent identity.
#[tokio::test(flavor = "multi_thread")]
async fn supervised_brokered_create_flow() {
    use runeward_backend::incell::{SUPERVISOR_BIN, SUPERVISOR_EXEC_CONFIG_PATH};
    use runeward_backend::{BrokerHandle, SupervisorSpec};

    let cli = FakeCli::new();
    let d = backend(&cli, "docker", BackendConfig::default()).await;
    let ep = runeward_charter::Endpoint {
        name: "api".into(),
        host: "api.example.test".into(),
        protocol: "rest".into(),
        credential: "tok".into(),
        ..runeward_charter::Endpoint::default()
    };
    let cred = runeward_charter::Credential {
        name: "tok".into(),
        placeholder_env: "API_TOKEN".into(),
        ..runeward_charter::Credential::default()
    };
    let id = "00112233445566778899aabbccddeeff";
    let broker = runeward_egress::Broker::with_secret_values(
        id,
        vec![ep],
        vec![cred],
        HashMap::from([("tok".to_string(), "real-secret".to_string())]),
    )
    .expect("broker");
    let mut cfg = runeward_supervisor::SupervisorConfig::default().with_argv(["agent"]);
    cfg.workdir = "/workspace".into();
    cfg.process.user = "1500".into();
    let spec = Spec {
        id: id.into(),
        broker: Some(BrokerHandle::new(std::sync::Arc::new(broker))),
        supervisor: Some(SupervisorSpec {
            config: cfg,
            required: true,
        }),
        files: vec![File {
            path: "notes.txt".into(),
            content: "hi".into(),
            ..File::default()
        }],
        ..demo("governed")
    };
    let sb = d.create(spec).await.expect("create");
    assert_eq!(sb.id, id, "the caller's id is used");
    d.exec(&sb.id, ExecRequest::new(["id"]))
        .await
        .expect("exec");
    let report = d.supervisor_report(&sb.id).await.expect("report");
    assert_eq!(
        report.as_deref(),
        Some(""),
        "supervised, nothing reported yet"
    );
    d.kill(&sb.id).await.expect("kill");

    let calls: Vec<String> = cli.calls().iter().map(|c| c.join(" ")).collect();
    let pos = |pred: &dyn Fn(&str) -> bool, what: &str| -> usize {
        calls
            .iter()
            .position(|c| pred(c))
            .unwrap_or_else(|| panic!("no {what} in {calls:#?}"))
    };
    let probe = pos(
        &|c| c.starts_with("run --rm --network none") && c.ends_with("--version"),
        "supervisor probe",
    );
    let create = pos(&|c| c.starts_with("create --name runeward-"), "create");
    let cp_state = pos(
        &|c| c.ends_with(":/run/runeward") && c.starts_with("cp - "),
        "state cp",
    );
    let cp_ca = pos(
        &|c| c.ends_with(":/etc/runeward/ca") && c.starts_with("cp - "),
        "CA cp",
    );
    let start = pos(&|c| c.starts_with("start runeward-"), "start");
    let chown = pos(
        &|c| c.starts_with("exec -u 0 ") && c.contains(" chown 1500 /workspace"),
        "chown",
    );
    assert!(
        probe < create && create < cp_state && cp_state < cp_ca && cp_ca < start && start < chown
    );
    let c = &calls[create];
    assert!(
        c.contains("--cap-add SETUID") && c.contains("-u 0:0"),
        "{c}"
    );
    assert!(c.contains(&format!("--entrypoint {SUPERVISOR_BIN}")), "{c}");
    assert!(
        c.contains("-e HTTPS_PROXY=http://runeward:"),
        "broker proxy in path: {c}"
    );
    assert!(!c.contains("real-secret"), "{c}");
    // File projection runs as the agent, not root and not confined.
    let tar = pos(
        &|c| c.starts_with("exec -i -u 1500 ") && c.contains(" tar --no-same-owner"),
        "projection",
    );
    assert!(tar > start);
    let exec = pos(
        &|c| {
            c.contains(&format!(
                "{SUPERVISOR_BIN} exec --config {SUPERVISOR_EXEC_CONFIG_PATH} -- id"
            ))
        },
        "confined exec",
    );
    assert!(exec > tar);
    assert!(
        calls.iter().any(|c| c.starts_with("rm -f -v runeward-")),
        "anonymous volumes removed"
    );
    assert!(
        calls.iter().all(|c| !c.contains("real-secret")),
        "no secret on any argv"
    );

    // The staged files: two 0600 supervisor documents, the CA and bundle.
    let staged: Vec<Vec<TarEntry>> = (0..)
        .map(|n| cli.dir.path().join(format!("calls.log.cp.{n}")))
        .take_while(|p| p.exists())
        .map(|p| list_tar(&p))
        .collect();
    assert_eq!(staged.len(), 2, "{staged:?}");
    let modes: Vec<(String, u32)> = staged[0].iter().map(|e| (e.name.clone(), e.mode)).collect();
    assert_eq!(
        modes,
        [
            ("supervisor.json".to_owned(), 0o600),
            ("supervisor-exec.json".to_owned(), 0o600)
        ]
    );
    let names: Vec<&str> = staged[1].iter().map(|e| e.name.as_str()).collect();
    assert_eq!(names, ["broker-ca.pem", "ca-bundle.pem"]);
}

/// A CLI whose `exec` runs the command locally (dropping exec flags and the
/// container name), for exercising exec/attach plumbing. It is a
/// checked-in fixture, not a script written at test time: exec'ing a file
/// this process just wrote fails with ETXTBSY whenever a concurrent test's
/// fork still holds an inherited copy of the write descriptor.
fn passthrough_cli() -> PathBuf {
    fixtures_dir().join("passthrough-docker.sh")
}

async fn read_all(mut r: tokio::io::DuplexStream) -> String {
    use tokio::io::AsyncReadExt;
    let mut s = String::new();
    let _ = r.read_to_string(&mut s).await;
    s
}

#[tokio::test(flavor = "multi_thread")]
async fn exec_reports_exit_codes_streams_and_timeouts() {
    let bin = passthrough_cli();
    let d = Docker::with_cli("docker", bin, BackendConfig::default())
        .await
        .expect("backend");

    let res = d
        .exec(
            "x",
            ExecRequest::new(["sh", "-c", "echo out; echo err >&2; exit 3"]),
        )
        .await
        .expect("exec");
    assert_eq!(res.exit_code, 3);
    assert_eq!(res.stdout, "out\n");
    assert_eq!(res.stderr, "err\n");

    let (w, r) = tokio::io::duplex(1024);
    let req = ExecRequest {
        stdout: Some(Box::new(w)),
        stream_only: true,
        ..ExecRequest::new(["sh", "-c", "echo live"])
    };
    let res = d.exec("x", req).await.expect("stream exec");
    assert!(res.stdout.is_empty(), "stream_only keeps no copy");
    assert_eq!(read_all(r).await, "live\n");

    let req = ExecRequest {
        timeout: Some(std::time::Duration::from_millis(200)),
        ..ExecRequest::new(["sleep", "120"])
    };
    let started = std::time::Instant::now();
    let res = d.exec("x", req).await.expect("timeout is not an error");
    assert_eq!(res.exit_code, -1);
    // Far below the command's own runtime, with room for a loaded host.
    assert!(started.elapsed() < std::time::Duration::from_secs(60));
}

#[tokio::test(flavor = "multi_thread")]
async fn attach_pipes_and_tty() {
    let bin = passthrough_cli();
    let d = Docker::with_cli("docker", bin, BackendConfig::default())
        .await
        .expect("backend");

    // Without a TTY, stderr shares stdout when no stderr writer is given.
    let (w, r) = tokio::io::duplex(1024);
    let s = PtyStream {
        stdin: Some(Box::new(std::io::Cursor::new(b"hello".to_vec()))),
        stdout: Some(Box::new(w)),
        command: vec!["sh".into(), "-c".into(), "cat; echo e >&2".into()],
        ..PtyStream::default()
    };
    d.attach_pty("x", s).await.expect("attach");
    assert_eq!(read_all(r).await, "helloe\n");

    // With a TTY the session runs on a pseudo-terminal.
    let (w, r) = tokio::io::duplex(4096);
    let s = PtyStream {
        stdout: Some(Box::new(w)),
        tty: true,
        command: vec![
            "sh".into(),
            "-c".into(),
            "test -t 1 && echo is-a-tty".into(),
        ],
        ..PtyStream::default()
    };
    d.attach_pty("x", s).await.expect("attach tty");
    assert!(read_all(r).await.contains("is-a-tty"));

    let s = PtyStream {
        command: vec!["false".into()],
        ..PtyStream::default()
    };
    assert!(d.attach_pty("x", s).await.is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn export_extracts_into_destination() {
    let cli = FakeCli::new();
    let src = tempfile::tempdir().expect("src");
    std::fs::create_dir(src.path().join("d")).expect("mkdir");
    std::fs::write(src.path().join("d/f.txt"), "payload").expect("write");
    std::fs::write(
        cli.dir.path().join("export_dir"),
        src.path().to_string_lossy().as_bytes(),
    )
    .expect("write export_dir");
    let d = backend(&cli, "docker", BackendConfig::default()).await;
    let dest = tempfile::tempdir().expect("dest");
    runeward_backend::export_to_dir(&d, "abc", dest.path())
        .await
        .expect("export");
    let got = std::fs::read_to_string(dest.path().join("d/f.txt")).expect("read");
    assert_eq!(got, "payload");
}

#[tokio::test(flavor = "multi_thread")]
async fn copy_files_rejects_bad_input() {
    let cli = FakeCli::new();
    let d = backend(&cli, "docker", BackendConfig::default()).await;
    let bad_mode = File {
        path: "a".into(),
        content: "x".into(),
        mode: "644; id".into(),
        ..File::default()
    };
    assert!(d.copy_files("x", &[bad_mode]).await.is_err());
    let escape = File {
        path: "../etc/passwd".into(),
        content: "x".into(),
        ..File::default()
    };
    assert!(d.copy_files("x", &[escape]).await.is_err());
    let confine = BackendConfig::from_pairs([("RUNEWARD_CONFINE_FILES", "1")]);
    let d = backend(&cli, "docker", confine).await;
    let abs = File {
        path: "/root/.x".into(),
        content: "x".into(),
        ..File::default()
    };
    assert!(d.copy_files("x", &[abs]).await.is_err());
    assert!(cli.calls().is_empty(), "nothing may reach the CLI");
}

#[tokio::test(flavor = "multi_thread")]
async fn isolation_comes_from_evidence_not_the_runtime_name() {
    const INFO: &str = "runc|6.8.0-45-generic|Ubuntu 24.04 LTS";
    let cli = FakeCli::new();
    let vm_spec = || Spec {
        runtime_class: "kata-qemu".into(),
        ..demo("vm")
    };

    // A runtime registered as kata-qemu that really is runc: the sandbox
    // sees the host kernel, so the name's vm claim is refused.
    cli.set_engine(
        INFO,
        "@@osrelease\n6.8.0-45-generic\n@@cpuflags\nflags : fpu hypervisor\n",
    );
    let d = backend(&cli, "docker", BackendConfig::default()).await;
    let sb = d.create(vm_spec()).await.expect("create");
    assert_eq!(sb.isolation, IsolationTier::Container);
    let ev = sb.isolation_evidence.expect("evidence");
    for want in ["kernel:shared", "claim:vm", "verdict:container"] {
        assert!(ev.signals.contains(&want.to_owned()), "{want}: {ev:?}");
    }
    assert!(
        cli.calls()
            .iter()
            .any(|c| c.windows(2).any(|w| w == ["--runtime", "kata-qemu"]))
    );

    // A genuine microVM guest (synthetic probe output). The fake engine is
    // not on this machine, so the hypervisor process cannot be seen.
    cli.set_engine(
        INFO,
        "@@osrelease\n6.1.62\n@@cpuflags\nflags : fpu hypervisor\n@@cmdline\nconsole=ttyS0 virtio_mmio.device=4K@0xd0000000:5\n",
    );
    let d = backend(&cli, "docker", BackendConfig::default()).await;
    let sb = d.create(vm_spec()).await.expect("create");
    assert_eq!(sb.isolation, IsolationTier::Vm);
    let ev = sb.isolation_evidence.expect("evidence");
    assert_eq!(ev.hypervisor, "unknown");
    assert!(
        ev.signals.contains(&"host:hypervisor=unknown".to_owned()),
        "{ev:?}"
    );
    assert_eq!(cli.probes().len(), 1);

    // Probing disabled: the name is trusted and the evidence says so.
    let cfg = BackendConfig::from_pairs([(ISOLATION_PROBE_ENV, "off")]);
    let d = backend(&cli, "docker", cfg).await;
    let sb = d.create(vm_spec()).await.expect("create");
    assert_eq!(sb.isolation, IsolationTier::Vm);
    let ev = sb.isolation_evidence.expect("evidence");
    assert_eq!(ev.signals[0], "probe:disabled");
    assert!(cli.probes().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn kata_fc_is_refused_before_anything_runs() {
    let cli = FakeCli::new();
    let d = backend(&cli, "docker", BackendConfig::default()).await;
    for rc in ["kata-fc", "io.containerd.kata-fc.v2", "aws.firecracker"] {
        let err = d
            .create(Spec {
                runtime_class: rc.into(),
                ..demo("fc")
            })
            .await
            .expect_err("refused");
        let msg = err.to_string();
        assert!(msg.contains("devmapper snapshotter"), "{msg}");
        assert!(msg.contains("native Firecracker driver"), "{msg}");
    }
    assert!(cli.calls().is_empty(), "{:?}", cli.calls());
}

#[tokio::test(flavor = "multi_thread")]
async fn krun_is_refused_before_anything_runs() {
    let cli = FakeCli::new();
    for engine in ["docker", "podman"] {
        let d = backend(&cli, engine, BackendConfig::default()).await;
        for rc in ["krun", "crun-krun"] {
            let err = d
                .create(Spec {
                    runtime_class: rc.into(),
                    ..demo("krun")
                })
                .await
                .expect_err("refused");
            let msg = err.to_string();
            assert!(
                msg.contains("does not support exec"),
                "{engine} {rc}: {msg}"
            );
        }
    }
    assert!(cli.calls().is_empty(), "{:?}", cli.calls());
}

/// Makes the fake CLI fail `cmd` (only invocations containing `only` when
/// given) with `stderr` and exit 125.
fn fail_cli(cli: &FakeCli, cmd: &str, stderr: &str, only: Option<&str>) {
    std::fs::write(cli.dir.path().join(format!("fail.{cmd}")), stderr).expect("write fail");
    let m = cli.dir.path().join(format!("fail.{cmd}.match"));
    match only {
        Some(s) => std::fs::write(m, s).expect("write match"),
        None => {
            let _ = std::fs::remove_file(m);
        }
    }
}

fn clear_failures(cli: &FakeCli) {
    for e in std::fs::read_dir(cli.dir.path())
        .expect("read dir")
        .flatten()
    {
        if e.file_name().to_string_lossy().starts_with("fail.") {
            std::fs::remove_file(e.path()).expect("rm fail");
        }
    }
}

fn argv(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| (*s).to_owned()).collect()
}

/// Kata's runtime-rs shim when QEMU cannot start (observed on a KVM host).
const KATA_QMP_TIMEOUT: &str = "docker: Error response from daemon: failed to create task for container: failed to create shim task: Others(\"failed to handle message start vm: timed out waiting for QMP ready\"): unknown.";

#[tokio::test(flavor = "multi_thread")]
async fn failed_create_removes_container_volume_and_sidecar() {
    let cli = FakeCli::new();
    let rm_ctr = argv(&["rm", "-f", "-v", "runeward-<ID>"]);
    let rm_sidecar = argv(&["rm", "-f", "-v", "runeward-egress-<ID>"]);
    let rm_vol = argv(&["volume", "rm", "-f", "runeward-vol-<ID>"]);

    // `run -d` fails after the engine created the container (the Kata shim
    // timed out): the Created container and the workspace volume go, the
    // container first so the volume is no longer in use.
    fail_cli(&cli, "run", KATA_QMP_TIMEOUT, None);
    let d = backend(&cli, "docker", BackendConfig::default()).await;
    d.create(demo("leak")).await.expect_err("run fails");
    let calls = cli.calls();
    assert_eq!(calls[0][..2], ["volume", "create"], "{calls:#?}");
    assert_eq!(calls[1][..2], ["run", "-d"], "{calls:#?}");
    assert_eq!(calls[2..], [rm_ctr.clone(), rm_vol.clone()], "{calls:#?}");

    // Strict egress, the sandbox's run fails: the sidecar goes too.
    fail_cli(&cli, "run", KATA_QMP_TIMEOUT, Some("--entrypoint"));
    let d = backend(&cli, "docker", BackendConfig::default()).await;
    let spec = Spec {
        network: deny_network("l3"),
        ..demo("leak")
    };
    d.create(spec.clone()).await.expect_err("run fails");
    let calls = cli.calls();
    let n = calls.len();
    assert!(n > 3, "{calls:#?}");
    assert!(
        calls[n - 4].contains(&"--entrypoint".to_owned()),
        "{calls:#?}"
    );
    assert_eq!(
        calls[n - 3..],
        [rm_ctr.clone(), rm_sidecar.clone(), rm_vol.clone()],
        "{calls:#?}"
    );

    // The sidecar's own run fails: it and the volume go, no sandbox runs.
    fail_cli(&cli, "run", "sidecar boom", Some("--setup-iptables"));
    let d = backend(&cli, "docker", BackendConfig::default()).await;
    let err = d.create(spec).await.expect_err("sidecar fails");
    assert!(err.to_string().contains("egress sidecar"), "{err}");
    let calls = cli.calls();
    assert!(
        !calls.iter().any(|c| c.contains(&"--entrypoint".to_owned())),
        "{calls:#?}"
    );
    let n = calls.len();
    assert_eq!(calls[n - 2..], [rm_sidecar, rm_vol.clone()], "{calls:#?}");

    // A staged sandbox (broker) whose start fails: container and volume go.
    clear_failures(&cli);
    fail_cli(&cli, "start", KATA_QMP_TIMEOUT, None);
    let d = backend(&cli, "docker", BackendConfig::default()).await;
    let id = "00112233445566778899aabbccddeeff";
    let broker = runeward_egress::Broker::with_secret_values(id, vec![], vec![], HashMap::new())
        .expect("broker");
    let spec = Spec {
        id: id.into(),
        broker: Some(runeward_backend::BrokerHandle::new(std::sync::Arc::new(
            broker,
        ))),
        ..demo("leak")
    };
    d.create(spec).await.expect_err("start fails");
    let calls = cli.calls();
    let n = calls.len();
    assert_eq!(calls[n - 2..], [rm_ctr.clone(), rm_vol], "{calls:#?}");
    assert!(calls.iter().any(|c| c[0] == "start"), "{calls:#?}");

    // A rebuild around a kept workspace (wake after a restart) never
    // removes the volume, but still removes the failed container.
    clear_failures(&cli);
    fail_cli(&cli, "run", KATA_QMP_TIMEOUT, None);
    let d = backend(&cli, "docker", BackendConfig::default()).await;
    d.start(id, demo("leak")).await.expect_err("run fails");
    let calls = cli.calls();
    assert_eq!(calls.last(), Some(&rm_ctr), "{calls:#?}");
    assert!(
        !calls.iter().any(|c| c[..2] == ["volume", "rm"]),
        "{calls:#?}"
    );
    clear_failures(&cli);
}

#[tokio::test(flavor = "multi_thread")]
async fn vm_size_is_checked_against_the_engine_host() {
    // The KVM host the sizing bug was found on: 3.8 GiB, 2 CPUs.
    const INFO: &str = "runc|6.12.100+deb13-cloud-amd64|Debian GNU/Linux 13 (trixie)|4014825472|2";
    const KATA: &str = "io.containerd.kata-qemu.v2";
    let cli = FakeCli::new();
    cli.set_engine(INFO, "");
    let kata = || Spec {
        runtime_class: KATA.into(),
        ..demo("vm")
    };

    // Default limits (4g, 2 CPUs) plus the 2048 MiB / 1 vCPU overhead do
    // not fit: refused before anything reaches the engine.
    let d = backend(&cli, "docker", BackendConfig::default()).await;
    assert_eq!(d.capacity(), (4_014_825_472, 2));
    let err = d.create(kata()).await.expect_err("too big").to_string();
    for want in [
        "6144 MiB and 3 vCPUs",
        "3828 MiB and 2 CPUs",
        "[rationing] memory / cpus",
        "RUNEWARD_SANDBOX_MEMORY",
        "docs/isolation.md",
    ] {
        assert!(err.contains(want), "{want}: {err}");
    }
    assert!(cli.calls().is_empty(), "{:?}", cli.calls());
    // runc with the same limits is not a VM and is not checked.
    d.create(demo("ctr")).await.expect("runc create");

    // The limits that booted on that host fit; Charter limits count too.
    let small = BackendConfig::from_pairs([(SANDBOX_MEMORY_ENV, "512m"), (SANDBOX_CPUS_ENV, "1")]);
    let d = backend(&cli, "docker", small.clone()).await;
    d.create(kata()).await.expect("fits");
    let d = backend(&cli, "docker", BackendConfig::default()).await;
    d.create(Spec {
        resources: Resources {
            memory_bytes: 1 << 30,
            nano_cpus: 1_000_000_000,
        },
        ..kata()
    })
    .await
    .expect("charter limits fit");

    // The VM still fails to boot: the shim timeout is explained, and the
    // container and volume are removed.
    cli.reset();
    fail_cli(&cli, "run", KATA_QMP_TIMEOUT, None);
    let d = backend(&cli, "docker", small).await;
    let err = d.create(kata()).await.expect_err("boot fails").to_string();
    for want in [
        "VM did not start",
        "2560 MiB and 2 vCPUs",
        "/dev/kvm",
        "runtime-rs/configuration.toml",
        "timed out waiting for QMP ready",
    ] {
        assert!(err.contains(want), "{want}: {err}");
    }
    let calls = cli.calls();
    assert_eq!(
        calls[calls.len() - 2..],
        [
            argv(&["rm", "-f", "-v", "runeward-<ID>"]),
            argv(&["volume", "rm", "-f", "runeward-vol-<ID>"])
        ],
        "{calls:#?}"
    );
    clear_failures(&cli);
}
