//! End-to-end tests that run the real `runeward-supervisor` binary.
//!
//! They need Linux, root (to switch to an unprivileged uid) and an opt-in:
//! `RUNEWARD_TEST_SUPERVISOR=1`. Run them in a throwaway container, with the
//! engine's own seccomp profile off so every `EPERM` seen comes from the
//! supervisor's filter:
//!
//! ```text
//! docker run --rm --security-opt seccomp=unconfined -e RUNEWARD_TEST_SUPERVISOR=1 \
//!   -v "$PWD":/src -w /src rust:1 cargo test -p runeward-supervisor --test linux_supervisor
//! ```
//!
//! The agent is this test binary itself, re-run with `RUNEWARD_PROBE=1` so
//! that [`probe_entry`] performs the escape attempts and prints the results.
#![cfg(target_os = "linux")]

use std::collections::BTreeMap;
use std::io::{IoSliceMut, Read as _};
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use nix::errno::Errno;
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use runeward_supervisor::config::{LandlockMode, SupervisorConfig};
use runeward_supervisor::report::Report;

const BIN: &str = env!("CARGO_BIN_EXE_runeward-supervisor");
const UID: u32 = 1500;
const GID: u32 = 1600;

fn enabled() -> bool {
    if std::env::var("RUNEWARD_TEST_SUPERVISOR").as_deref() != Ok("1") {
        eprintln!("skipped: set RUNEWARD_TEST_SUPERVISOR=1 to run supervisor integration tests");
        return false;
    }
    if !nix::unistd::geteuid().is_root() {
        eprintln!("skipped: supervisor integration tests need root");
        return false;
    }
    true
}

fn errno_of(e: &std::io::Error) -> String {
    e.raw_os_error()
        .map_or_else(|| e.to_string(), |n| format!("{:?}", Errno::from_raw(n)))
}

fn io<T>(r: std::io::Result<T>) -> String {
    match r {
        Ok(_) => "ok".into(),
        Err(e) => errno_of(&e),
    }
}

fn sys<T>(r: nix::Result<T>) -> String {
    match r {
        Ok(_) => "ok".into(),
        Err(e) => format!("{e:?}"),
    }
}

/// The agent side: runs only when re-executed by the supervisor.
#[test]
fn probe_entry() {
    if std::env::var("RUNEWARD_PROBE").as_deref() != Ok("1") {
        return;
    }
    // libtest has already printed "test probe_entry ... " on this line.
    println!();
    let root = PathBuf::from(std::env::var("PROBE_ROOT").expect("PROBE_ROOT"));
    let mut out = BTreeMap::new();
    out.insert("uid", nix::unistd::getuid().to_string());
    out.insert("gid", nix::unistd::getgid().to_string());
    out.insert(
        "groups",
        nix::unistd::getgroups()
            .expect("groups")
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(","),
    );
    out.insert(
        "read_secret",
        io(std::fs::read(root.join("secret/secret.txt"))),
    );
    out.insert(
        "write_secret",
        io(std::fs::write(root.join("secret/new"), "x")),
    );
    out.insert("read_ro", io(std::fs::read(root.join("ro/file.txt"))));
    out.insert("write_ro", io(std::fs::write(root.join("ro/new"), "x")));
    // truncate(2) by path: Landlock ABI 3+ is needed to stop this.
    out.insert(
        "truncate_ro",
        sys(nix::unistd::truncate(&root.join("ro/file.txt"), 0)),
    );
    out.insert("write_work", io(std::fs::write(root.join("work/out"), "x")));
    out.insert(
        "read_report",
        io(std::fs::read(root.join("state/report.jsonl"))),
    );

    out.insert("ptrace", sys(nix::sys::ptrace::traceme()));
    let local = [7u8; 16];
    let mut buf = [0u8; 16];
    out.insert(
        "process_vm_readv",
        sys(nix::sys::uio::process_vm_readv(
            nix::unistd::getpid(),
            &mut [IoSliceMut::new(&mut buf)],
            &[nix::sys::uio::RemoteIoVec {
                base: local.as_ptr() as usize,
                len: local.len(),
            }],
        )),
    );
    out.insert(
        "unshare",
        sys(nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWUSER)),
    );
    out.insert(
        "mount",
        sys(nix::mount::mount(
            Some("none"),
            "/nonexistent-rw",
            Some("tmpfs"),
            nix::mount::MsFlags::empty(),
            None::<&str>,
        )),
    );
    out.insert(
        "umount2",
        sys(nix::mount::umount2(
            "/nonexistent-rw",
            nix::mount::MntFlags::empty(),
        )),
    );
    out.insert("chroot", sys(nix::unistd::chroot("/nonexistent-rw")));
    out.insert(
        "thread",
        if std::thread::spawn(|| 2 + 2).join().ok() == Some(4) {
            "ok".into()
        } else {
            "failed".into()
        },
    );
    out.insert(
        "spawn",
        match Command::new("/bin/true").status() {
            Ok(s) if s.success() => "ok".into(),
            Ok(s) => format!("status {s}"),
            Err(e) => errno_of(&e),
        },
    );
    if let Ok(sock) = std::env::var("PROBE_ATTRIB_SOCKET") {
        attribution_probe(&sock, &mut out);
    }
    for (k, v) in out {
        println!("PROBE {k}={v}");
    }
}

/// Opens a TCP connection and asks the attribution helper who holds it, as
/// the egress broker would; also tries to read the helper's secrets.
fn attribution_probe(sock: &str, out: &mut BTreeMap<&'static str, String>) {
    use runeward_attribution::{Key, client};
    let key = Key::from_hex(&std::env::var("PROBE_ATTRIB_KEY").expect("key")).expect("hex");
    let ln = std::net::TcpListener::bind("127.0.0.1:0").expect("listen");
    let c = std::net::TcpStream::connect(ln.local_addr().expect("addr")).expect("connect");
    let _server_side = ln.accept().expect("accept");
    match client::query(
        sock,
        &key,
        c.local_addr().expect("local"),
        Some(ln.local_addr().expect("addr")),
        Duration::from_secs(5),
    ) {
        Ok(a) => {
            out.insert("attrib_status", a.status.as_str().into());
            let me = std::process::id();
            let mine = a.holders.iter().find(|h| h.pid == me);
            out.insert(
                "attrib_exe",
                mine.map(|h| h.exe.clone()).unwrap_or_default(),
            );
            out.insert(
                "attrib_matches",
                mine.map(|h| h.matches.join(",")).unwrap_or_default(),
            );
            out.insert("attrib_holders", a.holders.len().to_string());
        }
        Err(e) => {
            out.insert("attrib_status", format!("err:{e}"));
        }
    }
    // Under Landlock /proc is out of reach; that is fine.
    let helper = std::fs::read_dir("/proc")
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .find(|e| {
            std::fs::read(e.path().join("cmdline"))
                .is_ok_and(|c| c.windows(18).any(|w| w == b"attribution-helper"))
        })
        .map(|e| e.path());
    match helper {
        Some(h) => {
            out.insert("helper_environ", io(std::fs::read(h.join("environ"))));
            out.insert("helper_fds", io(std::fs::read_dir(h.join("fd"))));
        }
        None => {
            out.insert("helper_environ", "no helper".into());
        }
    }
}

/// A scratch tree the agent is pointed at, readable by DAC so that every
/// denial seen comes from the supervisor.
struct Fixture {
    _dir: tempfile::TempDir,
    root: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::Builder::new()
            .prefix("rw-supervisor-")
            .tempdir_in("/tmp")
            .expect("tempdir");
        let root = dir.path().to_path_buf();
        let mode = |p: &Path, m: u32| {
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(m)).expect("chmod");
        };
        mode(&root, 0o755);
        for (d, m) in [("secret", 0o777), ("ro", 0o777), ("work", 0o777)] {
            std::fs::create_dir(root.join(d)).expect("mkdir");
            mode(&root.join(d), m);
        }
        std::fs::write(root.join("secret/secret.txt"), "top secret").expect("write");
        mode(&root.join("secret/secret.txt"), 0o644);
        std::fs::write(root.join("ro/file.txt"), "read me").expect("write");
        mode(&root.join("ro/file.txt"), 0o666);
        Self { _dir: dir, root }
    }

    fn path(&self, rel: &str) -> String {
        self.root.join(rel).display().to_string()
    }

    fn report_path(&self) -> String {
        self.path("state/report.jsonl")
    }

    /// A config that runs the probe confined to the fixture.
    fn probe_config(&self) -> SupervisorConfig {
        let exe = std::env::current_exe().expect("exe");
        let exe_dir = exe.parent().expect("exe dir").display().to_string();
        let mut cfg = SupervisorConfig::default().with_argv([
            exe.display().to_string(),
            "--exact".into(),
            "probe_entry".into(),
            "--nocapture".into(),
            "--test-threads=1".into(),
        ]);
        cfg.env.insert("RUNEWARD_PROBE".into(), "1".into());
        cfg.env
            .insert("PROBE_ROOT".into(), self.root.display().to_string());
        cfg.workdir = self.path("work");
        cfg.filesystem.landlock = LandlockMode::Required;
        cfg.filesystem.read_only = vec![
            "/usr".into(),
            "/lib".into(),
            "/lib64".into(),
            "/bin".into(),
            "/etc".into(),
            exe_dir,
            self.path("ro"),
        ];
        cfg.filesystem.read_write = vec![self.path("work"), "/dev/null".into()];
        cfg.process.user = UID.to_string();
        cfg.process.group = GID.to_string();
        cfg.protected_paths = vec![self.path("state")];
        cfg.report_path = self.report_path();
        cfg
    }

    fn reports(&self) -> Vec<Report> {
        std::fs::read_to_string(self.report_path())
            .unwrap_or_default()
            .lines()
            .map(|l| Report::parse(l).expect("report line"))
            .collect()
    }
}

struct Outcome {
    code: i32,
    probe: BTreeMap<String, String>,
    stderr: String,
}

fn run(cfg: &SupervisorConfig, mode: &str, env: &[(&str, &str)]) -> Outcome {
    let mut cmd = Command::new(BIN);
    cmd.arg(mode)
        .env("RUNEWARD_SUPERVISOR_CONFIG", cfg.to_json())
        .stdin(Stdio::null());
    for (k, v) in env {
        cmd.env(k, v);
    }
    let child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("run supervisor");
    // Watchdog: a hung agent fails the test instead of the whole run.
    let pid = Pid::from_raw(child.id().cast_signed());
    let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
    let watchdog = std::thread::spawn(move || {
        if done_rx.recv_timeout(Duration::from_secs(60)).is_err() {
            let _ = kill(pid, Signal::SIGKILL);
        }
    });
    let out = child.wait_with_output().expect("wait supervisor");
    let _ = done_tx.send(());
    let _ = watchdog.join();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let probe = stdout
        .lines()
        .filter_map(|l| l.strip_prefix("PROBE "))
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect();
    Outcome {
        code: out.status.code().unwrap_or(-1),
        probe,
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// Reports whether this test process already runs under a seccomp filter
/// (for example the container engine's default profile).
fn under_engine_seccomp() -> bool {
    std::fs::read_to_string("/proc/self/status")
        .unwrap_or_default()
        .lines()
        .find_map(|l| l.strip_prefix("Seccomp:"))
        .is_some_and(|v| v.trim() != "0")
}

fn kernel() -> String {
    std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .unwrap_or_default()
        .trim()
        .to_owned()
}

#[test]
fn confines_files_syscalls_and_identity() {
    if !enabled() {
        return;
    }
    let fx = Fixture::new();
    let out = run(&fx.probe_config(), "init", &[]);
    assert_eq!(out.code, 0, "stderr: {}", out.stderr);
    let p = &out.probe;
    let want = [
        ("uid", "1500"),
        ("gid", "1600"),
        ("groups", "1600"),
        ("read_secret", "EACCES"),
        ("write_secret", "EACCES"),
        ("read_ro", "ok"),
        ("write_ro", "EACCES"),
        ("truncate_ro", "EACCES"),
        ("write_work", "ok"),
        ("read_report", "EACCES"),
        ("ptrace", "EPERM"),
        ("process_vm_readv", "EPERM"),
        ("unshare", "EPERM"),
        ("mount", "EPERM"),
        ("umount2", "EPERM"),
        ("chroot", "EPERM"),
        ("thread", "ok"),
        ("spawn", "ok"),
    ];
    for (k, v) in want {
        assert_eq!(
            p.get(k).map(String::as_str),
            Some(v),
            "{k}: {p:?}\n{}",
            out.stderr
        );
    }

    let reports = fx.reports();
    assert_eq!(reports.len(), 1);
    let r = &reports[0];
    eprintln!(
        "kernel {} landlock abi {} status {}",
        kernel(),
        r.landlock.abi,
        r.landlock.status
    );
    assert!(r.ok && r.mode == "init" && r.error.is_none(), "{r:?}");
    assert_eq!(r.landlock.status, "enforced");
    assert!(r.landlock.abi >= 3, "{r:?}");
    assert!(r.protected_by_landlock);
    assert!(r.seccomp.enabled);
    assert_eq!(r.seccomp.action, "errno:EPERM");
    assert!(r.no_new_privs);
    assert_eq!(
        (r.uid, r.gid, r.groups.as_slice()),
        (Some(UID), Some(GID), &[GID][..])
    );
    let c = &r.capabilities;
    assert!(
        c.effective.is_empty()
            && c.permitted.is_empty()
            && c.inheritable.is_empty()
            && c.ambient.is_empty()
            && c.bounding.is_empty(),
        "{c:?}"
    );
    assert!(r.agent_pid.is_some_and(|p| p != r.supervisor_pid));
}

#[test]
fn control_run_without_confinement_succeeds() {
    if !enabled() {
        return;
    }
    // The same probe with Landlock and seccomp off: proves the denials above
    // come from the supervisor, not from file modes or the engine.
    let fx = Fixture::new();
    let mut cfg = fx.probe_config();
    cfg.filesystem.landlock = LandlockMode::Off;
    cfg.seccomp = false;
    let out = run(&cfg, "init", &[]);
    assert_eq!(out.code, 0, "stderr: {}", out.stderr);
    let p = &out.probe;
    for (k, v) in [
        ("uid", "1500"),
        ("read_secret", "ok"),
        ("write_secret", "ok"),
        ("write_ro", "ok"),
        ("ptrace", "ok"),
        ("process_vm_readv", "ok"),
        ("chroot", "ENOENT"),
        ("mount", "ENOENT"),
    ] {
        // An engine seccomp profile (Docker's default) denies mount itself.
        if k == "mount" && under_engine_seccomp() {
            continue;
        }
        assert_eq!(p.get(k).map(String::as_str), Some(v), "{k}: {p:?}");
    }
    let r = &fx.reports()[0];
    assert_eq!(r.landlock.status, "off");
    assert!(!r.seccomp.enabled && !r.protected_by_landlock);
}

#[test]
fn required_landlock_fails_closed_when_unsupported() {
    if !enabled() {
        return;
    }
    for abi in ["0", "2"] {
        let fx = Fixture::new();
        let marker = fx.path("work/ran");
        let cfg = fx
            .probe_config()
            .with_argv(["/bin/sh", "-c", &format!("touch {marker}")]);
        let out = run(
            &cfg,
            "init",
            &[("RUNEWARD_SUPERVISOR_TEST_LANDLOCK_ABI", abi)],
        );
        assert_eq!(
            out.code,
            runeward_supervisor::EXIT_REFUSED,
            "abi {abi}: {}",
            out.stderr
        );
        assert!(out.stderr.contains("required"), "{}", out.stderr);
        assert!(!Path::new(&marker).exists(), "the agent must not run");
        let r = &fx.reports()[0];
        assert!(!r.ok && r.agent_pid.is_none());
        assert!(
            r.error.as_deref().is_some_and(|e| e.contains("Landlock")),
            "{r:?}"
        );
    }
}

#[test]
fn best_effort_degrades_and_reports_it() {
    if !enabled() {
        return;
    }
    // No Landlock at all: the agent runs and the report says so.
    let fx = Fixture::new();
    let mut cfg = fx.probe_config();
    cfg.filesystem.landlock = LandlockMode::BestEffort;
    let out = run(
        &cfg,
        "init",
        &[("RUNEWARD_SUPERVISOR_TEST_LANDLOCK_ABI", "0")],
    );
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert_eq!(out.probe.get("read_secret").map(String::as_str), Some("ok"));
    assert_eq!(out.probe.get("ptrace").map(String::as_str), Some("EPERM"));
    let r = &fx.reports()[0];
    assert_eq!(
        (r.landlock.status.as_str(), r.landlock.abi),
        ("unsupported", 0)
    );
    assert!(!r.protected_by_landlock);

    // ABI 1: enforced at what the kernel (here, simulated) offers. ABI 1
    // cannot stop truncate, which is why `required` needs ABI 3.
    let fx = Fixture::new();
    let mut cfg = fx.probe_config();
    cfg.filesystem.landlock = LandlockMode::BestEffort;
    let out = run(
        &cfg,
        "init",
        &[("RUNEWARD_SUPERVISOR_TEST_LANDLOCK_ABI", "1")],
    );
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert_eq!(
        out.probe.get("read_secret").map(String::as_str),
        Some("EACCES")
    );
    assert_eq!(out.probe.get("truncate_ro").map(String::as_str), Some("ok"));
    let r = &fx.reports()[0];
    assert_eq!(
        (r.landlock.status.as_str(), r.landlock.abi),
        ("enforced", 1)
    );
}

#[test]
fn refuses_root_and_exposed_supervisor_paths() {
    if !enabled() {
        return;
    }
    let fx = Fixture::new();
    let mut cfg = fx.probe_config();
    cfg.process.user.clear();
    cfg.process.group.clear();
    let out = run(&cfg, "init", &[]);
    assert_eq!(
        out.code,
        runeward_supervisor::EXIT_REFUSED,
        "{}",
        out.stderr
    );
    assert!(out.stderr.contains("root"), "{}", out.stderr);
    assert!(out.probe.is_empty());

    let mut cfg = fx.probe_config();
    cfg.filesystem.read_only.push(fx.root.display().to_string());
    let out = run(&cfg, "init", &[]);
    assert_eq!(
        out.code,
        runeward_supervisor::EXIT_REFUSED,
        "{}",
        out.stderr
    );
    assert!(out.stderr.contains("protected"), "{}", out.stderr);

    let mut cfg = fx.probe_config();
    cfg.filesystem.read_write.push(
        Path::new(BIN)
            .parent()
            .expect("bin dir")
            .display()
            .to_string(),
    );
    let out = run(&cfg, "init", &[]);
    assert_eq!(
        out.code,
        runeward_supervisor::EXIT_REFUSED,
        "{}",
        out.stderr
    );
    assert!(out.stderr.contains("modify"), "{}", out.stderr);
}

#[test]
fn exec_mode_confines_in_place() {
    if !enabled() {
        return;
    }
    let fx = Fixture::new();
    let out = run(&fx.probe_config(), "exec", &[]);
    assert_eq!(out.code, 0, "{}", out.stderr);
    for (k, v) in [
        ("uid", "1500"),
        ("read_secret", "EACCES"),
        ("unshare", "EPERM"),
    ] {
        assert_eq!(out.probe.get(k).map(String::as_str), Some(v), "{k}");
    }
    let r = &fx.reports()[0];
    assert!(r.ok && r.mode == "exec");
    assert_eq!(r.agent_pid, Some(r.supervisor_pid));
}

#[test]
fn attribution_helper_identifies_the_agent_and_hides_its_key() {
    if !enabled() {
        return;
    }
    // With the agent unconfined by Landlock (so the probe can look at /proc
    // itself, and every denial comes from the helper being non-dumpable),
    // and with the agent under required Landlock (the helper, outside any
    // Landlock domain, must still see the agent's descriptors).
    for landlock in [LandlockMode::Off, LandlockMode::Required] {
        let fx = Fixture::new();
        let mut cfg = fx.probe_config();
        cfg.filesystem.landlock = landlock;
        let exe = std::env::current_exe().expect("exe").display().to_string();
        let key = runeward_attribution::Key::generate();
        let sock = format!("@rw-attribution-test-{}", std::process::id());
        let cfg = cfg.with_attribution(
            sock.clone(),
            key.to_hex().as_str(),
            vec![exe.clone(), "/no/such/binary".into()],
        );
        let out = run(
            &cfg,
            "init",
            &[
                ("PROBE_ATTRIB_SOCKET", &sock),
                ("PROBE_ATTRIB_KEY", key.to_hex().as_str()),
            ],
        );
        assert_eq!(out.code, 0, "{landlock:?} stderr: {}", out.stderr);
        let p = &out.probe;
        eprintln!("{landlock:?} probe: {p:?}");
        // The test harness above the supervisor runs as root, which the
        // helper cannot inspect, so the answer is incomplete here; in a
        // sandbox every process is the agent's. The agent itself is
        // identified either way.
        let status = p.get("attrib_status").map(String::as_str);
        assert!(
            matches!(status, Some("attributed" | "incomplete")),
            "{landlock:?} {p:?}\n{}",
            out.stderr
        );
        assert_eq!(p.get("attrib_exe"), Some(&exe), "{landlock:?} {p:?}");
        assert_eq!(p.get("attrib_matches"), Some(&exe), "{landlock:?} {p:?}");
        if landlock == LandlockMode::Off {
            for k in ["helper_environ", "helper_fds"] {
                assert_eq!(p.get(k).map(String::as_str), Some("EACCES"), "{k}: {p:?}");
            }
        }

        let r = &fx.reports()[0];
        let a = r.attribution.as_ref().expect("attribution report");
        assert_eq!(a.status, "enforced");
        assert_eq!(a.socket, sock);
        assert_eq!(a.pinned, vec![exe]);
        assert_eq!(a.missing, vec!["/no/such/binary".to_owned()]);
        assert!(a.pid.is_some_and(|h| h != r.supervisor_pid));
        // The key is never in the report.
        let hex = key.to_hex();
        assert!(
            !fx.reports()
                .iter()
                .any(|r| r.to_line().contains(hex.as_str()))
        );
    }
}

#[test]
fn attribution_failure_refuses_the_agent() {
    if !enabled() {
        return;
    }
    let fx = Fixture::new();
    let marker = fx.path("work/ran");
    let cfg = fx
        .probe_config()
        .with_argv(["/bin/sh", "-c", &format!("touch {marker}")])
        // The helper cannot bind a socket in a missing directory.
        .with_attribution(
            "/nonexistent-dir/attribution.sock",
            runeward_attribution::Key::generate().to_hex().as_str(),
            vec!["/bin/true".into()],
        );
    let out = run(&cfg, "init", &[]);
    assert_eq!(
        out.code,
        runeward_supervisor::EXIT_REFUSED,
        "{}",
        out.stderr
    );
    assert!(!Path::new(&marker).exists(), "the agent must not run");
    let r = &fx.reports()[0];
    assert!(!r.ok && r.agent_pid.is_none());
    assert_eq!(
        r.attribution.as_ref().map(|a| a.status.as_str()),
        Some("refused")
    );
    assert!(
        r.error
            .as_deref()
            .is_some_and(|e| e.contains("attribution")),
        "{r:?}"
    );
}

fn children(pid: u32) -> Vec<u32> {
    std::fs::read_to_string(format!("/proc/{pid}/task/{pid}/children"))
        .unwrap_or_default()
        .split_whitespace()
        .filter_map(|s| s.parse().ok())
        .collect()
}

#[test]
fn reaps_orphans_and_propagates_exit_status() {
    if !enabled() {
        return;
    }
    let fx = Fixture::new();
    let mut cfg = fx.probe_config();
    cfg.filesystem.landlock = LandlockMode::Off;
    // The subshell exits at once, orphaning `sleep 0.1`, which the
    // supervisor adopts and must reap.
    cfg.argv = ["/bin/sh", "-c", "(sleep 0.1 &); sleep 1; exit 3"]
        .map(String::from)
        .to_vec();
    let mut child = Command::new(BIN)
        .env("RUNEWARD_SUPERVISOR_CONFIG", cfg.to_json())
        .spawn()
        .expect("spawn");
    std::thread::sleep(Duration::from_millis(600));
    let agent = fx.reports()[0].agent_pid.expect("agent pid");
    assert_eq!(children(child.id()), [agent], "orphan left unreaped");
    let status = child.wait().expect("wait");
    assert_eq!(status.code(), Some(3));
}

#[test]
fn forwards_signals_to_the_agent() {
    if !enabled() {
        return;
    }
    let fx = Fixture::new();
    let mut cfg = fx.probe_config();
    cfg.filesystem.landlock = LandlockMode::Off;
    cfg.argv = ["/bin/sleep", "30"].map(String::from).to_vec();
    let mut child = Command::new(BIN)
        .env("RUNEWARD_SUPERVISOR_CONFIG", cfg.to_json())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    let deadline = Instant::now() + Duration::from_secs(10);
    while fx.reports().is_empty() {
        assert!(Instant::now() < deadline, "no report");
        std::thread::sleep(Duration::from_millis(20));
    }
    let start = Instant::now();
    kill(Pid::from_raw(child.id().cast_signed()), Signal::SIGTERM).expect("kill");
    let status = child.wait().expect("wait");
    assert_eq!(status.code(), Some(128 + Signal::SIGTERM as i32));
    assert!(start.elapsed() < Duration::from_secs(5));
    let mut err = String::new();
    child
        .stderr
        .take()
        .expect("stderr")
        .read_to_string(&mut err)
        .expect("read");
    assert!(err.is_empty(), "{err}");
}
