//! Opt-in end-to-end test of the in-sandbox supervisor on a real Kubernetes
//! cluster.
//!
//! Runs only with `RUNEWARD_TEST_K8S=1`, against the kubeconfig context in
//! `RUNEWARD_KUBE_CONTEXT` (or the current one). The egress image named by
//! `RUNEWARD_EGRESS_IMAGE` must carry `runeward-supervisor`
//! (`deploy/Dockerfile.egress`) and be pullable by the nodes (for kind:
//! `kind load docker-image`); the sandbox image is `debian:stable-slim`.
//!
//! For a Charter with `[filesystem] landlock = "required"` and `[process]`,
//! once with the supervisor's own init container and once under strict
//! egress (whose init container installs it), it proves that:
//!
//! - the agent and every governed exec run as the Charter's uid with no
//!   capabilities, under Landlock (a write outside `read_write` and a read
//!   outside the allowed paths fail) and the seccomp filter (ptrace and
//!   user-namespace creation fail);
//! - the backend's own file projection runs as the agent, not root;
//! - the enforcement report is on the Citadel and in the signed ledger;
//! - a supervisor that refuses to start fails the create at once with its
//!   reason, leaving nothing behind.
//!
//! Everything the test creates is removed on the way out.
#![cfg(unix)]

use std::sync::Arc;
use std::time::Duration;

use runeward_backend::{Backend, BackendConfig, K8s, Spec, SupervisorSpec};
use runeward_charter::SignedCharters;
use runeward_controlplane::{CreateOptions, Manager, ManagerConfig};

const AGENT_UID: &str = "1500";
const IMAGE: &str = "debian:stable-slim";

fn enabled() -> bool {
    std::env::var("RUNEWARD_TEST_K8S").is_ok_and(|v| v == "1")
}

fn backend_config() -> BackendConfig {
    let mut pairs: Vec<(String, String)> = Vec::new();
    for k in [
        "RUNEWARD_KUBE_CONTEXT",
        "RUNEWARD_EGRESS_IMAGE",
        "RUNEWARD_EGRESS_PULL_POLICY",
        "RUNEWARD_K8S_NAMESPACE",
    ] {
        if let Ok(v) = std::env::var(k) {
            pairs.push((k.to_owned(), v));
        }
    }
    BackendConfig::from_pairs(pairs.iter().map(|(k, v)| (k.as_str(), v.as_str())))
}

fn charter(network: &str) -> String {
    format!(
        r#"
[host]
type = "k8s"
image = "{IMAGE}"
workdir = "/workspace"

[filesystem]
read_only = ["/usr", "/lib", "/bin", "/etc", "/proc"]
read_write = ["/tmp"]
landlock = "required"

[process]
run_as_user = "{AGENT_UID}"

{network}

[[file]]
path = "/workspace/notes.txt"
content = "projected"
"#
    )
}

/// Syscall numbers of ptrace(2).
fn ptrace_nr() -> u32 {
    if cfg!(target_arch = "aarch64") {
        117
    } else {
        101
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn supervised_k8s_sandbox_end_to_end() {
    if !enabled() {
        eprintln!("skipped: set RUNEWARD_TEST_K8S=1 to run against a cluster");
        return;
    }
    for (name, network) in [
        ("supervised", ""),
        (
            "supervised-strict",
            "[network]\ndefault = \"deny\"\nenforce = \"strict\"",
        ),
    ] {
        governed_citadel(name, network).await;
    }
    refused_supervisor_fails_fast().await;
}

async fn governed_citadel(name: &str, network: &str) {
    println!("== {name}");
    let dir = tempfile::tempdir().expect("tmp");
    let charters = dir.path().join("charters");
    std::fs::create_dir_all(&charters).expect("mkdir");
    std::fs::write(charters.join(format!("{name}.toml")), charter(network)).expect("charter");

    let mut cfg = ManagerConfig::from_lookup(|_| None);
    cfg.config_dir = Some(charters);
    cfg.state_dir = Some(dir.path().join("state"));
    cfg.signed_charters = SignedCharters::Disabled;
    cfg.sweep_interval = None;
    cfg.supervisor_report_wait = Duration::from_secs(60);
    let mgr: Arc<Manager> = Manager::builder(cfg)
        .backend_config(backend_config())
        .build()
        .await
        .expect("manager");

    let sb = mgr
        .create_sandbox(name, CreateOptions::default())
        .await
        .expect("create the supervised Citadel");
    println!("created {} ({})", sb.id, sb.image);
    let sh = |script: &str| {
        let mgr = Arc::clone(&mgr);
        let id = sb.id.clone();
        let script = script.to_owned();
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

    // Identity: the Charter's uid, no capabilities, no_new_privs, seccomp.
    let r = sh("id -u; grep -E '^(CapEff|CapPrm|NoNewPrivs|Seccomp):' /proc/self/status").await;
    let out = r.stdout;
    assert_eq!(out.lines().next(), Some(AGENT_UID), "{out}");
    assert!(out.contains("CapEff:\t0000000000000000"), "{out}");
    assert!(out.contains("CapPrm:\t0000000000000000"), "{out}");
    assert!(out.contains("NoNewPrivs:\t1"), "{out}");
    assert!(out.contains("Seccomp:\t2"), "{out}");

    // Landlock: the workspace and /tmp are writable; nothing else is, and
    // nothing outside the allowed paths is readable.
    let r = sh("echo ok > /workspace/w && echo ok > /tmp/t && cat /workspace/w").await;
    assert_eq!(r.exit_code, 0, "{}", r.stderr);
    let r = sh("echo x > /etc/denied").await;
    assert_ne!(r.exit_code, 0);
    assert!(r.stderr.contains("Permission denied"), "{}", r.stderr);
    let r = sh("ls /var").await;
    assert_ne!(r.exit_code, 0, "a read outside the allowed paths must fail");
    assert!(r.stderr.contains("Permission denied"), "{}", r.stderr);
    let r = sh("ls /run/runeward").await;
    assert_ne!(r.exit_code, 0, "the supervisor's state is unreachable");

    // seccomp: ptrace(PTRACE_TRACEME) and a user namespace are refused.
    let r = sh(&format!(
        "perl -e '$r = syscall({}, 0, 0, 0, 0); print \"$r $!\\n\"'",
        ptrace_nr()
    ))
    .await;
    assert!(
        r.stdout.starts_with("-1 Operation not permitted"),
        "{}",
        r.stdout
    );
    let r = sh("unshare -U true").await;
    assert_ne!(r.exit_code, 0);
    assert!(r.stderr.contains("Operation not permitted"), "{}", r.stderr);

    // The agent (PID 1's child) has the same identity.
    let r = sh("for p in /proc/[0-9]*; do [ \"$(cat $p/comm 2>/dev/null)\" = sleep ] && grep '^Uid:' $p/status; done").await;
    assert!(
        r.stdout.starts_with(&format!("Uid:\t{AGENT_UID}\t")),
        "{}",
        r.stdout
    );

    // The projected file and the workspace belong to the agent.
    let r = sh("stat -c '%u %n' /workspace /workspace/notes.txt").await;
    assert_eq!(
        r.stdout.trim(),
        format!("{AGENT_UID} /workspace\n{AGENT_UID} /workspace/notes.txt")
    );

    // Evidence on the Citadel and in the signed ledger.
    let info = mgr
        .list_sandbox_infos()
        .into_iter()
        .find(|i| i.sandbox.id == sb.id)
        .expect("info");
    let ev = info.enforcement.expect("enforcement evidence");
    println!("enforcement: {ev:?}");
    assert_eq!(ev.supervisor, "enforced");
    assert_eq!(ev.landlock, "enforced");
    assert_eq!(ev.uid, Some(1500));
    assert!(ev.seccomp && ev.no_new_privs && ev.capabilities_dropped);
    assert!(ev.protected_by_landlock);
    let ledger = Arc::clone(mgr.ledger());
    let records = tokio::task::spawn_blocking(move || ledger.records().expect("records"))
        .await
        .expect("join");
    let report = records
        .iter()
        .find(|e| e.tool == "supervisor" && e.action == "report")
        .expect("supervisor report chronicled");
    println!("ledger supervisor report: {}", report.meta["report"]);
    assert_eq!(report.meta["landlock"], "enforced");
    assert!(report.meta["report"].contains("\"mode\":\"init\""));
    mgr.verify_ledger().await.expect("signed ledger verifies");

    mgr.kill_sandbox(&sb.id).await.expect("kill");
    mgr.close().await.expect("close");
}

/// A supervisor that refuses its config (a read-write path exposing its
/// own state) fails the create with its reason instead of a timeout.
async fn refused_supervisor_fails_fast() {
    println!("== refused");
    let k = K8s::new(backend_config()).await.expect("k8s");
    let mut config =
        runeward_supervisor::SupervisorConfig::default().with_argv(["sleep", "infinity"]);
    config.workdir = "/workspace".into();
    config.filesystem.landlock = runeward_supervisor::LandlockMode::Required;
    config.filesystem.read_write = vec!["/run".into(), "/workspace".into()];
    config.process.user = AGENT_UID.into();
    let id = "5ca1ab1e5ca1ab1e5ca1ab1e5ca1ab1e";
    let started = std::time::Instant::now();
    let err = k
        .create(Spec {
            id: id.into(),
            image: IMAGE.into(),
            profile: "refused".into(),
            supervisor: Some(SupervisorSpec {
                config,
                required: true,
            }),
            ..Spec::default()
        })
        .await;
    let err = match err {
        Ok(sb) => {
            let _ = k.kill(&sb.id).await;
            panic!("the supervisor should have refused: {sb:?}");
        }
        Err(e) => e,
    };
    println!("refused in {:?}: {err}", started.elapsed());
    let msg = err.to_string();
    assert!(msg.contains("exit 77"), "{msg}");
    assert!(msg.contains("protected path"), "{msg}");
    assert!(started.elapsed() < Duration::from_secs(80), "fails fast");
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    while k.exists(id).await {
        assert!(std::time::Instant::now() < deadline, "nothing left behind");
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}
