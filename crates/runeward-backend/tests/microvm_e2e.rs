//! Opt-in end-to-end test of the native microVM backend on a host with a
//! usable hypervisor (Linux with `/dev/kvm`, or macOS on Apple silicon for
//! libkrun).
//!
//! `RUNEWARD_TEST_MICROVM=firecracker|libkrun` runs it; the backend reads
//! its usual settings (`RUNEWARD_MICROVM_DIR`, `RUNEWARD_MICROVM_AGENT`,
//! `RUNEWARD_MICROVM_KERNEL`, `RUNEWARD_FIRECRACKER_BIN`,
//! `RUNEWARD_KRUN_HELPER`, `RUNEWARD_LIBKRUN`, ...). The image
//! (`RUNEWARD_TEST_MICROVM_IMAGE`, default `curlimages/curl:8.11.1`) needs
//! `/bin/sh` and `curl`; `RUNEWARD_TEST_MICROVM_ALLOW` names a host the
//! egress policy allows (default `example.com`), which must be reachable
//! from the test host.
//!
//! `RUNEWARD_TEST_MICROVM_SUPERVISED=1` also runs a supervised, read-only
//! sandbox from `ghcr.io/runeeward/runeward-sandbox:latest` (or
//! `RUNEWARD_TEST_MICROVM_SUPERVISED_IMAGE`), an image carrying
//! `runeward-supervisor`.
//!
//! It checks: the `vm` verdict and its evidence, exec (status, streams,
//! environment, a TTY), files and workspace export, that the guest has no
//! network interface and no route around the proxy, that an allowed host
//! is reachable through the proxy and a denied one is refused, that the
//! workspace survives sleep and wake, and that destroying the sandbox
//! leaves no VMM process, socket or file behind.
#![cfg(unix)]

use std::collections::BTreeMap;
use std::path::PathBuf;

use runeward_backend::{
    Backend, BackendConfig, ExecRequest, IsolationTier, MicroVm, PtyStream, Spec, SupervisorSpec,
};
use runeward_charter::{File, Network, NetworkRule};

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_default().trim().to_owned()
}

/// Kills the sandbox on drop so a failed assertion leaves nothing running.
struct Cleanup<'a> {
    be: &'a MicroVm,
    id: String,
}

impl Drop for Cleanup<'_> {
    fn drop(&mut self) {
        let (be, id) = (self.be, self.id.clone());
        let handle = tokio::runtime::Handle::current();
        std::thread::scope(|s| {
            s.spawn(|| {
                let _ = handle.block_on(be.kill(&id));
            });
        });
    }
}

async fn sh(be: &MicroVm, id: &str, script: &str) -> runeward_backend::ExecResult {
    be.exec(id, ExecRequest::new(["/bin/sh", "-c", script]))
        .await
        .expect("exec")
}

/// The pids of processes whose command line mentions `needle`.
fn processes_mentioning(needle: &str) -> Vec<u32> {
    let Ok(d) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    d.flatten()
        .filter_map(|e| {
            let pid: u32 = e.file_name().to_str()?.parse().ok()?;
            let cmd = std::fs::read(e.path().join("cmdline")).ok()?;
            String::from_utf8_lossy(&cmd)
                .contains(needle)
                .then_some(pid)
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn microvm_end_to_end() {
    let vmm = env("RUNEWARD_TEST_MICROVM");
    if vmm.is_empty() {
        eprintln!("skipping: set RUNEWARD_TEST_MICROVM=firecracker|libkrun on a KVM host");
        return;
    }
    let image = match env("RUNEWARD_TEST_MICROVM_IMAGE") {
        s if s.is_empty() => "curlimages/curl:8.11.1".to_owned(),
        s => s,
    };
    let allowed = match env("RUNEWARD_TEST_MICROVM_ALLOW") {
        s if s.is_empty() => "example.com".to_owned(),
        s => s,
    };
    let config = BackendConfig::from_env();
    let be = MicroVm::new(config)
        .await
        .expect("open the microvm backend");
    assert_eq!(be.isolation_tier(), IsolationTier::Vm);
    let id = hex::encode(rand::random::<[u8; 16]>());
    let _cleanup = Cleanup {
        be: &be,
        id: id.clone(),
    };
    let spec = Spec {
        id: id.clone(),
        profile: "microvm-e2e".into(),
        image: image.clone(),
        runtime_class: vmm.clone(),
        env: BTreeMap::from([("CHARTER_VAR".into(), "charter".into())]),
        network: Network {
            default: "deny".into(),
            rules: vec![NetworkRule {
                hostname: allowed.clone(),
                ..NetworkRule::default()
            }],
            enforce: "strict".into(),
        },
        persist_workspace: true,
        files: vec![File {
            path: "projected.txt".into(),
            mode: "0640".into(),
            content: "projected".into(),
            ..File::default()
        }],
        ..Spec::default()
    };
    let started = std::time::Instant::now();
    let sb = be.create(spec.clone()).await.expect("create");
    eprintln!("created {} in {:?}", sb.id, started.elapsed());
    let ev = sb.isolation_evidence.clone().expect("evidence");
    eprintln!("evidence: {}", serde_json::to_string(&ev).expect("json"));
    assert_eq!(sb.isolation, IsolationTier::Vm, "{ev:?}");
    assert!(ev.signals.iter().any(|s| s == "kernel:separate"), "{ev:?}");
    assert!(ev.signals.iter().any(|s| s == "verdict:vm"), "{ev:?}");
    let want_hv = if vmm == "krun" {
        "libkrun"
    } else {
        vmm.as_str()
    };
    assert_eq!(ev.hypervisor, want_hv, "{ev:?}");
    let host_kernel = std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default();
    assert_ne!(ev.guest_kernel, host_kernel.trim());
    let dir = PathBuf::from(env("RUNEWARD_MICROVM_DIR"))
        .join("vms")
        .join(&id);
    assert!(
        !processes_mentioning(&dir.to_string_lossy()).is_empty(),
        "the VMM process runs on this host"
    );

    // Exec: status, streams, environment, identity, working directory.
    let r = sh(
        &be,
        &id,
        "echo out:$CHARTER_VAR:$(pwd); echo err >&2; exit 7",
    )
    .await;
    eprintln!("exec: {r:?}");
    assert_eq!(r.exit_code, 7);
    assert_eq!(r.stdout.trim(), "out:charter:/workspace");
    assert_eq!(r.stderr.trim(), "err");
    let r = sh(
        &be,
        &id,
        "uname -r; cat /proc/1/comm; id -u; mount | grep -E ' (/|/workspace) '",
    )
    .await;
    eprintln!("guest: {}", r.stdout);
    let (w, mut rd) = tokio::io::duplex(8192);
    be.attach_pty(
        &id,
        PtyStream {
            stdout: Some(Box::new(w)),
            tty: true,
            command: ["/bin/sh", "-c", "test -t 1 && echo tty-ok"]
                .map(String::from)
                .to_vec(),
            ..PtyStream::default()
        },
    )
    .await
    .expect("tty");
    let mut tty = String::new();
    tokio::io::AsyncReadExt::read_to_string(&mut rd, &mut tty)
        .await
        .expect("tty output");
    assert!(tty.contains("tty-ok"), "{tty:?}");

    // Files: the projected file, and the workspace tar.
    let r = sh(
        &be,
        &id,
        "cat /workspace/projected.txt; echo; stat -c %a /workspace/projected.txt",
    )
    .await;
    assert_eq!(
        r.stdout.split_whitespace().collect::<Vec<_>>(),
        ["projected", "640"]
    );
    let mut tar = Vec::new();
    be.export_workspace(&id, &mut tar).await.expect("export");
    let names: Vec<String> = tar::Archive::new(tar.as_slice())
        .entries()
        .expect("entries")
        .map(|e| {
            e.expect("entry")
                .path()
                .expect("path")
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    assert!(
        names.iter().any(|n| n.ends_with("projected.txt")),
        "{names:?}"
    );

    // Egress: no interface but loopback, no route around the proxy.
    let r = sh(
        &be,
        &id,
        "cat /proc/net/dev | tail -n +3 | cut -d: -f1 | tr -d ' '",
    )
    .await;
    eprintln!("interfaces: {:?}", r.stdout);
    // libkrunfw's kernel also has `dummy0`, a virtual device with nothing
    // behind it; there is no device that reaches the host or a network.
    let real: Vec<&str> = r
        .stdout
        .split_whitespace()
        .filter(|i| !i.starts_with("dummy"))
        .collect();
    assert_eq!(real, ["lo"], "{:?}", r.stdout);
    let r = sh(
        &be,
        &id,
        "curl -sS --noproxy '*' --max-time 5 -o /dev/null https://1.1.1.1 2>&1; echo rc=$?",
    )
    .await;
    eprintln!("direct: {}", r.stdout.trim());
    assert!(!r.stdout.contains("rc=0"), "{r:?}");
    let r = sh(
        &be,
        &id,
        &format!("curl -sS --max-time 20 -o /dev/null -w '%{{http_code}}' https://{allowed}/; echo ' rc='$?"),
    )
    .await;
    eprintln!("allowed: {}", r.stdout.trim());
    assert!(r.stdout.contains("rc=0"), "{r:?}");
    let r = sh(
        &be,
        &id,
        "curl -sS --max-time 20 -o /dev/null https://denied.example.org/ 2>&1; echo rc=$?",
    )
    .await;
    eprintln!("denied: {}", r.stdout.trim());
    assert!(
        r.stdout.contains("403") || !r.stdout.contains("rc=0"),
        "{r:?}"
    );
    let decisions = runeward_egress::list_decisions(&id);
    eprintln!("decisions: {decisions:?}");
    assert!(
        decisions
            .iter()
            .any(|d| d.allow && d.host.contains(&allowed))
    );
    assert!(
        decisions
            .iter()
            .any(|d| !d.allow && d.host.contains("denied.example.org"))
    );

    // Sleep and wake: the workspace disk survives, memory does not.
    sh(
        &be,
        &id,
        "echo kept > /workspace/kept.txt; echo lost > /tmp/lost.txt",
    )
    .await;
    be.stop(&id).await.expect("stop");
    assert!(
        processes_mentioning(&dir.to_string_lossy()).is_empty(),
        "stopped VMM is gone"
    );
    let listed = be.list().await.expect("list");
    assert!(
        listed.iter().any(|s| s.id == id && s.status == "stopped"),
        "{listed:?}"
    );
    let woke = be.start(&id, spec.clone()).await.expect("start");
    assert_eq!(woke.isolation, IsolationTier::Vm);
    let r = sh(
        &be,
        &id,
        "cat /workspace/kept.txt; cat /tmp/lost.txt 2>/dev/null || echo gone",
    )
    .await;
    assert_eq!(
        r.stdout.split_whitespace().collect::<Vec<_>>(),
        ["kept", "gone"]
    );

    // Destroy: nothing left.
    be.kill(&id).await.expect("kill");
    assert!(!be.exists(&id).await);
    assert!(!dir.exists(), "{} removed", dir.display());
    assert!(processes_mentioning(&dir.to_string_lossy()).is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn microvm_supervised_read_only() {
    let vmm = env("RUNEWARD_TEST_MICROVM");
    if vmm.is_empty() || env("RUNEWARD_TEST_MICROVM_SUPERVISED") != "1" {
        eprintln!("skipping: set RUNEWARD_TEST_MICROVM and RUNEWARD_TEST_MICROVM_SUPERVISED=1");
        return;
    }
    let image = match env("RUNEWARD_TEST_MICROVM_SUPERVISED_IMAGE") {
        s if s.is_empty() => "ghcr.io/runeeward/runeward-sandbox:latest".to_owned(),
        s => s,
    };
    let be = MicroVm::new(BackendConfig::from_env())
        .await
        .expect("open the microvm backend");
    let id = hex::encode(rand::random::<[u8; 16]>());
    let _cleanup = Cleanup {
        be: &be,
        id: id.clone(),
    };
    let mut config =
        runeward_supervisor::SupervisorConfig::default().with_argv(["sleep", "infinity"]);
    config.workdir = "/workspace".into();
    let spec = Spec {
        id: id.clone(),
        profile: "microvm-supervised".into(),
        image,
        runtime_class: vmm.clone(),
        read_only: true,
        persist_workspace: true,
        supervisor: Some(SupervisorSpec {
            config,
            required: true,
        }),
        ..Spec::default()
    };
    let started = std::time::Instant::now();
    let sb = be.create(spec).await.expect("create");
    eprintln!("created {} in {:?}", sb.id, started.elapsed());
    assert_eq!(
        sb.isolation,
        IsolationTier::Vm,
        "{:?}",
        sb.isolation_evidence
    );

    // Governed execs run under the supervisor as the agent identity.
    let r = sh(
        &be,
        &id,
        "id -un; cat /proc/1/comm; ps -o pid,user,args 2>/dev/null | head -5",
    )
    .await;
    eprintln!("supervised exec: {r:?}");
    assert_eq!(r.exit_code, 0, "{r:?}");
    assert_eq!(r.stdout.lines().next(), Some("sandbox"), "{r:?}");
    let report = be.supervisor_report(&id).await.expect("report");
    eprintln!("supervisor report: {report:?}");
    assert!(
        report
            .as_deref()
            .is_some_and(|r| r.contains("runeward.supervisor.report")),
        "{report:?}"
    );

    // Read-only root: the image cannot be changed, /tmp and the workspace
    // can.
    let r = sh(
        &be,
        &id,
        "touch /etc/rw-probe 2>&1; echo etc=$?; touch /tmp/x && echo tmp=ok; touch /workspace/x && echo ws=ok",
    )
    .await;
    eprintln!("read-only: {r:?}");
    assert!(
        r.stdout.contains("tmp=ok") && r.stdout.contains("ws=ok"),
        "{r:?}"
    );
    assert!(!r.stdout.contains("etc=0"), "{r:?}");

    // vsock: the host answers only on the egress port the monitor maps;
    // any other host port, the agent's own port included, is refused.
    let r = sh(
        &be,
        &id,
        "python3 - <<'PY'\nimport socket\nfor port in (22, 2375, 10789, 10790):\n    s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)\n    s.settimeout(3)\n    try:\n        s.connect((2, port))\n        print(port, 'open')\n    except OSError as e:\n        print(port, 'refused', e.errno)\n    s.close()\nPY",
    )
    .await;
    eprintln!("vsock: {r:?}");
    for port in ["22 ", "2375 ", "10789 "] {
        assert!(
            r.stdout
                .lines()
                .any(|l| l.starts_with(port) && l.contains("refused")),
            "host vsock port {port} reachable: {r:?}"
        );
    }

    be.kill(&id).await.expect("kill");
    assert!(!be.exists(&id).await);
}
