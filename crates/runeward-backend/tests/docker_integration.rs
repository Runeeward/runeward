//! Opt-in end-to-end test against a real Docker engine.
//!
//! Runs only with `RUNEWARD_TEST_DOCKER=1` and needs the `alpine` image. It
//! creates sandboxes, execs, seeds, projects files, attaches a TTY, exports,
//! snapshots and restores, and removes everything it created (and nothing
//! else), even when an assertion fails.
#![cfg(unix)]

use std::collections::BTreeMap;
use std::sync::Mutex;

use runeward_backend::{
    Backend, BackendConfig, Docker, ExecRequest, IsolationTier, PtyStream, Spec, container_name,
    egress_container_name, volume_name,
};
use runeward_charter::{File, Network, NetworkRule};
use tokio::io::AsyncReadExt;

fn enabled() -> bool {
    std::env::var("RUNEWARD_TEST_DOCKER").is_ok_and(|v| v == "1")
}

/// Force-removes every container, egress sidecar and workspace volume
/// created by the test on drop. Ids are assigned before `create`, so a
/// create that fails half-way is cleaned up too.
#[derive(Default)]
struct Cleanup {
    ids: Mutex<Vec<String>>,
}

impl Cleanup {
    /// Gives `spec` a fresh id and tracks it.
    fn assign(&self, mut spec: Spec) -> Spec {
        spec.id = hex::encode(rand::random::<[u8; 16]>());
        self.ids
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(spec.id.clone());
        spec
    }
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        let ids = self
            .ids
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for id in ids.iter() {
            for name in [container_name(id), egress_container_name(id)] {
                let _ = std::process::Command::new("docker")
                    .args(["rm", "-f", "-v", &name])
                    .output();
            }
            let _ = std::process::Command::new("docker")
                .args(["volume", "rm", "-f", &volume_name(id)])
                .output();
        }
    }
}

fn docker_ok(args: &[&str]) -> bool {
    std::process::Command::new("docker")
        .args(args)
        .output()
        .is_ok_and(|o| o.status.success())
}

async fn exec_out(d: &Docker, id: &str, cmd: &[&str]) -> (i32, String) {
    let res = d
        .exec(id, ExecRequest::new(cmd.iter().copied()))
        .await
        .expect("exec");
    (res.exit_code, res.stdout)
}

#[tokio::test(flavor = "multi_thread")]
async fn alpine_lifecycle() {
    if !enabled() {
        eprintln!("skipping: set RUNEWARD_TEST_DOCKER=1 to run");
        return;
    }
    let cleanup = Cleanup::default();
    let cfg = BackendConfig::from_pairs([
        ("RUNEWARD_SANDBOX_MEMORY", "256m"),
        ("RUNEWARD_SANDBOX_CPUS", "1"),
        ("RUNEWARD_SANDBOX_PIDS", "128"),
    ]);
    let d = Docker::docker(cfg).await.expect("docker backend");
    assert!(d.isolation_tier() >= IsolationTier::Container);

    let seed = tempfile::tempdir().expect("seed");
    std::fs::write(seed.path().join("hello.txt"), "hello from host\n").expect("write");
    std::fs::create_dir(seed.path().join("sub")).expect("mkdir");
    std::fs::write(seed.path().join("sub/nested.txt"), "nested\n").expect("write");
    std::os::unix::fs::symlink("hello.txt", seed.path().join("link")).expect("symlink");

    let spec = Spec {
        profile: "it".into(),
        image: "alpine".into(),
        read_only: true,
        env: BTreeMap::from([("GREETING".into(), "hi there".into())]),
        seed_dir: Some(seed.path().to_path_buf()),
        ..Spec::default()
    };
    let spec = cleanup.assign(spec);
    let sb = d.create(spec.clone()).await.expect("create");
    assert_eq!(sb.status, "running");
    assert!(d.exists(&sb.id).await);

    // Hardening is in place.
    let (code, out) = exec_out(&d, &sb.id, &["sh", "-c", "grep CapEff /proc/self/status"]).await;
    assert_eq!(code, 0);
    assert!(out.contains("0000000000000000"), "caps not dropped: {out}");
    let (code, _) = exec_out(&d, &sb.id, &["touch", "/etc/x"]).await;
    assert_ne!(code, 0, "root filesystem must be read-only");
    let (code, _) = exec_out(&d, &sb.id, &["touch", "/tmp/x"]).await;
    assert_eq!(code, 0, "/tmp must be writable");

    // Env and seed.
    let (_, out) = exec_out(&d, &sb.id, &["sh", "-c", "echo $GREETING"]).await;
    assert_eq!(out, "hi there\n");
    let (_, out) = exec_out(&d, &sb.id, &["cat", "/workspace/link"]).await;
    assert_eq!(out, "hello from host\n");
    let (_, out) = exec_out(&d, &sb.id, &["cat", "/workspace/sub/nested.txt"]).await;
    assert_eq!(out, "nested\n");

    // Exit codes, workdir and env on exec.
    let req = ExecRequest {
        workdir: "/workspace/sub".into(),
        env: BTreeMap::from([("X".into(), "42".into())]),
        ..ExecRequest::new(["sh", "-c", "pwd; echo $X; exit 7"])
    };
    let res = d.exec(&sb.id, req).await.expect("exec");
    assert_eq!(res.exit_code, 7);
    assert_eq!(res.stdout, "/workspace/sub\n42\n");

    // TTY attach runs on a terminal.
    let (w, mut r) = tokio::io::duplex(4096);
    let s = PtyStream {
        stdout: Some(Box::new(w)),
        tty: true,
        command: vec![
            "sh".into(),
            "-c".into(),
            "test -t 0 && echo on-a-tty".into(),
        ],
        ..PtyStream::default()
    };
    d.attach_pty(&sb.id, s).await.expect("attach");
    let mut out = String::new();
    let _ = r.read_to_string(&mut out).await;
    assert!(out.contains("on-a-tty"), "{out:?}");

    // Export to the host.
    let dest = tempfile::tempdir().expect("dest");
    runeward_backend::export_to_dir(&d, &sb.id, dest.path())
        .await
        .expect("export");
    assert_eq!(
        std::fs::read_to_string(dest.path().join("hello.txt")).expect("exported"),
        "hello from host\n"
    );
    assert_eq!(
        std::fs::read_link(dest.path().join("link")).expect("link"),
        std::path::Path::new("hello.txt")
    );

    // Snapshot and restore into a fresh sandbox.
    exec_out(
        &d,
        &sb.id,
        &["sh", "-c", "echo changed > /workspace/state.txt"],
    )
    .await;
    let snap = d.snapshot(&sb.id, "it").await.expect("snapshot");
    let restored = d
        .restore_with_spec(
            &snap,
            cleanup.assign(Spec {
                seed_dir: None,
                files: Vec::new(),
                ..spec.clone()
            }),
        )
        .await;
    let _ = std::fs::remove_file(&snap.location);
    let restored = restored.expect("restore");
    let (_, out) = exec_out(&d, &restored.id, &["cat", "/workspace/state.txt"]).await;
    assert_eq!(out, "changed\n");

    // List sees both; kill removes container and volume.
    let ids: Vec<String> = d
        .list()
        .await
        .expect("list")
        .into_iter()
        .map(|s| s.id)
        .collect();
    assert!(ids.contains(&sb.id) && ids.contains(&restored.id));
    for id in [&sb.id, &restored.id] {
        d.kill(id).await.expect("kill");
        assert!(!docker_ok(&["inspect", &container_name(id)]));
        assert!(!docker_ok(&["volume", "inspect", &volume_name(id)]));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn alpine_cooperative_egress_denies_unlisted_hosts() {
    if !enabled() {
        eprintln!("skipping: set RUNEWARD_TEST_DOCKER=1 to run");
        return;
    }
    let cleanup = Cleanup::default();
    let d = Docker::docker(BackendConfig::default())
        .await
        .expect("docker backend");
    let spec = Spec {
        profile: "it-net".into(),
        image: "alpine".into(),
        network: Network {
            default: "deny".into(),
            rules: vec![NetworkRule {
                hostname: "example.com".into(),
                ..NetworkRule::default()
            }],
            enforce: String::new(),
        },
        ..Spec::default()
    };
    let sb = d.create(cleanup.assign(spec)).await.expect("create");
    let (_, out) = exec_out(&d, &sb.id, &["sh", "-c", "echo $HTTP_PROXY"]).await;
    assert!(out.starts_with("http://runeward:"), "{out}");
    let res = d
        .exec(
            &sb.id,
            ExecRequest::new(["wget", "-q", "-O-", "http://denied.example.org/"]),
        )
        .await
        .expect("exec");
    assert_ne!(res.exit_code, 0);
    assert!(res.stderr.contains("403"), "{}", res.stderr);
    let (_, v6) = exec_out(
        &d,
        &sb.id,
        &["cat", "/proc/sys/net/ipv6/conf/all/disable_ipv6"],
    )
    .await;
    assert_eq!(v6.trim(), "1");
    d.kill(&sb.id).await.expect("kill");
}

#[tokio::test(flavor = "multi_thread")]
async fn alpine_projects_files() {
    if !enabled() {
        eprintln!("skipping: set RUNEWARD_TEST_DOCKER=1 to run");
        return;
    }
    let cleanup = Cleanup::default();
    let d = Docker::docker(BackendConfig::default())
        .await
        .expect("docker backend");
    let file = |path: &str, mode: &str| File {
        path: path.into(),
        content: format!("projected {path}\n"),
        mode: mode.into(),
        ..File::default()
    };
    // A relative target resolves against the workdir; an absolute one is
    // used as is. Both land owned by the sandbox user at the requested mode
    // even though every capability is dropped.
    let spec = Spec {
        profile: "it-files".into(),
        image: "alpine".into(),
        files: vec![
            file("notes/info.txt", "0640"),
            file("/workspace/abs.txt", ""),
            file("/root/.config/tool.conf", "0600"),
        ],
        ..Spec::default()
    };
    let sb = d.create(cleanup.assign(spec)).await.expect("create");
    let (code, out) = exec_out(
        &d,
        &sb.id,
        &[
            "stat",
            "-c",
            "%n %u:%g %a",
            "/workspace/notes/info.txt",
            "/workspace/abs.txt",
            "/root/.config/tool.conf",
        ],
    )
    .await;
    assert_eq!(code, 0, "{out}");
    assert_eq!(
        out,
        "/workspace/notes/info.txt 0:0 640\n/workspace/abs.txt 0:0 444\n/root/.config/tool.conf 0:0 600\n"
    );
    let (_, out) = exec_out(&d, &sb.id, &["cat", "/workspace/notes/info.txt"]).await;
    assert_eq!(out, "projected notes/info.txt\n");
    // Nothing is left at the `/`-relative path Go's `docker cp` used.
    let (code, _) = exec_out(&d, &sb.id, &["test", "-e", "/notes/info.txt"]).await;
    assert_ne!(code, 0);

    // The projected files export with the rest of the workspace.
    let dest = tempfile::tempdir().expect("dest");
    runeward_backend::export_to_dir(&d, &sb.id, dest.path())
        .await
        .expect("export");
    assert_eq!(
        std::fs::read_to_string(dest.path().join("notes/info.txt")).expect("exported"),
        "projected notes/info.txt\n"
    );
    d.kill(&sb.id).await.expect("kill");

    // A non-root sandbox owns what it is given.
    let spec = Spec {
        profile: "it-files-user".into(),
        image: "alpine".into(),
        user: "1000:1000".into(),
        files: vec![file("/tmp/proj/secret.txt", "0600")],
        ..Spec::default()
    };
    let sb = d
        .create(cleanup.assign(spec))
        .await
        .expect("create non-root");
    let (code, out) = exec_out(
        &d,
        &sb.id,
        &["stat", "-c", "%u:%g %a", "/tmp/proj/secret.txt"],
    )
    .await;
    assert_eq!((code, out.as_str()), (0, "1000:1000 600\n"));
    let (_, out) = exec_out(&d, &sb.id, &["cat", "/tmp/proj/secret.txt"]).await;
    assert_eq!(out, "projected /tmp/proj/secret.txt\n");
    d.kill(&sb.id).await.expect("kill");
}
