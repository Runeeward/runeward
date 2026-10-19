//! Opt-in end-to-end test of persistent workspaces and forks on a real
//! Docker engine.
//!
//! Runs only with `RUNEWARD_TEST_DOCKER=1`. With a Charter that sets
//! `[workspace] persist = true` it proves that:
//!
//! - a file written in the workspace survives sleep (the container is
//!   stopped, not removed) and a transparent wake;
//! - after a control-plane restart the sleeping workspace is rediscovered
//!   and rebuilt around its kept volume on first use, file intact;
//! - a fork starts with a copy of the workspace and is independent of the
//!   source afterwards.
//!
//! Everything the test creates (containers with their anonymous volumes
//! and the workspace volumes) is removed on the way out; nothing else is
//! touched.
#![cfg(unix)]

use std::process::Command;
use std::sync::{Arc, Mutex};

use runeward_backend::{BackendConfig, container_name, volume_name};
use runeward_charter::SignedCharters;
use runeward_controlplane::{CreateOptions, ForkOptions, Manager, ManagerConfig};

fn enabled() -> bool {
    std::env::var("RUNEWARD_TEST_DOCKER").is_ok_and(|v| v == "1")
}

fn docker(args: &[&str]) -> String {
    let out = Command::new("docker")
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("docker {args:?}: {e}"));
    String::from_utf8_lossy(&out.stdout).trim().to_owned()
}

/// Removes every sandbox the test created on drop.
#[derive(Default)]
struct Cleanup(Mutex<Vec<String>>);

impl Cleanup {
    fn track(&self, id: &str) {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(id.to_owned());
    }
}

impl Drop for Cleanup {
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

async fn manager(dir: &std::path::Path) -> Arc<Manager> {
    let cfg = ManagerConfig {
        config_dir: Some(dir.join("charters")),
        state_dir: Some(dir.join("state")),
        sweep_interval: None,
        context_tick: None,
        signed_charters: SignedCharters::Disabled,
        policy_default: None,
        approval_wait: None,
        ..ManagerConfig::default()
    };
    Manager::builder(cfg)
        .backend_config(BackendConfig::default())
        .build()
        .await
        .expect("manager")
}

fn running(id: &str) -> String {
    docker(&["inspect", "-f", "{{.State.Running}}", &container_name(id)])
}

async fn read(m: &Manager, id: &str, path: &str) -> String {
    let r = m.file_read(id, path).await.expect("read");
    assert_eq!(r.exit_code, 0, "read {path}: {}", r.stderr);
    r.stdout
}

#[tokio::test]
async fn sleep_wake_restart_and_fork_keep_the_workspace() {
    if !enabled() {
        eprintln!("skipping: set RUNEWARD_TEST_DOCKER=1 to run against Docker");
        return;
    }
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(dir.path().join("charters")).expect("mkdir");
    std::fs::write(
        dir.path().join("charters/ws.toml"),
        "[host]\ntype = \"container\"\nimage = \"debian:stable-slim\"\n\n[workspace]\npersist = true\nidle_timeout = \"15m\"\n",
    )
    .expect("charter");
    let cleanup = Cleanup::default();

    let m = manager(dir.path()).await;
    let id = m
        .create_sandbox("ws", CreateOptions::default())
        .await
        .expect("create")
        .id;
    cleanup.track(&id);
    let w = m
        .file_write(&id, "notes/keep.txt", "persisted")
        .await
        .expect("write");
    assert_eq!(w.exit_code, 0, "{}", w.stderr);

    // Sleep stops the container but keeps it; a call wakes it.
    assert!(m.sleep_citadel(&id).await.expect("sleep"));
    assert_eq!(running(&id), "false");
    assert_eq!(read(&m, &id, "notes/keep.txt").await, "persisted");
    assert_eq!(running(&id), "true");

    // Restart: rediscovered asleep, rebuilt around the volume on use.
    m.sleep_citadel(&id).await.expect("sleep again");
    m.close().await.expect("close");
    drop(m);
    let m = manager(dir.path()).await;
    let listed = m.sandbox(&id).expect("rediscovered");
    assert_eq!(listed.status, "sleeping");
    assert_eq!(read(&m, &id, "notes/keep.txt").await, "persisted");
    assert_eq!(running(&id), "true");

    // Fork: a copy that diverges independently.
    let fork = m
        .fork_citadel(&id, ForkOptions::default())
        .await
        .expect("fork")
        .id;
    cleanup.track(&fork);
    assert_ne!(fork, id);
    assert_eq!(read(&m, &fork, "notes/keep.txt").await, "persisted");
    let w = m
        .file_write(&fork, "notes/keep.txt", "fork only")
        .await
        .expect("write fork");
    assert_eq!(w.exit_code, 0, "{}", w.stderr);
    assert_eq!(read(&m, &fork, "notes/keep.txt").await, "fork only");
    assert_eq!(read(&m, &id, "notes/keep.txt").await, "persisted");

    m.kill_sandbox(&fork).await.expect("kill fork");
    m.kill_sandbox(&id).await.expect("kill");
    for gone in [&id, &fork] {
        assert!(
            docker(&[
                "volume",
                "ls",
                "-q",
                "--filter",
                &format!("name={}", volume_name(gone))
            ])
            .is_empty(),
            "volume of {gone} removed"
        );
    }
    m.close().await.expect("close");
}
