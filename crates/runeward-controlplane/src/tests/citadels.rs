//! Create, isolation floor, kill, runs and snapshots through the fake
//! driver.

use runeward_backend::IsolationTier;
use runeward_charter::Charter;
use runeward_ledger::gotime;

use super::support::{harness, lock};
use crate::runs::{RUNS_FILE_NAME, Run};
use crate::{CreateOptions, Error, Manager, SessionState};

const BASIC: &str = r#"
[host]
type = "container"
image = "ghcr.io/example/agent:1"
"#;

#[tokio::test]
async fn create_registers_run_and_chronicles_isolation() {
    let h = harness(None).await;
    h.write_charter("dev", BASIC);
    let sb = h
        .mgr
        .create_sandbox(
            "dev",
            CreateOptions {
                owner: "team".into(),
                actor: "codex".into(),
                agent: " codex ".into(),
                ..CreateOptions::default()
            },
        )
        .await
        .expect("create");
    assert_eq!(sb.isolation, IsolationTier::Container);
    let sess = h.mgr.session_handle(&sb.id).expect("session");
    assert_eq!(sess.state(), SessionState::Running);
    let run = h.mgr.run(sess.run_id()).expect("run");
    assert_eq!(
        (
            run.status.as_str(),
            run.charter.as_str(),
            run.isolation.as_str()
        ),
        ("running", "dev", "container")
    );
    assert_eq!(
        (run.tenant.as_str(), run.actor.as_str(), run.agent.as_str()),
        ("team", "codex", "codex")
    );
    let infos = h.mgr.list_sandbox_infos();
    assert_eq!(infos.len(), 1);
    assert_eq!(
        (infos[0].owner.as_str(), infos[0].isolation),
        ("team", IsolationTier::Container)
    );
    let v = serde_json::to_value(&infos[0]).expect("json");
    assert_eq!(v["Isolation"], "container");
    assert_eq!(v["Sandbox"]["ID"], sb.id);
    let created = h.records().await.pop().expect("event");
    assert_eq!(
        (created.tool.as_str(), created.action.as_str()),
        ("sandbox", "create")
    );
    assert_eq!(created.meta["isolation"], "container");
    assert_eq!(created.meta["isolation_runtime"], "fake");
    assert_eq!(created.meta["isolation_signals"], "verdict:container");
    // Capability discovery ran once (a custom image declares none).
    assert_eq!(h.fake.execs(), 1);

    h.mgr.kill_sandbox(&sb.id).await.expect("kill");
    let run = h.mgr.run(sess.run_id()).expect("run");
    assert_eq!(run.status, "completed");
    assert!(run.finished_at.is_some());
    assert_eq!(sess.state(), SessionState::Terminated);
    assert_eq!(*lock(&h.fake.killed), std::slice::from_ref(&sb.id));
    assert!(h.mgr.sandbox(&sb.id).is_none());
}

#[tokio::test]
async fn isolation_floor_refuses_weaker_sandbox_before_anything_runs() {
    let h = harness(None).await;
    h.write_charter(
        "strict",
        &format!("{BASIC}\n[isolation]\nminimum = \"kernel\"\n"),
    );
    let err = h
        .mgr
        .create_sandbox("strict", CreateOptions::default())
        .await
        .expect_err("container < kernel");
    assert!(matches!(err, Error::IsolationFloor { .. }), "{err:?}");
    assert!(
        err.to_string().contains("requires isolation \"kernel\""),
        "{err}"
    );
    assert_eq!(h.fake.execs(), 0, "nothing executed in the refused sandbox");
    assert_eq!(
        *lock(&h.fake.killed),
        ["fake-1"],
        "refused sandbox torn down"
    );
    assert!(h.mgr.list_sandboxes().is_empty());
    assert!(h.mgr.list_runs().is_empty(), "no run for a refused create");
    let refused = h.records().await.pop().expect("refusal chronicled");
    assert_eq!(
        (refused.tool.as_str(), refused.verdict.as_str()),
        ("sandbox", "deny")
    );
    assert_eq!(refused.meta["isolation"], "container");
    assert_eq!(refused.meta["isolation_minimum"], "kernel");
    assert_eq!(refused.meta["isolation_signals"], "verdict:container");

    // A backend that delivers the floor is accepted, and the tier sticks.
    *lock(&h.fake.tier) = IsolationTier::Kernel;
    let sb = h
        .mgr
        .create_sandbox("strict", CreateOptions::default())
        .await
        .expect("kernel meets kernel");
    assert_eq!(sb.isolation, IsolationTier::Kernel);
    let sess = h.mgr.session_handle(&sb.id).expect("session");
    assert_eq!(h.mgr.run(sess.run_id()).expect("run").isolation, "kernel");
}

#[tokio::test]
async fn create_fails_on_invalid_scrub_pattern() {
    let h = harness(None).await;
    h.write_charter(
        "invalid",
        &format!("{BASIC}\n[chronicle]\nscrub_patterns = [\"(\"]\n"),
    );
    let err = h
        .mgr
        .create_sandbox("invalid", CreateOptions::default())
        .await
        .expect_err("bad pattern");
    assert!(
        err.to_string().contains("chronicle.scrub_patterns"),
        "{err}"
    );
    assert_eq!(h.fake.creates.load(std::sync::atomic::Ordering::SeqCst), 0);
}

#[tokio::test]
async fn declared_capability_missing_kills_sandbox() {
    let h = harness(None).await;
    h.write_charter("py", &format!("capabilities = [\"python\"]\n{BASIC}"));
    h.fake.set_result(runeward_backend::ExecResult {
        exit_code: 127,
        ..Default::default()
    });
    let err = h
        .mgr
        .create_sandbox("py", CreateOptions::default())
        .await
        .expect_err("missing runtime");
    assert!(err.to_string().contains("does not provide"), "{err}");
    assert_eq!(lock(&h.fake.killed).len(), 1);
}

#[tokio::test]
async fn delegated_child_inherits_lineage_and_charter() {
    let h = harness(None).await;
    h.write_charter("dev", BASIC);
    h.write_charter("other", BASIC);
    let opts = |parent: &str| CreateOptions {
        owner: "team".into(),
        parent_sandbox: parent.into(),
        ..CreateOptions::default()
    };
    let parent = h.mgr.create_sandbox("dev", opts("")).await.expect("parent");
    let parent_run = h
        .mgr
        .session_handle(&parent.id)
        .expect("p")
        .run_id()
        .to_owned();
    let child = h
        .mgr
        .create_sandbox("dev", opts(&parent.id))
        .await
        .expect("child");
    let child_run = h
        .mgr
        .session_handle(&child.id)
        .expect("c")
        .run_id()
        .to_owned();
    assert_eq!(
        h.mgr.run(&child_run).expect("run").parent_run_id,
        parent_run
    );
    let ev = h.records().await.pop().expect("event");
    assert_eq!(ev.meta["parent_run_id"], parent_run);

    let err = h
        .mgr
        .create_sandbox("other", opts(&parent.id))
        .await
        .expect_err("charter");
    assert!(
        err.to_string()
            .contains("delegated child must use parent charter"),
        "{err}"
    );
    let err = h
        .mgr
        .create_sandbox(
            "dev",
            CreateOptions {
                owner: "intruder".into(),
                parent_sandbox: parent.id.clone(),
                ..CreateOptions::default()
            },
        )
        .await
        .expect_err("tenant");
    assert_eq!(err.client_status(), Some(404));
}

#[tokio::test]
async fn runs_persist_and_running_becomes_interrupted_on_restart() {
    let h = harness(None).await;
    lock(&h.mgr.runs).insert(
        "run-1".into(),
        Run {
            id: "run-1".into(),
            parent_run_id: String::new(),
            citadel_id: "citadel-1".into(),
            tenant: "team".into(),
            actor: "codex".into(),
            charter: "dev".into(),
            agent: String::new(),
            provider: String::new(),
            model: String::new(),
            status: "running".into(),
            created_at: gotime::now(),
            finished_at: None,
            error: String::new(),
            isolation: String::new(),
        },
    );
    h.mgr.save_runs().await.expect("save");
    h.mgr.close().await.expect("close");
    let restarted = Manager::builder(super::support::config(h.dir.path(), None))
        .build()
        .await
        .expect("restart");
    let run = restarted.run("run-1").expect("run");
    assert_eq!(run.status, "interrupted");
    assert!(run.finished_at.is_some() && !run.error.is_empty());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(h.state_dir().join(RUNS_FILE_NAME))
            .expect("stat")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}

#[tokio::test]
async fn snapshot_persists_profile_and_tenant_owner_and_restores() {
    let h = harness(None).await;
    h.write_charter("test", BASIC);
    h.inject_with(Charter::default(), vec![], |b| b.owner("tenant-alpha"));
    let snap = h
        .mgr
        .snapshot("fake-1", "before-upgrade")
        .await
        .expect("snapshot");
    assert_eq!(snap.profile, "test");
    let raw = std::fs::read_to_string(h.state_dir().join("snapshots.json")).expect("file");
    assert!(
        raw.contains("\"created\": \"2023-11-14T22:13:20Z\""),
        "{raw}"
    );
    h.mgr.close().await.expect("close");

    let reloaded = Manager::builder(super::support::config(h.dir.path(), None))
        .registry(h.mgr.registry.clone())
        .build()
        .await
        .expect("restart");
    let got = reloaded.snapshot_ref(&snap.id).expect("snapshot");
    assert_eq!(
        (got.profile.as_str(), got.name.as_str()),
        ("test", "before-upgrade")
    );
    assert_eq!(
        reloaded.snapshot_owner(&snap.id).as_deref(),
        Some("tenant-alpha")
    );
    assert_eq!(reloaded.list_snapshots().len(), 1);

    let sb = reloaded
        .restore_snapshot_for_identity(&snap.id, "tenant-alpha", "codex")
        .await
        .expect("restore");
    let sess = reloaded.session_handle(&sb.id).expect("restored session");
    assert_eq!((sess.owner(), sess.actor()), ("tenant-alpha", "codex"));
    assert_eq!(reloaded.run(sess.run_id()).expect("run").status, "running");
    let mut tar = Vec::new();
    reloaded
        .export_workspace(&sb.id, &mut tar)
        .await
        .expect("export");
    assert_eq!(tar, b"tar");
}

#[tokio::test]
async fn readiness_reports_policy_runtime_secrets_and_image() {
    let h = harness(None).await;
    h.write_charter("dev", BASIC);
    let r = h.mgr.check_readiness("dev").await;
    assert!(r.ready, "{r:?}");
    let names: Vec<_> = r.checks.iter().map(|c| c.name.as_str()).collect();
    assert_eq!(names, ["policy", "runtime", "secrets", "image"]);
    assert_eq!(r.checks[1].message, "fake reachable");

    h.write_charter(
        "local",
        "[host]\nimage = \"debian:dev\"\n[[env]]\nname = \"T\"\nop = \"env://RUNEWARD_TEST_UNSET_9C1E\"\n",
    );
    let r = h.mgr.check_readiness("local").await;
    assert!(!r.ready);
    let secrets = r
        .checks
        .iter()
        .find(|c| c.name == "secrets")
        .expect("secrets");
    assert_eq!(secrets.status, "fail");
    assert!(
        !secrets.message.contains("RUNEWARD_TEST_UNSET"),
        "no detail leaks"
    );
    assert_eq!(r.checks.last().expect("image").status, "warn");

    let r = h.mgr.check_readiness("missing").await;
    assert!(!r.ready && r.checks[0].status == "fail");

    let profiles = h.mgr.list_profiles().await.expect("profiles");
    let names: Vec<_> = profiles.iter().map(|p| p.name.as_str()).collect();
    assert_eq!(names, ["dev", "local"]);
    assert_eq!(profiles[0].host, "container");
}
