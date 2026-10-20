//! Cohorts: provisioning, signed leases, persistence and the legacy-claim
//! migration.

use std::time::Duration;

use runeward_fleet::{Task, TaskState};
use runeward_ledger::gotime;

use super::support::{harness, harness_with, lock};
use crate::fleet::{FLEETS_FILE_NAME, PersistedFleet};
use crate::statefile::marshal_indent;
use crate::{Error, Manager};

const COHORT: &str = r#"
[host]
image = "ghcr.io/example/agent:1"

[cohort]
replicas = 2
task_board = ["a", "b"]
"#;

#[tokio::test]
async fn cohort_lifecycle_with_signed_leases() {
    let h = harness(None).await;
    h.write_charter("crew", COHORT);
    let f = h
        .mgr
        .create_fleet_for_identity("crew", "team", "lead")
        .await
        .expect("fleet");
    let members = f.sandboxes.clone().expect("members");
    assert_eq!(members.len(), 2);
    assert_eq!((f.stats.total, f.stats.pending), (2, 2));
    assert_eq!(h.mgr.fleet_owner(&f.id).as_deref(), Some("team"));
    let sess = h.mgr.session_handle(&members[0]).expect("member");
    assert_eq!((sess.owner(), sess.actor()), ("team", "lead"));

    let t = h
        .mgr
        .claim_task(&f.id, "w1")
        .await
        .expect("claim")
        .expect("task");
    assert_eq!(
        (t.payload.as_str(), t.state.clone()),
        ("a", TaskState::Claimed)
    );
    assert!(!t.lease_token.is_empty());
    let token = t.lease_token.clone();

    // A token is bound to the worker, task and lease version.
    let err = h
        .mgr
        .complete_task(&f.id, &t.id, "w2", &token, "x")
        .await
        .expect_err("other worker");
    assert!(matches!(err, Error::InvalidLease));
    assert_eq!(err.client_status(), Some(401));
    let hb = h
        .mgr
        .heartbeat_task(&f.id, &t.id, "w1", &token)
        .await
        .expect("heartbeat");
    assert!(hb.lease_version > t.lease_version);
    let err = h
        .mgr
        .complete_task(&f.id, &t.id, "w1", &token, "x")
        .await
        .expect_err("stale token after heartbeat");
    assert!(matches!(err, Error::InvalidLease));
    h.mgr
        .complete_task(&f.id, &t.id, "w1", &hb.lease_token, "done")
        .await
        .expect("complete");

    let t2 = h
        .mgr
        .claim_task(&f.id, "w1")
        .await
        .expect("claim")
        .expect("task");
    h.mgr
        .fail_task(&f.id, &t2.id, "w1", &t2.lease_token, "flaky", true)
        .await
        .expect("fail+requeue");
    let added = h.mgr.add_task(&f.id, "c").await.expect("add");
    let tasks = h.mgr.list_tasks(&f.id).expect("tasks");
    assert_eq!(tasks.len(), 3);
    assert_eq!(tasks[0].state, TaskState::Done);
    assert_eq!(tasks[1].state, TaskState::Pending);
    assert_eq!(tasks[2].id, added.id);
    assert!(
        tasks.iter().all(|t| t.lease_token.is_empty()),
        "tokens never stored"
    );

    let err = h
        .mgr
        .heartbeat_task(&f.id, "missing", "w1", "x.y")
        .await
        .expect_err("unknown");
    assert_eq!(err.client_status(), Some(404));
    assert_eq!(
        h.mgr
            .claim_task("nope", "w")
            .await
            .expect_err("fleet")
            .client_status(),
        Some(404)
    );

    // The board survives a restart (sandboxes do not).
    h.mgr.close().await.expect("close");
    let restarted = Manager::builder(super::support::config(h.dir.path(), None))
        .build()
        .await
        .expect("restart");
    let view = restarted.fleet_view(&f.id).expect("restored");
    assert_eq!(view.stats.total, 3);
    assert!(restarted.fleet(&f.id).expect("fleet").restored());
    let raw = std::fs::read(h.state_dir().join("cohort-lease.key")).expect("key");
    assert_eq!(raw.len(), 32);
}

#[tokio::test]
async fn kill_fleet_tears_down_members() {
    let h = harness(None).await;
    h.write_charter("crew", COHORT);
    let f = h.mgr.create_fleet("crew").await.expect("fleet");
    assert_eq!(h.mgr.list_fleets().len(), 1);
    h.mgr.kill_fleet(&f.id).await.expect("kill");
    assert!(h.mgr.list_fleets().is_empty());
    assert!(h.mgr.list_sandboxes().is_empty());
    assert_eq!(lock(&h.fake.killed).len(), 2);
    assert!(h.mgr.kill_fleet(&f.id).await.is_err());
}

#[tokio::test]
async fn load_requeues_only_legacy_unsigned_claims() {
    let h = harness(None).await;
    let now = gotime::now();
    let task = |id: &str, state: TaskState, owner: &str, version: i64| Task {
        id: id.into(),
        state,
        owner: owner.into(),
        lease_version: version,
        lease_expiry: (version > 0).then(|| now + chrono::TimeDelta::minutes(1)),
        updated_at: now,
        result: if id == "done" {
            "ok".into()
        } else {
            String::new()
        },
        ..Task::default()
    };
    let state = vec![PersistedFleet {
        id: "cohort-1".into(),
        profile: "agent".into(),
        owner: "tenant-a".into(),
        sandboxes: None,
        created: now,
        tasks: Some(vec![
            task("legacy", TaskState::Claimed, "old-worker", 0),
            task("signed", TaskState::Claimed, "live-worker", 2),
            task("done", TaskState::Done, "", 0),
        ]),
    }];
    h.mgr
        .write_state(FLEETS_FILE_NAME, marshal_indent(&state).expect("json"))
        .await
        .expect("write");
    h.mgr.load_fleets().await.expect("load");
    let tasks = h.mgr.list_tasks("cohort-1").expect("tasks");
    assert_eq!(tasks[0].state, TaskState::Pending);
    assert!(tasks[0].owner.is_empty() && tasks[0].error.contains("legacy unsigned lease"));
    assert_eq!(
        (
            tasks[1].state.clone(),
            tasks[1].owner.as_str(),
            tasks[1].lease_version
        ),
        (TaskState::Claimed, "live-worker", 2)
    );
    assert_eq!(
        (tasks[2].state.clone(), tasks[2].result.as_str()),
        (TaskState::Done, "ok")
    );
    // The migration is durable.
    let raw = std::fs::read_to_string(h.state_dir().join(FLEETS_FILE_NAME)).expect("file");
    assert!(raw.contains("legacy unsigned lease requeued during v1 upgrade"));
    assert!(raw.contains("\"sandboxes\": null"), "null preserved: {raw}");
}

#[tokio::test]
async fn sweeper_requeues_expired_claims() {
    let h = harness_with(None, |c| c.fleet_lease = Duration::from_millis(1)).await;
    h.write_charter("crew", COHORT);
    let f = h.mgr.create_fleet("crew").await.expect("fleet");
    let t = h
        .mgr
        .claim_task(&f.id, "w1")
        .await
        .expect("claim")
        .expect("task");
    // The lease is wall-clock based.
    tokio::time::sleep(Duration::from_millis(5)).await;
    h.mgr.sweep_once().await;
    let got = h.mgr.list_tasks(&f.id).expect("tasks");
    let swept = got.iter().find(|x| x.id == t.id).expect("task");
    assert_eq!(swept.state, TaskState::Pending);
    let ev = h.records().await.pop().expect("requeue event");
    assert_eq!(
        (ev.tool.as_str(), ev.action.as_str()),
        ("fleet", "task.requeue")
    );
    assert_eq!(ev.session_id, format!("fleet:{}", f.id));
}
