//! Persistent workspaces (sleep, wake, idle, restart recovery), forks and
//! resumable agent turns, through the fake driver.

use std::time::Duration;

use runeward_ledger::Event;

use super::support::{Harness, harness, lock};
use crate::workspaces::WORKSPACES_FILE_NAME;
use crate::{
    AgentStatus, AgentTurnOptions, CreateOptions, Error, ForkOptions, Manager, SessionState,
    StartAgentSessionOptions,
};

const PERSISTENT: &str = r#"
[host]
type = "container"
image = "ghcr.io/example/agent:1"

[workspace]
persist = true
idle_timeout = "15m"
"#;

const PLAIN: &str = r#"
[host]
type = "container"
image = "ghcr.io/example/agent:1"
"#;

async fn create(h: &Harness, charter: &str) -> String {
    h.mgr
        .create_sandbox(
            charter,
            CreateOptions {
                owner: "team".into(),
                actor: "lead".into(),
                ..CreateOptions::default()
            },
        )
        .await
        .expect("create")
        .id
}

fn workspace_events(records: &[Event], id: &str) -> Vec<(String, String, String)> {
    records
        .iter()
        .filter(|e| e.tool == "workspace" && e.sandbox == id)
        .map(|e| {
            (
                e.action.clone(),
                e.verdict.clone(),
                e.meta.get("reason").cloned().unwrap_or_default(),
            )
        })
        .collect()
}

fn argv(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|s| (*s).to_owned()).collect()
}

#[tokio::test]
async fn sleeps_and_wakes_transparently_with_the_same_identity() {
    let h = harness(None).await;
    h.write_charter("ws", PERSISTENT);
    let id = create(&h, "ws").await;
    let sess = h.mgr.session_handle(&id).expect("session");
    let run_id = sess.run_id().to_owned();
    let status = h.mgr.workspace_status(&id).expect("tracked");
    assert_eq!(
        (status.state.as_str(), status.idle_timeout_secs),
        ("running", 900)
    );

    assert!(h.mgr.sleep_citadel(&id).await.expect("sleep"));
    assert!(
        !h.mgr.sleep_citadel(&id).await.expect("again"),
        "already asleep"
    );
    assert_eq!(sess.state(), SessionState::Sleeping);
    assert_eq!(*lock(&h.fake.stopped), std::slice::from_ref(&id));
    assert_eq!(h.mgr.sandbox(&id).expect("listed").status, "sleeping");
    let infos = h.mgr.list_sandbox_infos();
    assert_eq!(infos[0].sandbox.status, "sleeping");
    let state = std::fs::read_to_string(h.state_dir().join(WORKSPACES_FILE_NAME)).expect("file");
    assert!(state.contains("\"state\": \"sleeping\""), "{state}");

    // A governed call wakes it transparently.
    let res = h
        .mgr
        .shell(&id, &argv(&["echo", "hi"]), "")
        .await
        .expect("shell");
    assert_eq!(res.stdout, "echo hi");
    assert_eq!(sess.state(), SessionState::Running);
    assert_eq!(*lock(&h.fake.started), std::slice::from_ref(&id));
    assert_eq!(sess.run_id(), run_id, "same run");
    let spec = lock(&h.fake.last_spec).clone().expect("spec");
    assert_eq!(spec.id, id, "woken under the same id");
    assert_eq!(h.mgr.run(&run_id).expect("run").status, "running");

    let events = workspace_events(&h.records().await, &id);
    assert_eq!(
        events,
        [
            ("sleep".into(), "allow".into(), "manual".into()),
            ("wake".into(), "allow".into(), "activity".into()),
        ]
    );

    // Killing forgets the workspace.
    h.mgr.kill_sandbox(&id).await.expect("kill");
    assert!(h.mgr.workspace_status(&id).is_none());
}

#[tokio::test]
async fn non_persistent_citadels_do_not_sleep() {
    let h = harness(None).await;
    h.write_charter("plain", PLAIN);
    let id = create(&h, "plain").await;
    let err = h.mgr.sleep_citadel(&id).await.expect_err("not persistent");
    assert!(matches!(err, Error::BadInput(_)), "{err}");
    assert!(h.mgr.workspace_status(&id).is_none());
    let sess = h.mgr.session_handle(&id).expect("session");
    sess.activity.backdate(Duration::from_secs(3600));
    assert!(h.mgr.sleep_idle_once().await.is_empty());
}

#[tokio::test]
async fn idle_sleep_waits_for_calls_terminals_and_agent_turns() {
    let h = harness(None).await;
    h.write_charter("ws", PERSISTENT);
    let id = create(&h, "ws").await;
    let sess = h.mgr.session_handle(&id).expect("session");

    // Not idle long enough.
    assert!(h.mgr.sleep_idle_once().await.is_empty());

    // An in-flight call keeps it awake.
    sess.activity.backdate(Duration::from_secs(16 * 60));
    let busy = h.mgr.awake_session(&id).await.expect("busy");
    sess.activity.backdate(Duration::from_secs(16 * 60));
    assert!(h.mgr.sleep_idle_once().await.is_empty());
    let err = h.mgr.sleep_citadel(&id).await.expect_err("busy");
    assert_eq!(err.code(), Some("citadel_busy"));
    drop(busy);

    // So does a running agent turn.
    *lock(&h.fake.delay) = Some(Duration::from_millis(1500));
    let a = h
        .mgr
        .start_agent_session(
            &id,
            StartAgentSessionOptions {
                command: argv(&["agent"]),
                ..StartAgentSessionOptions::default()
            },
        )
        .await
        .expect("agent");
    sess.activity.backdate(Duration::from_secs(16 * 60));
    assert!(h.mgr.sleep_idle_once().await.is_empty());
    wait_terminal(&h.mgr, &a.id).await;
    *lock(&h.fake.delay) = None;

    sess.activity.backdate(Duration::from_secs(16 * 60));
    assert_eq!(h.mgr.sleep_idle_once().await, std::slice::from_ref(&id));
    assert_eq!(sess.state(), SessionState::Sleeping);
    let events = workspace_events(&h.records().await, &id);
    assert_eq!(events.last().map(|e| e.2.as_str()), Some("idle"));
}

#[tokio::test]
async fn a_failed_wake_keeps_the_workspace_asleep() {
    let h = harness(None).await;
    h.write_charter("ws", PERSISTENT);
    let id = create(&h, "ws").await;
    h.mgr.sleep_citadel(&id).await.expect("sleep");
    *lock(&h.fake.fail_start) = true;
    let err = h
        .mgr
        .shell(&id, &argv(&["true"]), "")
        .await
        .expect_err("wake fails");
    assert!(err.to_string().contains("engine unavailable"), "{err}");
    let sess = h.mgr.session_handle(&id).expect("session");
    assert_eq!(sess.state(), SessionState::Sleeping);
    assert!(lock(&h.fake.killed).is_empty(), "never torn down");
    h.mgr.wake_citadel(&id).await.expect("second wake works");
    assert_eq!(sess.state(), SessionState::Running);
}

#[tokio::test]
async fn restart_rediscovers_sleeping_workspaces_and_rebuilds_them_on_use() {
    let mut h = harness(None).await;
    h.write_charter("ws", PERSISTENT);
    h.write_charter("plain", PLAIN);
    let asleep = create(&h, "ws").await;
    let awake = create(&h, "ws").await;
    let gone = create(&h, "plain").await;
    let run_id = h
        .mgr
        .session_handle(&asleep)
        .expect("s")
        .run_id()
        .to_owned();
    h.mgr.sleep_citadel(&asleep).await.expect("sleep");
    let creates = h.fake.creates.load(std::sync::atomic::Ordering::SeqCst);

    h.restart().await;

    // Both persistent Citadels are listed asleep, owned and addressable;
    // the plain one is gone and its run interrupted.
    let mut listed: Vec<(String, String, String)> = h
        .mgr
        .list_sandbox_infos()
        .into_iter()
        .map(|i| (i.sandbox.id, i.sandbox.status, i.owner))
        .collect();
    listed.sort();
    let mut want = vec![
        (asleep.clone(), "sleeping".to_owned(), "team".to_owned()),
        (awake.clone(), "sleeping".to_owned(), "team".to_owned()),
    ];
    want.sort();
    assert_eq!(listed, want);
    assert!(h.mgr.sandbox(&gone).is_none());
    assert_eq!(h.mgr.sandbox_owner(&asleep).as_deref(), Some("team"));
    assert_eq!(h.mgr.run(&run_id).expect("run").status, "running");
    let plain_runs: Vec<String> = h
        .mgr
        .list_runs()
        .into_iter()
        .filter(|r| r.citadel_id == gone)
        .map(|r| r.status)
        .collect();
    assert_eq!(plain_runs, ["interrupted"]);

    // The one that was running is stopped in the background.
    for _ in 0..200 {
        if lock(&h.fake.stopped).contains(&awake) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(lock(&h.fake.stopped).contains(&awake));

    // First use rebuilds the governed session around the kept workspace.
    let res = h
        .mgr
        .shell(&asleep, &argv(&["ls"]), "")
        .await
        .expect("shell after restart");
    assert_eq!(res.exit_code, 0);
    let sess = h.mgr.session_handle(&asleep).expect("rebuilt");
    assert_eq!(
        (sess.run_id(), sess.owner(), sess.actor()),
        (run_id.as_str(), "team", "lead")
    );
    assert!(lock(&h.fake.started).contains(&asleep));
    assert_eq!(
        h.fake.creates.load(std::sync::atomic::Ordering::SeqCst),
        creates,
        "woken, not re-created"
    );
    let events = workspace_events(&h.records().await, &asleep);
    assert_eq!(
        events.last().map(|e| e.2.as_str()),
        Some("recovered after control-plane restart")
    );

    // A rediscovered workspace can be killed without waking it.
    h.mgr.kill_sandbox(&awake).await.expect("kill dormant");
    assert!(lock(&h.fake.killed).contains(&awake));
    assert!(h.mgr.sandbox(&awake).is_none());
}

const OPEN_CHARTER: &str = r#"
[host]
type = "container"
image = "ghcr.io/example/agent:1"

[network]
default = "allow"
"#;

const LOCKED_CHARTER: &str = r#"
[host]
type = "container"
image = "ghcr.io/example/agent:1"

[network]
default = "deny"
[[network.rule]]
verdict = "allow"
hostname = "pypi.org"
"#;

#[tokio::test]
async fn fork_copies_into_an_independent_citadel_with_lineage() {
    let h = harness(None).await;
    h.write_charter("locked", LOCKED_CHARTER);
    h.write_charter("open", OPEN_CHARTER);
    h.write_charter("ws", PERSISTENT);
    let src = create(&h, "locked").await;
    let src_run = h.mgr.session_handle(&src).expect("s").run_id().to_owned();

    let fork = h
        .mgr
        .fork_citadel(&src, ForkOptions::default())
        .await
        .expect("fork");
    assert_ne!(fork.id, src);
    let fsess = h.mgr.session_handle(&fork.id).expect("fork session");
    assert_eq!(fsess.forked_from(), src_run);
    assert_ne!(fsess.run_id(), src_run);
    assert_eq!(fsess.owner(), "team");
    let run = h.mgr.run(fsess.run_id()).expect("fork run");
    assert_eq!(
        (run.forked_from.as_str(), run.charter.as_str()),
        (src_run.as_str(), "locked")
    );
    assert_eq!(
        (run.charter_lineage.as_str(), run.parent_charter.as_str()),
        ("exact", "locked")
    );
    let forks: Vec<(String, String)> = h
        .records()
        .await
        .into_iter()
        .filter(|e| e.tool == "citadel" && e.action == "fork")
        .map(|e| (e.sandbox, e.args.join(",")))
        .collect();
    assert_eq!(
        forks,
        [
            (src.clone(), fork.id.clone()),
            (fork.id.clone(), src.clone())
        ]
    );

    // Broader egress needs an administrator.
    let err = h
        .mgr
        .fork_citadel(
            &src,
            ForkOptions {
                profile: "open".into(),
                ..ForkOptions::default()
            },
        )
        .await
        .expect_err("wider");
    assert_eq!(err.client_status(), Some(403), "{err}");
    h.mgr
        .fork_citadel(
            &src,
            ForkOptions {
                profile: "open".into(),
                admin: true,
                ..ForkOptions::default()
            },
        )
        .await
        .expect("admin fork");
    let admin_run = h
        .mgr
        .list_runs()
        .into_iter()
        .rfind(|r| r.charter == "open")
        .expect("admin fork run");
    assert_eq!(admin_run.charter_lineage, "admin-override");
    assert!(
        admin_run.charter_proof.contains("network: "),
        "{}",
        admin_run.charter_proof
    );

    // Forking a sleeping workspace wakes it first; a persistent fork is
    // tracked as a workspace with its lineage.
    let ws = create(&h, "ws").await;
    h.mgr.sleep_citadel(&ws).await.expect("sleep");
    let wfork = h
        .mgr
        .fork_citadel(&ws, ForkOptions::default())
        .await
        .expect("fork sleeping");
    assert!(lock(&h.fake.started).contains(&ws));
    let st = h.mgr.workspace_status(&wfork.id).expect("tracked fork");
    assert!(!st.forked_from.is_empty());
}

#[tokio::test]
async fn fork_respects_policy() {
    let h = harness(None).await;
    h.write_charter(
        "nofork",
        r#"
[host]
type = "container"
image = "ghcr.io/example/agent:1"

[[policy]]
tool = "citadel"
match = "fork"
verdict = "deny"
reason = "no forks here"
"#,
    );
    let id = create(&h, "nofork").await;
    let err = h
        .mgr
        .fork_citadel(&id, ForkOptions::default())
        .await
        .expect_err("denied");
    assert_eq!(err.to_string(), "no forks here");
    assert_eq!(err.client_status(), Some(403));
}

async fn wait_terminal(m: &Manager, id: &str) -> crate::AgentSession {
    for _ in 0..3000 {
        let s = m.agent_session(id).expect("session");
        if s.status.is_terminal() {
            return s;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("agent session {id} never finished");
}

#[tokio::test]
async fn agent_turns_are_exclusive_and_share_one_transcript() {
    let mut h = harness(None).await;
    h.write_charter("ws", PERSISTENT);
    let id = create(&h, "ws").await;
    let first = h
        .mgr
        .start_agent_session(
            &id,
            StartAgentSessionOptions {
                command: argv(&["agent", "one"]),
                ..StartAgentSessionOptions::default()
            },
        )
        .await
        .expect("start");
    let done = wait_terminal(&h.mgr, &first.id).await;
    assert_eq!(done.status, AgentStatus::Completed);
    assert_eq!(done.turn, 0);
    let after_first = done.last_seq;

    // The Citadel sleeps between turns; the next turn wakes it.
    h.mgr.sleep_citadel(&id).await.expect("sleep");
    *lock(&h.fake.delay) = Some(Duration::from_millis(1500));
    let second = h
        .mgr
        .start_agent_turn(
            &first.id,
            AgentTurnOptions {
                command: argv(&["agent", "two"]),
                ..AgentTurnOptions::default()
            },
        )
        .await
        .expect("second turn");
    assert_eq!(
        (second.turn, second.status.clone()),
        (2, AgentStatus::Queued)
    );
    assert!(lock(&h.fake.started).contains(&id));
    let err = h
        .mgr
        .start_agent_turn(
            &first.id,
            AgentTurnOptions {
                command: argv(&["agent", "three"]),
                ..AgentTurnOptions::default()
            },
        )
        .await
        .expect_err("busy");
    assert_eq!(
        (err.code(), err.client_status()),
        (Some("session_busy"), Some(409))
    );
    let done = wait_terminal(&h.mgr, &first.id).await;
    *lock(&h.fake.delay) = None;
    assert_eq!(done.command, argv(&["agent", "two"]));

    // Replay after the first turn shows only the second, starting with the
    // turn marker.
    let (_, events) = h
        .mgr
        .agent_session_events(&first.id, after_first)
        .await
        .expect("events");
    assert_eq!(
        (events[0].stream.as_str(), events[0].data.as_str()),
        ("turn", "2")
    );
    assert_eq!(events.last().map(|e| e.data.as_str()), Some("completed"));

    // Across a restart the whole transcript replays and the session takes
    // another turn.
    let total = done.last_seq;
    h.restart().await;
    let sub = h
        .mgr
        .subscribe_agent_session(&first.id, 0)
        .await
        .expect("subscribe");
    assert_eq!(sub.backlog.len() as i64, total);
    let third = h
        .mgr
        .start_agent_turn(
            &first.id,
            AgentTurnOptions {
                command: argv(&["agent", "three"]),
                ..AgentTurnOptions::default()
            },
        )
        .await
        .expect("third turn after restart");
    assert_eq!(third.turn, 3);
    assert_eq!(
        wait_terminal(&h.mgr, &first.id).await.status,
        AgentStatus::Completed
    );
}

#[tokio::test]
async fn a_lagging_subscriber_is_refilled_from_the_transcript() {
    let h = harness(None).await;
    h.inject(runeward_charter::Charter::default(), vec![]);
    let id = crate::new_id();
    h.mgr.insert_agent_session(crate::AgentSession {
        id: id.clone(),
        citadel_id: "fake-1".into(),
        tenant: String::new(),
        actor: String::new(),
        agent: String::new(),
        model: String::new(),
        cohort_id: String::new(),
        task_id: String::new(),
        command: Vec::new(),
        status: AgentStatus::Running,
        exit_code: None,
        error: String::new(),
        created_at: runeward_ledger::gotime::now(),
        started_at: None,
        finished_at: None,
        last_seq: 0,
        transcript_truncated: false,
        turn: 0,
    });
    let mut sub = h
        .mgr
        .subscribe_agent_session(&id, 0)
        .await
        .expect("subscribe");
    // Far more than the live buffer, without reading.
    for i in 0..600 {
        h.mgr
            .append_agent_event(&id, "stdout", &format!("line {i}\n"))
            .await;
    }
    h.mgr
        .finish_agent_session(&id, AgentStatus::Completed)
        .await;
    let mut seqs = Vec::new();
    while let Some(ev) = sub.recv().await {
        seqs.push(ev.seq);
    }
    assert_eq!(seqs, (1..=601).collect::<Vec<i64>>(), "no gaps, no repeats");
}

#[tokio::test]
async fn cancel_does_not_rewind() {
    let h = harness(None).await;
    h.write_charter("ws", PERSISTENT);
    let id = create(&h, "ws").await;
    *lock(&h.fake.delay) = Some(Duration::from_secs(5));
    let a = h
        .mgr
        .start_agent_session(
            &id,
            StartAgentSessionOptions {
                command: argv(&["agent"]),
                ..StartAgentSessionOptions::default()
            },
        )
        .await
        .expect("start");
    for _ in 0..200 {
        if h.mgr.agent_session(&a.id).expect("s").status == AgentStatus::Running {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(h.mgr.cancel_agent_session(&a.id));
    let done = wait_terminal(&h.mgr, &a.id).await;
    assert_eq!(done.status, AgentStatus::Canceled);
    *lock(&h.fake.delay) = None;
    // A canceled session can take another turn.
    let next = h
        .mgr
        .start_agent_turn(
            &a.id,
            AgentTurnOptions {
                command: argv(&["agent", "again"]),
                ..AgentTurnOptions::default()
            },
        )
        .await
        .expect("next turn");
    assert_eq!(next.turn, 2);
}
