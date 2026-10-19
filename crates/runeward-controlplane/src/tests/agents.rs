//! Agent sessions: streaming, redaction, persistence, replay and cancel.

use std::time::Duration;

use runeward_charter::{Charter, Verdict};
use runeward_ledger::gotime;

use super::support::{harness, lock, rule};
use crate::agent_sessions::{AGENT_SESSION_DIR_NAME, AGENT_SESSIONS_FILE_NAME};
use crate::{AgentSession, AgentStatus, Manager, StartAgentSessionOptions};

async fn wait_terminal(m: &Manager, id: &str) -> AgentSession {
    for _ in 0..400 {
        let s = m.agent_session(id).expect("session");
        if s.status.is_terminal() {
            return s;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("agent session {id} never finished");
}

fn opts(command: &[&str]) -> StartAgentSessionOptions {
    StartAgentSessionOptions {
        command: command.iter().map(|s| (*s).to_owned()).collect(),
        agent: "cursor".into(),
        model: "test-model".into(),
        ..StartAgentSessionOptions::default()
    }
}

#[tokio::test]
async fn streams_redacted_events_and_persists() {
    let h = harness(None).await;
    h.inject_with(Charter::default(), vec![], |b| {
        b.secrets(vec!["declared-secret".into()])
    });
    *lock(&h.fake.streaming) = true;
    let started = h
        .mgr
        .start_agent_session("fake-1", opts(&["agent", "-p", "use declared-secret"]))
        .await
        .expect("start");
    assert_eq!(started.status, AgentStatus::Queued);
    let done = wait_terminal(&h.mgr, &started.id).await;
    assert_eq!(
        (done.status.clone(), done.exit_code),
        (AgentStatus::Completed, Some(0))
    );
    assert!(done.started_at.is_some() && done.finished_at.is_some());

    let (current, events) = h
        .mgr
        .agent_session_events(&started.id, 0)
        .await
        .expect("events");
    let streams: Vec<(&str, &str)> = events
        .iter()
        .map(|e| (e.stream.as_str(), e.data.as_str()))
        .collect();
    assert_eq!(streams.first(), Some(&("status", "running")));
    assert_eq!(streams.last(), Some(&("status", "completed")));
    assert!(streams.contains(&("stdout", "hello\n")));
    assert!(streams.contains(&("stderr", "warning\n")));
    assert!(
        streams.contains(&("stdout", "partial")),
        "unterminated output is flushed: {streams:?}"
    );
    let all: String = events.iter().map(|e| e.data.as_str()).collect();
    assert!(
        !all.contains("sk-ant-") && all.contains("[REDACTED]"),
        "{all}"
    );
    assert!(!current.command.join(" ").contains("declared-secret"));
    let seqs: Vec<i64> = events.iter().map(|e| e.seq).collect();
    assert_eq!(seqs, (1..=events.len() as i64).collect::<Vec<_>>());
    assert_eq!(current.last_seq, events.len() as i64);
    let last = h.records().await.pop().expect("event");
    assert_eq!(
        (last.tool.as_str(), last.verdict.as_str()),
        ("shell", "allow")
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: std::path::PathBuf| {
            std::fs::metadata(p).expect("stat").permissions().mode() & 0o777
        };
        assert_eq!(mode(h.state_dir().join(AGENT_SESSIONS_FILE_NAME)), 0o600);
        assert_eq!(
            mode(
                h.state_dir()
                    .join(AGENT_SESSION_DIR_NAME)
                    .join(format!("{}.jsonl", started.id))
            ),
            0o600
        );
    }

    h.mgr.close().await.expect("close");
    let restarted = Manager::builder(super::support::config(h.dir.path(), None))
        .build()
        .await
        .expect("restart");
    let (restored, restored_events) = restarted
        .agent_session_events(&started.id, 0)
        .await
        .expect("restored");
    assert_eq!(restored.status, AgentStatus::Completed);
    assert_eq!(restored_events, events);
}

#[tokio::test]
async fn subscription_returns_backlog_then_live_events() {
    let h = harness(None).await;
    let id = crate::new_id();
    h.mgr.insert_agent_session(AgentSession {
        id: id.clone(),
        citadel_id: "c".into(),
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
        created_at: gotime::now(),
        started_at: None,
        finished_at: None,
        last_seq: 0,
        transcript_truncated: false,
        turn: 0,
    });
    h.mgr.append_agent_event(&id, "stdout", "first\n").await;
    let mut sub = h
        .mgr
        .subscribe_agent_session(&id, 0)
        .await
        .expect("subscribe");
    assert_eq!(sub.backlog.len(), 1);
    assert_eq!(sub.backlog[0].data, "first\n");
    h.mgr.append_agent_event(&id, "stderr", "second\n").await;
    let ev = tokio::time::timeout(Duration::from_secs(1), sub.recv())
        .await
        .expect("timely")
        .expect("event");
    assert_eq!((ev.data.as_str(), ev.seq), ("second\n", 2));
    // Oversized output splits into 32 KiB events.
    h.mgr
        .append_agent_event(&id, "stdout", &"x".repeat(crate::MAX_AGENT_EVENT_BYTES + 1))
        .await;
    let a = sub.recv().await.expect("a");
    let b = sub.recv().await.expect("b");
    assert_eq!(
        (a.data.len(), b.data.len()),
        (crate::MAX_AGENT_EVENT_BYTES, 1)
    );
    drop(sub);
    assert!(h.mgr.subscribe_agent_session("missing", 0).await.is_none());
}

#[tokio::test]
async fn backlog_beyond_memory_window_reads_the_transcript() {
    let h = harness(None).await;
    let id = crate::new_id();
    h.mgr.insert_agent_session(AgentSession {
        id: id.clone(),
        status: AgentStatus::Running,
        created_at: gotime::now(),
        ..serde_json::from_str("{}").expect("empty session")
    });
    let total = crate::MAX_AGENT_EVENTS_MEMORY + 10;
    let store = h.mgr.agents.clone();
    let sid = id.clone();
    tokio::task::spawn_blocking(move || {
        for i in 0..total {
            store.append(&sid, "stdout", &format!("{i}\n"));
        }
    })
    .await
    .expect("append");
    let (_, events) = h.mgr.agent_session_events(&id, 0).await.expect("events");
    assert_eq!(events.len(), total);
    assert_eq!(events[0].data, "0\n");
    let (_, tail) = h
        .mgr
        .agent_session_events(&id, total as i64 - 2)
        .await
        .expect("tail");
    assert_eq!(tail.len(), 2);
}

#[tokio::test]
async fn denied_and_failed_and_canceled_sessions() {
    let h = harness(None).await;
    h.inject(
        Charter::default(),
        vec![rule("shell", "rm *", Verdict::Deny, "nope")],
    );
    let s = h
        .mgr
        .start_agent_session("fake-1", opts(&["rm", "-rf", "/"]))
        .await
        .expect("start");
    let s = wait_terminal(&h.mgr, &s.id).await;
    assert_eq!((s.status, s.error.as_str()), (AgentStatus::Denied, "nope"));

    let s = h
        .mgr
        .start_agent_session("fake-1", opts(&["false"]))
        .await
        .expect("start");
    let s = wait_terminal(&h.mgr, &s.id).await;
    assert_eq!((s.status, s.exit_code), (AgentStatus::Failed, Some(1)));
    assert_eq!(s.error, "agent exited with status 1");

    *lock(&h.fake.delay) = Some(Duration::from_secs(30));
    let s = h
        .mgr
        .start_agent_session("fake-1", opts(&["sleep", "30"]))
        .await
        .expect("start");
    for _ in 0..200 {
        if h.mgr.agent_session(&s.id).expect("s").status == AgentStatus::Running {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(h.mgr.cancel_agent_session(&s.id));
    let s = wait_terminal(&h.mgr, &s.id).await;
    assert_eq!(
        (s.status, s.error.as_str()),
        (AgentStatus::Canceled, "agent session canceled")
    );
    assert!(!h.mgr.cancel_agent_session(&s.id), "already finished");
    assert_eq!(h.mgr.agent_sessions("").len(), 3);
    assert!(h.mgr.agent_sessions("cohort-x").is_empty());

    // Killing the Citadel cancels its running sessions.
    let s = h
        .mgr
        .start_agent_session("fake-1", opts(&["sleep", "30"]))
        .await
        .expect("start");
    h.mgr.kill_sandbox("fake-1").await.expect("kill");
    let s = wait_terminal(&h.mgr, &s.id).await;
    assert_eq!(s.status, AgentStatus::Canceled);
}

#[tokio::test]
async fn validation() {
    let h = harness(None).await;
    h.inject(Charter::default(), vec![]);
    assert!(
        h.mgr
            .start_agent_session("fake-1", opts(&[]))
            .await
            .is_err()
    );
    assert!(
        h.mgr
            .start_agent_session("missing", opts(&["x"]))
            .await
            .is_err()
    );
    let err = h
        .mgr
        .start_agent_session(
            "fake-1",
            StartAgentSessionOptions {
                cohort_id: "nope".into(),
                ..opts(&["x"])
            },
        )
        .await
        .expect_err("cohort");
    assert_eq!(err.to_string(), "cohort \"nope\" not found");
}

#[tokio::test]
async fn restart_finishes_or_interrupts_unfinished_sessions() {
    let h = harness(None).await;
    let mk = |status: AgentStatus| AgentSession {
        id: crate::new_id(),
        status,
        created_at: gotime::now(),
        ..serde_json::from_str("{}").expect("empty session")
    };
    let finished_in_transcript = mk(AgentStatus::Running);
    let cut_off = mk(AgentStatus::Queued);
    for s in [&finished_in_transcript, &cut_off] {
        h.mgr.insert_agent_session(s.clone());
    }
    h.mgr
        .append_agent_event(&finished_in_transcript.id, "status", "running")
        .await;
    h.mgr
        .append_agent_event(&finished_in_transcript.id, "status", "completed")
        .await;
    let store = h.mgr.agents.clone();
    tokio::task::spawn_blocking(move || store.save())
        .await
        .expect("join")
        .expect("save");
    h.mgr.close().await.expect("close");

    let restarted = Manager::builder(super::support::config(h.dir.path(), None))
        .build()
        .await
        .expect("restart");
    let a = restarted
        .agent_session(&finished_in_transcript.id)
        .expect("a");
    assert_eq!((a.status, a.last_seq), (AgentStatus::Completed, 2));
    let b = restarted.agent_session(&cut_off.id).expect("b");
    assert_eq!(b.status, AgentStatus::Interrupted);
    assert!(b.error.contains("restarted"));
}
