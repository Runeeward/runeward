//! Shared Cohort memory, handoffs and scheduled runs.

use std::time::Duration;

use runeward_ledger::gotime;

use super::support::{harness, lock};
use crate::memory::MEMORY_DIR_NAME;
use crate::schedules::SCHEDULES_FILE_NAME;
use crate::{AgentStatus, CreateOptions, Error, MemoryPut, MemoryQuery, ScheduleSpec, with_actor};

const COHORT: &str = r#"
[host]
image = "ghcr.io/example/agent:1"

[cohort]
replicas = 1
task_board = ["migrate the billing database"]
"#;

const COHORT_CLEAR: &str = r#"
[host]
image = "ghcr.io/example/agent:1"

[cohort]
replicas = 1

[chronicle]
redact = false
"#;

fn put(key: &str, text: &str, tags: &[&str]) -> MemoryPut {
    MemoryPut {
        key: key.into(),
        text: text.into(),
        tags: tags.iter().map(|t| (*t).to_owned()).collect(),
        expected_version: None,
    }
}

#[tokio::test]
async fn memory_is_versioned_attributed_and_hashed_in_the_ledger() {
    let mut h = harness(None).await;
    h.write_charter("crew", COHORT);
    let f = h
        .mgr
        .create_fleet_for_identity("crew", "team", "lead")
        .await
        .expect("fleet");

    let e = with_actor(
        "agent-a",
        h.mgr
            .memory_put(&f.id, put("db/schema", "users(id), orders(id)", &["db"])),
    )
    .await
    .expect("put");
    assert_eq!((e.version, e.author.as_str()), (1, "agent-a"));

    // Optimistic concurrency.
    let stale = MemoryPut {
        expected_version: Some(0),
        ..put("db/schema", "new", &[])
    };
    let err = h.mgr.memory_put(&f.id, stale).await.expect_err("exists");
    assert_eq!(
        (err.code(), err.client_status()),
        (Some("version_conflict"), Some(409))
    );
    let next = MemoryPut {
        expected_version: Some(1),
        ..put(
            "db/schema",
            "users(id, email), orders(id)",
            &["db", "schema"],
        )
    };
    let e2 = with_actor("agent-b", h.mgr.memory_put(&f.id, next))
        .await
        .expect("cas");
    assert_eq!((e2.version, e2.author.as_str()), (2, "agent-b"));
    assert_eq!(e2.created_at, e.created_at);

    with_actor(
        "agent-a",
        h.mgr
            .memory_put(&f.id, put("style", "rustfmt everything", &[])),
    )
    .await
    .expect("put style");
    let found = h
        .mgr
        .memory_search(
            &f.id,
            &MemoryQuery {
                query: "orders schema".into(),
                ..MemoryQuery::default()
            },
        )
        .await
        .expect("search");
    assert_eq!(
        found.iter().map(|e| e.key.as_str()).collect::<Vec<_>>(),
        ["db/schema"]
    );

    // Caps.
    let big = put("big", &"x".repeat(crate::MAX_MEMORY_TEXT_BYTES + 1), &[]);
    assert!(matches!(
        h.mgr.memory_put(&f.id, big).await,
        Err(Error::BadInput(_))
    ));
    assert!(matches!(
        h.mgr
            .memory_put("0123456789abcdef", put("k", "v", &[]))
            .await,
        Err(Error::NotFound(_))
    ));

    // The ledger has hashes, not text (redaction is on by default).
    let mem: Vec<_> = h
        .records()
        .await
        .into_iter()
        .filter(|e| e.tool == "memory")
        .collect();
    assert_eq!(mem.len(), 3);
    assert_eq!(mem[0].meta["actor"], "agent-a");
    assert_eq!(mem[0].meta["tenant"], "team");
    assert_eq!(
        mem[0].meta["text_sha256"],
        crate::memory::sha256_hex("users(id), orders(id)")
    );
    assert!(!mem[0].meta.contains_key("text"));

    // Durable across a restart.
    assert!(
        h.state_dir()
            .join(MEMORY_DIR_NAME)
            .join(format!("{}.json", f.id))
            .exists()
    );
    h.restart().await;
    let got = h
        .mgr
        .memory_get(&f.id, "db/schema")
        .await
        .expect("get")
        .expect("present");
    assert_eq!(got.version, 2);
    assert!(
        h.mgr
            .memory_delete(&f.id, "db/schema", Some(2))
            .await
            .expect("delete")
    );
    assert!(
        h.mgr
            .memory_get(&f.id, "db/schema")
            .await
            .expect("get")
            .is_none()
    );

    // Killing the Cohort drops its memory.
    h.mgr.kill_fleet(&f.id).await.expect("kill");
    assert!(
        !h.state_dir()
            .join(MEMORY_DIR_NAME)
            .join(format!("{}.json", f.id))
            .exists()
    );
}

#[tokio::test]
async fn memory_text_is_kept_when_the_charter_does_not_redact() {
    let h = harness(None).await;
    h.write_charter("clear", COHORT_CLEAR);
    let f = h.mgr.create_fleet("clear").await.expect("fleet");
    h.mgr
        .memory_put(&f.id, put("k", "plain text", &[]))
        .await
        .expect("put");
    let ev = h
        .records()
        .await
        .into_iter()
        .find(|e| e.tool == "memory")
        .expect("event");
    assert_eq!(ev.meta["text"], "plain text");
}

#[tokio::test]
async fn claims_carry_handoffs_briefs_and_ranked_memory() {
    let h = harness(None).await;
    h.write_charter("crew", COHORT);
    let f = h
        .mgr
        .create_fleet_for_identity("crew", "team", "lead")
        .await
        .expect("fleet");
    let parent = h.mgr.list_tasks(&f.id).expect("tasks").remove(0);
    h.mgr
        .memory_put(
            &f.id,
            put("billing-db", "billing runs on postgres 16", &["database"]),
        )
        .await
        .expect("memory");
    h.mgr
        .memory_put(&f.id, put("unrelated", "lunch is at noon", &[]))
        .await
        .expect("memory");

    // Worker 1 takes the parent, splits it and hands off.
    let claimed = h
        .mgr
        .claim_task_with_context(&f.id, "w1", 0)
        .await
        .expect("claim")
        .expect("task");
    assert_eq!(claimed.task.id, parent.id);
    assert_eq!(claimed.context.memory[0].key, "billing-db", "ranked first");
    let child = h
        .mgr
        .add_child_task(&f.id, &parent.id, "write the billing migration script")
        .await
        .expect("child");
    with_actor(
        "lead",
        h.mgr
            .set_task_brief(&f.id, &child.id, "w2", "keep downtime under 5 minutes"),
    )
    .await
    .expect("brief");
    with_actor(
        "lead",
        h.mgr
            .set_task_brief(&f.id, &parent.id, "*", "general brief"),
    )
    .await
    .expect("brief");
    h.mgr
        .complete_task_with_handoff(
            &f.id,
            &parent.id,
            "w1",
            &claimed.task.lease_token,
            "plan written",
            "schema is in memory under billing-db; start with the orders table",
        )
        .await
        .expect("complete");
    with_actor(
        "w1",
        h.mgr
            .add_task_note(&f.id, &child.id, "watch the FK on orders"),
    )
    .await
    .expect("note");

    // Worker 2 starts fresh and gets everything it needs.
    let next = h
        .mgr
        .claim_task_with_context(&f.id, "w2", 0)
        .await
        .expect("claim")
        .expect("child task");
    assert_eq!(next.task.id, child.id);
    let ctx = &next.context;
    assert_eq!(ctx.brief, "keep downtime under 5 minutes");
    let notes: Vec<(&str, &str)> = ctx
        .handoff
        .iter()
        .map(|n| (n.from.as_str(), n.text.as_str()))
        .collect();
    assert_eq!(
        notes,
        [
            (
                "w1",
                "schema is in memory under billing-db; start with the orders table"
            ),
            ("w1", "watch the FK on orders"),
        ]
    );
    let p = ctx.parent.as_ref().expect("parent");
    assert_eq!(
        (p.id.as_str(), p.state.as_str(), p.result.as_str()),
        (parent.id.as_str(), "done", "plan written")
    );
    assert_eq!(ctx.memory[0].key, "billing-db");

    // Caps and errors.
    assert!(matches!(
        h.mgr
            .add_task_note(&f.id, &child.id, &"x".repeat(crate::MAX_NOTE_BYTES + 1))
            .await,
        Err(Error::BadInput(_))
    ));
    assert!(matches!(
        h.mgr.add_task_note(&f.id, "nope", "x").await,
        Err(Error::Task(_))
    ));
    let err = h
        .mgr
        .complete_task_with_handoff(&f.id, &child.id, "w2", "forged", "", "note")
        .await
        .expect_err("bad lease");
    assert!(matches!(err, Error::InvalidLease));

    // Notes and briefs are Chronicled as hashes.
    let ctx_events: Vec<String> = h
        .records()
        .await
        .into_iter()
        .filter(|e| e.tool == "fleet" && e.action.starts_with("task."))
        .map(|e| {
            assert!(!e.meta.contains_key("text"), "{e:?}");
            e.action
        })
        .collect();
    assert_eq!(
        ctx_events,
        [
            "task.child",
            "task.brief",
            "task.brief",
            "task.handoff",
            "task.note"
        ]
    );
}

const WS: &str = r#"
[host]
type = "container"
image = "ghcr.io/example/agent:1"

[workspace]
persist = true
idle_timeout = "15m"
"#;

const WS_SELF: &str = r#"
[host]
type = "container"
image = "ghcr.io/example/agent:1"

[schedule]
self_service = true

[[policy]]
tool = "schedule"
match = "fire"
verdict = "deny"
reason = "no scheduled runs"
"#;

async fn citadel(h: &super::support::Harness, charter: &str) -> String {
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

fn spec(citadel: &str, every: &str, command: &[&str]) -> ScheduleSpec {
    ScheduleSpec {
        citadel_id: citadel.into(),
        every: every.into(),
        command: command.iter().map(|s| (*s).to_owned()).collect(),
        ..ScheduleSpec::default()
    }
}

#[tokio::test]
async fn schedules_validate_cap_and_gate_self_service() {
    let h = harness(None).await;
    h.write_charter("ws", WS);
    h.write_charter("self", WS_SELF);
    let id = citadel(&h, "ws").await;

    for (bad, want) in [
        (spec(&id, "30s", &["agent"]), "at least 1m"),
        (spec(&id, "", &["agent"]), "exactly one of cron and every"),
        (spec(&id, "5m", &[]), "command is required"),
        (spec("missing", "5m", &["agent"]), "not found"),
        (
            ScheduleSpec {
                cron: "* * * * * *".into(),
                ..spec(&id, "", &["agent"])
            },
            "cron",
        ),
    ] {
        let err = h.mgr.create_schedule(bad).await.expect_err(want);
        assert!(err.to_string().contains(want), "{want}: {err}");
    }

    let s = with_actor("lead", h.mgr.create_schedule(spec(&id, "1h", &["agent"])))
        .await
        .expect("create");
    assert_eq!((s.owner.as_str(), s.actor.as_str()), ("team", "lead"));
    let next = s.next_fire_at.expect("next");
    assert!(next > gotime::now() + chrono::Duration::minutes(59));
    for _ in 1..crate::MAX_SCHEDULES_PER_TARGET {
        h.mgr
            .create_schedule(spec(&id, "1h", &["agent"]))
            .await
            .expect("under the cap");
    }
    let err = h
        .mgr
        .create_schedule(spec(&id, "1h", &["agent"]))
        .await
        .expect_err("cap");
    assert!(err.to_string().contains("at most 50"), "{err}");

    // Agents need the Charter's opt-in.
    let err = h
        .mgr
        .create_self_schedule(spec(&id, "1h", &["agent"]))
        .await
        .expect_err("not allowed");
    assert_eq!(err.client_status(), Some(403));
    let selfie = citadel(&h, "self").await;
    let mine = h
        .mgr
        .create_self_schedule(spec(&selfie, "1h", &["agent"]))
        .await
        .expect("self-service");
    assert!(mine.self_service);

    // Policy can refuse a firing.
    let fired = h.mgr.run_schedule_now(&mine.id).await.expect("fire");
    assert_eq!(
        (fired.outcome.as_str(), fired.reason.as_str()),
        ("denied", "no scheduled runs")
    );

    // Killing the Citadel drops its schedules.
    h.mgr.kill_sandbox(&id).await.expect("kill");
    assert!(h.mgr.schedules_for("", &id).is_empty());
    assert!(h.mgr.delete_schedule(&mine.id).await.expect("delete"));
    assert!(h.mgr.schedule(&mine.id).is_none());
}

#[tokio::test]
async fn firings_precheck_then_start_a_fresh_session_and_never_backfill() {
    let mut h = harness(None).await;
    h.write_charter("ws", WS);
    let id = citadel(&h, "ws").await;
    let check = ScheduleSpec {
        precheck: vec!["false".into()],
        ..spec(&id, "1m", &["agent", "--check"])
    };
    let skipped = h.mgr.create_schedule(check).await.expect("schedule");
    let run = ScheduleSpec {
        prompt: "triage new issues".into(),
        precheck: vec!["true".into()],
        agent: "codex".into(),
        ..spec(&id, "1m", &["agent", "-p"])
    };
    let s = h.mgr.create_schedule(run).await.expect("schedule");

    // A sleeping workspace is woken by the precheck.
    h.mgr.sleep_citadel(&id).await.expect("sleep");
    let past = gotime::now() - chrono::Duration::hours(3);
    for sid in [&skipped.id, &s.id] {
        lock(&h.mgr.schedules)
            .get_mut(sid.as_str())
            .expect("schedule")
            .next_fire_at = Some(past);
    }
    let mut firings = h.mgr.fire_due_schedules().await;
    firings.sort_by(|a, b| a.schedule_id.cmp(&b.schedule_id));
    let by_id = |sid: &str| {
        firings
            .iter()
            .find(|f| f.schedule_id == sid)
            .cloned()
            .expect("fired")
    };
    let f1 = by_id(&skipped.id);
    assert_eq!(
        (f1.outcome.as_str(), f1.reason.as_str()),
        ("skipped_precheck", "precheck exited 1")
    );
    let f2 = by_id(&s.id);
    assert_eq!(f2.outcome, "started");
    assert!(lock(&h.fake.started).contains(&id), "woken");
    let a = h.mgr.agent_session(&f2.session_id).expect("session");
    assert_eq!(a.command, ["agent", "-p", "triage new issues"]);
    assert_eq!(a.agent, "codex");
    for _ in 0..300 {
        if h.mgr.agent_session(&a.id).expect("s").status.is_terminal() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(
        h.mgr.agent_session(&a.id).expect("s").status,
        AgentStatus::Completed
    );

    // Fired once, not three hours' worth; the next time is in the future.
    let cur = h.mgr.schedule(&s.id).expect("schedule");
    assert_eq!((cur.fire_count, cur.last_outcome.as_str()), (1, "started"));
    assert!(cur.next_fire_at.expect("next") > gotime::now());
    assert!(h.mgr.fire_due_schedules().await.is_empty(), "nothing due");

    let fires: Vec<String> = h
        .records()
        .await
        .into_iter()
        .filter(|e| e.tool == "schedule" && e.action == "fire")
        .map(|e| e.meta["reason"].clone())
        .collect();
    assert_eq!(fires.len(), 2);

    // Restart: schedules come back, missed windows are skipped.
    lock(&h.mgr.schedules)
        .get_mut(s.id.as_str())
        .expect("schedule")
        .next_fire_at = Some(past);
    h.mgr.fire_due_schedules().await;
    let file = std::fs::read_to_string(h.state_dir().join(SCHEDULES_FILE_NAME)).expect("file");
    assert!(file.contains(&s.id));
    h.restart().await;
    let back = h.mgr.schedule(&s.id).expect("reloaded");
    assert!(back.next_fire_at.expect("next") > gotime::now());
    assert_eq!(back.fire_count, 2);
}
