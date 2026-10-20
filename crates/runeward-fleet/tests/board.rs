//! Ports of Go `internal/fleet/board_test.go`.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::thread;

use runeward_fleet::{Board, FleetError, Stats, TaskState};

fn is_illegal<T: std::fmt::Debug>(r: Result<T, FleetError>) -> bool {
    matches!(r, Err(FleetError::IllegalTransition(_)))
}

fn is_not_found<T: std::fmt::Debug>(r: Result<T, FleetError>) -> bool {
    matches!(r, Err(FleetError::NotFound(_)))
}

fn stats(total: i64, pending: i64, claimed: i64, done: i64, failed: i64) -> Stats {
    Stats {
        total,
        pending,
        claimed,
        done,
        failed,
    }
}

#[test]
fn complete_fail_reject_wrong_owner() {
    let b = Board::seed(["a", "b"]);
    let ca = b.claim("w1").expect("claim a");
    assert!(is_illegal(b.complete(&ca.id, "w2", "done")));
    b.complete(&ca.id, "w1", "done").expect("complete by owner");

    let cb = b.claim("w1").expect("claim b");
    assert!(is_illegal(b.fail(&cb.id, "w2", "boom", false)));
    b.fail(&cb.id, "w1", "boom", false).expect("fail by owner");
}

#[test]
fn lifecycle() {
    let b = Board::new();
    let added = b.add("build");
    assert_eq!(added.state, TaskState::Pending);
    assert_eq!(b.stats(), stats(1, 1, 0, 0, 0));

    let claimed = b.claim("w1").expect("claim on non-empty board");
    assert_eq!(claimed.id, added.id);
    assert_eq!(claimed.state, TaskState::Claimed);
    assert_eq!(claimed.owner, "w1");
    assert_eq!(claimed.attempts, 1);
    assert_eq!(b.stats(), stats(1, 0, 1, 0, 0));

    b.complete(&claimed.id, "w1", "ok").expect("complete");
    let done = b.get(&claimed.id).expect("get");
    assert_eq!(done.state, TaskState::Done);
    assert_eq!(done.result, "ok");
    assert_eq!(b.stats(), stats(1, 0, 0, 1, 0));
    assert_eq!(b.remaining(), 0);
}

#[test]
fn claim_empty() {
    assert!(Board::new().claim("w1").is_none());
}

#[test]
fn fifo_claim_order() {
    let payloads = ["a", "b", "c", "d"];
    let b = Board::seed(payloads);
    for want in payloads {
        let got = b.claim("w").expect("claim");
        assert_eq!(got.payload, want, "FIFO order broken");
    }
    assert!(b.claim("w").is_none());
}

#[test]
fn fail_requeue() {
    let b = Board::seed(["x"]);
    let c1 = b.claim("w1").expect("claim");
    assert_eq!(c1.attempts, 1);

    b.fail(&c1.id, "w1", "boom", true).expect("fail requeue");
    let requeued = b.get(&c1.id).expect("get");
    assert_eq!(requeued.state, TaskState::Pending);
    assert_eq!(requeued.owner, "");
    assert_eq!(requeued.attempts, 1, "attempts preserved");
    assert_eq!(requeued.error, "boom");

    let c2 = b.claim("w2").expect("requeued task claimable again");
    assert_eq!(c2.attempts, 2);
}

#[test]
fn fail_no_requeue() {
    let b = Board::seed(["x"]);
    let c = b.claim("w1").expect("claim");
    b.fail(&c.id, "w1", "boom", false).expect("fail");
    assert_eq!(b.get(&c.id).expect("get").state, TaskState::Failed);
    assert_eq!(b.stats(), stats(1, 0, 0, 0, 1));
    assert!(b.claim("w2").is_none(), "failed task must not be claimable");
}

#[test]
fn illegal_transition() {
    let b = Board::seed(["x"]);
    let pending = b.list().remove(0);
    assert!(is_illegal(b.complete(&pending.id, "", "res")));
    assert!(is_illegal(b.fail(&pending.id, "", "e", false)));

    let c = b.claim("w").expect("claim");
    b.complete(&c.id, "w", "ok").expect("first complete");
    assert!(is_illegal(b.complete(&c.id, "w", "again")));
}

#[test]
fn not_found() {
    let b = Board::new();
    assert!(b.get("nope").is_none());
    assert!(is_not_found(b.complete("nope", "", "x")));
    assert!(is_not_found(b.fail("nope", "", "x", false)));
}

#[test]
fn error_messages_match_go() {
    let b = Board::seed(["x"]);
    let id = b.list()[0].id.clone();
    assert_eq!(
        b.complete("nope", "", "x").expect_err("error").to_string(),
        "fleet: task not found: \"nope\""
    );
    assert_eq!(
        b.complete(&id, "", "x").expect_err("error").to_string(),
        format!(
            "fleet: illegal state transition: complete requires claimed, task \"{id}\" is pending"
        )
    );
    b.claim("w1").expect("claim");
    assert_eq!(
        b.heartbeat(&id, "w2").expect_err("error").to_string(),
        format!("fleet: illegal state transition: task \"{id}\" is owned by \"w1\", not \"w2\"")
    );
}

#[test]
fn unique_ids() {
    let b = Board::new();
    let mut seen = HashSet::new();
    for i in 0..1000 {
        let id = b.add(format!("p{i}")).id;
        assert_eq!(id.len(), 16);
        assert!(seen.insert(id.clone()), "duplicate generated id {id}");
    }
}

/// No task is ever handed to two workers and every task ends up done.
#[test]
fn concurrent_claim() {
    const NUM_TASKS: usize = 1000;
    const NUM_WORKERS: usize = 8;
    let b = Arc::new(Board::seed((0..NUM_TASKS).map(|i| format!("task-{i}"))));
    let claimed = Arc::new(Mutex::new(HashSet::new()));

    let handles: Vec<_> = (0..NUM_WORKERS)
        .map(|w| {
            let b = Arc::clone(&b);
            let claimed = Arc::clone(&claimed);
            thread::spawn(move || {
                let owner = format!("w{w}");
                while let Some(task) = b.claim(&owner) {
                    assert!(
                        claimed.lock().expect("lock").insert(task.id.clone()),
                        "task {} double-claimed",
                        task.id
                    );
                    b.complete(&task.id, &task.owner, "done").expect("complete");
                }
            })
        })
        .collect();
    for h in handles {
        h.join().expect("worker");
    }

    assert_eq!(claimed.lock().expect("lock").len(), NUM_TASKS);
    let s = b.stats();
    assert_eq!((s.done, s.total), (NUM_TASKS as i64, NUM_TASKS as i64));
    assert_eq!(b.remaining(), 0);
}

/// Fails the first attempt on each task and completes the second, so every
/// task must finish done with at least two attempts.
#[test]
fn concurrent_claim_with_requeue() {
    const NUM_TASKS: usize = 500;
    const NUM_WORKERS: usize = 8;
    let b = Arc::new(Board::seed((0..NUM_TASKS).map(|i| format!("task-{i}"))));
    let failed_once = Arc::new(Mutex::new(HashSet::new()));

    let handles: Vec<_> = (0..NUM_WORKERS)
        .map(|w| {
            let b = Arc::clone(&b);
            let failed_once = Arc::clone(&failed_once);
            thread::spawn(move || {
                let owner = format!("w{w}");
                while let Some(task) = b.claim(&owner) {
                    let first = failed_once.lock().expect("lock").insert(task.id.clone());
                    if first {
                        b.fail(&task.id, &task.owner, "transient", true)
                            .expect("fail");
                    } else {
                        b.complete(&task.id, &task.owner, "done").expect("complete");
                    }
                }
            })
        })
        .collect();
    for h in handles {
        h.join().expect("worker");
    }

    assert_eq!(b.stats().done, NUM_TASKS as i64);
    for t in b.list() {
        assert!(t.attempts >= 2, "task {} attempts = {}", t.id, t.attempts);
    }
    assert_eq!(b.remaining(), 0);
}

#[test]
fn restore_and_remove() {
    let b = Board::seed(["a", "b", "c"]);
    let before = b.list()[1].clone();
    b.claim("w").expect("claim a");
    let claimed = b.claim("w").expect("claim b");
    assert_eq!(claimed.id, before.id);
    let mut snapshot = before.clone();
    snapshot.lease_token = "secret".into();
    assert!(b.restore(snapshot));
    let restored = b.get(&before.id).expect("get");
    assert_eq!(restored.state, TaskState::Pending);
    assert!(
        restored.lease_token.is_empty(),
        "restore drops the lease token"
    );

    let mut ghost = before.clone();
    ghost.id = "ghost".into();
    assert!(!b.restore(ghost));

    assert!(b.remove(&before.id));
    assert!(!b.remove(&before.id));
    let payloads: Vec<_> = b.list().into_iter().map(|t| t.payload).collect();
    assert_eq!(payloads, ["a", "c"]);
}

#[test]
fn multi_agent_context() {
    let b = Board::seed(["plan"]);
    let parent = b.list()[0].id.clone();
    let child = b.add_child(&parent, "implement").expect("add child");
    assert_eq!(child.parent, parent);
    assert_eq!(
        b.get(&parent).expect("parent").children,
        std::slice::from_ref(&child.id)
    );
    assert!(matches!(
        b.add_child("nope", "x"),
        Err(FleetError::NotFound(_))
    ));

    let t = b
        .add_note(&child.id, "planner", "start with the parser")
        .expect("note");
    assert_eq!(t.notes.len(), 1);
    assert_eq!(t.notes[0].from, "planner");
    let t = b
        .set_brief(&child.id, "coder", "you own src/parser")
        .expect("brief");
    assert_eq!(
        t.briefs.get("coder").map(String::as_str),
        Some("you own src/parser")
    );
    let t = b.set_brief(&child.id, "coder", "").expect("clear brief");
    assert!(t.briefs.is_empty());

    // FIFO still applies: the parent was added first.
    assert_eq!(b.claim("w").expect("claim").id, parent);
    assert_eq!(b.claim("w").expect("claim").id, child.id);

    assert!(b.remove(&child.id));
    assert!(b.get(&parent).expect("parent").children.is_empty());
}
