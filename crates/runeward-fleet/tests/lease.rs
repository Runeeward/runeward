//! Ports of Go `internal/fleet/lease_test.go`.

use std::thread;
use std::time::Duration;

use chrono::TimeDelta;
use runeward_fleet::{Board, TaskState};
use runeward_ledger::gotime;

#[test]
fn lease_sweep_requeues_dead_worker() {
    let b = Board::new();
    b.set_lease(Duration::from_millis(50));
    b.add("job");

    let claimed = b.claim("worker-1").expect("claim");
    assert!(
        claimed.lease_expiry.is_some(),
        "claim should stamp a lease expiry"
    );

    assert!(b.sweep(gotime::now()).is_empty(), "premature sweep");

    let requeued = b.sweep(gotime::now() + TimeDelta::seconds(1));
    assert_eq!(requeued.len(), 1);
    let got = b.get(&claimed.id).expect("get");
    assert_eq!(got.state, TaskState::Pending);
    assert_eq!(got.owner, "");
    assert_eq!(got.attempts, 1, "attempts retained");
    assert_eq!(got.error, "lease expired; requeued");
    assert!(got.lease_expiry.is_none());
}

#[test]
fn heartbeat_extends_lease() {
    let b = Board::new();
    b.set_lease(Duration::from_millis(50));
    b.add("job");
    let c = b.claim("w1").expect("claim");

    thread::sleep(Duration::from_millis(5));
    let hb = b.heartbeat(&c.id, "w1").expect("heartbeat");
    assert!(
        hb.lease_expiry > c.lease_expiry,
        "heartbeat should push expiry forward"
    );
    assert_eq!(
        hb.lease_version,
        c.lease_version + 1,
        "heartbeat rotates the lease version"
    );

    assert!(b.heartbeat(&c.id, "someone-else").is_err());
}

#[test]
fn load_restores_board() {
    let b = Board::new();
    b.add("a");
    b.add("b");
    let c = b.claim("w1").expect("claim");
    b.complete(&c.id, "w1", "done").expect("complete");

    let restored = Board::load(b.export(), Duration::from_secs(60));
    let s = restored.stats();
    assert_eq!((s.total, s.done, s.pending), (2, 1, 1));
}

#[test]
fn no_lease_never_swept() {
    let b = Board::seed(["job"]);
    let c = b.claim("w").expect("claim");
    assert!(c.lease_expiry.is_none());
    assert!(b.sweep(gotime::now() + TimeDelta::days(365)).is_empty());
}

#[test]
fn lease_version_rotates_on_every_claim() {
    let b = Board::seed(["job"]);
    let c1 = b.claim("w1").expect("claim");
    assert_eq!(c1.lease_version, 1);
    b.fail(&c1.id, "w1", "retry", true).expect("requeue");
    let c2 = b.claim("w2").expect("reclaim");
    assert_eq!(c2.lease_version, 2);
}
