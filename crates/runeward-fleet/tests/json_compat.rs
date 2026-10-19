//! Task JSON is byte-identical to Go's `encoding/json` output, so
//! `fleets.json` written by either implementation reads back in the other.

use runeward_fleet::{Board, Stats, Task, TaskState};
use runeward_ledger::gojson;

const COMPACT: &str = include_str!("testdata/tasks_compact.json");
const INDENT: &str = include_str!("testdata/tasks_indent.json");
const CLAIM: &str = include_str!("testdata/claim_with_token.json");
const STATS: &str = include_str!("testdata/stats.json");

fn decode(s: &str) -> Vec<Task> {
    serde_json::from_str(s).expect("decode Go tasks")
}

#[test]
fn go_tasks_round_trip_byte_identical() {
    let tasks = decode(COMPACT);
    assert_eq!(tasks.len(), 4);
    let out = gojson::marshal(&tasks).expect("marshal");
    assert_eq!(String::from_utf8(out).expect("utf8"), COMPACT);

    // json.MarshalIndent(tasks, "", "  ") has no trailing newline.
    let mut out = gojson::marshal_indent(&decode(INDENT)).expect("marshal");
    assert_eq!(out.pop(), Some(b'\n'));
    assert_eq!(String::from_utf8(out).expect("utf8"), INDENT);
}

#[test]
fn go_task_fields_decode() {
    let tasks = decode(COMPACT);
    assert_eq!(tasks[0].payload, "build <web> & test");
    assert_eq!(tasks[0].lease_expiry, None);
    assert_eq!(tasks[0].lease_version, 0);
    assert_eq!(tasks[1].state, TaskState::Claimed);
    assert_eq!(tasks[1].lease_version, 4);
    assert!(tasks[1].lease_expiry.is_some());
    assert_eq!(tasks[2].payload, "deploy\u{2028}now");
    assert_eq!(tasks[3].state, TaskState::Failed);
    assert_eq!(tasks[3].updated_at.offset().local_minus_utc(), 7200);

    let board = Board::load(tasks, std::time::Duration::ZERO);
    let s = board.stats();
    assert_eq!(
        (s.total, s.pending, s.claimed, s.done, s.failed),
        (4, 1, 1, 1, 1)
    );
}

#[test]
fn claim_reply_with_token() {
    let t: Task = serde_json::from_str(CLAIM).expect("decode");
    assert_eq!(t.lease_token, "tok.sig");
    assert_eq!(
        String::from_utf8(gojson::marshal(&t).expect("marshal")).expect("utf8"),
        CLAIM
    );
}

#[test]
fn stats_shape() {
    let s: Stats = serde_json::from_str(STATS).expect("decode");
    assert_eq!(
        String::from_utf8(gojson::marshal(&s).expect("marshal")).expect("utf8"),
        STATS
    );
}

#[test]
fn zero_task_matches_go() {
    let out = gojson::marshal(&Task::default()).expect("marshal");
    assert_eq!(
        String::from_utf8(out).expect("utf8"),
        r#"{"id":"","payload":"","state":"","owner":"","attempts":0,"created_at":"0001-01-01T00:00:00Z","updated_at":"0001-01-01T00:00:00Z","result":"","error":"","lease_expiry":"0001-01-01T00:00:00Z"}"#
    );
}

#[test]
fn nulls_and_unknown_fields_like_go() {
    let t: Task = serde_json::from_str(
        r#"{"id":"x","payload":null,"state":"paused","attempts":null,"lease_expiry":null,"future":1}"#,
    )
    .expect("decode");
    assert_eq!(t.payload, "");
    assert_eq!(t.state, TaskState::Other("paused".into()));
    assert_eq!(t.lease_expiry, None);
    let out = String::from_utf8(gojson::marshal(&t).expect("marshal")).expect("utf8");
    assert!(out.contains(r#""state":"paused""#), "{out}");
}

#[test]
fn context_fields_round_trip_and_stay_optional() {
    let b = Board::seed(["plan"]);
    let parent = b.list()[0].id.clone();
    let child = b.add_child(&parent, "build").expect("child");
    b.add_note(&child.id, "planner", "see <notes>")
        .expect("note");
    b.set_brief(&child.id, "coder", "own the parser")
        .expect("brief");

    let json = gojson::marshal(&b.export()).expect("marshal");
    let back: Vec<Task> = serde_json::from_slice(&json).expect("decode");
    assert_eq!(back, b.export());

    let plain = gojson::marshal(&Board::seed(["x"]).export()).expect("marshal");
    let plain = String::from_utf8(plain).expect("utf8");
    for key in [
        "parent",
        "children",
        "notes",
        "briefs",
        "lease_token",
        "lease_version",
    ] {
        assert!(
            !plain.contains(&format!("\"{key}\"")),
            "{key} leaked into {plain}"
        );
    }
}
