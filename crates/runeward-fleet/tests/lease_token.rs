//! Ports of Go `internal/controlplane/leasetoken_test.go`, plus interop with
//! tokens minted by the Go implementation.

use std::fs;

use chrono::TimeDelta;
use runeward_fleet::{InvalidLease, LEASE_KEY_FILE_NAME, LeaseSigner, Task};
use runeward_ledger::gotime;
use serde::Deserialize;

const KEY: &[u8] = b"01234567890123456789012345678901";

fn task(id: &str, owner: &str, expiry: TimeDelta, lease_version: i64) -> Task {
    Task {
        id: id.into(),
        owner: owner.into(),
        lease_expiry: Some(gotime::now() + expiry),
        lease_version,
        ..Task::default()
    }
}

#[test]
fn task_lease_binds_cohort_task_and_actor() {
    let m = LeaseSigner::new(KEY);
    let token = m
        .issue(
            "cohort-1",
            &task("task-1", "codex", TimeDelta::minutes(1), 3),
        )
        .expect("issue");
    m.verify(&token, "cohort-1", "task-1", "codex", 3)
        .expect("valid lease rejected");
    for (cohort, task, actor) in [
        ("other", "task-1", "codex"),
        ("cohort-1", "other", "codex"),
        ("cohort-1", "task-1", "claude"),
    ] {
        assert_eq!(
            m.verify(&token, cohort, task, actor, 3),
            Err(InvalidLease),
            "wrong binding accepted: {cohort} {task} {actor}"
        );
    }
    assert_eq!(
        m.verify(&token, "cohort-1", "task-1", "codex", 4),
        Err(InvalidLease),
        "stale lease version accepted"
    );
}

#[test]
fn task_lease_expires() {
    let m = LeaseSigner::new(KEY);
    let token = m
        .issue("c", &task("t", "a", TimeDelta::seconds(-1), 1))
        .expect("issue");
    assert_eq!(m.verify(&token, "c", "t", "a", 1), Err(InvalidLease));
}

#[test]
fn task_without_lease_gets_a_day() {
    let m = LeaseSigner::new(KEY);
    let t = Task {
        id: "t".into(),
        owner: "a".into(),
        lease_version: 1,
        ..Task::default()
    };
    let token = m.issue("c", &t).expect("issue");
    let claims = m.verify(&token, "c", "t", "a", 1).expect("verify");
    let left = claims.expires - gotime::now().timestamp();
    assert!((86_390..=86_400).contains(&left), "expiry {left}s from now");
}

#[test]
fn tampered_and_malformed_tokens_rejected() {
    let m = LeaseSigner::new(KEY);
    let token = m
        .issue("c", &task("t", "a", TimeDelta::minutes(1), 1))
        .expect("issue");
    let (body, sig) = token.split_once('.').expect("two parts");
    let other = LeaseSigner::new(*b"another-key-another-key-another-");
    let cases = [
        String::new(),
        body.to_owned(),
        format!("{body}."),
        format!(".{sig}"),
        format!("{token}.x"),
        format!("{body}x.{sig}"),
        format!("{body}.{}", &sig[1..]),
        format!("{body}.!!"),
    ];
    for bad in &cases {
        assert_eq!(
            m.verify(bad, "c", "t", "a", 1),
            Err(InvalidLease),
            "{bad:?}"
        );
    }
    assert_eq!(other.verify(&token, "c", "t", "a", 1), Err(InvalidLease));
}

#[test]
fn lease_key_is_persistent_and_private() {
    let dir = tempfile::tempdir().expect("tempdir");
    let state = dir.path().join("state");
    let first = LeaseSigner::load_or_create(&state).expect("create");
    let second = LeaseSigner::load_or_create(&state).expect("load");
    let token = first
        .issue("c", &task("t", "a", TimeDelta::minutes(1), 1))
        .expect("issue");
    second
        .verify(&token, "c", "t", "a", 1)
        .expect("lease key was not persisted");
    let key = fs::read(state.join(LEASE_KEY_FILE_NAME)).expect("read key");
    assert_eq!(key.len(), 32);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode =
            |p: &std::path::Path| fs::metadata(p).expect("stat").permissions().mode() & 0o777;
        assert_eq!(mode(&state.join(LEASE_KEY_FILE_NAME)), 0o600);
        assert_eq!(mode(&state), 0o700);

        fs::set_permissions(
            state.join(LEASE_KEY_FILE_NAME),
            fs::Permissions::from_mode(0o644),
        )
        .expect("chmod");
        let err = LeaseSigner::load_or_create(&state).expect_err("world-readable key");
        assert!(
            err.to_string().contains("must use 0600 permissions"),
            "{err}"
        );
    }
}

#[test]
fn lease_key_wrong_length_rejected() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join(LEASE_KEY_FILE_NAME);
    fs::write(&path, b"short").expect("write");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("chmod");
    }
    let err = LeaseSigner::load_or_create(dir.path()).expect_err("short key");
    assert!(err.to_string().contains("has invalid length"), "{err}");
    assert!(LeaseSigner::load_or_create(std::path::Path::new("")).is_err());
}

#[derive(Deserialize)]
struct Fixture {
    key_hex: String,
    tokens: Vec<FixtureToken>,
}

#[derive(Deserialize)]
struct FixtureToken {
    cohort: String,
    task: String,
    actor: String,
    lease: i64,
    token: String,
    valid: bool,
}

/// Tokens minted by the Go control plane (`issueTaskLease`) verify here.
#[test]
fn go_minted_tokens_verify() {
    let f: Fixture =
        serde_json::from_str(include_str!("testdata/go_lease_tokens.json")).expect("fixture");
    let m = LeaseSigner::new(hex::decode(&f.key_hex).expect("hex key"));
    assert_eq!(f.tokens.len(), 3);
    for t in &f.tokens {
        let got = m.verify(&t.token, &t.cohort, &t.task, &t.actor, t.lease);
        assert_eq!(got.is_ok(), t.valid, "{} -> {got:?}", t.token);
        if t.valid {
            let claims = got.expect("valid");
            assert_eq!(claims.version, 1);
            assert_eq!(claims.expires, 4_102_444_800);
            assert_eq!(
                m.verify(&t.token, &t.cohort, &t.task, &t.actor, t.lease + 1),
                Err(InvalidLease)
            );
        }
    }
}

/// Rust re-signs the Go claims to the identical token: same JSON bytes (Go's
/// HTML escaping included) and the same HMAC.
#[test]
fn rust_signing_matches_go_bytes() {
    let f: Fixture =
        serde_json::from_str(include_str!("testdata/go_lease_tokens.json")).expect("fixture");
    let m = LeaseSigner::new(hex::decode(&f.key_hex).expect("hex key"));
    for t in &f.tokens {
        let claims = m
            .verify_at(&t.token, &t.cohort, &t.task, &t.actor, t.lease, 0)
            .expect("decode");
        assert_eq!(m.sign(&claims).expect("sign"), t.token);
    }
}
