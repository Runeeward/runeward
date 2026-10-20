//! Byte-compatibility tests against fixtures written by the Go implementation
//! (`tools/golden`). Inputs below mirror that generator exactly.

use std::path::PathBuf;

use chrono::{FixedOffset, TimeZone, Utc};
use sha2::Digest as _;

use crate::evidence::{self, EvidenceError, Finding};
use crate::gotime::{self, Time};
use crate::ledger::{hash_event, hash_payload};
use crate::{Bundle, Event, Ledger, Signer, redact, scrub_string, verify_bundle};

fn golden_path(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../testdata/golden")
        .join(rel)
}

fn golden(rel: &str) -> Vec<u8> {
    std::fs::read(golden_path(rel)).unwrap_or_else(|e| panic!("read {rel}: {e}"))
}

fn golden_str(rel: &str) -> String {
    String::from_utf8(golden(rel)).expect("utf8 fixture")
}

fn at(secs: i64, nanos: i64) -> Time {
    let base = Utc
        .with_ymd_and_hms(2026, 10, 19, 12, 0, 0)
        .single()
        .expect("base time")
        .fixed_offset();
    base + chrono::Duration::seconds(secs) + chrono::Duration::nanoseconds(nanos)
}

fn golden_signer() -> Signer {
    let raw = golden("ledger/ledger.key");
    Signer::new(runeward_keys::private_from_bytes(&raw).expect("golden key"))
}

fn golden_public() -> ed25519_dalek::VerifyingKey {
    crate::decode_public_key(golden_str("ledger/ledger.pub").trim_end()).expect("decode pub")
}

/// The events `tools/golden` appends, before chain fields are assigned.
fn golden_inputs() -> Vec<Event> {
    let strs = |v: &[&str]| v.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
    let meta = |v: &[(&str, &str)]| {
        v.iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    };
    let wat = FixedOffset::east_opt(3600).expect("zone");
    let mut evs = vec![
        // Whole-second time: no fraction.
        Event {
            time: at(0, 0),
            session_id: "s-1".into(),
            sandbox: "cit-a".into(),
            profile: "quickstart".into(),
            tool: "shell".into(),
            action: "echo hi".into(),
            args: strs(&["echo", "hi"]),
            verdict: "allow".into(),
            duration_ms: 12,
            ..Event::default()
        },
        // Trailing fraction zeros stripped; meta keys sorted.
        Event {
            time: at(0, 120_000_000),
            session_id: "s-1".into(),
            sandbox: "cit-a".into(),
            profile: "quickstart".into(),
            tool: "shell".into(),
            action: "rm -rf /".into(),
            args: strs(&["rm", "-rf", "/"]),
            verdict: "deny".into(),
            exit_code: -1,
            meta: meta(&[
                ("reason", "destructive"),
                ("actor", "alice"),
                ("run_id", "run-1"),
            ]),
            ..Event::default()
        },
        // Full nanosecond precision and non-ASCII payloads.
        Event {
            time: at(1, 123_456_789),
            session_id: "s-2".into(),
            sandbox: "cit-b".into(),
            profile: "governed".into(),
            tool: "file".into(),
            action: "write café.txt".into(),
            verdict: "allow".into(),
            meta: meta(&[("bytes", "5"), ("path", "/work/café.txt")]),
            ..Event::default()
        },
        Event {
            time: at(2, 1000),
            session_id: "s-1".into(),
            sandbox: "cit-a".into(),
            profile: "quickstart".into(),
            tool: "egress".into(),
            action: "CONNECT api.github.com:443".into(),
            verdict: "require-approval".into(),
            duration_ms: 250,
            ..Event::default()
        },
        // Non-UTC time: JSON keeps the offset, the hash uses UTC.
        Event {
            time: at(3, 0).with_timezone(&wat),
            session_id: "s-2".into(),
            sandbox: "cit-b".into(),
            profile: "governed".into(),
            tool: "python".into(),
            action: "print(1)".into(),
            verdict: "allow".into(),
            exit_code: 3,
            duration_ms: 9_000_000_000,
            ..Event::default()
        },
        // Empty strings and an empty meta map.
        Event {
            time: at(4, 0),
            ..Event::default()
        },
    ];
    evs[3] = redact(evs[3].clone(), &[] as &[&str]);
    evs[4] = redact(evs[4].clone(), &["print(1)"]);
    evs
}

fn fixture_lines() -> Vec<String> {
    golden_str("ledger/ledger.jsonl")
        .lines()
        .map(str::to_owned)
        .collect()
}

#[test]
fn ledger_lines_rehash_and_reserialize_identically() {
    let signer = golden_signer();
    let lines = fixture_lines();
    assert_eq!(lines.len(), 6);
    let mut prev = String::new();
    for (i, line) in lines.iter().enumerate() {
        let ev: Event = serde_json::from_str(line).expect("parse line");
        assert_eq!(ev.seq, i as i64 + 1);
        assert_eq!(ev.prev_hash, prev);
        assert_eq!(hash_event(&ev), ev.hash, "hash of seq {}", ev.seq);
        assert_eq!(ev.key_id, signer.key_id());
        assert_eq!(signer.sign(&ev.hash), ev.sig, "sig of seq {}", ev.seq);
        let out = String::from_utf8(ev.to_json().expect("marshal")).expect("utf8");
        assert_eq!(&out, line, "re-serialized seq {}", ev.seq);
        prev = ev.hash;
    }
}

#[test]
fn payload_hashes_match_go_redaction() {
    let inputs = golden_inputs();
    for (input, line) in inputs.iter().zip(&fixture_lines()) {
        let ev: Event = serde_json::from_str(line).expect("parse line");
        assert_eq!(input.action, ev.action);
        assert_eq!(input.args, ev.args);
        assert_eq!(input.meta, ev.meta);
        assert_eq!(input.redacted, ev.redacted);
        assert_eq!(input.payload_hash, ev.payload_hash);
    }
    let original = Event {
        action: "print(1)".into(),
        ..Event::default()
    };
    assert_eq!(hash_payload(&original), inputs[4].payload_hash);
}

#[test]
fn golden_key_loads_and_matches_public_key() {
    let signer = golden_signer();
    let pub_line = golden_str("ledger/ledger.pub");
    assert_eq!(
        pub_line,
        format!("{}\n", runeward_keys::encode_public(&signer.public()))
    );
    assert_eq!(golden_public(), signer.public());
    assert_eq!(signer.key_id(), "0cca96cca04c8d2c");

    // The Go signer's on-disk layout loads unchanged.
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        dir.path().join(crate::KEY_FILE_NAME),
        golden("ledger/ledger.key"),
    )
    .expect("copy key");
    let loaded = Signer::load_or_create(dir.path()).expect("load");
    assert_eq!(loaded.public(), signer.public());
}

/// Writes the generator's events through [`Ledger::append`].
fn write_golden_ledger() -> (Ledger, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let l = Ledger::open(dir.path().join("ledger.jsonl")).expect("open");
    l.set_signer(Some(golden_signer()));
    for ev in golden_inputs() {
        l.append(ev).expect("append");
    }
    l.verify().expect("verify");
    (l, dir)
}

#[test]
fn append_writes_identical_bytes() {
    let (l, _dir) = write_golden_ledger();
    let written = std::fs::read(l.path()).expect("read ledger");
    assert_eq!(
        String::from_utf8(written).expect("utf8"),
        golden_str("ledger/ledger.jsonl")
    );
    l.verify_signatures(Some(&golden_public()), true)
        .expect("signatures");
}

#[test]
fn fixture_ledger_verifies_and_continues() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("ledger.jsonl");
    std::fs::write(&path, golden("ledger/ledger.jsonl")).expect("copy");
    let l = Ledger::open(&path).expect("open");
    l.verify().expect("verify");
    l.verify_signatures(Some(&golden_public()), true)
        .expect("signatures");
    let next = l.append(Event::default()).expect("append");
    assert_eq!(next.seq, 7);
    l.verify().expect("verify after append");
}

#[test]
fn bundles_export_verify_and_reserialize_identically() {
    let (l, _dir) = write_golden_ledger();
    let public = golden_public();
    for (session, rel, count) in [
        ("", "ledger/bundle-all.json", 6),
        ("s-1", "ledger/bundle-session-s-1.json", 3),
    ] {
        let want = golden_str(rel);
        let mut out = Vec::new();
        l.export_bundle(&mut out, session, &public).expect("export");
        assert_eq!(String::from_utf8(out).expect("utf8"), want, "{rel}");

        assert_eq!(
            verify_bundle(want.as_bytes()).expect("verify"),
            count,
            "{rel}"
        );
        let b: Bundle = serde_json::from_str(&want).expect("decode");
        let again = String::from_utf8(b.to_json_pretty().expect("encode")).expect("utf8");
        assert_eq!(again, want, "{rel}");
    }
}

#[test]
fn evidence_round_trips_and_verifies() {
    let want = golden_str("evidence.json");
    let doc = evidence::read(want.as_bytes()).expect("read");
    let mut out = Vec::new();
    evidence::write(&mut out, &doc).expect("write");
    assert_eq!(String::from_utf8(out).expect("utf8"), want);

    // The generator deliberately stores sha256("charter") rather than the
    // digest of `resolved`, so Go's Verify rejects the fixture as well.
    assert!(matches!(
        evidence::verify(&doc),
        Err(EvidenceError::PolicyHashMismatch)
    ));
    assert_eq!(doc.chronicle.verify().expect("chronicle"), 6);
    let mut fixed = doc.clone();
    fixed.policy.sha256 = hex::encode(sha2::Sha256::digest(fixed.policy.resolved.as_bytes()));
    assert_eq!(evidence::verify(&fixed).expect("verify"), 6);

    // Built from scratch the way the generator does.
    let bundle: Bundle = serde_json::from_slice(&golden("ledger/bundle-all.json")).expect("bundle");
    let mut built = evidence::new(
        "v0.0.0-golden",
        "quickstart",
        ".runeward/quickstart.toml",
        "ghcr.io/runewardd/sandbox:latest",
        "/abs/.runeward/quickstart.toml",
        vec![Finding {
            severity: "warning".into(),
            field: "network.default".into(),
            message: "egress is open".into(),
        }],
        bundle,
    );
    built.generated_at = at(5, 500_000_000);
    built.policy.sha256 = hex::encode(sha2::Sha256::digest(b"charter"));
    assert_eq!(built, doc);
}

#[test]
fn scrub_outputs_match() {
    #[derive(serde::Deserialize)]
    struct Case {
        #[serde(rename = "in")]
        input: String,
        #[serde(default)]
        sensitive: Vec<String>,
        out: String,
    }
    let cases: Vec<Case> = serde_json::from_slice(&golden("scrub.json")).expect("scrub.json");
    assert_eq!(cases.len(), 8);
    for c in cases {
        assert_eq!(scrub_string(&c.input, &c.sensitive), c.out, "{:?}", c.input);
    }
}

#[test]
fn hash_uses_utc_while_json_keeps_offset() {
    let ev: Event = serde_json::from_str(&fixture_lines()[4]).expect("parse");
    assert_eq!(
        gotime::format_rfc3339_nano(&ev.time),
        "2026-10-19T13:00:03+01:00"
    );
    assert_eq!(gotime::format_utc(&ev.time), "2026-10-19T12:00:03Z");
}
