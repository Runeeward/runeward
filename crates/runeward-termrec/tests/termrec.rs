//! Ports of Go `internal/termrec/recorder_test.go`, plus byte-for-byte
//! comparison with casts the Go recorder wrote.

use std::io::{self, Write};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use chrono::{DateTime, TimeDelta, Utc};
use runeward_termrec::{Clock, Header, MAX_GAP, Recorder, ReplayError, replay, replay_with_sleep};

const BASE: i64 = 1_700_000_000;

fn base() -> DateTime<Utc> {
    DateTime::from_timestamp(BASE, 0).expect("base time")
}

/// A clock that advances by `step` on every call, starting at BASE.
fn ticking(step: TimeDelta) -> Clock {
    let mut tick = 0i32;
    Box::new(move || {
        let t = base() + step * tick;
        tick += 1;
        t
    })
}

/// Always fails, to prove recorder writes never propagate errors.
struct FailingWriter;

impl Write for FailingWriter {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("boom"))
    }
    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::other("boom"))
    }
}

#[test]
fn recorder_header_and_frames() {
    let mut rec = Recorder::new(Vec::new(), 120, 40).with_clock(ticking(TimeDelta::seconds(1)));
    let writes = ["hello ", "world\n", "second frame"];
    for w in writes {
        assert_eq!(rec.write(w.as_bytes()).expect("write"), w.len());
    }
    let buf = rec.finish().expect("close");
    let text = String::from_utf8(buf).expect("utf8");
    let lines: Vec<&str> = text.trim_end_matches('\n').split('\n').collect();
    assert_eq!(lines.len(), writes.len() + 1);

    let h: Header = serde_json::from_str(lines[0]).expect("header JSON");
    assert_eq!((h.version, h.width, h.height), (2, 120, 40));
    assert_eq!(h.timestamp, BASE);

    for (i, line) in lines[1..].iter().enumerate() {
        let frame: Vec<serde_json::Value> = serde_json::from_str(line).expect("frame JSON");
        assert_eq!(frame.len(), 3, "frame {i}");
        assert!(frame[0].is_number(), "frame {i} timestamp");
        assert_eq!(frame[1], "o", "frame {i} kind");
    }
}

#[test]
fn replay_dump_round_trip() {
    let rec = Recorder::new(Vec::new(), 80, 24).with_clock(ticking(TimeDelta::milliseconds(500)));
    let writes: [&[u8]; 4] = [
        b"\x1b[32mgreen\x1b[0m ",
        b"line1\n",
        "üñïçødé".as_bytes(),
        b"\x00\x01\x02",
    ];
    let mut want = Vec::new();
    for w in writes {
        want.extend_from_slice(w);
        assert_eq!(rec.record(w), w.len());
    }
    let cast = rec.finish().expect("close");

    let mut out = Vec::new();
    replay(cast.as_slice(), &mut out, false).expect("replay");
    assert_eq!(out, want);
}

#[test]
fn write_swallows_underlying_error() {
    let mut rec = Recorder::new(FailingWriter, 80, 24);
    // Large enough to force the buffer through to the failing writer.
    let big = vec![b'x'; 128 * 1024];
    assert_eq!(rec.write(&big).expect("write"), big.len());
    assert_eq!(rec.write(b"more").expect("second write"), 4);
    rec.flush().expect("flush swallows errors too");
    assert!(rec.close().is_err(), "close reports the failure");
}

/// The Go recorder's output for the same writes and clock, byte for byte:
/// number formatting, HTML-safe escapes, U+2028/2029, control characters
/// and per-byte replacement of invalid UTF-8.
#[test]
fn byte_identical_to_go() {
    let offsets = [
        TimeDelta::zero(),
        TimeDelta::zero(),
        TimeDelta::nanoseconds(1),
        TimeDelta::nanoseconds(1_234_567),
        TimeDelta::milliseconds(500),
        TimeDelta::seconds(1),
        TimeDelta::milliseconds(1500),
        TimeDelta::nanoseconds(3_333_333_333),
        TimeDelta::minutes(90),
        TimeDelta::seconds(-1),
    ];
    let mut i = 0usize;
    let rec = Recorder::new(Vec::new(), 80, 24).with_clock(Box::new(move || {
        let d = offsets[i % offsets.len()];
        i += 1;
        base() + d
    }));
    let writes: [&[u8]; 9] = [
        b"plain",
        b"<b>&amp;</b>",
        b"\x1b[32mgreen\x1b[0m\r\n",
        "üñïçødé".as_bytes(),
        b"\x00\x01\x08\x0c\t\x7f",
        b"bad \xe2\x82 utf8 \xff",
        "line\u{2028}sep\u{2029}".as_bytes(),
        b"\"quoted\" \\ slash",
        b"end",
    ];
    for w in writes {
        rec.record(w);
    }
    let got = rec.finish().expect("close");
    assert_eq!(
        String::from_utf8(got).expect("utf8"),
        include_str!("testdata/session.cast")
    );

    let empty = Recorder::new(Vec::new(), 100, 30).with_clock(Box::new(base));
    assert_eq!(
        String::from_utf8(empty.finish().expect("close")).expect("utf8"),
        include_str!("testdata/empty.cast")
    );
}

#[test]
fn concurrent_writes_are_whole_frames() {
    let rec = Arc::new(Recorder::new(Vec::new(), 80, 24));
    let handles: Vec<_> = (0..4)
        .map(|n| {
            let rec = Arc::clone(&rec);
            thread::spawn(move || {
                for i in 0..100 {
                    // One write per frame (write! may split into several).
                    let mut w = &*rec;
                    w.write_all(format!("worker{n}-{i};").as_bytes())
                        .expect("write");
                }
            })
        })
        .collect();
    for h in handles {
        h.join().expect("join");
    }
    let rec = Arc::into_inner(rec).expect("sole owner");
    let cast = rec.finish().expect("close");
    let text = String::from_utf8(cast).expect("utf8");
    assert_eq!(text.lines().count(), 401);
    for line in text.lines().skip(1) {
        let frame: (f64, String, String) = serde_json::from_str(line).expect("frame");
        assert!(frame.2.ends_with(';'), "{line}");
    }
}

#[test]
fn file_recorder_is_private() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("session.cast");
    let rec = Recorder::create(&path, 80, 24).expect("create");
    rec.record(b"hi");
    drop(rec.finish().expect("close"));
    let text = std::fs::read_to_string(&path).expect("read");
    assert!(text.ends_with("\"o\",\"hi\"]\n"), "{text}");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).expect("stat").permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}

#[test]
fn replay_realtime_caps_gaps() {
    let cast = "{\"version\":2,\"width\":80,\"height\":24,\"timestamp\":0}\r\n\
                \n\
                [0.5,\"o\",\"a\"]\n\
                [0.5,\"i\",\"typed\"]\n\
                [1,\"o\"]\n\
                [100,\"o\",\"b\"]\n\
                [99,\"o\",\"c\"]\n\
                [99.0000000001,\"o\",\"d\"]";
    let mut gaps = Vec::new();
    let mut out = Vec::new();
    let mut sleep = |d: Duration| gaps.push(d);
    replay_with_sleep(cast.as_bytes(), &mut out, Some(&mut sleep)).expect("replay");
    assert_eq!(out, b"abcd");
    assert_eq!(
        gaps,
        [Duration::from_millis(500), MAX_GAP],
        "negative and sub-nanosecond gaps do not sleep"
    );
}

#[test]
fn replay_errors_match_go() {
    let run = |s: &str| {
        let mut out = Vec::new();
        replay(s.as_bytes(), &mut out, false).map(|()| out)
    };
    assert!(matches!(run(""), Err(ReplayError::MissingHeader)));
    assert!(matches!(run("\n\n"), Err(ReplayError::MissingHeader)));
    assert_eq!(
        run("{\"version\":1}").expect_err("v1").to_string(),
        "termrec: unsupported cast version 1"
    );
    assert!(matches!(run("[2]"), Err(ReplayError::InvalidHeader(_))));
    assert!(matches!(run("nope"), Err(ReplayError::InvalidHeader(_))));
    assert!(matches!(
        run("{\"version\":2}\n{\"t\":1}"),
        Err(ReplayError::InvalidFrame(_))
    ));
    assert!(matches!(
        run("{\"version\":2}\n[\"x\",\"o\",\"d\"]"),
        Err(ReplayError::InvalidTimestamp(_))
    ));
    assert!(matches!(
        run("{\"version\":2}\n[1,2,\"d\"]"),
        Err(ReplayError::InvalidType(_))
    ));
    assert!(matches!(
        run("{\"version\":2}\n[1,\"o\",3]"),
        Err(ReplayError::InvalidData(_))
    ));
    // Short frames, null frames and null fields are skipped or zeroed, as Go
    // does.
    assert_eq!(
        run("{\"version\":2}\n[1,\"o\"]\nnull\n[null,\"o\",null]\n[1,\"o\",\"x\"]").expect("ok"),
        b"x"
    );
}

#[test]
fn replay_rejects_oversized_lines() {
    let mut cast = b"{\"version\":2}\n[0,\"o\",\"".to_vec();
    cast.resize(cast.len() + 16 * 1024 * 1024 + 1, b'x');
    let mut out = Vec::new();
    assert!(matches!(
        replay(cast.as_slice(), &mut out, false),
        Err(ReplayError::LineTooLong)
    ));
}
