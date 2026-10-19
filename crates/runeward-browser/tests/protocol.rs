//! Ports of Go `internal/browser/protocol_test.go`, plus the exact bytes the
//! Go encoder writes.

use runeward_browser::protocol::decode;
use runeward_browser::{Command, CommandResult};

#[test]
fn command_round_trip() {
    let cmd = Command {
        action: "type".into(),
        token: "tok-123".into(),
        url: "https://example.com".into(),
        selector: "#login".into(),
        expr: "1+1".into(),
        text: "hunter2".into(),
        timeout_ms: 5000,
    };
    let back: Command = serde_json::from_slice(&cmd.to_json()).expect("decode");
    assert_eq!(back, cmd);
}

#[test]
fn command_omit_empty() {
    assert_eq!(Command::new("ping").to_json(), br#"{"action":"ping"}"#);
}

#[test]
fn result_round_trip() {
    for res in [
        CommandResult::value("hello"),
        CommandResult::err("boom"),
        CommandResult {
            ok: true,
            screenshot: "aGVsbG8=".into(),
            ..CommandResult::default()
        },
    ] {
        let back: CommandResult = serde_json::from_slice(&res.to_json()).expect("decode");
        assert_eq!(back, res);
    }
}

#[test]
fn result_error_omit_empty() {
    assert_eq!(CommandResult::ok().to_json(), br#"{"ok":true}"#);
}

/// Each line is what Go's `json.Encoder` wrote for the same value.
#[test]
fn wire_bytes_match_go() {
    let lines: Vec<&str> = include_str!("testdata/wire.jsonl").lines().collect();
    let commands = [
        Command::new("ping"),
        Command {
            action: "type".into(),
            token: "tok".into(),
            url: "https://example.com/?a=1&b=<2>".into(),
            selector: "#q".into(),
            expr: "1+1".into(),
            text: "hi\u{2028}".into(),
            timeout_ms: 5000,
        },
    ];
    let results = [
        CommandResult::ok(),
        CommandResult::err("boom & <bang>"),
        CommandResult {
            ok: true,
            value: "v".into(),
            screenshot: "aGVsbG8=".into(),
            ..CommandResult::default()
        },
    ];
    let mut got: Vec<Vec<u8>> = commands.iter().map(Command::to_json).collect();
    got.extend(results.iter().map(CommandResult::to_json));
    for (g, want) in got.iter().zip(&lines) {
        assert_eq!(String::from_utf8_lossy(g), *want);
        // And Go's bytes decode back to the same value.
    }
    for (line, cmd) in lines.iter().zip(&commands) {
        assert_eq!(&decode::<Command>(line.as_bytes()).expect("decode"), cmd);
    }
}

#[test]
fn decode_follows_go_rules() {
    // null fields and unknown keys are fine; null is the zero command.
    let c: Command = decode(br#"{"action":"eval","expr":null,"extra":1}"#).expect("decode");
    assert_eq!(c, Command::new("eval"));
    assert_eq!(
        decode::<Command>(b"null").expect("null"),
        Command::default()
    );
    // Only objects decode into a command.
    assert!(decode::<Command>(br#"["ping"]"#).is_err());
    assert!(decode::<Command>(br#""ping""#).is_err());
    assert!(decode::<Command>(br#"{"timeout_ms":1.5}"#).is_err());
}
