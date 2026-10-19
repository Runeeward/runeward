//! Ports of Go `cmd/runeward-browser/main_test.go` and driver exchanges
//! over in-memory and real sockets.

use runeward_browser::driver::{
    Disposition, Driver, Network, listen_control, no_sandbox_from, read_json_value,
};
use runeward_browser::{Command, CommandResult};
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

#[test]
fn browser_no_sandbox_enabled() {
    // Unset or empty means on: containers usually lack the user namespaces
    // Chromium's own sandbox needs.
    assert!(no_sandbox_from(None));
    assert!(no_sandbox_from(Some("")));
    assert!(no_sandbox_from(Some("1")));
    for off in ["0", "false", "no", "off", " OFF "] {
        assert!(!no_sandbox_from(Some(off)), "{off}");
    }
}

#[tokio::test]
async fn listen_control_tcp() {
    let (ln, network) = listen_control("tcp://127.0.0.1:0").await.expect("listen");
    assert_eq!(network, Network::Tcp);
    assert!(ln.unix_path().is_none());
}

/// Sends `request` bytes to a fresh driver connection and returns the
/// decoded reply and the disposition.
async fn exchange(driver: &Driver, request: &[u8]) -> (CommandResult, Disposition) {
    let (mut client, mut server) = duplex(64 * 1024);
    let (disp, ()) = tokio::join!(driver.handle_conn(&mut server), async {
        client.write_all(request).await.expect("send");
        // Like `call`, half-close so truncated input reads as EOF.
        client.shutdown().await.expect("half-close");
    });
    drop(server);
    let mut reply = Vec::new();
    client.read_to_end(&mut reply).await.expect("read");
    assert_eq!(reply.last(), Some(&b'\n'), "json.Encoder framing");
    (serde_json::from_slice(&reply).expect("result JSON"), disp)
}

#[tokio::test]
async fn handle_conn_rejects_invalid_token() {
    let d = Driver::new(None, "shared-secret");
    let mut req = Command {
        token: "wrong".into(),
        ..Command::new("ping")
    }
    .to_json();
    req.push(b'\n');
    let (res, disp) = exchange(&d, &req).await;
    assert!(!res.ok);
    assert_eq!(res.error, "unauthorized control token");
    assert_eq!(disp, Disposition::Continue);
}

#[tokio::test]
async fn handle_conn_ping_and_close() {
    let d = Driver::new(None, "s");
    // The connection stays open after the command; the driver must not wait
    // for EOF.
    let (mut client, mut server) = duplex(1024);
    client
        .write_all(br#"  {"action":"ping","token":"s"} trailing"#)
        .await
        .expect("send");
    assert_eq!(d.handle_conn(&mut server).await, Disposition::Continue);
    drop(server);
    let mut reply = String::new();
    client.read_to_string(&mut reply).await.expect("read");
    assert_eq!(reply, "{\"ok\":true}\n");

    let (res, disp) = exchange(&d, br#"{"action":"close","token":"s"}"#).await;
    assert!(res.ok);
    assert_eq!(disp, Disposition::Shutdown);
}

#[tokio::test]
async fn handle_conn_without_token_and_bad_input() {
    let d = Driver::new(None, "");
    let (res, _) = exchange(&d, br#"{"action":"ping"}"#).await;
    assert!(res.ok);

    let (res, _) = exchange(&d, br#"{"action":"#).await;
    assert_eq!(res.error, "decode command: unexpected EOF");
    let (res, _) = exchange(&d, b"").await;
    assert_eq!(res.error, "decode command: EOF");
    let (res, _) = exchange(&d, br#"["ping"]"#).await;
    assert!(res.error.starts_with("decode command: "), "{}", res.error);
    let (res, _) = exchange(&d, br#"{"action":"dance"}"#).await;
    assert_eq!(res.error, "browser is not attached");
}

#[tokio::test]
async fn execute_validates_before_touching_the_browser() {
    let d = Driver::new(None, "");
    assert!(d.execute(&Command::new("ping")).await.ok);
    // Without a browser every other action reports it.
    assert_eq!(
        d.execute(&Command::new("navigate")).await.error,
        "browser is not attached"
    );
}

#[tokio::test]
async fn read_json_value_streams() {
    let (mut a, mut b) = duplex(16);
    let writer = tokio::spawn(async move {
        for part in [&b"{\"act"[..], b"ion\":", b"\"ping\"}", b"{\"next\":1}"] {
            a.write_all(part).await.expect("write");
        }
        a
    });
    let v = read_json_value(&mut b).await.expect("value");
    assert_eq!(v, serde_json::json!({"action": "ping"}));
    drop(writer.await.expect("join"));
}

#[cfg(unix)]
#[tokio::test]
async fn unix_socket_call_round_trip() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("ctl.sock");
    // A stale file at the path is replaced.
    std::fs::write(&path, b"stale").expect("stale");
    let sock = path.display().to_string();
    let (ln, network) = listen_control(&format!("unix://{sock}"))
        .await
        .expect("listen");
    assert_eq!(network, Network::Unix);
    assert_eq!(ln.unix_path(), Some(path.as_path()));

    let server = tokio::spawn(async move {
        let d = Driver::new(None, "tok");
        loop {
            let mut conn = ln.accept().await.expect("accept");
            if d.handle_conn(&mut *conn).await == Disposition::Shutdown {
                return;
            }
        }
    });

    let run = |args: Vec<String>, stdin: &'static [u8]| async move {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let code = runeward_browser::cli::call(&args, stdin, &mut out, &mut err).await;
        (
            code,
            String::from_utf8(out).expect("utf8"),
            String::from_utf8(err).expect("utf8"),
        )
    };
    let args = |extra: &[&str]| {
        let mut v = vec!["-socket".to_owned(), sock.clone()];
        v.extend(extra.iter().map(|s| (*s).to_owned()));
        v
    };

    let (code, out, _) = run(
        args(&["--token=tok", "--json", r#"{"action":"ping"}"#]),
        b"",
    )
    .await;
    assert_eq!((code, out.as_str()), (0, "{\"ok\":true}\n"));

    let (code, out, err) = run(args(&["-token", "bad"]), br#"{"action":"ping"}"#).await;
    assert_eq!(code, 1);
    assert_eq!(
        out,
        "{\"ok\":false,\"error\":\"unauthorized control token\"}\n"
    );
    assert_eq!(err, "unauthorized control token\n");

    // A token inside the JSON wins over the flag.
    let (code, _, _) = run(
        args(&[
            "-token",
            "bad",
            "-json",
            r#"{"action":"ping","token":"tok"}"#,
        ]),
        b"",
    )
    .await;
    assert_eq!(code, 0);

    let (code, _, err) = run(args(&["-json", "{"]), b"").await;
    assert_eq!(code, 2);
    assert!(err.starts_with("call: invalid command JSON: "), "{err}");

    let (code, _, err) = run(vec![], b"").await;
    assert_eq!((code, err.as_str()), (2, "call: --socket is required\n"));

    let (code, _, err) = run(vec!["-bogus".into()], b"").await;
    assert_eq!(code, 2);
    assert!(
        err.starts_with("flag provided but not defined: -bogus\nUsage of call:"),
        "{err}"
    );

    let (code, _, _) = run(
        args(&["-token", "tok", "-json", r#"{"action":"close"}"#]),
        b"",
    )
    .await;
    assert_eq!(code, 0);
    server.await.expect("driver shut down on close");

    let missing = dir.path().join("missing.sock").display().to_string();
    let (code, _, err) = run(
        vec![
            "-socket".into(),
            missing.clone(),
            "-json".into(),
            "{}".into(),
        ],
        b"",
    )
    .await;
    assert_eq!(code, 2);
    assert!(err.starts_with(&format!("call: dial {missing}: ")), "{err}");
}
