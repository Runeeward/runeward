//! Ports of Go `internal/browser/cdp_test.go` against an in-test fake CDP
//! WebSocket server (no browser needed).

use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use runeward_browser::cdp::{CdpError, allow_private_from, stringify_value};
use runeward_browser::{Client, validate_navigate_url_with};
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;

/// Starts a fake CDP server; `reply` maps each request to the frames sent
/// back. Returns its ws:// URL.
async fn fake_cdp(reply: fn(&Value) -> Vec<Value>) -> String {
    let ln = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = ln.local_addr().expect("addr");
    tokio::spawn(async move {
        while let Ok((stream, _)) = ln.accept().await {
            tokio::spawn(async move {
                let Ok(mut ws) = tokio_tungstenite::accept_async(stream).await else {
                    return;
                };
                while let Some(Ok(msg)) = ws.next().await {
                    let Message::Text(t) = msg else { continue };
                    let Ok(req) = serde_json::from_str::<Value>(t.as_str()) else {
                        continue;
                    };
                    for frame in reply(&req) {
                        if ws.send(Message::text(frame.to_string())).await.is_err() {
                            return;
                        }
                    }
                }
            });
        }
    });
    format!("ws://{addr}")
}

/// Speaks just enough CDP to exercise the client.
fn standard(req: &Value) -> Vec<Value> {
    let id = &req["id"];
    match req["method"].as_str().unwrap_or_default() {
        "Page.navigate" => vec![
            json!({"id": id, "result": {"frameId": "frame-1"}}),
            json!({"method": "Page.loadEventFired", "params": {"timestamp": 1.0}}),
        ],
        "Runtime.evaluate" => {
            let expr = req["params"]["expression"].as_str().unwrap_or_default();
            let result =
                if expr.starts_with("!!document.querySelector") || expr.contains("el.click()") {
                    json!({"type": "boolean", "value": expr.contains("#present")})
                } else if expr == "null" {
                    json!({"type": "object", "subtype": "null", "value": null})
                } else if expr == "obj" {
                    json!({"type": "object", "value": {"a": 1, "b": [true, null]}})
                } else if expr == "undefined" {
                    json!({"type": "undefined"})
                } else {
                    json!({"type": "string", "value": "canned-value"})
                };
            vec![json!({"id": id, "result": {"result": result}})]
        }
        "Page.captureScreenshot" => vec![json!({"id": id, "result": {"data": "iVBORw0KGgo="}})],
        "Bad.method" => vec![
            json!({"id": id, "error": {"code": -32601, "message": "'Bad.method' wasn't found"}}),
        ],
        "Silent.method" => vec![],
        _ => vec![json!({"id": id, "result": {}})],
    }
}

async fn client() -> Client {
    let mut c = Client::dial(&fake_cdp(standard).await).await.expect("dial");
    c.set_call_timeout(Duration::from_secs(3));
    c
}

#[tokio::test]
async fn client_navigate_eval_text() {
    let c = client().await;
    c.navigate("http://example.com/", Duration::from_secs(2))
        .await
        .expect("navigate");
    assert_eq!(c.eval("1+1").await.expect("eval"), "canned-value");
    assert_eq!(c.text().await.expect("text"), "canned-value");
    assert_eq!(c.title().await.expect("title"), "canned-value");
    assert_eq!(c.html().await.expect("html"), "canned-value");
    assert_eq!(c.url().await.expect("url"), "canned-value");
    c.close().await;
}

#[tokio::test]
async fn eval_value_rendering() {
    let c = client().await;
    assert_eq!(c.eval("null").await.expect("null"), "null");
    assert_eq!(c.eval("undefined").await.expect("undefined"), "");
    assert_eq!(
        c.eval("obj").await.expect("obj"),
        r#"{"a":1,"b":[true,null]}"#
    );
}

#[tokio::test]
async fn client_eval_error() {
    fn throwing(req: &Value) -> Vec<Value> {
        vec![json!({
            "id": req["id"],
            "result": {
                "result": {"type": "object"},
                "exceptionDetails": {
                    "text": "Uncaught",
                    "exception": {"description": "ReferenceError: boom is not defined"},
                },
            },
        })]
    }
    let c = Client::dial(&fake_cdp(throwing).await).await.expect("dial");
    let err = c.eval("boom").await.expect_err("eval exception");
    assert_eq!(
        err.to_string(),
        "eval exception: ReferenceError: boom is not defined"
    );
}

#[tokio::test]
async fn screenshot_click_type_wait() {
    let c = client().await;
    assert_eq!(c.screenshot().await.expect("shot"), "iVBORw0KGgo=");
    c.click("#present").await.expect("click");
    assert_eq!(
        c.click("#missing").await.expect_err("missing").to_string(),
        "click: no element matches \"#missing\""
    );
    // The fake returns a string for type's snippet, which is not "true".
    assert!(c.type_text("#q", "it's \"quoted\"").await.is_err());
    c.wait_selector("#present", Duration::from_secs(1))
        .await
        .expect("wait");
    assert_eq!(
        c.wait_selector("#missing", Duration::from_millis(150))
            .await
            .expect_err("wait timeout")
            .to_string(),
        "wait: selector \"#missing\" not found within 150ms"
    );
}

#[tokio::test]
async fn remote_errors_and_timeouts() {
    let c = client().await;
    fn erroring(req: &Value) -> Vec<Value> {
        match req["method"].as_str().unwrap_or_default() {
            "Page.enable" => {
                vec![json!({"id": req["id"], "error": {"code": -32000, "message": "nope"}})]
            }
            _ => vec![],
        }
    }
    let mut bad = Client::dial(&fake_cdp(erroring).await).await.expect("dial");
    bad.set_call_timeout(Duration::from_millis(200));
    assert_eq!(
        bad.navigate("https://example.com", Duration::ZERO)
            .await
            .expect_err("remote error")
            .to_string(),
        "cdp Page.enable: nope (code -32000)"
    );
    assert_eq!(
        bad.eval("1").await.expect_err("timeout"),
        CdpError::Timeout {
            method: "Runtime.evaluate".into(),
            after: Duration::from_millis(200)
        }
    );
    assert_eq!(
        bad.eval("1").await.expect_err("timeout").to_string(),
        "cdp Runtime.evaluate: timeout after 200ms"
    );
    c.close().await;
    assert!(matches!(c.eval("1").await, Err(CdpError::Closed(_))));
}

#[tokio::test]
async fn navigate_load_timeout_is_not_fatal() {
    fn no_load_event(req: &Value) -> Vec<Value> {
        vec![json!({"id": req["id"], "result": {}})]
    }
    let c = Client::dial(&fake_cdp(no_load_event).await)
        .await
        .expect("dial");
    c.navigate("https://example.com", Duration::from_millis(100))
        .await
        .expect("load wait timeout is ignored");
}

#[tokio::test]
async fn server_disconnect_wakes_callers() {
    let ln = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = ln.local_addr().expect("addr");
    tokio::spawn(async move {
        let (stream, _) = ln.accept().await.expect("accept");
        let mut ws = tokio_tungstenite::accept_async(stream).await.expect("ws");
        let _ = ws.next().await;
        let _ = ws.close(None).await;
    });
    let c = Client::dial(&format!("ws://{addr}")).await.expect("dial");
    let err = c.eval("1").await.expect_err("closed");
    assert!(matches!(err, CdpError::Closed(_)), "{err}");
    assert!(
        err.to_string().starts_with("cdp connection closed"),
        "{err}"
    );
}

#[tokio::test]
async fn dial_failure() {
    let err = Client::dial("ws://127.0.0.1:1/devtools")
        .await
        .expect_err("refused");
    assert!(
        err.to_string()
            .starts_with("cdp dial ws://127.0.0.1:1/devtools: "),
        "{err}"
    );
}

#[test]
fn stringify_values() {
    let raw = |s: &str| serde_json::value::RawValue::from_string(s.to_owned()).expect("raw");
    for (typ, value, want) in [
        ("string", Some(raw(r#""hello""#)), "hello"),
        ("number", Some(raw("42")), "42"),
        ("boolean", Some(raw("true")), "true"),
        ("undefined", None, ""),
        ("object", Some(raw(r#"{"a":1}"#)), r#"{"a":1}"#),
        ("string", Some(raw("null")), ""),
    ] {
        assert_eq!(
            stringify_value(typ, value.as_deref()).expect("stringify"),
            want
        );
    }
}

#[test]
fn validate_navigate_urls() {
    for (url, ok) in [
        ("http://example.com", true),
        ("https://example.com", true),
        ("about:blank", true),
        ("  ABOUT:BLANK ", true),
        ("file:///etc/passwd", false),
        ("data:text/plain,boom", false),
        ("javascript:alert(1)", false),
        ("chrome://version", false),
        ("http://127.0.0.1:9222/json", false),
        ("http://localhost:8080", false),
        ("http://app.localhost", false),
        ("http://10.1.2.3", false),
        ("http://172.16.0.1", false),
        ("http://192.168.1.1", false),
        ("http://169.254.169.254/latest/meta-data", false),
        ("http://224.0.0.251", false),
        ("http://[::1]/", false),
        ("http://[fd00::1]/", false),
        ("http://[fe80::1]/", false),
        ("http://[ff02::1]/", false),
        ("http://[::ffff:127.0.0.1]/", false),
        ("http://8.8.8.8", true),
        ("http://[2001:db8::1]/", true),
        // WHATWG host parsing sees through numeric spellings of loopback.
        ("http://2130706433/", false),
        ("http://127.1/", false),
        ("", false),
        ("example.com", false),
        ("http://", false),
    ] {
        let got = validate_navigate_url_with(url, false);
        assert_eq!(got.is_ok(), ok, "{url:?}: {got:?}");
    }
    assert_eq!(
        validate_navigate_url_with("file:///x", false)
            .expect_err("file")
            .to_string(),
        "navigate: url scheme \"file\" is not allowed"
    );
    assert_eq!(
        validate_navigate_url_with("http://[::1]:9/", false)
            .expect_err("loopback")
            .to_string(),
        "navigate: target host \"::1\" is blocked"
    );
}

#[test]
fn validate_navigate_url_allows_private_when_enabled() {
    validate_navigate_url_with("http://127.0.0.1:9222/json", true).expect("override");
    assert!(validate_navigate_url_with("file:///etc/passwd", true).is_err());
    for v in ["1", "true", " YES ", "on"] {
        assert!(allow_private_from(Some(v)), "{v}");
    }
    for v in [None, Some(""), Some("0"), Some("off"), Some("maybe")] {
        assert!(!allow_private_from(v), "{v:?}");
    }
}
