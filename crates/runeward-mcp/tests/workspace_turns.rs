//! The workspace and agent-turn tools: sleep, wake and workspace status;
//! start a turn, cancel it and read the bounded transcript.

#![allow(clippy::unwrap_used)]

mod support;

use std::sync::Arc;
use std::time::Duration;

use runeward_authz::Store;
use runeward_mcp::McpConfig;
use serde_json::{Value, json};
use support::{Client, Harness, is_error, json, principal, store, text};

const PERSISTENT: &str = "[host]\ntype = \"container\"\nimage = \"ghcr.io/example/agent:1\"\n[workspace]\npersist = true\nidle_timeout = \"15m\"\n";

fn team_store() -> Arc<Store> {
    store(vec![
        principal("alice", "team-alpha", "token-alice", &["keep"]),
        principal("eve", "team-other", "token-eve", &["keep"]),
    ])
}

fn as_token(token: &str) -> McpConfig {
    McpConfig {
        default_token: token.into(),
        ..McpConfig::default()
    }
}

async fn finished(c: &Client, session: &str) -> Value {
    for _ in 0..2000 {
        let v = json(
            &c.call("runeward_session_events", json!({"session": session}))
                .await,
        );
        let status = v["session"]["status"].as_str().unwrap_or_default();
        if !matches!(status, "queued" | "running") {
            return v;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("agent session {session} never finished");
}

#[tokio::test]
async fn sleep_wake_and_status() {
    let h = Harness::new().await;
    h.write_charter("keep", PERSISTENT);
    let alice = Client::stdio(&h.mgr, Some(team_store()), as_token("token-alice")).await;
    let id = json(
        &alice
            .call("runeward_create_citadel", json!({"profile": "keep"}))
            .await,
    )["id"]
        .as_str()
        .unwrap()
        .to_owned();

    let st = json(
        &alice
            .call("runeward_workspace_status", json!({"sandbox": id}))
            .await,
    );
    assert_eq!(st["state"], "running", "{st}");
    assert_eq!(st["idle_timeout_secs"], 900);

    let slept = alice
        .call("runeward_sleep_citadel", json!({"sandbox": id}))
        .await;
    assert!(!is_error(&slept), "{}", text(&slept));
    assert_eq!(json(&slept)["slept"], true);
    let st = json(
        &alice
            .call("runeward_workspace_status", json!({"sandbox": id}))
            .await,
    );
    assert_eq!(st["state"], "sleeping", "{st}");

    let woke = alice
        .call("runeward_wake_citadel", json!({"sandbox": id}))
        .await;
    assert!(!is_error(&woke), "{}", text(&woke));
    let st = json(
        &alice
            .call("runeward_workspace_status", json!({"sandbox": id}))
            .await,
    );
    assert_eq!(st["state"], "running", "{st}");

    // Another tenant sees nothing.
    let eve = Client::stdio(&h.mgr, Some(team_store()), as_token("token-eve")).await;
    for tool in [
        "runeward_sleep_citadel",
        "runeward_wake_citadel",
        "runeward_workspace_status",
    ] {
        let hidden = eve.call(tool, json!({"sandbox": id})).await;
        assert_eq!(json(&hidden)["code"], "not_found", "{tool}");
    }
}

#[tokio::test]
async fn turns_cancel_and_bounded_events() {
    let h = Harness::new().await;
    h.write_charter("keep", PERSISTENT);
    let alice = Client::stdio(&h.mgr, Some(team_store()), as_token("token-alice")).await;
    let id = json(
        &alice
            .call("runeward_create_citadel", json!({"profile": "keep"}))
            .await,
    )["id"]
        .as_str()
        .unwrap()
        .to_owned();

    let both = alice
        .call(
            "runeward_start_turn",
            json!({"sandbox": id, "session": "x", "command": ["echo", "hi"]}),
        )
        .await;
    assert!(is_error(&both));

    let started = alice
        .call(
            "runeward_start_turn",
            json!({"sandbox": id, "command": ["echo", "first"], "agent": "codex"}),
        )
        .await;
    assert!(!is_error(&started), "{}", text(&started));
    let session = json(&started)["id"].as_str().unwrap().to_owned();
    let done = finished(&alice, &session).await;
    assert_eq!(done["session"]["status"], "completed", "{done}");
    let first_cursor = done["next_after"].as_i64().unwrap();
    assert!(first_cursor > 0);
    assert!(
        done["events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["stream"] == "status" && e["data"] == "completed"),
        "{done}"
    );

    // The next turn continues the same transcript.
    let next = alice
        .call(
            "runeward_start_turn",
            json!({"session": session, "command": ["echo", "second"]}),
        )
        .await;
    assert!(!is_error(&next), "{}", text(&next));
    finished(&alice, &session).await;
    let tail = json(
        &alice
            .call(
                "runeward_session_events",
                json!({"session": session, "after": first_cursor}),
            )
            .await,
    );
    let events = tail["events"].as_array().unwrap();
    assert!(!events.is_empty(), "{tail}");
    assert!(
        events
            .iter()
            .all(|e| e["seq"].as_i64().unwrap() > first_cursor)
    );
    assert_eq!(tail["session"]["command"], json!(["echo", "second"]));

    // Bounded: one event per page, with a cursor to continue.
    let page = json(
        &alice
            .call(
                "runeward_session_events",
                json!({"session": session, "limit": 1}),
            )
            .await,
    );
    assert_eq!(page["events"].as_array().unwrap().len(), 1);
    assert_eq!(page["more"], true);
    assert_eq!(page["next_after"], page["events"][0]["seq"]);

    // Nothing is running, so cancel reports false.
    let canceled = json(
        &alice
            .call("runeward_cancel_turn", json!({"session": session}))
            .await,
    );
    assert_eq!(canceled["canceled"], false);

    let eve = Client::stdio(&h.mgr, Some(team_store()), as_token("token-eve")).await;
    for (tool, args) in [
        ("runeward_cancel_turn", json!({"session": session})),
        ("runeward_session_events", json!({"session": session})),
        (
            "runeward_start_turn",
            json!({"session": session, "command": ["echo"]}),
        ),
    ] {
        let hidden = eve.call(tool, args).await;
        assert_eq!(json(&hidden)["code"], "not_found", "{tool}");
    }
}
