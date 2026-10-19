//! REST surface for keeping context: sleep/wake, fork, agent turns, Cohort
//! memory and handoffs, and schedules.

use std::time::Duration;

use axum::Router;
use serde_json::{Value, json};

use super::support::{Harness, call, get, harness_with, post, router_with_rbac, server};

const PERSISTENT: &str = r#"
[host]
type = "container"
image = "debian:stable-slim"

[workspace]
persist = true
idle_timeout = "15m"
"#;

const OPEN: &str = r#"
[host]
type = "container"
image = "debian:stable-slim"

[network]
default = "allow"
"#;

const LOCKED: &str = r#"
[host]
type = "container"
image = "debian:stable-slim"

[network]
default = "deny"
"#;

const COHORT: &str = r#"
[host]
type = "container"
image = "debian:stable-slim"

[cohort]
replicas = 1
task_board = ["migrate the billing database"]
"#;

async fn with_charters(charters: &[(&str, &str)]) -> Harness {
    let charters: Vec<(String, String)> = charters
        .iter()
        .map(|(n, b)| ((*n).to_owned(), (*b).to_owned()))
        .collect();
    harness_with(
        |_| {},
        move |dir| {
            for (name, body) in &charters {
                std::fs::write(dir.join("charters").join(format!("{name}.toml")), body)
                    .expect("write charter");
            }
        },
    )
    .await
}

async fn wait_finished(r: &Router, id: &str, token: Option<&str>) -> Value {
    for _ in 0..2000 {
        let v = get(r, &format!("/v1/agent-sessions/{id}"), token)
            .await
            .json();
        if !matches!(v["status"].as_str(), Some("queued" | "running")) {
            return v;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("agent session {id} never finished");
}

#[tokio::test]
async fn citadels_sleep_wake_and_report_their_workspace() {
    let h = with_charters(&[("ws", PERSISTENT), ("plain", OPEN)]).await;
    let r = server(&h).router();
    let created = post(&r, "/v1/citadels", None, r#"{"profile":"ws"}"#).await;
    assert_eq!(created.status, 201, "{}", created.text());

    let slept = post(&r, "/v1/citadels/fake-1/sleep", None, "").await;
    assert_eq!(slept.status, 200, "{}", slept.text());
    assert_eq!(slept.json(), json!({"ok": true, "slept": true}));
    let got = get(&r, "/v1/citadels/fake-1", None).await.json();
    assert_eq!(got["status"], "sleeping");
    assert_eq!(got["workspace"]["state"], "sleeping");
    assert_eq!(got["workspace"]["idle_timeout_secs"], 900);
    let listed = get(&r, "/v1/citadels", None).await.json();
    assert_eq!(listed["sandboxes"][0]["status"], "sleeping");

    // A governed call wakes it.
    let ran = post(
        &r,
        "/v1/citadels/fake-1/shell/exec",
        None,
        r#"{"command":["echo","hi"]}"#,
    )
    .await;
    assert_eq!(ran.status, 200, "{}", ran.text());
    let st = get(&r, "/v1/citadels/fake-1/workspace/status", None)
        .await
        .json();
    assert_eq!(st["state"], "running");
    assert!(st["woke_at"].is_string(), "{st}");

    post(&r, "/v1/citadels/fake-1/sleep", None, "").await;
    let woke = post(&r, "/v1/citadels/fake-1/wake", None, "").await;
    assert_eq!(woke.json(), json!({"ok": true}));

    // A plain Citadel cannot sleep.
    call(&r, "DELETE", "/v1/citadels/fake-1", None, None).await;
    post(&r, "/v1/citadels", None, r#"{"profile":"plain"}"#).await;
    let refused = post(&r, "/v1/citadels/fake-1/sleep", None, "").await;
    assert_eq!(refused.status, 400, "{}", refused.text());
    assert_eq!(
        get(&r, "/v1/citadels/fake-1/workspace/status", None)
            .await
            .status,
        404
    );
}

#[tokio::test]
async fn fork_creates_an_independent_citadel_and_guards_widening() {
    let h = with_charters(&[("team-locked", LOCKED), ("team-open", OPEN)]).await;
    h.inject("fake-1", "team-locked", "team-alpha").await;
    let r = router_with_rbac(&h);
    let alice = Some("tok-alice");

    let forked = post(&r, "/v1/citadels/fake-1/fork", alice, "").await;
    assert_eq!(forked.status, 201, "{}", forked.text());
    let v = forked.json();
    assert_eq!(v["forked_from"], "fake-1");
    assert_eq!(v["owner"], "team-alpha");
    let fork_id = v["id"].as_str().expect("id").to_owned();
    assert_ne!(fork_id, "fake-1");
    let runs = get(&r, "/v1/runs", alice).await.json();
    assert!(
        runs["runs"]
            .as_array()
            .expect("runs")
            .iter()
            .any(|run| run["citadel_id"] == fork_id.as_str()),
        "{runs}"
    );

    // Wider egress needs an administrator; other tenants never see it.
    let wider = post(
        &r,
        "/v1/citadels/fake-1/fork",
        alice,
        r#"{"profile":"team-open"}"#,
    )
    .await;
    assert_eq!(wider.status, 403, "{}", wider.text());
    let admin = post(
        &r,
        "/v1/citadels/fake-1/fork",
        Some("tok-admin"),
        r#"{"profile":"team-open"}"#,
    )
    .await;
    assert_eq!(admin.status, 201, "{}", admin.text());
    let eve = post(&r, "/v1/citadels/fake-1/fork", Some("tok-eve"), "").await;
    assert_eq!(eve.status, 404);
}

#[tokio::test]
async fn agent_sessions_take_turns_cancel_and_replay() {
    let h = with_charters(&[("ws", PERSISTENT)]).await;
    let r = server(&h).router();
    post(&r, "/v1/citadels", None, r#"{"profile":"ws"}"#).await;
    let started = post(
        &r,
        "/v1/citadels/fake-1/agent-sessions",
        None,
        r#"{"command":["agent","one"]}"#,
    )
    .await;
    assert_eq!(started.status, 202, "{}", started.text());
    let id = started.json()["id"].as_str().expect("id").to_owned();
    let first = wait_finished(&r, &id, None).await;
    assert_eq!(first["status"], "completed");
    let after = first["last_seq"].as_i64().expect("seq");

    // The next turn runs while the Citadel sleeps in between.
    post(&r, "/v1/citadels/fake-1/sleep", None, "").await;
    let turn = post(
        &r,
        &format!("/v1/agent-sessions/{id}/turns"),
        None,
        r#"{"command":["slow","two"]}"#,
    )
    .await;
    assert_eq!(turn.status, 202, "{}", turn.text());
    assert_eq!(turn.json()["turn"], 2);
    let busy = post(
        &r,
        &format!("/v1/agent-sessions/{id}/turns"),
        None,
        r#"{"command":["agent","three"]}"#,
    )
    .await;
    assert_eq!(busy.status, 409, "{}", busy.text());
    assert_eq!(busy.json()["code"], "session_busy");
    let busy_start = post(
        &r,
        "/v1/citadels/fake-1/agent-sessions",
        None,
        &format!(r#"{{"command":["agent"],"session_id":"{id}"}}"#),
    )
    .await;
    assert_eq!(busy_start.status, 409, "{}", busy_start.text());

    let canceled = post(&r, &format!("/v1/agent-sessions/{id}/cancel"), None, "").await;
    assert_eq!(canceled.status, 200, "{}", canceled.text());
    assert_eq!(canceled.json(), json!({"canceled": true}));
    assert_eq!(wait_finished(&r, &id, None).await["status"], "canceled");

    // The stream replays exactly the events after the cursor and ends.
    let stream = get(
        &r,
        &format!("/v1/agent-sessions/{id}/stream?after={after}"),
        None,
    )
    .await;
    assert_eq!(stream.status, 200);
    let body = stream.text();
    assert!(body.contains(&format!("id: {}\n", after + 1)), "{body}");
    assert!(!body.contains(&format!("id: {after}\n")), "{body}");
    assert!(body.contains("\"stream\":\"turn\""), "{body}");

    assert_eq!(
        post(
            &r,
            "/v1/agent-sessions/0123/turns",
            None,
            r#"{"command":["x"]}"#
        )
        .await
        .status,
        404
    );
}

#[tokio::test]
async fn cohort_memory_handoffs_and_context_over_rest() {
    let h = with_charters(&[("team-crew", COHORT)]).await;
    let r = router_with_rbac(&h);
    let alice = Some("tok-alice");
    let created = post(&r, "/v1/cohorts", alice, r#"{"profile":"team-crew"}"#).await;
    assert_eq!(created.status, 201, "{}", created.text());
    let cohort = created.json()["id"].as_str().expect("id").to_owned();
    let base = format!("/v1/cohorts/{cohort}");

    let put = post(
        &r,
        &format!("{base}/memory"),
        alice,
        r#"{"key":"billing/db","text":"postgres 16","tags":["database"],"expected_version":0}"#,
    )
    .await;
    assert_eq!(put.status, 200, "{}", put.text());
    assert_eq!(
        (put.json()["version"].clone(), put.json()["author"].clone()),
        (json!(1), json!("alice"))
    );
    let stale = post(
        &r,
        &format!("{base}/memory"),
        Some("tok-bob"),
        r#"{"key":"billing/db","text":"mysql","expected_version":0}"#,
    )
    .await;
    assert_eq!(stale.status, 409);
    assert_eq!(stale.json()["code"], "version_conflict");
    let one = get(&r, &format!("{base}/memory/billing/db"), alice).await;
    assert_eq!(one.json()["text"], "postgres 16");
    let found = get(&r, &format!("{base}/memory?query=database"), alice)
        .await
        .json();
    assert_eq!(found["entries"][0]["key"], "billing/db");
    // Another tenant sees nothing.
    assert_eq!(
        get(&r, &format!("{base}/memory"), Some("tok-eve"))
            .await
            .status,
        404
    );

    // Claim with context, split, brief, hand off.
    let claim = post(&r, &format!("{base}/claim"), alice, r#"{"context":true}"#)
        .await
        .json();
    assert_eq!(claim["claimed"], true);
    assert_eq!(claim["context"]["memory"][0]["key"], "billing/db");
    let parent = claim["task"]["id"].as_str().expect("task").to_owned();
    let lease = claim["task"]["lease_token"]
        .as_str()
        .expect("lease")
        .to_owned();
    let child = post(
        &r,
        &format!("{base}/tasks/{parent}/children"),
        alice,
        r#"{"payload":"write the migration"}"#,
    )
    .await;
    assert_eq!(child.status, 201, "{}", child.text());
    let child_id = child.json()["id"].as_str().expect("child").to_owned();
    let brief = call(
        &r,
        "PUT",
        &format!("{base}/tasks/{child_id}/brief"),
        alice,
        Some(r#"{"agent":"bob","brief":"keep downtime low"}"#),
    )
    .await;
    assert_eq!(brief.status, 200, "{}", brief.text());
    let note = post(
        &r,
        &format!("{base}/tasks/{child_id}/notes"),
        alice,
        r#"{"text":"watch the foreign keys"}"#,
    )
    .await;
    assert_eq!(note.status, 201, "{}", note.text());
    let done = post(
        &r,
        &format!("{base}/tasks/{parent}/complete"),
        alice,
        &format!(r#"{{"lease_token":"{lease}","result":"planned","handoff":"start with orders"}}"#),
    )
    .await;
    assert_eq!(done.status, 200, "{}", done.text());

    let next = post(
        &r,
        &format!("{base}/claim"),
        Some("tok-bob"),
        r#"{"context":true}"#,
    )
    .await
    .json();
    assert_eq!(next["task"]["id"], child_id.as_str());
    let ctx = &next["context"];
    assert_eq!(ctx["brief"], "keep downtime low");
    assert_eq!(ctx["parent"]["result"], "planned");
    let notes: Vec<&str> = ctx["handoff"]
        .as_array()
        .expect("handoff")
        .iter()
        .filter_map(|n| n["text"].as_str())
        .collect();
    assert_eq!(notes, ["start with orders", "watch the foreign keys"]);
    let viewed = get(
        &r,
        &format!("{base}/tasks/{child_id}/context?agent=bob"),
        alice,
    )
    .await
    .json();
    assert_eq!(viewed["context"]["brief"], "keep downtime low");

    let deleted = call(
        &r,
        "DELETE",
        &format!("{base}/memory/billing/db?version=1"),
        alice,
        None,
    )
    .await;
    assert_eq!(deleted.json(), json!({"deleted": true}));
}

#[tokio::test]
async fn schedules_over_rest_are_tenant_scoped() {
    let h = with_charters(&[("team-ws", PERSISTENT)]).await;
    let r = router_with_rbac(&h);
    let alice = Some("tok-alice");
    let created = post(&r, "/v1/citadels", alice, r#"{"profile":"team-ws"}"#).await;
    assert_eq!(created.status, 201, "{}", created.text());

    let bad = post(
        &r,
        "/v1/citadels/fake-1/schedules",
        alice,
        r#"{"every":"10s","command":["agent"]}"#,
    )
    .await;
    assert_eq!(bad.status, 400, "{}", bad.text());
    let made = post(
        &r,
        "/v1/citadels/fake-1/schedules",
        alice,
        r#"{"cron":"0 * * * *","command":["agent"],"prompt":"check the queue","precheck":["true"]}"#,
    )
    .await;
    assert_eq!(made.status, 201, "{}", made.text());
    let sid = made.json()["id"].as_str().expect("id").to_owned();
    assert_eq!(made.json()["owner"], "team-alpha");
    assert_eq!(made.json()["actor"], "alice");

    let mine = get(&r, "/v1/citadels/fake-1/schedules", alice).await.json();
    assert_eq!(mine["schedules"].as_array().map(Vec::len), Some(1));
    assert_eq!(
        get(&r, "/v1/schedules", alice).await.json()["schedules"]
            .as_array()
            .map(Vec::len),
        Some(1)
    );
    assert_eq!(
        get(&r, "/v1/schedules", Some("tok-eve")).await.json()["schedules"]
            .as_array()
            .map(Vec::len),
        Some(0)
    );
    assert_eq!(
        get(&r, &format!("/v1/schedules/{sid}"), Some("tok-eve"))
            .await
            .status,
        404
    );
    assert_eq!(
        get(&r, "/v1/citadels/fake-1/schedules", Some("tok-eve"))
            .await
            .status,
        404
    );

    let fired = post(&r, &format!("/v1/schedules/{sid}/run"), alice, "").await;
    assert_eq!(fired.status, 200, "{}", fired.text());
    assert_eq!(fired.json()["outcome"], "started");
    let session = fired.json()["session_id"]
        .as_str()
        .expect("session")
        .to_owned();
    let a = wait_finished(&r, &session, alice).await;
    assert_eq!(a["command"], json!(["agent", "check the queue"]));

    let gone = call(&r, "DELETE", &format!("/v1/schedules/{sid}"), alice, None).await;
    assert_eq!(gone.status, 200);
    assert_eq!(
        get(&r, &format!("/v1/schedules/{sid}"), alice).await.status,
        404
    );
}
