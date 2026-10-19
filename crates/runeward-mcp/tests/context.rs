//! The context tools: fork, Cohort memory, notes, briefs, handoffs, child
//! tasks and self-service schedules.

#![allow(clippy::unwrap_used)]

mod support;

use std::sync::Arc;

use runeward_authz::Store;
use runeward_mcp::McpConfig;
use serde_json::json;
use support::{Client, Harness, is_error, json, principal, store, text};

fn team_store() -> Arc<Store> {
    let mut admin = principal("root", "ops", "token-root", &[]);
    admin.admin = true;
    store(vec![
        principal(
            "alice",
            "team-alpha",
            "token-alice",
            &["dev", "open", "crew", "self"],
        ),
        principal(
            "bob",
            "team-alpha",
            "token-bob",
            &["dev", "open", "crew", "self"],
        ),
        principal("eve", "team-other", "token-eve", &["dev", "crew"]),
        admin,
    ])
}

fn as_token(token: &str) -> McpConfig {
    McpConfig {
        default_token: token.into(),
        ..McpConfig::default()
    }
}

const LOCKED: &str = "[host]\ntype = \"container\"\nimage = \"ghcr.io/example/agent:1\"\n[network]\ndefault = \"deny\"\n";
const OPEN: &str = "[host]\ntype = \"container\"\nimage = \"ghcr.io/example/agent:1\"\n[network]\ndefault = \"allow\"\n";
const CREW: &str = "[host]\ntype = \"container\"\nimage = \"ghcr.io/example/agent:1\"\n[cohort]\nreplicas = 1\ntask_board = [\"migrate the billing database\"]\n";
const SELF: &str = "[host]\ntype = \"container\"\nimage = \"ghcr.io/example/agent:1\"\n[schedule]\nself_service = true\n";

#[tokio::test]
async fn fork_citadel_tool() {
    let h = Harness::new().await;
    h.write_charter("dev", LOCKED);
    h.write_charter("open", OPEN);
    let alice = Client::stdio(&h.mgr, Some(team_store()), as_token("token-alice")).await;
    let created = json(
        &alice
            .call("runeward_create_citadel", json!({"profile": "dev"}))
            .await,
    );
    let src = created["id"].as_str().unwrap().to_owned();
    let forked = alice
        .call("runeward_fork_citadel", json!({"sandbox": src}))
        .await;
    assert!(!is_error(&forked), "{}", text(&forked));
    let v = json(&forked);
    assert_eq!(v["forked_from"], src.as_str());
    assert_ne!(v["id"], src.as_str());

    let wider = alice
        .call(
            "runeward_fork_citadel",
            json!({"sandbox": src, "profile": "open"}),
        )
        .await;
    assert!(is_error(&wider), "{}", text(&wider));
    let root = Client::stdio(&h.mgr, Some(team_store()), as_token("token-root")).await;
    let ok = root
        .call(
            "runeward_fork_citadel",
            json!({"sandbox": src, "profile": "open"}),
        )
        .await;
    assert!(!is_error(&ok), "{}", text(&ok));

    let eve = Client::stdio(&h.mgr, Some(team_store()), as_token("token-eve")).await;
    let hidden = eve
        .call("runeward_fork_citadel", json!({"sandbox": src}))
        .await;
    assert_eq!(json(&hidden)["code"], "not_found");
}

#[tokio::test]
async fn memory_notes_briefs_and_handoffs() {
    let h = Harness::new().await;
    h.write_charter("crew", CREW);
    let alice = Client::stdio(&h.mgr, Some(team_store()), as_token("token-alice")).await;
    let bob = Client::stdio(&h.mgr, Some(team_store()), as_token("token-bob")).await;
    let eve = Client::stdio(&h.mgr, Some(team_store()), as_token("token-eve")).await;
    let fleet = json(
        &alice
            .call("runeward_create_cohort", json!({"profile": "crew"}))
            .await,
    )["id"]
        .as_str()
        .unwrap()
        .to_owned();

    let put = json(
        &alice
            .call(
                "runeward_memory_put",
                json!({"fleet": fleet, "key": "billing/db", "text": "postgres 16", "tags": ["database"], "expected_version": 0}),
            )
            .await,
    );
    assert_eq!(
        (put["version"].clone(), put["author"].clone()),
        (json!(1), json!("alice"))
    );
    let stale = bob
        .call(
            "runeward_memory_put",
            json!({"fleet": fleet, "key": "billing/db", "text": "x", "expected_version": 0}),
        )
        .await;
    assert!(is_error(&stale));
    assert!(text(&stale).contains("version 1"), "{}", text(&stale));
    let got = json(
        &bob.call(
            "runeward_memory_get",
            json!({"fleet": fleet, "key": "billing/db"}),
        )
        .await,
    );
    assert_eq!(got["text"], "postgres 16");
    let found = json(
        &bob.call(
            "runeward_memory_search",
            json!({"fleet": fleet, "query": "database"}),
        )
        .await,
    );
    assert_eq!(found["entries"][0]["key"], "billing/db");
    let hidden = eve
        .call(
            "runeward_memory_get",
            json!({"fleet": fleet, "key": "billing/db"}),
        )
        .await;
    assert_eq!(json(&hidden)["code"], "not_found");

    // Claims carry context; alice splits the task and hands it off.
    let claim = json(
        &alice
            .call("runeward_claim_task", json!({"fleet": fleet}))
            .await,
    );
    assert_eq!(claim["context"]["memory"][0]["key"], "billing/db");
    let parent = claim["task"]["id"].as_str().unwrap().to_owned();
    let lease = claim["task"]["lease_token"].as_str().unwrap().to_owned();
    let child = json(
        &alice
            .call(
                "runeward_add_child_task",
                json!({"fleet": fleet, "task": parent, "payload": "write the migration"}),
            )
            .await,
    );
    let child_id = child["id"].as_str().unwrap().to_owned();
    let brief = alice
        .call(
            "runeward_set_brief",
            json!({"fleet": fleet, "task": child_id, "agent": "bob", "brief": "keep downtime low"}),
        )
        .await;
    assert!(!is_error(&brief), "{}", text(&brief));
    let note = alice
        .call(
            "runeward_add_note",
            json!({"fleet": fleet, "task": child_id, "text": "watch the foreign keys"}),
        )
        .await;
    assert!(!is_error(&note), "{}", text(&note));
    let handed = json(
        &alice
            .call(
                "runeward_handoff",
                json!({"fleet": fleet, "task": parent, "lease_token": lease, "result": "planned", "note": "start with orders"}),
            )
            .await,
    );
    assert_eq!(handed["state"], "done");

    let next = json(
        &bob.call("runeward_claim_task", json!({"fleet": fleet}))
            .await,
    );
    assert_eq!(next["task"]["id"], child_id.as_str());
    assert_eq!(next["context"]["brief"], "keep downtime low");
    assert_eq!(next["context"]["parent"]["result"], "planned");
    let notes: Vec<&str> = next["context"]["handoff"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|n| n["text"].as_str())
        .collect();
    assert_eq!(notes, ["start with orders", "watch the foreign keys"]);

    // Bob gives it back with a note for the next agent.
    let back = json(
        &bob.call(
            "runeward_handoff",
            json!({"fleet": fleet, "task": child_id, "lease_token": next["task"]["lease_token"], "note": "half done, see branch wip", "requeue": true}),
        )
        .await,
    );
    assert_eq!(back["state"], "pending");
    let again = json(
        &alice
            .call("runeward_claim_task", json!({"fleet": fleet}))
            .await,
    );
    assert_eq!(again["task"]["id"], child_id.as_str());
    let last = again["context"]["handoff"]
        .as_array()
        .unwrap()
        .last()
        .unwrap()
        .clone();
    assert_eq!(
        (last["from"].clone(), last["text"].clone()),
        (json!("bob"), json!("half done, see branch wip"))
    );
}

#[tokio::test]
async fn schedules_need_the_charter_opt_in() {
    let h = Harness::new().await;
    h.write_charter("dev", LOCKED);
    h.write_charter("self", SELF);
    let alice = Client::stdio(&h.mgr, Some(team_store()), as_token("token-alice")).await;
    let dev = json(
        &alice
            .call("runeward_create_citadel", json!({"profile": "dev"}))
            .await,
    )["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let refused = alice
        .call(
            "runeward_schedule_create",
            json!({"sandbox": dev, "every": "1h", "command": ["agent"]}),
        )
        .await;
    assert!(is_error(&refused));
    assert_eq!(json(&refused)["code"], "authz_denied", "{}", text(&refused));

    let selfie = json(
        &alice
            .call("runeward_create_citadel", json!({"profile": "self"}))
            .await,
    )["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let made = alice
        .call(
            "runeward_schedule_create",
            json!({"sandbox": selfie, "cron": "*/30 * * * *", "command": ["agent"], "precheck": ["test", "-f", "todo"]}),
        )
        .await;
    assert!(!is_error(&made), "{}", text(&made));
    let sched = json(&made);
    assert_eq!(sched["self_service"], true);
    let bad = alice
        .call(
            "runeward_schedule_create",
            json!({"sandbox": selfie, "every": "5s", "command": ["agent"]}),
        )
        .await;
    assert!(is_error(&bad));

    let listed = json(
        &alice
            .call("runeward_schedule_list", json!({"sandbox": selfie}))
            .await,
    );
    assert_eq!(listed["schedules"].as_array().map(Vec::len), Some(1));
    let eve = Client::stdio(&h.mgr, Some(team_store()), as_token("token-eve")).await;
    let none = json(&eve.call("runeward_schedule_list", json!({})).await);
    assert_eq!(none["schedules"].as_array().map(Vec::len), Some(0));
    let hidden = eve
        .call("runeward_schedule_delete", json!({"schedule": sched["id"]}))
        .await;
    assert_eq!(json(&hidden)["code"], "not_found");

    let gone = alice
        .call("runeward_schedule_delete", json!({"schedule": sched["id"]}))
        .await;
    assert!(!is_error(&gone), "{}", text(&gone));
    assert!(h.mgr.list_schedules().is_empty());
}
