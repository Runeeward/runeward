//! Tool behaviour over the stdio semantics (in-process transport): RBAC
//! tenancy, actor attribution, isolation tiers, approvals and the
//! tool-list digest.

#![allow(clippy::unwrap_used)]

mod support;

use std::sync::Arc;

use runeward_authz::Store;
use runeward_charter::Verdict;
use runeward_mcp::{McpConfig, canonical_json, tool_list_digest};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use support::{BASIC_CHARTER, Client, Harness, is_error, json, principal, rule, store, text};

fn team_store() -> Arc<Store> {
    let mut admin = principal("root", "ops", "token-root", &[]);
    admin.admin = true;
    store(vec![
        principal("alice", "team-alpha", "token-alice", &["dev", "test"]),
        principal("bob", "team-alpha", "token-bob", &["dev"]),
        principal("eve", "team-other", "token-eve", &["dev", "test"]),
        admin,
    ])
}

fn as_token(token: &str) -> McpConfig {
    McpConfig {
        default_token: token.into(),
        ..McpConfig::default()
    }
}

/// Port of Go's `TestCohortToolsEnforcePrincipalOwnership`.
#[tokio::test]
async fn cohort_tools_enforce_principal_ownership() {
    for (token, want_err) in [
        ("token-alice", false),
        ("token-bob", false),
        ("token-eve", true),
        ("token-root", false),
    ] {
        let h = Harness::with(
            |dir| {
                std::fs::write(
                    dir.join("state/fleets.json"),
                    r#"[{"id":"fleet-a","profile":"dev","owner":"team-alpha","sandboxes":[],"tasks":[]}]"#,
                )
                .unwrap();
            },
            |_| {},
        )
        .await;
        let c = Client::stdio(&h.mgr, Some(team_store()), as_token(token)).await;
        let res = c
            .call("runeward_list_tasks", json!({"fleet": "fleet-a"}))
            .await;
        assert_eq!(is_error(&res), want_err, "{token}: {}", text(&res));
        let listed = json(&c.call("runeward_list_cohorts", json!({})).await);
        assert_eq!(
            listed["cohorts"].as_array().unwrap().len(),
            usize::from(!want_err),
            "{token}"
        );
        if want_err {
            assert_eq!(
                json(&res),
                json!({"code": "not_found", "error": "cohort not found"})
            );
        }
    }
}

#[tokio::test]
async fn citadels_are_tenant_scoped() {
    let h = Harness::new().await;
    h.inject("cit-a", "team-alpha", vec![]);
    h.inject("cit-o", "team-other", vec![]);
    let alice = Client::stdio(&h.mgr, Some(team_store()), as_token("token-alice")).await;
    let ids = |v: Value| -> Vec<String> {
        v["citadels"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["id"].as_str().unwrap().to_owned())
            .collect()
    };
    let listed = json(&alice.call("runeward_list_citadels", json!({})).await);
    assert_eq!(ids(listed.clone()), vec!["cit-a"]);
    assert_eq!(listed["citadels"][0]["isolation"], "container");
    assert_eq!(listed["citadels"][0]["owner"], "team-alpha");

    let res = alice
        .call(
            "runeward_shell",
            json!({"sandbox": "cit-o", "command": ["id"]}),
        )
        .await;
    assert!(is_error(&res));
    assert_eq!(
        json(&res),
        json!({"code": "not_found", "error": "citadel not found"})
    );
    let res = alice
        .call(
            "runeward_shell",
            json!({"sandbox": "cit-a", "command": ["id"]}),
        )
        .await;
    assert!(!is_error(&res), "{}", text(&res));

    let root = Client::stdio(&h.mgr, Some(team_store()), as_token("token-root")).await;
    let listed = json(&root.call("runeward_list_citadels", json!({})).await);
    assert_eq!(ids(listed), vec!["cit-a", "cit-o"]);
}

#[tokio::test]
async fn tool_calls_are_attributed_to_the_principal() {
    let h = Harness::new().await;
    h.inject("cit-a", "team-alpha", vec![]);
    let bob = Client::stdio(&h.mgr, Some(team_store()), as_token("token-bob")).await;
    let res = bob
        .call(
            "runeward_shell",
            json!({"sandbox": "cit-a", "command": ["echo", "hi"]}),
        )
        .await;
    assert!(!is_error(&res));
    let last = h.records().await.pop().unwrap();
    assert_eq!(last.tool, "shell");
    assert_eq!(last.meta["actor"], "bob");
    assert_eq!(last.meta["tenant"], "team-alpha");
    assert_eq!(last.meta["isolation"], "container");

    let res = bob
        .call(
            "runeward_publish_conversation",
            json!({"sandbox": "cit-a", "role": "assistant", "content": "done"}),
        )
        .await;
    assert_eq!(json(&res)["author"], "bob", "{}", text(&res));
}

#[tokio::test]
async fn whoami_reports_rbac_scope() {
    let h = Harness::new().await;
    let alice = Client::stdio(&h.mgr, Some(team_store()), as_token("token-alice")).await;
    assert_eq!(
        text(&alice.call("runeward_whoami", json!({})).await),
        r#"{"authenticated":true,"principal":{"admin":false,"allowed_profiles":["dev","test"],"approval_profiles":[],"can_approve":false,"can_launch":true,"name":"alice","tenant":"team-alpha"},"rbac":true}"#
    );
    let res = alice.call("runeward_list_conclave", json!({})).await;
    assert_eq!(
        json(&res),
        json!({"code": "authz_denied", "error": "not authorized to view conclave decisions"})
    );
}

#[tokio::test]
async fn stdio_without_token_under_rbac_is_refused() {
    let h = Harness::new().await;
    let c = Client::stdio(&h.mgr, Some(team_store()), McpConfig::default()).await;
    let res = c.call("runeward_whoami", json!({})).await;
    assert!(is_error(&res));
    assert!(
        json(&res)["error"]
            .as_str()
            .unwrap()
            .starts_with("RUNEWARD_MCP_DEFAULT_TOKEN or `runeward auth login`")
    );
    // A token matching no principal is reported by every tool.
    let c = Client::stdio(&h.mgr, Some(team_store()), as_token("bogus")).await;
    let res = c.call("runeward_list_citadels", json!({})).await;
    assert_eq!(
        json(&res)["error"],
        "RUNEWARD_MCP_DEFAULT_TOKEN does not match any principal in RUNEWARD_AUTHZ_FILE"
    );
}

#[tokio::test]
async fn create_citadel_reports_isolation_and_enforces_launch_scope() {
    let h = Harness::new().await;
    h.write_charter("dev", BASIC_CHARTER);
    h.write_charter("prod", BASIC_CHARTER);
    let bob = Client::stdio(&h.mgr, Some(team_store()), as_token("token-bob")).await;
    let res = bob
        .call(
            "runeward_create_citadel",
            json!({"profile": "dev", "agent": "codex"}),
        )
        .await;
    assert!(!is_error(&res), "{}", text(&res));
    assert_eq!(
        text(&res),
        r#"{"backend":"fake","id":"created-1","image":"ghcr.io/example/agent:1","isolation":"container","profile":"dev","status":"running"}"#
    );
    assert_eq!(
        h.mgr.sandbox_owner("created-1").as_deref(),
        Some("team-alpha")
    );
    let run = h.mgr.list_runs().pop().unwrap();
    assert_eq!((run.actor.as_str(), run.agent.as_str()), ("bob", "codex"));

    let res = bob
        .call("runeward_create_citadel", json!({"profile": "prod"}))
        .await;
    assert_eq!(
        json(&res),
        json!({"code": "authz_denied", "error": "principal \"bob\" is not allowed to launch charter \"prod\""})
    );
    let res = bob
        .call(
            "runeward_create_citadel",
            json!({"profile": "dev", "copy_from": "/tmp"}),
        )
        .await;
    assert_eq!(
        json(&res)["error"],
        "copy_from overrides require an administrator"
    );
    let root = Client::stdio(&h.mgr, Some(team_store()), as_token("token-root")).await;
    let res = root
        .call(
            "runeward_create_citadel",
            json!({"profile": "dev", "copy_from": "/tmp"}),
        )
        .await;
    assert_eq!(
        json(&res)["error"],
        "copy_from is disabled under RBAC until RUNEWARD_COPY_FROM_ROOTS is configured"
    );
    let res = bob
        .call("runeward_readiness", json!({"profile": "prod"}))
        .await;
    assert_eq!(json(&res)["error"], "charter not found");
}

#[tokio::test]
async fn charters_are_filtered_by_launch_scope() {
    let h = Harness::new().await;
    h.write_charter("dev", BASIC_CHARTER);
    h.write_charter("prod", BASIC_CHARTER);
    let bob = Client::stdio(&h.mgr, Some(team_store()), as_token("token-bob")).await;
    let names: Vec<Value> = json(&bob.call("runeward_list_charters", json!({})).await)["charters"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["name"].clone())
        .collect();
    assert_eq!(names, vec![json!("dev")]);
}

#[tokio::test]
async fn approval_required_returns_guidance_not_an_error() {
    let h = Harness::new().await;
    h.inject(
        "cit-1",
        "",
        vec![rule(
            "shell",
            "deploy*",
            Verdict::RequireApproval,
            "needs a human",
        )],
    );
    let c = Client::stdio(&h.mgr, None, McpConfig::default()).await;
    let res = c
        .call(
            "runeward_shell",
            json!({"sandbox": "cit-1", "command": ["deploy", "prod"]}),
        )
        .await;
    assert!(!is_error(&res), "{}", text(&res));
    let v = json(&res);
    assert_eq!(v["code"], "approval_required");
    assert_eq!(v["verdict"], "require-approval");
    assert_eq!(v["reason"], "needs a human");
    assert!(!v["approval_id"].as_str().unwrap().is_empty());
    let keys: Vec<&String> = v.as_object().unwrap().keys().collect();
    assert_eq!(keys, ["approval_id", "code", "reason", "verdict"]);
}

#[tokio::test]
async fn fleet_task_lifecycle() {
    let h = Harness::new().await;
    h.write_charter(
        "crew",
        &format!("{BASIC_CHARTER}\n[cohort]\nreplicas = 2\ntask_board = [\"a\"]\n"),
    );
    let c = Client::stdio(&h.mgr, None, McpConfig::default()).await;
    let res = c
        .call("runeward_create_cohort", json!({"profile": "crew"}))
        .await;
    assert!(!is_error(&res), "{}", text(&res));
    let fleet = json(&res)["id"].as_str().unwrap().to_owned();
    assert_eq!(json(&res)["sandboxes"].as_array().unwrap().len(), 2);

    let res = c
        .call("runeward_add_task", json!({"fleet": fleet, "payload": "b"}))
        .await;
    assert!(!is_error(&res), "{}", text(&res));
    let claimed = json(&c.call("runeward_claim_task", json!({"fleet": fleet})).await);
    assert_eq!(claimed["claimed"], true);
    let task = claimed["task"]["id"].as_str().unwrap().to_owned();
    let lease = claimed["task"]["lease_token"].as_str().unwrap().to_owned();
    let hb = json(
        &c.call(
            "runeward_heartbeat_task",
            json!({"fleet": fleet, "task": task, "lease_token": lease}),
        )
        .await,
    );
    assert_eq!(hb["ok"], true, "{hb}");
    let lease = hb["task"]["lease_token"]
        .as_str()
        .unwrap_or(&lease)
        .to_owned();
    let done = c
        .call(
            "runeward_complete_task",
            json!({"fleet": fleet, "task": task, "lease_token": lease, "result": "ok"}),
        )
        .await;
    assert_eq!(
        text(&done),
        format!(r#"{{"ok":true,"state":"done","task":"{task}"}}"#)
    );
    let second = json(&c.call("runeward_claim_task", json!({"fleet": fleet})).await);
    let task2 = second["task"]["id"].as_str().unwrap().to_owned();
    let lease2 = second["task"]["lease_token"].as_str().unwrap().to_owned();
    let failed = c
        .call(
            "runeward_fail_task",
            json!({"fleet": fleet, "task": task2, "lease_token": lease2, "error": "x", "requeue": true}),
        )
        .await;
    assert_eq!(json(&failed)["state"], "failed and requeued");
    let bad = c
        .call(
            "runeward_complete_task",
            json!({"fleet": fleet, "task": task2, "lease_token": "forged"}),
        )
        .await;
    assert!(is_error(&bad));
    let killed = c
        .call("runeward_kill_cohort", json!({"fleet": fleet}))
        .await;
    assert_eq!(
        text(&killed),
        format!(r#"{{"cohort":"{fleet}","ok":true}}"#)
    );
}

#[tokio::test]
async fn server_info_reports_digest_version_and_caller() {
    let h = Harness::new().await;
    let alice = Client::stdio(&h.mgr, Some(team_store()), as_token("token-alice")).await;
    let info = json(&alice.call("runeward_server_info", json!({})).await);
    assert_eq!(info["name"], "runeward");
    assert_eq!(info["version"], "0.3.0");
    assert_eq!(info["tool_count"], 36);
    assert_eq!(info["tool_list_digest"], tool_list_digest());
    assert_eq!(
        info["caller"],
        json!({"admin": false, "name": "alice", "rbac": true, "tenant": "team-alpha"})
    );

    // A client recomputes the digest from the tool list it received.
    let listed = alice.service.list_all_tools().await.unwrap();
    assert_eq!(listed.len(), 36);
    let value = serde_json::to_value(&listed).unwrap();
    let digest = format!(
        "sha256:{}",
        hex_lower(&Sha256::digest(canonical_json(&value).as_bytes()))
    );
    assert_eq!(digest, info["tool_list_digest"].as_str().unwrap());
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[tokio::test]
async fn invalid_arguments_and_unknown_tools() {
    let h = Harness::new().await;
    let c = Client::stdio(&h.mgr, None, McpConfig::default()).await;
    let res = c.call("runeward_shell", json!({"sandbox": "x"})).await;
    assert!(is_error(&res));
    assert!(res.structured_content.is_none());
    assert!(
        text(&res).starts_with("validating \"arguments\": missing field `command`"),
        "{}",
        text(&res)
    );
    let res = c.call("runeward_whoami", json!({"surprise": 1})).await;
    assert!(is_error(&res), "unknown fields are rejected");

    let err = c
        .call_raw("runeward_nope", serde_json::Map::new())
        .await
        .expect_err("protocol error");
    assert!(err.contains("unknown tool"), "{err}");
}

#[tokio::test]
async fn verify_chronicle_and_usage() {
    let h = Harness::new().await;
    h.inject("cit-1", "", vec![]);
    let c = Client::stdio(&h.mgr, None, McpConfig::default()).await;
    assert_eq!(
        text(&c.call("runeward_verify_chronicle", json!({})).await),
        r#"{"ok":true}"#
    );
    let res = c
        .call(
            "runeward_report_usage",
            json!({"sandbox": "cit-1", "tokens": 7, "cost_usd": 2.0}),
        )
        .await;
    assert_eq!(text(&res), r#"{"Tokens":7,"CostUSD":2}"#);
    let res = c
        .call(
            "runeward_snapshot_citadel",
            json!({"sandbox": "cit-1", "name": "s"}),
        )
        .await;
    assert!(!is_error(&res), "{}", text(&res));
    let snaps = json(&c.call("runeward_list_snapshots", json!({})).await);
    assert_eq!(snaps["snapshots"][0]["id"], "snap-cit-1");
}
