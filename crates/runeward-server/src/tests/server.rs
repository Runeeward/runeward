//! Ports of Go `internal/server/server_test.go`.

use std::sync::Arc;

use runeward_authz::Principal;

use super::support::*;
use crate::Server;
use crate::handlers::fleet::task_owner;
use crate::state::Caller;

#[tokio::test]
async fn auth_token_required() {
    let h = harness().await;
    let r = router_with_token(&h, "s3cret");
    assert_eq!(get(&r, "/v1/citadels", None).await.status, 401, "no token");
    let wrong = get(&r, "/v1/citadels", Some("nope")).await;
    assert_eq!(wrong.status, 401, "wrong token");
    assert_eq!(wrong.header("www-authenticate"), "Bearer");
    assert_eq!(wrong.json()["code"], "authentication_required");
    assert_eq!(get(&r, "/v1/citadels", Some("s3cret")).await.status, 200);
    let x = send(
        &r,
        req(
            "GET",
            "/v1/citadels",
            &[("x-runeward-token", "s3cret")],
            None,
        ),
    )
    .await;
    assert_eq!(x.status, 200, "X-Runeward-Token");
    // Query-string tokens are refused for REST and for terminal sockets.
    assert_eq!(get(&r, "/v1/citadels?token=s3cret", None).await.status, 401);
    assert_eq!(
        get(&r, "/v1/citadels/nope/terminal?token=s3cret", None)
            .await
            .status,
        401
    );
    assert_eq!(
        get(&r, "/healthz", None).await.status,
        200,
        "healthz exempt"
    );
}

#[tokio::test]
async fn dashboard_auth_exemption_is_an_exact_asset_allowlist() {
    let h = harness().await;
    let r = server(&h).token("s3cret").dashboard(true).router();
    for path in ["/", "/app.js", "/style.css", "/logo.png"] {
        let resp = get(&r, path, None).await;
        assert_eq!(resp.status, 200, "GET {path}");
        assert_eq!(
            resp.header("cache-control"),
            "no-store, max-age=0, must-revalidate"
        );
    }
    let idx = get(&r, "/index.html", None).await;
    assert_eq!(idx.status, 301, "FileServer redirects /index.html");
    assert_eq!(idx.header("location"), "./");
    for path in ["/future-sensitive", "/debug/pprof", "/app.js/extra"] {
        assert_eq!(get(&r, path, None).await.status, 401, "GET {path}");
    }
    let post_root = send(&r, req("POST", "/", &[], None)).await;
    assert_eq!(post_root.status, 401, "only GET/HEAD are public");
    let head = send(&r, req("HEAD", "/app.js", &[], None)).await;
    assert_eq!(head.status, 200);
    assert!(head.body.is_empty());
}

#[tokio::test]
async fn dashboard_serves_embedded_assets() {
    let h = harness().await;
    let r = server(&h).dashboard(true).router();
    let index = get(&r, "/", None).await;
    assert_eq!(index.header("content-type"), "text/html; charset=utf-8");
    assert_eq!(&index.body[..], crate::web::INDEX_HTML);
    assert!(
        index
            .header("content-security-policy")
            .contains("default-src 'self'")
    );
    let js = get(&r, "/app.js", None).await;
    assert_eq!(js.header("content-type"), "text/javascript; charset=utf-8");
    assert_eq!(&js.body[..], crate::web::APP_JS);
    let png = get(&r, "/logo.png", None).await;
    assert_eq!(png.header("content-type"), "image/png");
    assert_eq!(get(&r, "/missing.js", None).await.status, 404);
    // The API still works next to the dashboard.
    assert_eq!(get(&r, "/v1/conclave", None).await.status, 200);
}

#[tokio::test]
async fn security_headers_cover_api_and_authentication_failures() {
    let h = harness().await;
    let r = router_with_token(&h, "s3cret");
    for path in ["/healthz", "/v1/citadels"] {
        let resp = get(&r, path, None).await;
        assert_eq!(resp.header("x-content-type-options"), "nosniff", "{path}");
        assert_eq!(resp.header("x-frame-options"), "DENY", "{path}");
        assert_eq!(resp.header("referrer-policy"), "no-referrer", "{path}");
        if path == "/v1/citadels" {
            assert_eq!(resp.header("cache-control"), "no-store");
            assert_eq!(
                resp.header("content-security-policy"),
                "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
            );
        }
    }
    let ide = get(&r, "/v1/citadels/ide1/ide/", None).await;
    assert_eq!(
        ide.header("content-security-policy"),
        "",
        "IDE proxy inherited API CSP; code-server assets would be blocked"
    );
    assert_eq!(ide.header("x-frame-options"), "");
    assert_eq!(ide.header("cache-control"), "no-store");
}

#[tokio::test]
async fn health() {
    let h = harness().await;
    let r = server(&h).router();
    let resp = get(&r, "/healthz", None).await;
    assert_eq!(resp.status, 200);
    assert_eq!(resp.json()["status"], "ok");
    assert_eq!(resp.header("content-type"), "application/json");
    assert!(
        resp.body.ends_with(b"\n"),
        "Go's encoder ends with a newline"
    );
}

#[tokio::test]
async fn audit_verify_empty() {
    let h = harness().await;
    let r = server(&h).router();
    let resp = get(&r, "/v1/chronicle/verify", None).await;
    assert_eq!(resp.status, 200);
    assert_eq!(resp.json()["ok"], true, "{}", resp.text());
}

#[tokio::test]
async fn approvals_empty() {
    let h = harness().await;
    let r = server(&h).router();
    let resp = get(&r, "/v1/conclave", None).await;
    assert_eq!(resp.status, 200);
    assert!(resp.text().contains(r#""approvals":[]"#), "{}", resp.text());
}

#[tokio::test]
async fn agent_sessions_empty() {
    let h = harness().await;
    let r = server(&h).router();
    let resp = get(&r, "/v1/agent-sessions", None).await;
    assert_eq!(resp.status, 200);
    assert!(resp.text().contains(r#""sessions":[]"#), "{}", resp.text());
}

#[tokio::test]
async fn agent_session_event_cursor_validation() {
    let h = harness().await;
    let r = server(&h).router();
    let resp = get(&r, "/v1/agent-sessions/missing/events?after=-1", None).await;
    assert_eq!(resp.status, 400);
}

#[tokio::test]
async fn create_sandbox_unknown_profile() {
    let h = harness().await;
    let r = server(&h).router();
    let resp = post(&r, "/v1/citadels", None, r#"{"profile":"does-not-exist"}"#).await;
    assert_eq!(resp.status, 400);
}

#[tokio::test]
async fn unknown_sandbox_404() {
    let h = harness().await;
    let r = server(&h).router();
    assert_eq!(get(&r, "/v1/citadels/nope", None).await.status, 404);
}

#[tokio::test]
async fn rbac_approvals_inbox_requires_approval_permission() {
    let h = harness().await;
    let r = router_with_rbac(&h);
    assert_eq!(get(&r, "/v1/conclave", Some("tok-alice")).await.status, 403);
    assert_eq!(
        get(&r, "/v1/conclave", Some("tok-reviewer")).await.status,
        200
    );
}

#[tokio::test]
async fn rbac_readiness_requires_charter_scope() {
    let h = harness().await;
    let r = router_with_rbac(&h);
    let resp = get(&r, "/v1/readiness?profile=ops-prod", Some("tok-alice")).await;
    assert_eq!(resp.status, 404);
}

#[tokio::test]
async fn rbac_copy_from_requires_admin() {
    let h = harness().await;
    let r = router_with_rbac(&h);
    let resp = post(
        &r,
        "/v1/citadels",
        Some("tok-alice"),
        r#"{"profile":"team-dev","copy_from":"/etc"}"#,
    )
    .await;
    assert_eq!(resp.status, 403, "{}", resp.text());
    // Even an admin needs RUNEWARD_COPY_FROM_ROOTS under RBAC.
    let resp = post(
        &r,
        "/v1/citadels",
        Some("tok-admin"),
        r#"{"profile":"team-dev","copy_from":"/etc"}"#,
    )
    .await;
    if std::env::var("RUNEWARD_COPY_FROM_ROOTS")
        .unwrap_or_default()
        .trim()
        .is_empty()
    {
        assert_eq!(resp.status, 403, "{}", resp.text());
    }
}

#[tokio::test]
async fn structured_authorization_error() {
    let h = harness().await;
    let r = router_with_rbac(&h);
    let resp = get(&r, "/v1/conclave", Some("tok-alice")).await;
    assert_eq!(resp.json()["code"], "authz_denied");
}

#[tokio::test]
async fn rbac_audit_export_requires_admin() {
    let h = harness().await;
    let r = router_with_rbac(&h);
    let resp = get(&r, "/v1/chronicle/export", Some("tok-reviewer")).await;
    assert_eq!(resp.status, 403);
    let resp = get(&r, "/v1/chronicle/export", Some("tok-admin")).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(
        resp.header("content-disposition"),
        "attachment; filename=runeward-audit-bundle.json"
    );
}

#[tokio::test]
async fn create_fleet_enforces_can_launch() {
    let h = harness().await;
    let r = router_with_rbac(&h);
    let resp = post(
        &r,
        "/v1/cohorts",
        Some("tok-alice"),
        r#"{"profile":"ops-prod"}"#,
    )
    .await;
    assert_eq!(resp.status, 403);
}

#[tokio::test]
async fn whoami_can_launch_reflects_allowed_profiles() {
    let h = harness().await;
    let r = router_with_rbac(&h);
    let alice = get(&r, "/v1/whoami", Some("tok-alice")).await;
    assert_eq!(alice.status, 200);
    let p = &alice.json()["principal"];
    assert_eq!(p["can_launch"], true);
    assert_eq!(p["tenant"], "team-alpha");
    assert_eq!(alice.json()["rbac"], true);

    let h2 = harness().await;
    let store = authz_store(
        h2.dir.path(),
        r#"{"principals":[{"name":"locked","token":"tok-locked","allowed_profiles":[]}]}"#,
    );
    let r2 = server(&h2).authz(Some(store)).router();
    let locked = get(&r2, "/v1/whoami", Some("tok-locked")).await;
    assert_eq!(locked.status, 200);
    assert_eq!(locked.json()["principal"]["can_launch"], false);

    let open = server(&h2).router();
    let anon = get(&open, "/v1/whoami", None).await.json();
    assert_eq!(anon["rbac"], false);
    assert_eq!(anon["principal"]["admin"], true);
    assert_eq!(anon["principal"]["name"], "");
}

#[tokio::test]
async fn rbac_tenant_allows_collaboration_but_blocks_other_tenant() {
    let h = harness_with(
        |_| {},
        |dir| {
            std::fs::write(
                dir.join("state").join("fleets.json"),
                r#"[{
                    "id":"fleet-team","profile":"team-dev","owner":"team-alpha",
                    "sandboxes":[],"created":"2026-01-01T00:00:00Z","tasks":[]
                }]"#,
            )
            .expect("write fleets");
        },
    )
    .await;
    let store = authz_store(
        h.dir.path(),
        r#"{"principals":[
            {"name":"alice","tenant":"team-alpha","token":"tok-alice"},
            {"name":"bob","tenant":"team-alpha","token":"tok-bob"},
            {"name":"eve","tenant":"team-other","token":"tok-eve"}
        ]}"#,
    );
    let r = server(&h).authz(Some(store)).router();
    for (token, want) in [("tok-alice", 200), ("tok-bob", 200), ("tok-eve", 404)] {
        let resp = get(&r, "/v1/cohorts/fleet-team", Some(token)).await;
        assert_eq!(resp.status, want, "{token}: {}", resp.text());
    }
    let listed = get(&r, "/v1/cohorts", Some("tok-eve")).await.json();
    assert_eq!(listed["fleets"], serde_json::json!([]));
}

#[tokio::test]
async fn rbac_citadels_are_tenant_scoped() {
    let h = harness().await;
    h.inject("cit-a", "team-dev", "team-alpha").await;
    let r = router_with_rbac(&h);
    let alice = get(&r, "/v1/citadels", Some("tok-alice")).await.json();
    assert_eq!(alice["sandboxes"][0]["id"], "cit-a");
    assert_eq!(alice["sandboxes"][0]["owner"], "team-alpha");
    assert_eq!(alice["sandboxes"][0]["isolation"], "container");
    let eve = get(&r, "/v1/citadels", Some("tok-eve")).await.json();
    assert_eq!(eve["sandboxes"], serde_json::json!([]));
    assert_eq!(
        get(&r, "/v1/citadels/cit-a", Some("tok-eve")).await.status,
        404
    );
    let shell = post(
        &r,
        "/v1/citadels/cit-a/shell/exec",
        Some("tok-eve"),
        r#"{"command":["ls"]}"#,
    )
    .await;
    assert_eq!(shell.status, 404);
    assert_eq!(shell.json()["error"], "sandbox not found");
    let ok = post(
        &r,
        "/v1/citadels/cit-a/shell/exec",
        Some("tok-bob"),
        r#"{"command":["ls"]}"#,
    )
    .await;
    assert_eq!(ok.status, 200, "same tenant collaborates: {}", ok.text());
    assert_eq!(
        get(&r, "/v1/citadels/cit-a", Some("tok-admin"))
            .await
            .status,
        200
    );
}

#[tokio::test]
async fn rbac_charters_filtered_by_can_launch() {
    let h = harness_with(
        |_| {},
        |dir| {
            for name in ["team-dev", "ops-prod"] {
                std::fs::write(
                    dir.join("charters").join(format!("{name}.toml")),
                    "[host]\ntype = \"container\"\nimage = \"debian:stable-slim\"\n",
                )
                .expect("write charter");
            }
        },
    )
    .await;
    let r = router_with_rbac(&h);
    let resp = get(&r, "/v1/charters", Some("tok-alice")).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let profiles = resp.json()["profiles"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(!profiles.is_empty());
    for p in profiles {
        let name = p["name"].as_str().unwrap_or_default();
        assert!(
            name.starts_with("team-"),
            "alice saw unauthorized charter {name}"
        );
    }
    let admin = get(&r, "/v1/charters", Some("tok-admin")).await.json();
    assert_eq!(admin["profiles"].as_array().map(Vec::len), Some(2));
}

#[tokio::test]
async fn rbac_policy_simulate_requires_can_launch() {
    let h = harness().await;
    let r = router_with_rbac(&h);
    let resp = post(
        &r,
        "/v1/policy/simulate",
        Some("tok-alice"),
        r#"{"profile_name":"ops-prod","actions":[{"tool":"shell","command":"echo hi"}]}"#,
    )
    .await;
    assert_eq!(resp.status, 403, "{}", resp.text());
    let resp = post(
        &r,
        "/v1/policy/simulate",
        Some("tok-alice"),
        r#"{"profile":{"host":{"type":"container","image":"debian:stable-slim"},"policy":[]},"actions":[{"tool":"shell","command":"echo hi"}]}"#,
    )
    .await;
    assert_eq!(resp.status, 403, "inline: {}", resp.text());
}

#[test]
fn task_owner_from_request() {
    let anon = Caller(None);
    assert!(
        task_owner(&anon, "").is_err(),
        "empty unauthenticated owner"
    );
    assert_eq!(task_owner(&anon, " worker-a ").as_deref(), Ok("worker-a"));
    let alice = Caller(Some(Arc::new(Principal {
        name: "alice".into(),
        ..Principal::default()
    })));
    assert_eq!(task_owner(&alice, "worker-a").as_deref(), Ok("alice"));
}

#[tokio::test]
async fn terminal_ticket_single_use() {
    let h = harness().await;
    let r = router_with_token(&h, "s3cret");
    let mint = post(&r, "/v1/citadels/sb1/terminal-ticket", Some("s3cret"), "").await;
    assert_eq!(mint.status, 201);
    let ticket = mint.json()["ticket"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    assert_eq!(ticket.len(), 32);
    assert!(
        mint.json()["expires_at"]
            .as_str()
            .is_some_and(|t| t.ends_with('Z'))
    );
    let uri = format!("/v1/citadels/sb1/terminal?ticket={ticket}");
    assert_eq!(get(&r, &uri, None).await.status, 404, "first use");
    assert_eq!(get(&r, &uri, None).await.status, 401, "second use");
}

#[tokio::test]
async fn general_download_ticket_single_use() {
    let h = harness().await;
    let r = router_with_token(&h, "s3cret");
    let mint = post(
        &r,
        "/v1/tickets",
        Some("s3cret"),
        r#"{"kind":"download","path":"/v1/chronicle/export"}"#,
    )
    .await;
    assert_eq!(mint.status, 201);
    let ticket = mint.json()["ticket"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    assert!(!ticket.trim().is_empty());
    let uri = format!("/v1/chronicle/export?ticket={ticket}");
    let first = get(&r, &uri, None).await;
    assert_eq!(first.status, 200, "first use: {}", first.text());
    assert_eq!(get(&r, &uri, None).await.status, 401, "second use");

    // A download ticket is bound to its path and to GET/HEAD.
    let mint = post(&r, "/v1/tickets", Some("s3cret"), r#"{"kind":"download"}"#).await;
    let ticket = mint.json()["ticket"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    let other = get(&r, &format!("/v1/citadels?ticket={ticket}"), None).await;
    assert_eq!(other.status, 401, "path-scoped");
}

#[tokio::test]
async fn policy_simulate_builtin() {
    let h = harness().await;
    let r = server(&h).router();
    let body = r#"{
        "profile": {
            "host": {"type":"container","image":"ghcr.io/runeeward/runeward-sandbox:latest","workdir":"/workspace"},
            "network": {"default":"allow"},
            "policy":[
                {"tool":"shell","match":"rm *","verdict":"deny","reason":"dangerous"},
                {"tool":"*","match":"*","verdict":"allow"}
            ]
        },
        "actions":[
            {"name":"deny rm","tool":"shell","command":"rm -rf /"},
            {"name":"allow ls","tool":"shell","command":"ls -la"}
        ]
    }"#;
    let resp = post(&r, "/v1/policy/simulate", None, body).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let v = resp.json();
    let results = v["results"].as_array().cloned().unwrap_or_default();
    assert_eq!(results.len(), 2);
    assert_eq!(results[0]["verdict"], "deny");
    assert_eq!(results[0]["matched_rule"]["reason"], "dangerous");
    assert!(
        results[0]["trace"]
            .as_array()
            .is_some_and(|t| !t.is_empty())
    );
    assert_eq!(results[1]["verdict"], "allow");
    assert_eq!(results[1]["trace"].as_array().map(Vec::len), Some(2));
    assert_eq!(v["profile"]["name"], "inline");
}

#[tokio::test]
async fn cross_origin_writes_are_refused() {
    let h = harness().await;
    h.inject("cit-1", "parity", "").await;
    let r = server(&h).router();
    let evil = send(
        &r,
        req(
            "POST",
            "/v1/citadels/cit-1/shell/exec",
            &[("origin", "https://evil.example"), ("host", "cp.example")],
            Some(r#"{"command":["ls"]}"#),
        ),
    )
    .await;
    assert_eq!(evil.status, 403);
    assert_eq!(evil.json()["error"], "cross-origin request refused");
    let same = send(
        &r,
        req(
            "POST",
            "/v1/citadels/cit-1/shell/exec",
            &[("origin", "https://cp.example"), ("host", "cp.example")],
            Some(r#"{"command":["ls"]}"#),
        ),
    )
    .await;
    assert_eq!(same.status, 200, "{}", same.text());
}

#[tokio::test]
async fn rate_limit_refuses_bursts() {
    let h = harness().await;
    let r = Server::new(Arc::clone(&h.mgr))
        .rate_limit(Some(1.0))
        .router();
    assert_eq!(get(&r, "/healthz", None).await.status, 200);
    assert_eq!(get(&r, "/healthz", None).await.status, 200);
    let limited = get(&r, "/healthz", None).await;
    assert_eq!(limited.status, 429);
    assert_eq!(limited.json()["code"], "rate_limited");
}

#[tokio::test]
async fn oversized_bodies_are_refused() {
    let h = harness().await;
    h.inject("cit-1", "parity", "").await;
    let r = server(&h).router();
    let big = format!(
        r#"{{"path":"a","content":"{}"}}"#,
        "x".repeat(crate::respond::MAX_REQUEST_BODY_BYTES)
    );
    let resp = post(&r, "/v1/citadels/cit-1/file/write", None, &big).await;
    assert_eq!(resp.status, 400);
    assert_eq!(resp.json()["error"], "http: request body too large");
}

#[tokio::test]
async fn citadel_lifecycle_through_the_api() {
    let h = harness_with(
        |_| {},
        |dir| {
            std::fs::write(
                dir.join("charters").join("dev.toml"),
                "[host]\ntype = \"container\"\nimage = \"debian:stable-slim\"\n",
            )
            .expect("write charter");
        },
    )
    .await;
    let r = server(&h).router();
    let created = post(&r, "/v1/citadels", None, r#"{"profile":"dev"}"#).await;
    assert_eq!(created.status, 201, "{}", created.text());
    let v = created.json();
    assert_eq!(v["id"], "fake-1");
    assert_eq!(v["isolation"], "container");
    let got = get(&r, "/v1/citadels/fake-1", None).await.json();
    assert_eq!(got["usage"]["tokens"], 0);
    assert!(got["limits"].is_object(), "{got}");
    let runs = get(&r, "/v1/runs", None).await.json();
    assert_eq!(runs["runs"].as_array().map(Vec::len), Some(1));
    let run_id = runs["runs"][0]["id"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    assert_eq!(
        get(&r, &format!("/v1/runs/{run_id}"), None).await.status,
        200
    );
    let snap = post(&r, "/v1/citadels/fake-1/snapshot", None, "").await;
    assert_eq!(snap.status, 201, "{}", snap.text());
    let ws = get(&r, "/v1/citadels/fake-1/workspace", None).await;
    assert_eq!(ws.status, 200);
    assert_eq!(&ws.body[..], b"tar");
    assert_eq!(ws.header("content-type"), "application/x-tar");
    assert_eq!(
        ws.header("content-disposition"),
        "attachment; filename=runeward-workspace-fake-1.tar"
    );
    let ev = get(&r, "/v1/citadels/fake-1/evidence", None).await;
    assert_eq!(ev.status, 200, "{}", ev.text());
    assert_eq!(ev.json()["format"], "runeward-evidence/v1");
    let killed = send(&r, req("DELETE", "/v1/citadels/fake-1", &[], None)).await;
    assert_eq!(killed.status, 200);
    assert_eq!(killed.json()["ok"], true);
    assert_eq!(get(&r, "/v1/citadels/fake-1", None).await.status, 404);
}
