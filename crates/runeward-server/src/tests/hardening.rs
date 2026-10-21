//! Request ids, refusal bodies, per-principal limits, the perimeter list
//! and the hardened-mode startup gate.

use std::sync::Arc;

use runeward_charter::{Charter, PolicyRule, Verdict};
use runeward_controlplane::hardening::Rule;

use super::support::*;
use crate::{ServeError, Server, ServerConfig};

#[tokio::test]
async fn request_id_is_echoed_or_generated_on_every_response() {
    let h = harness().await;
    let r = server(&h).router();
    let mine = send(
        &r,
        req("GET", "/healthz", &[("x-request-id", "trace-42")], None),
    )
    .await;
    assert_eq!(mine.status, 200);
    assert_eq!(mine.header("x-request-id"), "trace-42");

    let generated = get(&r, "/healthz", None).await;
    let id = generated.header("x-request-id");
    assert_eq!(id.len(), 16, "{id}");

    // A header-injection attempt is replaced, not echoed.
    let bad = send(&r, req("GET", "/healthz", &[("x-request-id", "a b")], None)).await;
    assert_ne!(bad.header("x-request-id"), "a b");
    assert_eq!(bad.header("x-request-id").len(), 16);
}

#[tokio::test]
async fn error_bodies_carry_the_refusal_fields() {
    let h = harness().await;
    let r = server(&h).router();
    let resp = send(
        &r,
        req(
            "GET",
            "/v1/citadels/nope/perimeter",
            &[("x-request-id", "rid-1")],
            None,
        ),
    )
    .await;
    assert_eq!(resp.status, 404);
    let v = resp.json();
    // Existing fields stay for the dashboard and SDKs.
    assert_eq!(v["error"], "sandbox not found");
    assert_eq!(v["code"], "not_found");
    assert!(
        v.get("reason").is_none(),
        "the dashboard reads body.reason first"
    );
    let rf = &v["refusal"];
    assert_eq!(rf["refused"], true);
    assert_eq!(rf["reason"], "request");
    assert_eq!(rf["retryable"], false);
    assert_eq!(rf["request_id"], "rid-1");
    assert_eq!(rf["message"], "sandbox not found");

    // A bad body.
    let resp = post(&r, "/v1/citadels", None, "{\"bogus\":1}").await;
    assert_eq!(resp.status, 400);
    assert_eq!(resp.json()["refusal"]["reason"], "request");
    assert_eq!(
        resp.json()["refusal"]["request_id"].as_str(),
        Some(resp.header("x-request-id").as_str())
    );
}

#[tokio::test]
async fn rate_limits_are_retryable_capacity_refusals() {
    let h = harness().await;
    let r = Server::new(Arc::clone(&h.mgr))
        .rate_limit(Some(1.0))
        .router();
    get(&r, "/healthz", None).await;
    get(&r, "/healthz", None).await;
    let limited = get(&r, "/healthz", None).await;
    assert_eq!(limited.status, 429);
    let v = limited.json();
    assert_eq!(v["code"], "rate_limited");
    assert_eq!(v["refusal"]["reason"], "capacity");
    assert_eq!(v["refusal"]["retryable"], true);
}

#[tokio::test]
async fn denied_tool_calls_nest_the_refusal() {
    let h = harness().await;
    let charter = Charter {
        name: "deny".into(),
        policy: vec![PolicyRule {
            tool: "shell".into(),
            match_glob: "rm *".into(),
            verdict: Verdict::Deny,
            reason: "no deletes".into(),
            ..PolicyRule::default()
        }],
        ..Charter::default()
    };
    h.inject_charter("cit-deny", charter, "");
    let r = server(&h).router();
    let resp = post(
        &r,
        "/v1/citadels/cit-deny/shell/exec",
        None,
        r#"{"command":["rm","-rf","/"]}"#,
    )
    .await;
    assert_eq!(resp.status, 403, "{}", resp.text());
    let v = resp.json();
    assert_eq!(v["verdict"], "deny");
    assert!(
        v["reason"]
            .as_str()
            .is_some_and(|s| s.contains("no deletes")),
        "{v}"
    );
    assert_eq!(v["refusal"]["refused"], true);
    assert_eq!(v["refusal"]["reason"], "policy");
    assert_eq!(v["refusal"]["retryable"], false);
    assert_eq!(
        v["refusal"]["request_id"].as_str(),
        Some(resp.header("x-request-id").as_str())
    );

    // An allowed call has no refusal.
    let ok = post(
        &r,
        "/v1/citadels/cit-deny/shell/exec",
        None,
        r#"{"command":["echo","hi"]}"#,
    )
    .await;
    assert_eq!(ok.status, 200);
    assert!(ok.json().get("refusal").is_none());
}

#[tokio::test]
async fn principals_are_rate_limited_separately() {
    let h = harness().await;
    let r = server(&h)
        .authz(Some(authz_store(h.dir.path(), RBAC_PRINCIPALS)))
        .principal_rate_limit(Some(1.0))
        .router();
    assert_eq!(get(&r, "/v1/whoami", Some("tok-alice")).await.status, 200);
    assert_eq!(get(&r, "/v1/whoami", Some("tok-alice")).await.status, 200);
    let limited = get(&r, "/v1/whoami", Some("tok-alice")).await;
    assert_eq!(limited.status, 429);
    assert_eq!(limited.json()["refusal"]["reason"], "capacity");
    assert_eq!(limited.header("retry-after"), "1");
    // Same client IP, different principal: unaffected.
    assert_eq!(get(&r, "/v1/whoami", Some("tok-bob")).await.status, 200);
}

#[tokio::test]
async fn perimeter_lists_sidecar_and_in_process_decisions() {
    let h = harness().await;
    h.inject("cit-perim", "", "").await;
    // A decision reported by an egress sidecar lands in the same ring as
    // the in-process broker's.
    runeward_egress::record_decision_entry(
        "cit-perim",
        runeward_egress::Decision {
            host: "api.test".into(),
            reason: "shed: upstream api answered 429".into(),
            reason_code: Some(runeward_egress::ReasonCode::Shed),
            ..runeward_egress::Decision::default()
        },
    );
    let r = server(&h).router();
    let resp = get(&r, "/v1/citadels/cit-perim/perimeter", None).await;
    assert_eq!(resp.status, 200);
    let decisions = resp.json()["decisions"].clone();
    assert_eq!(decisions[0]["host"], "api.test");
    assert_eq!(decisions[0]["reason_code"], "shed");
}

#[tokio::test]
async fn hardened_mode_refuses_to_start_and_lists_every_violation() {
    let h = harness_with(
        |_| {},
        |dir| {
            std::fs::write(
                dir.join("charters/loose.toml"),
                "[host]\ntype = \"container\"\nimage = \"alpine:3\"\nseccomp = \"unconfined\"\n",
            )
            .expect("charter");
        },
    )
    .await;
    let config = ServerConfig {
        port: 0,
        token: "x".repeat(40),
        hardened: true,
        ..ServerConfig::default()
    };
    let err = crate::serve(config, Arc::clone(&h.mgr), async {})
        .await
        .expect_err("hardened refuses");
    let ServeError::Hardened(violations) = &err else {
        panic!("unexpected error {err}");
    };
    let rules: Vec<Rule> = violations.iter().map(|v| v.rule).collect();
    for want in [
        Rule::Auth,
        Rule::SignedCharters,
        Rule::Isolation,
        Rule::Egress,
        Rule::ImageDigest,
        Rule::RateLimit,
        Rule::Seccomp,
    ] {
        assert!(rules.contains(&want), "missing {want:?} in {violations:?}");
    }
    assert!(err.to_string().contains("[seccomp] loose"), "{err}");
}

#[tokio::test]
async fn citadel_views_carry_isolation_evidence_and_enforcement() {
    use runeward_backend::Sandbox;
    use runeward_charter::Isolation;
    use runeward_controlplane::{IsolationEvidence, Session};

    let h = harness().await;
    // Plain Citadel: backend evidence only, no supervisor report.
    h.inject("cit-plain", "", "").await;
    // A Charter that asks for a kernel floor, run under the supervisor.
    let charter = Charter {
        name: "floor".into(),
        isolation: Isolation {
            minimum: "kernel".into(),
        },
        ..Charter::default()
    };
    let sb = Sandbox {
        id: "cit-sup".into(),
        profile: "floor".into(),
        backend: "fake".into(),
        status: "running".into(),
        ..Sandbox::default()
    };
    let evidence = IsolationEvidence {
        supervisor: "enforced".into(),
        required: true,
        landlock_requested: "required".into(),
        landlock: "enforced".into(),
        landlock_abi: 4,
        seccomp: true,
        no_new_privs: true,
        uid: Some(1000),
        gid: Some(1000),
        capabilities_dropped: true,
        protected_by_landlock: true,
        binary_attribution: String::new(),
    };
    let sess = Session::builder(sb, Arc::new(FakeBackend), charter)
        .workdir("/workspace")
        .enforcement(evidence)
        .build()
        .expect("session");
    h.mgr.inject_session(sess);
    let r = server(&h).router();

    let plain = get(&r, "/v1/citadels/cit-plain", None).await.json();
    assert_eq!(plain["isolation"], "container");
    assert_eq!(plain["isolation_evidence"]["tier"], "container");
    assert_eq!(plain["isolation_evidence"]["backend"], "fake");
    assert_eq!(plain["isolation_evidence"]["source"], "backend");
    assert!(plain.get("enforcement").is_none(), "{plain}");

    let sup = get(&r, "/v1/citadels/cit-sup", None).await.json();
    assert_eq!(sup["enforcement"]["supervisor"], "enforced");
    assert_eq!(sup["enforcement"]["landlock"], "enforced");
    assert_eq!(sup["enforcement"]["uid"], 1000);
    assert_eq!(sup["enforcement"]["capabilities_dropped"], true);

    // The listing carries the same evidence (without the Charter floor).
    let list = get(&r, "/v1/citadels", None).await.json();
    let listed = list["sandboxes"]
        .as_array()
        .and_then(|a| a.iter().find(|s| s["id"] == "cit-sup").cloned())
        .expect("listed");
    assert_eq!(listed["enforcement"]["seccomp"], true);
    assert_eq!(listed["isolation_evidence"]["tier"], "container");
}

#[test]
fn isolation_floor_is_compared_by_rank() {
    use serde_json::{Map, json};
    let view = |tier: &str| -> Map<String, serde_json::Value> {
        let v = json!({"isolation": tier, "isolation_evidence": {"tier": tier}});
        v.as_object().cloned().unwrap_or_default()
    };
    for (tier, floor, meets) in [
        ("container", "", true),
        ("container", "kernel", false),
        ("vm", "kernel", true),
        ("kernel", "kernel", true),
        ("process", "container", false),
    ] {
        let mut v = view(tier);
        crate::handlers::add_isolation_floor(&mut v, floor);
        assert_eq!(v["isolation_evidence"]["floor"], floor);
        assert_eq!(
            v["isolation_evidence"]["meets_floor"], meets,
            "{tier} vs {floor}"
        );
    }
}
