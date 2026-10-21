//! The request broker and the in-sandbox supervisor wired through create,
//! approvals and the ledger, against the fake backend.

use std::time::Duration;

use runeward_egress::{ApprovalHook, ApprovalOutcome, ApprovalRequest, Decision, ReasonCode};

use super::support::{TEST_TOKEN, harness, lock};
use crate::{CreateOptions, Error};

const BROKERED: &str = r#"
[host]
type = "container"
image = "ghcr.io/example/agent:1"

[[credential]]
name = "api"
source = "env://RW_TEST_API_TOKEN"
placeholder_env = "API_TOKEN"

[[endpoint]]
name = "api"
host = "api.example.test"
protocol = "rest"
credential = "api"
  [[endpoint.allow]]
  method = "GET"
  path = "/v1/**"
"#;

fn supervised(fs: &str) -> String {
    format!(
        r#"
[host]
type = "container"
image = "ghcr.io/example/agent:1"

[filesystem]
read_only = ["/usr", "/lib", "/etc"]
{fs}
"#
    )
}

fn report_line(status: &str, uid: u32) -> String {
    format!(
        r#"{{"schema":"runeward.supervisor.report.v1","ok":true,"mode":"init","pid1":true,"supervisor_pid":1,"agent_pid":7,"argv0":"sleep","landlock":{{"requested":"required","status":"{status}","abi":6,"read_only":["/usr"],"read_write":["/workspace"],"skipped":[]}},"seccomp":{{"enabled":true,"arch":"aarch64","action":"errno:EPERM","denied":["ptrace"],"clone_flags_denied":[],"clone3":"errno:ENOSYS"}},"no_new_privs":true,"uid":{uid},"gid":{uid},"groups":[{uid}],"capabilities":{{"effective":[],"permitted":[],"inheritable":[],"ambient":[],"bounding":[]}},"protected_paths":["/run/runeward"],"protected_by_landlock":true,"error":null}}"#
    )
}

async fn wait_for<F: Fn() -> bool>(f: F) {
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    while std::time::Instant::now() < deadline {
        if f() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("condition not reached");
}

#[tokio::test]
async fn broker_is_built_injected_and_chronicled() {
    let h = harness(None).await;
    h.write_charter("brokered", BROKERED);
    let sb = h
        .mgr
        .create_sandbox("brokered", CreateOptions::default())
        .await
        .expect("create");
    let spec = lock(&h.fake.last_spec).clone().expect("spec");
    assert_eq!(spec.id, sb.id, "the broker's sandbox id is the sandbox's");
    let broker = spec.broker.expect("broker handed to the backend").0;
    assert_eq!(broker.sandbox_id(), sb.id);
    let placeholder = spec.env["API_TOKEN"].clone();
    assert!(placeholder.starts_with("rwph_"), "{placeholder}");
    assert_eq!(broker.placeholder_env()["API_TOKEN"], placeholder);
    assert!(
        spec.env.values().all(|v| !v.contains(TEST_TOKEN)),
        "the sandbox only ever sees the placeholder"
    );
    assert!(spec.supervisor.is_none());
    let sess = h.mgr.session_handle(&sb.id).expect("session");
    assert_eq!(sess.env["API_TOKEN"], placeholder);
    assert!(
        sess.secrets.iter().any(|s| s == TEST_TOKEN),
        "redaction set"
    );

    // Decisions on the broker's stream land in the ledger as `egress`
    // events and on the perimeter list.
    broker.publish(Decision {
        host: "api.example.test".into(),
        allow: false,
        reason: format!("placeholder sent elsewhere, not {TEST_TOKEN}"),
        endpoint: Some("api".into()),
        method: Some("POST".into()),
        path: Some("/upload".into()),
        verdict: Some(runeward_egress::Verdict::Deny),
        reason_code: Some(ReasonCode::PlaceholderMisuse),
        credential: Some("api".into()),
        ..Decision::default()
    });
    let mut egress = Vec::new();
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    while std::time::Instant::now() < deadline {
        egress = h
            .records()
            .await
            .into_iter()
            .filter(|e| e.tool == "egress")
            .collect();
        if !egress.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let ev = egress.pop().expect("egress event");
    assert_eq!(ev.verdict, "deny");
    assert_eq!(ev.action, "POST api.example.test/upload");
    assert_eq!(ev.meta["reason_code"], "placeholder-misuse");
    assert_eq!(ev.meta["endpoint"], "api");
    assert_eq!(ev.meta["credential"], "api");
    assert_eq!(ev.meta["run_id"], sess.run_id);
    assert!(
        !serde_json::to_string(&ev)
            .expect("json")
            .contains(TEST_TOKEN),
        "secrets never reach the ledger"
    );
    let perimeter = h.mgr.perimeter(&sb.id).expect("perimeter");
    assert_eq!(perimeter.len(), 1);
    assert_eq!(
        perimeter[0].reason_code,
        Some(ReasonCode::PlaceholderMisuse)
    );
    assert!(!perimeter[0].reason.contains(TEST_TOKEN), "scrubbed");
    assert!(h.mgr.perimeter("nope").is_err());

    h.mgr.kill_sandbox(&sb.id).await.expect("kill");
    assert!(lock(&sess.tasks).is_empty(), "decision pump stopped");
}

#[tokio::test]
async fn unresolvable_credentials_fail_closed() {
    let h = harness(None).await;
    h.write_charter(
        "broken",
        &BROKERED.replace("env://RW_TEST_API_TOKEN", "env://RW_TEST_UNSET_7F2A"),
    );
    let err = h
        .mgr
        .create_sandbox("broken", CreateOptions::default())
        .await
        .expect_err("unresolvable");
    assert!(err.to_string().contains("credential \"api\""), "{err}");
    assert_eq!(
        h.fake.creates.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "nothing created"
    );
}

#[tokio::test]
async fn broker_approvals_go_through_conclave() {
    let h = harness(Some(Duration::from_secs(5))).await;
    h.write_charter("brokered", BROKERED);
    let mut env = Default::default();
    let mut secrets = Vec::new();
    let c = h.mgr.load_profile("brokered").await.expect("charter");
    let gov = h
        .mgr
        .prepare_governance(&c, &mut env, &mut secrets)
        .await
        .expect("governance");
    let hook = gov.approvals.clone().expect("hook");
    let decision = Decision {
        host: "api.example.test".into(),
        method: Some("tools/call".into()),
        tool: Some("deploy".into()),
        verdict: Some(runeward_egress::Verdict::RequireApproval),
        reason_code: Some(ReasonCode::Approval),
        reason: "irreversible tool".into(),
        ..Decision::default()
    };
    let sandbox_id = gov.sandbox_id.clone();
    let req = || ApprovalRequest {
        sandbox_id: sandbox_id.clone(),
        decision: decision.clone(),
    };
    // No session yet: refused rather than waiting on nobody.
    assert_eq!(
        hook.request_approval(req()).await,
        ApprovalOutcome::Unavailable
    );

    let sess = h.inject(c, vec![]);
    let gov_sandbox = sess.sandbox.id.clone();
    h.mgr.attach_governance(&sess, gov, "").await;

    let pending = tokio::spawn({
        let hook = hook.clone();
        let r = req();
        async move { hook.request_approval(r).await }
    });
    let mgr = h.mgr.clone();
    wait_for(|| !mgr.approvals().list().is_empty()).await;
    let view = h.mgr.approvals().list().pop().expect("pending");
    assert_eq!(view.tool, "egress");
    assert_eq!(view.sandbox, gov_sandbox);
    assert_eq!(view.action, "api.example.test tools/call deploy");
    assert!(h.mgr.resolve_approval(&view.id, true, "alice").await);
    assert_eq!(pending.await.expect("join"), ApprovalOutcome::Approved);

    let pending = tokio::spawn({
        let hook = hook.clone();
        let r = req();
        async move { hook.request_approval(r).await }
    });
    wait_for(|| !mgr.approvals().list().is_empty()).await;
    let view = h.mgr.approvals().list().pop().expect("pending");
    assert!(h.mgr.resolve_approval(&view.id, false, "bob").await);
    assert!(matches!(
        pending.await.expect("join"),
        ApprovalOutcome::Denied(_)
    ));

    let records = h.records().await;
    let asked: Vec<_> = records
        .iter()
        .filter(|e| e.tool == "approval" && e.verdict == "require-approval")
        .collect();
    assert_eq!(asked.len(), 2);
    assert_eq!(asked[0].meta["tool"], "deploy");
    assert!(asked[0].meta.contains_key("approval_id"));
    let decided: Vec<_> = records
        .iter()
        .filter(|e| e.tool == "approval" && e.meta.contains_key("approver"))
        .map(|e| (e.meta["approver"].as_str(), e.verdict.as_str()))
        .collect();
    assert_eq!(decided, [("alice", "allow"), ("bob", "deny")]);
    sess.stop_tasks();
}

#[tokio::test]
async fn broker_approval_times_out_like_a_pending_call() {
    let h = harness(Some(Duration::from_millis(50))).await;
    h.write_charter("brokered", BROKERED);
    let c = h.mgr.load_profile("brokered").await.expect("charter");
    let (mut env, mut secrets) = (Default::default(), Vec::new());
    let gov = h
        .mgr
        .prepare_governance(&c, &mut env, &mut secrets)
        .await
        .expect("governance");
    let hook = gov.approvals.clone().expect("hook");
    let sess = h.inject(c, vec![]);
    let id = gov.sandbox_id.clone();
    h.mgr.attach_governance(&sess, gov, "").await;
    let out = hook
        .request_approval(ApprovalRequest {
            sandbox_id: id,
            decision: Decision {
                host: "api.example.test".into(),
                ..Decision::default()
            },
        })
        .await;
    assert_eq!(out, ApprovalOutcome::Unavailable);
    assert!(h.mgr.approvals().list().is_empty(), "no orphan left behind");
    sess.stop_tasks();
}

#[tokio::test]
async fn supervisor_report_is_evidence_and_raised_on_sandbox_info() {
    let h = harness(None).await;
    h.write_charter(
        "confined",
        &supervised("landlock = \"required\"\n[process]\nrun_as_user = \"1500\""),
    );
    *lock(&h.fake.report) = format!("{}\n", report_line("enforced", 1500));
    let sb = h
        .mgr
        .create_sandbox("confined", CreateOptions::default())
        .await
        .expect("create");
    let spec = lock(&h.fake.last_spec).clone().expect("spec");
    let sup = spec.supervisor.expect("supervisor planned");
    assert!(sup.required);
    assert_eq!(sup.config.process.user, "1500");
    assert!(spec.broker.is_none() && spec.id.is_empty());

    let info = h
        .mgr
        .list_sandbox_infos()
        .into_iter()
        .find(|i| i.sandbox.id == sb.id)
        .expect("info");
    let ev = info.enforcement.clone().expect("evidence");
    assert_eq!(
        (ev.supervisor.as_str(), ev.landlock.as_str(), ev.uid),
        ("enforced", "enforced", Some(1500))
    );
    assert!(ev.seccomp && ev.no_new_privs && ev.capabilities_dropped);
    let v = serde_json::to_value(&info).expect("json");
    assert_eq!(v["Enforcement"]["landlock"], "enforced");

    let records = h.records().await;
    let rep = records
        .iter()
        .find(|e| e.tool == "supervisor")
        .expect("supervisor evidence chronicled");
    assert_eq!(rep.action, "report");
    assert_eq!(rep.meta["landlock"], "enforced");
    assert_eq!(rep.meta["uid"], "1500");
    assert!(rep.meta["report"].contains("runeward.supervisor.report.v1"));
}

#[tokio::test]
async fn required_landlock_not_enforced_fails_closed() {
    let h = harness(None).await;
    h.write_charter("confined", &supervised("landlock = \"required\""));
    *lock(&h.fake.report) = report_line("unsupported", 1500);
    let err = h
        .mgr
        .create_sandbox("confined", CreateOptions::default())
        .await
        .expect_err("not enforced");
    assert!(err.to_string().contains("landlock"), "{err}");
    assert_eq!(lock(&h.fake.killed).len(), 1, "torn down");
    assert!(h.mgr.list_sandboxes().is_empty());
    let refused = h.records().await.pop().expect("chronicled");
    assert_eq!(
        (refused.tool.as_str(), refused.verdict.as_str()),
        ("sandbox", "deny")
    );

    // A root agent is refused too.
    *lock(&h.fake.report) = report_line("enforced", 0);
    assert!(
        h.mgr
            .create_sandbox("confined", CreateOptions::default())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn missing_supervisor_is_refused_when_required_and_recorded_when_not() {
    let h = harness(None).await;
    *lock(&h.fake.supervisor_present) = false;
    h.write_charter("identity", &supervised("[process]\nrun_as_user = \"1500\""));
    let err = h
        .mgr
        .create_sandbox("identity", CreateOptions::default())
        .await
        .expect_err("required");
    assert!(!matches!(err, Error::IsolationFloor { .. }));
    assert!(err.to_string().contains("supervisor"), "{err}");

    h.write_charter("loose", &supervised(""));
    let sb = h
        .mgr
        .create_sandbox("loose", CreateOptions::default())
        .await
        .expect("best effort runs without it");
    let sess = h.mgr.session_handle(&sb.id).expect("session");
    let ev = sess.enforcement().expect("evidence");
    assert_eq!((ev.supervisor.as_str(), ev.required), ("absent", false));
    let rec = h
        .records()
        .await
        .into_iter()
        .find(|e| e.tool == "supervisor")
        .expect("recorded");
    assert_eq!(rec.action, "absent");
    assert_eq!(rec.meta["supervisor"], "absent");
}

#[tokio::test]
async fn silent_supervisor_fails_closed() {
    let h = super::support::harness_with(None, |c| {
        c.supervisor_report_wait = Duration::from_millis(100);
    })
    .await;
    h.write_charter("loose", &supervised(""));
    let err = h
        .mgr
        .create_sandbox("loose", CreateOptions::default())
        .await
        .expect_err("no report");
    assert!(err.to_string().contains("did not report"), "{err}");
}

fn binaries_charter(network: &str) -> String {
    format!(
        r#"
[host]
type = "container"
image = "ghcr.io/example/agent:1"
user = "1500"

{network}

[[endpoint]]
name = "gh"
host = "api.github.com"
protocol = "tcp"
binaries = ["/usr/bin/gh"]
"#
    )
}

#[tokio::test]
async fn endpoint_binaries_need_strict_egress_and_get_attribution() {
    let h = harness(None).await;
    // Cooperative egress cannot attribute connections: refused up front.
    h.write_charter("coop", &binaries_charter(""));
    let err = h
        .mgr
        .create_sandbox("coop", CreateOptions::default())
        .await
        .expect_err("cooperative");
    assert!(err.to_string().contains("strict egress"), "{err}");
    assert_eq!(
        h.fake.creates.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "nothing created"
    );

    // Strict egress: the broker gets an attribution key and the supervisor
    // is required, without [filesystem] or [process], with the same key.
    h.write_charter(
        "strict",
        &binaries_charter("[network]\ndefault = \"deny\"\nenforce = \"strict\""),
    );
    let c = h.mgr.load_profile("strict").await.expect("charter");
    let (mut env, mut secrets) = (Default::default(), Vec::new());
    let gov = h
        .mgr
        .prepare_governance(&c, &mut env, &mut secrets)
        .await
        .expect("governance");
    let broker = gov.broker.as_ref().expect("broker");
    let (socket, key) = broker.attribution().expect("attribution");
    assert_eq!(socket, runeward_egress::attribution::DEFAULT_SOCKET);
    let sup = gov.supervisor.as_ref().expect("supervisor");
    assert!(sup.required);
    let a = sup.config.attribution.as_ref().expect("helper settings");
    assert_eq!(a.key, key.to_hex().as_str());
    assert_eq!(a.binaries, ["/usr/bin/gh"]);
    // The sidecar document carries the same key.
    let doc = broker.sidecar_config();
    assert_eq!(
        doc.attribution.as_ref().map(|a| a.key.expose()),
        Some(key.to_hex().as_str())
    );

    // A supervisor that does not report attribution fails the create.
    *lock(&h.fake.report) = report_line("off", 1500);
    let err = h
        .mgr
        .create_sandbox("strict", CreateOptions::default())
        .await
        .expect_err("no attribution reported");
    assert!(err.to_string().contains("binary attribution"), "{err}");
}

#[test]
fn binary_decisions_reach_the_ledger_meta() {
    let mut m = std::collections::BTreeMap::new();
    crate::governance::decision_meta(
        &mut m,
        &Decision {
            host: "api.github.com".into(),
            endpoint: Some("gh".into()),
            binaries: Some(vec!["/usr/bin/gh".into()]),
            binary: Some("/usr/bin/python3.11".into()),
            binary_enforced: Some(true),
            reason_code: Some(ReasonCode::Binary),
            ..Decision::default()
        },
    );
    assert_eq!(m["binary"], "/usr/bin/python3.11");
    assert_eq!(m["binary_enforced"], "true");
    assert_eq!(m["reason_code"], "binary");
}
