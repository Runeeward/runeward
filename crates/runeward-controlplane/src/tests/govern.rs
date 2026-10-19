//! The governed path: policy, approvals, guardrails, budgets, scrubbing.

use std::sync::Arc;
use std::time::Duration;

use regex::Regex;
use runeward_backend::ExecResult;
use runeward_charter::{Audit, Charter, Ide, Limits, Verdict};
use runeward_ledger::Scrubber;

use super::support::{argv, harness, harness_with, rule};
use crate::govern::GovernCall;
use crate::{Error, with_actor};

#[tokio::test]
async fn govern_allow() {
    let h = harness(Some(Duration::from_secs(1))).await;
    h.inject(Charter::default(), vec![]);
    let res = h
        .mgr
        .shell("fake-1", &argv(&["echo", "hi"]), "")
        .await
        .expect("shell");
    assert_eq!(res.verdict, Verdict::Allow);
    assert_eq!(res.stdout, "echo hi");
    h.mgr.verify_ledger().await.expect("ledger verifies");
    let last = h.records().await.pop().expect("event");
    assert_eq!(
        (last.tool.as_str(), last.verdict.as_str()),
        ("shell", "allow")
    );
    assert_eq!(last.meta["isolation"], "container");
    assert!(!last.sig.is_empty(), "ledger is signed");
}

#[tokio::test]
async fn code_capability_is_enforced_before_execution() {
    let h = harness(Some(Duration::from_secs(1))).await;
    h.inject(Charter::default(), vec![]);
    let err = h
        .mgr
        .python("fake-1", "print(1)")
        .await
        .expect_err("undeclared");
    assert!(
        matches!(err, Error::BadInput(_)) && err.to_string().contains("not declared"),
        "{err}"
    );
    assert_eq!(h.fake.execs(), 0);

    let c = Charter {
        capabilities: vec!["python".into()],
        ..Charter::default()
    };
    h.inject(c, vec![]);
    let res = h.mgr.python("fake-1", "print(1)").await.expect("python");
    assert_eq!((res.exit_code, h.fake.execs()), (0, 1));
    assert_eq!(
        super::support::lock(&h.fake.calls)[0],
        argv(&["python3", "-c", "print(1)"])
    );
}

#[tokio::test]
async fn govern_deny_never_executes() {
    let h = harness(Some(Duration::from_secs(1))).await;
    h.inject(
        Charter::default(),
        vec![rule("shell", "rm *", Verdict::Deny, "no deletes")],
    );
    let res = h
        .mgr
        .shell("fake-1", &argv(&["rm", "-rf", "/"]), "")
        .await
        .expect("shell");
    assert_eq!(
        (res.verdict, res.reason.as_str()),
        (Verdict::Deny, "no deletes")
    );
    assert_eq!(h.fake.execs(), 0);
    let last = h.records().await.pop().expect("event");
    assert_eq!((last.verdict.as_str(), last.exit_code), ("deny", -1));
    assert_eq!(last.meta["reason"], "no deletes");
}

#[tokio::test]
async fn approval_times_out_to_pending() {
    let h = harness(Some(Duration::from_millis(20))).await;
    h.inject(
        Charter::default(),
        vec![rule(
            "file.write",
            "/etc/*",
            Verdict::RequireApproval,
            "sensitive path",
        )],
    );
    // Unconfined workdir so the absolute path reaches policy.
    let res = h
        .mgr
        .file_write("fake-1", "/etc/passwd", "x")
        .await
        .expect("write");
    assert!(
        res.pending && res.verdict == Verdict::RequireApproval,
        "{res:?}"
    );
    assert!(!res.approval_id.is_empty());
    assert!(
        h.mgr.approvals().list().is_empty(),
        "timed-out approval is forgotten"
    );
    assert_eq!(h.fake.execs(), 0);
}

#[tokio::test]
async fn approval_approved_then_runs_and_denial_is_recorded() {
    let h = harness(Some(Duration::from_secs(5))).await;
    h.inject(
        Charter::default(),
        vec![rule("file.write", "/etc/*", Verdict::RequireApproval, "")],
    );
    let mgr = Arc::clone(&h.mgr);
    let call =
        tokio::spawn(async move { mgr.file_write("fake-1", "/etc/hosts", "127.0.0.1 x").await });
    let id = wait_for_approval(&h).await;
    let view = h.mgr.approvals().get(&id).expect("pending");
    assert_eq!(
        (view.tool.as_str(), view.action.as_str()),
        ("file.write", "/etc/hosts")
    );
    assert!(h.mgr.resolve_approval(&id, true, "alice").await);
    let res = call.await.expect("join").expect("write");
    assert_eq!(res.verdict, Verdict::Allow);
    assert_eq!(h.fake.execs(), 1);
    let approver = h
        .records()
        .await
        .into_iter()
        .find(|e| e.tool == "approval" && e.verdict == "allow")
        .expect("approval decision recorded");
    assert_eq!(approver.meta["approver"], "alice");
    assert_eq!(approver.meta["decision"], "approved");

    let mgr = Arc::clone(&h.mgr);
    let call = tokio::spawn(async move { mgr.file_write("fake-1", "/etc/x", "y").await });
    let id = wait_for_approval(&h).await;
    assert!(h.mgr.resolve_approval(&id, false, "").await);
    let res = call.await.expect("join").expect("write");
    assert_eq!(
        (res.verdict, res.reason.as_str()),
        (Verdict::Deny, "denied by approver")
    );
    assert_eq!(res.approval_id, id);
    assert_eq!(h.fake.execs(), 1, "denied call never ran");
    assert!(
        !h.mgr.resolve_approval(&id, true, "x").await,
        "already resolved"
    );
}

async fn wait_for_approval(h: &super::support::Harness) -> String {
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    while std::time::Instant::now() < deadline {
        if let Some(a) = h.mgr.approvals().list().pop() {
            return a.id;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("approval never appeared");
}

#[tokio::test]
async fn guard_max_execs() {
    let h = harness(Some(Duration::from_secs(1))).await;
    let c = Charter {
        name: "capped".into(),
        limits: Limits {
            max_execs: 1,
            ..Limits::default()
        },
        ..Charter::default()
    };
    h.inject(c, vec![]);
    let first = h
        .mgr
        .shell("fake-1", &argv(&["echo", "1"]), "")
        .await
        .expect("1");
    assert_eq!(first.verdict, Verdict::Allow);
    let second = h
        .mgr
        .shell("fake-1", &argv(&["echo", "2"]), "")
        .await
        .expect("2");
    assert_eq!(second.verdict, Verdict::Deny);
    assert_eq!(second.reason, "policy: max execs exceeded");
}

#[tokio::test]
async fn custom_scrub_patterns_cover_output_and_ledger() {
    let h = harness(Some(Duration::from_secs(1))).await;
    h.inject_with(Charter::default(), vec![], |b| {
        b.scrubber(Scrubber::new([
            Regex::new("RUNETOKEN-[0-9]{4}").expect("re")
        ]))
    });
    let res = h
        .mgr
        .shell("fake-1", &argv(&["echo", "RUNETOKEN-4242"]), "")
        .await
        .expect("shell");
    assert!(!res.stdout.contains("RUNETOKEN-4242"), "{}", res.stdout);
    let last = h.records().await.pop().expect("event");
    assert!(!last.action.contains("RUNETOKEN-4242"));
    assert!(last.args.iter().all(|a| !a.contains("RUNETOKEN-4242")));
    assert!(last.redacted);
}

#[tokio::test]
async fn declared_secrets_are_redacted_unless_disabled() {
    let h = harness(Some(Duration::from_secs(1))).await;
    h.inject_with(Charter::default(), vec![], |b| {
        b.secrets(vec!["hunter2-value".into()])
    });
    let res = h
        .mgr
        .shell("fake-1", &argv(&["echo", "hunter2-value"]), "")
        .await
        .expect("shell");
    assert!(!res.stdout.contains("hunter2-value"));
    let off = Charter {
        audit: Audit {
            redact: Some(false),
            ..Audit::default()
        },
        ..Charter::default()
    };
    h.inject_with(off, vec![], |b| b.secrets(vec!["hunter2-value".into()]));
    let res = h
        .mgr
        .shell("fake-1", &argv(&["echo", "hunter2-value"]), "")
        .await
        .expect("shell");
    assert_eq!(res.stdout, "echo hunter2-value", "redaction is opt-out");
}

#[tokio::test]
async fn raw_stdout_preserves_screenshots() {
    let h = harness(Some(Duration::from_secs(1))).await;
    let sess = h.inject(Charter::default(), vec![]);
    let blob = format!(
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJ{}",
        "AAAABBBBCCCCDDDD1234".repeat(20)
    );
    h.fake.set_result(ExecResult {
        stdout: blob.clone(),
        duration: Duration::from_millis(1),
        ..ExecResult::default()
    });
    let run = || async {
        Ok(ExecResult {
            stdout: blob.clone(),
            ..ExecResult::default()
        })
    };
    let scrubbed = h
        .mgr
        .govern(
            &sess,
            GovernCall::new("browser", "u", argv(&["u", "text"])),
            run,
        )
        .await
        .expect("govern");
    assert!(
        !scrubbed.stdout.contains(&blob),
        "default path scrubs the blob"
    );
    let mut call = GovernCall::new("browser", "u", argv(&["u", "screenshot"]));
    call.raw_stdout = true;
    let raw = h.mgr.govern(&sess, call, run).await.expect("govern");
    assert_eq!(raw.stdout, blob);
}

#[tokio::test]
async fn usage_validation_and_budget() {
    let h = harness(Some(Duration::from_secs(1))).await;
    let c = Charter {
        limits: Limits {
            max_tokens: 1,
            ..Limits::default()
        },
        ..Charter::default()
    };
    h.inject(c, vec![]);
    assert!(h.mgr.record_usage("fake-1", -1, 0.0).await.is_err());
    assert!(h.mgr.record_usage("fake-1", 0, -1.0).await.is_err());
    assert!(h.mgr.record_usage("fake-1", 0, f64::NAN).await.is_err());
    h.mgr
        .record_usage(
            "fake-1",
            crate::citadels::MAX_CLIENT_USAGE_TOKEN_DELTA + 1,
            0.0,
        )
        .await
        .expect("absurd delta ignored");
    assert_eq!(h.mgr.sandbox_usage("fake-1").tokens, 0);
    assert!(h.mgr.record_usage("missing", 1, 0.0).await.is_err());

    h.mgr.record_usage("fake-1", 2, 0.5).await.expect("usage");
    let last = h.records().await.pop().expect("usage event");
    assert_eq!(
        (last.tool.as_str(), last.meta["tokens_tot"].as_str()),
        ("usage", "2")
    );
    assert_eq!(last.meta["cost_usd"], "0.5");
    let res = h
        .mgr
        .shell("fake-1", &argv(&["echo"]), "")
        .await
        .expect("shell");
    assert_eq!(res.verdict, Verdict::Deny, "over budget fails closed");
    assert!(
        res.reason.contains("token budget exhausted"),
        "{}",
        res.reason
    );
}

#[tokio::test]
async fn budget_skipped_when_client_usage_ignored() {
    let h = harness_with(Some(Duration::from_secs(1)), |c| {
        c.ignore_client_usage = true
    })
    .await;
    let c = Charter {
        limits: Limits {
            max_tokens: 1,
            ..Limits::default()
        },
        ..Charter::default()
    };
    h.inject(c, vec![]);
    h.mgr.record_usage("fake-1", 2, 0.0).await.expect("usage");
    let res = h
        .mgr
        .shell("fake-1", &argv(&["echo", "ok"]), "")
        .await
        .expect("shell");
    assert_eq!(res.verdict, Verdict::Allow);
}

#[tokio::test]
async fn chronicle_uses_current_actor_within_tenant() {
    let h = harness(None).await;
    h.inject_with(Charter::default(), vec![], |b| {
        b.owner("team-alpha").actor("creator").run_id("run-1")
    });
    with_actor(
        "codex-agent",
        h.mgr.shell("fake-1", &argv(&["echo", "hi"]), ""),
    )
    .await
    .expect("shell");
    let last = h.records().await.pop().expect("event");
    assert_eq!(last.meta["actor"], "codex-agent");
    assert_eq!(last.meta["tenant"], "team-alpha");
    assert_eq!(last.meta["run_id"], "run-1");
    h.mgr
        .shell("fake-1", &argv(&["echo", "hi"]), "")
        .await
        .expect("shell");
    assert_eq!(
        h.records().await.pop().expect("event").meta["actor"],
        "creator"
    );
}

#[tokio::test]
async fn file_tools_are_confined_and_quoted() {
    let h = harness(None).await;
    h.inject_with(Charter::default(), vec![], |b| b.workdir("/workspace"));
    let err = h
        .mgr
        .file_read("fake-1", "../etc/passwd")
        .await
        .expect_err("escape");
    assert_eq!(err.client_status(), Some(400));
    h.mgr.file_read("fake-1", "-n").await.expect("read");
    h.mgr.file_search("fake-1", "-x", "").await.expect("search");
    h.mgr
        .file_write("fake-1", "a b/c.txt", "hé")
        .await
        .expect("write");
    h.mgr.file_list("fake-1", "").await.expect("list");
    let calls = super::support::lock(&h.fake.calls).clone();
    assert_eq!(calls[0], argv(&["cat", "--", "/workspace/-n"]));
    assert_eq!(
        calls[1],
        argv(&["grep", "-rn", "-e", "-x", "--", "/workspace"])
    );
    assert_eq!(
        calls[2][2],
        "mkdir -p \"$(dirname '/workspace/a b/c.txt')\" && printf %s 'aMOp' | base64 -d > '/workspace/a b/c.txt'"
    );
    assert_eq!(calls[3], argv(&["ls", "-la", "--", "/workspace"]));
}

#[tokio::test]
async fn terminal_attach_is_policy_gated() {
    let h = harness(None).await;
    h.inject(
        Charter::default(),
        vec![rule("terminal", "*", Verdict::RequireApproval, "")],
    );
    let err = h
        .mgr
        .attach_terminal("fake-1", runeward_backend::PtyStream::default())
        .await
        .expect_err("approval counts as deny");
    assert_eq!(err.to_string(), "terminal attach denied by policy");
    h.inject(Charter::default(), vec![]);
    h.mgr
        .attach_terminal("fake-1", runeward_backend::PtyStream::default())
        .await
        .expect("attach");
}

#[tokio::test]
async fn conversation_publishes_redacted_display_safe_turns() {
    let h = harness(None).await;
    h.inject_with(Charter::default(), vec![], |b| {
        b.actor("agent-a")
            .run_id("run-1")
            .secrets(vec!["declared-secret".into()])
    });
    let mut stream = h.mgr.subscribe_conversation("fake-1").expect("subscribe");
    let msg = with_actor(
        "codex",
        h.mgr.publish_conversation(
            "fake-1",
            "assistant",
            "done declared-secret\x1b]52;c;bad\x07",
            "",
        ),
    )
    .await
    .expect("publish");
    assert_eq!(
        (msg.author.as_str(), msg.run_id.as_str()),
        ("codex", "run-1")
    );
    assert!(msg.redacted);
    assert!(
        !msg.content.contains("declared-secret")
            && !msg.content.contains('\x1b')
            && !msg.content.contains('\x07')
    );
    let got = tokio::time::timeout(Duration::from_secs(1), stream.recv())
        .await
        .expect("timely")
        .expect("turn");
    assert_eq!(got.id, msg.id);
    let history = h
        .mgr
        .conversation_history("fake-1", 0, 10)
        .expect("history");
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].id, msg.id);

    // Validation.
    assert!(
        h.mgr
            .publish_conversation("fake-1", "owner", "hello", "")
            .await
            .is_err()
    );
    assert!(
        h.mgr
            .publish_conversation("fake-1", "user", "", "")
            .await
            .is_err()
    );
    assert!(
        h.mgr
            .publish_conversation("missing", "user", "hello", "")
            .await
            .is_err()
    );
    assert!(
        h.mgr
            .publish_conversation("fake-1", "user", &"x".repeat((64 << 10) + 1), "")
            .await
            .is_err()
    );

    // Killing the Citadel ends live subscriptions.
    h.mgr.kill_sandbox("fake-1").await.expect("kill");
    assert!(stream.recv().await.is_none());
}

#[tokio::test]
async fn ide_flags_and_endpoint_lifecycle() {
    let h = harness(None).await;
    assert!(!h.mgr.experimental_ide_enabled());
    assert_eq!(h.mgr.ide_readiness().status, "fail");
    let h2 = harness_with(None, |c| c.experimental_ide = true).await;
    assert!(h2.mgr.experimental_ide_enabled());
    assert_eq!(h2.mgr.ide_readiness().status, "ok");

    let c = Charter {
        name: "p".into(),
        ide: Ide {
            enabled: true,
            port: 8080,
            agents: vec!["codex".into()],
            ..Ide::default()
        },
        ..Charter::default()
    };
    h.inject(c, vec![]);
    assert_eq!(h.mgr.ide_endpoint("fake-1"), None);
    h.mgr.set_ide_endpoint_for_test("fake-1", "10.0.0.2:8080");
    assert_eq!(
        h.mgr.ide_endpoint("fake-1").as_deref(),
        Some("10.0.0.2:8080")
    );
    assert_eq!(h.mgr.ide_agents("fake-1"), ["codex"]);
    h.mgr.kill_sandbox("fake-1").await.expect("kill");
    let events = h.records().await;
    let close = &events[events.len() - 2];
    assert_eq!(
        (close.tool.as_str(), close.action.as_str()),
        ("ide", "close")
    );
    assert_eq!(close.args, ["10.0.0.2:8080"]);
}

#[tokio::test]
async fn browser_is_flag_and_capability_gated() {
    let h = harness(None).await;
    h.inject(Charter::default(), vec![]);
    let err = h
        .mgr
        .browser("fake-1", "https://e.com", "text")
        .await
        .expect_err("flag off");
    assert!(err.to_string().contains("experimental"));
    let h = harness_with(None, |c| c.experimental_browser = true).await;
    h.inject(Charter::default(), vec![]);
    let err = h
        .mgr
        .browser("fake-1", "https://e.com", "text")
        .await
        .expect_err("no capability");
    assert_eq!(err.client_status(), Some(400));
    let c = Charter {
        capabilities: vec!["browser".into()],
        ..Charter::default()
    };
    h.inject(c, vec![]);
    let res = h
        .mgr
        .browser("fake-1", "https://e.com", "text")
        .await
        .expect("browser");
    assert_eq!(res.verdict, Verdict::Allow);
    let err = h
        .mgr
        .browser_act("fake-1", "nope", Default::default())
        .await
        .expect_err("unknown");
    assert_eq!(err.client_status(), Some(404));
}

#[tokio::test]
async fn unknown_sandbox_is_not_found() {
    let h = harness(None).await;
    let err = h
        .mgr
        .shell("nope", &argv(&["true"]), "")
        .await
        .expect_err("missing");
    assert_eq!(err.client_status(), Some(404));
    assert_eq!(err.to_string(), "sandbox \"nope\" not found");
    assert!(h.mgr.kill_sandbox("nope").await.is_err());
}
