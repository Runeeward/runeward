//! The REST-client commands against an in-process `runeward serve`
//! (the server's router over a Manager with an in-memory backend, on a
//! loopback port). No Docker.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use runeward_backend::{
    Backend, BackendConfig, Driver, ExecRequest, ExecResult, IsolationTier, PtyStream, Registry,
    Result as BResult, Sandbox, SnapshotRef, Spec,
};
use runeward_charter::{Charter, File, SignedCharters};
use runeward_controlplane::{Manager, ManagerConfig};
use serde_json::{Value, json};
use tokio::io::{AsyncWrite, AsyncWriteExt};

use super::*;
use crate::cohort::{CONTEXT_BEGIN, CONTEXT_END, EXIT_REFUSED, EXIT_RETRYABLE, Refused};

/// Echoes exec argv as stdout and supports sleep.
#[derive(Debug, Default)]
struct FakeBackend;

#[async_trait]
impl Backend for FakeBackend {
    fn name(&self) -> &str {
        "fake"
    }

    fn isolation_tier(&self) -> IsolationTier {
        IsolationTier::Container
    }

    async fn create(&self, spec: Spec) -> BResult<Sandbox> {
        Ok(Sandbox {
            id: format!("cit-{}", hex::encode(rand::random::<[u8; 4]>())),
            profile: spec.profile,
            backend: "fake".into(),
            image: spec.image,
            status: "running".into(),
            ..Sandbox::default()
        })
    }

    async fn exec(&self, _: &str, req: ExecRequest) -> BResult<ExecResult> {
        Ok(ExecResult {
            stdout: req.command.join(" "),
            duration: Duration::from_millis(1),
            ..ExecResult::default()
        })
    }

    async fn attach_pty(&self, _: &str, _: PtyStream) -> BResult<()> {
        Ok(())
    }

    async fn copy_files(&self, _: &str, _: &[File]) -> BResult<()> {
        Ok(())
    }

    async fn export_workspace(
        &self,
        _: &str,
        w: &mut (dyn AsyncWrite + Send + Unpin),
    ) -> BResult<()> {
        let _ = w.write_all(b"tar").await;
        Ok(())
    }

    async fn snapshot(&self, id: &str, name: &str) -> BResult<SnapshotRef> {
        Ok(SnapshotRef {
            id: format!("snap-{id}"),
            name: name.into(),
            profile: String::new(),
            backend: "fake".into(),
            location: format!("snapshots/{id}"),
            sha256: String::new(),
            created: chrono::DateTime::UNIX_EPOCH,
        })
    }

    async fn restore(&self, s: &SnapshotRef) -> BResult<Sandbox> {
        self.create(Spec {
            profile: s.profile.clone(),
            ..Spec::default()
        })
        .await
    }

    fn supports_sleep(&self) -> bool {
        true
    }

    async fn stop(&self, _: &str) -> BResult<()> {
        Ok(())
    }

    async fn start(&self, id: &str, spec: Spec) -> BResult<Sandbox> {
        Ok(Sandbox {
            id: id.into(),
            profile: spec.profile,
            backend: "fake".into(),
            image: spec.image,
            status: "running".into(),
            ..Sandbox::default()
        })
    }

    async fn kill(&self, _: &str) -> BResult<()> {
        Ok(())
    }

    async fn list(&self) -> BResult<Vec<Sandbox>> {
        Ok(Vec::new())
    }

    async fn exists(&self, _: &str) -> bool {
        true
    }
}

struct FakeDriver;

#[async_trait]
impl Driver for FakeDriver {
    async fn open(&self, _: &Charter, _: &BackendConfig) -> BResult<Arc<dyn Backend>> {
        Ok(Arc::new(FakeBackend))
    }
}

const PERSISTENT: &str = "[host]\ntype = \"container\"\nimage = \"debian:stable-slim\"\n[workspace]\npersist = true\nidle_timeout = \"15m\"\n";
const GUARDED: &str = "[host]\ntype = \"container\"\nimage = \"debian:stable-slim\"\n[[policy]]\ntool = \"citadel\"\nmatch = \"fork*\"\nverdict = \"deny\"\nreason = \"forks are not allowed here\"\n";
const CREW: &str = "[host]\ntype = \"container\"\nimage = \"debian:stable-slim\"\n[cohort]\nreplicas = 1\ntask_board = [\"migrate the billing database\"]\n";

/// A control plane on a loopback port.
struct Plane {
    base: String,
    _dir: tempfile::TempDir,
}

impl Plane {
    async fn start(rate_limit: Option<f64>) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let charters = dir.path().join("charters");
        std::fs::create_dir_all(&charters).unwrap();
        std::fs::create_dir_all(dir.path().join("state")).unwrap();
        for (name, body) in [("keep", PERSISTENT), ("guarded", GUARDED), ("crew", CREW)] {
            std::fs::write(charters.join(format!("{name}.toml")), body).unwrap();
        }
        let cfg = ManagerConfig {
            config_dir: Some(charters),
            state_dir: Some(dir.path().join("state")),
            sweep_interval: None,
            context_tick: None,
            signed_charters: SignedCharters::Disabled,
            policy_default: None,
            ..ManagerConfig::default()
        };
        let mut registry = Registry::new();
        for host in ["", "container", "k8s"] {
            registry.register(host, Arc::new(FakeDriver));
        }
        let mgr = Manager::builder(cfg)
            .registry(registry)
            .build()
            .await
            .unwrap();
        let router = runeward_server::Server::new(mgr)
            .rate_limit(rate_limit)
            .router();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(
                listener,
                router.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await;
        });
        Self {
            base: format!("http://{addr}"),
            _dir: dir,
        }
    }

    fn client(&self) -> FleetClient {
        FleetClient::new(&self.base, "")
    }
}

/// Runs a command with captured output.
macro_rules! capture {
    ($json:expr, |$out:ident| $body:expr) => {{
        let mut buf: Vec<u8> = Vec::new();
        let res = {
            let mut o = Out {
                w: &mut buf,
                json: $json,
            };
            let $out = &mut o;
            $body.await
        };
        (res, String::from_utf8(buf).unwrap())
    }};
}

async fn create_citadel(c: &FleetClient, profile: &str) -> String {
    let v: Value = c
        .post("/v1/citadels", json!({"profile": profile}))
        .await
        .unwrap();
    v["id"].as_str().unwrap().to_owned()
}

fn refused(e: &anyhow::Error) -> &Refused {
    e.downcast_ref::<Refused>()
        .unwrap_or_else(|| panic!("not a refusal: {e:#}"))
}

#[tokio::test]
async fn citadel_fork_sleep_wake_status_and_perimeter() {
    let p = Plane::start(None).await;
    let c = p.client();
    let id = create_citadel(&c, "keep").await;

    let (res, text) = capture!(false, |o| citadel_status(&c, o, &id));
    res.unwrap();
    assert!(text.contains(&format!("citadel     {id}")), "{text}");
    assert!(text.contains("isolation   container"), "{text}");
    assert!(text.contains("persistent, running (idle"), "{text}");
    assert!(text.contains("of 900s"), "{text}");

    let (res, text) = capture!(false, |o| citadel_sleep(&c, o, &id));
    res.unwrap();
    assert_eq!(text, format!("citadel {id} is asleep (workspace kept)\n"));
    let (res, text) = capture!(true, |o| citadel_status(&c, o, &id));
    res.unwrap();
    let v: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(v["workspace"]["state"], "sleeping", "{v}");

    let (res, text) = capture!(false, |o| citadel_wake(&c, o, &id));
    res.unwrap();
    assert_eq!(text, format!("citadel {id} is awake\n"));

    let (res, text) = capture!(false, |o| citadel_fork(&c, o, &id, "", "codex", ""));
    res.unwrap();
    assert!(text.starts_with(&format!("forked {id} -> cit-")), "{text}");
    assert!(text.contains("charter=keep, isolation=container"), "{text}");

    let (res, text) = capture!(false, |o| citadel_perimeter(&c, o, &id));
    res.unwrap();
    assert_eq!(text, format!("no perimeter decisions recorded for {id}\n"));
    let (res, text) = capture!(true, |o| citadel_perimeter(&c, o, &id));
    res.unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&text).unwrap()["decisions"],
        json!([])
    );
}

#[tokio::test]
async fn policy_refusals_exit_3_and_request_errors_exit_1() {
    let p = Plane::start(None).await;
    let c = p.client();
    let id = create_citadel(&c, "guarded").await;
    let (res, text) = capture!(false, |o| citadel_fork(&c, o, &id, "", "", ""));
    assert!(text.is_empty());
    let err = res.unwrap_err();
    let r = refused(&err);
    // The fork gate reports a Charter denial as a permission refusal.
    assert_eq!(r.reason, "permission", "{r:?}");
    assert_eq!(r.message, "forks are not allowed here");
    assert!(!r.retryable);
    assert!(!r.request_id.is_empty());
    assert_eq!(r.exit_code(), EXIT_REFUSED);
    assert!(
        err.to_string().starts_with(&format!(
            "refused (permission, retryable=false, request_id={}): ",
            r.request_id
        )),
        "{err}"
    );

    // Through the real entry point: the exit code is the contract.
    let argv = |args: &[&str]| -> Vec<std::ffi::OsString> { args.iter().map(Into::into).collect() };
    let code = crate::execute(argv(&["citadel", "fork", &id, "--base", &p.base])).await;
    assert_eq!(code, EXIT_REFUSED);
    let code = crate::execute(argv(&["citadel", "status", "nope", "--base", &p.base])).await;
    assert_eq!(code, 1);
}

#[tokio::test]
async fn capacity_refusals_are_retryable_and_exit_4() {
    let p = Plane::start(Some(0.5)).await;
    let c = p.client();
    let mut last = None;
    for _ in 0..4 {
        let (res, _) = capture!(false, |o| citadel_status(&c, o, "nope"));
        if let Err(e) = res
            && refused(&e).reason == "capacity"
        {
            last = Some(e);
            break;
        }
    }
    let err = last.expect("rate limit never refused");
    let r = refused(&err);
    assert!(r.retryable);
    assert_eq!(r.exit_code(), EXIT_RETRYABLE);
    let code = crate::execute(
        ["citadel", "status", "nope", "--base", p.base.as_str()]
            .iter()
            .map(Into::into)
            .collect(),
    )
    .await;
    assert_eq!(code, EXIT_RETRYABLE);
}

#[tokio::test]
async fn session_turn_attach_and_cancel() {
    let p = Plane::start(None).await;
    let c = p.client();
    let id = create_citadel(&c, "keep").await;
    let started: Value = c
        .post(
            &format!("/v1/citadels/{id}/agent-sessions"),
            json!({"command": ["codex", "exec", "first"], "agent": "codex"}),
        )
        .await
        .unwrap();
    let sid = started["id"].as_str().unwrap().to_owned();
    // Attach replays from the start and follows to the end.
    let (res, text) = capture!(true, |o| session_attach(&c, o, &sid, 0));
    res.unwrap();
    let first: Vec<Value> = text
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert!(!first.is_empty(), "{text}");
    assert!(
        first
            .iter()
            .any(|e| e["stream"] == "status" && e["data"] == "completed"),
        "{text}"
    );
    let last_seq = first.last().unwrap()["seq"].as_i64().unwrap();

    // The next turn runs the session's agent CLI with the prompt and
    // streams only its own events.
    let (res, text) = capture!(true, |o| session_turn(&c, o, &sid, "second prompt", "", ""));
    res.unwrap();
    let events: Vec<Value> = text
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert!(!events.is_empty());
    assert!(events.iter().all(|e| e["seq"].as_i64().unwrap() > last_seq));
    let s: Value = c.get(&format!("/v1/agent-sessions/{sid}")).await.unwrap();
    assert_eq!(s["status"], "completed");
    assert_eq!(
        s["command"],
        json!([
            "codex",
            "exec",
            "--skip-git-repo-check",
            "--dangerously-bypass-approvals-and-sandbox",
            "second prompt"
        ])
    );

    // Replaying after the first turn shows only the second.
    let (res, text) = capture!(true, |o| session_attach(&c, o, &sid, last_seq));
    res.unwrap();
    assert_eq!(text.lines().count(), events.len());

    let (res, text) = capture!(false, |o| session_cancel(&c, o, &sid));
    res.unwrap();
    assert_eq!(text, format!("session {sid} has no active turn\n"));

    let (res, _) = capture!(false, |o| session_cancel(&c, o, "nope"));
    assert_eq!(refused(&res.unwrap_err()).reason, "request");
}

#[tokio::test]
async fn cohort_memory_notes_briefs_context_and_handoffs() {
    let p = Plane::start(None).await;
    let c = p.client();
    let fv: Value = c
        .post("/v1/cohorts", json!({"profile": "crew"}))
        .await
        .unwrap();
    let fleet = fv["id"].as_str().unwrap().to_owned();
    let tasks: Value = c.get(&format!("/v1/cohorts/{fleet}/tasks")).await.unwrap();
    let task = tasks["tasks"][0]["id"].as_str().unwrap().to_owned();

    let tags = vec!["database".to_owned()];
    let (res, text) = capture!(false, |o| memory_put(
        &c,
        o,
        &fleet,
        "billing/db",
        "postgres 16 on the primary",
        &tags,
        Some(0)
    ));
    res.unwrap();
    assert_eq!(text, "stored billing/db (version 1)\n");
    let (res, _) = capture!(false, |o| memory_put(
        &c,
        o,
        &fleet,
        "billing/db",
        "stale",
        &tags,
        Some(0)
    ));
    let err = res.unwrap_err();
    assert!(
        err.to_string().contains("409") || err.downcast_ref::<Refused>().is_some(),
        "{err}"
    );

    let (res, text) = capture!(false, |o| memory_get(&c, o, &fleet, "billing/db"));
    res.unwrap();
    assert!(text.starts_with("billing/db (version 1, by "), "{text}");
    assert!(text.contains("tags: database\n"), "{text}");
    assert!(text.ends_with("postgres 16 on the primary\n"), "{text}");

    let (res, text) = capture!(false, |o| memory_search(
        &c,
        o,
        &fleet,
        "postgres",
        &[],
        0,
        0
    ));
    res.unwrap();
    assert!(text.starts_with("KEY"), "{text}");
    assert!(text.contains("billing/db  v1"), "{text}");
    let (res, _) = capture!(false, |o| memory_search(&c, o, &fleet, " ", &[], 0, 0));
    assert!(res.is_err());
    let (res, text) = capture!(true, |o| memory_list(&c, o, &fleet));
    res.unwrap();
    let v: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(v["entries"][0]["key"], "billing/db");

    let (res, text) = capture!(false, |o| task_note(
        &c,
        o,
        &fleet,
        &task,
        "schema lives in db/schema.sql"
    ));
    res.unwrap();
    assert_eq!(text, format!("added a handoff note to task {task}\n"));
    let (res, text) = capture!(false, |o| task_brief(
        &c,
        o,
        &fleet,
        &task,
        "*",
        "keep the migration reversible"
    ));
    res.unwrap();
    assert_eq!(
        text,
        format!("set the brief for every agent on task {task}\n")
    );

    let (res, text) = capture!(false, |o| task_context(&c, o, &fleet, &task, "", 0));
    res.unwrap();
    assert!(text.contains("migrate the billing database"), "{text}");
    assert!(
        text.contains("Brief:\nkeep the migration reversible"),
        "{text}"
    );
    assert!(text.contains("schema lives in db/schema.sql"), "{text}");
    assert!(
        text.contains("billing/db [database] (v1): postgres 16"),
        "{text}"
    );

    let (res, text) = capture!(false, |o| task_child(
        &c,
        o,
        &fleet,
        &task,
        "write the rollback"
    ));
    res.unwrap();
    assert!(text.contains(&format!("under {task}")), "{text}");

    // `cohort run` claims with context, puts it in the agent's prompt in a
    // delimited section and completes with a handoff note.
    c.drain(&fleet, "codex", "").await.unwrap();
    let sessions: Value = c
        .get(&format!("/v1/agent-sessions?cohort_id={fleet}"))
        .await
        .unwrap();
    let parent_run = sessions["sessions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["task_id"] == task.as_str())
        .expect("a session for the seeded task");
    let prompt = parent_run["command"].as_array().unwrap().last().unwrap();
    let prompt = prompt.as_str().unwrap();
    assert!(
        prompt.starts_with("migrate the billing database\n\n"),
        "{prompt}"
    );
    assert!(prompt.contains(CONTEXT_BEGIN), "{prompt}");
    assert!(prompt.contains("keep the migration reversible"), "{prompt}");
    assert!(prompt.contains("postgres 16 on the primary"), "{prompt}");
    assert!(prompt.trim_end().ends_with(CONTEXT_END), "{prompt}");
    let tasks: Value = c.get(&format!("/v1/cohorts/{fleet}/tasks")).await.unwrap();
    for t in tasks["tasks"].as_array().unwrap() {
        assert_eq!(t["state"], "done", "{t}");
        let notes = t["notes"].as_array().cloned().unwrap_or_default();
        assert!(
            notes.iter().any(|n| n["text"]
                .as_str()
                .unwrap_or_default()
                .starts_with("codex finished in agent session")),
            "{t}"
        );
    }

    // A manual handoff: claim, then complete with a note.
    let added: Value = c
        .post(
            &format!("/v1/cohorts/{fleet}/tasks"),
            json!({"payload": "review"}),
        )
        .await
        .unwrap();
    let claim: Value = c
        .post(
            &format!("/v1/cohorts/{fleet}/claim"),
            json!({"owner": "cli"}),
        )
        .await
        .unwrap();
    assert_eq!(claim["task"]["id"], added["id"]);
    let tid = added["id"].as_str().unwrap();
    let h = Handoff {
        owner: "cli",
        lease_token: claim["task"]["lease_token"].as_str().unwrap(),
        note: "reviewed; follow up on indexes",
        result: "ok",
        requeue: false,
    };
    let (res, text) = capture!(false, |o| task_handoff(&c, o, &fleet, tid, &h));
    res.unwrap();
    assert_eq!(text, format!("completed task {tid} with a handoff note\n"));

    let (res, text) = capture!(false, |o| memory_delete(
        &c,
        o,
        &fleet,
        "billing/db",
        Some(1)
    ));
    res.unwrap();
    assert_eq!(text, "deleted billing/db\n");
}

#[tokio::test]
async fn schedules_create_list_get_run_and_delete() {
    let p = Plane::start(None).await;
    let c = p.client();
    let id = create_citadel(&c, "keep").await;
    let spec = ScheduleSpec {
        citadel: id.clone(),
        every: "1h".into(),
        prompt: "nightly triage".into(),
        agent: "codex".into(),
        precheck: "test -f /workspace/go".into(),
        ..ScheduleSpec::default()
    };
    let (res, text) = capture!(true, |o| schedule_create(&c, o, &spec));
    res.unwrap();
    let v: Value = serde_json::from_str(&text).unwrap();
    let sid = v["id"].as_str().unwrap().to_owned();
    assert_eq!(
        v["command"],
        json!([
            "codex",
            "exec",
            "--skip-git-repo-check",
            "--dangerously-bypass-approvals-and-sandbox"
        ])
    );
    assert_eq!(v["precheck"], json!(["test", "-f", "/workspace/go"]));

    let (res, text) = capture!(false, |o| schedule_list(&c, o, &id, ""));
    res.unwrap();
    assert!(text.starts_with("ID"), "{text}");
    assert!(text.contains(&sid) && text.contains("every 1h"), "{text}");

    let (res, text) = capture!(false, |o| schedule_get(&c, o, &sid));
    res.unwrap();
    assert!(
        text.contains(&format!("target        citadel {id}")),
        "{text}"
    );
    assert!(text.contains("prompt        nightly triage"), "{text}");

    let (res, text) = capture!(false, |o| schedule_run(&c, o, &sid));
    res.unwrap();
    assert!(text.starts_with(&format!("schedule {sid}: ")), "{text}");

    let (res, text) = capture!(false, |o| schedule_delete(&c, o, &sid));
    res.unwrap();
    assert_eq!(text, format!("deleted schedule {sid}\n"));
    let (res, text) = capture!(false, |o| schedule_list(&c, o, "", ""));
    res.unwrap();
    assert_eq!(text, "no schedules\n");

    let bad = ScheduleSpec {
        citadel: id.clone(),
        cron: "0 * * * *".into(),
        every: "1h".into(),
        agent: "codex".into(),
        ..ScheduleSpec::default()
    };
    let (res, _) = capture!(false, |o| schedule_create(&c, o, &bad));
    assert_eq!(
        res.unwrap_err().to_string(),
        "set exactly one of --cron and --every"
    );
}

#[test]
fn schedule_commands_leave_the_prompt_to_the_server() {
    assert_eq!(
        agent_command_without_prompt("claude", "opus").unwrap(),
        [
            "claude",
            "-p",
            "--dangerously-skip-permissions",
            "--model",
            "opus"
        ]
    );
    assert!(agent_command_without_prompt("vim", "").is_err());
}

#[test]
fn paths_and_queries_are_encoded() {
    assert_eq!(encode_path("billing/db v2"), "billing/db%20v2");
    assert_eq!(query(&[("a", String::new())]), "");
    assert_eq!(
        query(&[("query", "a b&c".into()), ("tags", "x,y".into())]),
        "?query=a+b%26c&tags=x%2Cy"
    );
}
