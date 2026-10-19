//! State written by the Go control plane loads in Rust and is rewritten
//! byte for byte (top-level element order aside where Go iterates a map).
//!
//! `testdata/go-state` was produced by `testdata/go-state-generator_test.go`
//! run inside `internal/controlplane` of the Go tree:
//! `RW_FIXTURE_OUT=<dir> go test ./internal/controlplane -run TestGenerateRustFixtures`.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use runeward_fleet::TaskState;

use super::support::config;
use crate::agent_sessions::{AGENT_SESSION_DIR_NAME, AGENT_SESSIONS_FILE_NAME, AgentEvent};
use crate::fleet::FLEETS_FILE_NAME;
use crate::runs::RUNS_FILE_NAME;
use crate::snapshots::SNAPSHOTS_FILE_NAME;
use crate::{AgentStatus, Manager};

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/go-state")
}

/// Copies the fixture into `dst` with private modes (git does not keep
/// 0600, and the key loaders insist on it).
fn copy_private(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).expect("mkdir");
    for e in std::fs::read_dir(src).expect("ls") {
        let e = e.expect("entry");
        let to = dst.join(e.file_name());
        if e.file_type().expect("type").is_dir() {
            copy_private(&e.path(), &to);
        } else {
            std::fs::copy(e.path(), &to).expect("copy");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&to, std::fs::Permissions::from_mode(0o600))
                    .expect("chmod");
            }
        }
    }
}

/// Splits a `json.MarshalIndent` top-level array into its element blocks.
fn elements(raw: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for line in raw.lines() {
        if line == "[" || line == "]" || line == "[]" {
            continue;
        }
        cur.push_str(line.trim_end_matches(','));
        cur.push('\n');
        if line == "  }" || line == "  }," {
            out.push(std::mem::take(&mut cur));
        }
    }
    out.sort();
    out
}

fn read(dir: &Path, name: &str) -> String {
    std::fs::read_to_string(dir.join(name)).expect(name)
}

#[tokio::test]
async fn go_state_loads_and_rewrites_identically() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let state = tmp.path().join("state");
    copy_private(&fixtures(), &state);
    let go = |name: &str| read(&fixtures(), name);

    let mgr: Arc<Manager> = Manager::builder(config(tmp.path(), None))
        .build()
        .await
        .expect("open Go state");

    // Everything loaded, with nothing rewritten on open (no running runs or
    // legacy claims in the fixture).
    assert_eq!(mgr.list_runs().len(), 2);
    assert_eq!(mgr.list_fleets().len(), 2);
    assert_eq!(mgr.list_snapshots().len(), 2);
    assert_eq!(mgr.agent_sessions("").len(), 2);
    for name in [
        RUNS_FILE_NAME,
        FLEETS_FILE_NAME,
        SNAPSHOTS_FILE_NAME,
        AGENT_SESSIONS_FILE_NAME,
    ] {
        assert_eq!(read(&state, name), go(name), "{name} untouched by load");
    }

    // Rewrites are identical: runs and agent sessions are sorted by
    // creation time, so byte for byte; fleets and snapshots come from a Go
    // map, so per element.
    mgr.save_runs().await.expect("runs");
    let agents = mgr.agents.clone();
    tokio::task::spawn_blocking(move || agents.save())
        .await
        .expect("join")
        .expect("agents");
    mgr.save_fleets().await.expect("fleets");
    mgr.save_snapshots().await.expect("snapshots");
    assert_eq!(read(&state, RUNS_FILE_NAME), go(RUNS_FILE_NAME));
    assert_eq!(
        read(&state, AGENT_SESSIONS_FILE_NAME),
        go(AGENT_SESSIONS_FILE_NAME)
    );
    for name in [FLEETS_FILE_NAME, SNAPSHOTS_FILE_NAME] {
        let (rust, golang) = (read(&state, name), go(name));
        assert_eq!(elements(&rust), elements(&golang), "{name}");
        assert_eq!(rust.len(), golang.len(), "{name}");
    }

    // Values survived intact.
    let run = mgr.run("run-b").expect("run-b");
    assert_eq!(
        (run.parent_run_id.as_str(), run.error.as_str()),
        ("run-a", "boom \"quoted\" é")
    );
    let snap = mgr.snapshot_ref("snap-1").expect("snap-1");
    assert_eq!(snap.sha256, "abc123");
    assert_eq!(mgr.snapshot_owner("snap-1").as_deref(), Some("team"));
    assert_eq!(
        mgr.fleet_view("cohort-2").expect("cohort-2").sandboxes,
        None
    );
    let s = mgr
        .agent_session("fedcba9876543210fedcba9876543210")
        .expect("session");
    assert_eq!(
        (s.status, s.exit_code, s.transcript_truncated),
        (AgentStatus::Failed, Some(2), true)
    );

    // Transcripts: Go lines re-encode identically and replay in order.
    let id = "0123456789abcdef0123456789abcdef";
    let transcript = read(&fixtures(), &format!("{AGENT_SESSION_DIR_NAME}/{id}.jsonl"));
    for line in transcript.lines() {
        let ev: AgentEvent = serde_json::from_str(line).expect("event");
        let again = runeward_ledger::gojson::marshal(&ev).expect("encode");
        assert_eq!(String::from_utf8(again).expect("utf8"), line);
    }
    let (_, events) = mgr.agent_session_events(id, 1).await.expect("events");
    assert_eq!(events.len(), 3);
    assert_eq!(events[0].data, "héllo <world> & \"friends\"\n");
    assert_eq!(events[1].data, "warn\u{2028}line\n");

    // The Go lease key verifies a Go-issued token, and the claim can be
    // heartbeated and completed through the Rust manager.
    let token = read(&fixtures(), "lease-token.txt");
    let hb = mgr
        .heartbeat_task("cohort-1", "t-claimed", "w1", token.trim())
        .await
        .expect("Go token accepted");
    assert_eq!(hb.lease_version, 4);
    mgr.complete_task("cohort-1", "t-claimed", "w1", &hb.lease_token, "done")
        .await
        .expect("complete");
    let tasks = mgr.list_tasks("cohort-1").expect("tasks");
    assert_eq!(tasks[1].state, TaskState::Done);

    // The Go ledger (and its signing key) verifies, and Rust appends extend
    // the same chain.
    mgr.verify_ledger().await.expect("Go ledger verifies");
    let before = mgr.ledger().records().expect("records").len();
    mgr.record_fleet(
        &mgr.fleet("cohort-1").expect("fleet"),
        "task.note",
        "t-done",
        "",
    )
    .await;
    mgr.verify_ledger().await.expect("chain continues");
    assert_eq!(mgr.ledger().records().expect("records").len(), before + 1);
    let (pubkey, _) = mgr.ledger_public_key().expect("signed");
    assert_eq!(pubkey, read(&fixtures(), "ledger.pub").trim());
}
