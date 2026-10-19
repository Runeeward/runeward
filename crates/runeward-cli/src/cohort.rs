//! `runeward cohort`: drives a governed Cohort on a running `runeward serve`
//! over REST — create it, push prompts, and run an agent (Cursor, Codex or
//! Claude) on each, all governed.

use std::sync::Mutex;
use std::time::Duration;

use anyhow::{Result, anyhow, bail};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

use crate::common::{expand_home, go_abs, go_join, go_quote};

/// Remembers the active Cohort id so subcommands need no `--cohort`.
pub const FLEET_STATE_FILE: &str = ".runeward-cohort";

const NO_ACTIVE_COHORT: &str =
    "no active cohort; run `runeward cohort up` first or pass --cohort <id>";

/// Connection and agent settings shared by every `cohort` subcommand.
#[derive(Debug, Clone)]
pub struct CohortOptions {
    /// Control-plane base URL.
    pub base: String,
    /// cursor | codex | claude.
    pub agent: String,
    /// Model slug passed to the agent.
    pub model: String,
    /// Explicit Cohort id.
    pub cohort: String,
    /// Bearer token.
    pub token: String,
}

/// A REST client of `runeward serve`.
#[derive(Debug)]
pub struct FleetClient {
    base: String,
    token: String,
    http: reqwest::Client,
}

/// A Cohort as the server reports it.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct FleetView {
    /// The Cohort id.
    pub id: String,
    /// Worker Citadel ids.
    pub sandboxes: Vec<String>,
}

/// A Command Board task.
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct Task {
    /// Task id.
    pub id: String,
    /// The prompt.
    pub payload: String,
    /// pending, claimed, done, failed.
    pub state: String,
    /// The claim's lease token.
    pub lease_token: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct ClaimResp {
    claimed: bool,
    task: Task,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct TasksResp {
    tasks: Vec<Task>,
}

/// An observable agent session.
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct AgentSession {
    /// Session id.
    pub id: String,
    /// running, completed, failed, ...
    pub status: String,
    /// The agent's exit code once finished.
    pub exit_code: Option<i64>,
    /// Why the session failed.
    pub error: String,
}

/// One output chunk of an agent session.
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct AgentEvent {
    /// Monotonic sequence number.
    pub seq: i64,
    /// stdout, stderr or a lifecycle stream.
    pub stream: String,
    /// The chunk.
    pub data: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct AgentEventsResp {
    session: AgentSession,
    events: Vec<AgentEvent>,
}

impl FleetClient {
    /// A client of the control plane at `base`.
    pub fn new(base: &str, token: &str) -> Self {
        Self {
            base: base.to_owned(),
            token: token.to_owned(),
            http: reqwest::Client::new(),
        }
    }

    /// Issues a JSON request and decodes a 2xx body (if any) into `T`.
    async fn call<T: DeserializeOwned + Default>(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<Value>,
    ) -> Result<T> {
        let mut req = self
            .http
            .request(method.clone(), format!("{}{path}", self.base));
        if let Some(b) = &body {
            req = req
                .header("Content-Type", "application/json")
                .body(serde_json::to_vec(b)?);
        }
        if !self.token.is_empty() {
            req = req.bearer_auth(&self.token);
        }
        let resp = req.send().await.map_err(|e| {
            anyhow!(
                "cannot reach control plane at {} (is `runeward serve` running?): {e}",
                self.base
            )
        })?;
        let status = resp.status();
        let data = resp.bytes().await.unwrap_or_default();
        if status.as_u16() >= 300 {
            let msg = server_error(&data);
            if msg.is_empty() {
                bail!("{method} {path}: {status}");
            }
            bail!("{method} {path}: {status} ({msg})");
        }
        if data.is_empty() {
            return Ok(T::default());
        }
        Ok(serde_json::from_slice(&data)?)
    }

    async fn post<T: DeserializeOwned + Default>(&self, path: &str, body: Value) -> Result<T> {
        self.call(reqwest::Method::POST, path, Some(body)).await
    }

    async fn get<T: DeserializeOwned + Default>(&self, path: &str) -> Result<T> {
        self.call(reqwest::Method::GET, path, None).await
    }

    /// Starts an agent command on `sandbox`, then follows its durable event
    /// backlog until the terminal status. Polling makes it reconnect-safe.
    #[allow(clippy::too_many_arguments)]
    pub async fn agent_session_exec(
        &self,
        sandbox: &str,
        command: &[String],
        agent: &str,
        model: &str,
        cohort_id: &str,
        task_id: &str,
        on_event: &(dyn Fn(&AgentEvent) + Sync),
    ) -> Result<AgentSession> {
        let mut session: AgentSession = self
            .post(
                &format!("/v1/citadels/{sandbox}/agent-sessions"),
                json!({
                    "command": command, "agent": agent, "model": model,
                    "cohort_id": cohort_id, "task_id": task_id,
                }),
            )
            .await?;
        let mut after = 0i64;
        let mut ticker = tokio::time::interval(Duration::from_millis(500));
        ticker.tick().await;
        loop {
            let page: AgentEventsResp = self
                .get(&format!(
                    "/v1/agent-sessions/{}/events?after={after}",
                    session.id
                ))
                .await?;
            for ev in &page.events {
                after = after.max(ev.seq);
                on_event(ev);
            }
            session = page.session;
            if agent_session_done(&session.status) {
                if session.status != "completed" {
                    let why = if session.error.is_empty() {
                        format!("agent session ended with status {}", session.status)
                    } else {
                        session.error.clone()
                    };
                    bail!(why);
                }
                return Ok(session);
            }
            ticker.tick().await;
        }
    }

    /// Runs one worker per Citadel; each claims and builds pending tasks
    /// until the Command Board is empty, in parallel.
    pub async fn drain(&self, fleet_id: &str, agent: &str, model: &str) -> Result<()> {
        let fv: FleetView = self.get(&format!("/v1/cohorts/{fleet_id}")).await?;
        if fv.sandboxes.is_empty() {
            bail!("cohort {fleet_id} has no citadels");
        }
        let lock = Mutex::new(());
        let say = |line: String| {
            let _g = lock.lock();
            eprintln!("{line}");
        };
        let workers = fv.sandboxes.iter().enumerate().map(|(i, sb)| {
            let owner = format!("worker-{}", i + 1);
            let say = &say;
            let lock = &lock;
            async move {
                loop {
                    let claim: ClaimResp = match self
                        .post(
                            &format!("/v1/cohorts/{fleet_id}/claim"),
                            json!({ "owner": owner }),
                        )
                        .await
                    {
                        Ok(c) => c,
                        Err(e) => {
                            say(format!("!! [{owner}] claim failed: {e}"));
                            return;
                        }
                    };
                    if !claim.claimed {
                        return;
                    }
                    let task = claim.task;
                    say(format!(">> [{owner}/{sb}] building: {}", task.payload));
                    let cmd = match agent_command(agent, model, &task.payload) {
                        Ok(c) => c,
                        Err(e) => {
                            say(format!("!! [{owner}] {e}"));
                            return;
                        }
                    };
                    let on_event = |ev: &AgentEvent| {
                        if ev.stream != "stdout" && ev.stream != "stderr" {
                            return;
                        }
                        let _g = lock.lock();
                        let nl = if ev.data.ends_with('\n') { "" } else { "\n" };
                        eprint!("[{owner}/{}] {}{nl}", ev.stream, ev.data);
                    };
                    match self
                        .agent_session_exec(sb, &cmd, agent, model, fleet_id, &task.id, &on_event)
                        .await
                    {
                        Err(e) => {
                            let _: Result<Value> = self
                                .post(
                                    &format!("/v1/cohorts/{fleet_id}/tasks/{}/fail", task.id),
                                    json!({
                                        "owner": owner, "lease_token": task.lease_token,
                                        "error": e.to_string(), "requeue": true,
                                    }),
                                )
                                .await;
                            say(format!("!! [{owner}] failed (requeued) {}: {e}", task.id));
                        }
                        Ok(session) => {
                            let _: Result<Value> = self
                                .post(
                                    &format!("/v1/cohorts/{fleet_id}/tasks/{}/complete", task.id),
                                    json!({
                                        "owner": owner, "lease_token": task.lease_token,
                                        "result": format!("agent session {}", session.id),
                                    }),
                                )
                                .await;
                            say(format!(
                                "<< [{owner}] done: {} (session {})",
                                task.id, session.id
                            ));
                        }
                    }
                }
            }
        });
        futures_util::future::join_all(workers).await;
        Ok(())
    }
}

/// The `error` field of a JSON error body, if any.
fn server_error(data: &[u8]) -> String {
    serde_json::from_slice::<Value>(data)
        .ok()
        .and_then(|v| v.get("error").and_then(|e| e.as_str()).map(str::to_owned))
        .unwrap_or_default()
}

fn agent_session_done(status: &str) -> bool {
    matches!(
        status,
        "completed" | "failed" | "denied" | "canceled" | "interrupted"
    )
}

/// The exec argv for the selected agent.
pub fn agent_command(agent: &str, model: &str, prompt: &str) -> Result<Vec<String>> {
    let s = |v: &str| v.to_owned();
    let mut cmd = match agent {
        "cursor" => vec![
            s("agent"),
            s("-p"),
            s(prompt),
            s("--force"),
            s("--output-format"),
            s("text"),
        ],
        "codex" => vec![
            s("codex"),
            s("exec"),
            s("--skip-git-repo-check"),
            s("--dangerously-bypass-approvals-and-sandbox"),
        ],
        "claude" => vec![
            s("claude"),
            s("-p"),
            s(prompt),
            s("--dangerously-skip-permissions"),
        ],
        other => bail!(
            "unknown agent {} (use cursor, codex, or claude)",
            go_quote(other)
        ),
    };
    if !model.is_empty() {
        let flag = if agent == "codex" { "-m" } else { "--model" };
        cmd.extend([s(flag), s(model)]);
    }
    if agent == "codex" {
        cmd.push(s(prompt));
    }
    Ok(cmd)
}

/// The explicit id, else the one saved by `cohort up`.
pub fn resolve_fleet_id(explicit: &str) -> Result<String> {
    if !explicit.is_empty() {
        return Ok(explicit.to_owned());
    }
    let b = std::fs::read(FLEET_STATE_FILE).map_err(|_| anyhow!(NO_ACTIVE_COHORT))?;
    let id = String::from_utf8_lossy(&b).trim().to_owned();
    if id.is_empty() {
        bail!(NO_ACTIVE_COHORT);
    }
    Ok(id)
}

/// `cohort up [charter]`: creates a Cohort and remembers its id.
pub async fn up(opts: &CohortOptions, charter: Option<&str>) -> Result<()> {
    let profile = charter.unwrap_or("build-fleet");
    let client = FleetClient::new(&opts.base, &opts.token);
    let fv: FleetView = client
        .post("/v1/cohorts", json!({ "profile": profile }))
        .await?;
    crate::signing::write_file(FLEET_STATE_FILE, fv.id.as_bytes(), 0o644)?;
    eprintln!(
        "runeward: cohort {} up (charter={profile}, {} citadels)",
        fv.id,
        fv.sandboxes.len()
    );
    for s in &fv.sandboxes {
        eprintln!("  {s}");
    }
    Ok(())
}

/// `cohort add <prompt>`.
pub async fn add(opts: &CohortOptions, prompt: &str) -> Result<()> {
    let id = resolve_fleet_id(&opts.cohort)?;
    let client = FleetClient::new(&opts.base, &opts.token);
    let t: Task = client
        .post(
            &format!("/v1/cohorts/{id}/tasks"),
            json!({ "payload": prompt }),
        )
        .await?;
    eprintln!("runeward: added task {}", t.id);
    Ok(())
}

/// `cohort run`.
pub async fn run(opts: &CohortOptions) -> Result<()> {
    let id = resolve_fleet_id(&opts.cohort)?;
    FleetClient::new(&opts.base, &opts.token)
        .drain(&id, &opts.agent, &opts.model)
        .await
}

/// `cohort build <prompt>`: up-if-needed, add, run.
pub async fn build(opts: &CohortOptions, prompt: &str) -> Result<()> {
    if std::fs::metadata(FLEET_STATE_FILE).is_err() {
        up(opts, None).await?;
    }
    let id = resolve_fleet_id(&opts.cohort)?;
    let client = FleetClient::new(&opts.base, &opts.token);
    let _: Task = client
        .post(
            &format!("/v1/cohorts/{id}/tasks"),
            json!({ "payload": prompt }),
        )
        .await?;
    client.drain(&id, &opts.agent, &opts.model).await
}

/// `cohort exec <prompt>`: one Citadel, so changes accumulate.
pub async fn exec(opts: &CohortOptions, citadel: &str, prompt: &str) -> Result<()> {
    let id = resolve_fleet_id(&opts.cohort)?;
    let client = FleetClient::new(&opts.base, &opts.token);
    let sb = if citadel.is_empty() {
        let fv: FleetView = client.get(&format!("/v1/cohorts/{id}")).await?;
        match fv.sandboxes.first() {
            Some(s) => s.clone(),
            None => bail!("cohort {id} has no citadels"),
        }
    } else {
        citadel.to_owned()
    };
    let cmd = agent_command(&opts.agent, &opts.model, prompt)?;
    eprintln!("runeward: [{sb}] {prompt}");
    let on_event = |ev: &AgentEvent| match ev.stream.as_str() {
        "stdout" => {
            use std::io::Write;
            print!("{}", ev.data);
            let _ = std::io::stdout().flush();
        }
        "stderr" => eprint!("{}", ev.data),
        _ => {}
    };
    let session = client
        .agent_session_exec(&sb, &cmd, &opts.agent, &opts.model, &id, "", &on_event)
        .await?;
    eprintln!("runeward: agent session {} completed", session.id);
    Ok(())
}

/// `cohort status`: the Command Board.
pub async fn status(opts: &CohortOptions) -> Result<()> {
    let id = resolve_fleet_id(&opts.cohort)?;
    let tr: TasksResp = FleetClient::new(&opts.base, &opts.token)
        .get(&format!("/v1/cohorts/{id}/tasks"))
        .await?;
    for t in &tr.tasks {
        println!("{:<9} {}\t{}", t.state, t.id, t.payload);
    }
    Ok(())
}

/// `cohort export [dir]`: every worker's /workspace to `<dir>/<citadel>`.
pub async fn export(opts: &CohortOptions, dest: Option<&str>) -> Result<()> {
    let id = resolve_fleet_id(&opts.cohort)?;
    let dest = dest.unwrap_or("./out");
    let fv: FleetView = FleetClient::new(&opts.base, &opts.token)
        .get(&format!("/v1/cohorts/{id}"))
        .await?;
    for sb in &fv.sandboxes {
        let out = go_abs(&expand_home(&go_join(&[dest, sb])))?;
        runeward_backend::export(sb, std::path::Path::new(&out))
            .await
            .map_err(|e| anyhow!("export {sb}: {e}"))?;
        eprintln!("runeward: exported {sb} -> {out}");
    }
    Ok(())
}

/// `cohort down`: tears the Cohort down and forgets it.
pub async fn down(opts: &CohortOptions) -> Result<()> {
    let id = resolve_fleet_id(&opts.cohort)?;
    let _: Value = FleetClient::new(&opts.base, &opts.token)
        .call(reqwest::Method::DELETE, &format!("/v1/cohorts/{id}"), None)
        .await?;
    let _ = std::fs::remove_file(FLEET_STATE_FILE);
    eprintln!("runeward: cohort {id} down");
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn agent_commands_match_go() {
        assert_eq!(
            agent_command("cursor", "gpt-5", "hi").unwrap(),
            [
                "agent",
                "-p",
                "hi",
                "--force",
                "--output-format",
                "text",
                "--model",
                "gpt-5"
            ]
        );
        assert_eq!(
            agent_command("codex", "o3", "hi").unwrap(),
            [
                "codex",
                "exec",
                "--skip-git-repo-check",
                "--dangerously-bypass-approvals-and-sandbox",
                "-m",
                "o3",
                "hi"
            ]
        );
        assert_eq!(
            agent_command("codex", "", "hi").unwrap(),
            [
                "codex",
                "exec",
                "--skip-git-repo-check",
                "--dangerously-bypass-approvals-and-sandbox",
                "hi"
            ]
        );
        assert_eq!(
            agent_command("claude", "", "hi").unwrap(),
            ["claude", "-p", "hi", "--dangerously-skip-permissions"]
        );
        assert_eq!(
            agent_command("vim", "", "hi").unwrap_err().to_string(),
            "unknown agent \"vim\" (use cursor, codex, or claude)"
        );
    }

    #[test]
    fn server_errors_are_extracted() {
        assert_eq!(server_error(br#"{"error":"nope","code":"x"}"#), "nope");
        assert_eq!(server_error(b"not json"), "");
    }
}
