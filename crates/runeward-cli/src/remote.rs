//! REST-client commands of a running `runeward serve`: Citadel workspaces
//! (`citadel`), agent turns (`session`), Cohort memory and task context
//! (`cohort memory|note|brief|handoff|task`) and scheduled runs
//! (`schedule`).
//!
//! Every command writes human-readable output, or with `--json` the
//! server's JSON body, to the writer it is given, so tests can capture it.

use std::io::Write;

use anyhow::{Result, bail};
use serde_json::{Value, json};

use crate::cohort::{AgentEvent, AgentSession, FleetClient, agent_command, render_context};
use crate::tabwriter::TabWriter;

/// Where a command writes and how.
pub struct Out<'a> {
    /// stdout (or a test buffer).
    pub w: &'a mut (dyn Write + Send),
    /// Print the server's JSON instead of text.
    pub json: bool,
}

impl Out<'_> {
    fn json(&mut self, v: &Value) -> Result<()> {
        writeln!(self.w, "{}", serde_json::to_string_pretty(v)?)?;
        Ok(())
    }

    fn line(&mut self, s: &str) -> Result<()> {
        writeln!(self.w, "{s}")?;
        Ok(())
    }

    /// Prints `v` as JSON, or `text` otherwise.
    fn either(&mut self, v: &Value, text: impl FnOnce() -> String) -> Result<()> {
        if self.json {
            self.json(v)
        } else {
            let t = text();
            self.w.write_all(t.as_bytes())?;
            if !t.ends_with('\n') {
                writeln!(self.w)?;
            }
            Ok(())
        }
    }

    fn table(&mut self, header: &str, rows: impl IntoIterator<Item = String>) -> Result<()> {
        let mut tw = TabWriter::default();
        tw.push(header);
        tw.push("\n");
        for r in rows {
            tw.push(&r);
            tw.push("\n");
        }
        let mut s = String::new();
        tw.flush(&mut s);
        self.w.write_all(s.as_bytes())?;
        Ok(())
    }
}

/// A string field of a JSON object ("" when missing; numbers and bools are
/// printed as JSON).
fn s(v: &Value, k: &str) -> String {
    match v.get(k) {
        None | Some(Value::Null) => String::new(),
        Some(Value::String(x)) => x.clone(),
        Some(other) => other.to_string(),
    }
}

/// `-` for an empty table cell.
fn cell(x: String) -> String {
    if x.is_empty() { "-".into() } else { x }
}

/// Percent-encodes a path segment (keeps `/` so memory keys with slashes
/// address the wildcard route).
fn encode_path(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for b in raw.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~' | b'/') {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// `?k=v&...` for the non-empty pairs (empty when none).
fn query(pairs: &[(&str, String)]) -> String {
    let mut ser = url::form_urlencoded::Serializer::new(String::new());
    let mut any = false;
    for (k, v) in pairs {
        if !v.is_empty() {
            ser.append_pair(k, v);
            any = true;
        }
    }
    if any {
        format!("?{}", ser.finish())
    } else {
        String::new()
    }
}

// ---------------------------------------------------------------- citadel

/// `citadel fork <id>`.
pub async fn citadel_fork(
    c: &FleetClient,
    out: &mut Out<'_>,
    id: &str,
    charter: &str,
    agent: &str,
    model: &str,
) -> Result<()> {
    let v: Value = c
        .post(
            &format!("/v1/citadels/{}/fork", encode_path(id)),
            json!({"profile": charter, "agent": agent, "model": model}),
        )
        .await?;
    out.either(&v, || {
        format!(
            "forked {id} -> {} (charter={}, isolation={})",
            s(&v, "id"),
            s(&v, "profile"),
            s(&v, "isolation")
        )
    })
}

/// `citadel sleep <id>`.
pub async fn citadel_sleep(c: &FleetClient, out: &mut Out<'_>, id: &str) -> Result<()> {
    let v: Value = c
        .post(
            &format!("/v1/citadels/{}/sleep", encode_path(id)),
            json!({}),
        )
        .await?;
    out.either(&v, || {
        if v.get("slept").and_then(Value::as_bool) == Some(true) {
            format!("citadel {id} is asleep (workspace kept)")
        } else {
            format!("citadel {id} was already asleep")
        }
    })
}

/// `citadel wake <id>`.
pub async fn citadel_wake(c: &FleetClient, out: &mut Out<'_>, id: &str) -> Result<()> {
    let v: Value = c
        .post(&format!("/v1/citadels/{}/wake", encode_path(id)), json!({}))
        .await?;
    out.either(&v, || format!("citadel {id} is awake"))
}

/// `citadel status <id>`: the Citadel (isolation evidence, usage, limits)
/// and its workspace.
pub async fn citadel_status(c: &FleetClient, out: &mut Out<'_>, id: &str) -> Result<()> {
    let v: Value = c.get(&format!("/v1/citadels/{}", encode_path(id))).await?;
    out.either(&v, || {
        let mut t = String::new();
        let mut kv = |k: &str, val: String| {
            if !val.is_empty() {
                t.push_str(&format!("{k:<12}{val}\n"));
            }
        };
        kv("citadel", s(&v, "id"));
        kv("charter", s(&v, "profile"));
        kv("owner", s(&v, "owner"));
        kv("backend", s(&v, "backend"));
        kv("image", s(&v, "image"));
        kv("status", s(&v, "status"));
        kv("isolation", s(&v, "isolation"));
        match v.get("workspace").filter(|w| w.is_object()) {
            Some(w) => {
                let timeout = w
                    .get("idle_timeout_secs")
                    .and_then(Value::as_u64)
                    .unwrap_or(0);
                let idle = if timeout == 0 {
                    "never sleeps on idle".to_owned()
                } else {
                    format!(
                        "idle {}s of {timeout}s",
                        w.get("idle_secs").and_then(Value::as_u64).unwrap_or(0)
                    )
                };
                kv(
                    "workspace",
                    format!("persistent, {} ({idle})", s(w, "state")),
                );
                kv("slept at", s(w, "slept_at"));
                kv("woke at", s(w, "woke_at"));
                kv("forked from", s(w, "forked_from"));
            }
            None => kv("workspace", "not persistent".into()),
        }
        if let Some(u) = v.get("usage") {
            kv(
                "usage",
                format!("{} tokens, ${} cost", s(u, "tokens"), s(u, "cost_usd")),
            );
        }
        if let Some(caps) = v.get("capabilities").and_then(Value::as_array) {
            let caps: Vec<&str> = caps.iter().filter_map(Value::as_str).collect();
            kv("capabilities", caps.join(", "));
        }
        t
    })
}

/// `citadel perimeter <id>`: the egress and request-broker decisions.
pub async fn citadel_perimeter(c: &FleetClient, out: &mut Out<'_>, id: &str) -> Result<()> {
    let v: Value = c
        .get(&format!("/v1/citadels/{}/perimeter", encode_path(id)))
        .await?;
    if out.json {
        return out.json(&v);
    }
    let decisions = v
        .get("decisions")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if decisions.is_empty() {
        return out.line(&format!("no perimeter decisions recorded for {id}"));
    }
    let rows = decisions.iter().map(|d| {
        let verdict = match s(d, "verdict") {
            v if v.is_empty() => {
                if d.get("allow").and_then(Value::as_bool) == Some(true) {
                    "allow".into()
                } else {
                    "deny".into()
                }
            }
            v => v,
        };
        let target = match (s(d, "method"), s(d, "path")) {
            (m, p) if m.is_empty() && p.is_empty() => s(d, "host"),
            (m, p) => format!("{m} {}{p}", s(d, "host")).trim().to_owned(),
        };
        let reason = match s(d, "reason_code") {
            rc if rc.is_empty() => s(d, "reason"),
            rc => format!("{rc}: {}", s(d, "reason")),
        };
        format!(
            "{}\t{verdict}\t{}\t{}\t{}",
            cell(s(d, "timestamp")),
            cell(target),
            cell(s(d, "tool")),
            cell(reason)
        )
    });
    out.table("TIME\tVERDICT\tTARGET\tTOOL\tREASON", rows)
}

// ---------------------------------------------------------------- session

/// How a followed session prints.
fn print_event(w: &mut (dyn Write + Send), json_lines: bool, ev: &AgentEvent) {
    if json_lines {
        let line = json!({"seq": ev.seq, "stream": ev.stream, "data": ev.data});
        let _ = writeln!(w, "{line}");
        return;
    }
    match ev.stream.as_str() {
        "stdout" => {
            let _ = w.write_all(ev.data.as_bytes());
            let _ = w.flush();
        }
        "stderr" => eprint!("{}", ev.data),
        other => eprintln!("runeward: [{other} #{}] {}", ev.seq, ev.data.trim_end()),
    }
}

/// Follows `id` from `after` and fails unless it completed.
async fn follow(c: &FleetClient, out: &mut Out<'_>, id: &str, after: i64) -> Result<AgentSession> {
    let json_lines = out.json;
    let w = &mut *out.w;
    let session = c
        .follow_session(id, after, &mut |ev| print_event(w, json_lines, ev))
        .await?;
    if session.status != "completed" {
        let why = if session.error.is_empty() {
            format!("agent session {id} ended with status {}", session.status)
        } else {
            format!(
                "agent session {id} ended with status {}: {}",
                session.status, session.error
            )
        };
        bail!(why);
    }
    Ok(session)
}

/// `session turn <id> <prompt>`: starts the next turn (the session's agent
/// CLI with `prompt`) and streams it.
pub async fn session_turn(
    c: &FleetClient,
    out: &mut Out<'_>,
    id: &str,
    prompt: &str,
    agent: &str,
    model: &str,
) -> Result<()> {
    let path = format!("/v1/agent-sessions/{}", encode_path(id));
    let current: AgentSession = c.get(&path).await?;
    let agent = if agent.is_empty() {
        current.agent.as_str()
    } else {
        agent
    };
    if agent.is_empty() {
        bail!("agent session {id} has no agent name; pass --agent cursor|codex|claude");
    }
    let model_for_cmd = if model.is_empty() {
        current.model.as_str()
    } else {
        model
    };
    let cmd = agent_command(agent, model_for_cmd, prompt)?;
    let started: AgentSession = c
        .post(
            &format!("{path}/turns"),
            json!({"command": cmd, "model": model}),
        )
        .await?;
    eprintln!(
        "runeward: session {id} turn {} started ({agent})",
        started.turn.max(1)
    );
    let done = follow(c, out, id, current.last_seq).await?;
    eprintln!("runeward: session {id} turn {} completed", done.turn.max(1));
    Ok(())
}

/// `session attach <id> [--after N]`: replays the transcript after `N`,
/// then follows live output.
pub async fn session_attach(
    c: &FleetClient,
    out: &mut Out<'_>,
    id: &str,
    after: i64,
) -> Result<()> {
    let done = follow(c, out, id, after).await?;
    eprintln!(
        "runeward: session {id} {} (last event #{})",
        done.status, done.last_seq
    );
    Ok(())
}

/// `session cancel <id>`.
pub async fn session_cancel(c: &FleetClient, out: &mut Out<'_>, id: &str) -> Result<()> {
    let v: Value = c
        .post(
            &format!("/v1/agent-sessions/{}/cancel", encode_path(id)),
            json!({}),
        )
        .await?;
    out.either(&v, || {
        if v.get("canceled").and_then(Value::as_bool) == Some(true) {
            format!("canceled the active turn of session {id} (changes already made stay)")
        } else {
            format!("session {id} has no active turn")
        }
    })
}

// ----------------------------------------------------------- cohort memory

fn tags_of(v: &Value) -> String {
    v.get("tags")
        .and_then(Value::as_array)
        .map(|t| {
            t.iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(",")
        })
        .unwrap_or_default()
}

fn memory_table(out: &mut Out<'_>, v: &Value) -> Result<()> {
    if out.json {
        return out.json(v);
    }
    let entries = v
        .get("entries")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if entries.is_empty() {
        return out.line("no memory entries");
    }
    let rows = entries.iter().map(|e| {
        let text = s(e, "text").replace(['\n', '\t'], " ");
        let preview: String = text.chars().take(60).collect();
        let more = if text.chars().count() > 60 { "..." } else { "" };
        format!(
            "{}\tv{}\t{}\t{}\t{preview}{more}",
            s(e, "key"),
            s(e, "version"),
            cell(s(e, "author")),
            cell(tags_of(e))
        )
    });
    out.table("KEY\tVERSION\tAUTHOR\tTAGS\tTEXT", rows)
}

/// `cohort memory put <key> <text>`.
pub async fn memory_put(
    c: &FleetClient,
    out: &mut Out<'_>,
    cohort: &str,
    key: &str,
    text: &str,
    tags: &[String],
    expected_version: Option<u64>,
) -> Result<()> {
    let mut body = json!({"key": key, "text": text, "tags": tags});
    if let Some(v) = expected_version {
        body["expected_version"] = json!(v);
    }
    let v: Value = c
        .post(&format!("/v1/cohorts/{}/memory", encode_path(cohort)), body)
        .await?;
    out.either(&v, || {
        format!("stored {} (version {})", s(&v, "key"), s(&v, "version"))
    })
}

/// `cohort memory get <key>`.
pub async fn memory_get(c: &FleetClient, out: &mut Out<'_>, cohort: &str, key: &str) -> Result<()> {
    let v: Value = c
        .get(&format!(
            "/v1/cohorts/{}/memory/{}",
            encode_path(cohort),
            encode_path(key)
        ))
        .await?;
    out.either(&v, || {
        let mut t = format!(
            "{} (version {}, by {}, updated {})\n",
            s(&v, "key"),
            s(&v, "version"),
            cell(s(&v, "author")),
            s(&v, "updated_at")
        );
        let tags = tags_of(&v);
        if !tags.is_empty() {
            t.push_str(&format!("tags: {tags}\n"));
        }
        t.push_str(&s(&v, "text"));
        t
    })
}

/// `cohort memory search [query] [--tag ...]`.
pub async fn memory_search(
    c: &FleetClient,
    out: &mut Out<'_>,
    cohort: &str,
    q: &str,
    tags: &[String],
    limit: usize,
    max_bytes: usize,
) -> Result<()> {
    if q.trim().is_empty() && tags.is_empty() {
        bail!("give a query or at least one --tag (use `cohort memory list` to list everything)");
    }
    let num = |n: usize| if n == 0 { String::new() } else { n.to_string() };
    let qs = query(&[
        ("query", q.to_owned()),
        ("tags", tags.join(",")),
        ("limit", num(limit)),
        ("max_bytes", num(max_bytes)),
    ]);
    let v: Value = c
        .get(&format!("/v1/cohorts/{}/memory{qs}", encode_path(cohort)))
        .await?;
    memory_table(out, &v)
}

/// `cohort memory list`.
pub async fn memory_list(c: &FleetClient, out: &mut Out<'_>, cohort: &str) -> Result<()> {
    let v: Value = c
        .get(&format!("/v1/cohorts/{}/memory", encode_path(cohort)))
        .await?;
    memory_table(out, &v)
}

/// `cohort memory delete <key> [--version N]`.
pub async fn memory_delete(
    c: &FleetClient,
    out: &mut Out<'_>,
    cohort: &str,
    key: &str,
    version: Option<u64>,
) -> Result<()> {
    let qs = query(&[(
        "version",
        version.map(|v| v.to_string()).unwrap_or_default(),
    )]);
    let v: Value = c
        .delete(&format!(
            "/v1/cohorts/{}/memory/{}{qs}",
            encode_path(cohort),
            encode_path(key)
        ))
        .await?;
    out.either(&v, || {
        if v.get("deleted").and_then(Value::as_bool) == Some(true) {
            format!("deleted {key}")
        } else {
            format!("{key} was not there")
        }
    })
}

// ------------------------------------------------------------ cohort tasks

fn task_path(cohort: &str, task: &str) -> String {
    format!(
        "/v1/cohorts/{}/tasks/{}",
        encode_path(cohort),
        encode_path(task)
    )
}

/// `cohort note <task> <text>`.
pub async fn task_note(
    c: &FleetClient,
    out: &mut Out<'_>,
    cohort: &str,
    task: &str,
    text: &str,
) -> Result<()> {
    let v: Value = c
        .post(
            &format!("{}/notes", task_path(cohort, task)),
            json!({"text": text}),
        )
        .await?;
    out.either(&v, || format!("added a handoff note to task {task}"))
}

/// `cohort brief <task> <brief> [--for agent]`.
pub async fn task_brief(
    c: &FleetClient,
    out: &mut Out<'_>,
    cohort: &str,
    task: &str,
    agent: &str,
    brief: &str,
) -> Result<()> {
    let v: Value = c
        .put(
            &format!("{}/brief", task_path(cohort, task)),
            json!({"agent": agent, "brief": brief}),
        )
        .await?;
    out.either(&v, || {
        let who = if agent == "*" {
            "every agent".to_owned()
        } else {
            agent.to_owned()
        };
        if brief.is_empty() {
            format!("cleared the brief for {who} on task {task}")
        } else {
            format!("set the brief for {who} on task {task}")
        }
    })
}

/// What `cohort handoff` does with the task.
pub struct Handoff<'a> {
    /// The worker that holds the lease.
    pub owner: &'a str,
    /// The lease token from the claim.
    pub lease_token: &'a str,
    /// The note for whoever works on it next.
    pub note: &'a str,
    /// The result when completing.
    pub result: &'a str,
    /// Give the task back instead of completing it.
    pub requeue: bool,
}

/// `cohort handoff <task>`: complete (or requeue) a claimed task with a
/// handoff note.
pub async fn task_handoff(
    c: &FleetClient,
    out: &mut Out<'_>,
    cohort: &str,
    task: &str,
    h: &Handoff<'_>,
) -> Result<()> {
    let base = task_path(cohort, task);
    let v: Value = if h.requeue {
        c.post(
            &format!("{base}/fail"),
            json!({
                "owner": h.owner, "lease_token": h.lease_token, "error": "handed off",
                "requeue": true, "handoff": h.note,
            }),
        )
        .await?
    } else {
        c.post(
            &format!("{base}/complete"),
            json!({
                "owner": h.owner, "lease_token": h.lease_token, "result": h.result,
                "handoff": h.note,
            }),
        )
        .await?
    };
    out.either(&v, || {
        if h.requeue {
            format!("handed task {task} back to the board with a note")
        } else {
            format!("completed task {task} with a handoff note")
        }
    })
}

/// `cohort task context <task>`.
pub async fn task_context(
    c: &FleetClient,
    out: &mut Out<'_>,
    cohort: &str,
    task: &str,
    agent: &str,
    memory_bytes: usize,
) -> Result<()> {
    let num = if memory_bytes == 0 {
        String::new()
    } else {
        memory_bytes.to_string()
    };
    let qs = query(&[("agent", agent.to_owned()), ("memory_bytes", num)]);
    let v: Value = c
        .get(&format!("{}/context{qs}", task_path(cohort, task)))
        .await?;
    out.either(&v, || {
        let t = v.get("task").cloned().unwrap_or_default();
        let ctx = render_context(v.get("context").unwrap_or(&Value::Null));
        let mut text = format!(
            "task {} ({}): {}\n",
            s(&t, "id"),
            s(&t, "state"),
            s(&t, "payload")
        );
        if ctx.is_empty() {
            text.push_str("no context yet (no brief, notes, parent or matching memory)\n");
        } else {
            text.push_str(&ctx);
        }
        text
    })
}

/// `cohort task child <task> <payload>`.
pub async fn task_child(
    c: &FleetClient,
    out: &mut Out<'_>,
    cohort: &str,
    task: &str,
    payload: &str,
) -> Result<()> {
    let v: Value = c
        .post(
            &format!("{}/children", task_path(cohort, task)),
            json!({"payload": payload}),
        )
        .await?;
    out.either(&v, || {
        format!("added child task {} under {task}", s(&v, "id"))
    })
}

// --------------------------------------------------------------- schedules

/// Where and what a schedule runs.
#[derive(Debug, Default)]
pub struct ScheduleSpec {
    /// Target Citadel (or `cohort`).
    pub citadel: String,
    /// Target Cohort (or `citadel`).
    pub cohort: String,
    /// 5-field UTC cron (or `every`).
    pub cron: String,
    /// Fixed interval such as `30m` (or `cron`).
    pub every: String,
    /// Appended to the command as its last argument.
    pub prompt: String,
    /// cursor | codex | claude, used to build the command when none is
    /// given.
    pub agent: String,
    /// Model slug.
    pub model: String,
    /// Whitespace-separated precheck command.
    pub precheck: String,
    /// Explicit argv (after `--`).
    pub command: Vec<String>,
}

/// The agent CLI argv without its prompt (the server appends the prompt
/// as the last argument when the schedule fires).
pub fn agent_command_without_prompt(agent: &str, model: &str) -> Result<Vec<String>> {
    const MARK: &str = "\u{0}runeward-prompt\u{0}";
    let mut cmd = agent_command(agent, model, MARK)?;
    cmd.retain(|a| a != MARK);
    Ok(cmd)
}

impl ScheduleSpec {
    fn body(&self) -> Result<(String, Value)> {
        let path = match (self.citadel.trim(), self.cohort.trim()) {
            ("", "") => bail!("set --citadel or --cohort"),
            (c, "") => format!("/v1/citadels/{}/schedules", encode_path(c)),
            ("", f) => format!("/v1/cohorts/{}/schedules", encode_path(f)),
            _ => bail!("set either --citadel or --cohort, not both"),
        };
        if self.cron.trim().is_empty() == self.every.trim().is_empty() {
            bail!("set exactly one of --cron and --every");
        }
        let command = if self.command.is_empty() {
            if self.agent.is_empty() {
                bail!("give --agent cursor|codex|claude or a command after --");
            }
            agent_command_without_prompt(&self.agent, &self.model)?
        } else {
            self.command.clone()
        };
        let precheck: Vec<&str> = self.precheck.split_whitespace().collect();
        Ok((
            path,
            json!({
                "cron": self.cron, "every": self.every, "command": command,
                "prompt": self.prompt, "agent": self.agent, "model": self.model,
                "precheck": precheck,
            }),
        ))
    }
}

fn schedule_target(v: &Value) -> String {
    match (s(v, "citadel_id"), s(v, "cohort_id")) {
        (c, _) if !c.is_empty() => format!("citadel {c}"),
        (_, f) if !f.is_empty() => format!("cohort {f}"),
        _ => "-".into(),
    }
}

fn schedule_timing(v: &Value) -> String {
    match (s(v, "cron"), s(v, "every")) {
        (c, _) if !c.is_empty() => format!("cron {c}"),
        (_, e) => format!("every {e}"),
    }
}

fn describe_schedule(v: &Value) -> String {
    let mut t = String::new();
    let mut kv = |k: &str, val: String| {
        if !val.is_empty() {
            t.push_str(&format!("{k:<14}{val}\n"));
        }
    };
    kv("schedule", s(v, "id"));
    kv("target", schedule_target(v));
    kv("timing", schedule_timing(v));
    let argv = |k: &str| {
        v.get(k)
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .unwrap_or_default()
    };
    kv("command", argv("command"));
    kv("prompt", s(v, "prompt"));
    kv("precheck", argv("precheck"));
    kv("agent", s(v, "agent"));
    kv("model", s(v, "model"));
    kv("next fire", s(v, "next_fire_at"));
    kv("last fired", s(v, "last_fired_at"));
    let outcome = match (s(v, "last_outcome"), s(v, "last_reason")) {
        (o, r) if !r.is_empty() => format!("{o} ({r})"),
        (o, _) => o,
    };
    kv("last outcome", outcome);
    kv("last session", s(v, "last_session_id"));
    kv("fire count", s(v, "fire_count"));
    t
}

/// `schedule create`.
pub async fn schedule_create(
    c: &FleetClient,
    out: &mut Out<'_>,
    spec: &ScheduleSpec,
) -> Result<()> {
    let (path, body) = spec.body()?;
    let v: Value = c.post(&path, body).await?;
    out.either(&v, || {
        format!(
            "created schedule {} for {} ({}; next fire {})",
            s(&v, "id"),
            schedule_target(&v),
            schedule_timing(&v),
            cell(s(&v, "next_fire_at"))
        )
    })
}

/// `schedule list [--citadel X | --cohort Y]`.
pub async fn schedule_list(
    c: &FleetClient,
    out: &mut Out<'_>,
    citadel: &str,
    cohort: &str,
) -> Result<()> {
    let path = match (citadel.trim(), cohort.trim()) {
        ("", "") => "/v1/schedules".to_owned(),
        (x, "") => format!("/v1/citadels/{}/schedules", encode_path(x)),
        ("", f) => format!("/v1/cohorts/{}/schedules", encode_path(f)),
        _ => bail!("set either --citadel or --cohort, not both"),
    };
    let v: Value = c.get(&path).await?;
    if out.json {
        return out.json(&v);
    }
    let list = v
        .get("schedules")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if list.is_empty() {
        return out.line("no schedules");
    }
    let rows = list.iter().map(|x| {
        format!(
            "{}\t{}\t{}\t{}\t{}\t{}",
            s(x, "id"),
            schedule_target(x),
            schedule_timing(x),
            cell(s(x, "agent")),
            cell(s(x, "next_fire_at")),
            cell(s(x, "last_outcome"))
        )
    });
    out.table("ID\tTARGET\tTIMING\tAGENT\tNEXT FIRE\tLAST OUTCOME", rows)
}

/// `schedule get <id>`.
pub async fn schedule_get(c: &FleetClient, out: &mut Out<'_>, id: &str) -> Result<()> {
    let v: Value = c.get(&format!("/v1/schedules/{}", encode_path(id))).await?;
    out.either(&v, || describe_schedule(&v))
}

/// `schedule delete <id>`.
pub async fn schedule_delete(c: &FleetClient, out: &mut Out<'_>, id: &str) -> Result<()> {
    let v: Value = c
        .delete(&format!("/v1/schedules/{}", encode_path(id)))
        .await?;
    out.either(&v, || format!("deleted schedule {id}"))
}

/// `schedule run <id>`: fires it now (policy, precheck and budgets apply).
pub async fn schedule_run(c: &FleetClient, out: &mut Out<'_>, id: &str) -> Result<()> {
    let v: Value = c
        .post(&format!("/v1/schedules/{}/run", encode_path(id)), json!({}))
        .await?;
    out.either(&v, || {
        let mut t = format!("schedule {id}: {}", s(&v, "outcome"));
        let session = s(&v, "session_id");
        if !session.is_empty() {
            t.push_str(&format!(
                " (agent session {session} in {}; follow it with `runeward session attach {session}`)",
                s(&v, "citadel_id")
            ));
        }
        let reason = s(&v, "reason");
        if !reason.is_empty() {
            t.push_str(&format!(": {reason}"));
        }
        t
    })
}

#[cfg(test)]
#[path = "remote_tests.rs"]
mod tests;
