//! The governed path every tool call takes, and the tools built on it.

use std::future::Future;

use base64::Engine as _;
use runeward_backend::{ExecRequest, ExecResult};
use runeward_charter::Verdict;
use runeward_policy::Action;
use serde::Serialize;

use crate::approvals::ForgetOnDrop;
use crate::error::{Error, Result};
use crate::manager::Manager;
use crate::sessions::Session;

/// The governed outcome of one tool invocation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ToolResult {
    pub verdict: Verdict,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub reason: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub approval_id: String,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub pending: bool,
    pub exit_code: i64,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub stdout: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub stderr: String,
    pub duration_ms: i64,
}

impl ToolResult {
    fn refused(verdict: Verdict, reason: impl Into<String>) -> Self {
        Self {
            verdict,
            reason: reason.into(),
            approval_id: String::new(),
            pending: false,
            exit_code: 0,
            stdout: String::new(),
            stderr: String::new(),
            duration_ms: 0,
        }
    }
}

/// One action presented to the governed path.
///
/// This is the single place an [`Action`] is built for policy, so later
/// inputs slot in here: an effect class (read / write / irreversible, with
/// untagged actions treated as irreversible and gated on approval) and the
/// egress-broker route a call targets for per-route budgets.
#[derive(Debug, Clone)]
pub(crate) struct GovernCall {
    pub(crate) tool: String,
    /// The primary argument (command line, path, URL).
    pub(crate) arg: String,
    /// The raw argument vector for argv-aware rules and the ledger.
    pub(crate) args: Vec<String>,
    /// Skips the text scrubber for stdout (binary payloads like
    /// screenshots); stderr is always scrubbed.
    pub(crate) raw_stdout: bool,
}

impl GovernCall {
    pub(crate) fn new(tool: &str, arg: &str, args: Vec<String>) -> Self {
        Self {
            tool: tool.to_owned(),
            arg: arg.to_owned(),
            args,
            raw_stdout: false,
        }
    }

    fn action(&self) -> Action {
        Action::new(self.tool.clone(), self.arg.clone()).with_args(self.args.clone())
    }
}

/// Tools that cause outbound network access, subject to the egress budget.
fn is_egress_tool(tool: &str) -> bool {
    tool == "browser" || tool == "net"
}

pub(crate) fn or_reason(reason: &str, fallback: &str) -> String {
    if reason.trim().is_empty() {
        fallback.to_owned()
    } else {
        reason.to_owned()
    }
}

fn millis(d: std::time::Duration) -> i64 {
    i64::try_from(d.as_millis()).unwrap_or(i64::MAX)
}

impl Manager {
    /// Runs one action through policy, the approval gate, guardrails and
    /// budgets; `run` is only invoked once the action is authorized.
    pub(crate) async fn govern<F, Fut>(
        &self,
        sess: &Session,
        call: GovernCall,
        run: F,
    ) -> Result<ToolResult>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = runeward_backend::Result<ExecResult>>,
    {
        sess.ensure_running()?;
        let dec = sess.engine.evaluate(&call.action());
        match dec.verdict {
            Verdict::Allow => {}
            Verdict::RequireApproval => {
                let reason = or_reason(&dec.reason, "approval required");
                let (view, decided) =
                    self.approvals
                        .create(&sess.sandbox.id, &call.tool, &call.arg, &reason);
                // An abandoned or timed-out call leaves no orphan; after a
                // decision the entry is already gone.
                let _forget = ForgetOnDrop {
                    store: &self.approvals,
                    id: view.id.clone(),
                };
                self.record(
                    sess,
                    "approval",
                    &call.arg,
                    &call.args,
                    Verdict::RequireApproval.as_str(),
                    -1,
                    0,
                    &reason,
                )
                .await;
                let outcome = match self.config.approval_wait.filter(|d| !d.is_zero()) {
                    Some(wait) => tokio::time::timeout(wait, decided).await.ok(),
                    None => Some(decided.await),
                };
                match outcome {
                    Some(Ok(true)) => {}
                    Some(Ok(false)) => {
                        self.record(
                            sess,
                            &call.tool,
                            &call.arg,
                            &call.args,
                            "deny",
                            -1,
                            0,
                            "denied by approver",
                        )
                        .await;
                        let mut r = ToolResult::refused(Verdict::Deny, "denied by approver");
                        r.approval_id = view.id;
                        return Ok(r);
                    }
                    // Timed out (or the store dropped the decision).
                    _ => {
                        let mut r = ToolResult::refused(Verdict::RequireApproval, reason);
                        r.pending = true;
                        r.approval_id = view.id;
                        return Ok(r);
                    }
                }
            }
            // Deny, and anything unrecognised, fails closed.
            _ => {
                return self
                    .deny(sess, &call, or_reason(&dec.reason, "denied by policy"))
                    .await;
            }
        }

        if let Err(e) = sess.guard.check_exec() {
            return self.deny(sess, &call, e.to_string()).await;
        }
        // Fail closed once reported usage exceeds the Charter's budget.
        if !self.config.ignore_client_usage
            && let Some(why) = self.accounting.over(
                &sess.sandbox.id,
                sess.charter.limits.max_tokens,
                sess.charter.limits.max_cost_usd,
            )
        {
            return self.deny(sess, &call, why).await;
        }
        if is_egress_tool(&call.tool)
            && let Err(e) = sess.guard.check_egress()
        {
            return self.deny(sess, &call, e.to_string()).await;
        }

        let loop_key = format!("{}|{}", call.tool, call.arg);
        let res = match run().await {
            Ok(res) => res,
            Err(e) => {
                sess.guard.record_outcome(&loop_key, true);
                let msg = e.to_string();
                self.record(
                    sess, &call.tool, &call.arg, &call.args, "error", -1, 0, &msg,
                )
                .await;
                return Err(Error::from(e));
            }
        };
        sess.guard.record_outcome(&loop_key, res.exit_code != 0);
        let dur = millis(res.duration);
        self.record(
            sess,
            &call.tool,
            &call.arg,
            &call.args,
            Verdict::Allow.as_str(),
            i64::from(res.exit_code),
            dur,
            "",
        )
        .await;

        // Redact returned output too, so a leaked credential never reaches
        // the API/MCP client in cleartext.
        let (mut stdout, mut stderr) = (res.stdout, res.stderr);
        if sess.charter.audit.redact_enabled() {
            if !call.raw_stdout {
                stdout = sess.scrub(&stdout);
            }
            stderr = sess.scrub(&stderr);
        }
        Ok(ToolResult {
            verdict: Verdict::Allow,
            reason: String::new(),
            approval_id: String::new(),
            pending: false,
            exit_code: i64::from(res.exit_code),
            stdout,
            stderr,
            duration_ms: dur,
        })
    }

    async fn deny(&self, sess: &Session, call: &GovernCall, reason: String) -> Result<ToolResult> {
        self.record(
            sess, &call.tool, &call.arg, &call.args, "deny", -1, 0, &reason,
        )
        .await;
        Ok(ToolResult::refused(Verdict::Deny, reason))
    }

    /// Runs `command` in `sess` with its environment.
    pub(crate) fn exec_request(sess: &Session, command: Vec<String>, workdir: &str) -> ExecRequest {
        ExecRequest {
            command,
            workdir: workdir.to_owned(),
            env: sess.env.clone(),
            ..ExecRequest::default()
        }
    }

    /// Runs a command vector under policy (`shell`).
    pub async fn shell(&self, id: &str, command: &[String], workdir: &str) -> Result<ToolResult> {
        let sess = self.awake_session(id).await?;
        if command.is_empty() {
            return Err(Error::other("empty command"));
        }
        let wd = if workdir.is_empty() {
            sess.workdir.clone()
        } else {
            workdir.to_owned()
        };
        let call = GovernCall::new("shell", &command.join(" "), command.to_vec());
        let req = Self::exec_request(&sess, command.to_vec(), &wd);
        self.govern(&sess, call, || sess.backend.exec(id, req))
            .await
    }

    /// Runs a Python snippet via `python3 -c` (needs the `python`
    /// capability).
    pub async fn python(&self, id: &str, code: &str) -> Result<ToolResult> {
        self.run_code(id, "python", ["python3", "-c", code], code)
            .await
    }

    /// Runs a JavaScript snippet via `node -e` (needs the `node`
    /// capability).
    pub async fn node(&self, id: &str, code: &str) -> Result<ToolResult> {
        self.run_code(id, "node", ["node", "-e", code], code).await
    }

    async fn run_code(
        &self,
        id: &str,
        tool: &str,
        command: [&str; 3],
        code: &str,
    ) -> Result<ToolResult> {
        let sess = self.awake_session(id).await?;
        if !has_capability(&sess.charter, tool) {
            return Err(Error::bad_input(format!(
                "{tool} is not declared by this Charter; add capabilities = [{tool:?}] and use an image that provides it"
            )));
        }
        let command = command.map(String::from).to_vec();
        let req = Self::exec_request(&sess, command, &sess.workdir);
        let call = GovernCall::new(tool, code, Vec::new());
        self.govern(&sess, call, || sess.backend.exec(id, req))
            .await
    }

    /// Reads a workspace file (`file.read`).
    pub async fn file_read(&self, id: &str, path: &str) -> Result<ToolResult> {
        let sess = self.awake_session(id).await?;
        let resolved = resolve_file_tool_path(&sess.workdir, path)?;
        // "--" stops a path beginning with "-" being parsed as a flag.
        let cmd = vec!["cat".into(), "--".into(), resolved];
        let req = Self::exec_request(&sess, cmd, &sess.workdir);
        let call = GovernCall::new("file.read", path, vec![path.to_owned()]);
        self.govern(&sess, call, || sess.backend.exec(id, req))
            .await
    }

    /// Writes a workspace file, creating parent directories (`file.write`).
    /// Content travels base64-encoded to stay binary-safe over the shell.
    pub async fn file_write(&self, id: &str, path: &str, content: &str) -> Result<ToolResult> {
        let sess = self.awake_session(id).await?;
        let resolved = resolve_file_tool_path(&sess.workdir, path)?;
        let b64 = base64::engine::general_purpose::STANDARD.encode(content.as_bytes());
        let q = sh_quote(&resolved);
        let script = format!("mkdir -p \"$(dirname {q})\" && printf %s '{b64}' | base64 -d > {q}");
        let cmd = vec!["sh".into(), "-c".into(), script];
        let req = Self::exec_request(&sess, cmd, &sess.workdir);
        let call = GovernCall::new("file.write", path, vec![path.to_owned()]);
        self.govern(&sess, call, || sess.backend.exec(id, req))
            .await
    }

    /// Lists a workspace directory (`file.read`).
    pub async fn file_list(&self, id: &str, path: &str) -> Result<ToolResult> {
        let sess = self.awake_session(id).await?;
        let path = if path.is_empty() { "." } else { path };
        let resolved = resolve_file_tool_path(&sess.workdir, path)?;
        let cmd = vec!["ls".into(), "-la".into(), "--".into(), resolved];
        let req = Self::exec_request(&sess, cmd, &sess.workdir);
        let call = GovernCall::new("file.read", path, vec![path.to_owned()]);
        self.govern(&sess, call, || sess.backend.exec(id, req))
            .await
    }

    /// Greps the workspace recursively from `path` (`file.read`).
    pub async fn file_search(&self, id: &str, query: &str, path: &str) -> Result<ToolResult> {
        let sess = self.awake_session(id).await?;
        let path = if path.is_empty() { "." } else { path };
        let resolved = resolve_file_tool_path(&sess.workdir, path)?;
        // "-e query" keeps a leading "-" a pattern; "--" ends flags.
        let cmd = ["grep", "-rn", "-e", query, "--", &resolved]
            .map(String::from)
            .to_vec();
        let req = Self::exec_request(&sess, cmd, &sess.workdir);
        let call = GovernCall::new("file.read", query, vec![query.to_owned(), path.to_owned()]);
        self.govern(&sess, call, || sess.backend.exec(id, req))
            .await
    }
}

/// Reports whether the session's Charter declares (or its image implies)
/// `wanted`.
pub(crate) fn has_capability(c: &runeward_charter::Charter, wanted: &str) -> bool {
    runeward_backend::charter_capabilities(c)
        .iter()
        .any(|c| c == wanted)
}

/// Single-quotes `s` for an `sh -c` script.
pub(crate) fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// Confines a tool path to the workspace: absolute paths and `..` escapes
/// are refused; a relative path resolves against `workdir`.
pub(crate) fn resolve_file_tool_path(workdir: &str, rel: &str) -> Result<String> {
    if workdir.trim().is_empty() {
        return Ok(rel.to_owned());
    }
    if rel.starts_with('/') {
        return Err(Error::bad_input(format!(
            "path {rel:?} must be relative to workspace"
        )));
    }
    let root = if workdir.starts_with('/') {
        clean(workdir)
    } else {
        let cwd = std::env::current_dir()
            .map(|d| d.to_string_lossy().into_owned())
            .unwrap_or_default();
        clean(&format!("{cwd}/{workdir}"))
    };
    let cleaned = clean(&format!("{root}/{rel}"));
    let inside =
        cleaned == root || cleaned.starts_with(&format!("{}/", root.trim_end_matches('/')));
    if !inside {
        return Err(Error::bad_input(format!(
            "path {rel:?} escapes workspace root"
        )));
    }
    Ok(cleaned)
}

/// Go's `path.Clean` for slash paths.
pub(crate) fn clean(p: &str) -> String {
    if p.is_empty() {
        return ".".into();
    }
    let rooted = p.starts_with('/');
    let mut out: Vec<&str> = Vec::new();
    for part in p.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                if out.last().is_some_and(|l| *l != "..") {
                    out.pop();
                } else if !rooted {
                    out.push("..");
                }
            }
            other => out.push(other),
        }
    }
    let joined = out.join("/");
    match (rooted, joined.is_empty()) {
        (true, _) => format!("/{joined}"),
        (false, true) => ".".into(),
        (false, false) => joined,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_paths_are_confined() {
        let got = resolve_file_tool_path("/workspace", "notes/todo.txt").expect("ok");
        assert_eq!(got, "/workspace/notes/todo.txt");
        assert_eq!(
            resolve_file_tool_path("/workspace", ".").expect("ok"),
            "/workspace"
        );
        for bad in ["/etc/passwd", "../etc/passwd", "dir/../../etc/passwd"] {
            let err = resolve_file_tool_path("/workspace", bad).expect_err(bad);
            assert!(err.is_client_error(), "{bad}");
        }
        assert!(resolve_file_tool_path("/workspace", "../workspace2/x").is_err());
        assert_eq!(
            resolve_file_tool_path("", "../x").expect("unconfined"),
            "../x"
        );
        assert_eq!(
            resolve_file_tool_path("/", "etc/x").expect("root"),
            "/etc/x"
        );
    }

    #[test]
    fn quoting() {
        assert_eq!(sh_quote("it's"), r"'it'\''s'");
    }
}
