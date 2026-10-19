//! The experimental in-sandbox browser: one-shot renders and stateful CDP
//! sessions driven through the `runeward-browser` driver in the image.

use std::time::{Duration, Instant};

use runeward_browser::{Command, CommandResult};
use runeward_charter::Verdict;

use crate::error::{Error, Result};
use crate::govern::{GovernCall, ToolResult, has_capability, sh_quote};
use crate::manager::Manager;
use crate::sessions::{BrowserSession, Session, lock};

/// The in-sandbox CDP driver binary.
const BROWSER_DRIVER_BIN: &str = "runeward-browser";
/// How long [`Manager::browser_open`] waits for the driver socket.
const BROWSER_READY_TIMEOUT: Duration = Duration::from_secs(20);

const DISABLED: &str = "browser automation is experimental and disabled by default; set RUNEWARD_ENABLE_EXPERIMENTAL_BROWSER=1 only in a trusted deployment";

fn rand_id() -> String {
    hex::encode(rand::random::<[u8; 8]>())
}

/// The `sh -c` program rendering `url`: the driver when present (it runs a
/// loopback forwarder that adds Proxy-Authorization, which Chromium's
/// `--proxy-server` cannot carry), else raw Chromium, which only works
/// with an unauthenticated proxy. The proxy comes from the container's env.
pub(crate) fn browser_script(url: &str, mode: &str, chromium_sandbox: bool) -> String {
    let render_mode = if mode == "screenshot" {
        "screenshot"
    } else {
        "text"
    };
    let rb = format!(
        "runeward-browser render --mode {render_mode} ${{PROXY:+--proxy $PROXY}} {}",
        sh_quote(url)
    );
    let find = "CHROME=$(command -v chromium 2>/dev/null || command -v chromium-browser 2>/dev/null || command -v google-chrome 2>/dev/null || command -v google-chrome-stable 2>/dev/null || command -v headless-shell 2>/dev/null || echo chromium)";
    // Chromium's own sandbox needs user namespaces, usually unavailable in a
    // container; operators on gVisor/Kata or userns can keep it.
    let sandbox = if chromium_sandbox {
        ""
    } else {
        "--no-sandbox "
    };
    let flags =
        format!("--headless=new {sandbox}--disable-gpu --disable-dev-shm-usage --hide-scrollbars");
    let fallback = if mode == "screenshot" {
        format!(
            "{find}; \"$CHROME\" {flags} ${{PROXY:+--proxy-server=$PROXY}} --screenshot=/tmp/rw-shot.png {} >/dev/null 2>&1; base64 /tmp/rw-shot.png",
            sh_quote(url)
        )
    } else {
        format!(
            "{find}; \"$CHROME\" {flags} ${{PROXY:+--proxy-server=$PROXY}} --dump-dom {}",
            sh_quote(url)
        )
    };
    format!(
        "PROXY=\"${{HTTPS_PROXY:-$HTTP_PROXY}}\"; if command -v runeward-browser >/dev/null 2>&1; then {rb}; else {fallback}; fi"
    )
}

fn driver_call(socket: &str, token: &str, cmd: &Command) -> Result<Vec<String>> {
    let payload = serde_json::to_string(cmd).map_err(Error::other)?;
    Ok([
        BROWSER_DRIVER_BIN,
        "call",
        "--socket",
        socket,
        "--token",
        token,
        "--json",
        &payload,
    ]
    .map(String::from)
    .to_vec())
}

impl Manager {
    fn browser_session(sess: &Session, sid: &str) -> Result<BrowserSession> {
        lock(&sess.browsers)
            .get(sid)
            .cloned()
            .ok_or_else(|| Error::not_found(format!("browser session {sid:?} not found")))
    }

    /// Renders a page with headless Chromium in the sandbox (tool
    /// `browser`, arg = url). `mode` is `text` (rendered DOM) or
    /// `screenshot` (base64 PNG in stdout, which skips the text scrubber).
    pub async fn browser(&self, id: &str, url: &str, mode: &str) -> Result<ToolResult> {
        if !self.config.experimental_browser {
            return Err(Error::other(DISABLED));
        }
        let sess = self.session(id)?;
        if !has_capability(&sess.charter, "browser") {
            return Err(Error::bad_input(
                "browser is not declared by this Charter; add capabilities = [\"browser\"] and use an image with Chromium",
            ));
        }
        if url.is_empty() {
            return Err(Error::other("url is required"));
        }
        let script = browser_script(url, mode, self.config.chromium_sandbox);
        let mut call = GovernCall::new("browser", url, vec![url.to_owned(), mode.to_owned()]);
        call.raw_stdout = mode == "screenshot";
        let req = Self::exec_request(&sess, vec!["sh".into(), "-c".into(), script], &sess.workdir);
        self.govern(&sess, call, || sess.backend.exec(id, req))
            .await
    }

    /// Starts a stateful browser session (policy: tool `browser`, action
    /// `open`). A deny or pending verdict comes back without a session.
    pub async fn browser_open(&self, id: &str) -> Result<(Option<String>, ToolResult)> {
        if !self.config.experimental_browser {
            return Err(Error::other(DISABLED));
        }
        let sess = self.session(id)?;
        if !has_capability(&sess.charter, "browser") {
            return Err(Error::bad_input(
                "browser is not declared by this Charter; add capabilities = [\"browser\"] and use an image with the Runeward browser driver",
            ));
        }
        let sid = rand_id();
        let socket = format!("/tmp/rw-browser-{sid}.sock");
        let token = format!("{}{}", rand_id(), rand_id());
        let start = format!(
            "command -v {bin} >/dev/null 2>&1 || {{ echo 'runeward-browser not found in sandbox image' >&2; exit 127; }}; PROXY=\"${{HTTPS_PROXY:-$HTTP_PROXY}}\"; setsid {bin} serve --socket {} --token {} ${{PROXY:+--proxy $PROXY}} >/tmp/rw-browser-{sid}.log 2>&1 & echo started",
            sh_quote(&socket),
            sh_quote(&token),
            bin = BROWSER_DRIVER_BIN,
        );
        let call = GovernCall::new("browser", "open", vec!["open".into(), sid.clone()]);
        let req = Self::exec_request(&sess, vec!["sh".into(), "-c".into(), start], &sess.workdir);
        let res = self
            .govern(&sess, call, || sess.backend.exec(id, req))
            .await?;
        if res.verdict != Verdict::Allow {
            return Ok((None, res));
        }
        if res.exit_code != 0 {
            return Err(Error::other(format!(
                "start browser driver: {}",
                format!("{}{}", res.stderr, res.stdout).trim()
            )));
        }
        self.browser_wait_ready(&sess, &socket, &token).await?;
        lock(&sess.browsers).insert(sid.clone(), BrowserSession { socket, token });
        Ok((Some(sid), res))
    }

    /// Sends one action to a live browser session through the governed
    /// path. Stdout carries the value (or base64 screenshot); a driver
    /// failure surfaces in `reason`.
    pub async fn browser_act(
        &self,
        id: &str,
        session_id: &str,
        mut cmd: Command,
    ) -> Result<ToolResult> {
        let sess = self.session(id)?;
        let bs = Self::browser_session(&sess, session_id)?;
        if cmd.action.is_empty() {
            return Err(Error::other("action is required"));
        }
        cmd.token.clone_from(&bs.token);
        let argv = driver_call(&bs.socket, &bs.token, &cmd)?;
        let arg = if !cmd.url.is_empty() {
            format!("{} {}", cmd.action, cmd.url)
        } else if !cmd.selector.is_empty() {
            format!("{} {}", cmd.action, cmd.selector)
        } else {
            cmd.action.clone()
        };
        let mut call = GovernCall::new("browser", &arg, argv.clone());
        call.raw_stdout = cmd.action == "screenshot";
        let req = Self::exec_request(&sess, argv, &sess.workdir);
        let mut res = self
            .govern(&sess, call, || sess.backend.exec(id, req))
            .await?;
        if res.verdict != Verdict::Allow {
            return Ok(res);
        }
        // `call` exits non-zero on driver failure but still prints JSON.
        if let Ok(out) = serde_json::from_str::<CommandResult>(res.stdout.trim()) {
            res.stdout = if out.screenshot.is_empty() {
                out.value
            } else {
                out.screenshot
            };
            if !out.ok && !out.error.is_empty() {
                res.reason = out.error;
            }
        }
        Ok(res)
    }

    /// Shuts the driver down (best effort) and always drops the session.
    pub async fn browser_close(&self, id: &str, session_id: &str) -> Result<()> {
        let sess = self.session(id)?;
        let bs = Self::browser_session(&sess, session_id)?;
        let cmd = Command {
            action: "close".into(),
            token: bs.token.clone(),
            ..Command::default()
        };
        let argv = driver_call(&bs.socket, &bs.token, &cmd)?;
        let _ = sess
            .backend
            .exec(id, Self::exec_request(&sess, argv, &sess.workdir))
            .await;
        lock(&sess.browsers).remove(session_id);
        self.record(
            &sess,
            "browser",
            "close",
            &["close".into(), session_id.to_owned()],
            Verdict::Allow.as_str(),
            0,
            0,
            "",
        )
        .await;
        Ok(())
    }

    async fn browser_wait_ready(&self, sess: &Session, socket: &str, token: &str) -> Result<()> {
        let ping = Command {
            action: "ping".into(),
            token: token.to_owned(),
            ..Command::default()
        };
        let argv = driver_call(socket, token, &ping)?;
        let deadline = Instant::now() + BROWSER_READY_TIMEOUT;
        loop {
            let req = Self::exec_request(sess, argv.clone(), &sess.workdir);
            if let Ok(res) = sess.backend.exec(&sess.sandbox.id, req).await
                && res.exit_code == 0
                && serde_json::from_str::<CommandResult>(res.stdout.trim()).is_ok_and(|r| r.ok)
            {
                return Ok(());
            }
            if Instant::now() > deadline {
                return Err(Error::other(format!(
                    "browser driver did not become ready within {}s",
                    BROWSER_READY_TIMEOUT.as_secs()
                )));
            }
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn script_prefers_driver_and_quotes_url() {
        let s = browser_script("https://e.com/?q='x'", "screenshot", false);
        assert!(
            s.starts_with("PROXY=\"${HTTPS_PROXY:-$HTTP_PROXY}\"; if command -v runeward-browser")
        );
        assert!(s.contains(
            "render --mode screenshot ${PROXY:+--proxy $PROXY} 'https://e.com/?q='\\''x'\\'''"
        ));
        assert!(s.contains("--no-sandbox"));
        assert!(s.contains("base64 /tmp/rw-shot.png"));
        let s = browser_script("u", "text", true);
        assert!(!s.contains("--no-sandbox") && s.contains("--dump-dom 'u'"));
    }
}
