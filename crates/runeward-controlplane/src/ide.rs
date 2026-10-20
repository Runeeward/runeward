//! The experimental in-sandbox browser IDE (code-server) and its endpoint
//! for the ticketed reverse proxy.

use std::time::{Duration, Instant};

use runeward_backend::ExecRequest;
use runeward_charter::Verdict;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::citadels::ReadinessCheck;
use crate::error::{Error, Result};
use crate::govern::sh_quote;
use crate::manager::Manager;
use crate::sessions::{Session, lock};

const IDE_BINARY: &str = "code-server";
const IDE_READY_TIMEOUT: Duration = Duration::from_secs(45);
const IDE_READY_POLL: Duration = Duration::from_millis(250);
const IDE_PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// Waits until `endpoint` answers HTTP at all (code-server may redirect to
/// login or return 200; any response means it is up).
async fn wait_ide_ready(endpoint: &str) -> Result<()> {
    let deadline = Instant::now() + IDE_READY_TIMEOUT;
    let mut last = String::from("no response");
    while Instant::now() < deadline {
        match tokio::time::timeout(IDE_PROBE_TIMEOUT, probe(endpoint)).await {
            Ok(Ok(())) => return Ok(()),
            Ok(Err(e)) => last = e.to_string(),
            Err(_) => last = "timed out".into(),
        }
        tokio::time::sleep(IDE_READY_POLL).await;
    }
    Err(Error::other(format!("ide not ready at {endpoint}: {last}")))
}

async fn probe(endpoint: &str) -> std::io::Result<()> {
    let mut s = tokio::net::TcpStream::connect(endpoint).await?;
    s.write_all(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
        .await?;
    let mut buf = [0u8; 5];
    s.read_exact(&mut buf).await?;
    if &buf == b"HTTP/" {
        Ok(())
    } else {
        Err(std::io::Error::other("not an HTTP response"))
    }
}

impl Manager {
    /// Reports whether the experimental browser IDE is enabled.
    pub fn experimental_ide_enabled(&self) -> bool {
        self.config.experimental_ide
    }

    pub(crate) fn ide_readiness(&self) -> ReadinessCheck {
        if self.config.experimental_ide {
            ReadinessCheck {
                name: "ide".into(),
                status: "ok".into(),
                message: "experimental browser IDE enabled".into(),
            }
        } else {
            ReadinessCheck {
                name: "ide".into(),
                status: "fail".into(),
                message: "experimental browser IDE is disabled; restart the server with RUNEWARD_ENABLE_EXPERIMENTAL_IDE=1".into(),
            }
        }
    }

    /// Launches code-server in the Citadel and records its endpoint. A no-op
    /// when the Charter has no IDE or the flag is off.
    pub(crate) async fn start_ide(&self, sess: &Session) -> Result<()> {
        if !sess.charter.ide.enabled || !self.config.experimental_ide {
            return Ok(());
        }
        let port = if sess.charter.ide.port > 0 {
            sess.charter.ide.port
        } else {
            8080
        };
        let workdir = if sess.workdir.is_empty() {
            "/workspace".to_owned()
        } else {
            sess.workdir.clone()
        };
        let start = format!(
            "command -v {IDE_BINARY} >/dev/null 2>&1 || {{ echo '{IDE_BINARY} not found in Citadel image; build deploy/Dockerfile.ide' >&2; exit 127; }}; setsid {IDE_BINARY} --bind-addr 0.0.0.0:{port} --auth none --disable-telemetry --disable-update-check {} >/tmp/rw-ide.log 2>&1 & echo started",
            sh_quote(&workdir)
        );
        let req = ExecRequest {
            command: vec!["sh".into(), "-c".into(), start],
            workdir: workdir.clone(),
            env: sess.env.clone(),
            ..ExecRequest::default()
        };
        let res = sess
            .backend
            .exec(&sess.sandbox.id, req)
            .await
            .map_err(|e| Error::other(format!("start ide: {e}")))?;
        if res.exit_code != 0 {
            return Err(Error::other(format!(
                "start ide: {}",
                format!("{}{}", res.stderr, res.stdout).trim()
            )));
        }
        let reachable = sess.backend.reachable().ok_or_else(|| {
            Error::other(format!(
                "backend {:?} cannot resolve container IP for IDE proxy",
                sess.backend.name()
            ))
        })?;
        let ip = reachable
            .container_ip(&sess.sandbox.id)
            .await
            .map_err(|e| Error::other(format!("resolve ide endpoint: {e}")))?;
        let endpoint = if ip.contains(':') {
            format!("[{ip}]:{port}")
        } else {
            format!("{ip}:{port}")
        };
        wait_ide_ready(&endpoint).await?;
        lock(&sess.ide_endpoint).clone_from(&endpoint);
        self.record(
            sess,
            "ide",
            "open",
            &[endpoint],
            Verdict::Allow.as_str(),
            0,
            0,
            "",
        )
        .await;
        Ok(())
    }

    /// The in-cell IDE `host:port` when the experimental IDE is running.
    pub fn ide_endpoint(&self, id: &str) -> Option<String> {
        let sess = self.session_opt(id)?;
        let ep = lock(&sess.ide_endpoint).clone();
        (!ep.is_empty()).then_some(ep)
    }

    /// Charter-declared CLI agent hints for the Citadel IDE UI.
    pub fn ide_agents(&self, id: &str) -> Vec<String> {
        self.session_opt(id)
            .map(|s| s.charter.ide.agents.clone())
            .unwrap_or_default()
    }

    /// Sets the IDE proxy target without starting code-server (tests).
    pub fn set_ide_endpoint_for_test(&self, id: &str, endpoint: &str) {
        if let Some(sess) = self.session_opt(id) {
            *lock(&sess.ide_endpoint) = endpoint.to_owned();
        }
    }

    /// Chronicles `ide.close` when an IDE was started for the Citadel.
    pub(crate) async fn record_ide_close(&self, sess: &Session) {
        let ep = lock(&sess.ide_endpoint).clone();
        if ep.is_empty() {
            return;
        }
        self.record(
            sess,
            "ide",
            "close",
            &[ep],
            Verdict::Allow.as_str(),
            0,
            0,
            "",
        )
        .await;
    }
}
