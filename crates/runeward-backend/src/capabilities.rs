//! Optional in-image runtimes (`python`, `node`, `browser`): inferring them
//! from a Charter and verifying them against a running sandbox.

use runeward_charter::Charter;

use crate::backend::Backend;
use crate::error::{BackendError, Result};
use crate::types::ExecRequest;

const BROWSER_CHECK: &str = "command -v runeward-browser >/dev/null 2>&1 || command -v chromium >/dev/null 2>&1 || command -v chromium-browser >/dev/null 2>&1 || command -v google-chrome >/dev/null 2>&1 || command -v google-chrome-stable >/dev/null 2>&1 || command -v headless-shell >/dev/null 2>&1";

const DISCOVERY_SCRIPT: &str = "command -v python3 >/dev/null 2>&1 && echo python; command -v node >/dev/null 2>&1 && echo node; (command -v runeward-browser >/dev/null 2>&1 || command -v chromium >/dev/null 2>&1 || command -v chromium-browser >/dev/null 2>&1 || command -v google-chrome >/dev/null 2>&1 || command -v google-chrome-stable >/dev/null 2>&1 || command -v headless-shell >/dev/null 2>&1) && echo browser; true";

/// The capabilities a Charter declares, plus those implied by well-known
/// images, deduplicated in declaration order.
pub fn charter_capabilities(c: &Charter) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut add = |cap: &str| {
        if !out.iter().any(|c| c == cap) {
            out.push(cap.to_owned());
        }
    };
    for cap in &c.capabilities {
        let cap = cap.trim().to_lowercase();
        if matches!(cap.as_str(), "python" | "node" | "browser") {
            add(&cap);
        }
    }
    let image = c.host.image.to_lowercase();
    let has = |s: &str| image.contains(s);
    let agent_image =
        has("runeward-sandbox") || has("runeward-agent") || has("runeward-ide-agents");
    if has("python") || agent_image {
        add("python");
    }
    if has("node") || agent_image {
        add("node");
    }
    if has("alpine-chrome") || has("runeward-sandbox") {
        add("browser");
    }
    out
}

fn check_script(capability: &str) -> &'static str {
    match capability {
        "python" => "command -v python3 >/dev/null 2>&1",
        "node" => "command -v node >/dev/null 2>&1",
        "browser" => BROWSER_CHECK,
        _ => "",
    }
}

/// Confirms each capability the Charter declares is present in the running
/// sandbox, failing when one is missing. A Charter that declares none has
/// its capabilities discovered instead (backward compatibility). On success
/// `charter.capabilities` holds the verified or discovered set.
pub async fn verify_runtime_capabilities(
    be: &dyn Backend,
    id: &str,
    charter: &mut Charter,
) -> Result<()> {
    let capabilities = charter_capabilities(charter);
    let workdir = charter.host.workdir.clone();
    let req = |script: &str| ExecRequest {
        command: vec!["sh".into(), "-c".into(), script.into()],
        workdir: workdir.clone(),
        ..ExecRequest::default()
    };
    if capabilities.is_empty() {
        if let Ok(res) = be.exec(id, req(DISCOVERY_SCRIPT)).await
            && res.exit_code == 0
        {
            charter.capabilities = res.stdout.split_whitespace().map(String::from).collect();
        }
        return Ok(());
    }
    for capability in &capabilities {
        let res = be
            .exec(id, req(check_script(capability)))
            .await
            .map_err(|e| {
                BackendError::msg(format!("verify Charter capability {capability:?}: {e}"))
            })?;
        if res.exit_code != 0 {
            return Err(BackendError::msg(format!(
                "Charter declares capability {capability:?} but image {:?} does not provide it",
                charter.host.image
            )));
        }
    }
    charter.capabilities = capabilities;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use async_trait::async_trait;
    use runeward_charter::{File, Host};
    use tokio::io::AsyncWrite;

    use super::*;
    use crate::backend::Backend;
    use crate::isolation::IsolationTier;
    use crate::types::{ExecResult, PtyStream, Sandbox, SnapshotRef, Spec};

    /// A backend whose every exec returns a fixed result.
    #[derive(Debug, Default)]
    struct FakeBackend {
        result: ExecResult,
        calls: Mutex<Vec<Vec<String>>>,
    }

    #[async_trait]
    impl Backend for FakeBackend {
        fn name(&self) -> &str {
            "fake"
        }
        fn isolation_tier(&self) -> IsolationTier {
            IsolationTier::Process
        }
        async fn create(&self, _: Spec) -> Result<Sandbox> {
            Ok(Sandbox::default())
        }
        async fn exec(&self, _: &str, req: ExecRequest) -> Result<ExecResult> {
            self.calls
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(req.command);
            Ok(self.result.clone())
        }
        async fn attach_pty(&self, _: &str, _: PtyStream) -> Result<()> {
            Ok(())
        }
        async fn copy_files(&self, _: &str, _: &[File]) -> Result<()> {
            Ok(())
        }
        async fn export_workspace(
            &self,
            _: &str,
            _: &mut (dyn AsyncWrite + Send + Unpin),
        ) -> Result<()> {
            Ok(())
        }
        async fn snapshot(&self, _: &str, _: &str) -> Result<SnapshotRef> {
            Err(BackendError::Unsupported("snapshot".into()))
        }
        async fn restore(&self, _: &SnapshotRef) -> Result<Sandbox> {
            Err(BackendError::Unsupported("restore".into()))
        }
        async fn kill(&self, _: &str) -> Result<()> {
            Ok(())
        }
        async fn list(&self) -> Result<Vec<Sandbox>> {
            Ok(Vec::new())
        }
        async fn exists(&self, _: &str) -> bool {
            true
        }
    }

    fn charter(image: &str, caps: &[&str]) -> Charter {
        Charter {
            host: Host {
                image: image.into(),
                ..Host::default()
            },
            capabilities: caps.iter().map(|s| (*s).to_owned()).collect(),
            ..Charter::default()
        }
    }

    #[test]
    fn infers_official_images() {
        let got = charter_capabilities(&charter("ghcr.io/runeeward/runeward-sandbox:latest", &[]));
        assert_eq!(got, ["python", "node", "browser"]);
        assert!(charter_capabilities(&charter("debian:stable-slim", &[])).is_empty());
        assert!(charter_capabilities(&charter("runeward-ide:latest", &[])).is_empty());
        assert_eq!(
            charter_capabilities(&charter("custom:1", &[" Node ", "python", "node", "gpu"])),
            ["node", "python"]
        );
    }

    #[tokio::test]
    async fn verification_and_discovery() {
        let missing = FakeBackend {
            result: ExecResult {
                exit_code: 127,
                ..ExecResult::default()
            },
            ..FakeBackend::default()
        };
        let mut c = charter("custom:1", &["python"]);
        let err = verify_runtime_capabilities(&missing, "fake-1", &mut c)
            .await
            .expect_err("missing runtime");
        assert!(err.to_string().contains("does not provide"), "{err}");

        let discovered = FakeBackend {
            result: ExecResult {
                exit_code: 0,
                stdout: "python\nnode\n".into(),
                ..ExecResult::default()
            },
            ..FakeBackend::default()
        };
        let mut c = charter("custom:1", &[]);
        verify_runtime_capabilities(&discovered, "fake-1", &mut c)
            .await
            .expect("discovery");
        assert_eq!(c.capabilities, ["python", "node"]);
        let calls = discovered.calls.lock().expect("calls");
        assert_eq!(calls[0][..2], ["sh", "-c"]);
    }
}
