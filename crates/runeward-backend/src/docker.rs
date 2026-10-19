//! Docker and Podman backends, driven through their CLIs.
//!
//! The CLI contract is more stable across engine versions than the API, and
//! Podman accepts the same flags. One container (plus a named workspace
//! volume) is created per sandbox.

use std::collections::HashMap;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use chrono::Utc;
use runeward_charter::{File, Network};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::process::Command;

use crate::backend::{Backend, Reachable};
use crate::config::BackendConfig;
use crate::egress::{HostProxy, policy_from_network, policy_json, proxy_env};
use crate::error::{BackendError, Result};
use crate::isolation::{IsolationTier, classify_runtime};
use crate::pathutil::{self, expand_home};
use crate::seed::{self, filtered_file_stream, join_producer, seed_tar_stream};
use crate::streams::{drain, drain_shared, exit_string, shared, tar_in_error};
use crate::types::{
    ExecRequest, ExecResult, PtyStream, Sandbox, SnapshotRef, Spec, default_command, default_shell,
};
use crate::validate::{validate_file_mode, validate_projection_path, validate_seed_dir};
use crate::{
    LABEL_ID, LABEL_MANAGED, LABEL_PROFILE, LABEL_VOLUME, container_name, random_hex, volume_name,
};

/// A Docker- or Podman-backed container backend.
#[derive(Debug)]
pub struct Docker {
    runtime: String,
    bin: PathBuf,
    snap_dir: PathBuf,
    config: BackendConfig,
    default_runtime: String,
    state: Mutex<DockerState>,
}

#[derive(Debug, Default)]
struct DockerState {
    proxies: HashMap<String, HostProxy>,
    /// Sandbox id -> strict-egress sidecar container name.
    egress_ctr: HashMap<String, String>,
}

impl Docker {
    /// A Docker backend using `docker` from `PATH`. Fails fast when the CLI
    /// is missing or the engine is unreachable.
    pub async fn docker(config: BackendConfig) -> Result<Self> {
        Self::with_runtime("docker", config).await
    }

    /// A Podman backend using `podman` from `PATH`.
    pub async fn podman(config: BackendConfig) -> Result<Self> {
        Self::with_runtime("podman", config).await
    }

    /// A backend for `runtime` (`docker` or `podman`) resolved from `PATH`.
    pub async fn with_runtime(runtime: &str, config: BackendConfig) -> Result<Self> {
        let bin = crate::factory::look_path(runtime).ok_or_else(|| {
            BackendError::msg(format!(
                "{runtime} CLI not found in PATH (install {runtime} and add it to your PATH): executable file not found in $PATH"
            ))
        })?;
        Self::with_cli(runtime, bin, config).await
    }

    /// A backend driving the CLI at `bin` with `runtime`'s dialect.
    ///
    /// Probes the engine (`version`), then runs the isolation self-check:
    /// the engine's default OCI runtime decides the tier of sandboxes that
    /// do not pick a runtime.
    pub async fn with_cli(runtime: &str, bin: PathBuf, config: BackendConfig) -> Result<Self> {
        let probe = Command::new(&bin)
            .args(["version", "--format", "{{.Server.Version}}"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .output();
        let detail = match tokio::time::timeout(Duration::from_secs(5), probe).await {
            Ok(Ok(out)) if out.status.success() => None,
            Ok(Ok(out)) => {
                let stderr = String::from_utf8_lossy(&out.stderr).trim().to_owned();
                Some(if stderr.is_empty() {
                    exit_string(out.status)
                } else {
                    stderr
                })
            }
            Ok(Err(e)) => Some(e.to_string()),
            Err(_) => Some("signal: killed".to_owned()),
        };
        if let Some(detail) = detail {
            return Err(BackendError::msg(format!(
                "{runtime} engine not reachable; is {runtime} running? ({detail})"
            )));
        }
        let snap_dir = pathutil::snapshot_dir();
        std::fs::create_dir_all(&snap_dir)
            .map_err(|e| BackendError::io("create snapshot dir", e))?;
        let mut d = Self {
            runtime: runtime.to_owned(),
            bin,
            snap_dir,
            config,
            default_runtime: String::new(),
            state: Mutex::new(DockerState::default()),
        };
        d.default_runtime = d.detect_default_runtime().await;
        Ok(d)
    }

    /// The engine's default OCI runtime as reported at startup (empty when
    /// the engine did not say).
    pub fn default_runtime(&self) -> &str {
        &self.default_runtime
    }

    async fn detect_default_runtime(&self) -> String {
        let format = if self.runtime == "podman" {
            "{{.Host.OCIRuntime.Name}}"
        } else {
            "{{.DefaultRuntime}}"
        };
        match self.output(&["info", "--format", format]).await {
            Ok(out) => out.trim().to_owned(),
            Err(e) => {
                tracing::debug!(target: "runeward_backend", "isolation self-check failed: {e}");
                String::new()
            }
        }
    }

    /// The tier a sandbox gets with `runtime_class` (empty = engine default).
    fn tier_for(&self, runtime_class: &str) -> IsolationTier {
        if runtime_class.is_empty() {
            classify_runtime(&self.default_runtime)
        } else {
            classify_runtime(runtime_class)
        }
    }

    fn host_gateway_name(&self) -> &'static str {
        if self.name() == "podman" {
            "host.containers.internal"
        } else {
            "host.docker.internal"
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, DockerState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn command<S: AsRef<OsStr>>(&self, args: &[S]) -> Command {
        let mut c = Command::new(&self.bin);
        c.args(args).stdin(Stdio::null()).kill_on_drop(true);
        c
    }

    /// Runs the CLI and returns stdout; a non-zero exit is an error carrying
    /// stderr.
    async fn output<S: AsRef<OsStr>>(&self, args: &[S]) -> Result<String> {
        let first = args
            .first()
            .map(|a| a.as_ref().to_string_lossy().into_owned())
            .unwrap_or_default();
        let out = self
            .command(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .map_err(|e| BackendError::msg(format!("{} {first}: {e}", self.name())))?;
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        if !out.status.success() {
            return Err(BackendError::msg(format!(
                "{} {first}: {}: {}",
                self.name(),
                exit_string(out.status),
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        Ok(stdout)
    }

    async fn run<S: AsRef<OsStr>>(&self, args: &[S]) -> Result<()> {
        self.output(args).await.map(drop)
    }

    /// Best-effort cleanup call whose failure is ignored.
    async fn cleanup(&self, args: &[&str]) {
        let _ = self.run(args).await;
    }

    async fn wait_running(&self, name: &str) -> Result<()> {
        // Require the process to stay alive across several observations, to
        // catch entrypoints that start and then fail immediately.
        for _ in 0..3 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            let out = self
                .output(&["inspect", "--format", "{{.State.Running}}", name])
                .await?;
            let last = out.trim();
            if last != "true" {
                return Err(BackendError::msg(format!(
                    "runtime reported running={last:?}"
                )));
            }
        }
        Ok(())
    }

    async fn workdir(&self, id: &str) -> Result<String> {
        let out = self
            .output(&[
                "inspect",
                "-f",
                "{{.Config.WorkingDir}}",
                &container_name(id),
            ])
            .await?;
        let wd = out.trim();
        Ok(if wd.is_empty() { "/workspace" } else { wd }.to_owned())
    }

    async fn volume_of(&self, id: &str) -> Result<String> {
        let format = format!("{{{{index .Config.Labels {LABEL_VOLUME:?}}}}}");
        let out = self
            .output(&["inspect", "-f", &format, &container_name(id)])
            .await?;
        Ok(out.trim().to_owned())
    }

    /// Launches the strict-egress sidecar: it installs iptables REDIRECT
    /// rules (NET_ADMIN), drops to the exempt uid and serves the transparent
    /// proxy; the sandbox then joins its network namespace.
    async fn start_egress_container(&self, id: &str, net: &Network) -> Result<String> {
        let name = egress_container_name(id);
        let args = egress_run_args(id, &policy_json(net)?, &self.config);
        self.run(&args)
            .await
            .map_err(|e| BackendError::msg(format!("start transparent egress sidecar: {e}")))?;
        if let Err(e) = self.wait_egress_ready(&name).await {
            self.cleanup(&["rm", "-f", &name]).await;
            return Err(e);
        }
        Ok(name)
    }

    /// Waits until the sidecar's transparent proxy listens (only after the
    /// iptables rules are installed), closing the window where a sandbox
    /// could egress before enforcement is in place.
    async fn wait_egress_ready(&self, name: &str) -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline {
            let logs = self.output(&["logs", name]).await.unwrap_or_default();
            if logs.contains("transparent proxy listening") {
                return Ok(());
            }
            if let Ok(st) = self
                .output(&["inspect", "-f", "{{.State.Running}}", name])
                .await
                && st.trim() == "false"
            {
                return Err(BackendError::msg(format!(
                    "egress sidecar exited before it was ready: {}",
                    logs.trim()
                )));
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        Err(BackendError::Timeout(
            "timed out waiting for transparent egress proxy to become ready".into(),
        ))
    }

    /// Streams `src_dir` as a sanitized tar into `tar -x` in the container.
    async fn seed_workspace(&self, id: &str, workdir: &str, src_dir: &Path) -> Result<()> {
        check_seed_dir(src_dir, &self.config)?;
        let (stream, producer) = seed_tar_stream(src_dir.to_path_buf());
        let args = [
            "exec",
            "-i",
            &container_name(id),
            "tar",
            "-C",
            workdir,
            "-xf",
            "-",
        ];
        let (status, stderr) = self.run_with_stdin(&args, stream).await;
        let produced = join_producer(producer).await;
        match tar_in_error(status, produced, &stderr) {
            None => Ok(()),
            Some(e) => Err(BackendError::msg(format!(
                "seed workspace from {:?}: {e}",
                src_dir.display().to_string()
            ))),
        }
    }

    /// Runs the CLI with `input` piped to stdin; returns the exit status and
    /// captured stderr.
    async fn run_with_stdin<S: AsRef<OsStr>>(
        &self,
        args: &[S],
        input: impl AsyncRead + Unpin,
    ) -> (std::io::Result<ExitStatus>, String) {
        let mut child = match self
            .command(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(c) => c,
            Err(e) => return (Err(e), String::new()),
        };
        let stdin = child.stdin.take();
        let stderr = child.stderr.take();
        let feed = async {
            match stdin {
                // A write error means tar exited early; its status says why.
                Some(w) => seed::pump(input, w).await.map(drop),
                None => Ok(()),
            }
        };
        let collect = async {
            let mut buf = Vec::new();
            if let Some(mut r) = stderr {
                let _ = r.read_to_end(&mut buf).await;
            }
            buf
        };
        let (fed, errbuf, status) = tokio::join!(feed, collect, child.wait());
        let stderr = String::from_utf8_lossy(&errbuf).into_owned();
        match (status, fed) {
            (Ok(st), Err(e)) if st.success() => (Err(e), stderr),
            (status, _) => (status, stderr),
        }
    }

    /// Runs `exec ... tar -cf - .` with stdout streamed to `w`.
    async fn tar_out(
        &self,
        id: &str,
        workdir: &str,
        w: &mut (dyn AsyncWrite + Send + Unpin),
    ) -> std::result::Result<(), String> {
        let args = [
            "exec",
            &container_name(id),
            "tar",
            "-C",
            workdir,
            "-cf",
            "-",
            ".",
        ];
        let mut child = self
            .command(&args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| e.to_string())?;
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        let copy = async {
            match stdout {
                Some(mut r) => tokio::io::copy(&mut r, w).await.map(drop),
                None => Ok(()),
            }
        };
        let collect = async {
            let mut buf = Vec::new();
            if let Some(mut r) = stderr {
                let _ = r.read_to_end(&mut buf).await;
            }
            buf
        };
        let (copied, errbuf, status) = tokio::join!(copy, collect, child.wait());
        let errs = String::from_utf8_lossy(&errbuf).trim().to_owned();
        let status = status.map_err(|e| e.to_string())?;
        if !status.success() {
            return Err(format!("{}: {errs}", exit_string(status)));
        }
        copied.map_err(|e| format!("{e}: {errs}"))?;
        w.flush().await.map_err(|e| e.to_string())
    }

    async fn attach_tty(&self, args: Vec<String>, s: PtyStream) -> Result<()> {
        #[cfg(unix)]
        {
            pty_attach(&self.bin, args, s).await
        }
        #[cfg(not(unix))]
        {
            let _ = (args, s);
            Err(BackendError::Unsupported(
                "TTY attach requires a Unix host".into(),
            ))
        }
    }
}

#[async_trait]
impl Backend for Docker {
    fn name(&self) -> &str {
        if self.runtime.is_empty() {
            "docker"
        } else {
            &self.runtime
        }
    }

    fn isolation_tier(&self) -> IsolationTier {
        self.tier_for("")
    }

    async fn create(&self, spec: Spec) -> Result<Sandbox> {
        let id = random_hex();
        let name = container_name(&id);
        let vol = volume_name(&id);

        self.run(&[
            "volume",
            "create",
            "--label",
            &kv(LABEL_MANAGED, "true"),
            "--label",
            &kv(LABEL_ID, &id),
            &vol,
        ])
        .await
        .map_err(|e| BackendError::msg(format!("create workspace volume: {e}")))?;

        let workdir = if spec.workdir.is_empty() {
            "/workspace".to_owned()
        } else {
            spec.workdir.clone()
        };

        let mut host_proxy: Option<HostProxy> = None;
        let mut egress_env = Vec::new();
        let mut egress_ctr: Option<String> = None;
        if spec.network.deny_by_default() {
            if spec.network.strict_egress() {
                // Transparent L3 enforcement: all TCP is forced through the
                // sidecar's proxy regardless of proxy env vars.
                match self.start_egress_container(&id, &spec.network).await {
                    Ok(n) => egress_ctr = Some(n),
                    Err(e) => {
                        self.cleanup(&["volume", "rm", "-f", &vol]).await;
                        return Err(e);
                    }
                }
            } else {
                // Cooperative mode: hostname policy through HTTP(S)_PROXY;
                // non-proxy protocols are not policed.
                match HostProxy::start(policy_from_network(&spec.network), &id).await {
                    Ok(p) => {
                        egress_env = proxy_env(&p.url(self.host_gateway_name()));
                        host_proxy = Some(p);
                    }
                    Err(e) => {
                        self.cleanup(&["volume", "rm", "-f", &vol]).await;
                        return Err(BackendError::msg(format!("start egress proxy: {e}")));
                    }
                }
            }
        }

        let plan = RunPlan {
            runtime: self.name(),
            id: &id,
            workdir: &workdir,
            egress_container: egress_ctr.as_deref(),
            cooperative: host_proxy.is_some(),
            egress_env: &egress_env,
        };
        let args = docker_run_args(&plan, &spec, &self.config);
        let image = run_image(&spec);

        if let Err(e) = self.run(&args).await {
            drop(host_proxy);
            if let Some(n) = &egress_ctr {
                self.cleanup(&["rm", "-f", n]).await;
            }
            self.cleanup(&["volume", "rm", "-f", &vol]).await;
            if !spec.runtime_class.is_empty() {
                return Err(BackendError::msg(format!(
                    "run container with runtime {:?}: is it registered with the docker engine? (see docs/security-model.md): {e}",
                    spec.runtime_class
                )));
            }
            return Err(BackendError::msg(format!("run container: {e}")));
        }

        // A detached run can succeed even when its process exits at once.
        if let Err(e) = self.wait_running(&name).await {
            let logs = self
                .output(&["logs", "--tail", "50", &name])
                .await
                .unwrap_or_default();
            self.cleanup(&["rm", "-f", &name]).await;
            drop(host_proxy);
            if let Some(n) = &egress_ctr {
                self.cleanup(&["rm", "-f", n]).await;
            }
            self.cleanup(&["volume", "rm", "-f", &vol]).await;
            let detail = logs.trim();
            if !detail.is_empty() {
                return Err(BackendError::msg(format!(
                    "container exited during startup: {e}: {detail}"
                )));
            }
            return Err(BackendError::msg(format!(
                "container exited during startup: {e}"
            )));
        }

        {
            let mut st = self.lock();
            if let Some(p) = host_proxy {
                st.proxies.insert(id.clone(), p);
            }
            if let Some(n) = egress_ctr {
                st.egress_ctr.insert(id.clone(), n);
            }
        }

        if let Some(src) = &spec.seed_dir
            && let Err(e) = self.seed_workspace(&id, &workdir, src).await
        {
            let _ = self.kill(&id).await;
            return Err(e);
        }
        if !spec.files.is_empty()
            && let Err(e) = self.copy_files(&id, &spec.files).await
        {
            let _ = self.kill(&id).await;
            return Err(e);
        }

        Ok(Sandbox {
            id,
            profile: spec.profile.clone(),
            backend: self.name().to_owned(),
            image,
            status: "running".into(),
            created_at: Utc::now(),
            endpoint: String::new(),
            isolation: self.tier_for(&spec.runtime_class),
        })
    }

    async fn exec(&self, id: &str, req: ExecRequest) -> Result<ExecResult> {
        let args = docker_exec_args(id, &req);
        let start = Instant::now();
        let mut child = self
            .command(&args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| BackendError::msg(format!("{} exec: {e}", self.name())))?;
        let ExecRequest {
            timeout,
            stdout: mut out_stream,
            stderr: mut err_stream,
            stream_only,
            ..
        } = req;
        let mut out_buf = Vec::new();
        let mut err_buf = Vec::new();
        let out_r = child.stdout.take();
        let err_r = child.stderr.take();
        let drains = async {
            tokio::join!(
                drain(
                    out_r,
                    (!stream_only).then_some(&mut out_buf),
                    out_stream.as_mut()
                ),
                drain(
                    err_r,
                    (!stream_only).then_some(&mut err_buf),
                    err_stream.as_mut()
                ),
            )
        };
        let waiter = async {
            let deadline = async {
                match timeout {
                    Some(t) if !t.is_zero() => tokio::time::sleep(t).await,
                    _ => std::future::pending().await,
                }
            };
            tokio::select! {
                st = child.wait() => st.map(Some),
                () = deadline => {
                    let _ = child.kill().await;
                    Ok(None)
                }
            }
        };
        let (_, status) = tokio::join!(drains, waiter);
        let status = status.map_err(|e| BackendError::msg(format!("{} exec: {e}", self.name())))?;
        Ok(ExecResult {
            // A timeout kills the CLI; like Go's ExitError this reports -1.
            exit_code: status.and_then(|s| s.code()).unwrap_or(-1),
            stdout: String::from_utf8_lossy(&out_buf).into_owned(),
            stderr: String::from_utf8_lossy(&err_buf).into_owned(),
            duration: start.elapsed(),
        })
    }

    async fn attach_pty(&self, id: &str, s: PtyStream) -> Result<()> {
        let args = docker_attach_args(id, s.tty, &s.command);
        if s.tty {
            return self.attach_tty(args, s).await;
        }
        let PtyStream {
            stdin,
            stdout,
            stderr,
            ..
        } = s;
        let mut child = self
            .command(&args)
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| BackendError::msg(format!("{} exec: {e}", self.name())))?;
        let child_in = child.stdin.take();
        let out_r = child.stdout.take();
        let err_r = child.stderr.take();
        let feed = async move {
            if let (Some(input), Some(w)) = (stdin, child_in) {
                let _ = seed::pump(input, w).await;
            }
        };
        // Without a separate stderr writer, stderr shares stdout's.
        let (out_w, err_w) = match (stdout, stderr) {
            (Some(o), Some(e)) => (Some(shared(o)), Some(shared(e))),
            (Some(o), None) => {
                let o = shared(o);
                (Some(o.clone()), Some(o))
            }
            (None, e) => (None, e.map(shared)),
        };
        let (_, _, _, status) = tokio::join!(
            feed,
            drain_shared(out_r, out_w),
            drain_shared(err_r, err_w),
            child.wait()
        );
        let status = status.map_err(|e| BackendError::msg(format!("{} exec: {e}", self.name())))?;
        if status.success() {
            Ok(())
        } else {
            Err(BackendError::msg(exit_string(status)))
        }
    }

    async fn copy_files(&self, id: &str, files: &[File]) -> Result<()> {
        let name = container_name(id);
        let mut workdir: Option<String> = None;
        for f in files {
            validate_projection_path(&f.path, self.config.confine_files())?;
            validate_file_mode(&f.mode)?;
            let Some(data) = projected_data(f)? else {
                continue;
            };
            // A relative target lives under the workspace. Resolve it here:
            // `docker exec` starts in the workdir, but anything addressed by
            // path must not depend on that.
            let target = if f.path.starts_with('/') {
                pathutil::clean(&f.path)
            } else {
                let wd = match &workdir {
                    Some(wd) => wd.clone(),
                    None => {
                        let wd = self.workdir(id).await?;
                        workdir = Some(wd.clone());
                        wd
                    }
                };
                pathutil::clean(&format!("{wd}/{}", f.path))
            };
            let (dir, base) = split_target(&target);
            if dir != "/" {
                self.cleanup(&["exec", &name, "mkdir", "-p", &dir]).await;
            }
            // Stream a one-entry tar into `tar -x` running as the sandbox
            // user: the file lands owned by that user at the requested mode
            // without chmod/chown, which fail under --cap-drop ALL (and
            // `docker cp` would keep the host owner).
            let archive = projection_tar(&base, &data, projection_mode(&f.mode))
                .map_err(|e| BackendError::io("build projection archive", e))?;
            let args = [
                "exec",
                "-i",
                &name,
                "tar",
                "--no-same-owner",
                "-p",
                "-C",
                &dir,
                "-xf",
                "-",
            ];
            let (status, stderr) = self
                .run_with_stdin(&args, std::io::Cursor::new(archive))
                .await;
            if let Some(e) = tar_in_error(status, Ok(()), &stderr) {
                return Err(BackendError::msg(format!(
                    "copy file {:?} into sandbox: {e}",
                    f.path
                )));
            }
        }
        Ok(())
    }

    async fn export_workspace(
        &self,
        id: &str,
        w: &mut (dyn AsyncWrite + Send + Unpin),
    ) -> Result<()> {
        let workdir = self.workdir(id).await?;
        self.tar_out(id, &workdir, w)
            .await
            .map_err(|e| BackendError::msg(format!("export workspace: {e}")))
    }

    async fn snapshot(&self, id: &str, name: &str) -> Result<SnapshotRef> {
        let workdir = self.workdir(id).await?;
        let snap_id = random_hex();
        let loc = self.snap_dir.join(format!("{snap_id}.tar"));
        let mut out = tokio::fs::File::create(&loc)
            .await
            .map_err(|e| BackendError::io("create snapshot", e))?;
        if let Err(e) = self.tar_out(id, &workdir, &mut out).await {
            drop(out);
            let _ = std::fs::remove_file(&loc);
            return Err(BackendError::msg(format!("snapshot tar: {e}")));
        }
        drop(out);
        let sum = match seed::hash_file(&loc) {
            Ok(s) => s,
            Err(e) => {
                let _ = std::fs::remove_file(&loc);
                return Err(BackendError::io("snapshot hash", e));
            }
        };
        Ok(SnapshotRef {
            id: snap_id,
            name: name.to_owned(),
            profile: String::new(),
            backend: self.name().to_owned(),
            location: loc.to_string_lossy().into_owned(),
            sha256: sum,
            created: Utc::now(),
        })
    }

    async fn restore(&self, snapshot: &SnapshotRef) -> Result<Sandbox> {
        let spec = Spec {
            profile: snapshot.profile.clone(),
            ..Spec::default()
        };
        self.restore_with_spec(snapshot, spec).await
    }

    async fn restore_with_spec(&self, snapshot: &SnapshotRef, mut spec: Spec) -> Result<Sandbox> {
        if spec.profile.is_empty() {
            spec.profile = snapshot.profile.clone();
        }
        let sb = self.create(spec).await?;
        let res = async {
            let workdir = self.workdir(&sb.id).await?;
            seed::verify_snapshot(snapshot)?;
            let loc = PathBuf::from(&snapshot.location);
            std::fs::metadata(&loc)
                .map_err(|e| BackendError::io(format!("open {}", loc.display()), e))?;
            // Sanitize the archive host-side to prevent tar-slip.
            let (stream, producer) = filtered_file_stream(loc);
            let name = container_name(&sb.id);
            let args = ["exec", "-i", &name, "tar", "-C", &workdir, "-xf", "-"];
            let (status, stderr) = self.run_with_stdin(&args, stream).await;
            let produced = join_producer(producer).await;
            match tar_in_error(status, produced, &stderr) {
                None => Ok(()),
                Some(e) => Err(BackendError::msg(format!("restore untar: {e}"))),
            }
        }
        .await;
        if let Err(e) = res {
            let _ = self.kill(&sb.id).await;
            return Err(e);
        }
        Ok(sb)
    }

    async fn kill(&self, id: &str) -> Result<()> {
        let (proxy, egress) = {
            let mut st = self.lock();
            (st.proxies.remove(id), st.egress_ctr.remove(id))
        };
        if let Some(p) = proxy {
            p.stop();
        }
        let vol = self.volume_of(id).await.unwrap_or_default();
        self.run(&["rm", "-f", &container_name(id)])
            .await
            .map_err(|e| BackendError::msg(format!("remove container: {e}")))?;
        // Remove the strict-egress sidecar once nothing shares its netns.
        if let Some(n) = egress {
            self.cleanup(&["rm", "-f", &n]).await;
        }
        if !vol.is_empty() {
            self.cleanup(&["volume", "rm", "-f", &vol]).await;
        }
        Ok(())
    }

    async fn list(&self) -> Result<Vec<Sandbox>> {
        let filter = format!("label={LABEL_MANAGED}=true");
        let out = self
            .output(&["ps", "-a", "--filter", &filter, "--format", "{{json .}}"])
            .await?;
        Ok(parse_ps(&out, self.name()))
    }

    async fn exists(&self, id: &str) -> bool {
        self.output(&["inspect", "-f", "{{.Id}}", &container_name(id)])
            .await
            .is_ok()
    }

    fn reachable(&self) -> Option<&dyn Reachable> {
        Some(self)
    }
}

#[async_trait]
impl Reachable for Docker {
    /// The sandbox's IP on its Docker network, or its egress sidecar's when
    /// the sandbox shares that network namespace.
    async fn container_ip(&self, id: &str) -> Result<String> {
        let target = self
            .lock()
            .egress_ctr
            .get(id)
            .filter(|n| !n.is_empty())
            .cloned()
            .unwrap_or_else(|| container_name(id));
        let wrap = |e: BackendError| BackendError::msg(format!("inspect container IP: {e}"));
        let out = self
            .output(&[
                "inspect",
                "-f",
                "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
                &target,
            ])
            .await
            .map_err(wrap)?;
        let mut ip = out.trim().to_owned();
        if ip.is_empty() {
            ip = self
                .output(&["inspect", "-f", "{{.NetworkSettings.IPAddress}}", &target])
                .await
                .map_err(wrap)?
                .trim()
                .to_owned();
        }
        if ip.is_empty() {
            return Err(BackendError::msg(format!(
                "container {target} has no network IP"
            )));
        }
        Ok(ip)
    }
}

/// Inputs to [`docker_run_args`] decided during create.
#[derive(Debug, Clone, Copy)]
pub(crate) struct RunPlan<'a> {
    pub(crate) runtime: &'a str,
    pub(crate) id: &'a str,
    pub(crate) workdir: &'a str,
    /// Strict-egress sidecar whose network namespace the sandbox joins.
    pub(crate) egress_container: Option<&'a str>,
    /// Cooperative egress through the in-process host proxy.
    pub(crate) cooperative: bool,
    pub(crate) egress_env: &'a [(String, String)],
}

/// The `run -d ...` argv for a sandbox container.
pub(crate) fn docker_run_args(plan: &RunPlan<'_>, spec: &Spec, cfg: &BackendConfig) -> Vec<String> {
    let id = plan.id;
    let vol = volume_name(id);
    let mut a: Vec<String> = vec![
        "run".into(),
        "-d".into(),
        "--name".into(),
        container_name(id),
        "--label".into(),
        kv(LABEL_MANAGED, "true"),
        "--label".into(),
        kv(LABEL_PROFILE, &spec.profile),
        "--label".into(),
        kv(LABEL_ID, id),
        "--label".into(),
        kv(LABEL_VOLUME, &vol),
        "-w".into(),
        plan.workdir.into(),
        "-v".into(),
        format!("{vol}:{}", plan.workdir),
    ];
    if let Some(ctr) = plan.egress_container {
        // Enforcement is transparent at L3: no proxy env, no host gateway.
        a.extend(["--network".into(), format!("container:{ctr}")]);
    }
    if plan.cooperative {
        if plan.runtime == "docker" {
            a.extend([
                "--add-host".into(),
                "host.docker.internal:host-gateway".into(),
            ]);
        }
        // Only HTTP(S) is proxied; stop IPv6 from bypassing it.
        a.extend(
            [
                "--sysctl",
                "net.ipv6.conf.all.disable_ipv6=1",
                "--sysctl",
                "net.ipv6.conf.default.disable_ipv6=1",
            ]
            .map(String::from),
        );
    }
    if !spec.runtime_class.is_empty() {
        a.extend(["--runtime".into(), spec.runtime_class.clone()]);
    }
    a.extend(["--cap-drop", "ALL", "--security-opt", "no-new-privileges"].map(String::from));
    if !spec.seccomp.is_empty() {
        a.extend(["--security-opt".into(), format!("seccomp={}", spec.seccomp)]);
    }
    if !spec.apparmor.is_empty() {
        a.extend([
            "--security-opt".into(),
            format!("apparmor={}", spec.apparmor),
        ]);
    }
    if spec.read_only {
        // Writable tmpfs /tmp; the workspace volume stays writable.
        a.extend(["--read-only", "--tmpfs", "/tmp:rw,exec,nosuid,size=512m"].map(String::from));
    }
    let pids = cfg.default_pids_limit();
    if pids > 0 {
        a.extend(["--pids-limit".into(), pids.to_string()]);
    }
    if !spec.user.is_empty() {
        a.extend(["-u".into(), spec.user.clone()]);
    }
    for (k, v) in &spec.env {
        a.extend(["-e".into(), format!("{k}={v}")]);
    }
    for (k, v) in plan.egress_env {
        a.extend(["-e".into(), format!("{k}={v}")]);
    }
    for (k, v) in &spec.labels {
        a.extend(["--label".into(), kv(k, v)]);
    }
    let mem = match spec.resources.memory_bytes {
        0 => cfg.default_memory_bytes(),
        m => m,
    };
    if mem > 0 {
        a.extend(["--memory".into(), mem.to_string()]);
    }
    let nano = match spec.resources.nano_cpus {
        0 => cfg.default_nano_cpus(),
        n => n,
    };
    if nano > 0 {
        a.extend(["--cpus".into(), format!("{:.3}", nano as f64 / 1e9)]);
    }
    let command = if spec.command.is_empty() {
        default_command()
    } else {
        spec.command.clone()
    };
    // Override the entrypoint so the Charter picks the real keep-alive
    // executable (needed for application images such as headless Chrome).
    let (entry, rest) = command
        .split_first()
        .map_or(("", &[][..]), |(e, r)| (e.as_str(), r));
    a.extend(["--entrypoint".into(), entry.into(), run_image(spec)]);
    a.extend(rest.iter().cloned());
    a
}

fn run_image(spec: &Spec) -> String {
    if spec.image.is_empty() {
        crate::config::DEFAULT_IMAGE.to_owned()
    } else {
        spec.image.clone()
    }
}

/// The `run -d ...` argv for the strict-egress sidecar.
pub(crate) fn egress_run_args(id: &str, policy_json: &str, cfg: &BackendConfig) -> Vec<String> {
    let mut a: Vec<String> = vec![
        "run".into(),
        "-d".into(),
        "--name".into(),
        egress_container_name(id),
        "--label".into(),
        kv(LABEL_MANAGED, "true"),
        "--label".into(),
        kv(LABEL_ID, id),
        "--cap-add".into(),
        "NET_ADMIN".into(),
        "--cap-add".into(),
        "NET_RAW".into(),
        "-e".into(),
        format!("RUNEWARD_EGRESS_POLICY={policy_json}"),
    ];
    let resolvers = cfg.dns_resolvers();
    if !resolvers.is_empty() {
        a.extend(["-e".into(), format!("RUNEWARD_DNS_RESOLVERS={resolvers}")]);
    }
    a.extend([
        cfg.egress_image(),
        "--setup-iptables".into(),
        "--transparent".into(),
        "--redirect-port".into(),
        runeward_egress::STRICT_REDIRECT_PORT.to_string(),
        "--proxy-uid".into(),
        runeward_egress::STRICT_PROXY_UID.to_string(),
    ]);
    a
}

/// The `exec ...` argv for a one-shot command.
pub(crate) fn docker_exec_args(id: &str, req: &ExecRequest) -> Vec<String> {
    let mut a = vec!["exec".to_owned()];
    if !req.workdir.is_empty() {
        a.extend(["-w".into(), req.workdir.clone()]);
    }
    for (k, v) in &req.env {
        a.extend(["-e".into(), format!("{k}={v}")]);
    }
    a.push(container_name(id));
    a.extend(req.command.iter().cloned());
    a
}

/// The `exec -i [-t] ...` argv for an interactive session.
pub(crate) fn docker_attach_args(id: &str, tty: bool, command: &[String]) -> Vec<String> {
    let mut a = vec!["exec".to_owned(), "-i".to_owned()];
    if tty {
        a.push("-t".into());
    }
    a.push(container_name(id));
    if command.is_empty() {
        a.extend(default_shell());
    } else {
        a.extend(command.iter().cloned());
    }
    a
}

/// Name of the strict-egress sidecar container for a sandbox.
pub fn egress_container_name(id: &str) -> String {
    format!("runeward-egress-{id}")
}

fn kv(k: &str, v: &str) -> String {
    format!("{k}={v}")
}

/// Rejects a seed source that is not an existing directory or falls outside
/// the `copy_from` allowlist.
pub(crate) fn check_seed_dir(src_dir: &Path, cfg: &BackendConfig) -> Result<()> {
    let src = src_dir.display().to_string();
    match std::fs::metadata(src_dir) {
        Ok(m) if m.is_dir() => {}
        Ok(_) => {
            return Err(BackendError::msg(format!(
                "copy_from {src:?} must be an existing directory: <nil>"
            )));
        }
        Err(e) => {
            return Err(BackendError::msg(format!(
                "copy_from {src:?} must be an existing directory: {e}"
            )));
        }
    }
    validate_seed_dir(src_dir, cfg.copy_from_roots())
}

/// The bytes a `[[file]]` projects, or `None` when it has no source.
pub(crate) fn projected_data(f: &File) -> Result<Option<Vec<u8>>> {
    if !f.content.is_empty() {
        return Ok(Some(f.content.clone().into_bytes()));
    }
    if !f.file.is_empty() {
        return std::fs::read(expand_home(&f.file))
            .map(Some)
            .map_err(|e| BackendError::io(format!("read projected file {:?}", f.file), e));
    }
    Ok(None)
}

/// The numeric mode a `[[file]]` lands with (`0444` when unset).
pub(crate) fn projection_mode(mode: &str) -> u32 {
    if mode.is_empty() {
        return 0o444;
    }
    u32::from_str_radix(mode, 8).map_or(0o444, |m| m & 0o7777)
}

/// Splits a clean absolute target into its parent directory and file name.
fn split_target(target: &str) -> (String, String) {
    let dir = pathutil::dir(target);
    let base = target.rsplit('/').next().unwrap_or(target).to_owned();
    (dir, base)
}

/// A tar holding one regular file `name` with `data` and `mode`, owned by
/// uid/gid 0 (the extracting user's ids apply with `--no-same-owner`).
pub(crate) fn projection_tar(name: &str, data: &[u8], mode: u32) -> std::io::Result<Vec<u8>> {
    let mut header = tar::Header::new_ustar();
    header.set_entry_type(tar::EntryType::Regular);
    header.set_path(name)?;
    header.set_size(data.len() as u64);
    header.set_mode(mode);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()),
    );
    header.set_cksum();
    let mut b = tar::Builder::new(Vec::new());
    b.append(&header, data)?;
    b.into_inner()
}

/// Parses `ps --format '{{json .}}'` lines into sandboxes.
fn parse_ps(out: &str, backend: &str) -> Vec<Sandbox> {
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct Row {
        #[serde(default)]
        labels: serde_json::Value,
        #[serde(default)]
        image: String,
        #[serde(default)]
        state: String,
    }
    out.trim()
        .lines()
        .filter(|l| !l.is_empty())
        .filter_map(|l| serde_json::from_str::<Row>(l).ok())
        .map(|row| {
            let labels = match &row.labels {
                serde_json::Value::String(s) => parse_labels(s),
                // Podman reports labels as an object.
                serde_json::Value::Object(m) => m
                    .iter()
                    .map(|(k, v)| (k.clone(), v.as_str().unwrap_or_default().to_owned()))
                    .collect(),
                _ => HashMap::new(),
            };
            Sandbox {
                id: labels.get(LABEL_ID).cloned().unwrap_or_default(),
                profile: labels.get(LABEL_PROFILE).cloned().unwrap_or_default(),
                backend: backend.to_owned(),
                image: row.image,
                status: row.state,
                ..Sandbox::default()
            }
        })
        .collect()
}

fn parse_labels(s: &str) -> HashMap<String, String> {
    s.split(',')
        .filter_map(|pair| pair.split_once('='))
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect()
}

/// Runs `bin args` on a fresh pseudo-terminal, wiring it to the stream.
/// Stdin EOF closes the terminal (ending the session), as in Go.
#[cfg(unix)]
async fn pty_attach(bin: &Path, args: Vec<String>, s: PtyStream) -> Result<()> {
    let PtyStream {
        stdin,
        stdout,
        mut resize,
        ..
    } = s;
    let (pty, pts) =
        pty_process::open().map_err(|e| BackendError::msg(format!("start pty: {e}")))?;
    let mut child = pty_process::Command::new(bin)
        .args(&args)
        .kill_on_drop(true)
        .spawn(pts)
        .map_err(|e| BackendError::msg(format!("start pty: {e}")))?;
    let (mut rd, mut wr) = pty.into_split();
    let (eof_tx, eof_rx) = tokio::sync::oneshot::channel::<()>();
    let has_stdin = stdin.is_some();
    let input = tokio::spawn(async move {
        let mut stdin = stdin;
        let mut buf = vec![0u8; 8 * 1024];
        loop {
            let read = async {
                match stdin.as_mut() {
                    Some(r) => r.read(&mut buf).await,
                    None => std::future::pending().await,
                }
            };
            let size = async {
                match resize.as_mut() {
                    Some(rx) => rx.recv().await,
                    None => std::future::pending().await,
                }
            };
            tokio::select! {
                n = read => match n {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if wr.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                },
                sz = size => match sz {
                    Some(sz) => {
                        let _ = wr.resize(pty_process::Size::new(sz.rows, sz.cols));
                    }
                    None => resize = None,
                },
            }
        }
        let _ = eof_tx.send(());
    });
    let stdin_closed = async move {
        if has_stdin && eof_rx.await.is_ok() {
            return;
        }
        std::future::pending::<()>().await;
    };
    let mut stdout = stdout;
    let output = async {
        let mut buf = vec![0u8; 32 * 1024];
        loop {
            match rd.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if let Some(w) = stdout.as_mut()
                        && (w.write_all(&buf[..n]).await.is_err() || w.flush().await.is_err())
                    {
                        stdout = None;
                    }
                }
            }
        }
    };
    tokio::select! {
        () = output => {}
        () = stdin_closed => {}
    }
    input.abort();
    let _ = input.await;
    drop(rd);
    let status = child
        .wait()
        .await
        .map_err(|e| BackendError::msg(format!("wait for pty session: {e}")))?;
    if status.success() {
        Ok(())
    } else {
        Err(BackendError::msg(exit_string(status)))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    fn plan<'a>(id: &'a str, env: &'a [(String, String)]) -> RunPlan<'a> {
        RunPlan {
            runtime: "docker",
            id,
            workdir: "/workspace",
            egress_container: None,
            cooperative: false,
            egress_env: env,
        }
    }

    #[test]
    fn projection_tar_is_one_root_owned_entry() {
        let raw = projection_tar("a.txt", b"hi", projection_mode("0640")).expect("tar");
        let mut ar = tar::Archive::new(raw.as_slice());
        let entries: Vec<_> = ar
            .entries()
            .expect("entries")
            .map(|e| {
                let e = e.expect("entry");
                let h = e.header();
                (
                    String::from_utf8_lossy(&e.path_bytes()).into_owned(),
                    h.mode().expect("mode"),
                    h.uid().expect("uid"),
                    h.gid().expect("gid"),
                    h.size().expect("size"),
                )
            })
            .collect();
        assert_eq!(entries, [("a.txt".to_owned(), 0o640, 0, 0, 2)]);
        assert_eq!(projection_mode(""), 0o444);
        assert_eq!(projection_mode("755"), 0o755);
        assert_eq!(
            split_target("/workspace/a/b.txt"),
            ("/workspace/a".into(), "b.txt".into())
        );
        assert_eq!(split_target("/x"), ("/".into(), "x".into()));
    }

    #[test]
    fn run_args_minimal() {
        let spec = Spec {
            profile: "demo".into(),
            labels: BTreeMap::from([(LABEL_PROFILE.into(), "demo".into())]),
            ..Spec::default()
        };
        let args = docker_run_args(&plan("x", &[]), &spec, &BackendConfig::default());
        let want = "run -d --name runeward-x --label runeward.managed=true --label runeward.profile=demo \
            --label runeward.id=x --label runeward.volume=runeward-vol-x -w /workspace \
            -v runeward-vol-x:/workspace --cap-drop ALL --security-opt no-new-privileges \
            --pids-limit 1024 --label runeward.profile=demo --memory 4294967296 --cpus 2.000 \
            --entrypoint sleep debian:stable-slim infinity";
        assert_eq!(
            args.join(" "),
            want.split_whitespace().collect::<Vec<_>>().join(" ")
        );
    }

    #[test]
    fn run_args_env_is_sorted_and_cpus_formatted() {
        let spec = Spec {
            env: BTreeMap::from([("B".into(), "2".into()), ("A".into(), "1".into())]),
            resources: crate::Resources {
                nano_cpus: 333_333_333,
                memory_bytes: 1,
            },
            ..Spec::default()
        };
        let args = docker_run_args(&plan("x", &[]), &spec, &BackendConfig::default());
        let joined = args.join(" ");
        assert!(joined.contains("-e A=1 -e B=2"), "{joined}");
        assert!(joined.contains("--memory 1 --cpus 0.333"), "{joined}");
    }

    #[test]
    fn exec_and_attach_args() {
        let req = ExecRequest {
            command: vec!["env".into()],
            workdir: "/tmp".into(),
            env: BTreeMap::from([("A".into(), "1".into())]),
            ..ExecRequest::default()
        };
        assert_eq!(
            docker_exec_args("x", &req),
            ["exec", "-w", "/tmp", "-e", "A=1", "runeward-x", "env"]
        );
        assert_eq!(
            docker_attach_args("x", true, &["bash".into()]),
            ["exec", "-i", "-t", "runeward-x", "bash"]
        );
        assert_eq!(docker_attach_args("x", false, &[]).len(), 6);
    }

    #[test]
    fn ps_parsing_handles_docker_and_podman() {
        let out = concat!(
            r#"{"Labels":"runeward.id=a,runeward.profile=p,runeward.managed=true","Image":"img","State":"running"}"#,
            "\n",
            r#"{"Labels":{"runeward.id":"b","runeward.profile":"q"},"Image":"img2","State":"exited"}"#,
            "\nnot json\n"
        );
        let sbs = parse_ps(out, "docker");
        assert_eq!(sbs.len(), 2);
        assert_eq!((sbs[0].id.as_str(), sbs[0].profile.as_str()), ("a", "p"));
        assert_eq!(
            (sbs[1].id.as_str(), sbs[1].status.as_str()),
            ("b", "exited")
        );
    }

    #[test]
    fn egress_args_include_resolvers_only_when_set() {
        let cfg = BackendConfig::default();
        let a = egress_run_args("x", "{}", &cfg);
        assert!(!a.iter().any(|s| s.starts_with("RUNEWARD_DNS_RESOLVERS")));
        assert_eq!(a[a.len() - 7], "runeward-egress:latest");
        let cfg = cfg.with(crate::config::DNS_RESOLVERS_ENV, " 9.9.9.9 ");
        let a = egress_run_args("x", "{}", &cfg);
        assert!(a.contains(&"RUNEWARD_DNS_RESOLVERS=9.9.9.9".to_owned()));
    }
}
