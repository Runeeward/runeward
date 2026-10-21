//! Docker and Podman backends, driven through their CLIs.
//!
//! The CLI contract is more stable across engine versions than the API, and
//! Podman accepts the same flags. One container (plus a named workspace
//! volume) is created per sandbox.
//!
//! A sandbox with a request broker or the in-sandbox supervisor is created
//! stopped (`create`), gets its files copied in (`cp`: the supervisor
//! documents into an anonymous volume at `/run/runeward`, the broker CA and
//! trust bundle into one at `/etc/runeward/ca`), and only then started, so
//! PID 1 and the agent never see a half-configured sandbox. The broker sits
//! in the in-process cooperative proxy, or is exported to the strict
//! sidecar as a root-only document whose decisions are read back from the
//! sidecar's stdout. See [`crate::incell`].

use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use chrono::Utc;
use runeward_charter::{File, KRUN_NO_EXEC, Network, RuntimeFamily};
use runeward_egress::Broker;
use runeward_egress::broker::DecisionLine;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::process::Command;
use tokio::task::JoinHandle;

use crate::backend::{Backend, Reachable};
use crate::config::BackendConfig;
use crate::egress::{HostProxy, policy_from_network, policy_json, proxy_env};
use crate::error::{BackendError, Result};
use crate::evidence::{self, Assessment};
use crate::incell::{
    BROKER_CA_DIR, LABEL_SUPERVISED, SUPERVISOR_BIN, SUPERVISOR_CAPS, SUPERVISOR_REPORT_PATH,
    SUPERVISOR_STATE_DIR, SYSTEM_ROOTS, SupervisorPlan, ca_bundle, ca_env, first_file_in_tar,
    root_tar, supervised_command,
};
use crate::isolation::{IsolationTier, classify_runtime};
use crate::pathutil::{self, expand_home};
use crate::seed::{self, filtered_file_stream, join_producer, seed_tar_stream};
#[cfg(unix)]
use crate::streams::merged_output;
use crate::streams::{drain, drain_shared, exit_string, shared, tar_in_error};
use crate::types::{
    ExecRequest, ExecResult, PtyStream, Sandbox, SnapshotRef, Spec, default_command, default_shell,
};
use crate::validate::{validate_file_mode, validate_projection_path, validate_seed_dir};
use crate::vmsize::{self, EngineCapacity, GuestSize};
use crate::{
    LABEL_ID, LABEL_MANAGED, LABEL_PROFILE, LABEL_VOLUME, container_name, random_hex,
    sandbox_id_for, volume_name,
};

/// Bounds the in-sandbox isolation probe.
const PROBE_TIMEOUT: Duration = Duration::from_secs(15);

/// Reports whether an engine whose kernel is `host_kernel` runs on this
/// machine: Linux with the same kernel release, so `/proc` shows its
/// processes.
fn engine_is_local(host_kernel: &str) -> bool {
    cfg!(target_os = "linux")
        && !host_kernel.is_empty()
        && std::fs::read_to_string("/proc/sys/kernel/osrelease")
            .is_ok_and(|k| k.trim() == host_kernel.trim())
}

/// Refuses a broker whose endpoints list `binaries` where this backend
/// cannot attribute connections: the broker must run in the strict-egress
/// sidecar, which shares the sandbox's network namespace (and so reaches the
/// supervisor's attribution socket and sees the same TCP sockets); the
/// sandbox must share the host kernel with that sidecar (a container
/// runtime, not gVisor or a VM, whose network stacks and sockets the
/// sidecar cannot see); and the supervisor must run.
fn check_binary_attribution(
    broker: &Broker,
    net: &Network,
    runtime: &str,
    supervised: bool,
) -> Result<()> {
    if !broker.restricts_binaries() {
        return Ok(());
    }
    let why = if !net.strict_egress() {
        "they need strict egress ([network] default = \"deny\", enforce = \"strict\"), so the broker shares the sandbox's network namespace".to_owned()
    } else if RuntimeFamily::of(runtime) != RuntimeFamily::Container {
        format!(
            "runtime {runtime:?} keeps the sandbox's sockets out of the egress sidecar's sight; use a container runtime (runc, crun) for binary-restricted endpoints"
        )
    } else if broker.attribution().is_none() || !supervised {
        "the in-sandbox supervisor must run to attribute connections".to_owned()
    } else {
        return Ok(());
    };
    Err(BackendError::Unsupported(format!(
        "endpoint binaries cannot be enforced here: {why}"
    )))
}

/// Refuses runtimes the Docker/Podman path cannot run: the sandbox's own
/// runtime, or the engine default when the Spec names none.
fn check_engine_runtime(runtime_class: &str) -> Result<()> {
    match RuntimeFamily::of(runtime_class) {
        RuntimeFamily::KataFirecracker | RuntimeFamily::Firecracker => {
            Err(BackendError::Unsupported(format!(
                "runtime {runtime_class:?} cannot run under Docker or Podman: Firecracker has no shared filesystem and no device hot-plug, so it needs containerd with the devmapper snapshotter (Kubernetes RuntimeClass kata-fc) or a native Firecracker driver; use kata-qemu or kata-clh here (see docs/isolation.md)"
            )))
        }
        RuntimeFamily::Krun => Err(BackendError::Unsupported(format!(
            "runtime {runtime_class:?} cannot run a Rune Box sandbox: {KRUN_NO_EXEC} (see docs/isolation.md)"
        ))),
        _ => Ok(()),
    }
}

/// What one `info` call reports about the engine.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct EngineInfo {
    default_runtime: String,
    host_kernel: String,
    os: String,
    capacity: EngineCapacity,
}

/// Splits the `info` line `runtime|kernel|os|memtotal|ncpu` (missing
/// fields are empty, unparseable numbers 0).
fn parse_engine_info(out: &str) -> EngineInfo {
    let line = out.lines().next().unwrap_or("").trim();
    let mut parts = line.splitn(5, '|').map(|p| {
        let p = p.trim();
        if p == "<no value>" { "" } else { p }.to_owned()
    });
    let mut field = || parts.next().unwrap_or_default();
    let (default_runtime, host_kernel, os) = (field(), field(), field());
    let memory_bytes = field().parse().unwrap_or(0);
    let cpus = field().parse().unwrap_or(0);
    EngineInfo {
        default_runtime,
        host_kernel,
        os,
        capacity: EngineCapacity { memory_bytes, cpus },
    }
}

/// Where the strict sidecar reads its broker document (root-only, removed
/// by the sidecar once read).
pub const SIDECAR_BROKER_CONFIG: &str = "/etc/runeward/broker.json";

/// A Docker- or Podman-backed container backend.
#[derive(Debug)]
pub struct Docker {
    runtime: String,
    bin: PathBuf,
    snap_dir: PathBuf,
    config: BackendConfig,
    default_runtime: String,
    /// The engine host's kernel release (`docker info` KernelVersion,
    /// `podman info` Host.Kernel); empty when unknown.
    host_kernel: String,
    /// The engine's operating system (`Docker Desktop`, `OrbStack`, a
    /// distribution name, ...).
    engine_os: String,
    /// The engine host's total memory and CPUs, read once at startup and
    /// used to size VM sandboxes (zero when unknown).
    capacity: EngineCapacity,
    state: Mutex<DockerState>,
}

#[derive(Debug, Default)]
struct DockerState {
    proxies: HashMap<String, HostProxy>,
    /// Sandbox id -> strict-egress sidecar container name.
    egress_ctr: HashMap<String, String>,
    /// Sandbox id -> agent identity for supervised sandboxes, `""` for
    /// sandboxes known to run without the supervisor.
    supervised: HashMap<String, String>,
    /// Sandboxes created here without anonymous volumes; every other
    /// container is removed with its anonymous volumes.
    plain: HashSet<String>,
    /// Sandbox id -> task feeding sidecar broker decisions back.
    tails: HashMap<String, JoinHandle<()>>,
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
    /// the engine's default OCI runtime is the claim for sandboxes that do
    /// not pick a runtime, and its kernel release is what in-sandbox
    /// evidence is compared with.
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
            host_kernel: String::new(),
            engine_os: String::new(),
            capacity: EngineCapacity::default(),
            state: Mutex::new(DockerState::default()),
        };
        let info = d.engine_info().await;
        d.default_runtime = info.default_runtime;
        d.host_kernel = info.host_kernel;
        d.engine_os = info.os;
        d.capacity = info.capacity;
        Ok(d)
    }

    /// The engine's default OCI runtime as reported at startup (empty when
    /// the engine did not say).
    pub fn default_runtime(&self) -> &str {
        &self.default_runtime
    }

    /// The engine's kernel release as reported at startup (empty when the
    /// engine did not say).
    pub fn host_kernel(&self) -> &str {
        &self.host_kernel
    }

    /// The default runtime, host kernel, operating system and capacity
    /// from one `info` call; empty fields when the engine did not say.
    async fn engine_info(&self) -> EngineInfo {
        let format = if self.runtime == "podman" {
            "{{.Host.OCIRuntime.Name}}|{{.Host.Kernel}}|{{.Host.Distribution.Distribution}}|{{.Host.MemTotal}}|{{.Host.CPUs}}"
        } else {
            "{{.DefaultRuntime}}|{{.KernelVersion}}|{{.OperatingSystem}}|{{.MemTotal}}|{{.NCPU}}"
        };
        match self.output(&["info", "--format", format]).await {
            Ok(out) => parse_engine_info(&out),
            Err(e) => {
                tracing::debug!(target: "runeward_backend", "isolation self-check failed: {e}");
                Default::default()
            }
        }
    }

    /// The runtime a sandbox with `runtime_class` runs under (empty = the
    /// engine default).
    fn runtime_for(&self, runtime_class: &str) -> String {
        if runtime_class.is_empty() {
            self.default_runtime.clone()
        } else {
            runtime_class.to_owned()
        }
    }

    /// The tier a sandbox with `runtime_class` claims before evidence.
    fn tier_for(&self, runtime_class: &str) -> IsolationTier {
        classify_runtime(&self.runtime_for(runtime_class))
    }

    /// Probes a running sandbox and derives its tier from the evidence.
    async fn assess_isolation(&self, id: &str, runtime_class: &str) -> Assessment {
        let runtime = self.runtime_for(runtime_class);
        let mut a = if self.config.isolation_probe() {
            let mut args = vec!["exec".to_owned()];
            args.extend(self.internal_exec_flags(id).await);
            args.push(container_name(id));
            args.extend(evidence::probe_command());
            let res = match tokio::time::timeout(PROBE_TIMEOUT, self.output(&args)).await {
                Ok(Ok(out)) => Ok(out),
                Ok(Err(e)) => Err(e.to_string()),
                Err(_) => Err("probe timed out".to_owned()),
            };
            evidence::assess(
                &runtime,
                &self.host_kernel,
                res.as_deref().map_err(String::as_str),
            )
        } else {
            evidence::assess_unprobed(&runtime, &self.host_kernel)
        };
        if a.tier == IsolationTier::Vm {
            let found = self.host_hypervisor(id).await;
            a.attach_host_hypervisor(found.as_deref());
        }
        a.log(self.name(), id);
        a
    }

    /// The hypervisor process running a VM sandbox, when the engine runs on
    /// this machine (Linux, same kernel) so its processes are visible.
    async fn host_hypervisor(&self, id: &str) -> Option<String> {
        if !engine_is_local(&self.host_kernel) {
            return None;
        }
        let full = self
            .output(&["inspect", "-f", "{{.Id}}", &container_name(id)])
            .await
            .ok()?;
        evidence::find_hypervisor(Path::new("/proc"), full.trim())
    }

    /// The engine host's total memory and CPUs as reported at startup
    /// (zero when the engine did not say).
    pub fn capacity(&self) -> (i64, i64) {
        (self.capacity.memory_bytes, self.capacity.cpus)
    }

    /// Refuses a VM sandbox whose guest cannot fit on the engine host.
    fn check_vm_size(&self, spec: &Spec) -> Result<()> {
        let runtime = self.runtime_for(&spec.runtime_class);
        vmsize::check_fits(
            &runtime,
            self.name(),
            &GuestSize::of(spec, &self.config),
            self.capacity,
        )
        .map_err(BackendError::Unsupported)
    }

    /// Names the likely causes when a VM sandbox fails to start with a
    /// known VM start failure.
    fn explain_vm_failure(&self, spec: &Spec, err: &BackendError) -> Option<String> {
        vmsize::explain_start_failure(
            &self.runtime_for(&spec.runtime_class),
            &err.to_string(),
            &GuestSize::of(spec, &self.config),
            self.capacity,
        )
    }

    /// A hint for a VM runtime that cannot start on a desktop engine.
    fn nested_vm_hint(&self, runtime_class: &str) -> String {
        let os = self.engine_os.as_str();
        let desktop = ["Docker Desktop", "OrbStack"]
            .iter()
            .any(|d| os.contains(d));
        if desktop && RuntimeFamily::of(runtime_class).needs_kvm() {
            format!(
                "; {os} runs containers inside a VM without nested virtualisation, so {runtime_class:?} cannot start there (use a Linux host with /dev/kvm)"
            )
        } else {
            String::new()
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
    /// proxy; the sandbox then joins its network namespace. With a broker,
    /// the sidecar is created stopped, gets the broker document as a
    /// root-only file, and its decision lines are fed back into `broker`.
    async fn start_egress_container(
        &self,
        id: &str,
        net: &Network,
        broker: Option<&Arc<Broker>>,
    ) -> Result<String> {
        let name = egress_container_name(id);
        let args = egress_run_args(id, &policy_json(net)?, &self.config, broker.is_some());
        if let Err(e) = self.run(&args).await {
            // A failed `run`/`create` can still leave the container behind
            // (created but never started).
            self.cleanup(&["rm", "-f", "-v", &name]).await;
            return Err(BackendError::msg(format!(
                "start transparent egress sidecar: {e}"
            )));
        }
        if let Some(b) = broker {
            let staged = async {
                let doc = b.sidecar_config().to_json();
                let archive = root_tar(
                    &["runeward"],
                    0o700,
                    &[("runeward/broker.json".into(), doc.to_vec(), 0o600)],
                )
                .map_err(|e| BackendError::io("build broker archive", e))?;
                self.copy_in(&name, "/etc", archive).await?;
                self.run(&["start", &name]).await
            }
            .await;
            if let Err(e) = staged {
                self.cleanup(&["rm", "-f", "-v", &name]).await;
                return Err(BackendError::msg(format!(
                    "start transparent egress sidecar: {e}"
                )));
            }
        }
        if let Err(e) = self.wait_egress_ready(&name).await {
            self.cleanup(&["rm", "-f", "-v", &name]).await;
            return Err(e);
        }
        if let Some(b) = broker {
            let task = self.tail_decisions(&name, id, Arc::clone(b));
            self.lock().tails.insert(id.to_owned(), task);
        }
        Ok(name)
    }

    /// Follows the sidecar's stdout and republishes its decision lines on
    /// the control plane's broker. Anything else on stdout is ignored.
    fn tail_decisions(&self, name: &str, id: &str, broker: Arc<Broker>) -> JoinHandle<()> {
        let mut cmd = self.command(&["logs", "-f", name]);
        cmd.stdout(Stdio::piped()).stderr(Stdio::null());
        let id = id.to_owned();
        tokio::spawn(async move {
            let Ok(mut child) = cmd.spawn() else {
                tracing::warn!(target: "runeward_backend", "egress sidecar decision stream for {id} could not start");
                return;
            };
            let Some(out) = child.stdout.take() else {
                return;
            };
            let mut lines = tokio::io::BufReader::new(out).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                if let Some(l) = DecisionLine::parse(&line)
                    && l.sandbox_id == id
                {
                    broker.publish(l.decision);
                }
            }
            let _ = child.wait().await;
        })
    }

    /// Extracts a tar into `dest` inside a (possibly stopped) container.
    async fn copy_in(&self, name: &str, dest: &str, archive: Vec<u8>) -> Result<()> {
        let target = format!("{name}:{dest}");
        let args = ["cp", "-", target.as_str()];
        let (status, stderr) = self
            .run_with_stdin(&args, std::io::Cursor::new(archive))
            .await;
        match tar_in_error(status, Ok(()), &stderr) {
            None => Ok(()),
            Some(e) => Err(BackendError::msg(format!("copy into {dest}: {e}"))),
        }
    }

    /// Reads one file out of a (possibly stopped) container, following
    /// symlinks; `None` when it is missing or unreadable.
    async fn copy_out(&self, name: &str, path: &str) -> Option<Vec<u8>> {
        let src = format!("{name}:{path}");
        let out = self
            .command(&["cp", "-L", src.as_str(), "-"])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .output()
            .await
            .ok()?;
        if !out.status.success() {
            return None;
        }
        first_file_in_tar(&out.stdout)
    }

    /// Whether `image` carries a runnable supervisor.
    async fn image_has_supervisor(&self, image: &str) -> bool {
        self.run(&[
            "run",
            "--rm",
            "--network",
            "none",
            "--cap-drop",
            "ALL",
            "--entrypoint",
            SUPERVISOR_BIN,
            image,
            "--version",
        ])
        .await
        .is_ok()
    }

    /// The image's configured `USER` (empty when unset or unknown).
    async fn image_user(&self, image: &str) -> String {
        self.output(&["image", "inspect", "--format", "{{.Config.User}}", image])
            .await
            .map(|s| s.trim().to_owned())
            .unwrap_or_default()
    }

    /// Resolves the supervisor plan for a create: `None` when the image
    /// lacks the supervisor and the Charter does not require it.
    async fn plan_supervisor(
        &self,
        image: &str,
        s: &crate::types::SupervisorSpec,
    ) -> Result<Option<SupervisorPlan>> {
        if !self.image_has_supervisor(image).await {
            if s.required {
                return Err(BackendError::Unsupported(format!(
                    "image {image:?} does not contain {SUPERVISOR_BIN}, which this Charter requires ([filesystem] landlock = \"required\" or [process]); build the image from deploy/Dockerfile.sandbox or copy the binary in"
                )));
            }
            tracing::warn!(target: "runeward_backend", "image {image:?} has no {SUPERVISOR_BIN}; running without in-sandbox confinement (best effort)");
            return Ok(None);
        }
        let user = if s.config.process.user.trim().is_empty() {
            self.image_user(image).await
        } else {
            String::new()
        };
        SupervisorPlan::new(s.config.clone(), &user).map(Some)
    }

    /// Copies the supervisor documents and the broker trust files into a
    /// created (not yet started) sandbox container.
    async fn stage_files(
        &self,
        name: &str,
        supervisor: Option<&SupervisorPlan>,
        broker: Option<&Arc<Broker>>,
    ) -> Result<()> {
        if let Some(plan) = supervisor {
            let archive = root_tar(&[], 0o700, &plan.files())
                .map_err(|e| BackendError::io("build supervisor archive", e))?;
            self.copy_in(name, SUPERVISOR_STATE_DIR, archive).await?;
        }
        if let Some(b) = broker {
            let mut roots = None;
            for path in SYSTEM_ROOTS {
                if let Some(data) = self.copy_out(name, path).await
                    && !data.is_empty()
                {
                    roots = Some(data);
                    break;
                }
            }
            let ca = b.ca_cert_pem();
            let files = vec![
                ("broker-ca.pem".to_owned(), ca.as_bytes().to_vec(), 0o644),
                (
                    "ca-bundle.pem".to_owned(),
                    ca_bundle(roots.as_deref(), ca),
                    0o644,
                ),
            ];
            let archive = root_tar(&[], 0o755, &files)
                .map_err(|e| BackendError::io("build CA archive", e))?;
            self.copy_in(name, BROKER_CA_DIR, archive).await?;
        }
        Ok(())
    }

    /// The agent identity of a supervised sandbox, `None` when it runs
    /// without the supervisor. Unknown ids (created by another process) are
    /// looked up once from the container label.
    async fn supervision(&self, id: &str) -> Option<String> {
        if let Some(u) = self.lock().supervised.get(id) {
            return (!u.is_empty()).then(|| u.clone());
        }
        let format = format!("{{{{index .Config.Labels {LABEL_SUPERVISED:?}}}}}");
        let user = self
            .output(&["inspect", "-f", &format, &container_name(id)])
            .await
            .ok()?
            .trim()
            .to_owned();
        let user = if user == "<no value>" {
            String::new()
        } else {
            user
        };
        self.lock().supervised.insert(id.to_owned(), user.clone());
        (!user.is_empty()).then_some(user)
    }

    /// `exec` flags for the control plane's own operations: as the agent
    /// identity in a supervised sandbox (never root, never confined).
    async fn internal_exec_flags(&self, id: &str) -> Vec<String> {
        match self.supervision(id).await {
            Some(u) => vec!["-u".into(), u],
            None => Vec::new(),
        }
    }

    /// Waits until the sidecar's transparent proxy listens (only after the
    /// iptables rules are installed), closing the window where a sandbox
    /// could egress before enforcement is in place.
    async fn wait_egress_ready(&self, name: &str) -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline {
            // With a broker the sidecar keeps stdout for decision lines and
            // logs to stderr, so look at both streams.
            let logs = match self
                .command(&["logs", name])
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .output()
                .await
            {
                Ok(o) => format!(
                    "{}{}",
                    String::from_utf8_lossy(&o.stdout),
                    String::from_utf8_lossy(&o.stderr)
                ),
                Err(_) => String::new(),
            };
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
        let mut args = vec!["exec".to_owned(), "-i".to_owned()];
        args.extend(self.internal_exec_flags(id).await);
        args.extend([&container_name(id), "tar", "-C", workdir, "-xf", "-"].map(|s| s.to_owned()));
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
        let mut args = vec!["exec".to_owned()];
        args.extend(self.internal_exec_flags(id).await);
        args.extend(
            [&container_name(id), "tar", "-C", workdir, "-cf", "-", "."].map(|s| s.to_owned()),
        );
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

impl Docker {
    /// Creates a sandbox, or with `reuse` rebuilds one around the existing
    /// workspace volume of `spec.id` (waking after a control-plane restart).
    /// A failed rebuild never removes the reused volume.
    async fn provision(&self, spec: Spec, reuse: bool) -> Result<Sandbox> {
        check_engine_runtime(&self.runtime_for(&spec.runtime_class))?;
        self.check_vm_size(&spec)?;
        if let Some(b) = &spec.broker {
            check_binary_attribution(
                &b.0,
                &spec.network,
                &self.runtime_for(&spec.runtime_class),
                spec.supervisor.is_some(),
            )?;
        }
        let id = sandbox_id_for(&spec)?;
        let name = container_name(&id);
        let vol = volume_name(&id);
        let image = run_image(&spec);
        let broker = spec.broker.as_ref().map(|b| Arc::clone(&b.0));
        let supervisor = match &spec.supervisor {
            Some(s) => self.plan_supervisor(&image, s).await?,
            None => None,
        };

        if reuse {
            self.run(&["volume", "inspect", &vol])
                .await
                .map_err(|e| BackendError::msg(format!("workspace volume is gone: {e}")))?;
        } else {
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
        }

        let workdir = if spec.workdir.is_empty() {
            "/workspace".to_owned()
        } else {
            spec.workdir.clone()
        };

        let mut host_proxy: Option<HostProxy> = None;
        let mut egress_env = Vec::new();
        let mut egress_ctr: Option<String> = None;
        // A broker needs the proxy in the path even under an open network
        // policy: it is what swaps placeholders for secrets.
        if spec.network.deny_by_default() || broker.is_some() {
            if spec.network.strict_egress() {
                // Transparent L3 enforcement: all TCP is forced through the
                // sidecar's proxy regardless of proxy env vars.
                match self
                    .start_egress_container(&id, &spec.network, broker.as_ref())
                    .await
                {
                    Ok(n) => egress_ctr = Some(n),
                    Err(e) => {
                        if !reuse {
                            self.cleanup(&["volume", "rm", "-f", &vol]).await;
                        }
                        return Err(e);
                    }
                }
            } else {
                // Cooperative mode: hostname policy through HTTP(S)_PROXY;
                // non-proxy protocols are not policed.
                match HostProxy::start(policy_from_network(&spec.network), &id, broker.clone())
                    .await
                {
                    Ok(p) => {
                        egress_env = proxy_env(&p.url(self.host_gateway_name()));
                        host_proxy = Some(p);
                    }
                    Err(e) => {
                        if !reuse {
                            self.cleanup(&["volume", "rm", "-f", &vol]).await;
                        }
                        return Err(BackendError::msg(format!("start egress proxy: {e}")));
                    }
                }
            }
        }
        if broker.is_some() {
            egress_env.extend(ca_env());
        }

        let staged = supervisor.is_some() || broker.is_some();
        let plan = RunPlan {
            runtime: self.name(),
            id: &id,
            workdir: &workdir,
            egress_container: egress_ctr.as_deref(),
            cooperative: host_proxy.is_some(),
            egress_env: &egress_env,
            supervisor: supervisor.as_ref(),
            broker_ca: broker.is_some(),
        };
        let args = docker_run_args(&plan, &spec, &self.config);

        // Undoes everything made so far: the container (a failed `run` or
        // `create` can leave it behind in the `Created` state, holding the
        // workspace volume), the sidecar, the proxy and, unless rebuilding
        // around a kept workspace, the volume. The container goes first so
        // nothing still references the volume when it is removed.
        let abort = |host_proxy: Option<HostProxy>| {
            let egress_ctr = egress_ctr.clone();
            let name = name.clone();
            let vol = vol.clone();
            let id = id.clone();
            async move {
                drop(host_proxy);
                self.cleanup(&["rm", "-f", "-v", &name]).await;
                if let Some(t) = self.lock().tails.remove(&id) {
                    t.abort();
                }
                if let Some(n) = &egress_ctr {
                    self.cleanup(&["rm", "-f", "-v", n]).await;
                }
                if !reuse {
                    self.cleanup(&["volume", "rm", "-f", &vol]).await;
                }
            }
        };

        if let Err(e) = self.run(&args).await {
            abort(host_proxy).await;
            if let Some(why) = self.explain_vm_failure(&spec, &e) {
                return Err(BackendError::msg(format!(
                    "run container: {why}{}",
                    self.nested_vm_hint(&self.runtime_for(&spec.runtime_class))
                )));
            }
            if !spec.runtime_class.is_empty() {
                return Err(BackendError::msg(format!(
                    "run container with runtime {:?}: is it registered with the docker engine? (see docs/isolation.md): {e}{}",
                    spec.runtime_class,
                    self.nested_vm_hint(&spec.runtime_class)
                )));
            }
            return Err(BackendError::msg(format!("run container: {e}")));
        }
        if staged {
            let started = async {
                self.stage_files(&name, supervisor.as_ref(), broker.as_ref())
                    .await?;
                self.run(&["start", &name]).await
            }
            .await;
            if let Err(e) = started {
                let logs = self
                    .output(&["logs", "--tail", "50", &name])
                    .await
                    .unwrap_or_default();
                abort(host_proxy).await;
                if let Some(why) = self.explain_vm_failure(&spec, &e) {
                    return Err(BackendError::msg(format!(
                        "start container: {why}{}",
                        self.nested_vm_hint(&self.runtime_for(&spec.runtime_class))
                    )));
                }
                let detail = logs.trim();
                return Err(BackendError::msg(if detail.is_empty() {
                    format!("start container: {e}")
                } else {
                    format!("start container: {e}: {detail}")
                }));
            }
        }

        // A detached run can succeed even when its process exits at once.
        if let Err(e) = self.wait_running(&name).await {
            let logs = self
                .output(&["logs", "--tail", "50", &name])
                .await
                .unwrap_or_default();
            abort(host_proxy).await;
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
            st.supervised.insert(
                id.clone(),
                supervisor
                    .as_ref()
                    .map(|p| p.agent_user.clone())
                    .unwrap_or_default(),
            );
            if !staged {
                st.plain.insert(id.clone());
            }
        }

        if let Some(plan) = &supervisor {
            // The workspace volume starts owned by whoever owned the image's
            // directory; hand it to the agent. Root holds CHOWN only until
            // the supervisor drops it.
            if let Err(e) = self
                .run(&[
                    "exec",
                    "-u",
                    "0",
                    &name,
                    "chown",
                    &plan.agent_user,
                    &workdir,
                ])
                .await
            {
                tracing::warn!(target: "runeward_backend", "hand workspace {workdir} to {}: {e}", plan.agent_user);
            }
        }

        // Evidence first, before the workspace is populated.
        let assessment = self.assess_isolation(&id, &spec.runtime_class).await;

        if let Some(src) = &spec.seed_dir
            && let Err(e) = self.seed_workspace(&id, &workdir, src).await
        {
            let _ = self.teardown(&id, !reuse).await;
            return Err(e);
        }
        if !spec.files.is_empty()
            && let Err(e) = self.copy_files(&id, &spec.files).await
        {
            let _ = self.teardown(&id, !reuse).await;
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
            isolation: assessment.tier,
            isolation_evidence: Some(assessment.evidence),
        })
    }

    /// Removes a sandbox's container, sidecar and host-side state; the
    /// workspace volume only with `remove_volume`.
    async fn teardown(&self, id: &str, remove_volume: bool) -> Result<()> {
        let (proxy, egress, tail, plain) = {
            let mut st = self.lock();
            st.supervised.remove(id);
            (
                st.proxies.remove(id),
                st.egress_ctr.remove(id),
                st.tails.remove(id),
                st.plain.remove(id),
            )
        };
        if let Some(p) = proxy {
            p.stop();
        }
        if let Some(t) = tail {
            t.abort();
        }
        // The label names the volume; when the container is already gone,
        // fall back to the name every sandbox volume is created with.
        let vol = if remove_volume {
            match self.volume_of(id).await {
                Ok(v) if !v.is_empty() => v,
                _ => volume_name(id),
            }
        } else {
            String::new()
        };
        // Anonymous volumes (supervisor state, broker CA) go with the
        // container; only sandboxes created here without them skip `-v`.
        let name = container_name(id);
        let rm: &[&str] = if plain {
            &["rm", "-f", &name]
        } else {
            &["rm", "-f", "-v", &name]
        };
        // Keep going when the container cannot be removed, so the sidecar
        // and volume are still attempted; the error is reported after.
        let removed = self
            .run(rm)
            .await
            .map_err(|e| BackendError::msg(format!("remove container: {e}")));
        // Remove the strict-egress sidecar once nothing shares its netns.
        if let Some(n) = egress {
            self.cleanup(&["rm", "-f", &n]).await;
        }
        if !vol.is_empty() {
            self.cleanup(&["volume", "rm", "-f", &vol]).await;
        }
        removed
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
        self.provision(spec, false).await
    }

    async fn exec(&self, id: &str, req: ExecRequest) -> Result<ExecResult> {
        let supervised = self.supervision(id).await.is_some();
        let args = docker_exec_args(id, &req, supervised);
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
        let supervised = self.supervision(id).await.is_some();
        let args = docker_attach_args(id, s.tty, &s.command, supervised);
        if s.tty {
            return self.attach_tty(args, s).await;
        }
        let PtyStream {
            stdin,
            stdout,
            stderr,
            ..
        } = s;
        let mut cmd = self.command(&args);
        cmd.stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        });
        // Without a separate stderr writer, stderr shares stdout's: on Unix
        // through one pipe, so the two keep the order they were written in.
        #[cfg(unix)]
        let merged = match (&stdout, &stderr) {
            (Some(_), None) => {
                let (out, err, r) = merged_output()
                    .map_err(|e| BackendError::msg(format!("{} exec: {e}", self.name())))?;
                cmd.stdout(out).stderr(err);
                Some(r)
            }
            _ => None,
        };
        #[cfg(not(unix))]
        let merged: Option<tokio::io::Empty> = None;
        if merged.is_none() {
            cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
        }
        let mut child = cmd
            .spawn()
            .map_err(|e| BackendError::msg(format!("{} exec: {e}", self.name())))?;
        // Close this process's copies of the merged pipe's write ends, so the
        // read end sees EOF when the child exits.
        drop(cmd);
        let child_in = child.stdin.take();
        let out_r: Option<Box<dyn AsyncRead + Unpin + Send>> = match merged {
            Some(r) => Some(Box::new(r)),
            None => child
                .stdout
                .take()
                .map(|r| Box::new(r) as Box<dyn AsyncRead + Unpin + Send>),
        };
        let err_r = child.stderr.take();
        let feed = async move {
            if let (Some(input), Some(w)) = (stdin, child_in) {
                let _ = seed::pump(input, w).await;
            }
        };
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
        let mut as_user: Option<Vec<String>> = None;
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
            let flags = match &as_user {
                Some(f) => f.clone(),
                None => {
                    let f = self.internal_exec_flags(id).await;
                    as_user = Some(f.clone());
                    f
                }
            };
            if dir != "/" {
                let mut mkdir = vec!["exec".to_owned()];
                mkdir.extend(flags.iter().cloned());
                mkdir.extend([name.clone(), "mkdir".into(), "-p".into(), dir.clone()]);
                let _ = self.run(&mkdir).await;
            }
            // Stream a one-entry tar into `tar -x` running as the sandbox
            // user: the file lands owned by that user at the requested mode
            // without chmod/chown, which fail under --cap-drop ALL (and
            // `docker cp` would keep the host owner).
            let archive = projection_tar(&base, &data, projection_mode(&f.mode))
                .map_err(|e| BackendError::io("build projection archive", e))?;
            let mut args = vec!["exec".to_owned(), "-i".to_owned()];
            args.extend(flags);
            args.extend(
                [
                    name.as_str(),
                    "tar",
                    "--no-same-owner",
                    "-p",
                    "-C",
                    &dir,
                    "-xf",
                    "-",
                ]
                .map(|s| s.to_owned()),
            );
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
            let mut args = vec!["exec".to_owned(), "-i".to_owned()];
            args.extend(self.internal_exec_flags(&sb.id).await);
            args.extend([name.as_str(), "tar", "-C", &workdir, "-xf", "-"].map(|s| s.to_owned()));
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
        self.teardown(id, true).await
    }

    fn supports_sleep(&self) -> bool {
        true
    }

    /// Stops the container and keeps it, its workspace volume and its
    /// anonymous volumes. The strict-egress sidecar and the cooperative
    /// proxy stay up, so a wake rejoins the same egress path.
    async fn stop(&self, id: &str) -> Result<()> {
        crate::validate_sandbox_id(id)?;
        self.run(&["stop", "-t", "10", &container_name(id)])
            .await
            .map_err(|e| BackendError::msg(format!("stop container: {e}")))
    }

    /// Restarts a container this backend stopped; after a control-plane
    /// restart (no runtime state for `id`) rebuilds the container around
    /// the kept workspace volume from `spec`.
    async fn start(&self, id: &str, mut spec: Spec) -> Result<Sandbox> {
        crate::validate_sandbox_id(id)?;
        spec.id = id.to_owned();
        let name = container_name(id);
        let known = self.lock().supervised.contains_key(id);
        if known {
            self.run(&["start", &name])
                .await
                .map_err(|e| BackendError::msg(format!("start container: {e}")))?;
            self.wait_running(&name).await?;
            // Re-probe rather than trust the runtime name: the engine may
            // have been reconfigured while the workspace slept.
            let assessment = self.assess_isolation(id, &spec.runtime_class).await;
            return Ok(Sandbox {
                id: id.to_owned(),
                profile: spec.profile.clone(),
                backend: self.name().to_owned(),
                image: run_image(&spec),
                status: "running".into(),
                created_at: Utc::now(),
                endpoint: String::new(),
                isolation: assessment.tier,
                isolation_evidence: Some(assessment.evidence),
            });
        }
        // The old container and sidecar were configured for a broker and
        // proxy that no longer exist; rebuild both around the volume.
        self.cleanup(&["rm", "-f", "-v", &name]).await;
        self.cleanup(&["rm", "-f", &egress_container_name(id)])
            .await;
        self.provision(spec, true).await
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

    async fn supervisor_report(&self, id: &str) -> Result<Option<String>> {
        if self.supervision(id).await.is_none() {
            return Ok(None);
        }
        let data = self
            .copy_out(&container_name(id), SUPERVISOR_REPORT_PATH)
            .await
            .unwrap_or_default();
        Ok(Some(String::from_utf8_lossy(&data).into_owned()))
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
    /// Runs the agent under the supervisor (PID 1).
    pub(crate) supervisor: Option<&'a SupervisorPlan>,
    /// Gives the sandbox a directory for the broker CA and trust bundle.
    pub(crate) broker_ca: bool,
}

impl RunPlan<'_> {
    /// Whether files must be copied in between create and start.
    fn staged(&self) -> bool {
        self.supervisor.is_some() || self.broker_ca
    }
}

/// The `run -d ...` argv for a sandbox container.
pub(crate) fn docker_run_args(plan: &RunPlan<'_>, spec: &Spec, cfg: &BackendConfig) -> Vec<String> {
    let id = plan.id;
    let vol = volume_name(id);
    // Staged sandboxes are created stopped, get their files, then start.
    let mut a: Vec<String> = if plan.staged() {
        vec!["create".into()]
    } else {
        vec!["run".into(), "-d".into()]
    };
    a.extend([
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
    ]);
    if let Some(sup) = plan.supervisor {
        a.extend(["-v".into(), SUPERVISOR_STATE_DIR.into()]);
        for (k, v) in crate::incell::supervised_labels(sup) {
            a.extend(["--label".into(), kv(&k, &v)]);
        }
    }
    if plan.broker_ca {
        a.extend(["-v".into(), BROKER_CA_DIR.into()]);
    }
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
    a.extend(["--cap-drop", "ALL"].map(String::from));
    if plan.supervisor.is_some() {
        // PID 1 starts as root with just enough to switch identity; the
        // supervisor clears every capability before the agent runs.
        for cap in SUPERVISOR_CAPS {
            a.extend(["--cap-add".into(), cap.into()]);
        }
    }
    a.extend(["--security-opt", "no-new-privileges"].map(String::from));
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
    if plan.supervisor.is_some() {
        // The agent identity lives in the supervisor config.
        a.extend(["-u".into(), "0:0".into()]);
    } else if !spec.user.is_empty() {
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
    let mem = cfg.sandbox_memory_bytes(spec.resources.memory_bytes);
    if mem > 0 {
        a.extend(["--memory".into(), mem.to_string()]);
    }
    let nano = cfg.sandbox_nano_cpus(spec.resources.nano_cpus);
    if nano > 0 {
        a.extend(["--cpus".into(), format!("{:.3}", nano as f64 / 1e9)]);
    }
    let command = if plan.supervisor.is_some() {
        // The agent command is in the supervisor config.
        let mut c = vec![SUPERVISOR_BIN.to_owned()];
        c.extend(SupervisorPlan::init_args());
        c
    } else if spec.command.is_empty() {
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
pub(crate) fn egress_run_args(
    id: &str,
    policy_json: &str,
    cfg: &BackendConfig,
    broker: bool,
) -> Vec<String> {
    // With a broker the sidecar is created stopped so its document can be
    // copied in before it starts.
    let mut a: Vec<String> = if broker {
        vec!["create".into()]
    } else {
        vec!["run".into(), "-d".into()]
    };
    a.extend([
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
        // The egress image runs as an unprivileged USER; the sidecar must
        // start as root to install the iptables rules, then drops to the
        // proxy uid itself.
        "-u".into(),
        "0:0".into(),
        "-e".into(),
        format!("RUNEWARD_EGRESS_POLICY={policy_json}"),
    ]);
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
    if broker {
        a.extend([
            "--broker-config".into(),
            SIDECAR_BROKER_CONFIG.into(),
            "--sandbox-id".into(),
            id.into(),
        ]);
    }
    a
}

/// The `exec ...` argv for a one-shot command; `supervised` runs it under
/// the supervisor's exec mode.
pub(crate) fn docker_exec_args(id: &str, req: &ExecRequest, supervised: bool) -> Vec<String> {
    let mut a = vec!["exec".to_owned()];
    if !req.workdir.is_empty() {
        a.extend(["-w".into(), req.workdir.clone()]);
    }
    for (k, v) in &req.env {
        a.extend(["-e".into(), format!("{k}={v}")]);
    }
    a.push(container_name(id));
    if supervised {
        a.extend(supervised_command(&req.command));
    } else {
        a.extend(req.command.iter().cloned());
    }
    a
}

/// The `exec -i [-t] ...` argv for an interactive session.
pub(crate) fn docker_attach_args(
    id: &str,
    tty: bool,
    command: &[String],
    supervised: bool,
) -> Vec<String> {
    let mut a = vec!["exec".to_owned(), "-i".to_owned()];
    if tty {
        a.push("-t".into());
    }
    a.push(container_name(id));
    let command = if command.is_empty() {
        default_shell()
    } else {
        command.to_vec()
    };
    if supervised {
        a.extend(supervised_command(&command));
    } else {
        a.extend(command);
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

    #[test]
    fn binary_attribution_needs_strict_egress_a_container_runtime_and_the_supervisor() {
        let ep = |binaries: &[&str]| runeward_charter::Endpoint {
            name: "gh".into(),
            host: "api.github.com".into(),
            binaries: binaries.iter().map(|s| (*s).to_owned()).collect(),
            ..runeward_charter::Endpoint::default()
        };
        let build = |binaries: &[&str]| {
            Broker::with_secret_values(
                "sb",
                vec![ep(binaries)],
                vec![],
                std::collections::HashMap::new(),
            )
            .expect("broker")
        };
        let attributed = build(&["/usr/bin/gh"]).with_attribution(
            runeward_egress::attribution::DEFAULT_SOCKET,
            runeward_egress::attribution::Key::generate(),
        );
        let strict = Network {
            default: "deny".into(),
            enforce: "strict".into(),
            ..Network::default()
        };
        let cooperative = Network {
            default: "deny".into(),
            ..Network::default()
        };
        check_binary_attribution(&attributed, &strict, "runc", true).expect("supported");
        // No binaries: nothing to check.
        check_binary_attribution(&build(&[]), &cooperative, "runsc", false).expect("no binaries");
        for (b, net, rt, sup, want) in [
            (&attributed, &cooperative, "runc", true, "strict egress"),
            (&attributed, &strict, "runsc", true, "runsc"),
            (&attributed, &strict, "kata-qemu", true, "kata-qemu"),
            (&attributed, &strict, "runc", false, "supervisor"),
            (
                &build(&["/usr/bin/gh"]),
                &strict,
                "runc",
                true,
                "supervisor",
            ),
        ] {
            let err = check_binary_attribution(b, net, rt, sup).expect_err(want);
            assert!(
                matches!(&err, BackendError::Unsupported(m) if m.contains(want)),
                "{want}: {err}"
            );
        }
    }

    #[test]
    fn engine_info_parsing() {
        let info = |rt: &str, k: &str, os: &str, mem: i64, cpus: i64| EngineInfo {
            default_runtime: rt.to_owned(),
            host_kernel: k.to_owned(),
            os: os.to_owned(),
            capacity: EngineCapacity {
                memory_bytes: mem,
                cpus,
            },
        };
        assert_eq!(
            parse_engine_info(
                "runc|6.12.100+deb13-cloud-amd64|Debian GNU/Linux 13 (trixie)|4014825472|2\n"
            ),
            info(
                "runc",
                "6.12.100+deb13-cloud-amd64",
                "Debian GNU/Linux 13 (trixie)",
                4_014_825_472,
                2
            )
        );
        assert_eq!(
            parse_engine_info("runc|6.8.0-45-generic|Ubuntu 24.04.1 LTS\n"),
            info("runc", "6.8.0-45-generic", "Ubuntu 24.04.1 LTS", 0, 0)
        );
        assert_eq!(parse_engine_info("runc"), info("runc", "", "", 0, 0));
        assert_eq!(
            parse_engine_info("crun|<no value>|fedora|<no value>|x"),
            info("crun", "", "fedora", 0, 0)
        );
        assert_eq!(parse_engine_info(""), EngineInfo::default());
    }

    fn plan<'a>(id: &'a str, env: &'a [(String, String)]) -> RunPlan<'a> {
        RunPlan {
            runtime: "docker",
            id,
            workdir: "/workspace",
            egress_container: None,
            cooperative: false,
            egress_env: env,
            supervisor: None,
            broker_ca: false,
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
            docker_exec_args("x", &req, false),
            ["exec", "-w", "/tmp", "-e", "A=1", "runeward-x", "env"]
        );
        assert_eq!(
            docker_attach_args("x", true, &["bash".into()], false),
            ["exec", "-i", "-t", "runeward-x", "bash"]
        );
        assert_eq!(docker_attach_args("x", false, &[], false).len(), 6);
        // Supervised: the same call, confined by the supervisor's exec mode.
        assert_eq!(
            docker_exec_args("x", &req, true).join(" "),
            "exec -w /tmp -e A=1 runeward-x /usr/local/bin/runeward-supervisor exec \
             --config /run/runeward/supervisor-exec.json -- env"
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
        );
        let a = docker_attach_args("x", true, &[], true);
        assert_eq!(a[4..9], supervised_command(&[])[..]);
        assert_eq!(a[9..], default_shell()[..]);
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
        let a = egress_run_args("x", "{}", &cfg, false);
        assert!(!a.iter().any(|s| s.starts_with("RUNEWARD_DNS_RESOLVERS")));
        assert_eq!(a[a.len() - 7], "runeward-egress:latest");
        let cfg = cfg.with(crate::config::DNS_RESOLVERS_ENV, " 9.9.9.9 ");
        let a = egress_run_args("x", "{}", &cfg, false);
        assert!(a.contains(&"RUNEWARD_DNS_RESOLVERS=9.9.9.9".to_owned()));
    }

    #[test]
    fn egress_args_with_broker_stage_the_document() {
        let a = egress_run_args("x", "{}", &BackendConfig::default(), true);
        assert_eq!(
            a[0], "create",
            "created stopped, document copied, then started"
        );
        let tail = a[a.len() - 4..].join(" ");
        assert_eq!(
            tail,
            "--broker-config /etc/runeward/broker.json --sandbox-id x"
        );
        // The document never travels on the command line or in env.
        assert!(
            !a.iter()
                .any(|s| s.contains("rwph_") || s.contains("PRIVATE"))
        );
    }

    #[test]
    fn supervised_run_args() {
        let mut cfg = runeward_supervisor::SupervisorConfig::default().with_argv(["sleep", "1"]);
        cfg.process.user = "1500".into();
        let sup = SupervisorPlan::new(cfg, "").expect("plan");
        let spec = Spec {
            user: "1000".into(),
            command: vec!["agent".into()],
            ..Spec::default()
        };
        let env = ca_env();
        let mut p = plan("x", &env);
        p.supervisor = Some(&sup);
        p.broker_ca = true;
        let a = docker_run_args(&p, &spec, &BackendConfig::default()).join(" ");
        assert!(a.starts_with("create --name runeward-x "), "{a}");
        for want in [
            "-v /run/runeward",
            "-v /etc/runeward/ca",
            "--label runeward.supervised=1500",
            "--cap-drop ALL --cap-add SETUID --cap-add SETGID --cap-add CHOWN --security-opt no-new-privileges",
            "-u 0:0",
            "-e SSL_CERT_FILE=/etc/runeward/ca/ca-bundle.pem",
            "--entrypoint /usr/local/bin/runeward-supervisor debian:stable-slim init --config /run/runeward/supervisor.json",
        ] {
            assert!(a.contains(want), "missing {want:?} in {a}");
        }
        assert!(!a.contains("-u 1000"), "{a}");
        assert!(
            !a.contains(" agent"),
            "the agent command is in the config: {a}"
        );

        // Broker without supervisor: staged, CA dir, the Charter's command.
        let mut p = plan("x", &env);
        p.broker_ca = true;
        let a = docker_run_args(&p, &spec, &BackendConfig::default()).join(" ");
        assert!(a.starts_with("create "), "{a}");
        assert!(
            a.contains("-u 1000") && a.ends_with("--entrypoint agent debian:stable-slim"),
            "{a}"
        );
        assert!(!a.contains("SETUID"), "{a}");
    }
}
