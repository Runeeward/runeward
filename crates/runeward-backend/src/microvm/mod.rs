//! The native microVM backend (`host.type = "microvm"`): Firecracker or
//! libkrun booted directly, without a container engine, Kata or Kubernetes.
//!
//! One VM per sandbox:
//!
//! - **Image.** The Charter's OCI image is pulled from its registry and
//!   converted once into a read-only ext4 disk ([`rootfs`]), shared by every
//!   VM of that image. The guest writes into an overlay in its own memory.
//! - **Guest.** `runeward-vmagent` is PID 1 (Firecracker: the initramfs
//!   `/init`; libkrun: `/init.krun` served from host memory). It mounts the
//!   image and the workspace disk and serves exec, files, the isolation
//!   probe and shutdown over vsock ([`client`]).
//! - **Workspace.** A per-sandbox ext4 disk image, kept across sleep and
//!   wake ([`Backend::stop`] powers the VM off; [`Backend::start`] boots a
//!   new one on the same disk), removed by [`Backend::kill`].
//! - **Egress.** The VM has no network device. Processes reach the
//!   Charter's egress proxy through `HTTP(S)_PROXY` at an in-guest address
//!   the agent forwards over vsock to a host Unix socket ([`egress`]); with
//!   no route out, `default = "deny"` cannot be bypassed from the guest,
//!   and non-HTTP traffic has no path at all.
//! - **Isolation.** The agent collects the same probe as the container
//!   backends; the tier is derived with [`crate::evidence::assess`] and is
//!   `vm` only when the guest shows a separate kernel and a hypervisor
//!   marker, and the VMM process is confirmed running on this host.
//!
//! State lives under `RUNEWARD_MICROVM_DIR` (default
//! `~/.runeward/microvm`): `images/` (the disk cache), `agent/` (the
//! Firecracker initramfs), `vms/<id>/` (workspace disk, sockets, logs,
//! `state.json`) and `snapshots/`.

mod client;
mod egress;
mod ext4;
mod initramfs;
mod rootfs;
mod vmm;

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use runeward_charter::{Charter, File};
use runeward_vmagent::proto::{
    ExecSpec, FileAction, FileRequest, FileStat, GUEST_PROXY_ADDR, HelloResult, InitRequest,
    ProbeResult, Request, StartRequest, Started,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::AsyncWrite;
use tokio::net::UnixStream;
use tokio::process::Child;

use self::client::{ExecIo, ExecOutput};
use self::egress::EgressServer;
use self::ext4::Tools;
use self::rootfs::{Image, ImageStore};
use self::vmm::{Firecracker, LaunchPlan, Libkrun, Vmm};
use crate::backend::Backend;
use crate::config::{
    BackendConfig, DEFAULT_IMAGE, FIRECRACKER_BIN_ENV, KRUN_HELPER_ENV, LIBKRUN_ENV,
    MICROVM_AGENT_ENV, MICROVM_DIR_ENV, MICROVM_DISK_SIZE_ENV, MICROVM_KERNEL_ENV, MICROVM_VMM_ENV,
    parse_size,
};
use crate::docker::{check_seed_dir, projected_data, projection_mode};
use crate::egress::{policy_from_network, proxy_env};
use crate::error::{BackendError, Result};
use crate::evidence::{self, Assessment};
use crate::factory::{Driver, look_path};
use crate::incell::{
    BROKER_CA_DIR, SUPERVISOR_BIN, SUPERVISOR_REPORT_PATH, SUPERVISOR_STATE_DIR, SYSTEM_ROOTS,
    SupervisorPlan, ca_bundle, ca_env, supervised_command,
};
use crate::isolation::IsolationTier;
use crate::pathutil::{self, expand_home};
use crate::seed::{self, filtered_file_stream, join_producer, seed_tar_stream};
use crate::types::{
    ExecRequest, ExecResult, PtyStream, Sandbox, SnapshotRef, Spec, SupervisorSpec,
    default_command, default_shell,
};
use crate::validate::{validate_file_mode, validate_projection_path, validate_sandbox_id};
use crate::{random_hex, sandbox_id_for};

/// The backend's name.
pub const MICROVM_BACKEND: &str = "microvm";

/// The default size of a new workspace disk (sparse).
const DEFAULT_DISK_BYTES: u64 = 8 << 30;
/// How long a booting guest has to answer.
const BOOT_TIMEOUT: Duration = Duration::from_secs(60);
/// How long a guest has to power off before its VMM is killed.
const STOP_GRACE: Duration = Duration::from_secs(15);
/// Unix socket paths must fit `sun_path` (104 bytes on macOS, 108 on
/// Linux), with room for Firecracker's `_<port>` suffix.
const MAX_SOCKET_PATH: usize = 96;

/// Where an image disk comes from.
#[async_trait]
pub(crate) trait Images: Send + Sync + std::fmt::Debug {
    /// The disk and config for `reference`.
    async fn ensure(&self, reference: &str) -> Result<Image>;
}

#[async_trait]
impl Images for ImageStore {
    async fn ensure(&self, reference: &str) -> Result<Image> {
        ImageStore::ensure(self, reference).await
    }
}

/// Creates workspace disks.
#[async_trait]
pub(crate) trait Disks: Send + Sync + std::fmt::Debug {
    /// An empty ext4 disk of `size` bytes at `path`.
    async fn make_workspace(&self, path: &Path, size: u64) -> Result<()>;
}

#[async_trait]
impl Disks for Tools {
    async fn make_workspace(&self, path: &Path, size: u64) -> Result<()> {
        self.make_empty(path, size, "rw-workspace").await
    }
}

/// What is recorded on disk for each sandbox.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
struct VmState {
    id: String,
    profile: String,
    image: String,
    digest: String,
    vmm: String,
    status: String,
    pid: u32,
    workdir: String,
    /// The agent identity of a supervised sandbox (empty: unsupervised).
    agent_user: String,
    supervised: bool,
    created_at: DateTime<Utc>,
}

impl Default for VmState {
    fn default() -> Self {
        Self {
            id: String::new(),
            profile: String::new(),
            image: String::new(),
            digest: String::new(),
            vmm: String::new(),
            status: String::new(),
            pid: 0,
            workdir: String::new(),
            agent_user: String::new(),
            supervised: false,
            created_at: crate::types::go_zero_time(),
        }
    }
}

/// A VM this process started.
#[derive(Debug)]
struct Live {
    child: Child,
    _egress: EgressServer,
}

/// The native microVM backend.
#[derive(Debug)]
pub struct MicroVm {
    config: BackendConfig,
    dir: PathBuf,
    images: Arc<dyn Images>,
    disks: Arc<dyn Disks>,
    vmms: BTreeMap<&'static str, Arc<dyn Vmm>>,
    default_vmm: &'static str,
    host_kernel: String,
    stop_grace: Duration,
    live: Mutex<HashMap<String, Live>>,
}

/// Opens the [`MicroVm`] backend for `host.type = "microvm"`.
#[derive(Debug, Clone, Copy, Default)]
pub struct MicroVmDriver;

#[async_trait]
impl Driver for MicroVmDriver {
    async fn open(&self, _: &Charter, config: &BackendConfig) -> Result<Arc<dyn Backend>> {
        Ok(Arc::new(MicroVm::new(config.clone()).await?))
    }
}

/// The ELF machine of this host's architecture (`EM_X86_64`, `EM_AARCH64`).
fn host_elf_machine() -> Option<u16> {
    match std::env::consts::ARCH {
        "x86_64" => Some(62),
        "aarch64" => Some(183),
        _ => None,
    }
}

/// Checks that `path` is an ELF executable for the guest architecture.
fn check_agent(path: &Path) -> Result<Vec<u8>> {
    let data = std::fs::read(path)
        .map_err(|e| BackendError::io(format!("read the guest agent {}", path.display()), e))?;
    let machine = (data.len() > 20 && data[..4] == *b"\x7fELF")
        .then(|| u16::from_le_bytes([data[18], data[19]]));
    match (machine, host_elf_machine()) {
        (Some(m), Some(want)) if m == want => Ok(data),
        (None, _) => Err(BackendError::Unsupported(format!(
            "{} is not a Linux ELF binary; {MICROVM_AGENT_ENV} must name a static runeward-vmagent built for {}-unknown-linux-musl",
            path.display(),
            std::env::consts::ARCH
        ))),
        _ => Err(BackendError::Unsupported(format!(
            "{} is built for another architecture than this host ({})",
            path.display(),
            std::env::consts::ARCH
        ))),
    }
}

/// The kernel release of this host.
fn host_kernel_release() -> String {
    if let Ok(k) = std::fs::read_to_string("/proc/sys/kernel/osrelease") {
        return k.trim().to_owned();
    }
    std::process::Command::new("uname")
        .arg("-r")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
        .unwrap_or_default()
}

/// Reports whether hardware virtualisation is usable by this process.
fn hypervisor_available() -> std::result::Result<(), String> {
    if cfg!(target_os = "linux") {
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/kvm")
            .map(drop)
            .map_err(|e| {
                format!("/dev/kvm is not usable by this user ({e}); add it to the kvm group")
            })
    } else if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        // Hypervisor.framework; the libkrun helper needs the
        // com.apple.security.hypervisor entitlement (checked at boot).
        Ok(())
    } else {
        Err(format!(
            "no supported hypervisor on {}/{}",
            std::env::consts::OS,
            std::env::consts::ARCH
        ))
    }
}

/// The VMM a runtime name selects.
fn vmm_key(runtime: &str) -> Option<&'static str> {
    match runtime.trim().to_ascii_lowercase().as_str() {
        "" => None,
        "firecracker" | "fc" => Some("firecracker"),
        "libkrun" | "krun" => Some("libkrun"),
        _ => Some("?"),
    }
}

/// The guest size for a Spec: memory in MiB and whole vCPUs.
fn guest_size(spec: &Spec, cfg: &BackendConfig) -> (u32, u8) {
    let mem = cfg.sandbox_memory_bytes(spec.resources.memory_bytes);
    let mem_mib = if mem > 0 { (mem >> 20).max(256) } else { 1024 };
    let nano = cfg.sandbox_nano_cpus(spec.resources.nano_cpus);
    let vcpus = if nano > 0 {
        (nano + 999_999_999) / 1_000_000_000
    } else {
        1
    };
    (
        u32::try_from(mem_mib).unwrap_or(u32::MAX),
        u8::try_from(vcpus.clamp(1, 32)).unwrap_or(1),
    )
}

/// Refuses Spec fields the backend cannot honour.
fn check_spec(spec: &Spec) -> Result<()> {
    if !spec.seccomp.is_empty() {
        return Err(BackendError::Unsupported(
            "host.seccomp is a container-engine profile; the microvm backend's boundary is the VM (its VMM runs under its own seccomp filters). Remove host.seccomp, or use the in-sandbox supervisor's seccomp ([process])".into(),
        ));
    }
    if !spec.apparmor.is_empty() {
        return Err(BackendError::Unsupported(
            "host.apparmor confines container processes on the host kernel; it does not apply inside a microVM".into(),
        ));
    }
    if spec.ide_port > 0 {
        return Err(BackendError::Unsupported(
            "the in-cell IDE needs a sandbox network address, and microvm sandboxes have no network device".into(),
        ));
    }
    if spec
        .broker
        .as_ref()
        .is_some_and(|b| b.0.restricts_binaries())
    {
        return Err(BackendError::Unsupported(
            "endpoint binaries cannot be enforced here: the egress broker runs on the host, outside the VM, so it cannot ask the in-sandbox supervisor which executable opened a connection".into(),
        ));
    }
    if vmm_key(&spec.runtime_class) == Some("?") {
        return Err(BackendError::Unsupported(format!(
            "host.runtime {:?} is not a microVM monitor (want \"firecracker\" or \"libkrun\")",
            spec.runtime_class
        )));
    }
    Ok(())
}

fn run_image(spec: &Spec) -> String {
    if spec.image.is_empty() {
        DEFAULT_IMAGE.to_owned()
    } else {
        spec.image.clone()
    }
}

fn workdir_of(spec: &Spec) -> String {
    if spec.workdir.is_empty() {
        "/workspace".to_owned()
    } else {
        spec.workdir.clone()
    }
}

impl MicroVm {
    /// Builds the backend from operator settings: needs a usable
    /// hypervisor, e2fsprogs, the static guest agent, and Firecracker
    /// (with a guest kernel) or the libkrun helper.
    pub async fn new(config: BackendConfig) -> Result<Self> {
        if let Err(why) = hypervisor_available() {
            return Err(BackendError::Unsupported(format!(
                "the microvm backend needs hardware virtualisation: {why}"
            )));
        }
        let dir = {
            let set = config.raw(MICROVM_DIR_ENV).trim();
            expand_home(if set.is_empty() {
                "~/.runeward/microvm"
            } else {
                set
            })
        };
        let tools = Tools::find(&config)?;
        let agent = {
            let set = config.raw(MICROVM_AGENT_ENV).trim();
            if set.is_empty() {
                std::env::current_exe()
                    .ok()
                    .and_then(|e| e.parent().map(|d| d.join("runeward-vmagent")))
                    .filter(|p| p.is_file())
                    .or_else(|| look_path("runeward-vmagent"))
            } else {
                Some(PathBuf::from(set))
            }
        }
        .ok_or_else(|| {
            BackendError::Unsupported(format!(
                "the microvm backend boots a static runeward-vmagent as the guest's init; build it (cargo build --release --target {}-unknown-linux-musl -p runeward-vmagent) and set {MICROVM_AGENT_ENV}",
                std::env::consts::ARCH
            ))
        })?;
        let agent_bytes = check_agent(&agent)?;
        let mut vmms: BTreeMap<&'static str, Arc<dyn Vmm>> = BTreeMap::new();
        let mut missing = Vec::new();
        if cfg!(target_os = "linux") {
            let bin = {
                let set = config.raw(FIRECRACKER_BIN_ENV).trim();
                if set.is_empty() {
                    look_path("firecracker")
                } else {
                    Some(PathBuf::from(set))
                }
            };
            let kernel = config.raw(MICROVM_KERNEL_ENV).trim();
            match (bin.filter(|b| b.is_file()), kernel) {
                (None, _) => missing.push(format!(
                    "firecracker: not found (set {FIRECRACKER_BIN_ENV})"
                )),
                (Some(_), "") => missing.push(format!(
                    "firecracker: no guest kernel (set {MICROVM_KERNEL_ENV})"
                )),
                (Some(bin), kernel) => {
                    let initramfs = Self::initramfs(&dir, &agent_bytes)?;
                    vmms.insert(
                        "firecracker",
                        Arc::new(Firecracker {
                            bin,
                            kernel: expand_home(kernel),
                            initramfs,
                        }),
                    );
                }
            }
        }
        let helper = {
            let set = config.raw(KRUN_HELPER_ENV).trim();
            if set.is_empty() {
                look_path("runeward-krun")
            } else {
                Some(PathBuf::from(set))
            }
        };
        match helper.filter(|h| h.is_file()) {
            Some(helper) => {
                let lib = config.raw(LIBKRUN_ENV).trim();
                let library = if !lib.is_empty() {
                    lib.to_owned()
                } else if cfg!(target_os = "macos") {
                    "libkrun.1.dylib".to_owned()
                } else {
                    "libkrun.so.1".to_owned()
                };
                vmms.insert(
                    "libkrun",
                    Arc::new(Libkrun {
                        helper,
                        library,
                        agent: agent.clone(),
                    }),
                );
            }
            None => missing.push(format!(
                "libkrun: runeward-krun not found (set {KRUN_HELPER_ENV})"
            )),
        }
        if vmms.is_empty() {
            return Err(BackendError::Unsupported(format!(
                "no microVM monitor is available: {}",
                missing.join("; ")
            )));
        }
        let default_vmm = match vmm_key(config.raw(MICROVM_VMM_ENV)) {
            Some("?") => {
                return Err(BackendError::Unsupported(format!(
                    "{MICROVM_VMM_ENV} must be firecracker or libkrun"
                )));
            }
            Some(k) => k,
            None if vmms.contains_key("firecracker") => "firecracker",
            None => "libkrun",
        };
        let images = ImageStore::new(dir.join("images"), tools.clone());
        Ok(Self::with_parts(
            config,
            dir,
            Arc::new(images),
            Arc::new(tools),
            vmms,
            default_vmm,
        ))
    }

    /// Assembles the backend (tests swap in fakes).
    pub(crate) fn with_parts(
        config: BackendConfig,
        dir: PathBuf,
        images: Arc<dyn Images>,
        disks: Arc<dyn Disks>,
        vmms: BTreeMap<&'static str, Arc<dyn Vmm>>,
        default_vmm: &'static str,
    ) -> Self {
        Self {
            config,
            dir,
            images,
            disks,
            vmms,
            default_vmm,
            host_kernel: host_kernel_release(),
            stop_grace: STOP_GRACE,
            live: Mutex::new(HashMap::new()),
        }
    }

    /// Writes (once per agent build) the Firecracker initramfs.
    fn initramfs(dir: &Path, agent: &[u8]) -> Result<PathBuf> {
        let sum = hex::encode(Sha256::digest(agent));
        let out = dir
            .join("agent")
            .join(format!("initramfs-{}.cpio", &sum[..16]));
        if !out.is_file() {
            std::fs::create_dir_all(dir.join("agent"))
                .map_err(|e| BackendError::io("create the agent directory", e))?;
            let tmp = out.with_extension("part");
            std::fs::write(&tmp, initramfs::build(agent))
                .map_err(|e| BackendError::io("write the initramfs", e))?;
            std::fs::rename(&tmp, &out).map_err(|e| BackendError::io("write the initramfs", e))?;
        }
        Ok(out)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Live>> {
        self.live.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn vm_dir(&self, id: &str) -> PathBuf {
        self.dir.join("vms").join(id)
    }

    fn snap_dir(&self) -> PathBuf {
        self.dir.join("snapshots")
    }

    fn read_state(&self, id: &str) -> Result<VmState> {
        validate_sandbox_id(id)?;
        let p = self.vm_dir(id).join("state.json");
        let data = std::fs::read(&p)
            .map_err(|_| BackendError::NotFound(format!("sandbox {id:?} not found")))?;
        serde_json::from_slice(&data)
            .map_err(|e| BackendError::msg(format!("read {}: {e}", p.display())))
    }

    fn write_state(&self, st: &VmState) -> Result<()> {
        let p = self.vm_dir(&st.id).join("state.json");
        let tmp = p.with_extension("json.tmp");
        let data = serde_json::to_vec_pretty(st).map_err(|e| BackendError::msg(e.to_string()))?;
        std::fs::write(&tmp, data).map_err(|e| BackendError::io("write sandbox state", e))?;
        std::fs::rename(&tmp, &p).map_err(|e| BackendError::io("write sandbox state", e))
    }

    fn vmm(&self, name: &str) -> Result<Arc<dyn Vmm>> {
        let key = vmm_key(name).unwrap_or(self.default_vmm);
        self.vmms.get(key).cloned().ok_or_else(|| {
            BackendError::Unsupported(format!(
                "the {key} monitor is not available on this host (available: {})",
                self.vmms.keys().copied().collect::<Vec<_>>().join(", ")
            ))
        })
    }

    async fn connect(&self, st: &VmState) -> Result<UnixStream> {
        let vmm = self.vmm(&st.vmm)?;
        vmm.connect(&self.vm_dir(&st.id))
            .await
            .map_err(|e| BackendError::io(format!("connect to the guest agent of {}", st.id), e))
    }

    /// Waits until the guest agent answers, failing early when the VMM
    /// exits.
    async fn wait_ready(&self, vmm: &dyn Vmm, dir: &Path, child: &mut Child) -> Result<()> {
        let deadline = Instant::now() + BOOT_TIMEOUT;
        let mut last = String::new();
        while Instant::now() < deadline {
            if let Ok(Some(st)) = child.try_wait() {
                return Err(BackendError::msg(format!(
                    "the {} VMM exited during boot ({st}): {}",
                    vmm.name(),
                    log_tail(dir)
                )));
            }
            match vmm.connect(dir).await {
                Ok(s) => match tokio::time::timeout(
                    Duration::from_secs(5),
                    client::call::<HelloResult>(s, &Request::Hello),
                )
                .await
                {
                    Ok(Ok(_)) => return Ok(()),
                    Ok(Err(e)) => last = e.to_string(),
                    Err(_) => last = "hello timed out".into(),
                },
                Err(e) => last = e.to_string(),
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        Err(BackendError::Timeout(format!(
            "the guest agent did not answer within {BOOT_TIMEOUT:?} ({last}): {}",
            log_tail(dir)
        )))
    }

    /// Stats `path` in the guest as root.
    async fn guest_stat(&self, st: &VmState, path: &str) -> Option<FileStat> {
        let s = self.connect(st).await.ok()?;
        client::call::<FileStat>(
            s,
            &Request::File(FileRequest {
                action: FileAction::Stat,
                path: path.into(),
                user: "0:0".into(),
                ..FileRequest::default()
            }),
        )
        .await
        .ok()
    }

    /// Writes `data` to `path` in the guest as `user`.
    async fn guest_write(
        &self,
        st: &VmState,
        path: &str,
        mode: u32,
        user: &str,
        data: Vec<u8>,
    ) -> Result<()> {
        let s = self.connect(st).await?;
        client::file_write(
            s,
            FileRequest {
                action: FileAction::Write,
                path: path.into(),
                mode,
                user: user.into(),
            },
            std::io::Cursor::new(data),
        )
        .await
    }

    /// Reads `path` from the guest as `user`.
    async fn guest_read(&self, st: &VmState, path: &str, user: &str) -> Result<Vec<u8>> {
        let s = self.connect(st).await?;
        let mut buf = Vec::new();
        client::file_read(
            s,
            FileRequest {
                action: FileAction::Read,
                path: path.into(),
                user: user.into(),
                ..FileRequest::default()
            },
            &mut buf,
        )
        .await?;
        Ok(buf)
    }

    /// Runs a command to completion and returns its output.
    async fn guest_run(&self, st: &VmState, argv: &[&str], user: &str) -> Result<ExecOutput> {
        let s = self.connect(st).await?;
        client::exec(
            s,
            ExecSpec {
                argv: argv.iter().map(|a| (*a).to_owned()).collect(),
                user: user.into(),
                ..ExecSpec::default()
            },
            ExecIo {
                capture: true,
                timeout: Some(Duration::from_secs(60)),
                ..ExecIo::default()
            },
        )
        .await
    }

    /// The supervisor plan for a create: `None` when the image lacks the
    /// supervisor and the Charter does not require it.
    async fn plan_supervisor(
        &self,
        st: &VmState,
        image: &Image,
        s: &SupervisorSpec,
    ) -> Result<Option<SupervisorPlan>> {
        let present = self
            .guest_stat(st, SUPERVISOR_BIN)
            .await
            .is_some_and(|f| f.kind == "file" && f.mode & 0o111 != 0);
        if !present {
            if s.required {
                return Err(BackendError::Unsupported(format!(
                    "image {:?} does not contain {SUPERVISOR_BIN}, which this Charter requires ([filesystem] landlock = \"required\" or [process]); build the image from deploy/Dockerfile.sandbox or copy the binary in",
                    image.reference
                )));
            }
            tracing::warn!(target: "runeward_backend", "image {:?} has no {SUPERVISOR_BIN}; running without in-sandbox confinement (best effort)", image.reference);
            return Ok(None);
        }
        let user = if s.config.process.user.trim().is_empty() {
            image.config.user.clone()
        } else {
            String::new()
        };
        SupervisorPlan::new(s.config.clone(), &user).map(Some)
    }

    /// Copies the broker CA and a trust bundle of the image's roots plus
    /// that CA into the guest.
    async fn stage_broker_ca(&self, st: &VmState, ca: &str) -> Result<()> {
        let mut roots = None;
        for p in SYSTEM_ROOTS {
            if let Ok(data) = self.guest_read(st, p, "0:0").await
                && !data.is_empty()
            {
                roots = Some(data);
                break;
            }
        }
        self.guest_write(
            st,
            &format!("{BROKER_CA_DIR}/broker-ca.pem"),
            0o644,
            "0:0",
            ca.as_bytes().to_vec(),
        )
        .await?;
        self.guest_write(
            st,
            &format!("{BROKER_CA_DIR}/ca-bundle.pem"),
            0o644,
            "0:0",
            ca_bundle(roots.as_deref(), ca),
        )
        .await
    }

    /// Collects isolation evidence from the guest.
    async fn assess(&self, st: &VmState, vmm: &dyn Vmm, workdir: &str) -> Assessment {
        if !self.config.isolation_probe() {
            return evidence::assess_unprobed(vmm.name(), &self.host_kernel);
        }
        let probe = match self.connect(st).await {
            Ok(s) => tokio::time::timeout(
                Duration::from_secs(15),
                client::call::<ProbeResult>(s, &Request::Probe),
            )
            .await
            .map_err(|_| "probe timed out".to_owned())
            .and_then(|r| r.map(|p| p.output).map_err(|e| e.to_string())),
            Err(e) => Err(e.to_string()),
        };
        let mut a = evidence::assess(
            vmm.name(),
            &self.host_kernel,
            probe.as_deref().map_err(String::as_str),
        );
        // The host side: this process launched the VMM and it is still
        // running, so the monitor is known rather than inferred.
        let running = self
            .lock()
            .get_mut(&st.id)
            .is_some_and(|l| matches!(l.child.try_wait(), Ok(None)));
        a.attach_host_hypervisor(running.then_some(vmm.name()));
        if let Ok(out) = &probe {
            a.check_workspace(out, workdir);
        }
        a
    }

    /// Kills a VMM this process does not hold (left by an earlier control
    /// plane), after checking the pid still belongs to it.
    fn kill_orphan(&self, st: &VmState) {
        if st.pid == 0 || self.lock().contains_key(&st.id) {
            return;
        }
        let dir = self.vm_dir(&st.id);
        if process_command(st.pid).contains(&*dir.to_string_lossy()) {
            let _ = std::process::Command::new("kill")
                .args(["-KILL", &st.pid.to_string()])
                .status();
        }
    }

    /// Powers a VM off (gracefully, then by force) and stops its egress.
    async fn power_off(&self, st: &VmState) {
        let live = self.lock().remove(&st.id);
        let Some(mut live) = live else {
            self.kill_orphan(st);
            return;
        };
        if matches!(live.child.try_wait(), Ok(None)) {
            if let Ok(s) = self.connect(st).await {
                let _ = tokio::time::timeout(
                    Duration::from_secs(5),
                    client::call::<serde_json::Value>(s, &Request::Shutdown),
                )
                .await;
            }
            if tokio::time::timeout(self.stop_grace, live.child.wait())
                .await
                .is_err()
            {
                let _ = live.child.kill().await;
            }
        }
        let _ = live.child.wait().await;
    }

    /// Creates a sandbox, or with `reuse` boots one around the kept
    /// workspace disk of `spec.id` (wake). A failed wake never removes the
    /// workspace disk.
    async fn provision(&self, spec: Spec, reuse: bool) -> Result<Sandbox> {
        check_spec(&spec)?;
        let id = sandbox_id_for(&spec)?;
        let vmm = self.vmm(&spec.runtime_class)?;
        let dir = self.vm_dir(&id);
        let longest = vmm.egress_socket(&dir);
        if longest.as_os_str().len() > MAX_SOCKET_PATH {
            return Err(BackendError::Unsupported(format!(
                "socket path {} is too long for a Unix socket; set {MICROVM_DIR_ENV} to a shorter directory",
                longest.display()
            )));
        }
        let ws = dir.join("workspace.ext4");
        if reuse {
            if !ws.is_file() {
                return Err(BackendError::msg(format!(
                    "the workspace disk of {id} is gone"
                )));
            }
        } else {
            if dir.exists() {
                return Err(BackendError::msg(format!("sandbox {id} already exists")));
            }
            std::fs::create_dir_all(&dir)
                .map_err(|e| BackendError::io(format!("create {}", dir.display()), e))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
            }
        }
        let res = self.boot(&spec, &id, vmm, reuse).await;
        if res.is_err() {
            if let Some(mut live) = self.lock().remove(&id) {
                let _ = live.child.start_kill();
                // Reaped by tokio's orphan queue.
            }
            if reuse {
                if let Ok(mut st) = self.read_state(&id) {
                    st.status = "stopped".into();
                    st.pid = 0;
                    let _ = self.write_state(&st);
                }
            } else {
                let _ = std::fs::remove_dir_all(&dir);
            }
        }
        res
    }

    async fn boot(&self, spec: &Spec, id: &str, vmm: Arc<dyn Vmm>, reuse: bool) -> Result<Sandbox> {
        let dir = self.vm_dir(id);
        let image = self.images.ensure(&run_image(spec)).await?;
        let ws = dir.join("workspace.ext4");
        if !reuse {
            let size = {
                let raw = self.config.raw(MICROVM_DISK_SIZE_ENV).trim();
                if raw.is_empty() {
                    DEFAULT_DISK_BYTES
                } else {
                    parse_size(raw)
                        .and_then(|n| u64::try_from(n).ok())
                        .filter(|n| *n >= 16 << 20)
                        .ok_or_else(|| {
                            BackendError::msg(format!(
                                "{MICROVM_DISK_SIZE_ENV}={raw:?} is not a size of at least 16m"
                            ))
                        })?
                }
            };
            self.disks.make_workspace(&ws, size).await?;
        }
        let workdir = workdir_of(spec);
        let broker = spec.broker.as_ref().map(|b| Arc::clone(&b.0));
        let egress = EgressServer::start(
            &vmm.egress_socket(&dir),
            policy_from_network(&spec.network),
            id,
            broker.clone(),
        )
        .await?;
        let (mem_mib, vcpus) = guest_size(spec, &self.config);
        let plan = LaunchPlan {
            dir: dir.clone(),
            name: format!("rw-{}", &id[..id.len().min(12)]),
            rootfs: image.rootfs.clone(),
            workspace: Some(ws),
            vcpus,
            mem_mib,
        };
        let mut child = vmm.launch(&plan).await?;
        let pid = child.id().unwrap_or(0);
        if let Err(e) = self.wait_ready(vmm.as_ref(), &dir, &mut child).await {
            let _ = child.start_kill();
            return Err(e);
        }
        self.lock().insert(
            id.to_owned(),
            Live {
                child,
                _egress: egress,
            },
        );
        let mut st = VmState {
            id: id.to_owned(),
            profile: spec.profile.clone(),
            image: image.reference.clone(),
            digest: image.digest.clone(),
            vmm: vmm.name().to_owned(),
            status: "booting".into(),
            pid,
            workdir: workdir.clone(),
            created_at: Utc::now(),
            ..VmState::default()
        };
        if reuse && let Ok(old) = self.read_state(id) {
            st.created_at = old.created_at;
        }
        self.write_state(&st)?;

        let mut env = image.config.env_map();
        env.extend(spec.env.iter().map(|(k, v)| (k.clone(), v.clone())));
        env.extend(proxy_env(&format!("http://{GUEST_PROXY_ADDR}")));
        if broker.is_some() {
            env.extend(ca_env());
        }
        let user = if spec.user.is_empty() {
            image.config.user.clone()
        } else {
            spec.user.clone()
        };
        let s = self.connect(&st).await?;
        client::call::<serde_json::Value>(
            s,
            &Request::Init(InitRequest {
                hostname: id[..id.len().min(12)].to_owned(),
                workdir: workdir.clone(),
                read_only: spec.read_only,
                env,
                user,
                writable: vec![SUPERVISOR_STATE_DIR.to_owned(), BROKER_CA_DIR.to_owned()],
            }),
        )
        .await
        .map_err(|e| BackendError::msg(format!("prepare the guest: {e}")))?;

        let supervisor = match &spec.supervisor {
            Some(s) => self.plan_supervisor(&st, &image, s).await?,
            None => None,
        };
        if let Some(plan) = &supervisor {
            for (name, data, mode) in plan.files() {
                self.guest_write(
                    &st,
                    &format!("{SUPERVISOR_STATE_DIR}/{name}"),
                    mode,
                    "0:0",
                    data,
                )
                .await?;
            }
            st.supervised = true;
            st.agent_user = plan.agent_user.clone();
            // The workspace disk starts owned like the image's directory;
            // hand it to the agent identity.
            match self
                .guest_run(&st, &["chown", &plan.agent_user, &workdir], "0:0")
                .await
            {
                Ok(o) if o.exit.code == 0 => {}
                Ok(o) => {
                    tracing::warn!(target: "runeward_backend", "hand workspace {workdir} to {}: {}", plan.agent_user, String::from_utf8_lossy(&o.stderr).trim())
                }
                Err(e) => {
                    tracing::warn!(target: "runeward_backend", "hand workspace {workdir} to {}: {e}", plan.agent_user)
                }
            }
        }
        if let Some(b) = &broker {
            self.stage_broker_ca(&st, b.ca_cert_pem()).await?;
        }

        // Evidence first, before the workload starts or the workspace is
        // populated.
        let assessment = self.assess(&st, vmm.as_ref(), &workdir).await;
        assessment.log(MICROVM_BACKEND, id);
        if spec.persist_workspace && assessment.workspace_ephemeral() {
            return Err(BackendError::Unsupported(format!(
                "the workspace {workdir} is not the workspace disk; refusing a persistent workspace"
            )));
        }

        let argv = if supervisor.is_some() {
            let mut c = vec![SUPERVISOR_BIN.to_owned()];
            c.extend(SupervisorPlan::init_args());
            c
        } else if spec.command.is_empty() {
            default_command()
        } else {
            spec.command.clone()
        };
        let s = self.connect(&st).await?;
        client::call::<Started>(
            s,
            &Request::Start(StartRequest {
                argv,
                user: if supervisor.is_some() {
                    "0:0".into()
                } else {
                    String::new()
                },
            }),
        )
        .await
        .map_err(|e| BackendError::msg(format!("start the sandbox process: {e}")))?;
        st.status = "running".into();
        self.write_state(&st)?;

        if let Some(src) = &spec.seed_dir {
            self.seed_workspace(&st, src).await?;
        }
        if !spec.files.is_empty() {
            self.copy_files(id, &spec.files).await?;
        }
        Ok(Sandbox {
            id: id.to_owned(),
            profile: spec.profile.clone(),
            backend: MICROVM_BACKEND.to_owned(),
            image: image.reference,
            status: "running".into(),
            created_at: st.created_at,
            endpoint: String::new(),
            isolation: assessment.tier,
            isolation_evidence: Some(assessment.evidence),
        })
    }

    /// The identity the backend's own file operations use: the agent
    /// identity of a supervised sandbox, else the sandbox default.
    fn internal_user(st: &VmState) -> String {
        st.agent_user.clone()
    }

    async fn seed_workspace(&self, st: &VmState, src: &Path) -> Result<()> {
        check_seed_dir(src, &self.config)?;
        let (stream, producer) = seed_tar_stream(src.to_path_buf());
        let s = self.connect(st).await?;
        let res = client::file_write(
            s,
            FileRequest {
                action: FileAction::TarIn,
                path: st.workdir.clone(),
                user: Self::internal_user(st),
                ..FileRequest::default()
            },
            stream,
        )
        .await;
        let produced = join_producer(producer).await;
        res.and(produced.map_err(|e| BackendError::io("read copy_from", e)))
            .map_err(|e| {
                BackendError::msg(format!(
                    "seed workspace from {:?}: {e}",
                    src.display().to_string()
                ))
            })
    }

    /// Streams a tar of the workspace into `w`.
    async fn tar_out(&self, st: &VmState, w: &mut (dyn AsyncWrite + Send + Unpin)) -> Result<()> {
        let s = self.connect(st).await?;
        client::file_read(
            s,
            FileRequest {
                action: FileAction::TarOut,
                path: st.workdir.clone(),
                user: Self::internal_user(st),
                ..FileRequest::default()
            },
            w,
        )
        .await
        .map(drop)
    }

    fn sandbox_of(&self, st: &VmState) -> Sandbox {
        let status = match self.lock().get_mut(&st.id) {
            Some(l) => match l.child.try_wait() {
                Ok(None) => "running".to_owned(),
                _ => "exited".to_owned(),
            },
            None if st.status == "running" => {
                // A VM left by an earlier control plane: still running if its
                // monitor is.
                let dir = self.vm_dir(&st.id);
                if process_command(st.pid).contains(&*dir.to_string_lossy()) {
                    "running".to_owned()
                } else {
                    "exited".to_owned()
                }
            }
            None => st.status.clone(),
        };
        Sandbox {
            id: st.id.clone(),
            profile: st.profile.clone(),
            backend: MICROVM_BACKEND.to_owned(),
            image: st.image.clone(),
            status,
            created_at: st.created_at,
            endpoint: String::new(),
            isolation: IsolationTier::default(),
            isolation_evidence: None,
        }
    }
}

/// The command line of process `pid` (empty when it is gone): `/proc` on
/// Linux, `ps` elsewhere.
fn process_command(pid: u32) -> String {
    if pid == 0 {
        return String::new();
    }
    if let Ok(raw) = std::fs::read(format!("/proc/{pid}/cmdline")) {
        return String::from_utf8_lossy(&raw).replace('\0', " ");
    }
    if cfg!(target_os = "linux") {
        return String::new();
    }
    std::process::Command::new("ps")
        .args(["-o", "command=", "-p", &pid.to_string()])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default()
}

/// The last lines of a VM's logs, for boot failures.
fn log_tail(dir: &Path) -> String {
    let mut out = Vec::new();
    for name in ["vmm.log", "console.log"] {
        if let Ok(s) = std::fs::read_to_string(dir.join(name)) {
            let lines: Vec<&str> = s.lines().collect();
            let tail = lines[lines.len().saturating_sub(15)..].join(" | ");
            if !tail.trim().is_empty() {
                out.push(format!("{name}: {tail}"));
            }
        }
    }
    if out.is_empty() {
        "no VMM output".into()
    } else {
        out.join("; ")
    }
}

/// An exit as the container backends report it: the code, `128 + n` for a
/// signal.
fn exit_code(o: &ExecOutput) -> i32 {
    if o.timed_out {
        return -1;
    }
    match o.exit.signal {
        Some(s) if o.exit.code < 0 => 128 + s,
        _ => o.exit.code,
    }
}

#[async_trait]
impl Backend for MicroVm {
    fn name(&self) -> &str {
        MICROVM_BACKEND
    }

    fn isolation_tier(&self) -> IsolationTier {
        IsolationTier::Vm
    }

    async fn create(&self, spec: Spec) -> Result<Sandbox> {
        self.provision(spec, false).await
    }

    async fn exec(&self, id: &str, req: ExecRequest) -> Result<ExecResult> {
        let st = self.read_state(id)?;
        let argv = if st.supervised {
            supervised_command(&req.command)
        } else {
            req.command.clone()
        };
        if argv.is_empty() {
            return Err(BackendError::msg("exec: empty command"));
        }
        let start = Instant::now();
        let s = self.connect(&st).await?;
        let out = client::exec(
            s,
            ExecSpec {
                argv,
                env: req.env.clone(),
                workdir: req.workdir.clone(),
                user: if st.supervised {
                    "0:0".into()
                } else {
                    String::new()
                },
                ..ExecSpec::default()
            },
            ExecIo {
                stdout: req.stdout,
                stderr: req.stderr,
                capture: !req.stream_only,
                timeout: req.timeout,
                ..ExecIo::default()
            },
        )
        .await?;
        Ok(ExecResult {
            exit_code: exit_code(&out),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
            duration: start.elapsed(),
        })
    }

    async fn attach_pty(&self, id: &str, s: PtyStream) -> Result<()> {
        let st = self.read_state(id)?;
        let command = if s.command.is_empty() {
            default_shell()
        } else {
            s.command.clone()
        };
        let argv = if st.supervised {
            supervised_command(&command)
        } else {
            command
        };
        let conn = self.connect(&st).await?;
        let merge = s.stderr.is_none();
        let out = client::exec(
            conn,
            ExecSpec {
                argv,
                user: if st.supervised {
                    "0:0".into()
                } else {
                    String::new()
                },
                tty: s.tty,
                ..ExecSpec::default()
            },
            ExecIo {
                stdin: s.stdin,
                stdout: s.stdout,
                stderr: s.stderr,
                merge_stderr: merge,
                resize: s.resize,
                ..ExecIo::default()
            },
        )
        .await?;
        match exit_code(&out) {
            0 => Ok(()),
            c if out.exit.signal.is_some() => Err(BackendError::msg(match out.exit.signal {
                Some(9) => "signal: killed".to_owned(),
                Some(15) => "signal: terminated".to_owned(),
                Some(n) => format!("signal: {n}"),
                None => format!("exit status {c}"),
            })),
            c => Err(BackendError::msg(format!("exit status {c}"))),
        }
    }

    async fn copy_files(&self, id: &str, files: &[File]) -> Result<()> {
        let st = self.read_state(id)?;
        for f in files {
            validate_projection_path(&f.path, self.config.confine_files())?;
            validate_file_mode(&f.mode)?;
            let Some(data) = projected_data(f)? else {
                continue;
            };
            let target = if f.path.starts_with('/') {
                pathutil::clean(&f.path)
            } else {
                pathutil::clean(&format!("{}/{}", st.workdir, f.path))
            };
            self.guest_write(
                &st,
                &target,
                projection_mode(&f.mode),
                &Self::internal_user(&st),
                data,
            )
            .await
            .map_err(|e| BackendError::msg(format!("copy file {:?} into sandbox: {e}", f.path)))?;
        }
        Ok(())
    }

    async fn export_workspace(
        &self,
        id: &str,
        w: &mut (dyn AsyncWrite + Send + Unpin),
    ) -> Result<()> {
        let st = self.read_state(id)?;
        self.tar_out(&st, w)
            .await
            .map_err(|e| BackendError::msg(format!("export workspace: {e}")))
    }

    async fn snapshot(&self, id: &str, name: &str) -> Result<SnapshotRef> {
        let st = self.read_state(id)?;
        let dir = self.snap_dir();
        std::fs::create_dir_all(&dir).map_err(|e| BackendError::io("create snapshot dir", e))?;
        let snap_id = random_hex();
        let loc = dir.join(format!("{snap_id}.tar"));
        let mut out = tokio::fs::File::create(&loc)
            .await
            .map_err(|e| BackendError::io("create snapshot", e))?;
        if let Err(e) = self.tar_out(&st, &mut out).await {
            drop(out);
            let _ = std::fs::remove_file(&loc);
            return Err(BackendError::msg(format!("snapshot tar: {e}")));
        }
        drop(out);
        let sum = seed::hash_file(&loc).map_err(|e| {
            let _ = std::fs::remove_file(&loc);
            BackendError::io("snapshot hash", e)
        })?;
        Ok(SnapshotRef {
            id: snap_id,
            name: name.to_owned(),
            profile: st.profile.clone(),
            backend: MICROVM_BACKEND.to_owned(),
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
        seed::verify_snapshot(snapshot)?;
        let sb = self.create(spec).await?;
        let res = async {
            let st = self.read_state(&sb.id)?;
            let (stream, producer) = filtered_file_stream(PathBuf::from(&snapshot.location));
            let s = self.connect(&st).await?;
            let res = client::file_write(
                s,
                FileRequest {
                    action: FileAction::TarIn,
                    path: st.workdir.clone(),
                    user: Self::internal_user(&st),
                    ..FileRequest::default()
                },
                stream,
            )
            .await;
            let produced = join_producer(producer).await;
            res.and(produced.map_err(|e| BackendError::io("read snapshot", e)))
                .map_err(|e| BackendError::msg(format!("restore untar: {e}")))
        }
        .await;
        if let Err(e) = res {
            let _ = self.kill(&sb.id).await;
            return Err(e);
        }
        Ok(sb)
    }

    async fn kill(&self, id: &str) -> Result<()> {
        validate_sandbox_id(id)?;
        if let Ok(st) = self.read_state(id) {
            self.power_off(&st).await;
        } else if let Some(mut live) = self.lock().remove(id) {
            let _ = live.child.start_kill();
        }
        let dir = self.vm_dir(id);
        match std::fs::remove_dir_all(&dir) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(BackendError::io(format!("remove {}", dir.display()), e)),
        }
    }

    fn supports_sleep(&self) -> bool {
        true
    }

    /// Powers the VM off: processes, guest memory and the egress path go;
    /// the workspace disk and the sandbox id stay.
    async fn stop(&self, id: &str) -> Result<()> {
        let mut st = self.read_state(id)?;
        self.power_off(&st).await;
        st.status = "stopped".into();
        st.pid = 0;
        self.write_state(&st)
    }

    /// Boots a new VM for `id` on its kept workspace disk, from `spec`
    /// (re-pulling nothing that is cached), with a fresh egress path.
    async fn start(&self, id: &str, mut spec: Spec) -> Result<Sandbox> {
        let st = self.read_state(id)?;
        spec.id = id.to_owned();
        self.power_off(&st).await;
        if spec.runtime_class.is_empty() {
            spec.runtime_class = st.vmm.clone();
        }
        self.provision(spec, true).await
    }

    async fn list(&self) -> Result<Vec<Sandbox>> {
        let mut out = Vec::new();
        let Ok(entries) = std::fs::read_dir(self.dir.join("vms")) else {
            return Ok(out);
        };
        for e in entries.flatten() {
            let id = e.file_name().to_string_lossy().into_owned();
            if let Ok(st) = self.read_state(&id) {
                out.push(self.sandbox_of(&st));
            }
        }
        out.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(out)
    }

    async fn exists(&self, id: &str) -> bool {
        self.read_state(id).is_ok()
    }

    async fn supervisor_report(&self, id: &str) -> Result<Option<String>> {
        let st = self.read_state(id)?;
        if !st.supervised {
            return Ok(None);
        }
        let data = self
            .guest_read(&st, SUPERVISOR_REPORT_PATH, "0:0")
            .await
            .unwrap_or_default();
        Ok(Some(String::from_utf8_lossy(&data).into_owned()))
    }
}

#[cfg(test)]
mod tests;
