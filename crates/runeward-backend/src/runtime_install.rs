//! Planning and applying the installation of sandbox runtimes.
//!
//! `runeward runtime install <gvisor|kata|kata-fc|krun>` is built on this
//! module: [`probe_host`] gathers [`HostFacts`], [`plan`] turns a
//! [`Request`] and the facts into a [`Plan`] (host checks plus the exact
//! steps), [`Plan::render`] prints it (the dry run), and [`apply`] performs
//! it.
//!
//! The behaviour of the Go installer is kept:
//!
//! - dry run by default: nothing is mutated until [`apply`] is called;
//! - gVisor's `runsc` and `containerd-shim-runsc-v1` are downloaded from the
//!   official release bucket and verified fail-closed, against a `sha256`
//!   pin when given, otherwise against the bucket's `.sha512` sidecar;
//! - `/etc/docker/daemon.json` is merged (other keys and runtimes kept);
//!   without root, the exact `sudo` commands are printed instead of writing;
//! - Kubernetes gets a RuntimeClass applied with `kubectl apply -f -`;
//! - Kata's distribution-specific install is not automated: the plan prints
//!   guidance and registers an installed Kata with the engine.
//!
//! New: crun with libkrun (`krun`); Kata with Firecracker (`kata-fc`) for
//! Kubernetes only (Docker and Podman are refused: Firecracker needs a
//! block-device rootfs and has no hot-plug); Kata on Docker through the
//! containerd runtime type `io.containerd.kata[-<hypervisor>].v2` with the
//! shim linked onto dockerd's PATH instead of a daemon.json entry; and host
//! checks for `/dev/kvm`, its permissions, nested virtualisation and
//! desktop engines (Docker Desktop, OrbStack) that cannot run VM runtimes.
//! A plan with a failing check is refused by [`apply`].

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use k8s_openapi::api::node::v1::{Overhead, RuntimeClass, Scheduling};
use k8s_openapi::apimachinery::pkg::api::resource::Quantity;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use runeward_charter::RuntimeFamily;
use sha2::{Digest, Sha256, Sha512};
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

use crate::error::{BackendError, Result};

/// The default `/etc/docker/daemon.json` location.
pub const DOCKER_DAEMON_JSON: &str = "/etc/docker/daemon.json";
/// Where downloaded binaries are installed.
pub const LOCAL_BIN_DIR: &str = "/usr/local/bin";
/// The official gVisor release bucket.
pub const GVISOR_RELEASE_BASE: &str = "https://storage.googleapis.com/gvisor/releases/release";
/// Where Kata's static release keeps its hypervisor configurations.
pub const KATA_CONFIG_DIRS: &[&str] = &[
    "/opt/kata/share/defaults/kata-containers",
    "/usr/share/defaults/kata-containers",
    "/etc/kata-containers",
];

const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(60);
const APPLY_TIMEOUT: Duration = Duration::from_secs(30);
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// A runtime the installer knows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VmRuntime {
    /// gVisor (`runsc`): a user-space kernel, `kernel` tier, no KVM needed.
    Gvisor,
    /// Kata Containers with its default hypervisor (QEMU or Cloud
    /// Hypervisor): `kernel`, or `vm` when evidence confirms it.
    Kata,
    /// Kata Containers with Firecracker: a microVM per sandbox (`vm`).
    KataFc,
    /// crun built with libkrun: a microVM per sandbox (`vm`).
    Krun,
}

impl VmRuntime {
    /// Every runtime, in documentation order.
    pub const ALL: [Self; 4] = [Self::Gvisor, Self::Kata, Self::KataFc, Self::Krun];

    /// Parses the CLI spelling (`gvisor`, `kata`, `kata-fc`, `krun`).
    pub fn parse(s: &str) -> std::result::Result<Self, String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "gvisor" | "runsc" => Ok(Self::Gvisor),
            "kata" => Ok(Self::Kata),
            "kata-fc" | "kata-firecracker" | "firecracker" => Ok(Self::KataFc),
            "krun" | "libkrun" => Ok(Self::Krun),
            other => Err(format!(
                "unknown runtime {other:?}: expected \"gvisor\", \"kata\", \"kata-fc\" or \"krun\""
            )),
        }
    }

    /// The CLI spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Gvisor => "gvisor",
            Self::Kata => "kata",
            Self::KataFc => "kata-fc",
            Self::Krun => "krun",
        }
    }

    /// The runtime name registered with Docker/Podman.
    pub fn engine_name(self) -> &'static str {
        match self {
            Self::Gvisor => "runsc",
            Self::Kata => "kata",
            Self::KataFc => "kata-fc",
            Self::Krun => "krun",
        }
    }

    /// The default Kubernetes RuntimeClass name.
    pub fn default_class(self) -> &'static str {
        match self {
            Self::Gvisor => "gvisor",
            Self::Kata => "kata",
            Self::KataFc => "kata-fc",
            Self::Krun => "krun",
        }
    }

    /// The CRI handler a RuntimeClass points at.
    pub fn handler(self) -> &'static str {
        match self {
            Self::Gvisor => "runsc",
            Self::Kata => "kata",
            Self::KataFc => "kata-fc",
            Self::Krun => "krun",
        }
    }

    /// A human label.
    pub fn label(self) -> &'static str {
        match self {
            Self::Gvisor => "gVisor (runsc)",
            Self::Kata => "Kata Containers",
            Self::KataFc => "Kata Containers with Firecracker",
            Self::Krun => "crun with libkrun (krun)",
        }
    }

    /// Reports whether sandboxes under this runtime need `/dev/kvm`.
    pub fn needs_kvm(self) -> bool {
        RuntimeFamily::of(self.engine_name()).needs_kvm()
    }
}

/// The engine a runtime is installed for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Engine {
    /// Docker (runtimes in `/etc/docker/daemon.json`).
    Docker,
    /// Podman (runtimes found by name in `containers.conf`).
    Podman,
    /// Kubernetes (a RuntimeClass; nodes are configured separately).
    K8s,
}

impl Engine {
    /// Parses `docker`, `podman` or `k8s`.
    pub fn parse(s: &str) -> std::result::Result<Self, String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "docker" => Ok(Self::Docker),
            "podman" => Ok(Self::Podman),
            "k8s" | "kubernetes" => Ok(Self::K8s),
            other => Err(format!(
                "unknown engine {other:?}: expected \"docker\", \"podman\" or \"k8s\""
            )),
        }
    }

    /// The CLI spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Docker => "docker",
            Self::Podman => "podman",
            Self::K8s => "k8s",
        }
    }
}

/// What to install.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// The runtime.
    pub runtime: VmRuntime,
    /// The engine to register it with.
    pub engine: Engine,
    /// gVisor release (`latest` or a date such as `20240101`).
    pub version: String,
    /// Kubernetes RuntimeClass name; empty uses [`VmRuntime::default_class`].
    pub runtime_class: String,
    /// Optional sha256 pin (hex) for the downloaded `runsc` binary.
    pub sha256: String,
    /// Release base URL for gVisor downloads (a mirror); empty uses
    /// [`GVISOR_RELEASE_BASE`].
    pub release_base: String,
    /// Where binaries are installed; empty uses [`LOCAL_BIN_DIR`].
    pub bin_dir: PathBuf,
    /// The Docker daemon configuration; empty uses [`DOCKER_DAEMON_JSON`].
    pub daemon_json: PathBuf,
    /// Kata only: `qemu` or `clh` selects the Docker runtime type
    /// `io.containerd.kata-<h>.v2`; empty uses `io.containerd.kata.v2`.
    pub hypervisor: String,
}

impl Request {
    /// A request with every option at its default.
    pub fn new(runtime: VmRuntime, engine: Engine) -> Self {
        Self {
            runtime,
            engine,
            version: String::new(),
            runtime_class: String::new(),
            sha256: String::new(),
            release_base: String::new(),
            bin_dir: PathBuf::new(),
            daemon_json: PathBuf::new(),
            hypervisor: String::new(),
        }
    }

    fn version(&self) -> &str {
        non_empty(self.version.trim(), "latest")
    }

    fn class(&self) -> &str {
        non_empty(self.runtime_class.trim(), self.runtime.default_class())
    }

    fn bin_dir(&self) -> PathBuf {
        if self.bin_dir.as_os_str().is_empty() {
            PathBuf::from(LOCAL_BIN_DIR)
        } else {
            self.bin_dir.clone()
        }
    }

    fn daemon_json(&self) -> PathBuf {
        if self.daemon_json.as_os_str().is_empty() {
            PathBuf::from(DOCKER_DAEMON_JSON)
        } else {
            self.daemon_json.clone()
        }
    }
}

fn non_empty<'a>(v: &'a str, fallback: &'a str) -> &'a str {
    if v.is_empty() { fallback } else { v }
}

/// Access to `/dev/kvm` on this host.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum KvmAccess {
    /// `/dev/kvm` does not exist.
    #[default]
    Missing,
    /// It exists but this user cannot open it read-write.
    NoPermission,
    /// It exists and opens read-write.
    Usable,
}

/// What [`plan`] needs to know about the host. [`probe_host`] fills it in;
/// tests build it by hand.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostFacts {
    /// `std::env::consts::OS`.
    pub os: String,
    /// `std::env::consts::ARCH`.
    pub arch: String,
    /// Whether the installer runs as root.
    pub root: bool,
    /// `/dev/kvm` access.
    pub kvm: KvmAccess,
    /// Whether this host is itself a VM (the x86 `hypervisor` CPU flag).
    pub virtualised: bool,
    /// The `kvm_intel`/`kvm_amd` `nested` parameter, when readable.
    pub nested: Option<bool>,
    /// Whether the engine answered.
    pub engine_reachable: bool,
    /// The engine's operating system (`OrbStack`, `Docker Desktop`, ...).
    pub engine_os: String,
    /// Runtimes already registered with the engine (or RuntimeClasses).
    pub registered: Vec<String>,
    /// The current daemon.json contents (`None` when absent).
    pub daemon_json: Option<String>,
    /// Installed binaries found (name -> path): `runsc`,
    /// `containerd-shim-kata-v2`, `kata-runtime`, `krun`, `kubectl`.
    pub binaries: BTreeMap<String, PathBuf>,
    /// Kata hypervisor configurations found (`fc`, `qemu`, `clh`).
    pub kata_configs: BTreeMap<String, PathBuf>,
}

/// The outcome of one host check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CheckStatus {
    /// Fine.
    Ok,
    /// Worth knowing; does not stop the install.
    Warn,
    /// The runtime cannot work here; [`apply`] refuses the plan.
    Fail,
}

impl CheckStatus {
    fn tag(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Warn => "warn",
            Self::Fail => "FAIL",
        }
    }
}

/// One host check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    /// Short name (`kvm`, `arch`, `engine`, ...).
    pub name: String,
    /// The outcome.
    pub status: CheckStatus,
    /// What was found and what to do about it.
    pub detail: String,
}

/// How a download is verified (always fail-closed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verify {
    /// Against a sha256 pin (hex).
    Sha256(String),
    /// Against the `sha512sum`-style sidecar at this URL.
    Sha512Sidecar(String),
}

/// One step of a plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// Download `url` into the staging directory as `name`, verified.
    Download {
        /// Source URL.
        url: String,
        /// File name in the staging directory.
        name: String,
        /// Verification.
        verify: Verify,
    },
    /// Install the staged file `name` at `dest` with mode 0755.
    Install {
        /// Staged file name.
        name: String,
        /// Destination path.
        dest: PathBuf,
    },
    /// Symlink `link` to `target` (a containerd shim onto dockerd's PATH).
    Link {
        /// The installed binary.
        target: PathBuf,
        /// The link to create (replaced if present).
        link: PathBuf,
    },
    /// Write the merged Docker daemon configuration.
    WriteDaemonJson {
        /// The file.
        path: PathBuf,
        /// The full merged contents.
        content: String,
    },
    /// Apply a RuntimeClass with `kubectl apply -f -`.
    ApplyRuntimeClass {
        /// The manifest.
        manifest: String,
    },
    /// Something the operator does by hand (printed, never run).
    Manual {
        /// Instructions.
        text: String,
    },
}

/// A complete installation plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    /// What was asked for.
    pub request: Request,
    /// Host checks.
    pub checks: Vec<Check>,
    /// Steps, in order.
    pub steps: Vec<Step>,
    /// What to set as `host.runtime_class` in a Charter.
    pub runtime_class: String,
    /// Whether privileged writes can be made directly.
    pub root: bool,
}

impl Plan {
    /// Reports whether a check failed, so [`apply`] would refuse.
    pub fn blocked(&self) -> bool {
        self.checks.iter().any(|c| c.status == CheckStatus::Fail)
    }

    /// The dry-run text: header, checks, steps and next steps.
    pub fn render(&self) -> String {
        let mut w = String::new();
        let title = format!(
            "{} -> {}",
            self.request.runtime.label(),
            match self.request.engine {
                Engine::Docker => "Docker",
                Engine::Podman => "Podman",
                Engine::K8s => "Kubernetes RuntimeClass",
            }
        );
        let _ = writeln!(w, "{title}\n{}\n", "=".repeat(title.len()));
        if !self.checks.is_empty() {
            let _ = writeln!(w, "Host checks:");
            for c in &self.checks {
                let _ = writeln!(w, "  [{}] {}: {}", c.status.tag(), c.name, c.detail);
            }
            let _ = writeln!(w);
        }
        let _ = writeln!(w, "Plan:");
        for (i, s) in self.steps.iter().enumerate() {
            let n = i + 1;
            match s {
                Step::Download { url, verify, .. } => {
                    let how = match verify {
                        Verify::Sha256(h) => format!("sha256 pin {}", short_hex(h)),
                        Verify::Sha512Sidecar(_) => "+ .sha512".to_owned(),
                    };
                    let _ = writeln!(w, "  {n}. Download + checksum-verify {url} ({how})");
                }
                Step::Install { name, dest } => {
                    let _ = writeln!(
                        w,
                        "  {n}. chmod 0755 and install {name} at {}",
                        dest.display()
                    );
                }
                Step::Link { target, link } => {
                    let _ = writeln!(
                        w,
                        "  {n}. Link {} -> {} (dockerd/containerd find shims on PATH; no daemon.json change)",
                        link.display(),
                        target.display()
                    );
                }
                Step::WriteDaemonJson { path, content } => {
                    let _ = writeln!(
                        w,
                        "  {n}. Merge into {} (existing keys preserved), then restart the engine (systemctl restart docker):",
                        path.display()
                    );
                    for line in content.lines() {
                        let _ = writeln!(w, "       {line}");
                    }
                }
                Step::ApplyRuntimeClass { manifest } => {
                    let _ = writeln!(w, "  {n}. kubectl apply -f - <<'EOF'");
                    for line in manifest.lines() {
                        let _ = writeln!(w, "       {line}");
                    }
                    let _ = writeln!(w, "     EOF");
                }
                Step::Manual { text } => {
                    let mut lines = text.lines();
                    let _ = writeln!(w, "  {n}. (manual) {}", lines.next().unwrap_or(""));
                    for line in lines {
                        let _ = writeln!(w, "       {line}");
                    }
                }
            }
        }
        let _ = writeln!(w);
        if self.blocked() {
            let _ = writeln!(
                w,
                "Blocked: fix the failing checks above; --apply refuses this plan."
            );
        } else {
            let _ = writeln!(
                w,
                "Dry-run (default): nothing above was executed.\nRe-run with --apply to perform these steps."
            );
        }
        w.push_str(&next_steps(&self.runtime_class));
        w
    }
}

fn next_steps(class: &str) -> String {
    format!(
        "\nNext steps\n----------\n  1. Set runtime_class = {class:?} under [host] in your Charter.\n  2. Verify with: runeward runtime check (the sandbox's tier comes from in-sandbox evidence)\n  3. Details: docs/isolation.md\n"
    )
}

fn short_hex(h: &str) -> String {
    if h.len() > 12 {
        format!("{}...", &h[..12])
    } else {
        h.to_owned()
    }
}

/// Maps a Rust target arch to the gVisor bucket's arch directory.
pub fn gvisor_arch(arch: &str) -> std::result::Result<&'static str, String> {
    match arch {
        "x86_64" | "amd64" => Ok("x86_64"),
        "aarch64" | "arm64" => Ok("arm64"),
        other => Err(format!(
            "unsupported architecture {other:?}: gVisor publishes amd64 (x86_64) and arm64 builds"
        )),
    }
}

/// The minimal RuntimeClass manifest the Go installer printed.
pub fn runtime_class_manifest(name: &str, handler: &str) -> String {
    format!(
        "apiVersion: node.k8s.io/v1\nkind: RuntimeClass\nmetadata:\n  name: {name}\nhandler: {handler}\n"
    )
}

/// The RuntimeClass object for `runtime` named `name`. Kata with
/// Firecracker carries kata-deploy's pod overhead and node selector.
pub fn runtime_class_object(runtime: VmRuntime, name: &str) -> RuntimeClass {
    let mut rc = RuntimeClass {
        metadata: ObjectMeta {
            name: Some(name.to_owned()),
            ..ObjectMeta::default()
        },
        handler: runtime.handler().to_owned(),
        ..RuntimeClass::default()
    };
    if runtime == VmRuntime::KataFc {
        rc.overhead = Some(Overhead {
            pod_fixed: Some(BTreeMap::from([
                ("memory".to_owned(), Quantity("130Mi".into())),
                ("cpu".to_owned(), Quantity("250m".into())),
            ])),
        });
        rc.scheduling = Some(Scheduling {
            node_selector: Some(BTreeMap::from([(
                "katacontainers.io/kata-runtime".to_owned(),
                "true".to_owned(),
            )])),
            tolerations: None,
        });
    }
    rc
}

/// Renders [`runtime_class_object`] as a manifest (YAML for the Go-parity
/// minimal classes, JSON, which kubectl also accepts, otherwise).
pub fn runtime_class_document(runtime: VmRuntime, name: &str) -> String {
    let rc = runtime_class_object(runtime, name);
    if rc.overhead.is_none() && rc.scheduling.is_none() {
        return runtime_class_manifest(name, &rc.handler);
    }
    let mut v = serde_json::to_value(&rc).unwrap_or_default();
    if let Some(o) = v.as_object_mut() {
        o.insert("apiVersion".into(), "node.k8s.io/v1".into());
        o.insert("kind".into(), "RuntimeClass".into());
    }
    let mut s = serde_json::to_string_pretty(&v).unwrap_or_default();
    s.push('\n');
    s
}

/// Merges one runtime entry into a daemon.json document, keeping every other
/// key and runtime. `existing` is the current file (`None` when absent).
pub fn merge_docker_runtime(
    existing: Option<&str>,
    name: &str,
    entry: serde_json::Value,
) -> std::result::Result<String, String> {
    let mut top = match existing.map(str::trim) {
        Some(s) if !s.is_empty() => match serde_json::from_str::<serde_json::Value>(s) {
            Ok(serde_json::Value::Object(m)) => m,
            Ok(_) => return Err(format!("parse {DOCKER_DAEMON_JSON}: not a JSON object")),
            Err(e) => return Err(format!("parse {DOCKER_DAEMON_JSON}: {e}")),
        },
        _ => serde_json::Map::new(),
    };
    let runtimes = top
        .entry("runtimes")
        .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
    let Some(runtimes) = runtimes.as_object_mut() else {
        return Err(format!(
            "parse runtimes in {DOCKER_DAEMON_JSON}: not a JSON object"
        ));
    };
    runtimes.insert(name.to_owned(), entry);
    serde_json::to_string_pretty(&top).map_err(|e| e.to_string())
}

/// Builds the plan for `req` on a host described by `facts`.
pub fn plan(req: &Request, facts: &HostFacts) -> Plan {
    let mut p = Plan {
        request: req.clone(),
        checks: Vec::new(),
        steps: Vec::new(),
        runtime_class: match req.engine {
            Engine::K8s => req.class().to_owned(),
            _ => req.runtime.engine_name().to_owned(),
        },
        root: facts.root,
    };
    match req.engine {
        Engine::K8s => plan_k8s(req, facts, &mut p),
        Engine::Docker | Engine::Podman => {
            host_checks(req, facts, &mut p.checks);
            match req.runtime {
                VmRuntime::Gvisor => plan_gvisor(req, facts, &mut p),
                VmRuntime::Kata | VmRuntime::KataFc => plan_kata(req, facts, &mut p),
                VmRuntime::Krun => plan_krun(req, facts, &mut p),
            }
        }
    }
    p
}

fn check(out: &mut Vec<Check>, name: &str, status: CheckStatus, detail: impl Into<String>) {
    out.push(Check {
        name: name.to_owned(),
        status,
        detail: detail.into(),
    });
}

/// Checks for a local engine: OS, desktop engines, KVM and nesting.
fn host_checks(req: &Request, facts: &HostFacts, out: &mut Vec<Check>) {
    let engine = req.engine.as_str();
    if facts.os != "linux" {
        check(
            out,
            "os",
            CheckStatus::Fail,
            format!(
                "{} runs {engine} containers inside a Linux VM; install the runtime inside that VM or on a Linux host",
                facts.os
            ),
        );
    }
    let desktop = ["Docker Desktop", "OrbStack"]
        .into_iter()
        .find(|d| facts.engine_os.contains(d));
    if let Some(d) = desktop {
        let status = if req.runtime.needs_kvm() {
            CheckStatus::Fail
        } else {
            CheckStatus::Warn
        };
        check(
            out,
            "engine",
            status,
            format!(
                "{d} runs containers in its own VM without nested virtualisation; {} cannot be registered there{}",
                req.runtime.label(),
                if req.runtime.needs_kvm() {
                    " (nested VM runtimes are unavailable)"
                } else {
                    ""
                }
            ),
        );
    } else if !facts.engine_reachable {
        check(
            out,
            "engine",
            CheckStatus::Warn,
            format!("{engine} engine not reachable; registration cannot be verified"),
        );
    }
    if facts
        .registered
        .iter()
        .any(|r| r == req.runtime.engine_name())
    {
        check(
            out,
            "registered",
            CheckStatus::Ok,
            format!(
                "{engine} already lists runtime {:?}; the steps below are idempotent",
                req.runtime.engine_name()
            ),
        );
    }
    if !req.runtime.needs_kvm() {
        check(
            out,
            "kvm",
            CheckStatus::Ok,
            format!(
                "{} does not need /dev/kvm (systrap platform)",
                req.runtime.label()
            ),
        );
        return;
    }
    match facts.kvm {
        KvmAccess::Missing => check(
            out,
            "kvm",
            CheckStatus::Fail,
            if facts.virtualised {
                "/dev/kvm is missing and this host is itself a VM: enable nested virtualisation on the hypervisor (or use a bare-metal / nested-capable instance), then load kvm_intel or kvm_amd"
            } else {
                "/dev/kvm is missing: enable VT-x/AMD-V in firmware and load kvm_intel or kvm_amd (modprobe kvm_intel)"
            },
        ),
        KvmAccess::NoPermission => check(
            out,
            "kvm",
            CheckStatus::Warn,
            "/dev/kvm exists but this user cannot open it; a root engine is fine, rootless Podman needs the user in the kvm group (usermod -aG kvm $USER)",
        ),
        KvmAccess::Usable => check(out, "kvm", CheckStatus::Ok, "/dev/kvm is usable"),
    }
    if facts.virtualised {
        match facts.nested {
            Some(true) => check(
                out,
                "nested",
                CheckStatus::Ok,
                "this host is a VM with nested virtualisation enabled",
            ),
            Some(false) => check(
                out,
                "nested",
                CheckStatus::Warn,
                "this host is a VM and the kvm module reports nested=N; guests may fail to start",
            ),
            None => check(
                out,
                "nested",
                CheckStatus::Warn,
                "this host is a VM; nested virtualisation could not be confirmed",
            ),
        }
    }
}

fn plan_gvisor(req: &Request, facts: &HostFacts, p: &mut Plan) {
    let arch = match gvisor_arch(&facts.arch) {
        Ok(a) => a,
        Err(e) => {
            check(&mut p.checks, "arch", CheckStatus::Fail, e);
            return;
        }
    };
    let base = format!(
        "{}/{}/{arch}",
        non_empty(req.release_base.trim_end_matches('/'), GVISOR_RELEASE_BASE),
        req.version()
    );
    let bin = req.bin_dir();
    for name in ["runsc", "containerd-shim-runsc-v1"] {
        let url = format!("{base}/{name}");
        let pin = req.sha256.trim().to_ascii_lowercase();
        let verify = if name == "runsc" && !pin.is_empty() {
            Verify::Sha256(pin)
        } else {
            Verify::Sha512Sidecar(format!("{url}.sha512"))
        };
        p.steps.push(Step::Download {
            url,
            name: name.to_owned(),
            verify,
        });
    }
    for name in ["runsc", "containerd-shim-runsc-v1"] {
        p.steps.push(Step::Install {
            name: name.to_owned(),
            dest: bin.join(name),
        });
    }
    match req.engine {
        Engine::Docker => {
            let entry = serde_json::json!({ "path": bin.join("runsc").to_string_lossy() });
            daemon_step(req, facts, p, "runsc", entry);
        }
        _ => p.steps.push(Step::Manual {
            text: format!(
                "Podman finds runsc in {} through containers.conf [engine.runtimes]; run with --runtime runsc.",
                bin.display()
            ),
        }),
    }
}

fn daemon_step(
    req: &Request,
    facts: &HostFacts,
    p: &mut Plan,
    name: &str,
    entry: serde_json::Value,
) {
    match merge_docker_runtime(facts.daemon_json.as_deref(), name, entry) {
        Ok(content) => p.steps.push(Step::WriteDaemonJson {
            path: req.daemon_json(),
            content,
        }),
        Err(e) => check(&mut p.checks, "daemon.json", CheckStatus::Fail, e),
    }
}

fn kata_shim(facts: &HostFacts) -> Option<&PathBuf> {
    facts.binaries.get("containerd-shim-kata-v2")
}

/// The hypervisors a Kata install can be pointed at for Docker/Podman.
pub const KATA_HYPERVISORS: &[&str] = &["qemu", "clh"];

/// The containerd runtime type Docker is given for Kata with `hypervisor`
/// (`io.containerd.kata.v2` when empty).
pub fn kata_runtime_type(hypervisor: &str) -> String {
    if hypervisor.is_empty() {
        "io.containerd.kata.v2".to_owned()
    } else {
        format!("io.containerd.kata-{hypervisor}.v2")
    }
}

/// The shim binary containerd looks up for [`kata_runtime_type`].
pub fn kata_shim_name(hypervisor: &str) -> String {
    if hypervisor.is_empty() {
        "containerd-shim-kata-v2".to_owned()
    } else {
        format!("containerd-shim-kata-{hypervisor}-v2")
    }
}

fn plan_kata(req: &Request, facts: &HostFacts, p: &mut Plan) {
    if req.runtime == VmRuntime::KataFc {
        // Observed on a KVM host with Kata 4.2.0 under Docker: "share fs is
        // unavailable" (no virtio-fs/9p) and, with a network, "add net
        // device: After 500 attempts" (no hot-plug).
        check(
            &mut p.checks,
            "engine",
            CheckStatus::Fail,
            format!(
                "Kata with Firecracker cannot run under {}: Firecracker has no shared filesystem and no device hot-plug, so it needs containerd with the devmapper snapshotter (use --engine k8s) or a native Firecracker driver; use kata (qemu or clh) or krun with this engine",
                req.engine.as_str()
            ),
        );
        return;
    }
    let hv = req.hypervisor.trim().to_ascii_lowercase();
    if !hv.is_empty() && !KATA_HYPERVISORS.contains(&hv.as_str()) {
        check(
            &mut p.checks,
            "hypervisor",
            CheckStatus::Fail,
            format!("unknown Kata hypervisor {hv:?}: expected one of {KATA_HYPERVISORS:?}"),
        );
        return;
    }
    p.steps.push(Step::Manual {
        text: "Install Kata Containers (distribution-specific, not automated here): the static release\nbundle in /opt/kata or your distribution's packages, see https://github.com/kata-containers/kata-containers/tree/main/docs/install".to_owned(),
    });
    let shim = kata_shim(facts);
    let legacy = facts.binaries.get("kata-runtime");
    if shim.is_none() && legacy.is_none() {
        check(
            &mut p.checks,
            "kata",
            CheckStatus::Fail,
            "Kata not found (looked for containerd-shim-kata-v2, including /opt/kata/runtime-rs/bin, and kata-runtime); install it first, then re-run",
        );
    }
    // Kata 4's runtime-rs shim ignores its own name when picking the
    // hypervisor: it loads the first runtime-rs/configuration.toml it finds.
    check(
        &mut p.checks,
        "hypervisor-config",
        CheckStatus::Warn,
        "Kata's runtime-rs shim chooses the hypervisor from runtime-rs/configuration.toml (first of /etc/kata-containers, /usr/share/defaults/kata-containers, /opt/kata/share/defaults/kata-containers), not from the runtime name; the sandbox's evidence records the hypervisor that really ran",
    );
    if !hv.is_empty() {
        p.steps.push(Step::Manual {
            text: format!(
                "Point /etc/kata-containers/runtime-rs/configuration.toml at the {hv} configuration shipped in\n/opt/kata/share/defaults/kata-containers/runtime-rs/ (a symlink); KATA_CONF_FILE is only honoured for those same paths."
            ),
        });
    }
    match (req.engine, shim, legacy) {
        (Engine::Docker, Some(shim), _) => {
            // Docker runs containerd shims by runtime type: no daemon.json
            // change, only the shim on dockerd's PATH.
            let link = req.bin_dir().join(kata_shim_name(&hv));
            p.runtime_class = kata_runtime_type(&hv);
            if shim != &link {
                p.steps.push(Step::Link {
                    target: shim.clone(),
                    link,
                });
            }
        }
        (Engine::Docker, None, Some(path)) => {
            // A legacy kata-runtime is an OCI runtime registered by path.
            let entry = serde_json::json!({ "path": path.to_string_lossy() });
            daemon_step(req, facts, p, "kata", entry);
        }
        (Engine::Docker, None, None) => {
            p.runtime_class = kata_runtime_type(&hv);
        }
        _ => {
            check(
                &mut p.checks,
                "podman",
                CheckStatus::Warn,
                "Podman drives OCI runtimes directly and needs a kata-runtime compatible binary; containerd-based Kata support is limited",
            );
            p.steps.push(Step::Manual {
                text: "Register the binary under [engine.runtimes] in containers.conf, e.g.\nkata = [\"/usr/bin/kata-runtime\"]\nthen run with --runtime kata.".to_owned(),
            });
        }
    }
}

fn plan_krun(req: &Request, facts: &HostFacts, p: &mut Plan) {
    check(
        &mut p.checks,
        "tested",
        CheckStatus::Warn,
        "krun has not been verified on a real KVM host by Rune Box yet; the sandbox's evidence decides its tier",
    );
    let krun = facts.binaries.get("krun");
    if krun.is_none() {
        check(
            &mut p.checks,
            "krun",
            CheckStatus::Fail,
            "krun not found: install crun built with libkrun (Fedora/CentOS Stream: dnf install crun-krun; elsewhere build libkrunfw, libkrun and crun --with-libkrun), then re-run",
        );
        p.steps.push(Step::Manual {
            text: "Install crun with libkrun: dnf install crun-krun (Fedora/CentOS Stream), or build\nlibkrunfw + libkrun and configure crun with --with-libkrun; it provides /usr/bin/krun.".to_owned(),
        });
    }
    let path = krun
        .cloned()
        .unwrap_or_else(|| PathBuf::from("/usr/bin/krun"));
    match req.engine {
        Engine::Docker => {
            let entry = serde_json::json!({ "path": path.to_string_lossy() });
            daemon_step(req, facts, p, "krun", entry);
        }
        _ => p.steps.push(Step::Manual {
            text: "Podman knows krun by name (containers.conf [engine.runtimes] krun); run with --runtime krun.".to_owned(),
        }),
    }
}

fn plan_k8s(req: &Request, facts: &HostFacts, p: &mut Plan) {
    let class = req.class().to_owned();
    if req.runtime.needs_kvm() {
        check(
            &mut p.checks,
            "nodes",
            CheckStatus::Warn,
            "the nodes that run these pods need /dev/kvm (bare metal or nested virtualisation); this host is not checked",
        );
    }
    if req.runtime == VmRuntime::KataFc {
        check(
            &mut p.checks,
            "kata-fc-config",
            CheckStatus::Warn,
            "Kata 4.2.0 ships an invalid runtime-rs configuration-rs-fc.toml (dial_timeout_ms = 45000 without reconnect_timeout_ms fails validation); set dial_timeout_ms = 10 and reconnect_timeout_ms = 45000 on the nodes",
        );
    }
    if !facts.binaries.contains_key("kubectl") {
        check(
            &mut p.checks,
            "kubectl",
            CheckStatus::Warn,
            "kubectl not found in PATH; apply the manifest by hand",
        );
    }
    if facts.registered.iter().any(|r| r == &class) {
        check(
            &mut p.checks,
            "registered",
            CheckStatus::Ok,
            format!("RuntimeClass {class:?} already exists; apply updates it"),
        );
    }
    let node_setup = match req.runtime {
        VmRuntime::Gvisor => {
            "Install runsc and containerd-shim-runsc-v1 on each node and add to containerd's config:\n[plugins.\"io.containerd.grpc.v1.cri\".containerd.runtimes.runsc]\n  runtime_type = \"io.containerd.runsc.v1\"".to_owned()
        }
        VmRuntime::Kata | VmRuntime::KataFc => format!(
            "Install Kata on the nodes with kata-deploy (Kata Containers install docs); it registers\nthe containerd handler {:?} and labels nodes katacontainers.io/kata-runtime=true.{}",
            req.runtime.handler(),
            if req.runtime == VmRuntime::KataFc {
                "\nkata-fc also needs containerd's devmapper snapshotter on those nodes."
            } else {
                ""
            }
        ),
        VmRuntime::Krun => "Install crun with libkrun (krun) on each node and register the handler, for CRI-O:\n[crio.runtime.runtimes.krun]\n  runtime_path = \"/usr/bin/krun\"\n  runtime_type = \"oci\"\nor for containerd:\n[plugins.\"io.containerd.grpc.v1.cri\".containerd.runtimes.krun]\n  runtime_type = \"io.containerd.runc.v2\"\n  [plugins.\"io.containerd.grpc.v1.cri\".containerd.runtimes.krun.options]\n    BinaryName = \"/usr/bin/krun\"".to_owned(),
    };
    p.steps.push(Step::Manual { text: node_setup });
    p.steps.push(Step::ApplyRuntimeClass {
        manifest: runtime_class_document(req.runtime, &class),
    });
}

/// Gathers [`HostFacts`] for `engine` on this machine. Every probe is
/// bounded and best-effort; missing tools leave fields empty.
pub async fn probe_host(engine: Engine) -> HostFacts {
    let mut f = HostFacts {
        os: std::env::consts::OS.to_owned(),
        arch: std::env::consts::ARCH.to_owned(),
        ..HostFacts::default()
    };
    f.root = run_capture("id", &["-u"])
        .await
        .is_some_and(|s| s.trim() == "0");
    f.kvm = kvm_access(Path::new("/dev/kvm"));
    f.virtualised = std::fs::read_to_string("/proc/cpuinfo").is_ok_and(|c| {
        c.lines()
            .any(|l| l.starts_with("flags") && l.split_whitespace().any(|w| w == "hypervisor"))
    });
    f.nested = ["kvm_intel", "kvm_amd"].iter().find_map(|m| {
        std::fs::read_to_string(format!("/sys/module/{m}/parameters/nested"))
            .ok()
            .map(|v| matches!(v.trim(), "Y" | "y" | "1"))
    });
    for name in [
        "runsc",
        "containerd-shim-runsc-v1",
        "containerd-shim-kata-v2",
        "kata-runtime",
        "krun",
        "kubectl",
    ] {
        let found = crate::factory::look_path(name).or_else(|| {
            [
                "/usr/bin",
                "/usr/local/bin",
                "/opt/kata/runtime-rs/bin",
                "/opt/kata/bin",
            ]
            .iter()
            .map(|d| Path::new(d).join(name))
            .find(|p| p.is_file())
        });
        if let Some(p) = found {
            f.binaries.insert(name.to_owned(), p);
        }
    }
    for (key, file) in [
        ("fc", "configuration-fc.toml"),
        ("qemu", "configuration-qemu.toml"),
        ("clh", "configuration-clh.toml"),
    ] {
        if let Some(p) = KATA_CONFIG_DIRS
            .iter()
            .map(|d| Path::new(d).join(file))
            .find(|p| p.is_file())
        {
            f.kata_configs.insert(key.to_owned(), p);
        }
    }
    match engine {
        Engine::Docker => {
            if let Some(out) = run_capture(
                "docker",
                &[
                    "info",
                    "--format",
                    "{{.OperatingSystem}}|{{json .Runtimes}}",
                ],
            )
            .await
            {
                f.engine_reachable = true;
                let (os, runtimes) = out.trim().split_once('|').unwrap_or((out.trim(), "{}"));
                f.engine_os = os.to_owned();
                if let Ok(serde_json::Value::Object(m)) = serde_json::from_str(runtimes) {
                    f.registered = m.keys().cloned().collect();
                }
            }
            f.daemon_json = std::fs::read_to_string(DOCKER_DAEMON_JSON).ok();
        }
        Engine::Podman => {
            if let Some(out) = run_capture(
                "podman",
                &["info", "--format", "{{.Host.Distribution.Distribution}}"],
            )
            .await
            {
                f.engine_reachable = true;
                f.engine_os = out.trim().to_owned();
            }
        }
        Engine::K8s => {
            if let Some(out) = run_capture("kubectl", &["get", "runtimeclass", "-o", "name"]).await
            {
                f.engine_reachable = true;
                f.registered = out
                    .lines()
                    .map(|l| l.trim())
                    .filter(|l| !l.is_empty())
                    .map(|l| l.rsplit('/').next().unwrap_or(l).to_owned())
                    .collect();
            }
        }
    }
    f
}

fn kvm_access(dev: &Path) -> KvmAccess {
    if !dev.exists() {
        return KvmAccess::Missing;
    }
    match std::fs::OpenOptions::new().read(true).write(true).open(dev) {
        Ok(_) => KvmAccess::Usable,
        Err(_) => KvmAccess::NoPermission,
    }
}

/// Runs a command with a short timeout and returns stdout on success.
async fn run_capture(bin: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(bin)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .output();
    match tokio::time::timeout(PROBE_TIMEOUT, out).await {
        Ok(Ok(o)) if o.status.success() => Some(String::from_utf8_lossy(&o.stdout).into_owned()),
        _ => None,
    }
}

/// Performs a plan and returns what was done, line by line. Privileged
/// writes happen only when the plan was made as root; otherwise binaries
/// are staged and verified, and the exact `sudo` commands are returned.
/// A plan with a failing check is refused.
pub async fn apply(plan: &Plan) -> Result<Vec<String>> {
    if plan.blocked() {
        let failed: Vec<String> = plan
            .checks
            .iter()
            .filter(|c| c.status == CheckStatus::Fail)
            .map(|c| format!("{}: {}", c.name, c.detail))
            .collect();
        return Err(BackendError::msg(format!(
            "refusing to apply: {}",
            failed.join("; ")
        )));
    }
    let mut log = Vec::new();
    let needs_staging = plan
        .steps
        .iter()
        .any(|s| matches!(s, Step::Download { .. }));
    let staging = if needs_staging {
        Some(
            tempfile::Builder::new()
                .prefix("runeward-runtime-")
                .tempdir()
                .map_err(|e| BackendError::io("create staging dir", e))?,
        )
    } else {
        None
    };
    let client = reqwest::Client::builder()
        .timeout(DOWNLOAD_TIMEOUT)
        .build()
        .map_err(|e| BackendError::msg(format!("http client: {e}")))?;
    for step in &plan.steps {
        match step {
            Step::Download { url, name, verify } => {
                let dir = staging
                    .as_ref()
                    .map(tempfile::TempDir::path)
                    .ok_or_else(|| {
                        BackendError::msg("no staging directory for download".to_owned())
                    })?;
                let dst = dir.join(name);
                download_verified(&client, url, &dst, verify, &mut log).await?;
            }
            Step::Install { name, dest } => {
                let dir = staging
                    .as_ref()
                    .map(tempfile::TempDir::path)
                    .ok_or_else(|| {
                        BackendError::msg("no staging directory for install".to_owned())
                    })?;
                let src = dir.join(name);
                set_executable(&src)?;
                if plan.root {
                    install_file(&src, dest)?;
                    log.push(format!("installed {}", dest.display()));
                } else {
                    log.push(format!(
                        "sudo install -m 0755 {} {}",
                        src.display(),
                        dest.display()
                    ));
                }
            }
            Step::Link { target, link } => {
                if plan.root {
                    link_file(target, link)?;
                    log.push(format!("linked {} -> {}", link.display(), target.display()));
                } else {
                    log.push(format!(
                        "sudo ln -sf {} {}",
                        target.display(),
                        link.display()
                    ));
                }
            }
            Step::WriteDaemonJson { path, content } => {
                if plan.root {
                    if let Some(parent) = path.parent() {
                        std::fs::create_dir_all(parent)
                            .map_err(|e| BackendError::io("create daemon.json dir", e))?;
                    }
                    std::fs::write(path, format!("{content}\n"))
                        .map_err(|e| BackendError::io("write daemon.json", e))?;
                    log.push(format!("wrote {}", path.display()));
                    log.push("restart the engine: systemctl restart docker".to_owned());
                } else {
                    log.push(format!(
                        "# not root: write the merged {} yourself:",
                        path.display()
                    ));
                    log.push(format!(
                        "sudo tee {} >/dev/null <<'EOF'\n{content}\nEOF",
                        path.display()
                    ));
                    log.push("sudo systemctl restart docker".to_owned());
                }
            }
            Step::ApplyRuntimeClass { manifest } => {
                log.extend(apply_manifest(manifest).await?);
            }
            Step::Manual { text } => log.push(format!("manual: {text}")),
        }
    }
    if let Some(dir) = staging
        && !plan.root
    {
        // Keep the verified binaries for the printed sudo commands.
        let kept = dir.keep();
        log.push(format!(
            "(remove the staging dir when done: rm -rf {})",
            kept.display()
        ));
    }
    log.push(next_steps(&plan.runtime_class));
    Ok(log)
}

async fn apply_manifest(manifest: &str) -> Result<Vec<String>> {
    let Some(kubectl) = crate::factory::look_path("kubectl") else {
        return Ok(vec![format!(
            "kubectl not found in PATH; apply the manifest by hand:\nkubectl apply -f - <<'EOF'\n{manifest}EOF"
        )]);
    };
    let mut child = Command::new(kubectl)
        .args(["apply", "-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| BackendError::msg(format!("kubectl apply: {e}")))?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(manifest.as_bytes())
            .await
            .map_err(|e| BackendError::io("kubectl stdin", e))?;
    }
    let out = tokio::time::timeout(APPLY_TIMEOUT, child.wait_with_output())
        .await
        .map_err(|_| BackendError::Timeout("kubectl apply timed out".into()))?
        .map_err(|e| BackendError::msg(format!("kubectl apply: {e}")))?;
    if !out.status.success() {
        let detail = String::from_utf8_lossy(&out.stderr);
        return Err(BackendError::msg(format!(
            "kubectl apply failed: {}",
            detail.lines().next().unwrap_or("").trim()
        )));
    }
    Ok(vec![String::from_utf8_lossy(&out.stdout).trim().to_owned()])
}

/// Downloads `url` to `dst` and verifies it, failing closed: a mismatch or
/// a missing sidecar removes the file and errors.
async fn download_verified(
    client: &reqwest::Client,
    url: &str,
    dst: &Path,
    verify: &Verify,
    log: &mut Vec<String>,
) -> Result<()> {
    http_get_to_file(client, url, dst)
        .await
        .map_err(|e| BackendError::msg(format!("download {url}: {e}")))?;
    let result: std::result::Result<String, String> = async {
        match verify {
            Verify::Sha256(want) => verify_digest::<Sha256>(dst, want)
                .map(|()| format!("sha256 {}", short_hex(want))),
            Verify::Sha512Sidecar(sidecar) => {
                let mut side = dst.as_os_str().to_owned();
                side.push(".sha512");
                let side = PathBuf::from(side);
                http_get_to_file(client, sidecar, &side).await.map_err(|e| {
                    format!(
                        "download checksum {sidecar}: {e} (refusing to install an unverified binary)"
                    )
                })?;
                let data = std::fs::read_to_string(&side).map_err(|e| e.to_string())?;
                let want = parse_checksum_sidecar(&data)?;
                verify_digest::<Sha512>(dst, &want)
                    .map(|()| format!("sha512 {}", short_hex(&want)))
            }
        }
    }
    .await;
    match result {
        Ok(how) => {
            let name = dst
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            log.push(format!("verified {name} ({how})"));
            Ok(())
        }
        Err(e) => {
            let _ = std::fs::remove_file(dst);
            Err(BackendError::msg(e))
        }
    }
}

async fn http_get_to_file(
    client: &reqwest::Client,
    url: &str,
    dst: &Path,
) -> std::result::Result<(), String> {
    let mut resp = client.get(url).send().await.map_err(|e| e.to_string())?;
    if resp.status() != reqwest::StatusCode::OK {
        return Err(format!("unexpected status {}", resp.status()));
    }
    let mut f = tokio::fs::File::create(dst)
        .await
        .map_err(|e| e.to_string())?;
    while let Some(chunk) = resp.chunk().await.map_err(|e| e.to_string())? {
        f.write_all(&chunk).await.map_err(|e| e.to_string())?;
    }
    f.flush().await.map_err(|e| e.to_string())
}

/// Extracts the digest from a `sha512sum`-style sidecar (`<hex>  <file>`).
pub fn parse_checksum_sidecar(data: &str) -> std::result::Result<String, String> {
    data.split_whitespace()
        .next()
        .filter(|h| !h.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| "empty or malformed checksum sidecar".to_owned())
}

/// Hashes `path` with `D` and compares (case-insensitively) with `want`.
fn verify_digest<D: Digest>(path: &Path, want: &str) -> std::result::Result<(), String> {
    let data = std::fs::read(path).map_err(|e| e.to_string())?;
    let got = hex::encode(D::digest(&data));
    if got.eq_ignore_ascii_case(want.trim()) {
        Ok(())
    } else {
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        Err(format!(
            "checksum mismatch for {name}: got {got}, want {} (failing closed)",
            want.trim()
        ))
    }
}

#[cfg(unix)]
fn set_executable(p: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o755))
        .map_err(|e| BackendError::io("chmod staged binary", e))
}

#[cfg(not(unix))]
fn set_executable(_: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn link_file(target: &Path, link: &Path) -> Result<()> {
    if let Some(parent) = link.parent() {
        std::fs::create_dir_all(parent).map_err(|e| BackendError::io("create bin dir", e))?;
    }
    if link.symlink_metadata().is_ok() {
        std::fs::remove_file(link).map_err(|e| BackendError::io("replace link", e))?;
    }
    std::os::unix::fs::symlink(target, link).map_err(|e| BackendError::io("create link", e))
}

#[cfg(not(unix))]
fn link_file(_: &Path, _: &Path) -> Result<()> {
    Err(BackendError::Unsupported(
        "symlinks need a Unix host".into(),
    ))
}

/// Moves `src` to `dst`, copying when they are on different filesystems.
fn install_file(src: &Path, dst: &Path) -> Result<()> {
    if let Some(parent) = dst.parent() {
        std::fs::create_dir_all(parent).map_err(|e| BackendError::io("create bin dir", e))?;
    }
    if std::fs::rename(src, dst).is_ok() {
        return Ok(());
    }
    std::fs::copy(src, dst).map_err(|e| BackendError::io("install binary", e))?;
    set_executable(dst)?;
    std::fs::remove_file(src).map_err(|e| BackendError::io("remove staged binary", e))
}

#[cfg(test)]
mod tests;
