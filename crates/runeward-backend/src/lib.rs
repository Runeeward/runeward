//! Sandbox runtime backends for Rune Box.
//!
//! A [`Backend`] provisions and controls sandboxes for one execution host so
//! callers do not care whether a sandbox is a container, a Kubernetes Pod or
//! (later) a microVM. Every backend works from the same runtime-neutral
//! [`Spec`] and reports the [`IsolationTier`] each sandbox actually got.
//!
//! Built in:
//!
//! - [`Docker`] (Docker or Podman): drives the CLI exactly as the Go
//!   implementation does. Strict egress runs a transparent-proxy sidecar
//!   whose network namespace the sandbox joins; cooperative egress serves an
//!   authenticated in-process proxy reached via `host.docker.internal`.
//! - [`K8s`]: one Pod plus a workspace PVC per sandbox, Pod Security
//!   Admission labels on the namespace, an optional default-deny
//!   NetworkPolicy, egress sidecar (and iptables init container in strict
//!   mode), RuntimeClass and seccomp/AppArmor; exec and TTY attach over the
//!   WebSocket API.
//!
//! A [`Spec`] can also carry the Charter's request broker
//! ([`Spec::broker`]) and an in-sandbox supervisor plan
//! ([`Spec::supervisor`]); [`incell`] has the paths and helpers both
//! backends share. Both run the agent and every governed exec under
//! `runeward-supervisor`: Docker/Podman from the sandbox image, Kubernetes
//! from the egress image through an init container. Kubernetes runs the
//! broker in its egress sidecar.
//!
//! - [`MicroVm`] (`host.type = "microvm"`, Unix): Firecracker or libkrun
//!   booted directly, one VM per sandbox, from the Charter's OCI image
//!   converted to a read-only ext4 disk; the `runeward-vmagent` guest agent
//!   serves exec, files and the isolation probe over vsock, the workspace is
//!   a per-sandbox disk image, and the guest has no network device: egress
//!   goes through the Charter's proxy over vsock.
//!
//! microVM isolation is also available through OCI runtimes on the
//! container backends (Kata with QEMU, Cloud Hypervisor or Firecracker);
//! every sandbox's tier is derived from in-sandbox [`evidence`], never from
//! the runtime name alone. [`runtime_install`] plans and applies runtime
//! installation.
//!
//! Operator settings come from the same `RUNEWARD_*` variables as the Go
//! implementation, captured into a [`BackendConfig`].

mod backend;
mod capabilities;
pub mod config;
mod docker;
mod egress;
mod error;
pub mod evidence;
mod export;
mod factory;
pub mod gotime;
pub mod incell;
mod isolation;
pub mod k8s;
#[cfg(unix)]
mod microvm;
mod pathutil;
pub mod runtime_install;
mod seed;
mod streams;
mod types;
mod validate;
mod vmsize;

pub use backend::{Backend, Reachable, restore_snapshot};
pub use capabilities::{charter_capabilities, verify_runtime_capabilities};
pub use config::BackendConfig;
pub use docker::{Docker, egress_container_name};
pub use egress::{policy_from_network, proxy_env};
pub use error::{BackendError, Result};
pub use evidence::{Assessment, IsolationEvidence};
pub use export::{detect, export, export_to_dir};
pub use factory::{
    ContainerDriver, Driver, K8sDriver, MICROVM_HOST_TYPE, Registry, for_charter, look_path,
    resources_from_limits, select_container_runtime, spec_from_charter,
};
pub use isolation::{IsolationTier, classify_runtime, runtime_ceiling};
pub use k8s::K8s;
#[cfg(unix)]
pub use microvm::{MICROVM_BACKEND, MicroVm, MicroVmDriver};
pub use pathutil::expand_home;
pub use seed::{
    extract_tar, filter_tar_safe, hash_file, tar_entry_safe, verify_snapshot, write_dir_tar,
};
pub use types::{
    BoxReader, BoxWriter, BrokerHandle, ExecRequest, ExecResult, PtyStream, Resources, Sandbox,
    SnapshotRef, Spec, SupervisorSpec, TermSize, go_zero_time,
};
pub use validate::{
    validate_env_name, validate_file_mode, validate_projection_path, validate_sandbox_id,
    validate_seed_dir, validate_strict_egress_user,
};

/// Label marking every object Rune Box manages.
pub const LABEL_MANAGED: &str = "runeward.managed";
/// Label carrying the Charter name.
pub const LABEL_PROFILE: &str = "runeward.profile";
/// Label carrying the sandbox id.
pub const LABEL_ID: &str = "runeward.id";
/// Label naming a container's workspace volume.
pub const LABEL_VOLUME: &str = "runeward.volume";

/// The container (or pod) name for a sandbox id.
pub fn container_name(id: &str) -> String {
    format!("runeward-{id}")
}

/// The workspace volume (or PVC) name for a sandbox id.
pub fn volume_name(id: &str) -> String {
    format!("runeward-vol-{id}")
}

/// A fresh 128-bit hex id, unguessable even without authentication.
pub(crate) fn random_hex() -> String {
    hex::encode(rand::random::<[u8; 16]>())
}

/// The id for a new sandbox: the Spec's (validated) or a fresh one.
pub(crate) fn sandbox_id_for(spec: &Spec) -> Result<String> {
    if spec.id.is_empty() {
        Ok(random_hex())
    } else {
        validate_sandbox_id(&spec.id)?;
        Ok(spec.id.clone())
    }
}
