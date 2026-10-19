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
//! New isolation drivers (libkrun or Firecracker microVMs, an in-sandbox
//! Landlock/seccomp supervisor) implement [`Backend`] and register a
//! [`Driver`] for their `host.type` in a [`Registry`]; see the trait docs for
//! the contract they must keep.
//!
//! Operator settings come from the same `RUNEWARD_*` variables as the Go
//! implementation, captured into a [`BackendConfig`].

mod backend;
mod capabilities;
pub mod config;
mod docker;
mod egress;
mod error;
mod export;
mod factory;
pub mod gotime;
mod isolation;
pub mod k8s;
mod pathutil;
mod seed;
mod streams;
mod types;
mod validate;

pub use backend::{Backend, Reachable, restore_snapshot};
pub use capabilities::{charter_capabilities, verify_runtime_capabilities};
pub use config::BackendConfig;
pub use docker::{Docker, egress_container_name};
pub use egress::{policy_from_network, proxy_env};
pub use error::{BackendError, Result};
pub use export::{detect, export, export_to_dir};
pub use factory::{
    ContainerDriver, Driver, K8sDriver, Registry, for_charter, look_path, resources_from_limits,
    select_container_runtime, spec_from_charter,
};
pub use isolation::{IsolationTier, classify_runtime};
pub use k8s::K8s;
pub use pathutil::expand_home;
pub use seed::{
    extract_tar, filter_tar_safe, hash_file, tar_entry_safe, verify_snapshot, write_dir_tar,
};
pub use types::{
    BoxReader, BoxWriter, ExecRequest, ExecResult, PtyStream, Resources, Sandbox, SnapshotRef,
    Spec, TermSize, go_zero_time,
};
pub use validate::{
    validate_env_name, validate_file_mode, validate_projection_path, validate_seed_dir,
    validate_strict_egress_user,
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
