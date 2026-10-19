//! The [`Backend`] trait every sandbox driver implements.

use std::fmt;

use async_trait::async_trait;
use runeward_charter::File;
use tokio::io::AsyncWrite;

use crate::error::Result;
use crate::isolation::IsolationTier;
use crate::types::{ExecRequest, ExecResult, PtyStream, Sandbox, SnapshotRef, Spec};

/// Provisions and controls sandboxes for one execution host.
///
/// # Contract
///
/// - **Identity.** `create` returns a [`Sandbox`] whose `id` is an
///   unguessable 128-bit hex string ([`Spec::id`] when the caller chose
///   one); every other method addresses the sandbox by that id. Ids are scoped to the backend instance's host
///   (Docker engine, Kubernetes namespace, VM host).
/// - **Isolation.** `create` sets [`Sandbox::isolation`] to the tier the
///   sandbox really got, derived from the Spec and the backend's startup
///   self-check; it never reports a tier it could not confirm.
///   [`Backend::isolation_tier`] is the tier a Spec with no `runtime_class`
///   gets.
/// - **Hardening is not optional.** Security fields in [`Spec`] (read-only
///   root, seccomp, AppArmor, egress policy, resource caps) are applied or
///   the create fails with [`crate::BackendError::Unsupported`]; a driver
///   never silently drops one. Egress with `default = "deny"` must be
///   enforced before the workload can send traffic.
/// - **Failure is atomic.** A failed `create` removes everything it made
///   (volumes, sidecars, proxies) before returning.
/// - **In-sandbox governance.** [`Spec::broker`] is put in the egress path
///   with its CA trusted inside the sandbox, and [`Spec::supervisor`] runs
///   the agent and every `exec`/`attach_pty` under the supervisor, or the
///   create fails (a non-required supervisor may be skipped, and then
///   [`Backend::supervisor_report`] returns `None`).
/// - **Exec.** argv is executed directly, never via a shell. A non-zero exit
///   is a successful call with [`ExecResult::exit_code`] set; errors mean
///   the command could not be run (or timed out).
/// - **Workspace I/O** is a tar stream of the workspace directory's contents
///   with relative paths. Inbound archives are sanitized host-side (no
///   absolute paths, `..` or escaping symlinks) before reaching the sandbox.
/// - **Cancellation.** Dropping a returned future cancels the operation and
///   kills any helper process it started.
/// - **No runtime-specific types** cross this boundary, so container,
///   Kubernetes and microVM (libkrun, Firecracker) drivers, or a process
///   supervisor (Landlock/seccomp), all fit the same trait.
#[async_trait]
pub trait Backend: Send + Sync + fmt::Debug {
    /// Short backend name (`docker`, `podman`, `k8s`, ...).
    fn name(&self) -> &str;

    /// The isolation tier a sandbox gets when its Spec does not request a
    /// specific runtime.
    fn isolation_tier(&self) -> IsolationTier;

    /// Provisions a sandbox and waits until it is running.
    async fn create(&self, spec: Spec) -> Result<Sandbox>;

    /// Runs a one-shot command.
    async fn exec(&self, id: &str, req: ExecRequest) -> Result<ExecResult>;

    /// Attaches an interactive (optionally TTY) session until it exits.
    async fn attach_pty(&self, id: &str, stream: PtyStream) -> Result<()>;

    /// Projects files into the sandbox at their mode, owned by the sandbox
    /// user (root when the sandbox runs as root). Relative targets resolve
    /// against the workspace directory.
    async fn copy_files(&self, id: &str, files: &[File]) -> Result<()>;

    /// Streams a tar of the workspace contents to `w`.
    async fn export_workspace(
        &self,
        id: &str,
        w: &mut (dyn AsyncWrite + Send + Unpin),
    ) -> Result<()>;

    /// Captures the workspace into a host-side tarball.
    async fn snapshot(&self, id: &str, name: &str) -> Result<SnapshotRef>;

    /// Creates a new sandbox from a snapshot with a minimal Spec.
    async fn restore(&self, snapshot: &SnapshotRef) -> Result<Sandbox>;

    /// Creates a new sandbox from `spec` and restores the snapshot into it.
    /// The default ignores `spec` and calls [`Backend::restore`].
    async fn restore_with_spec(&self, snapshot: &SnapshotRef, spec: Spec) -> Result<Sandbox> {
        let _ = spec;
        self.restore(snapshot).await
    }

    /// Tears a sandbox down with everything created for it.
    async fn kill(&self, id: &str) -> Result<()>;

    /// Lists the sandboxes this backend manages.
    async fn list(&self) -> Result<Vec<Sandbox>>;

    /// Reports whether a sandbox with `id` exists on this backend.
    async fn exists(&self, id: &str) -> bool;

    /// The optional [`Reachable`] capability.
    fn reachable(&self) -> Option<&dyn Reachable> {
        None
    }

    /// The in-sandbox supervisor's enforcement report
    /// (`runeward.supervisor.report.v1` JSON lines, oldest first). `None`
    /// means the sandbox does not run under the supervisor; `Some("")`
    /// means it does but has not reported yet.
    async fn supervisor_report(&self, id: &str) -> Result<Option<String>> {
        let _ = id;
        Ok(None)
    }
}

/// Optional capability: resolve a sandbox's network address so the control
/// plane can reverse-proxy to an in-cell HTTP service (for example an IDE)
/// without publishing host ports.
#[async_trait]
pub trait Reachable: Send + Sync {
    /// The sandbox's IP on the backend network.
    async fn container_ip(&self, id: &str) -> Result<String>;
}

/// Restores a snapshot using the full Spec path when the backend supports it.
pub async fn restore_snapshot(
    be: &dyn Backend,
    snapshot: &SnapshotRef,
    spec: Spec,
) -> Result<Sandbox> {
    be.restore_with_spec(snapshot, spec).await
}
