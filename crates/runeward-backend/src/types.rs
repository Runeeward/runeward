//! Backend-agnostic descriptions of sandboxes and the operations on them.

use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, TimeZone, Utc};
use runeward_charter::{File, Network};
use runeward_egress::Broker;
use runeward_supervisor::SupervisorConfig;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;

use crate::evidence::IsolationEvidence;
use crate::isolation::IsolationTier;

/// A boxed async byte sink.
pub type BoxWriter = Box<dyn AsyncWrite + Send + Unpin>;
/// A boxed async byte source.
pub type BoxReader = Box<dyn AsyncRead + Send + Unpin>;

/// The resolved, backend-agnostic description of a sandbox to create.
///
/// Nothing here is specific to one runtime: container backends map the
/// security fields onto CLI flags or a PodSpec, VM drivers onto the guest
/// configuration, and a field a driver cannot honour must be rejected with
/// [`crate::BackendError::Unsupported`] rather than ignored.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Spec {
    /// A sandbox id chosen by the caller (32 lowercase hex characters), so
    /// per-sandbox state built before the sandbox exists (the request
    /// broker, its CA and placeholders) carries the final id. Empty lets
    /// the backend generate one. A backend must use it when set.
    pub id: String,
    /// Charter name, recorded as the `runeward.profile` label.
    pub profile: String,
    /// Image reference; empty selects the backend default.
    pub image: String,
    /// Workspace directory; empty means `/workspace`.
    pub workdir: String,
    /// User (`uid[:gid]` or a name) the keep-alive process runs as.
    pub user: String,
    /// Keep-alive entrypoint; empty means `sleep infinity`.
    pub command: Vec<String>,
    /// Environment, already resolved to literals.
    pub env: BTreeMap<String, String>,
    /// Extra labels attached to the sandbox.
    pub labels: BTreeMap<String, String>,
    /// Files projected into the sandbox after creation.
    pub files: Vec<File>,
    /// Host directory copied (never mounted) into the workspace.
    pub seed_dir: Option<PathBuf>,
    /// Egress policy.
    pub network: Network,
    /// Resource caps; zero fields fall back to operator defaults.
    pub resources: Resources,
    /// Sandboxed runtime (Docker `--runtime`, Kubernetes RuntimeClass).
    pub runtime_class: String,
    /// The workspace must outlive the sandbox (`[workspace] persist`): a
    /// backend refuses a sandbox whose workspace turns out not to be the
    /// volume it mounted (see [`crate::evidence::WORKSPACE_EPHEMERAL`]).
    pub persist_workspace: bool,
    /// Mounts the root filesystem read-only.
    pub read_only: bool,
    /// Seccomp profile path; empty means the runtime default.
    pub seccomp: String,
    /// AppArmor profile name.
    pub apparmor: String,
    /// When in `1..=65535`, an in-cell IDE listen port to make reachable.
    pub ide_port: i64,
    /// The request broker for the Charter's `[[endpoint]]`s and
    /// `[[credential]]`s. The backend puts it in the egress path (in
    /// process, or exported to its egress sidecar), installs its CA in the
    /// sandbox trust store and points the usual CA variables at a bundle of
    /// the image's roots plus the broker CA. Placeholders are already in
    /// `env`.
    pub broker: Option<BrokerHandle>,
    /// Runs the agent (and every exec) under `runeward-supervisor`.
    pub supervisor: Option<SupervisorSpec>,
}

/// A shared [`Broker`], compared by identity so [`Spec`] stays comparable.
#[derive(Clone)]
pub struct BrokerHandle(pub Arc<Broker>);

impl BrokerHandle {
    /// Wraps a broker.
    pub fn new(broker: Arc<Broker>) -> Self {
        Self(broker)
    }
}

impl PartialEq for BrokerHandle {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl fmt::Debug for BrokerHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// How to run a sandbox under the in-sandbox supervisor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupervisorSpec {
    /// The `runeward.supervisor.config.v1` document for the agent (PID 1).
    /// Governed execs use the same document with an empty `workdir`, so a
    /// per-call working directory still applies.
    pub config: SupervisorConfig,
    /// When set, a sandbox that cannot run the supervisor (image without
    /// the binary, backend without support) is refused. When clear, the
    /// backend may run the sandbox without it and says so by returning no
    /// report from [`crate::Backend::supervisor_report`].
    pub required: bool,
}

/// Best-effort resource caps.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Resources {
    /// CPU in billionths of a core.
    pub nano_cpus: i64,
    /// Memory in bytes.
    pub memory_bytes: i64,
}

/// A handle to a provisioned sandbox.
///
/// Serializes with the Go field names (`ID`, `Profile`, ...) so API payloads
/// are unchanged; `Isolation` is new.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Sandbox {
    /// Unguessable 128-bit hex id.
    #[serde(rename = "ID")]
    pub id: String,
    /// Charter name.
    pub profile: String,
    /// Backend name (`docker`, `podman`, `k8s`, ...).
    pub backend: String,
    /// Image the sandbox runs.
    pub image: String,
    /// Runtime-reported state (`running`, a pod phase, ...).
    pub status: String,
    /// Creation time (the Go zero time when unknown).
    #[serde(with = "crate::gotime")]
    pub created_at: DateTime<Utc>,
    /// Optional endpoint for in-cell services.
    pub endpoint: String,
    /// The isolation tier this sandbox actually runs behind.
    #[serde(default)]
    pub isolation: IsolationTier,
    /// What the backend observed to derive [`Sandbox::isolation`]: set by
    /// `create`, absent on sandboxes listed from the engine.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub isolation_evidence: Option<IsolationEvidence>,
}

impl Default for Sandbox {
    fn default() -> Self {
        Self {
            id: String::new(),
            profile: String::new(),
            backend: String::new(),
            image: String::new(),
            status: String::new(),
            created_at: go_zero_time(),
            endpoint: String::new(),
            isolation: IsolationTier::default(),
            isolation_evidence: None,
        }
    }
}

/// Go's zero `time.Time` (0001-01-01T00:00:00Z).
pub fn go_zero_time() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(1, 1, 1, 0, 0, 0)
        .single()
        .unwrap_or(DateTime::<Utc>::MIN_UTC)
}

/// A one-shot command execution.
#[derive(Default)]
pub struct ExecRequest {
    /// argv; executed directly, never through a shell by the backend.
    pub command: Vec<String>,
    /// Working directory; empty keeps the sandbox default.
    pub workdir: String,
    /// Extra environment.
    pub env: BTreeMap<String, String>,
    /// Kills the command after this long.
    pub timeout: Option<Duration>,
    /// Receives stdout as it is produced.
    pub stdout: Option<BoxWriter>,
    /// Receives stderr as it is produced.
    pub stderr: Option<BoxWriter>,
    /// Skips the in-memory copy in [`ExecResult`] (output only goes to the
    /// stream writers).
    pub stream_only: bool,
}

impl ExecRequest {
    /// A request running `command` with no other options.
    pub fn new<I, S>(command: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            command: command.into_iter().map(Into::into).collect(),
            ..Self::default()
        }
    }
}

impl fmt::Debug for ExecRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExecRequest")
            .field("command", &self.command)
            .field("workdir", &self.workdir)
            .field("env", &self.env.keys().collect::<Vec<_>>())
            .field("timeout", &self.timeout)
            .field("stdout", &self.stdout.is_some())
            .field("stderr", &self.stderr.is_some())
            .field("stream_only", &self.stream_only)
            .finish()
    }
}

/// The outcome of an [`ExecRequest`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExecResult {
    /// The command's exit status (non-zero exits are not errors).
    pub exit_code: i32,
    /// Captured stdout (empty with `stream_only`).
    pub stdout: String,
    /// Captured stderr (empty with `stream_only`).
    pub stderr: String,
    /// Wall-clock duration.
    pub duration: Duration,
}

/// Interactive terminal I/O for [`crate::Backend::attach_pty`].
#[derive(Default)]
pub struct PtyStream {
    /// Keystrokes / input; `None` attaches no stdin.
    pub stdin: Option<BoxReader>,
    /// Terminal output (stdout, and stderr when `tty` is set).
    pub stdout: Option<BoxWriter>,
    /// Stderr when `tty` is false; `None` merges it into `stdout`.
    pub stderr: Option<BoxWriter>,
    /// Allocates a terminal.
    pub tty: bool,
    /// argv; empty starts bash (or sh).
    pub command: Vec<String>,
    /// Window size updates.
    pub resize: Option<mpsc::Receiver<TermSize>>,
}

impl fmt::Debug for PtyStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PtyStream")
            .field("stdin", &self.stdin.is_some())
            .field("stdout", &self.stdout.is_some())
            .field("stderr", &self.stderr.is_some())
            .field("tty", &self.tty)
            .field("command", &self.command)
            .field("resize", &self.resize.is_some())
            .finish()
    }
}

/// A terminal window size.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TermSize {
    /// Rows.
    pub rows: u16,
    /// Columns.
    pub cols: u16,
}

/// A captured workspace snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotRef {
    /// Snapshot id.
    pub id: String,
    /// Operator-chosen name.
    pub name: String,
    /// Charter of the sandbox it came from.
    pub profile: String,
    /// Backend that captured it.
    pub backend: String,
    /// Tarball path on the host.
    pub location: String,
    /// Hex SHA-256 of the tarball, verified on restore when set.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub sha256: String,
    /// Capture time.
    #[serde(with = "crate::gotime")]
    pub created: DateTime<Utc>,
}

/// The default interactive shell: bash when present, else sh.
pub(crate) fn default_shell() -> Vec<String> {
    [
        "/bin/sh",
        "-c",
        "command -v bash >/dev/null 2>&1 && exec bash || exec sh",
    ]
    .map(String::from)
    .to_vec()
}

/// The default keep-alive command.
pub(crate) fn default_command() -> Vec<String> {
    vec!["sleep".into(), "infinity".into()]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sandbox_json_uses_go_field_names() {
        let sb = Sandbox {
            id: "abc".into(),
            profile: "p".into(),
            backend: "docker".into(),
            ..Sandbox::default()
        };
        let v = serde_json::to_value(&sb).expect("serialize");
        assert_eq!(v["ID"], "abc");
        assert_eq!(v["Profile"], "p");
        assert_eq!(v["CreatedAt"], "0001-01-01T00:00:00Z");
        assert_eq!(v["Isolation"], "container");
    }

    #[test]
    fn snapshot_ref_json_matches_go_tags() {
        let r = SnapshotRef {
            id: "i".into(),
            name: "n".into(),
            profile: "p".into(),
            backend: "docker".into(),
            location: "/x.tar".into(),
            sha256: String::new(),
            created: go_zero_time(),
        };
        let v = serde_json::to_value(&r).expect("serialize");
        assert!(v.get("sha256").is_none());
        assert_eq!(v["location"], "/x.tar");
        let back: SnapshotRef = serde_json::from_value(v).expect("deserialize");
        assert_eq!(back, r);
    }
}
