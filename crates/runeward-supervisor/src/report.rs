//! The enforcement report: one JSON line describing what the supervisor
//! actually enforced, for the control plane to record in the audit ledger.

use serde::{Deserialize, Serialize};

/// The `schema` value every report line carries.
pub const REPORT_SCHEMA: &str = "runeward.supervisor.report.v1";

/// What Landlock delivered.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct LandlockReport {
    /// The configured mode: `best-effort`, `required` or `off`.
    pub requested: String,
    /// `enforced`, `unsupported` (kernel without Landlock, best-effort ran
    /// unconfined), `off`, or `refused` (required but not available).
    pub status: String,
    /// The Landlock ABI the ruleset was built for; 0 when none.
    pub abi: u32,
    /// Allowed paths that were applied.
    pub read_only: Vec<String>,
    pub read_write: Vec<String>,
    /// Allowed paths skipped because they do not exist in the sandbox.
    pub skipped: Vec<String>,
}

/// What the seccomp filter delivered.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SeccompReport {
    pub enabled: bool,
    /// `x86_64` or `aarch64`.
    pub arch: String,
    /// The action for denied syscalls (`errno:EPERM`).
    pub action: String,
    /// Names of the syscalls answered with `action`.
    pub denied: Vec<String>,
    /// `clone(2)` namespace flags answered with `action`.
    pub clone_flags_denied: Vec<String>,
    /// `clone3(2)` answer (`errno:ENOSYS`), forcing the inspectable `clone`.
    pub clone3: String,
}

/// Capability sets after the drop, as lowercase capability names.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct CapsReport {
    pub effective: Vec<String>,
    pub permitted: Vec<String>,
    pub inheritable: Vec<String>,
    pub ambient: Vec<String>,
    pub bounding: Vec<String>,
}

/// One report line (`runeward.supervisor.report.v1`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Report {
    pub schema: String,
    /// False when the supervisor refused to start the agent.
    pub ok: bool,
    /// `init` (supervising, normally as PID 1) or `exec` (confine and exec).
    pub mode: String,
    /// Whether the supervisor is PID 1 in its PID namespace.
    pub pid1: bool,
    pub supervisor_pid: u32,
    /// The agent's pid; in `exec` mode it equals `supervisor_pid`.
    pub agent_pid: Option<u32>,
    pub argv0: String,
    pub landlock: LandlockReport,
    pub seccomp: SeccompReport,
    pub no_new_privs: bool,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub groups: Vec<u32>,
    pub capabilities: CapsReport,
    /// Paths held back from the agent.
    pub protected_paths: Vec<String>,
    /// True when Landlock (not only file permissions) guards
    /// `protected_paths`.
    pub protected_by_landlock: bool,
    pub error: Option<String>,
}

impl Default for Report {
    fn default() -> Self {
        Self {
            schema: REPORT_SCHEMA.to_owned(),
            ok: false,
            mode: String::new(),
            pid1: false,
            supervisor_pid: std::process::id(),
            agent_pid: None,
            argv0: String::new(),
            landlock: LandlockReport::default(),
            seccomp: SeccompReport::default(),
            no_new_privs: false,
            uid: None,
            gid: None,
            groups: Vec::new(),
            capabilities: CapsReport::default(),
            protected_paths: Vec::new(),
            protected_by_landlock: false,
            error: None,
        }
    }
}

impl Report {
    /// The report as a single JSON line with a trailing newline.
    pub fn to_line(&self) -> String {
        let mut s = serde_json::to_string(self).unwrap_or_default();
        s.push('\n');
        s
    }

    /// Parses a report line.
    pub fn parse(line: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(line.trim())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_as_one_line() {
        let r = Report {
            ok: true,
            mode: "init".into(),
            uid: Some(1500),
            landlock: LandlockReport {
                requested: "required".into(),
                status: "enforced".into(),
                abi: 6,
                ..LandlockReport::default()
            },
            ..Report::default()
        };
        let line = r.to_line();
        assert_eq!(line.matches('\n').count(), 1);
        assert!(line.starts_with(r#"{"schema":"runeward.supervisor.report.v1","ok":true"#));
        assert_eq!(Report::parse(&line).expect("parse"), r);
    }
}
