//! In-sandbox plumbing shared by the backends: the supervisor entrypoint
//! and its config files, and the request broker's CA trust bundle.
//!
//! # Supervisor
//!
//! A supervised sandbox starts as root with only `SETUID`, `SETGID` and
//! `CHOWN` added back to an otherwise empty capability set, so
//! [`SUPERVISOR_BIN`] (PID 1) can apply Landlock and seccomp, drop to the
//! agent identity and clear every capability before the agent starts. Its
//! config documents live in [`runeward_supervisor::config::STATE_DIR`]
//! (`0600`, root-owned, unreachable from the agent), next to the
//! enforcement report. Governed execs run
//! `runeward-supervisor exec --config` [`SUPERVISOR_EXEC_CONFIG_PATH`]` --
//! argv...`, so they get exactly the agent's confinement. The control
//! plane's own operations (workspace tar streams, file projection) run as
//! the agent identity instead, unconfined but unprivileged.
//!
//! # Broker CA
//!
//! The broker terminates TLS for inspected endpoints with a per-sandbox CA.
//! The sandbox gets the CA at [`BROKER_CA_FILE`] and a bundle of the
//! image's own roots plus that CA at [`CA_BUNDLE_FILE`]; [`CA_ENV`] all
//! point at the bundle.

use std::collections::BTreeMap;

use runeward_supervisor::SupervisorConfig;
use runeward_supervisor::config::{DEFAULT_CONFIG_PATH, DEFAULT_REPORT_PATH, STATE_DIR};

use crate::error::{BackendError, Result};

/// Where images carry the supervisor (see `deploy/Dockerfile.sandbox`).
pub const SUPERVISOR_BIN: &str = "/usr/local/bin/runeward-supervisor";
/// The supervisor's state directory inside the sandbox.
pub const SUPERVISOR_STATE_DIR: &str = STATE_DIR;
/// The PID 1 config document.
pub const SUPERVISOR_CONFIG_PATH: &str = DEFAULT_CONFIG_PATH;
/// The config document governed execs run under.
pub const SUPERVISOR_EXEC_CONFIG_PATH: &str = "/run/runeward/supervisor-exec.json";
/// The enforcement report (`runeward.supervisor.report.v1` lines).
pub const SUPERVISOR_REPORT_PATH: &str = DEFAULT_REPORT_PATH;
/// Label marking a supervised container; its value is the agent identity
/// (`user[:group]`) the backend's own operations run as.
pub const LABEL_SUPERVISED: &str = "runeward.supervised";
/// Capabilities a supervised container's root keeps until the supervisor
/// drops them: switching identity, and handing the workspace to the agent.
pub const SUPERVISOR_CAPS: [&str; 3] = ["SETUID", "SETGID", "CHOWN"];

/// Directory holding the broker CA and the trust bundle.
pub const BROKER_CA_DIR: &str = "/etc/runeward/ca";
/// The per-sandbox broker CA certificate.
pub const BROKER_CA_FILE: &str = "/etc/runeward/ca/broker-ca.pem";
/// The image's roots plus the broker CA.
pub const CA_BUNDLE_FILE: &str = "/etc/runeward/ca/ca-bundle.pem";
/// Variables common TLS stacks (OpenSSL, Node, Python requests, curl, git)
/// read for their trust store, all pointed at [`CA_BUNDLE_FILE`].
pub const CA_ENV: [&str; 5] = [
    "SSL_CERT_FILE",
    "NODE_EXTRA_CA_CERTS",
    "REQUESTS_CA_BUNDLE",
    "CURL_CA_BUNDLE",
    "GIT_SSL_CAINFO",
];
/// Where images commonly keep their system roots, tried in order.
pub const SYSTEM_ROOTS: [&str; 4] = [
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/cert.pem",
    "/etc/ssl/ca-bundle.pem",
];

/// The CA variables for a sandbox with a broker.
pub fn ca_env() -> Vec<(String, String)> {
    CA_ENV
        .iter()
        .map(|k| ((*k).to_owned(), CA_BUNDLE_FILE.to_owned()))
        .collect()
}

/// The trust bundle: the image's roots (when found) followed by the broker
/// CA.
pub fn ca_bundle(system_roots: Option<&[u8]>, broker_ca_pem: &str) -> Vec<u8> {
    let mut out = Vec::new();
    if let Some(roots) = system_roots {
        out.extend_from_slice(roots);
        if !roots.ends_with(b"\n") {
            out.push(b'\n');
        }
    }
    out.extend_from_slice(broker_ca_pem.as_bytes());
    out
}

/// The supervisor plan a backend applies: both config documents and the
/// identity its own operations run as.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupervisorPlan {
    /// PID 1 document.
    pub init: SupervisorConfig,
    /// Exec document (no `workdir`, so the call's own applies).
    pub exec: SupervisorConfig,
    /// `user[:group]` for the backend's own unconfined operations.
    pub agent_user: String,
}

impl SupervisorPlan {
    /// Builds the plan. An empty agent identity falls back to
    /// `image_user` (the image's `USER`); root is refused either way, since
    /// the supervisor never runs the agent as root.
    pub fn new(mut config: SupervisorConfig, image_user: &str) -> Result<Self> {
        if config.process.user.trim().is_empty() {
            let (u, g) = match image_user.trim().split_once(':') {
                Some((u, g)) => (u.to_owned(), g.to_owned()),
                None => (image_user.trim().to_owned(), String::new()),
            };
            if u.is_empty() || runeward_supervisor::config::is_root_name(&u) {
                return Err(BackendError::Unsupported(
                    "the in-sandbox supervisor needs a non-root agent identity: set [process] run_as_user (or host.user), or use an image whose USER is not root".into(),
                ));
            }
            config.process.user = u;
            if config.process.group.is_empty() {
                config.process.group = g;
            }
        }
        config
            .validate()
            .map_err(|e| BackendError::msg(format!("supervisor config: {e}")))?;
        let mut exec = config.clone();
        exec.workdir.clear();
        let agent_user = if config.process.group.is_empty() {
            config.process.user.clone()
        } else {
            format!("{}:{}", config.process.user, config.process.group)
        };
        Ok(Self {
            init: config,
            exec,
            agent_user,
        })
    }

    /// PID 1's command line after the entrypoint.
    pub fn init_args() -> Vec<String> {
        ["init", "--config", SUPERVISOR_CONFIG_PATH]
            .map(String::from)
            .to_vec()
    }

    /// The files staged into [`SUPERVISOR_STATE_DIR`] before start.
    pub fn files(&self) -> Vec<(String, Vec<u8>, u32)> {
        vec![
            (
                "supervisor.json".into(),
                self.init.to_json().into_bytes(),
                0o600,
            ),
            (
                "supervisor-exec.json".into(),
                self.exec.to_json().into_bytes(),
                0o600,
            ),
        ]
    }
}

/// Wraps `argv` so it runs under the supervisor's exec mode.
pub fn supervised_command(argv: &[String]) -> Vec<String> {
    let mut out: Vec<String> = [
        SUPERVISOR_BIN,
        "exec",
        "--config",
        SUPERVISOR_EXEC_CONFIG_PATH,
        "--",
    ]
    .map(String::from)
    .to_vec();
    out.extend(argv.iter().cloned());
    out
}

/// A tar of root-owned regular files (and their parent directories) to
/// extract under one destination directory. `dirs` are created with
/// `dir_mode`.
pub fn root_tar(
    dirs: &[&str],
    dir_mode: u32,
    files: &[(String, Vec<u8>, u32)],
) -> std::io::Result<Vec<u8>> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let mut b = tar::Builder::new(Vec::new());
    for d in dirs {
        let mut h = tar::Header::new_ustar();
        h.set_entry_type(tar::EntryType::Directory);
        h.set_path(format!("{}/", d.trim_end_matches('/')))?;
        h.set_size(0);
        h.set_mode(dir_mode);
        h.set_uid(0);
        h.set_gid(0);
        h.set_mtime(now);
        h.set_cksum();
        b.append(&h, std::io::empty())?;
    }
    for (name, data, mode) in files {
        let mut h = tar::Header::new_ustar();
        h.set_entry_type(tar::EntryType::Regular);
        h.set_path(name)?;
        h.set_size(data.len() as u64);
        h.set_mode(*mode);
        h.set_uid(0);
        h.set_gid(0);
        h.set_mtime(now);
        h.set_cksum();
        b.append(&h, data.as_slice())?;
    }
    b.into_inner()
}

/// The contents of the first regular file in a tar stream (what
/// `docker cp <ctr>:<file> -` prints).
pub fn first_file_in_tar(data: &[u8]) -> Option<Vec<u8>> {
    use std::io::Read as _;
    let mut a = tar::Archive::new(data);
    for entry in a.entries().ok()? {
        let mut e = entry.ok()?;
        if e.header().entry_type().is_file() {
            let mut out = Vec::new();
            e.read_to_end(&mut out).ok()?;
            return Some(out);
        }
    }
    None
}

/// Labels marking a supervised container.
pub fn supervised_labels(plan: &SupervisorPlan) -> BTreeMap<String, String> {
    BTreeMap::from([(LABEL_SUPERVISED.to_owned(), plan.agent_user.clone())])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(user: &str) -> SupervisorConfig {
        let mut c = SupervisorConfig::default().with_argv(["sleep", "infinity"]);
        c.workdir = "/workspace".into();
        c.process.user = user.into();
        c
    }

    #[test]
    fn plan_identity_fallback_and_root_refusal() {
        let p = SupervisorPlan::new(cfg("1500"), "").expect("plan");
        assert_eq!(p.agent_user, "1500");
        assert_eq!(p.init.workdir, "/workspace");
        assert!(p.exec.workdir.is_empty(), "exec keeps the call's workdir");

        let p = SupervisorPlan::new(cfg(""), "sandbox:staff").expect("image user");
        assert_eq!(p.agent_user, "sandbox:staff");
        assert_eq!(p.init.process.group, "staff");

        for image_user in ["", "root", "0", "0:0"] {
            let err = SupervisorPlan::new(cfg(""), image_user).expect_err(image_user);
            assert!(matches!(err, BackendError::Unsupported(_)), "{err}");
        }
        let files = SupervisorPlan::new(cfg("1500"), "").expect("plan").files();
        assert_eq!(files.len(), 2);
        assert!(files.iter().all(|(_, _, m)| *m == 0o600));
        let exec: SupervisorConfig =
            serde_json::from_slice(&files[1].1).expect("exec document parses");
        assert!(exec.workdir.is_empty());
    }

    #[test]
    fn commands_and_env() {
        let c = supervised_command(&["sh".into(), "-c".into(), "id".into()]);
        assert_eq!(
            c,
            [
                SUPERVISOR_BIN,
                "exec",
                "--config",
                SUPERVISOR_EXEC_CONFIG_PATH,
                "--",
                "sh",
                "-c",
                "id"
            ]
        );
        assert_eq!(
            SupervisorPlan::init_args(),
            ["init", "--config", "/run/runeward/supervisor.json"]
        );
        let env = ca_env();
        assert_eq!(env.len(), 5);
        assert!(env.iter().all(|(_, v)| v == CA_BUNDLE_FILE));
    }

    #[test]
    fn bundle_and_tars() {
        assert_eq!(ca_bundle(Some(b"ROOTS"), "CA\n"), b"ROOTS\nCA\n");
        assert_eq!(ca_bundle(Some(b"ROOTS\n"), "CA\n"), b"ROOTS\nCA\n");
        assert_eq!(ca_bundle(None, "CA\n"), b"CA\n");

        let t = root_tar(
            &["runeward"],
            0o700,
            &[("runeward/a.json".into(), b"{}".to_vec(), 0o600)],
        )
        .expect("tar");
        let mut a = tar::Archive::new(t.as_slice());
        let entries: Vec<(String, u32, u64)> = a
            .entries()
            .expect("entries")
            .map(|e| {
                let e = e.expect("entry");
                let h = e.header();
                (
                    e.path().expect("path").display().to_string(),
                    h.mode().expect("mode"),
                    h.uid().expect("uid"),
                )
            })
            .collect();
        assert_eq!(
            entries,
            [
                ("runeward/".to_string(), 0o700, 0),
                ("runeward/a.json".to_string(), 0o600, 0)
            ]
        );
        assert_eq!(first_file_in_tar(&t), Some(b"{}".to_vec()));
        assert_eq!(first_file_in_tar(b"not a tar"), None);
    }
}
