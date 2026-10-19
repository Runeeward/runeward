//! `runeward-supervisor`: the sandbox entrypoint that launches the agent
//! under in-boundary confinement and fails closed.
//!
//! The supervisor normally runs as PID 1 inside the container or VM. It
//! reads a [`SupervisorConfig`] derived from the Charter, confines itself,
//! then starts the agent, which inherits exactly that confinement:
//!
//! 1. resolves the agent identity (`[process]`) while `/etc/passwd` is
//!    still visible, and refuses root;
//! 2. sets `no_new_privs`;
//! 3. applies Landlock (`[filesystem]`): `read_only` paths get read and
//!    execute rights, `read_write` paths (including the workdir when
//!    `include_workdir`) get every right, everything else is unreachable.
//!    `best-effort` uses the kernel's best ABI and reports it, `required`
//!    refuses to start below ABI [`config::REQUIRED_MIN_ABI`], `off` skips;
//! 4. drops the bounding set, switches gid, groups and uid, and clears the
//!    inheritable, ambient, effective and permitted capability sets;
//! 5. installs the self-protection seccomp filter ([`syscalls::DENIED`]
//!    plus namespace-creating `clone` flags return `EPERM`; `clone3`
//!    returns `ENOSYS` so libc falls back to the inspectable `clone`);
//! 6. starts the agent, writes the enforcement [`Report`], then forwards
//!    signals to the agent and reaps zombies until the agent exits, exiting
//!    with its status (128 + signal when it was killed).
//!
//! Any failure before the agent starts stops the supervisor with
//! [`EXIT_REFUSED`] and a report line whose `ok` is false.
//!
//! The supervisor's own paths are always protected: an allowed path that is,
//! or contains, [`config::STATE_DIR`], the config file, the report file or a
//! `protected_paths` entry is refused, and so is a read-write path that
//! contains the supervisor binary.
//!
//! # Invocation
//!
//! ```text
//! runeward-supervisor [init] [--config PATH] [-- ARGV...]
//! runeward-supervisor exec   [--config PATH] [-- ARGV...]
//! ```
//!
//! `init` (the default) supervises the agent as described above. `exec`
//! confines itself the same way and then replaces itself with the agent, for
//! processes started next to PID 1 (such as `docker exec`). `ARGV` after
//! `--` replaces the config's `argv`.
//!
//! The config is read from, in order: `--config PATH`, the inline JSON in
//! `RUNEWARD_SUPERVISOR_CONFIG`, the file named by
//! `RUNEWARD_SUPERVISOR_CONFIG_FILE`, then [`config::DEFAULT_CONFIG_PATH`].
//! `RUNEWARD_SUPERVISOR_*` variables are never passed to the agent.
//!
//! # Config format (`runeward.supervisor.config.v1`)
//!
//! A JSON object; unknown fields are rejected and every field but `argv`
//! has a default. [`SupervisorConfig::from_charter`] produces it.
//!
//! ```json
//! {
//!   "schema": "runeward.supervisor.config.v1",
//!   "argv": ["/usr/local/bin/agent", "--serve"],
//!   "env": {"GITHUB_TOKEN": "rw-placeholder-github"},
//!   "inherit_env": true,
//!   "workdir": "/workspace",
//!   "filesystem": {
//!     "landlock": "required",
//!     "read_only": ["/usr", "/lib", "/etc", "/dev/random", "/dev/urandom"],
//!     "read_write": ["/tmp", "/workspace", "/dev/null", "/dev/tty"]
//!   },
//!   "process": {"user": "1500", "group": ""},
//!   "seccomp": true,
//!   "protected_paths": [],
//!   "report_path": "/run/runeward/supervisor-report.jsonl",
//!   "report_stderr": false
//! }
//! ```
//!
//! | field | default | meaning |
//! |---|---|---|
//! | `schema` | the v1 id | must equal [`config::CONFIG_SCHEMA`] |
//! | `argv` | required | agent command; `argv[0]` is looked up on `PATH` |
//! | `env` | `{}` | variables set for the agent |
//! | `inherit_env` | `true` | pass the supervisor's environment through first |
//! | `workdir` | `""` | agent working directory (absolute) |
//! | `filesystem.landlock` | `best-effort` | `best-effort`, `required` or `off` |
//! | `filesystem.read_only` | `[]` | absolute paths with read and execute rights |
//! | `filesystem.read_write` | `[]` | absolute paths with all rights |
//! | `process.user` | `""` | uid or name; empty keeps the current identity (refused when root) |
//! | `process.group` | `""` | gid or name; empty uses the user's primary group |
//! | `seccomp` | `true` | install the self-protection filter |
//! | `protected_paths` | `[]` | extra paths the agent must never reach |
//! | `report_path` | [`config::DEFAULT_REPORT_PATH`] | file report lines are appended to; `""` disables |
//! | `report_stderr` | `false` | also write report lines to stderr |
//!
//! # Report format (`runeward.supervisor.report.v1`)
//!
//! One JSON line per start (see [`Report`]), appended to `report_path`
//! (created `0600` in a `0700` directory before any confinement, so it stays
//! writable after the identity switch while the agent cannot reach it):
//!
//! ```json
//! {"schema":"runeward.supervisor.report.v1","ok":true,"mode":"init","pid1":true,
//!  "supervisor_pid":1,"agent_pid":7,"argv0":"/usr/local/bin/agent",
//!  "landlock":{"requested":"required","status":"enforced","abi":6,
//!    "read_only":["/usr"],"read_write":["/workspace"],"skipped":["/lib64"]},
//!  "seccomp":{"enabled":true,"arch":"aarch64","action":"errno:EPERM",
//!    "denied":["ptrace","..."],"clone_flags_denied":["CLONE_NEWUSER","..."],
//!    "clone3":"errno:ENOSYS"},
//!  "no_new_privs":true,"uid":1500,"gid":1500,"groups":[1500],
//!  "capabilities":{"effective":[],"permitted":[],"inheritable":[],"ambient":[],"bounding":[]},
//!  "protected_paths":["/run/runeward"],"protected_by_landlock":true,"error":null}
//! ```
//!
//! `landlock.status` is `enforced`, `unsupported` (best-effort on a kernel
//! without Landlock: the agent ran without filesystem confinement), `off`,
//! or `refused`. In `exec` mode the line is written just before the exec;
//! a failed exec appends a second line with `ok: false`.
//!
//! # Exit codes
//!
//! The agent's own status, or one of [`EXIT_USAGE`], [`EXIT_CONFIG`],
//! [`EXIT_REFUSED`], [`EXIT_UNSUPPORTED`], [`EXIT_SPAWN`], [`EXIT_INTERNAL`].
//!
//! The confinement itself is Linux-only. On other systems the binary
//! refuses to run, while the config builder still works.

pub mod config;
pub mod report;
pub mod syscalls;

#[cfg(target_os = "linux")]
pub mod linux;

use std::path::{Path, PathBuf};

pub use config::{ConfigError, FilesystemConfig, LandlockMode, ProcessConfig, SupervisorConfig};
pub use report::Report;

/// Bad command line.
pub const EXIT_USAGE: i32 = 64;
/// Unreadable or invalid config.
pub const EXIT_CONFIG: i32 = 78;
/// Confinement could not be established as configured; nothing ran.
pub const EXIT_REFUSED: i32 = 77;
/// Not running on Linux.
pub const EXIT_UNSUPPORTED: i32 = 69;
/// The agent command could not be started.
pub const EXIT_SPAWN: i32 = 127;
/// An unexpected supervisor failure.
pub const EXIT_INTERNAL: i32 = 70;

/// How the supervisor runs the agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Start the agent as a child, forward signals and reap zombies.
    Init,
    /// Replace the supervisor with the agent.
    Exec,
}

/// A parsed command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Args {
    pub mode: Mode,
    pub config: Option<PathBuf>,
    /// The command after `--`, if any.
    pub argv: Option<Vec<String>>,
    pub help: bool,
    pub version: bool,
}

/// Parses the command line (without the program name).
pub fn parse_args<I: IntoIterator<Item = String>>(args: I) -> Result<Args, String> {
    let mut out = Args {
        mode: Mode::Init,
        config: None,
        argv: None,
        help: false,
        version: false,
    };
    let mut it = args.into_iter();
    let mut first = true;
    while let Some(a) = it.next() {
        match a.as_str() {
            "init" if first => out.mode = Mode::Init,
            "exec" if first => out.mode = Mode::Exec,
            "-h" | "--help" => out.help = true,
            "-V" | "--version" => out.version = true,
            "--config" => {
                let p = it.next().ok_or("--config needs a path")?;
                out.config = Some(PathBuf::from(p));
            }
            "--" => {
                out.argv = Some(it.by_ref().collect());
                break;
            }
            other => match other.strip_prefix("--config=") {
                Some(p) => out.config = Some(PathBuf::from(p)),
                None => return Err(format!("unexpected argument {other:?}")),
            },
        }
        first = false;
    }
    Ok(out)
}

/// Usage text.
pub const USAGE: &str = "\
usage: runeward-supervisor [init] [--config PATH] [-- ARGV...]
       runeward-supervisor exec   [--config PATH] [-- ARGV...]

Runs the agent under Landlock, seccomp and a dropped identity (Linux only).
The config comes from --config, $RUNEWARD_SUPERVISOR_CONFIG (inline JSON),
$RUNEWARD_SUPERVISOR_CONFIG_FILE, or /run/runeward/supervisor.json.
";

/// Everything the Linux runner needs.
#[derive(Debug, Clone)]
pub struct Invocation {
    pub mode: Mode,
    pub config: SupervisorConfig,
    /// The config file, protected from the agent, when it came from one.
    pub config_path: Option<PathBuf>,
}

/// Loads and validates the config following the documented precedence;
/// `ARGV` after `--` replaces the document's `argv` before validation.
/// `env` looks up environment variables (injected for tests).
pub fn load_config(
    args: &Args,
    env: impl Fn(&str) -> Option<String>,
) -> Result<(SupervisorConfig, Option<PathBuf>), String> {
    let parse = |bytes: &[u8], what: &str| -> Result<SupervisorConfig, String> {
        serde_json::from_slice(bytes).map_err(|e| format!("{what}: config is not valid JSON: {e}"))
    };
    let from_file = |p: &Path| -> Result<(SupervisorConfig, Option<PathBuf>), String> {
        let bytes = std::fs::read(p).map_err(|e| format!("read config {}: {e}", p.display()))?;
        Ok((
            parse(&bytes, &p.display().to_string())?,
            Some(p.to_path_buf()),
        ))
    };
    let (mut cfg, path) = if let Some(p) = &args.config {
        from_file(p)?
    } else if let Some(inline) = env(config::CONFIG_ENV).filter(|s| !s.is_empty()) {
        (
            parse(inline.as_bytes(), &format!("${}", config::CONFIG_ENV))?,
            None,
        )
    } else if let Some(p) = env(config::CONFIG_FILE_ENV).filter(|s| !s.is_empty()) {
        from_file(Path::new(&p))?
    } else {
        from_file(Path::new(config::DEFAULT_CONFIG_PATH))?
    };
    if let Some(argv) = &args.argv {
        cfg.argv.clone_from(argv);
    }
    cfg.validate().map_err(|e| e.to_string())?;
    Ok((cfg, path))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(v: &[&str]) -> Result<Args, String> {
        parse_args(v.iter().map(|s| (*s).to_owned()))
    }

    #[test]
    fn parses_modes_and_argv() {
        let a = args(&[]).expect("empty");
        assert_eq!(a.mode, Mode::Init);
        assert!(a.argv.is_none());

        let a = args(&["exec", "--config", "/c.json", "--", "sh", "-c", "--"]).expect("exec");
        assert_eq!(a.mode, Mode::Exec);
        assert_eq!(a.config.as_deref(), Some(Path::new("/c.json")));
        assert_eq!(a.argv.expect("argv"), ["sh", "-c", "--"]);

        let a = args(&["--config=/x", "--version"]).expect("flags");
        assert!(a.version);
        assert!(args(&["--bogus"]).is_err());
        assert!(args(&["--config"]).is_err());
        assert!(args(&["--help", "exec"]).is_err(), "mode must come first");
    }

    #[test]
    fn config_precedence() {
        let dir = tempfile::tempdir().expect("tmp");
        let file = dir.path().join("c.json");
        std::fs::write(&file, r#"{"argv":["from-file"]}"#).expect("write");
        let file_s = file.display().to_string();

        let env_inline =
            |k: &str| (k == config::CONFIG_ENV).then(|| r#"{"argv":["from-env"]}"#.to_owned());
        let a = args(&[]).expect("args");
        let (cfg, path) = load_config(&a, env_inline).expect("inline");
        assert_eq!(cfg.argv, ["from-env"]);
        assert!(path.is_none());

        let env_file = |k: &str| (k == config::CONFIG_FILE_ENV).then(|| file_s.clone());
        let (cfg, path) = load_config(&a, env_file).expect("file env");
        assert_eq!(cfg.argv, ["from-file"]);
        assert_eq!(path.as_deref(), Some(file.as_path()));

        let a = args(&["--config", &file_s, "--", "override"]).expect("args");
        let (cfg, _) = load_config(&a, env_inline).expect("flag wins");
        assert_eq!(cfg.argv, ["override"]);

        // An inline document may leave argv to the command line.
        let env_noargv = |k: &str| (k == config::CONFIG_ENV).then(|| "{}".to_owned());
        let a = args(&["--", "sh"]).expect("args");
        assert_eq!(load_config(&a, env_noargv).expect("argv").0.argv, ["sh"]);
        assert!(load_config(&args(&[]).expect("args"), env_noargv).is_err());

        let bad = |k: &str| (k == config::CONFIG_ENV).then(|| "{".to_owned());
        assert!(load_config(&args(&[]).expect("args"), bad).is_err());
        let rooted = |k: &str| {
            (k == config::CONFIG_ENV)
                .then(|| r#"{"argv":["a"],"process":{"user":"root"}}"#.to_owned())
        };
        assert!(load_config(&args(&[]).expect("args"), rooted).is_err());
    }
}
