//! The supervisor's configuration document and its Charter builder.
//!
//! The control plane derives a [`SupervisorConfig`] from the Charter with
//! [`SupervisorConfig::from_charter`], serialises it as JSON and hands it to
//! the supervisor inside the sandbox. See the crate docs for the format.

use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};

use runeward_charter::Charter;
use serde::{Deserialize, Serialize};

/// The `schema` value every config document carries.
pub const CONFIG_SCHEMA: &str = "runeward.supervisor.config.v1";

/// The supervisor's state directory inside the sandbox. It is always
/// protected from the agent.
pub const STATE_DIR: &str = "/run/runeward";

/// Where the config is read from when no flag or env var names it.
pub const DEFAULT_CONFIG_PATH: &str = "/run/runeward/supervisor.json";

/// Where the enforcement report is appended by default.
pub const DEFAULT_REPORT_PATH: &str = "/run/runeward/supervisor-report.jsonl";

/// Env var holding the whole config document inline.
pub const CONFIG_ENV: &str = "RUNEWARD_SUPERVISOR_CONFIG";

/// Env var naming a config file.
pub const CONFIG_FILE_ENV: &str = "RUNEWARD_SUPERVISOR_CONFIG_FILE";

/// Prefix of every env var the supervisor reads. Variables with this prefix
/// are never passed on to the agent.
pub const ENV_PREFIX: &str = "RUNEWARD_SUPERVISOR_";

/// The command run when the Charter sets no `host.command`.
pub const DEFAULT_ARGV: [&str; 2] = ["sleep", "infinity"];

/// Device nodes granted read-write whenever Landlock is on, so ordinary
/// tools (shells, `>/dev/null` redirects, terminals) keep working.
pub const BASELINE_READ_WRITE: [&str; 6] = [
    "/dev/null",
    "/dev/zero",
    "/dev/full",
    "/dev/tty",
    "/dev/pts",
    "/dev/ptmx",
];

/// Device nodes granted read-only whenever Landlock is on.
pub const BASELINE_READ_ONLY: [&str; 2] = ["/dev/random", "/dev/urandom"];

/// How Landlock is applied.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LandlockMode {
    /// Use the best ABI the kernel offers; run unconfined (and say so in the
    /// report) when the kernel has no Landlock.
    #[default]
    BestEffort,
    /// Refuse to start unless the ruleset is fully enforced at
    /// [`REQUIRED_MIN_ABI`] or better.
    Required,
    /// Do not apply Landlock.
    Off,
}

impl LandlockMode {
    /// The config spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BestEffort => "best-effort",
            Self::Required => "required",
            Self::Off => "off",
        }
    }

    /// Parses the Charter spelling, where empty means best-effort.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "" | "best-effort" => Some(Self::BestEffort),
            "required" => Some(Self::Required),
            "off" => Some(Self::Off),
            _ => None,
        }
    }
}

/// The lowest Landlock ABI `required` accepts. ABI 3 (Linux 6.2) is the
/// first that can stop `truncate(2)` on read-only files, so anything older
/// cannot make a path truly read-only.
pub const REQUIRED_MIN_ABI: u32 = 3;

/// Filesystem rules, already merged with the workdir and baseline devices.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FilesystemConfig {
    pub landlock: LandlockMode,
    pub read_only: Vec<String>,
    pub read_write: Vec<String>,
}

/// The identity the agent runs as. Names are resolved inside the sandbox.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProcessConfig {
    /// A uid or user name. Empty keeps the supervisor's own identity, which
    /// is refused when that identity is root.
    pub user: String,
    /// A gid or group name. Empty uses the user's primary group (or the uid
    /// when the user has no passwd entry).
    pub group: String,
}

/// Binary attribution for the egress broker (Charter `[[endpoint]]`
/// `binaries`). When set, `init` starts the attribution helper before the
/// agent and refuses to start the agent without it; `exec` ignores it.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AttributionConfig {
    /// The helper's Unix socket: `@name` for an abstract socket in the
    /// sandbox's network namespace (the broker shares it), or a path.
    pub socket: String,
    /// The per-sandbox key (64 hex characters) authenticating answers.
    pub key: String,
    /// Every binary any endpoint lists, pinned by file identity at start.
    pub binaries: Vec<String>,
}

impl std::fmt::Debug for AttributionConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AttributionConfig")
            .field("socket", &self.socket)
            .field("binaries", &self.binaries)
            .finish_non_exhaustive()
    }
}

/// The supervisor configuration document (`runeward.supervisor.config.v1`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SupervisorConfig {
    pub schema: String,
    /// The agent command line. `argv[0]` is looked up on `PATH` when it has
    /// no slash.
    pub argv: Vec<String>,
    /// Variables set for the agent, overriding inherited ones.
    pub env: BTreeMap<String, String>,
    /// Passes the supervisor's own environment (minus `RUNEWARD_SUPERVISOR_*`)
    /// to the agent before applying `env`.
    pub inherit_env: bool,
    /// The agent's working directory; empty keeps the supervisor's.
    pub workdir: String,
    pub filesystem: FilesystemConfig,
    pub process: ProcessConfig,
    /// Installs the self-protection seccomp filter.
    pub seccomp: bool,
    /// Extra paths the agent must never reach. [`STATE_DIR`], the config file
    /// and the report file are always protected.
    pub protected_paths: Vec<String>,
    /// File the enforcement report line is appended to; empty disables it.
    pub report_path: String,
    /// Also writes the report line to stderr.
    pub report_stderr: bool,
    /// Binary attribution for the egress broker; absent when no endpoint
    /// lists `binaries`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attribution: Option<AttributionConfig>,
}

impl Default for SupervisorConfig {
    fn default() -> Self {
        Self {
            schema: CONFIG_SCHEMA.to_owned(),
            argv: Vec::new(),
            env: BTreeMap::new(),
            inherit_env: true,
            workdir: String::new(),
            filesystem: FilesystemConfig::default(),
            process: ProcessConfig::default(),
            seccomp: true,
            protected_paths: Vec::new(),
            report_path: DEFAULT_REPORT_PATH.to_owned(),
            report_stderr: false,
            attribution: None,
        }
    }
}

/// Why a config was rejected.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("config is not valid JSON: {0}")]
    Parse(String),
    #[error("{0}")]
    Invalid(String),
}

impl SupervisorConfig {
    /// Builds the config the control plane hands to the supervisor for a
    /// Charter. `workdir` is the resolved working directory inside the
    /// sandbox (the Charter's `host.workdir` after defaulting).
    ///
    /// - `argv` is `host.command`, or `sleep infinity` when unset.
    /// - Without a `[filesystem]` section Landlock is off. With one, the
    ///   lists are copied, `workdir` is added read-write when
    ///   `include_workdir` is true, and the baseline device nodes are added.
    /// - The identity is `[process]`, falling back to `host.user`
    ///   (`uid[:gid]`).
    /// - Charter env values are not copied: the backend already sets them on
    ///   the container and the agent inherits them. Use [`Self::with_env`]
    ///   for anything else.
    pub fn from_charter(charter: &Charter, workdir: &str) -> Result<Self, ConfigError> {
        let mut cfg = Self {
            argv: if charter.host.command.is_empty() {
                DEFAULT_ARGV.iter().map(|s| (*s).to_owned()).collect()
            } else {
                charter.host.command.clone()
            },
            workdir: workdir.to_owned(),
            ..Self::default()
        };

        match &charter.filesystem {
            None => cfg.filesystem.landlock = LandlockMode::Off,
            Some(fs) => {
                let mode = LandlockMode::parse(&fs.landlock).ok_or_else(|| {
                    ConfigError::Invalid(format!(
                        "filesystem.landlock must be best-effort, required or off, got {:?}",
                        fs.landlock
                    ))
                })?;
                cfg.filesystem.landlock = mode;
                cfg.filesystem.read_only = fs.read_only.clone();
                cfg.filesystem.read_write = fs.read_write.clone();
                if fs.include_workdir && !workdir.is_empty() {
                    cfg.filesystem.read_write.push(workdir.to_owned());
                }
                if mode != LandlockMode::Off {
                    cfg.filesystem
                        .read_write
                        .extend(BASELINE_READ_WRITE.iter().map(|s| (*s).to_owned()));
                    cfg.filesystem
                        .read_only
                        .extend(BASELINE_READ_ONLY.iter().map(|s| (*s).to_owned()));
                }
                dedup(&mut cfg.filesystem.read_only);
                dedup(&mut cfg.filesystem.read_write);
            }
        }

        let (host_user, host_group) = match charter.host.user.trim().split_once(':') {
            Some((u, g)) => (u.to_owned(), g.to_owned()),
            None => (charter.host.user.trim().to_owned(), String::new()),
        };
        match &charter.process {
            Some(p) if !p.run_as_user.is_empty() => {
                cfg.process.user = p.run_as_user.clone();
                cfg.process.group = p.run_as_group.clone();
            }
            Some(p) => {
                cfg.process.user = host_user;
                cfg.process.group = if p.run_as_group.is_empty() {
                    host_group
                } else {
                    p.run_as_group.clone()
                };
            }
            None => {
                cfg.process.user = host_user;
                cfg.process.group = host_group;
            }
        }

        cfg.validate()?;
        Ok(cfg)
    }

    /// Sets an env var for the agent.
    pub fn with_env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.insert(key.into(), value.into());
        self
    }

    /// Enables binary attribution: the helper listens on `socket`,
    /// authenticates answers with `key` (hex) and pins `binaries`.
    pub fn with_attribution(
        mut self,
        socket: impl Into<String>,
        key: impl Into<String>,
        binaries: Vec<String>,
    ) -> Self {
        self.attribution = Some(AttributionConfig {
            socket: socket.into(),
            key: key.into(),
            binaries,
        });
        self
    }

    /// Replaces the agent command line.
    pub fn with_argv<I, S>(mut self, argv: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.argv = argv.into_iter().map(Into::into).collect();
        self
    }

    /// Parses and validates a JSON document.
    pub fn from_json(src: &[u8]) -> Result<Self, ConfigError> {
        let cfg: Self =
            serde_json::from_slice(src).map_err(|e| ConfigError::Parse(e.to_string()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Serialises the document as pretty JSON.
    pub fn to_json(&self) -> String {
        // Serialising plain strings, maps and bools cannot fail.
        serde_json::to_string_pretty(self).unwrap_or_default()
    }

    /// Checks the invariants the supervisor relies on. It does not look at
    /// the filesystem; [`Self::check_protected`] does that.
    pub fn validate(&self) -> Result<(), ConfigError> {
        let bad = |m: String| Err(ConfigError::Invalid(m));
        if self.schema != CONFIG_SCHEMA {
            return bad(format!(
                "schema must be {CONFIG_SCHEMA:?}, got {:?}",
                self.schema
            ));
        }
        if self.argv.first().is_none_or(|a| a.is_empty()) {
            return bad("argv must name the agent command".into());
        }
        if !self.workdir.is_empty() && !self.workdir.starts_with('/') {
            return bad(format!("workdir {:?} must be absolute", self.workdir));
        }
        for (field, paths) in [
            ("filesystem.read_only", &self.filesystem.read_only),
            ("filesystem.read_write", &self.filesystem.read_write),
            ("protected_paths", &self.protected_paths),
        ] {
            if let Some(p) = paths.iter().find(|p| !p.starts_with('/')) {
                return bad(format!("{field}: path {p:?} must be absolute"));
            }
        }
        if !self.report_path.is_empty() && !self.report_path.starts_with('/') {
            return bad(format!(
                "report_path {:?} must be absolute",
                self.report_path
            ));
        }
        for (field, v) in [
            ("process.user", &self.process.user),
            ("process.group", &self.process.group),
        ] {
            if is_root_name(v) {
                return bad(format!("{field}: running the agent as root is not allowed"));
            }
        }
        if let Some(k) = self.env.keys().find(|k| k.is_empty() || k.contains('=')) {
            return bad(format!("env: invalid variable name {k:?}"));
        }
        if let Some(a) = &self.attribution {
            if !(a.socket.len() > 1 && (a.socket.starts_with('@') || a.socket.starts_with('/'))) {
                return bad(format!(
                    "attribution.socket {:?} must be @name or an absolute path",
                    a.socket
                ));
            }
            if runeward_attribution::Key::from_hex(&a.key).is_err() {
                return bad("attribution.key must be 64 hex characters".into());
            }
            if let Some(p) = a.binaries.iter().find(|p| !p.starts_with('/')) {
                return bad(format!("attribution.binaries: path {p:?} must be absolute"));
            }
        }
        Ok(())
    }

    /// Every path the agent must not reach: [`STATE_DIR`], the report file,
    /// `protected_paths` and `config_path` when the config came from a file.
    pub fn protected(&self, config_path: Option<&Path>) -> Vec<PathBuf> {
        let mut out = vec![PathBuf::from(STATE_DIR)];
        if !self.report_path.is_empty() {
            out.push(PathBuf::from(&self.report_path));
        }
        out.extend(self.protected_paths.iter().map(PathBuf::from));
        if let Some(p) = config_path {
            out.push(p.to_path_buf());
        }
        out.sort();
        out.dedup();
        out
    }

    /// Fails when an allowed path would expose a protected one: any allowed
    /// path at or above a protected path, and any read-write path at or
    /// above `write_protected` (such as the supervisor's own binary). Paths
    /// are compared lexically and, where they exist, after resolving
    /// symlinks.
    pub fn check_protected(
        &self,
        protected: &[PathBuf],
        write_protected: &[PathBuf],
    ) -> Result<(), ConfigError> {
        let ro = &self.filesystem.read_only;
        let rw = &self.filesystem.read_write;
        for allowed in ro.iter().chain(rw) {
            if let Some(p) = protected.iter().find(|p| covers(Path::new(allowed), p)) {
                return Err(ConfigError::Invalid(format!(
                    "filesystem path {allowed:?} would expose the supervisor's protected path {:?}",
                    p.display().to_string()
                )));
            }
        }
        for allowed in rw {
            if let Some(p) = write_protected
                .iter()
                .find(|p| covers(Path::new(allowed), p))
            {
                return Err(ConfigError::Invalid(format!(
                    "filesystem.read_write path {allowed:?} would let the agent modify {:?}",
                    p.display().to_string()
                )));
            }
        }
        Ok(())
    }
}

fn dedup(v: &mut Vec<String>) {
    let mut seen = std::collections::BTreeSet::new();
    v.retain(|p| seen.insert(p.clone()));
}

/// Reports whether `allowed` grants access to `protected`, i.e. `protected`
/// is `allowed` itself or lies beneath it.
pub fn covers(allowed: &Path, protected: &Path) -> bool {
    let a = normalize(allowed);
    let p = normalize(protected);
    if p.starts_with(&a) {
        return true;
    }
    // Compare resolved forms too, so a symlinked allowed path cannot alias a
    // protected one. A protected path that does not exist yet is resolved
    // through its nearest existing ancestor.
    let ra = std::fs::canonicalize(&a).unwrap_or(a);
    let rp = canonicalize_lenient(&p);
    rp.starts_with(&ra)
}

/// Lexically resolves `.` and `..` in an absolute path.
fn normalize(p: &Path) -> PathBuf {
    let mut out = PathBuf::from("/");
    for c in p.components() {
        match c {
            Component::Normal(s) => out.push(s),
            Component::ParentDir => {
                out.pop();
            }
            Component::RootDir | Component::CurDir | Component::Prefix(_) => {}
        }
    }
    out
}

fn canonicalize_lenient(p: &Path) -> PathBuf {
    let mut tail = Vec::new();
    let mut cur = p.to_path_buf();
    loop {
        if let Ok(real) = std::fs::canonicalize(&cur) {
            let mut out = real;
            for part in tail.iter().rev() {
                out.push(part);
            }
            return out;
        }
        match (cur.file_name().map(|s| s.to_owned()), cur.parent()) {
            (Some(name), Some(parent)) => {
                tail.push(name);
                cur = parent.to_path_buf();
            }
            _ => return p.to_path_buf(),
        }
    }
}

/// Reports whether a user or group spec names root.
pub fn is_root_name(v: &str) -> bool {
    let v = v.trim();
    v == "root" || (!v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()) && v.parse() == Ok(0u64))
}

#[cfg(test)]
mod tests {
    use super::*;
    use runeward_charter::{Filesystem, Process};

    fn charter() -> Charter {
        let mut c = Charter::default();
        c.host.image = "alpine".into();
        c
    }

    #[test]
    fn charter_without_sections_turns_landlock_off() {
        let cfg = SupervisorConfig::from_charter(&charter(), "/workspace").expect("cfg");
        assert_eq!(cfg.argv, ["sleep", "infinity"]);
        assert_eq!(cfg.filesystem.landlock, LandlockMode::Off);
        assert!(cfg.filesystem.read_write.is_empty());
        assert!(cfg.seccomp);
        assert_eq!(cfg.workdir, "/workspace");
        assert_eq!(cfg.report_path, DEFAULT_REPORT_PATH);
    }

    #[test]
    fn charter_filesystem_and_process_map_through() {
        let mut c = charter();
        c.host.command = vec!["/usr/bin/agent".into(), "--serve".into()];
        c.filesystem = Some(Filesystem {
            read_only: vec!["/usr".into(), "/usr".into()],
            read_write: vec!["/tmp".into()],
            landlock: "required".into(),
            ..Filesystem::default()
        });
        c.process = Some(Process {
            run_as_user: "1500".into(),
            run_as_group: "1600".into(),
        });
        let cfg = SupervisorConfig::from_charter(&c, "/workspace")
            .expect("cfg")
            .with_env("TOKEN", "placeholder");
        assert_eq!(cfg.argv, ["/usr/bin/agent", "--serve"]);
        assert_eq!(cfg.filesystem.landlock, LandlockMode::Required);
        assert_eq!(
            cfg.filesystem.read_only,
            ["/usr", "/dev/random", "/dev/urandom"]
        );
        assert_eq!(cfg.filesystem.read_write[..2], ["/tmp", "/workspace"]);
        assert!(cfg.filesystem.read_write.iter().any(|p| p == "/dev/null"));
        assert_eq!(cfg.process.user, "1500");
        assert_eq!(cfg.process.group, "1600");
        assert_eq!(cfg.env["TOKEN"], "placeholder");

        let round = SupervisorConfig::from_json(cfg.to_json().as_bytes()).expect("round trip");
        assert_eq!(round, cfg);
    }

    #[test]
    fn include_workdir_false_and_best_effort_default() {
        let mut c = charter();
        c.filesystem = Some(Filesystem {
            include_workdir: false,
            ..Filesystem::default()
        });
        let cfg = SupervisorConfig::from_charter(&c, "/workspace").expect("cfg");
        assert_eq!(cfg.filesystem.landlock, LandlockMode::BestEffort);
        assert!(!cfg.filesystem.read_write.iter().any(|p| p == "/workspace"));
    }

    #[test]
    fn identity_falls_back_to_host_user() {
        let mut c = charter();
        c.host.user = "1000:1001".into();
        let cfg = SupervisorConfig::from_charter(&c, "/w").expect("cfg");
        assert_eq!(
            (cfg.process.user.as_str(), cfg.process.group.as_str()),
            ("1000", "1001")
        );

        c.process = Some(Process {
            run_as_user: String::new(),
            run_as_group: "2000".into(),
        });
        let cfg = SupervisorConfig::from_charter(&c, "/w").expect("cfg");
        assert_eq!(
            (cfg.process.user.as_str(), cfg.process.group.as_str()),
            ("1000", "2000")
        );
    }

    #[test]
    fn root_is_refused() {
        let mut c = charter();
        c.host.user = "root".into();
        assert!(SupervisorConfig::from_charter(&c, "/w").is_err());
        c.host.user = "0:0".into();
        assert!(SupervisorConfig::from_charter(&c, "/w").is_err());
        c.host.user = "000".into();
        assert!(SupervisorConfig::from_charter(&c, "/w").is_err());
        assert!(!is_root_name("1000"));
        assert!(!is_root_name(""));
    }

    #[test]
    fn rejects_bad_documents() {
        let cases = [
            (r#"{"argv":[]}"#, "argv"),
            (r#"{"argv":["a"],"schema":"v0"}"#, "schema"),
            (r#"{"argv":["a"],"workdir":"rel"}"#, "workdir"),
            (
                r#"{"argv":["a"],"filesystem":{"read_only":["usr"]}}"#,
                "read_only",
            ),
            (
                r#"{"argv":["a"],"filesystem":{"landlock":"maybe"}}"#,
                "JSON",
            ),
            (r#"{"argv":["a"],"process":{"user":"0"}}"#, "root"),
            (r#"{"argv":["a"],"env":{"A=B":"c"}}"#, "env"),
            (r#"{"argv":["a"],"surprise":true}"#, "JSON"),
        ];
        for (doc, want) in cases {
            let err = SupervisorConfig::from_json(doc.as_bytes())
                .expect_err(doc)
                .to_string();
            assert!(err.contains(want), "{doc}: {err}");
        }
        let ok = SupervisorConfig::from_json(br#"{"argv":["sh"]}"#).expect("minimal");
        assert!(ok.seccomp && ok.inherit_env);
        assert_eq!(ok.filesystem.landlock, LandlockMode::BestEffort);
    }

    #[test]
    fn attribution_is_validated_and_its_key_redacted() {
        let key = "ab".repeat(32);
        let cfg = SupervisorConfig::default()
            .with_argv(["sh"])
            .with_attribution(
                "@runeward-attribution",
                key.clone(),
                vec!["/usr/bin/curl".into()],
            );
        cfg.validate().expect("valid");
        let round = SupervisorConfig::from_json(cfg.to_json().as_bytes()).expect("round trip");
        assert_eq!(round, cfg);
        assert!(
            !format!("{cfg:?}").contains(&key),
            "Debug must not print the key"
        );
        // Absent attribution is not serialised at all.
        let plain = SupervisorConfig::default().with_argv(["sh"]);
        assert!(!plain.to_json().contains("attribution"));

        for (socket, k, bins, want) in [
            ("runeward", key.as_str(), vec!["/a"], "socket"),
            ("@", key.as_str(), vec!["/a"], "socket"),
            ("/run/x.sock", "abcd", vec!["/a"], "key"),
            ("@x", key.as_str(), vec!["curl"], "absolute"),
        ] {
            let c = SupervisorConfig::default()
                .with_argv(["sh"])
                .with_attribution(socket, k, bins.into_iter().map(String::from).collect());
            let err = c.validate().expect_err(socket).to_string();
            assert!(err.contains(want), "{socket}: {err}");
        }
    }

    #[test]
    fn protected_paths_cannot_be_exposed() {
        let mut cfg = SupervisorConfig::from_json(br#"{"argv":["sh"]}"#).expect("cfg");
        let protected = cfg.protected(Some(Path::new("/etc/runeward/supervisor.json")));
        assert!(protected.contains(&PathBuf::from(STATE_DIR)));
        let exe = [PathBuf::from("/usr/local/bin/runeward-supervisor")];

        for (ro, rw, want) in [
            (vec!["/usr"], vec!["/tmp"], None),
            (vec!["/"], vec![], Some("\"/\"")),
            (vec!["/run"], vec![], Some("/run")),
            (vec!["/etc/runeward"], vec![], Some("supervisor.json")),
            (vec![], vec!["/run/runeward/../runeward/x/.."], Some("/run")),
            (vec!["/usr/local"], vec![], None),
            (vec![], vec!["/usr/local"], Some("modify")),
        ] {
            cfg.filesystem.read_only = ro.iter().map(|s| (*s).to_owned()).collect();
            cfg.filesystem.read_write = rw.iter().map(|s| (*s).to_owned()).collect();
            let got = cfg.check_protected(&protected, &exe);
            match want {
                None => assert!(got.is_ok(), "{ro:?} {rw:?}: {got:?}"),
                Some(w) => {
                    let e = got.expect_err("must fail").to_string();
                    assert!(e.contains(w), "{ro:?} {rw:?}: {e}");
                }
            }
        }
    }

    #[test]
    fn covers_is_component_wise() {
        assert!(covers(Path::new("/run"), Path::new("/run/runeward")));
        assert!(!covers(Path::new("/ru"), Path::new("/run/runeward")));
        assert!(!covers(
            Path::new("/run/runeward-x"),
            Path::new("/run/runeward")
        ));
        assert!(covers(Path::new("/a/b/.."), Path::new("/a/c")));
    }

    #[cfg(unix)]
    #[test]
    fn covers_sees_through_symlinks() {
        let dir = tempfile::tempdir().expect("tmp");
        let real = dir.path().join("state");
        std::fs::create_dir(&real).expect("mkdir");
        let link = dir.path().join("alias");
        std::os::unix::fs::symlink(&real, &link).expect("symlink");
        assert!(covers(&link, &real.join("report.jsonl")));
    }
}
