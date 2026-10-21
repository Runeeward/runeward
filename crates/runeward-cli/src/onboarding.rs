//! First-run commands: `init` (starter Charter), `doctor` (readiness checks)
//! and `quickstart` (starter Charter plus an allow/deny/audit proof).

use std::io::Write;

use anyhow::{Result, anyhow, bail};
use runeward_charter::{Charter, HostType, Severity, Verdict};
use runeward_controlplane::{CreateOptions, Manager, ManagerConfig};
use serde::Serialize;

use crate::common::{
    charter_options, expand_home, go_dir, go_io_error, go_join, go_quote, manager_config_dir,
    resolve_config_dir,
};
use crate::signing::mkdir_all;
use crate::version::VERSION;

/// The Charter written by `init` and `quickstart`.
pub const STARTER_CHARTER: &str = r#"# Runeward starter policy (a "Charter").
# Common terms come first: this file defines one governed AI-agent sandbox.
policy_default = "allow"

[host]
type    = "container"
image   = "ghcr.io/runeeward/runeward-sandbox:latest"
workdir = "/workspace"

# Start with no outbound network access. Add only the hosts the task needs.
[network]
default = "deny"

# Keep strict validation useful while preserving deny-by-default egress.
[[network.rule]]
verdict  = "allow"
hostname = "example.com"

# Demonstrates deterministic pre-execution blocking.
[[policy]]
tool    = "shell"
match   = "rm -rf *"
verdict = "deny"
reason  = "recursive force delete blocked by the starter policy"

# Keep ordinary local work usable while the starter policy stays understandable.
[[policy]]
tool    = "shell"
match   = "*"
verdict = "allow"

[[policy]]
tool    = "file.write"
match   = "/workspace/**"
verdict = "allow"

[[policy]]
tool    = "file.write"
match   = "*"
verdict = "require-approval"
reason  = "writes outside /workspace require human approval"

[rationing]
wall_clock = "30m"
max_execs  = 200

[chronicle]
redact = true
"#;

/// One readiness check reported by `doctor`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DoctorCheck {
    /// What was checked.
    pub name: String,
    /// `ok`, `warn` or `fail`.
    pub status: String,
    /// Details.
    pub message: String,
}

fn check(name: &str, status: &str, message: impl Into<String>) -> DoctorCheck {
    DoctorCheck {
        name: name.into(),
        status: status.into(),
        message: message.into(),
    }
}

#[cfg(unix)]
fn chmod(path: &str, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}

#[cfg(not(unix))]
fn chmod(_path: &str, _mode: u32) -> std::io::Result<()> {
    Ok(())
}

/// Writes the starter Charter to `<project_dir>/.runeward/<name>.toml`
/// (0600 in a 0700 directory). An existing file is kept (and re-secured)
/// unless `force`. Returns the path and whether it was written.
pub fn write_starter_charter(project_dir: &str, name: &str, force: bool) -> Result<(String, bool)> {
    let name = name.trim();
    if name.is_empty() || name.contains(['/', '\\']) || name == "." || name == ".." {
        bail!("invalid starter policy name {}", go_quote(name));
    }
    let config_dir = go_join(&[project_dir, ".runeward"]);
    mkdir_all(&config_dir, 0o700).map_err(|e| {
        anyhow!(
            "create {config_dir}: {}",
            go_io_error("mkdir", &config_dir, &e)
        )
    })?;
    chmod(&config_dir, 0o700).map_err(|e| {
        anyhow!(
            "secure {config_dir}: {}",
            go_io_error("chmod", &config_dir, &e)
        )
    })?;
    let path = go_join(&[&config_dir, &format!("{name}.toml")]);
    match std::fs::metadata(&path) {
        Ok(_) if !force => {
            chmod(&path, 0o600)
                .map_err(|e| anyhow!("secure {path}: {}", go_io_error("chmod", &path, &e)))?;
            return Ok((path, false));
        }
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => bail!(go_io_error("stat", &path, &e)),
    }
    crate::signing::write_file(&path, STARTER_CHARTER.as_bytes(), 0o600)
        .map_err(|e| anyhow!("write {path}: {e}"))?;
    chmod(&path, 0o600)
        .map_err(|e| anyhow!("secure {path}: {}", go_io_error("chmod", &path, &e)))?;
    Ok((path, true))
}

/// `runeward init [project-dir]`.
pub fn init(dir: Option<&str>, name: &str, force: bool) -> Result<()> {
    let dir = dir.unwrap_or(".");
    let (path, created) = write_starter_charter(dir, name, force)?;
    let verb = if created { "created" } else { "already exists" };
    let config = go_quote(&go_dir(&path));
    println!("{verb}: {path}");
    println!(
        "next: runeward --config-dir {config} doctor {name} && runeward --config-dir {config} enter {name} -- echo hello"
    );
    Ok(())
}

fn doctor_marker(status: &str) -> &'static str {
    match status {
        "ok" => "[ok]",
        "warn" => "[warn]",
        _ => "[fail]",
    }
}

fn render_checks(checks: &[DoctorCheck]) -> String {
    checks
        .iter()
        .map(|c| {
            format!(
                "{:<5} {:<12} {}\n",
                doctor_marker(&c.status),
                c.name,
                c.message
            )
        })
        .collect()
}

#[derive(Serialize)]
struct DoctorReport<'a> {
    checks: &'a [DoctorCheck],
    ready: bool,
}

/// `runeward doctor [charter]`.
pub async fn doctor(name: Option<&str>, as_json: bool, config_dir: &str) -> Result<()> {
    let (checks, ready) = run_doctor(&resolve_config_dir(config_dir), name.unwrap_or("")).await;
    let mut stdout = std::io::stdout().lock();
    if as_json {
        runeward_ledger::gojson::encode_indent(
            &mut stdout,
            &DoctorReport {
                checks: &checks,
                ready,
            },
        )?;
    } else {
        stdout.write_all(render_checks(&checks).as_bytes())?;
    }
    if !ready {
        bail!("setup is not ready; fix the failed checks above");
    }
    Ok(())
}

/// Runs every readiness check; the bool reports whether all passed.
pub async fn run_doctor(config_dir: &str, requested: &str) -> (Vec<DoctorCheck>, bool) {
    let mut checks = vec![check("version", "ok", VERSION)];
    let mut ready = true;
    let opts = charter_options(config_dir);
    let names = runeward_charter::list(&opts);
    if names.is_empty() {
        checks.push(check(
            "policies",
            "fail",
            "no policies found; run `runeward init`",
        ));
        return (checks, false);
    }
    checks.push(check("policies", "ok", format!("{} found", names.len())));

    let name = if requested.is_empty() {
        preferred_doctor_profile(&names, config_dir)
    } else {
        requested.to_owned()
    };
    let p = match runeward_charter::load(&name, &opts) {
        Ok(p) => p,
        Err(e) => {
            checks.push(check("charter", "fail", e.to_string()));
            return (checks, false);
        }
    };
    let findings = runeward_charter::lint(&p);
    let errs = findings
        .iter()
        .filter(|f| f.severity == Severity::Error)
        .count();
    let warns = findings.len() - errs;
    let status = if errs > 0 {
        ready = false;
        "fail"
    } else if warns > 0 {
        "warn"
    } else {
        "ok"
    };
    checks.push(check(
        "charter",
        status,
        format!("{name} ({errs} errors, {warns} warnings)"),
    ));

    match runeward_backend::for_charter(&p).await {
        Ok(be) => checks.push(check("runtime", "ok", format!("{} reachable", be.name()))),
        Err(e) => {
            checks.push(check(
                "runtime",
                "fail",
                friendly_runtime_error(&e.to_string()),
            ));
            ready = false;
        }
    }
    match check_profile_prerequisites(&p).await {
        Ok(()) => checks.push(check(
            "secrets",
            "ok",
            "required environment and secret sources resolved",
        )),
        Err(e) => {
            checks.push(check("secrets", "fail", e));
            ready = false;
        }
    }
    let image = &p.host.image;
    if image.ends_with(":dev") || !image.contains('/') {
        checks.push(check(
            "image",
            "warn",
            format!("{image} (local/development image; prefer a published immutable reference)"),
        ));
    } else {
        checks.push(check("image", "ok", image.clone()));
    }

    let state_dir = ManagerConfig::from_env()
        .state_dir
        .map(|d| d.to_string_lossy().into_owned())
        .unwrap_or_default();
    match check_writable_dir(&state_dir) {
        Ok(()) => checks.push(check("state", "ok", state_dir)),
        Err(e) => {
            checks.push(check("state", "fail", e));
            ready = false;
        }
    }
    (checks, ready)
}

/// Resolves every `[[env]]` source without exposing values, failing closed
/// like the control plane does when it provisions a sandbox.
async fn check_profile_prerequisites(p: &Charter) -> Result<(), String> {
    let resolver = runeward_secrets::Dispatcher::from_env();
    for e in &p.env {
        if !e.op.is_empty() {
            resolver.resolve(&e.op).await.map_err(|err| {
                format!(
                    "env {}: resolve {}: {err}",
                    go_quote(&e.name),
                    go_quote(&e.op)
                )
            })?;
        } else if !e.file.is_empty() {
            let path = expand_home(&e.file);
            std::fs::read(&path).map_err(|err| {
                format!(
                    "env {}: read file {}: {}",
                    go_quote(&e.name),
                    go_quote(&e.file),
                    go_io_error("open", &path, &err)
                )
            })?;
        }
    }
    Ok(())
}

/// Picks the Charter to check: a well-known starter name, else the first
/// container-hosted Charter, else the first name.
fn preferred_doctor_profile(names: &[String], config_dir: &str) -> String {
    for preferred in ["quickstart", "dev", "ns-auto"] {
        if names.iter().any(|n| n == preferred) {
            return preferred.to_owned();
        }
    }
    let mut sorted = names.to_vec();
    sorted.sort();
    let opts = charter_options(config_dir);
    for name in &sorted {
        if let Ok(p) = runeward_charter::load(name, &opts)
            && p.host.host_type == HostType::Container
        {
            return name.clone();
        }
    }
    sorted.first().cloned().unwrap_or_default()
}

/// Creates `dir` (0700) and proves a file can be created and removed in it.
fn check_writable_dir(dir: &str) -> Result<(), String> {
    mkdir_all(dir, 0o700)
        .map_err(|e| format!("create {dir}: {}", go_io_error("mkdir", dir, &e)))?;
    let probe = tempfile::Builder::new()
        .prefix(".doctor-")
        .tempfile_in(dir)
        .map_err(|e| {
            format!(
                "state directory {dir} is not writable: {}",
                go_io_error("open", &go_join(&[dir, ".doctor-*"]), &e)
            )
        })?;
    let name = probe.path().to_string_lossy().into_owned();
    probe.close().map_err(|e| {
        format!(
            "remove state-directory probe {name}: {}",
            go_io_error("remove", &name, &e)
        )
    })
}

/// Shortens an unreachable-engine error to an actionable message without
/// the raw socket detail.
pub fn friendly_runtime_error(msg: &str) -> String {
    if msg.contains("engine not reachable") {
        let short = match msg.find(" (") {
            Some(i) if i > 0 => &msg[..i],
            _ => msg,
        };
        return format!("{short}; start Docker/Podman, then run `runeward doctor` again");
    }
    msg.to_owned()
}

/// `runeward quickstart [project-dir]`.
pub async fn quickstart(dir: Option<&str>, no_run: bool, force: bool) -> Result<()> {
    let dir = dir.unwrap_or(".");
    let (path, _) = write_starter_charter(dir, "quickstart", force)?;
    println!("starter policy: {path}");
    if no_run {
        println!(
            "setup complete; run `runeward doctor quickstart` when your container engine is ready"
        );
        return Ok(());
    }
    let config_dir = go_join(&[dir, ".runeward"]);
    let (checks, ready) = run_doctor(&config_dir, "quickstart").await;
    if !ready {
        print!("{}", render_checks(&checks));
        bail!("quickstart is not ready; start the container engine and retry (or use --no-run)");
    }
    run_quickstart_proof(&config_dir).await
}

/// Creates a sandbox from the starter Charter, runs an allowed command,
/// proves a destructive one is denied, and verifies the signed Chronicle.
async fn run_quickstart_proof(config_dir: &str) -> Result<()> {
    let mgr = Manager::open(manager_config_dir(config_dir)).await?;
    let result = quickstart_proof(&mgr).await;
    let _ = mgr.close().await;
    result
}

async fn quickstart_proof(mgr: &Manager) -> Result<()> {
    let sb = mgr
        .create_sandbox("quickstart", CreateOptions::default())
        .await?;
    let result = async {
        let allowed = mgr
            .shell(
                &sb.id,
                &argv(&["sh", "-lc", "echo 'allow: sandbox command executed'"]),
                "/workspace",
            )
            .await?;
        print!("{}", allowed.stdout);
        std::io::stdout().flush()?;
        let denied = mgr
            .shell(
                &sb.id,
                &argv(&["rm", "-rf", "/tmp/runeward-proof"]),
                "/workspace",
            )
            .await?;
        if denied.verdict != Verdict::Deny {
            bail!(
                "starter policy proof failed: destructive command verdict was {}",
                go_quote(denied.verdict.as_str())
            );
        }
        println!("deny: {}", denied.reason);
        mgr.verify_ledger().await?;
        println!("audit: signed Chronicle verified for sandbox {}", sb.id);
        println!("next: runeward --config-dir .runeward serve");
        Ok(())
    }
    .await;
    let _ = mgr.kill_sandbox(&sb.id).await;
    result
}

fn argv(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|s| (*s).to_owned()).collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[cfg(unix)]
    fn mode(path: &str) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn write_starter_charter_creates_a_strict_private_policy() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().to_string_lossy().into_owned();
        let (path, created) = write_starter_charter(&dir, "quickstart", false).unwrap();
        assert!(created, "starter should be created");
        assert_eq!(path, go_join(&[&dir, ".runeward", "quickstart.toml"]));
        #[cfg(unix)]
        {
            assert_eq!(mode(&go_dir(&path)), 0o700);
            assert_eq!(mode(&path), 0o600);
        }
        let p = runeward_charter::load(
            "quickstart",
            &runeward_charter::Options {
                working_dir: Some(tmp.path().to_path_buf()),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(p.host.image, "ghcr.io/runeeward/runeward-sandbox:latest");
        assert_eq!(p.network.default, "deny");
        let findings = runeward_charter::lint(&p);
        assert!(
            findings.is_empty(),
            "starter must pass strict validation, findings: {findings:?}"
        );

        std::fs::write(&path, "sentinel").unwrap();
        #[cfg(unix)]
        {
            chmod(&go_dir(&path), 0o755).unwrap();
            chmod(&path, 0o644).unwrap();
        }
        let (_, created) = write_starter_charter(&dir, "quickstart", false).unwrap();
        assert!(!created, "existing file must not be recreated");
        assert_eq!(std::fs::read_to_string(&path).unwrap().trim(), "sentinel");
        #[cfg(unix)]
        {
            assert_eq!(mode(&go_dir(&path)), 0o700);
            assert_eq!(mode(&path), 0o600);
        }
    }

    #[test]
    fn starter_names_must_be_plain() {
        for bad in ["", "a/b", "a\\b", ".", ".."] {
            assert!(write_starter_charter(".", bad, false).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn friendly_runtime_error_redacts_socket_detail() {
        let got = friendly_runtime_error(
            "docker engine not reachable; is docker running? (dial unix /private/path.sock)",
        );
        assert!(
            !got.contains("/private/path.sock"),
            "raw socket path leaked: {got}"
        );
        assert!(
            got.contains("runeward doctor"),
            "missing recovery instruction: {got}"
        );
    }

    #[test]
    fn checks_render_like_go() {
        let out = render_checks(&[check("version", "ok", "1.0"), check("image", "warn", "x")]);
        assert_eq!(out, "[ok]  version      1.0\n[warn] image        x\n");
    }
}
