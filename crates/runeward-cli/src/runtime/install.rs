//! `runeward runtime install <gvisor|kata>`: a turnkey installer for the
//! hardened runtimes. Dry-run by default (prints the exact plan and mutates
//! nothing); every download is checksum-verified and fails closed; every
//! shell-out is timeout-bounded; missing tooling becomes guidance.

use std::fmt::Write as _;
use std::io::Write as _;
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Result, anyhow, bail};
use futures_util::StreamExt;
use sha2::{Digest, Sha256, Sha512};
use tokio::io::AsyncWriteExt;

use super::first_line;
use crate::common::{go_io_error, go_join, go_quote};

const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(60);
const APPLY_TIMEOUT: Duration = Duration::from_secs(30);
const DOCKER_DAEMON_JSON: &str = "/etc/docker/daemon.json";
const LOCAL_BIN_DIR: &str = "/usr/local/bin";

/// Validated installer inputs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallOpts {
    /// `gvisor` or `kata`.
    pub runtime: String,
    /// `docker` or `k8s`.
    pub engine: String,
    /// Actually perform the install.
    pub apply: bool,
    /// gVisor release (`latest` or a date).
    pub version: String,
    /// RuntimeClass / docker runtime name.
    pub runtime_class: String,
    /// Optional sha256 pin for runsc.
    pub sha256hex: String,
}

/// Validates the flags into [`InstallOpts`].
pub fn resolve_opts(
    runtime: &str,
    engine: &str,
    apply: bool,
    version: &str,
    runtime_class: &str,
    sha256hex: &str,
) -> Result<InstallOpts> {
    let rt = runtime.trim().to_lowercase();
    if rt != "gvisor" && rt != "kata" {
        bail!(
            "unknown runtime {}: expected \"gvisor\" or \"kata\"",
            go_quote(runtime)
        );
    }
    let eng = engine.trim().to_lowercase();
    if eng != "docker" && eng != "k8s" {
        bail!(
            "unknown --engine {}: expected \"docker\" or \"k8s\"",
            go_quote(engine)
        );
    }
    let cls = match runtime_class.trim() {
        "" => rt.clone(),
        c => c.to_owned(),
    };
    let ver = match version.trim() {
        "" => "latest".to_owned(),
        v => v.to_owned(),
    };
    Ok(InstallOpts {
        runtime: rt,
        engine: eng,
        apply,
        version: ver,
        runtime_class: cls,
        sha256hex: sha256hex.trim().to_lowercase(),
    })
}

/// Runs the installer, writing its report to stdout.
pub async fn run(opts: &InstallOpts) -> Result<()> {
    let mut out = Out::default();
    let result = if opts.engine == "k8s" {
        install_k8s(&mut out, opts).await
    } else if opts.runtime == "gvisor" {
        install_gvisor_docker(&mut out, opts).await
    } else {
        install_kata_docker(&mut out, opts)
    };
    out.flush();
    result
}

/// Buffered output flushed as the installer progresses.
#[derive(Debug, Default)]
struct Out(String);

impl Out {
    fn line(&mut self, s: &str) {
        self.0.push_str(s);
        self.0.push('\n');
    }
    fn flush(&mut self) {
        let mut stdout = std::io::stdout().lock();
        let _ = stdout.write_all(self.0.as_bytes());
        let _ = stdout.flush();
        self.0.clear();
    }
}

impl std::fmt::Write for Out {
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        self.0.push_str(s);
        Ok(())
    }
}

fn is_root() -> bool {
    #[cfg(unix)]
    {
        nix::unistd::geteuid().is_root()
    }
    #[cfg(not(unix))]
    {
        false
    }
}

/// The gVisor release-bucket architecture token for this build.
pub fn gvisor_arch(arch: &str) -> Result<&'static str> {
    match arch {
        "x86_64" | "amd64" => Ok("x86_64"),
        "aarch64" | "arm64" => Ok("arm64"),
        other => bail!(
            "unsupported architecture {}: gVisor publishes amd64 (x86_64) and arm64 builds",
            go_quote(other)
        ),
    }
}

async fn install_gvisor_docker(out: &mut Out, opts: &InstallOpts) -> Result<()> {
    let arch = gvisor_arch(std::env::consts::ARCH)?;
    let base = format!(
        "https://storage.googleapis.com/gvisor/releases/release/{}/{arch}",
        opts.version
    );
    let runsc_url = format!("{base}/runsc");
    let shim_url = format!("{base}/containerd-shim-runsc-v1");

    header(out, "gVisor (runsc) -> Docker");
    out.line("Plan:");
    out.line("  1. Download + checksum-verify:");
    let _ = writeln!(out, "       {runsc_url} (+ .sha512)");
    let _ = writeln!(out, "       {shim_url} (+ .sha512)");
    if !opts.sha256hex.is_empty() {
        let _ = writeln!(out, "     runsc pinned to --sha256 {}", opts.sha256hex);
    }
    let _ = writeln!(
        out,
        "  2. chmod 0755 and install runsc + containerd-shim-runsc-v1 into {LOCAL_BIN_DIR}"
    );
    let _ = writeln!(
        out,
        "  3. Merge a \"runsc\" entry under \"runtimes\" in {DOCKER_DAEMON_JSON} (existing keys preserved)"
    );
    out.line("  4. Restart the engine: systemctl restart docker");
    out.line("");

    if !opts.apply {
        dry_run_note(out);
        next_steps(out, "runsc");
        return Ok(());
    }

    let tmp = tempfile::Builder::new()
        .prefix("runeward-gvisor-")
        .tempdir()
        .map_err(|e| anyhow!("create temp dir: {e}"))?;
    let root = is_root();
    // As root the binaries are moved out and the temp dir removed; otherwise
    // it is kept so the printed `sudo install` commands can use it.
    let (tmp_path, _cleanup) = if root {
        (tmp.path().to_path_buf(), Some(tmp))
    } else {
        (tmp.keep(), None)
    };
    let tmp_str = tmp_path.to_string_lossy().into_owned();
    let runsc_path = go_join(&[&tmp_str, "runsc"]);
    let shim_path = go_join(&[&tmp_str, "containerd-shim-runsc-v1"]);

    out.line("Downloading and verifying...");
    out.flush();
    download_verified(out, &runsc_url, &runsc_path, &opts.sha256hex).await?;
    download_verified(out, &shim_url, &shim_path, "").await?;
    for p in [&runsc_path, &shim_path] {
        set_mode(p, 0o755).map_err(|e| anyhow!("chmod {p}: {}", go_io_error("chmod", p, &e)))?;
    }

    let names = ["runsc", "containerd-shim-runsc-v1"];
    if !root {
        out.line("");
        out.line("Not running as root: binaries verified in a temp dir. Finish as root:");
        for name in names {
            let _ = writeln!(
                out,
                "  sudo install -m 0755 {} {}",
                go_join(&[&tmp_str, name]),
                go_join(&[LOCAL_BIN_DIR, name])
            );
        }
        let merged = merge_docker_runtime(
            Path::new(DOCKER_DAEMON_JSON),
            "runsc",
            &go_join(&[LOCAL_BIN_DIR, "runsc"]),
        )?;
        apply_daemon_json(out, &merged, false)?;
        let _ = writeln!(out, "  (remove the temp dir when done: rm -rf {tmp_str})");
        next_steps(out, "runsc");
        return Ok(());
    }

    for name in names {
        let src = go_join(&[&tmp_str, name]);
        let dst = go_join(&[LOCAL_BIN_DIR, name]);
        move_file(&src, &dst).map_err(|e| anyhow!("install {dst}: {e}"))?;
        let _ = writeln!(out, "  installed {dst}");
    }
    let merged = merge_docker_runtime(
        Path::new(DOCKER_DAEMON_JSON),
        "runsc",
        &go_join(&[LOCAL_BIN_DIR, "runsc"]),
    )?;
    apply_daemon_json(out, &merged, true)?;
    next_steps(out, "runsc");
    Ok(())
}

fn install_kata_docker(out: &mut Out, opts: &InstallOpts) -> Result<()> {
    header(out, "Kata Containers -> Docker");
    out.line("Kata's runtime install is distro-specific and is NOT automated here.");
    out.line("Install it via your distro or the official installer, e.g.:");
    out.line("  https://github.com/kata-containers/kata-containers/tree/main/docs/install");
    out.line("");

    let kata_path = detect_kata_binary();
    let entry_path = kata_path
        .clone()
        .unwrap_or_else(|| "/usr/bin/containerd-shim-kata-v2".into());
    let _ = writeln!(
        out,
        "Docker runtimes entry to add to {DOCKER_DAEMON_JSON} (merge, don't clobber):"
    );
    let _ = writeln!(
        out,
        "  \"runtimes\": {{ \"kata\": {{ \"path\": {} }} }}",
        go_quote(&entry_path)
    );
    out.line("");
    out.line("Then restart the engine: systemctl restart docker");
    out.line("");

    if !opts.apply {
        dry_run_note(out);
        next_steps(out, "kata");
        return Ok(());
    }
    let Some(found) = kata_path else {
        out.line("Kata binary not found (looked for containerd-shim-kata-v2 / kata-runtime).");
        out.line("Install Kata first, then re-run with --apply to register it with docker.");
        next_steps(out, "kata");
        return Ok(());
    };
    let _ = writeln!(out, "Found Kata binary: {found}");
    let merged = merge_docker_runtime(Path::new(DOCKER_DAEMON_JSON), "kata", &entry_path)?;
    apply_daemon_json(out, &merged, is_root())?;
    next_steps(out, "kata");
    Ok(())
}

async fn install_k8s(out: &mut Out, opts: &InstallOpts) -> Result<()> {
    let (handler, label) = if opts.runtime == "kata" {
        ("kata", "Kata Containers")
    } else {
        ("runsc", "gVisor (runsc)")
    };
    header(out, &format!("{label} -> Kubernetes RuntimeClass"));
    let manifest = runtime_class_manifest(&opts.runtime_class, handler);
    out.line("RuntimeClass manifest:");
    out.line("");
    out.0.push_str(&manifest);
    out.line("");

    if !opts.apply {
        out.line("Dry-run (default): nothing was applied.");
        out.line("Re-run with --apply to `kubectl apply -f -` the manifest above.");
        next_steps(out, &opts.runtime_class);
        return Ok(());
    }
    let Some(bin) = runeward_backend::look_path("kubectl") else {
        out.line("kubectl not found in PATH — apply the manifest above manually, e.g.:");
        out.line("  kubectl apply -f - <<'EOF'");
        out.0.push_str(&manifest);
        out.line("EOF");
        next_steps(out, &opts.runtime_class);
        return Ok(());
    };
    let stdout = kubectl_apply(&bin, &manifest)
        .await
        .map_err(|detail| anyhow!("kubectl apply failed: {}", first_line(&detail)))?;
    let s = stdout.trim();
    if !s.is_empty() {
        out.line(s);
    }
    let _ = writeln!(
        out,
        "applied RuntimeClass {} (handler {handler})",
        go_quote(&opts.runtime_class)
    );
    next_steps(out, &opts.runtime_class);
    Ok(())
}

async fn kubectl_apply(bin: &Path, manifest: &str) -> Result<String, String> {
    let mut child = tokio::process::Command::new(bin)
        .args(["apply", "-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| e.to_string())?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(manifest.as_bytes())
            .await
            .map_err(|e| e.to_string())?;
    }
    let out = tokio::time::timeout(APPLY_TIMEOUT, child.wait_with_output())
        .await
        .map_err(|_| "signal: killed".to_owned())?
        .map_err(|e| e.to_string())?;
    if out.status.success() {
        return Ok(String::from_utf8_lossy(&out.stdout).into_owned());
    }
    let detail = String::from_utf8_lossy(&out.stderr).trim().to_owned();
    if detail.is_empty() {
        Err(super::exit_status_text(&out.status))
    } else {
        Err(detail)
    }
}

/// A minimal, valid RuntimeClass for `handler`.
pub fn runtime_class_manifest(name: &str, handler: &str) -> String {
    format!(
        "apiVersion: node.k8s.io/v1\nkind: RuntimeClass\nmetadata:\n  name: {name}\nhandler: {handler}\n"
    )
}

/// Fetches `url` into `dst` and verifies it, failing closed: against
/// `sha256hex` when set, otherwise against the required `<url>.sha512`
/// sidecar.
async fn download_verified(out: &mut Out, url: &str, dst: &str, sha256hex: &str) -> Result<()> {
    http_get_to_file(url, dst)
        .await
        .map_err(|e| anyhow!("download {url}: {e}"))?;
    let base = Path::new(dst)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    if !sha256hex.is_empty() {
        verify_checksum_file::<Sha256>(dst, sha256hex)?;
        let _ = writeln!(out, "  verified {base} (sha256 {})", short_hex(sha256hex));
        out.flush();
        return Ok(());
    }
    let sidecar = format!("{dst}.sha512");
    http_get_to_file(&format!("{url}.sha512"), &sidecar)
        .await
        .map_err(|e| {
            anyhow!(
                "download checksum {url}.sha512: {e} (refusing to install an unverified binary)"
            )
        })?;
    let data = std::fs::read(&sidecar).map_err(|e| anyhow!("read checksum sidecar: {e}"))?;
    let want = parse_checksum_sidecar(&data)?;
    verify_checksum_file::<Sha512>(dst, &want)?;
    let _ = writeln!(out, "  verified {base} (sha512 {})", short_hex(&want));
    out.flush();
    Ok(())
}

/// Streams a GET body to `dst`; any status but 200 is an error.
async fn http_get_to_file(url: &str, dst: &str) -> Result<()> {
    let client = reqwest::Client::builder()
        .timeout(DOWNLOAD_TIMEOUT)
        .build()?;
    let resp = client.get(url).send().await?;
    if resp.status() != reqwest::StatusCode::OK {
        bail!("unexpected status {}", resp.status());
    }
    let mut f = tokio::fs::File::create(dst)
        .await
        .map_err(|e| anyhow!(go_io_error("open", dst, &e)))?;
    let mut body = resp.bytes_stream();
    while let Some(chunk) = body.next().await {
        f.write_all(&chunk?).await?;
    }
    f.flush().await?;
    Ok(())
}

/// Hashes `path` with `D` and compares case-insensitively with `expected`.
fn verify_checksum_file<D: Digest>(path: &str, expected: &str) -> Result<()> {
    let data = std::fs::read(path).map_err(|e| anyhow!(go_io_error("open", path, &e)))?;
    let got = hex::encode(D::digest(&data));
    if !got.trim().eq_ignore_ascii_case(expected.trim()) {
        let base = Path::new(path)
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        bail!("checksum mismatch for {base}: got {got}, want {expected} (failing closed)");
    }
    Ok(())
}

/// The hex digest of a sha512sum-style sidecar (`<hex>  <filename>`).
pub fn parse_checksum_sidecar(data: &[u8]) -> Result<String> {
    String::from_utf8_lossy(data)
        .split_whitespace()
        .next()
        .map(str::to_owned)
        .ok_or_else(|| anyhow!("empty or malformed checksum sidecar"))
}

/// Read-merge-writes `daemon.json` in memory: adds or updates one runtime
/// under `runtimes`, keeping every other key, and returns indented JSON.
pub fn merge_docker_runtime(daemon_json: &Path, name: &str, path: &str) -> Result<String> {
    let shown = daemon_json.display();
    let mut top = serde_json::Map::new();
    match std::fs::read(daemon_json) {
        Ok(data) => {
            if !String::from_utf8_lossy(&data).trim().is_empty() {
                top = serde_json::from_slice(&data).map_err(|e| anyhow!("parse {shown}: {e}"))?;
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => bail!(
            "read {shown}: {}",
            go_io_error("open", &shown.to_string(), &e)
        ),
    }
    let mut runtimes = match top.remove("runtimes") {
        Some(serde_json::Value::Object(m)) => m,
        Some(serde_json::Value::Null) | None => serde_json::Map::new(),
        Some(_) => bail!("parse runtimes in {shown}: not a JSON object"),
    };
    runtimes.insert(name.to_owned(), serde_json::json!({ "path": path }));
    top.insert("runtimes".into(), serde_json::Value::Object(runtimes));
    // Sorted keys, as Go's encoding of a map.
    let sorted: std::collections::BTreeMap<_, _> = top.into_iter().collect();
    Ok(serde_json::to_string_pretty(&sorted)?)
}

/// Writes the merged `daemon.json` as root, else prints the sudo commands.
fn apply_daemon_json(out: &mut Out, merged: &str, root: bool) -> Result<()> {
    if root {
        crate::signing::mkdir_all("/etc/docker", 0o755)
            .map_err(|e| anyhow!("ensure {DOCKER_DAEMON_JSON} dir: {e}"))?;
        crate::signing::write_file(DOCKER_DAEMON_JSON, format!("{merged}\n").as_bytes(), 0o644)
            .map_err(|e| anyhow!("write {DOCKER_DAEMON_JSON}: {e}"))?;
        let _ = writeln!(out, "  wrote {DOCKER_DAEMON_JSON}");
        out.line("  restart the engine: systemctl restart docker");
        return Ok(());
    }
    let _ = writeln!(
        out,
        "  # not root: write the merged {DOCKER_DAEMON_JSON} yourself:"
    );
    let _ = writeln!(out, "  sudo tee {DOCKER_DAEMON_JSON} >/dev/null <<'EOF'");
    out.line(merged);
    out.line("EOF");
    out.line("  sudo systemctl restart docker");
    Ok(())
}

#[cfg(unix)]
fn set_mode(path: &str, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}

#[cfg(not(unix))]
fn set_mode(_path: &str, _mode: u32) -> std::io::Result<()> {
    Ok(())
}

/// Renames, falling back to copy+remove across filesystems.
fn move_file(src: &str, dst: &str) -> std::io::Result<()> {
    if std::fs::rename(src, dst).is_ok() {
        return Ok(());
    }
    std::fs::copy(src, dst)?;
    set_mode(dst, 0o755)?;
    std::fs::remove_file(src)
}

/// An installed Kata shim/runtime, if any.
fn detect_kata_binary() -> Option<String> {
    for c in [
        "/usr/bin/containerd-shim-kata-v2",
        "/usr/local/bin/containerd-shim-kata-v2",
        "/usr/bin/kata-runtime",
    ] {
        if std::fs::metadata(c).is_ok_and(|m| !m.is_dir()) {
            return Some(c.to_owned());
        }
    }
    ["containerd-shim-kata-v2", "kata-runtime"]
        .into_iter()
        .find_map(runeward_backend::look_path)
        .map(|p| p.to_string_lossy().into_owned())
}

fn header(out: &mut Out, title: &str) {
    out.line(title);
    out.line(&"=".repeat(title.len()));
    out.line("");
}

fn dry_run_note(out: &mut Out) {
    out.line("Dry-run (default): nothing above was executed.");
    out.line("Re-run with --apply to perform these steps.");
}

fn next_steps(out: &mut Out, class_name: &str) {
    out.line("");
    out.line("Next steps");
    out.line("----------");
    let _ = writeln!(
        out,
        "  1. Set runtime_class = {} under [host] in your Charter.",
        go_quote(class_name)
    );
    out.line("  2. Verify with: runeward runtime check");
    out.line("  3. Details: docs/security-model.md");
}

fn short_hex(h: &str) -> String {
    if h.len() > 12 {
        format!("{}...", &h[..12])
    } else {
        h.to_owned()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn opts_validate_and_default() {
        let o = resolve_opts(" GVisor ", "Docker", false, "", "", " ABC ").unwrap();
        assert_eq!(o.runtime, "gvisor");
        assert_eq!(o.engine, "docker");
        assert_eq!(o.version, "latest");
        assert_eq!(o.runtime_class, "gvisor");
        assert_eq!(o.sha256hex, "abc");
        assert_eq!(
            resolve_opts("runc", "docker", false, "", "", "")
                .unwrap_err()
                .to_string(),
            "unknown runtime \"runc\": expected \"gvisor\" or \"kata\""
        );
        assert!(resolve_opts("kata", "podman", false, "", "", "").is_err());
    }

    #[test]
    fn arch_and_manifest() {
        assert_eq!(gvisor_arch("x86_64").unwrap(), "x86_64");
        assert_eq!(gvisor_arch("aarch64").unwrap(), "arm64");
        assert!(gvisor_arch("riscv64").is_err());
        assert_eq!(
            runtime_class_manifest("gvisor", "runsc"),
            "apiVersion: node.k8s.io/v1\nkind: RuntimeClass\nmetadata:\n  name: gvisor\nhandler: runsc\n"
        );
    }

    #[test]
    fn checksums_fail_closed() {
        assert_eq!(
            parse_checksum_sidecar(b"abc123  runsc\n").unwrap(),
            "abc123"
        );
        assert!(parse_checksum_sidecar(b"  \n").is_err());
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("bin");
        std::fs::write(&f, b"hello").unwrap();
        let p = f.to_string_lossy();
        let good = hex::encode(Sha256::digest(b"hello"));
        verify_checksum_file::<Sha256>(&p, &good.to_uppercase()).unwrap();
        let err = verify_checksum_file::<Sha256>(&p, "00").unwrap_err();
        assert!(err.to_string().contains("failing closed"));
    }

    #[test]
    fn daemon_json_merge_keeps_other_keys() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("daemon.json");
        let fresh = merge_docker_runtime(&path, "runsc", "/usr/local/bin/runsc").unwrap();
        assert_eq!(
            fresh,
            "{\n  \"runtimes\": {\n    \"runsc\": {\n      \"path\": \"/usr/local/bin/runsc\"\n    }\n  }\n}"
        );
        std::fs::write(
            &path,
            r#"{"log-driver":"json-file","runtimes":{"kata":{"path":"/k"}}}"#,
        )
        .unwrap();
        let merged = merge_docker_runtime(&path, "runsc", "/r").unwrap();
        let v: serde_json::Value = serde_json::from_str(&merged).unwrap();
        assert_eq!(v["log-driver"], "json-file");
        assert_eq!(v["runtimes"]["kata"]["path"], "/k");
        assert_eq!(v["runtimes"]["runsc"]["path"], "/r");
        std::fs::write(&path, "{not json").unwrap();
        assert!(merge_docker_runtime(&path, "runsc", "/r").is_err());
    }
}
