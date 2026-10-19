//! Helpers shared by several commands: Charter resolution, `[[env]]`
//! projection, Go-compatible path joining and quoting, and shutdown signals.

use std::collections::BTreeMap;
use std::io;
use std::path::PathBuf;

use runeward_charter::{Charter, LoadError, Options};

/// Pins Charter resolution when `--config-dir` is not given.
pub const CONFIG_DIR_ENV: &str = "RUNEWARD_CONFIG_DIR";

/// The configuration directory: the `--config-dir` flag, else
/// `$RUNEWARD_CONFIG_DIR` (empty means the default search path).
pub fn resolve_config_dir(flag: &str) -> String {
    if flag.is_empty() {
        std::env::var(CONFIG_DIR_ENV).unwrap_or_default()
    } else {
        flag.to_owned()
    }
}

/// Charter loader options for an (already resolved) configuration directory.
pub fn charter_options(config_dir: &str) -> Options {
    Options {
        config_dir: (!config_dir.is_empty()).then(|| PathBuf::from(config_dir)),
        ..Options::default()
    }
}

/// The configuration directory as the control plane takes it.
pub fn manager_config_dir(config_dir: &str) -> Option<PathBuf> {
    (!config_dir.is_empty()).then(|| PathBuf::from(config_dir))
}

/// Resolves a Charter by name, honoring `--config-dir` and
/// `$RUNEWARD_CONFIG_DIR`.
pub fn load_profile(name: &str, config_dir_flag: &str) -> Result<Charter, LoadError> {
    runeward_charter::load(name, &charter_options(&resolve_config_dir(config_dir_flag)))
}

/// Turns a Charter's `[[env]]` entries into name/value pairs for `enter`.
/// Values are never written to disk; non-fatal problems come back as
/// warnings.
pub fn resolve_env(c: &Charter) -> (BTreeMap<String, String>, Vec<String>) {
    let mut out = BTreeMap::new();
    let mut warnings = Vec::new();
    for e in &c.env {
        if !e.op.is_empty() {
            warnings.push(format!(
                "env {}: 1Password resolution ({}) not yet implemented; skipped",
                e.name, e.op
            ));
        } else if !e.file.is_empty() {
            match std::fs::read(expand_home(&e.file)) {
                Ok(b) => {
                    let v = String::from_utf8_lossy(&b);
                    out.insert(e.name.clone(), v.trim_end_matches(['\r', '\n']).to_owned());
                }
                Err(err) => warnings.push(format!(
                    "env {}: read {}: {}; skipped",
                    e.name,
                    e.file,
                    go_io_error("open", &expand_home(&e.file), &err)
                )),
            }
        } else if !e.value.is_empty() {
            out.insert(e.name.clone(), e.value.clone());
        }
    }
    (out, warnings)
}

/// Expands a leading `~/` to the home directory.
pub fn expand_home(p: &str) -> String {
    if let Some(rest) = p.strip_prefix("~/")
        && let Some(home) = std::env::home_dir()
    {
        return format!("{}/{rest}", home.display());
    }
    p.to_owned()
}

/// Go's `strconv.Quote` (and `%q`): a double-quoted string with Go escapes.
pub fn go_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\x07' => out.push_str("\\a"),
            '\x08' => out.push_str("\\b"),
            '\x0c' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\x0b' => out.push_str("\\v"),
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                out.push_str(&format!("\\x{:02x}", c as u32));
            }
            c if c.is_control() => {
                let n = c as u32;
                if n > 0xffff {
                    out.push_str(&format!("\\U{n:08x}"));
                } else {
                    out.push_str(&format!("\\u{n:04x}"));
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Formats an I/O failure the way Go's `*PathError` prints
/// (`open <path>: no such file or directory`).
pub fn go_io_error(op: &str, path: &str, err: &io::Error) -> String {
    format!("{op} {path}: {}", go_errno_text(err))
}

/// The lower-case errno text Go prints for common failures.
pub fn go_errno_text(err: &io::Error) -> String {
    match err.kind() {
        io::ErrorKind::NotFound => "no such file or directory".into(),
        io::ErrorKind::PermissionDenied => "permission denied".into(),
        io::ErrorKind::AlreadyExists => "file exists".into(),
        io::ErrorKind::IsADirectory => "is a directory".into(),
        io::ErrorKind::NotADirectory => "not a directory".into(),
        _ => {
            let s = err.to_string();
            // Drop Rust's " (os error N)" suffix and lower-case the first
            // letter, which is what Go's syscall errors look like.
            let s = s.split(" (os error").next().unwrap_or_default();
            let mut chars = s.chars();
            match chars.next() {
                Some(f) => f.to_lowercase().chain(chars).collect(),
                None => String::new(),
            }
        }
    }
}

/// Reads a file, reporting failures like Go's `os.ReadFile`.
pub fn read_file(path: &str) -> Result<Vec<u8>, String> {
    std::fs::read(path).map_err(|e| go_io_error("open", path, &e))
}

/// Go's `filepath.Clean` for slash-separated paths.
pub fn go_clean(path: &str) -> String {
    if path.is_empty() {
        return ".".into();
    }
    let rooted = path.starts_with('/');
    let mut parts: Vec<&str> = Vec::new();
    for seg in path.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                if parts.last().is_some_and(|p| *p != "..") {
                    parts.pop();
                } else if !rooted {
                    parts.push("..");
                }
            }
            s => parts.push(s),
        }
    }
    let joined = parts.join("/");
    match (rooted, joined.is_empty()) {
        (true, _) => format!("/{joined}"),
        (false, true) => ".".into(),
        (false, false) => joined,
    }
}

/// Go's `filepath.Join`: joins the non-empty elements and cleans the result.
pub fn go_join(elems: &[&str]) -> String {
    let parts: Vec<&str> = elems.iter().copied().filter(|e| !e.is_empty()).collect();
    if parts.is_empty() {
        return String::new();
    }
    go_clean(&parts.join("/"))
}

/// Go's `filepath.Dir`.
pub fn go_dir(path: &str) -> String {
    match path.rfind('/') {
        Some(i) => go_clean(&path[..=i]),
        None => ".".into(),
    }
}

/// Go's `filepath.Abs`: absolute and cleaned.
pub fn go_abs(path: &str) -> io::Result<String> {
    if path.starts_with('/') {
        return Ok(go_clean(path));
    }
    let cwd = std::env::current_dir()?;
    Ok(go_join(&[&cwd.to_string_lossy(), path]))
}

/// The kubernetes namespace: `$RUNEWARD_K8S_NAMESPACE`, else `runeward`.
pub fn kube_namespace() -> String {
    std::env::var("RUNEWARD_K8S_NAMESPACE")
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "runeward".into())
}

/// The Kubernetes client: in-cluster configuration first, then the ambient
/// kubeconfig (`$RUNEWARD_KUBE_CONTEXT` pins the context).
pub async fn kube_client() -> anyhow::Result<kube::Client> {
    let config = match kube::Config::incluster() {
        Ok(c) => c,
        Err(_) => {
            let context = std::env::var("RUNEWARD_KUBE_CONTEXT")
                .ok()
                .filter(|c| !c.is_empty());
            kube::Config::from_kubeconfig(&kube::config::KubeConfigOptions {
                context,
                ..Default::default()
            })
            .await
            .map_err(|e| anyhow::anyhow!("load kubeconfig: {e}"))?
        }
    };
    kube::Client::try_from(config).map_err(|e| anyhow::anyhow!("build kubernetes client: {e}"))
}

/// Resolves on SIGINT (Ctrl-C) or, on unix, SIGTERM.
pub async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut term) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = term.recv() => {}
                }
            }
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quote_matches_go() {
        assert_eq!(go_quote("rm -rf /"), "\"rm -rf /\"");
        assert_eq!(go_quote("a\"b\\c\n\t\x01é"), "\"a\\\"b\\\\c\\n\\t\\x01é\"");
    }

    #[test]
    fn clean_and_join_match_go() {
        assert_eq!(go_join(&[".", ".runeward"]), ".runeward");
        assert_eq!(go_join(&["a/", "b", "../c"]), "a/c");
        assert_eq!(go_join(&["/x/./y/", "z"]), "/x/y/z");
        assert_eq!(go_clean("../a/.."), "..");
        assert_eq!(go_dir(".runeward/quickstart.toml"), ".runeward");
        assert_eq!(go_dir("quickstart.toml"), ".");
        assert_eq!(go_dir("/a/b"), "/a");
    }

    #[test]
    fn io_errors_read_like_go() {
        let err = io::Error::from(io::ErrorKind::NotFound);
        assert_eq!(
            go_io_error("open", "x.json", &err),
            "open x.json: no such file or directory"
        );
    }
}
