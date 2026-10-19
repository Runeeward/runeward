//! Input validation shared by every backend.

use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use regex::Regex;

use crate::config::COPY_FROM_ROOTS_ENV;
use crate::error::{BackendError, Result};
use crate::pathutil;
use crate::types::Spec;

static FILE_MODE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[0-7]{3,4}$").unwrap_or_else(|_| unreachable!()));
static ENV_NAME_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z_][A-Za-z0-9_]*$").unwrap_or_else(|_| unreachable!()));

/// Enforces the `copy_from` allowlist. When `roots` (the value of
/// `RUNEWARD_COPY_FROM_ROOTS`) is non-empty, `src_dir`, resolved through
/// symlinks, must equal or be nested under one of its colon-separated roots.
pub fn validate_seed_dir(src_dir: &Path, roots: &str) -> Result<()> {
    let roots = roots.trim();
    if roots.is_empty() {
        return Ok(());
    }
    let resolved = resolve(src_dir);
    for root in std::env::split_paths(roots) {
        if root.as_os_str().is_empty() {
            continue;
        }
        let rr = resolve(&root);
        if resolved == rr || resolved.starts_with(&rr) {
            return Ok(());
        }
    }
    Err(BackendError::msg(format!(
        "copy_from {:?} is outside the allowed roots ({COPY_FROM_ROOTS_ENV}={roots})",
        src_dir.display().to_string()
    )))
}

/// Resolves symlinks, falling back to a lexical clean when the path does not
/// resolve.
fn resolve(p: &Path) -> PathBuf {
    std::fs::canonicalize(p)
        .unwrap_or_else(|_| PathBuf::from(pathutil::clean(&p.to_string_lossy())))
}

/// Rejects a mode that is not 3-4 octal digits, so a value like
/// `644; rm -rf /` cannot reach a `chmod`.
pub fn validate_file_mode(mode: &str) -> Result<()> {
    if mode.is_empty() || FILE_MODE_RE.is_match(mode) {
        return Ok(());
    }
    Err(BackendError::msg(format!(
        "invalid file mode {mode:?}: want 3-4 octal digits"
    )))
}

/// Rejects environment variable names that are not identifier-safe.
pub fn validate_env_name(name: &str) -> Result<()> {
    if ENV_NAME_RE.is_match(name) {
        return Ok(());
    }
    Err(BackendError::msg(format!(
        "invalid environment variable name {name:?}"
    )))
}

/// Rejects file-projection targets that climb out with `..`. Absolute
/// targets are allowed unless `confine` (`RUNEWARD_CONFINE_FILES`) is set.
pub fn validate_projection_path(p: &str, confine: bool) -> Result<()> {
    if p.trim().is_empty() {
        return Err(BackendError::msg("file projection path is empty"));
    }
    let clean = pathutil::clean(p);
    if clean == ".." || clean.starts_with("../") || clean.contains("/../") {
        return Err(BackendError::msg(format!(
            "file projection path {p:?} escapes with '..'"
        )));
    }
    if confine && clean.starts_with('/') {
        return Err(BackendError::msg(format!(
            "file projection path {p:?} is absolute but RUNEWARD_CONFINE_FILES confines projections to the workspace"
        )));
    }
    Ok(())
}

/// Rejects a sandbox user that collides with the strict egress proxy uid,
/// which iptables exempts from interception.
pub fn validate_strict_egress_user(spec: &Spec) -> Result<()> {
    if !spec.network.strict_egress() {
        return Ok(());
    }
    match numeric_uid(&spec.user) {
        Some(uid) if uid == u64::from(runeward_egress::STRICT_PROXY_UID) => {
            Err(BackendError::msg(format!(
                "host.user uid {uid} is reserved for strict egress and cannot be used when network.enforce=strict"
            )))
        }
        _ => Ok(()),
    }
}

/// The numeric uid of a `uid[:gid]` user string, if it is numeric.
fn numeric_uid(user: &str) -> Option<u64> {
    let u = user.trim();
    let u = u.split_once(':').map_or(u, |(uid, _)| uid);
    if u.is_empty() || !u.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    u.parse().ok()
}

#[cfg(test)]
mod tests {
    use runeward_charter::Network;

    use super::*;

    #[test]
    fn seed_dir_allowlist() {
        let root = tempfile::tempdir().expect("tempdir");
        let inside = root.path().join("proj");
        std::fs::create_dir_all(&inside).expect("mkdir");
        let outside = tempfile::tempdir().expect("tempdir");

        // Unset: anything goes.
        assert!(validate_seed_dir(outside.path(), "").is_ok());

        let roots = root.path().to_string_lossy().to_string();
        assert!(validate_seed_dir(&inside, &roots).is_ok());
        assert!(validate_seed_dir(root.path(), &roots).is_ok());
        assert!(validate_seed_dir(outside.path(), &roots).is_err());

        // A sibling sharing the root as a string prefix is still outside.
        let sibling = PathBuf::from(format!("{}-evil", root.path().display()));
        assert!(validate_seed_dir(&sibling, &roots).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn seed_dir_allowlist_resolves_symlinks() {
        let root = tempfile::tempdir().expect("tempdir");
        let outside = tempfile::tempdir().expect("tempdir");
        let link = root.path().join("link");
        std::os::unix::fs::symlink(outside.path(), &link).expect("symlink");
        let roots = root.path().to_string_lossy().to_string();
        assert!(validate_seed_dir(&link, &roots).is_err());
    }

    #[test]
    fn file_mode() {
        for ok in ["", "644", "0644", "755", "0000"] {
            assert!(validate_file_mode(ok).is_ok(), "{ok}");
        }
        for bad in ["644; id", "abc", "9999", "0o644", "8"] {
            assert!(validate_file_mode(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn env_name() {
        for ok in ["PATH", "_x", "A1_B2", "foo"] {
            assert!(validate_env_name(ok).is_ok(), "{ok}");
        }
        for bad in ["1ABC", "A B", "A=b", "A;id", ""] {
            assert!(validate_env_name(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn projection_path() {
        for ok in ["a/b", "/root/.config/app", "file.txt", "./x"] {
            assert!(validate_projection_path(ok, false).is_ok(), "{ok}");
        }
        for bad in ["", "../etc/passwd", "a/../../b", ".."] {
            assert!(validate_projection_path(bad, false).is_err(), "{bad}");
        }
        assert!(validate_projection_path("/root/.gitconfig", true).is_err());
        assert!(validate_projection_path("notes/a.txt", true).is_ok());
    }

    #[test]
    fn strict_egress_user() {
        let strict = Network {
            default: "deny".into(),
            enforce: "strict".into(),
            ..Network::default()
        };
        let coop = Network {
            default: "deny".into(),
            ..Network::default()
        };
        let cases = [
            ("1337", strict.clone(), true),
            ("1337:1337", strict.clone(), true),
            ("1000", strict.clone(), false),
            ("root", strict, false),
            ("1337", coop, false),
        ];
        for (user, network, want_err) in cases {
            let spec = Spec {
                user: user.into(),
                network,
                ..Spec::default()
            };
            assert_eq!(
                validate_strict_egress_user(&spec).is_err(),
                want_err,
                "{user}"
            );
        }
    }
}
