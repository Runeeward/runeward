//! `op://<vault>/<item>/[<section>/]<field>` references (1Password).
//!
//! Resolution shells out to the official 1Password CLI (`op read`) rather
//! than speaking the 1Password protocol, so Rune Box carries no 1Password
//! crypto of its own. The CLI authenticates however the operator set it up:
//!
//! - a service account, when `OP_SERVICE_ACCOUNT_TOKEN` is in the
//!   environment (the recommended setup for servers and CI);
//! - the 1Password desktop app integration (biometric unlock), when the CLI
//!   is linked to a running, unlocked desktop app;
//! - an existing `op signin` session (`OP_SESSION_*`).
//!
//! The child inherits the resolving process's environment, so `OP_ACCOUNT`,
//! `OP_CONNECT_HOST`/`OP_CONNECT_TOKEN` and the variables above all work as
//! they do for `op` itself. The secret value only ever travels over the
//! child's stdout pipe; it is never logged and never included in an error.

use std::fmt;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use crate::resolver::{Error, ResolveFuture, Resolver, split_scheme};

/// Overrides the `op` executable (absolute path or a name looked up on
/// `PATH`).
pub const OP_BIN_ENV: &str = "RUNEWARD_OP_BIN";

/// Bounds one `op read`. Generous so a desktop-app biometric prompt can be
/// answered.
pub const DEFAULT_OP_TIMEOUT: Duration = Duration::from_secs(60);

/// Longest slice of `op`'s stderr quoted in an error.
const MAX_DIAGNOSTIC: usize = 240;

/// Resolves `op://` references with the 1Password CLI. It is fail-closed: a
/// missing CLI, an unauthenticated CLI, an unknown item or an empty value is
/// an error.
#[derive(Clone)]
pub struct OnePasswordResolver {
    /// The `op` executable to run.
    pub program: PathBuf,
    /// Upper bound on one `op read`; the child is killed when it elapses.
    pub timeout: Duration,
}

impl Default for OnePasswordResolver {
    fn default() -> Self {
        Self {
            program: PathBuf::from("op"),
            timeout: DEFAULT_OP_TIMEOUT,
        }
    }
}

impl fmt::Debug for OnePasswordResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OnePasswordResolver")
            .field("program", &self.program)
            .field("timeout", &self.timeout)
            .finish()
    }
}

impl OnePasswordResolver {
    /// The resolver for this process: `op` from `PATH`, or `$RUNEWARD_OP_BIN`
    /// when set. Authentication comes from the environment `op` itself reads
    /// (`OP_SERVICE_ACCOUNT_TOKEN`, desktop app integration, `OP_SESSION_*`).
    pub fn from_env() -> Self {
        let program = std::env::var_os(OP_BIN_ENV)
            .filter(|v| !v.is_empty())
            .map_or_else(|| PathBuf::from("op"), PathBuf::from);
        Self {
            program,
            ..Self::default()
        }
    }

    /// Reads the field named by an `op://` reference with `op read`.
    pub async fn resolve(&self, reference: &str) -> Result<String, Error> {
        validate_op_ref(reference)?;
        let mut cmd = tokio::process::Command::new(&self.program);
        cmd.args(["read", "--no-newline", "--", reference])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        let child = cmd.spawn().map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                Error::new(format!(
                    "secret reference {reference:?}: the 1Password CLI ({}) was not found; install `op` (https://developer.1password.com/docs/cli) or set {OP_BIN_ENV} to its path",
                    self.program.display()
                ))
            } else {
                Error::new(format!(
                    "secret reference {reference:?}: run the 1Password CLI ({}): {e}",
                    self.program.display()
                ))
            }
        })?;
        let out = match tokio::time::timeout(self.timeout, child.wait_with_output()).await {
            Ok(Ok(out)) => out,
            Ok(Err(e)) => {
                return Err(Error::new(format!(
                    "secret reference {reference:?}: wait for the 1Password CLI: {e}"
                )));
            }
            // Dropping the future drops the child, which kills it.
            Err(_) => {
                return Err(Error::new(format!(
                    "secret reference {reference:?}: the 1Password CLI did not answer within {}s (an unanswered desktop-app approval prompt?)",
                    self.timeout.as_secs()
                )));
            }
        };
        if !out.status.success() {
            // stdout is deliberately never inspected on failure: it is the
            // only channel that can carry a secret value.
            let diag = diagnostic(&out.stderr);
            return Err(Error::new(format!(
                "secret reference {reference:?}: {}",
                classify_failure(&diag)
            )));
        }
        let value = String::from_utf8_lossy(&out.stdout).into_owned();
        if value.is_empty() {
            return Err(Error::new(format!(
                "secret reference {reference:?}: 1Password returned an empty value"
            )));
        }
        Ok(value)
    }
}

impl Resolver for OnePasswordResolver {
    fn resolve<'a>(&'a self, reference: &'a str) -> ResolveFuture<'a> {
        Box::pin(OnePasswordResolver::resolve(self, reference))
    }
}

/// Checks the shape of a 1Password secret reference before running `op`:
/// `op://<vault>/<item>/<field>` or `op://<vault>/<item>/<section>/<field>`,
/// optionally followed by a `?attribute=...` query, with no empty segment and
/// no control characters.
pub(crate) fn validate_op_ref(reference: &str) -> Result<(), Error> {
    let rest = match split_scheme(reference) {
        Some((scheme, rest)) if scheme == "op" => rest,
        _ => {
            return Err(Error::new(format!(
                "secret reference {reference:?} is not an op:// reference"
            )));
        }
    };
    let invalid = |why: &str| {
        Error::new(format!(
            "secret reference {reference:?}: invalid 1Password reference ({why}); expected op://<vault>/<item>/[<section>/]<field>"
        ))
    };
    if reference.chars().any(char::is_control) {
        return Err(invalid("control character"));
    }
    let path = rest.split_once('?').map_or(rest, |(p, _)| p);
    let segments: Vec<&str> = path.split('/').collect();
    if !(3..=4).contains(&segments.len()) {
        return Err(invalid(&format!("{} path segments", segments.len())));
    }
    if segments.iter().any(|s| s.trim().is_empty()) {
        return Err(invalid("empty segment"));
    }
    Ok(())
}

/// The first meaningful line of `op`'s stderr, without its `[ERROR] <date>
/// <time>` prefix, control characters or excess length.
fn diagnostic(stderr: &[u8]) -> String {
    let text = String::from_utf8_lossy(stderr);
    let line = text
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or("");
    let mut line = line;
    if let Some(rest) = line.strip_prefix("[ERROR]") {
        line = rest.trim_start();
        // Drop "YYYY/MM/DD HH:MM:SS " when present.
        let mut parts = line.splitn(3, ' ');
        if let (Some(d), Some(t), Some(msg)) = (parts.next(), parts.next(), parts.next())
            && d.len() == 10
            && d.as_bytes().get(4) == Some(&b'/')
            && t.len() == 8
            && t.as_bytes().get(2) == Some(&b':')
        {
            line = msg;
        }
    }
    let clean: String = line.chars().filter(|c| !c.is_control()).collect();
    if clean.chars().count() > MAX_DIAGNOSTIC {
        let cut: String = clean.chars().take(MAX_DIAGNOSTIC).collect();
        format!("{cut}...")
    } else {
        clean
    }
}

/// Turns `op`'s diagnostic into an actionable message.
fn classify_failure(diag: &str) -> String {
    let lower = diag.to_lowercase();
    let detail = if diag.is_empty() {
        "no diagnostic".to_owned()
    } else {
        diag.to_owned()
    };
    let signed_out = [
        "not currently signed in",
        "not signed in",
        "op signin",
        "no accounts configured",
        "session expired",
        "authorization prompt dismissed",
        "authentication required",
        "unauthorized",
        "invalid service account token",
        "service account token",
    ];
    let bad_ref = [
        "isn't a valid secret reference",
        "invalid secret reference",
        "isn't a vault",
        "isn't an item",
        "isn't a field",
        "could not be found",
        "no item found",
        "not found in",
        "does not have a field",
    ];
    if signed_out.iter().any(|m| lower.contains(m)) {
        format!(
            "the 1Password CLI is not signed in ({detail}); set OP_SERVICE_ACCOUNT_TOKEN, enable the desktop app integration, or run `op signin`"
        )
    } else if bad_ref.iter().any(|m| lower.contains(m)) {
        format!("1Password could not resolve the reference ({detail})")
    } else {
        format!("the 1Password CLI failed ({detail})")
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    use super::*;
    use crate::test_support::{child_test_name, is_child, run_child};

    /// A stand-in `op`: checks it was called as `op read --no-newline --
    /// <ref>` with stdin closed, then answers by reference.
    const FAKE_OP: &str = r#"#!/bin/sh
if [ "$1" != "read" ] || [ "$2" != "--no-newline" ] || [ "$3" != "--" ] || [ $# -ne 4 ]; then
  echo "[ERROR] 2026/10/21 10:00:00 unexpected arguments: $*" >&2; exit 2
fi
if [ -n "$FAKE_OP_REQUIRE_TOKEN" ] && [ "$OP_SERVICE_ACCOUNT_TOKEN" != "$FAKE_OP_REQUIRE_TOKEN" ]; then
  echo "[ERROR] 2026/10/21 10:00:00 You are not currently signed in. Please run \`op signin --help\` for instructions" >&2; exit 1
fi
case "$4" in
  "op://Dev Vault/github/token") printf 'ghp_fake_value' ;;
  "op://vault/item/section/field") printf 'sectioned' ;;
  "op://vault/item/multi") printf 'line1\nline2\n' ;;
  "op://vault/item/empty") ;;
  "op://vault/item/leak") printf 'LEAKED_SECRET'; echo "[ERROR] 2026/10/21 10:00:00 boom" >&2; exit 1 ;;
  "op://vault/item/slow") sleep 5; printf 'late' ;;
  *) echo "[ERROR] 2026/10/21 10:00:00 could not read secret '$4': \"missing\" isn't an item in the \"vault\" vault" >&2; exit 1 ;;
esac
"#;

    fn fake_op(dir: &Path) -> PathBuf {
        let path = dir.join("op");
        std::fs::write(&path, FAKE_OP).expect("write fake op");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        path
    }

    fn resolver(dir: &Path) -> OnePasswordResolver {
        OnePasswordResolver {
            program: fake_op(dir),
            timeout: Duration::from_secs(10),
        }
    }

    #[tokio::test]
    async fn reads_field_values_verbatim() {
        let dir = tempfile::tempdir().expect("tempdir");
        let r = resolver(dir.path());
        assert_eq!(
            r.resolve("op://Dev Vault/github/token")
                .await
                .expect("read"),
            "ghp_fake_value"
        );
        assert_eq!(
            r.resolve("op://vault/item/section/field")
                .await
                .expect("read"),
            "sectioned"
        );
        assert_eq!(
            r.resolve("op://vault/item/multi").await.expect("read"),
            "line1\nline2\n"
        );
    }

    #[tokio::test]
    async fn empty_value_fails_closed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let err = resolver(dir.path())
            .resolve("op://vault/item/empty")
            .await
            .expect_err("empty");
        assert!(err.to_string().contains("empty value"), "{err}");
    }

    #[tokio::test]
    async fn unknown_item_is_a_clear_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let err = resolver(dir.path())
            .resolve("op://vault/missing/field")
            .await
            .expect_err("missing");
        let msg = err.to_string();
        assert!(msg.contains("could not resolve the reference"), "{msg}");
        assert!(msg.contains("isn't an item"), "{msg}");
        assert!(!msg.contains("[ERROR]"), "{msg}");
        assert!(!msg.contains("2026/10/21"), "{msg}");
    }

    #[tokio::test]
    async fn failure_never_echoes_stdout() {
        let dir = tempfile::tempdir().expect("tempdir");
        let err = resolver(dir.path())
            .resolve("op://vault/item/leak")
            .await
            .expect_err("fails");
        assert!(!err.to_string().contains("LEAKED_SECRET"), "{err}");
        assert!(err.to_string().contains("boom"), "{err}");
    }

    #[tokio::test]
    async fn missing_cli_is_a_clear_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let r = OnePasswordResolver {
            program: dir.path().join("no-such-op"),
            ..OnePasswordResolver::default()
        };
        let err = r
            .resolve("op://vault/item/field")
            .await
            .expect_err("no cli");
        let msg = err.to_string();
        assert!(msg.contains("1Password CLI"), "{msg}");
        assert!(msg.contains("not found"), "{msg}");
        assert!(msg.contains(OP_BIN_ENV), "{msg}");
    }

    #[tokio::test]
    async fn timeout_kills_the_cli() {
        let dir = tempfile::tempdir().expect("tempdir");
        let r = OnePasswordResolver {
            timeout: Duration::from_millis(200),
            ..resolver(dir.path())
        };
        let err = r.resolve("op://vault/item/slow").await.expect_err("slow");
        assert!(err.to_string().contains("did not answer"), "{err}");
    }

    #[tokio::test]
    async fn invalid_references_never_run_the_cli() {
        // A program that does not exist proves `op` is never spawned.
        let r = OnePasswordResolver {
            program: PathBuf::from("/nonexistent/op"),
            ..OnePasswordResolver::default()
        };
        for bad in [
            "op://",
            "op://vault",
            "op://vault/item",
            "op://vault//field",
            "op://a/b/c/d/e",
            "op://vault/item/fi\neld",
            "env://X",
        ] {
            let err = r.resolve(bad).await.expect_err(bad);
            assert!(!err.to_string().contains("not found"), "{bad}: {err}");
        }
        assert!(validate_op_ref("op://v/i/f?attribute=otp").is_ok());
    }

    /// `from_env` honours `RUNEWARD_OP_BIN` and the CLI sees the service
    /// account token from the environment.
    #[tokio::test]
    async fn service_account_token_reaches_the_cli() {
        let name = child_test_name(module_path!(), "service_account_token_reaches_the_cli");
        if !is_child(&name) {
            let dir = tempfile::tempdir().expect("tempdir");
            let op = fake_op(dir.path());
            let op = op.to_str().expect("utf-8 path");
            run_child(
                &name,
                &[
                    (OP_BIN_ENV, op),
                    ("FAKE_OP_REQUIRE_TOKEN", "ops_test"),
                    ("OP_SERVICE_ACCOUNT_TOKEN", "ops_test"),
                ],
                &[],
            );
            run_child(
                &format!("{name}_signed_out"),
                &[(OP_BIN_ENV, op), ("FAKE_OP_REQUIRE_TOKEN", "ops_test")],
                &["OP_SERVICE_ACCOUNT_TOKEN"],
            );
            return;
        }
        let got = OnePasswordResolver::from_env()
            .resolve("op://Dev Vault/github/token")
            .await
            .expect("read");
        assert_eq!(got, "ghp_fake_value");
    }

    #[tokio::test]
    async fn service_account_token_reaches_the_cli_signed_out() {
        let name = child_test_name(
            module_path!(),
            "service_account_token_reaches_the_cli_signed_out",
        );
        if !is_child(&name) {
            // Driven by `service_account_token_reaches_the_cli`.
            return;
        }
        let err = OnePasswordResolver::from_env()
            .resolve("op://Dev Vault/github/token")
            .await
            .expect_err("signed out");
        let msg = err.to_string();
        assert!(msg.contains("not signed in"), "{msg}");
        assert!(msg.contains("OP_SERVICE_ACCOUNT_TOKEN"), "{msg}");
    }

    #[test]
    fn diagnostic_strips_prefix_and_bounds_length() {
        assert_eq!(
            diagnostic(b"\n[ERROR] 2026/10/21 10:00:00 nope\nmore"),
            "nope"
        );
        assert_eq!(diagnostic(b"plain \x1b[31mred"), "plain [31mred");
        let long = "x".repeat(1000);
        assert_eq!(
            diagnostic(long.as_bytes()).chars().count(),
            MAX_DIAGNOSTIC + 3
        );
        assert_eq!(diagnostic(b""), "");
    }
}
