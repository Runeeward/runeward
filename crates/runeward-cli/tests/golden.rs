//! Golden-output parity with the Go CLI.
//!
//! Each case runs the `runeward` binary in a fresh temporary directory
//! (holding a copy of `tests/fixtures`) with a scrubbed environment and
//! compares exit code, stdout and stderr with `tests/golden/<case>.txt`.
//! The golden files were recorded from the Go binary:
//!
//! ```text
//! RUNEWARD_GOLDEN_RECORD=/path/to/go/runeward RUNEWARD_GOLDEN_RECORD_VERSION=0.4.0 \
//!     cargo test -p runeward-cli --test golden
//! ```
//!
//! Temporary paths, the repository root and the version string are
//! normalized to `$TMP`, `$REPO` and `$VERSION`.

#![allow(clippy::unwrap_used)]

use std::path::{Path, PathBuf};
use std::process::Command;

struct Case {
    name: &'static str,
    /// Setup commands run first (output ignored), then the checked command.
    steps: &'static [&'static [&'static str]],
    env: &'static [(&'static str, &'static str)],
}

const fn case(name: &'static str, steps: &'static [&'static [&'static str]]) -> Case {
    Case {
        name,
        steps,
        env: &[],
    }
}

const TOKEN32: &str = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";

const CASES: &[Case] = &[
    case("version", &[&["version"]]),
    case("root_version_flag", &[&["--version"]]),
    case("list", &[&["-c", "$EX", "list"]]),
    case("list_empty", &[&["--config-dir", "empty", "list"]]),
    case("validate_all", &[&["-c", "$EX", "validate"]]),
    case(
        "validate_named",
        &[&["-c", "$EX", "validate", "governed", "cel-policy", "rego"]],
    ),
    case(
        "validate_strict",
        &[&["-c", "$EX", "validate", "--strict", "dev"]],
    ),
    case("validate_missing", &[&["-c", "$EX", "validate", "nope"]]),
    case("validate_empty", &[&["-c", "empty", "validate"]]),
    case("print_governed", &[&["-c", "$EX", "print", "governed"]]),
    case("print_byo", &[&["-c", "$EX", "print", "byo-model-gateway"]]),
    case("print_rego", &[&["-c", "$EX", "print", "rego"]]),
    case(
        "print_build_fleet",
        &[&["-c", "$EX", "print", "build-fleet"]],
    ),
    case("bare_charter_missing", &[&["-c", "$EX", "nope"]]),
    case("policy_scaffold_list", &[&["policy", "scaffold"]]),
    case(
        "policy_scaffold_flag",
        &[&["policy", "scaffold", "--list", "block-prod"]],
    ),
    case(
        "policy_scaffold_block_prod",
        &[&["policy", "scaffold", "block-prod"]],
    ),
    case(
        "policy_scaffold_unknown",
        &[&["policy", "scaffold", "nope"]],
    ),
    case(
        "policy_test_cases",
        &[&[
            "-c",
            "$EX",
            "policy",
            "test",
            "governed",
            "--cases",
            "cases.toml",
        ]],
    ),
    case(
        "policy_test_inline",
        &[&[
            "-c",
            "$EX",
            "policy",
            "test",
            "rego",
            "--case",
            "tool=shell,action=rm -rf /,expect=deny",
            "--case",
            "name=ok,tool=shell,arg=ls,expect=allow",
        ]],
    ),
    case(
        "policy_test_cel",
        &[&[
            "-c",
            "$EX",
            "policy",
            "test",
            "cel-policy",
            "--cases",
            "cases.toml",
        ]],
    ),
    case(
        "policy_test_bundle",
        &[&[
            "-c",
            "$EX",
            "policy",
            "test",
            "policy-bundle",
            "--case",
            "tool=shell,action=x,expect=allow",
        ]],
    ),
    case(
        "policy_test_no_cases",
        &[&["-c", "$EX", "policy", "test", "governed"]],
    ),
    case(
        "policy_test_bad_case",
        &[&[
            "-c",
            "$EX",
            "policy",
            "test",
            "governed",
            "--case",
            "tool=shell,bogus=1",
        ]],
    ),
    case(
        "policy_test_bad_expect",
        &[&[
            "-c",
            "$EX",
            "policy",
            "test",
            "governed",
            "--case",
            "tool=shell,action=x,expect=maybe",
        ]],
    ),
    case("policy_learn", &[&["policy", "learn", "chronicle.json"]]),
    case(
        "policy_learn_allowed",
        &[&["policy", "learn", "--include-allowed", "chronicle.json"]],
    ),
    case(
        "policy_learn_evidence",
        &[&["policy", "learn", "evidence.json"]],
    ),
    case(
        "policy_learn_tampered",
        &[&["policy", "learn", "chronicle-tampered.json"]],
    ),
    case(
        "chronicle_verify",
        &[&["chronicle", "verify", "chronicle.json"]],
    ),
    case(
        "chronicle_verify_tampered",
        &[&["chronicle", "verify", "chronicle-tampered.json"]],
    ),
    case(
        "chronicle_verify_missing",
        &[&["chronicle", "verify", "missing.json"]],
    ),
    case(
        "evidence_verify",
        &[&["evidence", "verify", "evidence.json"]],
    ),
    case(
        "evidence_verify_tampered",
        &[&["evidence", "verify", "evidence-tampered.json"]],
    ),
    case(
        "charter_sign",
        &[&["charter", "sign", "charter.toml", "--key", "charter.key"]],
    ),
    case(
        "charter_sign_stdout",
        &[&[
            "charter",
            "sign",
            "charter.toml",
            "--key",
            "charter.key",
            "--out",
            "-",
        ]],
    ),
    case(
        "charter_sign_no_key",
        &[&["charter", "sign", "charter.toml"]],
    ),
    case(
        "charter_verify",
        &[
            &["charter", "sign", "charter.toml", "--key", "charter.key"],
            &[
                "charter",
                "verify",
                "charter.toml",
                "--verify-key",
                "charter.pub",
            ],
        ],
    ),
    case(
        "charter_verify_wrong_key",
        &[
            &["charter", "sign", "charter.toml", "--key", "charter.key"],
            &[
                "charter",
                "verify",
                "charter.toml",
                "--verify-key",
                "waxo+w/5yRxjbw1wnAtIiQE87ClPE9eJS6+XheeD7dE=",
            ],
        ],
    ),
    case(
        "charter_verify_no_sig",
        &[&[
            "charter",
            "verify",
            "charter.toml",
            "--verify-key",
            "charter.pub",
        ]],
    ),
    case("runtime_guide", &[&["runtime", "guide"]]),
    case("runtime_install_kata", &[&["runtime", "install", "kata"]]),
    case(
        "runtime_install_gvisor_k8s",
        &[&["runtime", "install", "gvisor", "--engine", "k8s"]],
    ),
    case(
        "runtime_install_kata_k8s_class",
        &[&[
            "runtime",
            "install",
            "KATA",
            "--engine",
            "K8S",
            "--runtime-class",
            "kata-qemu",
        ]],
    ),
    case(
        "runtime_install_unknown",
        &[&["runtime", "install", "runc"]],
    ),
    case(
        "runtime_install_bad_engine",
        &[&["runtime", "install", "gvisor", "--engine", "podman"]],
    ),
    case("init", &[&["init"]]),
    case("init_again", &[&["init"], &["init"]]),
    case("init_named_dir", &[&["init", "proj", "--name", "dev"]]),
    case("init_bad_name", &[&["init", "--name", "a/b"]]),
    case("quickstart_no_run", &[&["quickstart", "--no-run"]]),
    case("doctor_empty", &[&["-c", "empty", "doctor"]]),
    case("doctor_empty_json", &[&["-c", "empty", "doctor", "--json"]]),
    case(
        "doctor_missing_charter",
        &[&["-c", "$EX", "doctor", "nope"]],
    ),
    case("replay", &[&["replay", "--no-timing", "session.cast"]]),
    case(
        "replay_realtime_false",
        &[&["replay", "--realtime=false", "session.cast"]],
    ),
    case("replay_missing", &[&["replay", "missing.cast"]]),
    case("cohort_status_no_state", &[&["cohort", "status"]]),
    case(
        "cohort_exec_bad_agent",
        &[&[
            "cohort",
            "--cohort",
            "c1",
            "--agent",
            "vim",
            "exec",
            "hi",
            "--citadel",
            "sb",
        ]],
    ),
    case(
        "serve_plaintext",
        &[&["serve", "--bind", "0.0.0.0", "--token", TOKEN32]],
    ),
    case(
        "serve_short_token",
        &[&["serve", "--bind", "0.0.0.0", "--token", "short"]],
    ),
    case("serve_no_auth", &[&["serve", "--bind", "0.0.0.0"]]),
    case("serve_tls_pair", &[&["serve", "--tls-cert", "x.pem"]]),
    case(
        "mcp_plaintext",
        &[&["mcp", "--http", "--bind", "0.0.0.0", "--token", TOKEN32]],
    ),
    case(
        "archive_push_bad_engine",
        &[&["archive", "push", "localhost:5000/p:1", "--engine", "wasm"]],
    ),
    case(
        "archive_push_no_policy",
        &[&["archive", "push", "localhost:5000/p:1", "--engine", "rego"]],
    ),
    Case {
        name: "auth_status_logged_out",
        steps: &[&["auth", "status"]],
        env: &[("RUNEWARD_CREDENTIALS_FILE", "$TMP/creds.json")],
    },
    Case {
        name: "auth_token_stdin_status",
        steps: &[&["auth", "login", "--token-stdin"], &["auth", "status"]],
        env: &[("RUNEWARD_CREDENTIALS_FILE", "$TMP/creds.json")],
    },
    Case {
        name: "auth_logout",
        steps: &[
            &["auth", "login", "--token-stdin"],
            &["auth", "logout"],
            &["auth", "status"],
        ],
        env: &[("RUNEWARD_CREDENTIALS_FILE", "$TMP/creds.json")],
    },
    case(
        "enter_missing",
        &[&["-c", "$EX", "enter", "nope", "--", "true"]],
    ),
];

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

fn copy_dir(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).unwrap();
    for e in std::fs::read_dir(src).unwrap() {
        let e = e.unwrap();
        std::fs::copy(e.path(), dst.join(e.file_name())).unwrap();
    }
}

/// The binary under test and the version string it prints.
fn binary() -> (PathBuf, String, bool) {
    match std::env::var("RUNEWARD_GOLDEN_RECORD") {
        Ok(go) if !go.is_empty() => (
            PathBuf::from(go),
            std::env::var("RUNEWARD_GOLDEN_RECORD_VERSION").unwrap_or_else(|_| "0.4.0".into()),
            true,
        ),
        _ => (
            PathBuf::from(env!("CARGO_BIN_EXE_runeward")),
            runeward_cli::VERSION.to_owned(),
            false,
        ),
    }
}

fn run_case(c: &Case, bin: &Path, version: &str) -> String {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().canonicalize().unwrap();
    let dir_s = dir.to_string_lossy().into_owned();
    let repo = repo_root();
    let repo_s = repo.to_string_lossy().into_owned();
    let examples = repo.join("examples").to_string_lossy().into_owned();
    copy_dir(&repo.join("crates/runeward-cli/tests/fixtures"), &dir);
    std::fs::create_dir_all(dir.join("empty")).unwrap();
    for sub in ["home", "xdg", "cache"] {
        std::fs::create_dir_all(dir.join(sub)).unwrap();
    }
    let subst = |s: &str| s.replace("$EX", &examples).replace("$TMP", &dir_s);

    let mut out = String::new();
    for step in c.steps {
        let mut cmd = Command::new(bin);
        cmd.args(step.iter().map(|a| subst(a)))
            .current_dir(&dir)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", dir.join("home"))
            .env("XDG_CONFIG_HOME", dir.join("xdg"))
            .env("XDG_CACHE_HOME", dir.join("cache"))
            .env("RUNEWARD_STATE_DIR", dir.join("state"))
            .env("RUNEWARD_TELEMETRY", "off")
            .env("DO_NOT_TRACK", "1");
        for (k, v) in c.env {
            cmd.env(k, subst(v));
        }
        let is_login = step.contains(&"--token-stdin");
        cmd.stdin(if is_login {
            std::process::Stdio::piped()
        } else {
            std::process::Stdio::null()
        });
        cmd.stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        let mut child = cmd.spawn().unwrap();
        if is_login {
            use std::io::Write;
            let mut stdin = child.stdin.take().unwrap();
            stdin.write_all(b"  stdin-token-value\n").unwrap();
        }
        let res = child.wait_with_output().unwrap();
        out.push_str(&format!(
            "$ runeward {}\nexit: {}\n--- stdout\n{}--- stderr\n{}",
            step.join(" "),
            res.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&res.stdout),
            String::from_utf8_lossy(&res.stderr)
        ));
    }
    out.replace(&dir_s, "$TMP")
        .replace(&repo_s, "$REPO")
        .replace(version, "$VERSION")
}

#[test]
fn golden_outputs_match_go() {
    let (bin, version, record) = binary();
    let golden_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden");
    let mut failures = Vec::new();
    for c in CASES {
        let got = run_case(c, &bin, &version);
        let path = golden_dir.join(format!("{}.txt", c.name));
        if record {
            std::fs::create_dir_all(&golden_dir).unwrap();
            std::fs::write(&path, &got).unwrap();
            continue;
        }
        let want = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        if got != want {
            failures.push(format!("=== {}\n--- want\n{want}\n--- got\n{got}", c.name));
        }
    }
    assert!(
        failures.is_empty(),
        "{} golden mismatches:\n{}",
        failures.len(),
        failures.join("\n")
    );
}
