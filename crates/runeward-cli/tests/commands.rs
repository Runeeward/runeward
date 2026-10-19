//! End-to-end checks of commands whose output is not byte-stable (fresh
//! keys, timestamps) and so is not covered by the golden files.

#![allow(clippy::unwrap_used)]

use std::path::Path;
use std::process::{Command, Output};

fn runeward(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_runeward"))
        .args(args)
        .current_dir(dir)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", dir)
        .env("XDG_CONFIG_HOME", dir.join("xdg"))
        .env("RUNEWARD_STATE_DIR", dir.join("state"))
        .output()
        .unwrap()
}

fn ok(out: &Output) -> String {
    assert!(
        out.status.success(),
        "exit {:?}\nstdout: {}\nstderr: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn examples() -> String {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples")
        .canonicalize()
        .unwrap()
        .to_string_lossy()
        .into_owned()
}

#[test]
fn evidence_export_round_trips_and_refuses_overwrite() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let ex = examples();
    let out = runeward(
        dir,
        &["-c", &ex, "evidence", "export", "governed", "-o", "ev.json"],
    );
    ok(&out);
    assert_eq!(
        String::from_utf8_lossy(&out.stderr),
        "evidence package: ev.json\n"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(dir.join("ev.json"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    let verified = ok(&runeward(dir, &["evidence", "verify", "ev.json"]));
    assert!(verified.starts_with("verified: policy digest and 0 signed audit event(s); key "));

    let again = runeward(
        dir,
        &["-c", &ex, "evidence", "export", "governed", "-o", "ev.json"],
    );
    assert_eq!(again.status.code(), Some(1));
    assert_eq!(
        String::from_utf8_lossy(&again.stderr),
        "error: output \"ev.json\" already exists; pass --force to replace it\n"
    );
    ok(&runeward(
        dir,
        &[
            "-c", &ex, "evidence", "export", "governed", "-o", "ev.json", "--force",
        ],
    ));

    // Stdout export is a valid document too, learnable as policy.
    let doc = ok(&runeward(
        dir,
        &["-c", &ex, "evidence", "export", "governed"],
    ));
    let v: serde_json::Value = serde_json::from_str(&doc).unwrap();
    assert_eq!(v["format"], "runeward-evidence/v1");
    assert_eq!(v["policy"]["source"], "governed.toml");
    assert_eq!(v["runeward_version"], runeward_cli::VERSION);
}

#[test]
fn keygen_keys_sign_and_verify_charters() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let printed = ok(&runeward(dir, &["archive", "keygen"]));
    assert!(printed.starts_with("key-id:      "), "{printed}");
    assert!(printed.contains("\nprivate-key: "), "{printed}");

    let out = ok(&runeward(dir, &["archive", "keygen", "--out", "keys"]));
    assert!(out.contains("private:    keys/bundle.key\n"), "{out}");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let key = std::fs::metadata(dir.join("keys/bundle.key")).unwrap();
        assert_eq!(key.permissions().mode() & 0o777, 0o600);
    }
    std::fs::write(dir.join("c.toml"), "[host]\nimage = \"x/y:1\"\n").unwrap();
    ok(&runeward(
        dir,
        &["charter", "sign", "c.toml", "--key", "keys/bundle.key"],
    ));
    let v = ok(&runeward(
        dir,
        &[
            "charter",
            "verify",
            "c.toml",
            "--verify-key",
            "keys/bundle.pub",
        ],
    ));
    assert!(v.starts_with("verified: "));
    std::fs::write(dir.join("c.toml"), "[host]\nimage = \"x/y:2\"\n").unwrap();
    let bad = runeward(
        dir,
        &[
            "charter",
            "verify",
            "c.toml",
            "--verify-key",
            "keys/bundle.pub",
        ],
    );
    assert_eq!(bad.status.code(), Some(1));
}

#[test]
fn help_names_the_product_and_usage_errors_exit_1() {
    let tmp = tempfile::tempdir().unwrap();
    let help = ok(&runeward(tmp.path(), &["--help"]));
    assert!(help.contains("Rune Box applies policy"), "{help}");
    let bare = ok(&runeward(tmp.path(), &[]));
    assert!(bare.contains("Usage: runeward"), "{bare}");
    let usage = runeward(tmp.path(), &["print"]);
    assert_eq!(usage.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&usage.stderr).starts_with("error: "));
    let completion = ok(&runeward(tmp.path(), &["completion", "bash"]));
    assert!(completion.contains("runeward"));
}
