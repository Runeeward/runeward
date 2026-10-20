//! Ports of Go `internal/credentials/store_test.go`, plus JSON fixtures the
//! Go package wrote.

use std::fs;
use std::process::Command;

use chrono::{SubsecRound, TimeDelta};
use runeward_credentials::{self as credentials, ENV_FILE, Login, Store};
use runeward_ledger::gotime;

#[test]
fn save_load_delete() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = Store::at(dir.path().join("credentials.json"));
    let want = Login {
        token: "secret".into(),
        issuer: "https://issuer.example".into(),
        expires_at: Some((gotime::now() + TimeDelta::hours(1)).trunc_subsecs(0)),
        ..Login::default()
    };
    store.save(want.clone()).expect("save");
    let got = store.load().expect("load");
    assert_eq!(got, want);
    assert_eq!(store.load_token(), want.token);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(store.path())
            .expect("stat")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "credential permissions");
    }

    store.delete().expect("delete");
    let err = store.load().expect_err("removed credential");
    assert!(err.is_not_found(), "{err}");
    store.delete().expect("deleting a missing file is fine");
}

#[test]
fn expired_and_empty_credentials_are_not_usable() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = Store::at(dir.path().join("credentials.json"));
    store
        .save(Login {
            token: "expired".into(),
            expires_at: Some(gotime::now() - TimeDelta::minutes(1)),
            ..Login::default()
        })
        .expect("save");
    assert_eq!(store.load_token(), "");
    assert!(store.save(Login::default()).is_err(), "empty credential");
    assert!(store.save(Login::new("   ")).is_err(), "blank credential");
}

#[test]
fn save_creates_private_parent_and_trims() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = Store::at(dir.path().join("nested/runeward/credentials.json"));
    store.save(Login::new("  tok \n")).expect("save");
    assert_eq!(store.load().expect("load").token, "tok");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let parent = store.path().parent().expect("parent");
        assert_eq!(
            fs::metadata(parent).expect("stat").permissions().mode() & 0o777,
            0o700
        );
        // Only the target remains: the temp file was renamed into place.
        assert_eq!(fs::read_dir(parent).expect("readdir").count(), 1);
    }
}

#[cfg(unix)]
#[test]
fn permissive_file_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("credentials.json");
    fs::write(&path, r#"{"token":"t"}"#).expect("write");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("chmod");
    let err = Store::at(&path).load().expect_err("0644 file");
    assert!(
        err.to_string().contains("must use 0600 permissions"),
        "{err}"
    );
    assert_eq!(Store::at(&path).load_token(), "");
}

#[test]
fn stored_blank_token_is_rejected() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("credentials.json");
    fs::write(&path, r#"{"token":"  ","issuer":null}"#).expect("write");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("chmod");
    }
    let err = Store::at(&path).load().expect_err("blank token");
    assert_eq!(err.to_string(), "stored Runeward credential is empty");
}

/// Files the Go CLI wrote are read, and Rust writes the same bytes.
#[test]
fn json_matches_go() {
    for (name, want) in [
        ("full", include_str!("testdata/credentials_full.json")),
        ("min", include_str!("testdata/credentials_min.json")),
    ] {
        let login: Login = serde_json::from_str(want).expect(name);
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Store::at(dir.path().join("credentials.json"));
        store.save(login).expect("save");
        assert_eq!(
            fs::read_to_string(store.path()).expect("read"),
            want,
            "{name}"
        );
    }
    let min: Login =
        serde_json::from_str(include_str!("testdata/credentials_min.json")).expect("min");
    assert_eq!(min.expires_at, None);
}

/// Runs the env-dependent checks in a child process so this test never
/// mutates its own environment.
#[test]
fn env_path_resolution() {
    let dir = tempfile::tempdir().expect("tempdir");
    let file = dir.path().join("from-env.json");
    let run = |envs: &[(&str, &str)]| {
        let mut cmd = Command::new(std::env::current_exe().expect("test binary"));
        cmd.args(["--exact", "env_child", "--nocapture", "--test-threads=1"])
            .env("RW_CREDENTIALS_CHILD", "1")
            .env("RW_EXPECT_DIR", dir.path());
        for (k, v) in envs {
            cmd.env(k, v);
        }
        let out = cmd.output().expect("run child");
        assert!(
            out.status.success(),
            "child failed:\n{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            String::from_utf8_lossy(&out.stdout).contains("1 passed"),
            "child did not run env_child"
        );
    };
    let file_s = format!("  {}  ", file.display());
    run(&[(ENV_FILE, &file_s), ("RW_CASE", "file")]);
    let home = dir.path().display().to_string();
    run(&[
        (ENV_FILE, " "),
        ("HOME", &home),
        ("XDG_CONFIG_HOME", &home),
        ("RW_CASE", "default"),
    ]);
}

#[test]
fn env_child() {
    let Ok(case) = std::env::var("RW_CASE") else {
        return;
    };
    if std::env::var_os("RW_CREDENTIALS_CHILD").is_none() {
        return;
    }
    let dir = std::path::PathBuf::from(std::env::var_os("RW_EXPECT_DIR").expect("dir"));
    match case.as_str() {
        "file" => {
            assert_eq!(
                credentials::path().expect("path"),
                dir.join("from-env.json")
            );
            credentials::save(Login::new("env-token")).expect("save");
            assert_eq!(credentials::load().expect("load").token, "env-token");
            assert_eq!(credentials::load_token(), "env-token");
            credentials::delete().expect("delete");
            assert!(credentials::load().expect_err("gone").is_not_found());
        }
        "default" => {
            let base = if cfg!(target_os = "macos") {
                dir.join("Library/Application Support")
            } else {
                dir.clone()
            };
            assert_eq!(
                credentials::path().expect("path"),
                base.join("runeward").join("credentials.json")
            );
        }
        other => panic!("unknown case {other}"),
    }
}
