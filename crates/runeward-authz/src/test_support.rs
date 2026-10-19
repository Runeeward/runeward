//! Runs a test body in a child test process with a modified environment.
//!
//! Mutating the process environment is `unsafe` in Rust 2024 and races with
//! other test threads, so tests that need Go's `t.Setenv` re-execute the test
//! binary filtered to themselves with the variables set on the child.

use std::process::Command;

const CHILD_ENV: &str = "RUNEWARD_TEST_CHILD";

/// The libtest name of `func` declared in the module `module_path`.
pub(crate) fn child_test_name(module_path: &str, func: &str) -> String {
    let module = module_path.split_once("::").map_or("", |(_, rest)| rest);
    if module.is_empty() {
        func.to_owned()
    } else {
        format!("{module}::{func}")
    }
}

/// Whether this process is the child spawned for `name`.
pub(crate) fn is_child(name: &str) -> bool {
    std::env::var(CHILD_ENV).as_deref() == Ok(name)
}

/// Builds the command that re-runs test `name` with `set` applied and
/// `remove` cleared.
pub(crate) fn child_command(name: &str, set: &[(&str, &str)], remove: &[&str]) -> Command {
    let exe = std::env::current_exe().expect("current test executable");
    let mut cmd = Command::new(exe);
    cmd.args([name, "--exact", "--nocapture", "--test-threads=1"])
        .env(CHILD_ENV, name);
    for key in remove {
        cmd.env_remove(key);
    }
    for (key, value) in set {
        cmd.env(key, value);
    }
    cmd
}

/// Re-runs test `name` in a child process and asserts that it passed.
pub(crate) fn run_child(name: &str, set: &[(&str, &str)], remove: &[&str]) {
    let out = child_command(name, set, remove)
        .output()
        .expect("spawn child test");
    assert_child_passed(name, &out);
}

/// Asserts that a child test run passed and actually ran the test.
pub(crate) fn assert_child_passed(name: &str, out: &std::process::Output) {
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success() && stdout.contains("1 passed"),
        "child test {name} failed\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
}
