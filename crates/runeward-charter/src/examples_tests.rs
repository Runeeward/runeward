//! Parity with the Go CLI over every Charter shipped in `examples/`.
//!
//! The fixtures are the stdout of the Go `runeward validate --strict` and
//! `runeward print` commands, run from the repository root with an empty
//! `$HOME` so `~/` paths resolve the same way on every machine.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use crate::lint::lint_with_home;
use crate::tabwriter::TabWriter;
use crate::{Finding, Options, Severity, SignedCharters, list, load, parse_duration, render};

const EXAMPLE_DIRS: [&str; 2] = ["examples", "examples/safe"];

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn fixture(name: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    std::fs::read_to_string(path).expect("read fixture")
}

fn opts(dir: &str) -> Options {
    Options {
        config_dir: Some(repo_root().join(dir)),
        signed: SignedCharters::Disabled,
        ..Options::default()
    }
}

/// Mirrors the Go CLI's `printProfileFindings`.
fn print_findings(out: &mut String, name: &str, findings: &[Finding]) {
    let _ = writeln!(out, "{name}");
    if findings.is_empty() {
        out.push_str("  ok\n");
        return;
    }
    let mut tw = TabWriter::default();
    for f in findings {
        let marker = match f.severity {
            Severity::Error => "[error]",
            Severity::Warn => "[warn] ",
        };
        tw.push(&format!("  {marker}\t{}\t{}\n", f.field, f.message));
    }
    tw.flush(out);
}

#[test]
fn validate_strict_matches_go() {
    let home = tempfile::tempdir().expect("tempdir");
    let mut out = String::new();
    let mut loaded = 0;
    for dir in EXAMPLE_DIRS {
        let o = opts(dir);
        let names = list(&o);
        assert!(!names.is_empty(), "no Charters in {dir}");
        for name in names {
            let charter = load(&name, &o).unwrap_or_else(|e| panic!("{dir}/{name}: {e}"));
            for d in [&charter.limits.wall_clock, &charter.limits.loop_window] {
                if !d.is_empty() {
                    parse_duration(d).unwrap_or_else(|e| panic!("{dir}/{name}: {e}"));
                }
            }
            print_findings(
                &mut out,
                &name,
                &lint_with_home(&charter, Some(home.path().to_owned())),
            );
            loaded += 1;
        }
    }
    assert!(loaded >= 33, "only {loaded} examples loaded");
    assert_eq!(out, fixture("go-validate-strict.txt"));
}

#[test]
fn print_matches_go() {
    let want = fixture("go-print.txt");
    let mut got = String::new();
    for dir in EXAMPLE_DIRS {
        let o = opts(dir);
        for name in list(&o) {
            let mut charter = load(&name, &o).expect("load");
            // Go prints the path as joined from the relative config dir.
            charter.source = Path::new(dir).join(format!("{name}.toml"));
            let _ = writeln!(got, "=== {dir}/{name}");
            got.push_str(&render(&charter));
        }
    }
    // Go's shell glob sorts `browser-stateful` before `browser`; compare the
    // per-Charter sections rather than the concatenation order.
    let sections = |s: &str| {
        let mut v: Vec<String> = s.split("=== ").map(str::to_owned).collect();
        v.sort();
        v
    };
    assert_eq!(sections(&got), sections(&want));
}

/// YAML (anchors, merge keys, explicit nulls, block scalars) and JSON Charters
/// decode, lint and print exactly as Go does.
#[test]
fn yaml_and_json_match_go() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/formats");
    let o = Options {
        config_dir: Some(dir),
        signed: SignedCharters::Disabled,
        ..Options::default()
    };
    let (mut printed, mut validated) = (String::new(), String::new());
    for (name, ext) in [("yaml-demo", "yaml"), ("json-demo", "json")] {
        let mut charter = load(name, &o).unwrap_or_else(|e| panic!("{name}: {e}"));
        print_findings(&mut validated, name, &lint_with_home(&charter, None));
        charter.source = PathBuf::from(format!("{name}.{ext}"));
        let _ = writeln!(printed, "=== {name}");
        printed.push_str(&render(&charter));
    }
    assert_eq!(printed, fixture("go-print-formats.txt"));
    assert_eq!(validated, fixture("go-validate-formats.txt"));

    let err = load("unknown", &o).expect_err("unknown field must fail");
    assert!(err.to_string().contains("imgae"), "{err}");
}
