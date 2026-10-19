//! Stamps the version reported by `runeward version`: `$RUNEWARD_VERSION`
//! when set at build time (release builds), otherwise the package version
//! plus the git commit when git is available.

use std::process::Command;

/// Runs git, falling back to the system git when the one on PATH cannot
/// start (e.g. a binary for another architecture).
fn git(args: &[&str]) -> Option<String> {
    let out = ["git", "/usr/bin/git"]
        .iter()
        .find_map(|bin| Command::new(bin).args(args).output().ok())?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8(out.stdout).ok()?.trim().to_owned();
    (!s.is_empty()).then_some(s)
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=RUNEWARD_VERSION");
    let pkg = std::env::var("CARGO_PKG_VERSION").unwrap_or_default();
    let version = match std::env::var("RUNEWARD_VERSION") {
        Ok(v) if !v.trim().is_empty() => v.trim().to_owned(),
        _ => match git(&["rev-parse", "--short=12", "HEAD"]) {
            Some(rev) => {
                for path in ["HEAD", "packed-refs"] {
                    if let Some(p) = git(&["rev-parse", "--git-path", path]) {
                        println!("cargo:rerun-if-changed={p}");
                    }
                }
                if let Some(head) = git(&["symbolic-ref", "-q", "HEAD"])
                    && let Some(p) = git(&["rev-parse", "--git-path", &head])
                {
                    println!("cargo:rerun-if-changed={p}");
                }
                format!("{pkg}+g{rev}")
            }
            None => pkg,
        },
    };
    println!("cargo:rustc-env=RUNEWARD_BUILD_VERSION={version}");
}
