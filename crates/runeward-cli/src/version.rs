//! The build version reported by `runeward version` and embedded in
//! evidence and telemetry.

/// `$RUNEWARD_VERSION` at build time, else the package version plus the git
/// commit (see `build.rs`).
pub const VERSION: &str = env!("RUNEWARD_BUILD_VERSION");

/// `runeward version`.
pub fn print() {
    println!("runeward {VERSION}");
}
