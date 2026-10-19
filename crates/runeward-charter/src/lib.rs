//! Charters: the declarative security contract a Rune Box session runs under.
//!
//! A Charter (called a "profile" in the Go implementation and on the wire) is
//! resolved by name from `.runeward/` or the user config dir, decoded strictly
//! from TOML, YAML or JSON, defaulted and validated. [`lint`] then reports
//! softer misconfigurations, [`print`] renders a redacted human view, and
//! [`Signature`] implements the detached `runeward.profile.sig.v1` envelope
//! that signed-Charter enforcement checks before decoding.

mod duration;
mod schema;
mod signature;

pub use duration::{DurationError, parse_duration, parse_go_duration};
pub use schema::{
    Audit, CelRule, Charter, EnvVar, File, Fleet, Host, HostType, Ide, Limits, Network,
    NetworkRule, PolicyBundle, PolicyRule, Prompt, RegoPolicy, Verdict,
};
pub use signature::{SIGNATURE_FORMAT, Signature, SignatureError, sign, verify};

/// Host uid reserved for the strict-mode egress proxy; sandboxes may not run
/// as it, because iptables exempts its traffic from interception.
pub const STRICT_PROXY_UID: u32 = 1337;
