//! Egress enforcement for Rune Box sandboxes.
//!
//! Two front ends constrain sandbox network traffic with a [`Policy`]
//! (ordered allow/deny rules on hostnames and CIDRs, first match wins):
//!
//! - [`Proxy`]: a cooperative forward proxy (`HTTP(S)_PROXY`) handling
//!   `CONNECT` tunnels and plain absolute-URI HTTP, optionally behind HTTP
//!   Basic proxy authentication.
//! - [`TransparentProxy`]: strict (L3) mode for connections redirected by
//!   iptables ([`setup_redirect`]); the destination comes from
//!   `SO_ORIGINAL_DST` and the hostname from TLS SNI or the HTTP `Host`
//!   header. Linux-only.
//!
//! Hostnames must be explicitly allowlisted and are resolved once and pinned
//! (see [`resolve`]), so the proxy dials exactly the IP it approved and DNS
//! rebinding can't swap the destination after the check. Every decision is
//! kept in a bounded per-sandbox ring ([`list_decisions`]).
//!
//! # Decision seam
//!
//! Each front end turns its input into a [`gate::EgressRequest`] and calls
//! [`gate::Gate::evaluate`] before any upstream socket exists; only an
//! allow decision yields a [`resolve::PinnedTarget`] to dial. This is where
//! an L7 broker slots in: per-endpoint method/path rules and MCP tool names
//! extend `EgressRequest` (the HTTP front end already fills `method` and
//! `path`), credential placeholder substitution becomes a rewrite carried by
//! the allow decision and applied by the front end between the gate and the
//! upstream write, and audit-vs-enforce mode is a gate setting that records
//! a would-deny but still allows. Transport code (dial, TLS, splice) does
//! not need to change for any of these.

pub mod decision_log;
pub mod gate;
pub mod iptables;
pub mod logger;
pub mod netutil;
pub mod policy;
pub mod proxy;
pub mod resolve;
pub mod sni;
pub mod transparent;

pub use decision_log::{Decision, MAX_DECISIONS_PER_SANDBOX, list_decisions, record_decision};
pub use iptables::{DNS_RESOLVERS_ENV, setup_redirect};
pub use logger::Logger;
pub use policy::{Policy, PolicyError, Rule, load_policy};
pub use proxy::Proxy;
pub use sni::extract_sni;
pub use transparent::TransparentProxy;

/// The uid the transparent proxy runs as; iptables exempts it so the proxy's
/// own upstream traffic isn't redirected back to itself. Sandboxes must run
/// as a different uid to be intercepted.
pub use runeward_charter::STRICT_PROXY_UID;

/// The transparent proxy's listen port and the iptables `REDIRECT` target.
pub const STRICT_REDIRECT_PORT: u16 = 15001;
