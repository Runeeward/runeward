//! The browser driver for Citadel sandboxes. Rust port of the Go
//! `internal/browser` package and the `cmd/runeward-browser` command.
//!
//! * [`protocol`]: the wire contract between the control plane and the
//!   in-sandbox driver. Each driver connection carries exactly one
//!   [`Command`] and one [`CommandResult`]; the JSON is identical to Go's.
//! * [`cdp`]: a minimal Chrome DevTools Protocol client over one page-level
//!   WebSocket.

pub mod cdp;
pub mod protocol;
mod util;

pub use cdp::{CdpError, Client, validate_navigate_url, validate_navigate_url_with};
pub use protocol::{Command, CommandResult};
