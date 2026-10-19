//! The browser driver for Citadel sandboxes. Rust port of the Go
//! `internal/browser` package and the `cmd/runeward-browser` command.
//!
//! * [`protocol`]: the wire contract between the control plane and the
//!   in-sandbox driver. Each driver connection carries exactly one
//!   [`Command`] and one [`CommandResult`]; the JSON is identical to Go's.
//! * [`cdp`]: a minimal Chrome DevTools Protocol client over one page-level
//!   WebSocket.
//! * [`driver`], [`proxyauth`] and [`cli`]: the `runeward-browser` binary
//!   (`serve`, `call` and one-shot `render`), which keeps a headless
//!   Chromium alive behind a control socket and, because Chromium cannot
//!   send proxy credentials, a loopback forwarder that adds proxy Basic
//!   auth for it.

pub mod cdp;
pub mod cli;
pub mod driver;
mod goflag;
pub mod protocol;
pub mod proxyauth;
mod util;

pub use cdp::{CdpError, Client, validate_navigate_url, validate_navigate_url_with};
pub use protocol::{Command, CommandResult};
