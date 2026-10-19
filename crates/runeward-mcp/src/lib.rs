//! Rune Box's governed tools over the Model Context Protocol.
//!
//! The server (implementation name `runeward`, version [`VERSION`]) exposes
//! 47 tools prefixed `runeward_`: the 35 tools of the Go server plus
//! `runeward_server_info` and the context tools (`runeward_fork_citadel`,
//! `runeward_memory_put`/`_get`/`_search`, `runeward_add_note`,
//! `runeward_set_brief`, `runeward_handoff`, `runeward_add_child_task` and
//! `runeward_schedule_create`/`_list`/`_delete`; agents can create
//! schedules only when the Charter sets `[schedule] self_service = true`).
//! `runeward_claim_task` also returns the task's context (handoff notes,
//! brief, parent and ranked shared memory) when there is any. Every tool goes through the same
//! [`runeward_controlplane::Manager`] path as the REST API (policy, Conclave
//! approvals, guardrails and the signed Chronicle). A policy deny surfaces as
//! a tool error with code `policy_denied`; require-approval returns
//! `approval_required` guidance telling the agent to pause for a human rather
//! than retry.
//!
//! # Transports
//!
//! - **stdio** ([`serve_stdio`]): for desktop agents. The caller is the
//!   principal named by `RUNEWARD_MCP_DEFAULT_PRINCIPAL` (default
//!   `mcp-stdio`), or, when `RUNEWARD_AUTHZ_FILE` is configured, the
//!   principal matching `RUNEWARD_MCP_DEFAULT_TOKEN` or the stored
//!   `runeward auth login` token.
//! - **streamable HTTP** ([`router`] to mount at `/mcp`, or [`serve_http`]
//!   for `runeward mcp --http`): the caller is identified per request from
//!   its `Authorization: Bearer` token. With an authz store, unknown or
//!   missing tokens are refused with 401 before reaching the MCP layer;
//!   without one, a shared `--token` gates the endpoint like the Go
//!   `TokenAuth` middleware.
//!
//! # Tenancy and attribution
//!
//! Citadels, Cohorts, runs and snapshots are visible only within the
//! caller's tenant unless the principal is an administrator; another
//! tenant's resources are reported as "not found". Every tool runs inside
//! [`runeward_controlplane::with_actor`] so Chronicle events are attributed
//! to the authenticated principal.
//!
//! # Tool-list integrity
//!
//! `runeward_server_info` returns [`tool_list_digest`], a SHA-256 over the
//! canonical JSON (object keys sorted, no insignificant whitespace) of the
//! `tools/list` array sorted by name, so clients can pin the tool surface and
//! detect stale or tampered definitions.

mod auth;
mod http;
mod results;
mod server;
mod tools;

pub use auth::{Identity, parse_bearer_token};
pub use http::{
    HttpConfig, McpArgs, ShutdownSignal, is_loopback_host, router, run, serve_http, serve_http_on,
};
pub use server::{McpConfig, McpServer, serve_stdio};
pub use tools::{canonical_json, tool_definitions, tool_list_digest};

/// The reported MCP server implementation name.
pub const SERVER_NAME: &str = "runeward";

/// The reported MCP server implementation version (the Go server's).
pub const VERSION: &str = "0.3.0";

/// Names the stdio principal when no authz store is configured.
pub const ENV_MCP_DEFAULT_PRINCIPAL: &str = "RUNEWARD_MCP_DEFAULT_PRINCIPAL";

/// Maps stdio sessions to an authz principal when `RUNEWARD_AUTHZ_FILE` is
/// configured.
pub const ENV_MCP_DEFAULT_TOKEN: &str = "RUNEWARD_MCP_DEFAULT_TOKEN"; // variable name, not a credential

/// The shared HTTP token used when `--token` is not given.
pub const ENV_API_TOKEN: &str = "RUNEWARD_API_TOKEN"; // variable name, not a credential

/// Enables `copy_from` under RBAC once set (shared with the backend).
pub const ENV_COPY_FROM_ROOTS: &str = "RUNEWARD_COPY_FROM_ROOTS";

/// Errors starting or running an MCP transport.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The transport configuration was refused (the same rules as the Go
    /// CLI, with the same messages).
    #[error("{0}")]
    Config(String),
    /// The authz store rejected the configuration.
    #[error(transparent)]
    Authz(#[from] runeward_authz::Error),
    /// TLS material could not be loaded.
    #[error("tls: {0}")]
    Tls(String),
    /// Binding or serving failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// The MCP session ended with an error.
    #[error("mcp: {0}")]
    Service(String),
}
