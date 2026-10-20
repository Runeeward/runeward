//! The routed control-plane surface and its middleware chain.

use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::extract::Request;
use axum::http::StatusCode;
use axum::middleware::{from_fn, from_fn_with_state};
use axum::response::Response;
use axum::routing::{any, delete, get, post, put};
use runeward_authz::Store;
use runeward_controlplane::Manager;
use tower::ServiceExt;
use tower_http::catch_panic::CatchPanicLayer;

use crate::handlers::{
    agents, chronicle, citadels, conversation, core, fleet, ide, schedules, simulate, terminal,
    tools,
};
use crate::limit::{RATE_LIMIT_ENV, RateLimiter, parse_rate_limit};
use crate::respond::error;
use crate::state::{AppState, SharedState};
use crate::{auth, hardened};

/// Builds the control-plane router over a [`Manager`].
///
/// Every tool call goes through the Manager's governed path, so governance
/// is always enforced. Authentication is RBAC when an authz [`Store`] is
/// set, else the legacy single bearer token, else open (loopback only, see
/// [`crate::ServerConfig::validate`]).
#[derive(Debug)]
pub struct Server {
    mgr: Arc<Manager>,
    token: String,
    authz: Option<Arc<Store>>,
    dashboard: bool,
    mcp: Option<Router>,
    version: String,
    rate_limit: Option<f64>,
    principal_rate_limit: Option<f64>,
}

impl Server {
    /// A server over `mgr` with no authentication, no dashboard, no MCP and
    /// the rate limit from `RUNEWARD_RATE_LIMIT` (default 50 req/s per IP).
    pub fn new(mgr: Arc<Manager>) -> Self {
        Self {
            mgr,
            token: String::new(),
            authz: None,
            dashboard: false,
            mcp: None,
            version: String::new(),
            rate_limit: parse_rate_limit(std::env::var(RATE_LIMIT_ENV).ok().as_deref()),
            principal_rate_limit:
                runeward_controlplane::principal_limit::principal_rate_limit_from_env(),
        }
    }

    /// Requires this bearer token (`Authorization: Bearer` or
    /// `X-Runeward-Token`) on every request except `/healthz` and the
    /// dashboard shell. Ignored when [`Server::authz`] is set.
    #[must_use]
    pub fn token(mut self, token: impl Into<String>) -> Self {
        self.token = token.into();
        self
    }

    /// Enables multi-principal RBAC (static principals and OIDC).
    #[must_use]
    pub fn authz(mut self, store: Option<Arc<Store>>) -> Self {
        self.authz = store;
        self
    }

    /// Serves the embedded dashboard at `/`.
    #[must_use]
    pub fn dashboard(mut self, on: bool) -> Self {
        self.dashboard = on;
        self
    }

    /// Mounts an MCP router at `/mcp` and `/mcp/...`. It receives requests
    /// with their original path (as Go's `mux.Handle("/mcp", h)` does), after
    /// authentication; the caller's principal, when RBAC is on, is in the
    /// request extensions as `Arc<runeward_authz::Principal>` and is the
    /// Chronicle actor of the request task.
    #[must_use]
    pub fn mcp(mut self, router: Option<Router>) -> Self {
        self.mcp = router;
        self
    }

    /// The version embedded in evidence exports.
    #[must_use]
    pub fn version(mut self, version: impl Into<String>) -> Self {
        self.version = version.into();
        self
    }

    /// Requests per second per client IP (burst twice that); `None`
    /// disables limiting.
    #[must_use]
    pub fn rate_limit(mut self, rps: Option<f64>) -> Self {
        self.rate_limit = rps;
        self
    }

    /// Requests per second per authenticated principal (burst twice
    /// that), on top of the per-IP limit; `None` disables it. Defaults to
    /// `RUNEWARD_PRINCIPAL_RATE_LIMIT` (unset: off).
    #[must_use]
    pub fn principal_rate_limit(mut self, rps: Option<f64>) -> Self {
        self.principal_rate_limit = rps;
        self
    }

    /// The routed service. Serve it with `ConnectInfo<SocketAddr>` (as
    /// [`crate::serve`] does) so rate limiting and the IDE cookie's
    /// loopback rule see the peer address.
    pub fn router(self) -> Router {
        let state: SharedState = Arc::new(AppState {
            mgr: self.mgr,
            token: self.token,
            authz: self.authz,
            dashboard: self.dashboard,
            version: self.version,
            limiter: self.rate_limit.and_then(RateLimiter::new),
            principal_limiter: self
                .principal_rate_limit
                .and_then(runeward_controlplane::PrincipalLimiter::new),
            tickets: Mutex::new(HashMap::new()),
            ide_sessions: Mutex::new(HashMap::new()),
            ide_client: ide::proxy_client(),
        });
        let mut r = api_routes();
        if let Some(mcp) = self.mcp {
            let svc = tower::service_fn(move |req: Request| {
                let mcp = mcp.clone();
                async move { Ok::<_, Infallible>(mcp.oneshot(req).await.unwrap_or_else(|e| match e {})) }
            });
            r = r
                .route_service("/mcp", svc.clone())
                .route_service("/mcp/", svc.clone())
                .route_service("/mcp/{*rest}", svc);
        }
        // A known path with another method falls through to `/` like Go's
        // mux, where the catch-all pattern matches every method.
        r = if state.dashboard {
            r.fallback(crate::web::dashboard)
                .method_not_allowed_fallback(crate::web::dashboard)
        } else {
            r.fallback(core::api_root)
                .method_not_allowed_fallback(core::api_root)
        };
        r.layer(from_fn(auth::csrf_guard))
            .layer(from_fn_with_state(state.clone(), auth::ownership_guard))
            .layer(from_fn_with_state(
                state.clone(),
                hardened::principal_rate_limit,
            ))
            .layer(from_fn_with_state(state.clone(), auth::authenticate))
            .layer(from_fn_with_state(state.clone(), auth::rate_limit))
            .layer(from_fn(auth::security_headers))
            .layer(CatchPanicLayer::custom(|_| panic_response()))
            .layer(from_fn(auth::log_requests))
            .layer(from_fn(hardened::request_id))
            .with_state(state)
    }
}

/// A panicking handler becomes a generic 500 (no stack or detail leaks).
fn panic_response() -> Response {
    tracing::error!("panic serving request");
    error(StatusCode::INTERNAL_SERVER_ERROR, "internal server error")
}

/// The REST surface (Go `server.go` route table).
fn api_routes() -> Router<SharedState> {
    Router::new()
        .route("/healthz", get(core::health))
        .route("/metrics", get(core::metrics))
        .route("/v1/whoami", get(core::whoami))
        .route("/v1/charters", get(core::list_profiles))
        .route("/v1/readiness", get(core::readiness))
        .route("/v1/tickets", post(core::create_ticket))
        .route("/v1/policy/simulate", post(simulate::simulate))
        .route("/v1/runs", get(core::list_runs))
        .route("/v1/runs/{id}", get(core::get_run))
        .route("/v1/agent-sessions", get(agents::list))
        .route("/v1/agent-sessions/{id}", get(agents::get))
        .route("/v1/agent-sessions/{id}/events", get(agents::events))
        .route("/v1/agent-sessions/{id}/stream", get(agents::stream))
        .route("/v1/agent-sessions/{id}/turns", post(agents::turn))
        .route("/v1/agent-sessions/{id}/cancel", post(agents::cancel))
        .route("/v1/citadels", post(citadels::create).get(citadels::list))
        .route(
            "/v1/citadels/{id}",
            get(citadels::get).delete(citadels::kill),
        )
        .route("/v1/citadels/{id}/shell/exec", post(tools::shell))
        .route("/v1/citadels/{id}/browser", post(tools::browser))
        .route(
            "/v1/citadels/{id}/browser/sessions",
            post(tools::browser_open),
        )
        .route(
            "/v1/citadels/{id}/browser/sessions/{sid}/act",
            post(tools::browser_act),
        )
        .route(
            "/v1/citadels/{id}/browser/sessions/{sid}",
            delete(tools::browser_close),
        )
        .route("/v1/citadels/{id}/code/python", post(tools::python))
        .route("/v1/citadels/{id}/code/node", post(tools::node))
        .route("/v1/citadels/{id}/file/read", post(tools::file_read))
        .route("/v1/citadels/{id}/file/write", post(tools::file_write))
        .route("/v1/citadels/{id}/file/list", post(tools::file_list))
        .route("/v1/citadels/{id}/file/search", post(tools::file_search))
        .route("/v1/citadels/{id}/usage", post(citadels::report_usage))
        .route("/v1/citadels/{id}/perimeter", get(citadels::perimeter))
        .route(
            "/v1/citadels/{id}/conversation",
            get(conversation::history).post(conversation::publish),
        )
        .route(
            "/v1/citadels/{id}/conversation/stream",
            get(conversation::stream),
        )
        .route("/v1/citadels/{id}/agent-sessions", post(agents::start))
        .route("/v1/citadels/{id}/fork", post(citadels::fork))
        .route("/v1/citadels/{id}/sleep", post(citadels::sleep))
        .route("/v1/citadels/{id}/wake", post(citadels::wake))
        .route(
            "/v1/citadels/{id}/workspace/status",
            get(citadels::workspace_status),
        )
        .route(
            "/v1/citadels/{id}/schedules",
            get(schedules::list_for_citadel).post(schedules::create_for_citadel),
        )
        .route(
            "/v1/cohorts/{id}/schedules",
            get(schedules::list_for_cohort).post(schedules::create_for_cohort),
        )
        .route("/v1/schedules", get(schedules::list))
        .route(
            "/v1/schedules/{id}",
            get(schedules::get).delete(schedules::delete),
        )
        .route("/v1/schedules/{id}/run", post(schedules::run))
        .route("/v1/cohorts", post(fleet::create).get(fleet::list))
        .route("/v1/cohorts/{id}", get(fleet::get).delete(fleet::kill))
        .route(
            "/v1/cohorts/{id}/tasks",
            get(fleet::list_tasks).post(fleet::add_task),
        )
        .route("/v1/cohorts/{id}/claim", post(fleet::claim))
        .route(
            "/v1/cohorts/{id}/tasks/{task_id}/complete",
            post(fleet::complete),
        )
        .route("/v1/cohorts/{id}/tasks/{task_id}/fail", post(fleet::fail))
        .route(
            "/v1/cohorts/{id}/tasks/{task_id}/children",
            post(fleet::add_child),
        )
        .route(
            "/v1/cohorts/{id}/tasks/{task_id}/notes",
            post(fleet::add_note),
        )
        .route(
            "/v1/cohorts/{id}/tasks/{task_id}/brief",
            put(fleet::set_brief),
        )
        .route(
            "/v1/cohorts/{id}/tasks/{task_id}/context",
            get(fleet::task_context),
        )
        .route(
            "/v1/cohorts/{id}/memory",
            get(fleet::memory_list).post(fleet::memory_put),
        )
        .route(
            "/v1/cohorts/{id}/memory/{*key}",
            get(fleet::memory_get).delete(fleet::memory_delete),
        )
        .route(
            "/v1/cohorts/{id}/tasks/{task_id}/heartbeat",
            post(fleet::heartbeat),
        )
        .route("/v1/citadels/{id}/snapshot", post(citadels::snapshot))
        .route(
            "/v1/citadels/{id}/workspace",
            get(citadels::workspace_export),
        )
        .route("/v1/citadels/{id}/evidence", get(citadels::evidence_export))
        .route("/v1/snapshots", get(citadels::list_snapshots))
        .route(
            "/v1/snapshots/{id}/restore",
            post(citadels::restore_snapshot),
        )
        .route("/v1/citadels/{id}/chronicle", get(chronicle::replay))
        .route("/v1/chronicle/verify", get(chronicle::verify))
        .route("/v1/chronicle/pubkey", get(chronicle::pubkey))
        .route("/v1/chronicle/export", get(chronicle::export))
        .route("/v1/conclave", get(chronicle::list_approvals))
        .route("/v1/conclave/{id}/approve", post(chronicle::approve))
        .route("/v1/conclave/{id}/deny", post(chronicle::deny))
        .route("/v1/citadels/{id}/terminal", get(terminal::terminal))
        .route("/v1/citadels/{id}/terminal-ticket", post(terminal::ticket))
        // Method-agnostic so code-server HTTP and WebSocket upgrades proxy.
        .route("/v1/citadels/{id}/ide", any(ide::proxy))
        .route("/v1/citadels/{id}/ide/", any(ide::proxy))
        .route("/v1/citadels/{id}/ide/{*path}", any(ide::proxy))
        .route("/v1/citadels/{id}/ide-ticket", post(ide::ticket))
}
