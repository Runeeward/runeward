//! The MCP server handler: tool dispatch over the control-plane
//! [`Manager`], plus the stdio transport.

use std::sync::Arc;

use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, Implementation, ListToolsResult,
    PaginatedRequestParams, ServerCapabilities, ServerConfig, Tool,
};
use rmcp::service::RequestContext;
use rmcp::{ErrorData, RoleServer, ServerHandler, ServiceExt};
use runeward_authz::Store;
use runeward_browser::Command;
use runeward_charter::Verdict;
use runeward_controlplane::{
    ApprovalView, ClaimContext, CreateOptions, FleetView, ForkOptions, Manager, MemoryEntry,
    MemoryPut, MemoryQuery, ProfileInfo, Run, Schedule, ScheduleSpec, with_actor,
};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::auth::{Identity, Resolver};
use crate::results::{blocked, cp_err, err_text, exec, go_float, raw, structured, text};
use crate::tools::{self, *};
use crate::{
    ENV_COPY_FROM_ROOTS, ENV_MCP_DEFAULT_PRINCIPAL, ENV_MCP_DEFAULT_TOKEN, Error, SERVER_NAME,
    VERSION,
};

/// Server settings shared by every transport.
#[derive(Clone)]
pub struct McpConfig {
    /// The stdio principal without RBAC (`RUNEWARD_MCP_DEFAULT_PRINCIPAL`;
    /// empty means `mcp-stdio`).
    pub default_principal: String,
    /// The token identifying the stdio principal when an authz store is
    /// configured (`RUNEWARD_MCP_DEFAULT_TOKEN`, else the stored
    /// `runeward auth login` token).
    pub default_token: String,
    /// The legacy shared HTTP bearer token, enforced by [`crate::router`]
    /// only when there is no authz store. Empty disables it.
    pub token: String,
    /// Accepted `Host` header values for the HTTP transport (DNS-rebinding
    /// protection). `None` accepts any host; the default accepts loopback
    /// names only.
    pub allowed_hosts: Option<Vec<String>>,
    /// Whether `RUNEWARD_COPY_FROM_ROOTS` is configured: under RBAC,
    /// `copy_from` stays disabled until it is.
    pub copy_from_roots_configured: bool,
    /// Requests per second per authenticated principal on the HTTP
    /// transport (`RUNEWARD_PRINCIPAL_RATE_LIMIT`); `None` disables it.
    pub principal_rate_limit: Option<f64>,
}

impl std::fmt::Debug for McpConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("McpConfig")
            .field("default_principal", &self.default_principal)
            .field("default_token", &redacted(&self.default_token))
            .field("token", &redacted(&self.token))
            .field("allowed_hosts", &self.allowed_hosts)
            .field(
                "copy_from_roots_configured",
                &self.copy_from_roots_configured,
            )
            .field("principal_rate_limit", &self.principal_rate_limit)
            .finish()
    }
}

fn redacted(s: &str) -> &'static str {
    if s.is_empty() { "" } else { "<redacted>" }
}

/// Loopback `Host` names accepted by default.
pub(crate) fn loopback_hosts() -> Vec<String> {
    ["localhost", "127.0.0.1", "::1", "[::1]"]
        .into_iter()
        .map(String::from)
        .collect()
}

impl Default for McpConfig {
    fn default() -> Self {
        Self {
            default_principal: String::new(),
            default_token: String::new(),
            token: String::new(),
            allowed_hosts: Some(loopback_hosts()),
            copy_from_roots_configured: false,
            principal_rate_limit: None,
        }
    }
}

impl McpConfig {
    /// Reads the stdio identity and copy-from setting from the environment
    /// like the Go server (the stored login token is the stdio fallback).
    pub fn from_env() -> Self {
        let env = |k: &str| std::env::var(k).unwrap_or_default().trim().to_owned();
        let mut default_token = env(ENV_MCP_DEFAULT_TOKEN);
        if default_token.is_empty() {
            default_token = runeward_credentials::load_token();
        }
        Self {
            default_principal: env(ENV_MCP_DEFAULT_PRINCIPAL),
            default_token,
            copy_from_roots_configured: !env(ENV_COPY_FROM_ROOTS).is_empty(),
            principal_rate_limit:
                runeward_controlplane::principal_limit::principal_rate_limit_from_env(),
            ..Self::default()
        }
    }
}

/// The `runeward` MCP server: an [`rmcp::ServerHandler`] usable with any
/// rmcp transport. Cheap to clone.
#[derive(Clone)]
pub struct McpServer {
    inner: Arc<Inner>,
}

struct Inner {
    mgr: Arc<Manager>,
    /// A resolver setup failure is reported by every tool (Go's
    /// `resolverErr`).
    resolver: Result<Resolver, String>,
    copy_from_roots: bool,
}

impl std::fmt::Debug for McpServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("McpServer")
            .field("manager", &self.inner.mgr)
            .field("resolver_ok", &self.inner.resolver.is_ok())
            .finish_non_exhaustive()
    }
}

impl McpServer {
    /// Builds a server, identifying the stdio principal from
    /// `config.default_token` when `authz` is configured. A token matching
    /// no principal does not fail here: every tool then reports it.
    pub async fn new(manager: Arc<Manager>, authz: Option<Arc<Store>>, config: &McpConfig) -> Self {
        let resolver = Resolver::new(authz, &config.default_principal, &config.default_token).await;
        Self::with_resolver(manager, resolver, config)
    }

    /// A server for HTTP transports, where callers are identified per
    /// request (no stdio identity is resolved).
    pub fn for_http(manager: Arc<Manager>, authz: Option<Arc<Store>>, config: &McpConfig) -> Self {
        let resolver = Ok(Resolver::http_only(authz, &config.default_principal));
        Self::with_resolver(manager, resolver, config)
    }

    fn with_resolver(
        mgr: Arc<Manager>,
        resolver: Result<Resolver, String>,
        config: &McpConfig,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                mgr,
                resolver,
                copy_from_roots: config.copy_from_roots_configured,
            }),
        }
    }

    fn mgr(&self) -> &Manager {
        &self.inner.mgr
    }

    async fn identity(
        &self,
        http: Option<&http::request::Parts>,
    ) -> Result<Identity, CallToolResult> {
        let resolver = self.inner.resolver.as_ref().map_err(|e| err_text(e))?;
        resolver.resolve(http).await.map_err(|e| err_text(&e))
    }

    /// Resolves the caller and checks it may use Citadel `id`.
    async fn citadel(
        &self,
        http: Option<&http::request::Parts>,
        id: &str,
    ) -> Result<Identity, CallToolResult> {
        let p = self.identity(http).await?;
        match self.mgr().sandbox_owner(id) {
            Some(owner) if p.sees(&owner) => Ok(p),
            _ => Err(err_text("citadel not found")),
        }
    }

    /// Resolves the caller and checks it may use Cohort `id`.
    async fn cohort(
        &self,
        http: Option<&http::request::Parts>,
        id: &str,
    ) -> Result<Identity, CallToolResult> {
        let p = self.identity(http).await?;
        match self.mgr().fleet_owner(id) {
            Some(owner) if p.sees(&owner) => Ok(p),
            _ => Err(err_text("cohort not found")),
        }
    }

    /// Runs one tool. `http` carries the HTTP request parts (`None` on
    /// stdio). Unknown tools are a protocol error, as in the Go SDK.
    pub(crate) async fn dispatch(
        &self,
        name: &str,
        args: Value,
        http: Option<&http::request::Parts>,
    ) -> Result<CallToolResult, ErrorData> {
        macro_rules! run {
            ($in:ty, $method:ident) => {
                match parse::<$in>(args) {
                    Ok(input) => self.$method(http, input).await,
                    Err(r) => r,
                }
            };
        }
        let res = match name {
            "runeward_whoami" => run!(NoInput, whoami),
            "runeward_server_info" => run!(NoInput, server_info),
            "runeward_list_charters" => run!(NoInput, list_charters),
            "runeward_readiness" => run!(ProfileIn, readiness),
            "runeward_create_citadel" => run!(CreateCitadelIn, create_citadel),
            "runeward_list_citadels" => run!(NoInput, list_citadels),
            "runeward_list_runs" => run!(NoInput, list_runs),
            "runeward_shell" => run!(ShellIn, shell),
            "runeward_browser" => run!(BrowserIn, browser),
            "runeward_browser_open" => run!(SandboxIn, browser_open),
            "runeward_browser_act" => run!(BrowserActIn, browser_act),
            "runeward_browser_close" => run!(BrowserCloseIn, browser_close),
            "runeward_python" => run!(PythonIn, python),
            "runeward_node" => run!(NodeIn, node),
            "runeward_read_file" => run!(ReadFileIn, read_file),
            "runeward_write_file" => run!(WriteFileIn, write_file),
            "runeward_list_files" => run!(ListFilesIn, list_files),
            "runeward_search_files" => run!(SearchFilesIn, search_files),
            "runeward_list_conclave" => run!(NoInput, list_conclave),
            "runeward_kill_citadel" => run!(SandboxIn, kill_citadel),
            "runeward_report_usage" => run!(ReportUsageIn, report_usage),
            "runeward_publish_conversation" => run!(PublishConversationIn, publish_conversation),
            "runeward_list_conversation" => run!(ListConversationIn, list_conversation),
            "runeward_snapshot_citadel" => run!(SnapshotIn, snapshot_citadel),
            "runeward_list_snapshots" => run!(NoInput, list_snapshots),
            "runeward_export_evidence" => run!(SandboxIn, export_evidence),
            "runeward_verify_chronicle" => run!(NoInput, verify_chronicle),
            "runeward_create_cohort" => run!(CreateCohortIn, create_cohort),
            "runeward_list_cohorts" => run!(NoInput, list_cohorts),
            "runeward_list_tasks" => run!(FleetIn, list_tasks),
            "runeward_add_task" => run!(AddTaskIn, add_task),
            "runeward_claim_task" => run!(FleetIn, claim_task),
            "runeward_heartbeat_task" => run!(HeartbeatIn, heartbeat_task),
            "runeward_complete_task" => run!(CompleteTaskIn, complete_task),
            "runeward_fail_task" => run!(FailTaskIn, fail_task),
            "runeward_kill_cohort" => run!(FleetIn, kill_cohort),
            "runeward_fork_citadel" => run!(ForkCitadelIn, fork_citadel),
            "runeward_memory_put" => run!(MemoryPutIn, memory_put),
            "runeward_memory_get" => run!(MemoryGetIn, memory_get),
            "runeward_memory_search" => run!(MemorySearchIn, memory_search),
            "runeward_add_note" => run!(AddNoteIn, add_note),
            "runeward_set_brief" => run!(SetBriefIn, set_brief),
            "runeward_handoff" => run!(HandoffIn, handoff),
            "runeward_add_child_task" => run!(AddChildTaskIn, add_child_task),
            "runeward_schedule_create" => run!(ScheduleCreateIn, schedule_create),
            "runeward_schedule_list" => run!(ScheduleListIn, schedule_list),
            "runeward_schedule_delete" => run!(ScheduleDeleteIn, schedule_delete),
            _ => {
                return Err(ErrorData::invalid_params(
                    format!("unknown tool {name:?}"),
                    None,
                ));
            }
        };
        Ok(res)
    }
}

/// Decodes tool arguments; a failure is a tool error, as in the Go SDK.
fn parse<T: DeserializeOwned>(args: Value) -> Result<T, CallToolResult> {
    serde_json::from_value(args).map_err(|e| {
        let mut r = text(format!("validating \"arguments\": {e}"));
        r.is_error = Some(true);
        r
    })
}

/// Unwraps a resolved identity or returns the tool error.
macro_rules! ok_or_return {
    ($e:expr) => {
        match $e {
            Ok(v) => v,
            Err(r) => return r,
        }
    };
}

#[derive(Serialize)]
struct Whoami<'a> {
    authenticated: bool,
    principal: WhoamiPrincipal<'a>,
    rbac: bool,
}

#[derive(Serialize)]
struct WhoamiPrincipal<'a> {
    admin: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    allowed_profiles: Option<&'a [String]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    approval_profiles: Option<&'a [String]>,
    can_approve: bool,
    can_launch: bool,
    name: &'a str,
    tenant: &'a str,
}

impl<'a> WhoamiPrincipal<'a> {
    fn of(p: &'a Identity) -> Self {
        match &p.principal {
            None => Self {
                admin: true,
                allowed_profiles: None,
                approval_profiles: None,
                can_approve: true,
                can_launch: true,
                name: &p.actor,
                tenant: &p.owner,
            },
            Some(rbac) => Self {
                admin: rbac.admin,
                allowed_profiles: Some(&rbac.allowed_profiles),
                approval_profiles: Some(&rbac.approval_profiles),
                can_approve: rbac.may_approve(),
                can_launch: rbac.may_launch(),
                name: &p.actor,
                tenant: &p.owner,
            },
        }
    }
}

#[derive(Serialize)]
struct ServerInfoOut<'a> {
    caller: ServerInfoCaller<'a>,
    digest_algorithm: &'a str,
    name: &'a str,
    tool_count: usize,
    tool_list_digest: &'a str,
    version: &'a str,
}

#[derive(Serialize)]
struct ServerInfoCaller<'a> {
    admin: bool,
    name: &'a str,
    rbac: bool,
    tenant: &'a str,
}

#[derive(Serialize)]
struct Charters<'a> {
    charters: &'a [ProfileInfo],
}

#[derive(Serialize)]
struct CitadelOut<'a> {
    backend: &'a str,
    id: &'a str,
    image: &'a str,
    isolation: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    owner: Option<&'a str>,
    profile: &'a str,
    status: &'a str,
}

#[derive(Serialize)]
struct Citadels<'a> {
    citadels: Vec<CitadelOut<'a>>,
}

#[derive(Serialize)]
struct Runs<'a> {
    runs: &'a [Run],
}

#[derive(Serialize)]
struct WriteOut<'a> {
    bytes: usize,
    path: &'a str,
    verdict: &'a str,
}

#[derive(Serialize)]
struct Approvals<'a> {
    approvals: &'a [ApprovalView],
}

#[derive(Serialize)]
struct KilledCitadel<'a> {
    citadel: &'a str,
    ok: bool,
}

/// Go's `accounting.Usage` (exported field names, no JSON tags).
#[derive(Serialize)]
struct UsageOut {
    #[serde(rename = "Tokens")]
    tokens: i64,
    #[serde(rename = "CostUSD", serialize_with = "go_float")]
    cost_usd: f64,
}

#[derive(Serialize)]
struct Messages<'a, T> {
    messages: &'a [T],
}

#[derive(Serialize)]
struct Snapshots<'a, T> {
    snapshots: &'a [T],
}

#[derive(Serialize)]
struct Verified<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<&'a str>,
    ok: bool,
}

#[derive(Serialize)]
struct Cohorts<'a> {
    cohorts: &'a [FleetView],
}

#[derive(Serialize)]
struct Tasks<'a, T> {
    tasks: &'a [T],
}

#[derive(Serialize)]
struct Claimed<'a, T> {
    claimed: bool,
    /// The task's handoff notes, brief, parent and relevant shared memory,
    /// when there is any.
    #[serde(skip_serializing_if = "Option::is_none")]
    context: Option<&'a ClaimContext>,
    #[serde(skip_serializing_if = "Option::is_none")]
    task: Option<&'a T>,
}

#[derive(Serialize)]
struct ForkedOut<'a> {
    backend: &'a str,
    forked_from: &'a str,
    id: &'a str,
    image: &'a str,
    isolation: &'a str,
    profile: &'a str,
    status: &'a str,
}

#[derive(Serialize)]
struct Entries<'a> {
    entries: &'a [MemoryEntry],
}

#[derive(Serialize)]
struct SchedulesOut<'a> {
    schedules: &'a [Schedule],
}

#[derive(Serialize)]
struct DeletedSchedule<'a> {
    ok: bool,
    schedule: &'a str,
}

#[derive(Serialize)]
struct OkTask<'a, T> {
    ok: bool,
    task: &'a T,
}

#[derive(Serialize)]
struct TaskState<'a> {
    ok: bool,
    state: &'a str,
    task: &'a str,
}

#[derive(Serialize)]
struct KilledCohort<'a> {
    cohort: &'a str,
    ok: bool,
}

type Parts<'a> = Option<&'a http::request::Parts>;

impl McpServer {
    async fn whoami(&self, http: Parts<'_>, _: NoInput) -> CallToolResult {
        let p = ok_or_return!(self.identity(http).await);
        structured(&Whoami {
            authenticated: true,
            principal: WhoamiPrincipal::of(&p),
            rbac: p.rbac(),
        })
    }

    async fn server_info(&self, http: Parts<'_>, _: NoInput) -> CallToolResult {
        let p = ok_or_return!(self.identity(http).await);
        structured(&ServerInfoOut {
            caller: ServerInfoCaller {
                admin: p.principal.is_none() || p.is_admin(),
                name: &p.actor,
                rbac: p.rbac(),
                tenant: &p.owner,
            },
            digest_algorithm: "sha256 over the canonical JSON (object keys sorted, no whitespace) of the tools/list array sorted by name",
            name: SERVER_NAME,
            tool_count: tools::tool_definitions().len(),
            tool_list_digest: tools::tool_list_digest(),
            version: VERSION,
        })
    }

    async fn list_charters(&self, http: Parts<'_>, _: NoInput) -> CallToolResult {
        let p = ok_or_return!(self.identity(http).await);
        let mut profiles = match self.mgr().list_profiles().await {
            Ok(v) => v,
            Err(e) => return cp_err(&e),
        };
        if p.rbac() && !p.is_admin() {
            profiles.retain(|info| p.can_launch(&info.name));
        }
        structured(&Charters {
            charters: &profiles,
        })
    }

    async fn readiness(&self, http: Parts<'_>, input: ProfileIn) -> CallToolResult {
        let p = ok_or_return!(self.identity(http).await);
        if !p.can_launch(&input.profile) {
            return err_text("charter not found");
        }
        structured(&self.mgr().check_readiness(&input.profile).await)
    }

    async fn create_citadel(&self, http: Parts<'_>, input: CreateCitadelIn) -> CallToolResult {
        let p = ok_or_return!(self.identity(http).await);
        if !p.can_launch(&input.profile) {
            return err_text(&format!(
                "principal {:?} is not allowed to launch charter {:?}",
                p.actor, input.profile
            ));
        }
        let copy_from = !input.copy_from.trim().is_empty();
        if copy_from && p.rbac() && !p.is_admin() {
            return err_text("copy_from overrides require an administrator");
        }
        if copy_from && p.rbac() && !self.inner.copy_from_roots {
            return err_text(
                "copy_from is disabled under RBAC until RUNEWARD_COPY_FROM_ROOTS is configured",
            );
        }
        let opts = CreateOptions {
            copy_from: input.copy_from,
            owner: p.owner.clone(),
            actor: p.actor.clone(),
            parent_sandbox: input.parent_citadel,
            run_id: input.run_id,
            agent: input.agent,
            provider: input.provider,
            model: input.model,
        };
        let created = with_actor(&p.actor, self.mgr().create_sandbox(&input.profile, opts)).await;
        match created {
            Ok(sb) => structured(&CitadelOut {
                backend: &sb.backend,
                id: &sb.id,
                image: &sb.image,
                isolation: sb.isolation.as_str(),
                owner: None,
                profile: &sb.profile,
                status: &sb.status,
            }),
            Err(e) => cp_err(&e),
        }
    }

    async fn list_citadels(&self, http: Parts<'_>, _: NoInput) -> CallToolResult {
        let p = ok_or_return!(self.identity(http).await);
        let mut infos = self.mgr().list_sandbox_infos();
        infos.retain(|info| p.sees(&info.owner));
        infos.sort_by(|a, b| a.sandbox.id.cmp(&b.sandbox.id));
        let citadels = infos
            .iter()
            .map(|info| CitadelOut {
                backend: &info.sandbox.backend,
                id: &info.sandbox.id,
                image: &info.sandbox.image,
                isolation: info.isolation.as_str(),
                owner: Some(&info.owner),
                profile: &info.sandbox.profile,
                status: &info.sandbox.status,
            })
            .collect();
        structured(&Citadels { citadels })
    }

    async fn list_runs(&self, http: Parts<'_>, _: NoInput) -> CallToolResult {
        let p = ok_or_return!(self.identity(http).await);
        let mut runs = self.mgr().list_runs();
        if p.rbac() && !p.is_admin() {
            runs.retain(|r| r.tenant == p.owner);
        }
        structured(&Runs { runs: &runs })
    }

    async fn shell(&self, http: Parts<'_>, input: ShellIn) -> CallToolResult {
        let p = ok_or_return!(self.citadel(http, &input.sandbox).await);
        let res = with_actor(
            &p.actor,
            self.mgr()
                .shell(&input.sandbox, &input.command, &input.workdir),
        )
        .await;
        exec(res)
    }

    async fn browser(&self, http: Parts<'_>, input: BrowserIn) -> CallToolResult {
        let p = ok_or_return!(self.citadel(http, &input.sandbox).await);
        let res = with_actor(
            &p.actor,
            self.mgr().browser(&input.sandbox, &input.url, &input.mode),
        )
        .await;
        exec(res)
    }

    async fn browser_open(&self, http: Parts<'_>, input: SandboxIn) -> CallToolResult {
        let p = ok_or_return!(self.citadel(http, &input.sandbox).await);
        match with_actor(&p.actor, self.mgr().browser_open(&input.sandbox)).await {
            Err(e) => cp_err(&e),
            Ok((_, res)) if res.verdict != Verdict::Allow => exec(Ok(res)),
            Ok((sid, _)) => text(format!(
                "browser session {} opened",
                sid.unwrap_or_default()
            )),
        }
    }

    async fn browser_act(&self, http: Parts<'_>, input: BrowserActIn) -> CallToolResult {
        let p = ok_or_return!(self.citadel(http, &input.sandbox).await);
        let cmd = Command {
            action: input.action,
            url: input.url,
            selector: input.selector,
            expr: input.expr,
            text: input.text,
            timeout_ms: input.timeout_ms,
            ..Command::default()
        };
        let res = with_actor(
            &p.actor,
            self.mgr().browser_act(&input.sandbox, &input.session, cmd),
        )
        .await;
        exec(res)
    }

    async fn browser_close(&self, http: Parts<'_>, input: BrowserCloseIn) -> CallToolResult {
        let p = ok_or_return!(self.citadel(http, &input.sandbox).await);
        let res = with_actor(
            &p.actor,
            self.mgr().browser_close(&input.sandbox, &input.session),
        )
        .await;
        match res {
            Ok(()) => text(format!("browser session {} closed", input.session)),
            Err(e) => cp_err(&e),
        }
    }

    async fn python(&self, http: Parts<'_>, input: PythonIn) -> CallToolResult {
        let p = ok_or_return!(self.citadel(http, &input.sandbox).await);
        exec(with_actor(&p.actor, self.mgr().python(&input.sandbox, &input.code)).await)
    }

    async fn node(&self, http: Parts<'_>, input: NodeIn) -> CallToolResult {
        let p = ok_or_return!(self.citadel(http, &input.sandbox).await);
        exec(with_actor(&p.actor, self.mgr().node(&input.sandbox, &input.code)).await)
    }

    async fn read_file(&self, http: Parts<'_>, input: ReadFileIn) -> CallToolResult {
        let p = ok_or_return!(self.citadel(http, &input.sandbox).await);
        raw(with_actor(&p.actor, self.mgr().file_read(&input.sandbox, &input.path)).await)
    }

    async fn write_file(&self, http: Parts<'_>, input: WriteFileIn) -> CallToolResult {
        let p = ok_or_return!(self.citadel(http, &input.sandbox).await);
        let res = with_actor(
            &p.actor,
            self.mgr()
                .file_write(&input.sandbox, &input.path, &input.content),
        )
        .await;
        let res = match res {
            Ok(r) => r,
            Err(e) => return cp_err(&e),
        };
        blocked(&res).unwrap_or_else(|| {
            structured(&WriteOut {
                bytes: input.content.len(),
                path: &input.path,
                verdict: "allow",
            })
        })
    }

    async fn list_files(&self, http: Parts<'_>, input: ListFilesIn) -> CallToolResult {
        let p = ok_or_return!(self.citadel(http, &input.sandbox).await);
        raw(with_actor(&p.actor, self.mgr().file_list(&input.sandbox, &input.path)).await)
    }

    async fn search_files(&self, http: Parts<'_>, input: SearchFilesIn) -> CallToolResult {
        let p = ok_or_return!(self.citadel(http, &input.sandbox).await);
        let res = with_actor(
            &p.actor,
            self.mgr()
                .file_search(&input.sandbox, &input.query, &input.path),
        )
        .await;
        raw(res)
    }

    async fn list_conclave(&self, http: Parts<'_>, _: NoInput) -> CallToolResult {
        let p = ok_or_return!(self.identity(http).await);
        if !p.may_approve() {
            return err_text("not authorized to view conclave decisions");
        }
        let mut list = self.mgr().approvals().list();
        if let Some(rbac) = p.principal.as_ref().filter(|_| !p.is_admin()) {
            list.retain(|a| {
                self.mgr()
                    .sandbox(&a.sandbox)
                    .is_some_and(|sb| rbac.can_approve_profile(&sb.profile))
            });
        }
        list.sort_by_key(|a| a.created);
        structured(&Approvals { approvals: &list })
    }

    async fn kill_citadel(&self, http: Parts<'_>, input: SandboxIn) -> CallToolResult {
        let p = ok_or_return!(self.citadel(http, &input.sandbox).await);
        match with_actor(&p.actor, self.mgr().kill_sandbox(&input.sandbox)).await {
            Ok(()) => structured(&KilledCitadel {
                citadel: &input.sandbox,
                ok: true,
            }),
            Err(e) => cp_err(&e),
        }
    }

    async fn report_usage(&self, http: Parts<'_>, input: ReportUsageIn) -> CallToolResult {
        let p = ok_or_return!(self.citadel(http, &input.sandbox).await);
        let res = with_actor(
            &p.actor,
            self.mgr()
                .record_usage(&input.sandbox, input.tokens, input.cost_usd),
        )
        .await;
        if let Err(e) = res {
            return cp_err(&e);
        }
        let u = self.mgr().sandbox_usage(&input.sandbox);
        structured(&UsageOut {
            tokens: u.tokens,
            cost_usd: u.cost_usd,
        })
    }

    async fn publish_conversation(
        &self,
        http: Parts<'_>,
        input: PublishConversationIn,
    ) -> CallToolResult {
        let p = ok_or_return!(self.citadel(http, &input.sandbox).await);
        let res = with_actor(
            &p.actor,
            self.mgr().publish_conversation(
                &input.sandbox,
                &input.role,
                &input.content,
                &input.run_id,
            ),
        )
        .await;
        match res {
            Ok(msg) => structured(&msg),
            Err(e) => cp_err(&e),
        }
    }

    async fn list_conversation(
        &self,
        http: Parts<'_>,
        input: ListConversationIn,
    ) -> CallToolResult {
        ok_or_return!(self.citadel(http, &input.sandbox).await);
        let limit = usize::try_from(input.limit).unwrap_or(0);
        match self
            .mgr()
            .conversation_history(&input.sandbox, input.after_id, limit)
        {
            Ok(messages) => structured(&Messages {
                messages: &messages,
            }),
            Err(e) => cp_err(&e),
        }
    }

    async fn snapshot_citadel(&self, http: Parts<'_>, input: SnapshotIn) -> CallToolResult {
        let p = ok_or_return!(self.citadel(http, &input.sandbox).await);
        match with_actor(&p.actor, self.mgr().snapshot(&input.sandbox, &input.name)).await {
            Ok(r) => structured(&r),
            Err(e) => cp_err(&e),
        }
    }

    async fn list_snapshots(&self, http: Parts<'_>, _: NoInput) -> CallToolResult {
        let p = ok_or_return!(self.identity(http).await);
        let mut refs = self.mgr().list_snapshots();
        if p.rbac() && !p.is_admin() {
            refs.retain(|r| self.mgr().snapshot_owner(&r.id).as_deref() == Some(&p.owner));
        }
        refs.sort_by(|a, b| (a.created, &a.id).cmp(&(b.created, &b.id)));
        structured(&Snapshots { snapshots: &refs })
    }

    async fn export_evidence(&self, http: Parts<'_>, input: SandboxIn) -> CallToolResult {
        ok_or_return!(self.citadel(http, &input.sandbox).await);
        match self.mgr().evidence(&input.sandbox, VERSION).await {
            Ok(doc) => structured(&doc),
            Err(e) => cp_err(&e),
        }
    }

    async fn verify_chronicle(&self, http: Parts<'_>, _: NoInput) -> CallToolResult {
        ok_or_return!(self.identity(http).await);
        match self.mgr().verify_ledger().await {
            Ok(()) => structured(&Verified {
                error: None,
                ok: true,
            }),
            Err(e) => structured(&Verified {
                error: Some(&e.to_string()),
                ok: false,
            }),
        }
    }

    async fn create_cohort(&self, http: Parts<'_>, input: CreateCohortIn) -> CallToolResult {
        let p = ok_or_return!(self.identity(http).await);
        if !p.can_launch(&input.profile) {
            return err_text(&format!(
                "principal {:?} is not allowed to launch charter {:?}",
                p.actor, input.profile
            ));
        }
        let res = with_actor(
            &p.actor,
            self.mgr()
                .create_fleet_for_identity(&input.profile, &p.owner, &p.actor),
        )
        .await;
        match res {
            Ok(v) => structured(&v),
            Err(e) => cp_err(&e),
        }
    }

    async fn list_cohorts(&self, http: Parts<'_>, _: NoInput) -> CallToolResult {
        let p = ok_or_return!(self.identity(http).await);
        let mut fleets = self.mgr().list_fleets();
        fleets.retain(|f| p.sees(&f.owner));
        fleets.sort_by(|a, b| (a.created, &a.id).cmp(&(b.created, &b.id)));
        structured(&Cohorts { cohorts: &fleets })
    }

    async fn list_tasks(&self, http: Parts<'_>, input: FleetIn) -> CallToolResult {
        ok_or_return!(self.cohort(http, &input.fleet).await);
        match self.mgr().list_tasks(&input.fleet) {
            Ok(tasks) => structured(&Tasks { tasks: &tasks }),
            Err(e) => cp_err(&e),
        }
    }

    async fn add_task(&self, http: Parts<'_>, input: AddTaskIn) -> CallToolResult {
        let p = ok_or_return!(self.cohort(http, &input.fleet).await);
        match with_actor(&p.actor, self.mgr().add_task(&input.fleet, &input.payload)).await {
            Ok(t) => structured(&t),
            Err(e) => cp_err(&e),
        }
    }

    async fn claim_task(&self, http: Parts<'_>, input: FleetIn) -> CallToolResult {
        let p = ok_or_return!(self.cohort(http, &input.fleet).await);
        let claimed = with_actor(
            &p.actor,
            self.mgr()
                .claim_task_with_context(&input.fleet, &p.actor, 0),
        )
        .await;
        match claimed {
            Ok(c) => structured(&Claimed {
                claimed: c.is_some(),
                context: c.as_ref().map(|c| &c.context).filter(|c| !c.is_empty()),
                task: c.as_ref().map(|c| &c.task),
            }),
            Err(e) => cp_err(&e),
        }
    }

    async fn heartbeat_task(&self, http: Parts<'_>, input: HeartbeatIn) -> CallToolResult {
        let p = ok_or_return!(self.cohort(http, &input.fleet).await);
        let res = with_actor(
            &p.actor,
            self.mgr()
                .heartbeat_task(&input.fleet, &input.task, &p.actor, &input.lease_token),
        )
        .await;
        match res {
            Ok(t) => structured(&OkTask { ok: true, task: &t }),
            Err(e) => cp_err(&e),
        }
    }

    async fn complete_task(&self, http: Parts<'_>, input: CompleteTaskIn) -> CallToolResult {
        let p = ok_or_return!(self.cohort(http, &input.fleet).await);
        let res = with_actor(
            &p.actor,
            self.mgr().complete_task(
                &input.fleet,
                &input.task,
                &p.actor,
                &input.lease_token,
                &input.result,
            ),
        )
        .await;
        match res {
            Ok(()) => structured(&TaskState {
                ok: true,
                state: "done",
                task: &input.task,
            }),
            Err(e) => cp_err(&e),
        }
    }

    async fn fail_task(&self, http: Parts<'_>, input: FailTaskIn) -> CallToolResult {
        let p = ok_or_return!(self.cohort(http, &input.fleet).await);
        let res = with_actor(
            &p.actor,
            self.mgr().fail_task(
                &input.fleet,
                &input.task,
                &p.actor,
                &input.lease_token,
                &input.error,
                input.requeue,
            ),
        )
        .await;
        match res {
            Ok(()) => structured(&TaskState {
                ok: true,
                state: if input.requeue {
                    "failed and requeued"
                } else {
                    "failed"
                },
                task: &input.task,
            }),
            Err(e) => cp_err(&e),
        }
    }

    async fn fork_citadel(&self, http: Parts<'_>, input: ForkCitadelIn) -> CallToolResult {
        let p = ok_or_return!(self.citadel(http, &input.sandbox).await);
        let target = if input.profile.trim().is_empty() {
            self.mgr()
                .sandbox(&input.sandbox)
                .map(|sb| sb.profile)
                .unwrap_or_default()
        } else {
            input.profile.trim().to_owned()
        };
        if !p.can_launch(&target) {
            return err_text(&format!(
                "principal {:?} is not allowed to launch charter {target:?}",
                p.actor
            ));
        }
        let opts = ForkOptions {
            profile: input.profile,
            admin: !p.rbac() || p.is_admin(),
            actor: p.actor.clone(),
            agent: input.agent,
            provider: input.provider,
            model: input.model,
            ..ForkOptions::default()
        };
        match with_actor(&p.actor, self.mgr().fork_citadel(&input.sandbox, opts)).await {
            Ok(sb) => structured(&ForkedOut {
                backend: &sb.backend,
                forked_from: &input.sandbox,
                id: &sb.id,
                image: &sb.image,
                isolation: sb.isolation.as_str(),
                profile: &sb.profile,
                status: &sb.status,
            }),
            Err(e) => cp_err(&e),
        }
    }

    async fn memory_put(&self, http: Parts<'_>, input: MemoryPutIn) -> CallToolResult {
        let p = ok_or_return!(self.cohort(http, &input.fleet).await);
        let put = MemoryPut {
            key: input.key,
            text: input.text,
            tags: input.tags,
            expected_version: input.expected_version,
        };
        match with_actor(&p.actor, self.mgr().memory_put(&input.fleet, put)).await {
            Ok(e) => structured(&e),
            Err(e) => cp_err(&e),
        }
    }

    async fn memory_get(&self, http: Parts<'_>, input: MemoryGetIn) -> CallToolResult {
        ok_or_return!(self.cohort(http, &input.fleet).await);
        match self.mgr().memory_get(&input.fleet, &input.key).await {
            Ok(Some(e)) => structured(&e),
            Ok(None) => err_text("memory entry not found"),
            Err(e) => cp_err(&e),
        }
    }

    async fn memory_search(&self, http: Parts<'_>, input: MemorySearchIn) -> CallToolResult {
        ok_or_return!(self.cohort(http, &input.fleet).await);
        let q = MemoryQuery {
            query: input.query,
            tags: input.tags,
            limit: usize::try_from(input.limit).unwrap_or(usize::MAX),
            max_bytes: usize::try_from(input.max_bytes).unwrap_or(usize::MAX),
        };
        match self.mgr().memory_search(&input.fleet, &q).await {
            Ok(entries) => structured(&Entries { entries: &entries }),
            Err(e) => cp_err(&e),
        }
    }

    async fn add_note(&self, http: Parts<'_>, input: AddNoteIn) -> CallToolResult {
        let p = ok_or_return!(self.cohort(http, &input.fleet).await);
        let res = with_actor(
            &p.actor,
            self.mgr()
                .add_task_note(&input.fleet, &input.task, &input.text),
        )
        .await;
        match res {
            Ok(t) => structured(&OkTask { ok: true, task: &t }),
            Err(e) => cp_err(&e),
        }
    }

    async fn set_brief(&self, http: Parts<'_>, input: SetBriefIn) -> CallToolResult {
        let p = ok_or_return!(self.cohort(http, &input.fleet).await);
        let agent = if input.agent.trim().is_empty() {
            p.actor.clone()
        } else {
            input.agent
        };
        let res = with_actor(
            &p.actor,
            self.mgr()
                .set_task_brief(&input.fleet, &input.task, &agent, &input.brief),
        )
        .await;
        match res {
            Ok(t) => structured(&OkTask { ok: true, task: &t }),
            Err(e) => cp_err(&e),
        }
    }

    async fn handoff(&self, http: Parts<'_>, input: HandoffIn) -> CallToolResult {
        let p = ok_or_return!(self.cohort(http, &input.fleet).await);
        let mgr = self.mgr();
        let res = if input.requeue {
            with_actor(
                &p.actor,
                mgr.fail_task_with_handoff(
                    &input.fleet,
                    &input.task,
                    &p.actor,
                    &input.lease_token,
                    "handed off",
                    true,
                    &input.note,
                ),
            )
            .await
        } else {
            with_actor(
                &p.actor,
                mgr.complete_task_with_handoff(
                    &input.fleet,
                    &input.task,
                    &p.actor,
                    &input.lease_token,
                    &input.result,
                    &input.note,
                ),
            )
            .await
        };
        match res {
            Ok(()) => structured(&TaskState {
                ok: true,
                state: if input.requeue { "pending" } else { "done" },
                task: &input.task,
            }),
            Err(e) => cp_err(&e),
        }
    }

    async fn add_child_task(&self, http: Parts<'_>, input: AddChildTaskIn) -> CallToolResult {
        let p = ok_or_return!(self.cohort(http, &input.fleet).await);
        let res = with_actor(
            &p.actor,
            self.mgr()
                .add_child_task(&input.fleet, &input.task, &input.payload),
        )
        .await;
        match res {
            Ok(t) => structured(&t),
            Err(e) => cp_err(&e),
        }
    }

    /// Resolves the caller against a schedule target (exactly one of a
    /// Citadel and a Cohort).
    async fn schedule_target(
        &self,
        http: Parts<'_>,
        sandbox: &str,
        fleet: &str,
    ) -> Result<crate::auth::Identity, CallToolResult> {
        match (sandbox.trim(), fleet.trim()) {
            ("", "") => self.identity(http).await,
            (s, "") => self.citadel(http, s).await,
            ("", f) => self.cohort(http, f).await,
            _ => Err(err_text("set either sandbox or fleet, not both")),
        }
    }

    async fn schedule_create(&self, http: Parts<'_>, input: ScheduleCreateIn) -> CallToolResult {
        if input.sandbox.trim().is_empty() == input.fleet.trim().is_empty() {
            return err_text("set exactly one of sandbox and fleet");
        }
        let p = ok_or_return!(
            self.schedule_target(http, &input.sandbox, &input.fleet)
                .await
        );
        let spec = ScheduleSpec {
            cohort_id: input.fleet,
            citadel_id: input.sandbox,
            cron: input.cron,
            every: input.every,
            command: input.command,
            prompt: input.prompt,
            agent: input.agent,
            model: input.model,
            precheck: input.precheck,
        };
        match with_actor(&p.actor, self.mgr().create_self_schedule(spec)).await {
            Ok(s) => structured(&s),
            Err(e) => cp_err(&e),
        }
    }

    async fn schedule_list(&self, http: Parts<'_>, input: ScheduleListIn) -> CallToolResult {
        let p = ok_or_return!(
            self.schedule_target(http, &input.sandbox, &input.fleet)
                .await
        );
        let mut all = if input.sandbox.trim().is_empty() && input.fleet.trim().is_empty() {
            self.mgr().list_schedules()
        } else {
            self.mgr()
                .schedules_for(input.fleet.trim(), input.sandbox.trim())
        };
        all.retain(|s| p.sees(&s.owner));
        structured(&SchedulesOut { schedules: &all })
    }

    async fn schedule_delete(&self, http: Parts<'_>, input: ScheduleDeleteIn) -> CallToolResult {
        let p = ok_or_return!(self.identity(http).await);
        let Some(s) = self
            .mgr()
            .schedule(&input.schedule)
            .filter(|s| p.sees(&s.owner))
        else {
            return err_text("schedule not found");
        };
        if !s.self_service && p.rbac() && !p.is_admin() {
            return err_text(
                "agents are not allowed to delete schedules an operator created; ask an administrator",
            );
        }
        match with_actor(&p.actor, self.mgr().delete_schedule(&input.schedule)).await {
            Ok(_) => structured(&DeletedSchedule {
                ok: true,
                schedule: &input.schedule,
            }),
            Err(e) => cp_err(&e),
        }
    }

    async fn kill_cohort(&self, http: Parts<'_>, input: FleetIn) -> CallToolResult {
        let p = ok_or_return!(self.cohort(http, &input.fleet).await);
        match with_actor(&p.actor, self.mgr().kill_fleet(&input.fleet)).await {
            Ok(()) => structured(&KilledCohort {
                cohort: &input.fleet,
                ok: true,
            }),
            Err(e) => cp_err(&e),
        }
    }
}

impl ServerHandler for McpServer {
    fn get_info(&self) -> ServerConfig {
        let mut info = ServerConfig::new(ServerCapabilities::builder().enable_tools().build());
        info.server_info = Implementation::new(SERVER_NAME, VERSION);
        info
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        Ok(ListToolsResult {
            tools: tools::tool_definitions().to_vec(),
            ..Default::default()
        })
    }

    fn get_tool(&self, name: &str) -> Option<Tool> {
        tools::tool_definitions()
            .iter()
            .find(|t| t.name == name)
            .cloned()
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        let http = context.extensions.get::<http::request::Parts>();
        let args = Value::Object(request.arguments.unwrap_or_default());
        self.dispatch(&request.name, args, http)
            .await
            .map(Into::into)
    }
}

/// Serves MCP over this process's stdin/stdout until the client
/// disconnects. The stdio caller comes from `config` (see
/// [`McpConfig::from_env`]).
pub async fn serve_stdio(
    manager: Arc<Manager>,
    authz: Option<Arc<Store>>,
    config: McpConfig,
) -> Result<(), Error> {
    let server = McpServer::new(manager, authz, &config).await;
    let running = server
        .serve(rmcp::transport::stdio())
        .await
        .map_err(|e| Error::Service(e.to_string()))?;
    running
        .waiting()
        .await
        .map(|_| ())
        .map_err(|e| Error::Service(e.to_string()))
}
