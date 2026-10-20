/**
 * A dependency-light TypeScript client for the Rune Box control plane.
 *
 * Uses the global `fetch` (Node 18+, Deno, Bun, browsers) so the core client
 * has **no runtime dependencies**. It mirrors the Rune Box REST contract 1:1
 * and translates the governance outcomes into typed errors:
 *
 * - HTTP `403` -> {@link RunewardDenied} (policy) or
 *   {@link RunewardAuthorizationError} (role / resource access)
 * - HTTP `202` -> {@link RunewardApprovalRequired} (carries the `approvalId`)
 * - any other refused call (the body carries a `refusal` object) ->
 *   {@link RefusedError}
 *
 * Any other non-2xx response becomes a {@link RunewardError}. Every error
 * exposes `requestId` (the server's `X-Request-Id`) and, when the server
 * proved the call never ran, the parsed {@link Refusal}.
 */

/** The isolation tier a sandbox actually runs behind. */
export type IsolationTier = "process" | "container" | "kernel" | "vm";

/** Where a sandbox's isolation tier comes from, and the Charter floor (on `getSandbox`). */
export interface IsolationTierEvidence {
  tier: IsolationTier | string;
  backend: string;
  /** Always `backend`: backends report the tier they delivered. */
  source: string;
  /** The Charter's `[isolation] minimum` (empty when unset); only on `getSandbox`. */
  floor?: string;
  meets_floor?: boolean;
}

/** What the in-sandbox supervisor reported enforcing. */
export interface IsolationEvidence {
  /** `enforced` or `absent`. */
  supervisor: string;
  required: boolean;
  landlock_requested: string;
  landlock: string;
  landlock_abi: number;
  seccomp: boolean;
  no_new_privs: boolean;
  uid?: number | null;
  gid?: number | null;
  capabilities_dropped: boolean;
  protected_by_landlock: boolean;
}

/** Metadata returned when a sandbox is created or fetched. */
export interface Sandbox {
  id: string;
  profile: string;
  backend: string;
  image: string;
  /** `running`, `sleeping`, `waking`, ... */
  status: string;
  /** The isolation tier the sandbox actually runs behind. */
  isolation?: IsolationTier | string;
  isolation_evidence?: IsolationTierEvidence;
  /** Supervisor enforcement evidence (Charters run under the in-sandbox supervisor). */
  enforcement?: IsolationEvidence;
  owner?: string;
  capabilities?: string[];
  ide?: boolean;
  forked_from?: string;
  workspace?: WorkspaceStatus;
  usage?: Usage;
  limits?: Record<string, unknown>;
}

/**
 * One egress decision. The first five fields are always present; the broker
 * fields only when the request broker decided.
 */
export interface PerimeterDecision {
  timestamp: string;
  host: string;
  ip: string;
  allow: boolean;
  reason: string;
  endpoint?: string;
  /** `tcp`, `rest`, `websocket`, `mcp` or `json-rpc`. */
  protocol?: string;
  method?: string;
  path?: string;
  tool?: string;
  /** `read`, `write` or `irreversible`. */
  effect?: string;
  rule?: string;
  verdict?: "allow" | "deny" | "require-approval";
  reason_code?: string;
  /** The attached credential's name (never its value). */
  credential?: string;
  binaries?: string[];
}

/** A persistent Citadel's workspace status. */
export interface WorkspaceStatus {
  citadel_id: string;
  state: string;
  idle_timeout_secs: number;
  idle_secs: number;
  slept_at?: string;
  woke_at?: string;
  forked_from?: string;
}

export interface ForkOptions {
  profile?: string;
  runId?: string;
  agent?: string;
  provider?: string;
  model?: string;
  nanoCpus?: number;
  memoryBytes?: number;
}

/** An agent session (one transcript, one turn at a time). */
export interface AgentSession {
  id: string;
  citadel_id: string;
  status?: string;
  turn?: number;
  [key: string]: unknown;
}

export interface StartAgentSessionOptions {
  agent?: string;
  model?: string;
  cohortId?: string;
  taskId?: string;
}

export interface Schedule {
  id: string;
  owner?: string;
  actor?: string;
  cohort_id?: string;
  citadel_id?: string;
  cron?: string;
  every?: string;
  command: string[];
  prompt?: string;
  agent?: string;
  model?: string;
  precheck?: string[];
  self_service?: boolean;
  created_at?: string;
  next_fire_at?: string;
  last_fired_at?: string;
  /** `started`, `skipped_precheck`, `skipped_busy`, `denied` or `error`. */
  last_outcome?: string;
  last_reason?: string;
  last_session_id?: string;
  fire_count?: number;
}

/** Target and timing of a new schedule: exactly one of `citadel`/`cohort` and of `cron`/`every`. */
export interface CreateScheduleOptions {
  citadel?: string;
  cohort?: string;
  /** 5-field cron expression, UTC. */
  cron?: string;
  /** Fixed interval such as `"30m"` (at least `1m`). */
  every?: string;
  prompt?: string;
  agent?: string;
  model?: string;
  precheck?: string[];
}

export interface ScheduleFiring {
  schedule_id: string;
  outcome: string;
  citadel_id?: string;
  session_id?: string;
  reason?: string;
}

export interface MemoryEntry {
  key: string;
  text: string;
  author: string;
  tags?: string[];
  created_at: string;
  updated_at: string;
  version: number;
}

export interface MemorySearchOptions {
  tags?: string[];
  limit?: number;
  maxBytes?: number;
}

/** The standard "nothing ran" object the server attaches as `refusal`. */
export interface Refusal {
  refused: boolean;
  /** `request`, `permission`, `policy`, `approval`, `budget`, `isolation`, `environment`, `capacity`, `shed` or `protocol`. */
  reason: string;
  /** True only when re-sending the identical request is safe and may succeed later. */
  retryable: boolean;
  request_id: string;
  message: string;
}

/** Parses `payload.refusal`; `undefined` when absent or malformed. */
export function parseRefusal(payload: unknown): Refusal | undefined {
  if (!payload || typeof payload !== "object") return undefined;
  const raw = (payload as Record<string, unknown>).refusal;
  if (!raw || typeof raw !== "object") return undefined;
  const r = raw as Record<string, unknown>;
  return {
    refused: r.refused === undefined ? true : Boolean(r.refused),
    reason: String(r.reason ?? ""),
    retryable: Boolean(r.retryable),
    request_id: String(r.request_id ?? ""),
    message: String(r.message ?? ""),
  };
}

/** A profile advertised by the control plane. */
export interface Profile {
  name: string;
  host: string;
  egress: string;
}

/** The result of a governed execution (shell / python / node). */
export interface ExecResult {
  verdict: "allow" | "deny" | "require-approval";
  exit_code: number;
  stdout: string;
  stderr: string;
  duration_ms: number;
}

/** A pending human-in-the-loop approval request. */
export interface Approval {
  id: string;
  sandbox: string;
  tool: string;
  action: string;
  reason: string;
  created: string;
}

export interface Principal {
  name: string;
	tenant?: string;
  admin: boolean;
  can_approve: boolean;
  can_launch: boolean;
  allowed_profiles?: string[];
  approval_profiles?: string[];
}

export interface Whoami { authenticated: boolean; rbac: boolean; principal: Principal; }
export interface Usage { tokens: number; cost_usd: number; }
export interface Cohort { id: string; profile: string; owner?: string; sandboxes: string[]; stats: Record<string, number>; created: string; }
export interface CohortTask { id: string; payload: string; state: string; owner?: string; attempts: number; result?: string; error?: string; lease_token?: string; }
export interface Snapshot { id: string; profile: string; [key: string]: unknown; }
export interface Run { id: string; parent_run_id?: string; citadel_id: string; tenant?: string; actor?: string; charter: string; agent?: string; provider?: string; model?: string; status: string; created_at: string; finished_at?: string; error?: string; }
export interface ConversationMessage { id: number; sandbox: string; role: "user" | "assistant" | "tool" | "system"; author: string; content: string; run_id?: string; created_at: string; redacted?: boolean; }
export interface CreateSandboxOptions {
  copyFrom?: string;
  parentCitadel?: string;
  runId?: string;
  agent?: string;
  provider?: string;
  model?: string;
}

/**
 * Base error for any non-success response from the control plane.
 * `requestId` correlates it with the server's logs; `refusal` is set when the
 * server proved the call never ran.
 */
export class RunewardError extends Error {
  readonly status?: number;
  readonly payload: Record<string, unknown>;
  readonly refusal?: Refusal;
  readonly code?: string;
  readonly requestId: string;

  constructor(message: string, status?: number, payload: Record<string, unknown> = {}, requestId = "") {
    super(message);
    this.name = "RunewardError";
    this.status = status;
    this.payload = payload;
    this.refusal = parseRefusal(payload);
    this.code = typeof payload.code === "string" ? payload.code : undefined;
    this.requestId = requestId || this.refusal?.request_id || String(payload.request_id ?? "");
  }
}

/**
 * Thrown when the server refused a call before it ran and no more specific
 * governance error applies (bad request, unknown resource, `session_busy`,
 * `version_conflict`, rate limit, budget, isolation floor, ...). Policy
 * denials, authorization failures and approval gates keep their own error
 * types, which also carry `refusal`.
 */
export class RefusedError extends RunewardError {
  readonly reason: string;
  readonly retryable: boolean;
  /** The server's refusal message (unformatted). */
  readonly refusalMessage: string;

  constructor(
    reason: string,
    retryable: boolean,
    requestId: string,
    message: string,
    status?: number,
    payload: Record<string, unknown> = {},
  ) {
    super(`runeward refused the call (${reason})${message ? `: ${message}` : ""}`, status, payload, requestId);
    this.name = "RefusedError";
    this.reason = reason;
    this.retryable = retryable;
    this.refusalMessage = message;
  }
}

/**
 * Thrown when policy denies an action (HTTP 403). A denial is a policy
 * decision, not a transient failure — do not retry the identical action.
 */
export class RunewardDenied extends RunewardError {
  readonly reason: string;

  constructor(reason: string, payload: Record<string, unknown> = {}, requestId = "") {
    super(`runeward denied action: ${reason}`, 403, payload, requestId);
    this.name = "RunewardDenied";
    this.reason = reason;
  }
}

/** Thrown when the caller is authenticated but lacks resource or role access. */
export class RunewardAuthorizationError extends RunewardError {
	constructor(message: string, payload: Record<string, unknown> = {}, requestId = "") {
		super(`runeward authorization denied: ${message}`, 403, payload, requestId);
		this.name = "RunewardAuthorizationError";
	}
}

/**
 * Thrown when an action needs human approval (HTTP 202). Pause and surface the
 * `approvalId` to a human rather than working around the gate.
 */
export class RunewardApprovalRequired extends RunewardError {
  readonly approvalId: string;
  readonly reason: string;

  constructor(approvalId: string, reason = "", payload: Record<string, unknown> = {}, requestId = "") {
    super(`runeward requires approval (id=${approvalId})${reason ? `: ${reason}` : ""}`, 202, payload, requestId);
    this.name = "RunewardApprovalRequired";
    this.approvalId = approvalId;
    this.reason = reason;
  }
}

/** Options for constructing a {@link RunewardClient}. */
export interface RunewardClientOptions {
  /** Control-plane base URL. Defaults to `http://localhost:8080`. */
  baseUrl?: string;
  /** Optional bearer token if the control plane requires auth. */
  token?: string;
  /** Per-request timeout in milliseconds. Defaults to 60_000. */
  timeoutMs?: number;
  /** Allow insecure `http://` to non-loopback hosts. */
  allowInsecure?: boolean;
}

/**
 * Thin, promise-based client over the Rune Box REST control plane.
 *
 * @example
 * ```ts
 * const rw = new RunewardClient({ baseUrl: "http://localhost:8080" });
 * const sbx = await rw.createSandbox("dev");
 * const out = await rw.shell(sbx.id, ["echo", "hello"]);
 * console.log(out.stdout); // "hello\n"
 * await rw.killSandbox(sbx.id);
 * ```
 */
export class RunewardClient {
  private readonly baseUrl: string;
  private readonly token?: string;
  private readonly timeoutMs: number;
  /** `X-Request-Id` of the most recent response (success or error). */
  lastRequestId = "";

  constructor(options: RunewardClientOptions = {}) {
    // Normalize so path joins never double up slashes.
    this.baseUrl = this.normalizeBaseUrl(options.baseUrl ?? "http://localhost:8080");
    this.validateTransport(this.baseUrl, options.allowInsecure ?? false);
    const env = (globalThis as { process?: { env?: Record<string, string | undefined> } }).process?.env;
    this.token = options.token ?? env?.RUNEWARD_API_TOKEN;
    this.timeoutMs = options.timeoutMs ?? 60_000;
  }

  private normalizeBaseUrl(baseUrl: string): string {
    const trimmed = baseUrl.trim();
    const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
    return withScheme.replace(/\/+$/, "");
  }

  private isLoopbackHost(hostname: string): boolean {
    const host = hostname.toLowerCase();
    return host === "localhost" || host === "127.0.0.1" || host === "::1";
  }

  private envAllowsInsecure(): boolean {
    const env = (globalThis as { process?: { env?: Record<string, string | undefined> } }).process?.env;
    const raw = env?.RUNEWARD_ALLOW_INSECURE_HTTP;
    if (!raw) return false;
    const value = raw.trim().toLowerCase();
    return value === "1" || value === "true" || value === "yes" || value === "on";
  }

  private validateTransport(baseUrl: string, allowInsecure: boolean): void {
    const parsed = new URL(baseUrl);
    if (parsed.protocol !== "http:") return;
    if (this.isLoopbackHost(parsed.hostname)) return;
    if (allowInsecure || this.envAllowsInsecure()) {
      console.warn(`runeward client using insecure HTTP transport to non-loopback host: ${baseUrl}`);
      return;
    }
    throw new Error(
      "refusing insecure http:// base URL to non-loopback host; use https://, set allowInsecure: true, or set RUNEWARD_ALLOW_INSECURE_HTTP=1",
    );
  }

  private segment(value: string): string {
    return encodeURIComponent(value);
  }

  /** A `?query` string of the params that are set (not undefined, "" or 0). */
  private query(params: Record<string, string | number | undefined>): string {
    const kept = Object.entries(params).filter(([, v]) => v !== undefined && v !== "" && v !== 0);
    if (kept.length === 0) return "";
    return `?${new URLSearchParams(kept.map(([k, v]) => [k, String(v)])).toString()}`;
  }

  private taskPath(cohort: string, task: string): string {
    return `/v1/cohorts/${this.segment(cohort)}/tasks/${this.segment(task)}`;
  }

  /** Copies the set (truthy) fields into `body`. */
  private setFields(body: Record<string, unknown>, fields: Record<string, unknown>): Record<string, unknown> {
    for (const [k, v] of Object.entries(fields)) if (v) body[k] = v;
    return body;
  }

  // -- low-level request plumbing --------------------------------------

  private async request<T>(method: string, path: string, body?: unknown, accepted = false): Promise<T> {
    const url = `${this.baseUrl}${path}`;
    const headers: Record<string, string> = { Accept: "application/json" };
    if (body !== undefined) headers["Content-Type"] = "application/json";
    if (this.token) headers["Authorization"] = `Bearer ${this.token}`;

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    let resp: Response;
    try {
      resp = await fetch(url, {
        method,
        headers,
        body: body !== undefined ? JSON.stringify(body) : undefined,
        signal: controller.signal,
      });
    } catch (err) {
      throw new RunewardError(`could not reach runeward at ${url}: ${(err as Error).message}`);
    } finally {
      clearTimeout(timer);
    }

    this.lastRequestId = resp.headers?.get?.("x-request-id") ?? "";
    const payload = await this.safeJson(resp);

    // 202 is a "successful" status to fetch but means an approval gate here,
    // except on routes that answer 202 Accepted for queued work (agent
    // sessions and turns); there only an explicit verdict is a gate.
    const gate = resp.status === 202 && (!accepted || "verdict" in payload || "refusal" in payload);
    if (!resp.ok || gate) {
      this.raiseForStatus(resp.status, payload, this.lastRequestId);
    }
    return payload as T;
  }

  private async safeJson(resp: Response): Promise<Record<string, unknown>> {
    const text = await resp.text();
    if (!text) return {};
    try {
      return JSON.parse(text) as Record<string, unknown>;
    } catch {
      return { raw: text };
    }
  }

  private raiseForStatus(status: number, payload: Record<string, unknown>, requestId = ""): never {
    if (payload.code === "authz_denied") {
      throw new RunewardAuthorizationError(String(payload.error ?? "not authorized"), payload, requestId);
    }
    if (payload.verdict === "deny" || (status === 403 && payload.code === undefined)) {
      throw new RunewardDenied(String(payload.reason ?? "denied by policy"), payload, requestId);
    }
    if (status === 202 || payload.verdict === "require-approval") {
      throw new RunewardApprovalRequired(
        String(payload.approval_id ?? ""),
        String(payload.reason ?? ""),
        payload,
        requestId,
      );
    }
    const refusal = parseRefusal(payload);
    if (refusal) {
      throw new RefusedError(
        refusal.reason,
        refusal.retryable,
        requestId || refusal.request_id,
        refusal.message || String(payload.error ?? ""),
        status,
        payload,
      );
    }
    throw new RunewardError(`runeward returned HTTP ${status}: ${JSON.stringify(payload)}`, status, payload, requestId);
  }

  // -- health & discovery ----------------------------------------------

  /** `GET /healthz` — liveness check. */
  healthz(): Promise<unknown> {
    return this.request("GET", "/healthz");
  }

  whoami(): Promise<Whoami> { return this.request("GET", "/v1/whoami"); }

  readiness(profile: string): Promise<Record<string, unknown>> {
    return this.request("GET", `/v1/readiness?profile=${this.segment(profile)}`);
  }

  simulatePolicy(profileName: string, actions: Array<Record<string, unknown>>): Promise<Record<string, unknown>> {
    return this.request("POST", "/v1/policy/simulate", { profile_name: profileName, actions });
  }

  /** `GET /v1/charters` — reachable profiles. */
  async listProfiles(): Promise<Profile[]> {
    const res = await this.request<{ profiles: Profile[] }>("GET", "/v1/charters");
    return res.profiles ?? [];
  }

  async listRuns(): Promise<Run[]> {
    const data = await this.request<{ runs?: Run[] }>("GET", "/v1/runs");
    return data.runs ?? [];
  }

  getRun(runId: string): Promise<Run> { return this.request("GET", `/v1/runs/${this.segment(runId)}`); }

  // -- sandbox lifecycle -----------------------------------------------

  /** `POST /v1/citadels` — provision a sandbox from `profile`; `isolation` names the tier it runs behind. */
  createSandbox(profile: string, options: CreateSandboxOptions = {}): Promise<Sandbox> {
    return this.request<Sandbox>("POST", "/v1/citadels", {
      profile,
      copy_from: options.copyFrom,
      parent_citadel: options.parentCitadel,
      run_id: options.runId,
      agent: options.agent,
      provider: options.provider,
      model: options.model,
    });
  }

  /** `GET /v1/citadels`. */
  async listSandboxes(): Promise<Sandbox[]> {
    const res = await this.request<{ sandboxes: Sandbox[] }>("GET", "/v1/citadels");
    return res.sandboxes ?? [];
  }

  /** `GET /v1/citadels/{id}`. */
  getSandbox(sandbox: string): Promise<Sandbox> {
    return this.request<Sandbox>("GET", `/v1/citadels/${this.segment(sandbox)}`);
  }

  /** `DELETE /v1/citadels/{id}` — tear the sandbox down. */
  killSandbox(sandbox: string): Promise<unknown> {
    return this.request("DELETE", `/v1/citadels/${this.segment(sandbox)}`);
  }

  // -- persistent workspaces --------------------------------------------

  /**
   * `POST /v1/citadels/{id}/fork` — copy the workspace into a new, independent
   * Citadel. A weaker isolation floor, broader egress or larger resources need
   * an administrator.
   */
  forkCitadel(sandbox: string, options: ForkOptions = {}): Promise<Sandbox> {
    const body = this.setFields({}, {
      profile: options.profile,
      run_id: options.runId,
      agent: options.agent,
      provider: options.provider,
      model: options.model,
      nano_cpus: options.nanoCpus,
      memory_bytes: options.memoryBytes,
    });
    return this.request("POST", `/v1/citadels/${this.segment(sandbox)}/fork`, body);
  }

  /** `POST /v1/citadels/{id}/sleep`; throws {@link RefusedError} (`citadel_busy`) while work is active. */
  sleepCitadel(sandbox: string): Promise<{ ok: boolean; slept: boolean }> {
    return this.request("POST", `/v1/citadels/${this.segment(sandbox)}/sleep`);
  }

  /** `POST /v1/citadels/{id}/wake` (any governed call also wakes it). */
  wakeCitadel(sandbox: string): Promise<{ ok: boolean }> {
    return this.request("POST", `/v1/citadels/${this.segment(sandbox)}/wake`);
  }

  /** `GET /v1/citadels/{id}/workspace/status` (persistent Citadels only). */
  workspaceStatus(sandbox: string): Promise<WorkspaceStatus> {
    return this.request("GET", `/v1/citadels/${this.segment(sandbox)}/workspace/status`);
  }

  // -- agent sessions ---------------------------------------------------

  /** `POST /v1/citadels/{id}/agent-sessions` — start an agent command. */
  startAgentSession(sandbox: string, command: string[], options: StartAgentSessionOptions = {}): Promise<AgentSession> {
    const body = this.setFields({ command }, {
      agent: options.agent,
      model: options.model,
      cohort_id: options.cohortId,
      task_id: options.taskId,
    });
    return this.request("POST", `/v1/citadels/${this.segment(sandbox)}/agent-sessions`, body, true);
  }

  async listAgentSessions(cohortId = ""): Promise<AgentSession[]> {
    const r = await this.request<{ sessions?: AgentSession[] }>("GET", `/v1/agent-sessions${this.query({ cohort_id: cohortId })}`);
    return r.sessions ?? [];
  }

  getAgentSession(session: string): Promise<AgentSession> {
    return this.request("GET", `/v1/agent-sessions/${this.segment(session)}`);
  }

  /** `GET /v1/agent-sessions/{id}/events?after=<seq>`; pass the last `seq` seen to resume. */
  agentSessionEvents(session: string, after = 0): Promise<{ session: AgentSession; events: Array<Record<string, unknown>> }> {
    return this.request("GET", `/v1/agent-sessions/${this.segment(session)}/events${this.query({ after })}`);
  }

  /** `POST /v1/agent-sessions/{id}/turns`; throws {@link RefusedError} (`session_busy`) while a turn is active. */
  agentTurn(session: string, command: string[], model = ""): Promise<AgentSession> {
    const body = this.setFields({ command }, { model });
    return this.request("POST", `/v1/agent-sessions/${this.segment(session)}/turns`, body, true);
  }

  /** `POST /v1/agent-sessions/{id}/cancel` — stop the active turn (does not rewind). */
  async cancelAgentTurn(session: string): Promise<boolean> {
    const r = await this.request<{ canceled?: boolean }>("POST", `/v1/agent-sessions/${this.segment(session)}/cancel`, {});
    return Boolean(r.canceled);
  }

  // -- schedules --------------------------------------------------------

  /** Every visible schedule, or those of one Citadel or Cohort. */
  async listSchedules(target: { citadel?: string; cohort?: string } = {}): Promise<Schedule[]> {
    if (target.citadel && target.cohort) throw new Error("pass at most one of citadel and cohort");
    const path = target.citadel
      ? `/v1/citadels/${this.segment(target.citadel)}/schedules`
      : target.cohort
        ? `/v1/cohorts/${this.segment(target.cohort)}/schedules`
        : "/v1/schedules";
    const r = await this.request<{ schedules?: Schedule[] }>("GET", path);
    return r.schedules ?? [];
  }

  /** Schedule an agent run on a Citadel or Cohort, on a UTC `cron` or a fixed `every` interval. */
  createSchedule(command: string[], options: CreateScheduleOptions): Promise<Schedule> {
    if (Boolean(options.citadel) === Boolean(options.cohort)) throw new Error("pass exactly one of citadel and cohort");
    if (Boolean(options.cron) === Boolean(options.every)) throw new Error("pass exactly one of cron and every");
    const body = this.setFields({ command }, {
      cron: options.cron,
      every: options.every,
      prompt: options.prompt,
      agent: options.agent,
      model: options.model,
      precheck: options.precheck && options.precheck.length ? options.precheck : undefined,
    });
    const path = options.citadel
      ? `/v1/citadels/${this.segment(options.citadel)}/schedules`
      : `/v1/cohorts/${this.segment(options.cohort as string)}/schedules`;
    return this.request("POST", path, body);
  }

  getSchedule(id: string): Promise<Schedule> { return this.request("GET", `/v1/schedules/${this.segment(id)}`); }
  deleteSchedule(id: string): Promise<unknown> { return this.request("DELETE", `/v1/schedules/${this.segment(id)}`); }
  /** Fire a schedule now (policy, precheck and budgets still apply). */
  runSchedule(id: string): Promise<ScheduleFiring> { return this.request("POST", `/v1/schedules/${this.segment(id)}/run`); }

  // -- execution -------------------------------------------------------

  /**
   * `POST .../shell/exec` — run `command` (an argv array) in the sandbox.
   * An `allow` verdict with a non-zero `exit_code` is a normal program error,
   * not a policy denial.
   */
  shell(sandbox: string, command: string[], workdir = ""): Promise<ExecResult> {
    return this.request<ExecResult>("POST", `/v1/citadels/${this.segment(sandbox)}/shell/exec`, { command, workdir });
  }

  /** `POST .../code/python` — run a Python snippet in the sandbox. */
  python(sandbox: string, code: string): Promise<ExecResult> {
    return this.request<ExecResult>("POST", `/v1/citadels/${this.segment(sandbox)}/code/python`, { code });
  }

  /** `POST .../code/node` — run a Node.js snippet in the sandbox. */
  node(sandbox: string, code: string): Promise<ExecResult> {
    return this.request<ExecResult>("POST", `/v1/citadels/${this.segment(sandbox)}/code/node`, { code });
  }

  browser(sandbox: string, url: string, mode = "text"): Promise<ExecResult> {
    return this.request("POST", `/v1/citadels/${this.segment(sandbox)}/browser`, { url, mode });
  }

  async openBrowser(sandbox: string): Promise<string> {
    const res = await this.request<{ session_id: string }>("POST", `/v1/citadels/${this.segment(sandbox)}/browser/sessions`);
    return res.session_id;
  }

  browserAct(sandbox: string, session: string, action: Record<string, unknown>): Promise<ExecResult> {
    return this.request("POST", `/v1/citadels/${this.segment(sandbox)}/browser/sessions/${this.segment(session)}/act`, action);
  }

  closeBrowser(sandbox: string, session: string): Promise<unknown> {
    return this.request("DELETE", `/v1/citadels/${this.segment(sandbox)}/browser/sessions/${this.segment(session)}`);
  }

  reportUsage(sandbox: string, tokens: number, costUsd: number): Promise<Usage> {
    return this.request("POST", `/v1/citadels/${this.segment(sandbox)}/usage`, { tokens, cost_usd: costUsd });
  }

  publishConversation(sandbox: string, role: ConversationMessage["role"], content: string, runId = ""): Promise<ConversationMessage> {
    return this.request("POST", `/v1/citadels/${this.segment(sandbox)}/conversation`, { role, content, run_id: runId });
  }

  async listConversation(sandbox: string, afterId = 0, limit = 500): Promise<ConversationMessage[]> {
    const path = `/v1/citadels/${this.segment(sandbox)}/conversation?after_id=${afterId}&limit=${limit}`;
    const result = await this.request<{ messages: ConversationMessage[] }>("GET", path);
    return result.messages ?? [];
  }

  /** Egress decisions; broker decisions add endpoint, protocol, method, path, tool, effect, verdict, reason_code and credential. */
  async perimeter(sandbox: string): Promise<PerimeterDecision[]> {
    const res = await this.request<{ decisions: PerimeterDecision[] }>("GET", `/v1/citadels/${this.segment(sandbox)}/perimeter`);
    return res.decisions ?? [];
  }

  // -- files -----------------------------------------------------------

  /** `POST .../file/read` — return the file's content. */
  async readFile(sandbox: string, path: string): Promise<string> {
    const res = await this.request<{ content: string }>("POST", `/v1/citadels/${this.segment(sandbox)}/file/read`, { path });
    return res.content ?? "";
  }

  /** `POST .../file/write` — write `content`; return the number of bytes written. */
  async writeFile(sandbox: string, path: string, content: string): Promise<number> {
    const res = await this.request<{ bytes: number }>("POST", `/v1/citadels/${this.segment(sandbox)}/file/write`, { path, content });
    return res.bytes ?? 0;
  }

  /** `POST .../file/list` — list a directory; return the raw output. */
  async listFiles(sandbox: string, path: string): Promise<string> {
    const res = await this.request<{ output: string }>("POST", `/v1/citadels/${this.segment(sandbox)}/file/list`, { path });
    return res.output ?? "";
  }

  /** `POST .../file/search` — search for `query` under `path`. */
  async searchFiles(sandbox: string, query: string, path: string): Promise<string> {
    const res = await this.request<{ output: string }>("POST", `/v1/citadels/${this.segment(sandbox)}/file/search`, { query, path });
    return res.output ?? "";
  }

  // -- audit -----------------------------------------------------------

  /** `GET .../chronicle` — this sandbox's ledger events. */
  async audit(sandbox: string): Promise<Array<Record<string, unknown>>> {
    const res = await this.request<{ events: Array<Record<string, unknown>> }>(
      "GET",
      `/v1/citadels/${this.segment(sandbox)}/chronicle`,
    );
    return res.events ?? [];
  }

  /** `GET /v1/chronicle/verify` — verify the ledger hash chain. */
  async verifyAudit(): Promise<boolean> {
    const res = await this.request<{ ok: boolean }>("GET", "/v1/chronicle/verify");
    return Boolean(res.ok);
  }

  exportEvidence(sandbox: string): Promise<Record<string, unknown>> {
    return this.request("GET", `/v1/citadels/${this.segment(sandbox)}/evidence`);
  }

  async createCohort(profile: string): Promise<Cohort> { return this.request("POST", "/v1/cohorts", { profile }); }
  async listCohorts(): Promise<Cohort[]> { const r = await this.request<{ fleets: Cohort[] }>("GET", "/v1/cohorts"); return r.fleets ?? []; }
  getCohort(id: string): Promise<Cohort> { return this.request("GET", `/v1/cohorts/${this.segment(id)}`); }
  killCohort(id: string): Promise<unknown> { return this.request("DELETE", `/v1/cohorts/${this.segment(id)}`); }
  async listTasks(id: string): Promise<CohortTask[]> { const r = await this.request<{ tasks: CohortTask[] }>("GET", `/v1/cohorts/${this.segment(id)}/tasks`); return r.tasks ?? []; }
  addTask(id: string, payload: string): Promise<CohortTask> { return this.request("POST", `/v1/cohorts/${this.segment(id)}/tasks`, { payload }); }
  /** Claim the next task; `context: true` also returns handoff notes, brief, parent and ranked memory. */
  claimTask(id: string, owner = "", options: { context?: boolean; memoryBytes?: number } = {}): Promise<{ claimed: boolean; task?: CohortTask; context?: Record<string, unknown> }> {
    const body = this.setFields({ owner }, { context: options.context, memory_bytes: options.memoryBytes });
    return this.request("POST", `/v1/cohorts/${this.segment(id)}/claim`, body);
  }
  heartbeatTask(id: string, task: string, leaseToken: string, owner = ""): Promise<unknown> { return this.request("POST", `/v1/cohorts/${this.segment(id)}/tasks/${this.segment(task)}/heartbeat`, { owner, lease_token: leaseToken }); }
  /** Complete a claimed task; `handoff` leaves a note for whoever picks up next. */
  completeTask(id: string, task: string, leaseToken: string, result = "", owner = "", handoff = ""): Promise<unknown> {
    const body = this.setFields({ owner, lease_token: leaseToken, result }, { handoff });
    return this.request("POST", `${this.taskPath(id, task)}/complete`, body);
  }
  failTask(id: string, task: string, leaseToken: string, error: string, requeue = false, owner = "", handoff = ""): Promise<unknown> {
    const body = this.setFields({ owner, lease_token: leaseToken, error, requeue }, { handoff });
    return this.request("POST", `${this.taskPath(id, task)}/fail`, body);
  }

  /** Split work: add a pending child task. */
  addChildTask(id: string, task: string, payload: string): Promise<CohortTask> {
    return this.request("POST", `${this.taskPath(id, task)}/children`, { payload });
  }
  /** Leave a handoff note on a task. */
  addTaskNote(id: string, task: string, text: string): Promise<CohortTask> {
    return this.request("POST", `${this.taskPath(id, task)}/notes`, { text });
  }
  /** Set (or with `""` clear) the brief for `agent` (`*`: every agent). */
  setTaskBrief(id: string, task: string, brief: string, agent = "*"): Promise<CohortTask> {
    return this.request("PUT", `${this.taskPath(id, task)}/brief`, { agent, brief });
  }
  /** Handoff notes, brief, parent summary and ranked memory for a task. */
  taskContext(id: string, task: string, options: { agent?: string; memoryBytes?: number } = {}): Promise<{ task: CohortTask; context: Record<string, unknown> }> {
    return this.request("GET", `${this.taskPath(id, task)}/context${this.query({ agent: options.agent, memory_bytes: options.memoryBytes })}`);
  }

  // -- cohort memory ----------------------------------------------------

  async listMemory(cohort: string): Promise<MemoryEntry[]> {
    const r = await this.request<{ entries?: MemoryEntry[] }>("GET", `/v1/cohorts/${this.segment(cohort)}/memory`);
    return r.entries ?? [];
  }
  /** Search shared memory, ranked by tag, key, text match and recency. */
  async searchMemory(cohort: string, query = "", options: MemorySearchOptions = {}): Promise<MemoryEntry[]> {
    const q = this.query({ query, tags: (options.tags ?? []).join(","), limit: options.limit, max_bytes: options.maxBytes });
    const r = await this.request<{ entries?: MemoryEntry[] }>("GET", `/v1/cohorts/${this.segment(cohort)}/memory${q}`);
    return r.entries ?? [];
  }
  /** Write an entry; `expectedVersion: 0` requires a new key. A stale version throws {@link RefusedError} (`version_conflict`). */
  putMemory(cohort: string, key: string, text: string, options: { tags?: string[]; expectedVersion?: number } = {}): Promise<MemoryEntry> {
    const body: Record<string, unknown> = { key, text, tags: options.tags ?? [] };
    if (options.expectedVersion !== undefined) body.expected_version = options.expectedVersion;
    return this.request("POST", `/v1/cohorts/${this.segment(cohort)}/memory`, body);
  }
  getMemory(cohort: string, key: string): Promise<MemoryEntry> {
    return this.request("GET", `/v1/cohorts/${this.segment(cohort)}/memory/${this.segment(key)}`);
  }
  /** Delete an entry (conditional on `version` when given); resolves to whether anything was deleted. */
  async deleteMemory(cohort: string, key: string, version?: number): Promise<boolean> {
    const q = version === undefined ? "" : `?version=${version}`;
    const r = await this.request<{ deleted?: boolean }>("DELETE", `/v1/cohorts/${this.segment(cohort)}/memory/${this.segment(key)}${q}`);
    return Boolean(r.deleted);
  }

  createSnapshot(sandbox: string, name = ""): Promise<Snapshot> { return this.request("POST", `/v1/citadels/${this.segment(sandbox)}/snapshot`, { name }); }
  async listSnapshots(): Promise<Snapshot[]> { const r = await this.request<{ snapshots: Snapshot[] }>("GET", "/v1/snapshots"); return r.snapshots ?? []; }
  restoreSnapshot(id: string): Promise<Sandbox> { return this.request("POST", `/v1/snapshots/${this.segment(id)}/restore`); }

  // -- approvals -------------------------------------------------------

  /** `GET /v1/conclave` — pending human-in-the-loop requests. */
  async listApprovals(): Promise<Approval[]> {
    const res = await this.request<{ approvals: Approval[] }>("GET", "/v1/conclave");
    return res.approvals ?? [];
  }

  /** `POST /v1/conclave/{id}/approve`. */
  approve(approvalId: string): Promise<unknown> {
    return this.request("POST", `/v1/conclave/${this.segment(approvalId)}/approve`);
  }

  /** `POST /v1/conclave/{id}/deny`. */
  deny(approvalId: string): Promise<unknown> {
    return this.request("POST", `/v1/conclave/${this.segment(approvalId)}/deny`);
  }
}
