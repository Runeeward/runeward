"use strict";

/* ------------------------------------------------------------------ *
 * Rune Box dashboard
 * Vanilla JS. Talks to the control-plane REST API at the same origin.
 * ------------------------------------------------------------------ */

const POLL_MS = 3000;

const state = {
  sandboxes: [],
  profiles: [],
  selected: null, // sandbox id
  activeTab: "terminal",
  approvals: [],
  activeView: "sandboxes", // "sandboxes" | "fleets"
  // fleets
  fleets: [],
  fleetSelected: null, // fleet id
  fleetTasks: [],
	taskLeases: {},
  agentSessions: [],
  agentSessionSelected: null,
  agentEvents: [],
  agentLastSeq: 0,
  agentStreamAbort: null,
  // terminal
  term: null,
  fitAddon: null,
  socket: null,
  termSandbox: null, // which sandbox the current socket belongs to
  conversationTerm: null,
  conversationFitAddon: null,
  conversationSocket: null,
  conversationSandbox: null,
  conversationReconnectTimer: null,
  // polling handles
  timers: { global: null, audit: null },
  // policy simulation
  simulation: null,
  // egress explorer
  egress: [],
  // budget view
  budget: null,
	readiness: null,
	snapshots: [],
	runs: [],
	taskResolution: null,
  // selected sandbox detail (isolation evidence, workspace)
  sandboxDetail: null,
  workspace: null, // workspace status, or null when not persistent
  sandboxSchedules: [],
  fleetSchedules: [],
  memory: [],
  memorySearched: false,
};

/* ---------------- DOM helpers ---------------- */
const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

function el(tag, attrs = {}, children = []) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") node.className = v;
    else if (k === "text") node.textContent = v;
    else if (k.startsWith("on") && typeof v === "function") {
      node.addEventListener(k.slice(2).toLowerCase(), v);
    } else if (v !== null && v !== undefined) {
      node.setAttribute(k, v);
    }
  }
  for (const c of [].concat(children)) {
    if (c === null || c === undefined) continue;
    node.appendChild(typeof c === "string" ? document.createTextNode(c) : c);
  }
  return node;
}

/* ---------------- Auth ---------------- */
const auth = {
  token: "",
  principal: null,
  rbac: false,
  onRequired: null, // callback invoked on a 401 (shows the login overlay)
};

function setToken(tok) {
  auth.token = (tok || "").trim();
}

// canApprove reports whether the current identity may resolve approvals. Open
// mode (no principal) and admins can; a principal must have can_approve.
function canApprove() {
  const p = auth.principal;
  return !p || p.can_approve !== false;
}

// canLaunch reports whether the current identity may create sandboxes/cohorts.
// Prefer the server's whoami.can_launch; fall back to allowed_profiles for
// older servers that always returned can_launch=true.
function canLaunch() {
  const p = auth.principal;
  if (!p) return true;
  if (p.admin) return true;
  if (p.can_launch === false) return false;
  if (auth.rbac && Array.isArray(p.allowed_profiles) && p.allowed_profiles.length === 0) {
    return false;
  }
  return p.can_launch !== false;
}

// profileAllowed mirrors authz.CanLaunch for client-side charter filtering.
function profileAllowed(name) {
  const p = auth.principal;
  if (!p || !auth.rbac || p.admin) return true;
  const patterns = Array.isArray(p.allowed_profiles) ? p.allowed_profiles : [];
  for (const pattern of patterns) {
    if (!pattern) continue;
    if (pattern === "*") return true;
	if (globMatches(pattern, name)) return true;
  }
  return false;
}

// Match Go path.Match's useful single-segment glob forms for profile names.
function globMatches(pattern, value) {
	let source = "";
	for (let i = 0; i < pattern.length; i++) {
		const ch = pattern[i];
		if (ch === "*") source += "[^/]*";
		else if (ch === "?") source += "[^/]";
		else if (ch === "[") {
			const end = pattern.indexOf("]", i + 1);
			if (end < 0) return false;
			source += pattern.slice(i, end + 1);
			i = end;
		} else source += ch.replace(/[.+^${}()|\\]/g, "\\$&");
	}
	try { return new RegExp("^" + source + "$").test(value); } catch { return false; }
}

/* ---------------- API layer ---------------- */
class ApiError extends Error {
  constructor(status, body, requestId) {
    body = body || {};
    const refusal = body.refusal && typeof body.refusal === "object" ? body.refusal : null;
    // Prefer the standard refusal's message; older servers only send
    // reason/error.
    super((refusal && refusal.message) || body.reason || body.error || body.message || `HTTP ${status}`);
    this.status = status;
    this.body = body;
    this.refusal = refusal;
    this.requestId = requestId || (refusal && refusal.request_id) || body.request_id || "";
  }
}

async function api(method, path, body) {
  const opts = { method, headers: {} };
  if (auth.token) opts.headers["Authorization"] = "Bearer " + auth.token;
  if (body !== undefined) {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  let res;
  try {
    res = await fetch(path, opts);
  } catch (e) {
    throw new ApiError(0, { error: "network error: " + e.message });
  }
  const text = await res.text();
  let data = {};
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = { raw: text };
    }
  }
  if (!res.ok) {
    if (res.status === 401 && typeof auth.onRequired === "function") {
      auth.onRequired();
    }
    throw new ApiError(res.status, data, res.headers.get("X-Request-Id") || "");
  }
  return { status: res.status, data };
}

/* ---------------- Toasts ---------------- */
function toast(msg, kind = "info", title, err) {
  const stack = $("#toast-stack");
  const detail = errorDetail(err);
  const node = el("div", { class: `toast ${kind}`, role: kind === "error" ? "alert" : "status" }, [
    title ? el("div", { class: "toast-title", text: title }) : null,
    el("div", { class: "toast-msg", text: msg }),
    detail ? el("div", { class: "toast-detail mono", text: detail }) : null,
  ]);
  stack.appendChild(node);
  setTimeout(() => {
    node.style.transition = "opacity 0.3s";
    node.style.opacity = "0";
    setTimeout(() => node.remove(), 300);
  }, kind === "error" ? 6000 : 3500);
}

/** "refused: policy · retryable · request 5f0c…" for an ApiError, else "". */
function errorDetail(err) {
  if (!err || !(err instanceof ApiError)) return "";
  const parts = [];
  if (err.refusal && err.refusal.reason) {
    parts.push("refused: " + err.refusal.reason + (err.refusal.retryable ? " (retryable)" : ""));
  }
  if (err.requestId) parts.push("request " + err.requestId);
  return parts.join(" · ");
}

/* ---------------- Header / health ---------------- */
async function refreshHealth() {
  const badge = $("#health-badge");
  const dot = $("#health-dot");
  const txt = $("#health-text");
  try {
    const { data } = await api("GET", "/healthz");
    const ok = data && data.status === "ok";
    badge.className = "badge " + (ok ? "ok" : "bad");
    dot.className = "dot " + (ok ? "dot-ok" : "dot-bad");
    txt.textContent = ok ? "online" : "unhealthy";
		if (ok) await refreshReadiness();
  } catch {
    badge.className = "badge bad";
    dot.className = "dot dot-bad";
    txt.textContent = "offline";
  }
}

function preferredProfileName() {
	const names = state.profiles.map((p) => p.name);
	for (const preferred of ["quickstart", "dev", "ns-auto"]) {
		if (names.includes(preferred)) return preferred;
	}
	const container = state.profiles.find((p) => p.host !== "k8s" && !(p.image || "").endsWith(":dev"));
	return (container || state.profiles[0] || {}).name || "";
}

function applyCreateAvailability() {
	const btn = state.activeView === "fleets" ? $("#fleet-create-btn") : $("#create-btn");
	if (!btn) return;
	const ready = !!(state.readiness && state.readiness.ready);
	btn.disabled = !canLaunch() || !ready;
	btn.title = !canLaunch()
		? "Your role is not permitted to launch policies"
		: ready
			? (state.activeView === "fleets" ? "Create agent group" : "Create sandbox")
			: "Selected policy is not ready; see setup status";
}

function refreshSelectedProfileReadiness() {
	state.readiness = null;
	applyCreateAvailability();
	return refreshReadiness();
}

async function refreshReadiness() {
	const select = state.activeView === "fleets" ? $("#fleet-profile-select") : $("#profile-select");
	const name = select && select.value;
	const note = state.activeView === "fleets" ? $("#fleet-setup-note") : $("#setup-note");
	if (!name) {
		state.readiness = null;
		if (note) {
			note.className = "setup-note blocked";
			note.textContent = "No policy selected. Run `runeward quickstart` on the server host.";
		}
		applyCreateAvailability();
		return;
	}
	try {
		const { data } = await api("GET", "/v1/readiness?profile=" + encodeURIComponent(name));
		state.readiness = data;
		const failed = (data.checks || []).filter((c) => c.status === "fail");
		if (note) {
			note.className = "setup-note " + (data.ready ? "ready" : "blocked");
			note.textContent = data.ready
				? `${name} is ready: policy valid and sandbox runtime reachable.`
				: (failed[0] && failed[0].message) || `Run runeward doctor ${name} on the server host.`;
		}
		const badge = $("#health-badge");
		const dot = $("#health-dot");
		const txt = $("#health-text");
		badge.className = "badge " + (data.ready ? "ok" : "badge-muted");
		dot.className = "dot " + (data.ready ? "dot-ok" : "dot-muted");
		txt.textContent = data.ready ? "ready" : "setup needed";
		badge.title = (data.checks || []).map((c) => `${c.name}: ${c.message}`).join("\n");
	} catch (e) {
		state.readiness = null;
		if (note) {
			note.className = "setup-note blocked";
			note.textContent = "Readiness check unavailable. Run `runeward doctor` on the server host.";
		}
	}
	applyCreateAvailability();
}

async function refreshAuditVerify() {
  const badge = $("#audit-badge");
  try {
    const { data } = await api("GET", "/v1/chronicle/verify");
    if (data && data.ok) {
      badge.className = "badge ok";
      badge.title = "Signed audit trail verified";
      badge.querySelector(".badge-dot") || badge.prepend(el("span", { class: "badge-dot" }));
      badge.lastChild.textContent = " Audit verified";
    } else {
      badge.className = "badge bad";
      badge.title = (data && data.error) || "Signed audit verification failed";
      badge.lastChild.textContent = " Audit tampered";
    }
  } catch (e) {
    badge.className = "badge bad";
    badge.title = e.message;
    badge.lastChild.textContent = " Audit ?";
  }
}

/* ---------------- Profiles ---------------- */
function fillProfileSelect(sel, text) {
  if (!sel) return;
  sel.innerHTML = "";
  if (text) {
    sel.appendChild(el("option", { value: "", text }));
    return;
  }
  if (state.profiles.length === 0) {
    sel.appendChild(el("option", { value: "", text: "No policies" }));
    return;
  }
  for (const p of state.profiles) {
    sel.appendChild(
      el("option", {
				value: p.name,
				text: `${p.name} · ${p.host || "?"}`,
				title: `network: ${p.egress || "unknown"}`,
			})
    );
  }
}

async function loadProfiles() {
	const previous = {
		sandbox: $("#profile-select") && $("#profile-select").value,
		fleet: $("#fleet-profile-select") && $("#fleet-profile-select").value,
		simulation: $("#sim-profile-select") && $("#sim-profile-select").value,
	};
  try {
    const { data } = await api("GET", "/v1/charters");
    // Server already scopes charters under RBAC; filter again client-side so
    // a stale cache or older control plane can't show unauthorized options.
    const all = (data && data.profiles) || [];
    state.profiles = all.filter((p) => profileAllowed(p.name));
    fillProfileSelect($("#profile-select"));
    fillProfileSelect($("#fleet-profile-select"));
    fillProfileSelect($("#sim-profile-select"));
		const fallback = preferredProfileName();
		const preserved = (name) => state.profiles.some((p) => p.name === name) ? name : fallback;
		if ($("#profile-select")) $("#profile-select").value = preserved(previous.sandbox);
		if ($("#fleet-profile-select")) $("#fleet-profile-select").value = preserved(previous.fleet);
		if ($("#sim-profile-select")) $("#sim-profile-select").value = preserved(previous.simulation);
		await refreshSelectedProfileReadiness();
  } catch (e) {
    fillProfileSelect($("#profile-select"), "policies unavailable");
    fillProfileSelect($("#fleet-profile-select"), "policies unavailable");
    fillProfileSelect($("#sim-profile-select"), "policies unavailable");
    toast("Could not load policies: " + e.message, "error", undefined, e);
  }
}

/* ---------------- Sandboxes ---------------- */
async function loadSandboxes() {
  try {
    const { data } = await api("GET", "/v1/citadels");
    state.sandboxes = (data && data.sandboxes) || [];
  } catch (e) {
    state.sandboxes = [];
    // don't spam toast on poll; health badge covers offline
  }
  renderSandboxList();
  if (state.selected && !state.sandboxes.find((s) => s.id === state.selected)) {
    selectSandbox(null);
  }
}

function renderSandboxList() {
  const list = $("#sandbox-list");
  list.innerHTML = "";
  if (state.sandboxes.length === 0) {
    list.appendChild(el("li", { class: "empty-note", text: "No sandboxes yet." }));
    return;
  }
  for (const s of state.sandboxes) {
    const status = (s.status || "unknown").toLowerCase();
    const item = el(
      "li",
      {
        class: "sandbox-item" + (s.id === state.selected ? " active" : ""),
        title: s.id,
        onClick: () => selectSandbox(s.id),
      },
      [
        el("div", { class: "sb-id", text: s.id }),
        el("div", { class: "sb-meta" }, [
          el("span", { text: s.profile || "—" }),
          el("span", { text: "·" }),
          el("span", { text: s.backend || "—" }),
          // Owner is only meaningful to an admin viewing other principals'
          // sandboxes; non-admins only ever see their own.
          (s.owner && auth.principal && auth.principal.admin)
            ? el("span", { class: "sb-owner", title: "owner", text: "@" + s.owner })
            : null,
          el("span", { class: `sb-status ${status}`, text: status }),
          s.isolation ? isolationBadge(s.isolation) : null,
        ]),
        el("button", {
          class: "kill-btn",
          title: "Remove sandbox",
          text: "✕",
          onClick: (ev) => {
            ev.stopPropagation();
            killSandbox(s.id);
          },
        }),
      ]
    );
    list.appendChild(item);
  }
}

function openNewSandboxModal() {
  const profile = $("#profile-select").value;
  if (!profile) {
    toast("Pick a policy first.", "warn");
    return;
  }
  $("#new-modal-profile").textContent = profile;
  $("#new-modal-copyfrom").value = "";
  $("#new-modal-progress").classList.add("hidden");
  $("#new-modal-progress").textContent = "";
  $("#new-modal").classList.remove("hidden");
  $("#new-modal-copyfrom").focus();
}

function closeNewSandboxModal() {
  $("#new-modal").classList.add("hidden");
}

async function createSandbox() {
  const profile = $("#new-modal-profile").textContent.trim();
  if (!profile) {
    toast("Pick a policy first.", "warn");
    return;
  }
  const copyFrom = $("#new-modal-copyfrom").value.trim();
  const btn = $("#new-modal-create");
  const progress = $("#new-modal-progress");
  btn.disabled = true;
  progress.classList.remove("hidden");
  progress.textContent = `Provisioning ${profile}… the first image pull can take several minutes.`;
  try {
    const body = { profile };
    if (copyFrom) body.copy_from = copyFrom;
    const { data } = await api("POST", "/v1/citadels", body);
    toast(`Sandbox ${data.id} created`, "success");
    closeNewSandboxModal();
    await loadSandboxes();
    if (data.id) selectSandbox(data.id);
  } catch (e) {
    progress.textContent = "Provisioning failed.";
    toast(`Could not create the sandbox: ${e.message}. Check setup status or run "runeward doctor ${profile}" on the server host.`, "error", undefined, e);
  } finally {
    btn.disabled = false;
  }
}

async function killSandbox(id) {
  try {
    await api("DELETE", "/v1/citadels/" + encodeURIComponent(id));
    toast(`Sandbox ${id} removed`, "info");
    if (state.selected === id) selectSandbox(null);
    await loadSandboxes();
  } catch (e) {
    toast("Kill failed: " + e.message, "error", undefined, e);
  }
}

function selectSandbox(id) {
  const changed = state.selected !== id;
  if (changed) resetSandboxViews();
  state.selected = id;
  renderSandboxList();

  const empty = $("#panel-empty");
  const bodyEl = $("#panel-body");
  if (!id) {
    empty.classList.remove("hidden");
    bodyEl.classList.add("hidden");
    teardownTerminalSocket();
    teardownConversationSocket();
    stopAuditPoll();
    state.egress = [];
    state.budget = null;
		state.snapshots = [];
    state.sandboxDetail = null;
    state.workspace = null;
    state.sandboxSchedules = [];
    renderSandboxDetail();
    renderEgress();
    renderBudget();
		renderSnapshots();
    const openIde = $("#open-ide");
    if (openIde) openIde.classList.add("hidden");
    const ideLink = $("#ide-link");
    if (ideLink) ideLink.classList.add("hidden");
    const ideHint = $("#ide-agents-hint");
    if (ideHint) {
      ideHint.textContent = "";
      ideHint.classList.add("hidden");
    }
    const agentSessions = $("#view-agent-sessions");
    if (agentSessions) {
      agentSessions.classList.add("hidden");
      delete agentSessions.dataset.cohortId;
      delete agentSessions.dataset.sandboxId;
    }
    return;
  }
  empty.classList.add("hidden");
  bodyEl.classList.remove("hidden");

  const sb = state.sandboxes.find((s) => s.id === id) || {};
  $("#sel-id").textContent = id;
  $("#sel-meta").textContent = `${sb.profile || "—"} · ${sb.backend || "—"} · ${sb.image || "—"} · ${sb.status || "—"}`;
  const openIde = $("#open-ide");
  const ideHint = $("#ide-agents-hint");
  if (openIde) {
    openIde.classList.toggle("hidden", !sb.ide);
  }
  const ideLink = $("#ide-link");
  if (ideLink) {
    ideLink.removeAttribute("href");
    ideLink.classList.add("hidden");
  }
  applySandboxCapabilities(sb);
  if (ideHint) {
    const agents = Array.isArray(sb.ide_agents) ? sb.ide_agents.filter(Boolean) : [];
    if (sb.ide && agents.length) {
      const cmds = agents.map((a) => {
        if (a === "cursor") return "agent";
        return a;
      });
      ideHint.textContent = `In IDE terminal: ${cmds.join(" · ")} (CLI — not Cursor/Claude Desktop GUIs)`;
      ideHint.classList.remove("hidden");
    } else {
      ideHint.textContent = "";
      ideHint.classList.add("hidden");
    }
  }
  const simSel = $("#sim-profile-select");
  if (simSel && sb.profile) {
    simSel.value = sb.profile;
  }
  updateAgentSessionsLink(id);
  if (changed) {
    state.sandboxDetail = null;
    state.workspace = null;
  }
  renderSandboxDetail();
  refreshSandboxDetail();

  // Re-activate the current tab for the new sandbox.
  activateTab(state.activeTab, true);
}

/* ---------------- Isolation & workspace ---------------- */
const ISOLATION_TIERS = {
  process: "Process: a host process, confined by the in-sandbox supervisor only",
  container: "Container: namespaces and cgroups on the host kernel",
  kernel: "Kernel: a separate or user-space kernel (gVisor, Kata)",
  vm: "VM: a dedicated virtual machine",
};

function isolationBadge(tier) {
  const t = String(tier || "").toLowerCase();
  return el("span", {
    class: "iso-badge iso-" + (ISOLATION_TIERS[t] ? t : "unknown"),
    title: ISOLATION_TIERS[t] || "Isolation tier",
    "aria-label": "Isolation tier: " + (t || "unknown"),
    text: t || "?",
  });
}

async function refreshSandboxDetail() {
  const id = state.selected;
  if (!id) return;
  const [detail, ws] = await Promise.allSettled([
    api("GET", sbPath("")),
    api("GET", sbPath("/workspace/status")),
  ]);
  if (state.selected !== id) return; // selection changed meanwhile
  if (detail.status === "fulfilled") state.sandboxDetail = detail.value.data || null;
  if (ws.status === "fulfilled") state.workspace = ws.value.data || null;
  else if (ws.reason instanceof ApiError && ws.reason.status === 404) state.workspace = null;
  renderSandboxDetail();
}

function boolText(v) {
  if (v === true) return "yes";
  if (v === false) return "no";
  return "—";
}

function renderSandboxDetail() {
  const listed = state.sandboxes.find((s) => s.id === state.selected) || {};
  const sb = Object.assign({}, listed, state.sandboxDetail || {});
  const badge = $("#sel-isolation");
  if (badge) {
    const tier = String(sb.isolation || "").toLowerCase();
    badge.textContent = tier ? "isolation: " + tier : "";
    badge.className = "iso-badge iso-" + (ISOLATION_TIERS[tier] ? tier : "unknown") + (tier ? "" : " hidden");
    badge.title = ISOLATION_TIERS[tier] || "";
    badge.setAttribute("aria-label", "Isolation tier: " + (tier || "unknown"));
  }

  // Evidence: the backend's tier claim plus the supervisor's report.
  const dl = $("#isolation-evidence");
  if (dl) {
    dl.innerHTML = "";
    const add = (label, value, cls) => {
      dl.appendChild(el("dt", { text: label }));
      dl.appendChild(el("dd", { class: cls || "", text: value == null || value === "" ? "—" : String(value) }));
    };
    const ie = sb.isolation_evidence || {};
    add("Tier", ie.tier || sb.isolation);
    add("Reported by", ie.backend || sb.backend);
    if (ie.source === "probe") {
      add("Runtime", ie.runtime);
      add("Guest / host kernel", `${ie.guest_kernel || "—"} / ${ie.host_kernel || "—"}`,
        ie.guest_kernel && ie.host_kernel && ie.guest_kernel !== ie.host_kernel ? "ok" : "");
      if (ie.hypervisor) add("Hypervisor", ie.hypervisor, ie.hypervisor === "unknown" ? "warn" : "ok");
      const sig = Array.isArray(ie.signals) ? ie.signals : [];
      if (sig.some((x) => x.startsWith("host:hypervisor-mismatch"))) {
        add("Warning", "runtime name and running hypervisor disagree", "bad");
      }
      if (sig.length) add("Signals", sig.join(", "));
    }
    if (ie.floor !== undefined) {
      add("Policy floor", ie.floor || "none");
      add("Meets floor", boolText(ie.meets_floor), ie.meets_floor === false ? "bad" : "ok");
    }
    const ev = sb.enforcement;
    if (ev) {
      add("Supervisor", ev.supervisor + (ev.required ? " (required)" : ""), ev.supervisor === "enforced" ? "ok" : "warn");
      add("Landlock", `${ev.landlock || "—"} (requested ${ev.landlock_requested || "—"}${ev.landlock_abi ? ", ABI " + ev.landlock_abi : ""})`,
        ev.landlock === "enforced" ? "ok" : "warn");
      add("Seccomp filter", boolText(ev.seccomp), ev.seccomp ? "ok" : "warn");
      add("no_new_privs", boolText(ev.no_new_privs), ev.no_new_privs ? "ok" : "warn");
      add("Agent uid / gid", `${ev.uid == null ? "—" : ev.uid} / ${ev.gid == null ? "—" : ev.gid}`);
      add("Capabilities dropped", boolText(ev.capabilities_dropped), ev.capabilities_dropped ? "ok" : "warn");
      add("Supervisor files guarded by Landlock", boolText(ev.protected_by_landlock));
    } else {
      add("Supervisor", "no report (this policy does not run the in-sandbox supervisor)");
    }
  }

  // Workspace status line and controls.
  const line = $("#workspace-status");
  const sleepBtn = $("#workspace-sleep");
  const wakeBtn = $("#workspace-wake");
  if (!line) return;
  const ws = state.workspace;
  if (!state.selected) {
    line.textContent = "—";
  } else if (!ws) {
    line.textContent = "ephemeral (the policy does not keep the workspace across sleep)";
  } else {
    const parts = [ws.state || sb.status || "unknown"];
    if (ws.state === "running" && ws.idle_timeout_secs) {
      parts.push(`idle ${fmtDuration(ws.idle_secs)} of ${fmtDuration(ws.idle_timeout_secs)}`);
    } else if (!ws.idle_timeout_secs) {
      parts.push("no idle sleep");
    }
    if (ws.slept_at) parts.push("slept " + fmtDateTime(ws.slept_at));
    if (ws.woke_at) parts.push("woke " + fmtDateTime(ws.woke_at));
    if (ws.forked_from) parts.push("forked from run " + ws.forked_from);
    line.textContent = parts.join(" · ");
  }
  const st = ws ? String(ws.state || "") : "";
  if (sleepBtn) sleepBtn.classList.toggle("hidden", !ws || st !== "running");
  if (wakeBtn) wakeBtn.classList.toggle("hidden", !ws || st !== "sleeping");
}

function fmtDuration(secs) {
  const n = Number(secs) || 0;
  if (n < 60) return n + "s";
  if (n < 3600) return Math.round(n / 60) + "m";
  return (n / 3600).toFixed(n % 3600 ? 1 : 0) + "h";
}

async function workspaceAction(action) {
  const id = state.selected;
  if (!id) return;
  const btn = $("#workspace-" + action);
  if (btn) btn.disabled = true;
  try {
    const { data } = await api("POST", sbPath("/" + action), action === "fork" ? {} : undefined);
    if (action === "fork") {
      toast(`Forked ${id} into ${data.id}`, "success");
      await loadSandboxes();
      if (data.id) selectSandbox(data.id);
      return;
    }
    if (action === "sleep" && data && data.slept === false) toast(`Sandbox ${id} was already asleep`, "info");
    else toast(`Sandbox ${id} ${action === "sleep" ? "is asleep" : "is awake"}`, "success");
    await loadSandboxes();
    await refreshSandboxDetail();
  } catch (e) {
    toast(`${action[0].toUpperCase() + action.slice(1)} failed: ${e.message}`, "error", undefined, e);
  } finally {
    if (btn) btn.disabled = false;
  }
}

/* ---------------- Schedules ---------------- */
function scheduleWhen(s) {
  if (s.cron) return "cron " + s.cron + " UTC";
  if (s.every) return "every " + s.every;
  return "—";
}

function renderScheduleRows(body, schedules, emptyText, onChange) {
  if (!body) return;
  body.innerHTML = "";
  if (!schedules.length) {
    body.appendChild(el("tr", {}, el("td", { colspan: "6", class: "empty-note", text: emptyText })));
    return;
  }
  for (const s of schedules) {
    const cmd = [...(s.command || []), s.prompt ? JSON.stringify(s.prompt) : ""].filter(Boolean).join(" ");
    const outcome = s.last_outcome || "";
    body.appendChild(el("tr", {}, [
      el("td", { text: scheduleWhen(s), title: s.id || "" }),
      el("td", { text: cmd || "—", title: (s.precheck && s.precheck.length ? "precheck: " + s.precheck.join(" ") + "\n" : "") + cmd }),
      el("td", { text: s.next_fire_at ? fmtDateTime(s.next_fire_at) : "—" }),
      el("td", { title: s.last_reason || "" }, outcome
        ? el("span", { class: "state-tag " + outcome, text: outcome + (s.last_reason ? ": " + s.last_reason : "") })
        : "—"),
      el("td", { text: String(s.fire_count || 0) }),
      el("td", { class: "row-actions" }, [
        el("button", { class: "btn btn-sm", type: "button", text: "Run now", "aria-label": "Run schedule " + (s.id || "") + " now", onClick: () => runSchedule(s.id, onChange) }),
        el("button", { class: "btn btn-sm btn-danger", type: "button", text: "Delete", "aria-label": "Delete schedule " + (s.id || ""), onClick: () => deleteSchedule(s.id, onChange) }),
      ]),
    ]));
  }
}

async function refreshSandboxSchedules() {
  const id = state.selected;
  if (!id) return;
  try {
    const { data } = await api("GET", sbPath("/schedules"));
    if (state.selected !== id) return;
    state.sandboxSchedules = (data && data.schedules) || [];
  } catch (e) {
    state.sandboxSchedules = [];
  }
  renderSandboxSchedules();
}

function renderSandboxSchedules() {
  renderScheduleRows($("#sb-schedule-body"), state.selected ? state.sandboxSchedules : [],
    state.selected ? "No schedules for this sandbox." : "Select a sandbox first.", refreshSandboxSchedules);
}

async function refreshFleetSchedules() {
  const id = state.fleetSelected;
  if (!id) return;
  try {
    const { data } = await api("GET", fleetPath("/schedules"));
    if (state.fleetSelected !== id) return;
    state.fleetSchedules = (data && data.schedules) || [];
  } catch (e) {
    state.fleetSchedules = [];
  }
  renderScheduleRows($("#fleet-schedule-body"), state.fleetSchedules, "No schedules for this agent group.", refreshFleetSchedules);
}

async function runSchedule(id, onChange) {
  try {
    const { data } = await api("POST", "/v1/schedules/" + encodeURIComponent(id) + "/run");
    const outcome = (data && data.outcome) || "fired";
    toast(`Schedule ${id}: ${outcome}${data && data.reason ? " (" + data.reason + ")" : ""}`, outcome === "started" ? "success" : "warn");
  } catch (e) {
    toast("Run failed: " + e.message, "error", undefined, e);
  }
  if (onChange) onChange();
}

async function deleteSchedule(id, onChange) {
  if (!window.confirm(`Delete schedule ${id}?`)) return;
  try {
    await api("DELETE", "/v1/schedules/" + encodeURIComponent(id));
    toast(`Schedule ${id} deleted`, "info");
  } catch (e) {
    toast("Delete failed: " + e.message, "error", undefined, e);
  }
  if (onChange) onChange();
}

/* ---------------- Cohort memory ---------------- */
async function loadMemory(search) {
  const id = state.fleetSelected;
  if (!id) return;
  const params = new URLSearchParams();
  if (search) {
    const q = $("#memory-query").value.trim();
    const tags = $("#memory-tags").value.split(",").map((t) => t.trim()).filter(Boolean).join(",");
    if (q) params.set("query", q);
    if (tags) params.set("tags", tags);
  }
  const qs = params.toString();
  try {
    const { data } = await api("GET", fleetPath("/memory" + (qs ? "?" + qs : "")));
    if (state.fleetSelected !== id) return;
    state.memory = (data && data.entries) || [];
    state.memorySearched = Boolean(qs);
  } catch (e) {
    state.memory = [];
    toast("Memory read failed: " + e.message, "error", undefined, e);
  }
  renderMemory();
}

function renderMemory() {
  const body = $("#memory-body");
  if (!body) return;
  body.innerHTML = "";
  if (!state.memory.length) {
    body.appendChild(el("tr", {}, el("td", {
      colspan: "6", class: "empty-note",
      text: state.memorySearched ? "No entries match." : "No shared memory yet.",
    })));
    return;
  }
  for (const m of state.memory) {
    const text = String(m.text || "");
    body.appendChild(el("tr", {}, [
      el("td", { text: m.key || "—", title: m.key || "" }),
      el("td", { class: "memory-text", text: text.length > 160 ? text.slice(0, 160) + "…" : text, title: text }),
      el("td", { text: (m.tags || []).join(", ") || "—" }),
      el("td", { text: m.author || "—" }),
      el("td", { text: String(m.version || "—") }),
      el("td", { text: fmtDateTime(m.updated_at) }),
    ]));
  }
}

async function updateAgentSessionsLink(sandboxID) {
  const button = $("#view-agent-sessions");
  if (!button) return;
  button.classList.add("hidden");
  delete button.dataset.cohortId;
  delete button.dataset.sandboxId;
  try {
    const { data } = await api("GET", "/v1/cohorts");
    if (state.selected !== sandboxID) return;
    const cohorts = (data && data.fleets) || [];
    const cohort = cohorts.find((item) => Array.isArray(item.sandboxes) && item.sandboxes.includes(sandboxID));
    if (!cohort) return;
    button.dataset.cohortId = cohort.id;
    button.dataset.sandboxId = sandboxID;
    button.classList.remove("hidden");
  } catch (_) {
    // The global health indicator covers connectivity; keep this shortcut hidden.
  }
}

async function openAgentSessionsForSelectedSandbox() {
  const button = $("#view-agent-sessions");
  const cohortID = button && button.dataset.cohortId;
  const sandboxID = button && button.dataset.sandboxId;
  if (!cohortID) return;
  switchView("fleets");
  await loadFleets();
  await selectFleet(cohortID);
  const latest = [...state.agentSessions]
    .filter((session) => !sandboxID || session.citadel_id === sandboxID)
    .sort((a, b) => String(b.created_at || "").localeCompare(String(a.created_at || "")))[0];
  if (latest) await selectAgentSession(latest.id);
}

function resetSandboxViews() {
  teardownTerminalSocket();
  teardownConversationSocket();
  stopAuditPoll();
  if (state.term) state.term.reset();
  if (state.conversationTerm) state.conversationTerm.reset();
  for (const id of ["list-output", "search-output", "shell-stdout", "shell-stderr", "code-stdout", "code-stderr", "browser-stdout", "browser-stderr"]) {
    const node = $("#" + id);
    if (node) node.textContent = "";
  }
  for (const id of ["shell-result", "code-result", "browser-result"]) {
    const node = $("#" + id);
    if (node) node.classList.add("hidden");
  }
  const screenshot = $("#browser-screenshot");
  if (screenshot) {
    screenshot.removeAttribute("src");
    screenshot.classList.add("hidden");
  }
  const fileNote = $("#file-note");
  if (fileNote) fileNote.textContent = "";
  const audit = $("#audit-body");
  if (audit) audit.innerHTML = '<tr><td colspan="6" class="empty-note">No events yet.</td></tr>';
  state.egress = [];
  state.budget = null;
  state.snapshots = [];
  state.runs = [];
  renderEgress();
  renderBudget();
  renderSnapshots();
}

function applySandboxCapabilities(sb) {
  const capabilities = new Set(Array.isArray(sb.capabilities) ? sb.capabilities : []);
  const langs = ["python", "node"].filter((lang) => capabilities.has(lang));
  const select = $("#code-lang");
  const card = $("#code-card");
  const note = $("#code-capability-note");
  if (select) {
    select.innerHTML = "";
    for (const lang of langs) select.appendChild(el("option", { value: lang, text: lang === "python" ? "Python" : "Node" }));
  }
  if (card) card.classList.toggle("hidden", langs.length === 0);
  if (note) note.textContent = langs.length ? `Available in this Charter: ${langs.join(", ")}` : "";
  const browserAvailable = capabilities.has("browser");
  const browserTab = $("#browser-tab");
  if (browserTab) browserTab.classList.toggle("hidden", !browserAvailable);
  if (!browserAvailable && state.activeTab === "browser") state.activeTab = "terminal";
}

/* ---------------- View switch (Sandboxes | Fleets) ---------------- */
function switchView(name) {
  if (name === state.activeView) return;
  state.activeView = name;

  $("#view-sandboxes").classList.toggle("active", name === "sandboxes");
  $("#view-sandboxes").setAttribute("aria-selected", String(name === "sandboxes"));
  $("#view-sandboxes").tabIndex = name === "sandboxes" ? 0 : -1;
  $("#view-fleets").classList.toggle("active", name === "fleets");
  $("#view-fleets").setAttribute("aria-selected", String(name === "fleets"));
  $("#view-fleets").tabIndex = name === "fleets" ? 0 : -1;

  $("#sb-sidebar").classList.toggle("hidden", name !== "sandboxes");
  $("#fleet-sidebar").classList.toggle("hidden", name !== "fleets");
  $("#sb-panel").classList.toggle("hidden", name !== "sandboxes");
  $("#fleet-panel").classList.toggle("hidden", name !== "fleets");

  refreshSelectedProfileReadiness();
  if (name === "fleets") refreshFleets();
}

/* ---------------- Fleets ---------------- */
function fleetPath(suffix) {
  return `/v1/cohorts/${encodeURIComponent(state.fleetSelected)}${suffix || ""}`;
}

async function refreshFleets() {
  await loadFleets();
  if (state.fleetSelected) await refreshFleetDetail();
}

async function loadFleets() {
  try {
    const { data } = await api("GET", "/v1/cohorts");
    state.fleets = (data && data.fleets) || [];
  } catch (e) {
    state.fleets = [];
    // don't spam toast on poll; health badge covers offline
  }
  renderFleetList();
  if (state.fleetSelected && !state.fleets.find((f) => f.id === state.fleetSelected)) {
    selectFleet(null);
  }
}

function renderFleetList() {
  const list = $("#fleet-list");
  list.innerHTML = "";
  if (state.fleets.length === 0) {
    list.appendChild(el("li", { class: "empty-note", text: "No agent groups yet." }));
    return;
  }
  for (const f of state.fleets) {
    const st = f.stats || {};
    const total = st.total != null ? st.total : 0;
    const done = st.done != null ? st.done : 0;
    const sbCount = (f.sandboxes || []).length;
    const item = el(
      "li",
      {
        class: "sandbox-item" + (f.id === state.fleetSelected ? " active" : ""),
        title: f.id,
        onClick: () => selectFleet(f.id),
      },
      [
        el("div", { class: "sb-id", text: f.id }),
        el("div", { class: "sb-meta" }, [
          el("span", { text: f.profile || "—" }),
          el("span", { text: "·" }),
          el("span", { text: `${done}/${total} done` }),
          el("span", { text: "·" }),
          el("span", { text: `${sbCount} sb` }),
        ]),
        el("button", {
          class: "kill-btn",
          title: "Delete agent group",
          text: "✕",
          onClick: (ev) => {
            ev.stopPropagation();
            deleteFleet(f.id);
          },
        }),
      ]
    );
    list.appendChild(item);
  }
}

async function createFleet() {
  const profile = $("#fleet-profile-select").value;
  if (!profile) {
    toast("Pick a policy first.", "warn");
    return;
  }
  const btn = $("#fleet-create-btn");
  btn.disabled = true;
  try {
    const { data } = await api("POST", "/v1/cohorts", { profile });
    toast(`Agent group ${data.id} created`, "success");
    await loadFleets();
    if (data.id) selectFleet(data.id);
  } catch (e) {
    toast("Create agent group failed: " + e.message, "error", undefined, e);
  } finally {
    btn.disabled = false;
  }
}

async function deleteFleet(id) {
  try {
    await api("DELETE", "/v1/cohorts/" + encodeURIComponent(id));
    toast(`Agent group ${id} deleted`, "info");
    if (state.fleetSelected === id) selectFleet(null);
    await loadFleets();
  } catch (e) {
    toast("Delete failed: " + e.message, "error", undefined, e);
  }
}

function selectFleet(id) {
  stopAgentStream();
  state.fleetSelected = id;
  state.fleetTasks = [];
  state.agentSessions = [];
  state.agentSessionSelected = null;
  state.agentEvents = [];
  state.agentLastSeq = 0;
  renderFleetList();

  const empty = $("#fleet-empty");
  const bodyEl = $("#fleet-body");
  if (!id) {
    empty.classList.remove("hidden");
    bodyEl.classList.add("hidden");
    return Promise.resolve();
  }
  empty.classList.add("hidden");
  bodyEl.classList.remove("hidden");
  $("#fleet-claim-note").classList.add("hidden");
  state.memory = [];
  state.memorySearched = false;
  state.fleetSchedules = [];
  renderMemory();
  loadMemory(false);
  refreshFleetSchedules();
  return refreshFleetDetail();
}

async function refreshFleetDetail() {
  if (!state.fleetSelected) return;
  try {
    const [fleetRes, tasksRes, sessionsRes] = await Promise.all([
      api("GET", fleetPath("")),
      api("GET", fleetPath("/tasks")),
      api("GET", "/v1/agent-sessions?cohort_id=" + encodeURIComponent(state.fleetSelected)),
    ]);
    state.fleetTasks = (tasksRes.data && tasksRes.data.tasks) || [];
    state.agentSessions = (sessionsRes.data && sessionsRes.data.sessions) || [];
    renderFleetDetail(fleetRes.data || {});
  } catch (e) {
    if (e instanceof ApiError && e.status === 404) {
      toast("Agent group no longer exists", "warn");
      selectFleet(null);
      loadFleets();
    }
    // otherwise leave prior contents; global health badge covers offline
  }
}

function renderFleetDetail(fleet) {
  const sbs = fleet.sandboxes || [];
  const sbCount = sbs.length;
  $("#fleet-sel-id").textContent = fleet.id || state.fleetSelected;
  $("#fleet-sel-meta").textContent =
    `${fleet.profile || "—"} · ${sbCount} sandbox${sbCount === 1 ? "" : "es"}`;
  $("#fleet-sb-count").textContent = `${sbCount} member${sbCount === 1 ? "" : "s"}`;

  renderFleetStats(fleet.stats || {});
  renderFleetChips(sbs);
  renderFleetTasks();
  renderAgentSessions();
}

function renderFleetStats(stats) {
  const bar = $("#fleet-stats");
  bar.innerHTML = "";
  for (const key of ["total", "pending", "claimed", "done", "failed"]) {
    bar.appendChild(
      el("span", { class: `stat ${key}` }, [
        key + " ",
        el("b", { text: String(stats[key] != null ? stats[key] : 0) }),
      ])
    );
  }
}

function renderFleetChips(ids) {
  const wrap = $("#fleet-chips");
  wrap.innerHTML = "";
  if (!ids.length) {
    wrap.appendChild(el("span", { class: "empty-note", text: "No member sandboxes." }));
    return;
  }
  for (const id of ids) {
    wrap.appendChild(el("span", { class: "chip", text: id, title: id }));
  }
}

function renderFleetTasks() {
  const body = $("#fleet-task-body");
  body.innerHTML = "";
  if (!state.fleetTasks.length) {
    body.appendChild(
      el("tr", {}, el("td", { colspan: "6", class: "empty-note", text: "No tasks yet." }))
    );
    return;
  }
  for (const t of state.fleetTasks) {
    const st = (t.state || "").toLowerCase();
    const resultOrError = st === "failed" ? t.error || "" : t.result || "";

    const actions = el("div", { class: "task-actions" });
    if (st === "claimed" && state.taskLeases[t.id]) {
      const requeue = el("input", { type: "checkbox", checked: "checked", class: "requeue-box" });
      actions.appendChild(
        el("button", {
          class: "btn btn-sm btn-approve",
          text: "Complete",
		  onClick: () => completeFleetTask(t.id, t.owner || ""),
        })
      );
      actions.appendChild(
        el("button", {
          class: "btn btn-sm btn-deny",
          text: "Fail",
		  onClick: () => failFleetTask(t.id, t.owner || "", requeue.checked),
        })
      );
      actions.appendChild(
        el("label", { class: "requeue-label", title: "Requeue task on failure" }, [requeue, " requeue"])
      );
    }

    body.appendChild(
      el("tr", {}, [
        el("td", { text: t.payload || "", title: t.payload || "" }),
        el("td", {}, el("span", { class: "state-tag " + st, text: st || "—" })),
        el("td", { text: t.owner || "—" }),
        el("td", { text: String(t.attempts != null ? t.attempts : 0) }),
        el("td", {
          class: st === "failed" ? "output-err" : "",
          text: resultOrError,
          title: resultOrError,
        }),
        el("td", {}, actions),
      ])
    );
  }
}

function renderAgentSessions() {
  const body = $("#agent-session-body");
  if (!body) return;
  body.innerHTML = "";
  if (!state.agentSessions.length) {
    body.appendChild(el("tr", {}, el("td", { colspan: "6", class: "empty-note", text: "No agent sessions yet." })));
    return;
  }
  const sessions = [...state.agentSessions].sort((a, b) => String(b.created_at || "").localeCompare(String(a.created_at || "")));
  for (const s of sessions) {
    const status = String(s.status || "unknown").toLowerCase();
    body.appendChild(el("tr", { class: s.id === state.agentSessionSelected ? "selected-row" : "" }, [
      el("td", { text: [s.agent || "agent", s.model || ""].filter(Boolean).join(" · ") }),
      el("td", { class: "mono", text: s.task_id || "—", title: s.task_id || "" }),
      el("td", { class: "mono", text: s.citadel_id || "—", title: s.citadel_id || "" }),
      el("td", {}, el("span", { class: "state-tag " + status, text: status })),
      el("td", { text: fmtTime(s.started_at || s.created_at) }),
      el("td", {}, el("button", { class: "btn btn-sm", text: "View", onClick: () => selectAgentSession(s.id) })),
    ]));
  }
  if (state.agentSessionSelected && !sessions.some((s) => s.id === state.agentSessionSelected)) {
    stopAgentStream();
    state.agentSessionSelected = null;
    $("#agent-transcript").classList.add("hidden");
  }
}

async function selectAgentSession(id) {
  stopAgentStream();
  state.agentSessionSelected = id;
  state.agentEvents = [];
  state.agentLastSeq = 0;
  renderAgentSessions();
  $("#agent-transcript").classList.remove("hidden");
  $("#agent-transcript-id").textContent = id;
  $("#agent-transcript-output").textContent = "";
  setAgentTranscriptStatus("conn-off", "loading…");
  try {
    const { data } = await api("GET", `/v1/agent-sessions/${encodeURIComponent(id)}/events?after=0`);
    appendAgentEvents((data && data.events) || []);
    const session = (data && data.session) || {};
    if (agentSessionTerminal(session.status)) {
      setAgentTranscriptStatus(session.status === "completed" ? "conn-on" : "conn-err", session.status || "finished");
    } else {
      startAgentStream(id, state.agentLastSeq);
    }
  } catch (e) {
    setAgentTranscriptStatus("conn-err", "error");
    toast("Transcript read failed: " + e.message, "error", undefined, e);
  }
}

function appendAgentEvents(events) {
  const out = $("#agent-transcript-output");
  if (!out) return;
  for (const ev of events) {
    if (!ev || Number(ev.seq || 0) <= state.agentLastSeq) continue;
    state.agentLastSeq = Number(ev.seq || state.agentLastSeq);
    state.agentEvents.push(ev);
    if (ev.stream === "status") {
      out.textContent += `\n[Rune Box] ${ev.data}\n`;
      const terminal = agentSessionTerminal(ev.data);
      setAgentTranscriptStatus(terminal && ev.data !== "completed" ? "conn-err" : "conn-on", ev.data);
    } else {
      const prefix = ev.stream === "stderr" ? "[stderr] " : "";
      out.textContent += prefix + String(ev.data || "");
    }
  }
  out.scrollTop = out.scrollHeight;
}

function setAgentTranscriptStatus(kind, label) {
  const node = $("#agent-transcript-status");
  if (!node) return;
  node.className = "conn-status " + kind;
  node.textContent = label;
}

function agentSessionTerminal(status) {
  return ["completed", "failed", "denied", "canceled", "interrupted"].includes(String(status || ""));
}

function stopAgentStream() {
  if (state.agentStreamAbort) {
    state.agentStreamAbort.abort();
    state.agentStreamAbort = null;
  }
}

async function startAgentStream(id, after) {
  stopAgentStream();
  const controller = new AbortController();
  state.agentStreamAbort = controller;
  setAgentTranscriptStatus("conn-on", "live");
  const headers = { Accept: "text/event-stream" };
  if (auth.token) headers.Authorization = "Bearer " + auth.token;
  try {
    const res = await fetch(`/v1/agent-sessions/${encodeURIComponent(id)}/stream?after=${Number(after || 0)}`, {
      headers,
      signal: controller.signal,
    });
    if (!res.ok || !res.body) throw new Error(`HTTP ${res.status}`);
    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      let boundary;
      while ((boundary = buffer.indexOf("\n\n")) >= 0) {
        const block = buffer.slice(0, boundary);
        buffer = buffer.slice(boundary + 2);
        const dataLines = block.split("\n").filter((line) => line.startsWith("data:")).map((line) => line.slice(5).trimStart());
        if (!dataLines.length) continue;
        try { appendAgentEvents([JSON.parse(dataLines.join("\n"))]); } catch {}
      }
    }
  } catch (e) {
    if (e.name !== "AbortError") {
      setAgentTranscriptStatus("conn-err", "disconnected");
    }
  } finally {
    if (state.agentStreamAbort === controller) state.agentStreamAbort = null;
    if (!controller.signal.aborted && state.agentSessionSelected === id) {
      try {
        const { data } = await api("GET", `/v1/agent-sessions/${encodeURIComponent(id)}`);
        setAgentTranscriptStatus(data.status === "completed" ? "conn-on" : "conn-err", data.status || "disconnected");
      } catch {}
      refreshFleetDetail();
    }
  }
}

async function addFleetTask() {
  if (!state.fleetSelected) return;
  const input = $("#fleet-task-payload");
  const payload = input.value.trim();
  if (!payload) {
    toast("Enter a task payload.", "warn");
    return;
  }
  const btn = $("#fleet-add-task");
  btn.disabled = true;
  try {
    await api("POST", fleetPath("/tasks"), { payload });
    input.value = "";
    toast("Task added", "success");
    await refreshFleetDetail();
  } catch (e) {
    toast("Add task failed: " + e.message, "error", undefined, e);
  } finally {
    btn.disabled = false;
  }
}

async function claimFleetTask() {
  if (!state.fleetSelected) return;
  const owner = $("#fleet-claim-owner").value.trim() || "operator";
  const note = $("#fleet-claim-note");
  const btn = $("#fleet-claim");
  btn.disabled = true;
  try {
    const { data } = await api("POST", fleetPath("/claim"), { owner });
    note.classList.remove("hidden");
    if (data && data.claimed && data.task) {
      note.className = "note ok";
	  state.taskLeases[data.task.id] = data.task.lease_token;
      const authoritativeOwner = data.task.owner || data.owner || owner;
      note.textContent = `Claimed ${data.task.id} by ${authoritativeOwner}: ${data.task.payload || ""}`;
      toast(`Task claimed by ${authoritativeOwner}`, "success");
    } else {
      note.className = "note";
      note.textContent = "No pending tasks to claim.";
    }
    await refreshFleetDetail();
  } catch (e) {
    toast("Claim failed: " + e.message, "error", undefined, e);
  } finally {
    btn.disabled = false;
  }
}

async function completeFleetTask(taskId, owner) {
  openTaskResolutionModal("complete", taskId, owner, false);
}

async function failFleetTask(taskId, owner, requeue) {
  openTaskResolutionModal("fail", taskId, owner, requeue);
}

function openTaskResolutionModal(mode, taskId, owner, requeue) {
  state.taskResolution = { mode, taskId, owner, requeue: !!requeue };
  $("#task-modal-title").textContent = mode === "complete" ? "Complete task" : "Fail task";
  $("#task-modal-label").textContent = mode === "complete" ? "Result" : "Failure reason";
  $("#task-modal-value").value = mode === "complete" ? "ok" : "error";
  $("#task-modal-submit").textContent = mode === "complete" ? "Complete" : (requeue ? "Fail and requeue" : "Fail");
  $("#task-modal").classList.remove("hidden");
  $("#task-modal-value").focus();
  $("#task-modal-value").select();
}

function closeTaskResolutionModal() {
  $("#task-modal").classList.add("hidden");
  state.taskResolution = null;
}

async function submitTaskResolution() {
  const pending = state.taskResolution;
  if (!pending) return;
  const value = $("#task-modal-value").value.trim();
  if (!value) {
    toast(pending.mode === "complete" ? "Enter a result." : "Enter a failure reason.", "warn");
    return;
  }
  const button = $("#task-modal-submit");
  button.disabled = true;
  try {
	const suffix = pending.mode === "complete" ? "complete" : "fail";
	const body = {
	  owner: pending.owner,
	  lease_token: state.taskLeases[pending.taskId],
	};
	if (pending.mode === "complete") body.result = value;
	else {
	  body.error = value;
	  body.requeue = pending.requeue;
	}
	await api("POST", fleetPath(`/tasks/${encodeURIComponent(pending.taskId)}/${suffix}`), body);
	delete state.taskLeases[pending.taskId];
	closeTaskResolutionModal();
	toast(pending.mode === "complete" ? "Task completed" : (pending.requeue ? "Task failed — requeued" : "Task failed"), pending.mode === "complete" ? "success" : "info");
    await refreshFleetDetail();
  } catch (e) {
    toast((pending.mode === "complete" ? "Complete" : "Fail") + " failed: " + e.message, "error", undefined, e);
  } finally {
    button.disabled = false;
  }
}

/* ---------------- Tabs ---------------- */
function activateTab(name, force = false) {
  if (!force && name === state.activeTab) return;
  state.activeTab = name;
  $$(".tab").forEach((t) => {
    const active = t.dataset.tab === name;
    t.classList.toggle("active", active);
    t.setAttribute("aria-selected", String(active));
    t.tabIndex = active ? 0 : -1;
  });
  $$(".tab-pane").forEach((p) => {
    const active = p.dataset.pane === name;
    p.classList.toggle("active", active);
    p.hidden = !active;
  });

  stopAuditPoll();

  if (name === "terminal") {
    ensureTerminal();
    connectTerminal();
  } else {
    // only keep the socket alive while the terminal tab is visible
    teardownTerminalSocket();
  }

  if (name === "conversation") {
    ensureConversationTTY();
    connectConversation();
  } else {
    teardownConversationSocket();
  }

  if (name === "audit") {
    refreshAudit();
    startAuditPoll();
  }
  if (name === "policy") {
    renderSimulationResults();
  }
  if (name === "egress") {
    refreshEgress();
  }
  if (name === "budget") {
    refreshBudget();
  }
	if (name === "recovery") {
		refreshRecovery();
	}
  if (name === "schedules") {
    renderSandboxSchedules();
    refreshSandboxSchedules();
  }
}

function enableArrowKeyTabs(selector) {
  $$(selector).forEach((tab) => {
    tab.addEventListener("keydown", (event) => {
      if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
      const tabs = $$(selector).filter((candidate) => !candidate.classList.contains("hidden"));
      const current = tabs.indexOf(tab);
      if (current < 0) return;
      event.preventDefault();
      let next = current;
      if (event.key === "Home") next = 0;
      else if (event.key === "End") next = tabs.length - 1;
      else if (event.key === "ArrowRight") next = (current + 1) % tabs.length;
      else next = (current - 1 + tabs.length) % tabs.length;
      tabs[next].focus();
      tabs[next].click();
    });
  });
}

/* ---------------- Terminal (xterm.js + WebSocket) ---------------- */
function ensureTerminal() {
  if (state.term) return;
  if (typeof Terminal === "undefined") {
    toast("xterm.js failed to load (offline CDN?)", "error");
    return;
  }
  const term = new Terminal({
    convertEol: true,
    cursorBlink: true,
    fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace',
    fontSize: 13,
    theme: {
      background: "#05070d",
      foreground: "#dde3ee",
      cursor: "#5b8cff",
      selectionBackground: "#2b3550",
    },
  });
  let fit = null;
  if (typeof FitAddon !== "undefined" && FitAddon.FitAddon) {
    fit = new FitAddon.FitAddon();
    term.loadAddon(fit);
  }
  term.open($("#terminal"));
  if (fit) {
    try { fit.fit(); } catch {}
  }
  term.onData((d) => {
    if (state.socket && state.socket.readyState === WebSocket.OPEN) {
      state.socket.send(d);
    }
  });
  state.term = term;
  state.fitAddon = fit;

  window.addEventListener("resize", debounce(fitAndResize, 120));
  $("#term-reconnect").addEventListener("click", () => connectTerminal(true));
  const openIdeBtn = $("#open-ide");
  if (openIdeBtn) openIdeBtn.addEventListener("click", openIDE);
}

function fitAndResize() {
  if (!state.term || !state.fitAddon) return;
  try { state.fitAddon.fit(); } catch { return; }
  sendResize();
}

function sendResize() {
  if (!state.term) return;
  if (state.socket && state.socket.readyState === WebSocket.OPEN) {
    const msg = { type: "resize", rows: state.term.rows, cols: state.term.cols };
    state.socket.send(JSON.stringify(msg));
  }
}

function setTermStatus(kind, label) {
  const s = $("#term-status");
  s.className = "conn-status " + kind;
  s.textContent = label;
}

function teardownTerminalSocket() {
  if (state.socket) {
    try { state.socket.close(); } catch {}
    state.socket = null;
  }
  state.termSandbox = null;
  setTermStatus("conn-off", "disconnected");
}

function connectTerminal(forceReconnect = false) {
  if (!state.selected || !state.term) return;
  // Already connected to the right sandbox?
  if (
    !forceReconnect &&
    state.socket &&
    state.termSandbox === state.selected &&
    (state.socket.readyState === WebSocket.OPEN || state.socket.readyState === WebSocket.CONNECTING)
  ) {
    return;
  }
  teardownTerminalSocket();
	const sandboxID = state.selected;

  const proto = location.protocol === "https:" ? "wss:" : "ws:";
  setTermStatus("conn-off", "connecting…");
  requestTerminalTicket(sandboxID)
    .then((ticket) => {
	  if (state.selected !== sandboxID) return;
      const url =
		`${proto}//${location.host}/v1/citadels/${encodeURIComponent(sandboxID)}/terminal` +
        `?ticket=${encodeURIComponent(ticket)}`;
      const socket = new WebSocket(url);
      socket.binaryType = "arraybuffer";
      state.socket = socket;
      state.termSandbox = sandboxID;

      socket.onopen = () => {
        setTermStatus("conn-on", "connected");
        fitAndResize();
        state.term.focus();
      };
      socket.onmessage = (ev) => {
		if (state.socket !== socket || state.selected !== sandboxID) return;
        if (typeof ev.data === "string") {
          state.term.write(ev.data);
        } else if (ev.data instanceof ArrayBuffer) {
          state.term.write(new Uint8Array(ev.data));
        } else if (ev.data instanceof Blob) {
          ev.data.arrayBuffer().then((buf) => state.term.write(new Uint8Array(buf)));
        }
      };
      socket.onerror = () => {
        setTermStatus("conn-err", "error");
      };
      socket.onclose = () => {
        if (state.socket === socket) {
          setTermStatus("conn-off", "disconnected");
          state.socket = null;
        }
      };
    })
    .catch((e) => {
      setTermStatus("conn-err", "error");
      toast("Terminal connect failed: " + e.message, "error", undefined, e);
    });
}

async function requestTerminalTicket(sandboxID) {
  const { data } = await api("POST", "/v1/tickets", {
    kind: "terminal",
    sandbox_id: sandboxID,
    ttl_seconds: 30,
  });
  if (!data || !data.ticket) {
    throw new Error("terminal ticket unavailable");
  }
  return data.ticket;
}

/* ---------------- Live chat (read-only xterm.js + WebSocket) ---------------- */
function ensureConversationTTY() {
  if (state.conversationTerm) return;
  if (typeof Terminal === "undefined") {
    toast("xterm.js failed to load (offline CDN?)", "error");
    return;
  }
  const term = new Terminal({
    convertEol: true,
    cursorBlink: false,
    disableStdin: true,
    screenReaderMode: true,
    fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace',
    fontSize: 13,
    scrollback: 5000,
    theme: {
      background: "#05070d",
      foreground: "#dde3ee",
      cursor: "#05070d",
      selectionBackground: "#2b3550",
    },
  });
  let fit = null;
  if (typeof FitAddon !== "undefined" && FitAddon.FitAddon) {
    fit = new FitAddon.FitAddon();
    term.loadAddon(fit);
  }
  term.open($("#conversation-terminal"));
  state.conversationTerm = term;
  state.conversationFitAddon = fit;
  window.addEventListener("resize", debounce(fitConversationTTY, 120));
  $("#conversation-reconnect").addEventListener("click", () => connectConversation(true));
  fitConversationTTY();
}

function fitConversationTTY() {
  if (!state.conversationTerm || !state.conversationFitAddon) return;
  try { state.conversationFitAddon.fit(); } catch {}
}

function setConversationStatus(kind, label) {
  const node = $("#conversation-status");
  if (!node) return;
  node.className = "conn-status " + kind;
  node.textContent = label;
}

function teardownConversationSocket() {
  if (state.conversationReconnectTimer) {
    clearTimeout(state.conversationReconnectTimer);
    state.conversationReconnectTimer = null;
  }
  if (state.conversationSocket) {
    try { state.conversationSocket.close(); } catch {}
    state.conversationSocket = null;
  }
  state.conversationSandbox = null;
  setConversationStatus("conn-off", "disconnected");
}

function scheduleConversationReconnect(sandboxID) {
  if (state.conversationReconnectTimer || state.selected !== sandboxID || state.activeTab !== "conversation") return;
  setConversationStatus("conn-off", "reconnecting…");
  state.conversationReconnectTimer = setTimeout(() => {
    state.conversationReconnectTimer = null;
    connectConversation();
  }, 1500);
}

function conversationColor(role) {
  if (role === "user") return "\x1b[36m";
  if (role === "assistant") return "\x1b[32m";
  if (role === "tool") return "\x1b[33m";
  return "\x1b[35m";
}

function renderConversationTurn(msg) {
  const term = state.conversationTerm;
  if (!term || !msg) return;
  const role = String(msg.role || "system").toLowerCase();
  const author = String(msg.author || role);
  const when = fmtTime(msg.created_at);
  const redacted = msg.redacted ? " · redacted" : "";
  term.write(`${conversationColor(role)}[${when}] ${role} · ${author}${redacted}\x1b[0m\r\n`);
  term.write(String(msg.content || "").replace(/\r?\n/g, "\r\n"));
  term.write("\r\n\r\n");
}

function connectConversation(forceReconnect = false) {
  if (!state.selected || !state.conversationTerm) return;
  if (
    !forceReconnect &&
    state.conversationSocket &&
    state.conversationSandbox === state.selected &&
    (state.conversationSocket.readyState === WebSocket.OPEN || state.conversationSocket.readyState === WebSocket.CONNECTING)
  ) return;

  teardownConversationSocket();
  const sandboxID = state.selected;
  state.conversationTerm.reset();
  state.conversationTerm.writeln("\x1b[90m[Rune Box] waiting for published conversation turns…\x1b[0m");
  const proto = location.protocol === "https:" ? "wss:" : "ws:";
  setConversationStatus("conn-off", "connecting…");
  requestConversationTicket(sandboxID)
    .then((ticket) => {
      if (state.selected !== sandboxID || state.activeTab !== "conversation") return;
      const url = `${proto}//${location.host}/v1/citadels/${encodeURIComponent(sandboxID)}/conversation/stream?ticket=${encodeURIComponent(ticket)}`;
      const socket = new WebSocket(url);
      state.conversationSocket = socket;
      state.conversationSandbox = sandboxID;
      socket.onopen = () => {
        if (state.conversationSocket !== socket) return;
        state.conversationTerm.reset();
        state.conversationTerm.writeln("\x1b[90m[Rune Box] connected; waiting for an agent to publish conversation turns…\x1b[0m");
        setConversationStatus("conn-on", "live · waiting");
        fitConversationTTY();
      };
      socket.onmessage = (ev) => {
        if (state.conversationSocket !== socket || state.selected !== sandboxID) return;
        try {
          setConversationStatus("conn-on", "following live");
          renderConversationTurn(JSON.parse(ev.data));
        } catch {}
      };
      socket.onerror = () => setConversationStatus("conn-err", "error");
      socket.onclose = () => {
        if (state.conversationSocket === socket) {
          state.conversationSocket = null;
          state.conversationSandbox = null;
          scheduleConversationReconnect(sandboxID);
        }
      };
    })
    .catch((e) => {
      if (state.selected !== sandboxID || state.activeTab !== "conversation") return;
      console.warn("Live chat connect failed:", e);
      scheduleConversationReconnect(sandboxID);
    });
}

async function requestConversationTicket(sandboxID) {
  const { data } = await api("POST", "/v1/tickets", {
    kind: "conversation",
    sandbox_id: sandboxID,
    ttl_seconds: 30,
  });
  if (!data || !data.ticket) throw new Error("conversation ticket unavailable");
  return data.ticket;
}

async function openIDE() {
  if (!state.selected) return;
  const sb = state.sandboxes.find((s) => s.id === state.selected) || {};
  if (!sb.ide) {
    toast("Browser IDE is not available for this Citadel.", "warn");
    return;
  }
  try {
    const { data } = await api("POST", "/v1/tickets", {
      kind: "ide",
      sandbox_id: state.selected,
      ttl_seconds: 30,
    });
    if (!data || !data.ticket) {
      throw new Error("ide ticket unavailable");
    }
    const url =
      `/v1/citadels/${encodeURIComponent(state.selected)}/ide` +
      `?ticket=${encodeURIComponent(data.ticket)}`;
    const link = $("#ide-link");
    link.href = url;
    link.classList.remove("hidden");
    const opened = window.open(url, "_blank");
    if (opened) opened.opener = null;
    if (!opened) toast("The browser blocked the new tab. Use the prepared IDE link.", "warn");
  } catch (e) {
    toast("Open IDE failed: " + e.message, "error", undefined, e);
  }
}

/* ---------------- Files tab ---------------- */
function sbPath(suffix) {
  return `/v1/citadels/${encodeURIComponent(state.selected)}${suffix}`;
}

async function fileList() {
  if (!state.selected) return;
  const path = $("#list-path").value || ".";
  const out = $("#list-output");
  out.textContent = "…";
  try {
    const { data } = await api("POST", sbPath("/file/list"), { path });
    out.textContent = data.output || "(empty)";
  } catch (e) {
    out.textContent = "";
    toast("List failed: " + e.message, "error", undefined, e);
  }
}

async function fileRead() {
  if (!state.selected) return;
  const path = $("#file-path").value.trim();
  const note = $("#file-note");
  if (!path) { toast("Enter a file path.", "warn"); return; }
  try {
    const { data } = await api("POST", sbPath("/file/read"), { path });
    $("#file-content").value = data.content != null ? data.content : "";
    note.className = "note ok";
    note.textContent = `Loaded ${path}`;
  } catch (e) {
    note.className = "note err";
    note.textContent = "Read failed: " + e.message;
  }
}

async function fileWrite() {
  if (!state.selected) return;
  const path = $("#file-path").value.trim();
  const content = $("#file-content").value;
  const note = $("#file-note");
  if (!path) { toast("Enter a file path.", "warn"); return; }
  try {
    const { data } = await api("POST", sbPath("/file/write"), { path, content });
    note.className = "note ok";
    note.textContent = `Wrote ${data.bytes != null ? data.bytes : content.length} bytes to ${path}`;
  } catch (e) {
    note.className = "note err";
    note.textContent = "Write failed: " + e.message;
  }
}

async function fileSearch() {
  if (!state.selected) return;
  const query = $("#search-query").value;
  const path = $("#search-path").value || ".";
  const out = $("#search-output");
  if (!query) { toast("Enter a search query.", "warn"); return; }
  out.textContent = "…";
  try {
    const { data } = await api("POST", sbPath("/file/search"), { query, path });
    out.textContent = data.output || "(no matches)";
  } catch (e) {
    out.textContent = "";
    toast("Search failed: " + e.message, "error", undefined, e);
  }
}

/* ---------------- Shell / code exec ---------------- */
function renderExecResult(prefix, status, data) {
  $(`#${prefix}-result`).classList.remove("hidden");
  const verdictEl = $(`#${prefix}-verdict`);
  const exitEl = $(`#${prefix}-exit`);
  const durEl = $(`#${prefix}-duration`);
  const noteEl = $(`#${prefix}-note`);
  const outEl = $(`#${prefix}-stdout`);
  const errEl = $(`#${prefix}-stderr`);

  noteEl.className = "note hidden";
  noteEl.textContent = "";

  const verdict = data.verdict || (status === 202 ? "require-approval" : status === 403 ? "deny" : "allow");
  verdictEl.className = "verdict " + verdict;
  verdictEl.textContent = verdict;

  if (status === 202 || verdict === "require-approval") {
    exitEl.textContent = "";
    durEl.textContent = "";
    outEl.textContent = "";
    errEl.textContent = "";
    noteEl.className = "note warn";
    noteEl.textContent =
      "Action requires approval" +
      (data.approval_id ? ` (id ${data.approval_id})` : "") +
      ". Open the Approvals panel to allow or deny it.";
    refreshApprovals();
    return;
  }
  if (status === 403 || verdict === "deny") {
    exitEl.textContent = "";
    durEl.textContent = "";
    outEl.textContent = "";
    errEl.textContent = "";
    noteEl.className = "note err";
    noteEl.textContent = "Denied by policy: " + (data.reason || "no reason given");
    return;
  }

  exitEl.textContent = "exit " + (data.exit_code != null ? data.exit_code : "?");
  durEl.textContent = data.duration_ms != null ? data.duration_ms + " ms" : "";
  outEl.textContent = data.stdout || "";
  errEl.textContent = data.stderr || "";
}

async function runShell() {
  if (!state.selected) return;
  const raw = $("#shell-cmd").value.trim();
  const workdir = $("#shell-workdir").value.trim();
  if (!raw) { toast("Enter a command.", "warn"); return; }
  const command = tokenize(raw);
  const btn = $("#shell-run");
  btn.disabled = true;
  try {
    const { status, data } = await api("POST", sbPath("/shell/exec"), { command, workdir });
    renderExecResult("shell", status, data);
  } catch (e) {
    if (e instanceof ApiError && (e.status === 403 || e.status === 202)) {
      renderExecResult("shell", e.status, e.body);
    } else {
      renderExecResult("shell", 500, { verdict: "deny", reason: e.message, stderr: e.message });
      toast("Exec failed: " + e.message, "error", undefined, e);
    }
  } finally {
    btn.disabled = false;
  }
}

async function runCode() {
  if (!state.selected) return;
  const lang = $("#code-lang").value;
  const code = $("#code-source").value;
  if (!code.trim()) { toast("Enter some code.", "warn"); return; }
  const btn = $("#code-run");
  btn.disabled = true;
  try {
    const { status, data } = await api("POST", sbPath("/code/" + lang), { code });
    renderExecResult("code", status, data);
  } catch (e) {
    if (e instanceof ApiError && (e.status === 403 || e.status === 202)) {
      renderExecResult("code", e.status, e.body);
    } else {
      renderExecResult("code", 500, { verdict: "deny", reason: e.message, stderr: e.message });
      toast("Code exec failed: " + e.message, "error", undefined, e);
    }
  } finally {
    btn.disabled = false;
  }
}

async function runBrowser() {
  if (!state.selected) return;
  const url = $("#browser-url").value.trim();
  const mode = $("#browser-mode").value;
  if (!url) { toast("Enter a URL.", "warn"); return; }
  const button = $("#browser-run");
  const screenshot = $("#browser-screenshot");
  button.disabled = true;
  screenshot.removeAttribute("src");
  screenshot.classList.add("hidden");
  try {
    const { status, data } = await api("POST", sbPath("/browser"), { url, mode });
    renderExecResult("browser", status, data);
    if (mode === "screenshot" && data.stdout && data.verdict === "allow" && data.exit_code === 0) {
      $("#browser-stdout").textContent = "";
      screenshot.src = "data:image/png;base64," + data.stdout.replace(/\s/g, "");
      screenshot.classList.remove("hidden");
    }
    refreshEgress();
  } catch (e) {
    if (e instanceof ApiError && (e.status === 403 || e.status === 202)) {
      renderExecResult("browser", e.status, e.body);
    } else {
      renderExecResult("browser", 500, { verdict: "deny", reason: e.message, stderr: e.message });
      toast("Browser action failed: " + e.message, "error", undefined, e);
    }
  } finally {
    button.disabled = false;
  }
}

// Minimal shell-ish tokenizer: splits on whitespace, respects single/double quotes.
function tokenize(str) {
  const out = [];
  const re = /"([^"]*)"|'([^']*)'|(\S+)/g;
  let m;
  while ((m = re.exec(str)) !== null) {
    out.push(m[1] !== undefined ? m[1] : m[2] !== undefined ? m[2] : m[3]);
  }
  return out.length ? out : [str];
}

/* ---------------- Audit tab ---------------- */
async function refreshAudit() {
  if (!state.selected) return;
  const body = $("#audit-body");
  try {
    const { data } = await api("GET", sbPath("/chronicle"));
    const events = (data && data.events) || [];
    if (events.length === 0) {
      body.innerHTML = "";
      body.appendChild(
        el("tr", {}, el("td", { colspan: "6", class: "empty-note", text: "No events yet." }))
      );
      return;
    }
    body.innerHTML = "";
    for (const ev of events) {
      const verdict = (ev.verdict || "").toLowerCase();
      body.appendChild(
        el("tr", {}, [
          el("td", { text: String(ev.seq != null ? ev.seq : "") }),
          el("td", { text: fmtTime(ev.time) }),
          el("td", { text: ev.tool || "" }),
          el("td", { text: ev.action || "", title: ev.action || "" }),
          el("td", {}, el("span", { class: "v-tag " + verdict, text: verdict || "—" })),
          el("td", { text: ev.exit_code != null ? String(ev.exit_code) : "" }),
        ])
      );
    }
  } catch (e) {
    // leave prior contents; only toast on manual
  }
}

function startAuditPoll() {
  stopAuditPoll();
  state.timers.audit = setInterval(refreshAudit, POLL_MS);
}
function stopAuditPoll() {
  if (state.timers.audit) {
    clearInterval(state.timers.audit);
    state.timers.audit = null;
  }
}

/* ---------------- Approvals ---------------- */
async function refreshApprovals() {
  try {
    const { data } = await api("GET", "/v1/conclave");
    state.approvals = (data && data.approvals) || [];
  } catch {
    state.approvals = state.approvals || [];
  }
  renderApprovals();
}

function renderApprovals() {
  const n = state.approvals.length;
  const countEl = $("#approvals-count");
  countEl.textContent = String(n);
  countEl.classList.toggle("hidden", n === 0);

  const list = $("#approvals-list");
  list.innerHTML = "";
  if (n === 0) {
    list.appendChild(el("li", { class: "empty-note", text: "No pending approvals." }));
    return;
  }
  for (const a of state.approvals) {
    list.appendChild(
      el("li", { class: "approval-item" }, [
        el("div", { class: "approval-head" }, [
          el("span", { class: "approval-tool", text: a.tool || "action" }),
          el("span", { class: "muted mono", text: a.sandbox || "" }),
        ]),
        el("div", { class: "approval-action", text: a.action || "" }),
        a.reason ? el("div", { class: "approval-reason", text: a.reason }) : null,
        el("div", { class: "approval-meta", text: `requested ${fmtTime(a.created)}` }),
        canApprove()
          ? el("div", { class: "approval-actions" }, [
              el("button", {
                class: "btn btn-sm btn-approve",
                text: "Approve",
                onClick: () => decideApproval(a.id, "approve"),
              }),
              el("button", {
                class: "btn btn-sm btn-deny",
                text: "Deny",
                onClick: () => decideApproval(a.id, "deny"),
              }),
            ])
          : el("div", { class: "approval-meta", text: "You do not have permission to resolve approvals." }),
      ])
    );
  }
}

async function decideApproval(id, decision) {
  try {
    await api("POST", `/v1/conclave/${encodeURIComponent(id)}/${decision}`);
    toast(`Approval ${decision === "approve" ? "approved" : "denied"}`, decision === "approve" ? "success" : "info");
    await refreshApprovals();
  } catch (e) {
    toast("Failed to " + decision + ": " + e.message, "error", undefined, e);
  }
}

function openDrawer() { $("#approvals-drawer").classList.remove("hidden"); refreshApprovals(); }
function closeDrawer() { $("#approvals-drawer").classList.add("hidden"); }

/* ---------------- Policy simulation ---------------- */
function parseSimulationActions(text) {
  const out = [];
  const lines = String(text || "").split(/\r?\n/);
  for (const line of lines) {
    const raw = line.trim();
    if (!raw || raw.startsWith("#")) continue;
    const parts = raw.split("|");
    if (parts.length < 2) {
      throw new Error(`invalid action line: "${raw}" (use "tool | action")`);
    }
    const tool = parts[0].trim();
    const action = parts.slice(1).join("|").trim();
    if (!tool || !action) {
      throw new Error(`invalid action line: "${raw}"`);
    }
    out.push({ tool, command: action, args: tokenize(action) });
  }
  return out;
}

async function runPolicySimulation() {
  const note = $("#sim-note");
  note.className = "note";
  note.textContent = "";
  if (!state.selected) {
    note.className = "note warn";
    note.textContent = "Select a sandbox first.";
    return;
  }
  const raw = $("#sim-actions").value;
  let actions;
  try {
    actions = parseSimulationActions(raw);
  } catch (e) {
    note.className = "note err";
    note.textContent = e.message;
    return;
  }
  if (!actions.length) {
    note.className = "note warn";
    note.textContent = "Add one or more sample actions.";
    return;
  }
  const useSelected = $("#sim-use-selected-profile").checked;
  const selectedSB = state.sandboxes.find((s) => s.id === state.selected) || {};
  const profileName = useSelected ? (selectedSB.profile || "") : ($("#sim-profile-select").value || "");
  if (!profileName) {
    note.className = "note warn";
    note.textContent = "Pick a policy to simulate.";
    return;
  }
  const btn = $("#sim-run");
  btn.disabled = true;
  try {
    const { data } = await api("POST", "/v1/policy/simulate", {
      profile_name: profileName,
      actions,
    });
    state.simulation = data || {};
    renderSimulationResults();
    note.className = "note ok";
    note.textContent = `Simulated ${actions.length} action${actions.length === 1 ? "" : "s"} against ${profileName}.`;
  } catch (e) {
    note.className = "note err";
    note.textContent = "Simulation failed: " + e.message;
  } finally {
    btn.disabled = false;
  }
}

function renderSimulationResults() {
  const wrap = $("#sim-results");
  if (!wrap) return;
  wrap.innerHTML = "";
  const results = (state.simulation && state.simulation.results) || [];
  if (!results.length) {
    wrap.className = "sim-results empty-note";
    wrap.textContent = "Run a simulation to see verdicts and trace.";
    return;
  }
  wrap.className = "sim-results";
  for (const r of results) {
    const verdict = String(r.verdict || "allow");
    const title = r.name || `${r.tool || "action"} ${r.arg || ""}`.trim();
    const trace = Array.isArray(r.trace) ? r.trace : [];
    const traceText = trace.map((step) => {
      const idx = step.index != null ? `#${step.index}` : "";
      const engine = step.engine || "";
      const match = step.matched ? "match" : "skip";
      const summary = step.expr || step.match || step.query || step.tool || "";
      return `${idx} ${engine} ${match} ${summary}`.trim();
    }).join("\n");
    wrap.appendChild(
      el("div", { class: "sim-item" }, [
        el("div", { class: "sim-head" }, [
          el("span", { class: "mono", text: title }),
          el("span", { class: "verdict " + verdict, text: verdict }),
        ]),
        r.reason ? el("div", { class: "note " + (verdict === "deny" ? "err" : "warn"), text: r.reason }) : null,
        traceText ? el("div", { class: "sim-trace", text: traceText }) : null,
      ])
    );
  }
}

/* ---------------- Egress explorer ---------------- */
async function refreshEgress() {
  if (!state.selected) return;
  try {
    const { data } = await api("GET", sbPath("/perimeter"));
    state.egress = (data && data.decisions) || [];
  } catch (e) {
    state.egress = [];
  }
  renderEgress();
}

function renderEgress() {
  const body = $("#egress-body");
  if (!body) return;
  body.innerHTML = "";
  if (!state.selected) {
    body.appendChild(el("tr", {}, el("td", { colspan: "7", class: "empty-note", text: "Select a sandbox first." })));
    return;
  }
  if (!state.egress.length) {
    body.appendChild(el("tr", {}, el("td", { colspan: "7", class: "empty-note", text: "No decisions yet." })));
    return;
  }
  for (const d of state.egress.slice().reverse()) {
    // Broker decisions carry a verdict (incl. require-approval); plain L4
    // decisions only allow/deny.
    const verdict = d.verdict || (d.allow ? "allow" : "deny");
    const request = [d.method, d.path].filter(Boolean).join(" ");
    const endpoint = [d.endpoint, d.protocol ? `(${d.protocol})` : ""].filter(Boolean).join(" ");
    body.appendChild(el("tr", {}, [
      el("td", { text: fmtTime(d.timestamp || d.time) }),
      el("td", { title: [d.host, d.ip].filter(Boolean).join(" · ") }, [
        el("div", { text: d.host || "—" }),
        d.ip ? el("div", { class: "cell-sub", text: d.ip }) : null,
      ]),
      el("td", {}, [
        el("div", { text: endpoint || "—" }),
        d.credential ? el("div", { class: "cell-sub", title: "Credential attached by the broker (name only)", text: "credential: " + d.credential }) : null,
      ]),
      el("td", { title: request }, [
        el("div", { text: request || "—" }),
        d.tool ? el("div", { class: "cell-sub", text: "tool: " + d.tool }) : null,
      ]),
      el("td", {}, d.effect ? el("span", { class: "effect-tag " + d.effect, text: d.effect }) : "—"),
      el("td", {}, el("span", { class: "verdict-cell " + verdict, text: verdict })),
      el("td", { title: [d.rule, d.reason].filter(Boolean).join(" · ") }, [
        d.reason_code ? el("span", { class: "reason-code", text: d.reason_code }) : null,
        el("span", { text: d.reason || "" }),
      ]),
    ]));
  }
}

/* ---------------- Budget burn-down ---------------- */
async function refreshBudget() {
  if (!state.selected) return;
  try {
    const [sbRes, auditRes] = await Promise.all([
      api("GET", sbPath("")),
      api("GET", sbPath("/chronicle")),
    ]);
    state.budget = deriveBudget(sbRes.data || {}, (auditRes.data && auditRes.data.events) || []);
  } catch (e) {
    state.budget = null;
  }
  renderBudget();
}

function deriveBudget(sb, events) {
  const limits = sb.limits || {};
  const usage = sb.usage || {};
  const execCount = events.filter((ev) => ev.tool && ev.tool !== "approval" && ev.tool !== "usage").length;
  const egressCount = events.filter((ev) => ev.tool === "browser" || ev.tool === "net").length;
  let wallSeconds = 0;
  if (events.length > 1) {
    const times = events
      .map((ev) => new Date(ev.time).getTime())
      .filter((v) => Number.isFinite(v))
      .sort((a, b) => a - b);
    if (times.length > 1) {
      wallSeconds = Math.max(0, Math.floor((times[times.length - 1] - times[0]) / 1000));
    }
  }
  return {
    usage: {
      tokens: usage.tokens || 0,
      cost_usd: usage.cost_usd || 0,
      execs: execCount,
      egress_requests: egressCount,
      wall_seconds: wallSeconds,
    },
    limits: {
      max_tokens: limits.max_tokens || 0,
      max_cost_usd: limits.max_cost_usd || 0,
      max_execs: limits.max_execs || 0,
      egress_requests: limits.egress_requests || 0,
      wall_clock: limits.wall_clock || "",
    },
  };
}

function parseDurationSeconds(raw) {
  const s = String(raw || "").trim();
  if (!s) return 0;
  let total = 0;
  const re = /(\d+)(h|m|s)/g;
  let m;
  while ((m = re.exec(s)) !== null) {
    const n = Number(m[1]);
    if (m[2] === "h") total += n * 3600;
    else if (m[2] === "m") total += n * 60;
    else total += n;
  }
  return total;
}

function money(v) {
  return "$" + Number(v || 0).toFixed(4);
}

function renderBudget() {
  const grid = $("#budget-grid");
  if (!grid) return;
  grid.innerHTML = "";
  if (!state.selected) {
    grid.appendChild(el("div", { class: "empty-note", text: "Select a sandbox first." }));
    return;
  }
  if (!state.budget) {
    grid.appendChild(el("div", { class: "empty-note", text: "Budget usage unavailable." }));
    return;
  }
  const u = state.budget.usage;
  const lim = state.budget.limits;
  const rows = [
    { label: "Tokens", used: u.tokens, limit: lim.max_tokens, usedLabel: String(u.tokens), limitLabel: lim.max_tokens ? String(lim.max_tokens) : "unlimited" },
    { label: "Cost USD", used: u.cost_usd, limit: lim.max_cost_usd, usedLabel: money(u.cost_usd), limitLabel: lim.max_cost_usd ? money(lim.max_cost_usd) : "unlimited" },
    { label: "Exec actions", used: u.execs, limit: lim.max_execs, usedLabel: String(u.execs), limitLabel: lim.max_execs ? String(lim.max_execs) : "unlimited" },
    { label: "Egress requests", used: u.egress_requests, limit: lim.egress_requests, usedLabel: String(u.egress_requests), limitLabel: lim.egress_requests ? String(lim.egress_requests) : "unlimited" },
    {
      label: "Wall clock",
      used: u.wall_seconds,
      limit: parseDurationSeconds(lim.wall_clock),
      usedLabel: `${u.wall_seconds}s`,
      limitLabel: lim.wall_clock || "unlimited",
    },
  ];
  for (const row of rows) {
    const ratio = row.limit > 0 ? Math.min(1, row.used / row.limit) : 0;
    grid.appendChild(el("div", { class: "budget-card" }, [
      el("div", { class: "budget-label", text: row.label }),
      el("div", { class: "budget-value", text: `${row.usedLabel} / ${row.limitLabel}` }),
      el("div", { class: "budget-bar" }, el("div", { class: "budget-fill", style: `width:${Math.round(ratio * 100)}%` })),
    ]));
  }
}

/* ---------------- Recovery and portable evidence ---------------- */
async function refreshRecovery() {
	if (!state.selected) return;
	try {
		const [snapshotResponse, runResponse] = await Promise.all([
			api("GET", "/v1/snapshots"),
			api("GET", "/v1/runs"),
		]);
		state.snapshots = (snapshotResponse.data && snapshotResponse.data.snapshots) || [];
		state.runs = (runResponse.data && runResponse.data.runs) || [];
	} catch (e) {
		state.snapshots = [];
		state.runs = [];
		toast("Could not load recovery snapshots: " + e.message, "error", undefined, e);
	}
	renderSnapshots();
	renderRuns();
}

function renderRuns() {
	const body = $("#run-body");
	if (!body) return;
	body.innerHTML = "";
	const runs = state.runs.slice().reverse();
	if (runs.length === 0) {
		body.appendChild(el("tr", {}, el("td", { colspan: "6", class: "empty-note", text: "No agent runs yet." })));
		return;
	}
	for (const run of runs) {
		const selected = run.citadel_id === state.selected;
		body.appendChild(el("tr", { class: selected ? "selected" : "" }, [
			el("td", { class: "mono", text: run.id || "—", title: run.id || "" }),
			el("td", { class: "mono", text: run.parent_run_id || "—", title: run.parent_run_id || "" }),
			el("td", { text: run.actor || "—" }),
			el("td", { text: [run.agent, run.provider, run.model].filter(Boolean).join(" · ") || "—" }),
			el("td", {}, el("span", { class: "v-tag " + (run.status || ""), text: run.status || "—" })),
			el("td", { text: fmtDateTime(run.created_at) }),
		]));
	}
}

function renderSnapshots() {
	const body = $("#snapshot-body");
	if (!body) return;
	body.innerHTML = "";
	const selected = state.sandboxes.find((s) => s.id === state.selected) || {};
	const snapshots = state.snapshots.filter((s) => !selected.profile || s.profile === selected.profile);
	if (!state.selected || snapshots.length === 0) {
		body.appendChild(el("tr", {}, el("td", { colspan: "5", class: "empty-note", text: "No recovery snapshots for this policy yet." })));
		return;
	}
	for (const snapshot of snapshots) {
		body.appendChild(el("tr", {}, [
			el("td", { text: snapshot.name || snapshot.id, title: snapshot.id }),
			el("td", { text: snapshot.profile || "—" }),
			el("td", { text: fmtDateTime(snapshot.created) }),
			el("td", { class: "mono", text: snapshot.sha256 ? snapshot.sha256.slice(0, 12) + "…" : "—", title: snapshot.sha256 || "" }),
			el("td", {}, el("button", { class: "btn btn-sm", text: "Restore", onClick: () => restoreSnapshot(snapshot.id) })),
		]));
	}
}

async function createSnapshot() {
	if (!state.selected) return;
	const name = $("#snapshot-name").value.trim() || `snapshot-${Date.now()}`;
	const button = $("#snapshot-create");
	button.disabled = true;
	try {
		await api("POST", sbPath("/snapshot"), { name });
		$("#snapshot-name").value = "";
		toast("Recovery snapshot created", "success");
		await refreshRecovery();
	} catch (e) {
		toast("Snapshot failed: " + e.message, "error", undefined, e);
	} finally {
		button.disabled = false;
	}
}

async function restoreSnapshot(id) {
	try {
		const { data } = await api("POST", `/v1/snapshots/${encodeURIComponent(id)}/restore`, {});
		toast(`Restored as sandbox ${data.id}`, "success");
		await loadSandboxes();
		if (data.id) selectSandbox(data.id);
	} catch (e) {
		toast("Restore failed: " + e.message, "error", undefined, e);
	}
}

async function downloadAuthenticated(path, fallbackName) {
	const headers = {};
	if (auth.token) headers.Authorization = "Bearer " + auth.token;
	let response;
	try {
		response = await fetch(path, { headers });
	} catch (e) {
		throw new Error("network error: " + e.message);
	}
	if (!response.ok) {
		let message = `HTTP ${response.status}`;
		try {
			const body = await response.json();
			message = body.error || message;
		} catch {}
		throw new Error(message);
	}
	const blob = await response.blob();
	const url = URL.createObjectURL(blob);
	const link = document.createElement("a");
	link.href = url;
	link.download = fallbackName;
	document.body.appendChild(link);
	link.click();
	link.remove();
	URL.revokeObjectURL(url);
}

async function downloadWorkspace() {
	if (!state.selected) return;
	try {
		await downloadAuthenticated(sbPath("/workspace"), `runeward-workspace-${state.selected}.tar`);
		toast("Workspace download started", "success");
	} catch (e) {
		toast("Workspace export failed: " + e.message, "error", undefined, e);
	}
}

async function downloadEvidence() {
	if (!state.selected) return;
	try {
		await downloadAuthenticated(sbPath("/evidence"), `runeward-evidence-${state.selected}.json`);
		toast("Signed evidence download started", "success");
	} catch (e) {
		toast("Evidence export failed: " + e.message, "error", undefined, e);
	}
}

/* ---------------- Utilities ---------------- */
function fmtTime(t) {
  if (!t) return "";
  const d = new Date(t);
  if (isNaN(d.getTime())) return String(t);
  return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function fmtDateTime(t) {
	if (!t) return "";
	const d = new Date(t);
	if (isNaN(d.getTime())) return String(t);
	return d.toLocaleString();
}

function debounce(fn, ms) {
  let h;
  return (...args) => {
    clearTimeout(h);
    h = setTimeout(() => fn(...args), ms);
  };
}

/* ---------------- Polling loop ---------------- */
function startGlobalPoll() {
  if (state.timers.global) return;
  const tick = async () => {
    await Promise.all([
      refreshHealth(),
      refreshAuditVerify(),
      loadSandboxes(),
      canApprove() ? refreshApprovals() : Promise.resolve(),
      state.activeView === "fleets" ? refreshFleets() : Promise.resolve(),
      state.activeTab === "egress" ? refreshEgress() : Promise.resolve(),
      state.activeTab === "budget" ? refreshBudget() : Promise.resolve(),
			state.activeTab === "recovery" ? refreshRecovery() : Promise.resolve(),
      state.activeView === "sandboxes" && state.selected ? refreshSandboxDetail() : Promise.resolve(),
      state.activeView === "fleets" && state.fleetSelected ? refreshFleetSchedules() : Promise.resolve(),
    ]);
  };
  tick();
  state.timers.global = setInterval(tick, POLL_MS);
}

function stopGlobalPoll() {
  if (state.timers.global) {
    clearInterval(state.timers.global);
    state.timers.global = null;
  }
}

/* ---------------- Wiring ---------------- */
function wireEvents() {
  $("#create-btn").addEventListener("click", openNewSandboxModal);
  $("#new-modal-create").addEventListener("click", createSandbox);
  $$("[data-close-modal]").forEach((n) => n.addEventListener("click", closeNewSandboxModal));
  $("#new-modal-copyfrom").addEventListener("keydown", (e) => { if (e.key === "Enter") createSandbox(); });
  $("#refresh-btn").addEventListener("click", () => { loadSandboxes(); loadProfiles(); });
	$("#profile-select").addEventListener("change", refreshSelectedProfileReadiness);
	$("#fleet-profile-select").addEventListener("change", refreshSelectedProfileReadiness);

  // View switch + fleets
  $("#view-sandboxes").addEventListener("click", () => switchView("sandboxes"));
  $("#view-fleets").addEventListener("click", () => switchView("fleets"));
  $("#view-agent-sessions").addEventListener("click", openAgentSessionsForSelectedSandbox);
  $("#fleet-create-btn").addEventListener("click", createFleet);
  $("#fleet-refresh-btn").addEventListener("click", () => { loadFleets(); loadProfiles(); });
  $("#fleet-add-task").addEventListener("click", addFleetTask);
  $("#fleet-task-payload").addEventListener("keydown", (e) => { if (e.key === "Enter") addFleetTask(); });
  $("#fleet-claim").addEventListener("click", claimFleetTask);
  $("#fleet-claim-owner").addEventListener("keydown", (e) => { if (e.key === "Enter") claimFleetTask(); });
  $("#agent-transcript-reconnect").addEventListener("click", () => {
    if (state.agentSessionSelected) startAgentStream(state.agentSessionSelected, state.agentLastSeq);
  });

  $$(".tab").forEach((t) =>
    t.addEventListener("click", () => activateTab(t.dataset.tab))
  );
  enableArrowKeyTabs("#tabs .tab");
  enableArrowKeyTabs(".view-switch .view-tab");

  $("#list-btn").addEventListener("click", fileList);
  $("#read-btn").addEventListener("click", fileRead);
  $("#write-btn").addEventListener("click", fileWrite);
  $("#search-btn").addEventListener("click", fileSearch);
  $("#search-query").addEventListener("keydown", (e) => { if (e.key === "Enter") fileSearch(); });
  $("#list-path").addEventListener("keydown", (e) => { if (e.key === "Enter") fileList(); });

  $("#shell-run").addEventListener("click", runShell);
  $("#shell-cmd").addEventListener("keydown", (e) => { if (e.key === "Enter") runShell(); });
  $("#code-run").addEventListener("click", runCode);
  $("#browser-run").addEventListener("click", runBrowser);
  $("#browser-url").addEventListener("keydown", (e) => { if (e.key === "Enter") runBrowser(); });
  $("#sim-run").addEventListener("click", runPolicySimulation);
  $("#sim-actions").addEventListener("keydown", (e) => { if ((e.metaKey || e.ctrlKey) && e.key === "Enter") runPolicySimulation(); });
  $("#egress-refresh").addEventListener("click", refreshEgress);
	$("#snapshot-create").addEventListener("click", createSnapshot);
	$("#snapshot-name").addEventListener("keydown", (e) => { if (e.key === "Enter") createSnapshot(); });
	$("#snapshot-refresh").addEventListener("click", refreshRecovery);
	$("#workspace-download").addEventListener("click", downloadWorkspace);
	$("#evidence-download").addEventListener("click", downloadEvidence);
  $("#workspace-sleep").addEventListener("click", () => workspaceAction("sleep"));
  $("#workspace-wake").addEventListener("click", () => workspaceAction("wake"));
  $("#workspace-fork").addEventListener("click", () => workspaceAction("fork"));
  $("#sb-schedule-refresh").addEventListener("click", refreshSandboxSchedules);
  $("#memory-search-form").addEventListener("submit", (e) => { e.preventDefault(); loadMemory(true); });
  $("#memory-list").addEventListener("click", () => {
    $("#memory-query").value = "";
    $("#memory-tags").value = "";
    loadMemory(false);
  });

  $("#approvals-btn").addEventListener("click", openDrawer);
  $$("[data-close-drawer]").forEach((n) => n.addEventListener("click", closeDrawer));
  $$("[data-close-task-modal]").forEach((n) => n.addEventListener("click", closeTaskResolutionModal));
  $("#task-modal-submit").addEventListener("click", submitTaskResolution);
  $("#task-modal-value").addEventListener("keydown", (e) => { if ((e.metaKey || e.ctrlKey) && e.key === "Enter") submitTaskResolution(); });
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") { closeDrawer(); closeNewSandboxModal(); closeTaskResolutionModal(); } });
}

/* ---------------- Login / identity ---------------- */
function showLogin() {
  const ov = $("#login-overlay");
  if (ov) ov.classList.remove("hidden");
  const t = $("#login-token");
  if (t) setTimeout(() => t.focus(), 0);
}

function hideLogin() {
  const ov = $("#login-overlay");
  if (ov) ov.classList.add("hidden");
}

// applyPrincipal renders the caller's identity in the topbar and gates
// controls (create, approvals) that the identity isn't permitted to use.
function applyPrincipal() {
  const p = auth.principal || {};
  const chip = $("#identity");
  if (chip) {
    chip.classList.remove("hidden");
    let name, role;
	if (auth.rbac) {
	  name = p.name || "(unnamed)";
	  role = p.admin ? "admin" : (p.can_approve && !p.can_launch ? "reviewer-only" : (p.can_approve ? "approver" : (p.can_launch ? "operator" : "locked")));
    } else {
      name = "open mode";
      role = "";
    }
    $("#identity-name").textContent = name;
    $("#identity-role").textContent = role;
	$("#identity-role").classList.toggle("hidden", !role);
	const launchScope = p.admin ? "all Charters" : ((p.allowed_profiles || []).join(", ") || "no Charters");
	const approvalScope = p.admin ? "all approvals" : (p.can_approve ? ((p.approval_profiles || []).join(", ") || "all approvals") : "no approvals");
	chip.title = `Launch: ${launchScope}; Review: ${approvalScope}`;
    // A sign-out only makes sense when authenticating with a token.
    $("#signout-btn").classList.toggle("hidden", !auth.token);
  }
  // Hide approvals entirely when the identity can't resolve them.
  $("#approvals-btn").classList.toggle("hidden", !canApprove());
  // Disable sandbox/fleet creation when the identity can launch nothing.
  const allowed = canLaunch();
	const fleetButton = $("#fleet-create-btn");
	if (fleetButton) {
		fleetButton.disabled = !allowed;
		if (!allowed) fleetButton.title = "Your role is not permitted to launch policies";
	}
	applyCreateAvailability();
}

// Start the live app exactly once, regardless of how many times boot runs
// (initial load, then again after an interactive login).
function startApp() {
  if (state.started) return;
  state.started = true;
	loadProfiles().finally(startGlobalPoll);
}

async function loadWhoami() {
  const { data } = await api("GET", "/v1/whoami");
  auth.principal = data.principal || null;
  auth.rbac = !!data.rbac;
}

async function bootSession() {
  try {
    await loadWhoami();
    hideLogin();
    applyPrincipal();
    startApp();
  } catch (e) {
    if (e.status === 401) {
      showLogin();
      return;
    }
    // whoami unavailable (older server / no auth): fall back to least privilege.
    auth.principal = { name: "", admin: false, can_approve: false, can_launch: false };
    auth.rbac = false;
    hideLogin();
    applyPrincipal();
    startApp();
  }
}

function wireLogin() {
  auth.onRequired = () => { stopGlobalPoll(); state.started = false; showLogin(); };
  const form = $("#login-form");
  if (form) {
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      const err = $("#login-error");
      err.classList.add("hidden");
      setToken($("#login-token").value);
      try {
        await loadWhoami();
        hideLogin();
        applyPrincipal();
        startApp();
        toast("Signed in" + (auth.principal && auth.principal.name ? ` as ${auth.principal.name}` : ""), "success");
      } catch (ex) {
        setToken("");
        err.textContent = ex.status === 401
          ? "Invalid token. Please try again."
          : "Sign-in failed: " + ex.message;
        err.classList.remove("hidden");
      }
    });
  }
  const signout = $("#signout-btn");
  if (signout) {
    signout.addEventListener("click", () => {
      setToken("");
      location.reload();
    });
  }
}

function init() {
  wireEvents();
  wireLogin();
  bootSession();
}

document.addEventListener("DOMContentLoaded", init);
