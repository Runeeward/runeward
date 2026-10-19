"""A dependency-light Python client for the Rune Box control plane.

Uses only the Python standard library (``urllib``) so it can be dropped into any
environment without pulling in ``requests`` or an async HTTP stack. The client
mirrors the Rune Box REST contract 1:1 and translates the governance outcomes
into exceptions:

* HTTP ``403`` -> :class:`RunewardDenied` (policy) or
  :class:`RunewardAuthorizationError` (role / resource access)
* HTTP ``202`` -> :class:`RunewardApprovalRequired` (carries the ``approval_id``)
* any other refused call (the body carries a ``refusal`` object: bad request,
  unknown resource, conflict, rate limit, ...) -> :class:`RefusedError`

Everything else that isn't a 2xx becomes a :class:`RunewardError`. Every error
exposes ``request_id`` (the ``X-Request-Id`` the server answered with) and,
when the server proved the call never ran, a parsed :class:`Refusal`.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
import warnings
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, TypedDict

__all__ = [
    "RunewardClient",
    "RunewardError",
    "RunewardDenied",
    "RunewardAuthorizationError",
    "RunewardApprovalRequired",
    "RefusedError",
    "Refusal",
    "Sandbox",
    "IsolationEvidence",
    "PerimeterDecision",
    "WorkspaceStatus",
    "Schedule",
    "ScheduleFiring",
    "MemoryEntry",
]

#: Header the server echoes (or generates) on every response.
REQUEST_ID_HEADER = "X-Request-Id"


# -- response shapes (informational; responses are plain dicts) -------------


class IsolationEvidence(TypedDict, total=False):
    """What the in-sandbox supervisor reported enforcing."""

    supervisor: str  # "enforced" or "absent"
    required: bool
    landlock_requested: str
    landlock: str
    landlock_abi: int
    seccomp: bool
    no_new_privs: bool
    uid: Optional[int]
    gid: Optional[int]
    capabilities_dropped: bool
    protected_by_landlock: bool


class Sandbox(TypedDict, total=False):
    """A Citadel view (``GET /v1/citadels/{id}`` and friends)."""

    id: str
    profile: str
    backend: str
    image: str
    status: str  # running, sleeping, waking, ...
    #: The isolation tier the sandbox actually runs behind:
    #: ``process``, ``container``, ``kernel`` or ``vm``.
    isolation: str
    #: Supervisor enforcement evidence, when the server reports it.
    enforcement: IsolationEvidence
    owner: str
    capabilities: List[str]
    ide: bool
    forked_from: str
    workspace: "WorkspaceStatus"
    usage: Dict[str, Any]
    limits: Dict[str, Any]


class PerimeterDecision(TypedDict, total=False):
    """One egress decision. The first five keys are always present; the
    request-broker keys only when the decision came from the broker."""

    timestamp: str
    host: str
    ip: str
    allow: bool
    reason: str
    endpoint: str
    protocol: str  # tcp, rest, websocket, mcp, json-rpc
    method: str
    path: str
    tool: str
    effect: str  # read, write, irreversible
    rule: str
    verdict: str  # allow, deny, require-approval
    reason_code: str
    credential: str  # the credential's name, never its value
    binaries: List[str]


class WorkspaceStatus(TypedDict, total=False):
    citadel_id: str
    state: str
    idle_timeout_secs: int
    idle_secs: int
    slept_at: str
    woke_at: str
    forked_from: str


class Schedule(TypedDict, total=False):
    id: str
    owner: str
    actor: str
    cohort_id: str
    citadel_id: str
    cron: str
    every: str
    command: List[str]
    prompt: str
    agent: str
    model: str
    precheck: List[str]
    self_service: bool
    created_at: str
    next_fire_at: str
    last_fired_at: str
    last_outcome: str
    last_reason: str
    last_session_id: str
    fire_count: int


class ScheduleFiring(TypedDict, total=False):
    schedule_id: str
    outcome: str  # started, skipped_precheck, skipped_busy, denied, error
    citadel_id: str
    session_id: str
    reason: str


class MemoryEntry(TypedDict, total=False):
    key: str
    text: str
    author: str
    tags: List[str]
    created_at: str
    updated_at: str
    version: int


# -- errors -------------------------------------------------------------------


@dataclass(frozen=True)
class Refusal:
    """The standard "nothing ran" object the server attaches as ``refusal``.

    ``reason`` is one of ``request``, ``permission``, ``policy``,
    ``approval``, ``budget``, ``isolation``, ``environment``, ``capacity``,
    ``shed`` or ``protocol``. ``retryable`` is true only when re-sending the
    identical request is safe and may succeed later (rate limits, shed
    retry storms).
    """

    refused: bool
    reason: str
    retryable: bool
    request_id: str
    message: str

    @classmethod
    def from_payload(cls, payload: Any) -> Optional["Refusal"]:
        """Parse ``payload["refusal"]``; ``None`` when absent or malformed."""
        if not isinstance(payload, dict):
            return None
        raw = payload.get("refusal")
        if not isinstance(raw, dict):
            return None
        return cls(
            refused=bool(raw.get("refused", True)),
            reason=str(raw.get("reason") or ""),
            retryable=bool(raw.get("retryable", False)),
            request_id=str(raw.get("request_id") or ""),
            message=str(raw.get("message") or ""),
        )


class RunewardError(Exception):
    """Base error for any non-success response from the control plane.

    ``request_id`` correlates the error with the server's logs (the
    ``X-Request-Id`` response header, else the refusal's or body's id).
    ``refusal`` is set when the server proved the call never ran.
    """

    def __init__(self, message: str, *, status: Optional[int] = None,
                 payload: Optional[Dict[str, Any]] = None,
                 request_id: str = "") -> None:
        super().__init__(message)
        self.status = status
        self.payload = payload or {}
        self.refusal: Optional[Refusal] = Refusal.from_payload(self.payload)
        self.code: str = str(self.payload.get("code") or "") if isinstance(self.payload, dict) else ""
        self.request_id: str = request_id or self._payload_request_id()

    def _payload_request_id(self) -> str:
        if self.refusal and self.refusal.request_id:
            return self.refusal.request_id
        if isinstance(self.payload, dict):
            return str(self.payload.get("request_id") or "")
        return ""


class RefusedError(RunewardError):
    """Raised when the server refused a call before it ran and no more
    specific governance error applies (bad request, unknown resource,
    conflict such as ``session_busy``/``version_conflict``, rate limit,
    budget, isolation floor, ...).

    Policy denials, authorization failures and approval gates keep raising
    :class:`RunewardDenied`, :class:`RunewardAuthorizationError` and
    :class:`RunewardApprovalRequired`; those also carry ``refusal``.
    """

    def __init__(self, reason: str, retryable: bool, request_id: str, message: str, *,
                 status: Optional[int] = None,
                 payload: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(
            f"runeward refused the call ({reason}): {message}".rstrip(": "),
            status=status, payload=payload, request_id=request_id,
        )
        self.reason = reason
        self.retryable = retryable
        self.message = message


class RunewardDenied(RunewardError):
    """Raised when policy denies an action (HTTP 403).

    ``reason`` explains *why* it was blocked. A denial is a policy decision, not
    a transient failure: do not retry the identical action.
    """

    def __init__(self, reason: str, *, payload: Optional[Dict[str, Any]] = None,
                 request_id: str = "") -> None:
        super().__init__(f"runeward denied action: {reason}", status=403, payload=payload,
                         request_id=request_id)
        self.reason = reason


class RunewardAuthorizationError(RunewardError):
    """Raised when an authenticated caller lacks role or resource access."""

    def __init__(self, message: str, *, payload: Optional[Dict[str, Any]] = None,
                 request_id: str = "") -> None:
        super().__init__(f"runeward authorization denied: {message}", status=403, payload=payload,
                         request_id=request_id)


class RunewardApprovalRequired(RunewardError):
    """Raised when an action needs human approval (HTTP 202).

    ``approval_id`` identifies the pending request in the approvals inbox. The
    caller should pause and surface this to a human rather than working around
    the gate.
    """

    def __init__(self, approval_id: str, *, reason: str = "",
                 payload: Optional[Dict[str, Any]] = None, request_id: str = "") -> None:
        super().__init__(
            f"runeward requires approval (id={approval_id}): {reason}".rstrip(": "),
            status=202,
            payload=payload,
            request_id=request_id,
        )
        self.approval_id = approval_id
        self.reason = reason


class RunewardClient:
    """Thin, synchronous client over the Rune Box REST control plane.

    Example
    -------
    >>> rw = RunewardClient("http://localhost:8080")
    >>> sbx = rw.create_sandbox("dev")
    >>> rw.shell(sbx["id"], ["echo", "hello"])["stdout"]
    'hello\\n'
    >>> rw.kill_sandbox(sbx["id"])
    """

    def __init__(self, base_url: str = "http://localhost:8080", *,
                 timeout: float = 60.0, token: Optional[str] = None,
                 allow_insecure: bool = False) -> None:
        # Normalize so we can safely join paths without doubling slashes.
        self.base_url = self._normalize_base_url(base_url)
        self._validate_transport(self.base_url, allow_insecure)
        self.timeout = timeout
        self.token = token or os.environ.get("RUNEWARD_API_TOKEN")
        #: ``X-Request-Id`` of the most recent response (success or error).
        self.last_request_id: str = ""

    # -- low-level request plumbing ---------------------------------------

    def _request(self, method: str, path: str,
                 body: Optional[Dict[str, Any]] = None, *,
                 accepted: bool = False) -> Any:
        """Perform an HTTP request and decode the JSON response.

        Maps governance status codes to typed exceptions before returning.
        """
        url = f"{self.base_url}{path}"
        data = None
        headers = {"Accept": "application/json"}
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                self.last_request_id = self._header(resp, REQUEST_ID_HEADER)
                return self._decode(resp.status, resp.read(), self.last_request_id, accepted)
        except urllib.error.HTTPError as exc:  # 4xx / 5xx arrive here
            self.last_request_id = self._header(exc, REQUEST_ID_HEADER)
            payload = self._safe_json(exc.read())
            self._raise_for_status(exc.code, payload, request_id=self.last_request_id)
            # _raise_for_status always raises for non-2xx; keep the type checker happy.
            raise
        except urllib.error.URLError as exc:  # connection refused, DNS, timeout
            raise RunewardError(f"could not reach runeward at {url}: {exc.reason}") from exc

    def _decode(self, status: int, raw: bytes, request_id: str = "",
                accepted: bool = False) -> Any:
        """Handle a response the stdlib treated as success (2xx)."""
        payload = self._safe_json(raw)
        # 202 is "success" to urllib but means an approval gate to runeward,
        # except on routes that answer 202 Accepted for queued work (agent
        # sessions and turns); there only an explicit verdict is a gate.
        if status == 202 and (not accepted or "verdict" in payload or "refusal" in payload):
            self._raise_for_status(status, payload, request_id=request_id)
        return payload

    @staticmethod
    def _header(resp: Any, name: str) -> str:
        headers = getattr(resp, "headers", None)
        if headers is None:
            return ""
        try:
            return str(headers.get(name) or "")
        except Exception:  # pragma: no cover - defensive
            return ""

    @staticmethod
    def _safe_json(raw: bytes) -> Dict[str, Any]:
        if not raw:
            return {}
        try:
            return json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return {"raw": raw.decode("utf-8", "replace")}

    @staticmethod
    def _normalize_base_url(base_url: str) -> str:
        base_url = base_url.strip()
        parsed = urllib.parse.urlsplit(base_url)
        if not parsed.scheme:
            base_url = f"https://{base_url}"
        return base_url.rstrip("/")

    @staticmethod
    def _is_loopback_host(hostname: Optional[str]) -> bool:
        if not hostname:
            return False
        host = hostname.lower().strip("[]")
        return host in {"localhost", "127.0.0.1", "::1"}

    @staticmethod
    def _env_allows_insecure() -> bool:
        value = os.environ.get("RUNEWARD_ALLOW_INSECURE_HTTP", "").strip().lower()
        return value in {"1", "true", "yes", "on"}

    @classmethod
    def _validate_transport(cls, base_url: str, allow_insecure: bool) -> None:
        parsed = urllib.parse.urlsplit(base_url)
        if parsed.scheme != "http":
            return
        if cls._is_loopback_host(parsed.hostname):
            return
        if allow_insecure or cls._env_allows_insecure():
            warnings.warn(
                f"runeward client using insecure HTTP transport to non-loopback host: {base_url}",
                RuntimeWarning,
                stacklevel=3,
            )
            return
        raise ValueError(
            "refusing insecure http:// base URL to non-loopback host; "
            "use https://, set allow_insecure=True, or set RUNEWARD_ALLOW_INSECURE_HTTP=1"
        )

    @staticmethod
    def _segment(value: str) -> str:
        return urllib.parse.quote(value, safe="")

    @staticmethod
    def _query(**params: Any) -> str:
        """A ``?query`` string of the params that are set (not None / "")."""
        kept = {k: v for k, v in params.items() if v is not None and v != ""}
        return f"?{urllib.parse.urlencode(kept)}" if kept else ""

    @staticmethod
    def _raise_for_status(status: int, payload: Dict[str, Any], *,
                          request_id: str = "") -> None:
        if not isinstance(payload, dict):
            payload = {"raw": payload}
        if payload.get("code") == "authz_denied":
            raise RunewardAuthorizationError(payload.get("error", "not authorized"), payload=payload,
                                             request_id=request_id)
        if payload.get("verdict") == "deny" or (status == 403 and not payload.get("code")):
            raise RunewardDenied(payload.get("reason", "denied by policy"), payload=payload,
                                 request_id=request_id)
        if status == 202 or payload.get("verdict") == "require-approval":
            raise RunewardApprovalRequired(
                payload.get("approval_id", ""),
                reason=payload.get("reason", ""),
                payload=payload,
                request_id=request_id,
            )
        refusal = Refusal.from_payload(payload)
        if refusal is not None:
            raise RefusedError(
                refusal.reason,
                refusal.retryable,
                request_id or refusal.request_id,
                refusal.message or str(payload.get("error") or ""),
                status=status,
                payload=payload,
            )
        raise RunewardError(
            f"runeward returned HTTP {status}: {payload}", status=status, payload=payload,
            request_id=request_id,
        )

    # -- health & discovery -----------------------------------------------

    def healthz(self) -> Any:
        """``GET /healthz`` — liveness check."""
        return self._request("GET", "/healthz")

    def whoami(self) -> Dict[str, Any]:
        return self._request("GET", "/v1/whoami")

    def readiness(self, profile: str) -> Dict[str, Any]:
        return self._request("GET", f"/v1/readiness?profile={self._segment(profile)}")

    def simulate_policy(self, profile_name: str, actions: List[Dict[str, Any]]) -> Dict[str, Any]:
        return self._request("POST", "/v1/policy/simulate", {
            "profile_name": profile_name, "actions": actions,
        })

    def list_profiles(self) -> List[Dict[str, Any]]:
        """``GET /v1/charters`` — reachable profiles."""
        return self._request("GET", "/v1/charters").get("profiles", [])

    def list_runs(self) -> List[Dict[str, Any]]:
        return self._request("GET", "/v1/runs").get("runs", [])

    def get_run(self, run_id: str) -> Dict[str, Any]:
        return self._request("GET", f"/v1/runs/{self._segment(run_id)}")

    # -- sandbox lifecycle -------------------------------------------------

    def create_sandbox(self, profile: str, *, copy_from: str = "",
                       parent_citadel: str = "", run_id: str = "",
                       agent: str = "", provider: str = "", model: str = "") -> Sandbox:
        """``POST /v1/citadels`` — provision a sandbox from ``profile``. The
        result's ``isolation`` names the tier it actually runs behind."""
        body = {"profile": profile}
        optional = {
            "copy_from": copy_from, "parent_citadel": parent_citadel,
            "run_id": run_id, "agent": agent, "provider": provider, "model": model,
        }
        body.update({key: value for key, value in optional.items() if value})
        return self._request("POST", "/v1/citadels", body)

    def list_sandboxes(self) -> List[Sandbox]:
        """``GET /v1/citadels``."""
        return self._request("GET", "/v1/citadels").get("sandboxes", [])

    def get_sandbox(self, sandbox: str) -> Sandbox:
        """``GET /v1/citadels/{id}``."""
        return self._request("GET", f"/v1/citadels/{self._segment(sandbox)}")

    def kill_sandbox(self, sandbox: str) -> Any:
        """``DELETE /v1/citadels/{id}`` — tear the sandbox down."""
        return self._request("DELETE", f"/v1/citadels/{self._segment(sandbox)}")

    # -- persistent workspaces -------------------------------------------------

    def fork_citadel(self, sandbox: str, *, profile: str = "", run_id: str = "",
                     agent: str = "", provider: str = "", model: str = "",
                     nano_cpus: int = 0, memory_bytes: int = 0) -> Sandbox:
        """``POST /v1/citadels/{id}/fork`` — copy the workspace into a new,
        independent Citadel (``forked_from`` names the source). A weaker
        isolation floor, broader egress or larger resources need an
        administrator."""
        optional = {
            "profile": profile, "run_id": run_id, "agent": agent,
            "provider": provider, "model": model,
            "nano_cpus": nano_cpus, "memory_bytes": memory_bytes,
        }
        body = {key: value for key, value in optional.items() if value}
        return self._request("POST", f"/v1/citadels/{self._segment(sandbox)}/fork", body)

    def sleep_citadel(self, sandbox: str) -> Dict[str, Any]:
        """``POST /v1/citadels/{id}/sleep`` — ``{"ok", "slept"}``. Raises
        :class:`RefusedError` (409 ``citadel_busy``) while work is active."""
        return self._request("POST", f"/v1/citadels/{self._segment(sandbox)}/sleep")

    def wake_citadel(self, sandbox: str) -> Dict[str, Any]:
        """``POST /v1/citadels/{id}/wake`` (any governed call also wakes it)."""
        return self._request("POST", f"/v1/citadels/{self._segment(sandbox)}/wake")

    def workspace_status(self, sandbox: str) -> WorkspaceStatus:
        """``GET /v1/citadels/{id}/workspace/status`` (persistent Citadels only)."""
        return self._request("GET", f"/v1/citadels/{self._segment(sandbox)}/workspace/status")

    # -- agent sessions ----------------------------------------------------------

    def start_agent_session(self, sandbox: str, command: List[str], *, agent: str = "",
                            model: str = "", cohort_id: str = "",
                            task_id: str = "") -> Dict[str, Any]:
        """``POST /v1/citadels/{id}/agent-sessions`` — start an agent command."""
        optional = {"agent": agent, "model": model, "cohort_id": cohort_id, "task_id": task_id}
        body: Dict[str, Any] = {"command": list(command)}
        body.update({key: value for key, value in optional.items() if value})
        return self._request("POST", f"/v1/citadels/{self._segment(sandbox)}/agent-sessions",
                             body, accepted=True)

    def list_agent_sessions(self, cohort_id: str = "") -> List[Dict[str, Any]]:
        """``GET /v1/agent-sessions`` (optionally one Cohort's)."""
        q = self._query(cohort_id=cohort_id)
        return self._request("GET", f"/v1/agent-sessions{q}").get("sessions", [])

    def get_agent_session(self, session: str) -> Dict[str, Any]:
        """``GET /v1/agent-sessions/{id}``."""
        return self._request("GET", f"/v1/agent-sessions/{self._segment(session)}")

    def agent_session_events(self, session: str, after: int = 0) -> Dict[str, Any]:
        """``GET /v1/agent-sessions/{id}/events?after=<seq>`` — ``{"session", "events"}``.
        Pass the last ``seq`` you saw to resume without losing output."""
        q = self._query(after=after or None)
        return self._request("GET", f"/v1/agent-sessions/{self._segment(session)}/events{q}")

    def agent_turn(self, session: str, command: List[str], model: str = "") -> Dict[str, Any]:
        """``POST /v1/agent-sessions/{id}/turns`` — start the next turn. Raises
        :class:`RefusedError` (409 ``session_busy``) while a turn is active."""
        body: Dict[str, Any] = {"command": list(command)}
        if model:
            body["model"] = model
        return self._request("POST", f"/v1/agent-sessions/{self._segment(session)}/turns",
                             body, accepted=True)

    def cancel_agent_turn(self, session: str) -> bool:
        """``POST /v1/agent-sessions/{id}/cancel`` — stop the active turn.
        Cancel does not rewind workspace changes. Returns whether a turn was
        canceled."""
        return bool(self._request(
            "POST", f"/v1/agent-sessions/{self._segment(session)}/cancel", {},
        ).get("canceled", False))

    # -- schedules -----------------------------------------------------------------

    def list_schedules(self, *, citadel: str = "", cohort: str = "") -> List[Schedule]:
        """Every visible schedule, or those of one Citadel or Cohort."""
        if citadel and cohort:
            raise ValueError("pass at most one of citadel and cohort")
        if citadel:
            path = f"/v1/citadels/{self._segment(citadel)}/schedules"
        elif cohort:
            path = f"/v1/cohorts/{self._segment(cohort)}/schedules"
        else:
            path = "/v1/schedules"
        return self._request("GET", path).get("schedules", [])

    def create_schedule(self, command: List[str], *, citadel: str = "", cohort: str = "",
                        cron: str = "", every: str = "", prompt: str = "",
                        agent: str = "", model: str = "",
                        precheck: Optional[List[str]] = None) -> Schedule:
        """Schedule an agent run on a Citadel or a Cohort (exactly one), firing
        on a 5-field UTC ``cron`` or a fixed interval ``every`` (e.g. ``"30m"``)."""
        if bool(citadel) == bool(cohort):
            raise ValueError("pass exactly one of citadel and cohort")
        if bool(cron) == bool(every):
            raise ValueError("pass exactly one of cron and every")
        body: Dict[str, Any] = {"command": list(command)}
        optional = {"cron": cron, "every": every, "prompt": prompt, "agent": agent,
                    "model": model, "precheck": list(precheck or [])}
        body.update({key: value for key, value in optional.items() if value})
        if citadel:
            path = f"/v1/citadels/{self._segment(citadel)}/schedules"
        else:
            path = f"/v1/cohorts/{self._segment(cohort)}/schedules"
        return self._request("POST", path, body)

    def get_schedule(self, schedule: str) -> Schedule:
        """``GET /v1/schedules/{id}``."""
        return self._request("GET", f"/v1/schedules/{self._segment(schedule)}")

    def delete_schedule(self, schedule: str) -> Any:
        """``DELETE /v1/schedules/{id}``."""
        return self._request("DELETE", f"/v1/schedules/{self._segment(schedule)}")

    def run_schedule(self, schedule: str) -> ScheduleFiring:
        """``POST /v1/schedules/{id}/run`` — fire now (policy, precheck and
        budgets still apply)."""
        return self._request("POST", f"/v1/schedules/{self._segment(schedule)}/run")

    # -- execution ---------------------------------------------------------

    def shell(self, sandbox: str, command: List[str], workdir: str = "") -> Dict[str, Any]:
        """``POST .../shell/exec`` — run ``command`` (an argv list) in the sandbox.

        Returns ``{"verdict","exit_code","stdout","stderr","duration_ms"}``. An
        ``allow`` verdict with a non-zero ``exit_code`` is a normal program
        error, not a policy denial.
        """
        return self._request(
            "POST", f"/v1/citadels/{self._segment(sandbox)}/shell/exec",
            {"command": list(command), "workdir": workdir},
        )

    def python(self, sandbox: str, code: str) -> Dict[str, Any]:
        """``POST .../code/python`` — run a Python snippet in the sandbox."""
        return self._request("POST", f"/v1/citadels/{self._segment(sandbox)}/code/python", {"code": code})

    def node(self, sandbox: str, code: str) -> Dict[str, Any]:
        """``POST .../code/node`` — run a Node.js snippet in the sandbox."""
        return self._request("POST", f"/v1/citadels/{self._segment(sandbox)}/code/node", {"code": code})

    def browser(self, sandbox: str, url: str, mode: str = "text") -> Dict[str, Any]:
        return self._request("POST", f"/v1/citadels/{self._segment(sandbox)}/browser", {"url": url, "mode": mode})

    def open_browser(self, sandbox: str) -> str:
        return self._request("POST", f"/v1/citadels/{self._segment(sandbox)}/browser/sessions")["session_id"]

    def browser_act(self, sandbox: str, session: str, **action: Any) -> Dict[str, Any]:
        return self._request("POST", f"/v1/citadels/{self._segment(sandbox)}/browser/sessions/{self._segment(session)}/act", action)

    def close_browser(self, sandbox: str, session: str) -> Any:
        return self._request("DELETE", f"/v1/citadels/{self._segment(sandbox)}/browser/sessions/{self._segment(session)}")

    def report_usage(self, sandbox: str, tokens: int, cost_usd: float) -> Dict[str, Any]:
        return self._request("POST", f"/v1/citadels/{self._segment(sandbox)}/usage", {"tokens": tokens, "cost_usd": cost_usd})

    def publish_conversation(self, sandbox: str, role: str, content: str,
                             run_id: str = "") -> Dict[str, Any]:
        """Publish one turn to the dashboard's read-only Live chat TTY."""
        return self._request(
            "POST", f"/v1/citadels/{self._segment(sandbox)}/conversation",
            {"role": role, "content": content, "run_id": run_id},
        )

    def list_conversation(self, sandbox: str, *, after_id: int = 0,
                          limit: int = 500) -> List[Dict[str, Any]]:
        query = urllib.parse.urlencode({"after_id": after_id, "limit": limit})
        return self._request(
            "GET", f"/v1/citadels/{self._segment(sandbox)}/conversation?{query}"
        ).get("messages", [])

    def perimeter(self, sandbox: str) -> List[PerimeterDecision]:
        """Egress decisions. Broker decisions add ``endpoint``, ``protocol``,
        ``method``, ``path``, ``tool``, ``effect``, ``verdict``,
        ``reason_code`` and ``credential``."""
        return self._request("GET", f"/v1/citadels/{self._segment(sandbox)}/perimeter").get("decisions", [])

    # -- files -------------------------------------------------------------

    def read_file(self, sandbox: str, path: str) -> str:
        """``POST .../file/read`` — return the file's ``content``."""
        return self._request(
            "POST", f"/v1/citadels/{self._segment(sandbox)}/file/read", {"path": path}
        ).get("content", "")

    def write_file(self, sandbox: str, path: str, content: str) -> int:
        """``POST .../file/write`` — write ``content``; return ``bytes`` written."""
        return self._request(
            "POST", f"/v1/citadels/{self._segment(sandbox)}/file/write",
            {"path": path, "content": content},
        ).get("bytes", 0)

    def list_files(self, sandbox: str, path: str) -> str:
        """``POST .../file/list`` — list a directory; return the raw ``output``."""
        return self._request(
            "POST", f"/v1/citadels/{self._segment(sandbox)}/file/list", {"path": path}
        ).get("output", "")

    def search_files(self, sandbox: str, query: str, path: str) -> str:
        """``POST .../file/search`` — search for ``query`` under ``path``."""
        return self._request(
            "POST", f"/v1/citadels/{self._segment(sandbox)}/file/search",
            {"query": query, "path": path},
        ).get("output", "")

    # -- audit -------------------------------------------------------------

    def audit(self, sandbox: str) -> List[Dict[str, Any]]:
        """``GET .../chronicle`` — this sandbox's ledger events."""
        return self._request("GET", f"/v1/citadels/{self._segment(sandbox)}/chronicle").get("events", [])

    def verify_audit(self) -> bool:
        """``GET /v1/chronicle/verify`` — verify the ledger hash chain."""
        return bool(self._request("GET", "/v1/chronicle/verify").get("ok", False))

    def export_evidence(self, sandbox: str) -> Dict[str, Any]:
        """Return the portable signed evidence document for a Citadel."""
        return self._request("GET", f"/v1/citadels/{self._segment(sandbox)}/evidence")

    def create_cohort(self, profile: str) -> Dict[str, Any]:
        return self._request("POST", "/v1/cohorts", {"profile": profile})

    def list_cohorts(self) -> List[Dict[str, Any]]:
        return self._request("GET", "/v1/cohorts").get("fleets", [])

    def get_cohort(self, cohort: str) -> Dict[str, Any]:
        return self._request("GET", f"/v1/cohorts/{self._segment(cohort)}")

    def kill_cohort(self, cohort: str) -> Any:
        return self._request("DELETE", f"/v1/cohorts/{self._segment(cohort)}")

    def list_tasks(self, cohort: str) -> List[Dict[str, Any]]:
        return self._request("GET", f"/v1/cohorts/{self._segment(cohort)}/tasks").get("tasks", [])

    def add_task(self, cohort: str, payload: str) -> Dict[str, Any]:
        return self._request("POST", f"/v1/cohorts/{self._segment(cohort)}/tasks", {"payload": payload})

    def claim_task(self, cohort: str, owner: str = "", *, context: bool = False,
                   memory_bytes: int = 0) -> Dict[str, Any]:
        """Claim the next task. With ``context=True`` the response also
        carries the task's handoff notes, brief, parent summary and a ranked
        slice of shared memory (``memory_bytes`` caps it; default 8 KiB)."""
        body: Dict[str, Any] = {"owner": owner}
        if context:
            body["context"] = True
        if memory_bytes:
            body["memory_bytes"] = memory_bytes
        return self._request("POST", f"/v1/cohorts/{self._segment(cohort)}/claim", body)

    def heartbeat_task(self, cohort: str, task: str, lease_token: str, owner: str = "") -> Any:
        return self._request("POST", f"/v1/cohorts/{self._segment(cohort)}/tasks/{self._segment(task)}/heartbeat", {"owner": owner, "lease_token": lease_token})

    def complete_task(self, cohort: str, task: str, lease_token: str, result: str = "",
                      owner: str = "", *, handoff: str = "") -> Any:
        """Complete a claimed task; ``handoff`` leaves a note for the next agent."""
        body: Dict[str, Any] = {"owner": owner, "lease_token": lease_token, "result": result}
        if handoff:
            body["handoff"] = handoff
        return self._request("POST", f"{self._task_path(cohort, task)}/complete", body)

    def fail_task(self, cohort: str, task: str, lease_token: str, error: str,
                  requeue: bool = False, owner: str = "", *, handoff: str = "") -> Any:
        """Fail (or with ``requeue`` give back) a claimed task."""
        body: Dict[str, Any] = {"owner": owner, "lease_token": lease_token, "error": error,
                                "requeue": requeue}
        if handoff:
            body["handoff"] = handoff
        return self._request("POST", f"{self._task_path(cohort, task)}/fail", body)

    def _task_path(self, cohort: str, task: str) -> str:
        return f"/v1/cohorts/{self._segment(cohort)}/tasks/{self._segment(task)}"

    def add_child_task(self, cohort: str, task: str, payload: str) -> Dict[str, Any]:
        """``POST .../tasks/{task}/children`` — split work into a pending child task."""
        return self._request("POST", f"{self._task_path(cohort, task)}/children", {"payload": payload})

    def add_task_note(self, cohort: str, task: str, text: str) -> Dict[str, Any]:
        """``POST .../tasks/{task}/notes`` — leave a handoff note on a task."""
        return self._request("POST", f"{self._task_path(cohort, task)}/notes", {"text": text})

    def set_task_brief(self, cohort: str, task: str, brief: str, agent: str = "*") -> Dict[str, Any]:
        """``PUT .../tasks/{task}/brief`` — set (or with ``""`` clear) the brief
        for ``agent`` (``*``: every agent)."""
        return self._request("PUT", f"{self._task_path(cohort, task)}/brief",
                             {"agent": agent, "brief": brief})

    def task_context(self, cohort: str, task: str, *, agent: str = "",
                     memory_bytes: int = 0) -> Dict[str, Any]:
        """``GET .../tasks/{task}/context`` — ``{"task", "context"}`` with the
        handoff notes, the brief for ``agent`` (default: the caller), the
        parent summary and ranked shared memory."""
        query = self._query(agent=agent, memory_bytes=memory_bytes or None)
        return self._request("GET", f"{self._task_path(cohort, task)}/context{query}")

    # -- cohort memory -------------------------------------------------------

    def list_memory(self, cohort: str) -> List[MemoryEntry]:
        """``GET /v1/cohorts/{id}/memory`` — every shared memory entry."""
        return self._request("GET", f"/v1/cohorts/{self._segment(cohort)}/memory").get("entries", [])

    def search_memory(self, cohort: str, query: str = "", *,
                      tags: Optional[Sequence[str]] = None, limit: int = 0,
                      max_bytes: int = 0) -> List[MemoryEntry]:
        """Search shared memory, ranked by tag, key, text match and recency."""
        q = self._query(query=query, tags=",".join(tags or []),
                        limit=limit or None, max_bytes=max_bytes or None)
        return self._request("GET", f"/v1/cohorts/{self._segment(cohort)}/memory{q}").get("entries", [])

    def put_memory(self, cohort: str, key: str, text: str, *,
                   tags: Optional[Sequence[str]] = None,
                   expected_version: Optional[int] = None) -> MemoryEntry:
        """Write a shared memory entry. ``expected_version=0`` requires a new
        key; a stale version raises :class:`RefusedError` (409
        ``version_conflict``)."""
        body: Dict[str, Any] = {"key": key, "text": text, "tags": list(tags or [])}
        if expected_version is not None:
            body["expected_version"] = expected_version
        return self._request("POST", f"/v1/cohorts/{self._segment(cohort)}/memory", body)

    def get_memory(self, cohort: str, key: str) -> MemoryEntry:
        """``GET /v1/cohorts/{id}/memory/{key}``."""
        return self._request("GET", f"/v1/cohorts/{self._segment(cohort)}/memory/{self._segment(key)}")

    def delete_memory(self, cohort: str, key: str, *, version: Optional[int] = None) -> bool:
        """Delete an entry (conditional on ``version`` when given); returns
        whether anything was deleted."""
        q = self._query(version=version)
        return bool(self._request(
            "DELETE", f"/v1/cohorts/{self._segment(cohort)}/memory/{self._segment(key)}{q}",
        ).get("deleted", False))

    def create_snapshot(self, sandbox: str, name: str = "") -> Dict[str, Any]:
        return self._request("POST", f"/v1/citadels/{self._segment(sandbox)}/snapshot", {"name": name})

    def list_snapshots(self) -> List[Dict[str, Any]]:
        return self._request("GET", "/v1/snapshots").get("snapshots", [])

    def restore_snapshot(self, snapshot: str) -> Dict[str, Any]:
        return self._request("POST", f"/v1/snapshots/{self._segment(snapshot)}/restore")

    # -- approvals ---------------------------------------------------------

    def list_approvals(self) -> List[Dict[str, Any]]:
        """``GET /v1/conclave`` — pending human-in-the-loop requests."""
        return self._request("GET", "/v1/conclave").get("approvals", [])

    def approve(self, approval_id: str) -> Any:
        """``POST /v1/conclave/{id}/approve``."""
        return self._request("POST", f"/v1/conclave/{self._segment(approval_id)}/approve")

    def deny(self, approval_id: str) -> Any:
        """``POST /v1/conclave/{id}/deny``."""
        return self._request("POST", f"/v1/conclave/{self._segment(approval_id)}/deny")
