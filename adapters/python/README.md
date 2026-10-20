# runeward (Python SDK for Rune Box)

A dependency-light Python client and agent-framework adapters for
[Rune Box](https://github.com/Runewardd/runeward), the open-source
**governance harness for AI agents** (formerly Runeward Sandbox). The package
and import name stay `runeward`.
Put policy, human approvals, isolated Citadels, Rationing, and signed Chronicles
around an existing agent without replacing its model or framework.

The core client uses **only the Python standard library** (`urllib`). The
LangChain, CrewAI, LlamaIndex, OpenAI Agents SDK, and Strands helpers are
optional extras and are imported lazily, so the base client works with nothing
else installed.

## Install

```bash
pip install runeward                    # core client only (no third-party deps)
pip install "runeward[langchain]"       # + LangChain tools
pip install "runeward[crewai]"          # + CrewAI tools
pip install "runeward[llamaindex]"      # + LlamaIndex tools
pip install "runeward[openai-agents]"   # + OpenAI Agents SDK tools
pip install "runeward[strands]"         # + Strands Agents SDK tools
```

During local development from this directory:

```bash
pip install -e .
```

## Quick start

Start the control plane first (`runeward serve`, default
`http://localhost:8080`), then:

```python
from runeward import RunewardClient, RunewardDenied, RunewardApprovalRequired

rw = RunewardClient("http://localhost:8080")  # uses RUNEWARD_API_TOKEN when set

sbx = rw.create_sandbox("dev")          # -> {"id": "sbx_...", "backend": "docker", ...}
sid = sbx["id"]

result = rw.shell(sid, ["python3", "--version"])
print(result["stdout"])                 # "Python 3.11.2\n"

rw.write_file(sid, "main.py", "print(2 + 2)")
print(rw.python(sid, "exec(open('/workspace/main.py').read())")["stdout"])  # "4\n"

rw.kill_sandbox(sid)                    # always tear down when done
```

Use `allow_insecure=True` (or `RUNEWARD_ALLOW_INSECURE_HTTP=1`) only when you must call a non-loopback `http://` control-plane endpoint.

### Handling governance verdicts

The two governance outcomes are raised as typed exceptions. Handle them
explicitly — a denial must **not** be blindly retried, and an approval gate must
**pause** for a human:

```python
try:
    rw.shell(sid, ["rm", "-rf", "/"])
except RunewardDenied as e:
    print("blocked by policy:", e.reason)     # do NOT retry the same action

try:
    rw.write_file(sid, "/etc/hosts", "127.0.0.1 example")
except RunewardApprovalRequired as e:
    print("needs a human:", e.approval_id)     # pause; ask an operator to approve/deny
```

### Refusals and request ids

When the server proves a call never ran, its body carries a standard
`refusal` object. The client parses it into a `Refusal` and, for refusals
that are not policy, authorization or approval outcomes (bad request,
unknown resource, `session_busy`, `version_conflict`, rate limits, budgets,
an unmet isolation floor), raises `RefusedError`. Every error, including
`RunewardDenied`, `RunewardAuthorizationError` and
`RunewardApprovalRequired`, exposes `request_id` (the server's
`X-Request-Id`) and `refusal`:

```python
from runeward import RefusedError, RunewardError

try:
    rw.agent_turn(session_id, ["claude", "-p", "next step"])
except RefusedError as e:
    print(e.reason, e.retryable, e.message, e.request_id)  # e.g. "request", False, ...
    if e.retryable:
        ...  # safe to send the identical request again later
except RunewardError as e:
    print("failed; quote this id to the operator:", e.request_id)
```

`rw.last_request_id` holds the id of the most recent response.

### Isolation

Citadel views carry `isolation` (`process`, `container`, `kernel` or `vm`:
the tier the sandbox actually runs behind), `isolation_evidence` (which
backend reported it and, on `get_sandbox`, the policy's floor and whether
it is met) and, for policies run under the in-sandbox supervisor,
`enforcement` (Landlock, seccomp, no_new_privs, uid/gid, dropped
capabilities).

### Workspaces, agent turns, schedules and shared memory

```python
fork = rw.fork_citadel(sid)                     # independent copy of the workspace
rw.sleep_citadel(sid); rw.wake_citadel(sid)     # persistent workspaces only
print(rw.workspace_status(sid)["state"])

sess = rw.start_agent_session(sid, ["claude", "-p", "fix the tests"])
rw.agent_turn(sess["id"], ["claude", "-p", "now update the docs"])
rw.cancel_agent_turn(sess["id"])                # does not rewind workspace changes

rw.create_schedule(["claude", "-p"], citadel=sid, every="1h",
                   prompt="triage new issues", precheck=["test", "-f", "NEW"])
for s in rw.list_schedules(citadel=sid):
    rw.run_schedule(s["id"])

rw.put_memory(cohort_id, "deploy/notes", "staging uses blue/green", tags=["ops"])
hits = rw.search_memory(cohort_id, "staging", tags=["ops"])
claimed = rw.claim_task(cohort_id, "agent-a", context=True)  # notes, brief, memory
```

### Approvals inbox

```python
for a in rw.list_approvals():
    print(a["id"], a["tool"], a["action"], a["reason"])

rw.approve("apr_31c")   # or rw.deny("apr_31c")
```

### Chronicle (audit ledger)

```python
events = rw.audit(sid)          # this Citadel's Chronicle events
assert rw.verify_audit()        # verify the tamper-evident hash chain
```

## Client method surface

| Method | REST endpoint |
| --- | --- |
| `healthz()` | `GET /healthz` |
| `list_profiles()` | `GET /v1/charters` |
| `whoami()` / `readiness(profile)` / `simulate_policy(...)` | Identity, setup, and dry-run policy APIs |
| `list_runs()` / `get_run(id)` | Durable provider-neutral Run lineage |
| `create_sandbox(profile)` | `POST /v1/citadels` |
| `list_sandboxes()` / `get_sandbox(id)` / `kill_sandbox(id)` | `GET`/`GET`/`DELETE /v1/citadels[/{id}]` |
| `shell(sandbox, command, workdir="")` | `POST .../shell/exec` |
| `python(sandbox, code)` / `node(sandbox, code)` | `POST .../code/{python,node}` |
| `read_file` / `write_file` / `list_files` / `search_files` | `POST .../file/{read,write,list,search}` |
| `audit(sandbox)` / `verify_audit()` | `GET .../chronicle`, `GET /v1/chronicle/verify` |
| `export_evidence(sandbox)` | Portable resolved Charter + signed Chronicle evidence |
| `create_cohort` / `list_cohorts` / `add_task` / `claim_task(context=)` | Cohort lifecycle and leased work queue |
| `heartbeat_task` / `complete_task` / `fail_task` (`handoff=`) | Signed-lease task transitions |
| `add_child_task` / `add_task_note` / `set_task_brief` / `task_context` | `POST .../tasks/{id}/{children,notes}`, `PUT .../brief`, `GET .../context` |
| `list_memory` / `search_memory` / `put_memory` / `get_memory` / `delete_memory` | `GET`/`POST /v1/cohorts/{id}/memory`, `GET`/`DELETE .../memory/{key}` |
| `fork_citadel` / `sleep_citadel` / `wake_citadel` / `workspace_status` | `POST .../{fork,sleep,wake}`, `GET .../workspace/status` |
| `start_agent_session` / `list_agent_sessions` / `get_agent_session` / `agent_session_events` | `POST .../agent-sessions`, `GET /v1/agent-sessions[/{id}[/events]]` |
| `agent_turn` / `cancel_agent_turn` | `POST /v1/agent-sessions/{id}/{turns,cancel}` |
| `list_schedules` / `create_schedule` / `get_schedule` / `delete_schedule` / `run_schedule` | `/v1/schedules`, `/v1/{citadels,cohorts}/{id}/schedules` |
| `perimeter(sandbox)` | `GET .../perimeter` (with request-broker fields) |
| `create_snapshot` / `list_snapshots` / `restore_snapshot` | Tenant-scoped recovery |
| `list_approvals()` / `approve(id)` / `deny(id)` | `GET /v1/conclave`, `POST /v1/conclave/{id}/{approve,deny}` |

## LangChain

```python
from runeward import RunewardClient
from runeward.langchain_tools import make_runeward_tools

tools = make_runeward_tools(RunewardClient("http://localhost:8080"))
# Pass `tools` to any LangChain agent / AgentExecutor.
```

The Python framework tools use the same stable concept names as MCP, including
`runeward_create_citadel`, `runeward_kill_citadel`, and
`runeward_list_conclave`. Governance verdicts are returned as descriptive
strings so the agent can reason about a denial or an approval gate.

## CrewAI

```python
from runeward import RunewardClient
from runeward.crewai_tools import make_runeward_tools

tools = make_runeward_tools(RunewardClient("http://localhost:8080"))
# Attach `tools` to a crewai.Agent(tools=tools, ...).
```

## LlamaIndex

```python
from runeward import RunewardClient
from runeward.llamaindex_tools import make_runeward_tools

tools = make_runeward_tools(RunewardClient("http://localhost:8080"))
# Pass `tools` to a FunctionAgent / ReActAgent / AgentRunner.
```

Returns `llama_index.core.tools.FunctionTool` instances; the tool schema is
derived from each function's type hints and docstring.

## OpenAI Agents SDK

```python
from agents import Agent, Runner
from runeward import RunewardClient
from runeward.openai_agents_tools import make_runeward_tools

tools = make_runeward_tools(RunewardClient("http://localhost:8080"))
agent = Agent(name="builder", instructions="Use the sandbox tools.", tools=tools)
result = Runner.run_sync(agent, "Create a dev sandbox, run `node --version`, then tear it down.")
```

Returns `@function_tool`-built tools; the SDK derives each schema from the
function's type hints and docstring.

## Strands Agents SDK

```python
from strands import Agent
from runeward import RunewardClient
from runeward.strands_tools import make_runeward_tools

tools = make_runeward_tools(RunewardClient("http://localhost:8080"))
agent = Agent(tools=tools)
agent("Create a dev sandbox, run `node --version`, then tear it down.")
```

Returns `@tool`-decorated functions; Strands derives each schema from the
function's type hints and docstring.

## Notes

- **`deny` is a policy decision, not a transient error.** Don't retry the same
  action; pick a different, allowed approach.
- **`require-approval` is a hard pause.** Surface the `approval_id` to a human
  and wait for the outcome.
- Prefer the tightest profile that lets the task succeed.
