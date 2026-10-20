# Concepts

Rune Box is a small control plane in front of a pluggable execution backend.
Everything an agent does passes through one governed path.

## Product vocabulary

Rune Box uses a desert-governance vocabulary in its dashboard and explanatory
copy. It is original product language, not a protocol change or a reference to
another fictional universe:

- **Citadel** — a sandbox or execution environment.
- **Cohort** — a fleet of Citadels.
- **Charter** — a profile: the declarative security contract for a Citadel.
- **Oracle** — policy simulation and preflight evaluation.
- **Conclave** — the human approval queue.
- **Chronicle** — the tamper-evident audit ledger.
- **Perimeter** — egress controls and their decision history.
- **Rationing** — time, execution, network, token, and cost guardrails.
- **Command Board** — a Cohort's shared task board.
- **Archive** — signed policy bundles and approved Charter templates.

These names are the canonical identifiers across the product: the CLI commands
(`runeward cohort`, `runeward chronicle`, `runeward charter`, `runeward
archive`), the REST paths (`/v1/citadels`, `/v1/cohorts`, `/v1/conclave`,
`/v1/chronicle`, `/v1/charters`, and the per-Citadel `/perimeter`), the MCP tool
names (`runeward_create_citadel`, `runeward_create_cohort`,
`runeward_list_conclave`, …), the Kubernetes CRD kinds (`Citadel`, `Cohort`),
and the Charter TOML tables (`[cohort]`, `[chronicle]`, `[rationing]`) all use
this vocabulary. Two things deliberately keep their historical spellings for
stability: the product/binary name `runeward` itself, and the JSON wire field
keys inside request/response bodies (e.g. `{"profile": "…"}`, the `sandbox`
argument to an MCP tool) along with the language SDK method names. `policy` (the
concept and its `[[policy]]` table) and `snapshot` are unchanged.

## The governed path

Every action — from REST, the dashboard, or MCP — flows through the same
pipeline before it touches a backend:

```
request -> policy engine -> approval gate -> guardrails -> backend exec -> audit ledger
```

If any stage says no, the action is denied or paused, and the outcome is recorded
either way.

## Citadel (sandbox / environment)

A **sandbox** is one isolated execution environment created from a
profile. It has its own filesystem workspace, its own egress policy, and its own
resource limits. Backends:

- **Docker/Podman** — zero-setup, ideal for laptops and CI.
- **Kubernetes** — Pods + PVCs, strict L3 egress via a sidecar, CRDs, an
  admission webhook for org-wide guardrails, and multi-tenancy hardening (Pod
  Security Admission labels + optional default-deny NetworkPolicy).

Everything above the backend is identical, so a profile runs the same either way.

## Charter (profile)

A **profile** is the declarative security contract for a sandbox: the base image,
workdir, network egress allowlist, environment/secret injection, per-action
policy, and resource limits. Anything not granted is denied by default. See
[Profiles](profiles.md).

## Policy, Oracle, and Conclave

Each action gets a verdict: `allow`, `deny`, or `require-approval`. The engine is
selectable per profile:

- `builtin` — first-match tool + glob rules.
- `cel` — CEL expressions over `{tool, arg}`.
- `rego` — an OPA/Rego module returning a decision.

`require-approval` pauses the action and surfaces it in the dashboard's
**Conclave** (and over REST) for a human to allow or deny. The dashboard's
**Oracle** simulates an action before it reaches this point; it does not alter
the policy or authorize the action.

## Perimeter (egress control)

Network egress is **deny-by-default**. Profiles declare an allowlist; on Docker
this is an in-process SNI-filtering proxy, and on Kubernetes it's enforced at L3
with a sidecar. Guardrails cap the number of egress requests to stop exfiltration
and runaway loops.

## Chronicle (audit ledger)

Every governed action and its verdict is appended to a **tamper-evident ledger**:
append-only, hash-chained, and signed with ed25519. It can be exported as a
transcript bundle and verified offline — the bundle embeds the public key, so a
third party can confirm nothing was altered or dropped.

!!! warning "One writer per ledger"
    The ledger is single-writer (guarded by a file lock). Run each instance with
    its own `RUNEWARD_STATE_DIR`; two processes sharing one ledger will break the
    hash chain and verification will report tampering.

## Cohorts (fleets)

A **fleet** is N sandboxes coordinated by an atomic **Command Board**. Workers
claim tasks with a lease (so a dead worker's task is reclaimed), do the work in
their own isolated workspace, and mark completion. See [Fleets](fleets.md).

## Rationing (guardrails)

Hard limits per sandbox: wall-clock time, exec count, egress request count, and
token/spend budgets (`rationing.max_tokens`, `rationing.max_cost_usd`, fed by the
usage API), plus retry-loop detection. When a cap is hit, further actions are
denied and logged.

## Developer gotchas

- A Citadel is never a mount of your project. `copy_from` makes a one-time
  copy; use `runeward export` to retrieve results.
- These names are the real identifiers, not display-only aliases: scripts call
  `/v1/citadels`, `runeward cohort`, and the `runeward_create_citadel` MCP tool.
  Only the JSON body field keys (e.g. `profile`, `sandbox`) and SDK method names
  keep their historical spellings; `[[policy]]` is unchanged.
- An Oracle result is advisory. It evaluates the supplied action against a
  Charter; the live action is still subject to current policy, approval, and
  guardrails.
- A Chronicle is single-writer. Give every Rune Box instance its own
  `RUNEWARD_STATE_DIR`; sharing it breaks ledger verification.
- Cohort members have separate workspaces. Use the Command Board for
  coordination rather than assuming that a change made by one worker appears
  in another worker's filesystem.

## Surfaces

The same governed core is reachable through:

- **CLI** — `runeward` ([reference](cli.md)).
- **REST API** — the control plane ([reference](rest-api.md)).
- **MCP server** — expose governed tools to an IDE/agent (Cursor, Claude Desktop,
  VS Code).
- **Web dashboard** — served by `runeward serve`.
- **Browser IDE (experimental)** — optional code-server inside the environment via ticketed
  proxy ([Browser IDE](browser-ide.md)); not a replacement for host MCP or
  desktop Cursor/Claude GUIs.
