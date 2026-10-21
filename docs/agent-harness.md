# Agent harnessing

Rune Box is an **agent governance harness**: an enforcement and evidence boundary around agents
that already exist. It does not choose a model, plan tasks, or replace an orchestration framework.
It governs the actions that an agent attempts to take.

```text
agent or subagent
        ↓
Rune Box policy → human approval when required → budgets → Citadel → signed Chronicle
```

The existing Rune Box concepts and programmatic names do not change:

- A **Citadel** is an isolated sandbox.
- A **Charter** is its policy and limits profile.
- A **Chronicle** is its signed audit trail.
- A **Cohort** is a group of peer workers sharing a task board.

## One agent

Connect the agent through MCP or one of the Python and TypeScript adapters. Give it a Charter with
the smallest tool, network, filesystem, and budget surface needed for the job. A denied action is a
final policy decision; an approval-required action pauses until an operator decides it.

## Peer workers

Use a Cohort when several equivalent workers should pull independent tasks from one command board.
Every worker runs in a Citadel created from the Cohort's Charter. The Cohort name and API remain
unchanged.

## Parent agents and delegated subagents

A subagent is a child delegated by a parent agent; it is not another name for a Cohort. To harness
an orchestrator that already supports subagents:

1. Route the parent and every child agent's tool calls through Rune Box.
2. Give each child its own Citadel when workspaces or evidence must be isolated.
3. Pass `parent_citadel`, `run_id`, `agent`, `provider`, and `model` when creating the child.
4. Give each child a distinct actor identity in the same tenant. Assign the parent's Charter or a
   narrower one. Rune Box rejects a child that changes the tenant or whose Charter it cannot prove
   is no broader than the parent's (see [Charter subsumption](#charter-subsumption)).
5. Never automatically retry a denial or work around an approval gate in a child agent.

Rune Box writes the lineage metadata to the Chronicle and a durable provider-neutral Run record.
`GET /v1/runs`, `runeward_list_runs`, and the dashboard recovery view expose the run tree even after
a Citadel is torn down.

### Charter subsumption

A delegated child (`parent_citadel` on `POST /v1/citadels` or the `runeward_create_citadel` MCP
tool) and a fork (`POST /v1/citadels/{id}/fork`, `runeward_fork_citadel`) may run under a
different Charter than their parent only when Rune Box can prove it grants no more power. The
check is conservative: it may refuse a Charter that is in fact narrower when containment cannot be
decided, but it never accepts a broader one. The parent's own Charter, unchanged, is admitted on a
fast path (`exact`).

| Dimension | The child is admitted when |
| --- | --- |
| `[[policy]]`, `policy_default` | For every action the child's verdict is no broader than the parent's (deny < require-approval < allow). The built-in first-match rules are compared exactly over every tool, every argument (an automaton over all `match` globs) and every combination of `match_argv` outcomes, so rule order is honoured: a child deny the parent lacked is fine; a child allow that shadows a parent deny is refused. An unset `policy_default` uses the server's `RUNEWARD_POLICY_DEFAULT`. |
| CEL, Rego, policy bundles | The configuration is identical (Rego inline, bundles pinned by `@sha256:` digest), or the child's built-in rules deny everything, or the parent's built-in rules allow everything. |
| `[network]` | The parent's egress is unrestricted, or the child's gate admits no hostname, port or IP range the parent's refuses (rule order honoured), keeps `enforce = "strict"`, and is not unrestricted itself. Hostname rules that could match IP literals are only accepted when identical. |
| `[[endpoint]]`, `[[credential]]` | Each child credential is one of the parent's. Wherever the parent inspects an endpoint, the child has one with the same protocol, enforce mode, credential and `health_path`, a subset of its `binaries`, no larger budgets, every parent deny rule, and a non-empty prefix of the parent's ordered allow rules with effects at least as strict. |
| Containment | `[isolation] minimum` is at least the parent's; host type, name, image, user, entrypoint, runtime, seccomp and AppArmor are unchanged; `copy_from` adds nothing; a read-only root stays read-only; `[filesystem]` grants (and `include_workdir`) are beneath the parent's with Landlock no weaker; `[process]` identity is unchanged. |
| Features | `[workspace] persist`, `[schedule] self_service` and `[ide]` only when the parent has them. |
| `[rationing]` | Every cap the parent sets is set and no higher (`wall_clock`, `max_execs`, `memory`, `cpus`, `egress_requests`, `max_tokens`, `max_cost_usd`); loop detection is at least as sensitive. |
| `[[env]]`, `[[file]]` | Every entry is one of the parent's. |
| `[chronicle]` | Same sink, redaction not disabled, every parent scrub pattern kept. |

Name, `prompt`, discovered `capabilities`, `packages`, `[cohort]` and the workspace idle timeout grant
no authority and are not compared.

A refusal is `403` and names the dimension and rule, for example `policy: child policy[0] (tool
"shell", match "git *", allow) yields allow for an action like shell "git push" …, where the
parent's policy[0] … yields deny`. A refused delegation is Chronicled on the parent as tool
`citadel`, action `delegate`, verdict `deny`. An admitted child's Run record and its `sandbox
create` (or `citadel fork`) event carry `charter_lineage` (`exact`, `subsumed`, or
`admin-override` for an administrator's fork), `parent_charter` and `charter_proof`, a per-dimension
summary of what was proven.

Limitations: `match_argv` globs are compared only by identity (a different executable glob is
refused rather than related to the parent's); CEL and Rego are never compared semantically; a
parent that was forked with smaller resource overrides is compared by its Charter's limits.

Cohort task claims are capabilities, not just worker-supplied names. A claim returns a signed,
expiring `lease_token`; heartbeat refreshes it, and complete/fail must present the current token.
This prevents one agent in a shared tenant from finishing another worker's task by guessing its id.

## Integration choices

| Agent surface | Recommended connection |
| --- | --- |
| MCP-capable agent or IDE | `runeward mcp` |
| Browser IDE against `/workspace` (experimental) | `[ide]` + ticketed proxy — [Browser IDE](browser-ide.md) |
| Python agent framework | `runeward` package and the relevant optional adapter |
| TypeScript agent framework | `@runeward/sdk` and its framework subpath |
| Custom orchestrator | REST API or the dependency-light SDK client |
| Parallel peer workers | Existing `runeward cohort` commands and `/v1/cohorts` API |
| Live/replayable worker output | Durable agent sessions and `/v1/agent-sessions/{id}/stream` |

See [Adapters](adapters.md), [Cohorts](fleets.md), the [Security model](security-model.md), and
[Browser IDE](browser-ide.md) for the experimental code-server path and its limitations.
