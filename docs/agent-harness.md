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
4. Give each child a distinct actor identity in the same tenant. Assign the parent's Charter.
   Rune Box rejects a child that changes either the tenant or Charter.
5. Never automatically retry a denial or work around an approval gate in a child agent.

Rune Box writes the lineage metadata to the Chronicle and a durable provider-neutral Run record.
`GET /v1/runs`, `runeward_list_runs`, and the dashboard recovery view expose the run tree even after
a Citadel is torn down. Rune Box does not yet prove arbitrary policy-set subsumption; v1
deliberately requires the exact parent Charter instead of guessing whether a different Charter is
narrower.

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
