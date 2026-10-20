# Cohorts

A Cohort is N governed Citadels coordinated by an atomic Command Board. It's how
you run many agents in parallel (or iterate on one app) with the same isolation,
policy, egress, and audit guarantees as a single environment.

The `runeward cohort` command is a client to a running control plane
(`runeward serve`), so start that first.

## Subcommands

| Command | What it does |
| --- | --- |
| `runeward cohort up [charter]` | Create a Cohort of workers from a Charter. |
| `runeward cohort add <prompt>` | Queue a task (its own workspace when a worker picks it up). |
| `runeward cohort run` | Let idle workers claim and execute queued tasks in parallel. |
| `runeward cohort build <prompt>` | Shorthand: add a task and run it. |
| `runeward cohort exec <prompt>` | Run a prompt pinned to a single Citadel (accumulates in one workspace). |
| `runeward cohort status` | Show workers and Command Board state. |
| `runeward cohort export [dir]` | Copy the finished workspace(s) back to the host. |
| `runeward cohort down` | Tear the Cohort down. |

Select the agent and model with environment variables, e.g. `AGENT=claude`,
`MODEL=sonnet`, `AGENT=codex MODEL=gpt-5-codex`, or `AGENT=cursor`.
When the control plane uses a shared token or RBAC, also set
`RUNEWARD_TOKEN` to the worker principal's token. The example drivers attach
it as a bearer credential and use the signed task lease returned by every
claim; they never persist the token in `.runeward-fleet`.

## Two ways to work

Each worker has its own `/workspace` (Cohort isolation), so it matters whether
follow-ups land on the same one.

### A) Iterate on one app

Use `exec`, which pins to a single Citadel — the "pass a prompt, then add more
prompts/changes" flow where the same code accumulates:

```bash
AGENT=claude MODEL=sonnet runeward cohort up
runeward cohort exec "Build a FastAPI todo API in app/ with SQLite and pytest"
runeward cohort exec "Now add a PUT /todos/{id} endpoint and tests"   # same code
runeward cohort exec "Add a Dockerfile and a README"
runeward cohort export ./out
```

`cohort run`, `build`, and `exec` create durable agent sessions instead of
waiting on a buffered shell call. stdout/stderr appears while the agent is
working, and the dashboard's **Agent sessions** panel can reopen the redacted
transcript afterward. Each session records its Cohort/task/Citadel association;
the REST event stream supports reconnect from the last sequence received.
See the [recorded live agent and escape-denial demo](agent-session-escape-demo.md)
for a reproducible end-to-end walkthrough.

Switch agent/model any time by changing the env vars.

### B) Fan-out independent pieces

Use `add` + `run`; each prompt goes to whichever worker is free, in its own
workspace, and they build in parallel:

```bash
RUNEWARD_TOKEN="$DEV_TOKEN" AGENT=codex ./examples/fleet.sh up build-fleet-k8s
RUNEWARD_TOKEN="$DEV_TOKEN" AGENT=codex ./examples/fleet.sh add "Build the auth module in auth/ with tests"
RUNEWARD_TOKEN="$DEV_TOKEN" AGENT=codex ./examples/fleet.sh add "Build the billing module in billing/ with tests"
RUNEWARD_TOKEN="$DEV_TOKEN" AGENT=codex ./examples/fleet.sh add "Build the CLI in cmd/ with tests"
RUNEWARD_TOKEN="$DEV_TOKEN" AGENT=codex ./examples/fleet.sh run
```

## Inter-agent coordination

Agents don't talk peer-to-peer. Coordination happens through the control plane's
**atomic Command Board**: workers claim tasks under a lease, heartbeat while
working, and mark completion. If a worker dies, its lease expires and the task is
reclaimed by another. This is the same on Docker and Kubernetes.

## Multiple keys and local LLMs

A Cohort can mix providers (Cursor, Codex, Claude) and keys, and can target a
**local LLM** exposed over an OpenAI-compatible endpoint (e.g. Ollama, LM Studio)
by adding the endpoint to the Charter's egress allowlist and pointing the agent's
base-URL env var at it. See
[`examples/build-fleet.toml`](https://github.com/Runewardd/runeward/blob/main/examples/build-fleet.toml)
and
[`examples/build-fleet-k8s.toml`](https://github.com/Runewardd/runeward/blob/main/examples/build-fleet-k8s.toml).
