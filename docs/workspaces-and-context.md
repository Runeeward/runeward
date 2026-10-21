# Workspaces and context

Long-running agents need two things to keep their context cheaply: a disk
that outlives idle periods, and a shared place to hand work from one agent
to the next. Rune Box provides both without leaving the governed path:
every operation below goes through policy, budgets and the signed
Chronicle, and is scoped to the caller's tenant.

## Persistent workspaces

```toml
[workspace]
persist = true        # keep the workspace disk across sleep/wake and restarts
idle_timeout = "15m"  # sleep after 15 minutes without activity (at least 1m)
```

Both settings default off; Charters without `[workspace]` behave as before.

- **Sleep.** After `idle_timeout` with no governed calls, attached
  terminals or running agent turns, the Citadel goes `sleeping`. Docker and
  Podman stop the container and keep it with its volumes; Kubernetes
  deletes the Pod and keeps the workspace PVC. You can also sleep a
  Citadel explicitly (`POST /v1/citadels/{id}/sleep`); it refuses with
  `409 citadel_busy` while something is active. Citadels with the browser
  IDE enabled never sleep on idle.
- **Wake.** Any governed call, terminal attach, agent turn, snapshot, fork
  or scheduled run wakes it transparently (`waking` → `running`) under the
  same id, run, environment, request broker and supervisor plan.
- **Restarts.** Persistent Citadels are recorded in `workspaces.json` in the
  control-plane state. A restarted control plane lists them as `sleeping`,
  keeps their runs `running`, stops any it finds still running, and on
  first use rebuilds the governed session (Charter, secrets, broker,
  supervisor, policy) around the kept workspace.
- **Audit.** Every sleep and wake is a Chronicle event (tool `workspace`,
  action `sleep`/`wake`, with the reason: `idle`, `manual`, `activity` or a
  restart recovery).

**Anything that must survive a sleep must be on disk in the workspace.**
Processes, open browser sessions, in-memory state and `/tmp` on a read-only
root are gone after a wake. Put repositories, caches and agent notes under
the workspace directory (`/workspace` by default).

From the CLI: `runeward citadel sleep|wake|status <id>`. Over MCP:
`runeward_sleep_citadel`, `runeward_wake_citadel` and
`runeward_workspace_status`.

## Fork

`POST /v1/citadels/{id}/fork` (MCP `runeward_fork_citadel`) copies a
Citadel's workspace into a new, independent Citadel. The fork gets a new
run whose `forked_from` names the source run; after the copy the two never
share state. A sleeping source is woken first.

The fork may use another Charter and smaller resource caps, but only an
administrator may fork into a Charter that is not provably within the
source's (see [Charter subsumption](agent-harness.md#charter-subsumption):
policy, egress, endpoints, credentials, containment, rationing, secrets and
the Chronicle are all compared) or into larger resources. An administrator
override is recorded on the fork's Run as `charter_lineage =
"admin-override"` with the refusal it overrode. The source's policy must
allow tool `citadel`, action `fork`.

## Resumable agent turns

An agent session runs one turn at a time. `POST /v1/agent-sessions/{id}/turns`
starts the next command in a finished (or interrupted) session; while a turn
is queued or running it answers `409 session_busy`. All turns share one
transcript, and a `turn` event marks where each new turn starts.

`GET /v1/agent-sessions/{id}/stream?after=<seq>` replays every event after
`seq` and then follows live output. Transcripts live in the control plane,
so a client that drops and reconnects with the last sequence it saw loses
nothing, including across control-plane restarts and while the Citadel
sleeps. A subscriber that falls behind is refilled from the transcript.

From the CLI, `runeward session turn <id> <prompt>` starts a turn and
streams it, and `runeward session attach <id> --after <seq>` replays and
then follows. Over MCP, `runeward_start_turn` starts a turn (or a new session
in a Citadel), `runeward_session_events` reads a bounded page of the
transcript after a sequence number, and `runeward_cancel_turn` cancels.

`POST /v1/agent-sessions/{id}/cancel` stops the active turn. **Cancel does
not rewind**: changes the command already made in the workspace stay, and
its output so far stays in the transcript.

## Cohort memory and handoffs

Each Cohort has a shared memory store kept in the control-plane state
(`cohort-memory/<cohort id>.json`), never inside a sandbox. An entry has a
`key`, `text`, `tags`, the `author` that last wrote it, timestamps and a
`version`.

- **Optimistic concurrency.** A write may name `expected_version` (`0`
  means the key must be new); a stale write fails with `409
  version_conflict`.
- **Search** ranks by tag match, key match, text match and recency, and
  caps the result by bytes.
- **Limits.** Keys up to 256 bytes, text up to 16 KiB, 16 tags, 1000
  entries and 4 MiB per Cohort; notes and briefs up to 8 KiB.
- **Audit.** Every write is attributed and Chronicled; with
  `[chronicle] redact` on (the default) the ledger stores a SHA-256 of the
  text, not the text.

On the task board:

- **Child tasks** split work (`POST .../tasks/{task}/children`).
- **Notes** are handoff messages on a task; `complete` and `fail` accept a
  `handoff` note for whoever picks up the work next.
- **Briefs** are per-agent instructions on a task (`*` for every agent).
- **Claim with context** (`"context": true`, or MCP `runeward_claim_task`)
  returns the task plus its handoff notes (the parent's, then its own), the
  brief for the claimant, a summary of the parent and a ranked slice of
  shared memory, so an agent starting fresh does not need to replay
  transcripts.

MCP tools: `runeward_memory_put`, `runeward_memory_get`,
`runeward_memory_search`, `runeward_add_note`, `runeward_set_brief`,
`runeward_handoff` (complete, or with `requeue` give the task back, and
leave a note) and `runeward_add_child_task`.

## Scheduled runs

A schedule targets one Citadel or one Cohort (it runs in the first member)
and fires on a 5-field UTC cron expression or a fixed interval (`every`, at
least `1m`). Schedules live in `schedules.json` in the control-plane state,
so they can wake a sleeping workspace. Each firing:

1. asks the Citadel's policy about tool `schedule`, action `fire`;
2. runs the optional `precheck` command in the sandbox as a governed shell
   call, and stops unless it exits 0, so a cheap check never starts an
   expensive agent;
3. starts a fresh agent session with `command` (plus `prompt` as its last
   argument), subject to policy, guardrails and budgets.

Missed windows are never backfilled: after downtime the schedule fires once
at most and the next time is computed from now. A firing is skipped while
the previous run is still active. At most 50 schedules may target one
Citadel or Cohort.

Operators manage schedules over REST or with `runeward schedule
create|list|get|delete|run`. Agents can manage their own over MCP
(`runeward_schedule_create`, `runeward_schedule_list`,
`runeward_schedule_delete`) only when the Charter allows it:

```toml
[schedule]
self_service = true   # default false
```

## State files

All of this state is in the control-plane state directory, in new files
that older control planes ignore: `workspaces.json`, `schedules.json` and
`cohort-memory/`. Fields added to existing files (`forked_from` on runs,
`turn` on agent sessions) are optional and omitted while empty.
