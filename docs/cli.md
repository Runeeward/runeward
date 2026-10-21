# CLI reference

The `runeward` binary is the primary entrypoint. A bare Charter name is shorthand
for `enter <charter>`.

## Global flags

| Flag | Description |
| --- | --- |
| `-c`, `--config-dir` | Pin Charter resolution to a directory (or `$RUNEWARD_CONFIG_DIR`). |
| `--help` | Help for any command. |
| `--version` | Print the version. |

## Environment

| Variable | Purpose |
| --- | --- |
| `RUNEWARD_CONFIG_DIR` | Default Charter directory. |
| `RUNEWARD_STATE_DIR` | Where the ledger, keys, terminal recordings, and Cohort state live. **Use a distinct value per running instance.** |
| `RUNEWARD_API_TOKEN` | Bearer token required on every control-plane request (see `--token`). |
| `RUNEWARD_BASE` | Control-plane base URL for the REST-client commands (`cohort`, `citadel`, `session`, `schedule`); same as `--base`, default `http://127.0.0.1:8080`. |
| `RUNEWARD_AUTHZ_FILE` | JSON file of named RBAC principals (per-token profile/approval scopes); upgrades the single shared token to multi-principal auth. |
| `RUNEWARD_OIDC_ISSUER` / `RUNEWARD_OIDC_AUDIENCE` | Verify OIDC bearer JWTs and map signed Rune Box tenant/role claims. |
| `RUNEWARD_OIDC_JWKS_URL` | Optional explicit JWKS endpoint; normally discovered from the issuer. HTTPS required except on loopback. |
| `RUNEWARD_CREDENTIALS_FILE` | Optional path for the private client credential written by `runeward auth login`. |
| `RUNEWARD_RATE_LIMIT` | Requests/sec per client IP; defaults to `50`. Set `0`/`off` only for trusted benchmarks. |
| `RUNEWARD_RECORD_TERMINALS` | `1` records governed terminal sessions as asciinema casts under the state dir. |
| `RUNEWARD_AUDIT_WEBHOOK_URL` / `RUNEWARD_AUDIT_FILE` | Stream Chronicle events to a webhook and/or file sink in real time. |
| `RUNEWARD_COPY_FROM_ROOTS` | Colon-separated allowlist restricting `copy_from`/seed source directories. |
| `RUNEWARD_MCP_DEFAULT_TOKEN` | Selects the principal for a stdio MCP process; falls back to `runeward auth login`. |
| `RUNEWARD_K8S_NAMESPACE` | Namespace for k8s Citadel pods (default `runeward`). |
| `RUNEWARD_K8S_PSA_ENFORCE` | Pod Security Admission enforce level for the managed namespace (`privileged`\|`baseline`\|`restricted`; default `privileged`). |
| `RUNEWARD_K8S_DIRECT_VOLUME_CLASS` | StorageClass whose CSI driver hands volumes to Kata as direct-assigned block devices; workspaces on Kata with Firecracker (`kata-fc`) use it so they are a real disk and can persist. See [Isolation](isolation.md#kata-with-firecracker-kata-fc). |
| `RUNEWARD_K8S_NETWORK_POLICY` | Truthy creates a default-deny (DNS-only egress) NetworkPolicy in the managed namespace. |
| `RUNEWARD_MICROVM_DIR` | State and image-disk cache of the native microVM backend (`host.type = "microvm"`; default `~/.runeward/microvm`). Keep it short: its Unix socket paths must fit about 100 bytes. See [Isolation](isolation.md#native-microvms-hosttype-microvm). |
| `RUNEWARD_MICROVM_VMM` | The monitor a `microvm` Charter without `host.runtime` gets: `firecracker` or `libkrun` (default: Firecracker when configured). |
| `RUNEWARD_MICROVM_AGENT` | The static `runeward-vmagent` binary booted as the guest's PID 1 (default: next to `runeward`, then `PATH`). |
| `RUNEWARD_MICROVM_KERNEL` | The uncompressed guest kernel Firecracker boots. |
| `RUNEWARD_FIRECRACKER_BIN` | The `firecracker` binary (default: `PATH`). |
| `RUNEWARD_KRUN_HELPER` / `RUNEWARD_LIBKRUN` | The `runeward-krun` helper (default: `PATH`) and the libkrun library it loads (default `libkrun.so.1`, `libkrun.1.dylib` on macOS); libkrun must be built with block-device support. |
| `RUNEWARD_MICROVM_DISK_SIZE` | Size of a new persistent workspace disk (sparse; default `8g`). |
| `RUNEWARD_MICROVM_MKFS` | `mkfs.ext4` used to build image and workspace disks (`debugfs` is taken from the same directory). |
| `RUNEWARD_DNS_RESOLVERS` | Comma-separated resolver IPs to confine DNS to under strict egress. |
| `RUNEWARD_ENABLE_EXPERIMENTAL_BROWSER` | Set to `1` to enable the experimental browser surface in a trusted deployment; disabled by default. |
| `RUNEWARD_ENABLE_EXPERIMENTAL_IDE` | Set to `1` to enable the optional in-Citadel browser IDE (code-server) + ticketed reverse proxy; disabled by default. See [Browser IDE](browser-ide.md). |
| `RUNEWARD_OP_BIN` / `OP_SERVICE_ACCOUNT_TOKEN` | Locate and authenticate the 1Password CLI (`op`) that resolves `op://` Charter references; the desktop app integration works without a token. See [Charters](profiles.md#1password-op). |
| `GITHUB_TOKEN` | Optional GitHub credential for an agent running inside a Citadel. Rune Box injects it only when the Charter explicitly references `op = "env://GITHUB_TOKEN"`; use a least-privilege token and never place it in an MCP config or committed file. Host `gh` authentication is not passed into a Citadel automatically. |
| `OPENAI_BASE_URL` | Optional OpenAI-compatible API endpoint for agents or SDKs. It is used only when a Charter explicitly injects it; leave it unset for the provider's default endpoint. For Docker-hosted gateways use a container-reachable address such as `http://host.docker.internal:11434/v1` and allow the hostname in the Charter's network policy. |

Provider and source-control variables are not ambient Citadel credentials. They
remain on the host unless a Charter deliberately imports them with an `env://`
secret source, where they become subject to readiness validation, redaction,
and the Charter's egress policy.

## Commands

| Command | Description |
| --- | --- |
| `runeward auth login\|status\|logout` | Save or remove a client credential using OIDC device flow or `--token-stdin`. |
| `runeward init [project-dir]` | Create `.runeward/quickstart.toml` without overwriting an existing policy. |
| `runeward quickstart [project-dir]` | Prove allow, pre-execution denial, and signed audit. |
| `runeward doctor [charter] [--json]` | Check policy, runtime, required secret sources, image, and state readiness. |
| `runeward enter <charter> [-- cmd...]` | Create a Citadel and open a shell, or run a one-shot command. |
| `runeward serve [--bind ADDR] [--port N] [--token ... --tls-cert ... --tls-key ...] [--allow-insecure-http] [--no-ui] [--hardened]` | Start the control plane: REST API + web dashboard (default `--bind 127.0.0.1 --port 8080`). A non-loopback `--bind` requires authentication (`--token`/`RUNEWARD_API_TOKEN` of at least 32 characters, or `RUNEWARD_AUTHZ_FILE`) and TLS, unless `--allow-insecure-http` is passed for a trusted TLS-terminating proxy; `--no-ui` serves the REST API without the dashboard. `--hardened` (or `RUNEWARD_HARDENED=1`) refuses to start unless every hardened-mode check passes. |
| `runeward mcp [--http --tls-cert ... --tls-key ...]` | Run stdio or streamable-HTTP MCP exposing governed tools to an IDE/agent. |
| `runeward list` | List reachable Charters. |
| `runeward print <charter>` | Print a Charter's resolved, secret-redacted policy. |
| `runeward validate [charter...] [--strict]` | Statically lint Charters (missing images, unresolved secrets, unreachable rules, duplicate env); with no names, every resolvable Charter. `--strict` also fails on warnings. |
| `runeward policy test <charter> [--cases <file>] [--case <spec>]...` | Simulate a Charter's policy against sample actions from a TOML file (`--cases`) and/or inline `--case tool=...,action=...,expect=...` flags, exiting non-zero on mismatch. |
| `runeward policy scaffold [template] [--list]` | Print a ready-made policy template for a common control. |
| `runeward policy learn <evidence-or-chronicle.json>` | Print exact, reviewable proposals from a verified audit trail. |
| `runeward evidence export <charter> [-o file]` | Package the resolved policy and signed Chronicle events. |
| `runeward evidence verify <file>` | Verify the policy digest, event chain, and every signature. |
| `runeward charter sign\|verify <file>` | Produce/verify a detached ed25519 signature over a Charter. |
| `runeward runtime check\|guide\|install <gvisor\|kata>` | Inspect, explain, or install hardened runtimes (gVisor/Kata). |
| `runeward replay <cast>` | Replay a recorded terminal session (asciinema v2 cast). |
| `runeward export <citadel-id> <dest-dir>` | Copy a Citadel workspace back to the host (Docker and k8s). |
| `runeward cohort ...` | Drive multi-agent Cohorts — see [Cohorts](fleets.md) and [Cohort memory and task context](#cohort-memory-and-task-context). |
| `runeward citadel fork\|sleep\|wake\|status\|perimeter <id>` | Manage a running Citadel's workspace — see [Citadels, sessions and schedules](#citadels-sessions-and-schedules). |
| `runeward session turn\|attach\|cancel <session-id>` | Start, follow and cancel agent-session turns. |
| `runeward schedule create\|list\|get\|delete\|run` | Manage scheduled agent runs. |
| `runeward chronicle verify <bundle.json>` | Verify an exported, signed Chronicle transcript offline. |
| `runeward archive ...` | Manage signed OCI policy Archives (`keygen`, `push`, `pull`). |
| `runeward controller` | Run the Kubernetes controller (watches CRDs). |
| `runeward webhook` | Run the admission webhook. |
| `runeward up` | One-command install of the in-cluster control plane. |
| `runeward version` | Print version information. |

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Success. |
| `1` | Any other error, including malformed or unknown requests and usage errors. |
| `3` | Refused by policy, a human approval gate, missing permission, or an unmet isolation floor. Nothing ran. |
| `4` | Refused for a spent budget, capacity (rate limit) or load shedding. Nothing ran; retrying later may succeed. |

When the control plane answers with its standard `refusal` object, the CLI
prints one line to stderr instead of `error: ...`:

```text
refused (policy, retryable=false, request_id=5f0c9a7e21b4d3c8): denied by policy: no deletes
```

Quote the `request_id` when reporting a refusal; it matches the server's
`X-Request-Id` and log lines.

## Citadels, sessions and schedules

These commands are REST clients of a running `runeward serve`. Like
`cohort`, they take `--base` (or `$RUNEWARD_BASE`, default
`http://127.0.0.1:8080`) and `--token` (or `$RUNEWARD_API_TOKEN`, else the
`runeward auth login` credential). Add `--json` to print the server's JSON
instead of text. See [Workspaces and context](workspaces-and-context.md).

| Command | Description |
| --- | --- |
| `citadel fork <id> [--charter X]` | Copy the workspace into a new, independent Citadel. A Charter not provably within the source's ([Charter subsumption](agent-harness.md#charter-subsumption)) needs an administrator. |
| `citadel sleep <id>` | Sleep a persistent Citadel now (Charter `[workspace] persist = true`); the workspace disk is kept. |
| `citadel wake <id>` | Wake a sleeping Citadel under the same id. |
| `citadel status <id>` | The isolation tier the backend delivered, usage, capabilities and the workspace state (`running`/`sleeping`, idle time, last sleep/wake, `forked_from`). |
| `citadel perimeter <id>` | Table of egress and request-broker decisions (time, verdict, target, tool, reason). |
| `session turn <session-id> <prompt> [--agent A] [--model M]` | Start the next turn with the session's agent CLI (or `--agent`) and stream its output. |
| `session attach <session-id> [--after N]` | Replay the transcript after sequence `N`, then follow live output until the turn ends. Safe to re-run after a dropped connection. |
| `session cancel <session-id>` | Cancel the active turn. Cancel does not rewind: changes already made stay. |
| `schedule create (--citadel ID \| --cohort ID) (--cron "0 6 * * *" \| --every 30m) [--agent A] [--model M] [--prompt P] [--precheck "cmd args"] [-- cmd...]` | Schedule recurring runs. Without an explicit command after `--`, the agent CLI is used; the prompt is appended as the last argument when it fires. |
| `schedule list [--citadel ID \| --cohort ID]` | List visible schedules. |
| `schedule get\|delete\|run <id>` | Show, delete, or fire a schedule now (policy, precheck and budgets still apply). |

With `--json`, `session turn` and `session attach` print one JSON event per
line (`seq`, `stream`, `data`). Otherwise agent stdout goes to stdout, agent
stderr to stderr, and status events to stderr as `runeward: [status #N] ...`.

## Cohort memory and task context

These `cohort` subcommands use the active Cohort (`cohort up`) or
`--cohort <id>`, and accept `--json`.

| Command | Description |
| --- | --- |
| `cohort memory put <key> <text> [--tag T]... [--expected-version N]` | Write a shared memory entry (`--expected-version 0`: the key must be new). |
| `cohort memory get <key>` | Read one entry. |
| `cohort memory search [query] [--tag T]... [--limit N] [--max-bytes N]` | Ranked, byte-capped search. |
| `cohort memory list` | List every entry. |
| `cohort memory delete <key> [--version N]` | Delete an entry (conditionally with `--version`). |
| `cohort note <task> <text>` | Leave a handoff note on a task. |
| `cohort brief <task> <brief> [--for AGENT]` | Set the brief an agent gets when it claims the task (`*`, the default, means every agent; an empty brief clears it). |
| `cohort handoff <task> --lease-token T --note N [--result R] [--requeue] [--owner W]` | Complete a claimed task (or give it back with `--requeue`) and leave a note. |
| `cohort task context <task> [--for AGENT] [--memory-bytes N]` | Show what an agent gets on claim: brief, handoff notes, parent and ranked memory. |
| `cohort task child <task> <payload>` | Split a task by adding a linked child task. |

`cohort run` and `cohort build` claim tasks with their context. When a task
has a brief, notes, a parent or matching memory, the agent's prompt is the
task followed by a section between
`--- Rune Box task context (...) ---` and `--- end of Rune Box task context ---`.
When the agent finishes, the task is completed with a handoff note holding
the last 2 KiB of its output. A failed attempt leaves a note too, and
non-retryable refusals are not requeued. `cohort exec` does the same for
its own prompt when no older tasks are pending on the Command Board.
Otherwise it runs the prompt without a task, as before.

## Examples

```bash
# First-run proof
runeward quickstart

# Interactive Citadel
runeward --config-dir examples enter ns-auto

# One-shot command
runeward --config-dir examples enter ns-auto -- python --version

# Control plane with an isolated state dir
RUNEWARD_STATE_DIR=/tmp/rw runeward --config-dir examples serve

# Verify an exported Chronicle bundle
runeward chronicle verify ./transcript.json

# Sign and publish a policy Archive
runeward archive keygen --out ./keys
runeward archive push oci://ghcr.io/acme/runeward-policies:v3 \
  --policy prod.rego --engine rego --key ./keys/bundle.key

# Authenticated control plane on a non-loopback bind
RUNEWARD_API_TOKEN=$(openssl rand -hex 32) \
  runeward --config-dir examples serve --bind 0.0.0.0 --port 8443 \
  --tls-cert ./tls/server.crt --tls-key ./tls/server.key

# OIDC device login for Cohort CLI and stdio MCP clients
runeward auth login --issuer https://id.example.com \
  --client-id runeward-cli --audience runeward

# Lint every Charter in a directory and unit-test a policy
runeward --config-dir examples/safe validate --strict
runeward --config-dir examples policy test ns-auto \
  --case "tool=shell,action=rm -rf /,expect=deny"

# Scaffold a common policy and append it to a Charter
runeward policy scaffold package-approval >> mycharter.toml

# Export portable evidence, verify it, and draft reviewed policy additions
runeward --config-dir examples evidence export ns-auto -o evidence.json
runeward evidence verify evidence.json
runeward policy learn evidence.json > proposed-policy.toml

# Persistent workspaces, forks and resumable turns
runeward citadel status cit-1234
runeward citadel sleep cit-1234
runeward citadel fork cit-1234 --charter review
runeward session turn 9f2c... "now add tests for the parser"
runeward session attach 9f2c... --after 120

# Shared Cohort memory, briefs and a nightly schedule
runeward cohort memory put billing/db "postgres 16 on the primary" --tag database
runeward cohort brief task-3 "keep the migration reversible" --for claude
runeward schedule create --cohort coh-1 --every 24h --agent codex \
  --prompt "triage new issues" --precheck "test -f /workspace/.triage"

# Install and verify a hardened runtime (dry-run by default; --apply to execute)
runeward runtime install gvisor            # prints the plan
runeward runtime install gvisor --apply    # downloads + registers runsc
runeward runtime check                     # confirm it's registered
```
