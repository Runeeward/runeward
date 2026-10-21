<p align="center">
  <img src="docs/assets/rune-box-banner.svg" alt="Rune Box: an environment where your agent can roam freely but with receipts" width="760" />
</p>

<p align="center">
  <b>Rune Box: an environment where your agent can roam freely but with receipts.</b><br/>
  The open-source governance harness for AI agents, by Runeward.
</p>

<p align="center">
  <a href="LICENSE"><img alt="License: Apache-2.0" src="https://img.shields.io/badge/license-Apache--2.0-blue.svg"></a>
  <a href="https://github.com/Runeeward/runeward/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/Runeeward/runeward/actions/workflows/ci.yml/badge.svg"></a>
  <a href="Cargo.toml"><img alt="Rust MSRV 1.95" src="https://img.shields.io/badge/rust-1.95%2B-orange.svg"></a>
  <a href="https://github.com/Runeeward/runeward/releases"><img alt="Release" src="https://img.shields.io/github/v/release/Runeeward/runeward?sort=semver"></a>
</p>

Put enforceable policy, human approvals, isolated execution, budgets, and signed evidence around
any AI agent. Rune Box works with an existing agent or multi-agent framework rather than requiring
a new model or orchestration stack.

<p align="center">
  <img src="docs/assets/runeward-proof.svg" alt="An agent action goes to policy: allowed actions run in the isolated sandbox, reviewed ones wait for human approval first, denied ones stop at policy, and every verdict lands in a signed audit trail" width="820" />
</p>

## Prove it in one command

Prerequisites: a running Docker, OrbStack, or Podman engine and the `runeward` binary.

```bash
runeward quickstart
```

The command creates `.runeward/quickstart.toml`, checks the policy, runtime, image, and state path,
runs an allowed command, proves a destructive command is denied before execution, and verifies the
signed audit trail. It never overwrites an existing policy unless `--force` is passed.

`doctor` and dashboard readiness also resolve required secret sources. A Charter that references an
unset `env://` value is not presented as launch-ready.

```bash
runeward doctor quickstart                     # explain setup problems safely
runeward --config-dir .runeward serve          # dashboard + governed REST API
runeward evidence export quickstart -o run.json
runeward evidence verify run.json              # independent policy/audit verification
```

## What Rune Box adds

| Concern | Container alone | Rune Box |
| --- | --- | --- |
| Tool calls | Executes what the process requests | Checks every shell, code, file, network, and browser action first |
| Risky actions | Application-specific | `allow`, `deny`, or `require-approval` with an attributed decision |
| Network | Usually open unless separately configured | Deny-by-default hostname policy; strict L3 enforcement on Kubernetes |
| Limits | CPU/memory | Wall-clock, exec, egress, token, cost, and retry-loop budgets |
| Audit | Runtime logs | Append-only, hash-chained, Ed25519-signed events |
| Handoff | Ad-hoc logs and folders | Workspace tar, recovery snapshots, and portable signed evidence JSON |
| Agent identity | One opaque process | Tenant, actor, parent run, provider, model, and durable run lineage |
| Interfaces | Runtime-specific | CLI, REST, MCP, web dashboard, Kubernetes CRDs, and local SDK adapters |

Every governed action follows one path:

```text
agent request → policy → human approval when required → limits → sandbox → signed audit event
```

## Naming

Documentation and UI use familiar terms first. Existing API paths and file fields retain the
original themed names for compatibility.

| Plain-language term | Rune Box name | Existing surface |
| --- | --- | --- |
| Sandbox | Citadel | `/v1/citadels`, Kubernetes `Citadel` |
| Policy file/profile | Charter | `/v1/charters`, `*.toml` profile |
| Approvals | Conclave | `/v1/conclave` |
| Signed audit trail | Chronicle | `/v1/chronicle`, `[chronicle]` |
| Network controls | Perimeter | `/perimeter`, `[network]` |
| Budgets and limits | Rationing | `[rationing]` |
| Agent group/fleet | Cohort | `/v1/cohorts`, `[cohort]` |
| Signed policy bundle | Archive | `runeward archive`, `[policy_bundle]` |

See the full [naming and writing convention](docs/naming.md).

## Install

Choose the package that matches how you use Rune Box:

| Install with | What it installs | Command |
| --- | --- | --- |
| [Homebrew](https://github.com/Runeeward/homebrew-tap) | Rune Box CLI for macOS or Linux | `brew install Runeeward/tap/runeward` |
| [PyPI](https://pypi.org/project/runeward/) | Python client and agent-framework adapters | `python -m pip install runeward` |
| [npm](https://www.npmjs.com/package/@runeward/sdk) | TypeScript client and agent-framework tools | `npm install @runeward/sdk` |

For normal local use, install the CLI with Homebrew. For an agent integration, install the SDK for
its language as well. The pip and npm packages connect to a running Rune Box API; they do not
replace the CLI/runtime.

### Homebrew — CLI

Local sandboxes require a running Docker, OrbStack, or Podman engine.

```bash
brew install Runeeward/tap/runeward
runeward version
runeward quickstart
```

### pip — Python SDK

Requires Python 3.9 or newer. The base client has no third-party runtime dependencies.

```bash
python -m pip install runeward
python -c "import runeward; print(runeward.__version__)"
```

### npm — TypeScript SDK

Requires Node.js 18 or newer.

```bash
npm install @runeward/sdk
npm ls @runeward/sdk
```

See [Adapters](docs/adapters.md) for LangChain, CrewAI, LlamaIndex, OpenAI Agents, Strands,
Vercel AI SDK, and LangChain.js installation options.

### Other CLI installation options

The signed macOS/Linux installer requires
[`cosign`](https://docs.sigstore.dev/cosign/system_config/installation/) so it can fail closed while
verifying the checksum manifest. Windows binaries are available from
[Releases](https://github.com/Runeeward/runeward/releases).

```bash
curl -fsSL https://raw.githubusercontent.com/Runeeward/runeward/main/install.sh | sh
```

To build the current `main` branch, use Rust **1.95** or newer (the workspace MSRV):

```bash
git clone https://github.com/Runeeward/runeward
cd runeward
cargo build --release --locked -p runeward-cli --bin runeward
./target/release/runeward version
```

`cargo install --locked --path crates/runeward-cli` installs it into `~/.cargo/bin` instead.

## Use it with an agent

Expose governed tools to an MCP-capable IDE or agent:

```json
{
  "mcpServers": {
    "runeward": {
      "command": "runeward",
      "args": ["mcp", "--config-dir", ".runeward"]
    }
  }
}
```

Or place an agent CLI inside a sandbox and run one or many governed workers:

```bash
runeward cohort --agent claude --model sonnet build "Build a tested API"
```

Adapters are included for LangChain, CrewAI, LlamaIndex, OpenAI Agents, Strands, Vercel AI SDK,
and LangChain.js. See [Adapters](docs/adapters.md) and [agent groups](docs/fleets.md).

The dashboard also has a read-only **Live chat** TTY for each Citadel. Agent harnesses publish
`user`, `assistant`, `tool`, and `system` turns with `runeward_publish_conversation` (or the REST,
Python, and TypeScript equivalents), and authorized teammates can follow the redacted conversation
without terminal input access. Rune Box cannot infer private UI chat text that the agent client does
not publish; wire the publish call into the harness turn callback. The publisher must connect to the
same `runeward serve` control plane as the dashboard (through `/mcp`, REST, or an SDK).

## Harness agents and subagents

Rune Box is the enforcement boundary around an agent, not the component that decides how the agent
reasons. Route the tool calls of a parent agent and each delegated subagent through Rune Box to give
them explicit policy, approval, isolation, budget, and evidence boundaries.

Existing concepts keep their meaning: a **Cohort** is a group of peer workers sharing a task board;
it is not being renamed to “subagents.” The orchestrator still decides when to delegate, while
Rune Box records the parent/run/provider lineage and prevents a child Citadel from widening its
parent's tenant or Charter. Every participating agent can receive its own Citadel and Chronicle.
See [Agent harnessing](docs/agent-harness.md).

## Policy workflow

Policies support built-in glob rules, CEL, OPA/Rego, and signed OCI bundles. Test them in CI, start
from a reviewed scaffold, or derive exact proposals from verified production evidence:

```bash
runeward policy scaffold package-approval
runeward policy test quickstart --case 'tool=shell,action=rm -rf /,expect=deny'
runeward policy learn run.json > proposed-policy.toml
```

`policy learn` never edits a policy automatically. It verifies the evidence first, skips redacted
actions, produces exact matches, and requires a human to review and broaden them.

## Security posture

- The server binds to loopback by default and requires authentication before a non-loopback bind.
- Non-loopback HTTP also requires TLS unless `--allow-insecure-http` explicitly acknowledges that a
  trusted reverse proxy terminates TLS.
- Multi-principal RBAC scopes sandboxes, agent groups, recovery snapshots, and dashboard views to
  their tenant while attributing every operation to its actor. Static tokens and OIDC JWTs use the
  same authorization model, and embedded HTTP MCP shares the REST ownership checks.
- Browser automation is experimental and disabled by default. Enable it only in a trusted deployment
  with `RUNEWARD_ENABLE_EXPERIMENTAL_BROWSER=1` after reviewing the [security model](docs/security-model.md).
  Browser-capable Charters declare `capabilities = ["browser"]`; the dashboard then exposes governed
  rendered-text and screenshot actions and their policy/egress results.
- An optional browser IDE (code-server inside the environment + ticketed reverse proxy) is similarly experimental:
  `RUNEWARD_ENABLE_EXPERIMENTAL_IDE=1`, Charter `[ide]`, `Dockerfile.ide` targets
  `ide` / `ide-agents`, examples `ide-demo` / `ide-claude` / `ide-codex` / `ide-cursor`.
  Limits: not per-keystroke policy; no Cursor/Claude Desktop/Codex GUIs inside the environment; no
  first-class GitHub Copilot on code-server. See [Browser IDE](docs/browser-ide.md) and the
  [security model](docs/security-model.md).
- Per-action policy applies to tool calls routed through the control plane (REST, MCP, dashboard
  file/shell/code actions, and SDKs). An interactive terminal or a process already running inside a
  sandbox is a direct sandbox session: it receives isolation/network/resource controls and terminal
  recording, but its individual commands are not intercepted for approval. Use governed tool calls
  when command-level policy and signed verdicts are required.
- Report vulnerabilities privately using [SECURITY.md](SECURITY.md). Rune Box remains pre-1.0;
  residual limitations are tracked in [ROADMAP.md](ROADMAP.md).

## What's inside the environment

Beyond per-action policy, a Charter can confine the agent process itself and keep its work:

- **In-sandbox confinement.** `runeward-supervisor` runs as PID 1 in the sandbox image and launches
  the agent under Landlock filesystem rules, a seccomp filter and a dropped identity, from the
  Charter's `[filesystem]` and `[process]` sections. See [Isolation](docs/isolation.md) and the
  [security model](docs/security-model.md).
- **Credential brokering.** `[[endpoint]]` and `[[credential]]` entries let the egress proxy inject
  real secrets into approved requests while the agent only ever sees a placeholder, and an
  endpoint's `binaries` restrict it to the listed executables (attributed per connection by the
  in-sandbox supervisor, strict egress only). See the [security model](docs/security-model.md).
- **Persistent workspaces and forks.** `[workspace] persist = true` keeps a workspace across sleep,
  wake and control-plane restarts; forks start from a copy. Agent turns, Cohort memory, handoffs
  and `[schedule]` runs build on it. See [Workspaces and context](docs/workspaces-and-context.md).
- **Hardened mode.** `--hardened` (or `RUNEWARD_HARDENED=1`) refuses to start unless every hardening
  check passes, and calls that never ran return a standard refusal object. See the
  [CLI reference](docs/cli.md).

## Architecture

Rune Box is a Rust Cargo workspace (`crates/`) that builds four binaries:

| Binary | Runs | Crate |
| --- | --- | --- |
| `runeward` | CLI, control plane (`serve`), MCP server, Kubernetes controller and webhook | `runeward-cli` |
| `runeward-egress` | Policy-enforcing egress proxy and credential broker (Linux sidecar) | `runeward-egress` |
| `runeward-supervisor` | In-sandbox PID 1: Landlock, seccomp, dropped identity (Linux) | `runeward-supervisor` |
| `runeward-browser` | In-sandbox headless-browser driver (Linux) | `runeward-browser` |

The library crates split along the control loop:

- `runeward-charter`: Charter schema, loader, linter and signatures.
- `runeward-policy`: glob/argv, CEL and Rego engines, guardrails and usage accounting;
  `runeward-policybundle` distributes signed OCI policy bundles.
- `runeward-controlplane`: governed execution (policy, approval, limits, backend exec, ledger),
  workspaces, forks, agent turns, Cohort memory and schedules.
- `runeward-backend`: Docker, Podman and Kubernetes sandbox backends.
- `runeward-server` (REST, WebSockets, dashboard) and `runeward-mcp` (stdio and streamable HTTP).
- `runeward-k8s`: `runeward.dev` CRDs, the Citadel/Cohort controller and the admission webhook.
- `runeward-ledger`, `runeward-keys`, `runeward-auditsink`, `runeward-termrec`: the signed,
  hash-chained audit trail, its keys, sinks and terminal recordings.
- `runeward-authz`, `runeward-secrets`, `runeward-credentials`, `runeward-fleet`, `runeward-obs`:
  RBAC/OIDC, secret sources, CLI login, the Cohort task board, and logs/metrics.

Release binaries ship for Linux (static musl, amd64/arm64), macOS (amd64/arm64) and Windows
(amd64, CLI only); container images are multi-architecture and cosign-signed.

## Documentation

- [Quickstart](docs/quickstart.md)
- [Install](docs/install.md)
- [Isolation](docs/isolation.md)
- [Workspaces and context](docs/workspaces-and-context.md)
- [Policies / Charters](docs/profiles.md)
- [REST API](docs/rest-api.md)
- [Browser IDE](docs/browser-ide.md) (experimental code-server proxy)
- [Security model](docs/security-model.md)
- [End-to-end testing](docs/E2E-TESTING.md)
- Published site: [runeeward.github.io/runeward](https://runeeward.github.io/runeward/)

Contributions are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md). Licensed under
[Apache 2.0](LICENSE).
