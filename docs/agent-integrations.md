# Codex, Claude Code, and GitHub Copilot

Rune Box exposes the same governed execution surface to every MCP-capable agent. The checked-in `.mcp.json`, `.vscode/mcp.json`, Cursor configuration, Copilot custom agent, and `dist/codex-plugin/runeward` package all invoke `runeward mcp` without embedding credentials.

## Make conversations observable

The dashboard's per-Citadel **Live chat** tab is a read-only TTY. It shows bounded history and new
turns as they arrive. The feed applies the Citadel's secret scrubber, removes terminal control
sequences, and uses the same tenant ownership checks as the rest of the Citadel API.

MCP harnesses publish each visible turn with `runeward_publish_conversation`:

```json
{
  "sandbox": "citadel-id",
  "role": "assistant",
  "content": "I found the failing test and am applying the fix.",
  "run_id": "optional-run-id"
}
```

REST uses `POST /v1/citadels/{id}/conversation`; the Python and TypeScript clients expose
`publish_conversation(...)` and `publishConversation(...)`. Add the call to the harness callback
that receives user and model turns. Codex, Claude, and Copilot do not expose private UI transcript
text to Rune Box automatically, so turns not forwarded by the host application cannot appear.

The publisher and dashboard must use the same control-plane process. For a dashboard started with
`runeward serve`, connect the agent to that server's streamable HTTP `/mcp` endpoint or publish to
its REST endpoint. A separate `runeward mcp` stdio process owns separate in-memory Citadels and
cannot populate the dashboard served by another process.

Observers authenticate normally, request a short-lived `conversation` ticket, and connect to
`/v1/citadels/{id}/conversation/stream`. The socket rejects application input: it cannot steer the
agent or type into the Citadel terminal.

## Shared setup

Install Rune Box, put `runeward` on `PATH`, and export configuration in the process that launches the agent:

```bash
export RUNEWARD_CONFIG_DIR="$PWD/examples"
export RUNEWARD_STATE_DIR="$HOME/.cache/runeward/agent"
export RUNEWARD_AUTHZ_FILE="$HOME/.config/runeward/authz.json"
export RUNEWARD_MCP_DEFAULT_TOKEN="$(security find-generic-password -w -s runeward-agent)"
```

Set these optional variables only when the selected Charter imports them:

```bash
# GitHub operations performed by an agent inside a Citadel.
export GITHUB_TOKEN="$(security find-generic-password -w -s runeward-github)"

# A self-hosted OpenAI-compatible gateway; omit for the provider default.
export OPENAI_BASE_URL="http://host.docker.internal:11434/v1"
```

Host `gh auth login` credentials are not automatically exposed to Citadels.
Reference `op = "env://GITHUB_TOKEN"` in the Charter when GitHub access is
required, use a dedicated least-privilege token, and allow only the necessary
GitHub hosts. Likewise, an `OPENAI_BASE_URL` override must be imported by the
Charter and permitted by its network rules. Never commit either credential or
put bearer values in `.mcp.json`.

Alternatively, save a short-lived OIDC credential once; Cohort CLI and stdio
MCP use it automatically when an explicit environment token is absent:

```bash
runeward auth login --issuer https://id.example.com \
  --client-id runeward-cli --audience runeward
runeward auth status
```

Never commit the token or put it in MCP arguments. Give each human, agent, CI
job, and delegated worker a distinct principal. Principals that are meant to
collaborate share a `tenant`; their individual names remain the Chronicle actor.
Use at least 32 random characters for any static token accepted on a
non-loopback listener.

## Codex

Install the plugin under `dist/codex-plugin/runeward`, or use the repository `.mcp.json`. The bundled skill requires identity and Charter discovery, least privilege, Live chat publishing, hard pauses for Conclave approvals, delegated-run lineage, and teardown.

## Claude Code

Claude Code discovers the repository `.mcp.json`. Start Claude from an environment containing the variables above. Keep project configuration credential-free so forks and logs cannot disclose a bearer token.

## GitHub Copilot

VS Code uses `.vscode/mcp.json`. The custom agent at `.github/agents/runeward.agent.md` allowlists the normal Citadel execution and Live chat tools and intentionally excludes approval resolution and Cohort administration.

Copilot cloud agents cannot reach a developer's local Docker socket. Deploy `runeward serve` behind HTTPS and connect to its `/mcp` endpoint with a dedicated workload principal. Remote MCP requests are authorized per request; do not place a second shared proxy token in front of RBAC.

## Delegated agents

Pass `parent_citadel`, `run_id`, `agent`, `provider`, and `model` when creating a
child. Rune Box records durable provider-neutral Run lineage and requires a child
to inherit the parent's tenant and exact Charter. Use a separate principal per
concurrently trusted agent where practical.
