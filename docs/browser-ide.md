# Browser IDE (experimental)

Opt-in **browser IDE** against a Citadel’s `/workspace`: code-server runs
inside the environment; `runeward serve` reverse-proxies it behind short-lived tickets
(same family as the interactive terminal). This is additive — it does **not**
replace host-IDE MCP or in-environment CLI agents.

Enable with `RUNEWARD_ENABLE_EXPERIMENTAL_IDE=1`. Off by default.

## Ways to work with an IDE

| Setup | What you get | Charter / surface |
| --- | --- | --- |
| **1. Host IDE → MCP** | Cursor / Claude Desktop / VS Code on your machine call governed tools | `runeward mcp` |
| **2. In-environment CLI agents** | Headless `claude` / `codex` / Cursor `agent` inside the Citadel | `examples/*-agent.toml` |
| **3. Browser IDE (this page)** | code-server GUI in the browser, optional CLIs in its terminal | `[ide]`, `ide-*.toml` |

## What was added

- Charter `[ide]`: `enabled`, `port` (default `8080`), optional `path`, optional
  `agents = ["claude", "codex", "cursor"]` (dashboard hints only).
- Images from `deploy/Dockerfile.ide`:
  - target `ide` → `runeward-ide:latest` (lean code-server).
  - target `ide-agents` → `runeward-ide-agents:latest` (code-server + Claude
    Code + Codex CLIs; optional Cursor CLI via build-args).
- Example Charters: `ide-demo`, `ide-claude`, `ide-codex`, `ide-cursor`.
- Control plane: starts code-server inside the environment, records container/pod IP:port (no
  host `-p` / NodePort on the happy path), ticketed HTTP + WebSocket proxy at
  `/v1/citadels/{id}/ide`, dashboard **Open IDE**.
- Dashboard keeps a same-tab prepared IDE link visible if an embedded browser
  or popup blocker prevents `window.open` from opening the ticketed URL.
- Chronicle: `ide.open` on successful start, `ide.close` on Citadel kill.
- RBAC: non-owners get 404 on another principal’s IDE (same ownership guard as
  other Citadel routes).

### Quick start

```bash
docker build --target ide -f deploy/Dockerfile.ide -t runeward-ide:latest .

RUNEWARD_ENABLE_EXPERIMENTAL_IDE=1 \
  RUNEWARD_STATE_DIR=/tmp/rw-ide \
  ./bin/runeward --config-dir examples serve

# Create ide-demo → dashboard Open IDE, or:
# POST /v1/citadels {"profile":"ide-demo"}
# POST /v1/tickets {"kind":"ide","sandbox_id":"<id>"}
# open /v1/citadels/<id>/ide?ticket=<ticket>
```

### IDE + coding CLIs

```bash
docker build --target ide-agents -f deploy/Dockerfile.ide -t runeward-ide-agents:latest .

# Keys as documented in each Charter:
#   ~/.runeward-anthropic.key  → ide-claude  (terminal: claude)
#   ~/.runeward-openai.key     → ide-codex   (terminal: codex; source it from CODEX_API_KEY)
#   ~/.runeward-cursor.key     → ide-cursor  (terminal: agent; needs Cursor build-args)

RUNEWARD_ENABLE_EXPERIMENTAL_IDE=1 ./bin/runeward --config-dir examples serve
```

Cursor CLI in the agents image is opt-in (same digest-pinned installer as
`Dockerfile.agent`):

```bash
docker build --target ide-agents -f deploy/Dockerfile.ide -t runeward-ide-agents:latest \
  --build-arg INSTALL_CURSOR=true \
  --build-arg CURSOR_INSTALLER_SHA256=<digest> .
```

## Limitations

!!! warning "Interactive session — not per-keystroke policy"
    IDE keystrokes and commands run in the IDE terminal are **not** individually
    policy-gated. Isolation, egress allowlists, budgets, ownership, and Chronicle
    `ide.open` / `ide.close` still apply. Same boundary as the interactive
    terminal. See the [security model](security-model.md).

### Not supported

- **Cursor Desktop, Claude Desktop, or Codex GUIs inside the Citadel.** Those
  products do not ship a self-hosted browser IDE. Embedding Electron/noVNC
  desktops is out of scope.
- **First-class GitHub Copilot (or Microsoft Marketplace AI) on code-server.**
  code-server uses the **Open VSX** marketplace, not the Microsoft Marketplace.
  Copilot is not officially available there; manual VSIX sideloads are
  unsupported, often brittle, and may conflict with Microsoft’s terms.
- **Making the browser IDE the default Citadel experience.** Flag off; lean
  default images do not include code-server.
- **Per-keystroke Chronicle** or asciinema-style IDE recording (terminal
  recording remains a separate opt-in).

### Operational constraints

- **Egress.** Example `ide-demo` uses `network.default = "deny"` with no
  outbound allowlist — fine for local editing, but marketplace/extension
  downloads and cloud assistants will fail until you allowlist hosts (see
  `ide-claude` / `ide-codex` / `ide-cursor`).
- **Extensions.** Prefer Open VSX–compatible tools, or run the in-environment CLIs
  (`claude` / `codex` / `agent`) in the IDE terminal with a matching Charter.
  For Copilot-class UX on a real desktop IDE, use **setup 1** (host IDE → MCP).
- **Auth.** Outer ticket (then session cookie) authenticates the proxy;
  code-server runs with `--auth none` on the container network only — do not
  publish the IDE port on the host. The cookie is HttpOnly, SameSite strict,
  and path-scoped; it is Secure on HTTPS and non-loopback hosts. Loopback HTTP
  omits Secure because browsers otherwise reject the cookie and block IDE asset
  and WebSocket authentication.
- **Multi-replica `serve`.** IDE session cookies are process-local; sticky
  routing or a shared session store is not implemented.

## API surface

| Method | Path | Notes |
| --- | --- | --- |
| `POST` | `/v1/tickets` with `kind=ide` | Mint short-lived ticket (tenant-scoped under RBAC). |
| `POST` | `/v1/citadels/{id}/ide-ticket` | Same, Citadel-scoped helper. |
| `*` | `/v1/citadels/{id}/ide`… | Reverse proxy (HTTP + WebSocket). |

Citadel list/get may include `ide: true` and `ide_agents: [...]` when the IDE is
running. Browser-capable Citadels also include `capabilities: ["browser", ...]`;
the dashboard Browser tab can perform policy-gated rendered-text or screenshot
requests and then inspect Perimeter decisions. Full route table: [REST API](rest-api.md). Hands-on steps:
[E2E testing](E2E-TESTING.md#optional-browser-ide-experimental).
