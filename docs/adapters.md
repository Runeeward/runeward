# Adapters

**Adapters make Rune Box's governed tools a first-class citizen in the agent
frameworks you already use.** Instead of hand-rolling HTTP calls to the control
plane, you import a small client (or a ready-made set of framework "tools") and
hand them to your agent. The agent then calls `runeward_shell`,
`runeward_python`, `runeward_read_file`, … exactly as it would any other tool —
but every call is routed through the full governance path:

```
policy check  →  approval gate  →  cost/loop guardrails  →  sandbox exec  →  audit ledger
```

So work runs in a disposable, deny-by-default Citadel; risky actions are blocked
or escalated to a human; and everything is recorded in a tamper-evident Chronicle.

## Which one do I want?

- **Using an MCP client** (Claude Desktop, Cursor, VS Code)? You don't need an
  adapter at all — point the client at the Rune Box MCP server (`runeward mcp`).
  See the [REST API](rest-api.md) and the `dist/mcp/` manifest.
- **Building a Python agent** with LangChain, CrewAI, LlamaIndex, the OpenAI
  Agents SDK, or Strands? Use the [`runeward` Python package](#python-runeward).
- **Building a TypeScript agent** on the Vercel AI SDK, LangChain.js, or Strands?
  Use the [`@runeward/sdk` package](#typescript-runewardsdk).
- **Rolling your own?** Both `RunewardClient`s are thin, typed wrappers over the
  REST control plane and work standalone with zero third-party runtime
  dependencies.

All adapters target the same control plane started with `runeward serve` (default
`http://localhost:8080`) and expose the same method surface, mirroring the
governed tool set: `create_sandbox`, `shell`, `python`, `node`,
`read_file`/`write_file`/`list_files`/`search_files`,
`list_approvals`/`approve`/`deny`, `kill_sandbox`, plus `audit`/`verify_audit`.
(The client method names keep their original spellings even though the matching
MCP tools are now `runeward_create_citadel`, `runeward_kill_citadel`, and
`runeward_list_conclave`.)

## The governance contract every adapter preserves

Every tool call resolves to one of three verdicts. Adapters surface these
consistently — as typed exceptions on the raw client, and as short,
model-readable strings on the framework tools:

- **`allow`** — the action ran (for shell, still check `exit_code`).
- **`deny`** — policy refused it. **Do not retry the same action;** choose an
  allowed approach or report the block.
- **`require-approval`** — a human must sign off. **Pause** and surface the
  `approval_id`; don't route around the gate.

!!! note "Authentication"
    If `runeward serve` is started with a token (`--token` / `RUNEWARD_API_TOKEN`)
    or RBAC, pass it to the client — `RunewardClient(..., token="...")` in Python
    or `new RunewardClient({ token: "..." })` in TypeScript.

## Python (`runeward`)

The core client uses **only the Python standard library** (`urllib`). Framework
helpers are optional extras, imported lazily, so the base client works with
nothing else installed.

```bash
python -m pip install runeward
python -m pip install 'runeward[langchain]'
python -m pip install 'runeward[crewai]'
python -m pip install 'runeward[llamaindex]'
python -m pip install 'runeward[openai-agents]'
python -m pip install 'runeward[strands]'
```

For repository development, use `python -m pip install -e ./adapters/python`.

### Raw client

```python
from runeward import RunewardClient, RunewardDenied, RunewardApprovalRequired

rw = RunewardClient("http://localhost:8080")
sbx = rw.create_sandbox("dev")
print(rw.shell(sbx["id"], ["python3", "--version"])["stdout"])

try:
    rw.shell(sbx["id"], ["rm", "-rf", "/"])
except RunewardDenied as e:
    print("blocked by policy:", e.reason)        # do NOT retry
except RunewardApprovalRequired as e:
    print("needs a human:", e.approval_id)        # pause for an operator

rw.kill_sandbox(sbx["id"])
```

### Framework tools

Each framework module exposes a single `make_runeward_tools(client)` factory that
returns that framework's native tool objects, all named `runeward_*`:

```python
from runeward import RunewardClient

client = RunewardClient("http://localhost:8080")

# Pick one, matching your framework:
from runeward.langchain_tools import make_runeward_tools       # LangChain
from runeward.crewai_tools import make_runeward_tools          # CrewAI
from runeward.llamaindex_tools import make_runeward_tools      # LlamaIndex
from runeward.openai_agents_tools import make_runeward_tools   # OpenAI Agents SDK
from runeward.strands_tools import make_runeward_tools         # Strands Agents SDK

tools = make_runeward_tools(client)
# LangChain:     pass `tools` to an AgentExecutor / create_react_agent(...)
# CrewAI:        crewai.Agent(tools=tools, ...)
# LlamaIndex:    FunctionAgent(tools=tools, ...) / ReActAgent
# OpenAI Agents: agents.Agent(name="...", tools=tools)
# Strands:       strands.Agent(tools=tools)
```

See the [Python adapter README](https://github.com/Runeeward/runeward/tree/main/adapters/python)
for full, per-framework examples.

## TypeScript (`@runeward/sdk`)

The core `RunewardClient` uses the global `fetch` and has **no runtime
dependencies** (Node 18+, Deno, Bun, browsers). Tool wrappers require optional
peer dependencies, imported lazily.

```bash
npm install @runeward/sdk                            # core client
npm install @runeward/sdk ai zod                     # + Vercel AI SDK tools
npm install @runeward/sdk @langchain/core zod
npm install @runeward/sdk @strands-agents/sdk zod
```

For repository development, use `npm install ./adapters/typescript`.

### Raw client

```ts
import { RunewardClient, RunewardDenied } from "@runeward/sdk";

const rw = new RunewardClient({ baseUrl: "http://localhost:8080" });
const sbx = await rw.createSandbox("dev");
console.log((await rw.shell(sbx.id, ["node", "--version"])).stdout);
await rw.killSandbox(sbx.id);
```

### Vercel AI SDK

```ts
import { generateText } from "ai";
import { openai } from "@ai-sdk/openai";
import { RunewardClient } from "@runeward/sdk";
import { makeRunewardTools } from "@runeward/sdk/ai-tools";

const tools = await makeRunewardTools(new RunewardClient());
await generateText({ model: openai("gpt-4o"), tools, maxSteps: 8, prompt: "…" });
```

### LangChain.js

```ts
import { ChatOpenAI } from "@langchain/openai";
import { createReactAgent } from "@langchain/langgraph/prebuilt";
import { RunewardClient } from "@runeward/sdk";
import { makeRunewardTools } from "@runeward/sdk/langchain-tools";

const tools = await makeRunewardTools(new RunewardClient());
const agent = createReactAgent({ llm: new ChatOpenAI({ model: "gpt-4o" }), tools });
```

### Strands Agents SDK

```ts
import { Agent } from "@strands-agents/sdk";
import { RunewardClient } from "@runeward/sdk";
import { makeRunewardTools } from "@runeward/sdk/strands-tools";

const tools = await makeRunewardTools(new RunewardClient());
const agent = new Agent({ tools });
await agent.invoke("Create a dev sandbox, run `node --version`, then tear it down.");
```

See the [TypeScript adapter README](https://github.com/Runeeward/runeward/tree/main/adapters/typescript)
for more.

## Notes

- **`deny` is a policy decision, not a transient error.** Don't retry the same
  action; pick a different, allowed approach.
- **`require-approval` is a hard pause.** Surface the approval id to a human and
  wait for the outcome (resolve it via the dashboard, the CLI, or
  `POST /v1/conclave/{id}/{approve,deny}`).
- Prefer the tightest Charter that lets the task succeed.
