# @runeward/sdk (TypeScript SDK for Rune Box)

A dependency-light TypeScript client and [Vercel AI SDK](https://sdk.vercel.ai)
tool wrappers for [Rune Box](https://github.com/Runeeward/runeward), the
open-source **governance harness for AI agents** (formerly Runeward Sandbox).
The package name stays `@runeward/sdk`. Put policy, human approvals, isolated Citadels,
Rationing, and signed Chronicles around an existing agent without replacing
its model or framework.

The core `RunewardClient` uses the global `fetch` and has **no runtime
dependencies** (Node 18+, Deno, Bun, browsers). The Vercel AI SDK wrappers
require `ai` and `zod`; the LangChain.js wrappers require `@langchain/core` and
`zod`; the Strands wrappers require `@strands-agents/sdk` and `zod`. All are
optional peer dependencies, imported lazily.

## Install

```bash
npm install @runeward/sdk                           # core client only
npm install @runeward/sdk ai zod                    # + Vercel AI SDK tools
npm install @runeward/sdk @langchain/core zod       # + LangChain.js tools
npm install @runeward/sdk @strands-agents/sdk zod   # + Strands Agents SDK tools
```

Build from this directory during development:

```bash
npm install
npm run build      # emits ./dist
```

## Quick start

Start the control plane first (`runeward serve`, default
`http://localhost:8080`), then:

```ts
import { RunewardClient, RunewardDenied, RunewardApprovalRequired } from "@runeward/sdk";

const rw = new RunewardClient({ baseUrl: "http://localhost:8080" }); // uses RUNEWARD_API_TOKEN in Node when set

const sbx = await rw.createSandbox("dev");
const version = await rw.shell(sbx.id, ["python3", "--version"]);
console.log(version.stdout); // "Python 3.11.2\n"

await rw.writeFile(sbx.id, "main.py", "print(2 + 2)");
const run = await rw.python(sbx.id, "exec(open('/workspace/main.py').read())");
console.log(run.stdout); // "4\n"

await rw.killSandbox(sbx.id); // always tear down when done
```

Use `allowInsecure: true` (or `RUNEWARD_ALLOW_INSECURE_HTTP=1`) only when you must call a non-loopback `http://` control-plane endpoint.

### Handling governance verdicts

The two governance outcomes are thrown as typed errors. A denial must **not** be
blindly retried; an approval gate must **pause** for a human:

```ts
try {
  await rw.shell(sbx.id, ["rm", "-rf", "/"]);
} catch (err) {
  if (err instanceof RunewardDenied) {
    console.log("blocked by policy:", err.reason); // do NOT retry the same action
  }
}

try {
  await rw.writeFile(sbx.id, "/etc/hosts", "127.0.0.1 example");
} catch (err) {
  if (err instanceof RunewardApprovalRequired) {
    console.log("needs a human:", err.approvalId); // pause; approve/deny out-of-band
  }
}
```

### Refusals and request ids

When the server proves a call never ran, its body carries a standard
`refusal` object (`parseRefusal` reads it). Refusals that are not policy,
authorization or approval outcomes (bad request, unknown resource,
`session_busy`, `version_conflict`, rate limits, budgets, an unmet isolation
floor) throw `RefusedError`. Every error exposes `requestId` (the server's
`X-Request-Id`) and `refusal`; `rw.lastRequestId` holds the most recent id.

```ts
import { RefusedError, RunewardError } from "@runeward/sdk";

try {
  await rw.agentTurn(sessionId, ["claude", "-p", "next step"]);
} catch (err) {
  if (err instanceof RefusedError && err.retryable) {
    // safe to send the identical request again later
  } else if (err instanceof RunewardError) {
    console.log("failed; quote this id to the operator:", err.requestId);
  }
}
```

### Isolation, workspaces, schedules and shared memory

Citadel views carry `isolation` (`process`, `container`, `kernel` or `vm`),
`isolation_evidence` and, under the in-sandbox supervisor, `enforcement`.

```ts
const fork = await rw.forkCitadel(sbx.id);
await rw.sleepCitadel(sbx.id);
await rw.wakeCitadel(sbx.id);

const sess = await rw.startAgentSession(sbx.id, ["claude", "-p", "fix the tests"]);
await rw.agentTurn(sess.id, ["claude", "-p", "now update the docs"]);
await rw.cancelAgentTurn(sess.id); // does not rewind workspace changes

await rw.createSchedule(["claude", "-p"], { citadel: sbx.id, every: "1h", prompt: "triage new issues" });
await rw.putMemory(cohortId, "deploy/notes", "staging uses blue/green", { tags: ["ops"] });
const hits = await rw.searchMemory(cohortId, "staging", { tags: ["ops"] });
```

## Client method surface

| Method | REST endpoint |
| --- | --- |
| `healthz()` | `GET /healthz` |
| `listProfiles()` | `GET /v1/charters` |
| `whoami()` / `readiness(profile)` / `simulatePolicy(...)` | Identity, setup, and dry-run policy APIs |
| `listRuns()` / `getRun(id)` | Durable provider-neutral Run lineage |
| `createSandbox(profile)` | `POST /v1/citadels` |
| `listSandboxes()` / `getSandbox(id)` / `killSandbox(id)` | `GET`/`GET`/`DELETE /v1/citadels[/{id}]` |
| `shell(sandbox, command, workdir?)` | `POST .../shell/exec` |
| `python(sandbox, code)` / `node(sandbox, code)` | `POST .../code/{python,node}` |
| `readFile` / `writeFile` / `listFiles` / `searchFiles` | `POST .../file/{read,write,list,search}` |
| `audit(sandbox)` / `verifyAudit()` | `GET .../chronicle`, `GET /v1/chronicle/verify` |
| `exportEvidence(sandbox)` | Portable resolved Charter + signed Chronicle evidence |
| `createCohort` / `listCohorts` / `addTask` / `claimTask(id, owner, { context })` | Cohort lifecycle and leased work queue |
| `heartbeatTask` / `completeTask` / `failTask` (with `handoff`) | Signed-lease task transitions |
| `addChildTask` / `addTaskNote` / `setTaskBrief` / `taskContext` | `POST .../tasks/{id}/{children,notes}`, `PUT .../brief`, `GET .../context` |
| `listMemory` / `searchMemory` / `putMemory` / `getMemory` / `deleteMemory` | `GET`/`POST /v1/cohorts/{id}/memory`, `GET`/`DELETE .../memory/{key}` |
| `forkCitadel` / `sleepCitadel` / `wakeCitadel` / `workspaceStatus` | `POST .../{fork,sleep,wake}`, `GET .../workspace/status` |
| `startAgentSession` / `listAgentSessions` / `getAgentSession` / `agentSessionEvents` | `POST .../agent-sessions`, `GET /v1/agent-sessions[/{id}[/events]]` |
| `agentTurn` / `cancelAgentTurn` | `POST /v1/agent-sessions/{id}/{turns,cancel}` |
| `listSchedules` / `createSchedule` / `getSchedule` / `deleteSchedule` / `runSchedule` | `/v1/schedules`, `/v1/{citadels,cohorts}/{id}/schedules` |
| `perimeter(sandbox)` | `GET .../perimeter` (with request-broker fields) |
| `createSnapshot` / `listSnapshots` / `restoreSnapshot` | Tenant-scoped recovery |
| `listApprovals()` / `approve(id)` / `deny(id)` | `GET /v1/conclave`, `POST /v1/conclave/{id}/{approve,deny}` |

## Vercel AI SDK tools

```ts
import { generateText } from "ai";
import { openai } from "@ai-sdk/openai";
import { RunewardClient } from "@runeward/sdk";
import { makeRunewardTools } from "@runeward/sdk/ai-tools";

const tools = await makeRunewardTools(new RunewardClient());

const { text } = await generateText({
  model: openai("gpt-4o"),
  tools,
  maxSteps: 8,
  prompt: "Create a dev sandbox, run `node --version` in it, then tear it down.",
});
```

Tool names match the runeward MCP tools (`runeward_create_citadel`,
`runeward_shell`, …). Governance verdicts are returned to the model as
descriptive strings so it can react to a denial or an approval gate instead of
crashing the run.

## LangChain.js tools

```ts
import { ChatOpenAI } from "@langchain/openai";
import { createReactAgent } from "@langchain/langgraph/prebuilt";
import { RunewardClient } from "@runeward/sdk";
import { makeRunewardTools } from "@runeward/sdk/langchain-tools";

const tools = await makeRunewardTools(new RunewardClient());
const agent = createReactAgent({ llm: new ChatOpenAI({ model: "gpt-4o" }), tools });

const res = await agent.invoke({
  messages: [{ role: "user", content: "Create a dev sandbox, run `node --version`, then tear it down." }],
});
```

Returns `DynamicStructuredTool` instances (from `@langchain/core/tools`) with the
same runeward tool names and the same string-based verdict handling as above.

## Strands Agents SDK

```ts
import { Agent } from "@strands-agents/sdk";
import { RunewardClient } from "@runeward/sdk";
import { makeRunewardTools } from "@runeward/sdk/strands-tools";

const tools = await makeRunewardTools(new RunewardClient());
const agent = new Agent({ tools });

const res = await agent.invoke("Create a dev sandbox, run `node --version`, then tear it down.");
```

Returns Strands tools built with `tool({ name, description, inputSchema, callback })`
(Zod schemas), with the same runeward tool names and string-based verdict handling.

## Notes

- **`deny` is a policy decision, not a transient error.** Don't retry the same
  action; pick a different, allowed approach.
- **`require-approval` is a hard pause.** Surface the `approvalId` to a human and
  wait for the outcome.
- Prefer the tightest profile that lets the task succeed.
