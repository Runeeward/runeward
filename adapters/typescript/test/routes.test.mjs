import assert from "node:assert/strict";
import test from "node:test";

import {
  RefusedError,
  RunewardApprovalRequired,
  RunewardAuthorizationError,
  RunewardClient,
  RunewardDenied,
  RunewardError,
  parseRefusal,
} from "../dist/index.js";

const refusal = (reason, message, requestId = "rid-1", retryable = false) => ({
  refused: true, reason, retryable, request_id: requestId, message,
});

/** Replaces fetch with a recorder answering `responses` in order. */
async function withFetch(responses, fn) {
  const originalFetch = globalThis.fetch;
  const requests = [];
  globalThis.fetch = async (url, init) => {
    requests.push({ url: url.replace("http://localhost:8080", ""), method: init.method, body: init.body ? JSON.parse(init.body) : undefined });
    const [status, payload, requestId = "ok-1"] = responses.shift();
    return new Response(JSON.stringify(payload), { status, headers: { "x-request-id": requestId } });
  };
  try {
    return await fn(new RunewardClient(), requests);
  } finally {
    globalThis.fetch = originalFetch;
  }
}

test("refused calls throw RefusedError with the request id", async () => {
  await withFetch([[404, { error: "sandbox not found", code: "not_found", refusal: refusal("request", "sandbox not found") }, "rid-1"]], async (client) => {
    await assert.rejects(client.getSandbox("nope"), (err) => {
      assert.ok(err instanceof RefusedError);
      assert.ok(err instanceof RunewardError);
      assert.equal(err.status, 404);
      assert.equal(err.reason, "request");
      assert.equal(err.retryable, false);
      assert.equal(err.requestId, "rid-1");
      assert.equal(err.code, "not_found");
      assert.equal(err.refusalMessage, "sandbox not found");
      assert.deepEqual(err.refusal, refusal("request", "sandbox not found"));
      return true;
    });
    assert.equal(client.lastRequestId, "rid-1");
  });
});

test("rate limits are retryable; busy turns are refused", async () => {
  await withFetch([
    [429, { error: "rate limited", code: "rate_limited", refusal: refusal("capacity", "rate limited", "r2", true) }, "r2"],
    [409, { error: "agent session is busy", code: "session_busy", refusal: refusal("request", "agent session is busy") }],
  ], async (client) => {
    await assert.rejects(client.listSchedules(), (err) => err instanceof RefusedError && err.retryable === true && err.requestId === "r2");
    await assert.rejects(client.agentTurn("as-1", ["x"]), (err) => err instanceof RefusedError && err.code === "session_busy");
  });
});

test("governance errors keep their types and carry the refusal", async () => {
  await withFetch([
    [403, { verdict: "deny", reason: "no deletes", refusal: refusal("policy", "no deletes", "r9") }, "r9"],
    [403, { error: "nope", code: "authz_denied", refusal: refusal("permission", "nope") }, "r10"],
    [202, { verdict: "require-approval", approval_id: "apr-1", refusal: refusal("approval", "review") }, "r11"],
    [500, { error: "internal server error", code: "internal_error", request_id: "r500" }, ""],
  ], async (client) => {
    await assert.rejects(client.shell("c1", ["rm", "-rf", "/"]), (err) =>
      err instanceof RunewardDenied && err.reason === "no deletes" && err.requestId === "r9" && err.refusal.reason === "policy");
    await assert.rejects(client.getSandbox("c1"), (err) => err instanceof RunewardAuthorizationError && err.requestId === "r10");
    await assert.rejects(client.shell("c1", ["x"]), (err) => err instanceof RunewardApprovalRequired && err.approvalId === "apr-1");
    await assert.rejects(client.getSandbox("c1"), (err) =>
      err instanceof RunewardError && !(err instanceof RefusedError) && err.refusal === undefined && err.requestId === "r500");
  });
  assert.equal(parseRefusal({}), undefined);
  assert.equal(parseRefusal({ refusal: "x" }), undefined);
});

test("isolation and broker perimeter fields come through", async () => {
  await withFetch([
    [200, { id: "c1", isolation: "kernel", isolation_evidence: { tier: "kernel", backend: "docker", source: "backend" }, enforcement: { supervisor: "enforced", landlock: "enforced" } }],
    [200, { decisions: [{ host: "api.test", allow: false, reason: "deny[0]", endpoint: "github", method: "DELETE", path: "/repos/x", effect: "irreversible", verdict: "deny", reason_code: "rule", credential: "gh" }] }],
  ], async (client, requests) => {
    const sbx = await client.getSandbox("c1");
    assert.equal(sbx.isolation, "kernel");
    assert.equal(sbx.isolation_evidence.backend, "docker");
    assert.equal(sbx.enforcement.supervisor, "enforced");
    const [d] = await client.perimeter("c1");
    assert.equal(d.verdict, "deny");
    assert.equal(d.credential, "gh");
    assert.equal(requests[1].url, "/v1/citadels/c1/perimeter");
  });
});

test("workspace and agent-session routes", async () => {
  await withFetch([
    [201, { id: "c2", forked_from: "c/1" }],
    [200, { ok: true, slept: true }],
    [200, { ok: true }],
    [200, { citadel_id: "c1", state: "sleeping" }],
    [202, { id: "as-1", status: "queued" }],
    [202, { id: "as-1", turn: 2 }],
    [200, { canceled: true }],
    [200, { sessions: [{ id: "as-1" }] }],
    [200, { session: { id: "as-1" }, events: [] }],
    [202, { verdict: "require-approval", approval_id: "apr-2" }],
  ], async (client, r) => {
    await client.forkCitadel("c/1", { profile: "dev", memoryBytes: 1024 });
    assert.deepEqual(r[0], { url: "/v1/citadels/c%2F1/fork", method: "POST", body: { profile: "dev", memory_bytes: 1024 } });
    assert.equal((await client.sleepCitadel("c1")).slept, true);
    assert.equal(r[1].url, "/v1/citadels/c1/sleep");
    await client.wakeCitadel("c1");
    assert.equal(r[2].url, "/v1/citadels/c1/wake");
    assert.equal((await client.workspaceStatus("c1")).state, "sleeping");
    assert.equal(r[3].url, "/v1/citadels/c1/workspace/status");
    assert.equal((await client.startAgentSession("c1", ["claude"], { agent: "a" })).id, "as-1");
    assert.deepEqual(r[4].body, { command: ["claude"], agent: "a" });
    assert.equal((await client.agentTurn("as-1", ["next"], "m")).turn, 2);
    assert.deepEqual(r[5], { url: "/v1/agent-sessions/as-1/turns", method: "POST", body: { command: ["next"], model: "m" } });
    assert.equal(await client.cancelAgentTurn("as-1"), true);
    assert.equal(r[6].url, "/v1/agent-sessions/as-1/cancel");
    assert.equal((await client.listAgentSessions("co-1"))[0].id, "as-1");
    assert.equal(r[7].url, "/v1/agent-sessions?cohort_id=co-1");
    await client.agentSessionEvents("as-1", 7);
    assert.equal(r[8].url, "/v1/agent-sessions/as-1/events?after=7");
    await assert.rejects(client.startAgentSession("c1", ["x"]), RunewardApprovalRequired);
  });
});

test("schedule routes", async () => {
  await withFetch([
    [201, { id: "s1" }],
    [201, { id: "s2" }],
    [200, { schedules: [{ id: "s1" }] }],
    [200, { schedules: [] }],
    [200, { schedules: [] }],
    [200, { schedule_id: "s1", outcome: "started" }],
    [200, { ok: true }],
    [200, { id: "s1" }],
  ], async (client, r) => {
    await client.createSchedule(["claude"], { citadel: "c1", every: "30m", prompt: "triage", precheck: ["true"] });
    assert.deepEqual(r[0], { url: "/v1/citadels/c1/schedules", method: "POST", body: { command: ["claude"], every: "30m", prompt: "triage", precheck: ["true"] } });
    await client.createSchedule(["x"], { cohort: "co-1", cron: "0 * * * *" });
    assert.deepEqual(r[1].body, { command: ["x"], cron: "0 * * * *" });
    assert.equal(r[1].url, "/v1/cohorts/co-1/schedules");
    assert.equal((await client.listSchedules())[0].id, "s1");
    assert.equal(r[2].url, "/v1/schedules");
    await client.listSchedules({ citadel: "c1" });
    assert.equal(r[3].url, "/v1/citadels/c1/schedules");
    await client.listSchedules({ cohort: "co-1" });
    assert.equal(r[4].url, "/v1/cohorts/co-1/schedules");
    assert.equal((await client.runSchedule("s1")).outcome, "started");
    assert.deepEqual([r[5].method, r[5].url], ["POST", "/v1/schedules/s1/run"]);
    await client.deleteSchedule("s1");
    assert.deepEqual([r[6].method, r[6].url], ["DELETE", "/v1/schedules/s1"]);
    await client.getSchedule("s1");
    assert.equal(r[7].url, "/v1/schedules/s1");
  });
  const client = new RunewardClient();
  assert.throws(() => client.createSchedule(["x"], { every: "1m" }), /exactly one of citadel and cohort/);
  assert.throws(() => client.createSchedule(["x"], { citadel: "c", cron: "* * * * *", every: "1m" }), /exactly one of cron and every/);
});

test("cohort memory and task handoff routes", async () => {
  await withFetch([
    [200, { entries: [{ key: "k", version: 1 }] }],
    [200, { entries: [] }],
    [200, { key: "k", version: 1 }],
    [200, { key: "a/b" }],
    [200, { deleted: true }],
    [201, { id: "t2" }],
    [200, { id: "t1" }],
    [200, { id: "t1" }],
    [200, { task: {}, context: {} }],
    [200, { claimed: true }],
    [200, { ok: true }],
    [200, { ok: true }],
  ], async (client, r) => {
    assert.equal((await client.listMemory("co-1"))[0].key, "k");
    assert.equal(r[0].url, "/v1/cohorts/co-1/memory");
    await client.searchMemory("co-1", "deploy notes", { tags: ["ops", "ci"], limit: 5 });
    assert.equal(r[1].url, "/v1/cohorts/co-1/memory?query=deploy+notes&tags=ops%2Cci&limit=5");
    await client.putMemory("co-1", "k", "text", { tags: ["ops"], expectedVersion: 0 });
    assert.deepEqual(r[2].body, { key: "k", text: "text", tags: ["ops"], expected_version: 0 });
    await client.getMemory("co-1", "a/b");
    assert.equal(r[3].url, "/v1/cohorts/co-1/memory/a%2Fb");
    assert.equal(await client.deleteMemory("co-1", "k", 3), true);
    assert.deepEqual([r[4].method, r[4].url], ["DELETE", "/v1/cohorts/co-1/memory/k?version=3"]);
    await client.addChildTask("co", "t1", "sub");
    assert.deepEqual(r[5], { url: "/v1/cohorts/co/tasks/t1/children", method: "POST", body: { payload: "sub" } });
    await client.addTaskNote("co", "t1", "note");
    assert.deepEqual(r[6].body, { text: "note" });
    await client.setTaskBrief("co", "t1", "be brief");
    assert.deepEqual(r[7], { url: "/v1/cohorts/co/tasks/t1/brief", method: "PUT", body: { agent: "*", brief: "be brief" } });
    await client.taskContext("co", "t1", { agent: "a1", memoryBytes: 512 });
    assert.equal(r[8].url, "/v1/cohorts/co/tasks/t1/context?agent=a1&memory_bytes=512");
    await client.claimTask("co", "me", { context: true });
    assert.deepEqual(r[9].body, { owner: "me", context: true });
    await client.completeTask("co", "t1", "lease", "done", "", "next: deploy");
    assert.equal(r[10].body.handoff, "next: deploy");
    await client.failTask("co", "t1", "lease", "boom", true, "", "retry");
    assert.deepEqual(r[11].body, { owner: "", lease_token: "lease", error: "boom", requeue: true, handoff: "retry" });
  });
});
