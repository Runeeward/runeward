from __future__ import annotations

import email.message
import io
import json
import unittest
import urllib.error
from unittest import mock

from runeward import (
    Refusal,
    RefusedError,
    RunewardAuthorizationError,
    RunewardApprovalRequired,
    RunewardClient,
    RunewardDenied,
    RunewardError,
)


def _headers(request_id: str = "") -> email.message.Message:
    headers = email.message.Message()
    if request_id:
        headers["X-Request-Id"] = request_id
    return headers


def _http_error(status: int, payload: dict, request_id: str = "") -> urllib.error.HTTPError:
    return urllib.error.HTTPError(
        "http://localhost:8080/x", status, "error", _headers(request_id),
        io.BytesIO(json.dumps(payload).encode("utf-8")),
    )


class _Response:
    def __init__(self, status: int, payload: dict, request_id: str = "") -> None:
        self.status = status
        self._body = json.dumps(payload).encode("utf-8")
        self.headers = _headers(request_id)

    def __enter__(self) -> "_Response":
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def read(self) -> bytes:
        return self._body


class RunewardClientTests(unittest.TestCase):
    def test_rejects_insecure_remote_http(self) -> None:
        with self.assertRaisesRegex(ValueError, "refusing insecure http"):
            RunewardClient("http://control.example.com")

    @mock.patch("runeward.client.urllib.request.urlopen")
    def test_create_sandbox_uses_existing_citadel_endpoint(self, urlopen: mock.Mock) -> None:
        urlopen.return_value = _Response(201, {"id": "cit_123", "profile": "dev"})

        created = RunewardClient().create_sandbox("dev")

        self.assertEqual(created["id"], "cit_123")
        request = urlopen.call_args.args[0]
        self.assertEqual(request.full_url, "http://localhost:8080/v1/citadels")
        self.assertEqual(json.loads(request.data), {"profile": "dev"})

    def test_governance_verdicts_remain_typed(self) -> None:
        with self.assertRaises(RunewardAuthorizationError):
            RunewardClient._raise_for_status(403, {"code": "authz_denied", "error": "wrong owner"})
        with self.assertRaises(RunewardDenied):
            RunewardClient._raise_for_status(403, {"reason": "blocked"})
        with self.assertRaises(RunewardApprovalRequired):
            RunewardClient._raise_for_status(
                202,
                {"approval_id": "apr_123", "reason": "human review"},
            )

    @mock.patch("runeward.client.urllib.request.urlopen")
    def test_run_and_signed_lease_endpoints(self, urlopen: mock.Mock) -> None:
        urlopen.side_effect = [
            _Response(200, {"runs": [{"id": "run-1"}]}),
            _Response(200, {"ok": True}),
        ]
        client = RunewardClient()

        self.assertEqual(client.list_runs()[0]["id"], "run-1")
        client.complete_task("cohort/1", "task/1", "signed-lease", "done")

        request = urlopen.call_args_list[1].args[0]
        self.assertEqual(
            request.full_url,
            "http://localhost:8080/v1/cohorts/cohort%2F1/tasks/task%2F1/complete",
        )
        self.assertEqual(
            json.loads(request.data),
            {"owner": "", "lease_token": "signed-lease", "result": "done"},
        )

    @mock.patch("runeward.client.urllib.request.urlopen")
    def test_publish_conversation_uses_citadel_feed(self, urlopen: mock.Mock) -> None:
        urlopen.return_value = _Response(201, {"id": 1, "role": "assistant"})
        client = RunewardClient()
        client.publish_conversation("cit/1", "assistant", "Working on it", "run-1")
        request = urlopen.call_args.args[0]
        self.assertEqual(
            request.full_url,
            "http://localhost:8080/v1/citadels/cit%2F1/conversation",
        )
        self.assertEqual(json.loads(request.data), {
            "role": "assistant", "content": "Working on it", "run_id": "run-1",
        })



def _refusal(reason: str, message: str, request_id: str = "rid-1",
             retryable: bool = False) -> dict:
    return {"refused": True, "reason": reason, "retryable": retryable,
            "request_id": request_id, "message": message}


class RefusalTests(unittest.TestCase):
    @mock.patch("runeward.client.urllib.request.urlopen")
    def test_not_found_raises_refused_error_with_request_id(self, urlopen: mock.Mock) -> None:
        urlopen.side_effect = _http_error(404, {
            "error": "sandbox not found", "code": "not_found",
            "refusal": _refusal("request", "sandbox not found"),
        }, request_id="rid-1")
        client = RunewardClient()
        with self.assertRaises(RefusedError) as ctx:
            client.get_sandbox("nope")
        err = ctx.exception
        self.assertIsInstance(err, RunewardError)
        self.assertEqual(err.status, 404)
        self.assertEqual(err.reason, "request")
        self.assertFalse(err.retryable)
        self.assertEqual(err.request_id, "rid-1")
        self.assertEqual(err.message, "sandbox not found")
        self.assertEqual(err.code, "not_found")
        self.assertEqual(err.refusal, Refusal(True, "request", False, "rid-1", "sandbox not found"))
        self.assertEqual(client.last_request_id, "rid-1")

    def test_rate_limit_is_retryable(self) -> None:
        with self.assertRaises(RefusedError) as ctx:
            RunewardClient._raise_for_status(429, {
                "error": "rate limited", "code": "rate_limited",
                "refusal": _refusal("capacity", "rate limited", retryable=True),
            })
        self.assertTrue(ctx.exception.retryable)
        self.assertEqual(ctx.exception.request_id, "rid-1")

    @mock.patch("runeward.client.urllib.request.urlopen")
    def test_policy_denial_keeps_type_and_carries_refusal(self, urlopen: mock.Mock) -> None:
        urlopen.side_effect = _http_error(403, {
            "verdict": "deny", "reason": "no deletes",
            "refusal": _refusal("policy", "no deletes", request_id="rid-9"),
        }, request_id="rid-9")
        with self.assertRaises(RunewardDenied) as ctx:
            RunewardClient().shell("cit-1", ["rm", "-rf", "/"])
        self.assertEqual(ctx.exception.reason, "no deletes")
        self.assertEqual(ctx.exception.request_id, "rid-9")
        self.assertIsNotNone(ctx.exception.refusal)
        self.assertEqual(ctx.exception.refusal.reason, "policy")

    def test_authz_and_approval_carry_request_id(self) -> None:
        with self.assertRaises(RunewardAuthorizationError) as ctx:
            RunewardClient._raise_for_status(403, {
                "error": "nope", "code": "authz_denied",
                "refusal": _refusal("permission", "nope"),
            }, request_id="hdr-1")
        self.assertEqual(ctx.exception.request_id, "hdr-1")
        with self.assertRaises(RunewardApprovalRequired) as ctx2:
            RunewardClient._raise_for_status(202, {
                "verdict": "require-approval", "approval_id": "apr-1",
                "refusal": _refusal("approval", "needs review", request_id="rid-2"),
            })
        self.assertEqual(ctx2.exception.request_id, "rid-2")
        self.assertEqual(ctx2.exception.approval_id, "apr-1")

    def test_error_without_refusal_stays_plain(self) -> None:
        with self.assertRaises(RunewardError) as ctx:
            RunewardClient._raise_for_status(500, {
                "error": "internal server error", "code": "internal_error", "request_id": "r500",
            })
        self.assertNotIsInstance(ctx.exception, RefusedError)
        self.assertIsNone(ctx.exception.refusal)
        self.assertEqual(ctx.exception.request_id, "r500")

    def test_refusal_parsing_tolerates_missing_or_malformed(self) -> None:
        self.assertIsNone(Refusal.from_payload({}))
        self.assertIsNone(Refusal.from_payload({"refusal": "x"}))
        self.assertIsNone(Refusal.from_payload(None))


class _Recorder:
    """Answers every request with the next payload and records the requests."""

    def __init__(self, *responses: tuple) -> None:
        self.responses = list(responses)
        self.requests: list = []

    def __call__(self, request, timeout=None):  # noqa: ANN001 - urlopen signature
        self.requests.append(request)
        status, payload = self.responses.pop(0)
        return _Response(status, payload, request_id="ok-1")

    def last(self) -> tuple:
        req = self.requests[-1]
        body = json.loads(req.data) if req.data else None
        return req.get_method(), req.full_url.replace("http://localhost:8080", ""), body


class NewRouteTests(unittest.TestCase):
    def run_call(self, status: int, payload: dict, call):  # noqa: ANN001
        rec = _Recorder((status, payload))
        with mock.patch("runeward.client.urllib.request.urlopen", rec):
            client = RunewardClient()
            result = call(client)
            self.assertEqual(client.last_request_id, "ok-1")
        return result, rec.last()

    def test_isolation_tier_is_returned(self) -> None:
        sbx, _ = self.run_call(200, {"id": "c1", "isolation": "kernel", "status": "running"},
                               lambda c: c.get_sandbox("c1"))
        self.assertEqual(sbx["isolation"], "kernel")

    def test_perimeter_broker_fields(self) -> None:
        decisions, req = self.run_call(200, {"decisions": [{
            "host": "api.test", "allow": False, "reason": "deny[0]",
            "endpoint": "github", "protocol": "rest", "method": "DELETE",
            "path": "/repos/x", "effect": "irreversible", "verdict": "deny",
            "reason_code": "rule", "credential": "gh-token",
        }]}, lambda c: c.perimeter("c1"))
        self.assertEqual(req, ("GET", "/v1/citadels/c1/perimeter", None))
        self.assertEqual(decisions[0]["verdict"], "deny")
        self.assertEqual(decisions[0]["credential"], "gh-token")

    def test_workspace_routes(self) -> None:
        _, req = self.run_call(201, {"id": "c2", "forked_from": "c1"},
                               lambda c: c.fork_citadel("c/1", profile="dev", memory_bytes=1024))
        self.assertEqual(req, ("POST", "/v1/citadels/c%2F1/fork", {"profile": "dev", "memory_bytes": 1024}))
        _, req = self.run_call(201, {"id": "c2"}, lambda c: c.fork_citadel("c1"))
        self.assertEqual(req, ("POST", "/v1/citadels/c1/fork", {}))
        res, req = self.run_call(200, {"ok": True, "slept": True}, lambda c: c.sleep_citadel("c1"))
        self.assertEqual(req, ("POST", "/v1/citadels/c1/sleep", None))
        self.assertTrue(res["slept"])
        _, req = self.run_call(200, {"ok": True}, lambda c: c.wake_citadel("c1"))
        self.assertEqual(req, ("POST", "/v1/citadels/c1/wake", None))
        st, req = self.run_call(200, {"citadel_id": "c1", "state": "sleeping"},
                                lambda c: c.workspace_status("c1"))
        self.assertEqual(req, ("GET", "/v1/citadels/c1/workspace/status", None))
        self.assertEqual(st["state"], "sleeping")

    def test_agent_session_routes(self) -> None:
        sess, req = self.run_call(202, {"id": "as-1", "status": "queued"},
                                  lambda c: c.start_agent_session("c1", ["claude", "-p", "hi"], agent="a"))
        self.assertEqual(req, ("POST", "/v1/citadels/c1/agent-sessions",
                               {"command": ["claude", "-p", "hi"], "agent": "a"}))
        self.assertEqual(sess["id"], "as-1")
        sess, req = self.run_call(202, {"id": "as-1", "turn": 2},
                                  lambda c: c.agent_turn("as-1", ["claude", "-p", "next"], model="m"))
        self.assertEqual(req, ("POST", "/v1/agent-sessions/as-1/turns",
                               {"command": ["claude", "-p", "next"], "model": "m"}))
        self.assertEqual(sess["turn"], 2)
        canceled, req = self.run_call(200, {"canceled": True}, lambda c: c.cancel_agent_turn("as-1"))
        self.assertEqual(req, ("POST", "/v1/agent-sessions/as-1/cancel", {}))
        self.assertTrue(canceled)
        _, req = self.run_call(200, {"sessions": []}, lambda c: c.list_agent_sessions("co-1"))
        self.assertEqual(req, ("GET", "/v1/agent-sessions?cohort_id=co-1", None))
        _, req = self.run_call(200, {"session": {}, "events": []},
                               lambda c: c.agent_session_events("as-1", after=7))
        self.assertEqual(req, ("GET", "/v1/agent-sessions/as-1/events?after=7", None))

    def test_agent_turn_busy_is_refused(self) -> None:
        def raise_busy(request, timeout=None):  # noqa: ANN001
            raise _http_error(409, {"error": "agent session is busy", "code": "session_busy",
                                    "refusal": _refusal("request", "agent session is busy")})
        with mock.patch("runeward.client.urllib.request.urlopen", raise_busy):
            with self.assertRaises(RefusedError) as ctx:
                RunewardClient().agent_turn("as-1", ["x"])
        self.assertEqual(ctx.exception.code, "session_busy")

    def test_approval_gate_on_agent_route_still_raises(self) -> None:
        rec = _Recorder((202, {"verdict": "require-approval", "approval_id": "apr-1"}))
        with mock.patch("runeward.client.urllib.request.urlopen", rec):
            with self.assertRaises(RunewardApprovalRequired):
                RunewardClient().start_agent_session("c1", ["x"])

    def test_schedule_routes(self) -> None:
        _, req = self.run_call(201, {"id": "s1"}, lambda c: c.create_schedule(
            ["claude", "-p"], citadel="c1", every="30m", prompt="triage", precheck=["true"]))
        self.assertEqual(req, ("POST", "/v1/citadels/c1/schedules", {
            "command": ["claude", "-p"], "every": "30m", "prompt": "triage", "precheck": ["true"],
        }))
        _, req = self.run_call(201, {"id": "s2"}, lambda c: c.create_schedule(
            ["x"], cohort="co-1", cron="0 * * * *"))
        self.assertEqual(req, ("POST", "/v1/cohorts/co-1/schedules", {"command": ["x"], "cron": "0 * * * *"}))
        with self.assertRaises(ValueError):
            RunewardClient().create_schedule(["x"], citadel="c1", cron="* * * * *", every="1m")
        with self.assertRaises(ValueError):
            RunewardClient().create_schedule(["x"], every="1m")
        for kwargs, path in (({}, "/v1/schedules"), ({"citadel": "c1"}, "/v1/citadels/c1/schedules"),
                             ({"cohort": "co-1"}, "/v1/cohorts/co-1/schedules")):
            items, req = self.run_call(200, {"schedules": [{"id": "s1"}]},
                                       lambda c, kw=kwargs: c.list_schedules(**kw))
            self.assertEqual(req, ("GET", path, None))
            self.assertEqual(items[0]["id"], "s1")
        _, req = self.run_call(200, {"id": "s1"}, lambda c: c.get_schedule("s1"))
        self.assertEqual(req, ("GET", "/v1/schedules/s1", None))
        firing, req = self.run_call(200, {"schedule_id": "s1", "outcome": "started"},
                                    lambda c: c.run_schedule("s1"))
        self.assertEqual(req, ("POST", "/v1/schedules/s1/run", None))
        self.assertEqual(firing["outcome"], "started")
        _, req = self.run_call(200, {"ok": True}, lambda c: c.delete_schedule("s1"))
        self.assertEqual(req, ("DELETE", "/v1/schedules/s1", None))

    def test_cohort_memory_routes(self) -> None:
        entries, req = self.run_call(200, {"entries": [{"key": "k", "version": 1}]},
                                     lambda c: c.list_memory("co-1"))
        self.assertEqual(req, ("GET", "/v1/cohorts/co-1/memory", None))
        self.assertEqual(entries[0]["key"], "k")
        _, req = self.run_call(200, {"entries": []}, lambda c: c.search_memory(
            "co-1", "deploy notes", tags=["ops", "ci"], limit=5))
        self.assertEqual(req, ("GET", "/v1/cohorts/co-1/memory?query=deploy+notes&tags=ops%2Cci&limit=5", None))
        _, req = self.run_call(200, {"key": "k", "version": 1}, lambda c: c.put_memory(
            "co-1", "k", "text", tags=["ops"], expected_version=0))
        self.assertEqual(req, ("POST", "/v1/cohorts/co-1/memory",
                               {"key": "k", "text": "text", "tags": ["ops"], "expected_version": 0}))
        _, req = self.run_call(200, {"key": "a/b"}, lambda c: c.get_memory("co-1", "a/b"))
        self.assertEqual(req, ("GET", "/v1/cohorts/co-1/memory/a%2Fb", None))
        deleted, req = self.run_call(200, {"deleted": True},
                                     lambda c: c.delete_memory("co-1", "k", version=3))
        self.assertEqual(req, ("DELETE", "/v1/cohorts/co-1/memory/k?version=3", None))
        self.assertTrue(deleted)

    def test_task_handoff_routes(self) -> None:
        _, req = self.run_call(201, {"id": "t2"}, lambda c: c.add_child_task("co", "t1", "sub"))
        self.assertEqual(req, ("POST", "/v1/cohorts/co/tasks/t1/children", {"payload": "sub"}))
        _, req = self.run_call(200, {"id": "t1"}, lambda c: c.add_task_note("co", "t1", "note"))
        self.assertEqual(req, ("POST", "/v1/cohorts/co/tasks/t1/notes", {"text": "note"}))
        _, req = self.run_call(200, {"id": "t1"}, lambda c: c.set_task_brief("co", "t1", "be brief"))
        self.assertEqual(req, ("PUT", "/v1/cohorts/co/tasks/t1/brief", {"agent": "*", "brief": "be brief"}))
        _, req = self.run_call(200, {"task": {}, "context": {}},
                               lambda c: c.task_context("co", "t1", agent="a1", memory_bytes=512))
        self.assertEqual(req, ("GET", "/v1/cohorts/co/tasks/t1/context?agent=a1&memory_bytes=512", None))
        _, req = self.run_call(200, {"claimed": True}, lambda c: c.claim_task("co", "me", context=True))
        self.assertEqual(req, ("POST", "/v1/cohorts/co/claim", {"owner": "me", "context": True}))
        _, req = self.run_call(200, {"ok": True}, lambda c: c.complete_task(
            "co", "t1", "lease", "done", handoff="next: deploy"))
        self.assertEqual(req[2]["handoff"], "next: deploy")
        _, req = self.run_call(200, {"ok": True}, lambda c: c.fail_task(
            "co", "t1", "lease", "boom", requeue=True, handoff="retry with cache"))
        self.assertEqual(req[2], {"owner": "", "lease_token": "lease", "error": "boom",
                                  "requeue": True, "handoff": "retry with cache"})


if __name__ == "__main__":
    unittest.main()
