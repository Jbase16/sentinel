"""
Phase 4-G3 tests for core/ghost/replay.py.

The replay engine is the centerpiece of Phase 4 — it takes a captured
flow and re-executes it with mutations. These tests use httpx.MockTransport
so we don't need a live server; every "response" is scripted by the test.

Coverage:
  * NoOpMutation: replay matches capture (no divergence).
  * SwapAuthHeader: removes/replaces Authorization, gated by applies_to.
  * Replay against scripted responses: status / body / size diffs work.
  * Cookie isolation: per-replay client has its own jar.
  * Set-Cookie from step 1 propagates to step 2 within same replay.
  * Two parallel replays don't leak cookies between each other.
  * Network errors recorded as diverged step (replay_status=0), not raise.
  * stop_on_divergence halts after the first delta.
  * Per-step scope filter: out-of-scope steps are skipped.
  * Mutation that raises does NOT kill the replay.
  * to_dict() serializes ReplayResult cleanly.
"""
from __future__ import annotations

import asyncio
import json
from typing import Any, Callable, Dict, List, Optional

import httpx
import pytest

from core.ghost.flow import FlowStep, UserFlow
from core.ghost.replay import (
    NoOpMutation,
    ReplayResult,
    StepDiff,
    SwapAuthHeader,
    _clone_step,
    replay_flow,
)


def _run(coro):
    return asyncio.run(coro)


# ─────────────────────────── helpers ─────────────────────────────


def _build_flow_with_steps(steps_data: List[Dict[str, Any]]) -> UserFlow:
    """Construct a UserFlow with N pre-captured steps.

    Each dict in steps_data is:
      {method, url, headers (optional), request_body (optional),
       response_status, response_body, response_headers (optional)}
    """
    flow = UserFlow(name="test-flow")
    for d in steps_data:
        step = FlowStep(
            method=d.get("method", "GET"),
            url=d["url"],
            params=d.get("params", {}),
            headers=d.get("headers", {}),
            request_body=d.get("request_body", ""),
            request_content_type=d.get("request_content_type"),
        )
        step.set_response(
            status=d.get("response_status", 200),
            headers=d.get("response_headers", {}),
            body=d.get("response_body", ""),
            content_type=d.get("response_content_type"),
            elapsed_ms=d.get("response_elapsed_ms", 10.0),
        )
        flow.add_step(step)
    return flow


def _make_mock_transport(
    handler: Callable[[httpx.Request], httpx.Response],
) -> httpx.MockTransport:
    """Wrap a per-request handler into a MockTransport."""
    return httpx.MockTransport(handler)


# ───────────────────────── NoOp + SwapAuth unit ────────────────────────


class TestNoOpMutation:
    def test_applies_to_any_step(self):
        mut = NoOpMutation()
        step = FlowStep(method="GET", url="http://h/")
        assert mut.applies_to(step) is True

    def test_apply_returns_clone_not_same_object(self):
        mut = NoOpMutation()
        step = FlowStep(method="GET", url="http://h/", headers={"x": "1"})
        new = mut.apply(step)
        assert new is not step
        assert new.headers == step.headers
        # Mutating the clone must not affect the source.
        new.headers["x"] = "modified"
        assert step.headers["x"] == "1"


class TestSwapAuthHeader:
    def test_applies_only_if_authorization_present(self):
        mut = SwapAuthHeader()
        with_auth = FlowStep(method="GET", url="http://h/",
                             headers={"Authorization": "Bearer X"})
        no_auth = FlowStep(method="GET", url="http://h/")
        assert mut.applies_to(with_auth) is True
        assert mut.applies_to(no_auth) is False

    def test_apply_removes_header_when_new_value_none(self):
        mut = SwapAuthHeader(new_value=None)
        step = FlowStep(method="GET", url="http://h/",
                        headers={"Authorization": "Bearer X", "X-Other": "y"})
        new = mut.apply(step)
        assert "authorization" not in new.headers
        # Other headers preserved.
        assert new.headers["x-other"] == "y"

    def test_apply_replaces_header_when_new_value_set(self):
        mut = SwapAuthHeader(new_value="Bearer DIFFERENT")
        step = FlowStep(method="GET", url="http://h/",
                        headers={"Authorization": "Bearer X"})
        new = mut.apply(step)
        assert new.headers["authorization"] == "Bearer DIFFERENT"


# ───────────────────────── replay_flow integration ─────────────────────


class TestReplayIdentity:
    """No mutations + scripted responses identical to capture → zero
    divergence. This is the 'replay engine plumbing works' sanity check."""

    def test_baseline_replay_matches_capture_no_divergence(self):
        flow = _build_flow_with_steps([
            {"method": "GET", "url": "http://h/a",
             "response_status": 200, "response_body": "hello a"},
            {"method": "POST", "url": "http://h/b",
             "request_body": "x=1",
             "response_status": 201, "response_body": "created b"},
        ])

        def handler(req: httpx.Request) -> httpx.Response:
            if req.url.path == "/a":
                return httpx.Response(200, content=b"hello a")
            if req.url.path == "/b":
                return httpx.Response(201, content=b"created b")
            return httpx.Response(404, content=b"not found")

        result = _run(replay_flow(flow, transport=_make_mock_transport(handler)))
        assert result.error is None
        assert len(result.step_diffs) == 2
        # Zero divergence — replay perfectly matched capture.
        assert result.diverged_step_count == 0
        # Replay flow has the same step count + same URLs.
        assert len(result.replay_flow.steps) == 2
        assert result.replay_flow.steps[0].response_body == "hello a"
        assert result.replay_flow.steps[1].response_status == 201


class TestReplayDivergenceDetection:
    def test_status_change_flagged_as_diverged(self):
        flow = _build_flow_with_steps([
            {"url": "http://h/secret", "response_status": 200,
             "response_body": "sensitive data"},
        ])

        def handler(req):
            return httpx.Response(403, content=b"forbidden")

        result = _run(replay_flow(flow, transport=_make_mock_transport(handler)))
        diff = result.step_diffs[0]
        assert diff.status_changed is True
        assert diff.diverged is True
        assert diff.original_status == 200
        assert diff.replay_status == 403

    def test_body_change_flagged_as_diverged_even_with_same_status(self):
        flow = _build_flow_with_steps([
            {"url": "http://h/profile", "response_status": 200,
             "response_body": '{"id": 1, "name": "alice"}'},
        ])

        def handler(req):
            return httpx.Response(200, content=b'{"id": 1, "name": "bob"}')

        result = _run(replay_flow(flow, transport=_make_mock_transport(handler)))
        diff = result.step_diffs[0]
        assert diff.status_changed is False
        assert diff.body_changed is True
        assert diff.diverged is True


class TestMutationApplication:
    def test_swap_auth_makes_request_without_authorization(self):
        flow = _build_flow_with_steps([
            {"url": "http://h/protected",
             "headers": {"Authorization": "Bearer ALICE"},
             "response_status": 200,
             "response_body": "alice data"},
        ])

        observed_authorizations: List[Optional[str]] = []

        def handler(req: httpx.Request):
            observed_authorizations.append(
                req.headers.get("authorization") or req.headers.get("Authorization")
            )
            return httpx.Response(200, content=b"alice data")

        # Apply SwapAuthHeader(new_value=None) at step 0 — replay should
        # send the request WITHOUT the Authorization header.
        result = _run(replay_flow(
            flow,
            mutations_by_step_index={0: [SwapAuthHeader(new_value=None)]},
            transport=_make_mock_transport(handler),
        ))
        # Mutation applied.
        assert result.step_diffs[0].applied_mutations == ["swap-auth"]
        # The actual outgoing request had no Authorization.
        assert observed_authorizations == [None]

    def test_mutation_that_doesnt_apply_is_silently_skipped(self):
        """SwapAuthHeader on a step that has NO Authorization should be a
        no-op — applies_to() returns False, the mutation isn't applied,
        and the replay still goes through."""
        flow = _build_flow_with_steps([
            {"url": "http://h/public", "response_status": 200,
             "response_body": "public"},
        ])

        def handler(req):
            return httpx.Response(200, content=b"public")

        result = _run(replay_flow(
            flow,
            mutations_by_step_index={0: [SwapAuthHeader(new_value=None)]},
            transport=_make_mock_transport(handler),
        ))
        # Mutation didn't apply → applied_mutations is empty for this step.
        assert result.step_diffs[0].applied_mutations == []

    def test_raising_mutation_does_not_kill_replay(self):
        """A buggy mutation that raises must not crash the replay — the
        engine logs and continues with the unmutated step."""

        class BoomMutation:
            label = "boom"
            rationale = "raises in apply()"

            def applies_to(self, step): return True

            def apply(self, step):
                raise RuntimeError("simulated bug in mutation")

        flow = _build_flow_with_steps([
            {"url": "http://h/", "response_status": 200,
             "response_body": "ok"},
        ])

        def handler(req):
            return httpx.Response(200, content=b"ok")

        result = _run(replay_flow(
            flow,
            mutations_by_step_index={0: [BoomMutation()]},
            transport=_make_mock_transport(handler),
        ))
        # Engine completed; the diverged_step_count stays 0 because the
        # mutation was silently skipped and the replay matched the capture.
        assert result.error is None
        assert result.diverged_step_count == 0


# ─────────────────────── cookie / state isolation ────────────────────


class TestCookieState:
    def test_set_cookie_in_step_1_carries_to_step_2(self):
        """A step that returns Set-Cookie should populate the client's
        jar; the next step's outgoing request should include that cookie."""
        flow = _build_flow_with_steps([
            {"url": "http://h/login", "response_status": 200},
            {"url": "http://h/me", "response_status": 200},
        ])

        observed_cookies: List[str] = []

        def handler(req: httpx.Request):
            observed_cookies.append(req.headers.get("cookie", ""))
            if req.url.path == "/login":
                return httpx.Response(
                    200,
                    headers={"set-cookie": "session=xyz; Path=/"},
                    content=b"",
                )
            return httpx.Response(200, content=b"me")

        result = _run(replay_flow(flow, transport=_make_mock_transport(handler)))
        # Step 1 (login) was sent without a cookie; step 2 (me) was sent
        # WITH session=xyz because httpx jar carried it forward.
        assert observed_cookies[0] == ""
        assert "session=xyz" in observed_cookies[1]
        # And cookies_after_step on the replay's step 1 reflects the jar.
        assert result.replay_flow.steps[0].cookies_after_step.get("session") == "xyz"

    def test_two_parallel_replays_dont_share_cookies(self):
        """Two replays running concurrently must NOT see each other's
        cookies. Per-replay AsyncClient isolation is the guarantee."""
        flow = _build_flow_with_steps([
            {"url": "http://h/login", "response_status": 200},
            {"url": "http://h/me", "response_status": 200},
        ])

        # Replay A's handler sets session=A, B's sets session=B.
        def handler_a(req: httpx.Request):
            if req.url.path == "/login":
                return httpx.Response(200, headers={"set-cookie": "session=A; Path=/"},
                                      content=b"")
            return httpx.Response(200, content=req.headers.get("cookie", "").encode())

        def handler_b(req: httpx.Request):
            if req.url.path == "/login":
                return httpx.Response(200, headers={"set-cookie": "session=B; Path=/"},
                                      content=b"")
            return httpx.Response(200, content=req.headers.get("cookie", "").encode())

        async def run_both():
            return await asyncio.gather(
                replay_flow(flow, transport=_make_mock_transport(handler_a)),
                replay_flow(flow, transport=_make_mock_transport(handler_b)),
            )

        res_a, res_b = _run(run_both())
        # Replay A's step 2 saw session=A.
        assert "session=A" in res_a.replay_flow.steps[1].response_body
        # Replay B's step 2 saw session=B.
        assert "session=B" in res_b.replay_flow.steps[1].response_body


# ────────────────────────── network errors ──────────────────────────


class TestNetworkErrors:
    def test_step_error_recorded_not_raised(self):
        """Network errors on a step are recorded as a diverged StepDiff
        with replay_status=0 — the engine continues."""
        flow = _build_flow_with_steps([
            {"url": "http://h/will-fail", "response_status": 200,
             "response_body": "ok"},
            {"url": "http://h/ok", "response_status": 200,
             "response_body": "ok2"},
        ])

        def handler(req: httpx.Request):
            if req.url.path == "/will-fail":
                raise httpx.ConnectError("simulated network failure")
            return httpx.Response(200, content=b"ok2")

        result = _run(replay_flow(flow, transport=_make_mock_transport(handler)))
        # Did NOT raise.
        assert result.error is None
        # Step 0 has replay_status=0 (network error sentinel).
        assert result.step_diffs[0].replay_status == 0
        assert result.step_diffs[0].diverged is True
        # And step 1 still ran.
        assert result.step_diffs[1].replay_status == 200


# ────────────────────────── stop / scope ──────────────────────────


class TestReplayPolicy:
    def test_stop_on_divergence_halts_after_first_delta(self):
        flow = _build_flow_with_steps([
            {"url": "http://h/a", "response_status": 200},
            {"url": "http://h/b", "response_status": 200},
            {"url": "http://h/c", "response_status": 200},
        ])

        def handler(req):
            # /b will return 500 → divergence at step 1.
            if req.url.path == "/b":
                return httpx.Response(500, content=b"server error")
            return httpx.Response(200, content=b"")

        result = _run(replay_flow(
            flow,
            transport=_make_mock_transport(handler),
            stop_on_divergence=True,
        ))
        assert result.stopped_early is True
        # Only 2 diffs (steps 0 + 1); step 2 never ran.
        assert len(result.step_diffs) == 2

    def test_scope_filter_skips_out_of_scope_steps(self):
        flow = _build_flow_with_steps([
            {"url": "http://in.example/a", "response_status": 200},
            {"url": "http://out.example/b", "response_status": 200},
            {"url": "http://in.example/c", "response_status": 200},
        ])
        attempted_paths: List[str] = []

        def handler(req: httpx.Request):
            attempted_paths.append(req.url.path)
            return httpx.Response(200, content=b"")

        result = _run(replay_flow(
            flow,
            transport=_make_mock_transport(handler),
            scope_filter=lambda u: "in.example" in u,
        ))
        # Step 1 (out.example/b) was skipped entirely.
        assert "/b" not in attempted_paths
        # Only steps 0 + 2 produced diffs.
        urls_diffed = {d.url for d in result.step_diffs}
        assert "http://in.example/a" in urls_diffed
        assert "http://in.example/c" in urls_diffed
        assert "http://out.example/b" not in urls_diffed


# ─────────────────────────── ReplayResult ─────────────────────────────


class TestReplayResultSerialization:
    def test_to_dict_is_json_safe(self):
        flow = _build_flow_with_steps([
            {"url": "http://h/", "response_status": 200, "response_body": "x"},
        ])

        def handler(req): return httpx.Response(200, content=b"x")

        result = _run(replay_flow(flow, transport=_make_mock_transport(handler)))
        d = result.to_dict()
        # Must round-trip through json.dumps without raising.
        json.dumps(d)
        # Top-level shape contract.
        assert "step_diffs" in d
        assert "replay_flow" in d
        assert d["source_flow_name"] == "test-flow"
        assert d["diverged_step_count"] == 0


# ───────────────────────── _clone_step plumbing ──────────────────────


class TestCloneStep:
    def test_clone_preserves_identity(self):
        original = FlowStep(method="POST", url="http://h/",
                            headers={"Authorization": "x"})
        cloned = _clone_step(original)
        assert cloned.id == original.id  # critical for diff correlation
        # Independent dicts.
        cloned.headers["Authorization"] = "modified"
        assert original.headers["authorization"] == "x"
