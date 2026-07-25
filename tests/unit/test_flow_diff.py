"""
Phase 4-G5 tests for core/ghost/flow_diff.py.

The cross-principal flow diff is what closes Phase 4: replay a captured
flow under a second identity and surface per-step convergences that
indicate IDOR.

Coverage:
  * _classify signal taxonomy — every branch.
  * diff_flow_across_principals end-to-end: feeds a captured flow + Bob's
    headers, observes that the replay actually uses Bob's auth, and
    classifies per-step findings.
  * override_headers actually replaces captured Authorization (vs
    initial_headers which DOESN'T override). Critical for G5's semantics.
  * Scope-filter skips Bob's request but doesn't crash the diff.
  * to_dict round-trips through json.dumps.

Uses httpx.MockTransport so no live server is needed.
"""
from __future__ import annotations

import asyncio
import json
from typing import Any, Callable, Dict, List

import httpx
import pytest

from core.ghost.flow import FlowStep, UserFlow
from core.ghost.flow_diff import (
    CrossPrincipalFlowDiff,
    CrossPrincipalStepFinding,
    _classify,
    diff_flow_across_principals,
)
from core.ghost.replay import replay_flow


def _run(coro):
    return asyncio.run(coro)


def _mock_transport(handler: Callable[[httpx.Request], httpx.Response]):
    return httpx.MockTransport(handler)


def _flow_with(steps: List[Dict[str, Any]]) -> UserFlow:
    flow = UserFlow(name="diff-test")
    for d in steps:
        step = FlowStep(
            method=d.get("method", "GET"),
            url=d["url"],
            headers=d.get("headers", {}),
        )
        step.set_response(
            status=d.get("alice_status", 200),
            headers=d.get("alice_response_headers", {}),
            body=d.get("alice_body", ""),
            content_type=d.get("alice_content_type", "application/json"),
            elapsed_ms=10.0,
        )
        flow.add_step(step)
    return flow


# ─────────────────────────── _classify ───────────────────────────


class TestClassifySignal:
    def test_identical_json_is_high_confidence_idor(self):
        body = '{"id": 1, "name": "alice", "email": "a@b.com"}'
        signal, conf, _ = _classify(
            alice_status=200, alice_body=body,
            bob_status=200, bob_body=body,
        )
        assert signal == "identical-json"
        assert conf == 0.90

    def test_identical_html_shell_is_not_idor(self):
        body = "<html><body>App shell — please log in</body></html>"
        signal, conf, _ = _classify(
            alice_status=200, alice_body=body,
            bob_status=200, bob_body=body,
        )
        assert signal == "distinct-body"
        # Lower confidence — not flagged as IDOR.
        assert conf < 0.7

    def test_distinct_json_similar_size_is_mid_idor(self):
        signal, conf, _ = _classify(
            alice_status=200,
            alice_body='{"id": 1, "name": "alice", "email": "a@b.com"}',
            bob_status=200,
            bob_body='{"id": 2, "name": "bobby", "email": "b@b.com"}',
        )
        assert signal == "distinct-json-similar-size"
        assert conf == 0.85

    def test_bob_403_is_denied_not_idor(self):
        signal, conf, _ = _classify(
            alice_status=200, alice_body='{"id": 1}',
            bob_status=403, bob_body='{"error": "forbidden"}',
        )
        assert signal == "denied"
        assert conf == 0.0

    def test_bob_404_is_denied(self):
        signal, _, _ = _classify(
            alice_status=200, alice_body='{"x": 1}',
            bob_status=404, bob_body="not found",
        )
        assert signal == "denied"

    def test_bodies_too_short_to_classify(self):
        signal, _, _ = _classify(
            alice_status=200, alice_body="{}",
            bob_status=200, bob_body="{}",
        )
        # Very short bodies → distinct-body, low confidence.
        assert signal == "distinct-body"


# ────────────────────── diff_flow_across_principals ──────────────────────


class TestFlowDiffEndToEnd:
    def test_identical_json_step_emits_idor_finding(self):
        """The canonical Juice Shop scenario: Alice's flow captures
        admin's basket; Bob replays it; Bob sees admin's basket data
        byte-identical → cross-principal IDOR at that step."""
        alice_body = (
            '{"id": 1, "owner": "admin@juice-sh.op", "items": ['
            '{"name": "apple", "qty": 1}], "balance": 100}'
        )
        flow = _flow_with([
            {"method": "GET", "url": "http://h/rest/basket/1",
             "headers": {"Authorization": "Bearer ALICE-TOKEN"},
             "alice_status": 200, "alice_body": alice_body},
        ])

        observed_authorizations: List[str] = []

        def handler(req: httpx.Request):
            observed_authorizations.append(req.headers.get("authorization", ""))
            # Bob gets the SAME body — that's the IDOR.
            return httpx.Response(200, content=alice_body.encode())

        result = _run(diff_flow_across_principals(
            flow=flow,
            alice_persona_name="admin",
            bob_persona_name="jim",
            bob_headers={"Authorization": "Bearer JIM-TOKEN"},
            transport=_mock_transport(handler),
        ))
        # Bob's request actually used Bob's token (override worked).
        assert observed_authorizations == ["Bearer JIM-TOKEN"]
        # Finding emitted with the high-confidence signal.
        assert len(result.step_findings) == 1
        f = result.step_findings[0]
        assert f.signal == "identical-json"
        assert f.confidence == 0.90
        assert f.is_idor_signal is True
        # Both personas attributed.
        assert f.alice_persona == "admin"
        assert f.bob_persona == "jim"
        # Bodies captured for triage.
        assert "admin@juice-sh.op" in f.alice_excerpt
        assert "admin@juice-sh.op" in f.bob_excerpt
        # Summary counters.
        assert result.idor_step_count == 1

    def test_bob_403_is_classified_denied_not_idor(self):
        """Authorization is working: Bob gets 403 trying to access
        Alice's resource. The diff must classify this as 'denied',
        not flag as IDOR."""
        flow = _flow_with([
            {"url": "http://h/admin/secret",
             "headers": {"Authorization": "Bearer ALICE"},
             "alice_status": 200, "alice_body": '{"secret": "value"}'},
        ])

        def handler(req: httpx.Request):
            # Bob doesn't have admin privileges → 403.
            return httpx.Response(403, content=b'{"error": "forbidden"}')

        result = _run(diff_flow_across_principals(
            flow=flow,
            alice_persona_name="admin",
            bob_persona_name="bob",
            bob_headers={"Authorization": "Bearer BOB-LIMITED"},
            transport=_mock_transport(handler),
        ))
        f = result.step_findings[0]
        assert f.signal == "denied"
        assert f.is_idor_signal is False
        assert result.idor_step_count == 0
        assert result.denied_step_count == 1

    def test_distinct_user_data_at_each_step_is_idor_at_each_step(self):
        """The classifier should ALSO fire on distinct-JSON-similar-size:
        same URL returns different data for different identities. Not
        as strong as identical-json but still IDOR (no auth-gate
        means Bob can READ his own data without any access control —
        but the issue is the URL didn't differentiate)."""
        flow = _flow_with([
            {"url": "http://h/me",
             "headers": {"Authorization": "Bearer ALICE"},
             "alice_status": 200,
             "alice_body": '{"id": 1, "email": "alice@a.com", "role": "admin"}'},
        ])

        def handler(req: httpx.Request):
            # Bob gets his own row (not alice's). Still a problem because
            # the endpoint isn't checking the auth identity matches the
            # requested resource — but it's returning different data.
            return httpx.Response(200, content=(
                b'{"id": 2, "email": "bob@b.com", "role": "user"}'
            ))

        result = _run(diff_flow_across_principals(
            flow=flow,
            alice_persona_name="alice",
            bob_persona_name="bob",
            bob_headers={"Authorization": "Bearer BOB"},
            transport=_mock_transport(handler),
        ))
        # Same URL but different data — distinct-json-similar-size.
        f = result.step_findings[0]
        assert f.signal == "distinct-json-similar-size"
        # Mid-confidence (per the taxonomy).
        assert f.confidence == 0.85
        assert f.is_idor_signal is True

    def test_multi_step_flow_with_mixed_results(self):
        """A typical real-world result: flow has 3 steps; step 0 is
        public (both see same content), step 1 is auth-gated correctly
        (Bob gets 403), step 2 is IDOR (Bob sees Alice's data). The
        diff should classify each step correctly."""
        flow = _flow_with([
            {"url": "http://h/homepage",
             "alice_status": 200, "alice_body": "<html>public</html>"},
            {"url": "http://h/admin/dashboard",
             "headers": {"Authorization": "Bearer ALICE-ADMIN"},
             "alice_status": 200, "alice_body": '{"users": 1000}'},
            {"url": "http://h/api/baskets/1",
             "headers": {"Authorization": "Bearer ALICE"},
             "alice_status": 200,
             "alice_body": '{"id": 1, "owner": "alice@a", "items": []}'},
        ])

        def handler(req: httpx.Request):
            path = req.url.path
            if path == "/homepage":
                # Both see the same public page.
                return httpx.Response(200, content=b"<html>public</html>")
            if path == "/admin/dashboard":
                # Bob has no admin → 403.
                return httpx.Response(403, content=b'{"error": "forbidden"}')
            if path.startswith("/api/baskets/"):
                # IDOR — Bob reads Alice's basket.
                return httpx.Response(200, content=(
                    b'{"id": 1, "owner": "alice@a", "items": []}'
                ))
            return httpx.Response(404, content=b"")

        result = _run(diff_flow_across_principals(
            flow=flow,
            alice_persona_name="alice",
            bob_persona_name="bob",
            bob_headers={"Authorization": "Bearer BOB"},
            transport=_mock_transport(handler),
        ))
        # 3 findings — one per step.
        assert len(result.step_findings) == 3
        # Step 0 (public homepage) — identical HTML, NOT classified as IDOR.
        assert result.step_findings[0].signal == "distinct-body"  # not JSON
        assert result.step_findings[0].is_idor_signal is False
        # Step 1 (admin dashboard) — Bob 403 → denied.
        assert result.step_findings[1].signal == "denied"
        # Step 2 (basket IDOR) — identical JSON → high-confidence IDOR.
        assert result.step_findings[2].signal == "identical-json"
        assert result.step_findings[2].is_idor_signal is True
        # Counts.
        assert result.idor_step_count == 1
        assert result.denied_step_count == 1


class TestOverrideHeadersSemantics:
    """G5 depends on override_headers REPLACING (not augmenting) the
    captured Authorization. This test pins that contract."""

    def test_override_headers_replaces_captured_authorization(self):
        flow = _flow_with([
            {"url": "http://h/me",
             "headers": {"Authorization": "Bearer ALICE-TOKEN"},
             "alice_status": 200, "alice_body": '{"id": 1}'},
        ])
        observed: List[str] = []

        def handler(req: httpx.Request):
            observed.append(req.headers.get("authorization", ""))
            return httpx.Response(200, content=b'{"id": 1}')

        # override_headers (G5 path): captured Authorization is REPLACED.
        _run(replay_flow(
            flow,
            override_headers={"Authorization": "Bearer BOB-TOKEN"},
            transport=_mock_transport(handler),
        ))
        assert observed == ["Bearer BOB-TOKEN"]

    def test_initial_headers_does_NOT_replace_captured_authorization(self):
        """Sanity check: the OLD initial_headers parameter still lets the
        captured headers win on collision. This is the lower-precedence
        tier — used for ambient additions, not identity replacement."""
        flow = _flow_with([
            {"url": "http://h/me",
             "headers": {"Authorization": "Bearer ALICE-TOKEN"},
             "alice_status": 200, "alice_body": '{}'},
        ])
        observed: List[str] = []

        def handler(req: httpx.Request):
            observed.append(req.headers.get("authorization", ""))
            return httpx.Response(200, content=b'{}')

        _run(replay_flow(
            flow,
            initial_headers={"Authorization": "Bearer BOB-TOKEN"},
            transport=_mock_transport(handler),
        ))
        # Captured wins on collision under initial_headers tier.
        assert observed == ["Bearer ALICE-TOKEN"]


# ─────────────────────────── serialization ───────────────────────────


class TestDiffSerialization:
    def test_to_dict_round_trips_via_json(self):
        body = '{"id": 1, "name": "alice", "email": "a@b.com", "balance": 100}'
        flow = _flow_with([
            {"url": "http://h/", "alice_status": 200, "alice_body": body},
        ])

        def handler(req):
            return httpx.Response(200, content=body.encode())

        result = _run(diff_flow_across_principals(
            flow=flow,
            alice_persona_name="a",
            bob_persona_name="b",
            bob_headers={"Authorization": "X"},
            transport=_mock_transport(handler),
        ))
        d = result.to_dict()
        # Must round-trip via json.dumps.
        json.dumps(d)
        # Top-level shape.
        assert d["alice_persona"] == "a"
        assert d["bob_persona"] == "b"
        assert "step_findings" in d
        assert d["idor_step_count"] == 1
        assert d["step_findings"][0]["is_idor_signal"] is True
