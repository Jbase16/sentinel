"""
Unit tests for core/wraith/bola_replay.py — the capture-driven BOLA orchestrator.

Uses a synthetic two-persona capture (no target-specific ids) and a mock replay
transport modelling three server behaviours — one operation genuinely vulnerable,
one properly authorized, one that ignores the swapped id and returns the caller's
own data — to prove the three-way diff classifies each correctly.
"""
import json

import pytest

from core.wraith import bola_replay as br

ALICE = "RlLB9Tjpk7YfkTaBB0SpzA"   # attacker's owned business id (22-char enc shape)
BOB = "9QsBs4y23m6HH4aB38ffkA"     # victim's owned business id


def _rec(op_name, biz_id):
    return {
        "action": "network_capture", "type": "xhr", "url": "/gql/batch",
        "response_body": "[Binary]",
        "request_body": json.dumps([{"operationName": op_name,
                                     "variables": {"BizEncId": biz_id}}]),
    }


def _cap(biz_id):
    # three object-scoped ops + one noisy third-party record that must be dropped
    return [
        _rec("GetUpcomingAppointments", biz_id),
        _rec("GetNotifications", biz_id),
        _rec("GetBizLeftNav", biz_id),
        {"action": "network_capture", "type": "xhr",
         "url": "https://www.google-analytics.com/collect", "request_body": "x",
         "response_body": "ok"},
    ]


class MockTarget:
    """Models the origin. `GetUpcomingAppointments` is vulnerable (leaks victim data
    to the attacker), `GetNotifications` is secure (403), `GetBizLeftNav` ignores the
    swapped id and returns the caller's own data."""
    behaviour = {"GetUpcomingAppointments": "vulnerable",
                 "GetNotifications": "secure",
                 "GetBizLeftNav": "ignores"}

    def _op(self, req):
        try:
            return json.loads(req.body)[0].get("operationName")
        except Exception:
            return None

    async def send(self, persona, req):
        body = req.body or req.url or ""
        name = self._op(req)
        alice_data = f'{{"data":{{"biz":"{ALICE}","ownerName":"AliceCafePrivateLLC","phone":"4155550111"}}}}'
        bob_data = f'{{"data":{{"biz":"{BOB}","ownerName":"BobBurgersPrivateLLC","phone":"4155550222"}}}}'
        if persona == "victim":
            return br.ReplayResponse(200, bob_data)           # victim sees own object
        # attacker persona:
        if ALICE in body and BOB not in body:
            return br.ReplayResponse(200, alice_data)         # attacker baseline
        # attack: attacker session carrying the victim's id
        mode = self.behaviour.get(name, "secure")
        if mode == "vulnerable":
            return br.ReplayResponse(200, bob_data)           # leaked!
        if mode == "ignores":
            return br.ReplayResponse(200, alice_data)         # own data back
        return br.ReplayResponse(403, '{"error":"forbidden"}')


def test_owned_id_autodetect():
    assert br.extract_owned_ids(br.parse_capture(_cap(ALICE)))[0] == ALICE
    assert br.extract_owned_ids(br.parse_capture(_cap(BOB)))[0] == BOB


def test_parse_capture_drops_third_party():
    parsed = br.parse_capture(_cap(ALICE))
    assert all("google-analytics" not in r.get("url", "") for r in parsed)
    assert len(parsed) == 3


def test_find_object_scoped_ops():
    ops = br.find_object_scoped_ops(br.parse_capture(_cap(ALICE)), ALICE)
    labels = {o.label for o in ops}
    assert {"GetUpcomingAppointments", "GetNotifications", "GetBizLeftNav"} <= labels
    assert all(o.kind == "graphql" for o in ops)


def test_build_request_swaps_id():
    ops = br.find_object_scoped_ops(br.parse_capture(_cap(ALICE)), ALICE)
    op = next(o for o in ops if o.label == "GetUpcomingAppointments")
    req = br.build_request(op, use_id=BOB, attacker_id=ALICE)
    assert BOB in req.body and ALICE not in req.body   # attacker id fully swapped out
    assert req.method == "POST" and "GetUpcomingAppointments" in req.body


def test_headers_flow_through_and_are_cleaned():
    rec = {
        "action": "network_capture", "type": "xhr", "url": "/gql/batch",
        "response_body": "[Binary]",
        "request_body": json.dumps([{"operationName": "GetX",
                                     "variables": {"BizEncId": ALICE}}]),
        "request_headers": {
            "content-type": "application/json",
            "x-csrf-token": "tok-123",         # must survive → this is why we capture headers
            "cookie": "session=secret",         # forbidden → dropped (credentials:'include' handles it)
            "host": "biz.yelp.com",             # forbidden → dropped
            "x-biz-context": ALICE,             # carries the id → must be swapped too
        },
    }
    op = br.find_object_scoped_ops(br.parse_capture([rec]), ALICE)[0]
    assert op.headers.get("x-csrf-token") == "tok-123"
    req = br.build_request(op, use_id=BOB, attacker_id=ALICE)
    low = {k.lower() for k in req.headers}
    assert req.headers["x-csrf-token"] == "tok-123"     # CSRF preserved verbatim
    assert "cookie" not in low and "host" not in low     # forbidden dropped
    assert req.headers["x-biz-context"] == BOB           # id swapped inside the header
    assert req.headers["content-type"] == "application/json"


def test_marker_extraction_isolates_victim_private():
    victim = '{"ownerName":"BobBurgersPrivateLLC","shared":"YelpForBusiness"}'
    attacker = '{"ownerName":"AliceCafePrivateLLC","shared":"YelpForBusiness"}'
    markers = br.extract_victim_markers(victim, attacker, exclude={ALICE, BOB})
    assert "BobBurgersPrivateLLC" in markers      # victim-only → kept
    assert "YelpForBusiness" not in markers        # in attacker baseline too → dropped


@pytest.mark.asyncio
async def test_hunt_classifies_all_three():
    findings, verdicts = await br.hunt(
        _cap(ALICE), _cap(BOB), transport=MockTarget(),
        attacker_id=ALICE, victim_id=BOB)
    by = {v.op: v.verdict for v in verdicts}
    assert by["GetUpcomingAppointments"] == "BOLA_CONFIRMED"
    assert by["GetNotifications"] == "DENIED"
    assert by["GetBizLeftNav"] == "NO_CROSS_READ"
    # exactly one confirmed finding, and it carries the victim-private marker
    assert len(findings) == 1
    f = findings[0].to_finding()
    assert f["metadata"]["vuln_class"] == "bola"
    assert any("BobBurgersPrivateLLC" in m for m in findings[0].leaked)


@pytest.mark.asyncio
async def test_hunt_autodetects_ids_when_not_given():
    findings, verdicts = await br.hunt(_cap(ALICE), _cap(BOB), transport=MockTarget())
    assert any(v.verdict == "BOLA_CONFIRMED" for v in verdicts)
