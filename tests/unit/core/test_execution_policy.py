"""
Unit tests for the bounty-safe execution policy (core/safety/* + core/cortex/
execution_policy). These pin the ban-preventing envelope:

  * bounty mode refuses DELETE even if a caller proposes it (and hints otherwise)
  * bounty mode refuses financial / messaging / external-side-effect writes
  * bounty mode refuses UNKNOWN by omission
  * bounty mode allows a self-reflective mass-assignment proof (PATCH /me role)
  * bounty mode caps cross-object reads at 1 and caps per-endpoint enumeration
  * bounty mode refuses out-of-scope requests
  * passive mode allows reads only
  * lab mode is a transparent pass-through (unchanged behavior)
"""

import pytest

from core.safety import action_classifier as ac
from core.safety.proof_budget import endpoint_key
from core.cortex.execution_policy import (
    DENIED_STATUS, ExecutionPolicy, PolicyExecutor, make_executor,
)


# ------------------------------------------------------------------ classifier

def test_danger_beats_hint():
    # A DELETE hinted as a harmless read is still destructive.
    assert ac.classify("DELETE", "http://h/api/users/7", hint=ac.SAFE_READ) == ac.DESTRUCTIVE
    assert ac.classify("POST", "http://h/api/payments/charge", {"amt": 5}) == ac.FINANCIAL
    assert ac.classify("POST", "http://h/api/notify/email", {"to": "x"}) == ac.MESSAGING
    assert ac.classify("POST", "http://h/api/x", {"callback": "http://evil/cb"}) == ac.EXTERNAL_SIDE_EFFECT


def test_reads_and_privilege_and_unknown():
    assert ac.classify("GET", "http://h/api/files/9") == ac.SAFE_READ
    # a bare GET can only be a cross-read if the caller declares it
    assert ac.classify("GET", "http://h/api/files/9", hint=ac.CROSS_OBJECT_READ) == ac.CROSS_OBJECT_READ
    assert ac.classify("PATCH", "http://h/api/users/me", {"role": "admin"}) == ac.PRIVILEGE_MUTATION
    assert ac.classify("POST", "http://h/api/things", {"name": "x"}) == ac.OWNED_CREATE
    assert ac.classify("OPTIONS", "http://h/api/x") == ac.UNKNOWN


def test_endpoint_key_collapses_ids():
    assert endpoint_key("http://h/api/files/file_500") == endpoint_key("http://h/api/files/file_501")
    assert endpoint_key("http://h/rest/basket/7") == endpoint_key("http://h/rest/basket/999")


# ----------------------------------------------------------------- policy gate

def _policy(mode, scope_filter=None):
    return ExecutionPolicy(mode, scope_filter=scope_filter)


def test_bounty_refuses_delete_financial_messaging_unknown():
    p = _policy("bounty_safe")
    assert not p.evaluate("DELETE", "http://h/api/users/7").allowed
    assert not p.evaluate("POST", "http://h/api/payments", {"amt": 1}).allowed
    assert not p.evaluate("POST", "http://h/api/messages/send", {"t": "x"}).allowed
    assert not p.evaluate("OPTIONS", "http://h/api/x").allowed          # UNKNOWN → denied


def test_bounty_allows_self_reflective_mass_assignment():
    p = _policy("bounty_safe")
    d = p.evaluate("PATCH", "http://h/api/users/me", {"role": "admin"})
    assert d.allowed and d.action_class == ac.PRIVILEGE_MUTATION


def test_bounty_cross_read_requires_researcher_owned_target():
    # This is what makes allow_real_user_data_access real, not decorative: a
    # cross-object read against an UNOWNED/unknown target is refused; only a
    # researcher-owned second-persona object is permitted.
    p = _policy("bounty_safe")
    assert not p.evaluate("GET", "http://h/api/x/1", hint=ac.CROSS_OBJECT_READ).allowed
    assert p.evaluate("GET", "http://h/api/x/1", hint=ac.CROSS_OBJECT_READ,
                      target_is_researcher_owned=True).allowed


def test_bounty_caps_cross_object_reads_at_one():
    p = _policy("bounty_safe")
    d1 = p.evaluate("GET", "http://h/api/x/1", hint=ac.CROSS_OBJECT_READ,
                    target_is_researcher_owned=True)
    assert d1.allowed
    p.record(d1.action_class, "http://h/api/x/1")
    d2 = p.evaluate("GET", "http://h/api/y/2", hint=ac.CROSS_OBJECT_READ,
                    target_is_researcher_owned=True)
    assert not d2.allowed and "cross_object_read" in d2.reason


def test_bounty_caps_per_endpoint_enumeration():
    p = _policy("bounty_safe")
    cap = p.budget.max_requests_per_endpoint
    allowed = 0
    for i in range(cap + 8):
        url = f"http://h/api/files/file_{500 + i}"     # same endpoint template (id-collapsed)
        d = p.evaluate("GET", url)
        if d.allowed:
            allowed += 1
            p.record(d.action_class, url)
    assert allowed == cap        # enumeration stops at the per-endpoint cap


def test_bounty_refuses_out_of_scope():
    p = _policy("bounty_safe", scope_filter=lambda u: "in-scope" in u)
    assert not p.evaluate("GET", "http://h/other").allowed
    assert p.evaluate("GET", "http://h/in-scope/api/x").allowed


def test_passive_allows_reads_only():
    p = _policy("passive")
    assert p.evaluate("GET", "http://h/api/x/1").allowed
    assert not p.evaluate("POST", "http://h/api/things", {"n": 1}).allowed
    assert not p.evaluate("PATCH", "http://h/api/users/me", {"role": "admin"}).allowed


def test_lab_is_passthrough():
    p = _policy("lab")
    assert p.evaluate("DELETE", "http://h/api/users/7").allowed          # nothing denied
    assert p.evaluate("POST", "http://h/api/payments", {"amt": 1}).allowed


# --------------------------------------------------------------- executor seam

@pytest.mark.asyncio
async def test_executor_denies_without_sending_and_records_skips():
    sent = []

    async def raw(method, url, body=None, **kw):
        sent.append((method, url))
        return 200, {"ok": True}

    ex = make_executor(raw, mode="bounty_safe")
    st, resp = await ex.send("DELETE", "http://h/api/users/7")
    assert st == DENIED_STATUS and "_policy_denied" in resp
    assert sent == []                                    # never reached the transport
    assert ex.skipped and ex.skipped[0]["class"] == ac.DESTRUCTIVE

    st, resp = await ex.send("GET", "http://h/api/x/1")   # allowed → reaches transport
    assert st == 200 and ("GET", "http://h/api/x/1") in sent


@pytest.mark.asyncio
async def test_intent_kwargs_do_not_leak_to_raw_transport():
    # A raw send that only accepts (method, url, body) must not receive intent
    # kwargs (proof_goal/actor/…) — those belong on the CandidateAction, not the
    # wire. Leaking one raises TypeError and silently kills the probe.
    seen = {}

    async def raw(method, url, body=None):        # deliberately NO **kw
        seen["called"] = True
        return 200, {}

    ex = make_executor(raw, mode="bounty_safe")
    st, _ = await ex.send("GET", "http://h/x", hint=ac.CROSS_OBJECT_READ,
                          target_is_researcher_owned=True, actor="A", target_owner="B",
                          proof_goal="single_cross_owned_object_read")
    assert st == 200 and seen.get("called")


@pytest.mark.asyncio
async def test_denied_cross_read_does_not_consume_budget():
    # A 403 cross-read read NOTHING, so it must not consume the one-read budget —
    # otherwise the golden-path "confirm forbidden" probe eats the real read.
    statuses = iter([403, 200])

    async def raw(method, url, body=None, **kw):
        return next(statuses), {}

    ex = make_executor(raw, mode="bounty_safe")
    st, _ = await ex.send("GET", "http://h/a/1", hint=ac.CROSS_OBJECT_READ, target_is_researcher_owned=True)
    assert st == 403                                   # denied by the target → not counted
    st, _ = await ex.send("GET", "http://h/a/2", hint=ac.CROSS_OBJECT_READ, target_is_researcher_owned=True)
    assert st == 200                                   # the ONE real read → counted
    st, _ = await ex.send("GET", "http://h/a/3", hint=ac.CROSS_OBJECT_READ, target_is_researcher_owned=True)
    assert st == DENIED_STATUS                         # budget now exhausted


@pytest.mark.asyncio
async def test_allowed_action_emits_a_provenance_block():
    from core.safety.provenance import ProvenanceSink

    async def raw(method, url, body=None, **kw):
        return 200, {"id": 1, "marker": "sf_secret"}

    sink = ProvenanceSink()
    ex = PolicyExecutor(raw, ExecutionPolicy("bounty_safe"), provenance=sink)
    await ex.send("GET", "http://h/api/x/1", hint=ac.CROSS_OBJECT_READ,
                  target_is_researcher_owned=True, actor="A", target_owner="B")
    blk = sink.action_blocks[0].payload
    assert blk["allowed"] is True and blk["action_class"] == ac.CROSS_OBJECT_READ
    assert blk["actor_persona_id"] == "A" and blk["status"] == 200
    assert blk["response_body_hash"].startswith("sha256:")     # hashed, not raw
    assert "sf_secret" not in str(blk)                          # the raw body never lands here
    assert sink.root() is not None


@pytest.mark.asyncio
async def test_denied_action_emits_a_denial_block_and_is_not_sent():
    from core.safety.provenance import ProvenanceSink
    sent = []

    async def raw(method, url, body=None, **kw):
        sent.append((method, url))
        return 200, {}

    sink = ProvenanceSink()
    ex = PolicyExecutor(raw, ExecutionPolicy("bounty_safe"), provenance=sink)
    st, _ = await ex.send("DELETE", "http://h/api/users/7")
    assert st == DENIED_STATUS and sent == []                   # refused before transport
    blk = sink.action_blocks[0].payload
    assert blk["allowed"] is False and blk["action_class"] == ac.DESTRUCTIVE
    assert "DESTRUCTIVE" in blk["denial_reason"]                # class-gated in bounty mode
    assert sink.summary()["destructive_actions_denied"] == 1


@pytest.mark.asyncio
async def test_executor_passes_auth_kwarg_through():
    seen = {}

    async def raw(method, url, body=None, *, _auth=None, **kw):
        seen["auth"] = _auth
        return 200, {}

    ex = make_executor(raw, mode="lab")
    await ex.send("GET", "http://h/api/x", _auth="tok123")
    assert seen["auth"] == "tok123"
