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
    p = _policy("bounty_safe")   # max_requests_per_endpoint = 3
    allowed = 0
    for i in range(10):
        url = f"http://h/api/files/file_{500 + i}"     # same endpoint template
        d = p.evaluate("GET", url)
        if d.allowed:
            allowed += 1
            p.record(d.action_class, url)
    assert allowed == 3          # enumeration stops at the per-endpoint cap


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
async def test_executor_passes_auth_kwarg_through():
    seen = {}

    async def raw(method, url, body=None, *, _auth=None, **kw):
        seen["auth"] = _auth
        return 200, {}

    ex = make_executor(raw, mode="lab")
    await ex.send("GET", "http://h/api/x", _auth="tok123")
    assert seen["auth"] == "tok123"
