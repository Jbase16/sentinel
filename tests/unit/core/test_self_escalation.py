"""
Unit tests for bounty-safe self-escalation (core/wraith/self_escalation).

Pins both disciplines: least-spicy-first + stop-on-first, and the honesty ladder —
echo-only is NOT reported, a separate GET reflecting the role is MEDIUM, and a fresh
login still reflecting it is HIGH.
"""

from urllib.parse import urlparse

import pytest

from core.wraith import self_escalation as se
from core.wraith.self_escalation import prove_self_escalation


def _app(*, valid_roles=None, store=True):
    """A profile app. PATCH /api/users/me{role} is rejected (400) unless the role is
    in `valid_roles`; if accepted it is stored (GET reflects) when `store`, else only
    echoed in the PATCH response (a deranged parrot)."""
    state = {"role": "viewer"}

    def make_send():
        async def send(method, url, body=None, **kw):
            path = urlparse(url).path
            if path == "/api/users/me":
                if method == "GET":
                    return 200, {"id": "u1", "role": state["role"]}
                if method in ("PATCH", "PUT"):
                    r = (body or {}).get("role")
                    if valid_roles is not None and r not in valid_roles:
                        return 400, {"error": "unknown role"}
                    if store:
                        state["role"] = r
                    return 200, {"id": "u1", "role": r}      # echoes r regardless of storing
            return 404, {}
        return send

    return make_send


@pytest.mark.asyncio
async def test_high_confidence_when_fresh_login_reflects():
    make_send = _app(valid_roles={"member", "admin"})
    send = make_send()

    async def relogin():
        return make_send()           # a fresh session sees the same (stored) state

    proof = await prove_self_escalation("http://h", send=send, relogin=relogin)
    assert proof is not None
    assert proof.confidence == se.HIGH and proof.severity == "HIGH"
    assert proof.baseline_value == "viewer" and proof.escalated_value == "member"   # least-spicy, stopped


@pytest.mark.asyncio
async def test_medium_without_relogin():
    proof = await prove_self_escalation("http://h", send=_app(valid_roles={"member"})())
    assert proof is not None and proof.confidence == se.MEDIUM and proof.severity == "MEDIUM"


@pytest.mark.asyncio
async def test_echo_only_is_not_reported():
    # PATCH echoes the role but a separate GET still shows viewer → below MEDIUM.
    proof = await prove_self_escalation(
        "http://h", send=_app(valid_roles={"member"}, store=False)())
    assert proof is None


@pytest.mark.asyncio
async def test_rejected_values_are_skipped_until_a_valid_one():
    # member/contributor are rejected; support_agent is accepted → it wins.
    proof = await prove_self_escalation(
        "http://h", send=_app(valid_roles={"support_agent"})(), max_values=4)
    assert proof is not None and proof.escalated_value == "support_agent"


@pytest.mark.asyncio
async def test_no_finding_when_nothing_accepted():
    proof = await prove_self_escalation(
        "http://h", send=_app(valid_roles=set())(), max_values=3)
    assert proof is None


@pytest.mark.asyncio
async def test_to_finding_reports_confidence_and_stays_minimal_impact():
    proof = await prove_self_escalation("http://h", send=_app(valid_roles={"member"})())
    d = proof.to_finding()
    assert d["metadata"]["subtype"] == "self_escalation"
    assert d["metadata"]["confidence"] == se.MEDIUM
    assert "confidence_medium" in d["tags"] and "minimal_impact" in d["tags"]
    assert "capability confirmed, not consumed" in d["message"]


def test_plausible_roles_are_least_spicy_first_and_above_baseline():
    roles = se._plausible_roles("viewer", None)
    assert roles[0] == "member" and roles.index("member") < roles.index("admin")
    # a baseline already in the ladder only yields MORE privileged values
    assert "member" not in se._plausible_roles("manager", None)
