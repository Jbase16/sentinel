"""
Unit tests for escalation-amplified BOLA (core/cortex/escalation_amplification +
the compose_amplified_bola_chain composer).

Pins the denied→allowed differential gate: a finding requires objects denied at
baseline, an escalation that provably changed the role, and previously-denied
objects becoming readable. No denied objects, a refused escalation (secure mode),
or an escalation that grants nothing must all stay silent.
"""

from urllib.parse import urlparse

import pytest

from core.cortex import kill_chain as kc
from core.cortex.escalation_amplification import verify_escalation_amplifies_bola


def _app(*, escalation_works=True, role_grants=None):
    """A profile-update app. GET/PATCH /api/users/me exposes/mutates `role` (only
    when escalation_works). GET /api/notes/{id} is allowed iff the id is in
    role_grants[current_role]."""
    role_grants = role_grants or {}
    state = {"role": "viewer"}

    async def send(method, url, body=None):
        path = urlparse(url).path
        if path == "/api/users/me":
            if method == "GET":
                return 200, {"id": "u1", "username": "alice", "role": state["role"], "tenant_id": "t_a"}
            if method in ("PATCH", "PUT"):
                if escalation_works and body and "role" in body:
                    state["role"] = body["role"]
                    return 200, {"role": state["role"]}
                return 403, {"error": "immutable fields"}
        if method == "GET" and path.startswith("/api/notes/"):
            oid = path.rsplit("/", 1)[1]
            if oid in role_grants.get(state["role"], set()):
                return 200, {"id": oid, "tenant_id": "t_b", "secret": "x"}
            return 403, {"error": "forbidden"}
        return 404, {}

    return send


_REFS = ["/api/notes/n1", "/api/notes/n2", "/api/notes/n3"]


@pytest.mark.asyncio
async def test_fires_when_escalation_unlocks_denied_objects():
    send = _app(role_grants={"viewer": set(), "support_agent": {"n1", "n2"}})
    res = await verify_escalation_amplifies_bola("http://h", send, candidate_refs=_REFS)
    assert res is not None
    assert res.role_before == "viewer" and res.role_after == "support_agent"
    assert res.count == 2 and res.baseline_denied == 3


@pytest.mark.asyncio
async def test_silent_when_nothing_denied():
    # viewer can already read everything → no denied set → nothing to amplify.
    send = _app(role_grants={"viewer": {"n1", "n2", "n3"}})
    assert await verify_escalation_amplifies_bola("http://h", send, candidate_refs=_REFS) is None


@pytest.mark.asyncio
async def test_silent_when_escalation_refused():
    # Secure mode: PATCH role is rejected → no escalation → no chain.
    send = _app(escalation_works=False, role_grants={"viewer": set(), "support_agent": {"n1", "n2"}})
    assert await verify_escalation_amplifies_bola("http://h", send, candidate_refs=_REFS) is None


@pytest.mark.asyncio
async def test_silent_when_escalation_grants_nothing():
    # Role changes, but the new role still can't read the denied objects.
    send = _app(role_grants={"viewer": set(), "support_agent": set(), "admin": set()})
    assert await verify_escalation_amplifies_bola("http://h", send, candidate_refs=_REFS) is None


@pytest.mark.asyncio
async def test_keeps_the_value_that_amplifies_most():
    send = _app(role_grants={"viewer": set(), "support_agent": {"n1"}, "admin": {"n1", "n2", "n3"}})
    res = await verify_escalation_amplifies_bola("http://h", send, candidate_refs=_REFS)
    assert res is not None and res.role_after == "admin" and res.count == 3


@pytest.mark.asyncio
async def test_compose_amplified_bola_chain_shape():
    send = _app(role_grants={"viewer": set(), "support_agent": {"n1", "n2"}})
    chain = await kc.compose_amplified_bola_chain("http://h", baseline_send=send, candidate_refs=_REFS)
    assert chain is not None and chain.kind == "amplified_bola" and chain.severity == "CRITICAL"
    f = chain.to_finding()
    assert "escalation-amplified" in f["type"].lower()
    assert "amplified" in f["tags"] and "privilege_escalation" in f["tags"]
    assert len(chain.hops) == 3 and all(h.verified for h in chain.hops)


@pytest.mark.asyncio
async def test_compose_chains_includes_amplified_when_refs_given():
    send = _app(role_grants={"viewer": set(), "support_agent": {"n1", "n2"}})
    reg = ("/register", lambda e, p: {"email": e})
    chains = await kc.compose_chains(
        "http://h", register=reg, login=reg, post=send, authed_send=lambda t: send,
        baseline_send=send, candidate_refs=_REFS,
    )
    assert any(c.kind == "amplified_bola" for c in chains)
