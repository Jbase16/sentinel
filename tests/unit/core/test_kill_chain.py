"""
Unit tests for the kill-chain composer (core/cortex/kill_chain).

Pins the differential honesty gate that distinguishes a VERIFIED chain from a
fabricated one: a hop counts only when the normal principal is DENIED and the
escalated principal is ALLOWED. So the composer must (a) confirm a real gated
operation, (b) refuse to chain when the operation is open to everyone, and
(c) refuse to chain when the escalation field doesn't actually grant privilege.
"""

from urllib.parse import urlparse

import pytest

from core.cortex import kill_chain as kc
from core.cortex.kill_chain import compose_privilege_chain

_REGISTER = ("/users/v1/register", lambda e, p: {"username": e.split("@")[0], "password": p, "email": e})
_LOGIN = ("/users/v1/login", lambda e, p: {"username": e.split("@")[0], "password": p})


def _app(*, gated: bool, escalation_works: bool = True):
    """A VAmPI-shaped app. DELETE /users/v1/{u} requires admin when `gated`.
    When `escalation_works` is False the register endpoint ignores the admin
    field, so the 'escalated' principal isn't actually privileged."""
    users = {}

    def make_send(token):
        requester = token[4:] if token and token.startswith("tok_") else None

        async def send(method, url, body=None):
            path = urlparse(url).path
            if method == "POST" and path == "/users/v1/register":
                u = (body or {}).get("username")
                admin = bool((body or {}).get("admin")) if escalation_works else False
                users[u] = {"admin": admin}
                return 200, {"status": "success"}
            if method == "POST" and path == "/users/v1/login":
                return 200, {"auth_token": f"tok_{(body or {}).get('username')}"}
            if method == "DELETE" and path.startswith("/users/v1/"):
                victim = path.split("/users/v1/", 1)[1]
                is_admin = users.get(requester, {}).get("admin", False)
                if gated and not is_admin:
                    return 401, {"message": "Only Admins may delete users"}
                users.pop(victim, None)
                return 200, {"message": "User deleted."}
            return 404, {}
        return send

    return make_send


async def _compose(make_send):
    return await compose_privilege_chain(
        "http://h.test",
        register=_REGISTER, login=_LOGIN,
        privilege_field="admin", privilege_value=True,
        post=make_send(None), authed_send=make_send,
    )


@pytest.mark.asyncio
async def test_verifies_chain_when_operation_is_gated():
    chain = await _compose(_app(gated=True))
    assert chain is not None and chain.severity == "CRITICAL"
    labels = " ".join(chain.steps()).lower()
    assert "mass assignment" in labels and "delete any user" in labels
    # exactly the three hops: self-register, escalate, the one gated capability
    assert len(chain.hops) == 3 and all(h.verified for h in chain.hops)


@pytest.mark.asyncio
async def test_no_chain_when_operation_is_open_to_everyone():
    # Not gated → normal principal is NOT denied → no privilege boundary → no chain.
    assert await _compose(_app(gated=False)) is None


@pytest.mark.asyncio
async def test_no_chain_when_escalation_field_does_not_grant_privilege():
    # admin field is ignored by the server → the 'escalated' principal is still a
    # normal user → it is also denied → no differential → no fabricated chain.
    assert await _compose(_app(gated=True, escalation_works=False)) is None


@pytest.mark.asyncio
async def test_finding_and_proposal_shape():
    chain = await _compose(_app(gated=True))
    f = chain.to_finding()
    assert f["metadata"]["vuln_class"] == "exploit_chain"
    assert f["metadata"]["epistemic"] == "verified"
    assert "privilege_escalation" in f["tags"] and "confirmed_vuln" in f["families"]
    assert f["severity"] == "CRITICAL"
    p = chain.to_proposal()
    assert p.epistemic == "verified" and p.source == "composer" and p.length == 3


# --------------------------------------------------- data-exposure chain

def _pop_app():
    """register/login + a fully-enumerable basket population (every basket
    readable, owner = its own id)."""
    def make_send(token):
        async def send(method, url, body=None):
            path = urlparse(url).path
            if method == "POST" and path == "/users/v1/register":
                return 200, {"status": "success"}
            if method == "POST" and path == "/users/v1/login":
                return 200, {"auth_token": "tok_" + "z" * 32}
            if method == "GET" and path.startswith("/rest/basket/"):
                i = int(path.rsplit("/", 1)[1])
                return 200, {"data": {"id": i, "UserId": i}}
            return 404, {}
        return send
    return make_send


@pytest.mark.asyncio
async def test_data_exposure_chain_reverifies_from_fresh_account():
    make_send = _pop_app()
    scale = [{"metadata": {"endpoint": "http://h.test/rest/basket/{id}"}}]
    chain = await kc.compose_data_exposure_chain(
        "http://h.test", scale, register=_REGISTER, login=_LOGIN,
        post=make_send(None), authed_send=make_send,
    )
    assert chain is not None and chain.kind == "data_exposure" and chain.severity == "CRITICAL"
    f = chain.to_finding()
    assert "mass data exposure" in f["type"].lower()
    assert "mass_data_exposure" in f["tags"] and "privilege_escalation" not in f["tags"]
    assert len(chain.hops) == 2          # anonymous registration + the enumeration hop


@pytest.mark.asyncio
async def test_compose_chains_assembles_data_exposure():
    make_send = _pop_app()
    scale = [{"metadata": {"endpoint": "http://h.test/rest/basket/{id}"}}]
    chains = await kc.compose_chains(
        "http://h.test", register=_REGISTER, login=_LOGIN,
        post=make_send(None), authed_send=make_send, scale_findings=scale,
    )
    assert len(chains) == 1 and chains[0].kind == "data_exposure"


@pytest.mark.asyncio
async def test_compose_chains_empty_when_no_primitives():
    make_send = _pop_app()
    chains = await kc.compose_chains(
        "http://h.test", register=_REGISTER, login=_LOGIN,
        post=make_send(None), authed_send=make_send,
    )
    assert chains == []
