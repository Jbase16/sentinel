"""
Unit tests for the mass-assignment engine (core/wraith/mass_assignment).

Each test stands up a tiny in-memory "create" endpoint with a controllable trust
policy and a read-back, then asserts the differential honesty gate: a privilege
field is reported ONLY when an injected object carries it and a baseline object
does not. Covers the trusted case, the stripped case, the defaults-privileged
trap, the accept-but-not-persisted gate, the reflection fallback, and the
no-read-back case.
"""

import os

import pytest

from core.wraith import mass_assignment as ma


def _app(trust_fields, defaults=None, *, reflect=False, readable=True):
    """A minimal create endpoint.

    - `trust_fields`: request fields the server stores as-given (else ignored).
    - `defaults`: server-set defaults applied to every new record.
    - `reflect`: echo the stored record in the create response.
    - `readable`: whether read_back can see stored records (separate endpoint).
    """
    store = {}

    async def send(method, url, body=None):
        body = body or {}
        rec = dict(defaults or {})
        rec["username"] = body.get("username")
        for k, v in body.items():
            if k in trust_fields:
                rec[k] = v
        store[rec["username"]] = rec
        return (201, {"data": dict(rec)}) if reflect else (201, {"status": "ok"})

    async def read_back(body, _resp):
        return store.get(body.get("username")) if readable else None

    return send, read_back


def _make_body():
    return {"username": "u_" + os.urandom(4).hex(), "password": "Sf!Probe_9183"}


@pytest.mark.asyncio
async def test_confirms_trusted_admin_via_readback():
    send, read_back = _app(trust_fields={"admin"}, defaults={"admin": False})
    flaws = await ma.test_mass_assignment("POST", "http://h.test/register", _make_body, send, read_back)
    assert [f.field for f in flaws] == ["admin"]
    f = flaws[0]
    assert f.injected is True and f.baseline is False and f.klass == "privilege"


@pytest.mark.asyncio
async def test_no_flaw_when_field_is_stripped():
    # Server ignores client `admin` (always stores the default) → no differential.
    send, read_back = _app(trust_fields=set(), defaults={"admin": False})
    flaws = await ma.test_mass_assignment("POST", "http://h.test/register", _make_body, send, read_back)
    assert flaws == []


@pytest.mark.asyncio
async def test_default_privileged_field_not_reported():
    # `active` defaults True. Injecting active=True reads back True in BOTH baseline
    # and injected → no differential → must NOT be reported (the classic FP trap).
    send, read_back = _app(trust_fields={"active"}, defaults={"active": True})
    flaws = await ma.test_mass_assignment("POST", "http://h.test/register", _make_body, send, read_back)
    assert all(f.field != "active" for f in flaws)
    assert flaws == []


@pytest.mark.asyncio
async def test_accept_but_not_persisted_is_gated():
    # 2xx on every create, but read-back can't see records → nothing confirmable.
    send, read_back = _app(trust_fields={"admin"}, defaults={"admin": False}, readable=False)
    flaws = await ma.test_mass_assignment("POST", "http://h.test/register", _make_body, send, read_back)
    assert flaws == []


@pytest.mark.asyncio
async def test_reflection_fallback_confirms():
    # No separate read-back, but the create response echoes the stored object.
    send, read_back = _app(trust_fields={"isAdmin"}, defaults={"isAdmin": False},
                           reflect=True, readable=False)
    extra = [("isAdmin", True)]
    flaws = await ma.test_mass_assignment("POST", "http://h.test/register", _make_body, send, read_back,
                                          extra_fields=extra)
    assert any(f.field == "isAdmin" for f in flaws)


@pytest.mark.asyncio
async def test_ownership_field_labeled_via_extra_fields():
    send, read_back = _app(trust_fields={"ownerId"}, defaults={"ownerId": 0})
    flaws = await ma.test_mass_assignment("POST", "http://h.test/things", _make_body, send, read_back,
                                          extra_fields=[("ownerId", 999)])
    owners = [f for f in flaws if f.field == "ownerId"]
    assert owners and owners[0].klass == "ownership" and owners[0].injected == 999


@pytest.mark.asyncio
async def test_baseline_create_failure_yields_nothing():
    async def send(method, url, body=None):
        return 400, {"error": "registration closed"}

    async def read_back(body, _resp):
        return None

    flaws = await ma.test_mass_assignment("POST", "http://h.test/register", _make_body, send, read_back)
    assert flaws == []


@pytest.mark.asyncio
async def test_to_finding_shape():
    send, read_back = _app(trust_fields={"role"}, defaults={"role": "user"})
    flaws = await ma.test_mass_assignment("POST", "http://h.test/register", _make_body, send, read_back)
    roles = [f for f in flaws if f.field == "role"]
    assert roles
    d = roles[0].to_finding()
    assert d["metadata"]["vuln_class"] == "mass_assignment"
    assert "mass_assignment" in d["tags"] and "confirmed_vuln" in d["families"]
    assert d["severity"] == "HIGH"
