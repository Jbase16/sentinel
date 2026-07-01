"""
Unit tests for the bounty-safe two-persona owned proof (core/wraith/owned_proof).

Pins the minimal-impact contract: confirm a cross-object read with two researcher-
owned personas and a SINGLE object, create only safe object types, and stay silent
when authorization is actually enforced.
"""

from urllib.parse import urlparse

import pytest

from core.wraith import owned_proof as op
from core.wraith.owned_proof import prove_owned_cross_read


def _app(*, secure=False, safe_collection=True):
    """A tiny API. B creates an object; GET-by-id returns it to anyone (the BOLA)
    unless `secure`. The collection is a safe 'documents' type, or an unsafe
    'invoices' type that the prover must refuse to create in."""
    coll = "/api/documents" if safe_collection else "/api/invoices"
    store = {}
    created = {"n": 0}

    def make_send(persona):
        async def send(method, url, body=None, **kw):
            path = urlparse(url).path
            if path == "/openapi.json":
                return 200, {"paths": {
                    coll: {"post": {"requestBody": {"content": {"application/json": {"schema":
                          {"properties": {"title": {"type": "string"}, "secret": {"type": "string"}}}}}}}},
                    coll + "/{id}": {"get": {}}}}
            if method == "POST" and path == coll:
                created["n"] += 1
                oid = f"obj{created['n']}"
                store[oid] = {**(body or {}), "owner": persona}
                return 201, {"data": {"id": oid}}
            if method == "GET" and path.startswith(coll + "/"):
                oid = path.rsplit("/", 1)[1]
                o = store.get(oid)
                if not o:
                    return 404, {}
                if secure and o["owner"] != persona:
                    return 403, {}
                return 200, {"data": o}
            return 404, {}
        return send

    return make_send, created


@pytest.mark.asyncio
async def test_two_persona_bola_confirmed_minimally():
    make_send, created = _app()
    proof = await prove_owned_cross_read(
        "http://h", owner_send=make_send("B"), accessor_send=make_send("A"),
        owner_persona="B", accessor_persona="A")
    assert proof is not None
    assert proof.object_type == "documents" and proof.owner_persona == "B"
    assert proof.ownership_markers["planted"]          # B's marker leaked to A
    assert created["n"] == 1                           # one object, then stop
    d = proof.to_finding()
    assert d["metadata"]["subtype"] == "two_persona_owned" and "minimal_impact" in d["tags"]


@pytest.mark.asyncio
async def test_refuses_unsafe_object_types():
    # Only an 'invoices' collection exists → the prover must never create in it.
    make_send, created = _app(safe_collection=False)
    proof = await prove_owned_cross_read(
        "http://h", owner_send=make_send("B"), accessor_send=make_send("A"))
    assert proof is None and created["n"] == 0


@pytest.mark.asyncio
async def test_silent_when_authz_enforced():
    make_send, created = _app(secure=True)     # non-owner gets 403
    proof = await prove_owned_cross_read(
        "http://h", owner_send=make_send("B"), accessor_send=make_send("A"))
    assert proof is None
    assert created["n"] == 1                    # it created (owned) but the read was denied


def test_noun_skips_version_segments():
    assert op._noun("/books/v1") == "books"
    assert op._noun("/api/documents") == "documents"
    assert op._is_safe("/books/v1") and not op._is_safe("/api/invoices")
    assert not op._is_safe("/api/api-keys")
