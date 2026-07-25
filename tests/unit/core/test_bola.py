"""
Unit tests for the cross-principal BOLA engine + orchestrator
(core/wraith/bola, core/wraith/bola_probe).

The engine tests pin the honesty gate: a finding requires a 2xx AND an A-private
marker in the attacker's response (a 200 without the marker — a filtered/own view
— is not a finding). The orchestrator tests pin the two subtle correctness points:
the planted marker must exclude the reference field the attacker already knows,
and a full two-principal loop confirms BOLA only when authz is actually broken.
"""

from urllib.parse import urlparse

import pytest

from core.wraith import bola, bola_probe as bp
from core.wraith.bola import OwnedObject
from core.wraith.bola import test_bola as run_bola   # aliased: pytest must not collect it


# --------------------------------------------------------------------------- engine

@pytest.mark.asyncio
async def test_confirms_when_marker_leaks():
    async def attacker(method, url, body=None):
        return 200, {"id": 8, "UserId": 44, "secret": "A_SECRET_xyz"}
    owned = [OwnedObject(ref="http://h/basket/8", markers=['"UserId":44'], label="victim's basket")]
    found = await run_bola(owned, attacker)
    assert len(found) == 1 and found[0].leaked == ['"UserId":44']


@pytest.mark.asyncio
async def test_no_finding_on_2xx_without_marker():
    # The classic single-session false positive: 200, but it's the attacker's OWN
    # (or an empty/filtered) view — no victim marker → must not be reported.
    async def attacker(method, url, body=None):
        return 200, {"id": 9, "UserId": 45, "Products": []}
    owned = [OwnedObject(ref="http://h/basket/8", markers=['"UserId":44'])]
    assert await run_bola(owned, attacker) == []


@pytest.mark.asyncio
async def test_no_finding_when_access_denied():
    async def attacker(method, url, body=None):
        return 403, {"error": "forbidden"}
    owned = [OwnedObject(ref="http://h/basket/8", markers=['"UserId":44'])]
    assert await run_bola(owned, attacker) == []


@pytest.mark.asyncio
async def test_marker_match_is_whitespace_insensitive():
    async def attacker(method, url, body=None):
        return 200, {"UserId": 44}        # serializes as '"UserId": 44' (a space)
    owned = [OwnedObject(ref="http://h/x", markers=['"UserId":44'])]   # marker has none
    assert len(await run_bola(owned, attacker)) == 1


@pytest.mark.asyncio
async def test_to_finding_shape():
    async def attacker(method, url, body=None):
        return 200, {"secret": "nonce123"}
    owned = [OwnedObject(ref="http://h/books/v1/t", markers=["nonce123"], label="victim's book")]
    d = (await run_bola(owned, attacker))[0].to_finding()
    assert d["metadata"]["vuln_class"] == "bola"
    assert "idor" in d["tags"] and "confirmed_vuln" in d["families"]
    assert d["severity"] == "HIGH" and d["metadata"]["leaked_markers"] == ["nonce123"]


# ----------------------------------------------------------------------- helpers

def test_build_owned_body_excludes_reference_field():
    # book_title is the reference (in the by-id path) → its value is known to the
    # attacker → it must NOT be a marker. Only `secret` qualifies.
    props = {"book_title": {"type": "string"}, "secret": {"type": "string"}}
    body, markers = bp._build_owned_body(props, "/books/v1/{book_title}")
    assert set(body) == {"book_title", "secret"}
    assert markers == [body["secret"]]
    assert body["book_title"] not in markers


def test_fill_byid_from_body_and_created_id():
    assert bp._fill_byid("http://h", "/books/v1/{book_title}",
                         {"book_title": "tt"}, {}) == "http://h/books/v1/tt"
    assert bp._fill_byid("http://h", "/things/{id}", {}, {"id": 77}) == "http://h/things/77"


# ------------------------------------------------------------------- integration

def _vampi_like(secure: bool):
    """A VAmPI-shaped app: register/login (distinct tokens), an OpenAPI spec, and a
    /books/v1 whose GET-by-title returns the secret to anyone (the BOLA) unless
    `secure`, in which case non-owners get 403."""
    books = {}

    def make_send(token):
        async def send(method, url, body=None):
            path = urlparse(url).path
            if method == "POST" and path == "/users/v1/register":
                return 200, {"status": "success"}
            if method == "POST" and path == "/users/v1/login":
                return 200, {"auth_token": f"tok_{(body or {}).get('username')}"}
            if method == "GET" and path == "/openapi.json":
                return 200, {"paths": {
                    "/books/v1": {"post": {"requestBody": {"content": {"application/json":
                        {"schema": {"properties": {"book_title": {"type": "string"},
                                                   "secret": {"type": "string"}}}}}}}},
                    "/books/v1/{book_title}": {"get": {}},
                }}
            if method == "POST" and path == "/books/v1":
                t = (body or {}).get("book_title")
                books[t] = {**(body or {}), "owner": token}
                return 200, {"status": "success"}
            if method == "GET" and path.startswith("/books/v1/"):
                t = path.split("/books/v1/", 1)[1]
                b = books.get(t)
                if not b:
                    return 404, {}
                if secure and b["owner"] != token:
                    return 403, {}
                return 200, {"book_title": b["book_title"], "owner": b["owner"], "secret": b["secret"]}
            if method == "DELETE" and path.startswith("/books/v1/"):
                return 200, {}
            return 404, {}
        return send

    return make_send


@pytest.mark.asyncio
async def test_probe_bola_confirms_cross_principal_read():
    make_send = _vampi_like(secure=False)
    findings = await bp.probe_bola(
        "http://h.test", register_post=make_send(None), authed_send=make_send,
    )
    assert len(findings) == 1
    m = findings[0]["metadata"]
    assert m["vuln_class"] == "bola" and "/books/v1/" in m["object_ref"]
    assert m["leaked_markers"] and m["leaked_markers"][0].startswith("sfsec")


@pytest.mark.asyncio
async def test_probe_bola_silent_when_authz_enforced():
    make_send = _vampi_like(secure=True)   # non-owners get 403
    findings = await bp.probe_bola(
        "http://h.test", register_post=make_send(None), authed_send=make_send,
    )
    assert findings == []
