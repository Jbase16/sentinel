"""
Unit tests for object-graph BOLA at scale (core/wraith/bola_scale + the
probe_bola_scale orchestrator).

Pins the distinct-owner honesty gate: a finding requires reading objects from
>= min_owners distinct owners that are NOT the attacker. Same-owner data, public
(ownerless) data, and the attacker's own objects must never produce a finding.
"""

from urllib.parse import urlparse

import pytest

from core.wraith import bola_scale as bs
from core.wraith import bola_probe as bp
from core.wraith.bola_scale import sweep_object_ids


def _pop(owner_of):
    """A population endpoint: id -> {"data": {"id": i, "UserId": owner}} or 404."""
    async def send(method, url, body=None):
        i = int(url.rsplit("/", 1)[1])
        ow = owner_of(i)
        if ow is None:
            return 404, {}
        return 200, {"data": {"id": i, "UserId": ow}}
    return send


@pytest.mark.asyncio
async def test_confirms_when_many_distinct_owners():
    f = await sweep_object_ids("GET", "http://h/rest/basket/{id}", _pop(lambda i: i),
                               own_identity=set(), ids=range(1, 6), min_owners=3)
    assert f is not None and f.distinct_owners == 5 and f.owner_field == "UserId"
    assert f.accessed == 5


@pytest.mark.asyncio
async def test_no_finding_when_single_owner():
    # Every object owned by the same user → not systemic, not cross-principal scale.
    f = await sweep_object_ids("GET", "http://h/x/{id}", _pop(lambda i: 5),
                               own_identity=set(), ids=range(1, 8), min_owners=3)
    assert f is None


@pytest.mark.asyncio
async def test_excludes_attacker_own_objects():
    f = await sweep_object_ids("GET", "http://h/x/{id}", _pop(lambda i: i),
                               own_identity={"2", "4"}, ids=range(1, 6), min_owners=3)
    assert f is not None
    assert "2" not in f.sample_owners and "4" not in f.sample_owners
    assert f.distinct_owners == 3            # owners {1,3,5}


@pytest.mark.asyncio
async def test_no_finding_for_ownerless_public_data():
    async def send(method, url, body=None):
        i = int(url.rsplit("/", 1)[1])
        return 200, {"data": {"id": i, "name": "public-product"}}   # no owner field
    f = await sweep_object_ids("GET", "http://h/api/Products/{id}", send,
                               own_identity=set(), ids=range(1, 9), min_owners=3)
    assert f is None


@pytest.mark.asyncio
async def test_sensitive_endpoint_is_critical():
    f = await sweep_object_ids("GET", "http://h/api/Cards/{id}", _pop(lambda i: i),
                               own_identity=set(), ids=range(1, 5), min_owners=3)
    assert f is not None and f.severity == "CRITICAL"
    d = f.to_finding()
    assert d["metadata"]["subtype"] == "horizontal_enumeration"
    assert "bola_at_scale" in d["tags"] and d["metadata"]["vuln_class"] == "bola"


def test_extract_owner_handles_nested():
    assert bs._extract_owner({"id": 1, "UserId": 7}) == ("UserId", "7")
    assert bs._extract_owner({"id": 1, "owner": {"id": 9}}) == ("owner.id", "9")
    assert bs._extract_owner({"id": 1, "name": "x"}) is None


# ------------------------------------------------------------------- integration

@pytest.mark.asyncio
async def test_probe_bola_scale_full_loop():
    """Juice-shaped mock: register/login then a fully-enumerable basket population.
    The attacker's own basket (bid 99) must be excluded; ids 1..16 are others."""
    def make_send(token):
        async def send(method, url, body=None):
            path = urlparse(url).path
            if method == "POST" and path == "/api/Users":
                return 200, {"status": "success", "data": {"id": 99}}
            if method == "POST" and path == "/rest/user/login":
                return 200, {"authentication": {"token": "tokB_" + "x" * 32, "bid": 99}}
            if method == "GET" and path.startswith("/rest/basket/"):
                i = int(path.rsplit("/", 1)[1])
                return 200, {"data": {"id": i, "UserId": i}}    # every basket readable
            return 404, {}
        return send

    findings = await bp.probe_bola_scale(
        "http://h.test", register_post=make_send(None), authed_send=make_send,
    )
    basket = [f for f in findings if "/rest/basket/" in f["metadata"]["endpoint"]]
    assert basket, "expected a systemic basket BOLA finding"
    m = basket[0]["metadata"]
    assert m["distinct_owners"] >= 3 and "99" not in m["sample_owners"]
