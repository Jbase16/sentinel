"""
Unit tests for business-logic / server-trust invariant testing (core/wraith/logic_flaws).

The novel, undefended class: a well-formed authenticated request whose only fault
is violating an invariant the server should enforce but instead trusts from the
client. Guards the per-field invariant inference and the honesty gate (flag only
when the server ACCEPTS *and PERSISTS* the violation).
"""

import pytest

from core.wraith import logic_flaws as lf


# ──────────────────────────── invariant inference ───────────────────────────

def test_infer_probes_targets_the_right_fields():
    body = {"quantity": 1, "price": 9.99, "isAdmin": False, "name": "widget", "id": 5}
    fields = {p.field for p in lf.infer_probes(body)}
    assert "quantity" in fields            # quantity-like number
    assert "price" in fields               # money-like number
    assert "isAdmin" in fields             # privilege flag
    assert "name" not in fields and "id" not in fields   # ordinary fields untouched


def test_infer_probes_quantity_includes_negative_and_zero():
    vals = {p.value for p in lf.infer_probes({"quantity": 3}) if p.field == "quantity"}
    assert -999 in vals and 0 in vals


# ─────────────────────── end-to-end against a mock server ───────────────────

def _server(trusted: set):
    """A server that PERSISTS `trusted` fields as-given and sanitizes the rest
    (echoes a safe default), returning 200."""
    async def send(method, url, body):
        out = {k: (v if k in trusted else 1) for k, v in body.items()}
        return 200, {"status": "success", "data": out}
    return send


@pytest.mark.asyncio
async def test_confirms_trusted_quantity_violation():
    flaws = await lf.test_invariants("PUT", "http://h/api/BasketItems/9",
                                     {"quantity": 1}, _server({"quantity"}))
    assert len(flaws) == 1
    assert flaws[0].field == "quantity"
    assert flaws[0].violation in (-999, 0)
    assert "persisted" in flaws[0].evidence


@pytest.mark.asyncio
async def test_confirms_client_set_money():
    flaws = await lf.test_invariants("POST", "http://h/api/Orders",
                                     {"total": 100.0}, _server({"total"}))
    assert any(f.field == "total" for f in flaws)


@pytest.mark.asyncio
async def test_confirms_privilege_flag_assignment():
    flaws = await lf.test_invariants("PATCH", "http://h/api/Users/1",
                                     {"role": "customer"}, _server({"role"}))
    assert any(f.field == "role" and f.violation == "admin" for f in flaws)


# ─────────────────────────────── honesty gate ───────────────────────────────

@pytest.mark.asyncio
async def test_no_flaw_when_server_rejects():
    async def reject(method, url, body):
        return 400, {"error": "invalid quantity"}
    flaws = await lf.test_invariants("PUT", "http://h/x", {"quantity": 1}, reject)
    assert flaws == []


@pytest.mark.asyncio
async def test_no_flaw_when_accepted_but_not_persisted():
    # 200, but the server sanitizes the value (doesn't trust it) → no invariant broken.
    flaws = await lf.test_invariants("PUT", "http://h/x", {"quantity": 1}, _server(set()))
    assert flaws == []


@pytest.mark.asyncio
async def test_finding_shape_is_business_logic():
    flaws = await lf.test_invariants("PUT", "http://h/api/BasketItems/9",
                                     {"quantity": 1}, _server({"quantity"}))
    f = flaws[0].to_finding()
    assert f["metadata"]["vuln_class"] == "business_logic"
    assert f["severity"] == "HIGH"
    assert "business_logic" in f["tags"]
