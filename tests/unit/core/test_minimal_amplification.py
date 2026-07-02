"""
Unit tests for the composed escalation-amplified BOLA proof
(core/cortex/minimal_amplification).

These pin the milestone: ONE composed finding that proves an authorization
state-transition failure (same object, denied before a self-role change, allowed
after) and is shaped to be ACCEPTED by an external submission judge.

Everything runs against a hermetic in-memory workspace app — no live lab — driven
through the real bounty-safe PolicyExecutor so the budget accounting is genuine.
Two small oracles at the bottom mirror the AwardForge / BountyForge judge predicates
so "would it be accepted / would it pass" is asserted deterministically.
"""

import re
from urllib.parse import urlparse

import pytest

from core.cortex.execution_policy import ExecutionPolicy, PolicyExecutor
from core.cortex.minimal_amplification import (
    AuthorizationMatrixDelta, prove_minimal_escalation_amplified_bola,
)


# ------------------------------------------------------------------ hermetic target

class FakeWorkspaceApp:
    """A workspace app with the exact flaw both labs model: a foreign-workspace read
    that a role-only check lets through, plus self-serve role assignment. Two personas
    A (accessor) and B (owner) live in different workspaces."""

    def __init__(self, *, vuln_self_role=True, unlock_roles=("billing_manager", "workspace_admin"),
                 object_noun="invoices", sensitivity="billing"):
        self.vuln_self_role = vuln_self_role
        self.unlock_roles = set(unlock_roles)
        self.noun = object_noun
        self.sensitivity = sensitivity
        self.users = {"A": {"role": "member", "workspace_id": "wsA", "email": "a+sentinel@example.com"},
                      "B": {"role": "member", "workspace_id": "wsB", "email": "b+sentinel@example.com"}}
        self.objects = {}
        self._n = 0
        self.calls = []                       # (persona, method, path) — for same-object assertions

    def sender(self, who):
        async def raw(method, url, body=None, **kw):
            path = urlparse(url).path
            self.calls.append((who, method, path))
            return self._handle(who, method, path, body)
        return raw

    def _handle(self, who, method, path, body):
        if method == "GET" and path == "/api/me":
            return 200, dict(self.users[who])
        if method == "GET" and path == "/openapi.json":
            return 200, self._openapi()
        if method == "PATCH" and path == "/api/me/profile":
            role = (body or {}).get("role")
            if self.vuln_self_role and role:
                self.users[who]["role"] = role
                return 200, {"role": role}
            return 403, {"error": "role is server-controlled"}
        m = re.match(rf"^/api/workspaces/([^/]+)/{self.noun}$", path)
        if method == "POST" and m:
            ws = m.group(1)
            if self.users[who]["workspace_id"] != ws:
                return 403, {"error": "not your workspace"}
            self._n += 1
            oid = f"obj_{self._n}"
            self.objects[oid] = {"workspace_id": ws, "owner": who, "marker": (body or {}).get("marker")}
            return 201, {"id": oid, "workspace_id": ws, "marker": self.objects[oid]["marker"]}
        m = re.match(rf"^/api/workspaces/([^/]+)/{self.noun}/([^/]+)$", path)
        if method == "GET" and m:
            ws, oid = m.group(1), m.group(2)
            obj = self.objects.get(oid)
            if not obj or obj["workspace_id"] != ws:
                return 404, {"error": "not found"}
            allowed = self.users[who]["workspace_id"] == ws or self.users[who]["role"] in self.unlock_roles
            if not allowed:
                return 403, {"error": "forbidden"}
            return 200, {"id": oid, "workspace_id": ws, "marker": obj["marker"],
                         "object_class_sensitivity": self.sensitivity}
        return 404, {"error": "no route"}

    def _openapi(self):
        base = f"/api/workspaces/{{workspace_id}}/{self.noun}"
        return {"paths": {base: {"post": {"requestBody": {"content": {"application/json":
                                {"schema": {"$ref": "#/components/schemas/ObjCreate"}}}}}},
                          base + "/{object_id}": {"get": {}}},
                "components": {"schemas": {"ObjCreate": {"properties": {
                    "amount": {"type": "number", "default": 1},
                    "billing_email": {"type": "string", "format": "email"},
                    "marker": {"type": "string"}}}}}}


def _run(app, *, mode="bounty_safe", objects=None, roles=None):
    pol = ExecutionPolicy(mode)
    exA, exB = PolicyExecutor(app.sender("A"), pol), PolicyExecutor(app.sender("B"), pol)
    coro = prove_minimal_escalation_amplified_bola(
        "http://t", owner_send=exB.send, accessor_send=exA.send,
        object_types=objects or ["invoices"], escalation_values=roles or ["billing_manager", "workspace_admin"],
        owner_persona="B", accessor_persona="A")
    return pol, exA, exB, coro


def _byid_reads(app):
    return [c for c in app.calls if c[1] == "GET" and re.match(r"^/api/workspaces/[^/]+/\w+/[^/]+$", c[2])]


# ----------------------------------------------------------------------- the proof

@pytest.mark.asyncio
async def test_amplified_proof_confirmed_on_owned_object():
    app = FakeWorkspaceApp()
    _, _, _, coro = _run(app)
    proof = await coro
    assert proof is not None
    assert proof.pre_status == 403 and proof.post_status == 200
    assert proof.object_type == "invoice"


@pytest.mark.asyncio
async def test_budget_only_the_2xx_cross_read_is_consumed():
    # The 403 pre-check reads nothing; only the amplified 200 counts. Exactly one.
    app = FakeWorkspaceApp()
    pol, _, _, coro = _run(app)
    proof = await coro
    assert proof is not None
    snap = pol.budget.snapshot()
    assert snap["cross_object_reads"] == 1
    assert snap["creates"] == 1 and snap["privilege_mutations"] == 1


@pytest.mark.asyncio
async def test_same_object_is_used_before_and_after_escalation():
    app = FakeWorkspaceApp()
    _, _, _, coro = _run(app)
    proof = await coro
    reads = _byid_reads(app)
    assert len(reads) >= 2                                  # a pre-read and a post-read
    paths = {p for _, _, p in reads}
    assert len(paths) == 1                                  # the SAME object both times
    assert urlparse(proof.object_ref).path in paths


@pytest.mark.asyncio
async def test_finding_emits_authorization_matrix_delta():
    app = FakeWorkspaceApp()
    _, _, _, coro = _run(app)
    md = (await coro).to_finding()["metadata"]
    delta = md["authorization_matrix_delta"]
    assert delta["expected"] == "deny" and delta["actual"] == "allow"
    assert delta["principal_before"] == "member" and delta["principal_after"] == "billing_manager"
    assert delta["resource"] == "invoice" and delta["scope"] == "foreign_workspace"


@pytest.mark.asyncio
async def test_finding_emits_novelty_claims():
    app = FakeWorkspaceApp()
    _, _, _, coro = _run(app)
    md = (await coro).to_finding()["metadata"]
    assert {"matrix_cell_violation", "foreign_workspace_access", "owned_two_persona_proof"} \
        <= set(md["novelty_claims"])


@pytest.mark.asyncio
async def test_finding_emits_object_class_sensitivity():
    app = FakeWorkspaceApp()
    _, _, _, coro = _run(app)
    md = (await coro).to_finding()["metadata"]
    assert md["object_class_sensitivity"] == "billing"
    assert md["real_data_accessed"] is False


@pytest.mark.asyncio
async def test_finding_emits_intended_invariant_and_observed_violation():
    app = FakeWorkspaceApp()
    _, _, _, coro = _run(app)
    md = (await coro).to_finding()["metadata"]
    assert "billing_manager" in md["intended_invariant"]
    assert "member" in md["observed_violation"] and "billing_manager" in md["observed_violation"]
    assert "403" in md["observed_violation"] and "200" in md["observed_violation"]


@pytest.mark.asyncio
async def test_least_spicy_first_distinguishes_stuck_from_amplifying():
    # support_agent STICKS but unlocks nothing; billing_manager is what amplifies.
    # The proof must name the amplifying role, not merely the first role that changed.
    app = FakeWorkspaceApp(unlock_roles=("billing_manager", "workspace_admin"))
    pol, _, _, coro = _run(app, roles=["support_agent", "billing_manager"])
    proof = await coro
    assert proof is not None
    assert proof.delta.principal_after == "billing_manager"
    assert pol.budget.snapshot()["privilege_mutations"] == 2       # tried support_agent, then billing_manager


@pytest.mark.asyncio
async def test_secure_mode_returns_no_finding():
    # A hardened /me/profile that refuses role writes → no escalation → no amplification.
    app = FakeWorkspaceApp(vuln_self_role=False)
    _, _, _, coro = _run(app)
    assert await coro is None


@pytest.mark.asyncio
async def test_no_finding_when_baseline_already_reads_it():
    # If the base role can already read foreign objects, that's plain BOLA, not an
    # amplification — this composer must stay silent (owned_proof's job, not ours).
    app = FakeWorkspaceApp(unlock_roles=("member",))
    _, _, _, coro = _run(app)
    assert await coro is None


# --------------------------------------------------- external-judge oracles (faithful)

def _awardforge_verdict(md, cross_reads):
    """Mirrors awardforge/app/main.py::judge_submission (behavior pass assumed via
    cross_reads<=1). Returns the decision string."""
    required = ["intended_invariant", "observed_violation", "authorization_matrix_delta",
                "novelty_claims", "object_class_sensitivity", "restraint", "ledger_root"]
    if cross_reads > 1:
        return "unsafe_testing"
    if [k for k in required if not md.get(k)]:
        return "needs_more_information"
    novelty = set(md.get("novelty_claims") or [])
    if not ({"matrix_cell_violation", "foreign_workspace_access", "owned_two_persona_proof"} & novelty):
        return "duplicate_prone"
    delta = md.get("authorization_matrix_delta") or {}
    if delta.get("expected") == "deny" and delta.get("actual") == "allow":
        return "accepted"
    return "needs_more_information"


def _bountyforge_passes(md, cross_reads, violations):
    """Mirrors bountyforge/app/main.py::judge_report success: a confirmed finding,
    no violations, exactly one cross-read."""
    return bool(md) and not violations and cross_reads == 1


@pytest.mark.asyncio
async def test_finding_is_awardforge_acceptable():
    app = FakeWorkspaceApp()
    pol, _, _, coro = _run(app)
    proof = await coro
    md = dict(proof.to_finding()["metadata"])
    md["ledger_root"] = "stamped-by-submitter"        # the submitter supplies the target's chain root
    assert _awardforge_verdict(md, pol.budget.snapshot()["cross_object_reads"]) == "accepted"


@pytest.mark.asyncio
async def test_finding_passes_bountyforge():
    app = FakeWorkspaceApp(object_noun="documents", sensitivity="low", unlock_roles=("workspace_admin",))
    pol, exA, exB, coro = _run(app, objects=["documents"], roles=["workspace_admin"])
    proof = await coro
    assert proof is not None
    violations = exA.skipped + exB.skipped
    assert _bountyforge_passes(proof.to_finding()["metadata"],
                               pol.budget.snapshot()["cross_object_reads"], violations)


def test_authorization_matrix_delta_as_dict_is_stable():
    d = AuthorizationMatrixDelta("member", "billing_manager", "invoice", "foreign_workspace")
    assert d.as_dict() == {"principal_before": "member", "principal_after": "billing_manager",
                           "resource": "invoice", "scope": "foreign_workspace",
                           "expected": "deny", "actual": "allow"}
