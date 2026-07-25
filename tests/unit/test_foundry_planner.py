"""
Phase 7-PF5 tests for core/foundry/planner.py.

The planner maps "what vuln class am I testing" → "what account
topology do I need". Tests pin the topology for each vuln class AND
the merge behavior that keeps the account count minimal across
multiple classes.
"""
from __future__ import annotations

import json

import pytest

from core.foundry.planner import (
    AccountPlan,
    AccountRole,
    plan_accounts,
)


# ───────────────────────── single-class topologies ─────────────────────────


class TestSingleClassTopology:
    def test_cross_principal_idor_needs_two_different_tenants(self):
        plan = plan_accounts("airtable", ["idor_cross_principal"])
        assert plan.account_count == 2
        assert plan.tenant_count == 2  # DIFFERENT tenants
        roles = {a.role for a in plan.accounts}
        assert AccountRole.OWNER in roles
        assert AccountRole.PEER in roles
        # The two accounts are in different tenant groups.
        tenants = {a.tenant_group for a in plan.accounts}
        assert len(tenants) == 2

    def test_cross_principal_idor_plants_fingerprints(self):
        plan = plan_accounts("airtable", ["idor_cross_principal"])
        owner = next(a for a in plan.accounts if a.role is AccountRole.OWNER)
        assert owner.fingerprint is not None
        assert owner.fingerprint.startswith("OWNED_BY_VICTIM_")

    def test_privilege_escalation_needs_same_tenant_two_roles(self):
        plan = plan_accounts("airtable", ["privilege_escalation"])
        assert plan.account_count == 2
        assert plan.tenant_count == 1  # SAME tenant
        roles = {a.role for a in plan.accounts}
        assert AccountRole.SAME_TENANT_ADMIN in roles
        assert AccountRole.SAME_TENANT_MEMBER in roles

    def test_horizontal_idor_needs_one_account(self):
        plan = plan_accounts("airtable", ["idor_horizontal"])
        assert plan.account_count == 1
        assert plan.accounts[0].role is AccountRole.SOLE

    def test_mass_assignment_needs_one_account(self):
        plan = plan_accounts("airtable", ["mass_assignment"])
        assert plan.account_count == 1

    def test_csrf_needs_authed_plus_anonymous(self):
        plan = plan_accounts("airtable", ["csrf"])
        roles = {a.role for a in plan.accounts}
        assert AccountRole.SOLE in roles
        assert AccountRole.ANONYMOUS in roles
        # The anonymous context doesn't count as an account to create.
        assert plan.account_count == 1  # only the SOLE one needs signup


# ───────────────────────── merge behavior ─────────────────────────


class TestMerge:
    def test_two_classes_needing_same_topology_dont_double_accounts(self):
        # cross-principal IDOR and (hypothetically) another 2-different-
        # tenant class would share the same two accounts. Use the same
        # class twice to exercise the merge path deterministically.
        plan = plan_accounts(
            "airtable",
            ["idor_cross_principal", "idor_cross_principal"],
        )
        # Still only 2 accounts, not 4.
        assert plan.account_count == 2

    def test_mixed_classes_merge_minimally(self):
        # cross-principal IDOR (2 diff tenants) + horizontal IDOR (1 sole).
        # The sole account is a different topology, so total is 3
        # accounts across 3 tenant groups.
        plan = plan_accounts(
            "airtable",
            ["idor_cross_principal", "idor_horizontal"],
        )
        # owner(tenant_a) + attacker(tenant_b) + solo(tenant_solo) = 3
        assert plan.account_count == 3
        assert plan.tenant_count == 3

    def test_relationships_deduplicated(self):
        plan = plan_accounts(
            "airtable",
            ["idor_cross_principal", "idor_cross_principal"],
        )
        # The "different tenants" relationship appears once, not twice.
        assert len(plan.relationships) == len(set(plan.relationships))


# ───────────────────────── unknown classes ─────────────────────────


class TestUnknownClasses:
    def test_unknown_class_noted_not_dropped(self):
        plan = plan_accounts("airtable", ["some_exotic_bug"])
        # A note explains the planner had no topology.
        assert any("some_exotic_bug" in n for n in plan.notes)
        # Defaults to a single account so the operator isn't stuck.
        assert plan.account_count == 1

    def test_mix_known_and_unknown(self):
        plan = plan_accounts(
            "airtable",
            ["idor_cross_principal", "totally_made_up"],
        )
        # The known class drives the topology (2 accounts).
        assert plan.account_count == 2
        # The unknown is noted.
        assert any("totally_made_up" in n for n in plan.notes)


# ───────────────────────── case + spelling tolerance ─────────────────────────


class TestSpellingTolerance:
    def test_handles_spelling_variants(self):
        for spelling in (
            "idor_cross_principal",
            "cross_principal_idor",
            "Cross-Principal-IDOR",
            "CROSS PRINCIPAL IDOR",
        ):
            plan = plan_accounts("airtable", [spelling])
            assert plan.account_count == 2, f"failed for spelling {spelling!r}"


# ───────────────────────── output shape ─────────────────────────


class TestOutputShape:
    def test_summary_reads_well(self):
        plan = plan_accounts("airtable", ["idor_cross_principal"])
        s = plan.summary()
        assert "airtable" in s
        assert "2 account" in s
        assert "2 tenant" in s

    def test_to_dict_is_json_safe(self):
        plan = plan_accounts("airtable", ["idor_cross_principal", "privilege_escalation"])
        d = plan.to_dict()
        json.dumps(d)  # must not raise
        assert d["target_handle"] == "airtable"
        assert "accounts" in d
        assert "relationships" in d
        assert d["account_count"] >= 1
