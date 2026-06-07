"""
core/foundry/planner.py — Phase 7-PF5: the Account Topology Planner.

The front of the Foundry funnel, and the most novel framing in the
whole system. Every other tool asks "how do I create an account?" The
planner asks the question nobody else asks: "what account TOPOLOGY does
the test I'm running actually require?"

The insight: account creation isn't the goal — testing a specific
vulnerability class is. And different vuln classes need fundamentally
different account topologies:

  cross-principal IDOR  → TWO accounts in DIFFERENT tenants/workspaces,
                          each owning a private resource fingerprinted
                          so cross-tenant exposure is unambiguous.
  privilege escalation  → TWO accounts in the SAME tenant with
                          DIFFERENT roles (admin + member), so you can
                          test "member sees/does admin-only things."
  horizontal IDOR       → ONE account is enough (enumerate your OWN
                          resource IDs; ±1 to find a neighbor's).
  multi-tenant leakage  → TWO accounts in TWO orgs with shared-looking
                          but separate data.
  CSRF / auth bypass    → ONE authenticated account + an anonymous
                          context.
  mass assignment       → ONE account (send the privileged field in
                          your own profile update).

The planner takes the vuln classes you intend to test and emits an
AccountPlan: the exact accounts to create, their relationship, and
the setup each needs. That plan then drives the vault (how many
personas) and the replayer (which recipe, how many times). You don't
create accounts and then wonder what to do — you create THE RIGHT
accounts FOR THE TESTS.

This module is pure analysis: deterministic, no I/O, fully testable.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class AccountRole(str, Enum):
    """The role an account plays in a test topology."""
    OWNER = "owner"                       # owns a private resource (the "victim")
    PEER = "peer"                          # different tenant (the "attacker")
    SAME_TENANT_ADMIN = "same_tenant_admin"
    SAME_TENANT_MEMBER = "same_tenant_member"
    SOLE = "sole"                          # the only account a test needs
    ANONYMOUS = "anonymous"                # no account — unauth context


@dataclass
class AccountRequirement:
    """One account the test topology needs, with its setup."""
    role: AccountRole
    label: str                             # "alice" / "bob" / "admin" / …
    tenant_group: str                      # accounts sharing this string are
                                           # in the SAME tenant/workspace/org
    setup_actions: List[str] = field(default_factory=list)
    rationale: str = ""
    # The identifying fingerprint to plant so exposure is unambiguous,
    # e.g. "OWNED_BY_ALICE_7f3a". The replayer/operator creates a
    # resource carrying this exact string.
    fingerprint: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "role": self.role.value,
            "label": self.label,
            "tenant_group": self.tenant_group,
            "setup_actions": list(self.setup_actions),
            "rationale": self.rationale,
            "fingerprint": self.fingerprint,
        }


@dataclass
class AccountPlan:
    """The full account topology a set of vuln-class tests requires.

    `accounts` is the MERGED, de-duplicated set — if two vuln classes
    both need "two accounts in different tenants", we don't create four
    accounts, we reuse the same two. That merge is the planner's real
    value: minimum accounts to cover all the tests, never more (which
    matters for the vault's rate limit + duplicate-account hygiene).
    """
    target_handle: str
    vuln_classes: List[str]
    accounts: List[AccountRequirement] = field(default_factory=list)
    relationships: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    @property
    def account_count(self) -> int:
        # ANONYMOUS "accounts" don't require a signup.
        return sum(1 for a in self.accounts if a.role is not AccountRole.ANONYMOUS)

    @property
    def tenant_count(self) -> int:
        return len({
            a.tenant_group for a in self.accounts
            if a.role is not AccountRole.ANONYMOUS
        })

    def summary(self) -> str:
        return (
            f"{self.target_handle}: testing {', '.join(self.vuln_classes)} "
            f"needs {self.account_count} account(s) across "
            f"{self.tenant_count} tenant(s)."
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_handle": self.target_handle,
            "vuln_classes": list(self.vuln_classes),
            "account_count": self.account_count,
            "tenant_count": self.tenant_count,
            "accounts": [a.to_dict() for a in self.accounts],
            "relationships": list(self.relationships),
            "notes": list(self.notes),
            "summary": self.summary(),
        }


# ─────────────────────── per-vuln-class topologies ───────────────────────
#
# Each function returns the AccountRequirements + relationships a single
# vuln class needs. The planner MERGES across classes. Labels are
# canonical so merging can de-duplicate ("attacker" + "victim" reused
# across IDOR-family classes).


def _fingerprint(label: str) -> str:
    """A short, unique-ish, human-readable fingerprint to plant in the
    account's private resource so cross-tenant exposure is unambiguous
    in a response body."""
    import secrets
    return f"OWNED_BY_{label.upper()}_{secrets.token_hex(3)}"


def _topology_cross_principal_idor() -> Dict[str, Any]:
    return {
        "accounts": [
            AccountRequirement(
                role=AccountRole.OWNER, label="victim", tenant_group="tenant_a",
                setup_actions=[
                    "Create a private resource (base/record/document).",
                    "Put an identifying value in it (the fingerprint below).",
                    "Note the resource's URL/ID — that's the URL the "
                    "attacker will try to read.",
                ],
                fingerprint=_fingerprint("victim"),
                rationale=(
                    "The victim owns a private resource. Cross-principal "
                    "IDOR is confirmed when the attacker (a DIFFERENT "
                    "tenant) can read this exact resource."
                ),
            ),
            AccountRequirement(
                role=AccountRole.PEER, label="attacker", tenant_group="tenant_b",
                setup_actions=[
                    "No special setup — this account is the 'attacker' "
                    "identity used to request the victim's resource URL.",
                ],
                fingerprint=_fingerprint("attacker"),
                rationale=(
                    "A separate tenant. If requests authenticated as this "
                    "account return the victim's fingerprinted resource, "
                    "that's the IDOR."
                ),
            ),
        ],
        "relationships": [
            "victim and attacker MUST be in DIFFERENT tenants/workspaces "
            "(tenant_a vs tenant_b) — same-tenant access may be legitimate "
            "sharing, not a vulnerability.",
        ],
    }


def _topology_privilege_escalation() -> Dict[str, Any]:
    return {
        "accounts": [
            AccountRequirement(
                role=AccountRole.SAME_TENANT_ADMIN, label="admin",
                tenant_group="tenant_shared",
                setup_actions=[
                    "Create the tenant/workspace and an admin-only "
                    "resource or setting (e.g. a billing page, a member-"
                    "management action).",
                ],
                rationale=(
                    "The admin establishes the privileged surface. The "
                    "member account will try to reach it."
                ),
            ),
            AccountRequirement(
                role=AccountRole.SAME_TENANT_MEMBER, label="member",
                tenant_group="tenant_shared",
                setup_actions=[
                    "Invite this account into the admin's tenant as a "
                    "low-privilege member.",
                ],
                rationale=(
                    "A low-privilege member in the SAME tenant. Privilege "
                    "escalation is confirmed when the member can perform "
                    "an admin-only action."
                ),
            ),
        ],
        "relationships": [
            "admin and member MUST be in the SAME tenant (tenant_shared) "
            "with DIFFERENT roles — the test is 'low role reaches high-"
            "role capability within one tenant'.",
        ],
    }


def _topology_horizontal_idor() -> Dict[str, Any]:
    return {
        "accounts": [
            AccountRequirement(
                role=AccountRole.SOLE, label="solo", tenant_group="tenant_solo",
                setup_actions=[
                    "Create two resources you own so you have two known "
                    "IDs; enumerating from one to the other (and beyond) "
                    "tests horizontal IDOR within your own account.",
                ],
                rationale=(
                    "Horizontal IDOR (enumerating your own resource IDs to "
                    "reach a neighbor's) needs only ONE account."
                ),
            ),
        ],
        "relationships": [
            "single account — no tenant relationship needed.",
        ],
    }


def _topology_mass_assignment() -> Dict[str, Any]:
    return {
        "accounts": [
            AccountRequirement(
                role=AccountRole.SOLE, label="solo", tenant_group="tenant_solo",
                setup_actions=[
                    "No special setup — send a privileged field (is_admin, "
                    "role) in your OWN profile/settings update request.",
                ],
                rationale=(
                    "Mass assignment is tested against your own account; "
                    "one account suffices."
                ),
            ),
        ],
        "relationships": ["single account."],
    }


def _topology_auth_context() -> Dict[str, Any]:
    """CSRF / open-redirect / auth-bypass: one authed account + an
    anonymous context."""
    return {
        "accounts": [
            AccountRequirement(
                role=AccountRole.SOLE, label="solo", tenant_group="tenant_solo",
                setup_actions=["A standard authenticated account."],
                rationale="The authenticated victim context for CSRF / auth tests.",
            ),
            AccountRequirement(
                role=AccountRole.ANONYMOUS, label="anonymous",
                tenant_group="(none)",
                setup_actions=["No signup — the unauthenticated attacker context."],
                rationale="Anonymous context to contrast against the authed one.",
            ),
        ],
        "relationships": ["one authenticated account + an anonymous context."],
    }


# Map each known vuln-class id (from PT1's detection profile + common
# spellings) to its topology builder.
_TOPOLOGY_FOR_CLASS = {
    "idor_cross_principal": _topology_cross_principal_idor,
    "cross_principal_idor": _topology_cross_principal_idor,
    "cross-principal-idor": _topology_cross_principal_idor,
    "idor_horizontal": _topology_horizontal_idor,
    "horizontal_idor": _topology_horizontal_idor,
    "privilege_escalation": _topology_privilege_escalation,
    "privesc": _topology_privilege_escalation,
    "mass_assignment": _topology_mass_assignment,
    "oauth_state_strip": _topology_auth_context,
    "csrf": _topology_auth_context,
    "open_redirect": _topology_auth_context,
}


# ─────────────────────────── the planner ───────────────────────────


def plan_accounts(
    target_handle: str,
    vuln_classes: List[str],
) -> AccountPlan:
    """Compute the minimum account topology to test the given vuln
    classes against `target_handle`.

    The planner MERGES topologies across classes so we create the
    fewest accounts that cover every test. Two classes that both need
    "two accounts in different tenants" share the same two accounts.

    Unknown vuln classes are noted (not silently dropped) so the
    operator knows the planner didn't have a topology for them.
    """
    plan = AccountPlan(
        target_handle=target_handle,
        vuln_classes=list(vuln_classes),
    )

    # Accumulate requirements keyed by (role, tenant_group, label) so
    # identical accounts across classes merge into one.
    merged: Dict[tuple, AccountRequirement] = {}
    relationships: List[str] = []

    for vc in vuln_classes:
        builder = _TOPOLOGY_FOR_CLASS.get(vc.lower().replace(" ", "_"))
        if builder is None:
            plan.notes.append(
                f"no account topology known for vuln class {vc!r} — "
                f"the planner can't tell you what accounts it needs; "
                f"treat as single-account by default."
            )
            continue
        topology = builder()
        for req in topology["accounts"]:
            key = (req.role, req.tenant_group, req.label)
            if key not in merged:
                merged[key] = req
            else:
                # Merge setup actions (union, order-preserving).
                existing = merged[key]
                for action in req.setup_actions:
                    if action not in existing.setup_actions:
                        existing.setup_actions.append(action)
        for rel in topology["relationships"]:
            if rel not in relationships:
                relationships.append(rel)

    plan.accounts = list(merged.values())
    plan.relationships = relationships

    # If after all that we have zero accounts (all classes unknown),
    # default to a single sole account — you usually need at least one.
    if not plan.accounts:
        plan.accounts.append(AccountRequirement(
            role=AccountRole.SOLE, label="solo", tenant_group="tenant_solo",
            setup_actions=["A standard authenticated account."],
            rationale="Default — no specific topology matched the requested classes.",
        ))

    return plan
