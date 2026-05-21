"""
Tests for the Phase 2H bridge between PolicyEnforcement and ExecutionPolicy.

The bridge is two methods:
  - ``PolicyEnforcement.apply_to_execution_policy(policy)`` — translator
    that mutates an ExecutionPolicy in-place to reflect enforcement.

Contracts under test:
  1. disabled_tools merges into policy.banned_tools (union, no overwrite)
  2. rate_limit_rps takes the more-restrictive value if policy already
     has max_rps_per_host set
  3. Empty enforcement is a no-op on the policy
  4. scope_strict / max_capability_tier / required_attestations are NOT
     applied via this method (they're consumed elsewhere)
  5. Integers are coerced safely (rps as float → int conversion)
"""
from __future__ import annotations

import pytest

from core.base.execution_policy import ExecutionPolicy
from core.intel.policy_enforcer import PolicyEnforcement


# ─────────────────────────── disabled_tools ────────────────────────

class TestDisabledToolsBridge:
    def test_empty_disabled_set_is_noop(self):
        policy = ExecutionPolicy()
        enforcement = PolicyEnforcement()
        enforcement.apply_to_execution_policy(policy)
        # No banned_tools assigned — stays None as default.
        assert policy.banned_tools is None

    def test_disabled_tools_become_banned_tools(self):
        policy = ExecutionPolicy()
        enforcement = PolicyEnforcement(disabled_tools={"nuclei_mutating", "masscan"})
        enforcement.apply_to_execution_policy(policy)
        assert policy.banned_tools == {"nuclei_mutating", "masscan"}

    def test_disabled_tools_union_with_existing_banned(self):
        # If the operator already supplied a banned list (e.g. via
        # config), the enforcement adds to it rather than replacing.
        policy = ExecutionPolicy(banned_tools={"hydra"})
        enforcement = PolicyEnforcement(disabled_tools={"nuclei_mutating"})
        enforcement.apply_to_execution_policy(policy)
        assert policy.banned_tools == {"hydra", "nuclei_mutating"}

    def test_overlapping_sets_idempotent(self):
        # Restriction adds a tool already banned — no duplicate noise.
        policy = ExecutionPolicy(banned_tools={"nuclei_mutating"})
        enforcement = PolicyEnforcement(disabled_tools={"nuclei_mutating", "masscan"})
        enforcement.apply_to_execution_policy(policy)
        assert policy.banned_tools == {"nuclei_mutating", "masscan"}


# ─────────────────────────── rate_limit_rps ────────────────────────

class TestRateLimitBridge:
    def test_rate_limit_applied_to_max_rps_per_host(self):
        policy = ExecutionPolicy()  # default max_rps_per_host = 50
        enforcement = PolicyEnforcement(rate_limit_rps=5.0)
        enforcement.apply_to_execution_policy(policy)
        # 5.0 rps < 50, so the enforcement value wins.
        assert policy.max_rps_per_host == 5

    def test_higher_rate_limit_does_not_loosen_policy(self):
        # Existing policy is more restrictive than enforcement — enforcement
        # MUST NOT loosen it. Restrictions only tighten.
        policy = ExecutionPolicy(max_rps_per_host=2)
        enforcement = PolicyEnforcement(rate_limit_rps=10.0)
        enforcement.apply_to_execution_policy(policy)
        # Still 2 — enforcement's 10 was higher (more permissive) so was ignored.
        assert policy.max_rps_per_host == 2

    def test_no_rate_limit_in_enforcement_is_noop(self):
        policy = ExecutionPolicy(max_rps_per_host=42)
        enforcement = PolicyEnforcement()  # rate_limit_rps=None
        enforcement.apply_to_execution_policy(policy)
        assert policy.max_rps_per_host == 42

    def test_zero_rps_is_rejected_silently(self):
        # An rps of 0 from extraction is nonsense — defensive default.
        # It should not zero out the policy.
        policy = ExecutionPolicy(max_rps_per_host=50)
        enforcement = PolicyEnforcement(rate_limit_rps=0.0)
        enforcement.apply_to_execution_policy(policy)
        assert policy.max_rps_per_host == 50

    def test_fractional_rps_rounds_up_to_at_least_1(self):
        # 0.5 rps as int = 0, which is meaningless. The bridge enforces
        # max(1, int(rps)) so an impossibly tight extraction still produces
        # a valid (if very restrictive) integer.
        policy = ExecutionPolicy(max_rps_per_host=50)
        enforcement = PolicyEnforcement(rate_limit_rps=0.5)
        enforcement.apply_to_execution_policy(policy)
        assert policy.max_rps_per_host == 1


# ─────────────────────────── Fields NOT applied here ───────────────

class TestFieldsNotAppliedViaBridge:
    """These fields exist on PolicyEnforcement but are NOT mutated onto
    ExecutionPolicy by this bridge — they have consumers in different
    layers (ScopeContext, scan-gate, CapabilityGate, CLI prompt).

    The tests lock that boundary so a future refactor doesn't
    accidentally start mutating fields ExecutionPolicy doesn't have."""

    def test_scope_strict_does_not_touch_policy(self):
        policy = ExecutionPolicy()
        enforcement = PolicyEnforcement(scope_strict=True)
        enforcement.apply_to_execution_policy(policy)
        # Policy has no scope_strict field — bridge MUST NOT add one.
        assert not hasattr(policy, "scope_strict")

    def test_max_capability_tier_does_not_touch_policy(self):
        policy = ExecutionPolicy()
        enforcement = PolicyEnforcement(max_capability_tier="T2a_SAFE_VERIFY")
        enforcement.apply_to_execution_policy(policy)
        # Policy doesn't carry tier info — that's CapabilityGate's job.
        assert not hasattr(policy, "max_capability_tier")

    def test_scan_blocked_does_not_touch_policy(self):
        # scan_blocked is consumed by the scan-request gate BEFORE the
        # ExecutionPolicy is even built. If it's True, the bridge should
        # not even be called in practice; if it is called, it must not
        # silently apply some other field.
        policy = ExecutionPolicy()
        enforcement = PolicyEnforcement(scan_blocked=True, scan_blocked_reason="x")
        enforcement.apply_to_execution_policy(policy)
        # No tools banned, no rate limit set — just a no-op.
        assert policy.banned_tools is None


# ─────────────────────────── Combined / realistic case ─────────────

class TestRealisticEnforcement:
    def test_h1_security_program_style_enforcement(self):
        """Build an enforcement matching what Run #16 produced against
        HackerOne's `security` program: no DoS (disables nuclei
        variants + masscan), no data destruction (caps tier), rate limit."""
        policy = ExecutionPolicy()
        enforcement = PolicyEnforcement(
            disabled_tools={"nuclei", "nuclei_mutating", "masscan"},
            max_capability_tier="T2a_SAFE_VERIFY",
            rate_limit_rps=5.0,
            scope_strict=True,
        )
        enforcement.apply_to_execution_policy(policy)

        # Banned tools: all three from enforcement.
        assert policy.banned_tools == {"nuclei", "nuclei_mutating", "masscan"}
        # Rate limit: 5 rps coerced to int.
        assert policy.max_rps_per_host == 5
        # Tier cap NOT applied via this bridge (consumed by CapabilityGate).
        # scope_strict NOT applied via this bridge (consumed by ScopeContext setup).
        assert not hasattr(policy, "max_capability_tier")
        assert not hasattr(policy, "scope_strict")
