"""
Tests for the policy_enforcer (Phase 2E).

Contracts under test:

  1. Each enforcement strategy translates to the right
     PolicyEnforcement field.
  2. Tool-category lookup uses the static mapping (so a tool rename
     only touches policy_enforcer.py).
  3. Multiple restrictions of the same strategy combine sensibly:
     - tier caps take the LOWEST (most restrictive)
     - rate limits take the LOWEST
     - disabled-tool sets union together
  4. Soft restrictions still surface warnings.
  5. Unknown / malformed input fails open with a warning, not a crash.
  6. enforce_from_file handles missing / unparseable files gracefully.
  7. Round-trip from policy_gate output: emit restrictions.json with
     known restrictions → enforce → expected PolicyEnforcement.
"""
from __future__ import annotations

import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import pytest

from core.intel.compilers.policy_gate import (
    SCHEMA_VERSION,
    compile_restrictions_json,
)
from core.intel.policy_enforcer import (
    PolicyEnforcement,
    enforce,
    enforce_from_file,
)
from core.intel.program_scope import (
    Platform,
    ProgramScope,
    Restriction,
    RestrictionKind,
)


# ─────────────────────────── Helpers ───────────────────────────────

def _restriction(kind: str, strategy: str, severity: str = "hard",
                 args: dict = None, description: str = "") -> dict:
    out = {
        "kind": kind,
        "severity": severity,
        "description": description or kind,
        "enforcement": strategy,
    }
    if args is not None:
        out["enforcement_args"] = args
    return out


def _wrap(restrictions: list) -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "program": {"handle": "test", "platform": "hackerone", "name": "Test"},
        "rate_limit_rps": None,
        "restrictions": restrictions,
    }


# ─────────────────────────── disable_tool_categories ───────────────

class TestDisableToolCategories:
    def test_dos_category_disables_nuclei_variants(self):
        data = _wrap([_restriction(
            "no_dos", "disable_tool_categories",
            args={"categories": ["dos"]},
        )])
        result = enforce(data)
        assert "nuclei_mutating" in result.disabled_tools
        assert "nuclei" in result.disabled_tools
        # nuclei_safe should NOT be disabled (it's info-only).
        assert "nuclei_safe" not in result.disabled_tools

    def test_bruteforce_category_disables_gobuster_feroxbuster_nikto(self):
        data = _wrap([_restriction(
            "no_bruteforce", "disable_tool_categories",
            args={"categories": ["bruteforce"]},
        )])
        result = enforce(data)
        assert {"gobuster", "feroxbuster", "nikto"}.issubset(result.disabled_tools)

    def test_multiple_categories_union(self):
        # NO_DOS + NO_BRUTEFORCE in one restriction → all categories disabled.
        data = _wrap([_restriction(
            "no_dos", "disable_tool_categories",
            args={"categories": ["dos", "bruteforce"]},
        )])
        result = enforce(data)
        assert "nuclei_mutating" in result.disabled_tools
        assert "gobuster" in result.disabled_tools

    def test_unknown_category_surfaces_warning_not_crashes(self):
        data = _wrap([_restriction(
            "no_foo", "disable_tool_categories",
            args={"categories": ["some-future-category"]},
        )])
        result = enforce(data)
        # No tools disabled (we don't know what to disable).
        assert result.disabled_tools == set()
        # But a warning fired so the operator sees the gap.
        assert any("some-future-category" in w for w in result.warnings)

    def test_soft_restriction_still_disables_but_warns(self):
        data = _wrap([_restriction(
            "no_dos", "disable_tool_categories", severity="soft",
            args={"categories": ["dos"]},
        )])
        result = enforce(data)
        # Tools still disabled — the operator opted into the program
        # knowing the restriction was there.
        assert "nuclei_mutating" in result.disabled_tools
        # And a warning to make the soft enforcement visible.
        assert any("soft restriction" in w.lower() for w in result.warnings)

    def test_empty_category_list_is_safe(self):
        data = _wrap([_restriction(
            "no_x", "disable_tool_categories",
            args={"categories": []},
        )])
        result = enforce(data)
        assert result.disabled_tools == set()

    def test_missing_categories_arg_warns(self):
        data = _wrap([_restriction(
            "no_x", "disable_tool_categories",
            args={},  # missing 'categories'
        )])
        result = enforce(data)
        assert result.disabled_tools == set()
        # Doesn't crash either.


# ─────────────────────────── cap_capability_tier ───────────────────

class TestCapCapabilityTier:
    def test_t2a_safe_verify_caps_tier(self):
        data = _wrap([_restriction(
            "no_data_destruction", "cap_capability_tier",
            args={"max_tier": "T2a_SAFE_VERIFY"},
        )])
        result = enforce(data)
        assert result.max_capability_tier == "T2a_SAFE_VERIFY"

    def test_multiple_caps_take_lowest_most_restrictive(self):
        data = _wrap([
            _restriction("a", "cap_capability_tier",
                         args={"max_tier": "T3_EXPLOIT"}),
            _restriction("b", "cap_capability_tier",
                         args={"max_tier": "T2a_SAFE_VERIFY"}),
            _restriction("c", "cap_capability_tier",
                         args={"max_tier": "T4_DESTRUCTIVE"}),
        ])
        result = enforce(data)
        # The lowest = most restrictive = T2a_SAFE_VERIFY wins.
        assert result.max_capability_tier == "T2a_SAFE_VERIFY"

    def test_invalid_tier_name_warns_not_crashes(self):
        data = _wrap([_restriction(
            "no_x", "cap_capability_tier",
            args={"max_tier": "T9000_HYPERPOWER"},
        )])
        result = enforce(data)
        assert result.max_capability_tier is None
        assert any("invalid max_tier" in w.lower() or "t9000" in w.lower() for w in result.warnings)

    def test_missing_max_tier_arg_warns(self):
        data = _wrap([_restriction(
            "no_x", "cap_capability_tier",
            args={},
        )])
        result = enforce(data)
        assert result.max_capability_tier is None


# ─────────────────────────── set_rate_limit ────────────────────────

class TestSetRateLimit:
    def test_rate_limit_set_from_args(self):
        data = _wrap([_restriction(
            "rate_limited", "set_rate_limit",
            args={"rps": 5.0},
        )])
        result = enforce(data)
        assert result.rate_limit_rps == 5.0

    def test_multiple_rate_limits_take_lowest(self):
        data = _wrap([
            _restriction("a", "set_rate_limit", args={"rps": 10.0}),
            _restriction("b", "set_rate_limit", args={"rps": 3.0}),
            _restriction("c", "set_rate_limit", args={"rps": 5.0}),
        ])
        result = enforce(data)
        assert result.rate_limit_rps == 3.0

    def test_zero_rps_warns(self):
        data = _wrap([_restriction(
            "x", "set_rate_limit", args={"rps": 0},
        )])
        result = enforce(data)
        assert result.rate_limit_rps is None
        assert any("rate-limit" in w.lower() for w in result.warnings)

    def test_negative_rps_warns(self):
        data = _wrap([_restriction(
            "x", "set_rate_limit", args={"rps": -5},
        )])
        result = enforce(data)
        assert result.rate_limit_rps is None


# ─────────────────────────── block_scan ────────────────────────────

class TestBlockScan:
    def test_hard_severity_blocks_scan(self):
        data = _wrap([_restriction(
            "no_automated_scan", "block_scan", severity="hard",
            description="Automated scanning is prohibited.",
        )])
        result = enforce(data)
        assert result.scan_blocked is True
        assert result.scan_blocked_reason == "Automated scanning is prohibited."

    def test_soft_severity_warns_only(self):
        data = _wrap([_restriction(
            "no_automated_scan", "block_scan", severity="soft",
            description="Please avoid automated scanning.",
        )])
        result = enforce(data)
        assert result.scan_blocked is False
        assert any("soft restriction" in w.lower() for w in result.warnings)


# ─────────────────────────── enforce_strict_scope ──────────────────

class TestEnforceStrictScope:
    def test_sets_scope_strict_flag(self):
        data = _wrap([_restriction(
            "no_third_party", "enforce_strict_scope",
        )])
        result = enforce(data)
        assert result.scope_strict is True

    def test_soft_restriction_still_enables_scope_strict(self):
        # Defensive default: scope strictness is cheap to enable and
        # prevents accidental out-of-scope hits.
        data = _wrap([_restriction(
            "no_third_party", "enforce_strict_scope", severity="soft",
        )])
        result = enforce(data)
        assert result.scope_strict is True
        assert any("scope_strict" in w.lower() for w in result.warnings)


# ─────────────────────────── require_attestation ───────────────────

class TestRequireAttestation:
    def test_queues_attestation_prompt(self):
        data = _wrap([_restriction(
            "requires_prior_approval", "require_attestation",
            description="Contact the program manager before scanning.",
        )])
        result = enforce(data)
        assert len(result.required_attestations) == 1
        assert "Contact the program manager" in result.required_attestations[0]

    def test_multiple_attestations_all_queued(self):
        data = _wrap([
            _restriction("a", "require_attestation", description="A"),
            _restriction("b", "require_attestation", description="B"),
        ])
        result = enforce(data)
        assert len(result.required_attestations) == 2


# ─────────────────────────── warn strategy ─────────────────────────

class TestWarnStrategy:
    def test_warn_strategy_emits_warning(self):
        data = _wrap([_restriction(
            "business_hours_only", "warn",
            description="Test only during business hours.",
        )])
        result = enforce(data)
        assert any("business_hours_only" in w for w in result.warnings)
        # No other enforcement applied.
        assert result.scan_blocked is False
        assert result.disabled_tools == set()


# ─────────────────────────── Unknown strategies ────────────────────

class TestUnknownStrategy:
    def test_unknown_strategy_surfaces_warning(self):
        data = _wrap([_restriction(
            "weird", "future_strategy_we_dont_know",
        )])
        result = enforce(data)
        assert any("future_strategy_we_dont_know" in w for w in result.warnings)
        assert any("NOT enforced" in w for w in result.warnings)


# ─────────────────────────── Schema mismatch ───────────────────────

class TestSchemaMismatch:
    def test_unknown_schema_version_warns_but_continues(self):
        data = {
            "schema_version": "sentinelforge-restrictions-v999",
            "restrictions": [],
        }
        result = enforce(data)
        assert any("schema_version" in w.lower() for w in result.warnings)

    def test_missing_restrictions_list_warns(self):
        data = {"schema_version": SCHEMA_VERSION}
        result = enforce(data)
        # No restrictions to apply — result is empty.
        assert result.is_empty() is True

    def test_restrictions_not_a_list_warns(self):
        data = {
            "schema_version": SCHEMA_VERSION,
            "restrictions": "this should be a list",
        }
        result = enforce(data)
        assert any("not a list" in w for w in result.warnings)


# ─────────────────────────── enforce_from_file ─────────────────────

class TestEnforceFromFile:
    def test_loads_and_enforces_real_file(self):
        data = _wrap([_restriction(
            "no_dos", "disable_tool_categories",
            args={"categories": ["dos"]},
        )])
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            path = f.name
        try:
            result = enforce_from_file(path)
            assert "nuclei_mutating" in result.disabled_tools
        finally:
            Path(path).unlink(missing_ok=True)

    def test_missing_file_returns_empty_with_warning(self):
        result = enforce_from_file("/tmp/nonexistent-restrictions-asdf.json")
        assert result.disabled_tools == set()
        assert any("not found" in w for w in result.warnings)

    def test_invalid_json_returns_empty_with_warning(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            f.write("{ not valid json")
            path = f.name
        try:
            result = enforce_from_file(path)
            assert any("could not parse" in w.lower() for w in result.warnings)
        finally:
            Path(path).unlink(missing_ok=True)


# ─────────────────────────── PolicyEnforcement.is_empty ────────────

class TestIsEmpty:
    def test_default_is_empty(self):
        assert PolicyEnforcement().is_empty() is True

    def test_any_field_makes_it_non_empty(self):
        p = PolicyEnforcement(disabled_tools={"x"})
        assert p.is_empty() is False
        p = PolicyEnforcement(max_capability_tier="T1_PROBE")
        assert p.is_empty() is False
        p = PolicyEnforcement(rate_limit_rps=5.0)
        assert p.is_empty() is False
        p = PolicyEnforcement(scan_blocked=True)
        assert p.is_empty() is False
        p = PolicyEnforcement(scope_strict=True)
        assert p.is_empty() is False
        p = PolicyEnforcement(required_attestations=["x"])
        assert p.is_empty() is False
        p = PolicyEnforcement(warnings=["x"])
        assert p.is_empty() is False


# ─────────────────────────── End-to-end via policy_gate ────────────

class TestRoundTripFromPolicyGate:
    """The biggest contract: emit restrictions.json with policy_gate,
    pass it through enforce(), get the expected enforcement config."""

    def test_no_dos_restriction_round_trips(self):
        scope = ProgramScope(
            handle="t", platform=Platform.HACKERONE, name="x",
            source_url="https://x", fetched_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            restrictions=[Restriction(
                kind=RestrictionKind.NO_DOS, severity="hard",
                description="No DoS.",
            )],
        )
        emitted = compile_restrictions_json(scope)
        loaded = json.loads(emitted)
        result = enforce(loaded)
        assert "nuclei_mutating" in result.disabled_tools
        assert "nuclei" in result.disabled_tools

    def test_full_restriction_set_round_trips(self):
        scope = ProgramScope(
            handle="t", platform=Platform.HACKERONE, name="x",
            source_url="https://x", fetched_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            restrictions=[
                Restriction(kind=RestrictionKind.NO_DOS, severity="hard", description="x"),
                Restriction(kind=RestrictionKind.NO_BRUTEFORCE, severity="hard", description="x"),
                Restriction(kind=RestrictionKind.NO_DATA_DESTRUCTION, severity="hard", description="x"),
                Restriction(kind=RestrictionKind.NO_THIRD_PARTY, severity="hard", description="x"),
                Restriction(kind=RestrictionKind.REQUIRES_PRIOR_APPROVAL, severity="hard", description="Contact PM."),
            ],
            rate_limit_rps=5.0,
        )
        emitted = compile_restrictions_json(scope)
        result = enforce(json.loads(emitted))

        # NO_DOS + NO_BRUTEFORCE → disabled tools.
        assert {"nuclei_mutating", "gobuster", "feroxbuster", "nikto"}.issubset(result.disabled_tools)
        # NO_DATA_DESTRUCTION → cap tier at T2a_SAFE_VERIFY.
        assert result.max_capability_tier == "T2a_SAFE_VERIFY"
        # NO_THIRD_PARTY → scope_strict.
        assert result.scope_strict is True
        # Synthesized RATE_LIMITED from rate_limit_rps=5.0.
        assert result.rate_limit_rps == 5.0
        # REQUIRES_PRIOR_APPROVAL → attestation queued.
        assert len(result.required_attestations) == 1
        assert "Contact PM" in result.required_attestations[0]


# ─────────────────────────── applies_to scoping (Calibration Run #17) ──

class TestAppliesToScoping:
    """The fix for the H1 misclassification: a block_scan rule scoped to a
    specific testing category (not 'all') must NOT halt the whole scan."""

    def test_global_no_automated_scan_still_blocks(self):
        # applies_to=["all"] → genuine program-wide ban → scan blocked.
        data = _wrap([{
            "kind": "no_automated_scan", "severity": "hard",
            "description": "No automated scanning anywhere on the program.",
            "enforcement": "block_scan",
            "applies_to": ["all"],
        }])
        result = enforce(data)
        assert result.scan_blocked is True

    def test_dos_scoped_no_automated_scan_does_not_block(self):
        # The exact H1 case: "No automated tools" inside a DoS section.
        # applies_to=["dos"] → downgrade to disabling DoS tools, scan proceeds.
        data = _wrap([{
            "kind": "no_automated_scan", "severity": "hard",
            "description": "No automated tools or high-volume attacks (DoS testing).",
            "enforcement": "block_scan",
            "applies_to": ["dos"],
        }])
        result = enforce(data)
        assert result.scan_blocked is False
        # DoS tools disabled instead.
        assert "nuclei_mutating" in result.disabled_tools
        # And a warning explains the downgrade.
        assert any("downgraded" in w.lower() for w in result.warnings)

    def test_missing_applies_to_defaults_to_all_and_blocks(self):
        # Backward-compat: a pre-1.1 restriction with no applies_to field
        # is treated as ["all"] → still blocks (conservative default).
        data = _wrap([{
            "kind": "no_automated_scan", "severity": "hard",
            "description": "No automated scanning.",
            "enforcement": "block_scan",
            # no applies_to
        }])
        result = enforce(data)
        assert result.scan_blocked is True

    def test_bruteforce_scoped_block_downgrades_to_bruteforce_tools(self):
        data = _wrap([{
            "kind": "no_automated_scan", "severity": "hard",
            "description": "No automated brute forcing.",
            "enforcement": "block_scan",
            "applies_to": ["bruteforce"],
        }])
        result = enforce(data)
        assert result.scan_blocked is False
        assert {"gobuster", "feroxbuster", "nikto"}.issubset(result.disabled_tools)

    def test_unmappable_scope_warns_but_does_not_block(self):
        # A scope we can't map to tool categories (e.g. "automated") should
        # not block and should surface a clear "not enforced" warning.
        data = _wrap([{
            "kind": "no_automated_scan", "severity": "hard",
            "description": "No automated traffic (manual testing only).",
            "enforcement": "block_scan",
            "applies_to": ["automated"],
        }])
        result = enforce(data)
        assert result.scan_blocked is False
        assert any("not enforced" in w.lower() or "could not map" in w.lower()
                   for w in result.warnings)

    def test_multi_scope_with_all_present_blocks(self):
        # If "all" is among multiple scopes, the program-wide ban wins.
        data = _wrap([{
            "kind": "no_automated_scan", "severity": "hard",
            "description": "x",
            "enforcement": "block_scan",
            "applies_to": ["dos", "all"],
        }])
        result = enforce(data)
        assert result.scan_blocked is True

    def test_soft_scoped_block_just_warns(self):
        data = _wrap([{
            "kind": "no_automated_scan", "severity": "soft",
            "description": "Prefer manual testing for DoS.",
            "enforcement": "block_scan",
            "applies_to": ["dos"],
        }])
        result = enforce(data)
        assert result.scan_blocked is False
        assert result.disabled_tools == set()  # soft → no disabling, just warn
        assert any("soft restriction" in w.lower() for w in result.warnings)
