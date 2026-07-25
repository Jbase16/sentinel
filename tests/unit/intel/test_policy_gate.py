"""
Tests for policy_gate (Phase 2C).

Contracts:

  1. Output is valid JSON conforming to the schema documented at the
     top of policy_gate.py.
  2. Each RestrictionKind maps to its documented enforcement strategy.
  3. Enforcement args are populated correctly for each strategy.
  4. ``scope.rate_limit_rps`` auto-synthesizes a RATE_LIMITED
     restriction when none exists.
  5. Schema version is present and stable.
  6. Empty restrictions produces a syntactically-valid file with empty
     ``restrictions`` array.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from core.intel.compilers.policy_gate import SCHEMA_VERSION, compile_restrictions_json
from core.intel.program_scope import (
    Platform,
    ProgramScope,
    Restriction,
    RestrictionKind,
)


def _make_scope(*restrictions: Restriction, rate_limit: float = None) -> ProgramScope:
    return ProgramScope(
        handle="example",
        platform=Platform.HACKERONE,
        name="Example",
        source_url="https://hackerone.com/example",
        fetched_at=datetime(2026, 5, 18, tzinfo=timezone.utc),
        restrictions=list(restrictions),
        rate_limit_rps=rate_limit,
    )


# ─────────────────────────── Shape ─────────────────────────────────

class TestShape:
    def test_output_is_valid_json(self):
        scope = _make_scope()
        out = compile_restrictions_json(scope)
        parsed = json.loads(out)
        assert isinstance(parsed, dict)

    def test_includes_schema_version(self):
        scope = _make_scope()
        parsed = json.loads(compile_restrictions_json(scope))
        assert parsed["schema_version"] == SCHEMA_VERSION

    def test_includes_program_metadata(self):
        scope = _make_scope()
        parsed = json.loads(compile_restrictions_json(scope))
        prog = parsed["program"]
        assert prog["handle"] == "example"
        assert prog["platform"] == "hackerone"
        assert prog["name"] == "Example"

    def test_output_ends_with_newline(self):
        scope = _make_scope()
        out = compile_restrictions_json(scope)
        assert out.endswith("\n")


# ─────────────────────────── Empty scope ───────────────────────────

class TestEmptyScope:
    def test_no_restrictions_produces_empty_list(self):
        scope = _make_scope()
        parsed = json.loads(compile_restrictions_json(scope))
        assert parsed["restrictions"] == []
        assert parsed["rate_limit_rps"] is None


# ─────────────────────────── Enforcement strategy mapping ──────────

class TestEnforcementStrategy:
    """Lock in the RestrictionKind → enforcement-strategy mapping.

    Bumping any of these strategy strings is a schema break — bump
    SCHEMA_VERSION in policy_gate.py if you do.
    """

    def _strategy_for(self, kind: RestrictionKind) -> str:
        scope = _make_scope(Restriction(kind=kind, severity="hard", description="x"))
        parsed = json.loads(compile_restrictions_json(scope))
        return parsed["restrictions"][0]["enforcement"]

    def test_no_dos_uses_disable_tool_categories(self):
        assert self._strategy_for(RestrictionKind.NO_DOS) == "disable_tool_categories"

    def test_no_bruteforce_uses_disable_tool_categories(self):
        assert self._strategy_for(RestrictionKind.NO_BRUTEFORCE) == "disable_tool_categories"

    def test_no_social_eng_uses_disable_tool_categories(self):
        assert self._strategy_for(RestrictionKind.NO_SOCIAL_ENG) == "disable_tool_categories"

    def test_no_data_destruction_uses_cap_capability_tier(self):
        assert self._strategy_for(RestrictionKind.NO_DATA_DESTRUCTION) == "cap_capability_tier"

    def test_no_automated_scan_uses_block_scan(self):
        assert self._strategy_for(RestrictionKind.NO_AUTOMATED_SCAN) == "block_scan"

    def test_no_third_party_uses_enforce_strict_scope(self):
        assert self._strategy_for(RestrictionKind.NO_THIRD_PARTY) == "enforce_strict_scope"

    def test_rate_limited_uses_set_rate_limit(self):
        assert self._strategy_for(RestrictionKind.RATE_LIMITED) == "set_rate_limit"

    def test_business_hours_uses_warn(self):
        assert self._strategy_for(RestrictionKind.BUSINESS_HOURS_ONLY) == "warn"

    def test_region_restricted_uses_warn(self):
        assert self._strategy_for(RestrictionKind.REGION_RESTRICTED) == "warn"

    def test_requires_prior_approval_uses_require_attestation(self):
        assert self._strategy_for(RestrictionKind.REQUIRES_PRIOR_APPROVAL) == "require_attestation"

    def test_other_uses_warn(self):
        assert self._strategy_for(RestrictionKind.OTHER) == "warn"


# ─────────────────────────── Enforcement args ──────────────────────

class TestEnforcementArgs:
    def test_no_dos_args_list_dos_categories(self):
        scope = _make_scope(Restriction(kind=RestrictionKind.NO_DOS, severity="hard", description="x"))
        r = json.loads(compile_restrictions_json(scope))["restrictions"][0]
        assert "dos" in r["enforcement_args"]["categories"]
        assert "stress-test" in r["enforcement_args"]["categories"]

    def test_no_bruteforce_args_list_bruteforce_category(self):
        scope = _make_scope(Restriction(kind=RestrictionKind.NO_BRUTEFORCE, severity="hard", description="x"))
        r = json.loads(compile_restrictions_json(scope))["restrictions"][0]
        assert "bruteforce" in r["enforcement_args"]["categories"]

    def test_no_data_destruction_args_set_capability_tier_cap(self):
        scope = _make_scope(Restriction(kind=RestrictionKind.NO_DATA_DESTRUCTION, severity="hard", description="x"))
        r = json.loads(compile_restrictions_json(scope))["restrictions"][0]
        assert r["enforcement_args"]["max_tier"] == "T2a_SAFE_VERIFY"

    def test_no_social_eng_args_list_social_categories(self):
        scope = _make_scope(Restriction(kind=RestrictionKind.NO_SOCIAL_ENG, severity="hard", description="x"))
        r = json.loads(compile_restrictions_json(scope))["restrictions"][0]
        assert "social-engineering" in r["enforcement_args"]["categories"]

    def test_strategies_with_no_args_omit_field(self):
        # block_scan, warn, etc. don't need args — the field should not
        # appear, not be present-but-empty.
        scope = _make_scope(Restriction(kind=RestrictionKind.BUSINESS_HOURS_ONLY, severity="soft", description="x"))
        r = json.loads(compile_restrictions_json(scope))["restrictions"][0]
        assert "enforcement_args" not in r


# ─────────────────────────── Restriction fields ────────────────────

class TestRestrictionFields:
    def test_kind_severity_description_preserved(self):
        scope = _make_scope(Restriction(
            kind=RestrictionKind.NO_DOS,
            severity="hard",
            description="No DoS testing per policy.",
        ))
        r = json.loads(compile_restrictions_json(scope))["restrictions"][0]
        assert r["kind"] == "no_dos"
        assert r["severity"] == "hard"
        assert r["description"] == "No DoS testing per policy."

    def test_raw_quote_preserved_when_present(self):
        scope = _make_scope(Restriction(
            kind=RestrictionKind.NO_DOS,
            severity="hard",
            description="x",
            raw_quote="DoS testing is strictly prohibited.",
        ))
        r = json.loads(compile_restrictions_json(scope))["restrictions"][0]
        assert r["raw_quote"] == "DoS testing is strictly prohibited."

    def test_raw_quote_omitted_when_absent(self):
        scope = _make_scope(Restriction(
            kind=RestrictionKind.NO_DOS,
            severity="hard",
            description="x",
            # raw_quote=None
        ))
        r = json.loads(compile_restrictions_json(scope))["restrictions"][0]
        assert "raw_quote" not in r


# ─────────────────────────── Rate-limit synthesis ──────────────────

class TestRateLimitSynthesis:
    def test_rate_limit_rps_creates_synthetic_restriction(self):
        # If the LLM extracted rate_limit_rps but didn't catalog it as a
        # RATE_LIMITED restriction, compile_restrictions_json should
        # synthesize one.
        scope = _make_scope(rate_limit=5.0)
        parsed = json.loads(compile_restrictions_json(scope))
        rls = [r for r in parsed["restrictions"] if r["kind"] == "rate_limited"]
        assert len(rls) == 1
        assert rls[0]["enforcement_args"]["rps"] == 5.0

    def test_does_not_duplicate_rate_limited_restriction(self):
        # If RATE_LIMITED is already an explicit restriction, don't
        # synthesize a duplicate.
        scope = _make_scope(
            Restriction(kind=RestrictionKind.RATE_LIMITED, severity="soft", description="explicit"),
            rate_limit=5.0,
        )
        parsed = json.loads(compile_restrictions_json(scope))
        rls = [r for r in parsed["restrictions"] if r["kind"] == "rate_limited"]
        assert len(rls) == 1

    def test_no_rate_limit_set_no_synthesis(self):
        scope = _make_scope()  # rate_limit defaults to None
        parsed = json.loads(compile_restrictions_json(scope))
        assert parsed["rate_limit_rps"] is None
        rls = [r for r in parsed["restrictions"] if r["kind"] == "rate_limited"]
        assert len(rls) == 0


# ─────────────────────────── Multiple restrictions ─────────────────

class TestMultipleRestrictions:
    def test_all_restrictions_emitted_in_order(self):
        scope = _make_scope(
            Restriction(kind=RestrictionKind.NO_DOS, severity="hard", description="1"),
            Restriction(kind=RestrictionKind.NO_BRUTEFORCE, severity="hard", description="2"),
            Restriction(kind=RestrictionKind.RATE_LIMITED, severity="soft", description="3"),
        )
        parsed = json.loads(compile_restrictions_json(scope))
        descriptions = [r["description"] for r in parsed["restrictions"]]
        assert descriptions == ["1", "2", "3"]

    def test_mixed_hard_and_soft_preserved(self):
        scope = _make_scope(
            Restriction(kind=RestrictionKind.NO_DOS, severity="hard", description="x"),
            Restriction(kind=RestrictionKind.BUSINESS_HOURS_ONLY, severity="soft", description="y"),
        )
        parsed = json.loads(compile_restrictions_json(scope))
        severities = [r["severity"] for r in parsed["restrictions"]]
        assert "hard" in severities
        assert "soft" in severities
