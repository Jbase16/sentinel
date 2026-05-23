"""
Tests for the ProgramScope data model (Phase 2A).

The contract every other Phase 2 module depends on:

  1. Round-trip: any ProgramScope → JSON → ProgramScope is identity.
  2. Enums serialize as their .value (string), never as repr.
  3. Schema mismatch on load is a clear, loud error — not silent corruption.
  4. Convenience accessors (verified_personas, in_scope_domains, etc.)
     return the expected projections without mutating state.
  5. content_hash is deterministic and stable across Python sessions.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from core.intel.program_scope import (
    CredentialSource,
    LoginFlow,
    Persona,
    Platform,
    ProgramScope,
    Restriction,
    RestrictionKind,
    ScopeRule,
    ScopeRuleType,
    VerificationStatus,
    content_hash,
)


def _fully_populated_scope() -> ProgramScope:
    """A ProgramScope with every field non-default. Used as a fuzz seed
    for round-trip tests — if every field round-trips here, partial
    populations also round-trip."""
    return ProgramScope(
        handle="example-program",
        platform=Platform.HACKERONE,
        name="Example Inc",
        source_url="https://hackerone.com/example-program",
        fetched_at=datetime(2026, 5, 18, 12, 0, 0, tzinfo=timezone.utc),
        scope_rules=[
            ScopeRule(
                pattern="*.example.com",
                rule_type=ScopeRuleType.DOMAIN,
                in_scope=True,
                notes="primary surface",
            ),
            ScopeRule(
                pattern="admin.example.com",
                rule_type=ScopeRuleType.DOMAIN,
                in_scope=False,
                notes="off-limits",
            ),
            ScopeRule(
                pattern="10.0.0.0/8",
                rule_type=ScopeRuleType.IP_CIDR,
                in_scope=False,
                notes="internal",
            ),
        ],
        personas=[
            Persona(
                name="anonymous",
                persona_type="anonymous",
                base_url="https://example.com",
                source=CredentialSource.OPERATOR_PROVIDED,
                verified=VerificationStatus.UNVERIFIED,
            ),
            Persona(
                name="researcher",
                persona_type="user",
                base_url="https://example.com",
                login_flow=LoginFlow(
                    endpoint="/api/login",
                    method="POST",
                    username_param="email",
                    password_param="password",
                    content_type="application/json",
                    token_extract_path="data.token",
                    additional_fields={"X-CSRF-Token": "$CSRF_FROM:/login"},
                ),
                username="tester@example.com",
                password="known-test-pass",
                role_hint="standard user — read/write own data",
                source=CredentialSource.POLICY_EXPLICIT,
                verified=VerificationStatus.VERIFIED,
                confidence=0.95,
            ),
        ],
        signup_endpoint="/api/signup",
        restrictions=[
            Restriction(
                kind=RestrictionKind.NO_DOS,
                severity="hard",
                description="No denial-of-service or volumetric testing.",
                raw_quote="DoS or load testing is strictly prohibited.",
            ),
            Restriction(
                kind=RestrictionKind.RATE_LIMITED,
                severity="soft",
                description="Please rate-limit automated scanning to 5 rps.",
            ),
        ],
        rate_limit_rps=5.0,
        payout_max_usd=50000,
        raw_content_hash="abcd" * 16,  # 64 hex chars — sha256 length
        extractor_version="generic_url@0.1",
        extraction_confidence=0.87,
    )


# ─────────────────────────── Round-trip ────────────────────────────

class TestRoundTrip:
    def test_to_json_from_json_is_identity(self):
        original = _fully_populated_scope()
        rebuilt = ProgramScope.from_json(original.to_json())

        # Field-by-field equality so a mismatch points at the bad field.
        assert rebuilt.handle == original.handle
        assert rebuilt.platform == original.platform
        assert rebuilt.name == original.name
        assert rebuilt.source_url == original.source_url
        assert rebuilt.fetched_at == original.fetched_at
        assert rebuilt.scope_rules == original.scope_rules
        assert rebuilt.personas == original.personas
        assert rebuilt.signup_endpoint == original.signup_endpoint
        assert rebuilt.restrictions == original.restrictions
        assert rebuilt.rate_limit_rps == original.rate_limit_rps
        assert rebuilt.payout_max_usd == original.payout_max_usd
        assert rebuilt.raw_content_hash == original.raw_content_hash
        assert rebuilt.extractor_version == original.extractor_version
        assert rebuilt.extraction_confidence == original.extraction_confidence

    def test_double_round_trip_is_stable(self):
        # to_json → from_json → to_json should produce identical text the
        # second time. If it doesn't, something is non-deterministic in
        # serialization order or string formatting.
        original = _fully_populated_scope()
        first = original.to_json()
        second = ProgramScope.from_json(first).to_json()
        assert first == second

    def test_minimal_scope_round_trips(self):
        # No personas, no rules, no restrictions — bare identity only.
        minimal = ProgramScope(
            handle=None,
            platform=Platform.DIRECT_URL,
            name="adhoc",
            source_url="https://example.com/security.txt",
            fetched_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        )
        rebuilt = ProgramScope.from_json(minimal.to_json())
        assert rebuilt.handle is None
        assert rebuilt.platform == Platform.DIRECT_URL
        assert rebuilt.scope_rules == []
        assert rebuilt.personas == []
        assert rebuilt.restrictions == []


# ─────────────────────────── Enum serialization ────────────────────

class TestEnumSerialization:
    def test_platform_serializes_as_string_value(self):
        scope = _fully_populated_scope()
        payload = json.loads(scope.to_json())
        # Not "Platform.HACKERONE", not 0 — the string value.
        assert payload["platform"] == "hackerone"

    def test_verification_status_serializes_as_string_value(self):
        scope = _fully_populated_scope()
        payload = json.loads(scope.to_json())
        verified_persona = next(p for p in payload["personas"] if p["name"] == "researcher")
        assert verified_persona["verified"] == "verified"
        assert verified_persona["source"] == "policy_explicit"

    def test_restriction_kind_serializes_as_string_value(self):
        scope = _fully_populated_scope()
        payload = json.loads(scope.to_json())
        kinds = sorted(r["kind"] for r in payload["restrictions"])
        assert kinds == ["no_dos", "rate_limited"]

    def test_scope_rule_type_serializes_as_string_value(self):
        scope = _fully_populated_scope()
        payload = json.loads(scope.to_json())
        types = sorted({r["rule_type"] for r in payload["scope_rules"]})
        assert types == ["domain", "ip_cidr"]


# ─────────────────────────── Schema versioning ─────────────────────

class TestSchemaVersion:
    def test_schema_version_present_in_output(self):
        scope = _fully_populated_scope()
        payload = json.loads(scope.to_json())
        assert payload["schema_version"] == ProgramScope.SCHEMA_VERSION

    def test_stale_schema_raises_on_load(self):
        scope = _fully_populated_scope()
        payload = json.loads(scope.to_json())
        payload["schema_version"] = "0.0"  # ancient
        with pytest.raises(ValueError, match="schema mismatch"):
            ProgramScope.from_dict(payload)

    def test_missing_schema_version_raises(self):
        scope = _fully_populated_scope()
        payload = json.loads(scope.to_json())
        del payload["schema_version"]
        with pytest.raises(ValueError, match="schema mismatch"):
            ProgramScope.from_dict(payload)


# ─────────────────────────── Convenience accessors ─────────────────

class TestConvenienceAccessors:
    def test_in_scope_domains_returns_only_in_scope_domain_rules(self):
        scope = _fully_populated_scope()
        # Has *.example.com (in, domain), admin.example.com (out, domain),
        # 10.0.0.0/8 (out, cidr). Only the first qualifies.
        assert scope.in_scope_domains() == ["*.example.com"]

    def test_verified_personas_returns_only_verified(self):
        scope = _fully_populated_scope()
        verified = scope.verified_personas()
        assert len(verified) == 1
        assert verified[0].name == "researcher"

    def test_hard_restrictions_filters_by_severity(self):
        scope = _fully_populated_scope()
        hard = scope.hard_restrictions()
        assert len(hard) == 1
        assert hard[0].kind == RestrictionKind.NO_DOS

    def test_accessors_do_not_mutate_underlying_lists(self):
        scope = _fully_populated_scope()
        before = len(scope.personas)
        _ = scope.verified_personas()
        _ = scope.in_scope_domains()
        _ = scope.hard_restrictions()
        assert len(scope.personas) == before


# ─────────────────────────── Content hashing ───────────────────────

class TestContentHash:
    def test_hash_is_deterministic(self):
        assert content_hash("hello") == content_hash("hello")

    def test_hash_differs_for_different_input(self):
        assert content_hash("hello") != content_hash("hello!")

    def test_hash_is_sha256_hex(self):
        h = content_hash("test")
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)

    def test_hash_handles_unicode(self):
        # Must encode as UTF-8 consistently regardless of Python version.
        h_en = content_hash("hello")
        h_emoji = content_hash("hello 👋")
        assert h_en != h_emoji
        assert len(h_emoji) == 64


# ─────────────────────────── Defaults sanity ───────────────────────

class TestDefaults:
    def test_persona_defaults_are_unverified_unknown(self):
        p = Persona(name="x", persona_type="user", base_url="https://x")
        assert p.verified == VerificationStatus.UNVERIFIED
        assert p.source == CredentialSource.UNKNOWN
        assert p.login_flow is None
        assert p.username is None
        assert p.password is None
        assert p.confidence == 0.0

    def test_login_flow_defaults_are_post_json(self):
        lf = LoginFlow(endpoint="/login")
        assert lf.method == "POST"
        assert lf.content_type == "application/json"
        assert lf.username_param == "email"
        assert lf.password_param == "password"
        assert lf.additional_fields == {}

    def test_scope_defaults_have_empty_collections(self):
        s = ProgramScope(
            handle=None,
            platform=Platform.UNKNOWN,
            name="x",
            source_url="https://x",
            fetched_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        )
        assert s.scope_rules == []
        assert s.personas == []
        assert s.restrictions == []
        assert s.signup_endpoint is None
        assert s.rate_limit_rps is None
        assert s.payout_max_usd is None
