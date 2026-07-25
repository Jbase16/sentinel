"""
Tests for persona_compiler (Phase 2C).

Contracts under test:

  1. Output JSON has the wraith-expected shape: list of dicts, each with
     ``name``, ``persona_type``, ``base_url``, optional ``login_flow``.
  2. Field-name translations are applied:
     - ``persona.username`` → ``login_flow.username_value``
     - ``persona.password`` → ``login_flow.password_value``
     - ``login_flow.cookie_extract_name`` → ``login_flow.cookie_extract``
  3. FAILED personas are dropped by default; included with ``include_failed=True``.
  4. Personas with missing username/password are dropped (useless creds).
  5. An anonymous baseline is auto-synthesized if none exists.
  6. Output is JSON-parseable (no trailing comma errors, valid encoding).
  7. The existing ``pysentinel.py:_load_personas_file`` validator passes
     on the emitted file (round-trip with the actual loader).
"""
from __future__ import annotations

import json
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

import pytest

from core.intel.compilers.persona_compiler import compile_personas_json
from core.intel.program_scope import (
    CredentialSource,
    LoginFlow,
    Persona,
    Platform,
    ProgramScope,
    VerificationStatus,
)


# ─────────────────────────── Helpers ───────────────────────────────

def _make_scope(*personas: Persona) -> ProgramScope:
    return ProgramScope(
        handle="example",
        platform=Platform.HACKERONE,
        name="Example",
        source_url="https://hackerone.com/example/policy",
        fetched_at=datetime(2026, 5, 18, tzinfo=timezone.utc),
        personas=list(personas),
    )


def _verified_user(name: str = "researcher", **kwargs) -> Persona:
    """Build a fully-credentialed, verified Persona."""
    defaults = dict(
        persona_type="user",
        base_url="https://app.example.com",
        username="test@example.com",
        password="known-good",
        login_flow=LoginFlow(
            endpoint="/api/login",
            method="POST",
            username_param="email",
            password_param="password",
            content_type="application/json",
            token_extract_path="data.token",
        ),
        source=CredentialSource.POLICY_EXPLICIT,
        verified=VerificationStatus.VERIFIED,
    )
    defaults.update(kwargs)
    return Persona(name=name, **defaults)


# ─────────────────────────── Shape ─────────────────────────────────

class TestShape:
    def test_output_is_valid_json(self):
        scope = _make_scope(_verified_user())
        out = compile_personas_json(scope)
        # Must parse cleanly.
        parsed = json.loads(out)
        assert isinstance(parsed, list)

    def test_each_persona_has_required_fields(self):
        scope = _make_scope(_verified_user())
        parsed = json.loads(compile_personas_json(scope))
        for p in parsed:
            assert "name" in p
            assert "persona_type" in p
            assert "base_url" in p

    def test_output_ends_with_newline(self):
        scope = _make_scope(_verified_user())
        out = compile_personas_json(scope)
        # POSIX-compliant file ending.
        assert out.endswith("\n")


# ─────────────────────────── Field translations ────────────────────

class TestFieldTranslations:
    def test_username_hoisted_to_login_flow_value(self):
        # The biggest trap: persona.username → login_flow.username_value
        scope = _make_scope(_verified_user(username="my-user@x.com"))
        parsed = json.loads(compile_personas_json(scope))
        # The 'researcher' persona — anonymous is at index 0.
        researcher = next(p for p in parsed if p["name"] == "researcher")
        assert "login_flow" in researcher
        assert researcher["login_flow"]["username_value"] == "my-user@x.com"
        # Top-level username should NOT appear.
        assert "username" not in researcher

    def test_password_hoisted_to_login_flow_value(self):
        scope = _make_scope(_verified_user(password="hunter2"))
        parsed = json.loads(compile_personas_json(scope))
        researcher = next(p for p in parsed if p["name"] == "researcher")
        assert researcher["login_flow"]["password_value"] == "hunter2"
        assert "password" not in researcher

    def test_cookie_extract_name_renamed(self):
        """The wraith dataclass field is `cookie_extract` (singular), not
        `cookie_extract_name`. The compiler MUST rename."""
        user = _verified_user(
            login_flow=LoginFlow(
                endpoint="/login",
                cookie_extract_name="session_id",
            ),
            password="x", username="y@z.com",  # required for inclusion
        )
        scope = _make_scope(user)
        parsed = json.loads(compile_personas_json(scope))
        researcher = next(p for p in parsed if p["name"] == "researcher")
        assert researcher["login_flow"]["cookie_extract"] == "session_id"
        assert "cookie_extract_name" not in researcher["login_flow"]

    def test_token_extract_path_preserved(self):
        # Token path is the same name on both sides — no rename needed.
        scope = _make_scope(_verified_user())
        parsed = json.loads(compile_personas_json(scope))
        researcher = next(p for p in parsed if p["name"] == "researcher")
        assert researcher["login_flow"]["token_extract_path"] == "data.token"


# ─────────────────────────── Filtering ─────────────────────────────

class TestFiltering:
    def test_anonymous_persona_always_included(self):
        anon = Persona(
            name="anon", persona_type="anonymous", base_url="https://app.example.com",
            verified=VerificationStatus.UNVERIFIED,
        )
        scope = _make_scope(anon)
        parsed = json.loads(compile_personas_json(scope))
        names = [p["name"] for p in parsed]
        assert "anon" in names

    def test_failed_persona_dropped_by_default(self):
        bad = _verified_user(name="bad", verified=VerificationStatus.FAILED)
        scope = _make_scope(bad)
        parsed = json.loads(compile_personas_json(scope))
        names = [p["name"] for p in parsed]
        assert "bad" not in names

    def test_failed_persona_included_when_flag_set(self):
        bad = _verified_user(name="bad", verified=VerificationStatus.FAILED)
        scope = _make_scope(bad)
        parsed = json.loads(compile_personas_json(scope, include_failed=True))
        names = [p["name"] for p in parsed]
        assert "bad" in names

    def test_persona_without_credentials_dropped(self):
        no_creds = Persona(
            name="no-creds", persona_type="user", base_url="https://x",
            login_flow=LoginFlow(endpoint="/login"),
            # no username/password
            verified=VerificationStatus.UNVERIFIED,
        )
        scope = _make_scope(no_creds)
        parsed = json.loads(compile_personas_json(scope))
        names = [p["name"] for p in parsed]
        assert "no-creds" not in names

    def test_unverified_with_credentials_included(self):
        # Operator may still want to verify these manually.
        unverified = _verified_user(
            name="unverified-but-has-creds",
            verified=VerificationStatus.UNVERIFIED,
        )
        scope = _make_scope(unverified)
        parsed = json.loads(compile_personas_json(scope))
        names = [p["name"] for p in parsed]
        assert "unverified-but-has-creds" in names


# ─────────────────────────── Anonymous synthesis ───────────────────

class TestAnonymousSynthesis:
    def test_synthesizes_anonymous_when_only_user_personas_exist(self):
        # When the scope has only authenticated personas, the compiler
        # should add an anonymous baseline so wraith has both sides of
        # the diff.
        scope = _make_scope(_verified_user(name="user1"))
        parsed = json.loads(compile_personas_json(scope))
        anon = next((p for p in parsed if p["persona_type"] == "anonymous"), None)
        assert anon is not None
        assert anon["name"] == "anonymous"
        # Uses the user's base_url as the anonymous base too.
        assert anon["base_url"] == "https://app.example.com"

    def test_does_not_synthesize_when_anonymous_already_present(self):
        anon_existing = Persona(
            name="existing-anon", persona_type="anonymous", base_url="https://x.com",
        )
        scope = _make_scope(anon_existing, _verified_user())
        parsed = json.loads(compile_personas_json(scope))
        anons = [p for p in parsed if p["persona_type"] == "anonymous"]
        # Exactly one anonymous — the existing one, not a duplicate.
        assert len(anons) == 1
        assert anons[0]["name"] == "existing-anon"

    def test_anonymous_synthesized_at_position_0(self):
        # Tests are easier when anonymous is the first entry; also matches
        # the convention in scripts/lab/megashop-personas.json.
        scope = _make_scope(_verified_user())
        parsed = json.loads(compile_personas_json(scope))
        assert parsed[0]["persona_type"] == "anonymous"

    def test_no_synthesis_when_scope_has_no_personas(self):
        # Empty scope.personas means we have nothing to diff against, so
        # synthesizing a lone anonymous is pointless.
        scope = _make_scope()
        parsed = json.loads(compile_personas_json(scope))
        assert parsed == []

    def test_h1_scope_does_NOT_use_api_source_url_as_base(self):
        # Regression for the Calibration Run #17 bug: for an H1 scope,
        # source_url is the API endpoint (api.hackerone.com), NOT the
        # target. We must never emit that as a scan base. With no persona
        # base_url and no scope rules, synthesis is skipped entirely.
        user = _verified_user(base_url="")
        scope = ProgramScope(
            handle="example", platform=Platform.HACKERONE, name="Example",
            source_url="https://api.hackerone.com/v1/hackers/programs/example",
            fetched_at=datetime(2026, 5, 18, tzinfo=timezone.utc),
            personas=[user],
        )
        parsed = json.loads(compile_personas_json(scope))
        # No anonymous baseline synthesized (no usable target host) —
        # and crucially NO api.hackerone.com leaked in as a base_url.
        assert all("api.hackerone.com" not in p.get("base_url", "") for p in parsed)

    def test_h1_scope_uses_first_in_scope_domain_as_base(self):
        # The correct source for an H1 anonymous base is the first
        # concrete in-scope domain, not the API URL.
        from core.intel.program_scope import ScopeRule, ScopeRuleType
        user = _verified_user(base_url="")
        scope = ProgramScope(
            handle="example", platform=Platform.HACKERONE, name="Example",
            source_url="https://api.hackerone.com/v1/hackers/programs/example",
            fetched_at=datetime(2026, 5, 18, tzinfo=timezone.utc),
            personas=[user],
            scope_rules=[
                ScopeRule(pattern="*.example.com", rule_type=ScopeRuleType.DOMAIN, in_scope=True),
                ScopeRule(pattern="app.example.com", rule_type=ScopeRuleType.DOMAIN, in_scope=True),
            ],
        )
        parsed = json.loads(compile_personas_json(scope))
        anon = next(p for p in parsed if p["persona_type"] == "anonymous")
        # First *concrete* in-scope host (wildcard skipped) → app.example.com
        assert anon["base_url"] == "https://app.example.com"

    def test_direct_url_scope_still_uses_source_url_fallback(self):
        # For DIRECT_URL scopes (operator pasted a real policy page URL),
        # the source_url IS the target host — fallback still applies.
        user = _verified_user(base_url="")
        scope = ProgramScope(
            handle=None, platform=Platform.DIRECT_URL, name="Example",
            source_url="https://example.com/security/policy",
            fetched_at=datetime(2026, 5, 18, tzinfo=timezone.utc),
            personas=[user],
        )
        parsed = json.loads(compile_personas_json(scope))
        anon = next(p for p in parsed if p["persona_type"] == "anonymous")
        assert anon["base_url"] == "https://example.com"

    def test_zero_personas_still_emits_loadable_file(self):
        # The Calibration Run #17 blocker: GitLab's LLM extraction timed
        # out → 0 personas → compiler emitted [] → pysentinel rejected it.
        # Now: even with 0 personas, if there's an in-scope domain we
        # synthesize the anonymous baseline so the file is loadable.
        from core.intel.program_scope import ScopeRule, ScopeRuleType
        scope = ProgramScope(
            handle="gitlab", platform=Platform.HACKERONE, name="GitLab",
            source_url="https://api.hackerone.com/v1/hackers/programs/gitlab",
            fetched_at=datetime(2026, 5, 18, tzinfo=timezone.utc),
            personas=[],  # LLM extracted nothing
            scope_rules=[
                ScopeRule(pattern="gitlab.com", rule_type=ScopeRuleType.DOMAIN, in_scope=True),
            ],
        )
        parsed = json.loads(compile_personas_json(scope))
        assert len(parsed) == 1
        assert parsed[0]["persona_type"] == "anonymous"
        assert parsed[0]["base_url"] == "https://gitlab.com"


# ─────────────────────────── Loader round-trip ─────────────────────

class TestLoaderRoundTrip:
    """Emit personas.json, then load with pysentinel's actual
    ``_load_personas_file``. If the loader rejects our output, ingest
    silently breaks scans."""

    def test_loader_accepts_compiled_output(self):
        scope = _make_scope(_verified_user())
        out = compile_personas_json(scope)
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            f.write(out)
            path = f.name
        try:
            # Import the real loader from pysentinel.
            sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))
            from pysentinel import _load_personas_file
            loaded = _load_personas_file(path)
            # The loader returns the raw list of dicts; if it raised
            # SystemExit (which it does on validation errors), this
            # test fails noisily.
            assert isinstance(loaded, list)
            assert all("name" in p for p in loaded)
        finally:
            Path(path).unlink(missing_ok=True)

    def test_compiled_output_is_valid_json_no_trailing_commas(self):
        # Defensive: json.dumps shouldn't produce trailing commas, but
        # a future refactor to manual formatting could.
        scope = _make_scope(_verified_user())
        out = compile_personas_json(scope)
        # If this raises, the file isn't valid JSON.
        json.loads(out)


# ─────────────────────────── Multiple personas ─────────────────────

class TestMultiplePersonas:
    def test_user_and_admin_both_emitted(self):
        user = _verified_user(name="user", persona_type="user")
        admin = _verified_user(name="admin", persona_type="admin")
        scope = _make_scope(user, admin)
        parsed = json.loads(compile_personas_json(scope))
        types = {p["persona_type"] for p in parsed}
        assert "user" in types
        assert "admin" in types
        assert "anonymous" in types  # synthesized

    def test_order_preserved_from_scope(self):
        u1 = _verified_user(name="first")
        u2 = _verified_user(name="second")
        scope = _make_scope(u1, u2)
        parsed = json.loads(compile_personas_json(scope))
        # Anonymous synthesized at position 0, then originals in order.
        non_anon = [p for p in parsed if p["persona_type"] != "anonymous"]
        assert [p["name"] for p in non_anon] == ["first", "second"]
