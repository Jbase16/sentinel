"""
Tests for HackerOneExtractor (Phase 2G refactor).

The extractor has two paths:

  1. **API path** — used when a credential is present in the token store.
     Calls H1's official API, parses structured_scopes directly,
     LLM-extracts personas/restrictions from the policy text.
  2. **No-credential path** — raises ExtractorError with actionable message
     pointing the operator to ``sentinel-token add hackerone``.

Both are tested here with all I/O mocked (no real HTTP, no real Keychain).
"""
from __future__ import annotations

import json
from typing import Optional

import pytest

from core.intel.extractors.base import ExtractorError
from core.intel.extractors.hackerone import HackerOneExtractor
from core.intel.llm_extraction import (
    ExtractedScope,
    ExtractedPersona,
    ExtractedRestriction,
)
from core.intel.program_scope import (
    Platform,
    ScopeRuleType,
    VerificationStatus,
)
from core.intel.token_store import StoredCredential


# ─────────────────────────── Test doubles ──────────────────────────

class _FakeResponse:
    def __init__(self, *, status_code=200, json_body=None):
        self.status_code = status_code
        self._json_body = json_body or {}

    def json(self):
        return self._json_body


class _FakeClient:
    def __init__(self, responses):
        self._responses = list(responses)
        self.calls: list = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False

    async def get(self, url, **kwargs):
        self.calls.append({"url": url, **kwargs})
        if isinstance(self._responses[0], Exception):
            raise self._responses.pop(0)
        return self._responses.pop(0)


def _make_factory(*responses):
    client = _FakeClient(list(responses))

    def factory():
        return client

    factory.client = client
    return factory


def _make_llm_extractor(returns):
    calls = []

    async def fake(text):
        calls.append(text)
        return returns

    fake.calls = calls
    return fake


def _good_extracted_scope():
    return ExtractedScope(
        name="ignored — H1 API gives us the program name",
        personas=[
            ExtractedPersona(
                name="researcher",
                persona_type="user",
                base_url="https://example.com",
                username="researcher@example.com",
                password="known-good-pw",
            ),
        ],
        restrictions=[
            ExtractedRestriction(
                kind="no_dos", severity="hard",
                description="No DoS testing.",
            ),
        ],
        signup_endpoint="/signup",
        rate_limit_rps=10.0,
        extraction_confidence=0.92,
    )


def _credential_returning(handle="test-handle", token="TEST_TOKEN"):
    return lambda: StoredCredential(platform="hackerone", handle=handle, token=token)


def _no_credential():
    return lambda: None


def _h1_api_payload(*, name="Test Program", policy="Test policy text.", scopes=None):
    """Build a realistic H1 API response payload."""
    return {
        "id": "13",
        "type": "program",
        "attributes": {
            "handle": "test",
            "name": name,
            "policy": policy,
            "submission_state": "open",
            "state": "public_mode",
            "started_accepting_at": "2020-01-01T00:00:00Z",
        },
        "relationships": {
            "structured_scopes": {
                "data": scopes or [],
            },
        },
    }


def _h1_scope_item(*, identifier, asset_type="URL", eligible=True, instruction=None):
    return {
        "id": "999",
        "type": "structured-scope",
        "attributes": {
            "asset_identifier": identifier,
            "asset_type": asset_type,
            "eligible_for_bounty": eligible,
            "eligible_for_submission": eligible,
            "instruction": instruction,
            "max_severity": "critical",
        },
    }


# ─────────────────────────── can_handle ────────────────────────────

class TestCanHandle:
    def setup_method(self):
        # No credential needed for can_handle.
        self.ex = HackerOneExtractor(credential_lookup=_no_credential())

    def test_accepts_prefix_form(self):
        assert self.ex.can_handle("hackerone:gitlab")

    def test_accepts_hackerone_url(self):
        assert self.ex.can_handle("https://hackerone.com/gitlab")
        assert self.ex.can_handle("https://hackerone.com/gitlab/policy")

    def test_accepts_www_hackerone_url(self):
        assert self.ex.can_handle("https://www.hackerone.com/gitlab")

    def test_rejects_bugcrowd_url(self):
        assert not self.ex.can_handle("https://bugcrowd.com/tesla")

    def test_rejects_bare_handle(self):
        assert not self.ex.can_handle("gitlab")

    def test_rejects_empty_and_none(self):
        assert not self.ex.can_handle("")
        assert not self.ex.can_handle(None)  # type: ignore[arg-type]


# ─────────────────────────── No-credential path ────────────────────

class TestNoCredentialPath:
    """When no credential is configured, extract() must raise an
    actionable ExtractorError pointing the operator to sentinel-token."""

    async def test_raises_actionable_error_without_credential(self):
        ex = HackerOneExtractor(
            http_factory=_make_factory(),
            credential_lookup=_no_credential(),
        )
        with pytest.raises(ExtractorError) as exc_info:
            await ex.extract("hackerone:gitlab")
        msg = str(exc_info.value)
        assert "requires an API token" in msg
        assert "sentinel-token add hackerone" in msg
        assert "gitlab" in msg

    async def test_does_not_attempt_http_when_no_credential(self):
        # The error path must short-circuit BEFORE any HTTP call.
        # Verify the factory wasn't invoked.
        factory = _make_factory()
        ex = HackerOneExtractor(
            http_factory=factory,
            credential_lookup=_no_credential(),
        )
        with pytest.raises(ExtractorError):
            await ex.extract("hackerone:gitlab")
        # No client was created → factory.client.calls is empty.
        assert factory.client.calls == []


# ─────────────────────────── API path: HTTP wiring ─────────────────

class TestApiPathHttpWiring:
    async def test_calls_correct_api_endpoint(self):
        factory = _make_factory(_FakeResponse(
            json_body=_h1_api_payload(scopes=[]),
        ))
        ex = HackerOneExtractor(
            http_factory=factory,
            llm_extractor=_make_llm_extractor(_good_extracted_scope()),
            credential_lookup=_credential_returning(),
        )
        await ex.extract("hackerone:security")
        call = factory.client.calls[0]
        assert call["url"] == "https://api.hackerone.com/v1/hackers/programs/security"

    async def test_uses_basic_auth_with_handle_and_token(self):
        factory = _make_factory(_FakeResponse(json_body=_h1_api_payload()))
        ex = HackerOneExtractor(
            http_factory=factory,
            llm_extractor=_make_llm_extractor(_good_extracted_scope()),
            credential_lookup=_credential_returning("my-handle", "MY-TOKEN"),
        )
        await ex.extract("hackerone:security")
        call = factory.client.calls[0]
        # auth is an httpx.BasicAuth instance — check that BasicAuth is used.
        import httpx
        assert isinstance(call["auth"], httpx.BasicAuth)

    async def test_401_raises_actionable_error(self):
        factory = _make_factory(_FakeResponse(status_code=401))
        ex = HackerOneExtractor(
            http_factory=factory,
            llm_extractor=_make_llm_extractor(_good_extracted_scope()),
            credential_lookup=_credential_returning(),
        )
        with pytest.raises(ExtractorError, match="401"):
            await ex.extract("hackerone:security")

    async def test_404_returns_none(self):
        factory = _make_factory(_FakeResponse(status_code=404))
        ex = HackerOneExtractor(
            http_factory=factory,
            llm_extractor=_make_llm_extractor(_good_extracted_scope()),
            credential_lookup=_credential_returning(),
        )
        result = await ex.extract("hackerone:no-such-program")
        assert result is None

    async def test_network_error_returns_none_not_raises(self):
        import httpx
        factory = _make_factory(httpx.ConnectError("dns"))
        ex = HackerOneExtractor(
            http_factory=factory,
            llm_extractor=_make_llm_extractor(_good_extracted_scope()),
            credential_lookup=_credential_returning(),
        )
        result = await ex.extract("hackerone:security")
        assert result is None


# ─────────────────────────── API path: scope parsing ───────────────

class TestApiPathScopeParsing:
    async def test_structured_scopes_translate_to_scope_rules(self):
        payload = _h1_api_payload(scopes=[
            _h1_scope_item(identifier="*.example.com", asset_type="WILDCARD", eligible=True),
            _h1_scope_item(identifier="api.example.com", asset_type="URL", eligible=True),
            _h1_scope_item(identifier="10.0.0.0/8", asset_type="CIDR", eligible=True),
            _h1_scope_item(identifier="internal.example.com", asset_type="URL", eligible=False),
        ])
        factory = _make_factory(_FakeResponse(json_body=payload))
        ex = HackerOneExtractor(
            http_factory=factory,
            llm_extractor=_make_llm_extractor(_good_extracted_scope()),
            credential_lookup=_credential_returning(),
        )
        result = await ex.extract("hackerone:test")
        assert result is not None
        assert len(result.scope_rules) == 4
        patterns_in_scope = {r.pattern for r in result.scope_rules if r.in_scope}
        patterns_out_of_scope = {r.pattern for r in result.scope_rules if not r.in_scope}
        assert patterns_in_scope == {"*.example.com", "api.example.com", "10.0.0.0/8"}
        assert patterns_out_of_scope == {"internal.example.com"}

    async def test_wildcard_type_prepends_glob_if_missing(self):
        # H1's API sometimes returns WILDCARD identifier without the "*."
        # prefix. Our renderer needs the glob to function.
        payload = _h1_api_payload(scopes=[
            _h1_scope_item(identifier="example.com", asset_type="WILDCARD", eligible=True),
        ])
        factory = _make_factory(_FakeResponse(json_body=payload))
        ex = HackerOneExtractor(
            http_factory=factory,
            llm_extractor=_make_llm_extractor(_good_extracted_scope()),
            credential_lookup=_credential_returning(),
        )
        result = await ex.extract("hackerone:test")
        assert result is not None
        assert result.scope_rules[0].pattern == "*.example.com"

    async def test_cidr_type_maps_to_ip_cidr_rule_type(self):
        payload = _h1_api_payload(scopes=[
            _h1_scope_item(identifier="10.0.0.0/24", asset_type="CIDR", eligible=True),
        ])
        factory = _make_factory(_FakeResponse(json_body=payload))
        ex = HackerOneExtractor(
            http_factory=factory,
            llm_extractor=_make_llm_extractor(_good_extracted_scope()),
            credential_lookup=_credential_returning(),
        )
        result = await ex.extract("hackerone:test")
        assert result is not None
        assert result.scope_rules[0].rule_type == ScopeRuleType.IP_CIDR

    async def test_mobile_app_types_map_to_mobile_app(self):
        for h1_type in ("GOOGLE_PLAY_APP_ID", "APPLE_STORE_APP_ID", "OTHER_APK", "OTHER_IPA"):
            payload = _h1_api_payload(scopes=[
                _h1_scope_item(identifier="com.example.app", asset_type=h1_type, eligible=True),
            ])
            factory = _make_factory(_FakeResponse(json_body=payload))
            ex = HackerOneExtractor(
                http_factory=factory,
                llm_extractor=_make_llm_extractor(_good_extracted_scope()),
                credential_lookup=_credential_returning(),
            )
            result = await ex.extract("hackerone:test")
            assert result is not None
            assert result.scope_rules[0].rule_type == ScopeRuleType.MOBILE_APP, (
                f"H1 asset_type {h1_type} should map to MOBILE_APP"
            )

    async def test_unknown_asset_type_coerces_to_other(self):
        payload = _h1_api_payload(scopes=[
            _h1_scope_item(identifier="something", asset_type="SOMETHING_FUTURE", eligible=True),
        ])
        factory = _make_factory(_FakeResponse(json_body=payload))
        ex = HackerOneExtractor(
            http_factory=factory,
            llm_extractor=_make_llm_extractor(_good_extracted_scope()),
            credential_lookup=_credential_returning(),
        )
        result = await ex.extract("hackerone:test")
        assert result is not None
        assert result.scope_rules[0].rule_type == ScopeRuleType.OTHER

    async def test_instruction_and_max_severity_become_notes(self):
        payload = _h1_api_payload(scopes=[
            {
                "id": "1", "type": "structured-scope",
                "attributes": {
                    "asset_identifier": "example.com",
                    "asset_type": "URL",
                    "eligible_for_submission": True,
                    "instruction": "Test only the public API.",
                    "max_severity": "high",
                },
            },
        ])
        factory = _make_factory(_FakeResponse(json_body=payload))
        ex = HackerOneExtractor(
            http_factory=factory,
            llm_extractor=_make_llm_extractor(_good_extracted_scope()),
            credential_lookup=_credential_returning(),
        )
        result = await ex.extract("hackerone:test")
        assert result is not None
        notes = result.scope_rules[0].notes or ""
        assert "Test only the public API." in notes
        assert "max_severity=high" in notes

    async def test_scope_item_without_identifier_skipped(self):
        payload = _h1_api_payload(scopes=[
            _h1_scope_item(identifier="ok.example.com"),
            {"id": "x", "type": "structured-scope", "attributes": {"asset_identifier": ""}},
        ])
        factory = _make_factory(_FakeResponse(json_body=payload))
        ex = HackerOneExtractor(
            http_factory=factory,
            llm_extractor=_make_llm_extractor(_good_extracted_scope()),
            credential_lookup=_credential_returning(),
        )
        result = await ex.extract("hackerone:test")
        assert result is not None
        assert len(result.scope_rules) == 1


# ─────────────────────────── API path: LLM on policy text ──────────

class TestApiPathLlmOnPolicy:
    async def test_policy_text_passed_to_llm_extractor(self):
        llm = _make_llm_extractor(_good_extracted_scope())
        factory = _make_factory(_FakeResponse(json_body=_h1_api_payload(
            policy="UNIQUE_POLICY_MARKER The program permits researchers...",
        )))
        ex = HackerOneExtractor(
            http_factory=factory,
            llm_extractor=llm,
            credential_lookup=_credential_returning(),
        )
        await ex.extract("hackerone:test")
        assert len(llm.calls) == 1
        assert "UNIQUE_POLICY_MARKER" in llm.calls[0]

    async def test_personas_from_llm_appear_in_scope(self):
        factory = _make_factory(_FakeResponse(json_body=_h1_api_payload()))
        ex = HackerOneExtractor(
            http_factory=factory,
            llm_extractor=_make_llm_extractor(_good_extracted_scope()),
            credential_lookup=_credential_returning(),
        )
        result = await ex.extract("hackerone:test")
        assert result is not None
        assert len(result.personas) == 1
        assert result.personas[0].username == "researcher@example.com"

    async def test_restrictions_from_llm_appear_in_scope(self):
        factory = _make_factory(_FakeResponse(json_body=_h1_api_payload()))
        ex = HackerOneExtractor(
            http_factory=factory,
            llm_extractor=_make_llm_extractor(_good_extracted_scope()),
            credential_lookup=_credential_returning(),
        )
        result = await ex.extract("hackerone:test")
        assert result is not None
        assert len(result.restrictions) == 1
        assert "DoS" in result.restrictions[0].description

    async def test_empty_policy_text_skips_llm(self):
        llm = _make_llm_extractor(_good_extracted_scope())
        factory = _make_factory(_FakeResponse(json_body=_h1_api_payload(policy="")))
        ex = HackerOneExtractor(
            http_factory=factory,
            llm_extractor=llm,
            credential_lookup=_credential_returning(),
        )
        result = await ex.extract("hackerone:test")
        # We got a ProgramScope (with scope rules only).
        assert result is not None
        # LLM was NOT called for empty policy.
        assert llm.calls == []

    async def test_llm_failure_doesnt_break_scope_extraction(self):
        # If the LLM blows up, we still get a usable ProgramScope from
        # the structured API data — just without personas/restrictions.
        async def crashing_llm(text):
            raise RuntimeError("LLM unavailable")
        factory = _make_factory(_FakeResponse(json_body=_h1_api_payload(
            scopes=[_h1_scope_item(identifier="x.com")],
        )))
        ex = HackerOneExtractor(
            http_factory=factory,
            llm_extractor=crashing_llm,
            credential_lookup=_credential_returning(),
        )
        result = await ex.extract("hackerone:test")
        assert result is not None
        assert len(result.scope_rules) == 1
        assert result.personas == []
        assert result.restrictions == []


# ─────────────────────────── Provenance metadata ───────────────────

class TestProvenance:
    async def test_platform_set_to_hackerone(self):
        factory = _make_factory(_FakeResponse(json_body=_h1_api_payload()))
        ex = HackerOneExtractor(
            http_factory=factory,
            llm_extractor=_make_llm_extractor(_good_extracted_scope()),
            credential_lookup=_credential_returning(),
        )
        result = await ex.extract("hackerone:test")
        assert result.platform == Platform.HACKERONE

    async def test_handle_set_from_identifier(self):
        factory = _make_factory(_FakeResponse(json_body=_h1_api_payload()))
        ex = HackerOneExtractor(
            http_factory=factory,
            llm_extractor=_make_llm_extractor(_good_extracted_scope()),
            credential_lookup=_credential_returning(),
        )
        result = await ex.extract("hackerone:security")
        assert result.handle == "security"

    async def test_extractor_version_marks_api_path(self):
        factory = _make_factory(_FakeResponse(json_body=_h1_api_payload()))
        ex = HackerOneExtractor(
            http_factory=factory,
            llm_extractor=_make_llm_extractor(_good_extracted_scope()),
            credential_lookup=_credential_returning(),
        )
        result = await ex.extract("hackerone:test")
        # Version 2.0 (API path) — proves the new code path ran, not the old scraping.
        assert "hackerone@2.0+api+" in result.extractor_version

    async def test_program_name_from_api_attributes_not_handle(self):
        factory = _make_factory(_FakeResponse(json_body=_h1_api_payload(
            name="GitLab Bug Bounty",
        )))
        ex = HackerOneExtractor(
            http_factory=factory,
            llm_extractor=_make_llm_extractor(_good_extracted_scope()),
            credential_lookup=_credential_returning("h", "T"),
        )
        result = await ex.extract("hackerone:gitlab")
        # name should be the H1-supplied display name, not the handle.
        assert result.name == "GitLab Bug Bounty"

    async def test_source_url_is_api_endpoint(self):
        # source_url should reflect where we actually fetched, not the
        # web policy URL (which we didn't fetch).
        factory = _make_factory(_FakeResponse(json_body=_h1_api_payload()))
        ex = HackerOneExtractor(
            http_factory=factory,
            llm_extractor=_make_llm_extractor(_good_extracted_scope()),
            credential_lookup=_credential_returning(),
        )
        result = await ex.extract("hackerone:test")
        assert result.source_url == "https://api.hackerone.com/v1/hackers/programs/test"


# ─────────────────────────── Identifier validation ─────────────────

class TestIdentifierValidation:
    async def test_invalid_handle_with_slash_raises(self):
        ex = HackerOneExtractor(credential_lookup=_credential_returning())
        with pytest.raises(ExtractorError, match="not a valid program handle"):
            await ex.extract("hackerone:foo/bar")

    async def test_invalid_handle_with_uppercase_raises(self):
        ex = HackerOneExtractor(credential_lookup=_credential_returning())
        with pytest.raises(ExtractorError, match="not a valid program handle"):
            await ex.extract("hackerone:GitLab")

    async def test_empty_handle_raises(self):
        ex = HackerOneExtractor(credential_lookup=_credential_returning())
        with pytest.raises(ExtractorError, match="not a valid program handle"):
            await ex.extract("hackerone:")

    async def test_non_hackerone_url_raises_cannot_handle(self):
        ex = HackerOneExtractor(credential_lookup=_credential_returning())
        with pytest.raises(ExtractorError, match="cannot handle"):
            await ex.extract("https://example.com/")
