"""
Tests for the LLM extraction layer (Phase 2A).

The LLM itself is mocked — we're not testing whether Ollama produces
good extraction (that's an integration concern). We're testing:

  1. Valid model output produces a clean ExtractedScope.
  2. Invalid model output triggers one retry with the validation error
     appended to the prompt.
  3. Persistent invalid output returns None gracefully.
  4. None from the engine (circuit-breaker open) returns None immediately
     — no retry storm against a dead engine.
  5. Markdown-fenced model output is handled.
  6. The Pydantic → dataclass translators preserve all fields and
     coerce unknown enum values to OTHER (not crash).
"""
from __future__ import annotations

import json
from typing import List, Optional
from unittest.mock import AsyncMock

import pytest

from core.intel.llm_extraction import (
    EXTRACTOR_VERSION,
    ExtractedLoginFlow,
    ExtractedPersona,
    ExtractedRestriction,
    ExtractedScope,
    ExtractedScopeRule,
    extract_scope_with_llm,
    to_persona,
    to_restriction,
    to_scope_rule,
)
from core.intel.program_scope import (
    CredentialSource,
    RestrictionKind,
    ScopeRuleType,
    VerificationStatus,
)


class _MockEngine:
    """Stand-in for AIEngine with a programmable response queue.

    Each call to safe_generate pops the next response. Test passes
    responses as a list — None means "engine returned nothing".
    """

    def __init__(self, responses: List[Optional[str]]):
        self.responses = list(responses)
        self.calls: List[tuple] = []  # (prompt, system, force_json)

    async def safe_generate(self, prompt: str, system: str = "", force_json: bool = True) -> Optional[str]:
        self.calls.append((prompt, system, force_json))
        if not self.responses:
            return None
        return self.responses.pop(0)


def _valid_extraction_json(*, name: str = "Test Program", confidence: float = 0.85) -> str:
    return json.dumps({
        "name": name,
        "scope_rules": [
            {"pattern": "*.example.com", "rule_type": "domain",
             "in_scope": True, "notes": None}
        ],
        "personas": [],
        "signup_endpoint": None,
        "restrictions": [],
        "rate_limit_rps": None,
        "payout_max_usd": None,
        "extraction_confidence": confidence,
    })


# ─────────────────────────── Happy path ────────────────────────────

class TestExtractScopeWithLLM:
    async def test_returns_extracted_scope_on_valid_response(self):
        engine = _MockEngine([_valid_extraction_json()])

        result = await extract_scope_with_llm(
            "Some policy text here",
            ai_engine=engine,
        )

        assert result is not None
        assert isinstance(result, ExtractedScope)
        assert result.name == "Test Program"
        assert len(result.scope_rules) == 1
        assert result.scope_rules[0].pattern == "*.example.com"
        assert result.extraction_confidence == 0.85
        # Only one LLM call should have happened on the happy path.
        assert len(engine.calls) == 1

    async def test_returns_none_on_empty_input(self):
        engine = _MockEngine([_valid_extraction_json()])
        result = await extract_scope_with_llm("", ai_engine=engine)
        assert result is None
        # Crucial: we did NOT spend an LLM call on empty input.
        assert engine.calls == []

    async def test_handles_markdown_fenced_response(self):
        # Local models sometimes wrap JSON in ```json ... ``` despite
        # being told not to. _extract_json_payload should strip that.
        fenced = "```json\n" + _valid_extraction_json() + "\n```"
        engine = _MockEngine([fenced])
        result = await extract_scope_with_llm("policy", ai_engine=engine)
        assert result is not None
        assert result.name == "Test Program"


# ─────────────────────────── Retry behavior ────────────────────────

class TestRetryOnValidationFailure:
    async def test_retries_once_on_schema_error_then_succeeds(self):
        # First response is invalid JSON; second is valid.
        bad = '{"this is not": "valid", "missing": "name field"}'
        good = _valid_extraction_json()
        engine = _MockEngine([bad, good])

        result = await extract_scope_with_llm("policy", ai_engine=engine)

        assert result is not None
        assert result.name == "Test Program"
        # Two calls — the retry must have happened.
        assert len(engine.calls) == 2
        # The second call's prompt should contain the validation error
        # as a self-correction hint.
        second_prompt = engine.calls[1][0]
        assert "previous response failed validation" in second_prompt

    async def test_returns_none_after_persistent_validation_failures(self):
        engine = _MockEngine(['{"bad": "shape"}', '{"still": "bad"}'])
        result = await extract_scope_with_llm(
            "policy", ai_engine=engine, max_retries=1
        )
        assert result is None
        assert len(engine.calls) == 2  # initial + 1 retry

    async def test_max_retries_zero_means_no_retry(self):
        engine = _MockEngine(['{"bad": "shape"}', _valid_extraction_json()])
        result = await extract_scope_with_llm(
            "policy", ai_engine=engine, max_retries=0
        )
        assert result is None
        # Only one call — no retry because max_retries=0.
        assert len(engine.calls) == 1


# ─────────────────────────── Engine-unavailable path ───────────────

class TestEngineUnavailable:
    async def test_returns_none_when_engine_returns_none(self):
        engine = _MockEngine([None])
        result = await extract_scope_with_llm("policy", ai_engine=engine)
        assert result is None

    async def test_does_not_retry_when_engine_returns_none(self):
        # If the engine is down/circuit-broken, immediate retry won't
        # help — the breaker is already managing back-off. We should
        # bail after one attempt.
        engine = _MockEngine([None, _valid_extraction_json()])
        result = await extract_scope_with_llm(
            "policy", ai_engine=engine, max_retries=3
        )
        assert result is None
        assert len(engine.calls) == 1  # We did NOT consume the would-be-good 2nd response


# ─────────────────────────── Prompt construction ───────────────────

class TestPromptConstruction:
    async def test_system_prompt_warns_against_hallucination(self):
        engine = _MockEngine([_valid_extraction_json()])
        await extract_scope_with_llm("policy text", ai_engine=engine)
        system = engine.calls[0][1]
        # Confirm the anti-hallucination rule is in the system prompt.
        # If a refactor strips it, this test fires and points at why.
        assert "hallucin" in system.lower() or "guess" in system.lower()

    async def test_user_prompt_includes_policy_text(self):
        engine = _MockEngine([_valid_extraction_json()])
        await extract_scope_with_llm("UNIQUE_MARKER_POLICY_TEXT", ai_engine=engine)
        user = engine.calls[0][0]
        assert "UNIQUE_MARKER_POLICY_TEXT" in user

    async def test_force_json_is_requested(self):
        engine = _MockEngine([_valid_extraction_json()])
        await extract_scope_with_llm("policy", ai_engine=engine)
        force_json = engine.calls[0][2]
        assert force_json is True


# ─────────────────────────── Translator: to_scope_rule ─────────────

class TestToScopeRule:
    def test_preserves_pattern_and_in_scope(self):
        e = ExtractedScopeRule(
            pattern="*.foo.com", rule_type="domain",
            in_scope=True, notes="primary",
        )
        rule = to_scope_rule(e)
        assert rule.pattern == "*.foo.com"
        assert rule.rule_type == ScopeRuleType.DOMAIN
        assert rule.in_scope is True
        assert rule.notes == "primary"

    def test_out_of_scope_preserved(self):
        e = ExtractedScopeRule(
            pattern="admin.foo.com", rule_type="domain", in_scope=False,
        )
        assert to_scope_rule(e).in_scope is False

    def test_unknown_rule_type_coerces_to_other(self):
        # Future-proofing: the LLM might emit a label we haven't
        # enumerated. We should not crash — we coerce to OTHER.
        e = ExtractedScopeRule(
            pattern="??", rule_type="some-future-label", in_scope=True,
        )
        rule = to_scope_rule(e)
        assert rule.rule_type == ScopeRuleType.OTHER


# ─────────────────────────── Translator: to_persona ────────────────

class TestToPersona:
    def test_with_login_flow(self):
        e = ExtractedPersona(
            name="researcher",
            persona_type="user",
            base_url="https://x.com",
            username="test@x.com",
            password="hunter2",
            login_flow=ExtractedLoginFlow(
                endpoint="/api/login",
                method="POST",
                username_param="email",
                password_param="password",
                content_type="application/json",
            ),
            role_hint="standard user",
        )
        p = to_persona(e)
        assert p.name == "researcher"
        assert p.username == "test@x.com"
        assert p.password == "hunter2"
        assert p.role_hint == "standard user"
        assert p.login_flow is not None
        assert p.login_flow.endpoint == "/api/login"
        # Persona starts unverified — verifier sets that later.
        assert p.verified == VerificationStatus.UNVERIFIED
        # Source must be POLICY_EXPLICIT — that's where the LLM found it.
        assert p.source == CredentialSource.POLICY_EXPLICIT

    def test_without_login_flow(self):
        e = ExtractedPersona(
            name="anon",
            persona_type="anonymous",
            base_url="https://x.com",
        )
        p = to_persona(e)
        assert p.login_flow is None
        assert p.username is None
        assert p.password is None


# ─────────────────────────── Translator: to_restriction ────────────

class TestToRestriction:
    def test_known_kind_preserved(self):
        e = ExtractedRestriction(
            kind="no_dos",
            severity="hard",
            description="No DoS testing.",
            raw_quote="DoS is prohibited.",
        )
        r = to_restriction(e)
        assert r.kind == RestrictionKind.NO_DOS
        assert r.severity == "hard"
        assert r.raw_quote == "DoS is prohibited."

    def test_unknown_kind_coerces_to_other(self):
        e = ExtractedRestriction(
            kind="some_new_restriction_we_havent_added",
            severity="hard",
            description="x",
        )
        r = to_restriction(e)
        assert r.kind == RestrictionKind.OTHER

    def test_invalid_severity_coerces_to_soft(self):
        # Defensive: if the LLM emits "warning" or some other word
        # instead of "hard"/"soft", we default to soft rather than crash.
        e = ExtractedRestriction(
            kind="rate_limited",
            severity="warning",  # not allowed
            description="x",
        )
        r = to_restriction(e)
        assert r.severity == "soft"


# ─────────────────────────── Version sanity ────────────────────────

class TestExtractorVersion:
    def test_version_string_is_present_and_stable(self):
        # If this string is ever changed, all cached ProgramScope JSONs
        # become stale — that's intentional but it should be a deliberate
        # bump, not an accident.
        assert EXTRACTOR_VERSION.startswith("llm_extraction@")
        # Format: name@MAJOR.MINOR — split into 2 parts on @.
        _, version = EXTRACTOR_VERSION.split("@")
        assert "." in version


# ─────────────────────────── Chunked extraction (Run #18) ──────────

class TestChunkedExtraction:
    """Large policies are split + merged to avoid the one-shot timeout that
    GitLab's 25KB policy hit (Calibration Run #17)."""

    def test_chunk_policy_splits_on_paragraph_boundaries(self):
        from core.intel.llm_extraction import _chunk_policy
        # 3 paragraphs, each ~5k chars → with 10k chunk size, expect 2 chunks
        # (two paras fit in chunk 1, third in chunk 2) or similar grouping.
        paras = ["A" * 5000, "B" * 5000, "C" * 5000]
        text = "\n\n".join(paras)
        chunks = _chunk_policy(text, chunk_size=10_000)
        assert len(chunks) >= 2
        # No chunk should split a paragraph mid-way (each chunk is whole paras).
        rejoined = "\n\n".join(chunks)
        assert "A" * 5000 in rejoined
        assert "C" * 5000 in rejoined

    def test_chunk_policy_handles_oversized_single_paragraph(self):
        from core.intel.llm_extraction import _chunk_policy
        # One paragraph bigger than chunk_size → hard-split, not dropped.
        text = "X" * 25_000
        chunks = _chunk_policy(text, chunk_size=10_000)
        assert len(chunks) == 3  # 25000 / 10000 → 3 pieces
        assert "".join(chunks) == text  # nothing lost

    async def test_small_policy_uses_single_path(self):
        # Below threshold → single extraction (exactly one LLM call, no chunking).
        from core.intel.llm_extraction import CHUNK_THRESHOLD_CHARS
        engine = _MockEngine([_valid_extraction_json()])
        small = "x" * (CHUNK_THRESHOLD_CHARS - 1)
        result = await extract_scope_with_llm(small, ai_engine=engine)
        assert result is not None
        # Single path → one call. (Chunking would produce 2+.)
        assert len(engine.calls) == 1

    async def test_large_policy_chunks_and_merges(self):
        # A policy over the threshold → multiple LLM calls, merged result.
        from core.intel.llm_extraction import CHUNK_THRESHOLD_CHARS
        # Build two chunks worth of distinct content.
        big = ("A" * 9000) + "\n\n" + ("B" * 9000)
        assert len(big) > CHUNK_THRESHOLD_CHARS
        # Each chunk returns a different restriction so we can verify the merge.
        chunk1 = json.dumps({
            "name": "Prog", "scope_rules": [], "personas": [],
            "signup_endpoint": None,
            "restrictions": [{"kind": "no_dos", "severity": "hard",
                              "description": "No DoS", "applies_to": ["dos"]}],
            "rate_limit_rps": None, "extraction_confidence": 0.8,
        })
        chunk2 = json.dumps({
            "name": "Prog", "scope_rules": [], "personas": [],
            "signup_endpoint": None,
            "restrictions": [{"kind": "no_bruteforce", "severity": "hard",
                              "description": "No BF", "applies_to": ["bruteforce"]}],
            "rate_limit_rps": 5.0, "extraction_confidence": 0.6,
        })
        engine = _MockEngine([chunk1, chunk2])
        result = await extract_scope_with_llm(big, ai_engine=engine)
        assert result is not None
        # Both chunks' restrictions merged.
        kinds = {r.kind for r in result.restrictions}
        assert kinds == {"no_dos", "no_bruteforce"}
        # rate_limit_rps picked up from chunk2.
        assert result.rate_limit_rps == 5.0
        # Confidence is the minimum across chunks.
        assert result.extraction_confidence == 0.6
        # Two LLM calls (one per chunk).
        assert len(engine.calls) == 2

    async def test_large_policy_one_chunk_fails_other_succeeds(self):
        # If one chunk fails extraction, the successful chunk still yields
        # a usable partial result.
        big = ("A" * 9000) + "\n\n" + ("B" * 9000)
        good = json.dumps({
            "name": "Prog", "scope_rules": [], "personas": [],
            "signup_endpoint": None,
            "restrictions": [{"kind": "no_dos", "severity": "hard",
                              "description": "No DoS", "applies_to": ["dos"]}],
            "rate_limit_rps": None, "extraction_confidence": 0.7,
        })
        # chunk1 invalid JSON (fails after retry), chunk2 good.
        engine = _MockEngine(["{bad", "{bad-retry", good])
        result = await extract_scope_with_llm(big, ai_engine=engine, max_retries=1)
        assert result is not None
        assert len(result.restrictions) == 1

    async def test_large_policy_all_chunks_fail_returns_none(self):
        big = ("A" * 9000) + "\n\n" + ("B" * 9000)
        engine = _MockEngine(["{bad"] * 10)  # everything fails
        result = await extract_scope_with_llm(big, ai_engine=engine, max_retries=1)
        assert result is None

    def test_merge_dedups_restrictions(self):
        from core.intel.llm_extraction import _merge_extracted_scopes
        # Same restriction in two chunks → deduped.
        s1 = ExtractedScope(
            name="P", restrictions=[ExtractedRestriction(
                kind="no_dos", severity="hard", description="No DoS")],
            extraction_confidence=0.8)
        s2 = ExtractedScope(
            name="P", restrictions=[ExtractedRestriction(
                kind="no_dos", severity="hard", description="No DoS")],
            extraction_confidence=0.9)
        merged = _merge_extracted_scopes([s1, s2])
        assert len(merged.restrictions) == 1
        # Confidence is the minimum.
        assert merged.extraction_confidence == 0.8
