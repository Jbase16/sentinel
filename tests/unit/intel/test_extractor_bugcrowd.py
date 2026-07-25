"""
Tests for BugcrowdExtractor (Phase 2B).

Mirrors the HackerOne adapter's test structure since the two share the
same composition-over-inheritance pattern. The contracts under test:

  1. can_handle: ``bugcrowd:<handle>`` and ``bugcrowd.com`` URLs accepted.
  2. URL resolution: ``bugcrowd:tesla`` → ``https://bugcrowd.com/tesla``
     (note: NO ``/policy`` suffix — Bugcrowd uses the bare handle URL).
  3. Result has ``platform == BUGCROWD`` and the correct handle.
  4. ``extractor_version`` is the Bugcrowd stamp, not the generic one.
  5. Invalid handles raise ``ExtractorError``.
  6. Soft failures pass through as None.
"""
from __future__ import annotations

from typing import Optional

import pytest

from core.intel.extractors.base import ExtractorError
from core.intel.extractors.bugcrowd import BugcrowdExtractor
from core.intel.llm_extraction import ExtractedScope, ExtractedScopeRule
from core.intel.program_scope import Platform


class _FakeResponse:
    def __init__(self, *, status_code=200, text="<html><body><main>policy</main></body></html>",
                 content_type="text/html"):
        self.status_code = status_code
        self.text = text
        self.headers = {"content-type": content_type}


class _FakeClient:
    def __init__(self, response):
        self.response = response
        self.gets: list = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False

    async def get(self, url, **kwargs):
        self.gets.append(url)
        return self.response


def _make_factory(response=None):
    if response is None:
        response = _FakeResponse()
    client = _FakeClient(response)

    def factory():
        return client

    factory.client = client
    return factory


def _make_llm_extractor(returns):
    async def fake(text):
        return returns
    return fake


def _good_extraction():
    return ExtractedScope(
        name="Test Bugcrowd Program",
        scope_rules=[
            ExtractedScopeRule(pattern="*.test.com", rule_type="domain", in_scope=True),
        ],
        extraction_confidence=0.82,
    )


# ─────────────────────────── can_handle ────────────────────────────

class TestCanHandle:
    def setup_method(self):
        self.ex = BugcrowdExtractor()

    def test_accepts_prefix_form(self):
        assert self.ex.can_handle("bugcrowd:tesla")

    def test_accepts_bugcrowd_url(self):
        assert self.ex.can_handle("https://bugcrowd.com/tesla")

    def test_accepts_www_bugcrowd_url(self):
        assert self.ex.can_handle("https://www.bugcrowd.com/tesla")

    def test_rejects_hackerone_url(self):
        assert not self.ex.can_handle("https://hackerone.com/gitlab")

    def test_rejects_hackerone_prefix(self):
        assert not self.ex.can_handle("hackerone:gitlab")

    def test_rejects_bare_handle(self):
        assert not self.ex.can_handle("tesla")

    def test_rejects_other_url(self):
        assert not self.ex.can_handle("https://example.com/")

    def test_rejects_empty_and_none(self):
        assert not self.ex.can_handle("")
        assert not self.ex.can_handle(None)  # type: ignore[arg-type]


# ─────────────────────────── URL resolution ────────────────────────

class TestUrlResolution:
    async def test_prefix_form_builds_canonical_url(self):
        # Bugcrowd uses the bare handle URL — no /policy suffix.
        factory = _make_factory()
        ex = BugcrowdExtractor(
            http_factory=factory,
            llm_extractor=_make_llm_extractor(_good_extraction()),
        )
        await ex.extract("bugcrowd:tesla")
        assert factory.client.gets == ["https://bugcrowd.com/tesla"]

    async def test_full_url_passed_through(self):
        factory = _make_factory()
        ex = BugcrowdExtractor(
            http_factory=factory,
            llm_extractor=_make_llm_extractor(_good_extraction()),
        )
        await ex.extract("https://bugcrowd.com/tesla")
        assert factory.client.gets == ["https://bugcrowd.com/tesla"]


# ─────────────────────────── Platform stamp ────────────────────────

class TestPlatformStamp:
    async def test_result_has_platform_bugcrowd(self):
        ex = BugcrowdExtractor(
            http_factory=_make_factory(),
            llm_extractor=_make_llm_extractor(_good_extraction()),
        )
        result = await ex.extract("bugcrowd:tesla")
        assert result is not None
        assert result.platform == Platform.BUGCROWD

    async def test_result_has_resolved_handle(self):
        ex = BugcrowdExtractor(
            http_factory=_make_factory(),
            llm_extractor=_make_llm_extractor(_good_extraction()),
        )
        result = await ex.extract("bugcrowd:tesla")
        assert result is not None
        assert result.handle == "tesla"

    async def test_extractor_version_is_bugcrowd_not_generic(self):
        ex = BugcrowdExtractor(
            http_factory=_make_factory(),
            llm_extractor=_make_llm_extractor(_good_extraction()),
        )
        result = await ex.extract("bugcrowd:tesla")
        assert result is not None
        assert result.extractor_version.startswith("bugcrowd@1.0+llm_extraction@")
        assert "generic_url" not in result.extractor_version
        assert "hackerone" not in result.extractor_version


# ─────────────────────────── Invalid handle ────────────────────────

class TestInvalidHandle:
    async def test_handle_with_slashes_rejected(self):
        ex = BugcrowdExtractor(
            http_factory=_make_factory(),
            llm_extractor=_make_llm_extractor(_good_extraction()),
        )
        with pytest.raises(ExtractorError, match="not a valid program handle"):
            await ex.extract("bugcrowd:foo/bar")

    async def test_handle_with_uppercase_rejected(self):
        ex = BugcrowdExtractor(
            http_factory=_make_factory(),
            llm_extractor=_make_llm_extractor(_good_extraction()),
        )
        with pytest.raises(ExtractorError, match="not a valid program handle"):
            await ex.extract("bugcrowd:Tesla")

    async def test_empty_handle_rejected(self):
        ex = BugcrowdExtractor(
            http_factory=_make_factory(),
            llm_extractor=_make_llm_extractor(_good_extraction()),
        )
        with pytest.raises(ExtractorError, match="not a valid program handle"):
            await ex.extract("bugcrowd:")

    async def test_url_with_no_path_rejected(self):
        ex = BugcrowdExtractor(
            http_factory=_make_factory(),
            llm_extractor=_make_llm_extractor(_good_extraction()),
        )
        with pytest.raises(ExtractorError, match="no path|not a valid program handle"):
            await ex.extract("https://bugcrowd.com/")

    async def test_non_bugcrowd_url_raises(self):
        ex = BugcrowdExtractor(
            http_factory=_make_factory(),
            llm_extractor=_make_llm_extractor(_good_extraction()),
        )
        with pytest.raises(ExtractorError, match="cannot handle"):
            await ex.extract("https://example.com/")


# ─────────────────────────── Soft failures pass through ────────────

class TestSoftFailuresPassThrough:
    async def test_returns_none_when_http_fails(self):
        ex = BugcrowdExtractor(
            http_factory=_make_factory(_FakeResponse(status_code=404)),
            llm_extractor=_make_llm_extractor(_good_extraction()),
        )
        result = await ex.extract("bugcrowd:tesla")
        assert result is None

    async def test_returns_none_when_llm_fails(self):
        ex = BugcrowdExtractor(
            http_factory=_make_factory(),
            llm_extractor=_make_llm_extractor(None),
        )
        result = await ex.extract("bugcrowd:tesla")
        assert result is None


# ─────────────────────────── Cross-adapter isolation ───────────────

class TestCrossAdapterIsolation:
    """Bugcrowd extractor MUST NOT accidentally claim HackerOne identifiers.

    This is the contract that makes the resolver's priority ordering
    actually useful — without it, adding a new adapter could silently
    hijack identifiers another adapter handled."""

    def test_bugcrowd_rejects_hackerone_handle_prefix(self):
        ex = BugcrowdExtractor()
        assert not ex.can_handle("hackerone:gitlab")

    def test_bugcrowd_rejects_hackerone_urls_even_subpath(self):
        ex = BugcrowdExtractor()
        assert not ex.can_handle("https://hackerone.com/gitlab/policy")
