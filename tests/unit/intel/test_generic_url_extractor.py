"""
Tests for GenericUrlExtractor (Phase 2A).

We mock the HTTP fetch and the LLM extraction so tests are deterministic
and offline. The pieces under test are:

  1. ``can_handle`` correctly accepts http(s) URLs and rejects everything else
  2. End-to-end ``extract`` produces a fully-populated ``ProgramScope``
     with provenance fields filled (source_url, fetched_at, hash, version)
  3. HTTP errors (4xx/5xx, network exceptions, non-text content) return
     ``None`` — soft failure
  4. The HTML sanitizer strips ``<script>``, ``<nav>``, etc., and prefers
     ``<main>`` over ``<body>`` when both exist
  5. ``raw_content_hash`` is the hash of the *sanitized* text, not raw HTML
     — so cosmetic HTML changes don't invalidate the cache
"""
from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Optional
from unittest.mock import MagicMock

import pytest

from core.intel.extractors.base import ExtractorError
from core.intel.extractors.generic_url import GenericUrlExtractor
from core.intel.llm_extraction import (
    ExtractedScope,
    ExtractedScopeRule,
    ExtractedPersona,
    ExtractedRestriction,
)
from core.intel.program_scope import (
    Platform,
    ProgramScope,
    RestrictionKind,
    ScopeRuleType,
    content_hash,
)


# ─────────────────────────── Test doubles ──────────────────────────

class _FakeResponse:
    def __init__(self, *, status_code: int = 200, text: str = "",
                 content_type: str = "text/html; charset=utf-8"):
        self.status_code = status_code
        self.text = text
        self.headers = {"content-type": content_type}


class _FakeClient:
    """Async context manager that records GET calls and returns programmed responses."""

    def __init__(self, response):
        self.response = response
        self.gets: list[tuple] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False

    async def get(self, url, **kwargs):
        self.gets.append((url, kwargs))
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


def _make_http_factory(response):
    """Build an http_factory callable that returns a _FakeClient."""
    client = _FakeClient(response)
    def factory():
        return client
    factory.client = client  # for inspection
    return factory


def _make_llm_extractor(returns: Optional[ExtractedScope]):
    """Build a mock LLM extractor that records its calls."""
    calls: list[str] = []

    async def fake(text: str):
        calls.append(text)
        return returns

    fake.calls = calls
    return fake


def _good_extracted_scope() -> ExtractedScope:
    return ExtractedScope(
        name="Example Bug Bounty",
        scope_rules=[
            ExtractedScopeRule(pattern="*.example.com", rule_type="domain", in_scope=True),
            ExtractedScopeRule(pattern="internal.example.com", rule_type="domain", in_scope=False),
        ],
        personas=[
            ExtractedPersona(
                name="researcher",
                persona_type="user",
                base_url="https://example.com",
                username="test@example.com",
                password="known-pass",
            ),
        ],
        signup_endpoint="/signup",
        restrictions=[
            ExtractedRestriction(
                kind="no_dos", severity="hard",
                description="No DoS testing.",
                raw_quote="DoS or load testing is strictly prohibited.",
            ),
        ],
        rate_limit_rps=10.0,
        payout_max_usd=5000,
        extraction_confidence=0.88,
    )


# ─────────────────────────── can_handle ────────────────────────────

class TestCanHandle:
    def setup_method(self):
        self.ex = GenericUrlExtractor()

    def test_accepts_https_url(self):
        assert self.ex.can_handle("https://example.com/bug-bounty")

    def test_accepts_http_url(self):
        assert self.ex.can_handle("http://example.com/")

    def test_rejects_handle(self):
        # A bare handle like "gitlab" isn't a URL — platform-specific
        # extractors should resolve handles, not generic_url.
        assert not self.ex.can_handle("gitlab")

    def test_rejects_relative_path(self):
        assert not self.ex.can_handle("/bug-bounty")

    def test_rejects_unknown_scheme(self):
        assert not self.ex.can_handle("ftp://example.com/policy.txt")
        assert not self.ex.can_handle("file:///etc/policy")

    def test_rejects_empty_and_none_safe(self):
        assert not self.ex.can_handle("")
        # Should not crash on None — uses try/except on urlparse.
        assert not self.ex.can_handle(None)  # type: ignore[arg-type]


# ─────────────────────────── End-to-end happy path ─────────────────

class TestExtractHappyPath:
    async def test_returns_program_scope_with_provenance(self):
        html = "<html><body><main><h1>Bug Bounty</h1><p>policy text</p></main></body></html>"
        ex = GenericUrlExtractor(
            http_factory=_make_http_factory(_FakeResponse(text=html)),
            llm_extractor=_make_llm_extractor(_good_extracted_scope()),
        )
        result = await ex.extract("https://example.com/bug-bounty")

        assert isinstance(result, ProgramScope)
        # Identity
        assert result.platform == Platform.DIRECT_URL
        assert result.handle is None
        assert result.source_url == "https://example.com/bug-bounty"
        assert result.name == "Example Bug Bounty"
        # Provenance
        assert result.raw_content_hash != ""
        assert len(result.raw_content_hash) == 64  # sha256 hex
        assert result.extractor_version.startswith("generic_url@1.0+llm_extraction@")
        assert result.extraction_confidence == 0.88
        assert result.fetched_at is not None
        # Substance — fields translated from ExtractedScope
        assert len(result.scope_rules) == 2
        assert any(r.in_scope and r.pattern == "*.example.com" for r in result.scope_rules)
        assert any(not r.in_scope and r.pattern == "internal.example.com" for r in result.scope_rules)
        assert len(result.personas) == 1
        assert result.personas[0].username == "test@example.com"
        assert result.signup_endpoint == "/signup"
        assert len(result.restrictions) == 1
        assert result.restrictions[0].kind == RestrictionKind.NO_DOS
        assert result.rate_limit_rps == 10.0
        assert result.payout_max_usd == 5000

    async def test_raises_on_non_url_identifier(self):
        ex = GenericUrlExtractor(
            http_factory=_make_http_factory(_FakeResponse(text="x")),
            llm_extractor=_make_llm_extractor(_good_extracted_scope()),
        )
        with pytest.raises(ExtractorError):
            await ex.extract("not-a-url")


# ─────────────────────────── HTTP error paths ──────────────────────

class TestHttpErrorHandling:
    async def test_returns_none_on_4xx(self):
        ex = GenericUrlExtractor(
            http_factory=_make_http_factory(_FakeResponse(status_code=404, text="not found")),
            llm_extractor=_make_llm_extractor(_good_extracted_scope()),
        )
        assert await ex.extract("https://example.com/missing") is None

    async def test_returns_none_on_5xx(self):
        ex = GenericUrlExtractor(
            http_factory=_make_http_factory(_FakeResponse(status_code=503)),
            llm_extractor=_make_llm_extractor(_good_extracted_scope()),
        )
        assert await ex.extract("https://example.com/down") is None

    async def test_returns_none_on_network_exception(self):
        import httpx
        ex = GenericUrlExtractor(
            http_factory=_make_http_factory(httpx.ConnectError("dns fail")),
            llm_extractor=_make_llm_extractor(_good_extracted_scope()),
        )
        assert await ex.extract("https://no-such-host.example/") is None

    async def test_returns_none_on_non_text_content_type(self):
        ex = GenericUrlExtractor(
            http_factory=_make_http_factory(_FakeResponse(
                text='{"json":"is not policy text"}',
                content_type="application/json",
            )),
            llm_extractor=_make_llm_extractor(_good_extracted_scope()),
        )
        assert await ex.extract("https://example.com/api") is None

    async def test_accepts_text_markdown(self):
        ex = GenericUrlExtractor(
            http_factory=_make_http_factory(_FakeResponse(
                text="# Bug Bounty Policy\n\nIn scope: *.example.com",
                content_type="text/markdown; charset=utf-8",
            )),
            llm_extractor=_make_llm_extractor(_good_extracted_scope()),
        )
        result = await ex.extract("https://raw.githubusercontent.com/x/y/main/security.md")
        assert result is not None

    async def test_returns_none_when_llm_extraction_fails(self):
        ex = GenericUrlExtractor(
            http_factory=_make_http_factory(_FakeResponse(text="<html>policy</html>")),
            llm_extractor=_make_llm_extractor(None),  # LLM returned nothing
        )
        assert await ex.extract("https://example.com/") is None


# ─────────────────────────── Sanitizer behavior ────────────────────

class TestSanitizer:
    def setup_method(self):
        self.ex = GenericUrlExtractor()

    def test_strips_script_tags(self):
        html = "<html><body><script>alert('xss')</script><p>real content</p></body></html>"
        cleaned = self.ex._sanitize(html)
        assert "alert" not in cleaned
        assert "xss" not in cleaned
        assert "real content" in cleaned

    def test_strips_style_tags(self):
        html = "<html><body><style>.foo{color:red}</style><p>policy</p></body></html>"
        cleaned = self.ex._sanitize(html)
        assert "color:red" not in cleaned
        assert "policy" in cleaned

    def test_strips_nav_and_footer(self):
        html = """
        <html><body>
          <nav>Home About Contact</nav>
          <main><h1>Bug Bounty</h1><p>scope is *.example.com</p></main>
          <footer>copyright 2026</footer>
        </body></html>
        """
        cleaned = self.ex._sanitize(html)
        # Main content preserved
        assert "Bug Bounty" in cleaned
        assert "*.example.com" in cleaned
        # Noise stripped
        assert "Home About Contact" not in cleaned
        assert "copyright" not in cleaned

    def test_prefers_main_over_body(self):
        # If <main> is present, body-level text outside it should be
        # excluded.
        html = """
        <html><body>
          <p>this is outside main and should be stripped</p>
          <main><p>this is the policy content</p></main>
        </body></html>
        """
        cleaned = self.ex._sanitize(html)
        assert "policy content" in cleaned
        assert "outside main" not in cleaned

    def test_falls_back_to_body_when_no_main(self):
        # Plain HTML without <main> should still produce text.
        html = "<html><body><p>just body content</p></body></html>"
        cleaned = self.ex._sanitize(html)
        assert "just body content" in cleaned

    def test_strips_html_comments(self):
        html = "<html><body><!-- giant block of commented HTML --><p>content</p></body></html>"
        cleaned = self.ex._sanitize(html)
        assert "giant block" not in cleaned
        assert "content" in cleaned

    def test_collapses_excessive_whitespace(self):
        html = "<html><body><p>a</p>\n\n\n\n\n<p>b</p></body></html>"
        cleaned = self.ex._sanitize(html)
        # No run of 3+ blank lines anywhere.
        assert "\n\n\n" not in cleaned


# ─────────────────────────── Hash is over sanitized text ───────────

class TestRawContentHash:
    async def test_hash_is_over_sanitized_not_raw_html(self):
        # Two HTML inputs with different cosmetic markup but the same
        # cleaned text should produce the same hash. This is the
        # cache-invalidation contract — cosmetic HTML changes should not
        # invalidate the cache, only substantive content changes should.
        html_v1 = "<html><body><main><p>real policy text</p></main></body></html>"
        html_v2 = """<html>
            <body class="newClass">
              <main id="newId">
                <p>real policy text</p>
              </main>
            </body>
          </html>"""

        scope_v1 = await GenericUrlExtractor(
            http_factory=_make_http_factory(_FakeResponse(text=html_v1)),
            llm_extractor=_make_llm_extractor(_good_extracted_scope()),
        ).extract("https://example.com/")

        scope_v2 = await GenericUrlExtractor(
            http_factory=_make_http_factory(_FakeResponse(text=html_v2)),
            llm_extractor=_make_llm_extractor(_good_extracted_scope()),
        ).extract("https://example.com/")

        assert scope_v1 is not None and scope_v2 is not None
        # Same semantic content → same hash. Markup variation is invisible.
        assert scope_v1.raw_content_hash == scope_v2.raw_content_hash

    async def test_hash_changes_when_content_changes(self):
        html_a = "<html><body><main><p>policy A</p></main></body></html>"
        html_b = "<html><body><main><p>policy B</p></main></body></html>"

        scope_a = await GenericUrlExtractor(
            http_factory=_make_http_factory(_FakeResponse(text=html_a)),
            llm_extractor=_make_llm_extractor(_good_extracted_scope()),
        ).extract("https://example.com/")

        scope_b = await GenericUrlExtractor(
            http_factory=_make_http_factory(_FakeResponse(text=html_b)),
            llm_extractor=_make_llm_extractor(_good_extracted_scope()),
        ).extract("https://example.com/")

        assert scope_a is not None and scope_b is not None
        assert scope_a.raw_content_hash != scope_b.raw_content_hash


# ─────────────────────────── LLM input quality ─────────────────────

class TestLlmReceivesCleanedText:
    async def test_llm_called_with_sanitized_text(self):
        html = "<html><body><script>alert('x')</script><main><p>actual policy</p></main></body></html>"
        llm = _make_llm_extractor(_good_extracted_scope())
        ex = GenericUrlExtractor(
            http_factory=_make_http_factory(_FakeResponse(text=html)),
            llm_extractor=llm,
        )
        await ex.extract("https://example.com/")

        # The LLM was called exactly once with text containing the
        # policy but not the script.
        assert len(llm.calls) == 1
        passed_text = llm.calls[0]
        assert "actual policy" in passed_text
        assert "alert" not in passed_text
