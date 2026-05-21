"""
GenericUrlExtractor — the LLM-only fallback extractor.

Given any URL, it:

  1. Fetches the page over HTTP via ``core.net.http_factory`` (so TLS,
     timeout, redirect policy are uniform with the rest of Sentinel).
  2. Sanitizes the response — strips script/style/nav, isolates the
     main content area when one is identifiable, normalizes whitespace.
  3. Sends the cleaned text to the LLM extraction layer.
  4. Wraps the LLM's output in a ``ProgramScope`` with provenance
     (source_url, fetched_at, raw_content_hash, extractor_version).

This is the *fallback* extractor — anything goes here. Platform-specific
extractors (HackerOne, Bugcrowd) ship later and do strictly better on
their domains because they understand the page structure. But for any
program hosted outside those platforms, this is the workhorse.

Design notes:

  - ``raw_content_hash`` is the SHA-256 of the **sanitized** text, not
    the raw HTML, so cosmetic HTML changes (asset URLs, build hashes
    in CSS classes) don't invalidate the cache. Substantive policy
    changes — the actual words — do invalidate it.
  - The sanitizer prefers ``<main>``, ``<article>``, or ``#content``-style
    container ids over the full body. Most policy pages have a clear
    content region; isolating it cuts the LLM input by 50-80% and
    improves extraction accuracy.
  - Non-2xx responses, content-type that isn't text/html/markdown/plain,
    and empty bodies all return ``None`` (soft failure). Malformed URLs
    raise ``ExtractorError`` (hard).
"""
from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

from bs4 import BeautifulSoup, Comment

from core.intel.extractors.base import Extractor, ExtractorError
from core.intel.llm_extraction import (
    EXTRACTOR_VERSION as LLM_VERSION,
    ExtractedScope,
    extract_scope_with_llm,
    to_persona,
    to_restriction,
    to_scope_rule,
)
from core.intel.program_scope import (
    Platform,
    ProgramScope,
    content_hash,
)

logger = logging.getLogger(__name__)


# Tags that are pure noise on a policy page — they should never carry
# extractable signal and they bloat the LLM input.
_NOISE_TAGS = (
    "script", "style", "noscript", "iframe", "svg", "canvas",
    "nav", "footer", "header", "aside", "form",
)

# Candidate selectors for the main content region, in priority order.
# The first match wins; if none match, we fall back to <body>.
_MAIN_CONTENT_SELECTORS = (
    "main",
    "article",
    "[role='main']",
    "#main-content",
    "#content",
    "#policy",
    ".policy",
    ".program-policy",
    ".markdown-body",  # GitHub README rendering
)

# Heuristic: collapse runs of 3+ blank lines to two, which is plenty
# for the LLM to grok structure.
_BLANK_RUN = re.compile(r"\n{3,}")
_WHITESPACE_RUN = re.compile(r"[ \t]+")


class GenericUrlExtractor(Extractor):
    """Fetches an arbitrary URL and runs LLM-only extraction.

    Use this when no platform-specific extractor matches the input.
    """

    name = "generic_url"
    version = "1.0"

    def __init__(
        self,
        *,
        http_factory=None,
        llm_extractor=extract_scope_with_llm,
    ):
        """Both dependencies are injectable for testing.

        ``http_factory`` should be a callable returning an
        ``httpx.AsyncClient`` (typically
        ``core.net.http_factory.create_async_client``). Tests pass a
        mock that returns a fake client.

        ``llm_extractor`` is the async function that takes policy text
        and returns ``ExtractedScope | None``. Tests pass a mock.
        """
        self._http_factory = http_factory
        self._llm_extractor = llm_extractor

    # ─── Extractor protocol ───────────────────────────────────────────

    def can_handle(self, identifier: str) -> bool:
        """Generic URL extractor handles anything that parses as an
        absolute http/https URL. It's intentionally the broadest matcher
        — it's the fallback. The resolver should consult it last."""
        try:
            parsed = urlparse(identifier)
        except (ValueError, AttributeError):
            return False
        return parsed.scheme in ("http", "https") and bool(parsed.netloc)

    async def extract(self, identifier: str) -> Optional[ProgramScope]:
        if not self.can_handle(identifier):
            raise ExtractorError(
                f"GenericUrlExtractor cannot handle {identifier!r} "
                "— expected an absolute http(s) URL."
            )

        # Step 1: fetch the page.
        raw_html = await self._fetch(identifier)
        if raw_html is None:
            return None

        # Step 2: sanitize.
        cleaned_text = self._sanitize(raw_html)
        if not cleaned_text.strip():
            logger.warning("[intel.generic_url] sanitized text empty for %s", identifier)
            return None

        # Step 3: LLM extraction.
        extracted: Optional[ExtractedScope] = await self._llm_extractor(cleaned_text)
        if extracted is None:
            logger.warning("[intel.generic_url] LLM extraction returned None for %s", identifier)
            return None

        # Step 4: build the ProgramScope with provenance.
        return ProgramScope(
            handle=None,                              # Generic URL has no platform handle
            platform=Platform.DIRECT_URL,
            name=extracted.name,
            source_url=identifier,
            fetched_at=datetime.now(timezone.utc),
            scope_rules=[to_scope_rule(r) for r in extracted.scope_rules],
            personas=[to_persona(p) for p in extracted.personas],
            signup_endpoint=extracted.signup_endpoint,
            restrictions=[to_restriction(r) for r in extracted.restrictions],
            rate_limit_rps=extracted.rate_limit_rps,
            payout_max_usd=extracted.payout_max_usd,
            raw_content_hash=content_hash(cleaned_text),
            extractor_version=f"{self.version_stamp}+{LLM_VERSION}",
            extraction_confidence=extracted.extraction_confidence,
        )

    # ─── Internals ────────────────────────────────────────────────────

    async def _fetch(self, url: str) -> Optional[str]:
        """Fetch a URL, return the body text or None on any HTTP error."""
        # Lazy import so the module loads without network config.
        if self._http_factory is None:
            from core.net.http_factory import create_async_client
            factory = create_async_client
        else:
            factory = self._http_factory

        try:
            async with factory() as client:
                response = await client.get(
                    url,
                    headers={
                        # A vanilla browser-ish UA so we don't get
                        # spurious 403s from anti-bot heuristics on
                        # platform pages. This is policy-page fetch,
                        # not active scanning — UA spoofing is fine.
                        "User-Agent": (
                            "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) "
                            "SentinelForge/Phase2-intel"
                        ),
                    },
                )
        except Exception as e:  # noqa: BLE001 - any fetch failure is a soft fail
            logger.warning("[intel.generic_url] fetch failed for %s: %s", url, e)
            return None

        if response.status_code >= 400:
            logger.warning(
                "[intel.generic_url] HTTP %d fetching %s", response.status_code, url,
            )
            return None

        content_type = response.headers.get("content-type", "").lower()
        # Accept text/html, text/plain, text/markdown, application/xhtml+xml.
        # Reject application/json, images, etc. — the policy page is text.
        if not any(t in content_type for t in ("text/", "xhtml")):
            logger.warning(
                "[intel.generic_url] non-text content-type %r at %s",
                content_type, url,
            )
            return None

        return response.text

    def _sanitize(self, html: str) -> str:
        """Strip HTML noise, isolate the policy content area, return text.

        Heuristics:
          1. Remove all ``<script>``, ``<style>``, ``<nav>``, etc.
          2. Find a main content container if one is identifiable.
          3. Get text with structure-preserving newlines.
          4. Normalize whitespace.
        """
        soup = BeautifulSoup(html, "html.parser")

        # Drop comments — they sometimes contain large blocks of HTML
        # comments that bloat the LLM input.
        for c in soup.find_all(string=lambda s: isinstance(s, Comment)):
            c.extract()

        # Strip noise tags wholesale.
        for tag_name in _NOISE_TAGS:
            for tag in soup.find_all(tag_name):
                tag.decompose()

        # Try to find a main content region.
        main = None
        for selector in _MAIN_CONTENT_SELECTORS:
            try:
                main = soup.select_one(selector)
            except Exception:  # bs4 throws on some malformed selectors
                main = None
            if main is not None:
                break
        if main is None:
            main = soup.body or soup

        # Convert to text. ``get_text("\n")`` puts a newline between
        # block-level elements which preserves list / table structure
        # enough for the LLM.
        text = main.get_text("\n")

        # Collapse runs.
        text = _WHITESPACE_RUN.sub(" ", text)
        text = _BLANK_RUN.sub("\n\n", text)

        # Strip leading/trailing whitespace on each line.
        lines = [line.strip() for line in text.splitlines()]
        # Drop fully-empty lines except where they separate paragraphs.
        cleaned_lines: list[str] = []
        prev_blank = False
        for line in lines:
            if line:
                cleaned_lines.append(line)
                prev_blank = False
            elif not prev_blank:
                cleaned_lines.append("")
                prev_blank = True

        return "\n".join(cleaned_lines).strip()
