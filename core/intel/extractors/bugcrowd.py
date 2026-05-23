"""
Bugcrowd platform adapter.

Recognized identifier forms:

  - ``bugcrowd:<handle>``                  (explicit prefix)
  - ``https://bugcrowd.com/<handle>``
  - ``https://www.bugcrowd.com/<handle>``

Resolved canonical URL: ``https://bugcrowd.com/<handle>``
(Bugcrowd's program landing page IS the policy page — there's no
separate ``/policy`` path the way HackerOne has).

Implementation strategy:

  Mirrors ``HackerOneExtractor`` — delegate the fetch + sanitize +
  LLM pipeline to ``GenericUrlExtractor``, then stamp the resulting
  ``ProgramScope`` with ``Platform.BUGCROWD`` and the handle.

  Bugcrowd-specific niceties (researcher dashboard data, scope tables,
  payout tier extraction via API) come in Phase 2G when API tokens
  are wired up. For Phase 2B, identical pipeline as HackerOne with a
  different platform stamp.
"""
from __future__ import annotations

import logging
import re
from typing import Optional
from urllib.parse import urlparse

from core.intel.extractors.base import Extractor, ExtractorError
from core.intel.extractors.generic_url import GenericUrlExtractor
from core.intel.llm_extraction import (
    EXTRACTOR_VERSION as LLM_VERSION,
    extract_scope_with_llm,
)
from core.intel.program_scope import Platform, ProgramScope

logger = logging.getLogger(__name__)


# Bugcrowd handles share the same character class as HackerOne in practice.
# Real handles are kebab-case or snake_case, 1-64 chars.
_HANDLE_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_\-]{0,63}$")

_BUGCROWD_HOSTS = frozenset({"bugcrowd.com", "www.bugcrowd.com"})


class BugcrowdExtractor(Extractor):
    """Extract a ``ProgramScope`` from a Bugcrowd program identifier."""

    name = "bugcrowd"
    version = "1.0"

    def __init__(
        self,
        *,
        http_factory=None,
        llm_extractor=extract_scope_with_llm,
    ):
        self._generic = GenericUrlExtractor(
            http_factory=http_factory,
            llm_extractor=llm_extractor,
        )

    # ─── Extractor protocol ───────────────────────────────────────────

    def can_handle(self, identifier: str) -> bool:
        if not isinstance(identifier, str) or not identifier:
            return False
        if identifier.startswith("bugcrowd:"):
            return True
        if identifier.startswith(("http://", "https://")):
            try:
                netloc = urlparse(identifier).netloc.lower()
            except (ValueError, AttributeError):
                return False
            return netloc in _BUGCROWD_HOSTS
        return False

    async def extract(self, identifier: str) -> Optional[ProgramScope]:
        if not self.can_handle(identifier):
            raise ExtractorError(
                f"BugcrowdExtractor cannot handle {identifier!r} — expected "
                "'bugcrowd:<handle>' or a bugcrowd.com URL."
            )

        handle, canonical_url = self._resolve(identifier)

        scope = await self._generic.extract(canonical_url)
        if scope is None:
            return None

        scope.platform = Platform.BUGCROWD
        scope.handle = handle
        scope.extractor_version = f"{self.version_stamp}+{LLM_VERSION}"

        logger.info(
            "[intel.bugcrowd] extracted scope for handle=%s (confidence=%.2f)",
            handle, scope.extraction_confidence,
        )
        return scope

    # ─── Internals ────────────────────────────────────────────────────

    def _resolve(self, identifier: str) -> tuple[str, str]:
        if identifier.startswith("bugcrowd:"):
            handle = identifier[len("bugcrowd:"):].strip()
        else:
            parsed = urlparse(identifier)
            segments = [s for s in parsed.path.split("/") if s]
            if not segments:
                raise ExtractorError(
                    f"Bugcrowd URL {identifier!r} has no path — cannot resolve handle."
                )
            handle = segments[0]

        if not _HANDLE_PATTERN.match(handle):
            raise ExtractorError(
                f"Bugcrowd handle {handle!r} is not a valid program handle "
                "(expected lowercase alphanumeric/hyphen/underscore, 1-64 chars)."
            )

        canonical_url = f"https://bugcrowd.com/{handle}"
        return handle, canonical_url
