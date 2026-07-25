"""
Resolver — picks the right Extractor for a given identifier.

The resolver holds an ordered list of registered ``Extractor`` instances.
For each ``resolve(identifier)`` call, it iterates the list and returns
the first extractor whose ``can_handle(identifier)`` returns True.

Ordering matters:

  - Platform-specific extractors (HackerOne, Bugcrowd) come first.
    They match narrowly — only their specific URL patterns or handle
    prefixes.
  - The ``GenericUrlExtractor`` fallback comes last. It matches any
    http(s) URL.

This ordering means:

  - ``"hackerone:gitlab"``               → HackerOneExtractor
  - ``"https://hackerone.com/gitlab"``   → HackerOneExtractor
  - ``"https://bugcrowd.com/tesla"``     → BugcrowdExtractor
  - ``"https://example.com/security"``   → GenericUrlExtractor
  - ``"gitlab"`` (bare handle, ambiguous) → None (operator must specify)

Why bare handles are deliberately rejected at this phase:
  ``"gitlab"`` could be a HackerOne handle, a Bugcrowd handle, an
  Intigriti handle, or a typo. Resolving it would require N HTTP
  probes ("does this handle exist on platform X?") which is expensive
  and noisy. Phase 2F will add smarter handle resolution using the
  platforms' search APIs; for now we require an explicit prefix.
"""
from __future__ import annotations

import logging
from typing import List, Optional

from core.intel.extractors.base import Extractor

logger = logging.getLogger(__name__)


class Resolver:
    """Dispatch ``identifier`` to the appropriate registered extractor."""

    def __init__(self, extractors: Optional[List[Extractor]] = None):
        """``extractors`` is the priority-ordered list. First match wins.

        Pass ``None`` (or omit) for an empty resolver — tests typically
        build resolvers with just the extractors they need. The factory
        function ``default_resolver()`` builds the production registry.
        """
        self._extractors: List[Extractor] = list(extractors) if extractors else []

    def register(self, extractor: Extractor) -> None:
        """Append an extractor to the end of the priority list.

        New registrations have the lowest priority — they only match
        identifiers that no earlier extractor claimed.
        """
        self._extractors.append(extractor)

    def register_first(self, extractor: Extractor) -> None:
        """Prepend an extractor to the front of the priority list.

        Useful for tests that want to override the default routing
        without disturbing existing registrations.
        """
        self._extractors.insert(0, extractor)

    def resolve(self, identifier: str) -> Optional[Extractor]:
        """Return the first registered extractor that can handle the
        given identifier, or ``None`` if none match."""
        if not identifier:
            return None
        for extractor in self._extractors:
            try:
                if extractor.can_handle(identifier):
                    logger.debug(
                        "[intel.resolver] %r → %s",
                        identifier, extractor.version_stamp,
                    )
                    return extractor
            except Exception as e:  # noqa: BLE001 - can_handle must never crash dispatch
                logger.warning(
                    "[intel.resolver] %s.can_handle raised %s on %r — skipping",
                    type(extractor).__name__, e, identifier,
                )
        logger.info("[intel.resolver] no extractor matched %r", identifier)
        return None

    @property
    def extractors(self) -> List[Extractor]:
        """Read-only view of the current priority list."""
        return list(self._extractors)


def default_resolver() -> Resolver:
    """Build the production resolver with platform adapters first,
    generic-URL fallback last.

    This is the factory the CLI / API entry points should use unless
    they have a specific reason to override.
    """
    # Lazy imports so individual extractor failures don't break the
    # entire intel package on import.
    from core.intel.extractors.bugcrowd import BugcrowdExtractor
    from core.intel.extractors.generic_url import GenericUrlExtractor
    from core.intel.extractors.hackerone import HackerOneExtractor

    return Resolver([
        HackerOneExtractor(),
        BugcrowdExtractor(),
        GenericUrlExtractor(),  # fallback — must be last
    ])
