"""
Abstract base class for program scope extractors.

Extractors take a handle (``"gitlab"``) or URL (``"https://example.com/security"``)
and produce a ``ProgramScope``. Each platform plugs in as a subclass of
``Extractor``.

Contracts:

  - ``can_handle(identifier)`` is a fast, side-effect-free check used by
    the resolver to dispatch a request to the right extractor.
  - ``extract(identifier)`` is async, may make network calls, may call
    the LLM, and returns either a ``ProgramScope`` or ``None``. Returning
    ``None`` is the soft-failure path; ``ExtractorError`` is the hard one
    (e.g. malformed input that should bubble to the operator).
  - ``name`` is a short stable string used as a prefix in
    ``ProgramScope.extractor_version``. Changing it invalidates cached
    ``ProgramScope`` files from the previous name — which is the right
    behavior when the extractor's identity changes.

Design choice: ``Extractor`` doesn't dictate *how* the page is fetched
or parsed. That keeps the abstraction usable for:

  - HTML pages (GenericUrlExtractor, HackerOneExtractor, BugcrowdExtractor)
  - Markdown / plain-text policy files (`/security.txt`, GitHub README)
  - API responses (HackerOne's official program API)

Each subclass picks its own fetch + parse strategy and uses the shared
LLM extraction when LLM help is needed.
"""
from __future__ import annotations

import abc
from typing import Optional

from core.intel.program_scope import ProgramScope


class ExtractorError(Exception):
    """Raised when the extractor encounters a hard input error — e.g.
    a malformed handle, an unsupported URL scheme, or a platform that
    explicitly says "not a bug bounty program."

    Soft failures (network blip, LLM unavailable, schema validation
    failure) should return ``None`` from ``extract()`` instead — the
    caller will fall back to a different extractor or alert the
    operator with appropriate severity.
    """


class Extractor(abc.ABC):
    """Abstract base for all program scope extractors."""

    #: Short stable identifier (e.g. ``"generic_url"``, ``"hackerone"``).
    #: Used as the prefix in ``ProgramScope.extractor_version``.
    name: str = "unknown"

    #: Bump per subclass when its extraction logic changes materially.
    #: Combined with ``name`` to form the full extractor_version stamp.
    version: str = "0.0"

    @abc.abstractmethod
    def can_handle(self, identifier: str) -> bool:
        """Return ``True`` if this extractor knows how to process the
        given identifier (URL, handle, etc.).

        MUST be fast and side-effect-free — no network, no IO. The
        resolver calls this on every registered extractor and picks
        the first match.
        """
        ...

    @abc.abstractmethod
    async def extract(self, identifier: str) -> Optional[ProgramScope]:
        """Fetch + parse + return a ``ProgramScope``.

        Returns ``None`` on soft failure (e.g. network timeout, LLM
        unavailable, page didn't contain extractable data). Raises
        ``ExtractorError`` on hard input errors that the operator
        should know about.
        """
        ...

    @property
    def version_stamp(self) -> str:
        """The ``name@version`` string written into
        ``ProgramScope.extractor_version`` so cached scopes track which
        extractor produced them."""
        return f"{self.name}@{self.version}"
