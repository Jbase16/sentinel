"""
Tests for the Resolver (Phase 2B).

The resolver is a tiny dispatcher — it iterates registered extractors
and returns the first one whose ``can_handle`` returns True. The
behavior we lock in:

  1. Empty resolver returns None for anything.
  2. First-match-wins ordering — priority is the list order.
  3. ``register`` appends (lowest priority); ``register_first`` prepends.
  4. ``can_handle`` raising an exception doesn't crash dispatch — the
     resolver logs and tries the next extractor.
  5. Empty / None identifier returns None without iterating.
  6. ``default_resolver`` builds the production registry in the
     expected priority order.
"""
from __future__ import annotations

from typing import Optional
from unittest.mock import MagicMock

import pytest

from core.intel.extractors.base import Extractor
from core.intel.program_scope import ProgramScope
from core.intel.resolver import Resolver, default_resolver


class _StubExtractor(Extractor):
    """Simple test extractor — matches identifiers in a known set."""

    def __init__(self, name: str, accepts: set[str], *, raises: bool = False):
        self.name = name
        self.version = "test"
        self._accepts = accepts
        self._raises = raises

    def can_handle(self, identifier: str) -> bool:
        if self._raises:
            raise RuntimeError("simulated can_handle failure")
        return identifier in self._accepts

    async def extract(self, identifier: str) -> Optional[ProgramScope]:
        return None  # Not exercised in these tests.


# ─────────────────────────── Empty + None ──────────────────────────

class TestEmptyAndNoneInput:
    def test_empty_resolver_returns_none(self):
        r = Resolver()
        assert r.resolve("anything") is None

    def test_empty_string_returns_none_without_iterating(self):
        called = {"n": 0}

        class _Tracker(Extractor):
            name = "tracker"
            version = "0"

            def can_handle(self, identifier):
                called["n"] += 1
                return True

            async def extract(self, identifier):
                return None

        r = Resolver([_Tracker()])
        assert r.resolve("") is None
        # Crucial: we did NOT call can_handle on empty input.
        assert called["n"] == 0

    def test_none_identifier_returns_none(self):
        r = Resolver([_StubExtractor("x", {"foo"})])
        assert r.resolve(None) is None  # type: ignore[arg-type]


# ─────────────────────────── First-match-wins ──────────────────────

class TestPriorityOrdering:
    def test_first_matching_extractor_wins(self):
        first = _StubExtractor("first", {"foo"})
        second = _StubExtractor("second", {"foo"})
        r = Resolver([first, second])
        # Both can_handle("foo"), but first wins by order.
        assert r.resolve("foo") is first

    def test_first_non_matching_is_skipped(self):
        a = _StubExtractor("a", {"only-a"})
        b = _StubExtractor("b", {"only-b"})
        r = Resolver([a, b])
        assert r.resolve("only-b") is b

    def test_no_match_returns_none(self):
        a = _StubExtractor("a", {"x"})
        b = _StubExtractor("b", {"y"})
        r = Resolver([a, b])
        assert r.resolve("z") is None


# ─────────────────────────── Registration ──────────────────────────

class TestRegistration:
    def test_register_appends_to_end(self):
        first = _StubExtractor("first", {"shared"})
        appended = _StubExtractor("appended", {"shared"})
        r = Resolver([first])
        r.register(appended)
        # First still wins for "shared".
        assert r.resolve("shared") is first

    def test_register_first_prepends(self):
        existing = _StubExtractor("existing", {"shared"})
        prepended = _StubExtractor("prepended", {"shared"})
        r = Resolver([existing])
        r.register_first(prepended)
        # Prepended now wins.
        assert r.resolve("shared") is prepended

    def test_extractors_property_returns_copy(self):
        e = _StubExtractor("x", set())
        r = Resolver([e])
        listed = r.extractors
        listed.append(_StubExtractor("y", set()))  # mutate the returned list
        # Internal list was unaffected.
        assert len(r.extractors) == 1


# ─────────────────────────── Exception safety ──────────────────────

class TestExceptionSafety:
    def test_can_handle_exception_is_caught_and_dispatch_continues(self):
        crashing = _StubExtractor("crash", set(), raises=True)
        good = _StubExtractor("good", {"foo"})
        r = Resolver([crashing, good])
        # Even though crashing.can_handle raises, the resolver moves on
        # and finds good for "foo".
        assert r.resolve("foo") is good

    def test_all_extractors_crashing_returns_none_not_raise(self):
        a = _StubExtractor("a", set(), raises=True)
        b = _StubExtractor("b", set(), raises=True)
        r = Resolver([a, b])
        # No match found — but the resolver does not propagate the
        # individual exceptions to the caller.
        assert r.resolve("anything") is None


# ─────────────────────────── default_resolver factory ──────────────

class TestDefaultResolver:
    def test_builds_with_three_extractors_in_expected_order(self):
        from core.intel.extractors.bugcrowd import BugcrowdExtractor
        from core.intel.extractors.generic_url import GenericUrlExtractor
        from core.intel.extractors.hackerone import HackerOneExtractor

        r = default_resolver()
        types = [type(e) for e in r.extractors]
        assert types == [HackerOneExtractor, BugcrowdExtractor, GenericUrlExtractor]

    def test_hackerone_url_routes_to_hackerone_extractor(self):
        from core.intel.extractors.hackerone import HackerOneExtractor
        r = default_resolver()
        result = r.resolve("https://hackerone.com/gitlab")
        assert isinstance(result, HackerOneExtractor)

    def test_bugcrowd_url_routes_to_bugcrowd_extractor(self):
        from core.intel.extractors.bugcrowd import BugcrowdExtractor
        r = default_resolver()
        result = r.resolve("https://bugcrowd.com/tesla")
        assert isinstance(result, BugcrowdExtractor)

    def test_arbitrary_url_falls_back_to_generic(self):
        from core.intel.extractors.generic_url import GenericUrlExtractor
        r = default_resolver()
        result = r.resolve("https://example.com/bug-bounty")
        assert isinstance(result, GenericUrlExtractor)

    def test_bare_handle_returns_none(self):
        # Bare handles are explicitly not resolved in Phase 2B — operator
        # must use a prefix. This test locks that contract so a future
        # refactor doesn't silently start resolving them.
        r = default_resolver()
        assert r.resolve("gitlab") is None
