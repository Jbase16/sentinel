"""
Unit tests for core/wraith/candidate_discovery (Phase 3 step 3).

This module bridges discovered URLs into verify_phase's (url, label,
vuln_class) tuple shape. Tests cover:

  * `classify_url` — the pure classifier. Single URL → multiple probe
    classes (a /?url=...&q=... is BOTH open_redirect AND sqli).
  * `classify_urls` — batched + scope-filtered + capped. Fail-CLOSED on
    scope-filter exceptions (must match verify_phase's own semantics).
  * `_ScopeOnlyPolicy.assert_url_allowed` — raises ScopeViolation when
    the filter says no OR raises (never silently allow).
  * `discover_candidates` (async) — top-level. Uses a monkeypatched
    HttpCrawler so we don't touch the network.

The crawler itself is core/web/crawler.py — its own tests cover the BFS,
parsing, etc. This file only verifies our adapters + classification.
"""
from __future__ import annotations

import asyncio
import pytest

from core.wraith.candidate_discovery import (
    _is_id_segment,
    _ScopeOnlyPolicy,
    classify_url,
    classify_urls,
    discover_candidates,
)


# ──────────────────────────── pure classifier ──────────────────────────────


class TestIsIdSegment:
    def test_numeric(self):
        assert _is_id_segment("1")
        assert _is_id_segment("999999")

    def test_uuid_dashed(self):
        assert _is_id_segment("550e8400-e29b-41d4-a716-446655440000")

    def test_uuid_undashed(self):
        # 32-char hex (no dashes) — sometimes seen in API paths.
        assert _is_id_segment("550e8400e29b41d4a716446655440000")

    def test_word_segment_rejected(self):
        assert not _is_id_segment("users")
        assert not _is_id_segment("profile")

    def test_empty_rejected(self):
        assert not _is_id_segment("")


class TestClassifyUrl:
    def test_sqli_for_any_query_param(self):
        out = classify_url("http://h/search?q=hello")
        vcs = [vc for _, _, vc in out]
        assert "sqli" in vcs

    def test_no_query_no_id_segment_no_candidates(self):
        # /about — no query, no ID segment → nothing for the verifier to do.
        assert classify_url("http://h/about") == []

    def test_url_param_emits_redirect_and_ssrf(self):
        out = classify_url("http://h/go?url=http://x.com")
        vcs = [vc for _, _, vc in out]
        # url=... is BOTH a redirect target AND an SSRF target.
        assert "open_redirect" in vcs
        assert "ssrf" in vcs
        # And still an SQLi candidate (any query-bearing URL is).
        assert "sqli" in vcs

    def test_file_param_emits_traversal(self):
        out = classify_url("http://h/dl?file=docs/readme.pdf")
        vcs = [vc for _, _, vc in out]
        assert "path_traversal" in vcs

    def test_numeric_terminal_path_segment_emits_idor(self):
        out = classify_url("http://h/api/users/42")
        vcs = [vc for _, _, vc in out]
        assert "idor" in vcs

    def test_uuid_terminal_path_segment_emits_idor(self):
        out = classify_url("http://h/api/items/550e8400-e29b-41d4-a716-446655440000")
        vcs = [vc for _, _, vc in out]
        assert "idor" in vcs

    def test_non_terminal_numeric_does_not_emit_idor(self):
        # /api/v1/users — `v1` could pass numeric check? No, "v1" isn't all-digit.
        # But verify the "must be terminal" rule: /api/2/users does NOT emit IDOR.
        out = classify_url("http://h/api/2/users")
        vcs = [vc for _, _, vc in out]
        assert "idor" not in vcs

    def test_multiple_classes_for_one_url(self):
        # A URL with redirect-shaped AND query → should yield SQLi + redirect
        # + SSRF, all three pointed at the SAME url string.
        out = classify_url("http://h/search?q=x&redirect=http://y.com")
        urls = {u for u, _, _ in out}
        vcs = {vc for _, _, vc in out}
        assert len(urls) == 1  # all candidates point at the same source URL
        assert vcs >= {"sqli", "open_redirect", "ssrf"}

    def test_malformed_url_returns_empty(self):
        assert classify_url("") == []
        assert classify_url("not-a-url") == []
        # Missing scheme — the function requires both scheme+netloc.
        assert classify_url("//no-scheme.com/x?q=1") == []

    def test_label_includes_host_and_path(self):
        # Labels are how Phase 3 attributes findings in reports — they MUST
        # disambiguate URLs (otherwise two confirmed findings on different
        # hosts look identical in the Findings tab).
        out = classify_url("http://h.example.com/api/search?q=x")
        labels = [label for _, label, _ in out]
        assert any("h.example.com" in label for label in labels)
        assert any("/api/search" in label for label in labels)


class TestClassifyUrls:
    def test_dedup_by_url_and_vc(self):
        # Same URL listed twice → each (url, vc) pair appears once.
        out = classify_urls(["http://h/?q=1", "http://h/?q=1"])
        pairs = [(u, vc) for u, _, vc in out]
        assert len(pairs) == len(set(pairs))

    def test_scope_filter_drops_out_of_scope_urls(self):
        out = classify_urls(
            ["http://in.example/?q=1", "http://out.example/?q=2"],
            scope_filter=lambda u: "in.example" in u,
        )
        assert all("in.example" in u for u, _, _ in out)
        assert not any("out.example" in u for u, _, _ in out)

    def test_scope_filter_exception_fails_closed(self):
        # Same semantics as verify_phase.seed_candidates — an exception in
        # the scope filter is NOT-IN-SCOPE. Never silently allow.
        def angry(_u):
            raise RuntimeError("scope check error")

        out = classify_urls(["http://h/?q=1"], scope_filter=angry)
        assert out == []

    def test_max_candidates_cap(self):
        # 100 distinct URLs × multi-class each → cap kicks in.
        urls = [f"http://h.example/page{i}?q=x" for i in range(100)]
        out = classify_urls(urls, max_candidates=10)
        assert len(out) == 10


# ─────────────────────────── policy adapter ────────────────────────────────


class TestScopeOnlyPolicy:
    def test_no_filter_allows_everything(self):
        from core.web.contracts.errors import ScopeViolation

        p = _ScopeOnlyPolicy(scope_filter=None)
        # Must not raise — no filter = no scope restriction.
        p.assert_url_allowed(mission=None, url="http://anywhere.example/")

    def test_filter_returning_true_allows(self):
        p = _ScopeOnlyPolicy(scope_filter=lambda _u: True)
        p.assert_url_allowed(mission=None, url="http://allowed/")

    def test_filter_returning_false_raises_scope_violation(self):
        from core.web.contracts.errors import ScopeViolation

        p = _ScopeOnlyPolicy(scope_filter=lambda _u: False)
        with pytest.raises(ScopeViolation):
            p.assert_url_allowed(mission=None, url="http://blocked/")

    def test_filter_exception_fails_closed_raises(self):
        # Fail-CLOSED: exception in scope_filter must raise ScopeViolation,
        # NOT be silently allowed. Otherwise a buggy filter exposes the
        # crawler to out-of-scope targets.
        from core.web.contracts.errors import ScopeViolation

        def angry(_u):
            raise RuntimeError("network down")

        p = _ScopeOnlyPolicy(scope_filter=angry)
        with pytest.raises(ScopeViolation):
            p.assert_url_allowed(mission=None, url="http://x/")


# ─────────────────────── discover_candidates (async) ───────────────────────


class TestDiscoverCandidatesAsync:
    """Top-level async API. Monkeypatch the HttpCrawler so no network calls."""

    def test_returns_empty_on_malformed_target(self):
        # _build_mission can't parse a hostless target — must return [].
        out = asyncio.run(discover_candidates(target="not-a-url"))
        assert out == []

    def test_uses_crawler_output_and_classifies(self, monkeypatch):
        # Monkeypatch the HttpCrawler.crawl to populate the registry with
        # a known URL set — we verify the classifier ran over it.
        import core.web.crawler as crawler_mod
        import core.web.surface_registry as reg_mod
        from core.web.contracts.models import EndpointCandidate
        from core.web.contracts.enums import SurfaceSource, WebMethod

        def fake_crawl(self, mission, ctx, registry):
            registry.add_urls([
                "http://h.example/api/search?q=hello",
                "http://h.example/redirect?url=http://x.com",
                "http://h.example/api/users/42",
                "http://h.example/about",  # no params, no ID → no candidates
            ])
            return None

        monkeypatch.setattr(crawler_mod.HttpCrawler, "crawl", fake_crawl)

        # Discovery uses _build_mission which validates origin — give it
        # a valid URL.
        out = asyncio.run(discover_candidates(
            target="http://h.example",
            max_depth=1,
            max_pages=5,
        ))
        urls = {u for u, _, _ in out}
        vcs_by_url = {}
        for u, _l, vc in out:
            vcs_by_url.setdefault(u, set()).add(vc)

        # Search URL → sqli
        assert "sqli" in vcs_by_url["http://h.example/api/search?q=hello"]
        # Redirect URL → open_redirect + ssrf + sqli (any query → sqli too)
        rd = vcs_by_url["http://h.example/redirect?url=http://x.com"]
        assert {"sqli", "open_redirect", "ssrf"} <= rd
        # /api/users/42 → idor
        assert "idor" in vcs_by_url["http://h.example/api/users/42"]
        # /about emitted nothing
        assert "http://h.example/about" not in urls

    def test_crawl_exception_returns_empty_not_raises(self, monkeypatch):
        # Discovery contract: NEVER raise — verify_phase still runs seed
        # probes even if discovery fails entirely.
        import core.web.crawler as crawler_mod

        def boom(self, mission, ctx, registry):
            raise RuntimeError("crawl simulated failure")

        monkeypatch.setattr(crawler_mod.HttpCrawler, "crawl", boom)

        # Must not raise.
        out = asyncio.run(discover_candidates(target="http://h.example"))
        assert out == []

    def test_scope_filter_threads_through_to_classify(self, monkeypatch):
        # Even if the crawler discovers an out-of-scope URL (it shouldn't,
        # but defense-in-depth), classify_urls must still reject it.
        import core.web.crawler as crawler_mod

        def fake_crawl(self, mission, ctx, registry):
            registry.add_urls([
                "http://in.example/?q=1",
                "http://out.example/?q=2",
            ])
            return None

        monkeypatch.setattr(crawler_mod.HttpCrawler, "crawl", fake_crawl)

        out = asyncio.run(discover_candidates(
            target="http://in.example",
            scope_filter=lambda u: "in.example" in u,
        ))
        # Out-of-scope URL must not appear.
        assert all("out.example" not in u for u, _, _ in out)
        assert any("in.example" in u for u, _, _ in out)
