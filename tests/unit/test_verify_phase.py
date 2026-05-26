"""
Unit tests for the Phase 3 active-verification phase (Run #26).

The phase is the integration that takes a scan's discovered hosts, seeds
candidate parameterized URLs, runs the (fixed) VulnVerifier against them,
and emits confirmed findings ready for FindingsStore.bulk_add.

These tests pin:
  * seed_candidates determinism, scope filtering, and host-cap bounds
  * run_verify_phase passes the right URLs/classes to VulnVerifier
  * confirmed findings have the FindingsStore-compatible shape
  * verifier errors on one candidate don't kill the whole phase
"""
from __future__ import annotations

import asyncio
import pytest

from core.wraith.verify_phase import seed_candidates, run_verify_phase


def _run(coro):
    return asyncio.run(coro)


# ───────────────────────── seed_candidates ────────────────────────

class TestSeedCandidates:
    def test_unique_hosts_only(self):
        # The same host given twice should produce one host's worth of probes.
        out = seed_candidates(["http://a.example.com", "http://a.example.com"])
        hosts = {u.split("/", 3)[2] for u, _, _ in out}
        assert hosts == {"a.example.com"}

    def test_each_host_gets_full_probe_set(self):
        out = seed_candidates(["http://a.example.com"])
        from core.wraith.verify_phase import _SEED_PROBES
        assert len(out) == len(_SEED_PROBES), (
            f"expected {len(_SEED_PROBES)} probes per host, got {len(out)}"
        )

    def test_scope_filter_excludes_out_of_scope(self):
        # Only allow URLs containing 'in-scope.test'.
        out = seed_candidates(
            ["http://in-scope.test", "http://out.example.com"],
            scope_filter=lambda url: "in-scope.test" in url,
        )
        # Every survivor must be in-scope.
        for url, _, _ in out:
            assert "in-scope.test" in url
        # And nothing from the out-of-scope host survived.
        assert not any("out.example.com" in u for u, _, _ in out)

    def test_scope_filter_exceptions_treated_as_out_of_scope(self):
        # A misbehaving scope filter must fail closed (zero candidates).
        def angry(_url):
            raise RuntimeError("scope check error")
        out = seed_candidates(["http://a.example.com"], scope_filter=angry)
        assert out == []

    def test_max_hosts_caps_unique_hosts(self):
        targets = [f"http://h{i}.example.com" for i in range(10)]
        out = seed_candidates(targets, max_hosts=3)
        hosts = {u.split("/", 3)[2] for u, _, _ in out}
        assert len(hosts) == 3

    def test_juice_shop_search_probe_present(self):
        # Critical: the Juice Shop-shaped probe must be in the seed set
        # (this is the live milestone target).
        out = seed_candidates(["http://127.0.0.1:3000"])
        assert any(u.endswith("/rest/products/search?q=sentinel_probe") for u, _, _ in out)

    def test_deterministic_order(self):
        a = seed_candidates(["http://a.example.com"])
        b = seed_candidates(["http://a.example.com"])
        assert a == b

    def test_bare_hostname_target_normalized_to_http(self):
        out = seed_candidates(["bare.example.com"])
        assert out, "bare hostname should still produce candidates"
        assert all(u.startswith("http://bare.example.com") for u, _, _ in out)


# ───────────────────────── run_verify_phase ────────────────────────

class _StubSession:
    """Minimal session shape — VulnVerifier touches .knowledge (passed to
    get_or_create_waf_engine, which does `knowledge.get(...)`). We use a real
    dict; the verifier itself is monkeypatched so its run path never matters."""
    knowledge: dict = {}


class TestRunVerifyPhase:
    def test_no_candidates_returns_empty(self, monkeypatch):
        # If targets list is empty, verifier must never be invoked.
        called = {"n": 0}
        from core.wraith.vuln_verifier import VulnVerifier

        async def fake_verify(self, **kw):
            called["n"] += 1
            return ([], 0)
        monkeypatch.setattr(VulnVerifier, "verify_finding", fake_verify)

        result = _run(run_verify_phase(session=_StubSession(), targets=[]))
        assert result == []
        assert called["n"] == 0

    def test_confirmation_produces_findings_store_shape(self, monkeypatch):
        from core.wraith.vuln_verifier import VulnVerifier
        from core.web.contracts.enums import VulnerabilityClass

        async def fake_verify(self, *, engine, finding, url, vuln_class, headers, cookies, budget=5):
            # Only confirm on the Juice-Shop-shaped probe; everything else returns clean.
            if "rest/products/search" in url and vuln_class == VulnerabilityClass.SQLI:
                return ([(0.92, "SQLITE_ERROR: near ...", "'))", "SQLi")], 2)
            return ([], 1)
        monkeypatch.setattr(VulnVerifier, "verify_finding", fake_verify)

        result = _run(run_verify_phase(session=_StubSession(), targets=["http://127.0.0.1:3000"]))
        assert len(result) == 1
        f = result[0]
        # Required fields for FindingsStore + the UI / AI briefing
        for key in ("id", "type", "severity", "tool", "target", "message", "proof", "tags", "families", "metadata"):
            assert key in f, f"missing field {key!r}"
        assert f["severity"] == "HIGH"
        assert f["tool"] == "vuln_verifier"
        assert "rest/products/search" in f["target"]
        assert f["metadata"]["payload"] == "'))"
        assert f["metadata"]["confidence"] == pytest.approx(0.92)
        assert f["metadata"]["vuln_class"] == "SQLi"
        assert "verified" in f["tags"]

    def test_verifier_exception_on_one_probe_does_not_kill_phase(self, monkeypatch):
        # The phase must isolate failures: one bad probe → continue probing.
        from core.wraith.vuln_verifier import VulnVerifier

        call_log = []

        async def fake_verify(self, *, engine, finding, url, vuln_class, headers, cookies, budget=5):
            call_log.append(url)
            if "search?q=sentinel_probe" in url:
                raise RuntimeError("simulated transport failure")
            return ([], 1)
        monkeypatch.setattr(VulnVerifier, "verify_finding", fake_verify)

        result = _run(run_verify_phase(session=_StubSession(), targets=["http://a.example.com"]))
        # Phase finished without raising AND probed multiple URLs (not stopped at the failing one)
        assert result == []
        assert len(call_log) > 5, "phase stopped after first error instead of continuing"

    def test_scope_filter_prevents_probes(self, monkeypatch):
        from core.wraith.vuln_verifier import VulnVerifier

        called = {"n": 0}

        async def fake_verify(self, **kw):
            called["n"] += 1
            return ([], 0)
        monkeypatch.setattr(VulnVerifier, "verify_finding", fake_verify)

        # Scope filter rejects everything → zero probes leave the phase.
        result = _run(run_verify_phase(
            session=_StubSession(),
            targets=["http://anything.example.com"],
            scope_filter=lambda _url: False,
        ))
        assert result == []
        assert called["n"] == 0, "scope filter must hard-gate probes"

    def test_max_hosts_caps_probe_volume(self, monkeypatch):
        from core.wraith.vuln_verifier import VulnVerifier

        seen_hosts = set()

        async def fake_verify(self, *, engine, finding, url, vuln_class, headers, cookies, budget=5):
            from urllib.parse import urlparse
            seen_hosts.add(urlparse(url).netloc)
            return ([], 0)
        monkeypatch.setattr(VulnVerifier, "verify_finding", fake_verify)

        targets = [f"http://h{i}.example.com" for i in range(20)]
        _run(run_verify_phase(session=_StubSession(), targets=targets, max_hosts=2))
        assert len(seen_hosts) <= 2
