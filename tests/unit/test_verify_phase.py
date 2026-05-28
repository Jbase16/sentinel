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

        result = _run(run_verify_phase(session=_StubSession(), targets=[], enable_discovery=False))
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

        result = _run(run_verify_phase(session=_StubSession(), targets=["http://127.0.0.1:3000"], enable_discovery=False))
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

        result = _run(run_verify_phase(session=_StubSession(), targets=["http://a.example.com"], enable_discovery=False))
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
            scope_filter=lambda _url: False, enable_discovery=False,))
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
        _run(run_verify_phase(session=_StubSession(), targets=targets, max_hosts=2, enable_discovery=False))
        assert len(seen_hosts) <= 2


# ─────────────────────── persona-aware run_verify_phase ───────────────────

class TestPersonaAwareVerifyPhase:
    """The persona dimension makes IDOR + authenticated-SQLi reachable.

    These tests pin:
      * authenticate_persona is awaited once per persona before probing.
      * Each candidate is probed once per identity context.
      * Findings carry per-persona metadata + tag so the report/AI attributes.
      * IDOR candidates are skipped for unauthenticated identities (they'd
        just confirm 'logged-out users can't see baskets').
      * IDOR candidates ARE probed under an authenticated identity.
    """

    def test_unauthenticated_skips_idor_probes(self, monkeypatch):
        from core.wraith.vuln_verifier import VulnVerifier
        from core.web.contracts.enums import VulnerabilityClass

        seen_classes = []

        async def fake_verify(self, *, engine, finding, url, vuln_class, headers, cookies, budget=5):
            seen_classes.append(vuln_class)
            return ([], 0)
        monkeypatch.setattr(VulnVerifier, "verify_finding", fake_verify)

        _run(run_verify_phase(session=_StubSession(), targets=["http://a.example.com"], enable_discovery=False))
        # IDOR class must NEVER be seen by the verifier when no personas are wired.
        assert VulnerabilityClass.IDOR not in seen_classes

    def test_authenticated_persona_probes_idor(self, monkeypatch):
        from core.wraith.vuln_verifier import VulnVerifier
        from core.web import contracts as _c  # noqa: F401
        from core.web.contracts.enums import VulnerabilityClass
        import core.wraith.verify_phase as vp_mod

        # Stub the authenticator to return obviously-authenticated creds
        # without touching the network.
        async def fake_auth(persona):
            return ({"Authorization": "Bearer FAKE"}, {})
        monkeypatch.setattr(
            "core.wraith.persona_auth.authenticate_persona", fake_auth
        )

        idor_urls = []

        async def fake_verify(self, *, engine, finding, url, vuln_class, headers, cookies, budget=5):
            if vuln_class == VulnerabilityClass.IDOR:
                idor_urls.append((url, headers.get("Authorization")))
                return ([(0.88, "id-leak: returned other user's basket", "2", "IDOR")], 1)
            return ([], 1)
        monkeypatch.setattr(VulnVerifier, "verify_finding", fake_verify)

        personas = [{
            "name": "admin",
            "login_url": "http://a.example.com/rest/user/login",
            "login_body": {"email": "a@b", "password": "p"},
            "token_path": "authentication.token",
            "auth_header": "Authorization: Bearer {token}",
        }]
        result = _run(run_verify_phase(
            session=_StubSession(),
            targets=["http://a.example.com"],
            personas=personas, enable_discovery=False,))

        # IDOR probes ran with the persona's Authorization header.
        assert idor_urls, "IDOR probes did not run for the authenticated persona"
        for _url, auth in idor_urls:
            assert auth == "Bearer FAKE"

        # Confirmed IDOR findings carry persona metadata + tag.
        idor_findings = [f for f in result if f["metadata"]["vuln_class"] == "IDOR"]
        assert idor_findings, "no IDOR finding emitted under authenticated persona"
        f = idor_findings[0]
        assert f["metadata"]["persona"] == "admin"
        assert f["metadata"]["authenticated"] is True
        assert "persona:admin" in f["tags"]

    def test_persona_auth_failure_falls_back_to_anonymous(self, monkeypatch):
        """A persona whose login blows up must NOT kill the phase — the
        identity falls back to anonymous (empty creds)."""
        from core.wraith.vuln_verifier import VulnVerifier

        async def angry_auth(persona):
            raise RuntimeError("auth subsystem on fire")
        monkeypatch.setattr(
            "core.wraith.persona_auth.authenticate_persona", angry_auth
        )

        observed_headers = []

        async def fake_verify(self, *, engine, finding, url, vuln_class, headers, cookies, budget=5):
            observed_headers.append(dict(headers))
            return ([], 1)
        monkeypatch.setattr(VulnVerifier, "verify_finding", fake_verify)

        result = _run(run_verify_phase(
            session=_StubSession(),
            targets=["http://a.example.com"],
            personas=[{"name": "broken"}], enable_discovery=False,))
        # The phase completed; verifier was invoked at least once.
        assert observed_headers, "verifier never ran after persona auth failure"
        # Fallback identity sees empty headers (anonymous).
        assert all(h == {} for h in observed_headers)
        assert result == []

    def test_multi_persona_runs_each_candidate_per_identity(self, monkeypatch):
        """Two personas × N candidates → each candidate probed twice."""
        from core.wraith.vuln_verifier import VulnVerifier

        async def fake_auth(persona):
            return ({"X-Identity": persona["name"]}, {})
        monkeypatch.setattr(
            "core.wraith.persona_auth.authenticate_persona", fake_auth
        )

        # Track (url, identity) tuples to verify cross-product.
        seen: list = []

        async def fake_verify(self, *, engine, finding, url, vuln_class, headers, cookies, budget=5):
            seen.append((url, headers.get("X-Identity")))
            return ([], 0)
        monkeypatch.setattr(VulnVerifier, "verify_finding", fake_verify)

        personas = [
            {"name": "alice", "login_url": "http://x/login"},
            {"name": "bob",   "login_url": "http://x/login"},
        ]
        _run(run_verify_phase(
            session=_StubSession(),
            targets=["http://a.example.com"],
            personas=personas, enable_discovery=False,))

        urls_for_alice = {u for u, ident in seen if ident == "alice"}
        urls_for_bob   = {u for u, ident in seen if ident == "bob"}
        # Both identities probed the same URL set.
        assert urls_for_alice, "alice never probed anything"
        assert urls_for_bob, "bob never probed anything"
        assert urls_for_alice == urls_for_bob, (
            "personas saw different URL sets — identity loop is asymmetric"
        )


# ─────────────── multi-principal IDOR pass (Phase 3 step 4) ───────────────

class TestMultiPrincipalIDOR:
    """Cross-principal IDOR detection — varies the IDENTITY, holds URL fixed.

    Distinct from horizontal IDOR (single-principal _confirm_idor): two
    AUTHENTICATED identities receiving distinct 200 responses for the same
    URL is the diagnostic signal for "Bob can read Alice's resource."

    Tests pin:
      * Skipped with <2 authenticated identities.
      * Identical-body responses across identities → NOT flagged (SPA shell).
      * Distinct-body 200 responses across identities → flagged.
      * Non-IDOR-shaped URLs (no numeric/UUID terminal segment) skipped.
      * Findings carry attacker + victim persona names in tags + metadata.
      * Scope filter re-checks each URL even if it passed upstream.
    """

    def _patch_httpx(self, monkeypatch, responses_by_identity):
        """Install a fake httpx.AsyncClient that returns responses keyed
        by the Authorization header (used to identify which persona is
        making the request).

        responses_by_identity: dict of identity-token -> (status, body)
        """
        import httpx
        import core.wraith.verify_phase as vp_mod

        class _FakeAsyncClient:
            def __init__(self, *args, **kwargs): pass
            async def __aenter__(self): return self
            async def __aexit__(self, *a): return False

            async def get(self, url, headers=None):
                headers = headers or {}
                auth = headers.get("Authorization", "")
                # Strip "Bearer " prefix to extract identity name.
                token = auth.replace("Bearer ", "")
                if token in responses_by_identity:
                    status, body = responses_by_identity[token]
                else:
                    status, body = (403, '{"error":"unauthenticated"}')

                class _Resp:
                    def __init__(self, status, body):
                        self.status_code = status
                        self.text = body
                return _Resp(status, body)

        monkeypatch.setattr(vp_mod.__name__.replace(".", "/") and __import__("httpx", fromlist=[""]), "AsyncClient", _FakeAsyncClient)
        # The actual monkeypatch — httpx imported inside _run_multi_principal_idor
        monkeypatch.setattr("httpx.AsyncClient", _FakeAsyncClient)

    def test_skipped_with_only_one_authenticated_identity(self, monkeypatch):
        """0 or 1 authenticated personas → multi-principal pass must not run.
        We verify by checking that no httpx call is ever made."""
        from core.wraith.vuln_verifier import VulnVerifier
        import core.wraith.verify_phase as vp_mod

        async def fake_verify(self, **kw):
            return ([], 0)
        monkeypatch.setattr(VulnVerifier, "verify_finding", fake_verify)

        # Simulate the multi-principal pass being called — but it shouldn't be.
        called = {"n": 0}
        orig = vp_mod._run_multi_principal_idor

        async def watcher(*args, **kwargs):
            called["n"] += 1
            return await orig(*args, **kwargs)
        monkeypatch.setattr(vp_mod, "_run_multi_principal_idor", watcher)

        async def fake_auth(p):
            return ({"Authorization": "Bearer X"}, {})
        monkeypatch.setattr("core.wraith.persona_auth.authenticate_persona", fake_auth)

        _run(run_verify_phase(
            session=_StubSession(),
            targets=["http://a.example.com"],
            personas=[{"name": "solo", "login_url": "http://a/login"}],
            enable_discovery=False,
        ))
        assert called["n"] == 0, "multi-principal pass should not run with only 1 identity"

    def test_distinct_200s_emit_finding(self, monkeypatch):
        """Two authenticated identities both get 200 OK with DISTINCT JSON
        bodies for the same /api/users/42 URL → IDOR confirmed."""
        from core.wraith.vuln_verifier import VulnVerifier
        import core.wraith.verify_phase as vp_mod

        # Single-principal verifier returns nothing (we're testing the
        # multi-principal pass separately).
        async def fake_verify(self, **kw):
            return ([], 0)
        monkeypatch.setattr(VulnVerifier, "verify_finding", fake_verify)

        # alice + bob personas.
        async def fake_auth(p):
            name = p["name"]
            return ({"Authorization": f"Bearer {name}"}, {})
        monkeypatch.setattr("core.wraith.persona_auth.authenticate_persona", fake_auth)

        # Inject a fake httpx that returns different JSON per identity.
        responses = {
            "alice": (200, '{"id": 42, "owner": "alice", "balance": 100}'),
            "bob":   (200, '{"id": 42, "owner": "bob",   "balance": 250}'),
        }

        class _FakeAsyncClient:
            def __init__(self, *args, **kwargs): pass
            async def __aenter__(self): return self
            async def __aexit__(self, *a): return False
            async def get(self, url, headers=None):
                token = (headers or {}).get("Authorization", "").replace("Bearer ", "")
                status, body = responses.get(token, (403, "denied"))
                class _R:
                    pass
                r = _R()
                r.status_code = status
                r.text = body
                return r
        monkeypatch.setattr("httpx.AsyncClient", _FakeAsyncClient)

        # We need the candidate generator to produce an IDOR-shaped URL.
        # The /api/users/42 path matches both the candidate_discovery
        # classifier AND _is_idor_shape. We disable discovery and pass
        # the URL via _SEED_PROBES override.
        original_seeds = vp_mod._SEED_PROBES
        vp_mod._SEED_PROBES = [("/api/users/42", "test-idor", "idor")]
        try:
            result = _run(run_verify_phase(
                session=_StubSession(),
                targets=["http://h.example.com"],
                personas=[
                    {"name": "alice", "login_url": "http://h/login"},
                    {"name": "bob",   "login_url": "http://h/login"},
                ],
                enable_discovery=False,
            ))
        finally:
            vp_mod._SEED_PROBES = original_seeds

        # Must include a cross-principal IDOR finding.
        cross = [f for f in result if "cross_principal" in f.get("metadata", {}).get("subclass", "")]
        assert cross, f"no cross-principal IDOR finding emitted; got: {[f['type'] for f in result]}"
        f = cross[0]
        # Both persona names must appear in tags.
        assert any("persona:alice" in t for t in f["tags"])
        assert any("persona:bob" in t for t in f["tags"])
        # metadata carries attribution.
        assert f["metadata"]["attacker_persona"] in {"alice", "bob"}
        assert f["metadata"]["victim_persona"] in {"alice", "bob"}
        assert f["metadata"]["attacker_persona"] != f["metadata"]["victim_persona"]
        # confidence is the high tier (both responses are JSON-shaped, similar size)
        assert f["metadata"]["confidence"] >= 0.80

    def test_identical_bodies_not_flagged(self, monkeypatch):
        """Both identities get the SAME body — that's a shared/anonymous
        resource or SPA shell, NOT IDOR. Must NOT emit."""
        from core.wraith.vuln_verifier import VulnVerifier
        import core.wraith.verify_phase as vp_mod

        async def fake_verify(self, **kw):
            return ([], 0)
        monkeypatch.setattr(VulnVerifier, "verify_finding", fake_verify)

        async def fake_auth(p):
            return ({"Authorization": f"Bearer {p['name']}"}, {})
        monkeypatch.setattr("core.wraith.persona_auth.authenticate_persona", fake_auth)

        shared_body = '<html><body>Public app shell — please log in</body></html>'

        class _FakeAsyncClient:
            def __init__(self, *args, **kwargs): pass
            async def __aenter__(self): return self
            async def __aexit__(self, *a): return False
            async def get(self, url, headers=None):
                class _R: pass
                r = _R()
                r.status_code = 200
                r.text = shared_body
                return r
        monkeypatch.setattr("httpx.AsyncClient", _FakeAsyncClient)

        original_seeds = vp_mod._SEED_PROBES
        vp_mod._SEED_PROBES = [("/api/users/42", "test-idor", "idor")]
        try:
            result = _run(run_verify_phase(
                session=_StubSession(),
                targets=["http://h.example.com"],
                personas=[
                    {"name": "alice", "login_url": "http://h/login"},
                    {"name": "bob",   "login_url": "http://h/login"},
                ],
                enable_discovery=False,
            ))
        finally:
            vp_mod._SEED_PROBES = original_seeds

        cross = [f for f in result if "cross_principal" in f.get("metadata", {}).get("subclass", "")]
        assert cross == [], (
            "identical-body responses across identities must NOT trigger "
            "cross-principal IDOR (SPA shell signature)"
        )

    def test_non_idor_shape_url_skipped(self, monkeypatch):
        """A URL with no terminal numeric/UUID segment (e.g. /search?q=x)
        is NOT an IDOR candidate even if multiple identities access it."""
        from core.wraith.vuln_verifier import VulnVerifier
        import core.wraith.verify_phase as vp_mod

        async def fake_verify(self, **kw):
            return ([], 0)
        monkeypatch.setattr(VulnVerifier, "verify_finding", fake_verify)

        async def fake_auth(p):
            return ({"Authorization": f"Bearer {p['name']}"}, {})
        monkeypatch.setattr("core.wraith.persona_auth.authenticate_persona", fake_auth)

        # If httpx is called at all, this test fails by side-effect (the
        # multi-principal pass shouldn't probe non-IDOR-shaped URLs).
        called = {"n": 0}

        class _FakeAsyncClient:
            def __init__(self, *args, **kwargs): pass
            async def __aenter__(self): return self
            async def __aexit__(self, *a): return False
            async def get(self, url, headers=None):
                called["n"] += 1
                class _R: pass
                r = _R()
                r.status_code = 200
                r.text = "x" * 100
                return r
        monkeypatch.setattr("httpx.AsyncClient", _FakeAsyncClient)

        # Seed a NON-idor-shape URL labeled as 'idor' — _is_idor_shape
        # should still reject it.
        original_seeds = vp_mod._SEED_PROBES
        vp_mod._SEED_PROBES = [("/api/users", "mislabel-idor", "idor")]
        try:
            _run(run_verify_phase(
                session=_StubSession(),
                targets=["http://h.example.com"],
                personas=[
                    {"name": "alice", "login_url": "http://h/login"},
                    {"name": "bob",   "login_url": "http://h/login"},
                ],
                enable_discovery=False,
            ))
        finally:
            vp_mod._SEED_PROBES = original_seeds

        assert called["n"] == 0, (
            "multi-principal pass probed a non-IDOR-shaped URL "
            f"({called['n']} httpx.get calls made)"
        )


    def test_identical_json_across_identities_is_cross_principal_idor(self, monkeypatch):
        """The Juice Shop case: Alice and Jim both fetch /rest/basket/1 and
        receive the SAME JSON body (admin's basket data). That's textbook
        cross-principal IDOR — Jim can read Alice's basket using Alice's URL.

        The earlier "identical body = SPA shell" rule was right for HTML
        but wrong for JSON. JSON is structured data, not chrome — two
        different auth'd identities receiving the same JSON for the same
        URL is the highest-confidence cross-principal IDOR signal."""
        from core.wraith.vuln_verifier import VulnVerifier
        import core.wraith.verify_phase as vp_mod

        async def fake_verify(self, **kw):
            return ([], 0)
        monkeypatch.setattr(VulnVerifier, "verify_finding", fake_verify)

        async def fake_auth(p):
            return ({"Authorization": f"Bearer {p['name']}"}, {})
        monkeypatch.setattr("core.wraith.persona_auth.authenticate_persona", fake_auth)

        # Both identities get the SAME JSON body. That's the IDOR signal.
        identical_json = '{"basketId": 1, "owner": "admin", "items": [{"name": "apple"}]}'

        class _FakeAsyncClient:
            def __init__(self, *args, **kwargs): pass
            async def __aenter__(self): return self
            async def __aexit__(self, *a): return False
            async def get(self, url, headers=None):
                class _R: pass
                r = _R()
                r.status_code = 200
                r.text = identical_json
                return r
        monkeypatch.setattr("httpx.AsyncClient", _FakeAsyncClient)

        original_seeds = vp_mod._SEED_PROBES
        vp_mod._SEED_PROBES = [("/rest/basket/1", "test-cross-idor", "idor")]
        try:
            result = _run(run_verify_phase(
                session=_StubSession(),
                targets=["http://h.example.com"],
                personas=[
                    {"name": "alice", "login_url": "http://h/login"},
                    {"name": "bob",   "login_url": "http://h/login"},
                ],
                enable_discovery=False,
            ))
        finally:
            vp_mod._SEED_PROBES = original_seeds

        cross = [f for f in result if "cross_principal" in f.get("metadata", {}).get("subclass", "")]
        assert cross, "identical-JSON cross-principal IDOR was not flagged"
        f = cross[0]
        # Highest confidence tier for this signal (per the design).
        assert f["metadata"]["confidence"] >= 0.85
        assert f["metadata"]["signal"] == "identical-json"

    def test_identical_html_shell_still_not_flagged(self, monkeypatch):
        """Defensive regression: identical HTML body (no JSON) across
        identities must STILL be skipped — that's the SPA shell case
        and the earlier behavior should be preserved for non-JSON."""
        from core.wraith.vuln_verifier import VulnVerifier
        import core.wraith.verify_phase as vp_mod

        async def fake_verify(self, **kw):
            return ([], 0)
        monkeypatch.setattr(VulnVerifier, "verify_finding", fake_verify)

        async def fake_auth(p):
            return ({"Authorization": f"Bearer {p['name']}"}, {})
        monkeypatch.setattr("core.wraith.persona_auth.authenticate_persona", fake_auth)

        shell_body = "<html><body>App shell — your session is active</body></html>"

        class _FakeAsyncClient:
            def __init__(self, *args, **kwargs): pass
            async def __aenter__(self): return self
            async def __aexit__(self, *a): return False
            async def get(self, url, headers=None):
                class _R: pass
                r = _R()
                r.status_code = 200
                r.text = shell_body
                return r
        monkeypatch.setattr("httpx.AsyncClient", _FakeAsyncClient)

        original_seeds = vp_mod._SEED_PROBES
        vp_mod._SEED_PROBES = [("/api/users/42", "test-shell", "idor")]
        try:
            result = _run(run_verify_phase(
                session=_StubSession(),
                targets=["http://h.example.com"],
                personas=[
                    {"name": "alice", "login_url": "http://h/login"},
                    {"name": "bob",   "login_url": "http://h/login"},
                ],
                enable_discovery=False,
            ))
        finally:
            vp_mod._SEED_PROBES = original_seeds

        cross = [f for f in result if "cross_principal" in f.get("metadata", {}).get("subclass", "")]
        assert cross == [], "identical HTML across identities must be treated as SPA shell, not IDOR"
