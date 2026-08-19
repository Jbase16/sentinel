"""
Cross-view report consistency — the integration test the report bug-class
demanded (Calibration Runs #20-21).

This test feeds retained consumers the same realistic finding set (the
exact shape ``db.get_findings()`` returns) and verifies the canonical report
endpoint remains session-scoped.

Two tiers:
  Tier 1 — retained consumer coverage for Bounty and Proof Lab.
  Tier 2 — endpoint session-scoping (fake DB): the Report Generator must
           read the canonical session, not a global store.

If any of these fail, a producer/consumer contract has drifted — which is
exactly the failure that reached production this session.
"""
from __future__ import annotations

from types import SimpleNamespace
from typing import Any, Dict, List

import pytest
from pydantic import ValidationError

from core.reporting.bounty_report import build_reports
from core.reporting.poc_generator import PoCGenerator


# ─────────────────────────────────────────────────────────────────────
# The seed: findings in the EXACT shape db.get_findings() returns
# (RawFinding.as_dict() + injected id/created_at). Mirrors a real
# about.gitlab.com scan: 7 missing headers, 4 ports, DNS, subdomain, WAF.
# ─────────────────────────────────────────────────────────────────────

_TARGET = "https://about.gitlab.com"


def _finding(fid, ftype, severity, message, metadata):
    return {
        "id": fid,
        "type": ftype,
        "severity": severity,
        "tool": "scanner",
        "target": _TARGET,
        "message": message,
        "proof": f"evidence for {message}",
        "tags": [],
        "families": ["misconfiguration"],
        "metadata": metadata,
        "created_at": 1779000000.0,
    }


def seeded_findings() -> List[Dict[str, Any]]:
    headers = [
        "content-security-policy", "x-frame-options", "referrer-policy",
        "permissions-policy", "x-content-type-options",
        "cross-origin-opener-policy", "cross-origin-embedder-policy",
    ]
    findings: List[Dict[str, Any]] = []
    for i, h in enumerate(headers):
        findings.append(_finding(f"hdr{i}", "Missing Security Header", "MEDIUM",
                                 f"{h} absent", {"header": h}))
    for i, p in enumerate([8443, 8080, 443, 80]):
        findings.append(_finding(f"port{i}", "Open Port", "INFO",
                                 f"about.gitlab.com:{p}", {"port": p, "host": "about.gitlab.com"}))
    findings.append(_finding("waf", "WAF Behavior Observed", "INFO", "cloudflare", {}))
    findings.append(_finding("sub", "Discovered Subdomain", "INFO",
                             "www.about.gitlab.com", {}))
    for i, ip in enumerate(["172.64.144.122", "104.18.43.134"]):
        findings.append(_finding(f"dns{i}", "DNS Record", "INFO",
                                 f"about.gitlab.com A {ip}", {}))
    return findings  # 7 + 4 + 1 + 1 + 2 = 15


class _NoPathAnalyzer:
    def critical_paths(self, max_paths: int = 5): return []


# ═════════════════════════ Tier 1: retained consumers ═══════════════

class TestRetainedConsumerCoverage:
    """One seed remains usable by Bounty and Proof Lab."""

    def test_every_finding_gets_a_usable_poc(self):
        # Proof Lab: every finding → non-empty commands + a real title.
        gen = PoCGenerator()
        for f in seeded_findings():
            art = gen.generate_for_finding(f)
            assert art.commands, f"{f['type']} produced an empty PoC"
            assert art.title and "Untitled" not in art.title, (
                f"{f['type']} produced an Untitled PoC"
            )
            assert not any("not mapped" in n for n in art.notes), (
                f"{f['type']} hit the empty generic fallback: {art.notes}"
            )

    def test_bounty_enumerates_every_finding(self):
        # Bounty groups by (type, asset) — but every finding must be
        # accounted for in the enumerated instances (none silently dropped).
        findings = seeded_findings()
        reports = build_reports(findings, scan_id="s", min_severity="INFO")
        # The 7 missing headers → 1 grouped report enumerating all 7.
        hdr_report = next(r for r in reports if "Missing Security Header" in r.title)
        for h in ("content-security-policy", "cross-origin-embedder-policy"):
            assert h in hdr_report.summary, f"bounty dropped header {h}"
        # The 4 ports → 1 grouped report enumerating all 4.
        port_report = next(r for r in reports if "Open Port" in r.title)
        for p in ("8443", "8080", "443", "80"):
            assert f"port {p}" in port_report.summary, f"bounty dropped port {p}"

# ═════════════════════════ Tier 2: endpoint session-scoping ════════

class _FakeDB:
    """Fake Database for report-session target authorization."""
    def __init__(self, sessions: Dict[str, List[Dict[str, Any]]]):
        self._sessions = sessions
        self.canonical_read_calls: List[str] = []

    async def fetch_all(self, query, params=()):
        # _resolve_session_id's "latest session" query.
        sids = list(self._sessions.keys())
        return [[sids[-1]]] if sids else []

    async def get_session(self, session_id):
        return {"target": _TARGET}


class _FakeCanonicalReadModel:
    def __init__(self, findings: List[Dict[str, Any]]) -> None:
        self._findings = findings

    def finding_views(self) -> List[Dict[str, Any]]:
        return list(self._findings)

    def evidence_views(self) -> List[Dict[str, Any]]:
        return []


class TestEndpointSessionScoping:
    async def _call(self, fake_db, monkeypatch, session_id):
        import core.data.db as db_mod
        from core.reporting import submission_candidate as candidate_module
        from core.server.routers import cortex
        monkeypatch.setattr(db_mod.Database, "instance", staticmethod(lambda: fake_db))
        def load_read_model(requested_session_id):
            fake_db.canonical_read_calls.append(requested_session_id)
            return _FakeCanonicalReadModel(
                fake_db._sessions.get(requested_session_id, [])
            )
        monkeypatch.setattr(
            cortex,
            "load_canonical_session_read_model",
            load_read_model,
        )
        selected = fake_db._sessions[session_id][0]
        claims = {
            "title": selected["type"],
            "severity": selected["severity"],
            "summary": selected["message"],
            "remediation": None,
            "confirmation_level": "probable",
            "target_url": selected["target"],
        }
        candidate = SimpleNamespace(
            candidate_digest="submission_candidate:" + "a" * 64,
            canonical_revision="canonical_session_read_model:" + "b" * 64,
            finding_id=selected["id"],
            target_url=selected["target"],
        )
        rendered = SimpleNamespace(
            render_digest="submission_candidate_render:" + "c" * 64,
            markdown=f"# {claims['title']}\n\n{claims['summary']}\n",
        )
        monkeypatch.setattr(
            candidate_module,
            "resolve_submission_candidate",
            lambda read_model, finding_id=None: candidate,
        )
        monkeypatch.setattr(
            candidate_module,
            "render_submission_candidate",
            lambda value: rendered,
        )
        monkeypatch.setattr(
            candidate_module,
            "candidate_report_payload",
            lambda value, rendered=None: {"claims": claims},
        )
        req = cortex.ReportGenerateRequest(
            target=_TARGET,
            format="markdown",
            session_id=session_id,
            finding_id=selected["id"],
        )
        return await cortex.generate_report(req, graph_analyzer=_NoPathAnalyzer())

    async def test_explicit_session_id_is_used(self, monkeypatch):
        fake = _FakeDB({"sess-A": seeded_findings(), "sess-B": []})
        resp = await self._call(fake, monkeypatch, "sess-A")
        # Endpoint pulled the canonical revision for the requested session.
        assert fake.canonical_read_calls == ["sess-A"]
        assert resp.claims["title"] == "Missing Security Header"
        assert "content-security-policy absent" in resp.content

    async def test_missing_session_id_is_rejected(self):
        # Sensitive artifact reads must never guess which session owns them.
        from core.server.routers import cortex

        with pytest.raises(ValidationError):
            cortex.ReportGenerateRequest(target=_TARGET, format="markdown")

    async def test_other_sessions_findings_do_not_leak(self, monkeypatch):
        # Requesting sess-A must NOT include sess-B's findings — the exact
        # global-store bug (cross-session leakage) this fixes.
        sess_b = [_finding("bX", "SQL Injection", "HIGH", "leaked!", {})]
        fake = _FakeDB({"sess-A": seeded_findings(), "sess-B": sess_b})
        resp = await self._call(fake, monkeypatch, "sess-A")
        assert "SQL Injection" not in resp.content
        assert "leaked!" not in resp.content
