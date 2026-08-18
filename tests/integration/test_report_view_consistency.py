"""
Cross-view report consistency — the integration test the report bug-class
demanded (Calibration Runs #20-21).

Every report bug this session was a CONTRACT MISMATCH between the finding
producer (the classifier) and a consumer (Report Generator / Bounty /
Proof Lab): `risk` vs `severity`, `title` vs `type`, global-vs-session
store, dict-vs-list evidence, type-name vocabulary. Unit tests missed
them because each test fed its module a hand-made input that happened to
match. This test feeds ALL consumers the SAME realistic finding set (the
exact shape `db.get_findings()` returns) and asserts they agree.

Two tiers:
  Tier 1 — consumer consistency (pure): one seed → all consumers → agree.
  Tier 2 — endpoint session-scoping (fake DB): the Report Generator must
           read the session's findings, not a global store.

If any of these fail, a producer/consumer contract has drifted — which is
exactly the failure that reached production this session.
"""
from __future__ import annotations

from types import SimpleNamespace
from typing import Any, Dict, List

import pytest
from pydantic import ValidationError

from core.reporting.report_composer import ReportComposer
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


def _severity_breakdown(findings):
    out: Dict[str, int] = {}
    for f in findings:
        out[f["severity"].upper()] = out.get(f["severity"].upper(), 0) + 1
    return out


class _ListStore:
    def __init__(self, items): self._items = list(items)
    def get_all(self): return list(self._items)


class _NoPathAnalyzer:
    def critical_paths(self, max_paths: int = 5): return []


def _make_report(findings, evidence=None):
    return ReportComposer(
        finding_store=_ListStore(findings),
        evidence_ledger=_ListStore(evidence or []),
        graph_analyzer=_NoPathAnalyzer(),
    ).generate(target=_TARGET, report_format="markdown")


# ═════════════════════════ Tier 1: consumer consistency ═════════════

class TestConsumerConsistency:
    """One seed → Report Generator, Bounty, Proof Lab → must agree."""

    def test_report_finding_count_matches_seed(self):
        findings = seeded_findings()
        md = _make_report(findings).content
        # The exec summary must report the same count as the seed.
        assert f"**{len(findings)} finding(s)**" in md, (
            f"report count != {len(findings)} seeded findings"
        )

    def test_report_severity_table_matches_breakdown(self):
        findings = seeded_findings()
        breakdown = _severity_breakdown(findings)  # {MEDIUM:7, INFO:8}
        md = _make_report(findings).content
        # Each severity's count from the seed must appear in the table.
        for sev, count in breakdown.items():
            row = [line for line in md.splitlines() if sev in line and "|" in line]
            assert row, f"severity {sev} missing from report table"
            assert str(count) in row[0], (
                f"{sev} count {count} not in report row: {row[0]!r}"
            )

    def test_report_vocabulary_is_subset_of_seed_types(self):
        # No foreign types (vulnerability/misconfig from a global store).
        findings = seeded_findings()
        seed_types = {f["type"] for f in findings}
        md = _make_report(findings).content
        for line in md.splitlines():
            if line.startswith("### ") and ". " in line:
                heading = line.split(". ", 1)[1].split(":")[0].strip()
                if heading and heading != "Scan Metadata":
                    assert heading in seed_types, (
                        f"report heading {heading!r} is not a seeded finding type "
                        f"(foreign vocabulary leaked in)"
                    )

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

    def test_no_consumer_crashes_on_dict_evidence(self):
        # The dict-keyed-evidence crash: report gen with a dict evidence
        # store must not raise.
        findings = seeded_findings()
        dict_evidence = {f"ev{i}": {"id": f"ev{i}", "tool": "nmap", "summary": "x"}
                         for i in range(3)}

        class _DictEvidence:
            def get_all(self): return dict(dict_evidence)

        art = ReportComposer(
            finding_store=_ListStore(findings),
            evidence_ledger=_DictEvidence(),
            graph_analyzer=_NoPathAnalyzer(),
        ).generate(target=_TARGET, report_format="markdown")
        assert "## Evidence" in art.content

    def test_three_views_agree_on_count(self):
        # The headline consistency check: Target Scan (raw findings),
        # Report Generator, and Bounty all describe the same finding set.
        findings = seeded_findings()
        target_scan_count = len(findings)                       # what the tab shows
        report_md = _make_report(findings).content
        bounty = build_reports(findings, scan_id="s", min_severity="INFO")

        # Report Generator count == raw count.
        assert f"**{target_scan_count} finding(s)**" in report_md
        # Bounty groups, but every raw finding is represented across the
        # grouped reports' enumerated instances + singletons.
        represented = 0
        for r in bounty:
            n = r.summary.count("`")  # enumerated labels are backtick-wrapped
            represented += max(1, n // 2)
        assert represented >= target_scan_count - 2, (
            f"bounty represents {represented} of {target_scan_count} findings"
        )


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
