"""
Calibration Run #24 — Scan Intelligence Briefing.

The briefing is the AI Assistant's "executive summary of the entire scan."
Its defining property: counts are COMPLETE — computed over every finding,
never a truncated sample. These tests deliberately use MORE than the old
30-finding chat cap to prove the briefing does not inherit that blindness.
"""
from __future__ import annotations

import re

from core.ai.scan_briefing import build_scan_briefing


def _finding(fid, ftype, severity, target, metadata=None):
    return {
        "id": fid, "type": ftype, "severity": severity, "tool": "scanner",
        "target": target, "message": f"{ftype} on {target}",
        "metadata": metadata or {},
    }


def _big_scan():
    """50 findings (> the old 30 cap): 5 critical SQLi, 10 medium headers,
    35 info ports across 3 hosts."""
    findings = []
    for i in range(5):
        findings.append(_finding(f"sqli{i}", "SQL Injection", "CRITICAL",
                                 "https://a.example.com", {"host": "a.example.com"}))
    for i in range(10):
        findings.append(_finding(f"hdr{i}", "Missing Security Header", "MEDIUM",
                                 "https://a.example.com", {"header": f"h{i}"}))
    for i in range(35):
        host = ["a.example.com", "b.example.com", "c.example.com"][i % 3]
        findings.append(_finding(f"port{i}", "Open Port", "INFO",
                                 f"https://{host}", {"host": host, "port": 8000 + i}))
    return findings


class TestCompleteness:
    """The briefing must count ALL findings, not the first 30."""

    def test_total_count_is_complete(self):
        findings = _big_scan()  # 50
        brief = build_scan_briefing(findings, [], target="https://a.example.com")
        assert "ALL 50 finding(s)" in brief, brief

    def test_severity_histogram_counts_everything(self):
        brief = build_scan_briefing(_big_scan(), [], target="x")
        # 5 critical + 10 medium + 35 info — all must be reflected exactly.
        assert "CRITICAL 5" in brief
        assert "MEDIUM 10" in brief
        assert "INFO 35" in brief

    def test_type_breakdown_counts_beyond_cap(self):
        brief = build_scan_briefing(_big_scan(), [], target="x")
        assert "Open Port ×35" in brief
        assert "Missing Security Header ×10" in brief
        assert "SQL Injection ×5" in brief

    def test_all_hosts_and_ports_surface(self):
        brief = build_scan_briefing(_big_scan(), [], target="x")
        for host in ("a.example.com", "b.example.com", "c.example.com"):
            assert host in brief
        # 35 distinct ports 8000..8034 — the list is complete.
        assert "8000" in brief and "8034" in brief


class TestBoundedSize:
    """Enumerations are capped so a huge scan can't blow the token budget,
    but totals stay exact and clipping is announced."""

    def test_type_enumeration_capped_with_marker(self):
        # 20 distinct types, cap at 5 → must announce the remainder.
        findings = [_finding(f"f{i}", f"Type{i:02d}", "INFO", "x") for i in range(20)]
        brief = build_scan_briefing(findings, [], target="x", max_types=5)
        assert "Finding types (20)" in brief          # total is exact
        assert re.search(r"\+15 more types", brief)    # clip announced

    def test_empty_scan_is_explicit(self):
        brief = build_scan_briefing([], [], target="x")
        assert "No findings or issues" in brief


class TestRichContext:
    def test_issue_confidence_and_top_issues(self):
        issues = [
            {"title": "SQLi login", "confirmation_level": "confirmed", "score": 9.1,
             "target": "a", "capability_types": ["execution"]},
            {"title": "SSRF maybe", "confirmation_level": "hypothesized", "score": 4.0,
             "target": "b", "capability_types": ["access"]},
        ]
        brief = build_scan_briefing([], issues, target="x")
        assert "confirmed 1" in brief and "hypothesized 1" in brief
        # Highest-scored issue listed first.
        assert brief.index("SQLi login") < brief.index("SSRF maybe")

    def test_graph_chains_and_pressure_points(self):
        graph_dto = {
            "count": {"nodes": 6, "edges": 3},
            "attack_chains": [
                {"id": "chain_1", "labels": ["Subdomain", "Open Port", "SQL Injection"],
                 "length": 3, "score": 1.9, "leaf_node": "sqli"},
            ],
            "pressure_points": [
                {"finding_title": "SQL Injection", "attack_paths_blocked": 4},
            ],
        }
        brief = build_scan_briefing(_big_scan(), [], target="x", graph_dto=graph_dto)
        assert "6 nodes, 3 edges" in brief
        assert "Subdomain → Open Port → SQL Injection" in brief
        assert "blocks 4 paths" in brief

    def test_coverage_gaps_from_failed_tools(self):
        tool_runs = [
            {"tool": "nmap", "target": "a.example.com", "timed_out": True, "exit_code": None},
            {"tool": "httpx", "target": "a.example.com", "exit_code": 0},
        ]
        brief = build_scan_briefing(_big_scan(), [], target="x", tool_runs=tool_runs)
        assert "Coverage gaps" in brief
        assert "nmap on a.example.com (TIMED OUT)" in brief
        assert "httpx" not in brief.split("Coverage gaps")[1]  # successful tool not flagged


class TestDeterminism:
    def test_same_input_same_briefing(self):
        f = _big_scan()
        assert build_scan_briefing(f, [], target="x") == build_scan_briefing(f, [], target="x")


class TestKeyTotalsAreQuotable:
    """Run #24 live test: a 9B model handed a 99-port list miscounted it as 79.
    The fix is explicit, labeled, copy-able totals leading the briefing so the
    model QUOTES the number instead of recounting."""

    def test_distinct_port_count_is_explicit(self):
        # _big_scan has 35 distinct ports (8000..8034).
        brief = build_scan_briefing(_big_scan(), [], target="x")
        assert "KEY TOTALS" in brief
        assert "Open ports (distinct): 35" in brief

    def test_finding_total_is_explicit(self):
        assert "Findings (total): 50" in build_scan_briefing(_big_scan(), [], target="x")

    def test_totals_precede_the_long_lists(self):
        # The quotable count must appear BEFORE the long port enumeration, so
        # the model reads the answer before it is tempted to recount.
        brief = build_scan_briefing(_big_scan(), [], target="x")
        assert brief.index("KEY TOTALS") < brief.index("Open ports (35 distinct):")

    def test_instructs_not_to_recount(self):
        brief = build_scan_briefing(_big_scan(), [], target="x")
        assert "do not recount" in brief.lower() or "never recount" in brief.lower()


class TestSelectRelevantFindings:
    """Run #25 drill-down: a finding the user asks about must reach the detail
    slice even when it is low-severity and outside the top-N-by-severity cut."""

    def test_empty_returns_empty(self):
        from core.ai.scan_briefing import select_relevant_findings
        assert select_relevant_findings("anything", []) == []

    def test_no_terms_falls_back_to_severity_order(self):
        from core.ai.scan_briefing import select_relevant_findings
        findings = [
            _finding("a", "Open Port", "INFO", "x"),
            _finding("b", "SQL Injection", "CRITICAL", "x"),
        ]
        # Stopword-only question → pure severity order (critical first).
        out = select_relevant_findings("what did you find", findings, limit=10)
        assert out[0]["id"] == "b"

    def test_asked_port_surfaces_low_sev_over_criticals(self):
        from core.ai.scan_briefing import select_relevant_findings
        # 40 criticals + 1 INFO port; only 30 slots. A naive severity cut would
        # drop the INFO port — relevance must rescue and rank it first.
        findings = [_finding(f"c{i}", "SQL Injection", "CRITICAL", "x") for i in range(40)]
        findings.append(_finding("p8443", "Open Port", "INFO", "x", {"port": 8443}))
        out = select_relevant_findings("what about port 8443?", findings, limit=30)
        assert out[0]["id"] == "p8443", "asked-about port not surfaced first"

    def test_asked_host_surfaces_its_low_sev_finding(self):
        from core.ai.scan_briefing import select_relevant_findings
        findings = [_finding(f"c{i}", "Open Port", "INFO", "https://a.example.com") for i in range(40)]
        findings.append(_finding("rare", "Session Cookie Misconfiguration", "LOW",
                                 "https://target.example.com", {"host": "target.example.com"}))
        out = select_relevant_findings("tell me about target.example.com", findings, limit=30)
        assert any(f["id"] == "rare" for f in out)

    def test_limit_respected(self):
        from core.ai.scan_briefing import select_relevant_findings
        findings = [_finding(f"f{i}", "Open Port", "INFO", "x") for i in range(50)]
        assert len(select_relevant_findings("ports", findings, limit=10)) == 10

    def test_deterministic(self):
        from core.ai.scan_briefing import select_relevant_findings
        findings = [_finding(f"f{i}", "Open Port", "INFO", "x", {"port": 8000 + i}) for i in range(20)]
        a = select_relevant_findings("port 8005", findings, limit=5)
        b = select_relevant_findings("port 8005", findings, limit=5)
        assert [f["id"] for f in a] == [f["id"] for f in b]
