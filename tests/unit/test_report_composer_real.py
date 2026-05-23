"""
Tests for core.reporting.report_composer.ReportComposer — the composer the
API actually uses (cortex.py:get_report_composer wires THIS one, not the
older core.reporting.composer).

Regression for the live bug: EvidenceStore.get_all() returns a DICT keyed
by evidence id. _safe_list_evidence did `list(dict)` which yields KEYS
(ints), and the markdown renderer then called `.get()` on an int →
AttributeError: 'int' object has no attribute 'get'. Report generation
500'd from the app's Report Composer tab.
"""
from __future__ import annotations

from core.reporting.report_composer import ReportComposer, _as_entry_list


# ─────────────────────────── Fakes matching real interfaces ────────

class _DictEvidenceStore:
    """Mimics core.data.evidence_store.EvidenceStore — get_all() returns a
    DICT keyed by evidence id (this is the shape that triggered the bug)."""
    def __init__(self, entries):
        self._entries = entries  # dict: id -> entry dict

    def get_all(self):
        return dict(self._entries)


class _ListFindingStore:
    def __init__(self, findings):
        self._findings = findings

    def get_all(self):
        return list(self._findings)


class _DictFindingStore:
    """A finding store that ALSO returns a dict (defensive — some stores do)."""
    def __init__(self, findings):
        self._findings = findings

    def get_all(self):
        return {f["id"]: f for f in self._findings}


class _NoPathAnalyzer:
    def critical_paths(self, max_paths: int = 5):
        return []


def _evidence_dict():
    # Real EvidenceStore value shape: id/tool/raw_output/metadata/summary/findings.
    return {
        "ev-1": {"id": "ev-1", "tool": "httpx", "raw_output": "HTTP/2 200",
                 "metadata": {}, "summary": "headers captured", "findings": []},
        "ev-2": {"id": "ev-2", "tool": "nmap", "raw_output": "22/tcp open",
                 "metadata": {}, "summary": None, "findings": []},
    }


# ─────────────────────────── The regression ────────────────────────

class TestEvidenceDictRegression:
    def test_generate_markdown_with_dict_evidence_does_not_crash(self):
        # This is the exact configuration that 500'd the report endpoint.
        composer = ReportComposer(
            finding_store=_ListFindingStore([
                {"id": "f1", "title": "Missing CSP", "risk": "medium"},
            ]),
            evidence_ledger=_DictEvidenceStore(_evidence_dict()),
            graph_analyzer=_NoPathAnalyzer(),
        )
        artifact = composer.generate(target="https://about.gitlab.com", report_format="markdown")
        assert artifact.format == "markdown"
        # The evidence section rendered using real keys, not int crash.
        assert "## Evidence" in artifact.content
        assert "2 evidence artifact" in artifact.content
        # tool name surfaced as the type (httpx/nmap), not generic "ARTIFACT".
        assert "HTTPX" in artifact.content or "NMAP" in artifact.content

    def test_generate_json_with_dict_evidence(self):
        composer = ReportComposer(
            finding_store=_ListFindingStore([]),
            evidence_ledger=_DictEvidenceStore(_evidence_dict()),
            graph_analyzer=_NoPathAnalyzer(),
        )
        artifact = composer.generate(target="x", report_format="json")
        assert artifact.format == "json"
        # The evidence entries are the dict VALUES (entry dicts), not keys.
        assert "ev-1" in artifact.content
        assert "httpx" in artifact.content


# ─────────────────────────── _as_entry_list unit ───────────────────

class TestAsEntryList:
    def test_dict_returns_values(self):
        result = _as_entry_list({"a": {"id": "a"}, "b": {"id": "b"}})
        assert result == [{"id": "a"}, {"id": "b"}]

    def test_list_passes_through(self):
        result = _as_entry_list([{"id": "a"}, {"id": "b"}])
        assert result == [{"id": "a"}, {"id": "b"}]

    def test_non_dict_entries_filtered_out(self):
        # The crash entries (ints) must be filtered, never reach the renderer.
        result = _as_entry_list({0: 0, 1: {"id": "ok"}})  # one int value, one dict
        assert result == [{"id": "ok"}]

    def test_list_with_scalars_filtered(self):
        result = _as_entry_list([1, 2, {"id": "ok"}, "str"])
        assert result == [{"id": "ok"}]

    def test_non_iterable_returns_empty(self):
        assert _as_entry_list(42) == []

    def test_empty_dict_returns_empty(self):
        assert _as_entry_list({}) == []


# ─────────────────────────── Dict-shaped finding store too ─────────

class TestDictFindingStore:
    def test_dict_finding_store_does_not_crash(self):
        # Same defensive handling applies to findings — a dict-returning
        # finding store must not produce int "findings".
        composer = ReportComposer(
            finding_store=_DictFindingStore([
                {"id": "f1", "title": "Missing CSP", "risk": "medium"},
                {"id": "f2", "title": "Open Redirect", "risk": "low"},
            ]),
            evidence_ledger=_DictEvidenceStore({}),
            graph_analyzer=_NoPathAnalyzer(),
        )
        artifact = composer.generate(target="x", report_format="markdown")
        # Both findings rendered.
        assert "Missing CSP" in artifact.content
        assert "Open Redirect" in artifact.content


# ─────────────────────────── Severity table + heading (Run #21) ────

class TestSeveritySummaryAndHeadings:
    """Run #21: _build_summary read `risk` (default 'unknown') but findings
    carry `severity`, so the severity table rendered EMPTY. And same-type
    findings rendered as identical headings."""

    def _composer(self, findings):
        return ReportComposer(
            finding_store=_ListFindingStore(findings),
            evidence_ledger=_DictEvidenceStore({}),
            graph_analyzer=_NoPathAnalyzer(),
        )

    def test_severity_table_counts_by_severity_field(self):
        findings = [
            {"id": "a", "type": "Missing Security Header", "severity": "MEDIUM",
             "target": "x", "metadata": {"header": "csp"}},
            {"id": "b", "type": "Missing Security Header", "severity": "MEDIUM",
             "target": "x", "metadata": {"header": "x-frame-options"}},
            {"id": "c", "type": "Open Port", "severity": "INFO",
             "target": "x", "metadata": {"port": 443}},
        ]
        md = self._composer(findings).generate(target="x", report_format="markdown").content
        # The severity table must have populated rows (was empty before).
        assert "MEDIUM" in md and "| 2 " in md.replace("|2", "| 2")
        assert "INFO" in md
        # Not every finding lumped as "unknown".
        assert "unknown" not in md.lower() or "UNKNOWN" not in md

    def test_same_type_findings_get_distinct_headings(self):
        findings = [
            {"id": "a", "type": "Missing Security Header", "severity": "MEDIUM",
             "target": "x", "metadata": {"header": "content-security-policy"}},
            {"id": "b", "type": "Missing Security Header", "severity": "MEDIUM",
             "target": "x", "metadata": {"header": "x-frame-options"}},
        ]
        md = self._composer(findings).generate(target="x", report_format="markdown").content
        # Each heading carries its distinguishing header — not two identical lines.
        assert "content-security-policy" in md
        assert "x-frame-options" in md

    def test_finding_heading_helper(self):
        from core.reporting.report_composer import _finding_heading
        assert _finding_heading({"type": "Open Port", "metadata": {"port": 8443}}) == "Open Port: port 8443"
        assert _finding_heading({"type": "Missing Security Header", "metadata": {"header": "csp"}}) == "Missing Security Header: csp"
        # No distinguishing detail → bare type.
        assert _finding_heading({"type": "WAF Behavior Observed", "metadata": {}}) == "WAF Behavior Observed"
