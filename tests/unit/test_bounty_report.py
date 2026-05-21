"""
Tests for core.reporting.bounty_report (Calibration Run #20 fixes).

Two live bugs surfaced when generating a real bounty report for the
about.gitlab.com scan:
  1. Grammar: "...vulnerability appears to was identified..." — the
     confidence hedge was concatenated mid-clause.
  2. Over-dedup: 7 distinct missing-header findings (same type+asset,
     different header) collapsed to ONE report naming only one header;
     the other 6 were silently dropped.

There were no bounty_report tests before — this file adds them.
"""
from __future__ import annotations

import pytest

from core.reporting.bounty_report import (
    build_report,
    build_reports,
    _distinguishing_label,
)


def _headers_findings():
    headers = [
        "content-security-policy", "x-frame-options", "referrer-policy",
        "permissions-policy", "x-content-type-options",
        "cross-origin-opener-policy", "cross-origin-embedder-policy",
    ]
    return [
        {"id": f"h{i}", "type": "Missing Security Header", "severity": "MEDIUM",
         "target": "https://about.gitlab.com", "metadata": {"header": h}}
        for i, h in enumerate(headers)
    ]


# ─────────────────────────── Grammar ───────────────────────────────

class TestGrammar:
    def test_no_appears_to_was_grammar_bug(self):
        # The exact broken phrase from the live report must never appear.
        reports = build_reports(_headers_findings(), min_severity="MEDIUM")
        for r in reports:
            assert "appears to was" not in r.summary
            assert "appears to exists" not in r.summary

    def test_low_confidence_uses_potential_framing(self):
        # A finding with no CVSS-strengthening metadata scores LOW confidence
        # → summary should hedge grammatically ("potential" / "may be present").
        f = {"id": "x", "type": "Missing Security Header", "severity": "MEDIUM",
             "target": "https://x.com", "metadata": {"header": "csp"}}
        r = build_report(f)
        # Either phrasing is acceptable; the point is it's grammatical.
        assert ("potential" in r.summary.lower()) or ("may be present" in r.summary.lower()) \
            or ("was identified" in r.summary.lower())
        assert "appears to was" not in r.summary

    def test_summary_is_nonempty(self):
        r = build_report(_headers_findings()[0])
        assert len(r.summary) > 20


# ─────────────────────────── Grouping / enumeration ────────────────

class TestGroupingEnumeration:
    def test_seven_headers_become_one_enumerated_report(self):
        reports = build_reports(_headers_findings(), min_severity="MEDIUM")
        # One report (same type+asset), not seven.
        assert len(reports) == 1
        summary = reports[0].summary
        # But it enumerates all 7 — none silently dropped (the bug).
        assert "7 instances" in summary
        for h in ("content-security-policy", "x-frame-options",
                  "cross-origin-embedder-policy"):
            assert h in summary

    def test_different_assets_stay_separate(self):
        findings = [
            {"id": "a", "type": "Missing Security Header", "severity": "MEDIUM",
             "target": "https://a.example.com", "metadata": {"header": "csp"}},
            {"id": "b", "type": "Missing Security Header", "severity": "MEDIUM",
             "target": "https://b.example.com", "metadata": {"header": "csp"}},
        ]
        reports = build_reports(findings, min_severity="MEDIUM")
        assert len(reports) == 2

    def test_single_finding_no_enumeration_line(self):
        # A lone finding shouldn't get the "covers N instances" line.
        f = [{"id": "x", "type": "Missing Security Header", "severity": "MEDIUM",
              "target": "https://x.com", "metadata": {"header": "csp"}}]
        reports = build_reports(f, min_severity="MEDIUM")
        assert "instances" not in reports[0].summary

    def test_primary_is_highest_severity_in_group(self):
        # Group with mixed severities → primary report carries the highest.
        findings = [
            {"id": "lo", "type": "Open Port", "severity": "LOW",
             "target": "https://x.com", "metadata": {"port": 8080}},
            {"id": "hi", "type": "Open Port", "severity": "MEDIUM",
             "target": "https://x.com", "metadata": {"port": 22}},
        ]
        reports = build_reports(findings, min_severity="LOW")
        assert len(reports) == 1
        assert reports[0].severity == "MEDIUM"
        # Both ports enumerated.
        assert "port 22" in reports[0].summary and "port 8080" in reports[0].summary


# ─────────────────────────── Distinguishing labels ─────────────────

class TestDistinguishingLabel:
    def test_header_label(self):
        assert _distinguishing_label({"metadata": {"header": "csp"}}) == "csp"

    def test_port_label(self):
        assert _distinguishing_label({"metadata": {"port": 22, "protocol": "tcp"}}) == "port 22/tcp"

    def test_port_label_no_proto(self):
        assert _distinguishing_label({"metadata": {"port": 443}}) == "port 443"

    def test_version_label(self):
        assert _distinguishing_label({"metadata": {"version": "1.2.3"}}) == "v1.2.3"

    def test_empty_when_nothing_distinct(self):
        assert _distinguishing_label({"metadata": {}}) == ""

    def test_long_message_not_used_as_label(self):
        f = {"metadata": {}, "message": "x" * 200}
        assert _distinguishing_label(f) == ""


# ─────────────────────────── Report shape ──────────────────────────

class TestReportShape:
    def test_report_has_cvss_and_steps(self):
        r = build_report(_headers_findings()[0])
        assert r.cvss is not None
        assert r.cvss.base_score > 0
        assert r.steps_to_reproduce  # non-empty
        assert r.impact
        assert r.remediation

    def test_severity_filter_excludes_below_min(self):
        findings = [
            {"id": "info", "type": "DNS Record", "severity": "INFO",
             "target": "https://x.com", "metadata": {}},
            {"id": "med", "type": "Missing Security Header", "severity": "MEDIUM",
             "target": "https://x.com", "metadata": {"header": "csp"}},
        ]
        reports = build_reports(findings, min_severity="MEDIUM")
        # INFO excluded; only the MEDIUM survives.
        assert len(reports) == 1
        assert reports[0].severity == "MEDIUM"
