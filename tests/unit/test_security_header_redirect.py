"""
Tests for the security-header redirect-attribution fix (Calibration Run #18).

The bug: when a tool follows redirects, output has one block per hop. The
old per-block logic flagged a header absent if ANY hop lacked it — so
gitlab.com's 301 (sets HSTS) → about.gitlab.com (no HSTS) produced a false
"HSTS absent on gitlab.com".

The fix: a header is present if it appears in ANY hop of the chain.
"""
from __future__ import annotations

from core.toolkit.raw_classifier import _detect_security_headers


def _missing(findings):
    return {f.metadata["header"] for f in findings}


class TestRedirectChainAttribution:
    def test_hsts_present_in_first_hop_not_flagged(self):
        # The exact gitlab.com shape: 301 with HSTS → 200 without it.
        output = (
            "HTTP/2 301\n"
            "location: https://about.gitlab.com/\n"
            "strict-transport-security: max-age=31536000\n"
            "\n"
            "HTTP/2 200\n"
            "content-type: text/html\n"
        )
        findings = _detect_security_headers("https://gitlab.com", output)
        # HSTS is present in hop 1 → must NOT be flagged absent.
        assert "strict-transport-security" not in _missing(findings)

    def test_genuinely_absent_header_still_flagged(self):
        # about.gitlab.com scanned directly: single response, no HSTS anywhere.
        output = "HTTP/2 200\ncontent-type: text/html\n"
        findings = _detect_security_headers("https://about.gitlab.com", output)
        assert "strict-transport-security" in _missing(findings)

    def test_header_in_any_hop_counts_as_present(self):
        # CSP present only in the final hop → present.
        output = (
            "HTTP/2 301\n"
            "location: https://app.example.com/\n"
            "\n"
            "HTTP/2 200\n"
            "content-security-policy: default-src 'self'\n"
        )
        findings = _detect_security_headers("https://example.com", output)
        assert "content-security-policy" not in _missing(findings)

    def test_redirect_hops_annotated_in_metadata(self):
        output = (
            "HTTP/2 301\nlocation: https://b.example.com/\n"
            "\n"
            "HTTP/2 200\ncontent-type: text/html\n"
        )
        findings = _detect_security_headers("https://example.com", output)
        # Any finding from a multi-hop chain carries redirect_hops.
        for f in findings:
            assert f.metadata.get("redirect_hops") == 2

    def test_single_response_no_redirect_metadata(self):
        output = "HTTP/2 200\ncontent-type: text/html\n"
        findings = _detect_security_headers("https://example.com", output)
        for f in findings:
            assert "redirect_hops" not in f.metadata

    def test_hsts_high_severity_on_https(self):
        output = "HTTP/2 200\ncontent-type: text/html\n"
        findings = _detect_security_headers("https://example.com", output)
        hsts = [f for f in findings if f.metadata["header"] == "strict-transport-security"]
        assert hsts and hsts[0].severity == "HIGH"

    def test_no_http_blocks_returns_empty(self):
        # Output with no HTTP response blocks → nothing to evaluate.
        findings = _detect_security_headers("https://example.com", "garbage output\nno http here")
        assert findings == []

    def test_all_headers_present_across_chain_no_findings(self):
        # A response chain where every security header appears somewhere.
        from core.toolkit.raw_classifier import SECURITY_HEADERS
        header_lines = "\n".join(f"{h}: value" for h in SECURITY_HEADERS)
        output = f"HTTP/2 200\n{header_lines}\n"
        findings = _detect_security_headers("https://example.com", output)
        assert findings == []
