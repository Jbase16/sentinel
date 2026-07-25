"""
Tests for the PoC generator against the REAL classifier finding-type names.

The Proof Lab was non-functional for 100% of real findings: the classifier
emits "Open Port" / "Missing Security Header" (Title Case, spaces) but the
templates dispatched on "open_port" (snake_case). Every finding fell through
to the empty generic fallback. These tests use the actual type strings that
appear in the DB, so the vocabulary mismatch can never silently regress.
"""
from __future__ import annotations

import pytest

from core.reporting.poc_generator import (
    PoCGenerator,
    PoCSafetyError,
    _normalize_ftype,
    _parse_target,
)


# Real type names emitted by core/toolkit/raw_classifier.py
_REAL_TYPES = [
    "Open Port",
    "Missing Security Header",
    "Session Cookie Misconfiguration",
    "DNS Record",
    "Discovered Subdomain",
    "Directory Listing Enabled",
    "Java Framework Detected",
    "Php Framework Detected",
    "WAF Behavior Observed",
    "Nikto Finding",
    "Backup Artifact Exposed",
    "SSRF Indicator",
    "Directory Enumeration",
]


def _gen(finding):
    return PoCGenerator().generate_for_finding(finding)


# ─────────────────────────── normalize ─────────────────────────────

class TestNormalizeFtype:
    @pytest.mark.parametrize("raw,expected", [
        ("Open Port", "open_port"),
        ("Missing Security Header", "missing_header"),
        ("Session Cookie Misconfiguration", "cookie_misconfig"),
        ("DNS Record", "dns_issue"),
        ("Discovered Subdomain", "subdomain"),
        ("Directory Listing Enabled", "directory_listing"),
        ("Java Framework Detected", "version_disclosure"),
        ("Php Framework Detected", "version_disclosure"),
        ("WAF Behavior Observed", "http_fetch"),
        ("Nikto Finding", "http_fetch"),
    ])
    def test_real_types_map_to_categories(self, raw, expected):
        assert _normalize_ftype(raw) == expected

    def test_unknown_type_falls_back_to_generic(self):
        assert _normalize_ftype("Some Brand New Finding") == "generic"


# ─────────────────────────── No empty PoCs for real types ──────────

class TestNoEmptyPoCs:
    @pytest.mark.parametrize("ftype", _REAL_TYPES)
    def test_real_finding_type_produces_commands(self, ftype):
        # The core regression: EVERY real finding type must produce at least
        # one command (the bug was that they all produced []).
        finding = {
            "id": "f1",
            "type": ftype,
            "severity": "MEDIUM",
            "target": "https://app.example.com",
            "metadata": {"port": 8443, "host": "app.example.com",
                         "header": "content-security-policy", "version": "1.2.3"},
        }
        art = _gen(finding)
        assert art.commands, f"{ftype!r} produced NO commands (regression to the empty-PoC bug)"
        # And it should NOT carry the "not mapped" note for known types.
        assert not any("not mapped" in n for n in art.notes), (
            f"{ftype!r} hit the generic fallback: {art.notes}"
        )


# ─────────────────────────── Field extraction ──────────────────────

class TestFieldExtraction:
    def test_port_pulled_from_metadata(self):
        finding = {"id": "f", "type": "Open Port", "target": "about.gitlab.com",
                   "metadata": {"port": 5432}}
        art = _gen(finding)
        assert any("5432" in c for c in art.commands)

    def test_host_pulled_from_target_url(self):
        finding = {"id": "f", "type": "Missing Security Header",
                   "target": "https://shop.example.com/cart",
                   "metadata": {"header": "x-frame-options"}}
        art = _gen(finding)
        assert any("shop.example.com" in c for c in art.commands)

    def test_https_default_when_scheme_unknown(self):
        # Bare-host target → PoC should default to https, not http.
        finding = {"id": "f", "type": "Missing Security Header",
                   "target": "about.gitlab.com",
                   "metadata": {"header": "content-security-policy"}}
        art = _gen(finding)
        assert any(c.startswith("curl") and "https://about.gitlab.com" in c for c in art.commands)

    def test_specific_header_named_in_title(self):
        finding = {"id": "f", "type": "Missing Security Header",
                   "target": "https://x.com", "metadata": {"header": "strict-transport-security"}}
        art = _gen(finding)
        assert "strict-transport-security" in art.title


# ─────────────────────────── _parse_target ─────────────────────────

class TestParseTarget:
    def test_full_url(self):
        assert _parse_target("https://x.com:8443/a") == ("https", "x.com", 8443, "/a")

    def test_bare_host(self):
        scheme, host, port, path = _parse_target("about.gitlab.com")
        assert host == "about.gitlab.com"
        assert scheme == ""  # unknown → caller defaults to https

    def test_host_with_port(self):
        scheme, host, port, path = _parse_target("example.com:8080")
        assert host == "example.com" and port == 8080

    def test_empty(self):
        assert _parse_target("") == ("", "", None, "")


# ─────────────────────────── Safety still enforced ─────────────────

class TestSafetyStillEnforced:
    @pytest.mark.parametrize("ftype", _REAL_TYPES)
    def test_all_real_type_commands_pass_safety(self, ftype):
        # Every command emitted for a real finding type must be safe
        # (allowlisted exe, no deny-pattern). generate_for_finding runs
        # _assert_safe_command on each — so if any were unsafe, this raises.
        finding = {"id": "f", "type": ftype, "severity": "MEDIUM",
                   "target": "https://app.example.com",
                   "metadata": {"port": 443, "host": "app.example.com",
                                "header": "csp", "version": "1.0"}}
        art = _gen(finding)  # would raise PoCSafetyError if any cmd unsafe
        for c in art.commands:
            exe = c.split(" ", 1)[0]
            assert exe in PoCGenerator._ALLOW_CMDS

    def test_malicious_host_still_rejected(self):
        # Host sanitization must still block injection attempts.
        finding = {"id": "f", "type": "Open Port",
                   "target": "evil.com; rm -rf /", "metadata": {"port": 22}}
        with pytest.raises(PoCSafetyError):
            _gen(finding)
