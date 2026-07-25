"""
Tests for CDN-aware port finding suppression (Calibration Run #18).

When a target resolves to a known CDN edge (Cloudflare, Fastly), naive
port scans hit the CDN, not the origin. Those port findings must be
demoted to INFO + annotated rather than sitting in the actionable tier.

Tests use IP literals + an injectable resolver so they're deterministic
(no real DNS).
"""
from __future__ import annotations

from core.toolkit.raw_classifier import (
    cdn_for_target,
    _handle_masscan,
    _handle_naabu,
    _handle_nmap,
    classify,
)


# ─────────────────────────── cdn_for_target ────────────────────────

class TestCdnForTarget:
    def test_cloudflare_ip_literal_detected(self):
        # 104.16.0.1 is inside Cloudflare's 104.16.0.0/13.
        assert cdn_for_target("https://104.16.0.1") == "cloudflare"

    def test_fastly_ip_literal_detected(self):
        # 151.101.1.1 is inside Fastly's 151.101.0.0/16.
        assert cdn_for_target("https://151.101.1.1") == "fastly"

    def test_non_cdn_ip_returns_none(self):
        # 8.8.8.8 (Google DNS) is not in our CDN ranges.
        assert cdn_for_target("https://8.8.8.8") is None

    def test_hostname_resolved_via_injected_resolver(self):
        # Inject a resolver that maps the host to a Cloudflare IP.
        cdn = cdn_for_target(
            "https://gitlab.com",
            resolver=lambda h: "104.16.5.5",
        )
        assert cdn == "cloudflare"

    def test_hostname_resolving_to_non_cdn_returns_none(self):
        cdn = cdn_for_target(
            "https://example.com",
            resolver=lambda h: "93.184.216.34",  # example.com's real IP, not CDN
        )
        assert cdn is None

    def test_unresolvable_host_returns_none(self):
        cdn = cdn_for_target("https://nonexistent.invalid", resolver=lambda h: None)
        assert cdn is None

    def test_host_with_port_parsed(self):
        assert cdn_for_target("104.16.0.1:443", resolver=lambda h: None) == "cloudflare"

    def test_bare_hostname_no_scheme(self):
        cdn = cdn_for_target("gitlab.com", resolver=lambda h: "172.64.1.1")
        assert cdn == "cloudflare"  # 172.64.0.0/13

    def test_empty_target_returns_none(self):
        assert cdn_for_target("", resolver=lambda h: None) is None

    def test_ipv6_cloudflare_detected(self):
        # 2606:4700::1 is inside Cloudflare's 2606:4700::/32.
        assert cdn_for_target("https://[2606:4700::1]", resolver=lambda h: None) == "cloudflare"


# ─────────────────────────── naabu CDN-awareness ───────────────────

class TestNaabuCdnAware:
    def _patch_resolver(self, monkeypatch, ip):
        # cdn_for_target resolves via _resolve_host inside the handler;
        # patch it module-wide so the handler's internal call uses our IP.
        import core.toolkit.raw_classifier as rc
        monkeypatch.setattr(rc, "_resolve_host", lambda h: ip)

    def test_cdn_ports_demoted_to_info(self, monkeypatch):
        self._patch_resolver(monkeypatch, "104.16.0.1")  # Cloudflare
        findings = _handle_naabu("https://gitlab.com", "gitlab.com:22\ngitlab.com:5432\n")
        assert findings
        for f in findings:
            assert f.severity == "INFO", f"CDN port should be INFO, got {f.severity}"
            assert f.metadata.get("cdn_edge") == "cloudflare"
            assert "cdn-edge" in f.tags
            assert "CDN edge" in f.message

    def test_non_cdn_ports_keep_normal_severity(self, monkeypatch):
        self._patch_resolver(monkeypatch, "93.184.216.34")  # not a CDN
        findings = _handle_naabu("https://example.com", "example.com:22\nexample.com:8080\n")
        sev = {f.metadata["port"]: f.severity for f in findings}
        # 22 is a management port → MEDIUM; 8080 → LOW.
        assert sev[22] == "MEDIUM"
        assert sev[8080] == "LOW"
        for f in findings:
            assert "cdn_edge" not in f.metadata


# ─────────────────────────── nmap CDN-awareness ────────────────────

class TestNmapCdnAware:
    def _patch_resolver(self, monkeypatch, ip):
        import core.toolkit.raw_classifier as rc
        monkeypatch.setattr(rc, "_resolve_host", lambda h: ip)

    def test_cdn_nmap_ports_demoted(self, monkeypatch):
        self._patch_resolver(monkeypatch, "104.16.0.1")
        nmap_output = (
            "PORT     STATE SERVICE\n"
            "22/tcp   open  ssh\n"
            "443/tcp  open  https\n"
        )
        findings = [f for f in _handle_nmap("https://gitlab.com", nmap_output)
                    if f.type == "Open Port"]
        assert findings
        for f in findings:
            assert f.severity == "INFO"
            assert f.metadata.get("cdn_edge") == "cloudflare"

    def test_non_cdn_nmap_keeps_management_medium(self, monkeypatch):
        self._patch_resolver(monkeypatch, "93.184.216.34")
        nmap_output = "PORT     STATE SERVICE\n22/tcp   open  ssh\n"
        findings = [f for f in _handle_nmap("https://example.com", nmap_output)
                    if f.type == "Open Port"]
        # 22/SSH on a non-CDN host stays MEDIUM (management surface).
        assert findings[0].severity == "MEDIUM"


# ─────────────────────────── masscan CDN-awareness ─────────────────

class TestMasscanCdnAware:
    def _patch_resolver(self, monkeypatch, ip):
        import core.toolkit.raw_classifier as rc
        monkeypatch.setattr(rc, "_resolve_host", lambda h: ip)

    def test_cdn_masscan_ports_demoted(self, monkeypatch):
        self._patch_resolver(monkeypatch, "151.101.1.1")  # Fastly
        output = "Discovered open port 5432/tcp on gitlab.com\n"
        findings = _handle_masscan("https://gitlab.com", output)
        assert findings[0].severity == "INFO"
        assert findings[0].metadata.get("cdn_edge") == "fastly"


# ─────────────────────────── End-to-end via classify() ─────────────

class TestClassifyEndToEnd:
    def test_naabu_classify_demotes_cdn_ports(self, monkeypatch):
        import core.toolkit.raw_classifier as rc
        monkeypatch.setattr(rc, "_resolve_host", lambda h: "104.16.0.1")
        results = classify("naabu", "https://gitlab.com", "gitlab.com:3389\n")
        open_ports = [r for r in results if r["type"] == "Open Port"]
        assert open_ports
        # 3389/RDP would normally be MEDIUM — but on a CDN edge it's INFO.
        assert all(r["severity"] == "INFO" for r in open_ports)
        assert all(r["metadata"].get("cdn_edge") == "cloudflare" for r in open_ports)
