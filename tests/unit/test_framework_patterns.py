"""
Tests for FRAMEWORK_PATTERNS regex contract — Bug #5.

The PHP and Java patterns historically lacked word boundaries, which caused:
  1. False positives from hostnames: "testphp.vulnweb.com" matched the
     PHP pattern and produced an INFO finding with version="".
  2. False positives from newline-bridging: proof text like
     "wp-config.php\\n403 GET" captured "403" as the PHP version because
     \\s* matched the newline.
  3. The Java pattern matched inside "javascript", producing spurious
     Java framework findings.

This test locks in the behavioral contract after the Bug #5 fix:
  - php / java patterns are word-isolated on both sides
  - the version separator (when present) does not cross newlines
  - a bare "PHP" / "Java" token still produces an informational match
"""
from __future__ import annotations

from core.toolkit.raw_classifier import FRAMEWORK_PATTERNS, _detect_frameworks


# ---------- Direct regex contract ----------

class TestPhpPatternIsWordBounded:
    """The PHP pattern must not match PHP-as-substring inside other words."""

    def test_does_not_match_inside_hostname(self):
        # Real-world false positive that triggered Bug #5 investigation.
        assert FRAMEWORK_PATTERNS["php"].search("testphp.vulnweb.com") is None

    def test_does_not_match_phpinfo_substring(self):
        # "phpinfo" is a function/word that should not be tagged as a
        # PHP framework finding.
        assert FRAMEWORK_PATTERNS["php"].search("phpinfo") is None

    def test_does_not_capture_403_across_newline(self):
        # Pre-fix this captured version="403" because \\s* matched \\n.
        match = FRAMEWORK_PATTERNS["php"].search("wp-config.php\n403 GET /admin")
        # Either the match is suppressed entirely, OR the version group is empty —
        # the critical thing is we never label "403" as a PHP version.
        if match is not None:
            assert (match.group(1) or "") == "", (
                f"newline-bridge regression: captured version={match.group(1)!r}"
            )

    def test_matches_powered_by_header(self):
        match = FRAMEWORK_PATTERNS["php"].search("X-Powered-By: PHP/5.6.40")
        assert match is not None
        assert match.group(1) == "5.6.40"

    def test_matches_bare_php_token(self):
        # Informational signal — bare "PHP" in a header still produces a finding.
        match = FRAMEWORK_PATTERNS["php"].search("Server: PHP")
        assert match is not None
        # Version is None for the optional group (the caller normalizes to "").
        assert match.group(1) is None

    def test_matches_with_space_separator(self):
        match = FRAMEWORK_PATTERNS["php"].search("PHP 7.4.10")
        assert match is not None
        assert match.group(1) == "7.4.10"


class TestJavaPatternIsWordBounded:
    """The Java pattern must not match inside 'javascript' or similar tokens."""

    def test_does_not_match_javascript(self):
        # The dominant false positive: every page that mentions JavaScript.
        assert FRAMEWORK_PATTERNS["java"].search("JavaScript: enabled") is None

    def test_does_not_match_inside_hostname(self):
        assert FRAMEWORK_PATTERNS["java"].search("javascript.example.com") is None

    def test_matches_java_version_in_header(self):
        match = FRAMEWORK_PATTERNS["java"].search("Server: Java/17.0.2")
        assert match is not None
        assert match.group(1) == "17.0.2"

    def test_matches_bare_java_token(self):
        match = FRAMEWORK_PATTERNS["java"].search("X-Powered-By: Java")
        assert match is not None
        assert match.group(1) is None


# ---------- End-to-end through _detect_frameworks ----------

class TestDetectFrameworksEndToEnd:
    """The caller of FRAMEWORK_PATTERNS — locks in the user-visible behavior."""

    def test_testphp_hostname_produces_no_php_finding(self):
        # This is the exact false-positive shape from the Bug #5 investigation:
        # tool output mentions testphp.vulnweb.com, and we got an INFO
        # "Php Framework Detected" finding with empty version.
        findings = _detect_frameworks(
            target="https://example.com",
            output="Crawled testphp.vulnweb.com and recorded redirect.",
        )
        php_findings = [f for f in findings if f.metadata.get("framework") == "php"]
        assert php_findings == [], (
            f"expected no PHP findings from testphp hostname, got {php_findings}"
        )

    def test_real_powered_by_php_still_detected(self):
        # The 24/80 cases that worked correctly before must keep working.
        findings = _detect_frameworks(
            target="https://example.com",
            output="HTTP/1.1 200 OK\nX-Powered-By: PHP/5.6.40\n",
        )
        php = [f for f in findings if f.metadata.get("framework") == "php"]
        assert len(php) == 1
        assert php[0].metadata["version"] == "5.6.40"

    def test_javascript_mention_produces_no_java_finding(self):
        findings = _detect_frameworks(
            target="https://example.com",
            output="Page loaded JavaScript dependencies successfully.",
        )
        java = [f for f in findings if f.metadata.get("framework") == "java"]
        assert java == []

    def test_wpconfig_proof_does_not_capture_403_as_version(self):
        # The "version=403" finding from the live DB — the regex must never
        # produce a numeric version from a filename followed by a status code.
        findings = _detect_frameworks(
            target="https://example.com",
            output="Found wp-config.php\n403 GET /wp-admin/",
        )
        php = [f for f in findings if f.metadata.get("framework") == "php"]
        # If we do match the bare "php" of "wp-config.php" (acceptable), the
        # captured version must be empty — never "403".
        for finding in php:
            assert finding.metadata["version"] != "403", (
                f"regressed Bug #5 newline-bridge: {finding.metadata}"
            )


# ---------- testssl client-simulation context filter (Calibration Run #17) ----------

class TestTlsClientSimFiltering:
    """testssl's client-simulation section lists TLS clients (Java, Safari,
    Chrome) connecting TO the server. Those are NOT server-side frameworks.
    The framework detector must not emit findings from those lines.

    These are the exact output shapes captured from the first live GitLab
    scan that produced false "Java Framework Detected" findings."""

    def test_testssl_java_client_sim_produces_no_java_finding(self):
        # Verbatim shape from the live gitlab.com testssl output.
        output = (
            " Java 8u442 (OpenJDK)         TLSv1.3   TLS_AES_256_GCM_SHA384            253 bit ECDH (X25519)\n"
            " Java 11.0.2 (OpenJDK)        TLSv1.3   TLS_AES_128_GCM_SHA256            256 bit ECDH (P-256)\n"
            " Java 17.0.3 (OpenJDK)        TLSv1.3   TLS_AES_256_GCM_SHA384            253 bit ECDH (X25519)\n"
            " Java 21.0.6                  TLSv1.3   TLS_AES_256_GCM_SHA384            253 bit ECDH (X25519)\n"
        )
        findings = _detect_frameworks(target="https://gitlab.com", output=output)
        java = [f for f in findings if f.metadata.get("framework") == "java"]
        assert java == [], f"testssl client-sim leaked Java findings: {[j.metadata for j in java]}"

    def test_testssl_safari_client_sim_produces_no_finding(self):
        output = " Safari 18.4 (macOS 15.4)     TLSv1.3   TLS_AES_128_GCM_SHA256   253 bit ECDH (X25519)\n"
        findings = _detect_frameworks(target="https://x.com", output=output)
        # No framework should be detected from a TLS client-sim line.
        assert findings == []

    def test_real_java_server_banner_still_detected(self):
        # A genuine server-side Java banner (no TLS-handshake tokens on the
        # line) must STILL be detected — we only suppress the client-sim case.
        output = "X-Powered-By: Java/17.0.3\nServer: Apache-Coyote/1.1\n"
        findings = _detect_frameworks(target="https://x.com", output=output)
        java = [f for f in findings if f.metadata.get("framework") == "java"]
        assert len(java) == 1
        assert java[0].metadata["version"] == "17.0.3"

    def test_mixed_output_keeps_server_banner_drops_client_sim(self):
        # Same scan output containing BOTH a real banner and client-sim lines.
        output = (
            "HTTP/1.1 200 OK\n"
            "X-Powered-By: Java/17.0.3\n"
            "\n"
            " Running client simulations (HTTP) via sockets\n"
            " Java 8u442 (OpenJDK)   TLSv1.3   TLS_AES_256_GCM_SHA384   253 bit ECDH (X25519)\n"
        )
        findings = _detect_frameworks(target="https://x.com", output=output)
        java = [f for f in findings if f.metadata.get("framework") == "java"]
        # Exactly one — the real banner. The client-sim "Java 8u442" is dropped.
        assert len(java) == 1
        assert java[0].metadata["version"] == "17.0.3"
