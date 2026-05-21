"""
Bug-bounty scope safety tests.

The single most important invariant for bounty work: Sentinel MUST NOT scan
anything outside the explicit scope. Out-of-scope reports get researchers
banned from programs. This test fixes that invariant in code.

Test layout mirrors a realistic HackerOne-style scope:
  - in-scope wildcard:        *.bounty-target.com
  - in-scope root:            bounty-target.com
  - in-scope CIDR:            203.0.113.0/24
  - explicit exclusion:       !staging.bounty-target.com
  - explicit exclusion:       !*.internal.bounty-target.com

Then we throw a battery of URLs at it and assert each one is allow/denied
correctly. Cloud-metadata and loopback targets are checked specifically
because they're the highest-impact SSRF self-pivots.
"""
from __future__ import annotations

import pytest

from core.base.scope import (
    AssetType,
    ScopeDecision,
    ScopeRegistry,
    ScopeRule,
)


def _build_bounty_registry() -> ScopeRegistry:
    """Build a registry that mirrors a typical bounty program's scope."""
    reg = ScopeRegistry(resolve_dns=False, bounty_mode=True)

    # In-scope: the root domain and all subdomains
    reg.add_rule(ScopeRule(AssetType.DOMAIN, "bounty-target.com", ScopeDecision.ALLOW))
    reg.add_rule(ScopeRule(AssetType.WILDCARD, "*.bounty-target.com", ScopeDecision.ALLOW))

    # In-scope: a specific CIDR block of company infrastructure
    reg.add_rule(ScopeRule(AssetType.CIDR, "203.0.113.0/24", ScopeDecision.ALLOW))

    # Explicit exclusions (DENY beats ALLOW at same specificity)
    reg.add_rule(ScopeRule(AssetType.DOMAIN, "staging.bounty-target.com", ScopeDecision.DENY))
    reg.add_rule(ScopeRule(AssetType.WILDCARD, "*.internal.bounty-target.com", ScopeDecision.DENY))

    return reg


# ---------------------------------------------------------------------------
# Positive cases — these should be ALLOWED
# ---------------------------------------------------------------------------

class TestBountyScopeAllowed:
    @pytest.fixture
    def registry(self) -> ScopeRegistry:
        return _build_bounty_registry()

    def test_root_domain_allowed(self, registry):
        decision = registry.resolve("https://bounty-target.com")
        assert decision.verdict == ScopeDecision.ALLOW

    def test_subdomain_allowed_by_wildcard(self, registry):
        decision = registry.resolve("https://api.bounty-target.com/v1/users")
        assert decision.verdict == ScopeDecision.ALLOW

    def test_deep_subdomain_allowed_by_wildcard(self, registry):
        decision = registry.resolve("https://www.api.bounty-target.com")
        assert decision.verdict == ScopeDecision.ALLOW

    def test_cidr_in_scope(self, registry):
        decision = registry.resolve("http://203.0.113.42")
        assert decision.verdict == ScopeDecision.ALLOW


# ---------------------------------------------------------------------------
# Negative cases — these MUST be DENIED in bounty mode
# ---------------------------------------------------------------------------

class TestBountyScopeDenied:
    @pytest.fixture
    def registry(self) -> ScopeRegistry:
        return _build_bounty_registry()

    def test_unknown_external_domain_denied(self, registry):
        """A completely unrelated domain must be rejected."""
        decision = registry.resolve("https://example.com")
        assert decision.verdict == ScopeDecision.DENY
        assert decision.reason_code == "NO_MATCH"

    def test_lookalike_domain_denied(self, registry):
        """Domain that LOOKS like the target but isn't."""
        decision = registry.resolve("https://bounty-target.com.evil.attacker.com")
        assert decision.verdict == ScopeDecision.DENY

    def test_suffix_attack_denied(self, registry):
        """Attacker-controlled domain that ends with target name."""
        decision = registry.resolve("https://nottargetbounty-target.com")
        assert decision.verdict == ScopeDecision.DENY

    def test_explicit_exclusion_overrides_wildcard(self, registry):
        """staging.bounty-target.com is explicitly excluded even though
        the wildcard *.bounty-target.com would otherwise allow it."""
        decision = registry.resolve("https://staging.bounty-target.com/login")
        assert decision.verdict == ScopeDecision.DENY
        assert decision.reason_code == "MATCH_DENY"

    def test_wildcard_exclusion_overrides_wildcard_allow(self, registry):
        """*.internal.bounty-target.com is excluded; *.bounty-target.com allows."""
        decision = registry.resolve("https://secret.internal.bounty-target.com")
        assert decision.verdict == ScopeDecision.DENY

    def test_cidr_neighbor_denied(self, registry):
        """An IP just outside the allowed CIDR must be denied."""
        decision = registry.resolve("http://203.0.114.1")
        assert decision.verdict == ScopeDecision.DENY


# ---------------------------------------------------------------------------
# SSRF self-pivot defense — the highest-impact safety checks
# ---------------------------------------------------------------------------

class TestSSRFSelfPivotDefense:
    """Cloud metadata endpoints and loopback addresses must not be scanned
    unless explicitly placed in scope. These are the targets a malicious
    target could try to redirect Sentinel into."""

    @pytest.fixture
    def registry(self) -> ScopeRegistry:
        return _build_bounty_registry()

    def test_aws_imds_denied(self, registry):
        decision = registry.resolve("http://169.254.169.254/latest/meta-data/")
        assert decision.verdict == ScopeDecision.DENY

    def test_gcp_metadata_denied(self, registry):
        decision = registry.resolve("http://metadata.google.internal/computeMetadata/v1/")
        assert decision.verdict == ScopeDecision.DENY

    def test_azure_imds_denied(self, registry):
        decision = registry.resolve("http://169.254.169.254/metadata/instance")
        assert decision.verdict == ScopeDecision.DENY

    def test_loopback_v4_denied(self, registry):
        decision = registry.resolve("http://127.0.0.1:8765")
        assert decision.verdict == ScopeDecision.DENY

    def test_loopback_v6_denied(self, registry):
        decision = registry.resolve("http://[::1]:8765")
        assert decision.verdict == ScopeDecision.DENY

    def test_rfc1918_denied(self, registry):
        """Private network space should not be reachable unless explicit."""
        for addr in ("http://10.0.0.1", "http://192.168.1.1", "http://172.16.0.1"):
            decision = registry.resolve(addr)
            assert decision.verdict == ScopeDecision.DENY, (
                f"{addr} should be denied in bounty mode"
            )


# ---------------------------------------------------------------------------
# Wildcard semantics — the tricky cases that catch real bugs
# ---------------------------------------------------------------------------

class TestWildcardSemantics:
    def test_wildcard_does_not_match_apex(self):
        """*.example.com matches sub.example.com but NOT example.com itself.

        This matches HackerOne's documented wildcard semantics. If a program
        wants the apex in scope, they list it separately as a DOMAIN rule.
        """
        reg = ScopeRegistry(bounty_mode=True)
        reg.add_rule(ScopeRule(AssetType.WILDCARD, "*.example.com", ScopeDecision.ALLOW))

        sub = reg.resolve("https://api.example.com")
        apex = reg.resolve("https://example.com")

        assert sub.verdict == ScopeDecision.ALLOW
        assert apex.verdict == ScopeDecision.DENY

    def test_more_specific_rule_wins(self):
        """A DOMAIN rule is more specific than a WILDCARD rule and beats it."""
        reg = ScopeRegistry(bounty_mode=True)
        reg.add_rule(ScopeRule(AssetType.WILDCARD, "*.example.com", ScopeDecision.ALLOW))
        reg.add_rule(ScopeRule(AssetType.DOMAIN, "admin.example.com", ScopeDecision.DENY))

        decision = reg.resolve("https://admin.example.com/internal")
        assert decision.verdict == ScopeDecision.DENY

    def test_punycode_normalization(self):
        """Unicode hostnames must be punycode-normalized so attackers can't
        bypass scope rules by using unicode lookalikes."""
        reg = ScopeRegistry(bounty_mode=True)
        reg.add_rule(ScopeRule(AssetType.DOMAIN, "bounty-target.com", ScopeDecision.ALLOW))

        # Unicode 'a' (U+0430 Cyrillic) instead of ASCII 'a' — classic IDN homograph
        decision = reg.resolve("https://bounty-tаrget.com")
        assert decision.verdict == ScopeDecision.DENY


# ---------------------------------------------------------------------------
# Empty / invalid input — must not crash, must fail closed
# ---------------------------------------------------------------------------

class TestInvalidInputs:
    @pytest.fixture
    def registry(self) -> ScopeRegistry:
        return _build_bounty_registry()

    def test_empty_string_denied(self, registry):
        decision = registry.resolve("")
        assert decision.verdict == ScopeDecision.DENY
        assert decision.reason_code == "INVALID_TARGET"

    def test_whitespace_only_denied(self, registry):
        decision = registry.resolve("   ")
        assert decision.verdict == ScopeDecision.DENY

    def test_malformed_url_denied(self, registry):
        """A nonsense input shouldn't accidentally match anything."""
        decision = registry.resolve("not a url at all")
        # Either INVALID_TARGET or NO_MATCH — either is fail-closed.
        assert decision.verdict == ScopeDecision.DENY
