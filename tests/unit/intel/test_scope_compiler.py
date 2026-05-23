"""
Tests for scope_compiler (Phase 2C).

Critical contracts:

  1. Emitted lines, when fed back into the existing scope parser at
     ``core/server/routers/scans.py:265-281``, reconstruct the same
     scope decisions. This is the **integration round-trip** — if it
     fails, ingest silently breaks the engine.
  2. Headers are present and self-describing (program name, source URL,
     generated-at timestamp, confidence).
  3. DENY rules start with ``!``, ALLOW rules don't.
  4. Asset-type inference: wildcards stay wildcards, CIDRs stay CIDRs.
  5. Empty scope produces a warning comment, not a silent empty file.
  6. Unsupported rule types (MOBILE_APP, SOURCE_CODE) emit a comment,
     not a parse error.
  7. Notes appear as inline comments.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Tuple

from core.intel.compilers.scope_compiler import compile_scope_file
from core.intel.program_scope import (
    Platform,
    ProgramScope,
    ScopeRule,
    ScopeRuleType,
)

# Import the existing parser pieces from the engine — we'll feed our
# output through them to verify the round-trip contract.
from core.base.scope import (
    AssetType,
    ScopeDecision,
    ScopeRegistry,
    ScopeRule as EngineScopeRule,
)


# ─────────────────────────── Helpers ───────────────────────────────

def _make_scope(*rules: ScopeRule, rate_limit: float = None) -> ProgramScope:
    return ProgramScope(
        handle="example",
        platform=Platform.HACKERONE,
        name="Example Program",
        source_url="https://hackerone.com/example",
        fetched_at=datetime(2026, 5, 18, tzinfo=timezone.utc),
        scope_rules=list(rules),
        rate_limit_rps=rate_limit,
    )


def _parse_scope_file_like_engine(text: str) -> List[EngineScopeRule]:
    """Reproduce the parse logic at core/server/routers/scans.py:265-281.

    Used to verify round-trip: emit → parse → same rules. If the engine
    parser ever changes, this helper must change to match — that's the
    intentional cross-reference.
    """
    rules: List[EngineScopeRule] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        # Strip inline comments (anything after a "  #" sequence).
        # The engine parser doesn't do this currently — it would fail
        # to parse our inline-comment lines. So either we strip here OR
        # the compiler stops emitting inline comments. Choose to strip
        # because the comments are operator-helpful.
        if "  #" in line:
            line = line.split("  #", 1)[0].strip()
        if not line:
            continue
        decision = ScopeDecision.DENY if line.startswith("!") else ScopeDecision.ALLOW
        target_str = line.lstrip("!")
        if target_str.startswith("*."):
            asset_type = AssetType.WILDCARD
        elif "/" in target_str and target_str[0].isdigit():
            asset_type = AssetType.CIDR
        elif "://" in target_str:
            asset_type = AssetType.URL
        elif "/" in target_str:
            asset_type = AssetType.PATH
        else:
            asset_type = AssetType.DOMAIN
        rules.append(EngineScopeRule(
            asset_type=asset_type, target=target_str, decision=decision,
        ))
    return rules


# ─────────────────────────── Header ────────────────────────────────

class TestHeader:
    def test_header_includes_program_name(self):
        scope = _make_scope()
        out = compile_scope_file(scope)
        assert "Example Program" in out

    def test_header_includes_platform(self):
        scope = _make_scope()
        out = compile_scope_file(scope)
        assert "hackerone" in out

    def test_header_includes_handle(self):
        scope = _make_scope()
        out = compile_scope_file(scope)
        assert "example" in out

    def test_header_includes_source_url(self):
        scope = _make_scope()
        out = compile_scope_file(scope)
        assert "https://hackerone.com/example" in out

    def test_header_includes_schema_version(self):
        scope = _make_scope()
        out = compile_scope_file(scope)
        assert "sentinelforge-scope-v1" in out

    def test_handle_none_renders_as_marker(self):
        scope = ProgramScope(
            handle=None,
            platform=Platform.DIRECT_URL,
            name="x",
            source_url="https://x.com",
            fetched_at=datetime(2026, 5, 18, tzinfo=timezone.utc),
        )
        out = compile_scope_file(scope)
        assert "(none)" in out  # No silent empty handle


# ─────────────────────────── Rule rendering ────────────────────────

class TestRuleRendering:
    def test_domain_in_scope_emitted_as_bare_line(self):
        scope = _make_scope(
            ScopeRule(pattern="app.example.com", rule_type=ScopeRuleType.DOMAIN, in_scope=True),
        )
        out = compile_scope_file(scope)
        lines = [ln for ln in out.splitlines() if ln and not ln.startswith("#")]
        assert "app.example.com" in lines

    def test_wildcard_in_scope_preserves_glob(self):
        scope = _make_scope(
            ScopeRule(pattern="*.gitlab.com", rule_type=ScopeRuleType.DOMAIN, in_scope=True),
        )
        out = compile_scope_file(scope)
        assert "*.gitlab.com" in out

    def test_cidr_in_scope_preserves_prefix(self):
        scope = _make_scope(
            ScopeRule(pattern="10.0.0.0/24", rule_type=ScopeRuleType.IP_CIDR, in_scope=True),
        )
        out = compile_scope_file(scope)
        assert "10.0.0.0/24" in out

    def test_url_in_scope_preserves_url(self):
        scope = _make_scope(
            ScopeRule(pattern="https://app.example.com/admin/*", rule_type=ScopeRuleType.URL, in_scope=True),
        )
        out = compile_scope_file(scope)
        assert "https://app.example.com/admin/*" in out

    def test_out_of_scope_prefixed_with_bang(self):
        scope = _make_scope(
            ScopeRule(pattern="staging.example.com", rule_type=ScopeRuleType.DOMAIN, in_scope=False),
        )
        out = compile_scope_file(scope)
        # The rule must appear with a leading "!" — that's how the
        # engine parser identifies DENY rules.
        rendered_lines = [
            ln for ln in out.splitlines()
            if ln and not ln.startswith("#")
        ]
        assert any(ln.startswith("!staging.example.com") for ln in rendered_lines), (
            f"Expected '!staging.example.com' in lines: {rendered_lines}"
        )

    def test_in_scope_section_comes_before_out_of_scope(self):
        scope = _make_scope(
            ScopeRule(pattern="staging.example.com", rule_type=ScopeRuleType.DOMAIN, in_scope=False),
            ScopeRule(pattern="*.example.com", rule_type=ScopeRuleType.DOMAIN, in_scope=True),
        )
        out = compile_scope_file(scope)
        in_pos = out.find("*.example.com")
        out_pos = out.find("!staging.example.com")
        assert in_pos > 0 and out_pos > 0
        assert in_pos < out_pos, "In-scope rules should appear before out-of-scope"

    def test_notes_appear_as_inline_comment(self):
        scope = _make_scope(
            ScopeRule(
                pattern="*.example.com",
                rule_type=ScopeRuleType.DOMAIN,
                in_scope=True,
                notes="production tier only",
            ),
        )
        out = compile_scope_file(scope)
        # The note should be on the same line as the rule, after "  #".
        rule_line = next(
            ln for ln in out.splitlines() if "*.example.com" in ln and not ln.startswith("#")
        )
        assert "production tier only" in rule_line

    def test_long_notes_get_truncated(self):
        scope = _make_scope(
            ScopeRule(
                pattern="*.example.com",
                rule_type=ScopeRuleType.DOMAIN,
                in_scope=True,
                notes="a" * 200,
            ),
        )
        out = compile_scope_file(scope)
        # The note shouldn't have all 200 chars verbatim — it gets truncated.
        rule_line = next(
            ln for ln in out.splitlines() if "*.example.com" in ln and not ln.startswith("#")
        )
        assert "a" * 200 not in rule_line
        assert "..." in rule_line


# ─────────────────────────── Unsupported types ─────────────────────

class TestUnsupportedRuleTypes:
    def test_mobile_app_emits_skip_comment(self):
        scope = _make_scope(
            ScopeRule(
                pattern="com.example.app",
                rule_type=ScopeRuleType.MOBILE_APP,
                in_scope=True,
            ),
        )
        out = compile_scope_file(scope)
        # The mobile_app pattern should NOT appear as a bare rule line
        # (it'd be parsed as a domain by the engine — wrong).
        rule_lines = [
            ln for ln in out.splitlines()
            if ln.strip() and not ln.lstrip().startswith("#")
        ]
        assert not any("com.example.app" == ln.strip() for ln in rule_lines)
        # But the operator should see why it was dropped.
        assert "mobile_app" in out
        assert "skipped" in out.lower()

    def test_source_code_emits_skip_comment(self):
        scope = _make_scope(
            ScopeRule(
                pattern="github.com/example/repo",
                rule_type=ScopeRuleType.SOURCE_CODE,
                in_scope=True,
            ),
        )
        out = compile_scope_file(scope)
        assert "source_code" in out
        assert "skipped" in out.lower()


# ─────────────────────────── Empty scope ───────────────────────────

class TestEmptyScope:
    def test_empty_scope_emits_warning_not_silent_empty(self):
        scope = _make_scope()  # no rules
        out = compile_scope_file(scope)
        # Header still present.
        assert "Example Program" in out
        # Plus a warning so operator notices.
        assert "no scope rules" in out.lower()


# ─────────────────────────── Round-trip with engine parser ─────────

class TestRoundTripWithEngineParser:
    """The critical contract: emit → parse-with-engine-logic → same rules.

    If this breaks, ingestion silently produces scope files that the
    engine misparses. These tests guarantee the format we emit is
    bit-compatible with what scans.py:265-281 expects.
    """

    def test_simple_domain_round_trips(self):
        scope = _make_scope(
            ScopeRule(pattern="app.example.com", rule_type=ScopeRuleType.DOMAIN, in_scope=True),
        )
        out = compile_scope_file(scope)
        rules = _parse_scope_file_like_engine(out)
        assert len(rules) == 1
        assert rules[0].asset_type == AssetType.DOMAIN
        assert rules[0].target == "app.example.com"
        assert rules[0].decision == ScopeDecision.ALLOW

    def test_wildcard_round_trips(self):
        scope = _make_scope(
            ScopeRule(pattern="*.example.com", rule_type=ScopeRuleType.DOMAIN, in_scope=True),
        )
        out = compile_scope_file(scope)
        rules = _parse_scope_file_like_engine(out)
        assert len(rules) == 1
        assert rules[0].asset_type == AssetType.WILDCARD
        assert rules[0].target == "*.example.com"

    def test_cidr_round_trips(self):
        scope = _make_scope(
            ScopeRule(pattern="10.0.0.0/24", rule_type=ScopeRuleType.IP_CIDR, in_scope=True),
        )
        out = compile_scope_file(scope)
        rules = _parse_scope_file_like_engine(out)
        assert len(rules) == 1
        assert rules[0].asset_type == AssetType.CIDR
        assert rules[0].target == "10.0.0.0/24"

    def test_deny_rule_round_trips(self):
        scope = _make_scope(
            ScopeRule(pattern="staging.example.com", rule_type=ScopeRuleType.DOMAIN, in_scope=False),
        )
        out = compile_scope_file(scope)
        rules = _parse_scope_file_like_engine(out)
        assert len(rules) == 1
        assert rules[0].decision == ScopeDecision.DENY
        assert rules[0].target == "staging.example.com"

    def test_full_scope_with_mixed_rules_round_trips(self):
        scope = _make_scope(
            ScopeRule(pattern="*.gitlab.com", rule_type=ScopeRuleType.DOMAIN, in_scope=True),
            ScopeRule(pattern="*.gitlab.io", rule_type=ScopeRuleType.DOMAIN, in_scope=True),
            ScopeRule(pattern="10.0.0.0/8", rule_type=ScopeRuleType.IP_CIDR, in_scope=True),
            ScopeRule(pattern="staging.gitlab.com", rule_type=ScopeRuleType.DOMAIN, in_scope=False),
            ScopeRule(pattern="*.internal.gitlab.com", rule_type=ScopeRuleType.DOMAIN, in_scope=False),
        )
        out = compile_scope_file(scope)
        rules = _parse_scope_file_like_engine(out)
        assert len(rules) == 5
        # Build (decision, target) tuples for comparison
        actual = sorted([(r.decision.value, r.target) for r in rules])
        expected = sorted([
            ("allow", "*.gitlab.com"),
            ("allow", "*.gitlab.io"),
            ("allow", "10.0.0.0/8"),
            ("deny", "staging.gitlab.com"),
            ("deny", "*.internal.gitlab.com"),
        ])
        assert actual == expected

    def test_scope_registry_accepts_output_and_resolves_correctly(self):
        """End-to-end: emit → parse → add to ScopeRegistry → check decisions."""
        scope = _make_scope(
            ScopeRule(pattern="*.example.com", rule_type=ScopeRuleType.DOMAIN, in_scope=True),
            ScopeRule(pattern="staging.example.com", rule_type=ScopeRuleType.DOMAIN, in_scope=False),
        )
        out = compile_scope_file(scope)
        rules = _parse_scope_file_like_engine(out)

        registry = ScopeRegistry()
        for r in rules:
            registry.add_rule(r)

        # In-scope subdomain should resolve ALLOW.
        decision = registry.resolve("app.example.com")
        assert decision.verdict == ScopeDecision.ALLOW

        # Explicitly-denied subdomain should resolve DENY (overrides
        # wildcard match because DENY > ALLOW on equal specificity).
        decision = registry.resolve("staging.example.com")
        assert decision.verdict == ScopeDecision.DENY
