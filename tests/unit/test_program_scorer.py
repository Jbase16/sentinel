"""
Phase 6-PT1 tests for core/intel/selection/scorer.py.

Coverage:
  * Scoring formula reacts correctly to each input:
    - payout_max_usd raises EV (more $ per landed find)
    - scope size raises EV (more probe surface)
    - verified personas raise EV (unlocks cross-principal IDOR)
    - saturation penalty crushes well-known programs
  * Top vuln classes by EV are surfaced correctly (highest-confidence
    × highest-payout combinations rank first).
  * rank_programs is stable sort by descending score.
  * Edge cases: empty program list, program with zero scope, program
    with no payout_max.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

import pytest

from core.intel.selection.scorer import (
    SENTINEL_DETECTION_PROFILE,
    rank_programs,
    score_program,
)


# ───────────────────── tiny fake ProgramScope ─────────────────────
#
# The scorer duck-types program — we don't need to import the real
# ProgramScope (which has 20+ fields). A minimal class that satisfies
# the read API is enough.


@dataclass
class _FakeProgram:
    name: str
    handle: Optional[str] = None
    payout_max_usd: Optional[int] = None
    _in_scope_domains: List[str] = field(default_factory=list)
    _verified_personas: List[object] = field(default_factory=list)

    def in_scope_domains(self) -> List[str]:
        return list(self._in_scope_domains)

    def verified_personas(self) -> List[object]:
        return list(self._verified_personas)


# ───────────────────── basic scoring ─────────────────────


class TestScoringFormula:
    def test_returns_positive_score_for_default_program(self):
        p = _FakeProgram(name="acme corp")
        s = score_program(p)
        # Even a no-info program returns a positive score (the
        # detection profile's typical-high payouts apply).
        assert s.final_score > 0

    def test_payout_max_caps_per_class_expected_value(self):
        """A program with payout_max=$100 can't yield more than ~$100
        × confidence per class. So a high-confidence class (jwt-alg-
        none, conf=0.95) contributes ~$95 to capabilities_match — not
        the $10000 typical-high."""
        low_payout = _FakeProgram(name="poor program", payout_max_usd=100)
        high_payout = _FakeProgram(name="rich program", payout_max_usd=10000)
        # Same saturation, same scope, same personas — only payout differs.
        s_low = score_program(low_payout)
        s_high = score_program(high_payout)
        assert s_high.capabilities_match_usd > s_low.capabilities_match_usd

    def test_more_scope_raises_score(self):
        small = _FakeProgram(name="small", _in_scope_domains=["app.example.com"])
        big = _FakeProgram(
            name="big",
            _in_scope_domains=[f"app{i}.example.com" for i in range(20)],
        )
        s_small = score_program(small)
        s_big = score_program(big)
        assert s_big.final_score > s_small.final_score
        assert s_big.scope_multiplier > s_small.scope_multiplier

    def test_scope_multiplier_saturates(self):
        """Adding scope assets beyond ~30 gives diminishing returns — the
        multiplier shouldn't grow without bound. Programs with thousands
        of subdomains shouldn't dominate."""
        moderate = _FakeProgram(
            name="moderate",
            _in_scope_domains=[f"a{i}.x" for i in range(30)],
        )
        huge = _FakeProgram(
            name="huge",
            _in_scope_domains=[f"a{i}.x" for i in range(500)],
        )
        s_mod = score_program(moderate)
        s_huge = score_program(huge)
        # Saturated at 1.5 for both.
        assert s_mod.scope_multiplier == 1.5
        assert s_huge.scope_multiplier == 1.5

    def test_verified_personas_raise_score(self):
        no_persona = _FakeProgram(name="acme")
        one_persona = _FakeProgram(name="acme", _verified_personas=[object()])
        two_personas = _FakeProgram(
            name="acme",
            _verified_personas=[object(), object()],
        )
        s_none = score_program(no_persona)
        s_one = score_program(one_persona)
        s_two = score_program(two_personas)
        # More personas = higher multiplier.
        assert s_one.persona_multiplier > s_none.persona_multiplier
        assert s_two.persona_multiplier > s_one.persona_multiplier
        # And the final score reflects that.
        assert s_two.final_score > s_one.final_score > s_none.final_score


# ───────────────────── saturation prior ─────────────────────


class TestSaturationPenalty:
    def test_well_known_program_gets_high_penalty(self):
        """GitLab, HackerOne, etc. are heavily picked-over. Their
        scores should be CRUSHED relative to unknown programs."""
        gitlab = _FakeProgram(name="GitLab", payout_max_usd=20000)
        unknown = _FakeProgram(name="some-tiny-startup", payout_max_usd=20000)
        s_gitlab = score_program(gitlab)
        s_unknown = score_program(unknown)
        # Both have the same payout/scope/etc — the only difference is
        # the saturation prior. The unknown program should score higher.
        assert s_unknown.final_score > s_gitlab.final_score
        assert s_gitlab.saturation_penalty > s_unknown.saturation_penalty

    def test_saturation_penalty_case_insensitive(self):
        """Whether the program name is 'GitLab' or 'gitlab' or 'GITLAB'
        shouldn't change the penalty."""
        cases = ["GitLab", "gitlab", "GITLAB", "Gitlab Inc."]
        penalties = [
            score_program(_FakeProgram(name=n)).saturation_penalty
            for n in cases
        ]
        assert len(set(penalties)) == 1, (
            f"Saturation penalty case-sensitive — got {penalties}"
        )


# ───────────────────── top vuln classes ─────────────────────


class TestTopVulnClassesReporting:
    def test_top_3_vuln_classes_surfaced(self):
        p = _FakeProgram(name="acme", payout_max_usd=10000)
        s = score_program(p)
        assert len(s.top_vuln_classes) == 3
        # First-ranked must have highest EV contribution.
        ev_descending = [tc["ev_contribution_usd"] for tc in s.top_vuln_classes]
        assert ev_descending == sorted(ev_descending, reverse=True)

    def test_top_vuln_class_includes_cwe_and_source_phase(self):
        """The 'why' fields must come through so the operator can read
        the recommendation and know which Sentinel capabilities apply."""
        p = _FakeProgram(name="acme", payout_max_usd=10000)
        s = score_program(p)
        for tc in s.top_vuln_classes:
            assert "cwe" in tc and tc["cwe"]
            assert "source_phase" in tc and tc["source_phase"]
            assert "confidence" in tc

    def test_jwt_alg_none_tops_the_chart_for_unconstrained_program(self):
        """High confidence (0.95) × high payout ($10k) = top expected
        value. Cross-principal IDOR is second (0.90 × $5k = $4500)."""
        p = _FakeProgram(name="acme", payout_max_usd=10000)
        s = score_program(p)
        # JWT alg:none has the highest EV (0.95 × 10000 = 9500)
        top = s.top_vuln_classes[0]
        assert top["vuln_class_id"] == "jwt_alg_none"


# ───────────────────── rank_programs ─────────────────────


class TestRankPrograms:
    def test_empty_list_returns_empty(self):
        assert rank_programs([]) == []

    def test_sorted_descending_by_final_score(self):
        programs = [
            _FakeProgram(name="small-no-personas", payout_max_usd=500),
            _FakeProgram(
                name="best-fit",
                payout_max_usd=20000,
                _in_scope_domains=[f"a{i}.x" for i in range(15)],
                _verified_personas=[object(), object()],
            ),
            _FakeProgram(name="GitLab", payout_max_usd=20000),  # saturated
        ]
        ranked = rank_programs(programs)
        names = [r.program_name for r in ranked]
        # best-fit should be #1.
        assert names[0] == "best-fit"
        # Verify monotonically descending.
        scores = [r.final_score for r in ranked]
        assert scores == sorted(scores, reverse=True)

    def test_rank_stable_across_calls(self):
        """Same input list → same output order. Determinism matters so
        the operator's recommendation list doesn't shuffle."""
        programs = [
            _FakeProgram(name="alpha", payout_max_usd=1000),
            _FakeProgram(name="beta", payout_max_usd=1000),
        ]
        first = rank_programs(programs)
        second = rank_programs(programs)
        assert [r.program_name for r in first] == [r.program_name for r in second]


# ───────────────────── serialization ─────────────────────


class TestSerialization:
    def test_to_dict_round_trips_via_json(self):
        import json
        p = _FakeProgram(name="acme", payout_max_usd=5000)
        s = score_program(p)
        d = s.to_dict()
        # Must round-trip cleanly.
        json.dumps(d)
        assert "final_score" in d
        assert "summary" in d
        assert d["summary"].startswith("acme: ")
