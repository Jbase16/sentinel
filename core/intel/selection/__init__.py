"""
core/intel/selection — Phase 6-PT1: target/program scorer.

Goal: maximize the probability of a PAID acceptance, not just a valid
finding. Picks programs where Sentinel's detection strengths × the
program's bounty tier × the program's surface size produces the
highest expected value.
"""
from core.intel.selection.scorer import (
    ProgramFitScore,
    SENTINEL_DETECTION_PROFILE,
    VulnClassProfile,
    rank_programs,
    score_program,
)

__all__ = [
    "ProgramFitScore",
    "SENTINEL_DETECTION_PROFILE",
    "VulnClassProfile",
    "rank_programs",
    "score_program",
]
