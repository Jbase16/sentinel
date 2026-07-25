"""
core/intel/selection/scorer.py — Phase 6-PT1.

Ranks ingested bug-bounty programs by how likely Sentinel is to find
AND get paid for a bug there. The success metric Phase 6 cares about
is dollars-in-pocket, not findings-in-tracker.

────────────────────────────────────────────────────────────────────
The scoring model
────────────────────────────────────────────────────────────────────

Per program × per vuln class Sentinel detects:

    expected_value = sentinel_confidence × expected_payout_for_class

Summed across the catalog gives a "Sentinel can reach $X of expected
value at this program" number. Then we modulate by:

  * Scope multiplier — more in-scope assets = more probes that can
    fire = more chances to find a bug. Logarithmic-ish; saturates.
  * Persona multiplier — verified personas unlock cross-principal
    IDOR + authenticated SQLi (Sentinel's strongest detections).
  * Saturation penalty — well-known programs have hundreds of
    duplicate reports; first-discovery probability is lower. Crude
    heuristic for V1 (operator should override after a few attempts).

The output is a deliberately PESSIMISTIC expected-value number.
$500 of expected value across the whole catalog is "this program is
probably worth trying"; $50 is "look elsewhere first."

────────────────────────────────────────────────────────────────────
The Sentinel detection profile
────────────────────────────────────────────────────────────────────

A static catalog of vuln classes Sentinel reliably detects. Each
entry encodes:

  confidence:                     0-1, "if a bug of this class exists
                                   here, will Sentinel find it?"
  typical_bounty_range_usd:        (low, high) across programs that
                                   pay for this class.
  cwe:                            CWE id for triager-friendly tagging.
  source_phase:                   which Sentinel phase produces it.
  operator_effort_hours:          rough "human time to verify +
                                   write the report" estimate.

The confidence numbers come from calibration runs #36, #38, #50 and
real-world fit observation. Updated when a calibration run shifts
our prior.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


# ───────────────────── detection profile ─────────────────────


@dataclass(frozen=True)
class VulnClassProfile:
    """How well Sentinel detects one vuln class, and what programs
    typically pay for it.

    `confidence` should be calibrated against real-world hit rate, NOT
    against unit-test pass rate. Phase 3+4+5 calibration runs are the
    primary source of truth here."""
    name: str
    cwe: str
    confidence: float                       # 0..1
    typical_bounty_range_usd: Tuple[int, int]  # (low, high)
    source_phase: str
    operator_effort_hours: float


# Phase 3 step 4 (multi-principal IDOR) + Phase 5 (Verify Console) made
# cross-principal IDOR Sentinel's STRONGEST detection. Calibration #50
# confirmed end-to-end submission-quality artifact.
SENTINEL_DETECTION_PROFILE: Dict[str, VulnClassProfile] = {
    "idor_cross_principal": VulnClassProfile(
        name="Cross-Principal IDOR (Alice's data readable by Bob)",
        cwe="CWE-639",
        confidence=0.90,
        typical_bounty_range_usd=(250, 5000),
        source_phase="Phase 3 step 4 + Phase 4-G5 flow diff",
        operator_effort_hours=0.5,
    ),
    "idor_horizontal": VulnClassProfile(
        name="Horizontal IDOR (single-principal ID enumeration)",
        cwe="CWE-639",
        confidence=0.85,
        typical_bounty_range_usd=(100, 2500),
        source_phase="Phase 3 step 4 verifier _confirm_idor",
        operator_effort_hours=0.5,
    ),
    "sqli_error_based": VulnClassProfile(
        name="Error-based SQL injection",
        cwe="CWE-89",
        confidence=0.85,
        typical_bounty_range_usd=(500, 10000),
        source_phase="Phase 3 step 1 VulnVerifier _confirm_sqli",
        operator_effort_hours=1.0,
    ),
    "jwt_alg_none": VulnClassProfile(
        name="JWT alg:none acceptance (CVE-2015-9235 class)",
        cwe="CWE-347",
        confidence=0.95,
        typical_bounty_range_usd=(1000, 10000),
        source_phase="Phase 4-G4 JWTAlgNone mutation",
        operator_effort_hours=1.0,
    ),
    "open_redirect": VulnClassProfile(
        name="Open redirect",
        cwe="CWE-601",
        confidence=0.70,
        typical_bounty_range_usd=(50, 500),
        source_phase="Phase 3 step 1 _confirm_open_redirect",
        operator_effort_hours=0.5,
    ),
    "path_traversal": VulnClassProfile(
        name="Path traversal / LFI",
        cwe="CWE-22",
        confidence=0.70,
        typical_bounty_range_usd=(250, 5000),
        source_phase="Phase 3 step 1 _confirm_path_traversal",
        operator_effort_hours=1.0,
    ),
    "ssrf_metadata": VulnClassProfile(
        name="SSRF (cloud metadata canary)",
        cwe="CWE-918",
        confidence=0.55,
        typical_bounty_range_usd=(500, 5000),
        source_phase="Phase 3 step 1 _confirm_ssrf",
        operator_effort_hours=1.0,
    ),
    "mass_assignment": VulnClassProfile(
        name="Mass assignment (is_admin / role injection)",
        cwe="CWE-915",
        confidence=0.65,
        typical_bounty_range_usd=(500, 5000),
        source_phase="Phase 4-G4 PrivilegeDowngrade mutation",
        operator_effort_hours=1.0,
    ),
    "logic_quantity_invariant": VulnClassProfile(
        name="Numeric invariant violation (negative quantity etc.)",
        cwe="CWE-840",
        confidence=0.65,
        typical_bounty_range_usd=(250, 2500),
        source_phase="Phase 4-G4 NegativeQuantity mutation",
        operator_effort_hours=1.0,
    ),
    "oauth_state_strip": VulnClassProfile(
        name="OAuth `state` CSRF (callback-handler missing state check)",
        cwe="CWE-352",
        confidence=0.50,
        typical_bounty_range_usd=(500, 5000),
        source_phase="Phase 4-G4 OAuthStateStrip mutation",
        operator_effort_hours=1.5,
    ),
}


# ───────────────────── saturation heuristic ─────────────────────


# Crude V1: well-known programs are picked-over. Operator should
# override these prior penalties as we run real submissions and learn
# which programs actually have lots of duplicates. Keys are case-
# insensitive substrings; first match wins.
_SATURATION_PRIORS: List[Tuple[str, float]] = [
    # Top-tier mature programs — heavy researcher attention.
    ("hackerone",   0.55),
    ("gitlab",      0.50),
    ("google",      0.55),
    ("microsoft",   0.55),
    ("github",      0.50),
    ("twitter",     0.50),
    ("x corp",      0.50),
    ("paypal",      0.50),
    ("uber",        0.45),
    ("shopify",     0.45),
    ("dropbox",     0.40),
    ("airbnb",      0.40),
    # Mid-tier: still well-covered but less crowded.
    ("yelp",        0.30),
    ("snap",        0.30),
    ("snapchat",    0.30),
    ("zoom",        0.30),
    ("slack",       0.30),
    ("coinbase",    0.30),
    # Default penalty applied below.
]


def _saturation_penalty_for(program_name: str) -> float:
    """Return 0-1 penalty (1 = max saturation, score gets crushed)."""
    if not program_name:
        return 0.20  # unknown program — assume moderate saturation
    lower = program_name.lower()
    for needle, penalty in _SATURATION_PRIORS:
        if needle in lower:
            return penalty
    # Default for unrecognized programs: assume they're less-trafficked.
    # Lower penalty = higher score = preference for unknown programs
    # over famous ones. This is the right prior for "find a paid bug
    # somewhere first." Operators can override per-program.
    return 0.15


# ───────────────────── result type ─────────────────────


@dataclass
class ProgramFitScore:
    """The output of scoring one program against Sentinel's profile.

    `final_score` is in USD-expected-value units (after multipliers
    and saturation penalty). Higher = better.

    `top_vuln_classes` surfaces the 3 vuln classes contributing most
    to the score, so the operator can read 'we expect to find $X
    here, mostly via {class1}, {class2}, {class3}'.
    """
    program_handle: Optional[str]
    program_name: str
    final_score: float
    capabilities_match_usd: float
    scope_size: int
    scope_multiplier: float
    verified_persona_count: int
    persona_multiplier: float
    saturation_penalty: float
    top_vuln_classes: List[Dict[str, Any]] = field(default_factory=list)
    # Human-readable one-line summary for CLI / API list view.
    summary: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "program_handle": self.program_handle,
            "program_name": self.program_name,
            "final_score": round(self.final_score, 2),
            "capabilities_match_usd": round(self.capabilities_match_usd, 2),
            "scope_size": self.scope_size,
            "scope_multiplier": round(self.scope_multiplier, 3),
            "verified_persona_count": self.verified_persona_count,
            "persona_multiplier": round(self.persona_multiplier, 3),
            "saturation_penalty": round(self.saturation_penalty, 3),
            "top_vuln_classes": self.top_vuln_classes,
            "summary": self.summary,
        }


# ───────────────────── scoring ─────────────────────


def _expected_payout_for_class(
    program_payout_max_usd: Optional[int],
    profile: VulnClassProfile,
) -> float:
    """Pick the bounty value to use for this (program, class) pair.

    If the program has an explicit max payout, cap our typical-high
    against it (the program won't pay more than its max regardless of
    severity). If no max is known, use the class's typical-high as the
    optimistic ceiling.

    We use the high end of the typical range as the "if it lands, this
    is what it's worth" anchor, then the confidence multiplier handles
    the "will it land?" half of the EV calculation."""
    typical_low, typical_high = profile.typical_bounty_range_usd
    if program_payout_max_usd:
        return float(min(typical_high, program_payout_max_usd))
    return float(typical_high)


def _scope_multiplier_for(scope_size: int) -> float:
    """More in-scope assets → more probe surface → more chances.

    Diminishing-returns curve so an enormous scope (e.g. *.example.com)
    doesn't dominate. At 0 in-scope assets the multiplier floors at
    0.3 (the program is barely usable but not zero). At ~30 assets we
    plateau around 1.5."""
    if scope_size <= 0:
        return 0.3
    # 0.5 base + 0.04 per asset, capped at 1.5
    return min(1.5, 0.5 + scope_size * 0.04)


def _persona_multiplier_for(verified_persona_count: int) -> float:
    """Verified personas unlock cross-principal IDOR + authenticated
    SQLi — Sentinel's strongest detections. Even 1 verified persona is
    a big jump; 2 unlocks multi-principal.

    Returns 1.0 for 0 personas (no auth-gated detection possible),
    1.25 for 1 persona, 1.5 for 2+ (multi-principal capable)."""
    if verified_persona_count <= 0:
        return 1.0
    if verified_persona_count == 1:
        return 1.25
    return 1.5


def score_program(program) -> ProgramFitScore:
    """Score one ProgramScope by Sentinel-fit expected value.

    The input is intentionally typed loosely (we duck-type
    `program.name`, `program.payout_max_usd`, `program.in_scope_domains()`,
    and `program.verified_personas()`) so this scorer can be tested with
    a tiny fake without importing the full ProgramScope machinery.
    """
    payout_max = getattr(program, "payout_max_usd", None)
    name = getattr(program, "name", "") or ""
    handle = getattr(program, "handle", None)

    try:
        scope_size = len(program.in_scope_domains())
    except Exception:
        scope_size = 0
    try:
        verified_personas = list(program.verified_personas())
    except Exception:
        verified_personas = []

    # Per-class expected value.
    capabilities_match = 0.0
    explanations: List[Dict[str, Any]] = []
    for vuln_id, profile in SENTINEL_DETECTION_PROFILE.items():
        expected_payout = _expected_payout_for_class(payout_max, profile)
        ev_contribution = profile.confidence * expected_payout
        capabilities_match += ev_contribution
        explanations.append({
            "vuln_class_id": vuln_id,
            "name": profile.name,
            "cwe": profile.cwe,
            "confidence": profile.confidence,
            "expected_payout_usd": round(expected_payout, 2),
            "ev_contribution_usd": round(ev_contribution, 2),
            "source_phase": profile.source_phase,
        })

    scope_mult = _scope_multiplier_for(scope_size)
    persona_mult = _persona_multiplier_for(len(verified_personas))
    saturation_pen = _saturation_penalty_for(name)

    final_score = (
        capabilities_match
        * scope_mult
        * persona_mult
        * (1.0 - saturation_pen)
    )

    # Top 3 vuln classes by EV contribution.
    top3 = sorted(explanations, key=lambda x: -x["ev_contribution_usd"])[:3]
    top3_names = ", ".join(t["name"].split("(")[0].strip() for t in top3)

    summary = (
        f"{name}: ${final_score:,.0f} expected value "
        f"(scope={scope_size}, personas={len(verified_personas)}, "
        f"saturation={int(saturation_pen * 100)}%) — top fits: {top3_names}"
    )

    return ProgramFitScore(
        program_handle=handle,
        program_name=name,
        final_score=final_score,
        capabilities_match_usd=capabilities_match,
        scope_size=scope_size,
        scope_multiplier=scope_mult,
        verified_persona_count=len(verified_personas),
        persona_multiplier=persona_mult,
        saturation_penalty=saturation_pen,
        top_vuln_classes=top3,
        summary=summary,
    )


def rank_programs(programs) -> List[ProgramFitScore]:
    """Score every program and return them sorted by descending
    final_score. The operator reads top-N as the recommendation."""
    scores = [score_program(p) for p in programs]
    scores.sort(key=lambda s: -s.final_score)
    return scores
