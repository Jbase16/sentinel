"""
core/cortex/triage_adversary.py

The Finding Adversary — try to KILL every finding before the researcher sees it.

The verifier already answered "is this technically valid?". The adversary answers
the only question that decides a payout: "would a real bounty triager reject this?"
It is deliberately hostile, and it DISTRUSTS the detector — every judgment is made
from the evidence in the EvidenceBundle, never from the finding's self-declared
class.

Nine axes, each returning pass / warn / reject with a stable CODE and the exact
rejection phrase a triager would type. Aggregate:

    SURFACE               every axis passes — a submission candidate
    HOLD_FOR_MORE_PROOF   a soft objection — needs framing / more (safe) evidence
    SUPPRESS              a hard objection — valid-but-unpayable; keep it out of sight

Routing matters: an `engineering` route judges "is this a useful internal result?"
(a local target is fine); a `bounty_submission` route judges "is this submittable?"
(a local target is a hard reject). Those are different gates and must not be mixed.

`next_action` and `evidence_needed` honor the safety envelope: anything whose only
strengthening path is a forbidden action (wield privilege, read real data) is
`safe_to_collect: false` and routes to MANUAL REVIEW — never autonomous escalation.

Deterministic (rules first, no LLM). `annotate` is the post-verification gate
primitive; on the bounty route a triage failure HOLDS (fail-safe), on the
engineering route it SURFACEs with an error (fail-open for visibility).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from core.cortex.evidence_bundle import EvidenceBundle

PASS, WARN, REJECT = "pass", "warn", "reject"
SURFACE, HOLD, SUPPRESS = "SURFACE", "HOLD_FOR_MORE_PROOF", "SUPPRESS"
BOUNTY, ENGINEERING = "bounty_submission", "engineering"
_SCORE = {PASS: 1.0, WARN: 0.5, REJECT: 0.0}


@dataclass
class TriageContext:
    route: str = BOUNTY
    scope_loaded: bool = False
    program_rules_loaded: bool = False


@dataclass
class TriageChallenge:
    axis: str
    verdict: str
    code: str
    reason: str
    rejection_phrase: str = ""
    required_fix: str = ""
    evidence_needed: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def needs_unsafe_proof(self) -> bool:
        return any(e.get("safe_to_collect") is False for e in self.evidence_needed)


@dataclass
class AdversarialTriageResult:
    decision: str
    route: str
    payable_likelihood: float
    novelty_likelihood: float
    impact_likelihood: float
    safety_likelihood: float
    next_action: str
    challenges: List[TriageChallenge] = field(default_factory=list)

    def top_rejection_risks(self) -> List[str]:
        return [c.code for c in self.challenges if c.verdict != PASS]

    def survived(self) -> List[str]:
        return [c.axis for c in self.challenges if c.verdict == PASS]

    def evidence_needed(self) -> List[Dict[str, Any]]:
        return [e for c in self.challenges for e in c.evidence_needed]

    def to_metadata(self) -> Dict[str, Any]:
        return {"adversarial_triage": {
            "decision": self.decision,
            "route": self.route,
            "payable_likelihood": round(self.payable_likelihood, 2),
            "novelty_likelihood": round(self.novelty_likelihood, 2),
            "impact_likelihood": round(self.impact_likelihood, 2),
            "safety_likelihood": round(self.safety_likelihood, 2),
            "top_rejection_risks": self.top_rejection_risks(),          # stable codes
            "survived_challenges": self.survived(),
            "predicted_rejections": [c.rejection_phrase for c in self.challenges
                                     if c.verdict != PASS and c.rejection_phrase],
            "evidence_needed": self.evidence_needed(),
            "next_action": self.next_action,
        }}


def _safe(t: str, desc: str) -> Dict[str, Any]:
    return {"type": t, "safe_to_collect": True, "description": desc}


def _unsafe(t: str, desc: str) -> Dict[str, Any]:
    return {"type": t, "safe_to_collect": False, "route": "manual_review_only", "description": desc}


# --------------------------------------------------------------------- axes

def _safety(b: EvidenceBundle, ctx: TriageContext) -> TriageChallenge:
    if b.used_destructive:
        return TriageChallenge("proof_minimality_safety", REJECT, "DESTRUCTIVE_PROOF_USED",
            "The proof performed a destructive action (exploitation, not demonstration).",
            "Closing: testing performed a destructive/irreversible action, violating our rules of engagement.",
            "Re-prove without any destructive action.")
    if b.proof_mode != "lab" and b.has_restraint and not b.owned_only:
        return TriageChallenge("proof_minimality_safety", REJECT, "NON_OWNED_DATA_ACCESSED",
            "Cross-object access was not confined to researcher-owned test accounts.",
            "Closing: testing accessed data that was not your own test data.",
            "Confine the proof to accounts you created.")
    if b.proof_mode == "lab" and ctx.route == BOUNTY:
        return TriageChallenge("proof_minimality_safety", WARN, "UNCONSTRAINED_LAB_PROOF",
            "Obtained with the unconstrained lab engine (may have enumerated / mutated broadly).",
            "", "Re-prove under bounty-safe minimal-impact constraints.",
            [_safe("bounty_safe_reproduction", "Reproduce the finding in bounty-safe mode.")])
    return TriageChallenge("proof_minimality_safety", PASS, "OK", "Minimal, owned-account proof.")


def _impact(b: EvidenceBundle, ctx: TriageContext) -> TriageChallenge:
    if not b.cross_boundary and not b.business_impact and not b.server_authz_delta:
        return TriageChallenge("impact_sufficiency", REJECT, "NO_CROSS_BOUNDARY_IMPACT",
            "No demonstrated impact beyond the researcher's own account.",
            "Closing as informational: no security impact to other users is demonstrated.",
            "Demonstrate impact across an account/tenant/role boundary.",
            [_unsafe("cross_boundary_proof", "Demonstrate access to another principal's resource.")])
    if b.subtype == "self_escalation":
        return TriageChallenge("impact_sufficiency", WARN, "SELF_ESCALATION_NOT_WIELDED",
            "A self-role change was proven, but nothing the elevated role UNLOCKS was demonstrated.",
            "Downgrading to informational unless you show what the elevated role can access.",
            "Show one action the elevated role enables that the base role cannot.",
            [_unsafe("privileged_capability_use", "Use the elevated role to reach a resource the base role cannot.")])
    if b.vuln_class == "mass_assignment" and not b.cross_boundary:
        return TriageChallenge("impact_sufficiency", WARN, "PRIVILEGE_EFFECT_NOT_SHOWN",
            "A privileged field was set on your own account, but its effect was not demonstrated.",
            "Downgrading unless the granted privilege is shown to have real effect.",
            "Demonstrate a capability the injected privilege confers.",
            [_unsafe("privileged_capability_use", "Show the injected privilege has real effect.")])
    if b.cross_boundary:
        sens = b.object_sensitivity
        if sens in ("synthetic_sensitive_class", "real_sensitive"):
            return TriageChallenge("impact_sufficiency", PASS, "OK",
                "Cross-boundary access to a sensitive object class.")
        code = "SYNTHETIC_OBJECT_NO_SENSITIVITY" if sens == "synthetic_low" else "OBJECT_SENSITIVITY_UNKNOWN"
        return TriageChallenge("impact_sufficiency", WARN, code,
            "Cross-account read confirmed, but the object's class sensitivity is not established.",
            "May downgrade: the exposed object is a test artifact with no demonstrated sensitive content.",
            "Declare (do not exfiltrate) what equivalent REAL objects of this class contain.",
            [_safe("schema_sensitivity", "Show the response schema for this object class includes sensitive fields.")])
    return TriageChallenge("impact_sufficiency", PASS, "OK", "Demonstrable business impact.")


def _duplicate(b: EvidenceBundle, ctx: TriageContext) -> TriageChallenge:
    novelty = b.novelty_claims
    if b.vuln_class == "exploit_chain":
        if novelty:
            return TriageChallenge("duplicate_likelihood", PASS, "OK",
                f"Chain carries novelty differentiators: {novelty}.")
        return TriageChallenge("duplicate_likelihood", WARN, "COMMODITY_CHAIN",
            "A chain, but a commodity one (e.g. register→admin→delete) with no stated novelty.",
            "Likely known: composing common bugs is not itself novel.",
            "State a novelty differentiator (tenant boundary, role transition, matrix-cell violation).",
            [_safe("novelty_framing", "Add novelty_claims / matrix-cell context.")])
    if b.generic_pattern and not novelty:
        return TriageChallenge("duplicate_likelihood", WARN, "COMMODITY_IDOR_PATTERN",
            "Resembles a commodity IDOR/mass-assignment pattern triage queues see constantly.",
            "Likely duplicate of a known generic IDOR unless a specific novelty is shown.",
            "Frame novelty around role-transition / tenant-boundary, not raw object-id tampering.",
            [_safe("novelty_framing", "Add the specific novelty differentiator.")])
    return TriageChallenge("duplicate_likelihood", PASS, "OK", "Specific enough to be unlikely as a generic dup.")


def _scope(b: EvidenceBundle, ctx: TriageContext) -> TriageChallenge:
    if ctx.route != BOUNTY:
        return TriageChallenge("scope_compliance", PASS, "OK", "Scope not required on the engineering route.")
    if not ctx.scope_loaded:
        return TriageChallenge("scope_compliance", WARN, "SCOPE_NOT_LOADED",
            "Program scope was not loaded during testing.",
            "", "Confirm the tested asset is explicitly in scope.",
            [_safe("load_scope", "Load the program scope and resolve the asset as in-scope.")])
    return TriageChallenge("scope_compliance", PASS, "OK", "Tested asset resolved in-scope.")


def _by_design(b: EvidenceBundle, ctx: TriageContext) -> TriageChallenge:
    if b.subtype == "self_escalation" and b.confidence != "HIGH":
        return TriageChallenge("by_design_plausibility", WARN, "POSSIBLE_ECHO_ONLY",
            "Role change confirmed only by reflection, which some apps do by design (echo).",
            "Possibly by-design: the endpoint may echo/accept the field without honoring it.",
            "Confirm the role is authoritative (survives a fresh login).",
            [_safe("fresh_login_persistence", "Show the elevated role survives a new login/session.")])
    return TriageChallenge("by_design_plausibility", PASS, "OK", "Not a plausibly-intended behavior.")


def _artifact(b: EvidenceBundle, ctx: TriageContext) -> TriageChallenge:
    if b.target_is_local:
        if ctx.route == BOUNTY:
            return TriageChallenge("environmental_artifact_risk", REJECT, "LOCAL_TARGET_ONLY",
                "Proven against a local / non-production instance — not submittable.",
                "Cannot reproduce: evidence is against a local host, not the program's asset.",
                "Reproduce against the in-scope production target.",
                [_safe("reproduce_on_production", "Re-run the same proof against the production asset.")])
        return TriageChallenge("environmental_artifact_risk", PASS, "OK",
            "Local target is expected on the engineering route.")
    return TriageChallenge("environmental_artifact_risk", PASS, "OK", "Production-shaped asset.")


def _clarity(b: EvidenceBundle, ctx: TriageContext) -> TriageChallenge:
    if not b.has_repro:
        return TriageChallenge("report_clarity_reproducibility", REJECT, "NO_REPRO_STEPS",
            "No reproducible request pair / steps captured.",
            "Closing as not reproducible: no clear steps were provided.",
            "Attach the exact request(s) and observed response.")
    return TriageChallenge("report_clarity_reproducibility", PASS, "OK", "Reproducible pair captured.")


def _eligibility(b: EvidenceBundle, ctx: TriageContext) -> TriageChallenge:
    if ctx.route != BOUNTY:
        return TriageChallenge("bounty_eligibility", PASS, "OK", "Eligibility not required on engineering route.")
    if not ctx.program_rules_loaded:
        return TriageChallenge("bounty_eligibility", WARN, "RULES_NOT_LOADED",
            "Program rules/policy were not loaded; class eligibility is unconfirmed.",
            "", "Load the program policy and confirm this class is eligible.",
            [_safe("load_program_rules", "Load the program policy and confirm eligibility.")])
    return TriageChallenge("bounty_eligibility", PASS, "OK", "Class eligible under the loaded policy.")


def _invariant(b: EvidenceBundle, ctx: TriageContext) -> TriageChallenge:
    """The bridge to belief (and to the future authorization matrix): a finding that
    cannot state the invariant it violates should not SURFACE — but it may be real,
    so HOLD, don't reject."""
    if b.intended_invariant:
        return TriageChallenge("invariant_articulation", PASS, "OK",
            f"States the violated invariant: {b.intended_invariant[:80]}")
    return TriageChallenge("invariant_articulation", WARN, "MISSING_INVARIANT",
        "The finding does not state the intended invariant it violates.",
        "Unclear what security property is broken.",
        "State: intended invariant vs observed behavior.",
        [_safe("articulate_invariant", "Add intended_invariant + observed_violation (the app's rule vs reality).")])


_AXES = [_safety, _impact, _duplicate, _scope, _by_design,
         _artifact, _clarity, _eligibility, _invariant]


def triage(bundle: EvidenceBundle, context: Optional[TriageContext] = None) -> AdversarialTriageResult:
    ctx = context or TriageContext()
    challenges = [axis(bundle, ctx) for axis in _AXES]
    by_axis = {c.axis: c.verdict for c in challenges}

    if any(c.verdict == REJECT for c in challenges):
        decision = SUPPRESS
    elif any(c.verdict == WARN for c in challenges):
        decision = HOLD
    else:
        decision = SURFACE

    safety_likelihood = _SCORE[by_axis["proof_minimality_safety"]]
    impact_likelihood = _SCORE[by_axis["impact_sufficiency"]]
    novelty_likelihood = _SCORE[by_axis["duplicate_likelihood"]]
    payable_likelihood = sum(_SCORE[c.verdict] for c in challenges) / len(challenges)
    if decision == SUPPRESS:
        payable_likelihood = min(payable_likelihood, 0.1)

    held = [c for c in challenges if c.verdict != PASS]
    safe_fixes = [c.required_fix for c in held if c.required_fix and not c.needs_unsafe_proof]
    if decision == SURFACE:
        next_action = "Surface as submission candidate — survived every triage challenge."
    elif decision == SUPPRESS:
        next_action = "Suppress (valid but not payable as-is): " + "; ".join(
            c.reason for c in challenges if c.verdict == REJECT)
    elif any(c.needs_unsafe_proof for c in held):
        next_action = ("Manual review required — stronger impact would need actions the bounty-safe "
                       "policy forbids (wielding privilege / reading real data).")
        if safe_fixes:
            next_action += " Meanwhile: " + "; ".join(safe_fixes)
    else:
        next_action = "Hold — safe next steps: " + "; ".join(safe_fixes)

    return AdversarialTriageResult(
        decision=decision, route=ctx.route, payable_likelihood=payable_likelihood,
        novelty_likelihood=novelty_likelihood, impact_likelihood=impact_likelihood,
        safety_likelihood=safety_likelihood, next_action=next_action, challenges=challenges)


def annotate(finding: Dict[str, Any], *, route: str = BOUNTY,
             scope: Any = None, program_rules: Any = None) -> str:
    """Post-verification gate primitive: triage IN PLACE (attach the
    `adversarial_triage` block) and return the decision. Fail behavior depends on
    route — bounty HOLDS on error (the gate must not wave dangerous traffic through),
    engineering SURFACEs with an error (fail-open for internal visibility)."""
    ctx = TriageContext(route=route, scope_loaded=scope is not None,
                        program_rules_loaded=program_rules is not None)
    meta = finding.setdefault("metadata", {})
    try:
        result = triage(EvidenceBundle.from_finding(finding), ctx)
    except Exception as e:
        fail = SURFACE if route == ENGINEERING else HOLD
        meta["adversarial_triage"] = {"decision": fail, "route": route,
                                      "error": f"triage_failed: {type(e).__name__}"}
        return fail
    meta.update(result.to_metadata())
    return result.decision
