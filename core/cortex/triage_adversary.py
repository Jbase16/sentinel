"""
core/cortex/triage_adversary.py

The Finding Adversary — try to KILL every finding before the researcher sees it.

The verifier already answered "is this technically valid?". The adversary answers
the only question that decides a payout: "would a real bounty triager reject this?"
It is deliberately hostile — imagine the triager woke late, spilled coffee, and has
400 duplicate IDOR reports in the queue.

Each finding is challenged across eight axes; each axis returns pass / warn / reject
plus the exact rejection phrase a triager would type. The aggregate decision:

    SURFACE               every axis passes — worth the researcher's time
    HOLD_FOR_MORE_PROOF   a soft objection — needs stronger framing or evidence
    SUPPRESS              a hard objection — valid-but-unpayable, don't waste attention

Suppression is not failure; it is how Sentinel avoids the most cursed bug-bounty
category: valid, unpaid nonsense. And "more proof" may only be requested if the
bounty-safe policy can obtain it safely — otherwise the next action is manual
review. The goblin stays caged.

Deterministic by design (rules first, no LLM). The AI layer can sharpen the prose
later; the decision must be reproducible and testable.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List

from core.cortex.evidence_bundle import EvidenceBundle

PASS, WARN, REJECT = "pass", "warn", "reject"
SURFACE, HOLD, SUPPRESS = "SURFACE", "HOLD_FOR_MORE_PROOF", "SUPPRESS"
_SCORE = {PASS: 1.0, WARN: 0.5, REJECT: 0.0}


@dataclass
class TriageChallenge:
    axis: str
    verdict: str
    reason: str
    rejection_phrase: str = ""
    required_fix: str = ""
    needs_unsafe_proof: bool = False       # can the fix only come from a forbidden action?


@dataclass
class AdversarialTriageResult:
    decision: str
    payable_likelihood: float
    novelty_likelihood: float
    impact_likelihood: float
    safety_likelihood: float
    next_action: str
    challenges: List[TriageChallenge] = field(default_factory=list)

    def top_rejection_risks(self) -> List[str]:
        return [c.axis for c in self.challenges if c.verdict != PASS]

    def survived(self) -> List[str]:
        return [c.axis for c in self.challenges if c.verdict == PASS]

    def to_metadata(self) -> Dict[str, Any]:
        return {"adversarial_triage": {
            "decision": self.decision,
            "payable_likelihood": round(self.payable_likelihood, 2),
            "novelty_likelihood": round(self.novelty_likelihood, 2),
            "impact_likelihood": round(self.impact_likelihood, 2),
            "safety_likelihood": round(self.safety_likelihood, 2),
            "top_rejection_risks": self.top_rejection_risks(),
            "survived_challenges": self.survived(),
            "predicted_rejections": [c.rejection_phrase for c in self.challenges
                                     if c.verdict != PASS and c.rejection_phrase],
            "next_action": self.next_action,
        }}


# --------------------------------------------------------------------- axes

def _safety(b: EvidenceBundle) -> TriageChallenge:
    if b.used_destructive:
        return TriageChallenge("proof_minimality_safety", REJECT,
            "Proof performed a destructive action (this is exploitation, not demonstration).",
            "Closing: testing performed a destructive/irreversible action, which violates our rules of engagement.",
            "Re-prove without any destructive action; confirm capability, do not consume it.")
    if b.proof_mode != "lab" and b.has_restraint and not b.owned_only:
        return TriageChallenge("proof_minimality_safety", REJECT,
            "Cross-object access was not confined to researcher-owned test accounts.",
            "Closing: testing accessed data that was not your own test data.",
            "Confine the proof to accounts you created; never read a real user's object.")
    if b.proof_mode == "lab":
        return TriageChallenge("proof_minimality_safety", WARN,
            "Obtained with the unconstrained lab engine (may have enumerated / mutated broadly).",
            "", "Re-prove under bounty-safe minimal-impact constraints before submitting.")
    return TriageChallenge("proof_minimality_safety", PASS,
        "Minimal, owned-account proof; no destructive action.")


def _impact(b: EvidenceBundle) -> TriageChallenge:
    if not b.cross_boundary and not b.business_impact and not b.server_authz_delta:
        return TriageChallenge("impact_sufficiency", REJECT,
            "No demonstrated impact beyond the researcher's own account.",
            "Closing as informational: no security impact to other users is demonstrated.",
            "Demonstrate impact that crosses an account, tenant, or role boundary.",
            needs_unsafe_proof=True)
    if b.subtype == "self_escalation":
        return TriageChallenge("impact_sufficiency", WARN,
            "A self-role change was proven, but nothing the elevated role UNLOCKS was demonstrated.",
            "Downgrading to informational unless you show what the elevated role can access.",
            "Show one action/read the elevated role enables that the base role cannot.",
            needs_unsafe_proof=True)
    if b.vuln_class == "mass_assignment" and not b.cross_boundary:
        return TriageChallenge("impact_sufficiency", WARN,
            "A privileged field was set on your own account, but its effect was not demonstrated.",
            "Downgrading unless the granted privilege is shown to have real effect.",
            "Demonstrate a capability the injected privilege actually confers.",
            needs_unsafe_proof=True)
    if b.cross_boundary and b.object_sensitivity == "synthetic":
        return TriageChallenge("impact_sufficiency", WARN,
            "Cross-account read confirmed, but against a synthetic object with no shown sensitivity.",
            "May downgrade: the exposed object is a test artifact with no demonstrated sensitive content.",
            "Explain (do not exfiltrate) what equivalent REAL objects of this class contain.")
    return TriageChallenge("impact_sufficiency", PASS,
        "Impact crosses a trust boundary with demonstrable business consequence.")


def _duplicate(b: EvidenceBundle) -> TriageChallenge:
    if b.vuln_class == "exploit_chain":
        return TriageChallenge("duplicate_likelihood", PASS,
            "Multi-step chain / role-transition composition — unlikely to collide with a commodity report.")
    if b.generic_pattern:
        return TriageChallenge("duplicate_likelihood", WARN,
            "Resembles a commodity IDOR/mass-assignment pattern that triage queues see constantly.",
            "Likely duplicate of a known generic IDOR unless a specific novelty is shown.",
            "Frame novelty around the role-transition / tenant-boundary aspect, not raw object-id tampering.")
    return TriageChallenge("duplicate_likelihood", PASS,
        "Pattern is specific enough to be unlikely as a generic duplicate.")


def _scope(b: EvidenceBundle) -> TriageChallenge:
    if not b.scope_loaded:
        return TriageChallenge("scope_compliance", WARN,
            "Program scope was not loaded during testing.",
            "", "Confirm the tested asset is explicitly in scope before submitting.")
    return TriageChallenge("scope_compliance", PASS, "Tested asset resolved as in-scope.")


def _by_design(b: EvidenceBundle) -> TriageChallenge:
    if b.subtype == "self_escalation" and b.confidence != "HIGH":
        return TriageChallenge("by_design_plausibility", WARN,
            "Role change confirmed only by reflection, which some apps do by design (echo).",
            "Possibly by-design: the endpoint may echo/accept the field without honoring it.",
            "Confirm the role is authoritative (survives a fresh login) before claiming escalation.")
    return TriageChallenge("by_design_plausibility", PASS,
        "The violated invariant is not a plausibly-intended behavior.")


def _artifact(b: EvidenceBundle) -> TriageChallenge:
    if b.target_is_local:
        return TriageChallenge("environmental_artifact_risk", WARN,
            "Proven against a local / non-production instance.",
            "Cannot reproduce: evidence is against a local host, not the program's asset.",
            "Reproduce against the in-scope production target and attach that evidence.")
    return TriageChallenge("environmental_artifact_risk", PASS,
        "Evidence is against a production-shaped, in-scope asset.")


def _clarity(b: EvidenceBundle) -> TriageChallenge:
    if not b.has_repro:
        return TriageChallenge("report_clarity_reproducibility", REJECT,
            "No reproducible request pair / steps captured.",
            "Closing as not reproducible: no clear steps to reproduce were provided.",
            "Attach the exact request(s) and observed response that prove the issue.")
    return TriageChallenge("report_clarity_reproducibility", PASS,
        "A reproducible request/response pair is captured.")


def _eligibility(b: EvidenceBundle) -> TriageChallenge:
    if not b.program_rules_loaded:
        return TriageChallenge("bounty_eligibility", WARN,
            "Program rules/policy were not loaded; class eligibility is unconfirmed.",
            "", "Load the program policy and confirm this vuln class is eligible for a bounty.")
    return TriageChallenge("bounty_eligibility", PASS, "Vuln class is eligible under the loaded policy.")


_AXES = [_safety, _impact, _duplicate, _scope, _by_design, _artifact, _clarity, _eligibility]


def annotate(finding: Dict[str, Any], *, scope: Any = None,
             program_rules: Any = None) -> str:
    """Triage a finding IN PLACE — attach the `adversarial_triage` block to its
    metadata — and return the decision. This is the post-verification gate's
    primitive: the detector detects, this judges, the caller routes on the result
    (SUPPRESS = don't spend the researcher's attention; HOLD = needs framing/proof;
    SURFACE = worth a look). Never raises — a triage failure degrades to SURFACE so
    a bug here can't silently swallow a real finding."""
    try:
        result = triage(EvidenceBundle.from_finding(finding, scope=scope, program_rules=program_rules))
    except Exception:
        finding.setdefault("metadata", {})["adversarial_triage"] = {"decision": SURFACE,
            "error": "triage_failed_open"}
        return SURFACE
    meta = finding.setdefault("metadata", {})
    meta.update(result.to_metadata())
    return result.decision


def triage(bundle: EvidenceBundle) -> AdversarialTriageResult:
    """Run the hostile gate. SUPPRESS on any hard objection, HOLD on any soft one,
    SURFACE only when every axis passes."""
    challenges = [axis(bundle) for axis in _AXES]
    verdicts = {c.axis: c.verdict for c in challenges}

    if any(c.verdict == REJECT for c in challenges):
        decision = SUPPRESS
    elif any(c.verdict == WARN for c in challenges):
        decision = HOLD
    else:
        decision = SURFACE

    def _s(axis: str) -> float:
        return _SCORE[verdicts[axis]]

    safety_likelihood = _s("proof_minimality_safety")
    impact_likelihood = _s("impact_sufficiency")
    novelty_likelihood = _s("duplicate_likelihood")
    payable_likelihood = sum(_SCORE[c.verdict] for c in challenges) / len(challenges)
    if decision == SUPPRESS:
        payable_likelihood = min(payable_likelihood, 0.1)

    # next_action honors the safety envelope: soft objections that could only be
    # answered by a forbidden action route to manual review, not autonomous escalation.
    held = [c for c in challenges if c.verdict != PASS]
    safe_fixes = [c.required_fix for c in held if c.required_fix and not c.needs_unsafe_proof]
    if decision == SURFACE:
        next_action = "Surface to researcher — survived all triage challenges."
    elif decision == SUPPRESS:
        next_action = "Suppress — valid but not payable as-is: " + "; ".join(
            c.reason for c in challenges if c.verdict == REJECT)
    elif any(c.needs_unsafe_proof for c in held):
        prefix = ("Manual review required — stronger impact proof would need actions the "
                  "bounty-safe policy forbids (wielding privilege / reading real data). ")
        next_action = prefix + (" Also: " + "; ".join(safe_fixes) if safe_fixes else "")
    else:
        next_action = "Hold — safe next steps: " + "; ".join(safe_fixes)

    return AdversarialTriageResult(
        decision=decision, payable_likelihood=payable_likelihood,
        novelty_likelihood=novelty_likelihood, impact_likelihood=impact_likelihood,
        safety_likelihood=safety_likelihood, next_action=next_action, challenges=challenges)
