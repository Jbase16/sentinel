"""
core/cortex/chain_verifier.py

Closing the loop: promote HYPOTHESIZED omega chains by live-testing their steps.

omega/NEXUS synthesizes exploit chains from domain knowledge (e.g.
`missing_auth → idor → account_takeover`). Those are HYPOTHESES — plausible, but
unproven. This module re-tests the chain's steps against the live target and
promotes the chain's epistemic status accordingly:

  - every live-testable step CONFIRMED  -> VERIFIED  (a real, evidenced killchain)
  - any live-testable step REFUTED       -> REFUTED   (the chain is broken)
  - no step is live-testable             -> stays HYPOTHESIZED (never asserted)

A chain only becomes fact by surviving verification — the same discipline as the
passive finding gate (core/toolkit/finding_verifier.py), one level up: findings →
chains.

This module is the ENGINE. It takes a `verify_step` callable so it stays a pure,
testable function of its inputs; the live wiring (scan finalization) supplies a
callable backed by wraith's VulnVerifier + MutationEngine, scope-gated and
budget-bounded. See docs/CHAIN_ARBITER.md (phase 2).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple

from core.cortex.chain_arbiter import ChainProposal, HYPOTHESIZED, OBSERVED

logger = logging.getLogger(__name__)

VERIFIED = "verified"
REFUTED = "refuted"

# Epistemic strength ordering (higher = stronger claim).
_RANK = {HYPOTHESIZED: 0, OBSERVED: 1, VERIFIED: 2, REFUTED: -1}

# omega PrimitiveType.value  ->  VulnVerifier vuln-class NAME (keys of the
# canonical vc_map in core/toolkit/internal_tools/vuln_verifier.py). Only types
# the verifier can actually confirm appear here; everything else is not
# live-testable and leaves the chain HYPOTHESIZED rather than falsely asserted.
PRIMITIVE_TO_VULN_CLASS: Dict[str, str] = {
    "idor_pattern": "idor",
    "ssrf_pattern": "ssrf",
    "sqli_pattern": "sqli",
    "open_redirect": "open redirect",
    "reflected_param": "reflected xss",
}

# (vuln_class_name, url) -> (outcome, evidence). Async; the live wiring hits the
# network (scope-gated); tests pass a deterministic mock.
#   outcome True  = step CONFIRMED (positive evidence)
#   outcome False = step REFUTED   (tested and disproven — breaks the chain)
#   outcome None  = INCONCLUSIVE   (out of scope / no auth / probe miss / error)
# Absence of a confirmation is NOT a refutation — only an explicit False refutes.
VerifyStep = Callable[[str, str], Awaitable[Tuple[Optional[bool], str]]]


@dataclass
class StepVerification:
    """Tri-state result retained for every live-testable primitive."""

    primitive_type: str
    vuln_class: str
    url: str
    outcome: str                       # confirmed | refuted | inconclusive
    evidence: str = ""

    def to_dict(self) -> Dict[str, str]:
        return {
            "primitive_type": self.primitive_type,
            "vuln_class": self.vuln_class,
            "url": self.url,
            "outcome": self.outcome,
            "evidence": self.evidence,
        }


@dataclass
class ChainVerification:
    """Outcome of re-testing one chain."""
    proposal: ChainProposal
    verdict: str                       # VERIFIED | REFUTED | HYPOTHESIZED
    tested: int = 0                    # live-testable steps attempted
    confirmed: int = 0                 # of those, confirmed
    evidence: str = ""
    steps: List[StepVerification] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d = self.proposal.to_dict()
        d.update({
            "epistemic": self.verdict,
            "verification": {
                "verdict": self.verdict,
                "tested_steps": self.tested,
                "confirmed_steps": self.confirmed,
                "evidence": self.evidence,
                "steps": [step.to_dict() for step in self.steps],
            },
        })
        return d


def _testable_steps(proposal: ChainProposal) -> List[Tuple[str, str, str]]:
    """Return [(primitive_type, vuln_class_name, url)] for steps we can live-test.
    Reads the omega raw payload (steps carry primitive_type + concrete target)."""
    out: List[Tuple[str, str, str]] = []
    raw = proposal.raw if isinstance(proposal.raw, dict) else {}
    for step in raw.get("steps", []) or []:
        if not isinstance(step, dict):
            continue
        ptype = str(step.get("primitive_type") or "").strip().lower()
        # Prefer the concrete URL the proposer re-attached; the bare `target`
        # is only a host and isn't enough to re-test a path/param vuln.
        url = str(step.get("url") or step.get("target") or "").strip()
        vclass = PRIMITIVE_TO_VULN_CLASS.get(ptype)
        if vclass and url and "://" in url:
            out.append((ptype, vclass, url))
    return out


class ChainVerifier:
    """Promotes hypothesized chains to verified/refuted by live-testing steps."""

    def __init__(self, max_steps_per_chain: int = 6):
        self._max_steps = max_steps_per_chain

    async def verify_chain(
        self, proposal: ChainProposal, verify_step: VerifyStep
    ) -> ChainVerification:
        # Only hypothesized (omega) chains are candidates; observed chains are
        # already evidence-grounded and have no primitive steps to re-test.
        if proposal.epistemic != HYPOTHESIZED:
            return ChainVerification(proposal, proposal.epistemic, evidence="not a hypothesis")

        all_steps = _testable_steps(proposal)
        if not all_steps:
            return ChainVerification(proposal, HYPOTHESIZED, evidence="no live-testable steps")

        attempted = all_steps[: self._max_steps]
        confirmed = 0
        tested = 0
        results: List[StepVerification] = []
        refuted: Optional[StepVerification] = None
        for ptype, vclass, url in attempted:
            tested += 1
            try:
                outcome, ev = await verify_step(vclass, url)
            except Exception as e:
                logger.debug("[ChainVerifier] step error %s @ %s: %s", vclass, url, e)
                results.append(StepVerification(
                    ptype, vclass, url, "inconclusive",
                    f"step verifier error: {type(e).__name__}",
                ))
                continue
            if outcome is True:
                confirmed += 1
                results.append(StepVerification(ptype, vclass, url, "confirmed", str(ev)))
            elif outcome is False:
                refuted = StepVerification(ptype, vclass, url, "refuted", str(ev))
                results.append(refuted)
                break
            else:
                results.append(StepVerification(ptype, vclass, url, "inconclusive", str(ev)))

        # Do not spend more proof budget after an explicit refutation or beyond the
        # per-chain cap, but retain those steps as inconclusive rather than erasing
        # them from the verification record.
        for ptype, vclass, url in all_steps[len(results):]:
            reason = "not attempted after an earlier refutation" if refuted else "step proof budget exhausted"
            results.append(StepVerification(ptype, vclass, url, "inconclusive", reason))

        if refuted is not None:
            proposal.epistemic = REFUTED
            return ChainVerification(
                proposal, REFUTED, tested=tested, confirmed=confirmed,
                evidence=(f"step refuted: {refuted.primitive_type} disproven at "
                          f"{refuted.url} ({refuted.evidence})"),
                steps=results,
            )

        if confirmed != len(all_steps):
            inconclusive = len(all_steps) - confirmed
            return ChainVerification(
                proposal, HYPOTHESIZED, tested=tested, confirmed=confirmed,
                evidence=(f"{confirmed}/{len(all_steps)} live-testable step(s) confirmed; "
                          f"{inconclusive} inconclusive — left hypothesized"),
                steps=results,
            )

        proposal.epistemic = VERIFIED
        return ChainVerification(
            proposal, VERIFIED, tested=tested, confirmed=confirmed,
            evidence=f"{confirmed}/{len(all_steps)} live-testable step(s) confirmed; "
                     f"goal={proposal.goal}", steps=results,
        )

    async def verify(
        self, proposals: List[ChainProposal], verify_step: VerifyStep
    ) -> Dict[str, Any]:
        """Verify every hypothesized chain. Returns the promoted set + a report.
        Refuted chains are separated out (the caller drops them); verified chains
        are the autonomous, evidenced killchains."""
        verified: List[ChainVerification] = []
        refuted: List[ChainVerification] = []
        untested: List[ChainVerification] = []
        for p in proposals:
            res = await self.verify_chain(p, verify_step)
            if res.verdict == VERIFIED:
                verified.append(res)
            elif res.verdict == REFUTED:
                refuted.append(res)
            else:
                untested.append(res)
        return {
            "verified": verified,
            "refuted": refuted,
            "untested": untested,
            "counts": {
                VERIFIED: len(verified),
                REFUTED: len(refuted),
                "untested": len(untested),
                "input": len(proposals),
            },
        }
