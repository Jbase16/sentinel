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
    "open_redirect": "open redirect",
    "reflected_param": "reflected xss",
    "sqli": "sqli",
    "path_traversal": "path traversal",
}

# (vuln_class_name, url) -> (outcome, evidence). Async; the live wiring hits the
# network (scope-gated); tests pass a deterministic mock.
#   outcome True  = step CONFIRMED (positive evidence)
#   outcome False = step REFUTED   (tested and disproven — breaks the chain)
#   outcome None  = INCONCLUSIVE   (out of scope / no auth / probe miss / error)
# Absence of a confirmation is NOT a refutation — only an explicit False refutes.
VerifyStep = Callable[[str, str], Awaitable[Tuple[Optional[bool], str]]]


@dataclass
class ChainVerification:
    """Outcome of re-testing one chain."""
    proposal: ChainProposal
    verdict: str                       # VERIFIED | REFUTED | HYPOTHESIZED
    tested: int = 0                    # live-testable steps attempted
    confirmed: int = 0                 # of those, confirmed
    evidence: str = ""

    def to_dict(self) -> Dict[str, Any]:
        d = self.proposal.to_dict()
        d.update({
            "epistemic": self.verdict,
            "verification": {
                "verdict": self.verdict,
                "tested_steps": self.tested,
                "confirmed_steps": self.confirmed,
                "evidence": self.evidence,
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

        steps = _testable_steps(proposal)[: self._max_steps]
        if not steps:
            return ChainVerification(proposal, HYPOTHESIZED, evidence="no live-testable steps")

        confirmed = 0
        for ptype, vclass, url in steps:
            try:
                outcome, ev = await verify_step(vclass, url)
            except Exception as e:
                logger.debug("[ChainVerifier] step error %s @ %s: %s", vclass, url, e)
                # An error is inconclusive, not a refutation — keep testing.
                continue
            if outcome is True:
                confirmed += 1
            elif outcome is False:
                # A step we COULD test and that was DISPROVEN breaks the chain.
                proposal.epistemic = REFUTED
                return ChainVerification(
                    proposal, REFUTED, tested=len(steps), confirmed=confirmed,
                    evidence=f"step refuted: {ptype} disproven at {url} ({ev})",
                )
            # outcome is None -> inconclusive; absence of signal never refutes.

        if confirmed == 0:
            return ChainVerification(
                proposal, HYPOTHESIZED, tested=len(steps), confirmed=0,
                evidence="no step could be confirmed (inconclusive) — left hypothesized",
            )

        proposal.epistemic = VERIFIED
        return ChainVerification(
            proposal, VERIFIED, tested=len(steps), confirmed=confirmed,
            evidence=f"{confirmed}/{len(steps)} live-testable step(s) confirmed; "
                     f"goal={proposal.goal}",
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
