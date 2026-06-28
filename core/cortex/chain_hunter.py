"""
core/cortex/chain_hunter.py

Phase 3 — self-direction. The closed, ITERATIVE hunt.

Phases 1-2 run once: discover → verify → synthesize chains → verify steps →
promote. This module makes the hunt re-plan from what it just proved. A verified
chain ending in primitive P means P is *confirmed exploitable*; omega's
enablement graph says what P unlocks (SQLI → IDOR/LEAKED_HEADER, …). So the
hunter goes and specifically verifies those follow-ons, folds any new
confirmations back into the primitive set, and re-synthesizes — deepening toward
higher goals (data_exfiltration → account_takeover → admin_access) until it
converges.

This is the jump from "finds and proves a killchain" to "keeps hunting until it
can't escalate further."

THE ENGINE IS PURE. It orchestrates three injected coroutines and owns only the
loop control + convergence + de-dup. The scan supplies the real `synthesize`
(omega), `verify_chains` (ChainVerifier + live VulnVerifier), and `expand`
(discover+verify the follow-ons the proven primitives unlock); tests supply
deterministic mocks. A hunt step never raises into the loop.

See docs/CHAIN_ARBITER.md (phase 3).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, List, Tuple

logger = logging.getLogger(__name__)

# synthesize(findings) -> hypothesized chain proposals
Synthesize = Callable[[List[Dict[str, Any]]], Awaitable[List[Any]]]
# verify_chains(chains) -> list of verified ChainVerification (refuted/untested dropped)
VerifyChains = Callable[[List[Any]], Awaitable[List[Any]]]
# expand(newly_verified, current_findings) -> new confirmed findings (the follow-on
# primitives the proven chains unlocked); [] when nothing new could be confirmed.
Expand = Callable[[List[Any], List[Dict[str, Any]]], Awaitable[List[Dict[str, Any]]]]


@dataclass
class HuntResult:
    """Everything the iterative hunt proved, plus its escalation trace."""
    verified: List[Any] = field(default_factory=list)       # ChainVerification across all iterations
    iterations: int = 0
    findings_added: List[Dict[str, Any]] = field(default_factory=list)  # follow-ons confirmed mid-hunt
    trace: List[str] = field(default_factory=list)          # human-readable per-iteration summary

    @property
    def top_goal(self) -> str:
        """Highest-impact goal reached (by GOAL_IMPACT_SCORES ordering)."""
        from core.omega.nexus_phase import GOAL_IMPACT_SCORES, GoalState
        best, best_score = "", -1.0
        for v in self.verified:
            goal = getattr(v.proposal, "goal", None)
            if not goal:
                continue
            try:
                score = GOAL_IMPACT_SCORES.get(GoalState(goal), 0.0)
            except Exception:
                score = 0.0
            if score > best_score:
                best, best_score = goal, score
        return best


def _finding_key(f: Dict[str, Any]) -> Tuple[str, str]:
    """Identity for dedup — a finding is 'new' if its (type, target) is unseen."""
    return (str(f.get("type") or f.get("title") or ""), str(f.get("target") or ""))


class ChainHunter:
    """Bounded, self-directing hunt: synthesize → verify → expand → repeat."""

    def __init__(self, max_iterations: int = 3):
        # Bounded so a target that keeps "unlocking" can't loop forever; each
        # iteration also issues live probes, so the cap is a traffic guard too.
        self._max = max(1, int(max_iterations))

    async def hunt(
        self,
        initial_findings: List[Dict[str, Any]],
        *,
        synthesize: Synthesize,
        verify_chains: VerifyChains,
        expand: Expand,
    ) -> HuntResult:
        findings: List[Dict[str, Any]] = list(initial_findings)
        seen_findings = {_finding_key(f) for f in findings}
        seen_chains: set = set()
        result = HuntResult()

        for i in range(self._max):
            result.iterations = i + 1
            try:
                chains = await synthesize(findings)
            except Exception as e:
                logger.warning("[ChainHunter] synthesize failed at iter %d: %s", i + 1, e)
                break
            if not chains:
                result.trace.append(f"iter {i+1}: 0 chains synthesized — stop")
                break

            try:
                verified = await verify_chains(chains)
            except Exception as e:
                logger.warning("[ChainHunter] verify failed at iter %d: %s", i + 1, e)
                break

            # Keep only chains we haven't already promoted in a prior iteration.
            fresh = []
            for v in verified:
                sig = v.proposal.signature() if hasattr(v.proposal, "signature") else id(v)
                if sig in seen_chains:
                    continue
                seen_chains.add(sig)
                fresh.append(v)
            result.verified.extend(fresh)
            result.trace.append(
                f"iter {i+1}: {len(chains)} synthesized → {len(fresh)} newly verified"
            )
            if not fresh:
                break  # converged — nothing new proved this round

            # SELF-DIRECTION: let the proven chains unlock follow-on primitives.
            try:
                unlocked = await expand(fresh, findings)
            except Exception as e:
                logger.warning("[ChainHunter] expand failed at iter %d: %s", i + 1, e)
                break
            novel = [f for f in (unlocked or []) if _finding_key(f) not in seen_findings]
            for f in novel:
                seen_findings.add(_finding_key(f))
            if not novel:
                result.trace.append(f"iter {i+1}: nothing new unlocked — converged")
                break
            findings.extend(novel)
            result.findings_added.extend(novel)
            result.trace.append(
                f"iter {i+1}: unlocked {len(novel)} new primitive(s): "
                f"{[_finding_key(f)[0] for f in novel]}"
            )

        return result
