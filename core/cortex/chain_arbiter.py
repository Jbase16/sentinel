"""
core/cortex/chain_arbiter.py

Multi-proposer exploit-chain ensemble.

SentinelForge has two chain engines that find DIFFERENT things (measured):
  - cortex/causal_graph : all_simple_paths over the OBSERVED correlation graph
                          → "what attack paths are present in what we detected"
                          → epistemic: OBSERVED
  - omega/NEXUS         : goal-directed BFS over a SEMANTIC enablement model
                          → "what primitive sequences could reach an adversary goal"
                          → epistemic: HYPOTHESIZED

Rather than have them fight over one `attack_chains` field, they are PROPOSERS
under an arbiter (the same propose→arbitrate pattern cortex/arbitration.py uses
for decisions). The arbiter runs every proposer best-effort, normalizes their
scores onto a common scale, dedups, and ranks into one canonical set.

THE EPISTEMIC RULE: an omega chain is a *hypothesis*, not a fact. It must never
be presented as an observed attack path — that's the generic-scanner noise the
verification gate exists to kill. Every ChainProposal carries `epistemic`; the
operator-facing observed-paths view stays cortex-only, and omega hypotheses live
in a clearly-labeled channel that the closed loop later promotes via verification.

See docs/CHAIN_ARBITER.md.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Protocol, Tuple, runtime_checkable

logger = logging.getLogger(__name__)

OBSERVED = "observed"
HYPOTHESIZED = "hypothesized"


@dataclass
class ChainContext:
    """Everything a proposer needs to produce chains for one session."""
    target: str
    findings: List[Dict[str, Any]] = field(default_factory=list)
    issues: List[Dict[str, Any]] = field(default_factory=list)
    graph_dto: Dict[str, Any] = field(default_factory=dict)
    session_id: Optional[str] = None


@dataclass
class ChainProposal:
    """A canonical exploit chain, source-agnostic."""
    source: str                 # proposer name, e.g. "cortex" | "omega"
    method: str                 # "observed-correlation" | "semantic-synthesis"
    epistemic: str              # OBSERVED | HYPOTHESIZED
    steps: List[str]            # ordered, human-readable step labels
    length: int
    score: float                # raw until arbitration, then normalized to [0,1]
    confidence: float = 0.5
    goal: Optional[str] = None  # adversary objective (omega) or None (cortex)
    node_ids: List[str] = field(default_factory=list)  # cortex graph linkage
    sources: List[str] = field(default_factory=list)   # set when merged
    raw: Dict[str, Any] = field(default_factory=dict)

    def signature(self) -> Tuple[Any, ...]:
        return (tuple(s.strip().lower() for s in self.steps), self.goal or "")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "method": self.method,
            "epistemic": self.epistemic,
            "steps": self.steps,
            "length": self.length,
            "score": round(self.score, 4),
            "confidence": round(self.confidence, 4),
            "goal": self.goal,
            "node_ids": self.node_ids,
            "sources": self.sources or [self.source],
        }


@runtime_checkable
class ChainProposer(Protocol):
    """A chain proposer. propose() MUST NOT raise into the arbiter — degrade to []."""
    name: str

    async def propose(self, ctx: ChainContext) -> List[ChainProposal]:
        ...


# --------------------------------------------------------------- proposers

class CortexChainProposer:
    """Adapts the chains cortex already computed (graph_dto['attack_chains']).

    Does NOT re-run cortex — it reads the DTO the live path already built, so it
    adds zero cost and stays decoupled from cortex's DB-bound machinery.
    """
    name = "cortex"

    async def propose(self, ctx: ChainContext) -> List[ChainProposal]:
        out: List[ChainProposal] = []
        chains = ctx.graph_dto.get("attack_chains", []) if isinstance(ctx.graph_dto, dict) else []
        if not isinstance(chains, list):
            return out
        for c in chains:
            if not isinstance(c, dict):
                continue
            steps = c.get("labels") or c.get("node_ids") or []
            steps = [str(s) for s in steps if s is not None]
            if not steps:
                continue
            out.append(ChainProposal(
                source=self.name,
                method="observed-correlation",
                epistemic=OBSERVED,
                steps=steps,
                length=len(steps),
                score=float(c.get("score", 0.0) or 0.0),
                confidence=float(c.get("confidence", 0.6) or 0.6),
                node_ids=[str(n) for n in (c.get("node_ids") or [])],
                raw=c,
            ))
        return out


class OmegaChainProposer:
    """Runs omega/NEXUS goal-directed chain synthesis over the session findings.

    Pure function of its inputs (no DB). Output is HYPOTHESIZED — chains it
    synthesizes from domain knowledge, not observed correlations. Never raises.
    """
    name = "omega"

    def __init__(self, top_n: int = 10):
        self._top_n = top_n

    async def propose(self, ctx: ChainContext) -> List[ChainProposal]:
        try:
            from core.aegis.nexus.primitives import PrimitiveCollector
            from core.omega.nexus_phase import NEXUSPhaseOrchestrator
        except Exception as e:  # pragma: no cover - import guard
            logger.warning("[ChainArbiter] omega unavailable: %s", e)
            return []
        try:
            inventory = PrimitiveCollector().collect(ctx.findings + ctx.issues, ctx.target)
            primitives = inventory.primitives
            if not primitives:
                return []
            result = await NEXUSPhaseOrchestrator(ctx.target, top_n=self._top_n).execute(primitives)
        except Exception as e:
            logger.warning("[ChainArbiter] omega proposer failed: %s", e)
            return []

        out: List[ChainProposal] = []
        for chain in getattr(result, "top_chains", []) or []:
            try:
                steps = [
                    f"{s.primitive.type.value}@{s.primitive.target}"
                    for s in chain.steps
                ]
                goal = chain.goal.value if hasattr(chain.goal, "value") else str(chain.goal)
                out.append(ChainProposal(
                    source=self.name,
                    method="semantic-synthesis",
                    epistemic=HYPOTHESIZED,
                    steps=steps + [f"⇒ {goal}"],
                    length=chain.chain_length,
                    score=float(chain.total_score),
                    confidence=float(chain.confidence_score),
                    goal=goal,
                    raw=chain.to_dict() if hasattr(chain, "to_dict") else {},
                ))
            except Exception as e:
                logger.debug("[ChainArbiter] omega chain adapt failed: %s", e)
                continue
        return out


# --------------------------------------------------------------- arbiter

class ChainArbiter:
    """Runs registered proposers, normalizes, dedups, and ranks into one set."""

    def __init__(self) -> None:
        self._proposers: List[ChainProposer] = []

    def register(self, proposer: ChainProposer) -> "ChainArbiter":
        self._proposers.append(proposer)
        return self

    @classmethod
    def default(cls) -> "ChainArbiter":
        """The standard ensemble: observed (cortex) + hypothesized (omega)."""
        return cls().register(CortexChainProposer()).register(OmegaChainProposer())

    async def arbitrate(self, ctx: ChainContext, top_n: int = 25) -> List[ChainProposal]:
        proposals: List[ChainProposal] = []
        for p in self._proposers:
            try:
                got = await p.propose(ctx)
            except Exception as e:  # proposers shouldn't raise, but never trust
                logger.warning("[ChainArbiter] proposer %s raised: %s", getattr(p, "name", "?"), e)
                continue
            if got:
                proposals.extend(got)

        self._normalize_scores(proposals)
        merged = self._dedup(proposals)
        merged.sort(key=lambda c: c.score, reverse=True)
        return merged[:top_n]

    @staticmethod
    def _normalize_scores(proposals: List[ChainProposal]) -> None:
        """Min-max each SOURCE's raw scores to [0,1] so different scales (omega's
        0–10 impact vs cortex's centrality) rank against each other fairly."""
        by_source: Dict[str, List[ChainProposal]] = {}
        for p in proposals:
            by_source.setdefault(p.source, []).append(p)
        for group in by_source.values():
            scores = [p.score for p in group]
            lo, hi = min(scores), max(scores)
            span = hi - lo
            for p in group:
                p.score = 1.0 if span == 0 else (p.score - lo) / span

    @staticmethod
    def _dedup(proposals: List[ChainProposal]) -> List[ChainProposal]:
        """Collapse identical chains; merge their sources. OBSERVED beats
        HYPOTHESIZED when the same chain is proposed by both."""
        seen: Dict[Tuple[Any, ...], ChainProposal] = {}
        for p in proposals:
            key = p.signature()
            if key not in seen:
                p.sources = [p.source]
                seen[key] = p
                continue
            keep = seen[key]
            if p.source not in keep.sources:
                keep.sources.append(p.source)
            keep.score = max(keep.score, p.score)
            keep.confidence = max(keep.confidence, p.confidence)
            if p.epistemic == OBSERVED:
                keep.epistemic = OBSERVED
                keep.method = p.method
        return list(seen.values())
