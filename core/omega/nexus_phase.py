"""
OMEGA NEXUS Phase Implementation

Causally-ordered exploit chain discovery with goal-based filtering and impact scoring.

A chain is not adjacency.
A chain is: An ordered, causally valid sequence of primitives where each step
enables the next, and the sequence moves system state toward an adversarial objective.

Three-layer architecture:
1. Generate candidate chains (dependency + causality graph)
2. Filter by goal states (explicit adversarial outcomes)
3. Score and rank (impact-weighted, cost-aware)

Operators see only top N chains. Everything else is noise.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

from core.aegis.nexus.primitives import Primitive, PrimitiveType, ReliabilityLevel
from core.cortex.events import GraphEvent, GraphEventType, get_event_bus

logger = logging.getLogger(__name__)


class GoalState(str, Enum):
    """Adversarial objectives that chains can reach."""
    ADMIN_ACCESS = "admin_access"
    DATA_EXFILTRATION = "data_exfiltration"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    RCE = "remote_code_execution"
    AUTHENTICATION_BYPASS = "authentication_bypass"
    ACCOUNT_TAKEOVER = "account_takeover"
    DATA_MODIFICATION = "data_modification"
    DENIAL_OF_SERVICE = "denial_of_service"


# Primitive enablement relationships: A → B means "A enables B"
PRIMITIVE_ENABLEMENT = {
    PrimitiveType.MISSING_AUTH: [
        PrimitiveType.IDOR_PATTERN,
        PrimitiveType.SSRF_PATTERN,
        PrimitiveType.FILE_UPLOAD,
    ],
    PrimitiveType.IDOR_PATTERN: [
        PrimitiveType.LEAKED_HEADER,
        PrimitiveType.REFLECTED_PARAM,
    ],
    PrimitiveType.REFLECTED_PARAM: [
        PrimitiveType.OPEN_REDIRECT,
        PrimitiveType.JSONP_ENDPOINT,
    ],
    PrimitiveType.SSRF_PATTERN: [
        PrimitiveType.WEBHOOK,
        PrimitiveType.OPEN_REDIRECT,
    ],
    PrimitiveType.FILE_UPLOAD: [
        PrimitiveType.TEMPLATE_INJECTION,
        PrimitiveType.DESERIALIZATION,
    ],
    PrimitiveType.WEAK_CORS: [
        PrimitiveType.JSONP_ENDPOINT,
        PrimitiveType.REFLECTED_PARAM,
    ],
}

# Goal states reachable from primitives
PRIMITIVE_GOALS = {
    PrimitiveType.MISSING_AUTH: [GoalState.AUTHENTICATION_BYPASS, GoalState.DATA_EXFILTRATION],
    PrimitiveType.IDOR_PATTERN: [GoalState.DATA_EXFILTRATION, GoalState.ACCOUNT_TAKEOVER],
    PrimitiveType.TEMPLATE_INJECTION: [GoalState.RCE, GoalState.DATA_EXFILTRATION],
    PrimitiveType.DESERIALIZATION: [GoalState.RCE],
    PrimitiveType.FILE_UPLOAD: [GoalState.RCE, GoalState.DATA_MODIFICATION],
    PrimitiveType.SSRF_PATTERN: [GoalState.DATA_EXFILTRATION, GoalState.PRIVILEGE_ESCALATION],
}

# Impact scores for goal states (0-10)
GOAL_IMPACT_SCORES = {
    GoalState.RCE: 10.0,
    GoalState.ADMIN_ACCESS: 9.5,
    GoalState.PRIVILEGE_ESCALATION: 9.0,
    GoalState.ACCOUNT_TAKEOVER: 8.5,
    GoalState.AUTHENTICATION_BYPASS: 8.0,
    GoalState.DATA_EXFILTRATION: 7.5,
    GoalState.DATA_MODIFICATION: 7.0,
    GoalState.DENIAL_OF_SERVICE: 5.0,
}


@dataclass
class ChainStep:
    """A single step in an exploit chain."""
    primitive: Primitive
    step_number: int
    preconditions: List[str] = field(default_factory=list)
    postconditions: List[str] = field(default_factory=list)
    confidence: float = 1.0


@dataclass
class ExploitChain:
    """A complete exploit chain from entry to goal."""
    id: str
    steps: List[ChainStep]
    goal: GoalState
    impact_score: float
    reachability_score: float
    confidence_score: float
    total_score: float
    chain_length: int
    requires_auth: bool
    discovered_at: datetime = field(default_factory=lambda: datetime.utcnow())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "goal": self.goal.value,
            "impact_score": round(self.impact_score, 2),
            "reachability_score": round(self.reachability_score, 2),
            "confidence_score": round(self.confidence_score, 2),
            "total_score": round(self.total_score, 2),
            "chain_length": self.chain_length,
            "requires_auth": self.requires_auth,
            "steps": [
                {
                    "step": step.step_number,
                    "primitive_type": step.primitive.type.value,
                    "target": step.primitive.target,
                    "confidence": step.confidence,
                }
                for step in self.steps
            ],
        }


@dataclass
class NEXUSPhaseResult:
    """Result of NEXUS phase execution."""
    target: str
    primitives_collected: int
    candidate_chains: int
    goal_filtered_chains: int
    top_chains: List[ExploitChain]
    goal_distribution: Dict[str, int]
    started_at: datetime
    completed_at: Optional[datetime] = None
    duration_seconds: float = 0.0
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "primitives_collected": self.primitives_collected,
            "candidate_chains": self.candidate_chains,
            "goal_filtered_chains": self.goal_filtered_chains,
            "top_chains_count": len(self.top_chains),
            "top_chains": [chain.to_dict() for chain in self.top_chains],
            "goal_distribution": self.goal_distribution,
            "duration_seconds": self.duration_seconds,
            "error": self.error,
        }


class NEXUSPhaseOrchestrator:
    """
    Orchestrates NEXUS phase: exploit chain discovery.

    Architecture:
    - Layer 1 (Option A): Generate all candidate chains via graph traversal
    - Layer 2 (Option B): Filter chains that reach goal states
    - Layer 3 (Option C): Score and rank by impact, return top N

    Never shows operators unscored chains. That's graph cosplay, not insight.
    """

    def __init__(self, target: str, top_n: int = 5):
        self.target = target
        self.top_n = top_n
        self.event_bus = get_event_bus()
        self.primitives: List[Primitive] = []
        self.primitive_index: Dict[str, Primitive] = {}

    async def execute(self, primitives: List[Primitive]) -> NEXUSPhaseResult:
        """Execute NEXUS phase: collect primitives, discover chains, score and rank."""
        started_at = datetime.utcnow()

        self.event_bus.emit(GraphEvent(
            type=GraphEventType.LOG,
            payload={"message": f"[NEXUS] Phase started: {self.target}"},
        ))

        # Store primitives
        self.primitives = primitives
        self.primitive_index = {p.id: p for p in primitives}

        logger.info(f"[NEXUS] Collected {len(primitives)} primitives")

        # Layer 1: Generate candidate chains (Option A)
        candidate_chains = self._generate_candidate_chains()
        logger.info(f"[NEXUS] Generated {len(candidate_chains)} candidate chains")

        # Layer 2: Filter by goal states (Option B)
        goal_chains = self._filter_by_goals(candidate_chains)
        logger.info(f"[NEXUS] Filtered to {len(goal_chains)} goal-reaching chains")

        # Layer 3: Score and rank (Option C)
        scored_chains = self._score_chains(goal_chains)
        top_chains = sorted(scored_chains, key=lambda c: c.total_score, reverse=True)[:self.top_n]

        logger.info(f"[NEXUS] Top {len(top_chains)} chains selected")

        # Calculate goal distribution
        goal_distribution = defaultdict(int)
        for chain in goal_chains:
            goal_distribution[chain.goal.value] += 1

        completed_at = datetime.utcnow()
        duration = (completed_at - started_at).total_seconds()

        self.event_bus.emit(GraphEvent(
            type=GraphEventType.LOG,
            payload={
                "message": f"[NEXUS] Phase completed: {len(top_chains)} chains discovered",
                "chains": len(top_chains),
            },
        ))

        return NEXUSPhaseResult(
            target=self.target,
            primitives_collected=len(primitives),
            candidate_chains=len(candidate_chains),
            goal_filtered_chains=len(goal_chains),
            top_chains=top_chains,
            goal_distribution=dict(goal_distribution),
            started_at=started_at,
            completed_at=completed_at,
            duration_seconds=duration,
        )

    def _generate_candidate_chains(self) -> List[List[Primitive]]:
        """
        Layer 1 (Option A): Generate all candidate chains via graph traversal.

        Uses BFS to find all paths through the enablement graph.
        Respects causality: only follows edges where A enables B.
        """
        candidate_chains = []

        # Build adjacency list from enablement relationships
        adjacency = defaultdict(list)
        for primitive in self.primitives:
            enabled_types = PRIMITIVE_ENABLEMENT.get(primitive.type, [])
            for other in self.primitives:
                if other.type in enabled_types and other.id != primitive.id:
                    adjacency[primitive.id].append(other.id)

        # Find all paths (up to max length)
        max_chain_length = 5  # Longer chains are less reliable

        for start_primitive in self.primitives:
            # BFS to explore all paths from this primitive
            queue = deque([(start_primitive.id, [start_primitive.id])])

            while queue:
                current_id, path = queue.popleft()

                # Store this path as a candidate chain
                if len(path) >= 2:  # Chains must have at least 2 steps
                    chain = [self.primitive_index[pid] for pid in path]
                    candidate_chains.append(chain)

                # Continue exploring if chain not too long
                if len(path) < max_chain_length:
                    for next_id in adjacency[current_id]:
                        if next_id not in path:  # Avoid cycles
                            queue.append((next_id, path + [next_id]))

        return candidate_chains

    def _filter_by_goals(self, candidate_chains: List[List[Primitive]]) -> List[ExploitChain]:
        """
        Layer 2 (Option B): Filter chains that reach adversarial goal states.

        A chain reaches a goal if its final primitive can achieve that goal.
        This prunes nonsense chains early.
        """
        goal_chains = []

        for i, chain in enumerate(candidate_chains):
            final_primitive = chain[-1]
            reachable_goals = PRIMITIVE_GOALS.get(final_primitive.type, [])

            if not reachable_goals:
                continue  # Chain doesn't reach any goal

            # Create ExploitChain for each reachable goal
            for goal in reachable_goals:
                steps = [
                    ChainStep(
                        primitive=primitive,
                        step_number=j + 1,
                        confidence=primitive.confidence,
                    )
                    for j, primitive in enumerate(chain)
                ]

                exploit_chain = ExploitChain(
                    id=f"chain_{uuid.uuid4().hex[:8]}",
                    steps=steps,
                    goal=goal,
                    impact_score=0.0,  # Calculated in scoring phase
                    reachability_score=0.0,
                    confidence_score=0.0,
                    total_score=0.0,
                    chain_length=len(chain),
                    requires_auth=any(p.type == PrimitiveType.MISSING_AUTH for p in chain),
                )

                goal_chains.append(exploit_chain)

        return goal_chains

    def _score_chains(self, chains: List[ExploitChain]) -> List[ExploitChain]:
        """
        Layer 3 (Option C): Score and rank chains by impact.

        Chain score combines:
        - Impact: Goal severity (10.0 for RCE, 5.0 for DoS)
        - Reachability: Does it require auth? Preconditions?
        - Chain length penalty: Longer chains are less reliable
        - Primitive confidence: Averaged across all steps
        - Exploit realism: Are primitives reliable?
        """
        scored_chains = []

        for chain in chains:
            # 1. Impact score (from goal)
            impact = GOAL_IMPACT_SCORES.get(chain.goal, 5.0)

            # 2. Reachability score (inverse of barriers)
            reachability = 1.0
            if chain.requires_auth:
                reachability *= 0.7  # Auth requirement reduces reachability

            # Check if all primitives are reliable
            unreliable_steps = sum(1 for step in chain.steps if not step.primitive.is_reliable)
            reachability *= (1.0 - (unreliable_steps * 0.1))  # 10% penalty per unreliable step

            # 3. Chain length penalty (exponential decay)
            length_penalty = 0.9 ** (chain.chain_length - 1)  # 10% penalty per additional step

            # 4. Primitive confidence (geometric mean for chain confidence)
            confidence_product = 1.0
            for step in chain.steps:
                confidence_product *= step.primitive.confidence
            confidence_score = confidence_product ** (1.0 / len(chain.steps))

            # 5. Exploit realism (based on primitive reliability)
            realism = sum(1 for step in chain.steps if step.primitive.is_reliable) / len(chain.steps)

            # Combine into total score (weighted)
            total_score = (
                impact * 0.40 +                    # 40% weight on impact
                reachability * 10.0 * 0.25 +       # 25% weight on reachability
                confidence_score * 10.0 * 0.20 +   # 20% weight on confidence
                realism * 10.0 * 0.15              # 15% weight on realism
            ) * length_penalty  # Apply length penalty

            # Update chain with scores
            chain.impact_score = impact
            chain.reachability_score = reachability * 10.0  # Scale to 0-10
            chain.confidence_score = confidence_score * 10.0
            chain.total_score = total_score

            scored_chains.append(chain)

        return scored_chains
