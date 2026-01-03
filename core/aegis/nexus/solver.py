"""
NEXUS Solver - Logic Chaining Engine

PURPOSE:
Calculate paths from "here" (current primitives) to "there" (goal state) by
linking low-severity findings into high-impact exploit chains.

THREAT MODEL (Defensive Framing):
This module helps organizations:
- Understand how minor issues combine into major risks
- Identify the most likely attack paths
- Prioritize remediation based on chain disruption
- Assess defense-in-depth effectiveness

ASSUMPTIONS:
1. Primitives can be linked in dependency graphs
2. Goals are well-defined (e.g., "read user data")
3. Success probability is estimable
4. Chains are theoretical models (not executed)

SAFETY CONSTRAINTS:
- SAFE_MODE: If True, excludes dangerous goal states
- No actual exploitation or execution
- Chains are models only (not carried out)
- Results are for authorized security assessments only

INTEGRATION POINTS:
- EventBus: Emits NEXUS_CHAIN_SOLVED, NEXUS_NO_PATH events
- DecisionLedger: Logs chain planning decisions
- KnowledgeGraph: Uses primitive graph for pathfinding

DEPENDENCIES (Future):
- networkx: For graph operations and pathfinding
- heapq: For priority queue in A* algorithm
- itertools: For chain combination generation
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse

# Safety fuse: prevents unsafe operations
SAFE_MODE: bool = True

logger = logging.getLogger(__name__)


class GoalState(str, Enum):
    """
    Target end-states for exploit chains.

    These represent high-impact outcomes that could result
    from chaining low-severity primitives.

    NOTE: In SAFE_MODE, dangerous goals are excluded.
    """
    # Information disclosure goals
    USER_READ_PII = "user_read_pii"           # Read user personal data
    ADMIN_ACCESS = "admin_access"               # Access admin panel
    SOURCE_CODE_READ = "source_code_read"       # Read source code
    CONFIG_READ = "config_read"                 # Read configuration

    # Data manipulation goals
    USER_MODIFY_DATA = "user_modify_data"       # Modify other users' data
    DELETE_DATA = "delete_data"                 # Delete arbitrary data

    # Dangerous goals (excluded in SAFE_MODE)
    RCE = "rce"                                 # Remote code execution
    SSRF_TO_CLOUD = "ssrf_to_cloud"             # SSRF to cloud metadata
    FULL_COMPROMISE = "full_compromise"         # Complete system takeover

    def is_dangerous(self) -> bool:
        """Check if this is a dangerous goal state."""
        return self in (GoalState.RCE, GoalState.SSRF_TO_CLOUD, GoalState.FULL_COMPROMISE)


@dataclass(frozen=True)
class ChainStep:
    """
    A single step in an exploit chain.

    Each step represents using one primitive to enable the next.

    Attributes:
        primitive_id: Which primitive to use
        primitive_type: Type of the primitive
        description: What this step does
        cost: Estimated "cost" (complexity, detection risk, etc.)
        success_probability: How likely this step succeeds (0.0-1.0)
    """
    primitive_id: str
    primitive_type: str
    description: str
    cost: float = 1.0
    success_probability: float = 0.5

    def __post_init__(self):
        """Validate step fields."""
        if not 0.0 <= self.success_probability <= 1.0:
            raise ValueError(
                f"success_probability must be 0.0-1.0, got {self.success_probability}"
            )
        if self.cost < 0:
            raise ValueError(f"cost must be non-negative, got {self.cost}")

    def to_dict(self) -> Dict[str, Any]:
        """Serialize step to dict."""
        return {
            "primitive_id": self.primitive_id,
            "primitive_type": self.primitive_type,
            "description": self.description,
            "cost": self.cost,
            "success_probability": self.success_probability,
        }


@dataclass
class ChainPlan:
    """
    A complete exploit chain plan.

    This represents a theoretical path from current primitives
    to a goal state, with each step justified.

    Attributes:
        id: Unique identifier for this plan
        goal: Target end-state
        start_primitive: Where the chain starts
        steps: Ordered list of steps to execute
        total_cost: Sum of all step costs
        success_probability: Overall chain success probability
        confidence: How confident we are in this plan (0.0-1.0)
        planned_at: When this plan was generated
    """
    id: str
    goal: GoalState
    start_primitive: str
    steps: List[ChainStep] = field(default_factory=list)
    total_cost: float = 0.0
    success_probability: float = 0.0
    confidence: float = 0.5
    planned_at: datetime = field(default_factory=lambda: datetime.utcnow())

    @property
    def step_count(self) -> int:
        """Get number of steps in this chain."""
        return len(self.steps)

    @property
    def is_feasible(self) -> bool:
        """Check if this chain is feasible (has steps and non-zero probability)."""
        return self.step_count > 0 and self.success_probability > 0.1

    def to_dict(self) -> Dict[str, Any]:
        """Serialize plan to dict."""
        return {
            "id": self.id,
            "goal": self.goal.value,
            "start_primitive": self.start_primitive,
            "step_count": self.step_count,
            "total_cost": self.total_cost,
            "success_probability": self.success_probability,
            "confidence": self.confidence,
            "planned_at": self.planned_at.isoformat(),
            "steps": [step.to_dict() for step in self.steps],
        }


@dataclass
class SolveResult:
    """
    Result of a solve operation.

    Attributes:
        target: Domain being analyzed
        goal: Target goal state
        found_paths: List of valid chains (sorted by quality)
        best_plan: Highest quality plan (if any)
        no_path_reason: Why no path was found (if applicable)
        solved_at: When solving was performed
    """
    target: str
    goal: GoalState
    found_paths: List[ChainPlan] = field(default_factory=list)
    best_plan: Optional[ChainPlan] = None
    no_path_reason: Optional[str] = None
    solved_at: datetime = field(default_factory=lambda: datetime.utcnow())

    @property
    def has_solution(self) -> bool:
        """Check if a valid chain was found."""
        return len(self.found_paths) > 0 and self.best_plan is not None

    def to_dict(self) -> Dict[str, Any]:
        """Serialize result to dict."""
        return {
            "target": self.target,
            "goal": self.goal.value,
            "has_solution": self.has_solution,
            "path_count": len(self.found_paths),
            "no_path_reason": self.no_path_reason,
            "solved_at": self.solved_at.isoformat(),
            "best_plan": self.best_plan.to_dict() if self.best_plan else None,
        }


class ChainSolver:
    """
    Solves for exploit chains using primitive inventory.

    This class implements pathfinding algorithms to discover
    how low-severity primitives can be chained into high-impact
    attacks.

    SOLVING STRATEGY:
    1. Build dependency graph from primitives
    2. Use A* or greedy search to find paths
    3. Calculate success probability for each path
    4. Rank chains by cost/probability ratio
    5. Return best chain(s) for the goal

    EXAMPLE USAGE:
        ```python
        solver = ChainSolver()
        inventory = PrimitiveInventory(...)
        result = solver.solve_chain(
            inventory=inventory,
            start_primitive_id="prim_123",
            goal=GoalState.ADMIN_ACCESS,
        )
        if result.has_solution:
            print(f"Found {len(result.found_paths)} chains")
        ```
    """

    # Event names for integration with EventBus
    EVENT_SOLVE_STARTED = "nexus_solve_started"
    EVENT_SOLVE_COMPLETED = "nexus_solve_completed"
    EVENT_CHAIN_FOUND = "nexus_chain_found"
    EVENT_NO_PATH = "nexus_no_path"

    # Cost weights for pathfinding
    COST_REFLECTED_PARAM = 1.0
    COST_OPEN_REDIRECT = 2.0
    COST_SSRF_PATTERN = 5.0
    COST_MISSING_AUTH = 3.0
    COST_WEAK_CORS = 1.5

    def __init__(self, safe_mode: bool = SAFE_MODE):
        """
        Initialize ChainSolver.

        Args:
            safe_mode: If True, excludes dangerous goals
        """
        self._safe_mode = safe_mode
        self._solve_count = 0

    @property
    def safe_mode(self) -> bool:
        """Check if operating in safe mode."""
        return self._safe_mode

    @property
    def solve_count(self) -> int:
        """Get number of solves performed."""
        return self._solve_count

    def solve_chain(
        self,
        inventory: "PrimitiveInventory",
        start_primitive_id: str,
        goal: GoalState,
        max_depth: int = 5,
        max_paths: int = 10,
    ) -> SolveResult:
        """
        Find exploit chains from start primitive to goal state.

        TODO: Implement A* search algorithm.
        TODO: Build dependency graph from primitives.
        TODO: Calculate heuristic for goal distance.
        TODO: Generate multiple paths for comparison.
        TODO: Filter by safe_mode if enabled.

        Args:
            inventory: Available primitives
            start_primitive_id: Entry point for chain
            goal: Target end-state
            max_depth: Maximum chain length
            max_paths: Maximum number of paths to return

        Returns:
            SolveResult with discovered chains

        Raises:
            NotImplementedError: This is a wrapper-only implementation
        """
        # Check safe mode
        if self._safe_mode and goal.is_dangerous():
            raise ValueError(
                f"SAFE_MODE: Dangerous goal not allowed: {goal.value}"
            )

        # Update statistics
        self._solve_count += 1

        # Emit event (integration point)
        logger.debug(
            f"[ChainSolver] {self.EVENT_SOLVE_STARTED}: "
            f"goal={goal.value}, start={start_primitive_id}"
        )

        # Create result skeleton
        result = SolveResult(
            target=inventory.target,
            goal=goal,
        )

        raise NotImplementedError(
            "Wrapper-only: Chain solving implementation deferred. "
            "Future implementation should use A* with heuristic."
        )

    def calculate_success_probability(
        self,
        chain: ChainPlan
    ) -> float:
        """
        Calculate overall success probability for a chain.

        TODO: Multiply step probabilities.
        TODO: Adjust for chain length (longer = less reliable).
        TODO: Consider weakest link in chain.
        TODO: Apply confidence adjustment.

        Args:
            chain: The chain plan to evaluate

        Returns:
            Overall success probability (0.0-1.0)

        Raises:
            NotImplementedError: This is a wrapper-only implementation
        """
        raise NotImplementedError(
            "Wrapper-only: Success probability calculation deferred. "
            "Future implementation should multiply step probabilities."
        )

    def calculate_step_cost(
        self,
        primitive: "Primitive",
    ) -> float:
        """
        Calculate "cost" of using a primitive in a chain.

        TODO: Assign costs based on primitive type.
        TODO: Consider detection risk.
        TODO: Consider complexity/effort.
        TODO: Consider reliability level.

        Args:
            primitive: The primitive to cost

        Returns:
            Cost value (lower is better/easier)

        Raises:
            NotImplementedError: This is a wrapper-only implementation
        """
        raise NotImplementedError(
            "Wrapper-only: Step cost calculation deferred. "
            "Future implementation should use type-based cost table."
        )

    def rank_chains(
        self,
        chains: List[ChainPlan]
    ) -> List[ChainPlan]:
        """
        Rank chains by quality (cost vs probability).

        TODO: Sort by success_probability / total_cost ratio.
        TODO: Prefer shorter chains with equal ratios.
        TODO: Filter out infeasible chains.
        TODO: Apply confidence weighting.

        Args:
            chains: Unsorted list of chain plans

        Returns:
            Sorted list (best first)

        Raises:
            NotImplementedError: This is a wrapper-only implementation
        """
        raise NotImplementedError(
            "Wrapper-only: Chain ranking deferred. "
            "Future implementation should sort by value metric."
        )

    def replay(self, recorded_solve: Dict[str, Any]) -> SolveResult:
        """
        Replay a previously solved chain plan.

        Enables replayability without re-solving.

        Args:
            recorded_solve: Serialized SolveResult from to_dict()

        Returns:
            Reconstructed SolveResult

        Raises:
            NotImplementedError: This is a wrapper-only implementation
        """
        raise NotImplementedError(
            "Wrapper-only: Solve replay implementation deferred. "
            "Future implementation should deserialize from evidence store."
        )

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get usage statistics for this ChainSolver instance.

        Returns:
            Dictionary with solve statistics
        """
        return {
            "solve_count": self._solve_count,
            "safe_mode": self._safe_mode,
        }


def create_chain_solver(safe_mode: bool = SAFE_MODE) -> ChainSolver:
    """
    Factory function to create ChainSolver instance.

    This is the recommended way to create ChainSolver objects in production code.

    Args:
        safe_mode: Safety mode flag

    Returns:
        Configured ChainSolver instance
    """
    return ChainSolver(safe_mode=safe_mode)


# ============================================================================
# Module Self-Test (Design Verification)
# ============================================================================

if __name__ == "__main__":
    from core.aegis.nexus.primitives import Primitive, PrimitiveType

    # Verify GoalState enum
    assert GoalState.ADMIN_ACCESS.value == "admin_access"
    assert GoalState.RCE.is_dangerous() is True
    assert GoalState.ADMIN_ACCESS.is_dangerous() is False
    print("✓ GoalState enum works")

    # Verify ChainStep dataclass
    step = ChainStep(
        primitive_id="prim_123",
        primitive_type="reflected_param",
        description="Use reflected param for XSS",
        cost=1.0,
        success_probability=0.7,
    )
    assert step.to_dict()["primitive_id"] == "prim_123"
    print("✓ ChainStep structure works")

    # Verify ChainPlan dataclass
    plan = ChainPlan(
        id=str(uuid.uuid4()),
        goal=GoalState.ADMIN_ACCESS,
        start_primitive="prim_123",
        steps=[step],
    )
    assert plan.step_count == 1
    assert plan.to_dict()["goal"] == "admin_access"
    print("✓ ChainPlan structure works")

    # Verify SolveResult dataclass
    result = SolveResult(
        target="example.com",
        goal=GoalState.ADMIN_ACCESS,
        found_paths=[plan],
        best_plan=plan,
    )
    assert result.has_solution is True
    assert result.to_dict()["has_solution"] is True
    print("✓ SolveResult aggregation works")

    # Verify ChainSolver creation
    solver = create_chain_solver()
    assert solver.safe_mode is True
    assert solver.solve_count == 0
    print("✓ ChainSolver factory works")

    # Verify safe mode enforcement
    try:
        solver.solve_chain(
            inventory=PrimitiveInventory(target="example.com"),
            start_primitive_id="prim_123",
            goal=GoalState.RCE,  # Dangerous goal
        )
        print("✗ Safe mode enforcement failed")
    except ValueError as e:
        if "SAFE_MODE" in str(e):
            print("✓ Safe mode enforcement works")
        else:
            print(f"✗ Unexpected error: {e}")

    print("\n✅ All ChainSolver design invariants verified!")
