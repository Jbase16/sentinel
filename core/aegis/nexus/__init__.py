"""
Project NEXUS - The Chain Reactor

Logic chaining to turn low-severity findings (Primitives) into high-impact chains.
This transforms "noise" into "signal" by connecting individual vulnerabilities into
exploit paths.

THREAT MODEL (Defensive Framing):
This module helps organizations:
- Understand the cumulative risk of minor issues
- Identify exploit chains that attackers could use
- Prioritize remediation based on actual impact potential
- Test defense-in-depth during red team exercises

SAFETY CONSTRAINTS:
- All chains are theoretical models (not executed)
- No exploitation or payload injection
- Results are for authorized security assessments only

INTEGRATION POINTS:
- EventBus: Emits NEXUS_CHAIN_DISCOVERED, NEXUS_PRIMITIVE_COLLECTED events
- DecisionLedger: Logs chain construction decisions
- KnowledgeGraph: Stores primitive relationships and chains
"""

from core.aegis.nexus.primitives import (
    Primitive,
    PrimitiveType,
    PrimitiveInventory,
    PrimitiveCollector,
    ReliabilityLevel,
    SAFE_MODE,
    create_primitive_collector,
)
from core.aegis.nexus.solver import (
    ChainSolver,
    ChainPlan,
    ChainStep,
    GoalState,
    SolveResult,
    create_chain_solver,
)
from core.aegis.nexus.chain import (
    ChainExecutor,
    ChainResult,
    ExecutionProof,
    StepResult,
    ExecutionStatus,
    StepStatus,
    SAFE_MODE as CHAIN_SAFE_MODE,
    create_chain_executor,
)

# Export SAFE_MODE from primitives as the module-level constant
SAFE_MODE = SAFE_MODE

# Aliases for shorter factory function names (convenience)
create_collector = create_primitive_collector
create_solver = create_chain_solver
create_executor = create_chain_executor

__all__ = [
    # Primitives
    "Primitive",
    "PrimitiveType",
    "PrimitiveInventory",
    "PrimitiveCollector",
    "ReliabilityLevel",
    # Solver
    "ChainSolver",
    "ChainPlan",
    "ChainStep",
    "GoalState",
    "SolveResult",
    # Chain Executor
    "ChainExecutor",
    "ChainResult",
    "ExecutionProof",
    "StepResult",
    "ExecutionStatus",
    "StepStatus",
    # Factory Functions
    "create_primitive_collector",
    "create_chain_solver",
    "create_chain_executor",
    "create_collector",  # alias
    "create_solver",  # alias
    "create_executor",  # alias
    # Safety
    "SAFE_MODE",
]
