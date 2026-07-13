"""Passive behavioral-analysis primitives.

Gate C lives in :mod:`core.behavior.active` and is deliberately not imported here,
so importing the passive shadow observer does not load an execution surface.
"""

from .graph import BehaviorGraph, GraphLimits, ObservationResult
from .compiler import (
    ANALYSIS_ONLY_MODE,
    BackwardExploitCompiler,
    BackwardGoal,
    BackwardPlan,
    Capability,
    CapabilityKind,
    CompilerLimits,
    CompilerPolicy,
    OperationCatalogLimits,
    OperationContract,
    OperationSafety,
    high_value_goals,
    operation_contracts_from_records,
)
from .explorer import (
    BehavioralReadExplorer,
    ReadExplorationLimits,
    ReadExplorationResult,
)
from .graphql_catalog import (
    GraphQLCatalogLimits,
    GraphQLResolutionResult,
    PersistedOperationCatalog,
)
from .models import NormalizedExchange
from .normalize import normalize_exchange
from .proposals import (
    AuthorizationExperimentProposal,
    ProposalBatch,
    ProposalLimits,
    compile_authorization_proposals,
)
from .receipts import BehavioralExecutionReceipt, BehavioralReceiptStore
from .shadow import ShadowBehaviorRegistry

__all__ = [
    "ANALYSIS_ONLY_MODE",
    "BackwardExploitCompiler",
    "BackwardGoal",
    "BackwardPlan",
    "BehaviorGraph",
    "BehavioralReadExplorer",
    "BehavioralExecutionReceipt",
    "BehavioralReceiptStore",
    "Capability",
    "CapabilityKind",
    "CompilerLimits",
    "CompilerPolicy",
    "GraphLimits",
    "GraphQLCatalogLimits",
    "GraphQLResolutionResult",
    "NormalizedExchange",
    "ObservationResult",
    "OperationCatalogLimits",
    "OperationContract",
    "OperationSafety",
    "AuthorizationExperimentProposal",
    "ProposalBatch",
    "ProposalLimits",
    "ReadExplorationLimits",
    "ReadExplorationResult",
    "PersistedOperationCatalog",
    "ShadowBehaviorRegistry",
    "compile_authorization_proposals",
    "high_value_goals",
    "normalize_exchange",
    "operation_contracts_from_records",
]
