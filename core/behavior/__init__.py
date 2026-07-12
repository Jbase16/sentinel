"""Passive behavioral-analysis primitives.

Gate C lives in :mod:`core.behavior.active` and is deliberately not imported here,
so importing the passive shadow observer does not load an execution surface.
"""

from .graph import BehaviorGraph, GraphLimits, ObservationResult
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
    "BehaviorGraph",
    "BehavioralReadExplorer",
    "BehavioralExecutionReceipt",
    "BehavioralReceiptStore",
    "GraphLimits",
    "GraphQLCatalogLimits",
    "GraphQLResolutionResult",
    "NormalizedExchange",
    "ObservationResult",
    "AuthorizationExperimentProposal",
    "ProposalBatch",
    "ProposalLimits",
    "ReadExplorationLimits",
    "ReadExplorationResult",
    "PersistedOperationCatalog",
    "ShadowBehaviorRegistry",
    "compile_authorization_proposals",
    "normalize_exchange",
]
