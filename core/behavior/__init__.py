"""Passive behavioral-analysis primitives.

Gate C lives in :mod:`core.behavior.active` and is deliberately not imported here,
so importing the passive shadow observer does not load an execution surface.
"""

from .graph import BehaviorGraph, GraphLimits, ObservationResult
from .models import NormalizedExchange
from .normalize import normalize_exchange
from .proposals import (
    AuthorizationExperimentProposal,
    ProposalBatch,
    ProposalLimits,
    compile_authorization_proposals,
)
from .shadow import ShadowBehaviorRegistry

__all__ = [
    "BehaviorGraph",
    "GraphLimits",
    "NormalizedExchange",
    "ObservationResult",
    "AuthorizationExperimentProposal",
    "ProposalBatch",
    "ProposalLimits",
    "ShadowBehaviorRegistry",
    "compile_authorization_proposals",
    "normalize_exchange",
]
