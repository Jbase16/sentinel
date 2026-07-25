"""
Pressure Graph: Deterministic causal analysis for security decision-making.

This module provides a deterministic, evidence-based decision engine that identifies
which fixes most reduce pressure on crown jewel assets.

Core Components:
- PressureNode: Represents security entities (assets, vulnerabilities, exposures)
- PressureEdge: Represents causal relationships
- PressurePropagator: Cycle-safe pressure propagation using iterative relaxation
- CounterfactualEngine: Fast remediation simulation with dirty subgraph optimization
- MinimalFixSetEngine: Node-splitting min-cut to find optimal remediation sets
"""

from .models import (
    PressureNode,
    PressureEdge,
    Remediation,
    EdgeType
)
from .propagator import PressurePropagator
from .counterfactual import CounterfactualEngine
from .min_fix_set import MinimalFixSetEngine
from .manager import PressureGraphManager

__all__ = [
    'PressureNode',
    'PressureEdge',
    'Remediation',
    'EdgeType',
    'PressurePropagator',
    'CounterfactualEngine',
    'MinimalFixSetEngine',
    'PressureGraphManager',
]