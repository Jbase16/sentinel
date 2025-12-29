"""
Core data models.

Architectural Note: These dataclasses are frozen.
This enforces functional purity. To mutate state, create a new instance.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Set, Dict, List, Optional

# Type aliases for clarity and stricter checking
NodeId = str
EdgeId = str


class EdgeType(Enum):
    """Types of causal relationships."""
    ENABLES = "enables"
    REACHES = "reaches"
    REQUIRES = "requires"
    AMPLIFIES = "amplifies"


@dataclass(frozen=True)
class PressureNode:
    """
    Immutable security entity.
    
    Invariant: base_pressure is deterministic and constant for the lifetime 
    of the instance.
    """
    id: NodeId
    type: str
    
    # Factors
    severity: float
    exposure: float
    exploitability: float
    privilege_gain: float
    asset_value: float
    
    # Evidence
    tool_reliability: float = 1.0
    evidence_quality: float = 1.0
    corroboration_count: int = 0
    
    # Computed Field (set once in __post_init__)
    base_pressure: float = field(init=False)
    
    def __post_init__(self):
        # Using object.__setattr__ because the class is frozen=True
        object.__setattr__(
            self, 
            'base_pressure',
            self.severity * self.exposure * self.exploitability * 
            self.privilege_gain * self.asset_value
        )


@dataclass(frozen=True)
class PressureEdge:
    """
    Immutable causal relationship.
    """
    id: EdgeId
    source_id: NodeId
    target_id: NodeId
    type: EdgeType
    
    transfer_factor: float
    confidence: float
    
    evidence_sources: List[str] = field(default_factory=list)
    
    # Internal state for optimization (mutable for perf, logically immutable)
    # We allow _cached_... fields to be mutable to support post-init normalization
    _normalized_transfer_factor: Optional[float] = field(default=None, init=False, compare=False)
    
    @property
    def effective_transfer(self) -> float:
        """
        Returns the transfer factor adjusted for confidence.
        
        Optimization: If normalization has occurred, returns the pre-computed value.
        """
        if self._normalized_transfer_factor is not None:
            return self._normalized_transfer_factor
        
        return self.transfer_factor * self.confidence


@dataclass(frozen=True)
class Remediation:
    """
    A description of a state transition.
    """
    id: str
    name: str
    
    nodes_to_remove: Set[NodeId] = field(default_factory=set)
    edges_to_remove: Set[EdgeId] = field(default_factory=set)
    node_pressure_reductions: Dict[NodeId, float] = field(default_factory=dict)
    edge_transfer_reductions: Dict[EdgeId, float] = field(default_factory=dict)
    
    effort: float = 0.5
    cost: float = 1.0