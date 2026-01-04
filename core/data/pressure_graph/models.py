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


class PressureSource(Enum):
    """Origin of the pressure value."""
    ENGINE = "engine"         # Calculated by our Propagator
    INTERPOLATED = "interpolated" # Smooth transition state (frontend only usually, but allowed here)
    DECAYING = "decaying"     # Post-remediation cooling


class RemediationState(Enum):
    """Lifecycle of a fix."""
    NONE = "none"
    PROPOSED = "proposed"     # Simulated relief
    APPLIED = "applied"       # User clicked "Fix"
    VERIFIED = "verified"     # Scanner confirmed fix
    REVERTED = "reverted"     # Fix failed or undone


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
    
    # V2: State & Audit
    pressure_source: PressureSource = PressureSource.ENGINE
    remediation_state: RemediationState = RemediationState.NONE
    revision: int = 1
    
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
    created_at: float = 0.0
    
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
    state: RemediationState = RemediationState.PROPOSED
    
    nodes_to_remove: Set[NodeId] = field(default_factory=set)
    edges_to_remove: Set[EdgeId] = field(default_factory=set)
    node_pressure_reductions: Dict[NodeId, float] = field(default_factory=dict)
    edge_transfer_reductions: Dict[EdgeId, float] = field(default_factory=dict)
    
    effort: float = 0.5
    cost: float = 1.0

    def apply_to_node(self, node: PressureNode) -> Optional[PressureNode]:
        """Returns modified node or None if removed."""
        if self.state == RemediationState.REVERTED:
            return node
            
        if node.id in self.nodes_to_remove:
            return None
            
        if node.id in self.node_pressure_reductions:
            reduction = self.node_pressure_reductions[node.id]
            # Create new derived node with reduced severity
            new_severity = node.severity * (1.0 - reduction)
            return PressureNode(
                id=node.id,
                type=node.type,
                severity=new_severity, # Reduced
                exposure=node.exposure,
                exploitability=node.exploitability,
                privilege_gain=node.privilege_gain,
                asset_value=node.asset_value,
                tool_reliability=node.tool_reliability,
                evidence_quality=node.evidence_quality,
                corroboration_count=node.corroboration_count,
                pressure_source=node.pressure_source,
                remediation_state=self.state,
                revision=node.revision + 1
            )
        return node

    def apply_to_edge(self, edge: PressureEdge) -> Optional[PressureEdge]:
        """Returns modified edge or None if removed."""
        if self.state == RemediationState.REVERTED:
            return edge
            
        if edge.id in self.edges_to_remove:
            return None
            
        if edge.id in self.edge_transfer_reductions:
            reduction = self.edge_transfer_reductions[edge.id]
            new_transfer = edge.transfer_factor * (1.0 - reduction)
            return PressureEdge(
                id=edge.id,
                source_id=edge.source_id,
                target_id=edge.target_id,
                type=edge.type,
                transfer_factor=new_transfer,
                confidence=edge.confidence,
                evidence_sources=edge.evidence_sources
            )
        return edge