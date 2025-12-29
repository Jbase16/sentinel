"""
Core data models for pressure graph.

All models are deterministic and traceable to evidence.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Set, Dict, List, Optional


class EdgeType(Enum):
    """Types of causal relationships between pressure nodes."""
    ENABLES = "enables"      # A creates opportunity for B
    REACHES = "reaches"      # A can communicate with B
    REQUIRES = "requires"    # A depends on B
    AMPLIFIES = "amplifies"  # A increases impact of B


@dataclass
class PressureNode:
    """
    Represents a security entity in the pressure graph.
    
    Pressure is deterministic: severity × exposure × exploitability × privilege_gain × asset_value.
    """
    id: str
    type: str  # "asset", "vulnerability", "exposure", "identity_issue", "trust"
    
    # Input factors (all traceable to evidence)
    severity: float  # 0-10, from CVSS or tool output
    exposure: float  # 0-1, how accessible is this?
    exploitability: float  # 0-1, how easily can it be exploited?
    privilege_gain: float  # 0-1, what access does this provide?
    asset_value: float  # 0-10, business criticality
    
    # Evidence traceability
    tool_reliability: float = 1.0  # 0-1, reliability of source tool
    evidence_quality: float = 1.0  # 0-1, quality of evidence
    corroboration_count: int = 0  # Number of corroborating findings
    
    # Computed values
    base_pressure: float = field(init=False)
    confidence: float = field(init=False)
    inbound_pressure: float = 0.0  # Pressure flowing from upstream nodes
    
    def __post_init__(self):
        """Compute deterministic values after initialization."""
        # Base pressure: deterministic product
        self.base_pressure = (
            self.severity *
            self.exposure *
            self.exploitability *
            self.privilege_gain *
            self.asset_value
        )
        
        # Confidence: deterministic calculation based on evidence
        # Formula: tool_reliability * (0.5 + 0.5 * evidence_quality) * (1.0 - 0.1^(corroboration_count + 1))
        self.confidence = (
            self.tool_reliability *
            (0.5 + 0.5 * self.evidence_quality) *
            (1.0 - 0.1 ** (self.corroboration_count + 1))
        )


@dataclass
class PressureEdge:
    """
    Represents a causal relationship between pressure nodes.
    
    Pressure propagates from source to target based on transfer_factor.
    """
    id: str
    source_id: str
    target_id: str
    type: EdgeType
    
    # How much pressure propagates (0-1)
    transfer_factor: float
    
    # How certain we are this edge exists (0-1)
    confidence: float
    
    # Evidence traceability
    evidence_sources: List[str] = field(default_factory=list)  # Which tools/findings created this edge
    created_at: float = 0.0  # When was this edge discovered
    
    # For optimization
    cached_pressure_delta: float = 0.0  # Δ pressure at target if this edge is removed


@dataclass
class Remediation:
    """
    Represents a security fix or mitigation.
    
    Remediations can be:
    - Remove node (e.g., patch vulnerability)
    - Remove edge (e.g., block network path)
    - Reduce node pressure (e.g., add WAF)
    - Reduce edge transfer factor (e.g., add MFA)
    """
    id: str
    name: str
    
    # What this remediation does
    nodes_to_remove: Set[str] = field(default_factory=set)
    edges_to_remove: Set[str] = field(default_factory=set)
    node_pressure_reductions: Dict[str, float] = field(default_factory=dict)
    edge_transfer_reductions: Dict[str, float] = field(default_factory=dict)
    
    # Cost/effort metrics
    effort: float = 0.5  # 0-1, how hard is this to implement?
    cost: float = 1.0  # Monetary or effort cost
    
    # Evidence
    evidence_sources: List[str] = field(default_factory=list)
    
    def apply_to_node(self, node: 'PressureNode') -> Optional['PressureNode']:
        """
        Apply this remediation to a node.
        Returns modified node or None if node is removed.
        """
        if node.id in self.nodes_to_remove:
            return None  # Node is removed
        
        if node.id in self.node_pressure_reductions:
            # Create new node with reduced base pressure
            from copy import deepcopy
            new_node = deepcopy(node)
            reduction = self.node_pressure_reductions[node.id]
            new_node.base_pressure = max(0.0, node.base_pressure - reduction)
            return new_node
        
        return node  # No change
    
    def apply_to_edge(self, edge: 'PressureEdge') -> Optional['PressureEdge']:
        """
        Apply this remediation to an edge.
        Returns modified edge or None if edge is removed.
        """
        if edge.id in self.edges_to_remove:
            return None  # Edge is removed
        
        if edge.id in self.edge_transfer_reductions:
            # Create new edge with reduced transfer factor
            from copy import deepcopy
            new_edge = deepcopy(edge)
            reduction = self.edge_transfer_reductions[edge.id]
            new_edge.transfer_factor = max(0.0, edge.transfer_factor - reduction)
            return new_edge
        
        return edge  # No change