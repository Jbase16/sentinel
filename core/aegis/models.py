"""
Aegis Data Models.
Immutable structures for the Business Logic Graph.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Optional, Set

@dataclass(frozen=True)
class BusinessNode:
    """
    Represents a business asset, process, or abstract value.
    Example: 'Payment Processing', 'Customer Database', 'Brand Reputation'.
    """
    id: str
    name: str
    type: str  # 'asset', 'process', 'reputation', 'service'
    
    # Intrinsic Business Value (1.0 - 10.0)
    # 10.0 = Company Ending Event (Crown Jewel)
    # 1.0  = Minor Operational Nuisance
    value: float
    
    # Description or Notes
    description: Optional[str] = None
    
    # Metadata for UI/Rendering
    tags: Set[str] = field(default_factory=set)

@dataclass(frozen=True)
class BusinessEdge:
    """
    Directional relationship between business entities.
    Source -> Target means "Source affects Target" or "Target depends on Source".
    """
    source_id: str
    target_id: str
    type: str  # 'depends_on', 'impacts', 'part_of'
    
    # Impact Weight (0.0 - 1.0)
    # How much of the source's risk transfers to the target?
    weight: float = 1.0
