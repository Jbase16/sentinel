"""
Aegis Bridge.
The "Synapse" between the Technical Graph (Pressure) and Business Graph (Aegis).
"""

from typing import List, Dict, Optional, Tuple
import re
import logging

from .models import BusinessNode, BusinessEdge
from core.data.pressure_graph.models import PressureNode

logger = logging.getLogger(__name__)

class AegisBridge:
    """
    Automated mapper that links Technical Nodes -> Business Nodes.
    """
    
    def __init__(self):
        # Regex heuristics: Pattern -> (Business Entity Name, Entity Type, Value Score)
        self.heuristics: List[Tuple[str, str, str, float]] = [
            (r"/api/v1/payments", "Payment Gateway", "service", 9.0),
            (r"/api/v1/billing", "Billing Service", "service", 8.5),
            (r"/admin", "Admin Portal", "asset", 9.5),
            (r"login", "Authentication Service", "service", 9.0),
            (r"customer", "Customer Database", "asset", 8.0),
            (r"invoice", "Financial Records", "asset", 7.5),
            (r"health", "Monitoring System", "service", 3.0),
        ]
        
    def suggest_business_links(self, technical_node: PressureNode) -> List[BusinessNode]:
        """
        Analyze a technical node and suggest potential business entities it impacts.
        """
        suggestions = []
        
        # Check ID and Type against heuristics
        # Ideally we'd have rich metadata (URL, hostname) but for now we often shove it in ID
        target_str = technical_node.id
        
        for pattern, name, b_type, value in self.heuristics:
            if re.search(pattern, target_str, re.IGNORECASE):
                suggestions.append(
                    BusinessNode(
                        id=name.lower().replace(" ", "_"),
                        name=name,
                        type=b_type,
                        value=value,
                        description=f"Auto-discovered via pattern '{pattern}' matching '{target_str}'"
                    )
                )
                
        return suggestions

    def create_bridge_edge(self, technical_node_id: str, business_node_id: str) -> BusinessEdge:
        """
        Create a dependency edge: Business Node depends on Technical Node.
        Wait... dependency direction is tricky.
        
        If Technical Node (SQLi) implies Risk on Business Node (Data),
        then Risk flows Technical -> Business.
        
        In the Risk Graph:
        Source (Exploit) -> Target (Business Asset).
        
        So we return an edge Source=Tech, Target=Business.
        BUT Aegis Graph is strictly Business Objects.
        
        Architectural Decision:
        Aegis Graph calculates risk *on top* of Pressure Graph.
        The Bridge acts as the adapter. 
        It returns a MAPPING, not necessarily a raw edge in the same graph (unless we merge them).
        
        For now, let's assume we maintain a separate mapping registry.
        """
        pass # The bridge is logic, not data storage. Keep it simple.
