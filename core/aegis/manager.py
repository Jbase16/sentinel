"""
Aegis Manager.
Orchestrates the Business Graph, Bridge, and Risk Calculation.
Listens to Technical Graph updates to keep Business Risk live.
"""

import logging
from typing import Dict, List, Optional

from .models import BusinessNode, BusinessEdge
from .graph import BusinessModelGraph
from .bridge import AegisBridge
from core.data.pressure_graph.manager import PressureGraphManager
from core.data.pressure_graph.models import PressureNode
# removed Observer import

logger = logging.getLogger(__name__)

class AegisManager:
    """
    The Business Logic Governor.
    
    Responsibilities:
    1. Maintain the Business BusinessModelGraph.
    2. Bridge Technical findings to Business Assets.
    3. Calculate and broadcasting Business Risk.
    """
    
    def __init__(self, technical_manager: PressureGraphManager):
        self.tech_manager = technical_manager
        self.graph = BusinessModelGraph()
        self.bridge = AegisBridge()
        self.last_calculated_risk: Dict[str, float] = {}
        
        # Subscribe to technical updates
        self.tech_manager.graph_updated.connect(self._on_technical_update)
            
    def _on_technical_update(self):
        """
        Called when the pressure graph changes.
        Re-evaluates business impact.
        """
        logger.info("[Aegis] Detected Technical Graph update. Recalculating Business Risk...")
        
        # 1. Harvest Technical Nodes
        tech_nodes = self.tech_manager.nodes
        
        # 2. Bridge & Discovery
        # For every technical node, see if it implies a Business Entity logic
        for t_node in tech_nodes.values():
            suggestions = self.bridge.suggest_business_links(t_node)
            for business_node in suggestions:
                # Add node if new (idempotent)
                if business_node.id not in self.graph.nodes:
                    self.graph.add_node(business_node)
                    
                # Create implicit dependency edge (Business depends on Tech)
                # But our graph is Business-to-Business.
                # Do we want to map tech nodes *into* the business graph?
                # Or just use technical pressure as an input vector?
                
                # Design Choice: The Business Graph contains ONLY Business Nodes.
                # Technical Pressure is an *external force* being applied to them.
                pass

        # 3. Calculate Risk
        # Map Tech ID -> Pressure Value
        # But we need Tech ID -> Business ID mapping.
        # The bridge gave us that mapping implicitly via suggestions.
        
        # Let's formalize the mapping for this cycle
        tech_to_business_map: Dict[str, List[str]] = {} # tech_id -> [bus_id]
        
        for t_node in tech_nodes.values():
             suggestions = self.bridge.suggest_business_links(t_node)
             for b_node in suggestions:
                 if t_node.id not in tech_to_business_map:
                     tech_to_business_map[t_node.id] = []
                 tech_to_business_map[t_node.id].append(b_node.id)
                 
        # 4. Aggregate Pressure per Business Node
        business_pressure_input: Dict[str, float] = {}
        
        for t_id, b_ids in tech_to_business_map.items():
            t_node = tech_nodes.get(t_id)
            if not t_node: continue
            
            # Use base_pressure (or current pressure if dynamic)
            # Assuming base_pressure for now
            pressure = t_node.base_pressure 
            
            for b_id in b_ids:
                # Sum pressure? Max?
                business_pressure_input[b_id] = business_pressure_input.get(b_id, 0.0) + pressure
                
        # 5. Run Graph Propagation
        final_risk = self.graph.calculate_total_risk(business_pressure_input)
        self.last_calculated_risk = final_risk
        
        # 6. Report
        top_risks = sorted(final_risk.items(), key=lambda x: x[1], reverse=True)[:5]
        for bid, risk in top_risks:
            node = self.graph.nodes.get(bid)
            if node and risk > 1.0:
                logger.warning(f"[Aegis] CRITICAL BUSINESS RISK: {node.name} (Score: {risk:.2f})")
