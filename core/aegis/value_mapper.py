from typing import Dict, Optional, Tuple
from core.aegis.graph import BusinessModelGraph

class ValueMapper:
    """
    The Financial Logic Engine.
    Assigns monetary/severity scores to technical assets based on the Business Graph.
    """
    
    def __init__(self, graph: BusinessModelGraph):
        self.graph = graph

    def calculate_financial_severity(self, endpoint: str, finding_type: str = "Generic") -> Tuple[float, str]:
        """
        Calculate the Financial Severity Score (0.0 - 1.0) and generate a justification.
        
        Args:
            endpoint: The URL or API route (e.g., "/api/v1/billing/update")
            finding_type: The technical bug class (e.g., "SQL Injection", "Info Disclosure")
        
        Returns:
            (score, justification)
        """
        impacted_entities = self.graph.map_endpoint(endpoint)
        
        if not impacted_entities:
            # Fallback: No business context found. standard severity applies.
            return 0.1, "Technical finding with no mapped business asset."

        # Take the highest value entity (Node)
        crown_jewel = impacted_entities[0]
        # Normalize 1-10 scale to 0-1
        base_score = crown_jewel.value / 10.0

        # Contextual Multipliers
        # (A logic flaw in a billing endpoint is worse than a typo)
        multiplier = 1.0
        if "SQL" in finding_type or "RCE" in finding_type:
            multiplier = 1.0 # Full impact
        elif "XSS" in finding_type:
            multiplier = 0.7 # User impact, secondary to data
        elif "Info" in finding_type:
             multiplier = 0.5
        
        final_score = min(base_score * multiplier, 1.0)
        
        justification = (
            f"Finding affects '{crown_jewel.name}' (Value: {crown_jewel.value}). "
            f"Business Impact: High risk to {crown_jewel.description or 'core revenue/operations'}."
        )
        
        return final_score, justification
