"""
core/sentient/economics.py

Purpose:
    The "Id/Ego" mediator. Calculates the "Profitability" of a test execution.
    Prioritizes actions that yield high information value at low cost/risk.
"""

from __future__ import annotations
from .models import EconomicFactor


class EconomicEngine:
    """
    Calculates Test Return on Investment (ROI).
    """
    
    def compute_roi(self, factor: EconomicFactor) -> float:
        """
        ROI Formula:
        Expected Value = (Probability * Value)
        Total Cost = (Execution Cost + Risk Penalty)
        ROI = Expected Value - Total Cost
        
        Example:
        - Prob(Breach) = 0.1
        - Value = 1000 (Credits)
        - Cost = 1
        - Risk = 10 (Chance of crashing prod)
        
        ROI = (0.1 * 1000) - (1 + 10) = 100 - 11 = 89.0 (Positive -> Approve)
        """
        expected_value = factor.breach_probability * factor.discovery_value
        total_cost = factor.scan_cost_credits + factor.risk_penalty
        
        return expected_value - total_cost

    def estimate_factors(self, target_value: float, risk_level: float) -> EconomicFactor:
        """
        Heuristic generator for factors based on inputs.
        
        Args:
            target_value: From Aegis (1.0 - 10.0). We scale this to 'Credits'.
            risk_level: 0.0 (Safe) - 1.0 (Dangerous).
        """
        # Scale Aegis value (1-10) to Economic Credits (100 - 10,000)
        # Logarithmic or Exponential scale usually better, using linear * 1000 for simplicity now.
        discovery_val = target_value * 1000.0
        
        # Base cost of running a request
        base_cost = 1.0
        
        # Risk penalty scales heavily with risk level
        # Risk 0.1 -> Penalty ~125
        # Risk 0.9 -> Penalty ~8000
        # This ensures that even high-value targets require very safe mutations.
        penalty = 100.0 * (10.0 ** risk_level) if risk_level > 0 else 0.0
        
        # Probability is currently a guess; usually derived from Thanatos confidence?
        # For now, assume a baseline 10% effectiveness of generated hypotheses.
        prob = 0.10 

        return EconomicFactor(
            scan_cost_credits=base_cost,
            risk_penalty=penalty,
            discovery_value=discovery_val,
            breach_probability=prob
        )
