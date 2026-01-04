"""
core/sentient/service.py

Purpose:
    The Public API of Pillar II.
    External components (like Thanatos Manager) call this to get permission to run a test.
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Dict

from .models import SentientDecision, Verdict
from .ethics import EthicalGuard
from .economics import EconomicEngine

@dataclass
class SentientService:
    ethics: EthicalGuard
    economics: EconomicEngine

    def decide(self, target_context: Dict[str, Any], risk_level: float = 0.5) -> SentientDecision:
        """
        Evaluate a proposed action against ethical and economic rules.
        
        Args:
            target_context: Dict containing 'target_value' (1.0-10.0) and other metadata.
            risk_level: Estimated risk of the action (0.0 - 1.0).
            
        Returns:
            SentientDecision with Verdict (APPROVE/REJECT/DEFER).
        """
        # 1. Ethical Guard (Hard Gate)
        failed_constraints = self.ethics.evaluate(target_context)
        checked_constraints = [c.name for c in self.ethics.constraints]
        
        if failed_constraints:
            # Check if we should DEFER or REJECT based on the constraint type
            # For now, TimeWindow implies DEFER, but simpler to just REJECT/DEFER broadly.
            # Let's say if ANY failed, we DEFER/REJECT.
            
            # Simple logic: If it's a TimeWindow failure, DEFER. Else REJECT.
            verdict = Verdict.REJECT
            if "TimeWindow" in failed_constraints and len(failed_constraints) == 1:
                verdict = Verdict.DEFER
            
            return SentientDecision(
                verdict=verdict,
                rationale=f"Blocked by ethical constraints: {', '.join(failed_constraints)}",
                constraints_checked=checked_constraints,
                constraints_failed=failed_constraints,
                roi_score=0.0
            )

        # 2. Economic Engine (Soft Gate)
        target_value = target_context.get("target_value", 0.0)
        factors = self.economics.estimate_factors(target_value, risk_level)
        roi = self.economics.compute_roi(factors)
        
        if roi > 0:
            return SentientDecision(
                verdict=Verdict.APPROVE,
                rationale=f"Positive ROI ({roi:.2f}) on value {target_value} vs risk {risk_level}",
                constraints_checked=checked_constraints,
                roi_score=roi
            )
        else:
            return SentientDecision(
                verdict=Verdict.REJECT,
                rationale=f"Negative ROI ({roi:.2f}). Risk implies cost exceeds value.",
                constraints_checked=checked_constraints,
                roi_score=roi
            )
