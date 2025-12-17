# ============================================================================
# core/cortex/policy.py
# Layer 4: Policy Arbitration (Protocol)
# ============================================================================
#
# PURPOSE:
# Defines the interface for policies that *review* decisions.
# This is NOT the "Brain" that decides what to do.
# This is the "Judge" that decides if a decision is allowed.
#
# VERDICTS:
# - APPROVE: The decision is valid.
# - VETO: The decision violates a rule and must be blocked.
# - MODIFY: The decision is valid IF modified (e.g., "Add rate limit").
#
# ============================================================================

from __future__ import annotations

from abc import ABC, abstractmethod
from enum import Enum
from dataclasses import dataclass
from typing import Dict, Any, Optional

from core.scheduler.decisions import DecisionPoint

class Verdict(str, Enum):
    APPROVE = "approve"
    VETO = "veto"
    MODIFY = "modify"

@dataclass
class Judgment:
    """
    The output of a Policy evaluation.
    """
    verdict: Verdict
    policy_name: str
    reason: str
    modifications: Optional[Dict[str, Any]] = None # Only for MODIFY

class Policy(ABC):
    """
    Protocol for Arbitration Rules.
    """
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Unique identifier for this policy."""
        pass

    @abstractmethod
    def evaluate(self, decision: DecisionPoint, context: Dict[str, Any]) -> Judgment:
        """
        Judge the proposed decision.
        """
        pass

class ScopePolicy(Policy):
    """
    Enforces that all actions target authorized scopes only.
    """
    @property
    def name(self) -> str:
        return "ScopePolicy"
        
    def evaluate(self, decision: DecisionPoint, context: Dict[str, Any]) -> Judgment:
        # If decision proposes a tool targeting a host, check if it's in scope.
        # This is a stub logic - normally we'd check decision.context['target'] vs global scope.
        # For now, we assume if "target" is in context, it must be safe or explicitly allowed.
        # Real implementation would check `self.scope_manager.is_allowed(target)`.
        
        target = decision.context.get("target") or context.get("target")
        if target:
            # Example: Block .edu or .gov if strict rules apply
            if "forbidden.com" in target:
                 return Judgment(Verdict.VETO, self.name, f"Target {target} is explicitly forbidden.")
                 
        return Judgment(Verdict.APPROVE, self.name, "Scope OK")

class RiskPolicy(Policy):
    """
    Enforces risk limits based on current engagement mode.
    """
    @property
    def name(self) -> str:
        return "RiskPolicy"
        
    def evaluate(self, decision: DecisionPoint, context: Dict[str, Any]) -> Judgment:
        # Example: If Mode is PASSIVE, block ACTIVE tools.
        # This duplicates some reasoning in Strategos, but as a hard safety net.
        
        mode = context.get("mode", "standard")
        tool_risk = decision.context.get("risk", "low") # Assumes tool definition provides risk
        
        if mode == "passive" and tool_risk in ["high", "critical"]:
             return Judgment(Verdict.VETO, self.name, f"High risk tool blocked in PASSIVE mode.")
             
        return Judgment(Verdict.APPROVE, self.name, "Risk Level Acceptable")
