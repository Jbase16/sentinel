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
