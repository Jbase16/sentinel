"""
core/sentient/models.py

Purpose:
    Defines the data structures for the Sentient Governor (Pillar II).
    These models capture the decision logic: "Should this test run right now?"

Semantics:
    - Verdict: The final decision (APPROVE/REJECT/DEFER).
    - Constraint: A hard rule that must pass (Ethical Gate).
    - EconomicFactor: Inputs for ROI calculation (Economic Gate).
    - SentientDecision: The auditable result of a governance check.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Protocol, runtime_checkable

@runtime_checkable
class Constraint(Protocol):
    """
    A hard ethical or operational rule.
    """
    name: str

    def check(self, context: Dict[str, Any]) -> bool:
        """
        Returns True if the constraint is satisfied (SAFE to proceed).
        Returns False if the constraint is violated (UNSAFE / BLOCK).
        """
        ...


class Verdict(str, Enum):
    APPROVE = "APPROVE"  # Safe, valuable, and timely. Proceed.
    REJECT = "REJECT"    # Unsafe, unethical, or negative ROI. Drop it.
    DEFER = "DEFER"      # Safe/valuable, but wrong time (e.g. out of window). Retry later.


@dataclass(frozen=True)
class EconomicFactor:
    """
    Inputs for the ROI calculation.
    ROI = (probability_breakage * asset_value) - (execution_cost + risk_penalty)
    """
    scan_cost_credits: float        # CPU/Network cost estimate
    risk_penalty: float             # Penalty for high-risk mutations (e.g. 10x for data deletion)
    discovery_value: float          # Potential value of finding a bug here (linked to Aegis Node Value)
    breach_probability: float       # Likelihood estimate (0.0 - 1.0)


@dataclass(frozen=True)
class SentientDecision:
    """
    The Governor's Decree.
    This object serves as the audit trail for WHY a test was allowed or blocked.
    """
    verdict: Verdict
    rationale: str
    constraints_checked: List[str] = field(default_factory=list)
    constraints_failed: List[str] = field(default_factory=list)
    roi_score: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "verdict": self.verdict.value,
            "rationale": self.rationale,
            "constraints_checked": self.constraints_checked,
            "constraints_failed": self.constraints_failed,
            "roi_score": self.roi_score,
        }
