"""Typed policy contracts for decision arbitration."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Optional

from core.scheduler.decisions import DecisionPoint


class Verdict(str, Enum):
    """The result of reviewing a proposed decision."""

    APPROVE = "approve"
    VETO = "veto"
    MODIFY = "modify"


@dataclass
class Judgment:
    """The output of a policy evaluation."""

    verdict: Verdict
    policy_name: str
    reason: str
    modifications: Optional[Dict[str, Any]] = None


class Policy(ABC):
    """Protocol for typed decision-review policies."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Return the unique policy identifier."""

    @abstractmethod
    def evaluate(self, decision: DecisionPoint, context: Dict[str, Any]) -> Judgment:
        """Judge a proposed decision without granting execution authority."""


class ScopePolicy(Policy):
    """Reject explicitly forbidden target names before proposal admission."""

    @property
    def name(self) -> str:
        return "ScopePolicy"

    @property
    def priority(self) -> int:
        return 60

    def evaluate(self, decision: DecisionPoint, context: Dict[str, Any]) -> Judgment:
        target = decision.context.get("target") or context.get("target")
        if target and "forbidden.com" in target:
            return Judgment(
                Verdict.VETO,
                self.name,
                f"Target {target} is explicitly forbidden.",
            )
        return Judgment(Verdict.APPROVE, self.name, "Scope OK")


class RiskPolicy(Policy):
    """Reject high-risk tool proposals in passive mode."""

    @property
    def name(self) -> str:
        return "RiskPolicy"

    @property
    def priority(self) -> int:
        return 55

    def evaluate(self, decision: DecisionPoint, context: Dict[str, Any]) -> Judgment:
        mode = context.get("mode", "standard")
        tool_risk = decision.context.get("risk", "low")
        if mode == "passive" and tool_risk in ["high", "critical"]:
            return Judgment(
                Verdict.VETO,
                self.name,
                "High risk tool blocked in PASSIVE mode.",
            )
        return Judgment(Verdict.APPROVE, self.name, "Risk Level Acceptable")
