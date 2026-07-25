"""Module policy: inline documentation for /Users/jason/Developer/sentinelforge/core/cortex/policy.py."""
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

from __future__ import annotations

from abc import ABC, abstractmethod
from enum import Enum
from dataclasses import dataclass
from typing import Dict, Any, Optional

from core.scheduler.decisions import DecisionPoint

class Verdict(str, Enum):
    """Class Verdict."""
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
        """Function name."""
        return "ScopePolicy"

    @property
    def priority(self) -> int:
        """Priority for evaluation order (0-100, higher = first)."""
        return 60  # Higher than default (50) - scope checks are important

    def evaluate(self, decision: DecisionPoint, context: Dict[str, Any]) -> Judgment:
        # If decision proposes a tool targeting a host, check if it's in scope.
        # This is a stub logic - normally we'd check decision.context['target'] vs global scope.
        # For now, we assume if "target" is in context, it must be safe or explicitly allowed.
        # Real implementation would check `self.scope_manager.is_allowed(target)`.
        
        """Function evaluate."""
        target = decision.context.get("target") or context.get("target")
        # Conditional branch.
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
        """Function name."""
        return "RiskPolicy"

    @property
    def priority(self) -> int:
        """Priority for evaluation order (0-100, higher = first)."""
        return 55  # Slightly above default - risk checks are important

    def evaluate(self, decision: DecisionPoint, context: Dict[str, Any]) -> Judgment:
        # Example: If Mode is PASSIVE, block ACTIVE tools.
        # This duplicates some reasoning in Strategos, but as a hard safety net.

        """Function evaluate."""
        mode = context.get("mode", "standard")
        tool_risk = decision.context.get("risk", "low") # Assumes tool definition provides risk

        # Conditional branch.
        if mode == "passive" and tool_risk in ["high", "critical"]:
             return Judgment(Verdict.VETO, self.name, "High risk tool blocked in PASSIVE mode.")

        return Judgment(Verdict.APPROVE, self.name, "Risk Level Acceptable")

class CALCompiledPolicy(Policy):
    """
    Wraps a CAL Law into a Policy for ArbitrationEngine.

    This bridges the CAL DSL (declarative When/Then rules) with the
    Python Policy protocol (imperative evaluate() method).

    Example CAL:
        Law PassiveBeforeActive {
            Priority: 80
            Claim: "Aggressive tools are forbidden during passive phase"
            When: context.phase_index < 2
            And:  tool.phase >= 2
            Then: DENY "Passive Mode Violation"
        }
    """
    def __init__(self, law: 'Law'):
        """
        Args:
            law: A parsed CAL Law object from core.cal.parser
        """
        from core.cal.parser import Law, Action

        self._law: Law = law
        self._action: Action = law.action
        self._priority: int = law.priority

    @property
    def name(self) -> str:
        """Returns the law name as policy identifier."""
        return f"CAL:{self._law.name}"

    @property
    def priority(self) -> int:
        """Returns the policy priority (0-100, higher = evaluated first)."""
        return self._priority

    def evaluate(self, decision: DecisionPoint, context: Dict[str, Any]) -> Judgment:
        """
        Evaluates the CAL law's conditions against the decision context.

        Translation logic:
        - All conditions must pass (AND logic)
        - If all pass and action is DENY → VETO
        - If all pass and action is ALLOW → APPROVE
        - If conditions fail → APPROVE (law doesn't apply)
        """
        # Extract tool definition from decision context
        # Strategos stores tool info in decision.context['tool'] or passes via evaluate context
        tool_def = decision.context.get("tool") or context.get("tool") or {}

        # Build evaluation context (matches CAL parser expectations)
        # Wrap in _ContextWrapper to support dot notation (context.phase_index)
        eval_context = _ContextWrapper({
            "phase_index": context.get("phase_index", 0),
            "knowledge": context.get("knowledge", {}),
            "active_tools": context.get("active_tools", 0),
            "max_concurrent": context.get("max_concurrent", 10),
            # Include any other context fields
            **context
        })

        # Evaluate all conditions (AND logic)
        all_conditions_met = True
        for condition in self._law.conditions:
            try:
                if not condition.evaluate(eval_context, tool_def):
                    all_conditions_met = False
                    break
            except Exception as e:
                # Fail closed: if evaluation crashes, treat as condition not met
                # Log the error but don't crash the entire policy engine
                import logging
                logger = logging.getLogger(__name__)
                logger.error(f"[CAL] Condition evaluation failed for {self.name}: {e}")
                all_conditions_met = False
                break

        # If conditions don't apply, law doesn't trigger (approve by default)
        if not all_conditions_met:
            return Judgment(
                verdict=Verdict.APPROVE,
                policy_name=self.name,
                reason=f"Law {self._law.name} does not apply"
            )

        # Conditions passed - execute the action
        if self._action:
            reason = self._format_reason(self._action.reason_template, eval_context, tool_def)

            if self._action.verb == "DENY":
                return Judgment(
                    verdict=Verdict.VETO,
                    policy_name=self.name,
                    reason=reason
                )
            elif self._action.verb == "ALLOW":
                return Judgment(
                    verdict=Verdict.APPROVE,
                    policy_name=self.name,
                    reason=reason
                )
            elif self._action.verb == "MODIFY":
                # MODIFY verdict can suggest changes without blocking
                # Extract modification hints from the reason (format: "key=value")
                modifications = self._parse_modifications(reason)
                return Judgment(
                    verdict=Verdict.MODIFY,
                    policy_name=self.name,
                    reason=reason,
                    modifications=modifications
                )

        # No action or unknown verb - default to approve
        return Judgment(
            verdict=Verdict.APPROVE,
            policy_name=self.name,
            reason=f"Law {self._law.name} has no action"
        )

    def _format_reason(self, template: str, context: Any, tool: Dict) -> str:
        """
        Simple template formatter for reason strings.
        Supports {context.field} and {tool.field} syntax.
        """
        result = template

        # Replace context placeholders
        try:
            import re
            # Find all {context.field} patterns
            for match in re.finditer(r'\{context\.(\w+)\}', template):
                field = match.group(1)
                value = getattr(context, field, context._data.get(field, "?")) if hasattr(context, '_data') else "?"
                result = result.replace(match.group(0), str(value))

            # Find all {tool.field} patterns
            for match in re.finditer(r'\{tool\.(\w+)\}', template):
                field = match.group(1)
                value = tool.get(field, "?")
                result = result.replace(match.group(0), str(value))
        except Exception:
            # If formatting fails, return template as-is
            pass

        return result

    def _parse_modifications(self, reason: str) -> Dict[str, Any]:
        """
        Parse modification hints from reason string.

        Expected format: "Add rate_limit=10 and timeout=30"
        Extracts: {"rate_limit": "10", "timeout": "30"}

        Args:
            reason: The reason string potentially containing modifications

        Returns:
            Dictionary of key=value pairs found in reason
        """
        modifications = {}
        try:
            import re
            # Find all key=value patterns
            pattern = r'(\w+)=([^\s,]+)'
            matches = re.findall(pattern, reason)
            for key, value in matches:
                # Try to convert to int/float if possible
                try:
                    if '.' in value:
                        modifications[key] = float(value)
                    else:
                        modifications[key] = int(value)
                except ValueError:
                    # Keep as string if not a number
                    modifications[key] = value
        except Exception:
            # If parsing fails, return empty dict
            pass

        return modifications

class _ContextWrapper:
    """
    Helper to allow dot notation for dict access in CAL conditions.
    Matches the _DictWrapper pattern used in CAL parser.
    """
    def __init__(self, data: Dict[str, Any]):
        self._data = data

    def __getattr__(self, item: str):
        val = self._data.get(item)
        if isinstance(val, dict):
            return _ContextWrapper(val)
        return val
