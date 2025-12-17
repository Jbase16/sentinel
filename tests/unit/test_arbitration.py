"""Module test_arbitration: inline documentation for /Users/jason/Developer/sentinelforge/tests/unit/test_arbitration.py."""
import pytest
from typing import Dict, Any

from core.cortex.policy import Policy, Judgment, Verdict
from core.cortex.arbitration import ArbitrationEngine
from core.scheduler.decisions import DecisionPoint, DecisionType

class StrictPolicy(Policy):
    """Class StrictPolicy."""
    name = "StrictPolicy"
    def evaluate(self, decision: DecisionPoint, context: Dict[str, Any]) -> Judgment:
        """Function evaluate."""
        if decision.chosen == "UNSAFE_ACTION":
            return Judgment(Verdict.VETO, self.name, "Unsafe action detected")
        return Judgment(Verdict.APPROVE, self.name, "Looks good")

class LoosePolicy(Policy):
    """Class LoosePolicy."""
    name = "LoosePolicy"
    def evaluate(self, decision: DecisionPoint, context: Dict[str, Any]) -> Judgment:
        # Always approves
        """Function evaluate."""
        return Judgment(Verdict.APPROVE, self.name, "Whatever man")

class CrashingPolicy(Policy):
    """Class CrashingPolicy."""
    name = "CrashingPolicy"
    def evaluate(self, decision: DecisionPoint, context: Dict[str, Any]) -> Judgment:
        """Function evaluate."""
        raise ValueError("Boom")

def test_arbitration_approval():
    """Function test_arbitration_approval."""
    engine = ArbitrationEngine()
    engine.register_policy(StrictPolicy())
    engine.register_policy(LoosePolicy())
    
    # Safe decision
    dp = DecisionPoint.create(DecisionType.TOOL_SELECTION, "SAFE_ACTION", "Testing")
    judgment = engine.review(dp, {})
    
    assert judgment.verdict == Verdict.APPROVE
    assert "Consensus" in judgment.reason

def test_arbitration_veto():
    """Function test_arbitration_veto."""
    engine = ArbitrationEngine()
    engine.register_policy(StrictPolicy())
    engine.register_policy(LoosePolicy())
    
    # Unsafe decision -> StrictPolicy VETOs
    dp = DecisionPoint.create(DecisionType.TOOL_SELECTION, "UNSAFE_ACTION", "Testing")
    judgment = engine.review(dp, {})
    
    assert judgment.verdict == Verdict.VETO
    assert "StrictPolicy" in judgment.reason
    assert "Unsafe action detected" in judgment.reason

def test_arbitration_fail_closed():
    """Function test_arbitration_fail_closed."""
    engine = ArbitrationEngine()
    engine.register_policy(LoosePolicy())
    engine.register_policy(CrashingPolicy()) # This guy crashes
    
    dp = DecisionPoint.create(DecisionType.TOOL_SELECTION, "ANY_ACTION", "Testing")
    judgment = engine.review(dp, {})
    
    # Must fail closed
    assert judgment.verdict == Verdict.VETO
    assert "CrashingPolicy" in judgment.reason
    assert "Boom" in judgment.reason
