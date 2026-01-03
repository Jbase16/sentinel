"""
Test CAL Policy Integration with ArbitrationEngine

Verifies that CAL laws are correctly compiled and enforced
through the unified policy arbitration system.
"""

import pytest
from core.cortex.arbitration import ArbitrationEngine
from core.cortex.policy import Verdict
from core.scheduler.decisions import DecisionPoint, DecisionType


def test_cal_policy_loading():
    """Test that CAL policies can be loaded from string."""
    engine = ArbitrationEngine()

    cal_source = """
    Law TestRule {
        Claim: "Block forbidden target"
        When: context.target == "forbidden.example.com"
        Then: DENY "Target is explicitly forbidden"
    }
    """

    policies = engine.load_cal_policy(cal_source)

    assert len(policies) == 1
    assert policies[0].name == "CAL:TestRule"
    assert "CAL:TestRule" in engine.list_policies()


def test_cal_policy_enforcement_veto():
    """Test that CAL DENY rules result in VETO verdicts."""
    engine = ArbitrationEngine()

    cal_source = """
    Law BlockProduction {
        Claim: "Production scans require approval"
        When: context.target == "prod.example.com"
        Then: DENY "Production scans are forbidden"
    }
    """

    engine.load_cal_policy(cal_source)

    # Create a decision targeting production
    decision = DecisionPoint.create(
        DecisionType.TOOL_SELECTION,
        chosen="nmap",
        reason="Test scan",
        context={"target": "prod.example.com"}
    )

    context = {"target": "prod.example.com"}
    judgment = engine.review(decision, context)

    assert judgment.verdict == Verdict.VETO
    assert "Production scans are forbidden" in judgment.reason


def test_cal_policy_enforcement_approve():
    """Test that CAL rules approve when conditions don't match."""
    engine = ArbitrationEngine()

    cal_source = """
    Law BlockProduction {
        Claim: "Production scans require approval"
        When: context.target == "prod.example.com"
        Then: DENY "Production scans are forbidden"
    }
    """

    engine.load_cal_policy(cal_source)

    # Create a decision targeting non-production
    decision = DecisionPoint.create(
        DecisionType.TOOL_SELECTION,
        chosen="nmap",
        reason="Test scan",
        context={"target": "test.example.com"}
    )

    context = {"target": "test.example.com"}
    judgment = engine.review(decision, context)

    # Should approve because condition doesn't match
    assert judgment.verdict == Verdict.APPROVE


def test_cal_phase_enforcement():
    """Test that phase-based CAL rules work correctly."""
    engine = ArbitrationEngine()

    cal_source = """
    Law PassiveBeforeActive {
        Claim: "Aggressive tools forbidden in passive phase"
        When: context.phase_index < 2
        And:  tool.phase >= 2
        Then: DENY "Passive phase violation"
    }
    """

    engine.load_cal_policy(cal_source)

    # Try to use phase 2 tool in phase 0
    tool_def = {"phase": 2, "name": "httpx"}
    decision = DecisionPoint.create(
        DecisionType.TOOL_SELECTION,
        chosen="httpx",
        reason="Test scan",
        context={"tool": tool_def}
    )

    context = {
        "phase_index": 0,  # Passive phase
        "tool": tool_def
    }

    judgment = engine.review(decision, context)

    assert judgment.verdict == Verdict.VETO
    assert "Passive phase violation" in judgment.reason


def test_multiple_cal_policies():
    """Test that multiple CAL policies can coexist."""
    engine = ArbitrationEngine()

    cal_source = """
    Law BlockProduction {
        When: context.target == "prod.example.com"
        Then: DENY "Production blocked"
    }

    Law RequireAuth {
        When: context.mode == "aggressive"
        Then: DENY "Aggressive mode requires auth"
    }
    """

    policies = engine.load_cal_policy(cal_source)

    assert len(policies) == 2
    assert "CAL:BlockProduction" in engine.list_policies()
    assert "CAL:RequireAuth" in engine.list_policies()


def test_cal_with_python_policies():
    """Test that CAL and Python policies work together."""
    from core.cortex.policy import ScopePolicy

    engine = ArbitrationEngine()

    # Register Python policy
    engine.register_policy(ScopePolicy())

    # Load CAL policy
    cal_source = """
    Law BlockTest {
        When: context.target == "test.forbidden.com"
        Then: DENY "Test blocked by CAL"
    }
    """
    engine.load_cal_policy(cal_source)

    # Both policies should be registered
    policies = engine.list_policies()
    assert "ScopePolicy" in policies
    assert "CAL:BlockTest" in policies
    assert len(policies) == 2


def test_constitution_file_loading():
    """Test loading actual constitution.cal file."""
    engine = ArbitrationEngine()

    # Load the real constitution
    policies = engine.load_cal_file("assets/laws/constitution.cal")

    # Should have loaded PassiveBeforeActive, EvidenceGates, ResourceAwareness
    assert len(policies) >= 3

    policy_names = engine.list_policies()
    assert "CAL:PassiveBeforeActive" in policy_names
    assert "CAL:EvidenceGates" in policy_names
    assert "CAL:ResourceAwareness" in policy_names


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
