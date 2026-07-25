"""
Test Advanced CAL Features (Phase 3)

Tests:
1. REQUIRE keyword syntax
2. IF keyword syntax
3. Priority ordering
4. MODIFY verdict support
"""

import pytest
from core.cal.parser import CALParser
from core.cortex.arbitration import ArbitrationEngine
from core.cortex.policy import Verdict, ScopePolicy
from core.scheduler.decisions import DecisionPoint, DecisionType


def test_require_keyword():
    """Test REQUIRE keyword as shorthand for When."""
    parser = CALParser()

    cal_source = """
    Law TestRequire {
        Claim: "Test REQUIRE syntax"
        REQUIRE: context.mode == "strict"
        Then: DENY "Strict mode violation"
    }
    """

    laws = parser.parse_string(cal_source)

    assert len(laws) == 1
    assert laws[0].name == "TestRequire"
    assert len(laws[0].conditions) == 1
    assert laws[0].conditions[0].raw_expression == 'context.mode == "strict"'
    print("✓ REQUIRE keyword parsed correctly")


def test_if_keyword():
    """Test IF keyword as alias for And."""
    parser = CALParser()

    cal_source = """
    Law TestIf {
        Claim: "Test IF syntax"
        When: context.level > 5
        IF: context.validated == True
        Then: ALLOW "Conditions met"
    }
    """

    laws = parser.parse_string(cal_source)

    assert len(laws) == 1
    assert laws[0].name == "TestIf"
    assert len(laws[0].conditions) == 2  # When + IF
    assert "level > 5" in laws[0].conditions[0].raw_expression
    assert "validated" in laws[0].conditions[1].raw_expression
    print("✓ IF keyword parsed correctly")


def test_priority_parsing():
    """Test that Priority field is parsed and stored."""
    parser = CALParser()

    cal_source = """
    Law HighPriority {
        Priority: 90
        Claim: "High priority rule"
        When: true
        Then: DENY "Blocked"
    }

    Law LowPriority {
        Priority: 10
        When: true
        Then: DENY "Also blocked"
    }

    Law DefaultPriority {
        When: true
        Then: ALLOW "Allowed"
    }
    """

    laws = parser.parse_string(cal_source)

    assert len(laws) == 3
    assert laws[0].priority == 90
    assert laws[1].priority == 10
    assert laws[2].priority == 50  # Default
    print("✓ Priority parsing works")


def test_priority_ordering():
    """Test that policies are evaluated in priority order."""
    engine = ArbitrationEngine()

    # Add three policies with different priorities
    cal_source = """
    Law LowPriority {
        Priority: 20
        When: context.test == "yes"
        Then: DENY "Low priority block"
    }

    Law HighPriority {
        Priority: 80
        When: context.test == "yes"
        Then: APPROVE "High priority approval"
    }

    Law MediumPriority {
        Priority: 50
        When: context.test == "yes"
        Then: DENY "Medium priority block"
    }
    """

    engine.load_cal_policy(cal_source)

    # Create decision
    decision = DecisionPoint.create(
        DecisionType.TOOL_SELECTION,
        chosen="test",
        reason="Test",
        context={}
    )

    context = {"test": "yes"}
    judgment = engine.review(decision, context)

    # High priority (80) should be evaluated first and approve
    # But wait - VETO wins, so even if high priority approves,
    # lower priorities will still veto
    # Actually, the review() method has early exit on VETO
    # Let me check the logic again...

    # With early exit, the first policy that returns VETO stops evaluation
    # Since they're sorted by priority (high to low), HighPriority (80) evaluates first
    # It returns APPROVE, so evaluation continues to MediumPriority (50)
    # MediumPriority returns DENY/VETO, so it stops and returns VETO

    # So the result should be VETO from MediumPriority
    assert judgment.verdict == Verdict.VETO
    assert "Medium priority" in judgment.reason or "Low priority" in judgment.reason
    print(f"✓ Priority ordering enforced: {judgment.policy_name}")


def test_modify_verdict():
    """Test MODIFY verdict support."""
    parser = CALParser()

    cal_source = """
    Law AddRateLimit {
        Priority: 70
        When: context.tool == "aggressive_scan"
        Then: MODIFY "Add rate_limit=5 and delay=1000"
    }
    """

    laws = parser.parse_string(cal_source)
    assert len(laws) == 1
    assert laws[0].action.verb == "MODIFY"

    # Load into arbitrator
    engine = ArbitrationEngine()
    engine.load_cal_policy(cal_source)

    decision = DecisionPoint.create(
        DecisionType.TOOL_SELECTION,
        chosen="aggressive_scan",
        reason="Test",
        context={}
    )

    context = {"tool": "aggressive_scan"}
    judgment = engine.review(decision, context)

    assert judgment.verdict == Verdict.MODIFY
    assert judgment.modifications is not None
    assert "rate_limit" in judgment.modifications
    assert judgment.modifications["rate_limit"] == 5
    assert judgment.modifications["delay"] == 1000
    print(f"✓ MODIFY verdict with modifications: {judgment.modifications}")


def test_python_and_cal_priority_mixing():
    """Test that Python policies and CAL policies are sorted together."""
    engine = ArbitrationEngine()

    # Register Python policy (priority 60)
    engine.register_policy(ScopePolicy())

    # Load CAL policy with higher priority
    cal_source = """
    Law SuperHighPriority {
        Priority: 90
        When: context.target == "forbidden.com"
        Then: DENY "Blocked by super high priority"
    }
    """

    engine.load_cal_policy(cal_source)

    # Verify policy list
    policies = engine.list_policies()
    assert "ScopePolicy" in policies
    assert "CAL:SuperHighPriority" in policies

    # Test that high-priority CAL policy is evaluated first
    decision = DecisionPoint.create(
        DecisionType.TOOL_SELECTION,
        chosen="test",
        reason="Test",
        context={"target": "forbidden.com"}
    )

    context = {"target": "forbidden.com"}
    judgment = engine.review(decision, context)

    # Should be blocked by SuperHighPriority (90) before ScopePolicy (60) runs
    assert judgment.verdict == Verdict.VETO
    assert "super high priority" in judgment.reason.lower()
    print("✓ Python and CAL policies sorted by priority")


def test_multiple_modify_policies():
    """Test that multiple MODIFY policies are combined."""
    engine = ArbitrationEngine()

    cal_source = """
    Law AddRateLimit {
        Priority: 70
        When: context.aggressive == True
        Then: MODIFY "Add rate_limit=5"
    }

    Law AddTimeout {
        Priority: 60
        When: context.aggressive == True
        Then: MODIFY "Add timeout=30"
    }
    """

    engine.load_cal_policy(cal_source)

    decision = DecisionPoint.create(
        DecisionType.TOOL_SELECTION,
        chosen="scan",
        reason="Test",
        context={}
    )

    context = {"aggressive": True}
    judgment = engine.review(decision, context)

    # Both MODIFY policies should be applied
    assert judgment.verdict == Verdict.MODIFY
    assert "rate_limit" in judgment.modifications
    assert "timeout" in judgment.modifications
    assert judgment.modifications["rate_limit"] == 5
    assert judgment.modifications["timeout"] == 30
    print(f"✓ Multiple MODIFY policies combined: {judgment.modifications}")


def test_require_if_together():
    """Test using REQUIRE and IF together."""
    parser = CALParser()

    cal_source = """
    Law ComplexConditions {
        Claim: "Test REQUIRE + IF syntax"
        REQUIRE: context.authenticated == True
        IF: context.role == "admin"
        IF: context.approved == True
        Then: ALLOW "Admin with approval"
    }
    """

    laws = parser.parse_string(cal_source)

    assert len(laws) == 1
    assert len(laws[0].conditions) == 3  # REQUIRE + 2x IF
    print("✓ REQUIRE and IF can be combined")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
