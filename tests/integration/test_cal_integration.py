
import pytest
from unittest.mock import MagicMock
from core.scheduler.laws import Constitution
from core.cal.parser import Law, Action

def test_cal_integration_loading():
    # Ensure it loads the laws we defined in step 3192
    c = Constitution.instance()
    # It might fail if run from different cwd, so let's force re-load if needed or check count
    # Default path is assets/laws/constitution.cal
    
    # If the file exists, we expect laws.
    if not c.laws:
        # Try loading explicitly with absolute path if CWD issues in test env
        import os
        base = os.getcwd()
        c._load_laws("assets/laws/constitution.cal")
        
    assert len(c.laws) >= 3
    names = [l.name for l in c.laws]
    assert "PassiveBeforeActive" in names

def test_cal_integration_enforcement():
    c = Constitution.instance()
    
    # Mock Context: Phase 0 (Passive)
    context = MagicMock()
    context.phase_index = 0
    context.active_tools = 0
    context.max_concurrent = 5
    context.knowledge.tags = []
    
    # 1. Test Law1: PassiveBeforeActive (Should Block Phase 2 Tool)
    tool_aggressive = {"phase": 2, "gates": [], "resource_cost": 1}
    decision = c.check(context, tool_aggressive)
    assert decision.allowed is False
    assert "Passive Mode Violation" in decision.reason
    assert decision.blocking_law == "PassiveBeforeActive"
    
    # 2. Test Law1: Allow Phase 1 Tool
    tool_passive = {"phase": 1, "gates": [], "resource_cost": 1}
    decision = c.check(context, tool_passive)
    assert decision.allowed is True

    # 3. Test Law ResourceAwareness
    context.active_tools = 5
    decision = c.check(context, tool_passive)
    assert decision.allowed is False
    assert "System load too high" in decision.reason

