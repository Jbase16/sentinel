# ============================================================================
# tests/unit/test_narrative_templates.py
# Verification of Layer 3 Phase 2: Narrative Templates
# ============================================================================

import pytest
from core.scheduler.decisions import DecisionPoint, DecisionType
from core.cortex.narrative_templates import (
    PhaseTemplate,
    IntentTemplate,
    ToolSelectionTemplate,
    ToolRejectionTemplate,
    ModeAdaptationTemplate
)

def test_tool_selection_with_target():
    tmpl = ToolSelectionTemplate()
    d = DecisionPoint.create(
        DecisionType.TOOL_SELECTION,
        "nmap",
        "Port scan",
        context={"target": "10.0.0.1"}
    )
    msg = tmpl.render(d)
    assert "Deploying 1 tools: [nmap] against 10.0.0.1" in msg

def test_tool_rejection_with_blocker():
    tmpl = ToolRejectionTemplate()
    d = DecisionPoint.create(
        DecisionType.TOOL_REJECTION,
        "exploit_db",
        "Too risky",
        context={"tool": "exploit_db", "blocker": "BugBountyRules"}
    )
    msg = tmpl.render(d)
    assert "DEFENSE: Blocked exploit_db by BugBountyRules" in msg

def test_grouped_tool_rejection():
    tmpl = ToolRejectionTemplate()
    d = DecisionPoint.create(
        DecisionType.TOOL_REJECTION,
        "BLOCKED",
        "Mode Overlay",
        context={"tools": ["masscan", "zmap"], "count": 2}
    )
    msg = tmpl.render(d)
    assert "DEFENSE: Blocked 2 tools [masscan, zmap] by Mode Overlay" in msg

def test_mode_adaptation():
    tmpl = ModeAdaptationTemplate()
    d = DecisionPoint.create(
        DecisionType.MODE_ADAPTATION,
        "reduce_concurrency",
        "Stealth mode requires slow scan"
    )
    msg = tmpl.render(d)
    assert "ADAPTATION: Stealth mode requires slow scan" in msg

def test_template_matching():
    d = DecisionPoint.create(DecisionType.PHASE_TRANSITION, "PHASE_1", "Testing")
    
    assert PhaseTemplate().matches(d.type) is True
    assert IntentTemplate().matches(d.type) is False
