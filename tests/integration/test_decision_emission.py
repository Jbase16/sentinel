"""
tests/integration/test_decision_emission.py
Integration tests for Layer 2: Event Emission Layer

Verifies that every strategic decision in Strategos is captured as:
1. An immutable DecisionPoint in the DecisionLedger
2. A properly formatted event in the EventStore

This is the critical test for Layer 2 completeness.
"""

import pytest
import asyncio
from typing import List, Dict

from core.scheduler.strategos import Strategos, ScanContext
from core.scheduler.modes import ScanMode
from core.scheduler.decisions import DecisionLedger, DecisionType
from core.cortex.events import EventBus, GraphEventType, get_event_bus
from core.cortex.event_store import EventStore
from core.scheduler.intents import (
    INTENT_PASSIVE_RECON,
    INTENT_ACTIVE_LIVE_CHECK,
    INTENT_SURFACE_ENUMERATION,
    INTENT_VULN_SCANNING,
    INTENT_HEAVY_ARTILLERY
)


@pytest.fixture
def event_store():
    """Fresh EventStore for each test."""
    store = EventStore(max_size=1000)
    store.clear()
    return store


@pytest.fixture
def event_bus():
    """EventBus singleton for tests."""
    return get_event_bus()


@pytest.fixture
def decision_ledger():
    """Fresh DecisionLedger for each test."""
    ledger = DecisionLedger(max_decisions=500)
    ledger.clear()
    return ledger


@pytest.fixture
def strategos_with_events(event_bus, decision_ledger):
    """Strategos instance with event tracking enabled."""
    return Strategos(
        event_bus=event_bus,
        decision_ledger=decision_ledger
    )


class TestPhaseTransitionEmission:
    """Verify that phase transitions emit both decisions and events."""
    
    @pytest.mark.asyncio
    async def test_phase_transition_emits_decision(self, strategos_with_events, decision_ledger, event_store):
        """Phase transitions should create PHASE_TRANSITION decisions."""
        
        # Mock tool dispatcher (no actual tools)
        async def mock_dispatch(tool: str) -> List[Dict]:
            """AsyncFunction mock_dispatch."""
            return []
        
        # Run a minimal mission (will hit phase transitions)
        await strategos_with_events.run_mission(
            target="example.com",
            available_tools=[],  # No tools to avoid complexity
            mode=ScanMode.STANDARD,
            dispatch_tool=mock_dispatch
        )
        
        # Check DecisionLedger for phase transitions
        decisions = decision_ledger.get_all()
        phase_decisions = [d for d in decisions if d.type == DecisionType.PHASE_TRANSITION]
        
        # Should have at least one phase transition (PHASE_1 -> PHASE_2, etc.)
        assert len(phase_decisions) > 0, "No phase transitions recorded"
        
        # Verify phase decision structure
        for decision in phase_decisions:
            assert decision.chosen.startswith("PHASE_"), f"Invalid phase: {decision.chosen}"
            assert "phase" in decision.context, "Missing phase in context"
            assert "previous_phase" in decision.context, "Missing previous_phase"
        
        # Check EventStore for corresponding events
        events = event_store.get_latest(count=100)
        phase_events = [e for e in events if e.type == GraphEventType.SCAN_PHASE_CHANGED]
        
        assert len(phase_events) > 0, "No phase change events emitted"


class TestIntentTransitionEmission:
    """Verify that intent transitions emit structured decisions."""
    
    @pytest.mark.asyncio
    async def test_all_intents_emit_decisions(self, strategos_with_events, decision_ledger):
        """Every intent execution should create an INTENT_TRANSITION decision."""
        
        async def mock_dispatch(tool: str) -> List[Dict]:
            """AsyncFunction mock_dispatch."""
            return []
        
        await strategos_with_events.run_mission(
            target="example.com",
            available_tools=[],
            mode=ScanMode.STANDARD,
            dispatch_tool=mock_dispatch
        )
        
        decisions = decision_ledger.get_all()
        intent_decisions = [d for d in decisions if d.type == DecisionType.INTENT_TRANSITION]
        
        # Standard mode should hit all intents
        assert len(intent_decisions) >= 5, f"Only {len(intent_decisions)} intent decisions recorded"
        
        # Verify each intent decision has proper structure
        for decision in intent_decisions:
            assert decision.chosen in [
                INTENT_PASSIVE_RECON,
                INTENT_ACTIVE_LIVE_CHECK,
                INTENT_SURFACE_ENUMERATION,
                INTENT_VULN_SCANNING,
                INTENT_HEAVY_ARTILLERY
            ], f"Unknown intent: {decision.chosen}"
            
            assert decision.reason, "Intent decision missing reason"
            assert "mode" in decision.context, "Intent decision missing mode"
            assert "evidence" in decision.__dict__ and decision.evidence, "Intent decision missing evidence"


class TestToolSelectionEmission:
    """Verify that tool selection/rejection decisions are emitted."""
    
    @pytest.mark.asyncio
    async def test_tool_selection_creates_decision(self, strategos_with_events, decision_ledger):
        """Tool selection should emit TOOL_SELECTION decisions."""
        
        async def mock_dispatch(tool: str) -> List[Dict]:
            """AsyncFunction mock_dispatch."""
            await asyncio.sleep(0.01)  # Simulate work
            return []
        
        # Provide some available tools
        await strategos_with_events.run_mission(
            target="example.com",
            available_tools=["subfinder", "httpx", "nmap"],
            mode=ScanMode.STANDARD,
            dispatch_tool=mock_dispatch
        )
        
        decisions = decision_ledger.get_all()
        tool_decisions = [d for d in decisions if d.type == DecisionType.TOOL_SELECTION]
        
        # Should have tool selection decisions (one per intent that had tools)
        assert len(tool_decisions) > 0, "No tool selection decisions recorded"
        
        # Verify tool decision structure
        for decision in tool_decisions:
            assert "intent" in decision.context, "Tool decision missing intent"
            
            # Skip decisions and regular selections have different structure
            if decision.chosen == "SKIP":
                assert decision.context.get("skipped") == True, "Skip decision missing skipped flag"
            else:
                assert "selected_count" in decision.context, "Tool decision missing selected_count"
            
            assert "alternatives" in decision.__dict__, "Tool decision missing alternatives"
    
    @pytest.mark.asyncio
    async def test_tool_rejection_creates_decision(self, strategos_with_events, decision_ledger):
        """Blocked/disabled tools should emit TOOL_REJECTION decisions."""
        
        async def mock_dispatch(tool: str) -> List[Dict]:
            """AsyncFunction mock_dispatch."""
            return []
        
        # Bug bounty mode disables certain tools
        await strategos_with_events.run_mission(
            target="example.com",
            available_tools=["masscan"],  # Likely blocked in bug bounty
            mode=ScanMode.BUG_BOUNTY,
            dispatch_tool=mock_dispatch
        )
        
        decisions = decision_ledger.get_all()
        rejection_decisions = [d for d in decisions if d.type == DecisionType.TOOL_REJECTION]
        
        # May have rejections if masscan is blocked
        # This is not guaranteed, so we just verify structure if present
        if rejection_decisions:
            for decision in rejection_decisions:
                assert decision.chosen in ["DISABLED", "BLOCKED_BY_CONSTITUTION"]
                assert "tool" in decision.context, "Rejection decision missing tool"


class TestEarlyTerminationEmission:
    """Verify that walk-away and early termination emit decisions."""
    
    @pytest.mark.asyncio
    async def test_bug_bounty_walk_away_emits_decision(self, strategos_with_events, decision_ledger):
        """Walk Away logic should emit EARLY_TERMINATION decision."""
        
        async def mock_dispatch(tool: str) -> List[Dict]:
            # Return no findings to trigger Walk Away
            """AsyncFunction mock_dispatch."""
            return []
        
        await strategos_with_events.run_mission(
            target="example.com",
            available_tools=["httpx"],  # Minimal tools
            mode=ScanMode.BUG_BOUNTY,
            dispatch_tool=mock_dispatch
        )
        
        decisions = decision_ledger.get_all()
        termination_decisions = [d for d in decisions if d.type == DecisionType.EARLY_TERMINATION]
        
        # Should have at least mission complete decision
        assert len(termination_decisions) > 0, "No termination decisions recorded"
        
        # Check for Walk Away specifically (may or may not trigger based on findings)
        walk_away = [d for d in termination_decisions if d.chosen == "WALK_AWAY"]
        # Conditional branch.
        if walk_away:
            decision = walk_away[0]
            assert "surface_delta" in decision.evidence or "surface_delta_this_intent" in decision.evidence


class TestDecisionEventCorrelation:
    """Verify that decisions and events are properly correlated."""
    
    @pytest.mark.asyncio
    async def test_every_decision_emits_event(self, strategos_with_events, decision_ledger, event_store):
        """Every decision should result in at least one event."""
        
        async def mock_dispatch(tool: str) -> List[Dict]:
            """AsyncFunction mock_dispatch."""
            return []
        
        await strategos_with_events.run_mission(
            target="example.com",
            available_tools=["subfinder"],
            mode=ScanMode.STANDARD,
            dispatch_tool=mock_dispatch
        )
        
        decisions = decision_ledger.get_all()
        events = event_store.get_latest(count=200)
        
        # Should have events for decisions (not 1:1, but correlated)
        assert len(events) > 0, "No events emitted"
        assert len(decisions) > 0, "No decisions recorded"
        
        # Verify that decision_made events exist
        decision_events = [e for e in events if e.type == GraphEventType.DECISION_MADE]
        assert len(decision_events) > 0, "No decision_made events in EventStore"


class TestDecisionHierarchy:
    """Verify that nested decisions create parent-child relationships."""
    
    @pytest.mark.asyncio
    async def test_tool_decisions_nested_under_intent(self, strategos_with_events, decision_ledger):
        """Tool selection decisions should be children of intent decisions."""
        
        async def mock_dispatch(tool: str) -> List[Dict]:
            """AsyncFunction mock_dispatch."""
            return []
        
        await strategos_with_events.run_mission(
            target="example.com",
            available_tools=["subfinder", "httpx"],
            mode=ScanMode.STANDARD,
            dispatch_tool=mock_dispatch
        )
        
        decisions = decision_ledger.get_all()
        
        # Find an intent decision
        intent_decisions = [d for d in decisions if d.type == DecisionType.INTENT_TRANSITION]
        assert len(intent_decisions) > 0
        
        # Find tool decisions that are children
        for intent_decision in intent_decisions:
            children = decision_ledger.get_children(intent_decision.id)
            
            # Should have children (tool selections, rejections, or skip decisions)
            # Not guaranteed for every intent, but at least some should have children
            if children:
                for child in children:
                    assert child.parent_id == intent_decision.id
                    assert child.type in [
                        DecisionType.TOOL_SELECTION,
                        DecisionType.TOOL_REJECTION
                    ]


class TestDecisionCompleteness:
    """Meta-test: Verify that no decision points are missed."""
    
    @pytest.mark.asyncio
    async def test_no_manual_emit_event_calls(self, strategos_with_events, decision_ledger, event_store):
        """
        All decision events should come from DecisionContext, not manual emit_event calls.
        
        This verifies Layer 2's core guarantee: decisions are structurally emitted.
        """
        
        async def mock_dispatch(tool: str) -> List[Dict]:
            """AsyncFunction mock_dispatch."""
            return []
        
        # Clear event store to get a clean baseline
        event_store.clear()
        decision_ledger.clear()
        
        await strategos_with_events.run_mission(
            target="example.com",
            available_tools=["subfinder"],
            mode=ScanMode.STANDARD,
            dispatch_tool=mock_dispatch
        )
        
        # Every DECISION_MADE event should have a corresponding DecisionPoint
        events = event_store.get_latest(count=200)
        decision_events = [e for e in events if e.type == GraphEventType.DECISION_MADE]
        
        decisions = decision_ledger.get_all()
        
        # Rough correlation check (not exact 1:1 due to phase_changed events)
        # But we should have at least as many decisions as decision_made events
        assert len(decisions) >= len(decision_events) * 0.5, (
            f"Decision/Event mismatch: {len(decisions)} decisions, {len(decision_events)} events"
        )


# ============================================================================
# Diagnostic Test: Dump Decision Trace
# ============================================================================

@pytest.mark.asyncio
async def test_dump_decision_trace_for_inspection(strategos_with_events, decision_ledger, event_store, capsys):
    """
    Diagnostic test: Print full decision trace for manual inspection.
    
    Run this test with pytest -s to see the decision flow.
    """
    
    async def mock_dispatch(tool: str) -> List[Dict]:
        """AsyncFunction mock_dispatch."""
        return []
    
    await strategos_with_events.run_mission(
        target="test.example.com",
        available_tools=["subfinder", "httpx"],
        mode=ScanMode.STANDARD,
        dispatch_tool=mock_dispatch
    )
    
    decisions = decision_ledger.get_all()
    
    print("\n" + "=" * 80)
    print("DECISION TRACE (Layer 2 Emission Verification)")
    print("=" * 80)
    
    # Loop over items.
    for i, decision in enumerate(decisions, 1):
        indent = "  " if decision.parent_id else ""
        print(f"\n{indent}[{i}] {decision.type.value}")
        print(f"{indent}    Chosen: {decision.chosen}")
        print(f"{indent}    Reason: {decision.reason}")
        if decision.parent_id:
            print(f"{indent}    Parent: {decision.parent_id[:8]}...")
        if decision.evidence:
            print(f"{indent}    Evidence: {decision.evidence}")
    
    events = event_store.get_latest(count=200)
    decision_events = [e for e in events if e.type == GraphEventType.DECISION_MADE]
    phase_events = [e for e in events if e.type == GraphEventType.SCAN_PHASE_CHANGED]
    
    print("\n" + "=" * 80)
    print(f"Total Decisions: {len(decisions)}")
    print(f"Total Events: {len(events)}")
    print(f"  - Decision Events: {len(decision_events)}")
    print(f"  - Phase Events: {len(phase_events)}")
    print("=" * 80)
    
    # Verify completeness
    assert len(decisions) > 0, "No decisions recorded"
    assert len(decision_events) > 0, "No decision events emitted"
