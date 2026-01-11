"""
tests/core/cronus/test_cronus_phase2.py
Verification suite for Cronus (Phase 2).
"""

import pytest
import time
from unittest.mock import MagicMock
from core.cronus.manager import CronusManager
from core.contracts.events import EventType
from core.cortex.events import GraphEvent, reset_event_sequence

@pytest.fixture
def manager():
    reset_event_sequence()
    bus = MagicMock()
    bus.subscribe = MagicMock()
    bus.emit = MagicMock()
    
    mgr = CronusManager(event_bus=bus)
    return mgr, bus

def test_cronus_lifecycle(manager):
    mgr, bus = manager
    id_a = "scan-A"
    
    # Start
    mgr._handle_event(GraphEvent(type=EventType.SCAN_STARTED, payload={"session_id": id_a}))
    assert id_a in mgr.sessions
    
    # Stop
    mgr._handle_event(GraphEvent(type=EventType.SCAN_COMPLETED, payload={"session_id": id_a}))
    assert id_a not in mgr.sessions

def test_budget_finding_limit(manager):
    mgr, bus = manager
    id_a = "scan-budget-test"
    
    # Start (default budget has 1000 max findings)
    mgr._handle_event(GraphEvent(type=EventType.SCAN_STARTED, payload={"session_id": id_a}))
    session = mgr.sessions[id_a]
    
    # Reduce budget for test
    session.budget.max_findings = 5
    
    # Add 5 findings (OK)
    mgr._handle_event(GraphEvent(
        type=EventType.TOOL_COMPLETED, 
        payload={"scan_id": id_a, "tool": "fast-tool", "findings_count": 5}
    ))
    
    # Add 1 more (Should Trip)
    mgr._handle_event(GraphEvent(
        type=EventType.TOOL_COMPLETED, 
        payload={"scan_id": id_a, "tool": "fail-tool", "findings_count": 1}
    ))
    
    # Verify KILL event
    calls = bus.emit.call_args_list
    kill_calls = [c for c in calls if c[0][0].type == EventType.RESOURCE_GUARD_TRIP]
    assert len(kill_calls) == 1
    assert "findings" in kill_calls[0][0][0].payload["message"]

def test_budget_time_limit(manager):
    mgr, bus = manager
    id_a = "scan-time-test"
    
    mgr._handle_event(GraphEvent(type=EventType.SCAN_STARTED, payload={"session_id": id_a}))
    session = mgr.sessions[id_a]
    
    # Artificial time limit
    session.budget.max_time_ms = 100 # 100ms
    
    time.sleep(0.2) # Sleep 200ms
    
    # Any action should trigger check
    mgr._handle_event(GraphEvent(
        type=EventType.TOOL_STARTED, 
        payload={"scan_id": id_a, "tool": "slow-tool"}
    ))
    
    # Verify KILL event
    calls = bus.emit.call_args_list
    kill_calls = [c for c in calls if c[0][0].type == EventType.RESOURCE_GUARD_TRIP]
    assert len(kill_calls) == 1
    assert "time_ms" in kill_calls[0][0][0].payload["message"]
