"""
tests/core/cortex/test_nexus_phase1.py

Verification suite for Phase 1:
1. Nexus Isolation: Ensure no cross-talk between concurrent scan sessions.
2. Observer Logic: Ensure timers fire EVENT_SILENCE.
3. Lifecycle: Ensure sessions are created/destroyed correctly.
"""

import pytest
import time
from unittest.mock import MagicMock, patch
from core.cortex.manager import NexusManager
from core.cortex.session import NexusSession
from core.cortex.events import EventBus, GraphEvent, reset_event_sequence
from core.contracts.events import EventType

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_bus():
    """Return a mock EventBus."""
    bus = MagicMock(spec=EventBus)
    bus.subscribe = MagicMock()
    bus.emit = MagicMock()
    return bus

@pytest.fixture
def manager(mock_bus):
    """Return a NexusManager with mocked bus."""
    # VALIDATION FIX: Initialize sequence authority
    reset_event_sequence()
    
    # Mock loop to prevent "no running event loop" error during session.apply
    with patch("core.cortex.session.get_running_loop") as mock_get_loop:
        mock_loop = MagicMock()
        mock_get_loop.return_value = mock_loop
        
        mgr = NexusManager(event_bus=mock_bus)
        mgr.start()
        yield mgr

# ---------------------------------------------------------------------------
# Isolation Tests
# ---------------------------------------------------------------------------

def test_session_lifecycle(manager):
    """Test creation and destruction of sessions via events."""
    scan_id = "scan-A"
    
    # 1. Start Scan
    manager._handle_event(GraphEvent(
        type=EventType.SCAN_STARTED,
        payload={"session_id": scan_id},
        event_sequence=1
    ))
    
    assert scan_id in manager.sessions
    assert isinstance(manager.sessions[scan_id], NexusSession)
    
    # 2. Complete Scan
    manager._handle_event(GraphEvent(
        type=EventType.SCAN_COMPLETED,
        payload={"session_id": scan_id},
        event_sequence=100
    ))
    
    assert scan_id not in manager.sessions

def test_cross_talk_isolation(manager, mock_bus):
    """Test that events for Scan A do not affect Scan B."""
    id_a = "scan-A"
    id_b = "scan-B"
    
    # Start both
    manager._handle_event(GraphEvent(type=EventType.SCAN_STARTED, payload={"session_id": id_a}))
    manager._handle_event(GraphEvent(type=EventType.SCAN_STARTED, payload={"session_id": id_b}))
    
    session_a = manager.sessions[id_a]
    session_b = manager.sessions[id_b]
    
    # Inject finding into A
    manager._handle_event(GraphEvent(
        type=EventType.FINDING_CREATED,
        payload={"scan_id": id_a, "finding_id": "f_a_1"},
        event_sequence=10
    ))
    
    # Inject finding into B
    manager._handle_event(GraphEvent(
        type=EventType.FINDING_CREATED,
        payload={"scan_id": id_b, "finding_id": "f_b_1"},
        event_sequence=11
    ))
    
    # Verify State Isolation
    assert "f_a_1" in session_a.knowledge["findings"]
    assert "f_b_1" not in session_a.knowledge["findings"]
    
    assert "f_b_1" in session_b.knowledge["findings"]
    assert "f_a_1" not in session_b.knowledge["findings"]

# ---------------------------------------------------------------------------
# Observer Tests
# ---------------------------------------------------------------------------

def test_observer_silence_timer():
    """Test that silence timer fires EVENT_SILENCE."""
    catured_events = []
    def capture_emit(evt_type, payload):
        catured_events.append((evt_type, payload))

    # Mock the asyncio loop within the session
    with patch("core.cortex.session.get_running_loop") as mock_get_loop:
        mock_loop = MagicMock()
        mock_get_loop.return_value = mock_loop
        
        session = NexusSession("scan-silent", capture_emit)
        
        # Trigger progress (should schedule timer)
        session._record_progress(EventType.SCAN_STARTED)
        assert mock_loop.call_later.called
        
        # Manually trigger timeout
        session.last_progress_at = time.time() - 35.0 # Force 35s silence
        session._on_silence_timeout()
        
        assert len(catured_events) == 1
        assert catured_events[0][0] == EventType.EVENT_SILENCE
        assert catured_events[0][1]["silence_seconds"] >= 35.0

def test_tool_churn_detection():
    catured_events = []
    session = NexusSession("scan-churn", lambda t, p: catured_events.append((t, p)))
    
    # Simulate rapid tool starts (6 in <10s)
    for i in range(6):
        session.apply(EventType.TOOL_STARTED, {"tool": f"tool-{i}"}, i)
    
    # Should trigger CHURN event
    assert len(catured_events) >= 1
    types = [e[0] for e in catured_events]
    assert EventType.TOOL_CHURN in types
    
    # Verify Honesty
    churn_payload = catured_events[0][1]
    assert churn_payload["is_assumed_zero_findings"] is True

# ---------------------------------------------------------------------------
# Routing Safety Tests
# ---------------------------------------------------------------------------

def test_routing_safety_violations(manager, mock_bus):
    """Test violations and orphan events."""
    
    # 1. Missing session_id on SCAN_STARTED (Contract Violation)
    manager._handle_event(GraphEvent(
        type=EventType.SCAN_STARTED,
        payload={}, # Missing
        event_sequence=1
    ))
    
    # Verify violation emitted
    calls = mock_bus.emit.call_args_list
    violation_calls = [c for c in calls if c[0][0].type == EventType.CONTRACT_VIOLATION]
    assert len(violation_calls) == 1
    assert "Missing session_id" in violation_calls[0][0][0].payload["violations"][0]
    
    # 2. Event for missing session (Orphan Drop)
    mock_bus.emit.reset_mock()
    manager._handle_event(GraphEvent(
        type=EventType.TOOL_STARTED,
        payload={"scan_id": "ghost-scan", "tool": "nmap"},
        event_sequence=2
    ))
    
    calls = mock_bus.emit.call_args_list
    orphan_calls = [c for c in calls if c[0][0].type == EventType.ORPHAN_EVENT_DROPPED]
    assert len(orphan_calls) == 1
    assert orphan_calls[0][0][0].payload["scan_id"] == "ghost-scan"
    assert "not found" in orphan_calls[0][0][0].payload["reason"]
