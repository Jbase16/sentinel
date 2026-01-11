"""
tests/core/contracts/test_causal_isolation.py
Verification suite for Causal Isolation (Phase 2).
"""

import pytest
from core.contracts.events import CausalTracker, EventType

@pytest.fixture
def tracker():
    return CausalTracker()

def test_single_scan_causality(tracker):
    """Test standard causality for one scan."""
    scan_id = "scan-1"
    
    # 1. Start Scan
    assert tracker.on_event(EventType.SCAN_STARTED, {"session_id": scan_id}) is None
    
    # 2. Start Tool
    assert tracker.on_event(EventType.TOOL_STARTED, {"scan_id": scan_id, "tool": "nmap"}) is None
    
    # 3. Complete Tool (Valid)
    assert tracker.on_event(EventType.TOOL_COMPLETED, {"scan_id": scan_id, "tool": "nmap"}) is None
    
    # 4. Complete Tool (Invalid - Not Started)
    violation = tracker.on_event(EventType.TOOL_COMPLETED, {"scan_id": scan_id, "tool": "nuclei"})
    assert violation is not None
    assert "without prior tool_started" in violation

def test_concurrent_scan_isolation(tracker):
    """Test that two scans do not share causal state."""
    scan_a = "scan-A"
    scan_b = "scan-B"
    
    # Start both
    tracker.on_event(EventType.SCAN_STARTED, {"session_id": scan_a})
    tracker.on_event(EventType.SCAN_STARTED, {"session_id": scan_b})
    
    # Start Nmap in A only
    tracker.on_event(EventType.TOOL_STARTED, {"scan_id": scan_a, "tool": "nmap"})
    
    # 1. Try to complete Nmap in B (Should fail)
    violation_b = tracker.on_event(EventType.TOOL_COMPLETED, {"scan_id": scan_b, "tool": "nmap"})
    assert violation_b is not None
    assert "scan 'scan-B'" in violation_b
    
    # 2. Complete Nmap in A (Should succeed)
    violation_a = tracker.on_event(EventType.TOOL_COMPLETED, {"scan_id": scan_a, "tool": "nmap"})
    assert violation_a is None

def test_lifecycle_cleanup(tracker):
    """Test that state is cleaned up after completion."""
    scan_id = "scan-Z"
    
    tracker.on_event(EventType.SCAN_STARTED, {"session_id": scan_id})
    tracker.on_event(EventType.TOOL_STARTED, {"scan_id": scan_id, "tool": "nmap"})
    
    # Complete Scan
    tracker.on_event(EventType.SCAN_COMPLETED, {"session_id": scan_id})
    
    # Internal check: state should be gone
    assert scan_id not in tracker._active_scans
    assert scan_id not in tracker._scan_tool_state
