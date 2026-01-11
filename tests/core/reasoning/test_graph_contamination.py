"""
tests/core/reasoning/test_graph_contamination.py
Verification ensuring Hypotheses do NOT pollute the KnowledgeGraph.
"""
import pytest
from unittest.mock import MagicMock
from core.cortex.events import EventBus, GraphEvent
from core.contracts.events import EventType
from core.reasoning.engine import ReasoningEngine
from core.base.sequence import GlobalSequenceAuthority
from itertools import count

def setup_module():
    # Force initialization for tests
    if not GlobalSequenceAuthority._initialized:
        # Bypass __new__ checks by setting class attributes directly if needed
        # Or just use the instance if created, but we need to set _initialized=True
        # To be clean, we can just instantiate updates
        auth = GlobalSequenceAuthority.__new__(GlobalSequenceAuthority)
        auth._counter = count(start=1)
        auth._last_issued = 0
        GlobalSequenceAuthority._instance = auth
        GlobalSequenceAuthority._initialized = True

def test_hypothesis_isolation():
    # Setup
    bus = EventBus()
    engine = ReasoningEngine.get(bus)
    engine.start()
    
    # Mock a "Graph" (in reality, we check if any graph-mutating events are emitted)
    # The ReasoningEngine should ONLY emit NEXUS_HYPOTHESIS_* events.
    # It should NEVER emit findings or topology updates directly.
    
    emitted_types = []
    def spy(event: GraphEvent):
        emitted_types.append(event.type)
        
    bus.subscribe(spy)
    
    # Trigger a hypothesis via Mimic event
    scan_id = "isolation_test_scan"
    trigger = GraphEvent(
        type=EventType.MIMIC_ROUTE_FOUND,
        scan_id=scan_id,
        payload={
            "scan_id": scan_id,
            "asset_id": "asset_1",
            "route": "/admin/dashboard",
            "method": "GET"
        }
    )
    
    # Action
    # Use bus emit to simulate system flow
    # Note: EventBus dispatch is immediate in current implementation
    bus.emit(trigger)
    
    # Assert
    # 1. Hypothesis FORMED should exist
    assert EventType.NEXUS_HYPOTHESIS_FORMED in emitted_types
    
    # 2. No Graph-polluting events (NEXUS_PRIMITIVE_FOUND, etc)
    # The engine strictly emits hypothesis lifecycle events
    forbidden = [
        EventType.NEXUS_PRIMITIVE_FOUND, 
        EventType.NEXUS_CHAIN_FOUND,
        EventType.TRAFFIC_OBSERVED
    ]
    for et in emitted_types:
        assert et not in forbidden, f"ReasoningEngine emitted forbidden event: {et}"
        
    engine.stop()
