"""
tests/core/reasoning/test_reasoning_logic.py
Verification of Rule Logic and Confidence Arithmetic.
"""
import pytest
from core.cortex.events import EventBus, GraphEvent
from core.contracts.events import EventType
from core.reasoning.engine import ReasoningEngine
from core.reasoning.models import Confidence
from core.base.sequence import GlobalSequenceAuthority
from itertools import count

def setup_module():
    # Force initialization for tests
    if not GlobalSequenceAuthority._initialized:
        auth = GlobalSequenceAuthority.__new__(GlobalSequenceAuthority)
        auth._counter = count(start=1)
        auth._last_issued = 0
        GlobalSequenceAuthority._instance = auth
        GlobalSequenceAuthority._initialized = True

def test_confidence_arithmetic():
    c = Confidence(0.5)
    c.add(0.2)
    assert c.value == 0.7
    
    c.add(0.5)
    assert c.value == 1.0 # Clamped
    
    c.decay(0.5)
    assert c.value == 0.5
    
    c.decay(0.0)
    assert c.value == 0.0

def test_admin_surface_rule():
    bus = EventBus()
    engine = ReasoningEngine(bus) # Fresh instance
    
    evidence = []
    def spy(event: GraphEvent):
        if event.type == EventType.NEXUS_HYPOTHESIS_FORMED:
            evidence.append(event.payload)
            
    bus.subscribe(spy, event_types=[EventType.NEXUS_HYPOTHESIS_FORMED])
    
    # Trigger
    bus.emit(GraphEvent(
        type=EventType.MIMIC_ROUTE_FOUND,
        scan_id="test_scan",
        payload={
            "scan_id": "test_scan",
            "asset_id": "a1",
            "route": "/internal/config",
            "confidence": 80
        }
    ))
    
    assert len(evidence) == 1
    hyp = evidence[0]
    assert hyp["rule_id"] == "RULE_ADMIN_SURFACE"
    assert hyp["confidence"] >= 0.35
    assert "possible administrative" in hyp["summary"].lower()
