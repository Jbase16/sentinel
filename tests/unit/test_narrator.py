"""Module test_narrator: inline documentation for /Users/jason/Developer/sentinelforge/tests/unit/test_narrator.py."""
import pytest
from typing import List, Dict, Any
from core.cortex.events import EventBus, GraphEventType, GraphEvent
from core.cortex.narrator import NarratorEngine
from core.scheduler.decisions import DecisionContext, DecisionType, DecisionLedger

class MockSubscriber:
    """Class MockSubscriber."""
    def __init__(self):
        """Function __init__."""
        self.events: List[GraphEvent] = []
        
    def __call__(self, event: GraphEvent):
        """Function __call__."""
        self.events.append(event)

def test_narrator_integration():
    # 1. Setup Infrastructure
    """Function test_narrator_integration."""
    bus = EventBus()
    subscriber = MockSubscriber()
    bus.subscribe(subscriber)
    
    narrator = NarratorEngine(event_bus=bus)
    ledger = DecisionLedger()
    
    # 2. Execute Decision Loop
    with DecisionContext(event_bus=bus, ledger=ledger, narrator=narrator) as ctx:
        
        # A. Intent Change
        ctx.choose(
            DecisionType.INTENT_TRANSITION,
            "intent_vuln_scanning",
            "Moving to attack phase"
        )
        
        # B. Tool Selection
        ctx.choose(
            DecisionType.TOOL_SELECTION,
            ["nuclei", "zap"],
            "Standard web scan"
        )
        
        # C. Tool Blocking
        ctx.choose(
            DecisionType.TOOL_REJECTION,
            "exclude_me",
            "Constitution Violation",
            context={"tool": "masscan"}
        )

    # 3. Verify Events
    narratives = [e for e in subscriber.events if e.type == GraphEventType.NARRATIVE_EMITTED]
    assert len(narratives) == 3
    
    # Check A
    n1 = narratives[0]
    assert n1.payload["decision_type"] == DecisionType.INTENT_TRANSITION.value
    assert "STRATEGY: Transitioning to Vuln Scanning" in n1.payload["narrative"]
    
    # Check B
    n2 = narratives[1]
    assert "TACTIC: Deploying 2 tools: [nuclei, zap]" in n2.payload["narrative"]
    
    # Check C
    n3 = narratives[2]
    assert "DEFENSE: Blocked masscan" in n3.payload["narrative"]
    assert "Constitution Violation" in n3.payload["narrative"]

def test_narrator_determinism():
    # Verify string formatting without event bus
    """Function test_narrator_determinism."""
    narrator = NarratorEngine()
    
    # Phase Transition
    from core.scheduler.decisions import DecisionPoint
    d = DecisionPoint.create(
        DecisionType.PHASE_TRANSITION,
        "PHASE_2_ACTIVE",
        "Go time"
    )
    msg = narrator._generate_narrative(d)
    assert "PHASE CHANGE: Entering Phase 2 Active" in msg

if __name__ == "__main__":
    # Self-test if run directly
    test_narrator_integration()
    test_narrator_determinism()
    print("✅ Narrator Verified")
