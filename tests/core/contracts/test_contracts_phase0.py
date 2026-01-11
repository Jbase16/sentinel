"""
tests/core/contracts/test_contracts_phase0.py

Verification suite for Phase 0:
1. Strict Pydantic Validation via EventContract.
2. Budget object consumption and overruns.
3. EventBus CONTRACT_VIOLATION emission mechanics.
4. Ghost Redaction enforcement.
"""

import pytest
from core.contracts.events import EventContract, EventType, ContractViolation, validate_event
from core.contracts.budget import Budget, BudgetOverrun
from core.cortex.events import EventBus, GraphEvent, set_strict_contract_mode, reset_event_sequence

# ---------------------------------------------------------------------------
# Setup / Teardown
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def setup_contracts():
    """Reset global state before each test."""
    reset_event_sequence()
    # Default to STRICT for these tests unless overriden
    set_strict_contract_mode(True)
    yield
    set_strict_contract_mode(False)

# ---------------------------------------------------------------------------
# Budget Tests
# ---------------------------------------------------------------------------

def test_budget_consumption():
    budget = Budget(max_time_ms=1000, max_findings=10)
    
    # Normal consumption
    new_level = budget.consume("max_findings", 5)
    assert new_level == 5.0
    assert budget.remaining("max_findings") == 5.0
    
    # Overrun
    with pytest.raises(BudgetOverrun) as exc:
        budget.consume("max_findings", 6) # Total 11 > 10
    
    assert exc.value.metric == "max_findings"
    assert exc.value.limit == 10
    assert exc.value.current == 11

def test_budget_reporting():
    b = Budget(max_time_ms=100)
    b.consume("max_time_ms", 50)
    report = b.usage_report()
    
    assert report["max_time_ms"]["percent"] == 50.0
    assert report["max_findings"]["used"] == 0.0

# ---------------------------------------------------------------------------
# Contract & Pydantic Tests
# ---------------------------------------------------------------------------

def test_valid_traffic_event():
    payload = {
        "scan_id": "scan-1",
        "mode": "omega",
        "method": "GET",
        "url": "http://example.com/api",
        "host": "example.com",
        "headers": {"User-Agent": "Sentinel", "Authorization": "REDACTED"}, # Valid
        "size_bytes": 100
    }
    # Should not raise (strict mode is True by fixture)
    validate_event(EventType.TRAFFIC_OBSERVED, payload)

def test_redaction_failure():
    payload = {
        "scan_id": "scan-1",
        "mode": "omega",
        "method": "GET",
        "url": "http://example.com/api",
        "host": "example.com",
        "headers": {"Authorization": "Bearer secret123"}, # INVALID: Unredacted
        "size_bytes": 100
    }
    
    with pytest.raises(ContractViolation) as exc:
        validate_event(EventType.TRAFFIC_OBSERVED, payload)
    
    assert "Authorization" in str(exc.value)

def test_missing_field_pydantic():
    payload = {
        "scan_id": "scan-1",
        # Missing mode
        "metric": "cpu",
        "limit": 100,
        "current": 105,
        "phase": "test"
    }
    
    with pytest.raises(ContractViolation) as exc:
        validate_event(EventType.RESOURCE_GUARD_TRIP, payload)
    
    assert "mode" in str(exc.value)

# ---------------------------------------------------------------------------
# EventBus Governance Tests
# ---------------------------------------------------------------------------

def test_event_bus_emits_violation_event():
    # Setup
    bus = EventBus(validate=True)
    set_strict_contract_mode(False) # We WANT to suppress raise, but catch the event
    
    violations_captured = []
    def on_violation(event):
        if event.type == EventType.CONTRACT_VIOLATION:
            violations_captured.append(event)
    
    bus.subscribe(on_violation)
    
    # Emit invalid event
    invalid_payload = {
        "scan_id": "scan-1",
        # Missing mode
    }
    
    # We use RESOURCE_GUARD_TRIP which requires 'mode'
    # strict=False means emit() won't raise Python exception, 
    # but SHOULD emit a CONTRACT_VIOLATION event.
    bus.emit(GraphEvent(
        type=EventType.RESOURCE_GUARD_TRIP,
        payload=invalid_payload
    ))
    
    assert len(violations_captured) == 1
    v = violations_captured[0]
    assert v.payload["offending_event_type"] == EventType.RESOURCE_GUARD_TRIP.value
    # The violation details usually contain the field name 'mode'
    assert "mode" in str(v.payload["violations"])

def test_strict_mode_raises():
    bus = EventBus(validate=True)
    # Fixture sets strict=True, but let's be explicit
    set_strict_contract_mode(True)
    
    with pytest.raises(ContractViolation):
        bus.emit(GraphEvent(
            type=EventType.RESOURCE_GUARD_TRIP,
            payload={"broken": "payload"}
        ))
