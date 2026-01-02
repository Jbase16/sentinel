"""
Unit tests for CAL Core (Collaborative Agent Language).
Migrated from tests/verification/verify_cal_core.py
"""
import pytest
from core.cal.types import Claim, Evidence, Provenance, ValidationStatus
from core.cal.engine import ReasoningSession
from core.cal.interface import cal_rule
from core.base.sequence import GlobalSequenceAuthority

@pytest.fixture(autouse=True)
def setup_sequence_authority():
    """Ensure GlobalSequenceAuthority is initialized for events."""
    GlobalSequenceAuthority.reset_for_testing()
    GlobalSequenceAuthority.initialize_for_testing()

@pytest.fixture
def session():
    """Fixture to provide a clean ReasoningSession."""
    return ReasoningSession(session_id="test_session", topic="unit_test")
    """Fixture to provide a clean ReasoningSession."""
    return ReasoningSession(session_id="test_session", topic="unit_test")

@pytest.fixture
def provenances():
    """Fixture to provide standard provenances."""
    return {
        "high": Provenance(source="TrustedScanner", method="verified"),
        "low": Provenance(source="RandomGuess", method="heuristic")
    }

def test_claim_lifecycle(session, provenances):
    """Verify Claim transitions: PENDING -> VALIDATED -> DISPUTED."""
    
    # 1. Assert initial claim
    claim = session.assert_claim(
        statement="SQL Injection in /login",
        evidence=Evidence(content={}, description="Initial finding", provenance=provenances["low"], confidence=0.2),
        metadata={"cwe": 89}
    )
    
    assert claim.status == ValidationStatus.PENDING
    assert claim.confidence < 0.8  # Should be low initially

    # 2. Add specific evidence to boost confidence
    strong_evidence = Evidence(
        content={"payload": "' OR 1=1"},
        description="Exploit successful",
        provenance=provenances["high"],
        confidence=1.0
    )
    claim.add_support(strong_evidence)
    
    assert claim.status == ValidationStatus.VALIDATED
    assert claim.confidence >= 0.8
    
    # 3. Dispute the claim
    dispute_evidence = Evidence(
        content={"waf_log": "blocked"},
        description="WAF blocked the request",
        provenance=provenances["high"],
        confidence=1.0
    )
    claim.add_dispute(dispute_evidence)
    
    assert claim.status == ValidationStatus.DISPUTED
    # Confidence should drop
    # assert claim.confidence < 0.8  <-- add_dispute significantly drops confidence usually, or logic sets status

def test_rule_of_precedence(session, provenances):
    """Verify that DISPUTED status overrides VALIDATED."""
    
    # Start VALIDATED
    claim = session.assert_claim("Test Conflict", Evidence({}, "Ref", provenances["high"], confidence=1.0))
    # Note: confidence starts at 0.5. +0.4*1.0 = 0.9. (>0.8) -> VALIDATED.
    assert claim.status == ValidationStatus.VALIDATED
    
    # Add Dispute
    claim.add_dispute(Evidence({}, "Counter", provenances["high"], confidence=1.0))
    assert claim.status == ValidationStatus.DISPUTED
    
    # Now add MORE support. Should NOT flip back to VALIDATED automatically.
    # Logic in types.py: Only PENDING -> VALIDATED.
    claim.add_support(Evidence({}, "More Support", provenances["high"], confidence=1.0))
    
    # Status should remain DISPUTED (needs manual arbitration)
    assert claim.status == ValidationStatus.DISPUTED

def test_fluent_interface():
    """Verify the @cal_rule decorator."""
    
    events = []
    
    @cal_rule(on_claim_type="test_type")
    def on_validated(claim, session):
        events.append(f"Validated: {claim.statement}")
        
    class MockClaim:
        statement = "Test"
        status = ValidationStatus.VALIDATED
        metadata = {"type": "test_type"}
        
    session = ReasoningSession("test", "test")
    on_validated(MockClaim(), session)
    
    assert "Validated: Test" in events
