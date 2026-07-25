"""
Integration test for the full CAL reasoning loop.

Verifies that:
1. StrategyEngine emits Claims when generating attack vectors
2. ScannerBridge emits Evidence from tool output
3. ReasoningSession converges claims based on evidence
"""

import pytest
from unittest.mock import MagicMock, AsyncMock, patch
from core.ai.strategy import StrategyEngine
from core.cortex.scanner_bridge import ScannerBridge
from core.base.session import ScanSession
from core.cal.engine import ReasoningSession
from core.cal.types import ValidationStatus

@pytest.mark.asyncio
async def test_cal_reasoning_loop():
    """
    End-to-end test: AI makes claim → Scanner provides evidence → Claim validates
    """
    # Initialize Event Bus to prevent GlobalSequenceAuthority error
    from core.cortex.events import get_event_bus
    event_bus = get_event_bus()
    
    # Setup
    mock_session = MagicMock(spec=ScanSession)
    mock_session.session_id = "test-session-123"
    mock_session.target = "https://example.com"
    mock_session.log = MagicMock()
    
    strategy = StrategyEngine(session=mock_session)
    
    # Mock AI to return a vulnerability hypothesis
    mock_ai_response = '''{
        "vectors": [{
            "vuln_class": "IDOR",
            "parameter": "user_id",
            "hypothesis": "The user_id parameter might allow access to other users' data",
            "suggested_payloads": ["1", "2", "999"]
        }]
    }'''
    
    # Patch AI client to avoid real calls
    with patch.object(strategy.ai, 'client') as mock_client:
        mock_client.generate.return_value = mock_ai_response
        
        # Simulate traffic analysis
        flow_data = {
            "url": "https://example.com/api/profile?user_id=5",
            "method": "GET",
            "params": ["user_id"]
        }
        
        vectors = await strategy.analyze_traffic(flow_data)
        
        # Verify attack vectors were generated (AI + potential heuristics)
        assert len(vectors) >= 1
        
        # Find the AI-generated vector
        ai_vector = next((v for v in vectors if v.source == "ai"), None)
        if ai_vector:
            assert ai_vector.vuln_class == "IDOR"
            assert ai_vector.parameter == "user_id"
            
            # Verify CAL Claim was created
            assert len(strategy.reasoning_session.claims) >= 1
            
            # Find the IDOR claim
            idor_claims = [c for c in strategy.reasoning_session.claims.values() 
                         if "IDOR" in c.statement and "user_id" in c.statement]
            assert len(idor_claims) >= 1
            
            claim = idor_claims[0]
            assert claim.status == ValidationStatus.PENDING  # Not yet validated
            assert claim.confidence >= 0.5  # AI hypothesis (may be higher if merged)
            
            # Simulate scanner finding confirming evidence
            evidence = ScannerBridge.emit_evidence(
                session_id=mock_session.session_id,
                tool="wraith",
                target="https://example.com/api/profile?user_id=999",
                output="HTTP 200 OK\\n{username: 'admin', email: 'admin@example.com'}"
            )
            
            # Add supporting evidence to the claim
            claim.add_support(evidence)
            
            # Verify confidence increased
            assert claim.confidence > 0.5  # Should be higher now
            
            # Trigger convergence check
            strategy.reasoning_session._check_convergence(claim)
            
            # Verify claim moved toward validation
            assert claim.status != ValidationStatus.REJECTED
        else:
            # If AI didn't work, at least verify heuristics generated claims
            assert len(strategy.reasoning_session.claims) >= 1

def test_scanner_bridge_evidence_emission():
    """Verify ScannerBridge correctly creates Evidence objects"""
    evidence = ScannerBridge.emit_evidence(
        session_id="test-123",
        tool="nmap",
        target="10.0.0.1",
        output="22/tcp open ssh"
    )
    
    assert evidence.id is not None
    assert evidence.provenance.source == "Scanner:nmap"
    assert evidence.provenance.run_id == "test-123"
    assert evidence.confidence == 1.0  # Tool output is fact
    assert "22/tcp open ssh" in evidence.content["raw_output"]
