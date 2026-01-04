import logging
import asyncio
from unittest.mock import AsyncMock, patch, MagicMock
from httpx import Response

from core.thanatos.models import LogicTestCase, InvariantClass, MutationOpType, OracleSpec, InvariantDomain, BreachHypothesis, TargetHandle, MutationSpec
from core.sentient.models import SentientDecision, Verdict
from core.executor.models import ExecutionOrder, ExecutionStatus, BreachStatus
from core.executor.http_harness import HttpHarness
from core.executor.oracle import StandardOracleEvaluator

logging.basicConfig(level=logging.INFO, format="%(levelname)s:%(name)s:%(message)s")
log = logging.getLogger("verify_executor_refined")

# Mock Data
MOCK_TEST_CASE = LogicTestCase(
    id="test-case-1",
    hypothesis=BreachHypothesis(
        invariant=InvariantClass.NON_NEGATIVE_AMOUNT, 
        domain=InvariantDomain.ECONOMIC,
        rationale="Test"
    ),
    mutation=MutationSpec(
        op=MutationOpType.SET_NUMERIC_BELOW_MIN,
        params={"field": "amount", "value": -1}
    ),
    oracle=OracleSpec(
        name="Security Headers", 
        forbidden={"json_subset": {"success": True}} 
    ),
    priority=0.9,
    target=TargetHandle(node_id="test", endpoint="/api/test", method="POST", value=5.0) 
)

MOCK_ORDER = ExecutionOrder(
    test_case=MOCK_TEST_CASE,
    decision=SentientDecision(verdict=Verdict.APPROVE, rationale="Test"),
    idempotency_token="abc"
)

async def test_refined_semantics():
    log.info("--- Testing Refined Semantics ---")
    
    harness = HttpHarness()
    oracle = StandardOracleEvaluator()

    # Mock Response: Breach Scenario
    mock_response = MagicMock(spec=Response)
    mock_response.status_code = 200
    mock_response.text = '{"success": true, "data": {"id": 123}}'
    mock_response.headers = {}
    mock_response.url = "http://localhost:8000/api/test"
    mock_response.http_version = "HTTP/1.1"

    # Async mock wrapper
    mock_client = AsyncMock()
    mock_client.request.return_value = mock_response

    with patch.object(HttpHarness, 'get_client', return_value=mock_client):
        # 1. Execute
        result = await harness.execute(MOCK_ORDER)
        
        # Verify ExecutionStatus
        if result.status == ExecutionStatus.EXECUTED:
            log.info("✅ Harness status is EXECUTED (Correct).")
        else:
            log.error(f"❌ Unexpected ExecutionStatus: {result.status}")
            
        # 2. Evaluate
        breach_status = oracle.evaluate(result, MOCK_TEST_CASE.oracle)
        
        # Verify BreachStatus
        if breach_status == BreachStatus.BREACH:
            log.info("✅ Oracle status is BREACH (Correct).")
        else:
            log.error(f"❌ Unexpected BreachStatus: {breach_status}")

    # 3. Lifecycle Check
    await HttpHarness.close_client()
    log.info("✅ Lifecycle close_client called without error.")

def main():
    asyncio.run(test_refined_semantics())
    log.info("\n✅ Refined Verification Complete.")

if __name__ == "__main__":
    main()
