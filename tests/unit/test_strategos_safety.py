
import pytest
import asyncio
import time
from unittest.mock import MagicMock, AsyncMock
from core.scheduler.strategos import (
    Strategos,
    ScanContext,
    CircuitBreaker,
    CircuitBreakerState,
    InsightQueue,
    InsightQueueStats
)
from core.contracts.schemas import InsightPayload, InsightActionType
from core.scheduler.events import ToolCompletedEvent

@pytest.mark.anyio
async def test_circuit_breaker_transition():
    """Verify circuit breaker transitions from CLOSED -> OPEN -> HALF_OPEN -> CLOSED."""
    cb = CircuitBreaker(failure_threshold=2, timeout_seconds=0.1, success_threshold=1)
    
    # Initial state
    assert cb.get_state() == "CLOSED"
    assert await cb.acquire() is True
    
    # 1st failure
    await cb.record_failure()
    assert cb.get_state() == "CLOSED"
    
    # 2nd failure -> OPEN
    await cb.record_failure()
    assert cb.get_state() == "OPEN"
    
    # Should not acquire
    assert await cb.acquire() is False
    
    # Wait for timeout
    await asyncio.sleep(0.15)
    
    # Should transition to HALF_OPEN on acquire
    assert await cb.acquire() is True
    assert cb.get_state() == "HALF_OPEN"
    
    # Success -> CLOSED
    await cb.record_success()
    assert cb.get_state() == "CLOSED"

@pytest.mark.anyio
async def test_insight_queue_drop_policy():
    """Verify queue drops newest when full."""
    queue = InsightQueue(maxsize=1)
    
    insight1 = InsightPayload(
        insight_id="1", scan_id="test", action_type=InsightActionType.GENERAL,
        confidence=1.0, target="t1", summary="summary1", details={}, source_tool="test"
    )
    insight2 = InsightPayload(
        insight_id="2", scan_id="test", action_type=InsightActionType.GENERAL,
        confidence=1.0, target="t2", summary="summary2", details={}, source_tool="test"
    )
    
    # Enqueue first
    assert await queue.enqueue(insight1) is True
    
    # Enqueue second (should fail due to full)
    assert await queue.enqueue(insight2) is False
    
    stats = queue.get_stats()
    assert stats.dropped_count == 1
    assert stats.total_enqueued == 1

@pytest.mark.anyio
async def test_insight_queue_circuit_breaker_integration():
    """Verify queue respects circuit breaker."""
    cb = CircuitBreaker()
    cb._state = CircuitBreakerState(state="OPEN", last_failure_time=time.time())
    
    # InsightQueue now uses per-action-type breakers; inject a factory that returns our OPEN breaker.
    queue = InsightQueue(maxsize=10, breaker_factory=lambda: cb)
    
    insight = InsightPayload(
        insight_id="1", scan_id="test", action_type=InsightActionType.GENERAL,
        confidence=1.0, target="t1", summary="summary_valid", details={}, source_tool="test"
    )
    
    await queue.enqueue(insight)
    
    # Processor should NOT process because breaker is OPEN
    mock_handler = AsyncMock()
    processed = await queue.process_one(mock_handler)
    
    assert processed is False
    mock_handler.assert_not_called()
    assert queue.get_stats().circuit_breaker_state == "OPEN"

@pytest.mark.anyio
async def test_context_lock_prevents_race():
    """Verify that queue operations are thread-safe (implicit via async lock)."""
    # Note: Explicit race condition testing is hard in async, but specific
    # verification of lock acquisition can be done via mocking if we want deep white-box.
    # For now, we trust asyncio.Lock logic, and verify queue integrity under load.
    
    queue = InsightQueue(maxsize=100)
    
    start_time = time.time()
    
    async def produce():
        for i in range(10):
            await queue.enqueue(InsightPayload(
                insight_id=str(i), scan_id="test", action_type=InsightActionType.GENERAL,
                confidence=1.0, target="t", summary="valid_summary", details={}, source_tool="test",
                priority=9-i
            ))
            
    await asyncio.gather(produce(), produce())
    
    assert queue.get_stats().total_enqueued == 20
    assert queue.get_stats().current_size == 20
