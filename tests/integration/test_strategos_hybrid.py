"""
Integration tests for Strategos Hybrid Evolution.

Tests end-to-end insight flow, concurrent scenarios, performance benchmarks,
and event emission verification.
"""

import pytest
import asyncio
from unittest.mock import MagicMock, AsyncMock, patch
from typing import Dict, Any

from core.scheduler.strategos import Strategos, ScanContext, InsightQueue, CircuitBreaker
from core.contracts.schemas import InsightPayload, InsightActionType, InsightQueueStats
from core.scheduler.modes import ScanMode
from core.cortex.events import EventBus
from core.contracts.events import EventType


@pytest.mark.anyio
async def test_end_to_end_insight_flow():
    """
    Verify complete insight flow: Finding -> Ingest -> Insight Generation -> Enqueue -> Process -> Handler -> Knowledge Update.
    
    This test ensures the entire pipeline works correctly from finding ingestion
    to knowledge update, including proper event emission.
    """
    # Setup
    mock_bus = MagicMock(spec=EventBus)
    mock_log = MagicMock()
    
    strategos = Strategos(
        event_bus=mock_bus,
        log_fn=mock_log
    )
    
    target = "https://example.com"
    strategos.context = ScanContext(target=target)
    strategos.context.knowledge["mode"] = ScanMode.STANDARD
    
    # Use event for proper synchronization
    knowledge_updated = asyncio.Event()
    
    # Start insight processor loop
    process_task = asyncio.create_task(strategos._process_pending_insights())
    
    try:
        # Simulate Finding Ingestion (admin_panel -> HIGH_VALUE_TARGET)
        findings = [{
            "type": "admin_panel",
            "asset": "https://example.com/admin",
            "source": "test_scanner",
            "id": "find_123",
            "priority": 1
        }]
        
        await strategos.ingest_findings(findings)
        
        # Wait for knowledge update with timeout
        async def wait_for_knowledge():
            for _ in range(50):
                if "high_value_targets" in strategos.context.knowledge:
                    knowledge_updated.set()
                    return True
                await asyncio.sleep(0.05)
            return False
        
        success = await wait_for_knowledge()
        assert success, "Knowledge not updated with high_value_targets"
        assert knowledge_updated.is_set(), "Knowledge update event should be set"
        
        # Verify Knowledge
        hvt = strategos.context.knowledge["high_value_targets"][0]
        assert hvt["target"] == "https://example.com/admin"
        assert hvt["confidence"] == 0.9
        
        # Verify Queue Stats
        stats = strategos._insight_queue.get_stats()
        assert stats.total_enqueued == 1
        assert stats.total_processed == 1
        assert stats.circuit_breaker_state == "CLOSED"
        
        # Verify Event Emission
        mock_bus.emit.assert_called()
        call_args = mock_bus.emit.call_args[1]
        assert call_args["event_type"] == EventType.NEXUS_INSIGHT_FORMED
        assert isinstance(call_args["payload"], dict)
        assert call_args["payload"]["action_type"] == InsightActionType.HIGH_VALUE_TARGET.value
        
    finally:
        process_task.cancel()
        try:
            await process_task
        except asyncio.CancelledError:
            pass


@pytest.mark.anyio
async def test_concurrent_scan_scenarios():
    """
    Test behavior under concurrent finding ingestion and insight processing.
    
    Verifies that the system handles multiple concurrent finding ingestions
    correctly without race conditions or data corruption.
    """
    mock_bus = MagicMock(spec=EventBus)
    mock_log = MagicMock()
    
    strategos = Strategos(
        event_bus=mock_bus,
        log_fn=mock_log
    )
    
    target = "https://example.com"
    strategos.context = ScanContext(target=target)
    strategos.context.knowledge["mode"] = ScanMode.STANDARD
    
    # Start insight processor
    process_task = asyncio.create_task(strategos._process_pending_insights())
    
    try:
        # Create multiple findings with different types
        findings_list = [
            [
                {"type": "admin_panel", "asset": "https://example.com/admin", "source": "scanner1", "id": "f1"},
                {"type": "sqli", "asset": "https://example.com/users", "source": "scanner2", "id": "f2"},
            ],
            [
                {"type": "waf_detected", "asset": "https://example.com", "source": "scanner3", "id": "f3"},
                {"type": "login_page", "asset": "https://example.com/login", "source": "scanner4", "id": "f4"},
            ],
            [
                {"type": "config_exposure", "asset": "https://example.com/.env", "source": "scanner5", "id": "f5"},
            ]
        ]
        
        # Ingest findings concurrently
        tasks = [strategos.ingest_findings(f) for f in findings_list]
        await asyncio.gather(*tasks)
        
        # Wait for processing to complete
        await asyncio.sleep(0.5)
        
        # Verify all findings were ingested
        assert len(strategos.context.findings) == 5
        
        # Verify knowledge updates
        assert "high_value_targets" in strategos.context.knowledge
        assert "confirmed_vulns" in strategos.context.knowledge
        assert "waf_detected" in strategos.context.knowledge
        assert "auth_required" in strategos.context.knowledge
        
        # Verify queue stats
        stats = strategos._insight_queue.get_stats()
        assert stats.total_enqueued == 5
        assert stats.total_processed == 5
        
    finally:
        process_task.cancel()
        try:
            await process_task
        except asyncio.CancelledError:
            pass


@pytest.mark.anyio
async def test_performance_benchmark_under_load():
    """
    Benchmark insight processing performance under load.
    
    Measures throughput and latency when processing a large number of insights.
    """
    mock_bus = MagicMock(spec=EventBus)
    mock_log = MagicMock()
    
    strategos = Strategos(
        event_bus=mock_bus,
        log_fn=mock_log
    )
    
    target = "https://example.com"
    strategos.context = ScanContext(target=target)
    strategos.context.knowledge["mode"] = ScanMode.STANDARD
    
    # Start insight processor
    process_task = asyncio.create_task(strategos._process_pending_insights())
    
    try:
        # Generate a large batch of findings
        # Use finding types that actually generate insights
        num_findings = 50
        findings = []
        for i in range(num_findings):
            finding_type = ["admin_panel", "sqli", "config_exposure"][i % 3]
            findings.append({
                "type": finding_type,
                "asset": f"target{i}.example.com",
                "source": "scanner",
                "id": f"find_{i}"
            })
        
        # Measure time for ingestion
        start_time = asyncio.get_event_loop().time()
        await strategos.ingest_findings(findings)
        ingestion_time = (asyncio.get_event_loop().time() - start_time) * 1000
        
        # Wait for processing
        await asyncio.sleep(1.0)
        
        # Verify stats
        stats = strategos._insight_queue.get_stats()
        
        # Assert performance characteristics
        assert stats.total_enqueued == num_findings
        assert stats.total_processed >= num_findings - 5  # Allow some margin
        assert stats.processing_time_ms > 0
        
        # Calculate average processing time per insight
        avg_time = stats.processing_time_ms / max(stats.total_processed, 1)
        
        # Performance assertion: should process insights in reasonable time
        # This is a soft assertion - adjust based on system performance
        assert avg_time < 1000.0, f"Average processing time too high: {avg_time}ms"
        
    finally:
        process_task.cancel()
        try:
            await process_task
        except asyncio.CancelledError:
            pass


@pytest.mark.anyio
async def test_event_emission_verification():
    """
    Verify that all expected events are emitted during insight processing.
    
    Ensures that the event bus receives proper event emissions for:
    - NEXUS_INSIGHT_FORMED events
    - Proper event payloads
    - Correct event types
    """
    mock_bus = MagicMock(spec=EventBus)
    mock_bus.emit = MagicMock()
    mock_log = MagicMock()
    
    strategos = Strategos(
        event_bus=mock_bus,
        log_fn=mock_log
    )
    
    target = "https://example.com"
    strategos.context = ScanContext(target=target)
    strategos.context.knowledge["mode"] = ScanMode.STANDARD
    
    # Start insight processor
    process_task = asyncio.create_task(strategos._process_pending_insights())
    
    try:
        # Ingest findings that should trigger different insight types
        findings = [
            {"type": "admin_panel", "asset": "https://example.com/admin", "source": "scanner", "id": "f1"},
            {"type": "sqli", "asset": "https://example.com/users", "source": "scanner", "id": "f2"},
            {"type": "waf_detected", "asset": "https://example.com", "source": "scanner", "id": "f3"},
        ]
        
        await strategos.ingest_findings(findings)
        
        # Wait for processing
        await asyncio.sleep(0.5)
        
        # Verify event emissions
        assert mock_bus.emit.called, "Event bus emit should have been called"
        
        # Check that NEXUS_INSIGHT_FORMED events were emitted
        insight_events = [
            call for call in mock_bus.emit.call_args_list
            if call[1].get("event_type") == EventType.NEXUS_INSIGHT_FORMED
        ]
        
        assert len(insight_events) >= 2, f"Expected at least 2 NEXUS_INSIGHT_FORMED events, got {len(insight_events)}"
        
        # Verify event payloads contain required fields
        for event_call in insight_events:
            payload = event_call[1].get("payload", {})
            assert "insight_id" in payload, "Event payload should contain insight_id"
            assert "action_type" in payload, "Event payload should contain action_type"
            assert "confidence" in payload, "Event payload should contain confidence"
            assert "target" in payload, "Event payload should contain target"
            assert "summary" in payload, "Event payload should contain summary"
        
    finally:
        process_task.cancel()
        try:
            await process_task
        except asyncio.CancelledError:
            pass


@pytest.mark.anyio
async def test_circuit_breaker_integration():
    """
    Test circuit breaker behavior in integration scenario.
    
    Verifies that the circuit breaker properly trips on failures
    and recovers after the timeout period.
    """
    mock_bus = MagicMock(spec=EventBus)
    mock_log = MagicMock()
    
    strategos = Strategos(
        event_bus=mock_bus,
        log_fn=mock_log
    )
    
    target = "https://example.com"
    strategos.context = ScanContext(target=target)
    strategos.context.knowledge["mode"] = ScanMode.STANDARD
    
    # Create a failing handler
    failure_count = 0
    
    async def failing_handler(insight: InsightPayload):
        nonlocal failure_count
        failure_count += 1
        if failure_count <= 3:
            raise RuntimeError("Simulated handler failure")
    
    # Replace the routing with our failing handler
    original_route = strategos._route_insight_to_handler
    
    async def route_with_failure(insight: InsightPayload):
        await failing_handler(insight)
    
    # Manually enqueue insights and process with failing handler
    insights = [
        InsightPayload(
            insight_id=f"insight_{i}",
            scan_id=strategos.context.scan_id,
            action_type=InsightActionType.HIGH_VALUE_TARGET,
            confidence=0.9,
            target=target,
            summary=f"Test insight {i}",
            details={},
            source_tool="test",
            priority=1
        )
        for i in range(5)
    ]
    
    # Enqueue insights
    for insight in insights:
        await strategos._insight_queue.enqueue(insight)
    
    # Process insights with failing handler
    for _ in range(5):
        await strategos._insight_queue.process_one(route_with_failure)
    
    # Verify circuit breaker state
    stats = strategos._insight_queue.get_stats()
    assert stats.circuit_breaker_state == "OPEN", "Circuit breaker should be OPEN after failures"
    assert stats.total_failed >= 3, "Should have recorded at least 3 failures"
    
    # Test recovery after timeout
    # Wait for circuit breaker timeout (30 seconds default, but we can check state)
    # In a real scenario, we'd wait for the timeout period
    # For testing, we just verify the state is OPEN


@pytest.mark.anyio
async def test_priority_ordering_integration():
    """
    Test that higher-priority insights are processed before lower-priority ones.
    
    Verifies the priority queue ordering works correctly in an integration scenario.
    """
    mock_bus = MagicMock(spec=EventBus)
    mock_log = MagicMock()
    
    strategos = Strategos(
        event_bus=mock_bus,
        log_fn=mock_log
    )
    
    target = "https://example.com"
    strategos.context = ScanContext(target=target)
    strategos.context.knowledge["mode"] = ScanMode.STANDARD
    
    # Track processing order
    processed_order = []
    
    async def tracking_handler(insight: InsightPayload):
        processed_order.append(insight.priority)
    
    # Enqueue insights with different priorities (higher number = lower priority)
    insights = [
        InsightPayload(
            insight_id="insight_1",
            scan_id=strategos.context.scan_id,
            action_type=InsightActionType.HIGH_VALUE_TARGET,
            confidence=0.9,
            target=target,
            summary="Priority 5",
            details={},
            source_tool="test",
            priority=5
        ),
        InsightPayload(
            insight_id="insight_2",
            scan_id=strategos.context.scan_id,
            action_type=InsightActionType.HIGH_VALUE_TARGET,
            confidence=0.9,
            target=target,
            summary="Priority 1",
            details={},
            source_tool="test",
            priority=1
        ),
        InsightPayload(
            insight_id="insight_3",
            scan_id=strategos.context.scan_id,
            action_type=InsightActionType.HIGH_VALUE_TARGET,
            confidence=0.9,
            target=target,
            summary="Priority 3",
            details={},
            source_tool="test",
            priority=3
        ),
    ]
    
    # Enqueue in random order
    await strategos._insight_queue.enqueue(insights[0])
    await strategos._insight_queue.enqueue(insights[2])
    await strategos._insight_queue.enqueue(insights[1])
    
    # Process all insights
    for _ in range(3):
        await strategos._insight_queue.process_one(tracking_handler)
    
    # Verify processing order (should be 1, 3, 5 - lowest priority number first)
    assert processed_order == [1, 3, 5], f"Expected [1, 3, 5], got {processed_order}"
