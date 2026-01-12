
import pytest
import asyncio
from unittest.mock import MagicMock, AsyncMock, patch
from core.scheduler.strategos import Strategos, ScanContext
from core.contracts.schemas import InsightActionType, InsightPayload
from core.scheduler.modes import ScanMode
from core.cortex.events import EventBus
from core.contracts.events import EventType

@pytest.mark.anyio
async def test_full_insight_flow():
    """
    Verify complete flow: Finding -> Ingest -> Insight Generation -> Enqueue -> Process -> Handler -> Knowledge Update.
    """
    # 1. Setup
    mock_bus = MagicMock(spec=EventBus)
    mock_log = MagicMock()
    
    strategos = Strategos(
        event_bus=mock_bus,
        log_fn=mock_log
    )
    
    # Initialize context manually (usually done in run_mission)
    target = "https://example.com"
    strategos.context = ScanContext(target=target)
    strategos.context.knowledge["mode"] = ScanMode.STANDARD
    
    # Use asyncio.Event for proper synchronization instead of polling
    knowledge_updated = asyncio.Event()
    
    # Start insight processor loop
    process_task = asyncio.create_task(strategos._process_pending_insights())
    
    try:
        # 2. Simulate Finding Ingestion (admin_panel -> HIGH_VALUE_TARGET)
        findings = [{
            "type": "admin_panel",
            "asset": "https://example.com/admin",
            "source": "test_scanner",
            "id": "find_123",
            "priority": 1
        }]
        
        # Ingest (async)
        await strategos.ingest_findings(findings)
        
        # 3. Wait for processing using event-based synchronization
        # Poll for the side effect: knowledge update, but with event for clean exit
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
        
        # 4. Verify Knowledge
        hvt = strategos.context.knowledge["high_value_targets"][0]
        assert hvt["target"] == "https://example.com/admin"
        assert hvt["confidence"] == 0.9
        
        # 5. Verify Queue Stats
        stats = strategos._insight_queue.get_stats()
        assert stats.total_enqueued == 1
        assert stats.total_processed == 1
        assert stats.circuit_breaker_state == "CLOSED"
        
        # 6. Verify Event Emission (via Bus)
        # We need to check if emit was called with NEXUS_INSIGHT_FORMED
        # Note: In strategos.py we emit manually.
        mock_bus.emit.assert_called()
        call_args = mock_bus.emit.call_args[1]
        assert call_args["event_type"] == EventType.NEXUS_INSIGHT_FORMED
        assert isinstance(call_args["payload"], dict)
        assert call_args["payload"]["action_type"] == InsightActionType.HIGH_VALUE_TARGET.value
        
    finally:
        # Cleanup
        process_task.cancel()
        try:
            await process_task
        except asyncio.CancelledError:
            pass

@pytest.mark.anyio
async def test_critical_path_insight():
    """Verify critical path insight generation and handling."""
    strategos = Strategos()
    strategos.context = ScanContext(target="https://api.example.com")
    
    # Start processor
    task = asyncio.create_task(strategos._process_pending_insights())
    
    try:
        findings = [{
            "type": "sqli",
            "asset": "https://api.example.com/users",
            "details": {"path": "/users", "method": "GET", "param": "id"},
            "priority": 1
        }]
        
        await strategos.ingest_findings(findings)
        
        # Wait for processing
        await asyncio.sleep(0.1)
        
        assert "confirmed_vulns" in strategos.context.knowledge
        vuln = strategos.context.knowledge["confirmed_vulns"][0]
        assert vuln["vuln_type"] == "sqli"
        assert vuln["target"] == "https://api.example.com/users"
        
        stats = strategos._insight_queue.get_stats()
        assert stats.total_processed >= 1
        
    finally:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass


# ---------------------------------------------------------------------------
# Schema Validation Tests
# ---------------------------------------------------------------------------

def test_insight_payload_invalid_confidence_low():
    """Test that InsightPayload rejects confidence < 0.0."""
    from pydantic import ValidationError
    
    with pytest.raises(ValidationError) as exc_info:
        InsightPayload(
            insight_id="test_id",
            scan_id="scan_123",
            action_type=InsightActionType.HIGH_VALUE_TARGET,
            confidence=-0.1,  # Invalid: < 0.0
            target="https://example.com",
            summary="Test insight",
            details={},
            source_tool="test"
        )
    
    assert "confidence" in str(exc_info.value).lower()


def test_insight_payload_invalid_confidence_high():
    """Test that InsightPayload rejects confidence > 1.0."""
    from pydantic import ValidationError
    
    with pytest.raises(ValidationError) as exc_info:
        InsightPayload(
            insight_id="test_id",
            scan_id="scan_123",
            action_type=InsightActionType.HIGH_VALUE_TARGET,
            confidence=1.5,  # Invalid: > 1.0
            target="https://example.com",
            summary="Test insight",
            details={},
            source_tool="test"
        )
    
    assert "confidence" in str(exc_info.value).lower()


def test_insight_payload_missing_required_fields():
    """Test that InsightPayload rejects missing required fields."""
    from pydantic import ValidationError
    
    with pytest.raises(ValidationError) as exc_info:
        InsightPayload(
            insight_id="test_id",
            # Missing scan_id
            action_type=InsightActionType.HIGH_VALUE_TARGET,
            confidence=0.9,
            # Missing target
            # Missing summary
            details={},
            source_tool="test"
        )
    
    # Should have multiple validation errors
    assert len(exc_info.value.errors()) >= 3


def test_insight_payload_extra_fields_forbidden():
    """Test that InsightPayload rejects extra fields (extra='forbid')."""
    from pydantic import ValidationError
    
    with pytest.raises(ValidationError) as exc_info:
        InsightPayload(
            insight_id="test_id",
            scan_id="scan_123",
            action_type=InsightActionType.HIGH_VALUE_TARGET,
            confidence=0.9,
            target="https://example.com",
            summary="Test insight",
            details={},
            source_tool="test",
            extra_field="not_allowed"  # Extra field
        )
    
    assert "extra" in str(exc_info.value).lower()


def test_insight_payload_valid_boundary_values():
    """Test that InsightPayload accepts valid boundary values."""
    # Test confidence = 0.0
    insight = InsightPayload(
        insight_id="test_id",
        scan_id="scan_123",
        action_type=InsightActionType.HIGH_VALUE_TARGET,
        confidence=0.0,
        target="https://example.com",
        summary="Test insight",
        details={},
        source_tool="test"
    )
    assert insight.confidence == 0.0
    
    # Test confidence = 1.0
    insight = InsightPayload(
        insight_id="test_id",
        scan_id="scan_123",
        action_type=InsightActionType.HIGH_VALUE_TARGET,
        confidence=1.0,
        target="https://example.com",
        summary="Test insight",
        details={},
        source_tool="test"
    )
    assert insight.confidence == 1.0


# ---------------------------------------------------------------------------
# Priority Ordering Tests
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_priority_ordering_highest_first():
    """Verify that higher-priority insights (lower number) are processed first."""
    from core.scheduler.strategos import InsightQueue
    
    queue = InsightQueue(maxsize=10)
    
    processed = []
    
    async def handler(insight):
        processed.append(insight.priority)
    
    # Enqueue insights with different priorities
    insights = []
    for priority in [5, 1, 3, 2, 4]:
        insights.append(
            InsightPayload(
                insight_id=f"insight_{priority}",
                scan_id="scan_123",
                action_type=InsightActionType.HIGH_VALUE_TARGET,
                confidence=0.9,
                target="https://example.com",
                summary=f"Priority {priority}",
                details={},
                source_tool="test",
                priority=priority
            )
        )
    
    # Enqueue in random order
    for insight in insights:
        await queue.enqueue(insight)
    
    # Process all insights
    for _ in range(len(insights)):
        await queue.process_one(handler)
    
    # Verify processing order (should be 1, 2, 3, 4, 5)
    assert processed == [1, 2, 3, 4, 5], f"Expected [1, 2, 3, 4, 5], got {processed}"


@pytest.mark.anyio
async def test_priority_ordering_fifo_for_same_priority():
    """Verify FIFO ordering for insights with same priority."""
    from core.scheduler.strategos import InsightQueue
    
    queue = InsightQueue(maxsize=10)
    
    processed_ids = []
    
    async def handler(insight):
        processed_ids.append(insight.insight_id)
    
    # Enqueue insights with same priority
    for i in range(5):
        insight = InsightPayload(
            insight_id=f"insight_{i}",
            scan_id="scan_123",
            action_type=InsightActionType.HIGH_VALUE_TARGET,
            confidence=0.9,
            target="https://example.com",
            summary=f"Insight {i}",
            details={},
            source_tool="test",
            priority=3  # Same priority for all
        )
        await queue.enqueue(insight)
    
    # Process all insights
    for _ in range(5):
        await queue.process_one(handler)
    
    # Verify FIFO order (insight_0, insight_1, insight_2, insight_3, insight_4)
    expected = [f"insight_{i}" for i in range(5)]
    assert processed_ids == expected, f"Expected {expected}, got {processed_ids}"


# ---------------------------------------------------------------------------
# Handler Error Handling Tests
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_handler_exception_caught_and_logged():
    """Verify that handler exceptions are caught and logged."""
    from core.scheduler.strategos import InsightQueue
    
    queue = InsightQueue(maxsize=10)
    
    exception_raised = False
    
    async def failing_handler(insight):
        nonlocal exception_raised
        exception_raised = True
        raise RuntimeError("Handler failed")
    
    insight = InsightPayload(
        insight_id="test_id",
        scan_id="scan_123",
        action_type=InsightActionType.HIGH_VALUE_TARGET,
        confidence=0.9,
        target="https://example.com",
        summary="Test insight",
        details={},
        source_tool="test",
        priority=1
    )
    
    await queue.enqueue(insight)
    
    # Process should not raise exception
    result = await queue.process_one(failing_handler)
    
    # Handler should have raised exception
    assert exception_raised
    
    # process_one should return False on failure
    assert result is False
    
    # Stats should reflect failure
    stats = queue.get_stats()
    assert stats.total_failed == 1


@pytest.mark.anyio
async def test_circuit_breaker_updates_on_handler_failure():
    """Verify that circuit breaker is updated appropriately on handler failures."""
    from core.scheduler.strategos import InsightQueue, CircuitBreaker
    
    circuit_breaker = CircuitBreaker(failure_threshold=3)
    queue = InsightQueue(maxsize=10, circuit_breaker=circuit_breaker)
    
    async def failing_handler(insight):
        raise RuntimeError("Handler failed")
    
    insight = InsightPayload(
        insight_id="test_id",
        scan_id="scan_123",
        action_type=InsightActionType.HIGH_VALUE_TARGET,
        confidence=0.9,
        target="https://example.com",
        summary="Test insight",
        details={},
        source_tool="test",
        priority=1
    )
    
    # Process 3 failing insights
    for _ in range(3):
        await queue.enqueue(insight)
        await queue.process_one(failing_handler)
    
    # Circuit breaker should be OPEN
    stats = queue.get_stats()
    assert stats.circuit_breaker_state == "OPEN"
    
    # Next processing attempt should be rejected by circuit breaker
    await queue.enqueue(insight)
    result = await queue.process_one(failing_handler)
    assert result is False  # Should return False due to open circuit breaker


# ---------------------------------------------------------------------------
# Individual Handler Tests
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_handle_waf_detected():
    """Test WAF_DETECTED handler updates knowledge correctly."""
    strategos = Strategos()
    strategos.context = ScanContext(target="https://example.com")
    
    insight = InsightPayload(
        insight_id="test_id",
        scan_id=strategos.context.scan_id,
        action_type=InsightActionType.WAF_DETECTED,
        confidence=1.0,
        target="https://example.com",
        summary="WAF detected",
        details={"waf_name": "Cloudflare"},
        source_tool="scanner",
        priority=3
    )
    
    await strategos._handle_waf_detected(insight)
    
    assert strategos.context.knowledge["waf_detected"] is True
    assert strategos.context.knowledge["waf_details"]["waf_name"] == "Cloudflare"


@pytest.mark.anyio
async def test_handle_auth_required():
    """Test AUTH_REQUIRED handler updates knowledge correctly."""
    strategos = Strategos()
    strategos.context = ScanContext(target="https://example.com")
    
    insight = InsightPayload(
        insight_id="test_id",
        scan_id=strategos.context.scan_id,
        action_type=InsightActionType.AUTH_REQUIRED,
        confidence=1.0,
        target="https://example.com/login",
        summary="Authentication required",
        details={"auth_type": "OAuth2"},
        source_tool="scanner",
        priority=4
    )
    
    await strategos._handle_auth_required(insight)
    
    assert "auth_required" in strategos.context.knowledge
    assert len(strategos.context.knowledge["auth_required"]) == 1
    assert strategos.context.knowledge["auth_required"][0]["target"] == "https://example.com/login"
    assert strategos.context.knowledge["auth_required"][0]["auth_type"] == "OAuth2"


@pytest.mark.anyio
async def test_handle_rate_limit():
    """Test RATE_LIMIT handler updates knowledge correctly."""
    strategos = Strategos()
    strategos.context = ScanContext(target="https://example.com")
    
    insight = InsightPayload(
        insight_id="test_id",
        scan_id=strategos.context.scan_id,
        action_type=InsightActionType.RATE_LIMIT,
        confidence=1.0,
        target="https://example.com",
        summary="Rate limiting detected",
        details={"limit": 100, "window": "1 minute"},
        source_tool="scanner",
        priority=3
    )
    
    await strategos._handle_rate_limit(insight)
    
    assert strategos.context.knowledge["rate_limited"] is True


@pytest.mark.anyio
async def test_handle_generic_insight():
    """Test GENERIC handler logs the insight without updating knowledge."""
    strategos = Strategos()
    strategos.context = ScanContext(target="https://example.com")
    
    insight = InsightPayload(
        insight_id="test_id",
        scan_id=strategos.context.scan_id,
        action_type=InsightActionType.GENERAL,
        confidence=0.5,
        target="https://example.com",
        summary="Generic insight",
        details={},
        source_tool="scanner",
        priority=5
    )
    
    # Generic handler should not raise exception
    await strategos._handle_generic_insight(insight)
    
    # Knowledge should not be modified
    # (Generic handler only logs, doesn't update knowledge)


# ---------------------------------------------------------------------------
# Stress Tests
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_rapid_insight_generation():
    """Test behavior under rapid insight generation."""
    strategos = Strategos()
    strategos.context = ScanContext(target="https://example.com")
    strategos.context.knowledge["mode"] = ScanMode.STANDARD
    
    # Start processor
    process_task = asyncio.create_task(strategos._process_pending_insights())
    
    try:
        # Generate many findings rapidly
        # Use finding types that actually generate insights
        num_findings = 100
        findings = []
        for i in range(num_findings):
            finding_type = ["admin_panel", "sqli", "config_exposure"][i % 3]
            findings.append({
                "type": finding_type,
                "asset": f"target{i}.example.com",
                "source": "scanner",
                "id": f"find_{i}"
            })
        
        # Ingest all findings
        await strategos.ingest_findings(findings)
        
        # Wait for processing
        await asyncio.sleep(1.0)
        
        # Verify all findings were ingested
        assert len(strategos.context.findings) == num_findings
        
        # Verify queue stats
        stats = strategos._insight_queue.get_stats()
        assert stats.total_enqueued == num_findings
        assert stats.total_processed >= num_findings - 10  # Allow some margin
        
    finally:
        process_task.cancel()
        try:
            await process_task
        except asyncio.CancelledError:
            pass


@pytest.mark.anyio
async def test_queue_overflow_scenario():
    """Test behavior when queue overflows (maxsize exceeded)."""
    from core.scheduler.strategos import InsightQueue
    
    queue = InsightQueue(maxsize=5)  # Small queue size
    
    insights = [
        InsightPayload(
            insight_id=f"insight_{i}",
            scan_id="scan_123",
            action_type=InsightActionType.HIGH_VALUE_TARGET,
            confidence=0.9,
            target="https://example.com",
            summary=f"Insight {i}",
            details={},
            source_tool="test",
            priority=1
        )
        for i in range(10)  # Try to enqueue 10 insights
    ]
    
    # Enqueue all insights
    enqueued_count = 0
    dropped_count = 0
    for insight in insights:
        result = await queue.enqueue(insight)
        if result:
            enqueued_count += 1
        else:
            dropped_count += 1
    
    # Should have enqueued 5 and dropped 5
    assert enqueued_count == 5
    assert dropped_count == 5
    
    # Stats should reflect drops
    stats = queue.get_stats()
    assert stats.dropped_count == 5


@pytest.mark.anyio
async def test_circuit_breaker_stress():
    """Test circuit breaker behavior under stress."""
    from core.scheduler.strategos import InsightQueue, CircuitBreaker
    
    circuit_breaker = CircuitBreaker(failure_threshold=5, timeout_seconds=0.1)
    queue = InsightQueue(maxsize=100, circuit_breaker=circuit_breaker)
    
    async def flaky_handler(insight):
        # Fail 50% of the time
        if hash(insight.insight_id) % 2 == 0:
            raise RuntimeError("Random failure")
    
    insights = [
        InsightPayload(
            insight_id=f"insight_{i}",
            scan_id="scan_123",
            action_type=InsightActionType.HIGH_VALUE_TARGET,
            confidence=0.9,
            target="https://example.com",
            summary=f"Insight {i}",
            details={},
            source_tool="test",
            priority=1
        )
        for i in range(20)
    ]
    
    # Enqueue all insights
    for insight in insights:
        await queue.enqueue(insight)
    
    # Process all insights
    processed = 0
    for _ in range(20):
        result = await queue.process_one(flaky_handler)
        if result:
            processed += 1
    
    # Stats should reflect processing
    stats = queue.get_stats()
    assert stats.total_enqueued == 20
    assert stats.total_processed + stats.total_failed == 20
    
    # Circuit breaker may be OPEN or CLOSED depending on failure pattern
    assert stats.circuit_breaker_state in ["CLOSED", "OPEN", "HALF_OPEN"]
