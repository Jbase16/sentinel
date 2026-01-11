
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
        
        # 3. Wait for processing (allow loop to cycle)
        # We poll for the side effect: knowledge update
        
        async def wait_for_knowledge():
            for i in range(50):
                if "high_value_targets" in strategos.context.knowledge:
                    return True
                await asyncio.sleep(0.05)
            # Debug info
            print(f"DEBUG: Knowledge keys: {strategos.context.knowledge.keys()}")
            print(f"DEBUG: Queue stats: {strategos._insight_queue.get_stats()}")
            print("DEBUG: Logs captured:")
            for call in mock_log.call_args_list:
                print(f"  LOG: {call}")
            return False
            
        success = await wait_for_knowledge()
        assert success, "Knowledge not updated with high_value_targets"
        
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
