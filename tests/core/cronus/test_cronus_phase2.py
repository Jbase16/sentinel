"""
tests/core/cronus/test_cronus_phase2.py
Verification suite for Cronus (Phase 2).

CronusManager is a classmethod-based singleton. Tests must use the class
methods directly and clean up class-level state between runs.
"""

import asyncio
import pytest
import time
from unittest.mock import MagicMock, patch
from core.cronus.manager import CronusManager, CronusSession
from core.contracts.budget import Budget
from core.contracts.events import EventType
from core.cortex.events import GraphEvent, reset_event_sequence


@pytest.fixture(autouse=True)
def reset_cronus():
    """Reset CronusManager class-level state before and after each test."""
    reset_event_sequence()
    CronusManager._sessions = {}
    CronusManager._started = False
    CronusManager._subs = []
    CronusManager._bus = None
    yield
    CronusManager._sessions = {}
    CronusManager._started = False
    CronusManager._subs = []
    CronusManager._bus = None


def _run(coro):
    """Helper: run an async coroutine synchronously."""
    return asyncio.run(coro)


def test_cronus_lifecycle():
    id_a = "scan-A"

    # Directly invoke the async event handlers (bypassing EventBus subscription)
    _run(CronusManager._on_scan_started(
        GraphEvent(type=EventType.SCAN_STARTED, payload={"session_id": id_a})
    ))
    assert id_a in CronusManager._sessions

    _run(CronusManager._on_scan_completed(
        GraphEvent(type=EventType.SCAN_COMPLETED, payload={"session_id": id_a})
    ))
    assert id_a not in CronusManager._sessions


def test_budget_finding_limit():
    id_a = "scan-budget-test"

    _run(CronusManager._on_scan_started(
        GraphEvent(type=EventType.SCAN_STARTED, payload={"session_id": id_a})
    ))
    session = CronusManager._sessions[id_a]

    # Reduce budget for test
    session.budget = Budget(max_time_ms=900_000, max_findings=5)

    # Wire up a mock bus so _emit_budget_violation can emit
    mock_bus = MagicMock()
    mock_bus.emit = MagicMock()
    CronusManager._bus = mock_bus

    # Add 5 findings (OK — tool_completed with findings_count)
    _run(CronusManager._on_tool_completed(
        GraphEvent(
            type=EventType.TOOL_COMPLETED,
            payload={"scan_id": id_a, "tool": "fast-tool", "findings": 5}
        )
    ))

    # Add 1 more (should trip budget)
    _run(CronusManager._on_tool_completed(
        GraphEvent(
            type=EventType.TOOL_COMPLETED,
            payload={"scan_id": id_a, "tool": "fail-tool", "findings": 1}
        )
    ))

    # Verify budget violation was emitted
    calls = mock_bus.emit.call_args_list
    assert len(calls) >= 1, "Expected at least one budget violation event"
    # The violation payload should mention findings/budget
    payload_str = str(calls[0])
    assert "findings" in payload_str.lower() or "budget" in payload_str.lower() or "overrun" in payload_str.lower()


def test_budget_time_limit():
    id_a = "scan-time-test"

    _run(CronusManager._on_scan_started(
        GraphEvent(type=EventType.SCAN_STARTED, payload={"session_id": id_a})
    ))
    session = CronusManager._sessions[id_a]

    # Artificial time limit: 100ms
    session.budget = Budget(max_time_ms=100)

    # Wire up mock bus
    mock_bus = MagicMock()
    mock_bus.emit = MagicMock()
    CronusManager._bus = mock_bus

    time.sleep(0.2)  # Sleep 200ms to exceed 100ms budget

    # Any action should trigger time check
    _run(CronusManager._on_tool_started(
        GraphEvent(
            type=EventType.TOOL_STARTED,
            payload={"scan_id": id_a, "tool": "slow-tool"}
        )
    ))

    # Verify budget violation
    calls = mock_bus.emit.call_args_list
    assert len(calls) >= 1, "Expected budget overrun event for time_ms"
    payload_str = str(calls[0])
    assert "time" in payload_str.lower() or "overrun" in payload_str.lower()
