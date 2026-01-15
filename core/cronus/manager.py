"""
Cronus: Temporal Budget Enforcement Layer

CronusManager coordinates per-scan CronusSession instances.
CronusSession enforces time + findings budget constraints.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Dict, Optional

from core.contracts.budget import Budget, BudgetOverrun
from core.contracts.events import EventType
from core.cortex.events import EventBus, GraphEvent, get_event_bus, SubscriptionHandle

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Cronus Session
# ---------------------------------------------------------------------------

class CronusSession:
    """
    Per-scan session for Cronus.

    Responsibilities:
    1. Holds the immutable Budget.
    2. Tracks wall-clock time consumption.
    3. Authorizes or denies actions based on remaining budget.
    """

    def __init__(self, scan_id: str, budget: Budget):
        self.scan_id = scan_id
        self.budget = budget
        self.start_time = time.time()
        self.active_tools: Dict[str, float] = {}
        self._last_check_time = self.start_time

    def _consume_time(self) -> None:
        now = time.time()
        elapsed_ms = (now - self._last_check_time) * 1000.0
        if elapsed_ms > 0:
            self.budget.consume("time_ms", elapsed_ms)
            self._last_check_time = now

    def check_budget_precondition(self, cost_findings: int = 0) -> None:
        self._consume_time()
        if cost_findings > 0:
            self.budget.consume("findings", cost_findings)

    def on_tool_started(self, tool: str) -> None:
        self.check_budget_precondition()
        self.active_tools[tool] = time.time()

    def on_tool_completed(self, tool: str, findings_count: int) -> None:
        self.active_tools.pop(tool, None)
        self.check_budget_precondition(cost_findings=findings_count)

    def shutdown(self) -> None:
        try:
            self._consume_time()
        except BudgetOverrun:
            pass


# ---------------------------------------------------------------------------
# Cronus Manager
# ---------------------------------------------------------------------------

class CronusManager:
    """
    Coordinator for Cronus sessions.

    Responsibilities:
    - Create per-scan CronusSession on SCAN_STARTED
    - Enforce budgets on tool lifecycle events
    - Tear down sessions on SCAN_COMPLETED
    """

    _bus: Optional[EventBus] = None
    _sessions: Dict[str, CronusSession] = {}
    _subscriptions: list[SubscriptionHandle] = []
    _started: bool = False

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    @classmethod
    def start(cls) -> None:
        if cls._started:
            return

        cls._bus = get_event_bus()

        cls._subscriptions = [
            cls._bus.subscribe_sync(cls._on_scan_started, [EventType.SCAN_STARTED], name="cronus.scan_started"),
            cls._bus.subscribe_sync(cls._on_scan_completed, [EventType.SCAN_COMPLETED], name="cronus.scan_completed"),
            cls._bus.subscribe_sync(cls._on_tool_started, [EventType.TOOL_STARTED], name="cronus.tool_started"),
            cls._bus.subscribe_sync(cls._on_tool_completed, [EventType.TOOL_COMPLETED], name="cronus.tool_completed"),
        ]

        cls._started = True
        logger.info("[CronusManager] Started and subscribed to EventBus")

    @classmethod
    def shutdown(cls) -> None:
        for sub in cls._subscriptions:
            sub.unsubscribe()
        cls._subscriptions.clear()

        for session in list(cls._sessions.values()):
            session.shutdown()
        cls._sessions.clear()

        cls._started = False
        logger.info("[CronusManager] Shutdown complete")

    # ------------------------------------------------------------------
    # Event handlers
    # ------------------------------------------------------------------

    @classmethod
    def _on_scan_started(cls, event: GraphEvent) -> None:
        scan_id = event.scan_id
        payload = event.payload or {}

        if not scan_id:
            return

        budget = payload.get("budget")
        if not isinstance(budget, Budget):
            logger.debug(
                "[CronusManager] SCAN_STARTED without Budget; Cronus disabled for scan",
                extra={"scan_id": scan_id},
            )
            return

        cls._sessions[scan_id] = CronusSession(scan_id, budget)
        logger.info("[CronusManager] CronusSession created", extra={"scan_id": scan_id})

    @classmethod
    def _on_scan_completed(cls, event: GraphEvent) -> None:
        scan_id = event.scan_id
        if not scan_id:
            return

        session = cls._sessions.pop(scan_id, None)
        if session:
            session.shutdown()
            logger.info("[CronusManager] CronusSession closed", extra={"scan_id": scan_id})

    @classmethod
    def _on_tool_started(cls, event: GraphEvent) -> None:
        session = cls._sessions.get(event.scan_id)
        if not session:
            return

        tool = (event.payload or {}).get("tool")
        if not isinstance(tool, str) or not tool:
            return

        try:
            session.on_tool_started(tool)
        except BudgetOverrun as e:
            logger.error("[CronusManager] Budget overrun on tool start", extra={"scan_id": event.scan_id})
            cls._emit_budget_violation(event.scan_id, e)

    @classmethod
    def _on_tool_completed(cls, event: GraphEvent) -> None:
        session = cls._sessions.get(event.scan_id)
        if not session:
            return

        payload = event.payload or {}
        tool = payload.get("tool")
        findings = payload.get("findings_count", 0)

        try:
            findings = int(findings or 0)
        except Exception:
            findings = 0

        if not isinstance(tool, str) or not tool:
            return

        try:
            session.on_tool_completed(tool, findings)
        except BudgetOverrun as e:
            logger.error("[CronusManager] Budget overrun on tool completion", extra={"scan_id": event.scan_id})
            cls._emit_budget_violation(event.scan_id, e)

    # ------------------------------------------------------------------
    # Violations
    # ------------------------------------------------------------------

    @classmethod
    def _emit_budget_violation(cls, scan_id: str, error: BudgetOverrun) -> None:
        if not cls._bus or not scan_id:
            return

        event_type = getattr(EventType, "BUDGET_OVERRUN", EventType.CONTRACT_VIOLATION)

        payload: Dict[str, Any] = {
            "scan_id": scan_id,
            "resource": getattr(error, "resource", "unknown"),
            "used": getattr(error, "used", None),
            "limit": getattr(error, "limit", None),
            "message": str(error),
        }

        try:
            cls._bus.emit(
                GraphEvent(
                    type=event_type,
                    payload=payload,
                    scan_id=scan_id,
                    source="cronus",
                    priority=0,
                )
            )
        except Exception:
            logger.exception("[CronusManager] Failed to emit budget violation", extra={"scan_id": scan_id})