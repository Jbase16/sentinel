# core/cronus/manager.py

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
from core.cortex.events import EventBus, GraphEvent, get_event_bus
from core.cortex.subscriptions import SubscriptionHandle, subscribe_safe

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
# Cronus Manager (Coordinator)
# ---------------------------------------------------------------------------

class CronusManager:
    """
    Coordinator for Cronus sessions.

    Responsibilities:
    - Create per-scan CronusSession on SCAN_STARTED
    - Enforce budgets on tool lifecycle events
    - Tear down sessions on SCAN_COMPLETED
    """

    _sessions: Dict[str, CronusSession] = {}
    _bus: Optional[EventBus] = None
    _started: bool = False

    _subs: list[SubscriptionHandle] = []

    @classmethod
    def start(cls) -> None:
        if cls._started:
            return

        cls._bus = get_event_bus()

        # Subscribe using the single enforced entrypoint
        cls._subs = [
            subscribe_safe(cls._bus, cls._on_scan_started, event_types=[EventType.SCAN_STARTED], name="cronus.scan_started"),
            subscribe_safe(cls._bus, cls._on_scan_completed, event_types=[EventType.SCAN_COMPLETED], name="cronus.scan_completed"),
            subscribe_safe(cls._bus, cls._on_tool_started, event_types=[EventType.TOOL_STARTED], name="cronus.tool_started"),
            subscribe_safe(cls._bus, cls._on_tool_completed, event_types=[EventType.TOOL_COMPLETED], name="cronus.tool_completed"),
        ]

        cls._started = True
        logger.info("[CronusManager] Started and subscribed to EventBus")

    @classmethod
    def shutdown(cls) -> None:
        for session in list(cls._sessions.values()):
            session.shutdown()
        cls._sessions.clear()

        for sub in cls._subs:
            try:
                sub.unsubscribe()
            except Exception:
                pass
        cls._subs = []

        cls._started = False
        logger.info("[CronusManager] Shutdown complete")

    # ------------------------------------------------------------------
    # Event handlers
    # ------------------------------------------------------------------

    @classmethod
    async def _on_scan_started(cls, event: GraphEvent) -> None:
        scan_id = getattr(event, "scan_id", None) or (event.payload or {}).get("scan_id") or (event.payload or {}).get("session_id")
        payload = event.payload or {}

        budget = payload.get("budget")
        if not isinstance(budget, Budget):
            # Config drift fix: create a sane default Budget instead of skipping.
            # Without this, Cronus is silently disabled for every scan that doesn't
            # explicitly pass a Budget in the SCAN_STARTED event payload.
            logger.info(
                "[CronusManager] SCAN_STARTED missing Budget; using default (900s, 500 findings)",
                extra={"scan_id": scan_id},
            )
            budget = Budget(max_time_ms=900_000)  # 15 min default, 500 findings default

        if not scan_id:
            logger.warning("[CronusManager] SCAN_STARTED missing scan_id; skipping CronusSession")
            return

        cls._sessions[scan_id] = CronusSession(scan_id, budget)
        logger.info("[CronusManager] CronusSession created", extra={"scan_id": scan_id})

    @classmethod
    async def _on_scan_completed(cls, event: GraphEvent) -> None:
        scan_id = getattr(event, "scan_id", None) or (event.payload or {}).get("scan_id") or (event.payload or {}).get("session_id")
        if not scan_id:
            return

        session = cls._sessions.pop(scan_id, None)
        if session:
            session.shutdown()
            logger.info("[CronusManager] CronusSession closed", extra={"scan_id": scan_id})

    @classmethod
    async def _on_tool_started(cls, event: GraphEvent) -> None:
        scan_id = getattr(event, "scan_id", None) or (event.payload or {}).get("scan_id") or (event.payload or {}).get("session_id")
        if not scan_id:
            return

        session = cls._sessions.get(scan_id)
        if not session:
            return

        tool = (event.payload or {}).get("tool")
        if isinstance(tool, str) and tool:
            try:
                session.on_tool_started(tool)
            except BudgetOverrun as e:
                logger.error("[CronusManager] Budget overrun on tool start", extra={"scan_id": scan_id})
                cls._emit_budget_violation(scan_id, e)

    @classmethod
    async def _on_tool_completed(cls, event: GraphEvent) -> None:
        scan_id = getattr(event, "scan_id", None) or (event.payload or {}).get("scan_id") or (event.payload or {}).get("session_id")
        if not scan_id:
            return

        session = cls._sessions.get(scan_id)
        if not session:
            return

        payload = event.payload or {}
        tool = payload.get("tool")
        findings_raw = payload.get("findings", 0)

        try:
            findings = int(findings_raw or 0)
        except Exception:
            findings = 0

        if isinstance(tool, str) and tool:
            try:
                session.on_tool_completed(tool, findings)
            except BudgetOverrun as e:
                logger.error("[CronusManager] Budget overrun on tool completion", extra={"scan_id": scan_id})
                cls._emit_budget_violation(scan_id, e)

    # ------------------------------------------------------------------
    # Violations
    # ------------------------------------------------------------------

    @classmethod
    def _emit_budget_violation(cls, scan_id: str, error: BudgetOverrun) -> None:
        if not cls._bus:
            return

        event_type = getattr(EventType, "BUDGET_OVERRUN", None) or getattr(EventType, "CONTRACT_VIOLATION")

        payload = {
            "resource": getattr(error, "resource", "unknown"),
            "used": getattr(error, "used", None),
            "limit": getattr(error, "limit", None),
            "message": str(error),
        }

        try:
            # GraphEvent signature varies; safest is the fields used elsewhere in your codebase:
            cls._bus.emit(GraphEvent(type=event_type, payload={"scan_id": scan_id, **payload}))
        except Exception:
            logger.exception("[CronusManager] Failed to emit budget violation", extra={"scan_id": scan_id})