"""
Cronus: Temporal Budget Enforcement Layer

CronusManager coordinates per-scan CronusSession instances.
CronusSession enforces time + findings budget constraints.
"""

from __future__ import annotations

import inspect
import logging
import time
from typing import Any, Callable, Dict, Optional, Sequence

from core.contracts.budget import Budget, BudgetOverrun
from core.contracts.events import EventType
from core.cortex.events import EventBus, GraphEvent, get_event_bus

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
        """
        Raises BudgetOverrun if budget is exceeded.
        """
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
            # Shutdown should not explode the process
            pass


# ---------------------------------------------------------------------------
# EventBus subscribe adapter (signature-safe)
# ---------------------------------------------------------------------------

def _subscribe(bus: EventBus, event_type: Any, handler: Callable[[GraphEvent], None]) -> None:
    """
    Sentinel has evolved EventBus.subscribe a few times. We adapt safely.

    Supported shapes:
      - subscribe(handler, [event_type])
      - subscribe(handler, event_type)
      - subscribe([event_type], handler)
      - subscribe(event_type, handler)
      - subscribe(handler, event_type1, event_type2, ...)
    """
    sub = getattr(bus, "subscribe", None)
    if sub is None:
        raise RuntimeError("EventBus has no subscribe() method")

    # Inspect signature to infer argument ordering.
    try:
        sig = inspect.signature(sub)
        params = list(sig.parameters.values())

        # Drop 'self' if present (bound method usually won't show it, but be safe)
        if params and params[0].name == "self":
            params = params[1:]

        # Heuristic: if first param is named like handler/callback, assume handler-first.
        first_name = params[0].name if params else ""
        handler_first = first_name in {"handler", "callback", "fn", "listener", "subscriber"}

        # Another heuristic: if any param is named event_types, prefer that placement.
        names = {p.name for p in params}
        if "event_types" in names:
            # If first param isn't handler-ish, likely (event_types, handler)
            if not handler_first:
                handler_first = False
            else:
                handler_first = True

        if handler_first:
            # try (handler, [event_type]) first
            try:
                sub(handler, [event_type])
                return
            except TypeError:
                # try (handler, event_type)
                try:
                    sub(handler, event_type)
                    return
                except TypeError:
                    # try varargs: (handler, event_type)
                    sub(handler, event_type)
                    return
        else:
            # try ([event_type], handler) first
            try:
                sub([event_type], handler)
                return
            except TypeError:
                # try (event_type, handler)
                sub(event_type, handler)
                return

    except Exception:
        # Last-ditch fallback: most common in this codebase has been (handler, [event_type])
        try:
            sub(handler, [event_type])
        except TypeError:
            # Alternate common form: (event_type, handler)
            sub(event_type, handler)


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

    @classmethod
    def start(cls) -> None:
        if cls._started:
            return

        cls._bus = get_event_bus()

        # Subscribe using signature-safe adapter
        _subscribe(cls._bus, EventType.SCAN_STARTED, cls._on_scan_started)
        _subscribe(cls._bus, EventType.SCAN_COMPLETED, cls._on_scan_completed)
        _subscribe(cls._bus, EventType.TOOL_STARTED, cls._on_tool_started)
        _subscribe(cls._bus, EventType.TOOL_COMPLETED, cls._on_tool_completed)

        cls._started = True
        logger.info("[CronusManager] Started and subscribed to EventBus")

    @classmethod
    def shutdown(cls) -> None:
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

        budget = payload.get("budget")
        if not isinstance(budget, Budget):
            logger.warning(
                "[CronusManager] SCAN_STARTED missing Budget; skipping CronusSession",
                extra={"scan_id": scan_id},
            )
            return

        cls._sessions[scan_id] = CronusSession(scan_id, budget)
        logger.info("[CronusManager] CronusSession created", extra={"scan_id": scan_id})

    @classmethod
    def _on_scan_completed(cls, event: GraphEvent) -> None:
        session = cls._sessions.pop(event.scan_id, None)
        if session:
            session.shutdown()
            logger.info("[CronusManager] CronusSession closed", extra={"scan_id": event.scan_id})

    @classmethod
    def _on_tool_started(cls, event: GraphEvent) -> None:
        session = cls._sessions.get(event.scan_id)
        if not session:
            return

        tool = (event.payload or {}).get("tool")
        if isinstance(tool, str) and tool:
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
        findings_raw = payload.get("findings", 0)

        try:
            findings = int(findings_raw or 0)
        except Exception:
            findings = 0

        if isinstance(tool, str) and tool:
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
        if not cls._bus:
            return

        # Prefer a dedicated event type if it exists; otherwise fall back to CONTRACT_VIOLATION.
        event_type = getattr(EventType, "BUDGET_OVERRUN", None) or getattr(EventType, "CONTRACT_VIOLATION")

        payload = {
            "resource": getattr(error, "resource", "unknown"),
            "used": getattr(error, "used", None),
            "limit": getattr(error, "limit", None),
            "message": str(error),
        }

        try:
            evt = GraphEvent(event_type=event_type, scan_id=scan_id, payload=payload)
            cls._bus.emit(evt)
        except Exception:
            # Never let violation reporting take down the engine
            logger.exception("[CronusManager] Failed to emit budget violation", extra={"scan_id": scan_id})