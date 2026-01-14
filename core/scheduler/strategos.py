#
# PURPOSE:
# High-level strategic planning for security scans. Named after Greek "strategos"
# (military general), this module decides WHAT to scan and WHEN.
#
# WHAT STRATEGOS DOES:
# - Analyzes target to determine appropriate scanning strategy
# - Selects which tools to run based on target characteristics
# - Sequences tool execution for maximum efficiency
# - Adapts strategy based on intermediate findings
# - Manages resource allocation (rate limiting, parallelization)
#
# STRATEGIC DECISIONS:
# - Passive vs. Active: When to stay quiet vs. make noise
# - Breadth vs. Depth: Scan many targets shallowly or few deeply
# - Tool Selection: Use nmap for ports, httpx for web, etc.
# - Timing: Sequential (slow, stealthy) vs. Parallel (fast, noisy)
#
# KEY CONCEPTS:
# - **Strategy**: High-level plan (what and when to scan)
# - **Tactics**: Low-level execution (how to run each tool)
# - **Adaptive Planning**: Adjust strategy based on discoveries
#

"""
core/scheduler/strategos.py
The Mind of the Scanner.
Implements a True Async Agent Loop with Event-Driven Concurrency.

Fixes in this file (only-file changes):
- Per-insight-type circuit breakers (no global shared-fate breaker).
- Insight priority normalization/clamping and stable queue ordering.
- Tool timeout (prevents hung tools from deadlocking the mission).
- Scan cancellation with grace period (soft stop → hard cancel).
- Basic progress tracking via logs + existing event emissions (phase/tool events) when event_bus is present.
- Correct scan_id generation (scan_id != run_id).
- Ensure GraphEvent is imported when emitting raw events.
"""

import asyncio
import logging
from typing import List, Dict, Any, Callable, Awaitable, Optional, Set, Literal, TYPE_CHECKING, Tuple
import time
import itertools
from dataclasses import dataclass, field
from urllib.parse import urlparse
import uuid

# Constitution class replaced by CAL policies loaded into ArbitrationEngine
from core.scheduler.registry import (
    ToolRegistry,
    PHASE_1_PASSIVE,
    PHASE_2_LIGHT,
    PHASE_3_SURFACE,
    PHASE_4_DEEP,
    PHASE_5_HEAVY,
)
from core.scheduler.modes import ScanMode, ModeRegistry
from core.scheduler.intents import (
    INTENT_PASSIVE_RECON,
    INTENT_ACTIVE_LIVE_CHECK,
    INTENT_SURFACE_ENUMERATION,
    INTENT_VULN_SCANNING,
    INTENT_HEAVY_ARTILLERY,
)
from core.scheduler.events import ToolCompletedEvent, MissionTerminatedEvent
from core.cortex.events import EventBus, GraphEvent, get_run_id
from core.contracts.schemas import InsightPayload, InsightActionType, InsightQueueStats
from core.contracts.events import EventType

from core.scheduler.decisions import (
    DecisionContext,
    DecisionLedger,
    DecisionType,
    DecisionPoint,
    create_decision_context,
)
from core.cortex.arbitration import ArbitrationEngine
from core.cortex.policy import ScopePolicy, RiskPolicy, Verdict

if TYPE_CHECKING:
    from core.cortex.narrator import NarratorEngine

logger = logging.getLogger(__name__)

DEFAULT_EVENT_QUEUE_MAXSIZE = 1024

# Tool timeout and cancellation behavior (local-only policy knobs)
DEFAULT_TOOL_TIMEOUT_SECONDS = 300.0  # 5 min safe default; tool-specific overrides if available
DEFAULT_CANCEL_GRACE_SECONDS = 2.5    # short grace before hard-cancel
PROGRESS_LOG_THROTTLE_SECONDS = 0.5   # avoid spam under high event volume


def _clamp_int(value: int, lo: int, hi: int) -> int:
    try:
        v = int(value)
    except Exception:
        v = lo
    if v < lo:
        return lo
    if v > hi:
        return hi
    return v


def _now() -> float:
    return time.time()


@dataclass
class CircuitBreakerState:
    """Immutable state for circuit breaker."""
    state: Literal["CLOSED", "OPEN", "HALF_OPEN"] = "CLOSED"
    failure_count: int = 0
    last_failure_time: float = 0.0
    success_count: int = 0


class CircuitBreaker:
    """
    Circuit breaker for insight processing.

    Note:
      This class remains generic; Strategos now uses *per-action-type* instances
      to avoid global shared-fate failure.
    """

    def __init__(
        self,
        failure_threshold: int = 3,
        timeout_seconds: float = 30.0,
        success_threshold: int = 1,
    ):
        self._state = CircuitBreakerState()
        self._lock = asyncio.Lock()
        self._failure_threshold = int(failure_threshold)
        self._timeout_seconds = float(timeout_seconds)
        self._success_threshold = int(success_threshold)

    async def acquire(self) -> bool:
        """Return True if processing should proceed, False otherwise."""
        async with self._lock:
            if self._state.state == "OPEN":
                if _now() - self._state.last_failure_time > self._timeout_seconds:
                    self._state = CircuitBreakerState(state="HALF_OPEN")
                else:
                    return False
            return True

    async def record_success(self) -> None:
        async with self._lock:
            if self._state.state == "HALF_OPEN":
                self._state.success_count += 1
                if self._state.success_count >= self._success_threshold:
                    self._state = CircuitBreakerState(state="CLOSED")
            else:
                # CLOSED: reset failure count on success
                self._state.failure_count = 0

    async def record_failure(self) -> None:
        async with self._lock:
            self._state.failure_count += 1
            self._state.last_failure_time = _now()

            if self._state.failure_count >= self._failure_threshold:
                self._state = CircuitBreakerState(
                    state="OPEN",
                    last_failure_time=self._state.last_failure_time,
                    failure_count=self._state.failure_count,
                )
                logger.warning(f"[CircuitBreaker] Circuit OPEN - {self._failure_threshold} failures")

    def get_state(self) -> str:
        return self._state.state


class InsightQueue:
    """
    Async priority queue for insight processing.

    Fix: circuit breaker is now per-action-type (no global breaker).
    """

    def __init__(
        self,
        maxsize: int = 100,
        *,
        breaker_factory: Optional[Callable[[], CircuitBreaker]] = None,
    ):
        self._maxsize = int(maxsize)
        self._queue: asyncio.PriorityQueue = asyncio.PriorityQueue(maxsize=self._maxsize)
        self._lock = asyncio.Lock()
        self._counter = itertools.count()  # tie-breaker for stable FIFO among same priority

        self._breaker_factory = breaker_factory or (lambda: CircuitBreaker())
        self._breakers: Dict[InsightActionType, CircuitBreaker] = {}

        self._stats = InsightQueueStats()
        self._last_stats_update = 0.0

    def _get_breaker(self, action_type: InsightActionType) -> CircuitBreaker:
        br = self._breakers.get(action_type)
        if br is None:
            br = self._breaker_factory()
            self._breakers[action_type] = br
        return br

    def _aggregate_breaker_state(self) -> str:
        # Worst-state aggregation: OPEN > HALF_OPEN > CLOSED
        # (keeps InsightQueueStats schema stable without adding new fields)
        states = {br.get_state() for br in self._breakers.values()}
        if "OPEN" in states:
            return "OPEN"
        if "HALF_OPEN" in states:
            return "HALF_OPEN"
        return "CLOSED"

    async def enqueue(self, insight: InsightPayload) -> bool:
        """
        Enqueue an insight for processing.
        Non-blocking: returns False if queue is full.
        """
        async with self._lock:
            if self._queue.qsize() >= self._maxsize:
                self._stats.dropped_count += 1
                self._stats.current_size = self._queue.qsize()
                self._stats.circuit_breaker_state = self._aggregate_breaker_state()
                return False

            # Normalize priority: lower integer = higher priority
            priority = _clamp_int(getattr(insight, "priority", 5), 0, 9)
            count = next(self._counter)
            await self._queue.put((priority, count, insight))

            self._stats.total_enqueued += 1
            self._stats.current_size = self._queue.qsize()
            self._stats.circuit_breaker_state = self._aggregate_breaker_state()
            return True

    async def dequeue(self, timeout: float = 0.1) -> Optional[InsightPayload]:
        try:
            _priority, _count, insight = await asyncio.wait_for(self._queue.get(), timeout=timeout)
            async with self._lock:
                self._stats.current_size = self._queue.qsize()
            return insight
        except asyncio.TimeoutError:
            return None

    async def process_one(self, handler: Callable[[InsightPayload], Awaitable[None]]) -> bool:
        """
        Process a single insight. Returns True if processed successfully.
        """
        insight = await self.dequeue()
        if insight is None:
            return False

        breaker = self._get_breaker(insight.action_type)
        if not await breaker.acquire():
            # breaker open for this action type; requeue with slight deprioritization
            # to avoid tight loops while still preserving the item.
            try:
                insight.priority = _clamp_int(getattr(insight, "priority", 5) + 1, 0, 9)
            except Exception:
                pass
            await self.enqueue(insight)

            async with self._lock:
                self._stats.circuit_breaker_state = self._aggregate_breaker_state()
            return False

        start = asyncio.get_running_loop().time()
        success = False
        failed = False

        try:
            await handler(insight)
            await breaker.record_success()
            success = True
        except Exception as e:
            await breaker.record_failure()
            failed = True
            logger.error(f"[InsightQueue] Failed to process insight {insight.insight_id}: {e}")
        finally:
            duration_ms = (asyncio.get_running_loop().time() - start) * 1000.0
            async with self._lock:
                if success:
                    self._stats.total_processed += 1
                elif failed:
                    self._stats.total_failed += 1
                self._stats.processing_time_ms += duration_ms
                self._stats.current_size = self._queue.qsize()
                self._stats.circuit_breaker_state = self._aggregate_breaker_state()

        return success

    def get_stats(self) -> InsightQueueStats:
        return InsightQueueStats(
            total_enqueued=self._stats.total_enqueued,
            total_processed=self._stats.total_processed,
            total_failed=self._stats.total_failed,
            current_size=self._queue.qsize(),
            dropped_count=self._stats.dropped_count,
            processing_time_ms=self._stats.processing_time_ms,
            circuit_breaker_state=self._aggregate_breaker_state(),
        )


@dataclass
class ScanContext:
    target: str
    # Fix: scan_id must identify the scan, not the runtime.
    scan_id: str = field(default_factory=lambda: uuid.uuid4().hex)

    # Guard mutable state from concurrent access.
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    phase_index: int = 0
    knowledge: Dict[str, Any] = field(default_factory=dict)

    active_tools: int = 0
    max_concurrent: int = 3  # throttling limit

    findings: List[Dict[str, Any]] = field(default_factory=list)
    findings_this_intent: int = 0
    surface_delta_this_intent: int = 0

    running_tools: Set[str] = field(default_factory=set)
    completed_tools_per_intent: Dict[str, Set[str]] = field(default_factory=dict)
    surface_seen: Set[str] = field(default_factory=set)


class Strategos:
    """
    The Strategist.
    A concurrent, event-driven planner with first-class decision tracking.
    """

    def __init__(
        self,
        event_queue_maxsize: int = DEFAULT_EVENT_QUEUE_MAXSIZE,
        log_fn: Optional[Callable[[str], None]] = None,
        event_bus: Optional[EventBus] = None,
        decision_ledger: Optional[DecisionLedger] = None,
        narrator: Optional["NarratorEngine"] = None,
    ):
        self.registry = ToolRegistry()
        self.context: Optional[ScanContext] = None
        self.event_queue: asyncio.Queue = asyncio.Queue(maxsize=event_queue_maxsize)
        self._terminated = False
        self._dispatch_callback: Optional[Callable[[str], Awaitable[List[Dict[str, Any]]]]] = None
        self._tool_tasks: Dict[str, asyncio.Task] = {}
        self._tool_semaphore: Optional[asyncio.Semaphore] = None
        self._log_fn = log_fn
        self._event_bus = event_bus
        self._narrator = narrator

        # Cancellation control (graceful stop)
        self._stop_requested: bool = False
        self._stop_deadline: Optional[float] = None
        self._cancel_grace_seconds: float = DEFAULT_CANCEL_GRACE_SECONDS

        # Progress log throttling
        self._last_progress_log: float = 0.0

        # Insight queue with per-action breakers
        self._insight_queue = InsightQueue(
            maxsize=100,
            breaker_factory=lambda: CircuitBreaker(failure_threshold=3, timeout_seconds=30.0, success_threshold=1),
        )
        self._insight_processor_task: Optional[asyncio.Task] = None

        # Decision emission layer
        self._decision_ledger = decision_ledger or DecisionLedger()
        self._decision_ctx: Optional[DecisionContext] = None
        self._current_intent_decision: Optional[DecisionPoint] = None

        # Layer 4: Policy arbitration
        self.arbitrator = ArbitrationEngine()
        self.arbitrator.register_policy(ScopePolicy())
        self.arbitrator.register_policy(RiskPolicy())

        cal_policies = self.arbitrator.load_cal_file("assets/laws/constitution.cal")
        if cal_policies:
            logger.info(f"[Strategos] Loaded {len(cal_policies)} CAL laws from constitution")
        else:
            logger.warning("[Strategos] No CAL laws loaded - constitution.cal missing or empty")

    async def load_policies_from_db(self) -> int:
        """
        Load enabled CAL policies from database into ArbitrationEngine.
        Must be called after Database.init().
        """
        try:
            from core.data.db import Database

            db = Database.instance()
            db_policies = await db.list_policies()
            enabled_policies = [p for p in db_policies if p.get("enabled", True)]

            loaded_count = 0
            for policy in enabled_policies:
                try:
                    policies = self.arbitrator.load_cal_policy(policy["cal_source"])
                    loaded_count += len(policies)
                    logger.info(f"[Strategos] Loaded DB policy '{policy['name']}' with {len(policies)} laws")
                except Exception as e:
                    logger.error(f"[Strategos] Failed to load policy '{policy['name']}': {e}")

            if loaded_count > 0:
                logger.info(f"[Strategos] Loaded {loaded_count} policies from database")
            return loaded_count
        except Exception as e:
            logger.error(f"[Strategos] Failed to load policies from database: {e}")
            return 0

    def request_stop(self, *, grace_seconds: float = DEFAULT_CANCEL_GRACE_SECONDS) -> None:
        """
        Request mission stop.
        Soft-stop immediately (no new tool dispatch), then after grace_seconds,
        remaining tool tasks will be hard-cancelled.
        """
        self._stop_requested = True
        self._cancel_grace_seconds = float(grace_seconds)
        self._stop_deadline = _now() + self._cancel_grace_seconds

    def _emit_log(self, message: str, level: str = "info") -> None:
        try:
            log_method = getattr(logger, level, logger.info)
            log_method(message)
        except Exception:
            pass

        # per-mission override
        if hasattr(self, "_current_mission_log_fn") and self._current_mission_log_fn:
            try:
                self._current_mission_log_fn(message)
            except Exception:
                pass
        elif self._log_fn:
            try:
                self._log_fn(message)
            except Exception:
                pass

    def _maybe_progress_log(self, force: bool = False) -> None:
        if not self.context:
            return
        now = _now()
        if not force and (now - self._last_progress_log) < PROGRESS_LOG_THROTTLE_SECONDS:
            return
        self._last_progress_log = now
        self._emit_log(
            f"[Strategos] Progress: phase={self.context.phase_index} "
            f"active_tools={self.context.active_tools}/{self.context.max_concurrent} "
            f"running={len(self.context.running_tools)} "
            f"findings={len(self.context.findings)} "
            f"surface={len(self.context.surface_seen)}"
        )

    def _tool_timeout_seconds(self, tool: str) -> float:
        # Prefer tool-specific metadata if present; otherwise use default.
        try:
            tool_def = ToolRegistry.get(tool, mode=self.context.knowledge.get("mode", ScanMode.STANDARD) if self.context else ScanMode.STANDARD)
            if isinstance(tool_def, dict):
                for k in ("timeout_seconds", "timeout", "max_seconds"):
                    if k in tool_def:
                        return float(tool_def[k])
        except Exception:
            pass
        return DEFAULT_TOOL_TIMEOUT_SECONDS

    async def run_mission(
        self,
        target: str,
        available_tools: List[str],
        mode: ScanMode,
        dispatch_tool: Callable[[str], Awaitable[List[Dict[str, Any]]]],
        log_fn: Optional[Callable[[str], None]] = None,
    ) -> MissionTerminatedEvent:
        """
        The agent loop with first-class decision tracking.
        """
        # Clear event queue from previous runs
        while not self.event_queue.empty():
            try:
                self.event_queue.get_nowait()
            except asyncio.QueueEmpty:
                break

        self._current_mission_log_fn = log_fn

        # Init context
        self.context = ScanContext(target=target)
        self.context.knowledge["mode"] = mode

        # Seed tags
        existing_tags = self.context.knowledge.get("tags")
        if not isinstance(existing_tags, set):
            existing_tags = set()
        existing_tags.update({"protocol:http", "protocol:https"})
        self.context.knowledge["tags"] = existing_tags

        self._terminated = False
        self._stop_requested = False
        self._stop_deadline = None

        self._dispatch_callback = dispatch_tool
        self._tool_tasks = {}
        self._tool_semaphore = asyncio.Semaphore(self.context.max_concurrent)

        # Decision context
        self._decision_ctx = create_decision_context(
            event_bus=self._event_bus,
            ledger=self._decision_ledger,
            narrator=self._narrator,
            scan_id=self.context.scan_id,
            source="strategos",
        )

        current_intent = INTENT_PASSIVE_RECON
        self._emit_log(f"[Strategos] Mission Start: {target} (Mode: {mode.value}, scan_id={self.context.scan_id})")

        # Listener + insight processor
        listener_task = asyncio.create_task(self._event_listener())
        self._insight_processor_task = asyncio.create_task(self._process_pending_insights())

        try:
            while not self._terminated and not self._stop_requested:
                new_phase = self._get_phase_for_intent(current_intent)
                if new_phase != self.context.phase_index:
                    # Emit phase transition decision
                    self._decision_ctx.choose(
                        decision_type=DecisionType.PHASE_TRANSITION,
                        chosen=f"PHASE_{new_phase}",
                        reason=f"Intent {current_intent} requires phase {new_phase}",
                        alternatives=[f"PHASE_{self.context.phase_index}"],
                        context={
                            "phase": f"PHASE_{new_phase}",
                            "previous_phase": f"PHASE_{self.context.phase_index}",
                            "intent": current_intent,
                            "mode": mode.value,
                        },
                    )

                    # Emit existing event (no new EventTypes invented)
                    if self._event_bus:
                        try:
                            self._event_bus.emit_scan_phase_changed(
                                phase=f"PHASE_{new_phase}",
                                previous_phase=f"PHASE_{self.context.phase_index}",
                                scan_id=self.context.scan_id,
                            )
                        except Exception as e:
                            logger.debug(f"[Strategos] Failed to emit phase event: {e}")

                    self.context.phase_index = new_phase
                    self._maybe_progress_log(force=True)

                # Reset intent metrics
                self.context.findings_this_intent = 0
                self.context.surface_delta_this_intent = 0

                self._emit_log(f"[Strategos] Decision: Executing {current_intent}")
                self._current_intent_decision = self._decision_ctx.choose(
                    decision_type=DecisionType.INTENT_TRANSITION,
                    chosen=current_intent,
                    reason="Standard sequential progression through scan intents",
                    alternatives=self._get_available_intents(current_intent, mode),
                    context={"mode": mode.value, "target": target, "current_phase": new_phase},
                    evidence={
                        "findings_count": len(self.context.findings),
                        "surface_size": len(self.context.surface_seen),
                        "completed_tools": sum(
                            len(tools) for tools in self.context.completed_tools_per_intent.values()
                        ),
                    },
                )

                tools_to_run = self._select_tools(current_intent, available_tools, mode)

                if self._stop_requested:
                    break

                if not tools_to_run:
                    self._emit_log(f"[Strategos] No tools available for {current_intent}. Skipping.")
                    with self._decision_ctx.nested(self._current_intent_decision):
                        self._decision_ctx.choose(
                            decision_type=DecisionType.TOOL_SELECTION,
                            chosen="SKIP",
                            reason="No tools available or all tools blocked",
                            alternatives=available_tools,
                            context={"mode": mode.value, "intent": current_intent, "skipped": True},
                            evidence={"available_tools": available_tools, "candidate_tools_count": 0},
                        )
                else:
                    await self._dispatch_tools_async(tools_to_run, intent=current_intent)
                    await self._wait_for_intent_completion()

                next_intent = self._decide_next_step(current_intent)
                if next_intent is None:
                    self._terminated = True
                else:
                    current_intent = next_intent

        finally:
            # Soft stop / hard cancel
            self._terminated = True

            # If stop requested, give grace window before cancelling tool tasks
            if self._stop_requested and self._stop_deadline is not None and self.context:
                while self.context.running_tools and _now() < self._stop_deadline:
                    await asyncio.sleep(0.05)

            # Cancel remaining tool tasks
            tasks = list(self._tool_tasks.values())
            for task in tasks:
                task.cancel()
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
            self._tool_tasks.clear()

            listener_task.cancel()
            try:
                await listener_task
            except asyncio.CancelledError:
                pass

            if self._insight_processor_task:
                self._insight_processor_task.cancel()
                try:
                    await self._insight_processor_task
                except asyncio.CancelledError:
                    pass

            stats = self._insight_queue.get_stats()
            self._emit_log(
                f"[Strategos] Insight Queue Stats: "
                f"enqueued={stats.total_enqueued}, "
                f"processed={stats.total_processed}, "
                f"failed={stats.total_failed}, "
                f"dropped={stats.dropped_count}, "
                f"breaker={stats.circuit_breaker_state}"
            )

        reason = "Mission Complete. All intents exhausted or Walk Away triggered."
        if self._stop_requested:
            reason = "Mission Cancelled by operator."

        self._emit_log(f"[Strategos] {reason}")
        return MissionTerminatedEvent(reason=reason)

    async def _dispatch_tools_async(self, tools: List[str], intent: str) -> None:
        """
        Fire-and-forget dispatch with concurrency throttling.
        """
        if not self.context:
            return

        for tool in tools:
            if self._stop_requested:
                break

            if tool in self.context.running_tools:
                logger.debug(f"[Strategos] Skipping {tool}: already running.")
                continue
            if tool in self.context.completed_tools_per_intent.get(intent, set()):
                logger.debug(f"[Strategos] Skipping {tool}: already completed for {intent}.")
                continue

            await self._tool_semaphore.acquire()

            self.context.active_tools += 1
            self.context.running_tools.add(tool)

            self._emit_log(
                f"[Strategos] Dispatching: {tool} ({self.context.active_tools}/{self.context.max_concurrent})"
            )

            # Emit existing TOOL_STARTED event (no new EventTypes invented)
            if self._event_bus:
                try:
                    self._event_bus.emit_tool_invoked(
                        tool=tool,
                        target=self.context.target,
                        args=[],
                        scan_id=self.context.scan_id,
                    )
                except Exception as e:
                    logger.debug(f"[Strategos] Failed to emit tool_started: {e}")

            self._maybe_progress_log()

            task = asyncio.create_task(self._run_tool_worker(tool, intent=intent))
            self._tool_tasks[tool] = task

    def _surface_key(self, finding: Dict[str, Any]) -> Optional[str]:
        if not isinstance(finding, dict):
            return None
        metadata = finding.get("metadata") or {}
        raw = metadata.get("original_target") or finding.get("target") or finding.get("asset")
        if not raw or not isinstance(raw, str):
            return None
        raw = raw.strip()
        if not raw:
            return None

        if "://" not in raw:
            host = raw.lower().rstrip(".")
            if host.startswith("www."):
                host = host[4:]
            return host

        try:
            parsed = urlparse(raw)
        except Exception:
            return raw

        host = (parsed.hostname or "").lower().rstrip(".")
        if not host:
            return raw
        if host.startswith("www."):
            host = host[4:]

        scheme = (parsed.scheme or "https").lower()
        port = parsed.port
        netloc = host if port is None else f"{host}:{port}"

        path = parsed.path or ""
        if path and path != "/":
            path = path.rstrip("/")
        else:
            path = ""

        return f"{scheme}://{netloc}{path}"

    def _enqueue_event(self, event: Any) -> bool:
        try:
            self.event_queue.put_nowait(event)
            return True
        except asyncio.QueueFull:
            self._emit_log(
                f"[Strategos] Event queue full ({self.event_queue.qsize()}/{self.event_queue.maxsize}); "
                f"dropping {type(event).__name__}.",
                level="warning",
            )
            return False

    async def _run_tool_worker(self, tool: str, intent: str) -> None:
        """
        Run a tool with timeout protection and push ToolCompletedEvent.
        """
        if not self.context:
            return

        findings: List[Dict[str, Any]] = []
        success = True

        start = asyncio.get_running_loop().time()
        timeout_s = self._tool_timeout_seconds(tool)

        try:
            if self._stop_requested:
                success = False
                return

            # Timeout wrapper (fix: hung tools no longer deadlock mission)
            try:
                findings = await asyncio.wait_for(self._dispatch_callback(tool), timeout=timeout_s)  # type: ignore[arg-type]
            except asyncio.TimeoutError:
                success = False
                self._emit_log(f"[Strategos] Tool {tool} timed out after {timeout_s:.1f}s", level="warning")
                findings = []
            except asyncio.CancelledError:
                success = False
                raise
            except Exception as e:
                success = False
                self._emit_log(f"[Strategos] Tool {tool} failed: {e}", level="error")
                findings = []

        finally:
            duration = max(0.0, asyncio.get_running_loop().time() - start)

            try:
                if findings:
                    await self.ingest_findings(findings)
            finally:
                self.context.completed_tools_per_intent.setdefault(intent, set()).add(tool)
                self.context.running_tools.discard(tool)
                self._tool_tasks.pop(tool, None)
                self.context.active_tools = max(0, self.context.active_tools - 1)
                if self._tool_semaphore is not None:
                    self._tool_semaphore.release()

            # Emit existing TOOL_COMPLETED event (no new EventTypes invented)
            if self._event_bus:
                try:
                    self._event_bus.emit_tool_completed(
                        tool=tool,
                        exit_code=0 if success else 1,
                        findings_count=len(findings),
                        scan_id=self.context.scan_id,
                    )
                except Exception as e:
                    logger.debug(f"[Strategos] Failed to emit tool_completed: {e}")

            self._maybe_progress_log()

            event = ToolCompletedEvent(
                tool=tool,
                findings=findings,
                success=success,
                duration_seconds=duration,
            )
            if not self._enqueue_event(event):
                status = "✓" if event.success else "✗"
                self._emit_log(f"[Strategos] {status} {event.tool} complete. Findings: {len(event.findings)}")

    async def _event_listener(self) -> None:
        """
        Background task: consumes events from queue.
        """
        while not self._terminated:
            try:
                event = await asyncio.wait_for(self.event_queue.get(), timeout=0.5)
                if isinstance(event, ToolCompletedEvent):
                    self._handle_tool_completed(event)
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break

    async def _process_pending_insights(self) -> None:
        """
        Background loop for processing pending insights.
        """
        while not self._terminated:
            try:
                processed = await self._insight_queue.process_one(self._route_insight_to_handler)
                if not processed:
                    await asyncio.sleep(0.05)
            except asyncio.CancelledError:
                logger.info("[Strategos] Insight processing loop cancelled")
                break
            except Exception as e:
                logger.error(f"[Strategos] Error in insight processing loop: {e}")
                await asyncio.sleep(0.05)

    async def _route_insight_to_handler(self, insight: InsightPayload) -> None:
        action_type = insight.action_type

        if action_type == InsightActionType.HIGH_VALUE_TARGET:
            await self._handle_high_value_target(insight)
        elif action_type == InsightActionType.CRITICAL_PATH:
            await self._handle_critical_path(insight)
        elif action_type == InsightActionType.CONFIRMED_VULN:
            await self._handle_confirmed_vuln(insight)
        elif action_type == InsightActionType.WAF_DETECTED:
            await self._handle_waf_detected(insight)
        elif action_type == InsightActionType.AUTH_REQUIRED:
            await self._handle_auth_required(insight)
        elif action_type == InsightActionType.RATE_LIMIT:
            await self._handle_rate_limit(insight)
        else:
            await self._handle_generic_insight(insight)

    async def _emit_reaction_decision(self, insight: InsightPayload) -> None:
        if self._decision_ctx:
            self._decision_ctx.choose(
                decision_type=DecisionType.REACTIVE_SIGNAL,
                chosen=insight.action_type.value,
                reason=insight.summary,
                context={"target": insight.target, "insight_id": insight.insight_id},
                evidence={"confidence": insight.confidence, "source_tool": insight.source_tool},
            )

    async def _handle_high_value_target(self, insight: InsightPayload) -> None:
        if not self.context:
            return

        async with self.context.lock:
            self.context.knowledge.setdefault("high_value_targets", [])
            self.context.knowledge["high_value_targets"].append(
                {
                    "target": insight.target,
                    "insight_id": insight.insight_id,
                    "confidence": insight.confidence,
                    "details": insight.details,
                    "discovered_at": insight.created_at,
                }
            )

        await self._emit_reaction_decision(insight)
        self._emit_log(f"[Strategos] ⚠ High-value target discovered: {insight.target} (confidence: {insight.confidence})")

    async def _handle_critical_path(self, insight: InsightPayload) -> None:
        if not self.context:
            return

        async with self.context.lock:
            self.context.knowledge.setdefault("critical_paths", [])
            self.context.knowledge["critical_paths"].append(
                {
                    "target": insight.target,
                    "path": insight.details.get("path", ""),
                    "method": insight.details.get("method", "GET"),
                    "insight_id": insight.insight_id,
                    "confidence": insight.confidence,
                    "discovered_at": insight.created_at,
                }
            )

        await self._emit_reaction_decision(insight)
        self._emit_log(f"[Strategos] ⚡ Critical path discovered: {insight.details.get('path', '')} (confidence: {insight.confidence})")

    async def _handle_confirmed_vuln(self, insight: InsightPayload) -> None:
        if not self.context:
            return

        async with self.context.lock:
            self.context.knowledge.setdefault("confirmed_vulns", [])
            self.context.knowledge["confirmed_vulns"].append(
                {
                    "target": insight.target,
                    "vuln_type": insight.details.get("vuln_type") or insight.details.get("type", ""),
                    "insight_id": insight.insight_id,
                    "confidence": insight.confidence,
                }
            )

        await self._emit_reaction_decision(insight)
        self._emit_log(f"[Strategos] 💥 Confirmed vulnerability: {insight.summary}")

    async def _handle_waf_detected(self, insight: InsightPayload) -> None:
        if not self.context:
            return

        async with self.context.lock:
            self.context.knowledge["waf_detected"] = True
            self.context.knowledge["waf_details"] = insight.details

        await self._emit_reaction_decision(insight)
        self._emit_log(f"[Strategos] 🛡 WAF detected: {insight.summary}")

    async def _handle_auth_required(self, insight: InsightPayload) -> None:
        if not self.context:
            return

        async with self.context.lock:
            self.context.knowledge.setdefault("auth_required", [])
            self.context.knowledge["auth_required"].append(
                {"target": insight.target, "auth_type": insight.details.get("auth_type", "unknown"), "insight_id": insight.insight_id}
            )

        await self._emit_reaction_decision(insight)
        self._emit_log(f"[Strategos] 🔒 Authentication required: {insight.target}")

    async def _handle_rate_limit(self, insight: InsightPayload) -> None:
        if not self.context:
            return

        async with self.context.lock:
            self.context.knowledge["rate_limited"] = True

        await self._emit_reaction_decision(insight)
        self._emit_log(f"[Strategos] 🐌 Rate limiting detected: {insight.summary}")

    async def _handle_generic_insight(self, insight: InsightPayload) -> None:
        await self._emit_reaction_decision(insight)
        self._emit_log(f"[Strategos] ℹ Generic insight: {insight.summary}")

    def _handle_tool_completed(self, event: ToolCompletedEvent) -> None:
        status = "✓" if event.success else "✗"
        self._emit_log(f"[Strategos] {status} {event.tool} complete. Findings: {len(event.findings)}")

    async def _wait_for_intent_completion(self) -> None:
        """
        Wait until all tools for the current intent finish.
        Supports cancellation grace period.
        """
        if not self.context:
            return

        while self.context.running_tools:
            if self._stop_requested:
                # If grace elapsed, hard-cancel remaining tasks
                if self._stop_deadline is not None and _now() >= self._stop_deadline:
                    for t in list(self._tool_tasks.values()):
                        t.cancel()
                    break
            await asyncio.sleep(0.05)

    async def ingest_findings(self, findings: List[Dict[str, Any]]) -> None:
        """
        Active feedback: ingest findings and generate insights.
        """
        if not self.context:
            return

        for finding in findings:
            async with self.context.lock:
                self.context.findings.append(finding)
                self.context.findings_this_intent += 1

                surface_key = self._surface_key(finding)
                if surface_key and surface_key not in self.context.surface_seen:
                    self.context.surface_seen.add(surface_key)
                    self.context.surface_delta_this_intent += 1

                tags = list(finding.get("tags", []))
                finding_type = finding.get("type", "")
                if finding_type:
                    tags.append(finding_type)

                existing_tags = self.context.knowledge.get("tags", set())
                if not isinstance(existing_tags, set):
                    existing_tags = set(existing_tags) if existing_tags else set()
                existing_tags.update(tags)
                self.context.knowledge["tags"] = existing_tags

            # Generate insight outside lock
            insight = await self._generate_insights_from_finding(finding)
            if insight:
                enqueued = await self._insight_queue.enqueue(insight)
                if enqueued and self._event_bus:
                    # Emit existing insight-formed event (no new EventTypes invented)
                    try:
                        self._event_bus.emit(
                            GraphEvent(
                                type=EventType.NEXUS_INSIGHT_FORMED,
                                payload=insight.model_dump(),
                                scan_id=self.context.scan_id,
                                source="strategos",
                                priority=2,
                            )
                        )
                    except Exception as e:
                        logger.debug(f"[Strategos] Failed to emit insight event: {e}")

        self._emit_log(f"[Strategos] Ingested {len(findings)} findings. Total: {len(self.context.findings)}")
        self._maybe_progress_log()

    def _normalize_insight_priority(self, priority: Any) -> int:
        # Sentinel rule: small integer domain, stable ordering
        return _clamp_int(priority if priority is not None else 5, 0, 9)

    async def _generate_insights_from_finding(self, finding: Dict[str, Any]) -> Optional[InsightPayload]:
        """
        Generate actionable insights from raw findings.
        """
        if not self.context:
            return None

        finding_type = finding.get("type", "unknown")
        target = finding.get("asset") or finding.get("target") or "unknown"
        base_priority = self._normalize_insight_priority(finding.get("priority", 5))

        action_type: Optional[InsightActionType] = None
        confidence = 0.5
        summary = ""
        priority = base_priority

        # High Value Targets
        if finding_type in ["admin_panel", "config_exposure", "git_exposure"]:
            action_type = InsightActionType.HIGH_VALUE_TARGET
            confidence = 0.9
            summary = f"High Value Target discovered: {finding_type} at {target}"
            priority = 0  # top

        # Likely vulns (scanner-derived)
        elif finding_type in ["sqli", "rce", "lfi", "ssrf"]:
            action_type = InsightActionType.CONFIRMED_VULN
            confidence = 0.8
            summary = f"Possible Critical Vulnerability: {finding_type} at {target}"
            priority = 0

        # WAF
        elif finding_type == "waf_detected":
            action_type = InsightActionType.WAF_DETECTED
            confidence = 1.0
            summary = f"WAF Detected: {finding.get('details', {}).get('waf_name', 'Generic')}"
            priority = 3

        # Auth boundaries
        elif finding_type in ["login_page", "401_unauthorized", "403_forbidden"]:
            action_type = InsightActionType.AUTH_REQUIRED
            confidence = 1.0
            summary = f"Authentication Boundary found at {target}"
            priority = 4

        if not action_type:
            return None

        # Sanitize details to avoid bloated payloads/leakage
        details = finding.get("details", {}) or {}
        sanitized_details: Dict[str, Any] = {
            "finding_type": finding_type,
            "severity": finding.get("severity"),
            "path": details.get("path"),
            "method": details.get("method"),
            "vuln_type": details.get("vuln_type") or finding_type,
            "auth_type": details.get("auth_type"),
            "waf_name": details.get("waf_name"),
        }
        sanitized_details = {k: v for k, v in sanitized_details.items() if v is not None}

        priority = self._normalize_insight_priority(priority)

        return InsightPayload(
            insight_id=uuid.uuid4().hex,
            scan_id=self.context.scan_id,
            action_type=action_type,
            confidence=confidence,
            target=target,
            summary=summary,
            details=sanitized_details,
            source_tool=finding.get("source", "strategos_inference"),
            source_finding_id=finding.get("id"),
            priority=priority,
        )

    def _select_tools(self, intent: str, available_tools: List[str], mode: ScanMode) -> List[str]:
        """
        Select and prioritize tools for an intent.
        """
        if not self.context:
            return []

        candidates = ToolRegistry.get_tools_for_intent(intent, mode=mode)
        candidates = [t for t in candidates if t in available_tools]
        candidates = [t for t in candidates if t not in self.context.completed_tools_per_intent.get(intent, set())]

        scored: List[Tuple[str, int]] = []
        rejected_count = 0
        reasons: Dict[str, List[str]] = {}

        for t in candidates:
            tool_def = ToolRegistry.get(t, mode=mode)
            tool_def["name"] = t

            if tool_def.get("disabled"):
                rejected_count += 1
                reasons.setdefault("Mode Overlay", []).append(t)
                continue

            sim_ctx = {
                **tool_def,
                "tool": tool_def,
                "target": self.context.target,
                "mode": mode.value,
                "phase_index": self.context.phase_index,
                "knowledge": self.context.knowledge,
                "active_tools": len(self._tool_tasks),
                "max_concurrent": self.context.max_concurrent,
            }

            simulated_decision = DecisionPoint.create(
                DecisionType.TOOL_SELECTION,
                chosen=t,
                reason="Candidate Qualification",
                context=sim_ctx,
            )
            judgment = self.arbitrator.review(simulated_decision, sim_ctx)

            if judgment.verdict == Verdict.VETO:
                rejected_count += 1
                reason = f"Policy Veto: {judgment.policy_name}"
                reasons.setdefault(reason, []).append(t)
                continue

            score = self._calculate_score(tool_def, mode)
            scored.append((t, score))

        if self._decision_ctx and self._current_intent_decision and reasons:
            with self._decision_ctx.nested(self._current_intent_decision):
                for reason_desc, tools in reasons.items():
                    self._decision_ctx.choose(
                        decision_type=DecisionType.TOOL_REJECTION,
                        chosen="BLOCKED",
                        reason=reason_desc,
                        context={"tools": tools, "count": len(tools), "intent": intent, "mode": mode.value},
                    )

        scored.sort(key=lambda x: x[1], reverse=True)
        selected_tools = [t for t, _ in scored]

        if self._decision_ctx and self._current_intent_decision:
            with self._decision_ctx.nested(self._current_intent_decision):
                self._decision_ctx.choose(
                    decision_type=DecisionType.TOOL_SELECTION,
                    chosen=selected_tools,
                    reason=f"Selected {len(selected_tools)} tools for {intent} (rejected {rejected_count})",
                    alternatives=candidates,
                    context={
                        "intent": intent,
                        "mode": mode.value,
                        "selected_count": len(selected_tools),
                        "rejected_count": rejected_count,
                    },
                    evidence={
                        "tool_scores": {t: score for t, score in scored},
                        "available_count": len(available_tools),
                    },
                )

        return selected_tools

    def _calculate_score(self, tool_def: Dict[str, Any], mode: ScanMode) -> int:
        overlay_map = ModeRegistry.get_overlay(mode)
        tool_name = tool_def.get("name")
        overlay = overlay_map.get(tool_name) if tool_name else None

        priority = overlay.priority_boost if overlay and overlay.priority_boost else 0
        cost = int(tool_def.get("cost", 1))
        intrusiveness = int(tool_def.get("intrusiveness", 1))
        return (priority * 10) - (cost * 2) - intrusiveness

    def _decide_next_step(self, current_intent: str) -> Optional[str]:
        if self.context is None or current_intent is None:
            return INTENT_PASSIVE_RECON

        mode = self.context.knowledge.get("mode", ScanMode.STANDARD)

        if current_intent == INTENT_PASSIVE_RECON:
            next_intent = INTENT_ACTIVE_LIVE_CHECK
            if self._decision_ctx:
                self._decision_ctx.choose(
                    decision_type=DecisionType.INTENT_TRANSITION,
                    chosen=next_intent,
                    reason="Passive recon complete, proceeding to active live checks",
                    alternatives=[None],
                    context={"from": current_intent, "to": next_intent, "mode": mode.value},
                    evidence={"findings_count": len(self.context.findings)},
                )
            return next_intent

        if current_intent == INTENT_ACTIVE_LIVE_CHECK:
            next_intent = INTENT_SURFACE_ENUMERATION
            if self._decision_ctx:
                self._decision_ctx.choose(
                    decision_type=DecisionType.INTENT_TRANSITION,
                    chosen=next_intent,
                    reason="Live checks complete, proceeding to surface enumeration",
                    alternatives=[None],
                    context={"from": current_intent, "to": next_intent, "mode": mode.value},
                    evidence={"findings_count": len(self.context.findings)},
                )
            return next_intent

        if current_intent == INTENT_SURFACE_ENUMERATION:
            if mode == ScanMode.BUG_BOUNTY and self.context.surface_delta_this_intent == 0:
                self._emit_log("[Strategos] Walk Away: No new surface discovered. Aborting deep scan.")
                if self._decision_ctx:
                    self._decision_ctx.choose(
                        decision_type=DecisionType.EARLY_TERMINATION,
                        chosen="WALK_AWAY",
                        reason="No new attack surface discovered in surface enumeration phase",
                        alternatives=[INTENT_VULN_SCANNING],
                        context={"from": current_intent, "mode": mode.value, "trigger": "bug_bounty_zero_surface_delta"},
                        evidence={
                            "surface_delta_this_intent": self.context.surface_delta_this_intent,
                            "total_surface_size": len(self.context.surface_seen),
                            "findings_this_intent": self.context.findings_this_intent,
                        },
                    )
                return None

            next_intent = INTENT_VULN_SCANNING
            if self._decision_ctx:
                self._decision_ctx.choose(
                    decision_type=DecisionType.INTENT_TRANSITION,
                    chosen=next_intent,
                    reason="Surface enumeration complete, proceeding to vulnerability scanning",
                    alternatives=[None],
                    context={"from": current_intent, "to": next_intent, "mode": mode.value},
                    evidence={
                        "surface_delta": self.context.surface_delta_this_intent,
                        "total_surface": len(self.context.surface_seen),
                    },
                )
            return next_intent

        if current_intent == INTENT_VULN_SCANNING:
            if mode == ScanMode.BUG_BOUNTY:
                self._emit_log("[Strategos] Bug Bounty Mode: Skipping Heavy Artillery.")
                if self._decision_ctx:
                    self._decision_ctx.choose(
                        decision_type=DecisionType.MODE_ADAPTATION,
                        chosen="SKIP_HEAVY_ARTILLERY",
                        reason="Bug Bounty mode prohibits heavy/aggressive scanning tools",
                        alternatives=[INTENT_HEAVY_ARTILLERY],
                        context={"from": current_intent, "mode": mode.value, "skipped_intent": INTENT_HEAVY_ARTILLERY},
                    )
                return None

            next_intent = INTENT_HEAVY_ARTILLERY
            if self._decision_ctx:
                self._decision_ctx.choose(
                    decision_type=DecisionType.INTENT_TRANSITION,
                    chosen=next_intent,
                    reason="Vulnerability scanning complete, proceeding to heavy artillery",
                    alternatives=[None],
                    context={"from": current_intent, "to": next_intent, "mode": mode.value},
                    evidence={"findings_count": len(self.context.findings)},
                )
            return next_intent

        if self._decision_ctx:
            self._decision_ctx.choose(
                decision_type=DecisionType.EARLY_TERMINATION,
                chosen="MISSION_COMPLETE",
                reason="All intents exhausted, scan complete",
                context={"last_intent": current_intent, "mode": mode.value},
                evidence={
                    "total_findings": len(self.context.findings),
                    "total_surface": len(self.context.surface_seen),
                    "total_tools_run": sum(len(tools) for tools in self.context.completed_tools_per_intent.values()),
                },
            )

        return None

    def _get_phase_for_intent(self, intent: str) -> int:
        if intent == INTENT_PASSIVE_RECON:
            return PHASE_1_PASSIVE
        if intent == INTENT_ACTIVE_LIVE_CHECK:
            return PHASE_2_LIGHT
        if intent == INTENT_SURFACE_ENUMERATION:
            return PHASE_3_SURFACE
        if intent == INTENT_VULN_SCANNING:
            return PHASE_4_DEEP
        if intent == INTENT_HEAVY_ARTILLERY:
            return PHASE_5_HEAVY
        return 0

    def _get_available_intents(self, current_intent: str, mode: ScanMode) -> List[str]:
        if current_intent == INTENT_PASSIVE_RECON:
            return [INTENT_ACTIVE_LIVE_CHECK, None]
        if current_intent == INTENT_ACTIVE_LIVE_CHECK:
            return [INTENT_SURFACE_ENUMERATION, None]
        if current_intent == INTENT_SURFACE_ENUMERATION:
            return [INTENT_VULN_SCANNING, None]
        if current_intent == INTENT_VULN_SCANNING:
            if mode == ScanMode.BUG_BOUNTY:
                return [None]
            return [INTENT_HEAVY_ARTILLERY, None]
        return [None]