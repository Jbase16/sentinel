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
from enum import Enum
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
from core.cortex.nexus_context import NexusContext
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
    get_decision_ledger,
)
from core.cortex.arbitration import ArbitrationEngine
from core.cortex.policy import ScopePolicy, RiskPolicy, Verdict

# --- Integration: Capability Tiers + Feedback Loop + WAF Bypass ---
from core.cortex.capability_tiers import (
    CapabilityGate,
    CapabilityTier,
    ExecutionMode,
    GateResult,
    TOOL_TIER_CLASSIFICATION,
    get_capability_gate,
    set_capability_gate,
)
from core.scheduler.feedback_loop import (
    ActionFeedback,
    ActionOutcome,
    FeedbackTracker,
    StrategyAdvisor,
    create_feedback_system,
)

if TYPE_CHECKING:
    from core.cortex.narrator import NarratorEngine

logger = logging.getLogger(__name__)

DEFAULT_EVENT_QUEUE_MAXSIZE = 1024

# Tool timeout and cancellation behavior (local-only policy knobs)
DEFAULT_TOOL_TIMEOUT_SECONDS = 300.0  # 5 min safe default; tool-specific overrides if available
DEFAULT_CANCEL_GRACE_SECONDS = 2.5    # short grace before hard-cancel
PROGRESS_LOG_THROTTLE_SECONDS = 0.5   # avoid spam under high event volume


class ReconSkipReason(str, Enum):
    # Honest names: we're skipping DNS/WHOIS passive recon, not all recon.
    # Active probing (Phase 2+) still runs. Don't pretend otherwise.
    DNS_RECON_IRRELEVANT_FOR_IP = "DNS_RECON_IRRELEVANT_FOR_IP"  # was LOCAL_OR_IP_TARGET
    DNS_RECON_IRRELEVANT_FOR_FILE = "DNS_RECON_IRRELEVANT_FOR_FILE"  # was FILE_TARGET
    NO_PASSIVE_RECON_TOOLS = "NO_PASSIVE_RECON_TOOLS"  # was NO_RECON_TOOLS_AVAILABLE


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

        # Layer 4: Capability Gate + Feedback Loop
        self._capability_gate: CapabilityGate = get_capability_gate()
        self._feedback_tracker, self._action_queue, self._strategy_advisor = create_feedback_system(logger=logger)

        # Dedup set for reactive signals (prevents "💥 Confirmed vulnerability" spam)
        self._emitted_vuln_signals: Set[str] = set()

        # Layer 5: Policy arbitration
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

    async def _probe_target(self, target: str) -> bool:
        """Quick TCP connectivity probe to verify target is reachable."""
        from urllib.parse import urlparse
        parsed = urlparse(target)
        host = parsed.hostname or target
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=3.0
            )
            writer.close()
            await writer.wait_closed()
            return True
        except (asyncio.TimeoutError, OSError):
            return False

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

    def _determine_recon_skip_reason(self, target_classification: Any) -> Optional[ReconSkipReason]:
        """
        Decide whether passive recon should be skipped, and why.
        This is the single authoritative guard for recon skip logic.
        """
        from core.toolkit.normalizer import TargetClassification

        if target_classification in (TargetClassification.IP, TargetClassification.LOOPBACK):
            return ReconSkipReason.DNS_RECON_IRRELEVANT_FOR_IP
        if target_classification == TargetClassification.FILE:
            return ReconSkipReason.DNS_RECON_IRRELEVANT_FOR_FILE
        return None

    def _emit_recon_skipped(
        self,
        reason: ReconSkipReason,
        target: str,
        target_classification: Any,
        available_tools: List[str],
    ) -> None:
        """
        Emit a first-class recon-skipped outcome (decision + event + log).
        """
        if not self.context:
            return

        self.context.knowledge["recon_skipped"] = True
        self.context.knowledge["recon_skip_reason"] = reason.value
        self.context.knowledge["recon_satisfied"] = True

        classification_value = target_classification.value if hasattr(target_classification, "value") else str(target_classification)
        self._emit_log(f"[Strategos] Recon skipped: {reason.value} (target_classification={classification_value})")

        if self._event_bus:
            try:
                self._event_bus.emit_scan_recon_skipped(
                    target=target,
                    reason=reason.value,
                    target_classification=classification_value,
                    intent=INTENT_PASSIVE_RECON,
                    scan_id=self.context.scan_id,
                )
            except Exception as e:
                logger.debug(f"[Strategos] Failed to emit recon skipped event: {e}")

        if self._decision_ctx and self._current_intent_decision:
            with self._decision_ctx.nested(self._current_intent_decision):
                self._decision_ctx.choose(
                    decision_type=DecisionType.TOOL_SELECTION,
                    chosen="SKIP_RECON",
                    reason=f"Recon skipped: {reason.value}",
                    alternatives=available_tools,
                    context={
                        "intent": INTENT_PASSIVE_RECON,
                        "target": target,
                        "target_classification": classification_value,
                        "skipped": True,
                    },
                    evidence={
                        "reason": reason.value,
                        "available_tools": available_tools,
                    },
                )

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

        # Target classification is a first-class control-flow input.
        from core.toolkit.normalizer import classify_target
        target_classification = classify_target(target)
        self.context.knowledge["target_classification"] = target_classification.value

        self._terminated = False
        self._stop_requested = False
        self._stop_deadline = None

        # --- Integration: register target in capability gate scope ---
        self._capability_gate.add_scope_target(target)
        # Budget lifecycle is per mission; prevent cross-scan budget leakage.
        self._capability_gate.reset_target_budget(target)
        # Map ScanMode → ExecutionMode (BOUNTY modes get BOUNTY gate, rest get RESEARCH)
        if mode in (ScanMode.BUG_BOUNTY,):
            self._capability_gate.set_mode(ExecutionMode.BOUNTY)
        else:
            self._capability_gate.set_mode(ExecutionMode.RESEARCH)
        set_capability_gate(self._capability_gate)

        # Reset per-scan feedback state
        self._feedback_tracker, self._action_queue, self._strategy_advisor = create_feedback_system(logger=logger)
        self._emitted_vuln_signals = set()

        self._dispatch_callback = dispatch_tool
        self._tool_tasks = {}
        self._tool_semaphore = asyncio.Semaphore(self.context.max_concurrent)

        # Decision context
        self._decision_ctx = DecisionContext(
            event_bus=self._event_bus,
            ledger=get_decision_ledger(),
            narrator=self._narrator,
            scan_id=self.context.scan_id,
            source="strategos",
        )

        # Emit a capability/budget snapshot early so the UI can surface execution
        # mode, tier ceiling, and budget gauges immediately.
        try:
            budget = self._capability_gate.get_budget(target)
            allowed_tiers = self._capability_gate.get_allowed_tiers(target)
            tier_ceiling = max(allowed_tiers) if allowed_tiers else None
            self._decision_ctx.choose(
                decision_type=DecisionType.RESOURCE_ALLOCATION,
                chosen="CAPABILITY_GATE_INIT",
                reason="Initialized capability gate for this mission",
                context={"target": target, "mode": mode.value},
                evidence={
                    "execution_mode": self._capability_gate.mode.value,
                    "tier_ceiling": tier_ceiling.name if tier_ceiling else None,
                    "allowed_tiers": [t.name for t in allowed_tiers],
                    "budget": budget.summary(),
                },
            )
        except Exception as e:
            logger.debug(f"[Strategos] Failed to emit capability gate init decision: {e}")

        current_intent = INTENT_PASSIVE_RECON
        self._emit_log(f"[Strategos] Mission Start: {target} (Mode: {mode.value}, scan_id={self.context.scan_id})")

        # Listener + insight processor
        listener_task = asyncio.create_task(self._event_listener())
        self._insight_processor_task = asyncio.create_task(self._process_pending_insights())

        try:
            # === PHASE 0: Target Viability Gate ===
            # Hard invariant: target must be reachable before ANY tools run.
            # Without this, Phase 1 DNS tools produce noise findings that trick
            # the assessment into advancing through all 5 phases on a dead target.
            if not await self._probe_target(target):
                self._emit_log(f"[Strategos] ABORT: Target {target} is not reachable. No tools will be dispatched.")
                if self._decision_ctx:
                    self._decision_ctx.choose(
                        decision_type=DecisionType.EARLY_TERMINATION,
                        chosen="TARGET_UNREACHABLE",
                        reason=f"Target {target} failed TCP connectivity probe on declared port",
                        context={"target": target, "mode": mode.value},
                    )
                self._terminated = True

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

                tools_to_run: List[str] = []
                recon_skipped = False
                recon_skip_reason: Optional[ReconSkipReason] = None

                if current_intent == INTENT_PASSIVE_RECON:
                    # Recon is domain-centric; for IP/loopback/file targets it is meaningless.
                    # Skip recon explicitly and proceed to active/HTTP phases.
                    recon_skip_reason = self._determine_recon_skip_reason(target_classification)
                    if recon_skip_reason is None:
                        tools_to_run = self._select_tools(current_intent, available_tools, mode)
                        if not tools_to_run:
                            recon_skip_reason = ReconSkipReason.NO_PASSIVE_RECON_TOOLS
                    if recon_skip_reason is not None:
                        recon_skipped = True
                        self._emit_recon_skipped(
                            reason=recon_skip_reason,
                            target=target,
                            target_classification=target_classification,
                            available_tools=available_tools,
                        )
                else:
                    tools_to_run = self._select_tools(current_intent, available_tools, mode)

                if self._stop_requested:
                    break

                if recon_skipped:
                    # Recon intentionally skipped; do not treat as failure or "no tools" error.
                    pass
                elif not tools_to_run:
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

                # MANDATORY DECISION POINT: Assessment
                # Even if we engaged no tools or found nothing, we must commit to an assessment.
                # This ensures the Decision Ledger is never empty and explicitly records "Status Quo" choices.
                if self._current_intent_decision:
                    with self._decision_ctx.nested(self._current_intent_decision):
                        has_findings = self.context.findings_this_intent > 0
                        has_new_surface = self.context.surface_delta_this_intent > 0

                        # Logic for assessment
                        if current_intent == INTENT_PASSIVE_RECON and recon_skipped:
                            chosen_action = "CONTINUE_ENGAGEMENT"
                            rationale = f"Recon skipped ({recon_skip_reason.value}); proceeding to active phases."
                            suppressed = ["CONCLUDE_PHASE"]
                        elif mode == ScanMode.PASSIVE:
                            chosen_action = "MAINTAIN_PASSIVE_SCOPE"
                            rationale = "Passive mode restriction prevents escalation despite findings." if has_findings else "No triggers for escalation in passive mode."
                            suppressed = ["ESCALATE_TO_ACTIVE"] if has_findings else []
                        elif not tools_to_run:
                            # If this intent had no runnable tools, don't conclude the scan. Skipping
                            # must advance to the next intent so later phases can still execute.
                            chosen_action = "CONTINUE_ENGAGEMENT"
                            rationale = "No runnable tools for this intent; advancing to the next intent."
                            suppressed = ["CONCLUDE_PHASE"]
                        elif has_findings or has_new_surface:
                             chosen_action = "CONTINUE_ENGAGEMENT"
                             rationale = f"Novel surface or findings detected ({self.context.findings_this_intent} new)."
                             suppressed = ["ABORT_ENGAGEMENT"]
                        else:
                            chosen_action = "CONCLUDE_PHASE"
                            rationale = "No significant findings or surface expansion."
                            suppressed = ["ESCALATE_INTENSITY"]

                        # Explicitly cite evidence — enriched with feedback intelligence
                        _intel = self._feedback_tracker.get_target_intelligence(self.context.target)
                        evidence_pkg = {
                            "findings_total": len(self.context.findings),
                            "findings_new": self.context.findings_this_intent,
                            "surface_new": self.context.surface_delta_this_intent,
                            "mode": mode.value,
                            "feedback_success_rate": round(_intel.success_rate, 3),
                            "feedback_total_actions": _intel.total_actions,
                            "waf_detected": _intel.waf_detected or False,
                            "budget_remaining": self._capability_gate.get_budget(self.context.target).remaining_tokens,
                        }

                        self._decision_ctx.choose(
                             decision_type=DecisionType.ASSESSMENT,
                             chosen=chosen_action,
                             reason=rationale,
                             alternatives=["ESCALATE", "ABORT", "MAINTAIN"],
                             suppressed=suppressed,
                             context={"intent": current_intent, "phase": new_phase},
                             evidence=evidence_pkg,
                             confidence=1.0
                        )

                        # Store assessment outcome so _decide_next_step can read it
                        self.context.knowledge["last_assessment"] = chosen_action

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
            
            # Phase 7: System Self-Audit
            # Deterministic, replayable artifact emission
            if self.context and not self._stop_requested: # Only audit completed scans? Or all? User said "scan end".
                 # Even cancelled scans should be audited for what happened.
                 try:
                     # For replay determinism, we need the event sequence number.
                     # EventBus tracks this in persistence, but we don't have a direct handle to "last sequence ID" here cleanly.
                     # We'll rely on the AuditBuilder to just use 0 or fetch from ledger if possible, 
                     # or let NexusContext handle it via bus state if it knew it. 
                     # For now, pass 0 or current timestamp-derived sequence. 
                     # Replay determinism relies on the INPUTS being the same.
                     # We will pass a placeholder sequence since Strategos doesn't track sequence IDs directly.
                     NexusContext.instance().audit_scan(
                         scan_id=self.context.scan_id,
                         session_id=get_run_id(),
                         sequence_end=0 # TODO: Get real sequence number from persistence layer
                     )
                 except Exception as e:
                     logger.error(f"[Strategos] Failed to emit System Self-Audit: {e}")

        reason = "Mission Complete. All intents exhausted or Walk Away triggered."
        if self._stop_requested:
            reason = "Mission Cancelled by operator."

        # --- Integration: emit feedback loop summary ---
        try:
            feedback_stats = self._feedback_tracker.get_statistics()
            self._emit_log(
                f"[Strategos] Feedback Summary: "
                f"actions={feedback_stats['total_actions']}, "
                f"successes={feedback_stats['total_successes']}, "
                f"rate={feedback_stats['overall_success_rate']:.1%}, "
                f"tools_deployed={feedback_stats['tools_deployed']}, "
                f"waf_encounters={feedback_stats['waf_encounters']}"
            )
            budget = self._capability_gate.get_budget(self.context.target) if self.context else None
            if budget:
                self._emit_log(
                    f"[Strategos] Budget: {budget.remaining_tokens}/{budget.max_tokens} tokens remaining, "
                    f"{budget.actions_taken} actions taken"
                )
            # Emit lesson learned for the target
            if self.context:
                lesson = self._strategy_advisor.get_lesson_learned(self.context.target)
                self._emit_log(f"[Strategos] {lesson}")
        except Exception as e:
            logger.debug(f"[Strategos] Failed to emit feedback summary: {e}")

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

        # For localhost targets, only count surface that matches the declared port.
        # Without this, nmap finding "localhost:22" (SSH) counts as surface for a
        # scan targeting localhost:3003, polluting the attack surface model.
        if self.context and self.context.target:
            from core.toolkit.normalizer import is_localhost_target
            if is_localhost_target(self.context.target):
                declared_parsed = urlparse(self.context.target)
                declared_port = declared_parsed.port
                if declared_port:
                    finding_port = None
                    if "://" in raw:
                        try:
                            finding_port = urlparse(raw).port
                        except Exception:
                            pass
                    # If finding references a different port, it's host surface, not target surface
                    if finding_port is not None and finding_port != declared_port:
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
        blocked_by_gate = False
        gate_block_reason: Optional[str] = None

        start = asyncio.get_running_loop().time()
        timeout_s = self._tool_timeout_seconds(tool)

        try:
            if self._stop_requested:
                success = False
                return

            # Commit capability gate budget only when the tool is about to execute.
            gate_result = self._capability_gate.evaluate_tool(self.context.target, tool)
            if not gate_result.approved:
                blocked_by_gate = True
                gate_block_reason = gate_result.reason
                success = False
                self._emit_log(
                    f"[Strategos] Capability Gate blocked {tool}: {gate_result.reason}",
                    level="warning",
                )
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

            # --- Integration: feed ActionFeedback into FeedbackTracker ---
            try:
                outcome = ActionOutcome.SUCCESS if success else ActionOutcome.FAILURE
                if blocked_by_gate:
                    outcome = ActionOutcome.BLOCKED
                elif not success and duration > timeout_s * 0.95:
                    outcome = ActionOutcome.TIMEOUT

                # Derive vuln_class from tool tier classification
                tool_tier = TOOL_TIER_CLASSIFICATION.get(tool, CapabilityTier.T1_PROBE)
                vuln_class = "GENERAL"
                # Infer vuln_class from findings if possible
                for f in findings[:3]:
                    ft = str(f.get("type", "")).lower()
                    if ft in ("sqli", "xss", "rce", "ssrf", "lfi"):
                        vuln_class = ft.upper()
                        break

                feedback = ActionFeedback(
                    action_id=f"{self.context.scan_id}_{tool}_{int(start)}",
                    target=self.context.target,
                    tool_name=tool,
                    vuln_class=vuln_class,
                    tier=int(tool_tier),
                    outcome=outcome,
                    evidence_count=len(findings),
                    max_evidence_confidence=0.7 if findings else 0.0,
                    waf_detected=self.context.knowledge.get("waf_details", {}).get("waf_name") if self.context.knowledge.get("waf_detected") else None,
                    elapsed_ms=duration * 1000,
                    error_detail=None,
                    timestamp=time.time(),
                )
                self._feedback_tracker.process_feedback(feedback)
            except Exception as e:
                logger.debug(f"[Strategos] Failed to record feedback for {tool}: {e}")

            # Emit existing TOOL_COMPLETED event (no new EventTypes invented)
            if self._event_bus:
                try:
                    # Attach low-risk metadata for UI transparency.
                    tool_tier = TOOL_TIER_CLASSIFICATION.get(tool, CapabilityTier.T1_PROBE)
                    budget = self._capability_gate.get_budget(self.context.target)
                    metadata: Dict[str, Any] = {
                        "tier": tool_tier.name,
                        "tier_value": int(tool_tier),
                        "execution_mode": self._capability_gate.mode.value,
                        "budget": budget.summary(),
                    }
                    if blocked_by_gate:
                        metadata["blocked"] = True
                        metadata["block_reason"] = gate_block_reason
                    if self.context.knowledge.get("waf_detected"):
                        metadata["waf"] = self.context.knowledge.get("waf_details") or {}

                    self._event_bus.emit_tool_completed(
                        tool=tool,
                        exit_code=0 if success else 1,
                        findings_count=len(findings),
                        scan_id=self.context.scan_id,
                        metadata=metadata,
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
        elif action_type == InsightActionType.CONFIRMED_EXPOSURE:
            await self._handle_confirmed_exposure(insight)
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

    async def _handle_confirmed_exposure(self, insight: InsightPayload) -> None:
        if not self.context:
            return

        async with self.context.lock:
            self.context.knowledge.setdefault("confirmed_exposures", [])
            self.context.knowledge["confirmed_exposures"].append(
                {
                    "target": insight.target,
                    "insight_id": insight.insight_id,
                    "finding_type": insight.details.get("finding_type"),
                    "confidence": insight.confidence,
                    "details": insight.details,
                    "discovered_at": insight.created_at,
                }
            )

        await self._emit_reaction_decision(insight)
        self._emit_log(
            f"[Strategos] Confirmed exposure discovered: {insight.target} "
            f"(confidence: {insight.confidence})"
        )

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

        # --- Integration: deduplicate reactive signals ---
        # Without this, every single finding triggers "💥 Confirmed vulnerability" spam.
        # We dedup on (target, vuln_type, source_tool) to keep it meaningful.
        vuln_type = insight.details.get("vuln_type") or insight.details.get("type", "unknown")
        dedup_key = f"{insight.target}|{vuln_type}|{insight.source_tool}"
        is_new = dedup_key not in self._emitted_vuln_signals
        self._emitted_vuln_signals.add(dedup_key)

        async with self.context.lock:
            self.context.knowledge.setdefault("confirmed_vulns", [])
            self.context.knowledge["confirmed_vulns"].append(
                {
                    "target": insight.target,
                    "vuln_type": vuln_type,
                    "insight_id": insight.insight_id,
                    "confidence": insight.confidence,
                }
            )

        # Only emit decision + log for truly NEW vuln types (not every finding)
        if is_new:
            await self._emit_reaction_decision(insight)
            self._emit_log(f"[Strategos] 💥 Confirmed vulnerability: {insight.summary}")
        else:
            logger.debug(f"[Strategos] Duplicate vuln signal suppressed: {dedup_key}")

    async def _handle_waf_detected(self, insight: InsightPayload) -> None:
        if not self.context:
            return

        async with self.context.lock:
            self.context.knowledge["waf_detected"] = True
            self.context.knowledge["waf_details"] = insight.details

            # --- Integration: initialize WAF bypass engine ---
            if "waf_bypass_engine" not in self.context.knowledge:
                try:
                    from core.wraith.waf_bypass import WAFBypassEngine
                    waf_engine = WAFBypassEngine()
                    self.context.knowledge["waf_bypass_engine"] = waf_engine
                    waf_name = insight.details.get("waf_name", "unknown")
                    logger.info(f"[Strategos] WAFBypassEngine initialized for {waf_name}")
                except Exception as e:
                    logger.warning(f"[Strategos] Failed to initialize WAFBypassEngine: {e}")

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

                # Non-service finding types are metadata, not attack surface.
                # Counting them as surface tricks the assessment into continuing
                # through phases when no real target surface has been discovered.
                _NON_SURFACE_TYPES = {
                    "DNS Record", "connectivity", "service_unavailable",
                    "permissions", "tool_version", "subdomain",
                }
                finding_type = finding.get("type", "")
                if finding_type not in _NON_SURFACE_TYPES:
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
                                priority=int(insight.priority),
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

        finding_type_raw = finding.get("type", "unknown")
        finding_type = str(finding_type_raw).strip().lower()
        target = finding.get("asset") or finding.get("target") or "unknown"
        has_confirmation_field = "confirmation_level" in finding
        has_capability_field = "capability_types" in finding and finding.get("capability_types") is not None

        raw_capability_types = finding.get("capability_types", [])
        if isinstance(raw_capability_types, str):
            capability_types = [raw_capability_types.strip().lower()]
        elif isinstance(raw_capability_types, list):
            capability_types = [str(cap).strip().lower() for cap in raw_capability_types if str(cap).strip()]
        else:
            capability_types = []

        # Backward-compatible mapping for legacy findings without capability typing.
        if not capability_types:
            if finding_type in {"admin_panel", "config_exposure", "git_exposure"}:
                capability_types = ["information"]
            elif finding_type in {"sqli", "rce", "lfi", "ssrf"}:
                capability_types = ["execution"]
            else:
                capability_types = ["execution"]

        confirmation_level = str(finding.get("confirmation_level", "probable")).strip().lower()
        if confirmation_level not in {"confirmed", "probable", "hypothesized"}:
            confirmation_level = "probable"

        action_type: Optional[InsightActionType] = None
        confidence = 0.5
        summary = ""
        priority = self._normalize_insight_priority(finding.get("priority", 5))

        # --- P0: Source code / credential exposure findings ---
        # .git/config, .env, .git/HEAD, debug consoles, etc. are "stop everything" findings.
        # They can lead to full source disclosure, credential theft, and RCE.
        # These bypass the normal priority system and get priority 0 (highest).
        _P0_SOURCE_EXPOSURE_INDICATORS = {
            ".git/config", ".git/head", ".git/", ".gitignore",
            ".env", ".svn/", ".hg/", ".DS_Store",
            "debug", "console", "phpinfo", "server-status",
            "wp-config", "config.php", "database.yml",
            ".aws/credentials", ".ssh/", "id_rsa",
        }
        details = finding.get("details", {}) or {}
        finding_path = str(details.get("path", "") or finding.get("target", "")).lower()
        finding_description = str(finding.get("description", "")).lower()
        is_p0_exposure = any(
            indicator in finding_path or indicator in finding_description
            for indicator in _P0_SOURCE_EXPOSURE_INDICATORS
        )
        if is_p0_exposure:
            action_type = InsightActionType.HIGH_VALUE_TARGET
            confidence = 1.0
            summary = f"🚨 P0 Source/Config Exposure: {finding_path or finding_type_raw} at {target}"
            priority = 0
            return InsightPayload(
                insight_id=uuid.uuid4().hex,
                scan_id=self.context.scan_id,
                action_type=action_type,
                confidence=confidence,
                target=target,
                summary=summary,
                details={"finding_type": finding_type, "path": finding_path, "severity": "critical", "p0": True},
                source_tool=finding.get("source", "strategos_inference"),
                source_finding_id=finding.get("id"),
                priority=priority,
            )

        # Security boundary findings still follow explicit deterministic mapping.
        if finding_type == "waf_detected":
            action_type = InsightActionType.WAF_DETECTED
            confidence = 1.0
            summary = f"WAF Detected: {finding.get('details', {}).get('waf_name', 'Generic')}"
            priority = 3

        elif finding_type in ["login_page", "401_unauthorized", "403_forbidden"]:
            action_type = InsightActionType.AUTH_REQUIRED
            confidence = 1.0
            summary = f"Authentication Boundary found at {target}"
            priority = 4

        # Backward compatibility: preserve pre-Phase-2 behavior when neither new
        # confirmation nor capability fields are present on the finding.
        elif not has_confirmation_field and not has_capability_field and finding_type in {
            "admin_panel",
            "config_exposure",
            "git_exposure",
        }:
            action_type = InsightActionType.HIGH_VALUE_TARGET
            confidence = 0.9
            summary = f"High Value Target discovered: {finding_type_raw} at {target}"
            priority = 0

        elif not has_confirmation_field and not has_capability_field and finding_type in {
            "sqli",
            "rce",
            "lfi",
            "ssrf",
        }:
            action_type = InsightActionType.CONFIRMED_VULN
            confidence = 0.8
            summary = f"Possible Critical Vulnerability: {finding_type_raw} at {target}"
            priority = 0

        else:
            if confirmation_level == "confirmed":
                priority = 0
                if "access" in capability_types:
                    action_type = InsightActionType.CONFIRMED_EXPOSURE
                    confidence = 0.95
                    summary = f"Confirmed Access Capability: {finding_type_raw} at {target}"
                elif "information" in capability_types and "access" not in capability_types:
                    action_type = InsightActionType.HIGH_VALUE_TARGET
                    confidence = 0.90
                    summary = f"High Value Information Target: {finding_type_raw} at {target}"
                elif "execution" in capability_types:
                    action_type = InsightActionType.CONFIRMED_VULN
                    confidence = 0.85
                    summary = f"Confirmed Vulnerability: {finding_type_raw} at {target}"
            elif confirmation_level == "hypothesized":
                # +2 deprioritization relative to confirmed findings.
                priority = 2
                if "access" in capability_types:
                    action_type = InsightActionType.CONFIRMED_EXPOSURE
                    confidence = 0.50
                    summary = f"Possible Access Exposure (unconfirmed): {finding_type_raw} at {target}"
                elif "execution" in capability_types:
                    action_type = InsightActionType.CONFIRMED_VULN
                    confidence = 0.40
                    summary = f"Possible Vulnerability (unconfirmed): {finding_type_raw} at {target}"
                else:
                    action_type = InsightActionType.HIGH_VALUE_TARGET
                    confidence = 0.50
                    summary = f"Possible Information Target (unconfirmed): {finding_type_raw} at {target}"
            else:
                # PROBABLE tier: priority 1 (between confirmed=0 and hypothesized=2).
                # Guard order mirrors CONFIRMED branch: access → information → execution.
                priority = 1
                if "access" in capability_types:
                    action_type = InsightActionType.CONFIRMED_EXPOSURE
                    confidence = 0.75
                    summary = f"Probable Access Exposure: {finding_type_raw} at {target}"
                elif "information" in capability_types and "access" not in capability_types:
                    action_type = InsightActionType.HIGH_VALUE_TARGET
                    confidence = 0.70
                    summary = f"Probable Information Target: {finding_type_raw} at {target}"
                elif "execution" in capability_types:
                    action_type = InsightActionType.CONFIRMED_VULN
                    confidence = 0.65
                    summary = f"Probable Vulnerability: {finding_type_raw} at {target}"

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
            "capability_types": capability_types,
            "confirmation_level": confirmation_level,
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
        # reasons maps rejection reason → list of tool names rejected for that reason.
        # This is surfaced to the UI as TOOL_REJECTION decisions so operators can
        # see why expected tools did not run.
        reasons: Dict[str, List[str]] = {}

        # Filter tools incompatible with target type
        from core.toolkit.normalizer import is_private_target, is_localhost_target
        from core.toolkit.registry import (
            TOOLS_REQUIRING_PUBLIC_DOMAIN, TOOLS_REQUIRING_ROOT,
            TOOLS_REQUIRING_TLS, TOOLS_HOST_WIDE_PORT_SCAN,
        )
        if is_private_target(self.context.target):
            candidates = [t for t in candidates if t not in TOOLS_REQUIRING_PUBLIC_DOMAIN]
        import os
        if os.geteuid() != 0:
            candidates = [t for t in candidates if t not in TOOLS_REQUIRING_ROOT]

        # --- Policy A: Block TLS tools on non-HTTPS targets ---
        # If target scheme is http (not https) and no https listener discovered,
        # TLS scanners are guaranteed noise (testssl, pshtt, sslyze).
        target_scheme = urlparse(self.context.target).scheme or "http"
        https_discovered = self.context.knowledge.get("https_discovered", False)
        if target_scheme != "https" and not https_discovered:
            tls_blocked = [t for t in candidates if t in TOOLS_REQUIRING_TLS]
            if tls_blocked:
                candidates = [t for t in candidates if t not in TOOLS_REQUIRING_TLS]
                self._emit_log(f"[Strategos] Policy: Blocked TLS tools {tls_blocked} — target is {target_scheme}, no HTTPS listener found")
                rejected_count += len(tls_blocked)
                reasons.setdefault(
                    f"Policy: TLS tools require HTTPS (target is {target_scheme}, no HTTPS listener discovered)",
                    [],
                ).extend(tls_blocked)

        # --- Policy B: Block host-wide port scanners on loopback ---
        # nmap/naabu on localhost find YOUR machine's ports, not the app's.
        # This produces irrelevant noise (port 22, 445, 5432, etc.)
        if is_localhost_target(self.context.target):
            port_scan_blocked = [t for t in candidates if t in TOOLS_HOST_WIDE_PORT_SCAN]
            if port_scan_blocked:
                candidates = [t for t in candidates if t not in TOOLS_HOST_WIDE_PORT_SCAN]
                self._emit_log(f"[Strategos] Policy: Blocked host-wide port scanners {port_scan_blocked} — target is loopback")
                rejected_count += len(port_scan_blocked)
                reasons.setdefault(
                    "Policy: Host-wide port scanning is irrelevant for loopback targets",
                    [],
                ).extend(port_scan_blocked)

        for t in candidates:
            tool_def = ToolRegistry.get(t, mode=mode)
            tool_def["name"] = t

            if tool_def.get("disabled"):
                rejected_count += 1
                reasons.setdefault("Mode Overlay", []).append(t)
                continue

            # --- Integration: CapabilityGate tier check ---
            gate_result = self._capability_gate.evaluate_tool(self.context.target, t, dry_run=True)
            if not gate_result.approved:
                rejected_count += 1
                reason = f"Capability Gate: {gate_result.reason}"
                reasons.setdefault(reason, []).append(t)
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
                        chosen=f"BLOCKED ({len(tools)})",
                        reason=reason_desc,
                        context={"tools": tools, "count": len(tools), "intent": intent, "mode": mode.value},
                        evidence={"tools": tools, "count": len(tools), "intent": intent, "mode": mode.value},
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

        # --- Integration: boost score with feedback effectiveness ---
        effectiveness_boost = 0
        if tool_name:
            effectiveness = self._feedback_tracker.get_tool_effectiveness(tool_name)
            # effectiveness is 0.0-1.0; 0.5 is neutral/unknown → net-zero boost
            effectiveness_boost = int((effectiveness - 0.5) * 10)

        return (priority * 10) - (cost * 2) - intrusiveness + effectiveness_boost

    def _decide_next_step(self, current_intent: str) -> Optional[str]:
        if self.context is None or current_intent is None:
            return INTENT_PASSIVE_RECON

        mode = self.context.knowledge.get("mode", ScanMode.STANDARD)

        # --- Integration: consult StrategyAdvisor for abandonment ---
        target = self.context.target
        intel = self._feedback_tracker.get_target_intelligence(target)
        if intel.total_actions >= 3:
            # Check if advisor recommends abandoning this target entirely
            if self._strategy_advisor.should_abandon(target, "GENERAL"):
                self._emit_log(
                    f"[Strategos] StrategyAdvisor: ABANDON {target} "
                    f"(success_rate={intel.success_rate:.1%}, actions={intel.total_actions})"
                )
                if self._decision_ctx:
                    self._decision_ctx.choose(
                        decision_type=DecisionType.EARLY_TERMINATION,
                        chosen="ADVISOR_ABANDON",
                        reason=f"StrategyAdvisor recommends abandonment: {self._strategy_advisor.get_lesson_learned(target)}",
                        context={"from": current_intent, "mode": mode.value, "target": target},
                        evidence={
                            "success_rate": intel.success_rate,
                            "total_actions": intel.total_actions,
                            "failed_actions": intel.failed_actions,
                        },
                    )
                return None

        # --- Integration: check budget exhaustion ---
        budget = self._capability_gate.get_budget(target)
        if budget.is_exhausted:
            self._emit_log(
                f"[Strategos] Budget exhausted for {target} "
                f"({budget.remaining_tokens} tokens, {budget.time_remaining:.0f}s remaining). Terminating."
            )
            if self._decision_ctx:
                self._decision_ctx.choose(
                    decision_type=DecisionType.EARLY_TERMINATION,
                    chosen="BUDGET_EXHAUSTED",
                    reason=f"Budget exhausted: {budget.summary()}",
                    context={"from": current_intent, "mode": mode.value, "target": target},
                    evidence=budget.summary(),
                )
            return None

        # If assessment concluded the phase (no new findings/surface), stop advancing.
        # Without this gate, the scan unconditionally progresses through all 5 phases
        # even when producing zero meaningful results.
        last_assessment = self.context.knowledge.get("last_assessment", "CONTINUE_ENGAGEMENT")
        if last_assessment == "CONCLUDE_PHASE":
            self._emit_log(f"[Strategos] Assessment concluded phase at {current_intent}. Terminating scan.")
            if self._decision_ctx:
                self._decision_ctx.choose(
                    decision_type=DecisionType.EARLY_TERMINATION,
                    chosen="CONCLUDE_SCAN",
                    reason=f"No significant findings or surface expansion during {current_intent}",
                    context={"from": current_intent, "mode": mode.value},
                    evidence={
                        "findings_this_intent": self.context.findings_this_intent,
                        "surface_delta": self.context.surface_delta_this_intent,
                    },
                )
            return None  # Terminates the scan

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
