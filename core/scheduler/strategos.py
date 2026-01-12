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
"""

import asyncio
import logging
from typing import List, Dict, Any, Callable, Awaitable, Optional, Set, Literal, TYPE_CHECKING
import time
import itertools
from dataclasses import dataclass, field
from urllib.parse import urlparse

# Constitution class replaced by CAL policies loaded into ArbitrationEngine
from core.scheduler.registry import ToolRegistry, PHASE_1_PASSIVE, PHASE_2_LIGHT, PHASE_3_SURFACE, PHASE_4_DEEP, PHASE_5_HEAVY
from core.scheduler.modes import ScanMode, ModeRegistry
from core.scheduler.intents import (
    INTENT_PASSIVE_RECON,
    INTENT_ACTIVE_LIVE_CHECK, 
    INTENT_SURFACE_ENUMERATION,
    INTENT_VULN_SCANNING,
    INTENT_HEAVY_ARTILLERY
)
from core.scheduler.events import ToolCompletedEvent, MissionTerminatedEvent
from core.cortex.events import EventBus, get_run_id
from core.contracts.schemas import InsightPayload, InsightActionType, InsightQueueStats
from core.contracts.events import EventType
import uuid
from core.scheduler.decisions import (
    DecisionContext,
    DecisionLedger,
    DecisionType,
    DecisionPoint,
    create_decision_context
)
from core.cortex.arbitration import ArbitrationEngine
from core.cortex.policy import ScopePolicy, RiskPolicy, Verdict

if TYPE_CHECKING:
    from core.cortex.narrator import NarratorEngine

logger = logging.getLogger(__name__)

DEFAULT_EVENT_QUEUE_MAXSIZE = 1024


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
    Prevents cascading failures by stopping processing when failures exceed threshold.
    
    LIMITATION: This is currently global for all insight types. A failure in one
    handler type will trip the breaker for all insights. Phase 6 should introduce
    per-handler buckets if granularity is needed.
    """
    
    def __init__(
        self,
        failure_threshold: int = 3,
        timeout_seconds: float = 30.0,
        success_threshold: int = 1
    ):
        self._state = CircuitBreakerState()
        self._lock = asyncio.Lock()
        self._failure_threshold = failure_threshold
        self._timeout_seconds = timeout_seconds
        self._success_threshold = success_threshold
    
    async def acquire(self) -> bool:
        """
        Attempt to acquire permission to process.
        Returns True if processing should proceed, False otherwise.
        """
        async with self._lock:
            # Check if we should transition from OPEN to HALF_OPEN
            if self._state.state == "OPEN":
                if time.time() - self._state.last_failure_time > self._timeout_seconds:
                    self._state = CircuitBreakerState(state="HALF_OPEN")
                else:
                    return False
            
            return True
    
    async def record_success(self) -> None:
        """Record a successful processing attempt."""
        async with self._lock:
            if self._state.state == "HALF_OPEN":
                self._state.success_count += 1
                if self._state.success_count >= self._success_threshold:
                    self._state = CircuitBreakerState(state="CLOSED")
            else:
                # Reset failure count on success in CLOSED state
                self._state.failure_count = 0
    
    async def record_failure(self) -> None:
        """Record a failed processing attempt."""
        async with self._lock:
            self._state.failure_count += 1
            self._state.last_failure_time = time.time()
            
            if self._state.failure_count >= self._failure_threshold:
                self._state = CircuitBreakerState(
                    state="OPEN",
                    last_failure_time=self._state.last_failure_time,
                    failure_count=self._state.failure_count
                )
                logger.warning(
                    f"[CircuitBreaker] Circuit OPEN - {self._failure_threshold} failures"
                )
    
    def get_state(self) -> str:
        """Get current circuit breaker state (non-blocking)."""
        return self._state.state


class InsightQueue:
    """
    Thread-safe async queue for insight processing.
    """
    
    def __init__(
        self,
        maxsize: int = 100,
        circuit_breaker: Optional[CircuitBreaker] = None
    ):
        self._maxsize = maxsize
        self._queue: asyncio.PriorityQueue = asyncio.PriorityQueue(maxsize=maxsize)
        self._lock = asyncio.Lock()
        self._circuit_breaker = circuit_breaker or CircuitBreaker()
        self._stats = InsightQueueStats()
        self._counter = itertools.count()  # Tie-breaker for stable sorting in priority queue
    
    async def enqueue(self, insight: InsightPayload) -> bool:
        """
        Enqueue an insight for processing.
        Non-blocking operation: Returns False if queue is full.
        """
        async with self._lock:
            if self._queue.qsize() >= self._maxsize:
                self._stats.dropped_count += 1
                return False
            
            # Use priority as first element of tuple (lower integer = higher priority)
            # Use counter as second element to break ties (FIFO for same priority)
            # InsightPayload is third
            priority = insight.priority
            count = next(self._counter)
            await self._queue.put((priority, count, insight))
            self._stats.total_enqueued += 1
            self._stats.current_size = self._queue.qsize()
            return True
    
    async def dequeue(self, timeout: float = 0.1) -> Optional[InsightPayload]:
        """
        Dequeue an insight for processing.
        """
        try:
            # Tuple is (priority, count, insight)
            priority, count, insight = await asyncio.wait_for(
                self._queue.get(),
                timeout=timeout
            )
            async with self._lock:
                self._stats.current_size = self._queue.qsize()
            return insight
        except asyncio.TimeoutError:
            return None
    
    async def process_one(self, handler: Callable[[InsightPayload], Awaitable[None]]) -> bool:
        """
        Process one insight from the queue.
        Optimized to acquire lock once for all stat updates to reduce contention.
        """
        # Check circuit breaker (no lock needed - circuit breaker has its own lock)
        if not await self._circuit_breaker.acquire():
            # Update circuit breaker state in stats
            async with self._lock:
                self._stats.circuit_breaker_state = self._circuit_breaker.get_state()
            return False
        
        # Dequeue insight (no lock needed - queue has its own lock)
        insight = await self.dequeue()
        if insight is None:
            return False
        
        # Process insight
        start = asyncio.get_event_loop().time()
        success = False
        failed = False
        
        try:
            await handler(insight)
            await self._circuit_breaker.record_success()
            success = True
        except Exception as e:
            await self._circuit_breaker.record_failure()
            failed = True
            logger.error(f"[InsightQueue] Failed to process insight {insight.insight_id}: {e}")
        finally:
            duration = (asyncio.get_event_loop().time() - start) * 1000
            
            # Single lock acquisition for all stat updates
            async with self._lock:
                if success:
                    self._stats.total_processed += 1
                elif failed:
                    self._stats.total_failed += 1
                self._stats.processing_time_ms += duration
                self._stats.circuit_breaker_state = self._circuit_breaker.get_state()
        
        return success
    
    def get_stats(self) -> InsightQueueStats:
        """Get current queue statistics."""
        return InsightQueueStats(
            total_enqueued=self._stats.total_enqueued,
            total_processed=self._stats.total_processed,
            total_failed=self._stats.total_failed,
            current_size=self._queue.qsize(),
            dropped_count=self._stats.dropped_count,
            processing_time_ms=self._stats.processing_time_ms,
            circuit_breaker_state=self._circuit_breaker.get_state()
        )

@dataclass
class ScanContext:
    """Class ScanContext."""
    target: str
    scan_id: str = field(default_factory=lambda: get_run_id())
    # Lock for guarding mutable state (knowledge, findings) from concurrent access
    # by intent loop and insight handlers.
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    phase_index: int = 0
    knowledge: Dict[str, Any] = field(default_factory=dict)
    active_tools: int = 0
    max_concurrent: int = 3  # Real throttling limit
    findings: List[Dict] = field(default_factory=list)
    findings_this_intent: int = 0
    surface_delta_this_intent: int = 0
    running_tools: Set[str] = field(default_factory=set)
    completed_tools_per_intent: Dict[str, Set[str]] = field(default_factory=dict)
    surface_seen: Set[str] = field(default_factory=set)

class Strategos:
    """
    The Strategist.
    A truly concurrent, event-driven planner with first-class decision tracking.
    
    Every strategic decision is captured as an immutable DecisionPoint and
    automatically emitted as events to the EventBus. This ensures complete
    observability and audit trail without manual emit_event() calls.
    """
    
    def __init__(
        self,
        event_queue_maxsize: int = DEFAULT_EVENT_QUEUE_MAXSIZE,
        log_fn: Optional[Callable[[str], None]] = None,
        event_bus: Optional[EventBus] = None,
        decision_ledger: Optional[DecisionLedger] = None,
        narrator: Optional["NarratorEngine"] = None,
    ):
        """Function __init__."""
        # Constitution is now loaded into ArbitrationEngine (see Layer 4 below)
        self.registry = ToolRegistry()
        self.context: Optional[ScanContext] = None
        self.event_queue: asyncio.Queue = asyncio.Queue(maxsize=event_queue_maxsize)
        self._terminated = False
        self._dispatch_callback: Optional[Callable[[str], Awaitable[List[Dict]]]] = None
        self._tool_tasks: Dict[str, asyncio.Task] = {}
        self._tool_semaphore: Optional[asyncio.Semaphore] = None
        self._log_fn = log_fn
        self._event_bus = event_bus
        self._narrator = narrator
        
        # Phase 5: Insight Queue and Circuit Breaker
        self._circuit_breaker = CircuitBreaker()
        self._insight_queue = InsightQueue(
            maxsize=100,
            circuit_breaker=self._circuit_breaker
        )
        self._insight_processor_task: Optional[asyncio.Task] = None
        # Phase 5: Reactive Handlers
        # Buffer for concurrent insight handlers if we wanted to limit them specifically, 
        # but they are naturally throttled by the queue drain rate.

        # Decision Emission Layer: All strategic choices flow through this context
        # This creates a complete audit trail separate from the event stream
        self._decision_ledger = decision_ledger or DecisionLedger()
        self._decision_ctx: Optional[DecisionContext] = None
        
        # Track current decision for hierarchical decision trees
        # Track current decision for hierarchical decision trees
        self._current_intent_decision: Optional[DecisionPoint] = None

        # Layer 4: Policy Arbitration
        self.arbitrator = ArbitrationEngine()

        # Register Python policies
        self.arbitrator.register_policy(ScopePolicy())
        self.arbitrator.register_policy(RiskPolicy())

        # Load CAL constitution (replaces legacy Constitution class)
        # This unifies CAL laws with Python policies under a single enforcement engine
        cal_policies = self.arbitrator.load_cal_file("assets/laws/constitution.cal")
        if cal_policies:
            logger.info(f"[Strategos] Loaded {len(cal_policies)} CAL laws from constitution")
        else:
            logger.warning("[Strategos] No CAL laws loaded - constitution.cal missing or empty")

        # Note: Database policies loaded separately via load_policies_from_db()
        # (must be called after async DB initialization)

    async def load_policies_from_db(self):
        """
        Load enabled CAL policies from database into ArbitrationEngine.

        This must be called after Database.init() completes, as it requires
        database access. Typically called during server startup.

        Returns:
            Number of policies loaded
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

    def _emit_log(self, message: str, level: str = "info") -> None:
        """Function _emit_log."""
        # Error handling block.
        try:
            log_method = getattr(logger, level, logger.info)
            log_method(message)
        except Exception:
            pass

        # Conditional branch.
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
        
    async def run_mission(
        self, 
        target: str, 
        available_tools: List[str], 
        mode: ScanMode,
        dispatch_tool: Callable[[str], Awaitable[List[Dict]]],
        log_fn: Optional[Callable[[str], None]] = None
    ) -> MissionTerminatedEvent:
        """
        The Agent Loop with First-Class Decision Tracking.
        
        Every strategic decision (intent transition, tool selection, phase change)
        is captured as an immutable DecisionPoint and automatically emitted.
        
        Decision Flow Architecture:
        1. DecisionContext wraps entire mission lifecycle
        2. Each intent transition creates a parent decision
        3. Tool selections are child decisions linked to intent
        4. Phase transitions emit specialized phase_changed events
        5. Early termination (Walk Away) is an explicit decision
        
        This ensures complete decision audit trail without manual emit calls.
        """
        # Clear event queue from previous runs
        while not self.event_queue.empty():
            try:
                self.event_queue.get_nowait()
            except asyncio.QueueEmpty:
                break
        
        # Override log_fn for this mission if provided
        self._current_mission_log_fn = log_fn

        # Initialize scan context
        self.context = ScanContext(target=target)
        # scan_id will be auto-generated or could be passed if we modify signature
        
        self.context.knowledge["mode"] = mode
        
        # Seed baseline protocol tags for deterministic tool gating
        # Assumption: HTTP/HTTPS targets until proven otherwise
        existing_tags = self.context.knowledge.get("tags")
        # Conditional branch.
        if not isinstance(existing_tags, set):
            existing_tags = set()
        existing_tags.update({"protocol:http", "protocol:https"})
        self.context.knowledge["tags"] = existing_tags
        
        self._terminated = False
        self._dispatch_callback = dispatch_tool
        self._tool_tasks = {}
        self._tool_semaphore = asyncio.Semaphore(self.context.max_concurrent)
        
        # Initialize Decision Emission Layer
        # All decisions made during this mission flow through this context
        self._decision_ctx = create_decision_context(
            event_bus=self._event_bus,
            ledger=self._decision_ledger,
            narrator=self._narrator,
            scan_id=self.context.scan_id,
            source="strategos"
        )
        
        current_intent = INTENT_PASSIVE_RECON
        
        self._emit_log(f"[Strategos] Mission Start: {target} (Mode: {mode.value})")
        
        # Start event listener in background
        listener_task = asyncio.create_task(self._event_listener())
        
        # Phase 5: Start insight processor in background
        self._insight_processor_task = asyncio.create_task(
            self._process_pending_insights()
        )
        
        # Error handling block.
        try:
            # === THE AGENT LOOP (Decision-Driven) ===
            while not self._terminated:
                # DECISION POINT: Phase Transition
                # Check if we need to transition to a new phase based on intent
                new_phase = self._get_phase_for_intent(current_intent)
                if new_phase != self.context.phase_index:
                    # Emit phase transition as specialized decision
                    self._decision_ctx.choose(
                        decision_type=DecisionType.PHASE_TRANSITION,
                        chosen=f"PHASE_{new_phase}",
                        reason=f"Intent {current_intent} requires phase {new_phase}",
                        alternatives=[f"PHASE_{self.context.phase_index}"],  # What we're leaving
                        context={
                            "phase": f"PHASE_{new_phase}",
                            "previous_phase": f"PHASE_{self.context.phase_index}",
                            "intent": current_intent,
                            "mode": mode.value
                        }
                    )
                    self.context.phase_index = new_phase
                
                # Reset intent-scoped metrics
                self.context.findings_this_intent = 0
                self.context.surface_delta_this_intent = 0
                
                # DECISION POINT: Intent Execution
                # Declare intent to execute this strategic phase
                self._emit_log(f"[Strategos] Decision: Executing {current_intent}")
                self._current_intent_decision = self._decision_ctx.choose(
                    decision_type=DecisionType.INTENT_TRANSITION,
                    chosen=current_intent,
                    reason="Standard sequential progression through scan intents",
                    alternatives=self._get_available_intents(current_intent, mode),
                    context={
                        "mode": mode.value,
                        "target": target,
                        "current_phase": new_phase
                    },
                    evidence={
                        "findings_count": len(self.context.findings),
                        "surface_size": len(self.context.surface_seen),
                        "completed_tools": sum(
                            len(tools) 
                            for tools in self.context.completed_tools_per_intent.values()
                        )
                    }
                )
                
                # DECISION POINT: Tool Selection
                # Select which tools to run for this intent (may be empty)
                tools_to_run = self._select_tools(current_intent, available_tools, mode)
                
                if not tools_to_run:
                    # DECISION: Skip intent due to no available tools
                    self._emit_log(f"[Strategos] No tools available for {current_intent}. Skipping.")
                    
                    # Nested decision under current intent
                    with self._decision_ctx.nested(self._current_intent_decision):
                        self._decision_ctx.choose(
                            decision_type=DecisionType.TOOL_SELECTION,
                            chosen="SKIP",
                            reason="No tools available or all tools blocked",
                            alternatives=available_tools,  # What we could have chosen
                            context={
                                "mode": mode.value,
                                "intent": current_intent,
                                "skipped": True
                            },
                            evidence={
                                "available_tools": available_tools,
                                "candidate_tools_count": 0
                            }
                        )
                else:
                    # Dispatch all selected tools concurrently
                    await self._dispatch_tools_async(tools_to_run, intent=current_intent)
                    
                    # Wait for all tools in this intent to complete
                    await self._wait_for_intent_completion()
                
                # DECISION POINT: Next Intent Selection
                # Strategic decision: what to do next based on current state
                next_intent = self._decide_next_step(current_intent)
                
                if next_intent is None:
                    # Mission termination is a decision too
                    self._terminated = True
                else:
                    current_intent = next_intent
        finally:
            # Cleanup: Cancel all running tasks
            self._terminated = True
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
            
            # Phase 5: Cancel insight processor
            if self._insight_processor_task:
                self._insight_processor_task.cancel()
                try:
                    await self._insight_processor_task
                except asyncio.CancelledError:
                    pass
            
            # Log insight queue stats
            stats = self._insight_queue.get_stats()
            self._emit_log(
                f"[Strategos] Insight Queue Stats: "
                f"enqueued={stats.total_enqueued}, "
                f"processed={stats.total_processed}, "
                f"failed={stats.total_failed}, "
                f"dropped={stats.dropped_count}"
            )
        
        reason = "Mission Complete. All intents exhausted or Walk Away triggered."
        self._emit_log(f"[Strategos] {reason}")
        return MissionTerminatedEvent(reason=reason)
    
    async def _dispatch_tools_async(self, tools: List[str], intent: str):
        """
        Fire-and-forget dispatch with concurrency throttling.
        """
        # Loop over items.
        for tool in tools:
            if tool in self.context.running_tools:
                logger.debug(f"[Strategos] Skipping {tool}: already running.")
                continue
            if tool in self.context.completed_tools_per_intent.get(intent, set()):
                logger.debug(f"[Strategos] Skipping {tool}: already completed for {intent}.")
                continue

            # THROTTLE: Wait for a slot
            await self._tool_semaphore.acquire()
            
            # Dispatch (fire-and-forget)
            self.context.active_tools += 1
            self.context.running_tools.add(tool)
            self._emit_log(
                f"[Strategos] Dispatching: {tool} ({self.context.active_tools}/{self.context.max_concurrent})"
            )
            
            task = asyncio.create_task(self._run_tool_worker(tool, intent=intent))
            self._tool_tasks[tool] = task
    
    def _surface_key(self, finding: Dict[str, Any]) -> Optional[str]:
        """Function _surface_key."""
        # Conditional branch.
        if not isinstance(finding, dict):
            return None
        metadata = finding.get("metadata") or {}
        raw = metadata.get("original_target") or finding.get("target") or finding.get("asset")
        # Conditional branch.
        if not raw or not isinstance(raw, str):
            return None
        raw = raw.strip()
        # Conditional branch.
        if not raw:
            return None

        # Conditional branch.
        if "://" not in raw:
            host = raw.lower().rstrip(".")
            if host.startswith("www."):
                host = host[4:]
            return host

        # Error handling block.
        try:
            parsed = urlparse(raw)
        except Exception:
            return raw

        host = (parsed.hostname or "").lower().rstrip(".")
        # Conditional branch.
        if not host:
            return raw
        # Conditional branch.
        if host.startswith("www."):
            host = host[4:]

        scheme = (parsed.scheme or "https").lower()
        port = parsed.port
        netloc = host if port is None else f"{host}:{port}"

        path = parsed.path or ""
        # Conditional branch.
        if path and path != "/":
            path = path.rstrip("/")
        else:
            path = ""

        return f"{scheme}://{netloc}{path}"

    def _enqueue_event(self, event: Any) -> bool:
        """Function _enqueue_event."""
        # Error handling block.
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

    async def _run_tool_worker(self, tool: str, intent: str):
        """
        Runs a tool and pushes ToolCompletedEvent to queue.
        """
        findings = []
        success = True
        start = asyncio.get_running_loop().time()
        # Error handling block.
        try:
            findings = await self._dispatch_callback(tool)
            if findings is None:
                findings = []
        except asyncio.CancelledError:
            success = False
            raise
        except Exception as e:
            self._emit_log(f"[Strategos] Tool {tool} failed: {e}", level="error")
            success = False
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

            event = ToolCompletedEvent(
                tool=tool,
                findings=findings,
                success=success,
                duration_seconds=duration,
            )
            if not self._enqueue_event(event):
                status = "✓" if event.success else "✗"
                self._emit_log(f"[Strategos] {status} {event.tool} complete. Findings: {len(event.findings)}")
    
    async def _event_listener(self):
        """
        Background task: Consumes events from queue.
        """
        # While loop.
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
        Background loop for processing pending insights (Phase 5).
        """
        while not self._terminated:
            try:
                # Process one insight with timeout
                processed = await self._insight_queue.process_one(
                    self._route_insight_to_handler
                )
                
                if not processed:
                    # No insight available or circuit breaker open
                    await asyncio.sleep(0.1)
                    
            except asyncio.CancelledError:
                # Graceful shutdown
                logger.info("[Strategos] Insight processing loop cancelled")
                break
            except Exception as e:
                # Unexpected error - log and continue
                logger.error(f"[Strategos] Error in insight processing loop: {e}")
                await asyncio.sleep(0.1)

    async def _route_insight_to_handler(self, insight: InsightPayload) -> None:
        """
        Route insight to appropriate handler based on action type.
        """
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
            # Generic handler for unknown types
            await self._handle_generic_insight(insight)

    async def _emit_reaction_decision(self, insight: InsightPayload):
        """Emit a decision record for the reactive action taken."""
        if self._decision_ctx:
            # We don't strictly require a parent decision here since reactions are async,
            # but we can try to link to current intent if it exists.
            self._decision_ctx.choose(
                decision_type=DecisionType.REACTIVE_SIGNAL,
                chosen=insight.action_type.value,
                reason=insight.summary,
                context={
                    "target": insight.target,
                    "insight_id": insight.insight_id
                },
                evidence={
                    "confidence": insight.confidence,
                    "source_tool": insight.source_tool
                }
            )

    async def _handle_high_value_target(self, insight: InsightPayload) -> None:
        """Handle high-value target insights."""
        if not self.context:
             return
             
        async with self.context.lock:
            if "high_value_targets" not in self.context.knowledge:
                self.context.knowledge["high_value_targets"] = []
            
            self.context.knowledge["high_value_targets"].append({
                "target": insight.target,
                "insight_id": insight.insight_id,
                "confidence": insight.confidence,
                "details": insight.details,
                "discovered_at": insight.created_at
            })
        
        await self._emit_reaction_decision(insight)
        
        self._emit_log(
            f"[Strategos] ⚠ High-value target discovered: {insight.target} "
            f"(confidence: {insight.confidence})"
        )

    async def _handle_critical_path(self, insight: InsightPayload) -> None:
        """Handle critical path insights."""
        if not self.context:
             return

        async with self.context.lock:
            if "critical_paths" not in self.context.knowledge:
                self.context.knowledge["critical_paths"] = []
            
            self.context.knowledge["critical_paths"].append({
                "target": insight.target,
                "path": insight.details.get("path", ""),
                "method": insight.details.get("method", "GET"),
                "insight_id": insight.insight_id,
                "confidence": insight.confidence,
                "discovered_at": insight.created_at
            })
            
        await self._emit_reaction_decision(insight)

        self._emit_log(
            f"[Strategos] ⚡ Critical path discovered: {insight.details.get('path', '')} "
            f"(confidence: {insight.confidence})"
        )

    async def _handle_confirmed_vuln(self, insight: InsightPayload) -> None:
        """Handle confirmed vulnerability insights."""
        if not self.context:
             return

        async with self.context.lock:
            if "confirmed_vulns" not in self.context.knowledge:
                self.context.knowledge["confirmed_vulns"] = []
            
            self.context.knowledge["confirmed_vulns"].append({
                "target": insight.target,
                "vuln_type": insight.details.get("vuln_type") or insight.details.get("type", ""),
                "insight_id": insight.insight_id,
                "confidence": insight.confidence
            })
            
        await self._emit_reaction_decision(insight)

        self._emit_log(f"[Strategos] 💥 Confirmed vulnerability: {insight.summary}")

    async def _handle_waf_detected(self, insight: InsightPayload) -> None:
        """Handle WAF detection insights."""
        if not self.context:
             return

        async with self.context.lock:
            self.context.knowledge["waf_detected"] = True
            self.context.knowledge["waf_details"] = insight.details

        await self._emit_reaction_decision(insight)

        self._emit_log(f"[Strategos] 🛡 WAF detected: {insight.summary}")

    async def _handle_auth_required(self, insight: InsightPayload) -> None:
        """Handle authentication requirement insights."""
        if not self.context:
             return

        async with self.context.lock:
            if "auth_required" not in self.context.knowledge:
                self.context.knowledge["auth_required"] = []
            
            self.context.knowledge["auth_required"].append({
                "target": insight.target,
                "auth_type": insight.details.get("auth_type", "unknown"),
                "insight_id": insight.insight_id
            })

        await self._emit_reaction_decision(insight)

        self._emit_log(f"[Strategos] 🔒 Authentication required: {insight.target}")

    async def _handle_rate_limit(self, insight: InsightPayload) -> None:
        """Handle rate limit detection insights."""
        if not self.context:
             return

        async with self.context.lock:
            self.context.knowledge["rate_limited"] = True

        await self._emit_reaction_decision(insight)

        self._emit_log(f"[Strategos] 🐌 Rate limiting detected: {insight.summary}")

    async def _handle_generic_insight(self, insight: InsightPayload) -> None:
        """Handle generic insights."""
        await self._emit_reaction_decision(insight)
        self._emit_log(f"[Strategos] ℹ Generic insight: {insight.summary}")

    def _handle_tool_completed(self, event: ToolCompletedEvent):
        """
        Process a completed tool event.
        """
        status = "✓" if event.success else "✗"
        self._emit_log(f"[Strategos] {status} {event.tool} complete. Findings: {len(event.findings)}")
    
    async def _wait_for_intent_completion(self):
        """
        Block until all tools for current intent are finished.
        """
        # While loop.
        while self.context.running_tools:
            await asyncio.sleep(0.1)
    
    async def ingest_findings(self, findings: List[Dict]):
        """
        Active Feedback.
        Ingests findings and generates insights (Phase 5).
        """
        # Conditional branch.
        if not self.context:
            return
            
        # Loop over items.
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
                # Handle potential type mismatch if tags wasn't a set
                if not isinstance(existing_tags, set):
                     existing_tags = set(existing_tags) if existing_tags else set()
                existing_tags.update(tags)
                self.context.knowledge["tags"] = existing_tags
            
            # Phase 5: Generate and enqueue insights
            # Done OUTSIDE the lock to reduce contention
            insight = await self._generate_insights_from_finding(finding)
            if insight:
                enqueued = await self._insight_queue.enqueue(insight)
                if enqueued:
                    # Emit NEXUS_INSIGHT_FORMED event
                    # We can use the event bus if available, but for now we trust the queue processor
                    # to handle reactions. However, for full traceability we should emit.
                    if self._event_bus:
                        # Assuming emit_event is generic or we have a helper 
                        # We used to have generic emit, but now strict types.
                        # We need emit_nexus_insight_formed? No, use generic emit with Payload.
                        # But wait, event bus validates strictness.
                        # The EventType constant is NEXUS_INSIGHT_FORMED
                        # The payload is InsightPayload
                        
                        # Fix: Model dump for strict dictionary contract
                        try:
                           self._event_bus.emit(
                               event_type=EventType.NEXUS_INSIGHT_FORMED,
                               payload=insight.model_dump(),
                               scan_id=self.context.scan_id,
                               description=f"Insight formed: {insight.summary}",
                               source="strategos.nexus.hybrid"
                           )
                        except Exception as e:
                           logger.warning(f"Failed to emit insight event: {e}")
            
        self._emit_log(f"[Strategos] Ingested {len(findings)} findings. Total: {len(self.context.findings)}")

    async def _generate_insights_from_finding(self, finding: Dict) -> Optional[InsightPayload]:
        """
        Generate actionable insights from raw findings.
        This is the bridge between raw data (Scanner) and strategy (Brain).
        """
        if not self.context:
            return None
            
        finding_type = finding.get("type", "unknown")
        target = finding.get("asset") or finding.get("target") or "unknown"
        priority = finding.get("priority", 5)
        
        action_type = None
        confidence = 0.5
        summary = ""
        
        # Rule 1: High Value Targets (HVT)
        # e.g. admin panels, git configs, env files
        if finding_type in ["admin_panel", "config_exposure", "git_exposure"]:
            action_type = InsightActionType.HIGH_VALUE_TARGET
            confidence = 0.9
            summary = f"High Value Target discovered: {finding_type} at {target}"
            priority = 1
            
        # Rule 2: Critical Paths / Vulnerabilities
        elif finding_type in ["sqli", "rce", "lfi", "ssrf"]:
            action_type = InsightActionType.CONFIRMED_VULN  # Assuming scanner output implies some confidence
            confidence = 0.8 # Scanners can have false positives
            summary = f"Possible Critical Vulnerability: {finding_type} at {target}"
            priority = 1
            
        # Rule 3: WAF Detection
        elif finding_type == "waf_detected":
            action_type = InsightActionType.WAF_DETECTED
            confidence = 1.0
            summary = f"WAF Detected: {finding.get('details', {}).get('waf_name', 'Generic')}"
            priority = 3
            
        # Rule 4: Auth Boundaries
        elif finding_type in ["login_page", "401_unauthorized", "403_forbidden"]:
            action_type = InsightActionType.AUTH_REQUIRED
            confidence = 1.0
            summary = f"Authentication Boundary found at {target}"
            priority = 4
        
        if action_type:
            # Fix: Sanitize details instead of leaking raw finding (Fixes Problem 4)
            # We extract only what is needed for the insight context to avoid bloating
            sanitized_details = {
                 "finding_type": finding_type,
                 "severity": finding.get("severity"),
                 "path": finding.get("details", {}).get("path"),
                 "method": finding.get("details", {}).get("method"),
                 "vuln_type": finding.get("details", {}).get("vuln_type") or finding_type,
                 "auth_type": finding.get("details", {}).get("auth_type"),
                 "waf_name": finding.get("details", {}).get("waf_name")
            }
            # Remove None values
            sanitized_details = {k: v for k, v in sanitized_details.items() if v is not None}
            
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
                priority=priority
            )
            
        return None

    def _select_tools(self, intent: str, available_tools: List[str], mode: ScanMode) -> List[str]:
        """
        Select and prioritize tools for an intent.
        
        This is a critical decision point - tool selection determines scan coverage.
        Every tool that is blocked, disabled, or rejected gets its own decision record.
        
        Decision Flow:
        1. Get candidate tools for this intent
        2. Filter by availability and completion status
        3. For each candidate:
           a. Check if disabled by mode overlay
           b. Check against Constitution (safety rules)
           c. Calculate priority score
        4. Emit individual decisions for rejections
        5. Return sorted list of approved tools
        """
        candidates = ToolRegistry.get_tools_for_intent(intent, mode=mode)
        candidates = [t for t in candidates if t in available_tools]
        candidates = [t for t in candidates if t not in self.context.completed_tools_per_intent.get(intent, set())]
        
        scored = []
        rejected_count = 0
        reasons: Dict[str, List[str]] = {}
        
        # Loop over items.
        for t in candidates:
            tool_def = ToolRegistry.get(t, mode=mode)
            tool_def["name"] = t
            
            # DECISION POINT: Tool disabled by mode overlay
            if tool_def.get("disabled"):
                rejected_count += 1
                reasons.setdefault("Mode Overlay", []).append(t)
                continue

            # DECISION POINT: Policy Arbitration (Unified: CAL + Python)
            # Create enriched context for policy evaluation
            # Includes fields required by both CAL laws and Python policies
            sim_ctx = {
                # Tool definition fields
                **tool_def,
                "tool": tool_def,  # For CAL's tool.field access

                # Scan context fields
                "target": self.context.target if self.context else "unknown",
                "mode": mode.value,

                # CAL-specific fields (required by constitution.cal)
                "phase_index": self.context.phase_index if self.context else 0,
                "knowledge": self.context.knowledge if self.context else {},
                "active_tools": len(self._tool_tasks),
                "max_concurrent": self._tool_semaphore._value if self._tool_semaphore else 10,
            }
            simulated_decision = DecisionPoint.create(
                DecisionType.TOOL_SELECTION,
                chosen=t,
                reason="Candidate Qualification",
                context=sim_ctx
            )
            judgment = self.arbitrator.review(simulated_decision, sim_ctx)
            
            if judgment.verdict == Verdict.VETO:
                rejected_count += 1
                reason = f"Policy Veto: {judgment.policy_name}"
                reasons.setdefault(reason, []).append(t)
                continue
            
            # DECISION POINT: Scoring (implicit selection)
            score = self._calculate_score(tool_def, mode)
            scored.append((t, score))
            
        # Emit grouped rejection decisions
        if self._decision_ctx and self._current_intent_decision and reasons:
            with self._decision_ctx.nested(self._current_intent_decision):
                for reason_desc, tools in reasons.items():
                    self._decision_ctx.choose(
                        decision_type=DecisionType.TOOL_REJECTION,
                        chosen="BLOCKED",
                        reason=reason_desc,
                        context={
                            "tools": tools,
                            "count": len(tools),
                            "intent": intent,
                            "mode": mode.value
                        }
                    )
        
        # Sort by score (highest priority first)
        scored.sort(key=lambda x: x[1], reverse=True)
        selected_tools = [t for t, _ in scored]
        
        # DECISION POINT: Final tool selection for this intent
        # Emit a single decision recording all selected tools
        if self._decision_ctx and self._current_intent_decision:
            with self._decision_ctx.nested(self._current_intent_decision):
                self._decision_ctx.choose(
                    decision_type=DecisionType.TOOL_SELECTION,
                    chosen=selected_tools,
                    reason=f"Selected {len(selected_tools)} tools for {intent} (rejected {rejected_count})",
                    alternatives=candidates,  # All candidates considered
                    context={
                        "intent": intent,
                        "mode": mode.value,
                        "selected_count": len(selected_tools),
                        "rejected_count": rejected_count
                    },
                    evidence={
                        "tool_scores": {t: score for t, score in scored},
                        "available_count": len(available_tools)
                    }
                )
        
        return selected_tools

    def _calculate_score(self, tool_def: Dict, mode: ScanMode) -> int:
        """Function _calculate_score."""
        overlay_map = ModeRegistry.get_overlay(mode)
        tool_name = tool_def.get("name")
        overlay = overlay_map.get(tool_name)
        
        priority = overlay.priority_boost if overlay and overlay.priority_boost else 0
        cost = tool_def.get("cost", 1)
        intrusiveness = tool_def.get("intrusiveness", 1)
        
        return (priority * 10) - (cost * 2) - intrusiveness

    def _decide_next_step(self, current_intent: str) -> Optional[str]:
        """
        Strategic decision: what intent to execute next.
        
        This implements the core scan progression logic:
        - Standard: Passive → Active → Surface → Vuln → Heavy
        - Bug Bounty: Passive → Active → Surface → Vuln (skip Heavy)
        - Walk Away: Terminate early if no new surface discovered
        
        Every transition (or termination) is an explicit decision with justification.
        
        Decision Types:
        - Intent transition: Moving to next phase
        - Early termination: Walk Away logic
        - Mode adaptation: Skipping phases based on mode constraints
        """
        # Handle edge cases for unit tests and initial state
        if self.context is None or current_intent is None:
            return INTENT_PASSIVE_RECON
        
        mode = self.context.knowledge.get("mode", ScanMode.STANDARD)
        
        # DECISION POINT: Post-Passive Recon
        if current_intent == INTENT_PASSIVE_RECON:
            next_intent = INTENT_ACTIVE_LIVE_CHECK
            if self._decision_ctx:
                self._decision_ctx.choose(
                    decision_type=DecisionType.INTENT_TRANSITION,
                    chosen=next_intent,
                    reason="Passive recon complete, proceeding to active live checks",
                    alternatives=[None],  # Could terminate, but standard progression continues
                    context={"from": current_intent, "to": next_intent, "mode": mode.value},
                    evidence={"findings_count": len(self.context.findings)}
                )
            return next_intent
        
        # DECISION POINT: Post-Active Live Check
        if current_intent == INTENT_ACTIVE_LIVE_CHECK:
            next_intent = INTENT_SURFACE_ENUMERATION
            if self._decision_ctx:
                self._decision_ctx.choose(
                    decision_type=DecisionType.INTENT_TRANSITION,
                    chosen=next_intent,
                    reason="Live checks complete, proceeding to surface enumeration",
                    alternatives=[None],
                    context={"from": current_intent, "to": next_intent, "mode": mode.value},
                    evidence={"findings_count": len(self.context.findings)}
                )
            return next_intent
        
        # DECISION POINT: Post-Surface Enumeration (Walk Away Logic)
        if current_intent == INTENT_SURFACE_ENUMERATION:
            # Bug Bounty Walk Away: Terminate if no new surface discovered
            if mode == ScanMode.BUG_BOUNTY and self.context.surface_delta_this_intent == 0:
                self._emit_log("[Strategos] Walk Away: No new surface discovered. Aborting deep scan.")
                
                if self._decision_ctx:
                    self._decision_ctx.choose(
                        decision_type=DecisionType.EARLY_TERMINATION,
                        chosen="WALK_AWAY",
                        reason="No new attack surface discovered in surface enumeration phase",
                        alternatives=[INTENT_VULN_SCANNING],  # What we could do instead
                        context={
                            "from": current_intent,
                            "mode": mode.value,
                            "trigger": "bug_bounty_zero_surface_delta"
                        },
                        evidence={
                            "surface_delta_this_intent": self.context.surface_delta_this_intent,
                            "total_surface_size": len(self.context.surface_seen),
                            "findings_this_intent": self.context.findings_this_intent
                        }
                    )
                
                return None  # Terminate mission
            
            # Standard progression: proceed to vuln scanning
            next_intent = INTENT_VULN_SCANNING
            if self._decision_ctx:
                self._decision_ctx.choose(
                    decision_type=DecisionType.INTENT_TRANSITION,
                    chosen=next_intent,
                    reason="Surface enumeration complete, proceeding to vulnerability scanning",
                    alternatives=[None],  # Could Walk Away
                    context={"from": current_intent, "to": next_intent, "mode": mode.value},
                    evidence={
                        "surface_delta": self.context.surface_delta_this_intent,
                        "total_surface": len(self.context.surface_seen)
                    }
                )
            return next_intent
        
        # DECISION POINT: Post-Vuln Scanning (Mode-Based Heavy Artillery)
        if current_intent == INTENT_VULN_SCANNING:
            # Bug Bounty Mode: Skip heavy artillery (too aggressive)
            if mode == ScanMode.BUG_BOUNTY:
                self._emit_log("[Strategos] Bug Bounty Mode: Skipping Heavy Artillery.")
                
                if self._decision_ctx:
                    self._decision_ctx.choose(
                        decision_type=DecisionType.MODE_ADAPTATION,
                        chosen="SKIP_HEAVY_ARTILLERY",
                        reason="Bug Bounty mode prohibits heavy/aggressive scanning tools",
                        alternatives=[INTENT_HEAVY_ARTILLERY],  # What we're skipping
                        context={
                            "from": current_intent,
                            "mode": mode.value,
                            "skipped_intent": INTENT_HEAVY_ARTILLERY
                        }
                    )
                
                return None  # Terminate mission gracefully
            
            # Standard mode: proceed to heavy artillery
            next_intent = INTENT_HEAVY_ARTILLERY
            if self._decision_ctx:
                self._decision_ctx.choose(
                    decision_type=DecisionType.INTENT_TRANSITION,
                    chosen=next_intent,
                    reason="Vulnerability scanning complete, proceeding to heavy artillery",
                    alternatives=[None],  # Could stop here
                    context={"from": current_intent, "to": next_intent, "mode": mode.value},
                    evidence={"findings_count": len(self.context.findings)}
                )
            return next_intent
        
        # DECISION POINT: Post-Heavy Artillery (End of Standard Scan)
        # No more intents, mission complete
        if self._decision_ctx:
            self._decision_ctx.choose(
                decision_type=DecisionType.EARLY_TERMINATION,
                chosen="MISSION_COMPLETE",
                reason="All intents exhausted, scan complete",
                context={"last_intent": current_intent, "mode": mode.value},
                evidence={
                    "total_findings": len(self.context.findings),
                    "total_surface": len(self.context.surface_seen),
                    "total_tools_run": sum(
                        len(tools) for tools in self.context.completed_tools_per_intent.values()
                    )
                }
            )
        
        return None
    
    def _get_phase_for_intent(self, intent: str) -> int:
        """Map intent to numeric phase for compatibility with existing phase tracking."""
        # Conditional branch.
        if intent == INTENT_PASSIVE_RECON:
            return PHASE_1_PASSIVE
        # Conditional branch.
        if intent == INTENT_ACTIVE_LIVE_CHECK:
            return PHASE_2_LIGHT
        # Conditional branch.
        if intent == INTENT_SURFACE_ENUMERATION:
            return PHASE_3_SURFACE
        # Conditional branch.
        if intent == INTENT_VULN_SCANNING:
            return PHASE_4_DEEP
        # Conditional branch.
        if intent == INTENT_HEAVY_ARTILLERY:
            return PHASE_5_HEAVY
        return 0
    
    def _get_available_intents(self, current_intent: str, mode: ScanMode) -> List[str]:
        """
        Get the list of possible next intents for decision recording.
        
        This documents what alternatives existed at each decision point.
        Helps with decision replay and "what-if" analysis.
        """
        # Standard progression sequence
        if current_intent == INTENT_PASSIVE_RECON:
            return [INTENT_ACTIVE_LIVE_CHECK, None]  # Could terminate early
        
        # Conditional branch.
        if current_intent == INTENT_ACTIVE_LIVE_CHECK:
            return [INTENT_SURFACE_ENUMERATION, None]
        
        # Conditional branch.
        if current_intent == INTENT_SURFACE_ENUMERATION:
            if mode == ScanMode.BUG_BOUNTY:
                # Bug bounty has Walk Away option
                return [INTENT_VULN_SCANNING, None]
            return [INTENT_VULN_SCANNING, None]
        
        # Conditional branch.
        if current_intent == INTENT_VULN_SCANNING:
            if mode == ScanMode.BUG_BOUNTY:
                # No heavy artillery in bug bounty
                return [None]
            return [INTENT_HEAVY_ARTILLERY, None]
        
        # Heavy artillery is always terminal
        return [None]
