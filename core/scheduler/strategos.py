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
from typing import List, Dict, Any, Callable, Awaitable, Optional, Set, TYPE_CHECKING
from dataclasses import dataclass, field
from urllib.parse import urlparse

from core.scheduler.laws import Constitution
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
from core.cortex.events import EventBus
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
class ScanContext:
    """Class ScanContext."""
    target: str
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
        self.constitution = Constitution()
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
        
        # Decision Emission Layer: All strategic choices flow through this context
        # This creates a complete audit trail separate from the event stream
        self._decision_ledger = decision_ledger or DecisionLedger()
        self._decision_ctx: Optional[DecisionContext] = None
        
        # Track current decision for hierarchical decision trees
        # Track current decision for hierarchical decision trees
        self._current_intent_decision: Optional[DecisionPoint] = None

        # Layer 4: Policy Arbitration
        self.arbitrator = ArbitrationEngine()
        self.arbitrator.register_policy(ScopePolicy())
        self.arbitrator.register_policy(RiskPolicy())

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
            narrator=self._narrator
        )
        
        current_intent = INTENT_PASSIVE_RECON
        
        self._emit_log(f"[Strategos] Mission Start: {target} (Mode: {mode.value})")
        
        # Start event listener in background
        listener_task = asyncio.create_task(self._event_listener())
        
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
                    self.ingest_findings(findings)
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
    
    def ingest_findings(self, findings: List[Dict]):
        """
        Active Feedback.
        """
        # Conditional branch.
        if not self.context:
            return
            
        # Loop over items.
        for finding in findings:
            self.context.findings.append(finding)
            self.context.findings_this_intent += 1

            surface_key = self._surface_key(finding)
            if surface_key and surface_key not in self.context.surface_seen:
                self.context.surface_seen.add(surface_key)
                self.context.surface_delta_this_intent += 1
            
            tags = finding.get("tags", [])
            finding_type = finding.get("type", "")
            if finding_type:
                tags.append(finding_type)
            
            existing_tags = self.context.knowledge.get("tags", set())
            existing_tags.update(tags)
            self.context.knowledge["tags"] = existing_tags
            
        self._emit_log(f"[Strategos] Ingested {len(findings)} findings. Total: {len(self.context.findings)}")

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
            
            # DECISION POINT: Constitutional check (safety rules)
            constitution_decision = self.constitution.check(self.context, tool_def)
            if not constitution_decision.allowed:
                rejected_count += 1
                reason = f"{constitution_decision.blocking_law} ({constitution_decision.reason})"
                reasons.setdefault(reason, []).append(t)
                continue
            
            # DECISION POINT: Policy Arbitration (Flexible Rules)
            # Create a transient decision to query the arbitrator
            # We must verify if this tool is acceptable under current policies
            sim_ctx = {
                **tool_def, 
                "target": self.context.target if self.context else "unknown", 
                "mode": mode.value
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
