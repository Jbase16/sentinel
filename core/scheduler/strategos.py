# ============================================================================
# core/scheduler/strategos.py
# Strategos - Strategic Scan Planning and Coordination
# ============================================================================
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
# ============================================================================

"""
core/scheduler/strategos.py
The Mind of the Scanner.
Implements a True Async Agent Loop with Event-Driven Concurrency.
"""

import asyncio
import logging
from typing import List, Dict, Any, Callable, Awaitable, Optional, Set
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
from core.scheduler.events import ToolStartedEvent, ToolCompletedEvent, MissionTerminatedEvent

logger = logging.getLogger(__name__)

DEFAULT_EVENT_QUEUE_MAXSIZE = 1024

@dataclass
class ScanContext:
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
    A truly concurrent, event-driven planner.
    """
    
    def __init__(
        self,
        event_queue_maxsize: int = DEFAULT_EVENT_QUEUE_MAXSIZE,
        log_fn: Optional[Callable[[str], None]] = None,
    ):
        self.constitution = Constitution()
        self.registry = ToolRegistry()
        self.context: Optional[ScanContext] = None
        self.event_queue: asyncio.Queue = asyncio.Queue(maxsize=event_queue_maxsize)
        self._terminated = False
        self._dispatch_callback: Optional[Callable[[str], Awaitable[List[Dict]]]] = None
        self._tool_tasks: Dict[str, asyncio.Task] = {}
        self._tool_semaphore: Optional[asyncio.Semaphore] = None
        self._log_fn = log_fn

    def _emit_log(self, message: str, level: str = "info") -> None:
        try:
            log_method = getattr(logger, level, logger.info)
            log_method(message)
        except Exception:
            pass

        if self._log_fn:
            try:
                self._log_fn(message)
            except Exception:
                pass
        
    async def run_mission(
        self, 
        target: str, 
        available_tools: List[str], 
        mode: ScanMode,
        dispatch_tool: Callable[[str], Awaitable[List[Dict]]]
    ) -> MissionTerminatedEvent:
        """
        The Agent Loop.
        Dispatches tools concurrently, listens for events, and re-plans.
        """
        while not self.event_queue.empty():
            try:
                self.event_queue.get_nowait()
            except asyncio.QueueEmpty:
                break

        self.context = ScanContext(target=target)
        self.context.knowledge["mode"] = mode
        # Seed baseline tags so protocol-gated tools can run deterministically.
        # If the target is a URL, we still assume both HTTP and HTTPS are plausible
        # until evidence proves otherwise.
        existing_tags = self.context.knowledge.get("tags")
        if not isinstance(existing_tags, set):
            existing_tags = set()
        existing_tags.update({"protocol:http", "protocol:https"})
        self.context.knowledge["tags"] = existing_tags
        self._terminated = False
        self._dispatch_callback = dispatch_tool
        self._tool_tasks = {}
        self._tool_semaphore = asyncio.Semaphore(self.context.max_concurrent)
        
        current_intent = INTENT_PASSIVE_RECON
        
        self._emit_log(f"[Strategos] Mission Start: {target} (Mode: {mode.value})")
        
        # Start event listener in background
        listener_task = asyncio.create_task(self._event_listener())
        
        try:
            # === THE AGENT LOOP ===
            while not self._terminated:
                self.context.phase_index = self._get_phase_for_intent(current_intent)
                self.context.findings_this_intent = 0
                self.context.surface_delta_this_intent = 0
                
                self._emit_log(f"[Strategos] Decision: Executing {current_intent}")
                
                # Get tools for this intent
                tools_to_run = self._select_tools(current_intent, available_tools, mode)
                
                if not tools_to_run:
                    self._emit_log(f"[Strategos] No tools available for {current_intent}. Skipping.")
                else:
                    # Dispatch all tools for this intent (ASYNC)
                    await self._dispatch_tools_async(tools_to_run, intent=current_intent)
                    
                    # Wait for all tools in this intent to complete
                    await self._wait_for_intent_completion()
                
                # THINK: What next?
                next_intent = self._decide_next_step(current_intent)
                
                if next_intent is None:
                    self._terminated = True
                else:
                    current_intent = next_intent
        finally:
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

    async def _run_tool_worker(self, tool: str, intent: str):
        """
        Runs a tool and pushes ToolCompletedEvent to queue.
        """
        findings = []
        success = True
        start = asyncio.get_running_loop().time()
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
        while self.context.running_tools:
            await asyncio.sleep(0.1)
    
    def ingest_findings(self, findings: List[Dict]):
        """
        Active Feedback.
        """
        if not self.context:
            return
            
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
        """
        candidates = ToolRegistry.get_tools_for_intent(intent, mode=mode)
        candidates = [t for t in candidates if t in available_tools]
        candidates = [t for t in candidates if t not in self.context.completed_tools_per_intent.get(intent, set())]
        
        scored = []
        for t in candidates:
            tool_def = ToolRegistry.get(t, mode=mode)
            tool_def["name"] = t
            
            if tool_def.get("disabled"):
                continue
            
            decision = self.constitution.check(self.context, tool_def)
            if not decision.allowed:
                self._emit_log(f"[Strategos] Blocked {t}: {decision.reason} ({decision.blocking_law})")
                continue
                
            score = self._calculate_score(tool_def, mode)
            scored.append((t, score))
        
        scored.sort(key=lambda x: x[1], reverse=True)
        return [t for t, _ in scored]

    def _calculate_score(self, tool_def: Dict, mode: ScanMode) -> int:
        overlay_map = ModeRegistry.get_overlay(mode)
        tool_name = tool_def.get("name")
        overlay = overlay_map.get(tool_name)
        
        priority = overlay.priority_boost if overlay and overlay.priority_boost else 0
        cost = tool_def.get("cost", 1)
        intrusiveness = tool_def.get("intrusiveness", 1)
        
        return (priority * 10) - (cost * 2) - intrusiveness

    def _decide_next_step(self, current_intent: str) -> Optional[str]:
        mode = self.context.knowledge.get("mode", ScanMode.STANDARD)
        
        if current_intent == INTENT_PASSIVE_RECON:
            return INTENT_ACTIVE_LIVE_CHECK
            
        if current_intent == INTENT_ACTIVE_LIVE_CHECK:
            return INTENT_SURFACE_ENUMERATION
            
        if current_intent == INTENT_SURFACE_ENUMERATION:
            if mode == ScanMode.BUG_BOUNTY and self.context.surface_delta_this_intent == 0:
                self._emit_log("[Strategos] Walk Away: No new surface discovered. Aborting deep scan.")
                return None
            return INTENT_VULN_SCANNING
            
        if current_intent == INTENT_VULN_SCANNING:
            if mode == ScanMode.BUG_BOUNTY:
                self._emit_log("[Strategos] Bug Bounty Mode: Skipping Heavy Artillery.")
                return None
            return INTENT_HEAVY_ARTILLERY
            
        return None
    
    def _get_phase_for_intent(self, intent: str) -> int:
        if intent == INTENT_PASSIVE_RECON: return PHASE_1_PASSIVE
        if intent == INTENT_ACTIVE_LIVE_CHECK: return PHASE_2_LIGHT
        if intent == INTENT_SURFACE_ENUMERATION: return PHASE_3_SURFACE
        if intent == INTENT_VULN_SCANNING: return PHASE_4_DEEP
        if intent == INTENT_HEAVY_ARTILLERY: return PHASE_5_HEAVY
        return 0
