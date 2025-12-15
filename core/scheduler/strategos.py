"""
core/scheduler/strategos.py
The Mind of the Scanner.
Implements a True Async Agent Loop with Event-Driven Concurrency.
"""

import asyncio
import logging
from typing import List, Dict, Any, Callable, Awaitable, Optional, Set
from dataclasses import dataclass, field

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

@dataclass
class ScanContext:
    target: str
    phase_index: int = 0
    knowledge: Dict[str, Any] = field(default_factory=dict)
    active_tools: int = 0
    max_concurrent: int = 3  # Real throttling limit
    findings: List[Dict] = field(default_factory=list)
    findings_this_intent: int = 0
    running_tools: Set[str] = field(default_factory=set)

class Strategos:
    """
    The Strategist.
    A truly concurrent, event-driven planner.
    """
    
    def __init__(self):
        self.constitution = Constitution()
        self.registry = ToolRegistry()
        self.context: Optional[ScanContext] = None
        self.event_queue: asyncio.Queue = asyncio.Queue()
        self._terminated = False
        self._dispatch_callback: Optional[Callable[[str], Awaitable[None]]] = None
        
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
        self.context = ScanContext(target=target)
        self.context.knowledge["mode"] = mode
        self._terminated = False
        self._dispatch_callback = dispatch_tool
        
        current_intent = INTENT_PASSIVE_RECON
        
        logger.info(f"[Strategos] Mission Start: {target} (Mode: {mode.value})")
        
        # Start event listener in background
        listener_task = asyncio.create_task(self._event_listener())
        
        try:
            # === THE AGENT LOOP ===
            while not self._terminated:
                self.context.phase_index = self._get_phase_for_intent(current_intent)
                self.context.findings_this_intent = 0
                
                logger.info(f"[Strategos] Decision: Executing {current_intent}")
                
                # Get tools for this intent
                tools_to_run = self._select_tools(current_intent, available_tools, mode)
                
                if not tools_to_run:
                    logger.info(f"[Strategos] No tools available for {current_intent}. Skipping.")
                else:
                    # Dispatch all tools for this intent (ASYNC)
                    await self._dispatch_tools_async(tools_to_run)
                    
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
            listener_task.cancel()
            try:
                await listener_task
            except asyncio.CancelledError:
                pass
        
        reason = "Mission Complete. All intents exhausted or Walk Away triggered."
        logger.info(f"[Strategos] {reason}")
        return MissionTerminatedEvent(reason=reason)
    
    async def _dispatch_tools_async(self, tools: List[str]):
        """
        Fire-and-forget dispatch with concurrency throttling.
        """
        for tool in tools:
            # THROTTLE: Wait for a slot
            while self.context.active_tools >= self.context.max_concurrent:
                logger.debug(f"[Strategos] Throttling: {self.context.active_tools}/{self.context.max_concurrent} slots used.")
                await asyncio.sleep(0.1)
            
            # Dispatch (fire-and-forget)
            self.context.active_tools += 1
            self.context.running_tools.add(tool)
            logger.info(f"[Strategos] Dispatching: {tool} ({self.context.active_tools}/{self.context.max_concurrent})")
            
            asyncio.create_task(self._run_tool_worker(tool))
    
    async def _run_tool_worker(self, tool: str):
        """
        Runs a tool and pushes ToolCompletedEvent to queue.
        """
        findings = []
        success = True
        try:
            findings = await self._dispatch_callback(tool)
            if findings is None:
                findings = []
        except Exception as e:
            logger.error(f"[Strategos] Tool {tool} failed: {e}")
            success = False
        finally:
            event = ToolCompletedEvent(tool=tool, findings=findings, success=success)
            await self.event_queue.put(event)
    
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
        self.context.active_tools -= 1
        self.context.running_tools.discard(event.tool)
        
        if event.findings:
            self.ingest_findings(event.findings)
        
        status = "✓" if event.success else "✗"
        logger.info(f"[Strategos] {status} {event.tool} complete. Findings: {len(event.findings)}")
    
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
            
            tags = finding.get("tags", [])
            finding_type = finding.get("type", "")
            if finding_type:
                tags.append(finding_type)
            
            existing_tags = self.context.knowledge.get("tags", set())
            existing_tags.update(tags)
            self.context.knowledge["tags"] = existing_tags
            
        logger.info(f"[Strategos] Ingested {len(findings)} findings. Total: {len(self.context.findings)}")

    def _select_tools(self, intent: str, available_tools: List[str], mode: ScanMode) -> List[str]:
        """
        Select and prioritize tools for an intent.
        """
        candidates = ToolRegistry.get_tools_for_intent(intent, mode=mode)
        candidates = [t for t in candidates if t in available_tools]
        
        scored = []
        for t in candidates:
            tool_def = ToolRegistry.get(t, mode=mode)
            tool_def["name"] = t
            
            if tool_def.get("disabled"):
                continue
            
            decision = self.constitution.check(self.context, tool_def)
            if not decision.allowed:
                logger.info(f"[Strategos] Blocked {t}: {decision.reason} ({decision.blocking_law})")
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
            if mode == ScanMode.BUG_BOUNTY and self.context.findings_this_intent == 0:
                logger.info("[Strategos] Walk Away: No new surface discovered. Aborting deep scan.")
                return None
            return INTENT_VULN_SCANNING
            
        if current_intent == INTENT_VULN_SCANNING:
            if mode == ScanMode.BUG_BOUNTY:
                logger.info("[Strategos] Bug Bounty Mode: Skipping Heavy Artillery.")
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
