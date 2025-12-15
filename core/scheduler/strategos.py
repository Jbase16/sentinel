"""
core/scheduler/strategos.py
The Mind of the Scanner.
Implements the 7-Phase God-Tier Logic with Intent-Based Scheduling.
"""

import asyncio
import logging
from typing import List, Dict, AsyncGenerator
from dataclasses import dataclass, field

from core.scheduler.laws import Constitution
from core.scheduler.registry import ToolRegistry, PHASE_1_PASSIVE, PHASE_2_LIGHT, PHASE_3_SURFACE, PHASE_4_DEEP, PHASE_5_HEAVY
from core.scheduler.modes import ScanMode
from core.scheduler.intents import (
    INTENT_PASSIVE_RECON,
    INTENT_ACTIVE_LIVE_CHECK, 
    INTENT_SURFACE_ENUMERATION,
    INTENT_VULN_SCANNING,
    INTENT_HEAVY_ARTILLERY
)

logger = logging.getLogger(__name__)

@dataclass
class ScanContext:
    target: str
    phase_index: int = 0
    knowledge: Dict[str, Any] = field(default_factory=dict)
    active_tools: int = 0
    max_concurrent: int = 5
    findings: List[Dict] = field(default_factory=list)

class Strategos:
    """
    The Strategist.
    Decides WHAT to run and WHEN based on INTENTS.
    """
    
    # Map Phases to Intents
    PHASE_INTENTS = {
        PHASE_1_PASSIVE: [INTENT_PASSIVE_RECON],
        PHASE_2_LIGHT: [INTENT_ACTIVE_LIVE_CHECK],
        PHASE_3_SURFACE: [INTENT_SURFACE_ENUMERATION],
        PHASE_4_DEEP: [INTENT_VULN_SCANNING],
        PHASE_5_HEAVY: [INTENT_HEAVY_ARTILLERY]
    }

    def __init__(self):
        self.constitution = Constitution()
        self.registry = ToolRegistry()

    async def orchestrate(self, target: str, available_tools: List[str], mode: ScanMode = ScanMode.STANDARD) -> AsyncGenerator[str, None]:
        """
        The Thinking Loop.
        Continually asks: "What is the highest value intent now?"
        """
        context = ScanContext(target=target)
        context.knowledge["mode"] = mode

        # Initial State: We start at Phase 1 intent
        next_intent = INTENT_PASSIVE_RECON

        # State Loop
        while next_intent:
            logger.info(f"[Strategos] Decision: Executing {next_intent} (Mode: {mode.value})")

            # Execute the chosen intent
            async for tool in self._execute_intent(next_intent, context, available_tools, mode):
                yield tool

            # After execution, THINK.
            # "Based on what I found, what should I do next?"
            next_intent = self._decide_next_step(context, next_intent)

            if not next_intent:
                logger.info("[Strategos] No further valuable intents found. Mission Complete.")
                break

    def _decide_next_step(self, context: ScanContext, current_intent: str) -> str:
        """
        The Brain. Evaluates Knowledge to pick the next Intent.
        For V1, we implement a linear progression but with 'Wait' capability.
        """
        # Simple Phase Progression for now (with hooks for complex logic later)
        if current_intent == INTENT_PASSIVE_RECON:
            # If we found nothing in Passive, maybe stop? 
            # For now, proceed to Active
            context.phase_index = PHASE_2_LIGHT
            return INTENT_ACTIVE_LIVE_CHECK
            
        if current_intent == INTENT_ACTIVE_LIVE_CHECK:
            context.phase_index = PHASE_3_SURFACE
            return INTENT_SURFACE_ENUMERATION
            
        if current_intent == INTENT_SURFACE_ENUMERATION:
            # Check findings. If 0 open ports, maybe stop?
            context.phase_index = PHASE_4_DEEP
            return INTENT_VULN_SCANNING
            
        if current_intent == INTENT_VULN_SCANNING:
            # In Bug Bounty Mode, we might stop here.
            # In Standard Mode, maybe Heavy Artillery?
            mode = context.knowledge.get("mode", ScanMode.STANDARD)
            if mode == ScanMode.BUG_BOUNTY:
                logger.info("[Strategos] Bug Bounty Mode: Skipping Heavy Artillery.")
                return None
            
            context.phase_index = PHASE_5_HEAVY
            return INTENT_HEAVY_ARTILLERY
            
        return None

    async def _execute_intent(self, intent: str, context: ScanContext, available_tools: List[str], mode: ScanMode) -> AsyncGenerator[str, None]:
        """
        Realize an Intent into Tool Actions.
        """
        # Get candidates with Mode Filtering applied
        candidates = ToolRegistry.get_tools_for_intent(intent, mode=mode)

        # Filter: Must be in available_tools (installed)
        candidates = [t for t in candidates if t in available_tools]

        for tool in candidates:
            # Get tool def with Mode Layout applied (costs/disabled)
            tool_def = ToolRegistry.get(tool, mode=mode)
            if tool_def.get("disabled"):
                logger.info(f"[Strategos] Tool {tool} is DISABLED in {mode.value} mode.")
                continue

            tool_def["name"] = tool

            # LAW CHECK (Returns Decision)
            decision = self.constitution.check(context, tool_def)

            if decision.allowed:
                yield tool
            else:
                logger.info(f"[Strategos] Blocked {tool}: {decision.reason} ({decision.blocking_law})")

    def _get_phase_name(self, idx: int) -> str:
        if idx == PHASE_1_PASSIVE: return "Phase 1: Passive Recon"
        if idx == PHASE_2_LIGHT: return "Phase 2: Light Active"
        if idx == PHASE_3_SURFACE: return "Phase 3: Surface Mapping"
        if idx == PHASE_4_DEEP: return "Phase 4: Deep Scan"
        if idx == PHASE_5_HEAVY: return "Phase 5: Heavy Artillery"
        return f"Phase {idx}"
