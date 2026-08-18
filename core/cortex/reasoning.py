"""Module reasoning: inline documentation for /Users/jason/Developer/sentinelforge/core/cortex/reasoning.py."""
# core/cortex/reasoning.py
#
# PURPOSE:
# Composition root for strategic decisions, narration, and Nexus hypotheses.
#

from typing import Dict, Any, Optional
from core.cortex.arbitration import ArbitrationEngine
from core.cortex.narrator import NarratorEngine
from core.cortex.events import get_event_bus
from core.scheduler.decisions import DecisionLedger
from core.scheduler.strategos import Strategos

import logging

logger = logging.getLogger(__name__)

class ReasoningEngine:
    """
    Composition root for Strategos, typed arbitration, narration, and Nexus.
    """

    _instance = None

    def __init__(self):
        """Function __init__."""
        self.event_bus = get_event_bus()  # SINGLETON - never instantiate directly
        self.ledger = DecisionLedger()
        self.narrator = NarratorEngine(event_bus=self.event_bus)
        self.cortex = ArbitrationEngine()

        self.strategos = Strategos(
            event_bus=self.event_bus,
            narrator=self.narrator
        )
        
        # Initialize Epistemic Recoil (Automated Falsification)
        from core.aegis.nexus.recoil import Recoil
        self.recoil = Recoil()
        self.recoil.start()
        
        logger.info("ReasoningEngine initialized")
        
    @classmethod
    def instance(cls) -> "ReasoningEngine":
        """Get the singleton instance."""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance
    
    def analyze(self) -> dict:
        """
        Return a summary of the decision ledger and Nexus hypothesis state.
        Used by /cortex/reasoning API endpoint and Report Engine.
        """
        from core.cortex.nexus_context import NexusContext
        
        ledger_stats = {}
        if self.strategos._decision_ledger:
            ledger_stats = self.strategos._decision_ledger.stats()
            
        # Get synthesized context from Nexus
        nexus_context = NexusContext.instance().analyze_context()
        hypothesized_attack_paths = nexus_context.get(
            "hypothesized_attack_paths",
            nexus_context.get("attack_paths", []),
        )
            
        return {
            "status": "ok",
            "scope": "global",
            "decision_ledger": ledger_stats,
            # Canonical label: hypothesis-layer path synthesis from Nexus.
            "hypothesized_attack_paths": hypothesized_attack_paths,
            # Backward-compat alias (deprecated): use hypothesized_attack_paths.
            "attack_paths": hypothesized_attack_paths,
            "recommended_phases": nexus_context.get("recommended_phases", [])
        }
        
    async def start_scan(self, 
        target: str, 
        available_tools: list[str], 
        mode: str, 
        dispatch_tool: callable, 
        log_fn: callable = None,
        knowledge: Optional[Dict[str, Any]] = None,
    ):
        """
        Entry point used by API.
        """
        from core.scheduler.modes import ScanMode
        try:
            scan_mode = ScanMode(mode)
        except ValueError:
            scan_mode = ScanMode.STANDARD
            
        return await self.strategos.run_mission(
            target=target,
            available_tools=available_tools,
            mode=scan_mode,
            dispatch_tool=dispatch_tool,
            log_fn=log_fn,
            knowledge=knowledge,
        )
# Module-level compatibility import backed by the one composition-root instance.
reasoning_engine = ReasoningEngine.instance()
