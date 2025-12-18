"""Module reasoning: inline documentation for /Users/jason/Developer/sentinelforge/core/cortex/reasoning.py."""
# core/cortex/reasoning.py

from core.cortex.arbitration import ArbitrationEngine
from core.cortex.narrator import NarratorEngine
from core.cortex.events import get_event_bus
from core.scheduler.decisions import DecisionLedger, DecisionContext
from core.scheduler.strategos import Strategos

class ReasoningEngine:
    """
    Composition root for the reasoning stack.
    This wires Strategos + Cortex + Narrator together.
    """

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
        
    def analyze(self) -> dict:
        """
        Return a summary of the reasoning state (Decision Ledger).
        Used by /cortex/reasoning API endpoint.
        """
        # Conditional branch.
        if self.strategos._decision_ledger:
            stats = self.strategos._decision_ledger.stats()
            return {
                "status": "ok",
                "scope": "last_active_mission",
                "stats": stats,
            }
        return {
            "status": "ok", 
            "scope": "global",
            "stats": {}, 
            "message": "No decision ledger active"
        }
        
    async def start_scan(self, 
        target: str, 
        available_tools: list[str], 
        mode: str, 
        dispatch_tool: callable, 
        log_fn: callable = None
    ):
        """
        Entry point used by API.
        """
        from core.scheduler.modes import ScanMode
        # Error handling block.
        try:
            scan_mode = ScanMode(mode)
        except ValueError:
            scan_mode = ScanMode.STANDARD
            
        return await self.strategos.run_mission(
            target=target,
            available_tools=available_tools,
            mode=scan_mode,
            dispatch_tool=dispatch_tool,
            log_fn=log_fn
        )

# Optional singleton (matches API import)
reasoning_engine = ReasoningEngine()
