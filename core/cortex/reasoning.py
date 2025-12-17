# core/cortex/reasoning.py

from core.cortex.arbitration import ArbitrationEngine
from core.cortex.narrator import NarratorEngine
from core.cortex.events import EventBus
from core.scheduler.decisions import DecisionLedger, DecisionContext
from core.scheduler.strategos import Strategos

class ReasoningEngine:
    """
    Composition root for the reasoning stack.
    This wires Strategos + Cortex + Narrator together.
    """

    def __init__(self):
        self.event_bus = EventBus()
        self.ledger = DecisionLedger()
        self.narrator = NarratorEngine(event_bus=self.event_bus)
        self.cortex = ArbitrationEngine()

        self.strategos = Strategos(
            event_bus=self.event_bus,
            narrator=self.narrator
        )

        
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
