"""
core/observer/feedback.py

Purpose:
    The "Feedback Loop".
    Closes the cognitive cycle by routing outcomes back to the reasoning engines.
    
    Flow:
    1. Listen to Telemetry Events (e.g. BREACH_DETECTED).
    2. Normalize the signal.
    3. Update the State Engines (Aegis Pressure, Sentient Economics).
    
Magnum Opus Standards:
    - Async: Callbacks are async to support potentially IO-bound updates (like DB writes).
"""

import logging
from typing import Protocol, Any, Awaitable

from .events import TelemetryEvent, EventType
from .bus import get_event_bus

log = logging.getLogger("observer.feedback")

# Protocols for the systems we influence
class PressureSystem(Protocol):
    def increase_pressure(self, node_id: str, amount: float) -> None: ...

class EconomicSystem(Protocol):
    def record_cost(self, trace_id: str, cost: float) -> None: ...

class FeedbackPolicy(Protocol):
    """
    Defines HOW the system learns from outcomes.
    Separates policy (tuning) from mechanism (routing).
    """
    def breach_pressure(self, severity: float) -> float: ...
    def execution_cost(self, duration_ms: float) -> float: ...

class DefaultFeedbackPolicy:
    """Standard learning rates."""
    def breach_pressure(self, severity: float) -> float:
        return severity * 10.0

    def execution_cost(self, duration_ms: float) -> float:
        return duration_ms * 0.001

class FeedbackLoop:
    def __init__(
        self, 
        pressure_system: PressureSystem, 
        economic_system: EconomicSystem,
        policy: FeedbackPolicy = DefaultFeedbackPolicy()
    ):
        self.pressure_system = pressure_system
        self.economic_system = economic_system
        self.policy = policy
        self.bus = get_event_bus()

    def start(self):
        """Register subscriptions."""
        self.bus.subscribe(EventType.BREACH_DETECTED, self._on_breach)
        self.bus.subscribe(EventType.EXECUTION_COMPLETED, self._on_execution_complete)
        log.info("Feedback Loop engaged.")

    async def _on_breach(self, event: TelemetryEvent):
        """
        When a breach is detected, increase pressure on the target node.
        Async wrapper allows for future async system calls.
        """
        try:
            target_id = event.payload.get("target_node_id")
            severity = event.payload.get("severity", 1.0)
            
            if target_id:
                amount = self.policy.breach_pressure(float(severity))
                log.info(f"Feedback: Increasing pressure on {target_id} by {amount:.2f} (Breach).")
                self.pressure_system.increase_pressure(
                    node_id=target_id,
                    amount=amount,
                    reason=f"Feedback: {event.type.name}"
                )
        except Exception as e:
            log.error(f"Feedback Error (Breach): {e}")

    async def _on_execution_complete(self, event: TelemetryEvent):
        """
        Record the resource cost of the execution.
        """
        try:
            trace_id = event.trace_id
            duration = event.payload.get("duration_ms", 0)
            
            cost = self.policy.execution_cost(float(duration))
            
            if trace_id:
                self.economic_system.record_cost(trace_id, cost)
        except Exception as e:
            log.error(f"Feedback Error (Economics): {e}")
