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
    - Loose Coupling: Use Dependency Injection for target systems to avoid import cycles.
    - Resilience: Feedback errors must not stop the event stream.
"""

import logging
from typing import Protocol, Any

from .events import TelemetryEvent, EventType
from .bus import get_event_bus

log = logging.getLogger("observer.feedback")

# Protocols for the systems we influence
class PressureSystem(Protocol):
    def increase_pressure(self, node_id: str, amount: float) -> None: ...

class EconomicSystem(Protocol):
    def record_cost(self, trace_id: str, cost: float) -> None: ...
    def record_value(self, trace_id: str, value: float) -> None: ...

class FeedbackLoop:
    def __init__(self, pressure_system: PressureSystem, economic_system: EconomicSystem):
        self.pressure_system = pressure_system
        self.economic_system = economic_system
        self.bus = get_event_bus()

    def start(self):
        """Register subscriptions."""
        self.bus.subscribe(EventType.BREACH_DETECTED, self._on_breach)
        self.bus.subscribe(EventType.EXECUTION_COMPLETED, self._on_execution_complete)
        log.info("Feedback Loop engaged.")

    def _on_breach(self, event: TelemetryEvent):
        """
        When a breach is detected, increase pressure on the target node.
        """
        try:
            target_id = event.payload.get("target_node_id") # Assuming payload has this
            severity = event.payload.get("severity", 1.0)
            
            if target_id:
                log.info(f"Feedback: Increasing pressure on {target_id} due to Breach.")
                # We boost pressure significantly on a proven breach
                self.pressure_system.increase_pressure(target_id, amount=severity * 10.0)
        except Exception as e:
            log.error(f"Feedback Error (Breach): {e}")

    def _on_execution_complete(self, event: TelemetryEvent):
        """
        Record the resource cost of the execution.
        """
        try:
            trace_id = event.trace_id
            duration = event.payload.get("duration_ms", 0)
            
            # Simple cost model: 1ms = 0.001 units
            cost = duration * 0.001
            
            if trace_id:
                self.economic_system.record_cost(trace_id, cost)
        except Exception as e:
            log.error(f"Feedback Error (Economics): {e}")
