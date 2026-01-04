"""
core/observer/bus.py

Purpose:
    The central message bus.
    Implements the Publish-Subscribe pattern for system-wide telemetry.

Magnum Opus Standards:
    - Exception Safety: Subscriber errors are isolated.
    - Singleton Integrity: Single shared instance.
    - Typing: Callback protocols.
"""

from __future__ import annotations
import logging
from typing import Callable, List, Dict, Type
from collections import defaultdict

from .events import TelemetryEvent, EventType

log = logging.getLogger("observer.bus")

# Type alias for a subscriber callback
# Subscriber receives the event and returns nothing
Subscriber = Callable[[TelemetryEvent], None]

class EventBus:
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(EventBus, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
        
        # Subscribers map: EventType -> List[Callbacks]
        # Use "*" as a key for global subscribers (wildcard)
        self._subscribers: Dict[str, List[Subscriber]] = defaultdict(list)
        self._initialized = True
        log.info("EventBus initialized.")

    def subscribe(self, event_type: EventType | str, callback: Subscriber):
        """
        Register a callback for a specific event type.
        Use "*" for all events.
        """
        key = event_type.value if isinstance(event_type, EventType) else event_type
        self._subscribers[key].append(callback)
        log.debug(f"Subscribed {callback.__name__} to {key}")

    def emit(self, event: TelemetryEvent):
        """
        Publish an event to all interested subscribers.
        Errors in subscribers are caught and logged to prevent system crash.
        """
        # 1. Notify specific subscribers
        self._notify_list(event.type.value, event)
        
        # 2. Notify global subscribers ("*")
        self._notify_list("*", event)

    def _notify_list(self, key: str, event: TelemetryEvent):
        if key not in self._subscribers:
            return

        for callback in self._subscribers[key]:
            try:
                callback(event)
            except Exception as e:
                # CRITICAL: A logging error must not crash the app.
                # We use the python logger as a fallback.
                log.error(f"EventBus Subscriber Error ({callback.__name__}): {e}", exc_info=True)

    def clear(self):
        """Reset subscribers (Useful for testing)."""
        self._subscribers.clear()

# Global Accessor
_bus = EventBus()

def get_event_bus() -> EventBus:
    return _bus
