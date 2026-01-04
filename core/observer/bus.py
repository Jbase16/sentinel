"""
core/observer/bus.py

Purpose:
    The central asynchronous message bus.
    Implements the Publish-Subscribe pattern for system-wide telemetry.

Magnum Opus Standards:
    - Async Detection: Automatically handles both sync and async subscribers.
    - Exception Isolation: Failures in listeners never propagate to the emitter.
    - Performance: Low-overhead dispatch.
"""

from __future__ import annotations
import logging
import inspect
import asyncio
from typing import Callable, List, Dict, Union, Awaitable
from collections import defaultdict

from .events import TelemetryEvent, EventType

log = logging.getLogger("observer.bus")

# Subscriber can be a sync function or an async coroutine
Subscriber = Union[
    Callable[[TelemetryEvent], None],
    Callable[[TelemetryEvent], Awaitable[None]]
]

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
        
        # Subscribers map: EventType -> List[Subscriber]
        self._subscribers: Dict[str, List[Subscriber]] = defaultdict(list)
        self._initialized = True
        log.info("Async EventBus initialized.")

    def subscribe(self, event_type: EventType | str, callback: Subscriber):
        """
        Register a callback for a specific event type.
        Use "*" for all events.
        """
        key = event_type.value if isinstance(event_type, EventType) else event_type
        self._subscribers[key].append(callback)
        func_name = getattr(callback, "__name__", str(callback))
        log.debug(f"Subscribed {func_name} to {key}")

    async def emit(self, event: TelemetryEvent):
        """
        Publish an event to all interested subscribers.
        Awaits all async subscribers concurrently.
        """
        tasks = []
        
        # 1. Collect all callbacks (specific + global)
        specific = self._subscribers.get(event.type.value, [])
        global_subs = self._subscribers.get("*", [])
        
        # Deduplicate is tricky with objects, but usually lists are disjoint enough.
        # We will just iterate both.
        
        for callback in specific + global_subs:
            tasks.append(self._invoke(callback, event))
            
        if tasks:
            # Run all invokes; _invoke handles error catching internally
            await asyncio.gather(*tasks)

    async def _invoke(self, callback: Subscriber, event: TelemetryEvent):
        """
        Safely executes a single subscriber, handling sync vs async.
        """
        try:
            if inspect.iscoroutinefunction(callback):
                await callback(event)
            else:
                # Run sync functions directly (or could offload to thread if blocking?)
                # For high-perf, sync functions should remain fast/non-blocking.
                callback(event)
        except Exception as e:
            func_name = getattr(callback, "__name__", str(callback))
            log.error(f"EventBus Subscriber Error ({func_name}): {e}", exc_info=True)

    def clear(self):
        """Reset subscribers."""
        self._subscribers.clear()

# Global Accessor
_bus = EventBus()

def get_event_bus() -> EventBus:
    return _bus
