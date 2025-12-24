"""Module event_store: inline documentation for /Users/jason/Developer/sentinelforge/core/cortex/event_store.py."""
#
# PURPOSE:
# The "Memory" of the event system.
# 1. Subscribes to the ephemeral EventBus.
# 2. Persists events to an in-memory ring buffer with sequence IDs.
# 3. Provides accurate replay capabilities for late-connecting clients.
# 4. Supports live subscription with loop-safe asyncio delivery.
#

import asyncio
import json
import logging
from dataclasses import dataclass
from typing import List, Optional, AsyncIterator, Tuple
from collections import deque
import threading

from core.cortex.events import GraphEvent, get_event_bus

logger = logging.getLogger(__name__)


@dataclass
class StoredEvent:
    """
    Wrapper that attaches a monotonic sequence ID to each event.
    This enables accurate replay via `since=N`.
    """
    sequence: int
    event: GraphEvent

    def to_json(self) -> str:
        """Serialize for SSE transmission. Matches Swift GraphEvent structure."""
        import uuid
        from datetime import datetime
        
        # Generate a stable ID from sequence (or use UUID for uniqueness)
        event_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"sentinel-event-{self.sequence}"))
        
        # Human-readable wall time
        wall_time = datetime.fromtimestamp(self.event.timestamp).isoformat()
        
        # Extract source from payload if available, otherwise use default
        source = self.event.payload.get("source", "strategos")
        
        return json.dumps({
            "id": event_id,
            "sequence": self.sequence,
            "type": self.event.type.value,
            "payload": self.event.payload,
            "timestamp": self.event.timestamp,
            "wall_time": wall_time,
            "source": source
        }, default=str)


class EventStore:
    """
    Append-only store for GraphEvents with replay capabilities.
    
    Guarantees:
    1. Every event gets a unique, monotonically increasing sequence ID.
    2. `get_since(N)` returns exactly events with sequence > N.
    3. Subscriber notification is loop-safe across sync/async boundaries.
    """
    def __init__(self, max_size: int = 5000):
        """Function __init__."""
        self._events: deque[StoredEvent] = deque(maxlen=max_size)
        self._lock = threading.RLock()
        self._sequence: int = 0
        
        # Subscribers: (queue, loop) tuples for loop-safe delivery
        self._subscribers: List[Tuple[asyncio.Queue, asyncio.AbstractEventLoop]] = []
        self._subscribers_lock = threading.Lock()
        
        # Auto-wire: Subscribe to the bus immediately
        get_event_bus().subscribe(self.append)

    def append(self, event: GraphEvent) -> StoredEvent:
        """
        Commit an event to the store and notify live subscribers.
        This is called automatically by the EventBus.
        """
        # Context-managed operation.
        with self._lock:
            self._sequence += 1
            stored = StoredEvent(sequence=self._sequence, event=event)
            self._events.append(stored)
        
        # Notify live subscribers (outside lock to avoid deadlock)
        self._notify_subscribers(stored)
        return stored

    def get_since(self, since_sequence: int = 0) -> Tuple[List[StoredEvent], bool]:
        """
        Replay events with sequence > since_sequence.
        
        Returns:
            Tuple of (events, truncated) where truncated=True if oldest 
            available event is newer than requested since_sequence.
        """
        # Context-managed operation.
        with self._lock:
            oldest_seq = self._events[0].sequence if self._events else 0
            truncated = since_sequence > 0 and since_sequence < oldest_seq
            
            if since_sequence <= 0:
                return list(self._events), truncated
            
            # Filter: only events with sequence > since
            return [e for e in self._events if e.sequence > since_sequence], truncated

    async def subscribe(self) -> AsyncIterator[StoredEvent]:
        """
        Async generator for live events.
        Captures the current event loop for thread-safe delivery.
        """
        loop = asyncio.get_running_loop()
        q: asyncio.Queue = asyncio.Queue()
        
        # Context-managed operation.
        with self._subscribers_lock:
            self._subscribers.append((q, loop))
        
        # Error handling block.
        try:
            while True:
                stored_event = await q.get()
                yield stored_event
        finally:
            with self._subscribers_lock:
                self._subscribers.remove((q, loop))

    def _notify_subscribers(self, stored_event: StoredEvent):
        """
        Push event to all active subscriber queues.
        Uses loop.call_soon_threadsafe for cross-thread safety.
        """
        # Context-managed operation.
        with self._subscribers_lock:
            subscribers_copy = list(self._subscribers)
        
        # Loop over items.
        for q, loop in subscribers_copy:
            try:
                # Thread-safe delivery: schedule on subscriber's event loop
                loop.call_soon_threadsafe(q.put_nowait, stored_event)
            except RuntimeError:
                # Loop is closed or not running - subscriber will be cleaned up
                pass
            except Exception as e:
                logger.debug(f"[EventStore] Failed to notify subscriber: {e}")

    def clear(self) -> None:
        """Clear all stored events. Useful for testing."""
        with self._lock:
            self._events.clear()
            self._sequence = 0

    def stats(self) -> dict:
        """Function stats."""
        # Context-managed operation.
        with self._lock:
            return {
                "events_stored": len(self._events),
                "current_sequence": self._sequence,
                "active_subscribers": len(self._subscribers),
                "max_size": self._events.maxlen
            }


# --- Module-Level Singleton ---

_store: Optional[EventStore] = None

def get_event_store() -> EventStore:
    """Function get_event_store."""
    global _store
    # Conditional branch.
    if _store is None:
        _store = EventStore()
    return _store
