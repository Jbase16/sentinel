"""
core/cortex/events.py
Event-Sourced Reactive Graph: The Nervous System of Sentinel.

This module implements an append-only event log with typed events for all graph mutations.
Subscribers receive real-time push notifications of changes, eliminating the need for polling.

Architectural Invariants:
1. Events are immutable once created
2. Sequence numbers provide total ordering
3. Subscribers can replay from any checkpoint
4. Thread-safe for concurrent producers
"""

from __future__ import annotations

import asyncio
import json
import logging
import threading
import time
import uuid
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, AsyncIterator, Callable, Dict, List, Optional, Set
from collections import deque

logger = logging.getLogger(__name__)


# ============================================================================
# Event Types - Semantic Classification of Graph Mutations
# ============================================================================

class GraphEventType(str, Enum):
    """
    Typed events for graph mutations. Each type has specific payload semantics.
    Using str mixin for JSON serialization compatibility.
    """
    # Graph Structure Events
    NODE_ADDED = "node_added"           # New node in knowledge graph
    NODE_UPDATED = "node_updated"       # Attributes changed on existing node
    NODE_REMOVED = "node_removed"       # Node deleted (rare in security scans)
    EDGE_ADDED = "edge_added"           # New relationship between nodes
    EDGE_UPDATED = "edge_updated"       # Edge weight/attributes changed
    
    # Scan Lifecycle Events
    SCAN_STARTED = "scan_started"       # Scan initiated with target
    SCAN_PHASE_CHANGED = "scan_phase_changed"  # e.g., recon -> discovery -> exploitation
    SCAN_COMPLETED = "scan_completed"   # Scan finished (success or cancelled)
    SCAN_ERROR = "scan_error"           # Non-fatal error during scan
    
    # Finding Events
    FINDING_DISCOVERED = "finding_discovered"  # New vulnerability/issue found
    FINDING_CONFIRMED = "finding_confirmed"    # AI or manual verification
    FINDING_DISMISSED = "finding_dismissed"    # False positive marked
    
    # AI/Reasoning Events
    HYPOTHESIS_GENERATED = "hypothesis_generated"  # AI proposed next action
    TOOL_INVOKED = "tool_invoked"              # Scanner tool started
    TOOL_COMPLETED = "tool_completed"          # Scanner tool finished
    
    # Observability Events
    LOG_EMITTED = "log_emitted"         # Log line added


# ============================================================================
# GraphEvent - Immutable Event Record
# ============================================================================

@dataclass(frozen=True)
class GraphEvent:
    """
    Immutable event record representing a single graph mutation.
    
    Fields:
        id: Unique identifier (UUID v4)
        type: Event classification (GraphEventType)
        timestamp: Monotonic time when event was created
        wall_time: Wall clock time (ISO format) for human readability
        sequence: Global monotonically increasing sequence number
        payload: Type-specific data (shape varies by event type)
        source: Origin of the event (e.g., "scanner:nmap", "ai:reasoning")
    
    Contract:
        - `sequence` is unique and strictly increasing
        - `payload` is immutable (frozen dict would be ideal, but json-compat needed)
        - Serialization to JSON is lossless and reversible
    """
    id: str
    type: GraphEventType
    timestamp: float
    wall_time: str
    sequence: int
    payload: Dict[str, Any]
    source: str = "system"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        d = asdict(self)
        d["type"] = self.type.value  # Enum -> string
        return d
    
    def to_json(self) -> str:
        """Serialize to JSON string."""
        return json.dumps(self.to_dict(), default=str)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> GraphEvent:
        """Deserialize from dictionary."""
        data = dict(data)  # Defensive copy
        data["type"] = GraphEventType(data["type"])
        return cls(**data)
    
    @classmethod
    def from_json(cls, json_str: str) -> GraphEvent:
        """Deserialize from JSON string."""
        return cls.from_dict(json.loads(json_str))


# ============================================================================
# EventStore - Append-Only Log with Replay Support
# ============================================================================

class EventStore:
    """
    Append-only event log with O(1) append and O(n) replay.
    
    Design Decisions:
    - In-memory storage for low-latency (can be swapped to SQLite for persistence)
    - Uses deque with maxlen for bounded memory (circular buffer behavior)
    - Thread-safe via RLock for concurrent producers
    - Async iteration support for reactive consumers
    
    Invariants:
    - Sequence numbers are globally unique and monotonically increasing
    - No event is ever modified after creation
    - Subscribers see events in strict sequence order
    """
    
    _instance: Optional[EventStore] = None
    _instance_lock = threading.Lock()
    
    @classmethod
    def instance(cls) -> EventStore:
        """Thread-safe singleton access."""
        if cls._instance is None:
            with cls._instance_lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance
    
    def __init__(self, max_events: int = 10000):
        """
        Initialize the event store.
        
        Args:
            max_events: Maximum events to retain in memory. Older events are
                        evicted when limit is reached (circular buffer).
        """
        self._events: deque[GraphEvent] = deque(maxlen=max_events)
        self._sequence = 0
        self._lock = threading.RLock()
        self._subscribers: Set[asyncio.Queue] = set()
        self._subscriber_lock = threading.Lock()
        
        # Checkpoint support: last known sequence per client
        self._checkpoints: Dict[str, int] = {}
    
    def append(
        self,
        event_type: GraphEventType,
        payload: Dict[str, Any],
        source: str = "system"
    ) -> GraphEvent:
        """
        Append a new event to the log.
        
        This is the ONLY way to create events, ensuring sequence integrity.
        
        Args:
            event_type: Classification of the event
            payload: Type-specific data
            source: Origin identifier
            
        Returns:
            The created immutable event record
        """
        with self._lock:
            self._sequence += 1
            event = GraphEvent(
                id=str(uuid.uuid4()),
                type=event_type,
                timestamp=time.monotonic(),
                wall_time=time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime()),
                sequence=self._sequence,
                payload=payload,
                source=source
            )
            self._events.append(event)
        
        # Broadcast to subscribers (non-blocking)
        self._broadcast(event)
        
        logger.debug(f"[EventStore] Appended: {event.type.value} seq={event.sequence}")
        return event
    
    def get_since(self, since_sequence: int = 0) -> List[GraphEvent]:
        """
        Retrieve all events after a given sequence number.
        
        Used for replay when a client reconnects.
        
        Args:
            since_sequence: The last sequence the client received (exclusive)
            
        Returns:
            List of events with sequence > since_sequence, in order
        """
        with self._lock:
            return [e for e in self._events if e.sequence > since_sequence]
    
    def get_latest(self, count: int = 50) -> List[GraphEvent]:
        """Get the N most recent events."""
        with self._lock:
            return list(self._events)[-count:]
    
    def current_sequence(self) -> int:
        """Return the current highest sequence number."""
        with self._lock:
            return self._sequence
    
    # -------------------------------------------------------------------------
    # Subscription / Reactive Push
    # -------------------------------------------------------------------------
    
    async def subscribe(self) -> AsyncIterator[GraphEvent]:
        """
        Subscribe to new events as they arrive.
        
        This is an async generator that yields events indefinitely.
        Use within an async for loop.
        
        Example:
            async for event in event_store.subscribe():
                process(event)
        """
        queue: asyncio.Queue[GraphEvent] = asyncio.Queue()
        
        with self._subscriber_lock:
            self._subscribers.add(queue)
        
        try:
            while True:
                event = await queue.get()
                yield event
        finally:
            with self._subscriber_lock:
                self._subscribers.discard(queue)
    
    def _broadcast(self, event: GraphEvent) -> None:
        """
        Push event to all active subscribers.
        
        Non-blocking: if a subscriber's queue is full, the event is dropped
        for that subscriber (back-pressure handling).
        """
        with self._subscriber_lock:
            for queue in self._subscribers:
                try:
                    queue.put_nowait(event)
                except asyncio.QueueFull:
                    logger.warning(f"[EventStore] Subscriber queue full, dropping event {event.sequence}")
    
    # -------------------------------------------------------------------------
    # Checkpoint Management
    # -------------------------------------------------------------------------
    
    def checkpoint(self, client_id: str, sequence: int) -> None:
        """Record the last processed sequence for a client."""
        with self._lock:
            self._checkpoints[client_id] = sequence
    
    def get_checkpoint(self, client_id: str) -> int:
        """Get the last processed sequence for a client, or 0 if unknown."""
        with self._lock:
            return self._checkpoints.get(client_id, 0)
    
    # -------------------------------------------------------------------------
    # Lifecycle
    # -------------------------------------------------------------------------
    
    def clear(self) -> None:
        """Clear all events. Primarily for testing."""
        with self._lock:
            self._events.clear()
            self._sequence = 0
            self._checkpoints.clear()
    
    def stats(self) -> Dict[str, Any]:
        """Return diagnostic statistics."""
        with self._lock:
            return {
                "total_events": len(self._events),
                "current_sequence": self._sequence,
                "max_capacity": self._events.maxlen,
                "active_subscribers": len(self._subscribers),
                "checkpoints": len(self._checkpoints)
            }


# ============================================================================
# EventBus - Convenience Layer for Emitting Events
# ============================================================================

class EventBus:
    """
    Facade over EventStore providing domain-specific emit methods.
    
    This is the primary interface for producing events throughout the codebase.
    It provides type-safe, semantic methods instead of raw event creation.
    """
    
    def __init__(self, store: Optional[EventStore] = None):
        self._store = store or EventStore.instance()
    
    # -------------------------------------------------------------------------
    # Graph Mutations
    # -------------------------------------------------------------------------
    
    def emit_node_added(
        self, 
        node_id: str, 
        node_type: str, 
        attributes: Dict[str, Any],
        source: str = "graph"
    ) -> GraphEvent:
        """Emit event when a new node is added to the knowledge graph."""
        return self._store.append(
            GraphEventType.NODE_ADDED,
            {"node_id": node_id, "node_type": node_type, **attributes},
            source=source
        )
    
    def emit_node_updated(
        self,
        node_id: str,
        changes: Dict[str, Any],
        source: str = "graph"
    ) -> GraphEvent:
        """Emit event when node attributes are modified."""
        return self._store.append(
            GraphEventType.NODE_UPDATED,
            {"node_id": node_id, "changes": changes},
            source=source
        )
    
    def emit_edge_added(
        self,
        source_id: str,
        target_id: str,
        edge_type: str,
        weight: float = 1.0,
        source: str = "graph"
    ) -> GraphEvent:
        """Emit event when a new edge is created between nodes."""
        return self._store.append(
            GraphEventType.EDGE_ADDED,
            {"source_id": source_id, "target_id": target_id, "edge_type": edge_type, "weight": weight},
            source=source
        )
    
    # -------------------------------------------------------------------------
    # Scan Lifecycle
    # -------------------------------------------------------------------------
    
    def emit_scan_started(
        self,
        target: str,
        modules: List[str],
        session_id: str
    ) -> GraphEvent:
        """Emit event when a scan is initiated."""
        return self._store.append(
            GraphEventType.SCAN_STARTED,
            {"target": target, "modules": modules, "session_id": session_id},
            source="orchestrator"
        )
    
    def emit_scan_phase_changed(
        self,
        phase: str,
        previous_phase: Optional[str] = None
    ) -> GraphEvent:
        """Emit event when scan transitions to a new phase."""
        return self._store.append(
            GraphEventType.SCAN_PHASE_CHANGED,
            {"phase": phase, "previous_phase": previous_phase},
            source="orchestrator"
        )
    
    def emit_scan_completed(
        self,
        status: str,
        findings_count: int,
        duration_seconds: float
    ) -> GraphEvent:
        """Emit event when scan finishes."""
        return self._store.append(
            GraphEventType.SCAN_COMPLETED,
            {"status": status, "findings_count": findings_count, "duration_seconds": duration_seconds},
            source="orchestrator"
        )
    
    # -------------------------------------------------------------------------
    # Findings
    # -------------------------------------------------------------------------
    
    def emit_finding_discovered(
        self,
        finding_id: str,
        finding_type: str,
        severity: str,
        target: str,
        tool: str,
        message: str
    ) -> GraphEvent:
        """Emit event when a new vulnerability/finding is discovered."""
        return self._store.append(
            GraphEventType.FINDING_DISCOVERED,
            {
                "finding_id": finding_id,
                "type": finding_type,
                "severity": severity,
                "target": target,
                "tool": tool,
                "message": message[:500]  # Truncate for event size
            },
            source=f"scanner:{tool}"
        )
    
    # -------------------------------------------------------------------------
    # Tool Invocation
    # -------------------------------------------------------------------------
    
    def emit_tool_invoked(
        self,
        tool: str,
        target: str,
        args: List[str]
    ) -> GraphEvent:
        """Emit event when a scanner tool is started."""
        return self._store.append(
            GraphEventType.TOOL_INVOKED,
            {"tool": tool, "target": target, "args": args},
            source=f"scanner:{tool}"
        )
    
    def emit_tool_completed(
        self,
        tool: str,
        exit_code: int,
        findings_count: int
    ) -> GraphEvent:
        """Emit event when a scanner tool finishes."""
        return self._store.append(
            GraphEventType.TOOL_COMPLETED,
            {"tool": tool, "exit_code": exit_code, "findings_count": findings_count},
            source=f"scanner:{tool}"
        )
    
    # -------------------------------------------------------------------------
    # Logging
    # -------------------------------------------------------------------------
    
    def emit_log(
        self,
        message: str,
        level: str = "INFO",
        source: str = "system"
    ) -> GraphEvent:
        """Emit a log event for the live console."""
        return self._store.append(
            GraphEventType.LOG_EMITTED,
            {"message": message, "level": level},
            source=source
        )


# ============================================================================
# Module-Level Singleton Access
# ============================================================================

def get_event_store() -> EventStore:
    """Get the global EventStore singleton."""
    return EventStore.instance()

def get_event_bus() -> EventBus:
    """Get an EventBus instance connected to the global EventStore."""
    return EventBus(EventStore.instance())


# ============================================================================
# Self-Test (if run directly)
# ============================================================================

if __name__ == "__main__":
    import asyncio
    
    async def test_subscription():
        store = EventStore()
        received = []
        
        async def consumer():
            async for event in store.subscribe():
                received.append(event)
                if len(received) >= 3:
                    break
        
        consumer_task = asyncio.create_task(consumer())
        
        await asyncio.sleep(0.1)
        store.append(GraphEventType.SCAN_STARTED, {"target": "example.com"})
        store.append(GraphEventType.NODE_ADDED, {"node_id": "n1", "node_type": "asset"})
        store.append(GraphEventType.FINDING_DISCOVERED, {"finding_id": "f1", "severity": "HIGH"})
        
        await consumer_task
        
        assert len(received) == 3
        print(f"✓ Received {len(received)} events via subscription")
        print(f"✓ Sequence numbers: {[e.sequence for e in received]}")
        
        # Test replay
        replayed = store.get_since(1)
        assert len(replayed) == 2
        print(f"✓ Replay from seq=1 returned {len(replayed)} events")
        
        print("\n✅ All tests passed!")
    
    asyncio.run(test_subscription())
