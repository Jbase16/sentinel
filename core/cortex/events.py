"""
Module events: inline documentation for /Users/jason/Developer/sentinelforge/core/cortex/events.py.

PURPOSE
- The central nervous system of Strategos / Cortex.
- Decouples emission (engine/decisions) from consumption (UI/logs/persistence).

CORE PROPERTIES
- Monotonic global sequencing (via GlobalSequenceAuthority) for replay + total ordering.
- Contract validation (EventContract) for schema + causal integrity.
- Replay buffer (bounded) so late subscribers / UI reconnects can catch up.
- Subscriber lifecycle (unsubscribe / scope cleanup) to prevent accumulation.
- Explicit sync vs async subscribers (no runtime "maybe coroutine" guessing).

NOTES ON TRANSPORT SECURITY (IMPORTANT)
- Compression + encryption are transport-layer concerns (SSE/WebSocket/HTTP/TLS).
  This module provides:
    - payload size guards + hashing for large payloads
    - optional compressed serialization helpers for transport layers to use
  But it does NOT (and should not) pretend to provide encryption. Use TLS.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import inspect
import itertools
import json
import logging
import time
import uuid
import zlib
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Callable, Deque, Dict, Iterable, List, Optional, Tuple

from core.contracts.events import ContractViolation, EventContract, EventType

# Backward compatibility alias
GraphEventType = EventType

logger = logging.getLogger(__name__)

# -----------------------------------------------------------------------------
# Run identity (forensics)
# -----------------------------------------------------------------------------
_run_id: Optional[str] = None


def get_run_id() -> str:
    global _run_id
    if _run_id is None:
        _run_id = str(uuid.uuid4())
        logger.info(f"[EventBus] Generated new run_id: {_run_id}")
    return _run_id


def reset_run_id() -> None:
    """Tests only."""
    global _run_id
    _run_id = None


async def initialize_event_sequence_from_db() -> int:
    """
    Must be called during startup before emitting any events.
    Delegates to GlobalSequenceAuthority.
    """
    from core.base.sequence import GlobalSequenceAuthority

    return await GlobalSequenceAuthority.initialize_from_db()


def get_next_sequence() -> int:
    """
    Get the next global event sequence number.
    Delegates to GlobalSequenceAuthority.
    """
    from core.base.sequence import GlobalSequenceAuthority

    return GlobalSequenceAuthority.instance().next_id()


# -----------------------------------------------------------------------------
# Event envelope + subscription primitives
# -----------------------------------------------------------------------------
@dataclass(frozen=True)
class GraphEvent:
    """
    Immutable event envelope.

    Versioning:
      - schema_version: envelope version (this dataclass layout)
      - payload_schema_version: version of the payload schema for this event type
        (kept for future-proofing; authoritative validation remains in EventContract)

    Ordering:
      - event_sequence: global monotonically increasing sequence ID (total order)

    Source:
      - source: optional producer label (e.g. "engine", "ui", "replay", "import")
      - run_id: UUID v4 identifying runtime that created this envelope

    Internal:
      - _internal: diagnostic/internal event; bypass wildcard subscribers to prevent recursion loops
    """

    type: GraphEventType
    payload: Dict[str, Any]

    timestamp: float = field(default_factory=time.time)
    event_sequence: int = field(default_factory=get_next_sequence)

    run_id: str = field(default_factory=get_run_id)
    source: str = "engine"

    scan_id: Optional[str] = None
    entity_id: Optional[str] = None

    # Versioning hooks
    schema_version: int = 1
    payload_schema_version: int = 1

    # Priority lane: 0 = causal/high, 1 = normal, 2 = telemetry/noisy
    priority: int = 1

    _internal: bool = False


@dataclass(frozen=True)
class SubscriptionHandle:
    """Opaque handle returned from subscribe_*()."""

    bus: "EventBus"
    token: int

    def unsubscribe(self) -> bool:
        return self.bus.unsubscribe(self.token)


Predicate = Callable[[GraphEvent], bool]
SyncHandler = Callable[[GraphEvent], Any]
AsyncHandler = Callable[[GraphEvent], Any]  # must return awaitable (async def recommended)


@dataclass
class _Subscriber:
    token: int
    callback: Callable[[GraphEvent], Any]
    predicate: Optional[Predicate]
    scope_id: Optional[str]
    critical: bool
    name: str

    # Metrics / health
    calls: int = 0
    failures: int = 0
    total_ms: float = 0.0
    last_error: Optional[str] = None

    # Cascading failure guard
    consecutive_failures: int = 0
    circuit_open: bool = False
    circuit_opened_at: Optional[float] = None


# -----------------------------------------------------------------------------
# EventBus
# -----------------------------------------------------------------------------
class EventBus:
    """
    Synchronous Event Bus.

    This bus is intentionally sync so callers can emit without awaiting.

    Key guarantees:
    - Contract validation always runs before dispatch.
    - Deterministic dispatch order within a single process for events emitted here.
    - Replay buffer allows catch-up for late subscribers (bounded memory).
    - Dedupe/out-of-order guard based on global event_sequence.
    - Sync vs Async subscribers are explicit; async handlers are supervised tasks.

    Async handlers are NON-CAUSAL:
    - they are scheduled (never awaited)
    - they may execute after emit() returns
    - failures are recorded + optionally escalated (especially for critical handlers)

    Strictness:
    - EventContract strictness remains configurable; this bus adds a "core-strict"
      override for a set of core event types to prevent “constitution drift”.
    """

    def __init__(self):
        # Registries:
        # Map[EventType, List[_Subscriber]]
        self._sync_subscribers: Dict[EventType, List[_Subscriber]] = {}
        self._async_subscribers: Dict[EventType, List[_Subscriber]] = {}
        self._sync_wildcards: List[_Subscriber] = []
        self._async_wildcards: List[_Subscriber] = []

        self._token_counter = itertools.count(1)

        # Sequence / dedupe
        self._last_event_sequence: int = 0
        self._seen_sequences: Deque[int] = deque(maxlen=50_000)  # fast-ish LRU by sequence
        self._seen_set: set[int] = set()

        # Replay buffer (bounded)
        self._replay_buffer: Deque[GraphEvent] = deque(maxlen=25_000)

        # Identity
        self._run_id = get_run_id()

        # Policy knobs
        self._require_running_loop_for_async: bool = True
        self._run_id_policy: str = "warn"  # "warn" | "reject" | "tag"

        # Core strictness (recommended): enforce strict violations for core causal events.
        # This does NOT change EventContract's global strict flag; it adds an override.
        self._core_strict: bool = True
        self._core_event_types: set[EventType] = {
            EventType.SCAN_STARTED,
            EventType.SCAN_COMPLETED,
            EventType.SCAN_PHASE_CHANGED,
            EventType.TOOL_STARTED,
            EventType.TOOL_COMPLETED,
            EventType.FINDING_CREATED if hasattr(EventType, "FINDING_CREATED") else EventType.DECISION_MADE,
            EventType.CONTRACT_VIOLATION,
        }

        # Batching helpers (optional)
        self._batch_depth: int = 0
        self._batch_queue: List[GraphEvent] = []

        # Transport hook (for “plaintext” enforcement in the layer that knows truth)
        # If set, called on every event; should raise to reject.
        self._transport_security_checker: Optional[Callable[[GraphEvent], None]] = None

    # -------------------------------------------------------------------------
    # Configuration
    # -------------------------------------------------------------------------
    @property
    def last_event_sequence(self) -> int:
        return self._last_event_sequence

    def set_run_id_policy(self, policy: str) -> None:
        if policy not in ("warn", "reject", "tag"):
            raise ValueError("run_id policy must be one of: warn, reject, tag")
        self._run_id_policy = policy

    def set_require_running_loop_for_async(self, require: bool) -> None:
        self._require_running_loop_for_async = require

    def set_core_strict(self, enabled: bool) -> None:
        self._core_strict = enabled

    def set_replay_buffer_size(self, max_events: int) -> None:
        if max_events < 1000:
            raise ValueError("replay buffer too small")
        self._replay_buffer = deque(self._replay_buffer, maxlen=max_events)

    def set_dedupe_window(self, max_sequences: int) -> None:
        if max_sequences < 1000:
            raise ValueError("dedupe window too small")
        # rebuild structures with new window
        old = list(self._seen_sequences)
        self._seen_sequences = deque(old, maxlen=max_sequences)
        self._seen_set = set(old)

    def set_transport_security_checker(self, checker: Optional[Callable[[GraphEvent], None]]) -> None:
        """
        Allows the transport layer (which knows if TLS is used, etc.) to enforce.
        Example: checker can raise if event.source == "wire" and connection is not TLS.
        """
        self._transport_security_checker = checker

    # -------------------------------------------------------------------------
    # Subscription API (explicit sync vs async)
    # -------------------------------------------------------------------------
    def subscribe_sync(
        self,
        callback: SyncHandler,
        event_types: Optional[List[EventType]] = None,
        *,
        predicate: Optional[Predicate] = None,
        scope_id: Optional[str] = None,
        critical: bool = False,
        name: Optional[str] = None,
        replay_from_sequence: Optional[int] = None,
    ) -> SubscriptionHandle:
        token = next(self._token_counter)
        sub = _Subscriber(
            token=token,
            callback=callback,
            predicate=predicate,
            scope_id=scope_id,
            critical=critical,
            name=name or getattr(callback, "__name__", "sync_subscriber"),
        )
        self._register_subscriber(sub, event_types, async_registry=False)

        if replay_from_sequence is not None:
            self._replay_to_subscriber(sub, replay_from_sequence, async_handler=False)

        return SubscriptionHandle(bus=self, token=token)

    def subscribe_async(
        self,
        callback: AsyncHandler,
        event_types: Optional[List[EventType]] = None,
        *,
        predicate: Optional[Predicate] = None,
        scope_id: Optional[str] = None,
        critical: bool = False,
        name: Optional[str] = None,
        replay_from_sequence: Optional[int] = None,
    ) -> SubscriptionHandle:
        # Enforce that this is truly async-ish at registration time.
        if not inspect.iscoroutinefunction(callback):
            # We still allow callables returning awaitables, but warn loudly.
            logger.warning(
                f"[EventBus] subscribe_async() received non-coroutine function: {callback!r}. "
                "Prefer 'async def' handlers for correctness."
            )

        token = next(self._token_counter)
        sub = _Subscriber(
            token=token,
            callback=callback,
            predicate=predicate,
            scope_id=scope_id,
            critical=critical,
            name=name or getattr(callback, "__name__", "async_subscriber"),
        )
        self._register_subscriber(sub, event_types, async_registry=True)

        if replay_from_sequence is not None:
            self._replay_to_subscriber(sub, replay_from_sequence, async_handler=True)

        return SubscriptionHandle(bus=self, token=token)

    def _register_subscriber(self, sub: _Subscriber, event_types: Optional[List[EventType]], async_registry: bool) -> None:
        if event_types is None:
            if async_registry:
                self._async_wildcards.append(sub)
            else:
                self._sync_wildcards.append(sub)
            return

        valid_types: List[EventType] = []
        for et in event_types:
            if not isinstance(et, EventType):
                logger.warning(f"[EventBus] Subscriber registered with invalid key type {type(et)}; ignoring.")
                continue
            valid_types.append(et)

        registry = self._async_subscribers if async_registry else self._sync_subscribers
        for et in valid_types:
            registry.setdefault(et, []).append(sub)

    def unsubscribe(self, token: int) -> bool:
        removed = False

        def _prune_list(lst: List[_Subscriber]) -> Tuple[List[_Subscriber], bool]:
            before = len(lst)
            lst2 = [s for s in lst if s.token != token]
            return lst2, (len(lst2) != before)

        self._sync_wildcards, r = _prune_list(self._sync_wildcards)
        removed = removed or r
        self._async_wildcards, r = _prune_list(self._async_wildcards)
        removed = removed or r

        for reg in (self._sync_subscribers, self._async_subscribers):
            for et in list(reg.keys()):
                lst2, r = _prune_list(reg.get(et, []))
                removed = removed or r
                if lst2:
                    reg[et] = lst2
                else:
                    reg.pop(et, None)

        return removed

    def cleanup_scope(self, scope_id: str) -> int:
        removed = 0

        def _prune_scope(lst: List[_Subscriber]) -> List[_Subscriber]:
            nonlocal removed
            before = len(lst)
            lst2 = [s for s in lst if s.scope_id != scope_id]
            removed += before - len(lst2)
            return lst2

        self._sync_wildcards = _prune_scope(self._sync_wildcards)
        self._async_wildcards = _prune_scope(self._async_wildcards)

        for reg in (self._sync_subscribers, self._async_subscribers):
            for et in list(reg.keys()):
                before = len(reg.get(et, []))
                lst2 = [s for s in reg.get(et, []) if s.scope_id != scope_id]
                removed += before - len(lst2)
                if lst2:
                    reg[et] = lst2
                else:
                    reg.pop(et, None)

        return removed

    # -------------------------------------------------------------------------
    # Replay
    # -------------------------------------------------------------------------
    def get_events_since(self, last_sequence: int, *, include_internal: bool = False) -> List[GraphEvent]:
        """Return buffered events with event_sequence > last_sequence."""
        out: List[GraphEvent] = []
        for e in self._replay_buffer:
            if e.event_sequence > last_sequence and (include_internal or not e._internal):
                out.append(e)
        return out

    def _replay_to_subscriber(self, sub: _Subscriber, from_sequence: int, *, async_handler: bool) -> None:
        events = self.get_events_since(from_sequence, include_internal=False)
        if not events:
            return
        if async_handler:
            # best-effort schedule; do not block subscribe()
            for e in events:
                self._dispatch_one_async(sub, e)
        else:
            for e in events:
                self._dispatch_one_sync(sub, e)

    # -------------------------------------------------------------------------
    # Batching (optional)
    # -------------------------------------------------------------------------
    def begin_batch(self) -> None:
        self._batch_depth += 1

    def end_batch(self) -> None:
        if self._batch_depth <= 0:
            self._batch_depth = 0
            return
        self._batch_depth -= 1
        if self._batch_depth == 0 and self._batch_queue:
            queued = self._batch_queue
            self._batch_queue = []
            self.emit_many(queued)

    def emit_many(self, events: Iterable[GraphEvent]) -> None:
        for e in events:
            self.emit(e)

    # -------------------------------------------------------------------------
    # Emit
    # -------------------------------------------------------------------------
    def emit(self, event: GraphEvent) -> None:
        """
        Emit a single event.

        Worth-fixing-now behaviors implemented here:
        - Dedupe: drop already-seen sequences
        - Out-of-order guard: detect sequence regressions and flag
        - Replay buffer: store events (bounded)
        - Payload size guard: hash + preview + truncate oversized fields
        - Contract validation: always run; enforce strictness for core events
        - Sync/Async dispatch: explicit registries; supervised async scheduling
        - Cascading failure protection: circuit breaker for critical subscribers
        - Metrics: per-subscriber timings + failures
        """
        # Batching support: if batching is active, queue and return
        if self._batch_depth > 0:
            self._batch_queue.append(event)
            return

        # Transport enforcement hook (the layer that knows "plaintext vs TLS" should set this)
        if self._transport_security_checker is not None:
            try:
                self._transport_security_checker(event)
            except Exception as sec_err:
                # Reject hard: unsafe transport shouldn't be "warn-only"
                logger.error(f"[EventBus] Transport security check rejected event: {sec_err}")
                self._emit_violation_for_rejected_event(event, [f"transport_security: {sec_err}"])
                return

        # run_id policy (forensics / isolation)
        if event.run_id != self._run_id:
            if self._run_id_policy == "warn":
                logger.warning(f"[EventBus] Event run_id mismatch: {event.run_id} != {self._run_id}")
            elif self._run_id_policy == "tag":
                # cannot mutate frozen dataclass; tag via payload injection for downstream visibility
                event = self._clone_event_with_payload_patch(event, {"foreign_run_id": True})
            elif self._run_id_policy == "reject":
                self._emit_violation_for_rejected_event(
                    event, [f"run_id_mismatch: {event.run_id} != {self._run_id}"]
                )
                return

        # Dedupe by sequence (cheap, effective with GlobalSequenceAuthority)
        if self._is_duplicate_sequence(event.event_sequence):
            # Drop duplicates quietly but optionally emit internal diagnostic if desired
            return

        # Out-of-order guard (sequence regressions)
        if event.event_sequence <= self._last_event_sequence:
            # Not necessarily duplicate (dedupe window might have evicted it),
            # but it violates the expected monotonic progression within a run.
            self._emit_violation_for_rejected_event(
                event,
                [f"sequence_regression: {event.event_sequence} <= last_seen {self._last_event_sequence}"],
                internal_only=True,
            )
            # Accepting would corrupt ordering guarantees; drop.
            return

        self._last_event_sequence = event.event_sequence

        # Normalize payload (no mutation)
        payload = dict(event.payload or {})
        if event.scan_id and "scan_id" not in payload:
            payload["scan_id"] = event.scan_id

        # Payload size guard (avoid huge blobs in-memory / over-the-wire)
        payload = self._apply_payload_size_guard(payload)

        # Contract validation
        violations: List[str] = []
        try:
            violations = EventContract.validate(event.type, payload)
        except ContractViolation as e:
            violations = e.violations
            logger.warning(f"[EventBus] Contract violation (Strict): {e}")

        # Governance emission on violations (recursion protected)
        if violations and event.type != EventType.CONTRACT_VIOLATION:
            self._emit_contract_violation(offending_event=event, violations=violations)

        # Enforce strictness if:
        # - EventContract is strict OR
        # - core strict is enabled and this is a core event type
        if violations and (EventContract.is_strict() or (self._core_strict and event.type in self._core_event_types)):
            raise ContractViolation(event.type.value, violations)

        # Store in replay buffer (store the normalized payload version, not the original)
        stored = self._clone_event_with_payload(event, payload)
        self._replay_buffer.append(stored)

        # Dispatch by lanes (preserve order for causal/high priority by not reordering here)
        self._dispatch(stored)

    # -------------------------------------------------------------------------
    # Dispatch internals
    # -------------------------------------------------------------------------
    def _dispatch(self, event: GraphEvent) -> None:
        # Snapshot subscriber lists so unsubscribe during emit is safe and deterministic
        sync_typed = list(self._sync_subscribers.get(event.type, []))
        async_typed = list(self._async_subscribers.get(event.type, []))
        sync_wild = list(self._sync_wildcards)
        async_wild = list(self._async_wildcards)

        # Typed (sync)
        for sub in sync_typed:
            self._dispatch_one_sync(sub, event)

        # Typed (async)
        for sub in async_typed:
            self._dispatch_one_async(sub, event)

        # Wildcards are skipped for internal events to prevent recursion loops
        if not event._internal:
            for sub in sync_wild:
                self._dispatch_one_sync(sub, event)
            for sub in async_wild:
                self._dispatch_one_async(sub, event)

    def _dispatch_one_sync(self, sub: _Subscriber, event: GraphEvent) -> None:
        if sub.circuit_open:
            return
        if sub.predicate is not None:
            try:
                if not sub.predicate(event):
                    return
            except Exception as pred_err:
                self._record_failure(sub, f"predicate_error: {pred_err}")
                self._maybe_trip_circuit(sub, event)
                return

        start = time.perf_counter()
        try:
            sub.calls += 1
            sub.callback(event)
            self._record_success(sub, start)
        except Exception as err:
            self._record_failure(sub, str(err))
            self._maybe_trip_circuit(sub, event)

    def _dispatch_one_async(self, sub: _Subscriber, event: GraphEvent) -> None:
        if sub.circuit_open:
            return
        if sub.predicate is not None:
            try:
                if not sub.predicate(event):
                    return
            except Exception as pred_err:
                self._record_failure(sub, f"predicate_error: {pred_err}")
                self._maybe_trip_circuit(sub, event)
                return

        # Must have a running loop to schedule tasks safely.
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            msg = "no_running_event_loop_for_async_subscriber"
            self._record_failure(sub, msg)
            self._maybe_trip_circuit(sub, event)
            if self._require_running_loop_for_async:
                # This is a correctness violation: async side effects are being silently dropped.
                self._emit_contract_violation(
                    offending_event=event,
                    violations=[f"async_delivery_failed: {sub.name}: {msg}"],
                    internal=True,
                )
            return

        start = time.perf_counter()
        sub.calls += 1

        async def _runner() -> None:
            try:
                result = sub.callback(event)
                if not inspect.isawaitable(result):
                    # A "subscribe_async" handler that didn't return awaitable is a bug.
                    raise RuntimeError("async_subscriber_returned_non_awaitable")
                await result
                self._record_success(sub, start)
            except Exception as err:
                self._record_failure(sub, str(err))
                self._maybe_trip_circuit(sub, event)

        task = loop.create_task(_runner())
        task.add_done_callback(self._consume_task_exception)

    @staticmethod
    def _consume_task_exception(task: "asyncio.Task[None]") -> None:
        try:
            task.result()
        except Exception:
            # Already handled in _runner; this prevents "Task exception was never retrieved".
            return

    # -------------------------------------------------------------------------
    # Cascading failure protection + metrics
    # -------------------------------------------------------------------------
    def _record_success(self, sub: _Subscriber, start: float) -> None:
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        sub.total_ms += elapsed_ms
        sub.consecutive_failures = 0
        sub.last_error = None

    def _record_failure(self, sub: _Subscriber, error: str) -> None:
        sub.failures += 1
        sub.consecutive_failures += 1
        sub.last_error = error

    def _maybe_trip_circuit(self, sub: _Subscriber, event: GraphEvent) -> None:
        """
        Prevent cascading failures: if a CRITICAL subscriber keeps failing,
        open its circuit and emit governance. Non-critical subscribers never trip.
        """
        if not sub.critical:
            return
        # Tunable threshold: trip after 3 consecutive failures
        if sub.consecutive_failures >= 3 and not sub.circuit_open:
            sub.circuit_open = True
            sub.circuit_opened_at = time.time()
            self._emit_contract_violation(
                offending_event=event,
                violations=[f"critical_subscriber_circuit_open: {sub.name}: {sub.last_error}"],
                internal=True,
            )

    def get_metrics_snapshot(self) -> Dict[str, Any]:
        """
        Metrics for observability:
        - subscriber calls/failures/avg_ms
        - replay buffer size
        - dedupe window size
        """
        def _summarize(lst: List[_Subscriber]) -> List[Dict[str, Any]]:
            out: List[Dict[str, Any]] = []
            for s in lst:
                avg = (s.total_ms / s.calls) if s.calls else 0.0
                out.append(
                    {
                        "name": s.name,
                        "token": s.token,
                        "scope_id": s.scope_id,
                        "critical": s.critical,
                        "calls": s.calls,
                        "failures": s.failures,
                        "avg_ms": round(avg, 3),
                        "circuit_open": s.circuit_open,
                        "last_error": s.last_error,
                    }
                )
            return out

        # Flatten typed registries
        typed_sync = [s for lst in self._sync_subscribers.values() for s in lst]
        typed_async = [s for lst in self._async_subscribers.values() for s in lst]

        return {
            "last_event_sequence": self._last_event_sequence,
            "replay_buffer_size": len(self._replay_buffer),
            "replay_buffer_capacity": self._replay_buffer.maxlen,
            "dedupe_window": self._seen_sequences.maxlen,
            "subscribers": {
                "sync_typed": _summarize(typed_sync),
                "async_typed": _summarize(typed_async),
                "sync_wildcard": _summarize(self._sync_wildcards),
                "async_wildcard": _summarize(self._async_wildcards),
            },
        }

    # -------------------------------------------------------------------------
    # Utilities: violations, cloning, payload guard, dedupe
    # -------------------------------------------------------------------------
    def _emit_contract_violation(
        self,
        offending_event: GraphEvent,
        violations: List[str],
        *,
        internal: bool = True,
    ) -> None:
        if offending_event.type == EventType.CONTRACT_VIOLATION:
            return
        try:
            self.emit(
                GraphEvent(
                    type=EventType.CONTRACT_VIOLATION,
                    payload={
                        "offending_event_type": offending_event.type.value,
                        "violations": violations,
                        "context": {
                            "original_payload": str(offending_event.payload)[:1000],
                            "event_sequence": offending_event.event_sequence,
                            "run_id": offending_event.run_id,
                            "source": offending_event.source,
                        },
                    },
                    scan_id=offending_event.scan_id,
                    entity_id=offending_event.entity_id,
                    source="governance",
                    priority=0,
                    _internal=internal,
                )
            )
        except Exception as emit_err:
            logger.critical(f"[EventBus] FAILED TO EMIT CONTRACT_VIOLATION: {emit_err}")

    def _emit_violation_for_rejected_event(
        self, event: GraphEvent, violations: List[str], *, internal_only: bool = False
    ) -> None:
        # If rejection happens before validation, treat as governance signal.
        self._emit_contract_violation(event, violations, internal=True)
        if not internal_only:
            logger.error(f"[EventBus] Rejected event {event.type.value} seq={event.event_sequence}: {violations}")

    @staticmethod
    def _clone_event_with_payload(event: GraphEvent, payload: Dict[str, Any]) -> GraphEvent:
        # GraphEvent is frozen; create a new one preserving identity fields.
        return GraphEvent(
            type=event.type,
            payload=payload,
            timestamp=event.timestamp,
            event_sequence=event.event_sequence,
            run_id=event.run_id,
            source=event.source,
            scan_id=event.scan_id,
            entity_id=event.entity_id,
            schema_version=event.schema_version,
            payload_schema_version=event.payload_schema_version,
            priority=event.priority,
            _internal=event._internal,
        )

    def _clone_event_with_payload_patch(self, event: GraphEvent, patch: Dict[str, Any]) -> GraphEvent:
        payload = dict(event.payload or {})
        payload.update(patch)
        return self._clone_event_with_payload(event, payload)

    @staticmethod
    def _apply_payload_size_guard(payload: Dict[str, Any], *, max_bytes: int = 256_000) -> Dict[str, Any]:
        """
        Guard against oversized payloads (e.g., raw tool output blobs).
        This protects memory, replay buffer, and transport.

        Strategy:
        - Serialize payload to JSON; if too large:
            - keep a hash
            - keep a short preview
            - replace the original payload with a minimal safe envelope
        """
        try:
            raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), default=str).encode("utf-8")
        except Exception:
            raw = str(payload).encode("utf-8")

        if len(raw) <= max_bytes:
            return payload

        sha = hashlib.sha256(raw).hexdigest()
        preview = raw[:2048].decode("utf-8", errors="replace")

        # Preserve scan_id if present
        out: Dict[str, Any] = {}
        if "scan_id" in payload:
            out["scan_id"] = payload.get("scan_id")

        out.update(
            {
                "payload_truncated": True,
                "payload_sha256": sha,
                "payload_bytes": len(raw),
                "payload_preview": preview,
            }
        )
        return out

    def _is_duplicate_sequence(self, seq: int) -> bool:
        if seq in self._seen_set:
            return True

        self._seen_sequences.append(seq)
        self._seen_set.add(seq)

        # Evict oldest if deque rolled over
        while len(self._seen_set) > len(self._seen_sequences):
            # rebuild set cheaply when needed (rare)
            self._seen_set = set(self._seen_sequences)
            break

        return False

    # -------------------------------------------------------------------------
    # Serialization helpers (transport layer can use these)
    # -------------------------------------------------------------------------
    @staticmethod
    def to_dict(event: GraphEvent) -> Dict[str, Any]:
        return {
            "schema_version": event.schema_version,
            "payload_schema_version": event.payload_schema_version,
            "type": event.type.value,
            "timestamp": event.timestamp,
            "event_sequence": event.event_sequence,
            "run_id": event.run_id,
            "source": event.source,
            "scan_id": event.scan_id,
            "entity_id": event.entity_id,
            "priority": event.priority,
            "internal": event._internal,
            "payload": event.payload,
        }

    @classmethod
    def serialize_event_json(cls, event: GraphEvent) -> str:
        return json.dumps(cls.to_dict(event), ensure_ascii=False, separators=(",", ":"), default=str)

    @classmethod
    def serialize_event_compressed_b64(cls, event: GraphEvent) -> str:
        """
        Optional compression helper for transport layers.
        (Encryption must be handled by TLS; this is compression only.)
        """
        raw = cls.serialize_event_json(event).encode("utf-8")
        comp = zlib.compress(raw, level=6)
        return base64.b64encode(comp).decode("ascii")

    @classmethod
    def serialize_batch_compressed_b64(cls, events: List[GraphEvent]) -> str:
        raw = json.dumps([cls.to_dict(e) for e in events], ensure_ascii=False, separators=(",", ":"), default=str).encode(
            "utf-8"
        )
        comp = zlib.compress(raw, level=6)
        return base64.b64encode(comp).decode("ascii")

    # -------------------------------------------------------------------------
    # Convenience emitters (kept compatible; now include scan_id in envelope too)
    # -------------------------------------------------------------------------
    def emit_decision_made(
        self,
        intent: str,
        reason: str,
        context: Dict[str, Any],
        source: str = "strategos",
        scan_id: Optional[str] = None,
    ) -> None:
        payload: Dict[str, Any] = {"intent": intent, "reason": reason, "context": context, "source": source}
        if scan_id:
            payload["scan_id"] = scan_id
        self.emit(GraphEvent(type=EventType.DECISION_MADE, payload=payload, scan_id=scan_id, source=source, priority=0))

    def emit_narrative_emitted(
        self,
        narrative: str,
        decision_id: str,
        decision_type: str,
        context: Dict[str, Any],
        scan_id: Optional[str] = None,
    ) -> None:
        payload: Dict[str, Any] = {
            "narrative": narrative,
            "decision_id": decision_id,
            "decision_type": decision_type,
            "context": context,
        }
        if scan_id:
            payload["scan_id"] = scan_id
        self.emit(GraphEvent(type=EventType.NARRATIVE_EMITTED, payload=payload, scan_id=scan_id, source="strategos"))

    def emit_scan_phase_changed(self, phase: str, previous_phase: Optional[str] = None, scan_id: Optional[str] = None) -> None:
        payload: Dict[str, Any] = {"phase": phase, "previous_phase": previous_phase}
        if scan_id:
            payload["scan_id"] = scan_id
        self.emit(GraphEvent(type=EventType.SCAN_PHASE_CHANGED, payload=payload, scan_id=scan_id, source="engine", priority=0))

    def emit_scan_started(self, target: str, allowed_tools: List[str], scan_id: str) -> None:
        payload: Dict[str, Any] = {"target": target, "allowed_tools": allowed_tools, "scan_id": scan_id}
        self.emit(GraphEvent(type=EventType.SCAN_STARTED, payload=payload, scan_id=scan_id, source="engine", priority=0))

    def emit_scan_completed(self, status: str, findings_count: int, duration: float, scan_id: Optional[str] = None) -> None:
        payload: Dict[str, Any] = {"status": status, "findings_count": findings_count, "duration_seconds": duration}
        if scan_id:
            payload["scan_id"] = scan_id
        self.emit(GraphEvent(type=EventType.SCAN_COMPLETED, payload=payload, scan_id=scan_id, source="engine", priority=0))

    def emit_tool_invoked(self, tool: str, target: str, args: List[str], scan_id: Optional[str] = None) -> None:
        payload: Dict[str, Any] = {"tool": tool, "target": target, "args": args}
        if scan_id:
            payload["scan_id"] = scan_id
        self.emit(GraphEvent(type=EventType.TOOL_STARTED, payload=payload, scan_id=scan_id, source="engine", priority=0))

    def emit_tool_completed(
        self,
        tool: str,
        exit_code: int,
        findings_count: int,
        scan_id: Optional[str] = None,
        error: Optional[Dict[str, Any]] = None,
    ) -> None:
        payload: Dict[str, Any] = {"tool": tool, "exit_code": exit_code, "findings_count": findings_count}
        if error:
            payload["error"] = error
        if scan_id:
            payload["scan_id"] = scan_id
        self.emit(GraphEvent(type=EventType.TOOL_COMPLETED, payload=payload, scan_id=scan_id, source="engine", priority=0))

    # --- CRONUS convenience methods (add scan_id support now; keep signature-compatible by defaulting None) ---
    def emit_cronus_query_started(
        self,
        target: str,
        sources: List[str],
        timestamp_start: Optional[str] = None,
        timestamp_end: Optional[str] = None,
        scan_id: Optional[str] = None,
    ) -> None:
        payload: Dict[str, Any] = {"target": target, "sources": sources, "timestamp_start": timestamp_start, "timestamp_end": timestamp_end}
        if scan_id:
            payload["scan_id"] = scan_id
        self.emit(GraphEvent(type=GraphEventType.CRONUS_QUERY_STARTED, payload=payload, scan_id=scan_id, source="cronus", priority=1))

    def emit_cronus_query_completed(
        self,
        target: str,
        snapshots_found: int,
        duration_ms: Optional[int] = None,
        scan_id: Optional[str] = None,
    ) -> None:
        payload: Dict[str, Any] = {"target": target, "snapshots_found": snapshots_found, "duration_ms": duration_ms}
        if scan_id:
            payload["scan_id"] = scan_id
        self.emit(GraphEvent(type=GraphEventType.CRONUS_QUERY_COMPLETED, payload=payload, scan_id=scan_id, source="cronus", priority=1))

    def emit_cronus_query_failed(self, target: str, error: str, source: Optional[str] = None, scan_id: Optional[str] = None) -> None:
        payload: Dict[str, Any] = {"target": target, "error": error, "source": source}
        if scan_id:
            payload["scan_id"] = scan_id
        self.emit(GraphEvent(type=GraphEventType.CRONUS_QUERY_FAILED, payload=payload, scan_id=scan_id, source="cronus", priority=0))

    def emit_cronus_snapshot_found(self, url: str, timestamp: str, source: str, status_code: Optional[int] = None, scan_id: Optional[str] = None) -> None:
        payload: Dict[str, Any] = {"url": url, "timestamp": timestamp, "source": source, "status_code": status_code}
        if scan_id:
            payload["scan_id"] = scan_id
        self.emit(GraphEvent(type=GraphEventType.CRONUS_SNAPSHOT_FOUND, payload=payload, scan_id=scan_id, source="cronus", priority=2))

    def emit_cronus_diff_started(self, target: str, old_count: int, new_count: int, scan_id: Optional[str] = None) -> None:
        payload: Dict[str, Any] = {"target": target, "old_count": old_count, "new_count": new_count}
        if scan_id:
            payload["scan_id"] = scan_id
        self.emit(GraphEvent(type=GraphEventType.CRONUS_DIFF_STARTED, payload=payload, scan_id=scan_id, source="cronus", priority=1))

    def emit_cronus_diff_completed(
        self,
        target: str,
        deleted_count: int,
        stable_count: int,
        added_count: int,
        modified_count: int,
        confidence: Optional[float] = None,
        scan_id: Optional[str] = None,
    ) -> None:
        payload: Dict[str, Any] = {
            "target": target,
            "deleted_count": deleted_count,
            "stable_count": stable_count,
            "added_count": added_count,
            "modified_count": modified_count,
            "confidence": confidence,
        }
        if scan_id:
            payload["scan_id"] = scan_id
        self.emit(GraphEvent(type=GraphEventType.CRONUS_DIFF_COMPLETED, payload=payload, scan_id=scan_id, source="cronus", priority=1))

    def emit_cronus_hunt_started(self, target: str, candidate_count: int, scan_id: Optional[str] = None) -> None:
        payload: Dict[str, Any] = {"target": target, "candidate_count": candidate_count}
        if scan_id:
            payload["scan_id"] = scan_id
        self.emit(GraphEvent(type=GraphEventType.CRONUS_HUNT_STARTED, payload=payload, scan_id=scan_id, source="cronus", priority=1))

    def emit_cronus_hunt_completed(self, target: str, confirmed: int, denied: int, dead: int, duration_ms: Optional[int] = None, scan_id: Optional[str] = None) -> None:
        payload: Dict[str, Any] = {"target": target, "confirmed": confirmed, "denied": denied, "dead": dead, "duration_ms": duration_ms}
        if scan_id:
            payload["scan_id"] = scan_id
        self.emit(GraphEvent(type=GraphEventType.CRONUS_HUNT_COMPLETED, payload=payload, scan_id=scan_id, source="cronus", priority=1))

    def emit_cronus_zombie_confirmed(self, path: str, status_code: int, method: Optional[str] = None, confidence: Optional[float] = None, scan_id: Optional[str] = None) -> None:
        payload: Dict[str, Any] = {"path": path, "method": method, "status_code": status_code, "confidence": confidence}
        if scan_id:
            payload["scan_id"] = scan_id
        self.emit(GraphEvent(type=GraphEventType.CRONUS_ZOMBIE_CONFIRMED, payload=payload, scan_id=scan_id, source="cronus", priority=0))

    def emit_cronus_zombie_denied(self, path: str, status_code: int, method: Optional[str] = None, scan_id: Optional[str] = None) -> None:
        payload: Dict[str, Any] = {"path": path, "method": method, "status_code": status_code}
        if scan_id:
            payload["scan_id"] = scan_id
        self.emit(GraphEvent(type=GraphEventType.CRONUS_ZOMBIE_DENIED, payload=payload, scan_id=scan_id, source="cronus", priority=1))


# -----------------------------------------------------------------------------
# Singleton accessor
# -----------------------------------------------------------------------------
_event_bus: Optional[EventBus] = None


def get_event_bus() -> EventBus:
    global _event_bus
    if _event_bus is None:
        _event_bus = EventBus()
    return _event_bus


def reset_event_sequence() -> None:
    """
    Tests only: reset GlobalSequenceAuthority and re-init for memory-only use.
    """
    from core.base.sequence import GlobalSequenceAuthority

    GlobalSequenceAuthority.reset_for_testing()
    GlobalSequenceAuthority.initialize_for_testing()


# -----------------------------------------------------------------------------
# Contract configuration helpers
# -----------------------------------------------------------------------------
def set_strict_contract_mode(strict: bool) -> None:
    EventContract.set_strict_mode(strict)


def reset_contract_state() -> None:
    EventContract.reset_causal_state()


# Keep legacy behavior (migration-friendly). Core-strict in EventBus closes the gap for key events.
EventContract.set_strict_mode(False)
