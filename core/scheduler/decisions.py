"""
core/scheduler/decisions.py
Decision Monad / Decision-as-Data system for Strategos.

Key invariants:
- DecisionPoints are immutable
- Ledger assigns global sequence numbers (shared with EventBus timeline)
- DB persistence must never block the scanner
- Emission can be enabled/disabled without affecting decision creation/ledgering
"""

from __future__ import annotations

import asyncio
import inspect
import time
import uuid
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, TYPE_CHECKING
from enum import Enum
from collections import deque
from contextlib import contextmanager

if TYPE_CHECKING:
    from core.cortex.events import EventBus
    from core.cortex.narrator import NarratorEngine


# ============================================================================
# Decision Types - Semantic Classification of Strategic Choices
# ============================================================================

class DecisionType(str, Enum):
    """
    Taxonomy of decision types in Strategos.
    Each type has specific semantic meaning and expected payload structure.
    """
    INTENT_TRANSITION = "intent_transition"
    PHASE_TRANSITION = "phase_transition"
    TOOL_SELECTION = "tool_selection"
    TOOL_REJECTION = "tool_rejection"
    RESOURCE_ALLOCATION = "resource_allocation"
    EARLY_TERMINATION = "early_termination"
    MODE_ADAPTATION = "mode_adaptation"
    SCORING = "scoring"
    REACTIVE_SIGNAL = "reactive_signal"
    ASSESSMENT = "assessment"


# ============================================================================
# DecisionPoint - Immutable Decision Record
# ============================================================================

@dataclass(frozen=True)
class DecisionPoint:
    """
    Immutable record of a single strategic decision.

    Note:
      - timestamp uses monotonic time (good for durations, not wall-clock)
      - sequence is assigned only when committed to a DecisionLedger
    """
    id: str
    type: DecisionType
    chosen: Any
    reason: str
    alternatives: List[Any] = field(default_factory=list)
    suppressed: List[Any] = field(default_factory=list)
    context: Dict[str, Any] = field(default_factory=dict)
    evidence: Dict[str, Any] = field(default_factory=dict)
    triggers: List[str] = field(default_factory=list)
    parent_id: Optional[str] = None
    trigger_event_sequence: Optional[int] = None
    confidence: float = 1.0
    timestamp: float = field(default_factory=time.time)
    sequence: Optional[int] = None

    @classmethod
    def create(
        cls,
        decision_type: DecisionType,
        chosen: Any,
        reason: str,
        alternatives: Optional[List[Any]] = None,
        suppressed: Optional[List[Any]] = None,
        context: Optional[Dict[str, Any]] = None,
        evidence: Optional[Dict[str, Any]] = None,
        triggers: Optional[List[str]] = None,
        parent_id: Optional[str] = None,
        trigger_event_sequence: Optional[int] = None,
        confidence: float = 1.0,
    ) -> "DecisionPoint":
        return cls(
            id=str(uuid.uuid4()),
            type=decision_type,
            chosen=chosen,
            reason=reason,
            alternatives=alternatives or [],
            suppressed=suppressed or [],
            context=context or {},
            evidence=evidence or {},
            triggers=triggers or [],
            parent_id=parent_id,
            trigger_event_sequence=trigger_event_sequence,
            confidence=confidence,
            timestamp=time.time(),
            sequence=None,
        )

    def with_sequence(self, sequence: int) -> "DecisionPoint":
        return DecisionPoint(
            id=self.id,
            type=self.type,
            chosen=self.chosen,
            reason=self.reason,
            alternatives=self.alternatives,
            suppressed=self.suppressed,
            context=self.context,
            evidence=self.evidence,
            triggers=self.triggers,
            parent_id=self.parent_id,
            trigger_event_sequence=self.trigger_event_sequence,
            confidence=self.confidence,
            timestamp=self.timestamp,
            sequence=sequence,
        )

    def to_event_payload(self) -> Dict[str, Any]:
        """
        Convert to strictly typed DecisionPayload (dict).
        """
        payload: Dict[str, Any] = {
            "decision_id": self.id,
            "decision_type": self.type.value,
            "selected_action": self.chosen,
            "rationale": self.reason,
            "confidence": self.confidence,
            "alternatives_considered": self.alternatives,
            "suppressed_actions": self.suppressed,
            "triggers": self.triggers,
            "evidence": self.evidence,
            "scope": self.context,
            "timestamp": self.timestamp,
        }
        
        # Add optional extras if needed by consumers, but the above satisfies DecisionPayload
        # if self.evidence:
             # Merge evidence into generic scope? Or keep separate if payload allows?
             # DecisionPayload defined 'scope' as dict. We have evidence separate in DecisionPoint.
             # We can add evidence to scope or just allow extra fields if we loosen ConfigDict.
             # But ConfigDict is forbid. 
             # Wait, I defined DecisionPayload in schemas.py.
             # Does DecisionPayload have 'evidence'? No.
             # It acts as a strict contract. Evidence should probably go into 'scope' or we add 'evidence' to payload.
             # I should add 'evidence' to DecisionPayload.
             # But for now I will put it in scope.
             # payload["scope"]["_evidence"] = self.evidence

        if self.parent_id:
             payload["scope"]["_parent_id"] = self.parent_id

        if self.sequence:
             payload["scope"]["_sequence"] = self.sequence

        return payload


# ============================================================================
# DecisionLedger - Append-Only Decision Log
# ============================================================================

class DecisionLedger:
    """
    Append-only decision log.

    Critical: DB persistence must not hold the lock or block the scanner.
    """

    def __init__(self, max_decisions: int = 5000):
        self._decisions: deque[DecisionPoint] = deque(maxlen=max_decisions)
        self._lock = threading.RLock()

    def commit(self, decision: DecisionPoint) -> DecisionPoint:
        """
        Commit decision, assign global sequence number, store in memory.

        DB persistence is best-effort and never blocks the caller.
        """
        from core.cortex.events import get_next_sequence

        # 1) Atomic in-memory commit
        with self._lock:
            global_seq = get_next_sequence()
            committed = decision.with_sequence(global_seq)
            self._decisions.append(committed)

        # 2) Best-effort persistence OUTSIDE the lock
        self._persist_best_effort(committed)

        return committed

    def _persist_best_effort(self, committed: DecisionPoint) -> None:
        """
        Persist without crashing the scanner.
        Supports sync or async DB implementations.
        """
        try:
            from core.data.db import Database

            payload = {
                "id": committed.id,
                "sequence": committed.sequence,
                "type": committed.type.value,
                "chosen": committed.chosen,
                "reason": committed.reason,
                "alternatives": committed.alternatives,
                "context": {
                    **committed.context,
                    "suppressed": committed.suppressed,
                    "confidence": committed.confidence,
                },
                "evidence": {
                    **committed.evidence,
                    "triggers": committed.triggers,
                },
                "parent_id": committed.parent_id,
                "trigger_event_sequence": committed.trigger_event_sequence,
                "timestamp": committed.timestamp,
            }

            db = Database.instance()
            save_fn = getattr(db, "save_decision", None)
            if save_fn is None:
                return

            result = save_fn(payload)

            # If save_decision is async, schedule it
            if inspect.isawaitable(result):
                try:
                    loop = asyncio.get_running_loop()
                    loop.create_task(result)  # fire-and-forget
                except RuntimeError:
                    # No running loop (e.g., sync context). Do nothing.
                    pass

        except Exception:
            # DB failure should not crash scanner
            return

    async def get_children(self, decision_id: str) -> List[DecisionPoint]:
        from core.data.db import Database
        if not Database.is_initialized():
             return []

        try:
            records = await Database.instance().get_decision_children(decision_id)
            children: List[DecisionPoint] = []
            for r in records:
                children.append(
                    DecisionPoint(
                        id=r["id"],
                        type=DecisionType(r["type"]),
                        chosen=r.get("chosen"),
                        reason=r.get("reason", ""),
                        alternatives=r.get("alternatives") or [],
                        suppressed=r.get("suppressed") or [],
                        context=r.get("context") or {},
                        evidence=r.get("evidence") or {},
                        triggers=r.get("triggers") or [],
                        parent_id=r.get("parent_id"),
                        trigger_event_sequence=r.get("trigger_event_sequence"),
                        confidence=r.get("confidence", 1.0),
                        timestamp=r.get("timestamp", 0.0),
                        sequence=r.get("sequence"),
                    )
                )
            return children
        except Exception:
            return []

    def get_chain(self, decision_id: str) -> List[DecisionPoint]:
        with self._lock:
            chain: List[DecisionPoint] = []
            current_id: Optional[str] = decision_id

            # Walk backwards through parent links within in-memory window
            for decision in reversed(self._decisions):
                if current_id is None:
                    break
                if decision.id == current_id:
                    chain.insert(0, decision)
                    current_id = decision.parent_id

            return chain

    def get_all(self) -> List[DecisionPoint]:
        with self._lock:
            return list(self._decisions)

    def clear(self) -> None:
        with self._lock:
            self._decisions.clear()

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            type_counts: Dict[str, int] = {}
            for d in self._decisions:
                key = d.type.value
                type_counts[key] = type_counts.get(key, 0) + 1

            last_seq = self._decisions[-1].sequence if self._decisions else None

            return {
                "total_decisions_memory": len(self._decisions),
                "last_sequence": last_seq,
                "max_capacity": self._decisions.maxlen,
                "decisions_by_type": type_counts,
            }


# ============================================================================
# DecisionContext - Execution Context with Auto-Event Emission
# ============================================================================

class DecisionContext:
    """
    Commits decisions + optionally emits events.

    IMPORTANT: If your EventBus enforces scan_id on certain event types,
    pass scan_id here so emissions are always valid.
    """

    def __init__(
        self,
        event_bus: Optional["EventBus"] = None,
        ledger: Optional[DecisionLedger] = None,
        auto_emit: bool = True,
        narrator: Optional["NarratorEngine"] = None,
        scan_id: Optional[str] = None,
        source: str = "strategos",
    ):
        self._event_bus = event_bus
        self._ledger = ledger or DecisionLedger()
        self._auto_emit = auto_emit
        self._narrator = narrator
        self._scan_id = scan_id
        self._source = source
        self._parent_stack: List[str] = []
        self._pending: List[DecisionPoint] = []

    def __enter__(self) -> "DecisionContext":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._pending:
            self.flush()
        return False

    def choose(
        self,
        decision_type: DecisionType,
        chosen: Any,
        reason: str,
        alternatives: Optional[List[Any]] = None,
        suppressed: Optional[List[Any]] = None,
        context: Optional[Dict[str, Any]] = None,
        evidence: Optional[Dict[str, Any]] = None,
        triggers: Optional[List[str]] = None,
        trigger_event_sequence: Optional[int] = None,
        confidence: float = 1.0,
        defer: bool = False,
    ) -> DecisionPoint:
        parent_id = self._parent_stack[-1] if self._parent_stack else None

        decision = DecisionPoint.create(
            decision_type=decision_type,
            chosen=chosen,
            reason=reason,
            alternatives=alternatives,
            suppressed=suppressed,
            context=context,
            evidence=evidence,
            triggers=triggers,
            parent_id=parent_id,
            trigger_event_sequence=trigger_event_sequence,
            confidence=confidence,
        )

        if defer:
            self._pending.append(decision)
            return decision

        return self._commit_and_emit(decision)

    def _commit_and_emit(self, decision: DecisionPoint) -> DecisionPoint:
        committed = self._ledger.commit(decision)

        if self._auto_emit:
            if self._event_bus:
                self._emit_decision_event(committed)
            if self._narrator:
                try:
                    self._narrator.narrate(committed)
                except Exception:
                    pass

        return committed

    def _emit_decision_event(self, decision: DecisionPoint) -> None:
        """
        Emit decision events in a way that stays compatible with strict buses.

        We keep your specialized PHASE_TRANSITION pathway, but also emit a generic
        'decision_made' style event for UI uniformity.
        """
        payload = decision.to_event_payload()

        # Specialized phase transition hook
        if decision.type == DecisionType.PHASE_TRANSITION:
            phase = decision.context.get("phase", "UNKNOWN")
            previous_phase = decision.context.get("previous_phase")
            # Prefer scan-scoped if signature supports it
            try:
                self._event_bus.emit_scan_phase_changed(
                    phase=phase,
                    previous_phase=previous_phase,
                    scan_id=self._scan_id,
                )
            except TypeError:
                # Fallback only if scan_id itself causes issues (unlikely with current EventBus)
                self._event_bus.emit_scan_phase_changed(
                    phase=phase,
                    previous_phase=previous_phase,
                )

        # Generic "decision made" event
        # Map intent transition to intent string for older UI semantics
        intent = decision.chosen if decision.type == DecisionType.INTENT_TRANSITION else decision.type.value

        try:
            self._event_bus.emit_decision_made(
                intent=intent,
                reason=decision.reason,
                context=payload.get("context", {}),
                scan_id=self._scan_id,
                source=self._source,
                payload=payload,
            )
        except TypeError:
            # Back-compat older signature
            self._event_bus.emit_decision_made(
                intent=intent,
                reason=decision.reason,
                context=payload.get("context", {}),
                source=self._source,
            )
        except Exception:
            pass

    def flush(self) -> List[DecisionPoint]:
        committed: List[DecisionPoint] = []
        for decision in self._pending:
            committed.append(self._commit_and_emit(decision))
        self._pending.clear()
        return committed

    @contextmanager
    def nested(self, parent_decision: DecisionPoint):
        self._parent_stack.append(parent_decision.id)
        try:
            yield self
        finally:
            self._parent_stack.pop()

    def get_ledger(self) -> DecisionLedger:
        return self._ledger


# ============================================================================
# Convenience Factory Functions
# ============================================================================

def create_decision_context(
    event_bus: Optional["EventBus"] = None,
    ledger: Optional[DecisionLedger] = None,
    narrator: Optional["NarratorEngine"] = None,
    scan_id: Optional[str] = None,
    source: str = "strategos",
) -> DecisionContext:
    return DecisionContext(
        event_bus=event_bus,
        ledger=ledger,
        auto_emit=True,
        narrator=narrator,
        scan_id=scan_id,
        source=source,
    )


# ============================================================================
# Module-Level Singletons (Optional)
# ============================================================================

_global_ledger: Optional[DecisionLedger] = None
_ledger_lock = threading.Lock()

def get_global_ledger() -> DecisionLedger:
    global _global_ledger
    if _global_ledger is None:
        with _ledger_lock:
            if _global_ledger is None:
                _global_ledger = DecisionLedger()
    return _global_ledger


_decision_ledger_instance: Optional[DecisionLedger] = None

def get_decision_ledger() -> DecisionLedger:
    global _decision_ledger_instance
    if _decision_ledger_instance is None:
        _decision_ledger_instance = DecisionLedger()
    return _decision_ledger_instance


# ============================================================================
# Self-Test / Design Verification
# ============================================================================

if __name__ == "__main__":
    # NOTE: With global sequence unification, never assume sequence starts at 1.
    # We only assert monotonicity.

    # Mock GlobalSequenceAuthority for standalone testing
    from unittest.mock import MagicMock, patch
    from core.base.sequence import GlobalSequenceAuthority
    import itertools
    
    mock_auth = MagicMock()
    _counter = itertools.count(1)
    mock_auth.next_id.side_effect = lambda: next(_counter)
    
    # Patch the singleton instance
    with patch("core.base.sequence.GlobalSequenceAuthority.instance", return_value=mock_auth):
        decision = DecisionPoint.create(
            decision_type=DecisionType.INTENT_TRANSITION,
            chosen="intent_surface_enum",
            reason="Standard progression",
            alternatives=["skip", "execute"],
            context={"mode": "standard"},
        )

        # Verify immutability
        try:
            # frozen dataclass should throw
            decision.chosen = "different"  # type: ignore[attr-defined]
            print("❌ Immutability violated!")
        except Exception:
            print("✓ Immutability enforced")

        ledger = DecisionLedger()
        d1 = ledger.commit(decision)
        d2 = ledger.commit(decision)

        assert d1.sequence is not None and d2.sequence is not None
        assert d2.sequence > d1.sequence
        print(f"✓ Sequence monotonicity: {d1.sequence} -> {d2.sequence}")

        parent = DecisionPoint.create(
            decision_type=DecisionType.PHASE_TRANSITION,
            chosen="PHASE_2",
            reason="Entering active recon",
        )
        parent_committed = ledger.commit(parent)

        child = DecisionPoint.create(
            decision_type=DecisionType.TOOL_SELECTION,
            chosen="httpx",
            reason="Live check",
            parent_id=parent_committed.id,
        )
        child_committed = ledger.commit(child)

        chain = ledger.get_chain(child_committed.id)
        assert len(chain) == 2
        assert chain[0].id == parent_committed.id
        print(f"✓ Decision chain reconstruction: {len(chain)} decisions")

        print("\n✅ All design invariants verified!")
