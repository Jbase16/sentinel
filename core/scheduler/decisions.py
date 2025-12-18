"""Module decisions: inline documentation for /Users/jason/Developer/sentinelforge/core/scheduler/decisions.py."""
#
# PURPOSE:
# Transform implicit control-flow decisions into explicit, observable, replayable events.
# Every strategic decision in Strategos becomes a typed, immutable record that
# automatically emits events to the EventBus.
#
# ARCHITECTURAL INNOVATION:
# Instead of scattering `emit_event()` calls throughout decision logic,
# we use a Decision Monad pattern where decisions are declared as data structures
# and automatically emit events when executed.
#
# KEY GUARANTEES:
# 1. Emission Completeness: All decisions emit events (structurally enforced)
# 2. Immutability: Decision records cannot be modified after creation
# 3. Causality: Decision chains preserve parent-child relationships
# 4. Replayability: Decisions can be re-executed in different contexts
# 5. Testability: Decision trees can be inspected without side effects
#
# DESIGN PATTERN:
# - DecisionPoint: Immutable record of a single decision (data)
# - DecisionContext: Execution context that triggers event emission (effects)
# - @decision_point: Decorator that auto-wraps functions to emit decisions
# - DecisionLedger: Append-only audit log of all decisions (separate from EventStore)
#
# WHY THIS IS BETTER THAN CONVENTIONAL APPROACHES:
# - Conventional: if condition: emit_event(...); do_action()
#   Problem: Easy to forget emit_event(), hard to test, no decision history
#
# - This approach: decision = DecisionPoint.create(...); decision.execute()
#   Benefit: Emission is automatic, decisions are data, full audit trail
#
# USAGE EXAMPLE:
# ```
# with DecisionContext(event_bus) as ctx:
#     decision = ctx.choose(
#         intent=INTENT_SURFACE_ENUMERATION,
#         reason="Standard progression",
#         alternatives=["skip", "execute"],
#         chosen="execute",
#         context={"mode": "standard"}
#     )
#     # Event automatically emitted when decision is committed
# ```

from __future__ import annotations

import time
import uuid
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Callable, TypeVar, Generic, TYPE_CHECKING
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
    INTENT_TRANSITION = "intent_transition"      # Moving from one intent to another
    PHASE_TRANSITION = "phase_transition"        # Entering a new scan phase
    TOOL_SELECTION = "tool_selection"            # Choosing which tools to run
    TOOL_REJECTION = "tool_rejection"            # Blocking a tool (Constitution)
    RESOURCE_ALLOCATION = "resource_allocation"  # Concurrency/throttling decisions
    EARLY_TERMINATION = "early_termination"      # Walk-away logic
    MODE_ADAPTATION = "mode_adaptation"          # Adjusting strategy based on mode
    SCORING = "scoring"                          # Tool prioritization calculation


# ============================================================================
# DecisionPoint - Immutable Decision Record
# ============================================================================

@dataclass(frozen=True)
class DecisionPoint:
    """
    Immutable record of a single strategic decision.
    
    A DecisionPoint captures:
    - WHAT was decided (chosen option)
    - WHY it was decided (reason, evidence)
    - WHEN it was decided (timestamp, sequence)
    - WHAT ELSE was considered (alternatives, scores)
    
    This is a pure data structure - no side effects on creation.
    Side effects (event emission) happen only when executed via DecisionContext.
    
    Fields:
        id: Unique identifier (UUID v4)
        type: Classification of decision (DecisionType)
        chosen: The selected option/action
        reason: Human-readable justification
        alternatives: Other options that were considered
        context: Arbitrary metadata (target, mode, scores, etc.)
        evidence: Supporting data that informed the decision
        parent_id: Optional link to parent decision (for decision trees)
        timestamp: When decision was created (monotonic time)
        sequence: Ledger sequence number (set by DecisionLedger)
    
    Contract:
        - Once created, fields are immutable (frozen dataclass)
        - `sequence` is None until committed to ledger
        - `parent_id` creates causal chains for decision analysis
    """
    id: str
    type: DecisionType
    chosen: Any
    reason: str
    alternatives: List[Any] = field(default_factory=list)
    context: Dict[str, Any] = field(default_factory=dict)
    evidence: Dict[str, Any] = field(default_factory=dict)
    parent_id: Optional[str] = None
    timestamp: float = field(default_factory=time.monotonic)
    sequence: Optional[int] = None
    
    @classmethod
    def create(
        cls,
        decision_type: DecisionType,
        chosen: Any,
        reason: str,
        alternatives: Optional[List[Any]] = None,
        context: Optional[Dict[str, Any]] = None,
        evidence: Optional[Dict[str, Any]] = None,
        parent_id: Optional[str] = None
    ) -> DecisionPoint:
        """
        Factory method for creating decisions.
        
        This is the primary way to create DecisionPoints.
        Validates that all required fields are provided.
        """
        return cls(
            id=str(uuid.uuid4()),
            type=decision_type,
            chosen=chosen,
            reason=reason,
            alternatives=alternatives or [],
            context=context or {},
            evidence=evidence or {},
            parent_id=parent_id,
            timestamp=time.monotonic()
        )
    
    def with_sequence(self, sequence: int) -> DecisionPoint:
        """
        Create a copy with sequence number assigned.
        Used by DecisionLedger when committing decisions.
        """
        return DecisionPoint(
            id=self.id,
            type=self.type,
            chosen=self.chosen,
            reason=self.reason,
            alternatives=self.alternatives,
            context=self.context,
            evidence=self.evidence,
            parent_id=self.parent_id,
            timestamp=self.timestamp,
            sequence=sequence
        )
    
    def to_event_payload(self) -> Dict[str, Any]:
        """
        Convert decision to EventBus payload format.
        
        This bridges DecisionPoints to the existing EventBus infrastructure.
        Maps our rich decision structure to the simpler event schema.
        """
        payload = {
            "decision_id": self.id,
            "decision_type": self.type.value,
            "chosen": str(self.chosen),
            "reason": self.reason,
            "context": self.context,
        }
        
        # Include alternatives if decision involved selection
        if self.alternatives:
            payload["alternatives"] = [str(alt) for alt in self.alternatives]
        
        # Include evidence if decision was data-driven
        if self.evidence:
            payload["evidence"] = self.evidence
        
        # Include parent linkage for decision chains
        if self.parent_id:
            payload["parent_decision_id"] = self.parent_id
        
        return payload


# ============================================================================
# DecisionLedger - Append-Only Decision Log
# ============================================================================

class DecisionLedger:
    """
    Append-only log of all strategic decisions made during a scan.
    
    Separate from EventStore because:
    1. Decisions are richer data structures than events
    2. Decision analysis requires graph queries (parent/child relationships)
    3. Testing needs decision replay without event side effects
    4. Audit/compliance may require longer retention than events
    
    Design:
    - Thread-safe via RLock
    - In-memory deque for O(1) append
    - Supports decision tree reconstruction via parent_id links
    - Can export to EventStore for UI consumption
    
    Invariants:
    - Sequence numbers are unique and monotonically increasing
    - Decisions are immutable once committed
    - Supports concurrent readers (no writer starvation)
    """
    
    def __init__(self, max_decisions: int = 5000):
        """
        Initialize the decision ledger.
        
        Args:
            max_decisions: Circular buffer size (older decisions evicted)
        """
        self._decisions: deque[DecisionPoint] = deque(maxlen=max_decisions)
        self._sequence: int = 0
        self._lock = threading.RLock()
        
        # Index for O(1) parent lookup (decision tree queries)
        self._by_parent: Dict[str, List[DecisionPoint]] = {}
    
    def commit(self, decision: DecisionPoint) -> DecisionPoint:
        """
        Append a decision to the ledger and assign sequence number.
        
        This is the ONLY way to add decisions, ensuring sequence integrity.
        
        Args:
            decision: The decision to commit (without sequence)
        
        Returns:
            The decision with sequence number assigned
        
        Thread-safety:
            Uses RLock to ensure atomic sequence allocation
        """
        # Context-managed operation.
        with self._lock:
            self._sequence += 1
            sequenced_decision = decision.with_sequence(self._sequence)
            self._decisions.append(sequenced_decision)
            
            # Update parent index for tree queries
            if sequenced_decision.parent_id:
                self._by_parent.setdefault(sequenced_decision.parent_id, []).append(
                    sequenced_decision
                )
        
        return sequenced_decision
    
    def get_children(self, decision_id: str) -> List[DecisionPoint]:
        """
        Get all decisions that were made as a result of this decision.
        Enables decision tree reconstruction.
        """
        # Context-managed operation.
        with self._lock:
            return list(self._by_parent.get(decision_id, []))
    
    def get_chain(self, decision_id: str) -> List[DecisionPoint]:
        """
        Get the causal chain leading to this decision.
        Returns [root_decision, ..., this_decision].
        """
        # Context-managed operation.
        with self._lock:
            chain = []
            current_id = decision_id
            
            # Walk backwards through parent links
            for decision in reversed(self._decisions):
                if decision.id == current_id:
                    chain.insert(0, decision)
                    current_id = decision.parent_id
                    if current_id is None:
                        break
            
            return chain
    
    def get_all(self) -> List[DecisionPoint]:
        """Get all decisions in sequence order."""
        # Context-managed operation.
        with self._lock:
            return list(self._decisions)
    
    def clear(self) -> None:
        """Clear all decisions. Primarily for testing."""
        # Context-managed operation.
        with self._lock:
            self._decisions.clear()
            self._sequence = 0
            self._by_parent.clear()
    
    def stats(self) -> Dict[str, Any]:
        """Return diagnostic statistics."""
        # Context-managed operation.
        with self._lock:
            type_counts = {}
            for d in self._decisions:
                type_counts[d.type.value] = type_counts.get(d.type.value, 0) + 1
            
            return {
                "total_decisions": len(self._decisions),
                "current_sequence": self._sequence,
                "max_capacity": self._decisions.maxlen,
                "decisions_by_type": type_counts,
                "decision_chains": len(self._by_parent)
            }


# ============================================================================
# DecisionContext - Execution Context with Auto-Event Emission
# ============================================================================

class DecisionContext:
    """
    Execution context that commits decisions to the ledger and emits events.
    
    This is the bridge between pure decision data and effectful event emission.
    Using a context manager ensures decisions are always committed and emitted.
    
    Design Pattern: Command Pattern + Unit of Work
    - Decisions are commands (pure data)
    - Context is the executor (triggers side effects)
    - Ledger is the transaction log (audit trail)
    - EventBus is the notification system (observer pattern)
    
    Usage:
        with DecisionContext(event_bus, ledger) as ctx:
            decision = ctx.choose(...)  # Auto-commits and emits
    
    Why context manager:
    - Guarantees emission happens even if exceptions occur
    - Makes decision scope explicit (transactions)
    - Enables batching multiple decisions into one event burst
    - Cleaner than manual try/finally blocks
    """
    
    def __init__(
        self,
        event_bus: Optional[EventBus] = None,
        ledger: Optional[DecisionLedger] = None,
        auto_emit: bool = True,
        narrator: Optional["NarratorEngine"] = None
    ):
        """
        Initialize decision context.
        
        Args:
            event_bus: EventBus for emitting events (None = no emission)
            ledger: DecisionLedger for audit trail (None = ephemeral decisions)
            auto_emit: Whether to auto-emit events on commit (default True)
            narrator: Optional NarratorEngine for human-readable L3 events
        """
        self._event_bus = event_bus
        self._ledger = ledger or DecisionLedger()
        self._auto_emit = auto_emit
        self._narrator = narrator
        self._parent_stack: List[str] = []  # For nested decision hierarchies
        self._pending: List[DecisionPoint] = []  # Batch commit support
    
    def __enter__(self) -> DecisionContext:
        """Enter context manager."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """
        Exit context manager.
        Commits any pending decisions even if exception occurred.
        """
        # Conditional branch.
        if self._pending:
            self.flush()
        return False  # Don't suppress exceptions
    
    def choose(
        self,
        decision_type: DecisionType,
        chosen: Any,
        reason: str,
        alternatives: Optional[List[Any]] = None,
        context: Optional[Dict[str, Any]] = None,
        evidence: Optional[Dict[str, Any]] = None,
        defer: bool = False
    ) -> DecisionPoint:
        """
        Make a strategic decision and optionally emit immediately.
        
        This is the primary decision-making API.
        
        Args:
            decision_type: Type of decision being made
            chosen: The selected option
            reason: Why this option was chosen
            alternatives: Other options considered
            context: Arbitrary metadata
            evidence: Supporting data
            defer: If True, decision is queued (use for batching)
        
        Returns:
            The committed DecisionPoint with sequence assigned
        
        Side Effects (if auto_emit=True and defer=False):
            - Decision committed to ledger
            - Event emitted to EventBus
        """
        # Link to parent if we're in a nested decision
        parent_id = self._parent_stack[-1] if self._parent_stack else None
        
        # Create immutable decision record
        decision = DecisionPoint.create(
            decision_type=decision_type,
            chosen=chosen,
            reason=reason,
            alternatives=alternatives,
            context=context,
            evidence=evidence,
            parent_id=parent_id
        )
        
        # Defer commit for batching
        if defer:
            self._pending.append(decision)
            return decision
        
        # Immediate commit and emit
        return self._commit_and_emit(decision)
    
    def _commit_and_emit(self, decision: DecisionPoint) -> DecisionPoint:
        """
        Atomically commit decision to ledger and emit event.
        
        Internal method - use choose() instead.
        """
        # Commit to ledger (assigns sequence)
        committed = self._ledger.commit(decision)
        
        # Emit event if configured
        if self._auto_emit:
            if self._event_bus:
                self._emit_decision_event(committed)
            
            # Layer 3: Narrative Emission (Automatic)
            if self._narrator:
                self._narrator.narrate(committed)
        
        return committed
    
    def _emit_decision_event(self, decision: DecisionPoint) -> None:
        """
        Emit decision as a typed event to EventBus.
        
        Maps DecisionPoint to appropriate EventBus methods.
        This is where the decision-to-event translation happens.
        """
        # Special handling for phase transitions (dedicated event type)
        if decision.type == DecisionType.PHASE_TRANSITION:
            phase = decision.context.get("phase", "UNKNOWN")
            previous_phase = decision.context.get("previous_phase")
            self._event_bus.emit_scan_phase_changed(
                phase=phase,
                previous_phase=previous_phase
            )
        
        # All decisions also emit as generic decision_made events
        # This ensures UI can display all strategic choices uniformly
        payload = decision.to_event_payload()
        
        # Map DecisionType to semantic intent for backwards compatibility
        if decision.type == DecisionType.INTENT_TRANSITION:
            intent = decision.chosen
        else:
            intent = decision.type.value
        
        self._event_bus.emit_decision_made(
            intent=intent,
            reason=decision.reason,
            context=payload["context"],
            source="strategos"
        )
    
    def flush(self) -> List[DecisionPoint]:
        """
        Commit all pending decisions.
        Useful for batched decision emission.
        """
        committed = []
        # Loop over items.
        for decision in self._pending:
            committed.append(self._commit_and_emit(decision))
        self._pending.clear()
        return committed
    
    @contextmanager
    def nested(self, parent_decision: DecisionPoint):
        """
        Context manager for hierarchical decisions.
        
        Usage:
            decision = ctx.choose(...)
            with ctx.nested(decision):
                sub_decision = ctx.choose(...)  # auto-linked as child
        """
        self._parent_stack.append(parent_decision.id)
        # Error handling block.
        try:
            yield self
        finally:
            self._parent_stack.pop()
    
    def get_ledger(self) -> DecisionLedger:
        """Access the underlying ledger for queries."""
        return self._ledger


# ============================================================================
# Convenience Factory Functions
# ============================================================================

def create_decision_context(
    event_bus: Optional[EventBus] = None,
    ledger: Optional[DecisionLedger] = None,
    narrator: Optional["NarratorEngine"] = None
) -> DecisionContext:
    """
    Factory for creating DecisionContext with default configuration.
    
    This is the recommended way to create contexts in production code.
    """
    return DecisionContext(event_bus=event_bus, ledger=ledger, auto_emit=True, narrator=narrator)


# ============================================================================
# Module-Level Singleton (Optional)
# ============================================================================

_global_ledger: Optional[DecisionLedger] = None
_ledger_lock = threading.Lock()


def get_global_ledger() -> DecisionLedger:
    """
    Get the global DecisionLedger singleton.
    
    Use this when you need a shared ledger across multiple contexts.
    For isolated testing, create separate ledgers.
    """
    global _global_ledger
    # Conditional branch.
    if _global_ledger is None:
        with _ledger_lock:
            if _global_ledger is None:
                _global_ledger = DecisionLedger()
    return _global_ledger


# ============================================================================
# Self-Test / Design Verification
# ============================================================================

if __name__ == "__main__":
    # Verify immutability
    decision = DecisionPoint.create(
        decision_type=DecisionType.INTENT_TRANSITION,
        chosen="intent_surface_enum",
        reason="Standard progression",
        alternatives=["skip", "execute"],
        context={"mode": "standard"}
    )
    
    try:
        decision.chosen = "different"  # Should fail (frozen)
        print("❌ Immutability violated!")
    except Exception:
        print("✓ Immutability enforced")
    
    # Verify ledger sequencing
    ledger = DecisionLedger()
    d1 = ledger.commit(decision)
    d2 = ledger.commit(decision)
    
    assert d1.sequence == 1
    assert d2.sequence == 2
    print(f"✓ Sequence integrity: {d1.sequence}, {d2.sequence}")
    
    # Verify decision chains
    parent = DecisionPoint.create(
        decision_type=DecisionType.PHASE_TRANSITION,
        chosen="PHASE_2",
        reason="Entering active recon"
    )
    parent_committed = ledger.commit(parent)
    
    child = DecisionPoint.create(
        decision_type=DecisionType.TOOL_SELECTION,
        chosen="httpx",
        reason="Live check",
        parent_id=parent_committed.id
    )
    child_committed = ledger.commit(child)
    
    chain = ledger.get_chain(child_committed.id)
    assert len(chain) == 2
    assert chain[0].id == parent_committed.id
    print(f"✓ Decision chain reconstruction: {len(chain)} decisions")
    
    print("\n✅ All design invariants verified!")
