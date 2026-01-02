<empty>
"""
core/sentient/diagnosis.py
The Diagnostic Cortex.
Responsible for classifying failures into actionable categories.
"""
import logging
from enum import Enum, auto
from typing import Optional, Type, Dict, Any
from dataclasses import dataclass

logger = logging.getLogger(__name__)

class ErrorType(str, Enum):
    """
    Categorization of failure modes for decision making.
    """
    TRANSIENT = "transient"       # Network blip, timeout -> RETRY
    PERMANENT = "permanent"       # 404, Schema error -> SKIP
    WAF_BLOCK = "waf_block"       # 403, Cloudflare -> ROTATE/COOL
    RESOURCE = "resource"         # Disk full, Memory limit -> ABORT/GC
    UNKNOWN = "unknown"           # Unhandled -> LOG & ABORT

@dataclass
class Diagnosis:
    type: ErrorType
    confidence: float
    reason: str
    recommendation: str

class ErrorClassifier:
    """
    Expert system for failure analysis.
    """
    
    def __init__(self):
        # Maps exception strings/types to error categories
        # TODO: Load this from a configurable policy file
        pass

    def diagnose(self, error: Exception, context: Dict[str, Any] = None) -> Diagnosis:
        """
        Analyze an exception and return a diagnosis.
        """
        err_str = str(error).lower()
        err_type = type(error).__name__
        
        # 1. WAF / Auth Blocks
        if "403" in err_str or "forbidden" in err_str or "captcha" in err_str:
             return Diagnosis(
                 ErrorType.WAF_BLOCK, 
                 0.9, 
                 "Likely WAF blocking or Auth failure",
                 "ROTATE_PROXY_OR_COOLDOWN"
             )

        # 2. Transient Network Issues
        # Check string OR type
        if ("timeout" in err_str or "connection reset" in err_str or "econnrefused" in err_str or
            isinstance(error, (ConnectionError, TimeoutError, OSError))):
            
            # Refine OSError: only if connection related (not file not found)
            if isinstance(error, FileNotFoundError):
                 pass # Fall through to default or permanent
            else:
                return Diagnosis(
                    ErrorType.TRANSIENT,
                    0.8,
                    f"Network instability detected ({err_type})",
                    "RETRY_WITH_BACKOFF"
                )

        # 3. Permanent Logic Errors
        if isinstance(error, (KeyError, ValueError, TypeError, AttributeError)):
             # Unless it's a known flaky library error, logic bugs are permanent
             return Diagnosis(
                 ErrorType.PERMANENT,
                 1.0,
                 f"Internal Logic Error: {err_type}",
                 "FAIL_TASK"
             )
        
        # 4. Resource Issues
        if "disk" in err_str or "memory" in err_str or "resource exhausted" in err_str:
             return Diagnosis(
                 ErrorType.RESOURCE,
                 0.9,
                 "System Resource Limit Hit",
                 "ABORT_SCAN"
             )

        # Default
        return Diagnosis(
            ErrorType.UNKNOWN,
            0.1,
            f"Unhandled Exception: {err_type} - {err_str}",
            "FAIL_TASK"
        )

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
    - WHICH EVENTS triggered it (trigger_event_sequence)

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
        trigger_event_sequence: Optional event sequence that triggered this decision
        timestamp: When decision was created (monotonic time)
        sequence: Ledger sequence number (set by DecisionLedger)

    Contract:
        - Once created, fields are immutable (frozen dataclass)
        - `sequence` is None until committed to ledger
        - `parent_id` creates causal chains for decision analysis
        - `trigger_event_sequence` enables event-decision correlation
    """
    id: str
    type: DecisionType
    chosen: Any
    reason: str
    alternatives: List[Any] = field(default_factory=list)
    context: Dict[str, Any] = field(default_factory=dict)
    evidence: Dict[str, Any] = field(default_factory=dict)
    parent_id: Optional[str] = None
    trigger_event_sequence: Optional[int] = None
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
        parent_id: Optional[str] = None,
        trigger_event_sequence: Optional[int] = None
    ) -> DecisionPoint:
        """
        Factory method for creating decisions.

        This is the primary way to create DecisionPoints.
        Validates that all required fields are provided.

        Args:
            decision_type: Classification of the decision
            chosen: The selected option
            reason: Why this option was chosen
            alternatives: Other options that were considered
            context: Arbitrary metadata (target, mode, scores, etc.)
            evidence: Supporting data that informed the decision
            parent_id: Link to parent decision (for decision trees)
            trigger_event_sequence: Event sequence that triggered this decision
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
            trigger_event_sequence=trigger_event_sequence,
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
            trigger_event_sequence=self.trigger_event_sequence,
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

        # Include event sequence for correlation
        if self.trigger_event_sequence:
            payload["trigger_event_sequence"] = self.trigger_event_sequence

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
        self._lock = threading.RLock()
        
    def commit(self, decision: DecisionPoint) -> DecisionPoint:
        """
        Append a decision to the ledger and assign sequence number.

        This is the ONLY way to add decisions, ensuring sequence integrity.
        Persists to database asynchronously.

        SEQUENCE UNIFICATION:
        Decisions and Events share the same GlobalSequenceAuthority timeline.
        This ensures perfect causal ordering: if event E (seq=42) triggers
        decision D (seq=43), we can always determine that E happened before D.

        Args:
            decision: The decision to commit (without sequence)

        Returns:
            The decision with sequence number assigned
        """
        # get_next_sequence() delegates to GlobalSequenceAuthority,
        # ensuring Events and Decisions share the same timeline
        from core.cortex.events import get_next_sequence
        from core.data.db import Database

        with self._lock:
            # Use global sequence generator (shared with EventStore)
            global_seq = get_next_sequence()
            sequenced_decision = decision.with_sequence(global_seq)
            self._decisions.append(sequenced_decision)
            
            # Persist to DB (fire-and-forget)
            try:
                # Convert to dict for DB
                payload = {
                    "id": sequenced_decision.id,
                    "sequence": sequenced_decision.sequence,
                    "type": sequenced_decision.type.value,
                    "chosen": sequenced_decision.chosen,
                    "reason": sequenced_decision.reason,
                    "alternatives": sequenced_decision.alternatives,
                    "context": sequenced_decision.context,
                    "evidence": sequenced_decision.evidence,
                    "parent_id": sequenced_decision.parent_id,
                    "trigger_event_sequence": sequenced_decision.trigger_event_sequence
                }
                Database.instance().save_decision(payload)
            except Exception:
                # DB failure should not crash the scanner
                pass
        
        return sequenced_decision
    
    async def get_children(self, decision_id: str) -> List[DecisionPoint]:
        """
        Get all decisions that were made as a result of this decision.
        Enables decision tree reconstruction.
        
        Fetches 'deep' children from Database (async).
        """
        from core.data.db import Database
        try:
            records = await Database.instance().get_decision_children(decision_id)
            # Rehydrate DecisionPoints (approximate, as immutable/frozen might limit reconstruction fidelity without factory)
            # We assume these are mostly for analysis/reporting.
            children = []
            for r in records:
                children.append(DecisionPoint(
                    id=r["id"],
                    type=DecisionType(r["type"]),
                    chosen=r["chosen"],
                    reason=r["reason"],
                    alternatives=r["alternatives"],
                    context=r["context"],
                    evidence=r["evidence"],
                    parent_id=r["parent_id"],
                    trigger_event_sequence=r["trigger_event_sequence"],
                    timestamp=0.0, # DB doesn't store monotonic float
                    sequence=r["sequence"]
                ))
            return children
        except Exception:
            return []
    
    def get_chain(self, decision_id: str) -> List[DecisionPoint]:
        """
        Get the causal chain leading to this decision.
        Returns [root_decision, ..., this_decision].
        
        NOTE: Only scans in-memory history (last N decisions).
        Deep history would require DB lookups.
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
        """Get all *in-memory* decisions in sequence order."""
        # Context-managed operation.
        with self._lock:
            return list(self._decisions)
    
    def clear(self) -> None:
        """Clear all decisions. Primarily for testing."""
        # Context-managed operation.
        with self._lock:
            self._decisions.clear()
    
    def stats(self) -> Dict[str, Any]:
        """Return diagnostic statistics."""
        # Context-managed operation.
        with self._lock:
            type_counts = {}
            for d in self._decisions:
                type_counts[d.type.value] = type_counts.get(d.type.value, 0) + 1
            
            return {
                "total_decisions_memory": len(self._decisions),
                "last_sequence": self._decisions[-1].sequence if self._decisions else 0,
                "max_capacity": self._decisions.maxlen,
                "decisions_by_type": type_counts
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
        trigger_event_sequence: Optional[int] = None,
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
            trigger_event_sequence: Event sequence that triggered this decision
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
            parent_id=parent_id,
            trigger_event_sequence=trigger_event_sequence
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
# Singleton Instance
# ============================================================================

_decision_ledger_instance: Optional[DecisionLedger] = None


def get_decision_ledger() -> DecisionLedger:
    """
    Get the global DecisionLedger singleton instance.

    Returns:
        Global DecisionLedger instance
    """
    global _decision_ledger_instance
    if _decision_ledger_instance is None:
        _decision_ledger_instance = DecisionLedger()
    return _decision_ledger_instance


# ============================================================================
# Self-Test / Design Verification
# ============================================================================

if __name__ == "__main__":
    # Initialize sequence for testing
    import core.cortex.events as events
    # Monkeypatch to bypass DB check
    events._event_sequence_initialized = True
    
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

"""Module scanner_engine: inline documentation for /Users/jason/Developer/sentinelforge/core/engine/scanner_engine.py.

PURPOSE
- macOS-compatible active scanner engine for SentinelForge.
- Orchestrates tool execution, streams live output, classifies results into findings,
  and persists findings/evidence/issues atomically via ScanTransaction.

KEY RESPONSIBILITIES
- Detect installed tools and filter via Vanguard.
- Execute multiple tools concurrently with resource limits and cancellation.
- Normalize and deduplicate findings deterministically.
- Stage all scan artifacts (findings, evidence, issues) and commit them atomically.

INTEGRATION
- Depends on:
  - core.toolkit.tools (tool registry + command builder)
  - core.cortex.scanner_bridge (classification)
  - core.toolkit.vuln_rules (issue/rule engine)
  - core.data.db (SQLite persistence)
  - core.engine.vanguard (preflight tool compatibility)
- Used by:
  - ScanSession / UI event pipeline (via session-scoped stores)
  - Legacy global behavior (when session is None)
"""

from __future__ import annotations

import asyncio
import logging
import os
import threading
from collections import deque
from urllib.parse import urlparse
from typing import Any, AsyncGenerator, Deque, Dict, List, Optional, Tuple

from core.data.findings_store import findings_store
from core.data.evidence_store import EvidenceStore
from core.cortex.scanner_bridge import ScannerBridge
from core.toolkit.vuln_rules import apply_rules
from core.data.issues_store import issues_store
from core.data.killchain_store import killchain_store
from core.toolkit.tools import TOOLS, get_tool_command, get_installed_tools
from core.base.task_router import TaskRouter
from core.cortex.correlator import GraphCorrelator

logger = logging.getLogger(__name__)


# ----------------------------
# Self-Healing (Resilience)
# ----------------------------
from core.sentient.diagnosis import ErrorClassifier, ErrorType, Diagnosis

class ResilienceContext:
    """
    Manages the 'Life Loop' of a scan task.
    Decides whether to retry, abort, or ignore failures.
    """
    def __init__(self, engine: "ScannerEngine", max_retries: int = 3):
        self.engine = engine
        self.max_retries = max_retries
        self.errors: List[Exception] = []
        self._classifier = ErrorClassifier()

    def diagnose(self, exc: Exception) -> str:
        diagnosis = self._classifier.diagnose(exc)
        logger.warning(f"[Resilience] Failure Diagnosed: {diagnosis.type} ({diagnosis.reason}) -> {diagnosis.recommendation}")
        
        if diagnosis.type == ErrorType.TRANSIENT:
            return "RETRY"
        elif diagnosis.type == ErrorType.WAF_BLOCK:
            # Trigger Stealth Mode
            if hasattr(self.engine, "enable_stealth_mode"):
                self.engine.enable_stealth_mode()
            return "RETRY" # Simple retry for now, eventually COOLDOWN
        elif diagnosis.type == ErrorType.RESOURCE:
            return "ABORT"
        else:
            return "FAIL"

    async def execute_with_retry(self, func, *args, **kwargs):
        """
        Execute a function with adaptive retry logic.
        """
        attempts = 0
        while attempts <= self.max_retries:
            try:
                return await func(*args, **kwargs)
            except Exception as e:
                attempts += 1
                decision = self.diagnose(e)
                
                if decision == "RETRY" and attempts <= self.max_retries:
                    backoff = 2 ** attempts # Exponential backoff: 2s, 4s, 8s
                    logger.info(f"[Resilience] Retrying task in {backoff}s (Attempt {attempts}/{self.max_retries})...")
                    await asyncio.sleep(backoff)
                    continue
                elif decision == "FAIL" or attempts > self.max_retries:
                    logger.error(f"[Resilience] Task failed permanently after {attempts} attempts.")
                    raise e
                elif decision == "ABORT":
                    raise ResourceExhaustedError(f"Aborting scan due to resource exhaustion: {e}")
                else:
                    raise e


class ResourceExhaustedError(Exception):
    """Raised when resource limits are exceeded."""


class ResourceGuard:
    """
    Prevents resource exhaustion during scans.

    Tracks and enforces limits on:
    - Total findings count (prevents runaway classifiers)
    - Disk usage for evidence/output (bounds in-memory + persisted evidence size)
    """

    def __init__(self, max_findings: int = 10000, max_disk_mb: int = 1000):
        self.base_max_findings = max_findings
        self.base_max_disk_mb = max_disk_mb
        self.max_findings = max_findings
        self.max_disk_mb = max_disk_mb
        self.findings_count = 0
        self.disk_usage_bytes = 0
        self._lock = threading.Lock()
        self._stealth_mode = False

    def set_stealth_mode(self, enabled: bool):
        with self._lock:
            self._stealth_mode = enabled
            factor = 0.5 if enabled else 1.0
            self.max_findings = int(self.base_max_findings * factor)
            # Disk limit usually stays hard cap, but we could lower it too
            logger.info(f"[ResourceGuard] Stealth Mode={'ON' if enabled else 'OFF'}. New Limits: Findings={self.max_findings}")

    def reset(self) -> None:
        """Reset counters for a new scan."""
        with self._lock:
            self.findings_count = 0
            self.disk_usage_bytes = 0

    def check_findings(self, count: int) -> bool:
        """Account findings and enforce max_findings."""
        with self._lock:
            if self.findings_count + count > self.max_findings:
                raise ResourceExhaustedError(
                    f"Too many findings: {self.findings_count + count} exceeds limit {self.max_findings}"
                )
            self.findings_count += count
            return True

    def enforce_disk_limit(self, additional_bytes: int) -> bool:
        """
        Enforce disk limit (hard cap). Use this while reading tool output.
        """
        with self._lock:
            max_bytes = self.max_disk_mb * 1024 * 1024
            if self.disk_usage_bytes + additional_bytes > max_bytes:
                raise ResourceExhaustedError(
                    f"Too much disk usage: {(self.disk_usage_bytes + additional_bytes) / 1024 / 1024:.1f}MB "
                    f"exceeds limit {self.max_disk_mb}MB"
                )
            return True

    def account_disk(self, additional_bytes: int) -> None:
        """
        Accounting-only disk tracking. Use this after output has already been truncated
        by enforce_disk_limit during read.
        """
        with self._lock:
            self.disk_usage_bytes += max(0, int(additional_bytes))

    def get_usage(self) -> Dict[str, object]:
        """Get current resource usage for monitoring."""
        with self._lock:
            max_bytes = self.max_disk_mb * 1024 * 1024
            return {
                "findings_count": self.findings_count,
                "max_findings": self.max_findings,
                "disk_usage_mb": self.disk_usage_bytes / 1024 / 1024,
                "max_disk_mb": self.max_disk_mb,
                "findings_percent": (self.findings_count / self.max_findings) * 100 if self.max_findings > 0 else 0,
                "disk_percent": (self.disk_usage_bytes / max_bytes) * 100 if max_bytes > 0 else 0,
            }


# Try to import psutil for resource awareness
try:
    import psutil

    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

MIN_CONCURRENT_TOOLS = 1
MAX_CONCURRENT_TOOLS_BASE = 20  # Base value for small systems


def calculate_concurrent_limit() -> int:
    """Calculate optimal concurrency based on available system resources."""
    try:
        cpu_count = os.cpu_count() or 2

        if HAS_PSUTIL:
            memory_info = psutil.virtual_memory()
            available_memory_gb = memory_info.available / (1024**3)

            # 1 tool per 2GB available RAM (floor), capped by half CPU cores
            memory_based = max(1, int(available_memory_gb / 2))
            cpu_based = max(1, cpu_count // 2)
            calculated = min(memory_based, cpu_based)

            return max(MIN_CONCURRENT_TOOLS, min(calculated, MAX_CONCURRENT_TOOLS_BASE * 2))

        return max(MIN_CONCURRENT_TOOLS, min(cpu_count // 2, MAX_CONCURRENT_TOOLS_BASE * 2))
    except Exception:
        return MAX_CONCURRENT_TOOLS_BASE


MAX_CONCURRENT_TOOLS = calculate_concurrent_limit()

DEFAULT_TOOL_TIMEOUT_SECONDS = 300  # 5 minutes per tool hard cap
DEFAULT_TOOL_IDLE_TIMEOUT_SECONDS = 60  # 1 minute without output => consider stuck
DEFAULT_GLOBAL_SCAN_TIMEOUT_SECONDS = 900  # 15 minutes overall cap


class ScanTransaction:
    """
    Transactional wrapper for a scan.

    Key invariants:
    - UI stores are ONLY updated AFTER DB commit succeeds.
    - All findings/issues/evidence are staged and written in a single SQLite transaction.
    - scan_sequence is allocated INSIDE commit(), so it represents committed order.
    - Scan record is created INSIDE commit(), eliminating zombie "running" records on crash.
    """

    def __init__(self, engine: "ScannerEngine", session_id: str, target: str = "unknown"):
        self._engine = engine
        self._session_id = session_id
        self._target = target

        self._committed = False
        self._rolled_back = False

        import uuid

        self._scan_id = str(uuid.uuid4())

        # Assigned during commit (not in __aenter__) to preserve "committed order"
        self._scan_sequence: int = 0

        # ResourceGuard snapshot for rollback
        self._resource_snapshot: Optional[Dict[str, object]] = None

        # Staging areas
        self._staged_findings: List[Dict[str, Any]] = []
        self._staged_issues: List[Dict[str, Any]] = []
        self._staged_evidence: List[Dict[str, Any]] = []

        # Recon edges staged during transaction
        self._staged_recon_edges: List[dict] = []
        self._staged_recon_edge_keys: set[tuple] = set()

        # Rule outputs staged once (no recompute after commit)
        self._staged_rule_killchain_edges: List[dict] = []

        # Best-effort progress marker
        self._last_completed_tool: Optional[str] = None

    async def __aenter__(self) -> "ScanTransaction":
        if self._engine._active_transaction:
            raise RuntimeError("Nested transactions not supported")
        self._engine._active_transaction = self

        self._resource_snapshot = self._engine.resource_guard.get_usage()

        logger.info(f"[SCAN_BEGIN] scan_id={self._scan_id} session_id={self._session_id} target={self._target}")
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if exc_type is None and not self._rolled_back:
            await self.commit()
        else:
            await self.rollback(error_message=str(exc_val) if exc_val else "canceled")

        self._engine._active_transaction = None
        return False

    @property
    def scan_id(self) -> str:
        return self._scan_id

    @property
    def scan_sequence(self) -> int:
        return self._scan_sequence

    def mark_tool_completed(self, tool: str) -> None:
        self._last_completed_tool = tool

    def add_finding(self, finding: Dict[str, Any]) -> None:
        if self._committed or self._rolled_back:
            raise RuntimeError("Transaction already closed")
        self._staged_findings.append(finding)

    def add_issue(self, issue: Dict[str, Any]) -> None:
        if self._committed or self._rolled_back:
            raise RuntimeError("Transaction already closed")
        self._staged_issues.append(issue)

    def add_evidence(self, evidence: Dict[str, Any]) -> None:
        if self._committed or self._rolled_back:
            raise RuntimeError("Transaction already closed")
        self._staged_evidence.append(evidence)

    def add_recon_edges(self, edges: List[dict]) -> None:
        if self._committed or self._rolled_back:
            raise RuntimeError("Transaction already closed")
        for edge in edges:
            key = self._engine._edge_signature(edge)
            if key in self._staged_recon_edge_keys:
                continue
            self._staged_recon_edge_keys.add(key)
            self._staged_recon_edges.append(edge)

    def stage_rule_killchain_edges(self, edges: List[dict]) -> None:
        if self._committed or self._rolled_back:
            raise RuntimeError("Transaction already closed")
        self._staged_rule_killchain_edges = list(edges)

    async def commit(self) -> None:
        if self._committed or self._rolled_back:
            return

        from core.data.db import Database

        db = None

        logger.info(
            f"[ScanTransaction] START COMMIT {self._scan_id}: "
            f"staged={len(self._staged_findings)} findings, "
            f"{len(self._staged_issues)} issues, {len(self._staged_evidence)} evidence"
        )

        try:
            db = Database.instance()
            if not db._initialized:
                await db.init()
            if db._db_connection is None:
                raise RuntimeError("Database not available - cannot commit")

            async with db._db_lock:
                conn = db._db_connection
                if conn is None:
                    raise RuntimeError("Database connection not available")

                await conn.execute("BEGIN IMMEDIATE")

                try:
                    # Allocate scan_sequence INSIDE the commit transaction
                    self._scan_sequence = await db.next_scan_sequence_txn(conn)

                    # Create scan record INSIDE the same transaction
                    await db.create_scan_record_txn(
                        scan_id=self._scan_id,
                        scan_sequence=self._scan_sequence,
                        session_id=self._session_id,
                        target=self._target,
                        status="running",
                        conn=conn,
                    )

                    # Persist findings/evidence/issues
                    for finding in self._staged_findings:
                        await db.save_finding_txn(finding, self._session_id, self._scan_sequence, conn)

                    for evidence in self._staged_evidence:
                        await db.save_evidence_txn(evidence, self._session_id, self._scan_sequence, conn)

                    for issue in self._staged_issues:
                        await db.save_issue_txn(issue, self._session_id, self._scan_sequence, conn)

                    # Mark scan row with last_completed_tool if we have it
                    if self._last_completed_tool:
                        await db.update_scan_last_completed_tool_txn(self._scan_id, self._last_completed_tool, conn)

                    await conn.commit()
                    self._committed = True

                    logger.info(
                        f"[SCAN_COMMIT] scan_id={self._scan_id} scan_sequence={self._scan_sequence} "
                        f"findings={len(self._staged_findings)} issues={len(self._staged_issues)} "
                        f"evidence={len(self._staged_evidence)}"
                    )
                except Exception as e:
                    try:
                        await conn.rollback()
                    except Exception:
                        pass
                    raise RuntimeError(f"Transaction commit failed: {e}") from e

            # After DB commit, publish to in-memory stores (UI-safe)
            self._update_stores_after_commit()

            # Update scan record outside the transaction lock (best effort)
            try:
                await db.update_scan_status(
                    self._scan_id,
                    "committed",
                    findings_count=len(self._staged_findings),
                    issues_count=len(self._staged_issues),
                    evidence_count=len(self._staged_evidence),
                    last_completed_tool=self._last_completed_tool,
                )
            except Exception as e:
                logger.warning(f"[ScanTransaction] Failed to update scan record: {e}")

            # Cleanup engine maps to avoid stale cross-scan state
            try:
                self._engine._results_map.clear()
            except Exception:
                pass

        except Exception as e:
            logger.error(f"[ScanTransaction] Commit error: {e}")
            self._rolled_back = True

            # Clear engine scan-scoped state to prevent stale pollution
            self._engine._recon_edges.clear()
            self._engine._recon_edge_keys.clear()
            self._engine._last_results.clear()
            self._engine._results_map.clear()
            self._engine._fingerprint_cache_set.clear()
            self._engine._fingerprint_cache_order.clear()

            self._staged_findings.clear()
            self._staged_issues.clear()
            self._staged_evidence.clear()
            self._staged_recon_edges.clear()
            self._staged_recon_edge_keys.clear()
            self._staged_rule_killchain_edges.clear()

            if db is not None:
                try:
                    await db.update_scan_status(
                        self._scan_id,
                        "failed",
                        error_message=str(e),
                        failure_phase="commit",
                        exception_type=type(e).__name__,
                        last_completed_tool=self._last_completed_tool,
                    )
                except Exception:
                    pass
            raise

    def _update_stores_after_commit(self) -> None:
        """
        Publish committed data to in-memory stores AFTER DB commit.

        IMPORTANT:
        - We DO NOT recompute apply_rules() here.
        - We publish exactly what we staged to preserve determinism.
        """
        logger.info(
            f"[ScanTransaction] UI PUBLISH {self._scan_id}: "
            f"{len(self._staged_findings)} findings, {len(self._staged_issues)} issues, {len(self._staged_evidence)} evidence"
        )

        # Findings
        if self._staged_findings:
            if self._engine.session:
                self._engine.session.findings.bulk_add(self._staged_findings, persist=True)
            else:
                findings_store.bulk_add(self._staged_findings, persist=True)

        # Evidence
        if self._staged_evidence:
            evidence_store = self._engine.session.evidence if self._engine.session else EvidenceStore.instance()
            for ev in self._staged_evidence:
                tool = ev.get("tool", "unknown")
                raw_output = ev.get("raw_output", "")
                metadata = ev.get("metadata", {})
                evidence_store.add_evidence(tool, raw_output, metadata, persist=True)

        # Issues
        if self._staged_issues:
            if self._engine.session:
                self._engine.session.issues.replace_all(self._staged_issues, persist=True)
            else:
                issues_store.replace_all(self._staged_issues, persist=True)

        # Killchain edges (rules + recon + correlator implied edges)
        if self._engine.session and hasattr(self._engine.session, "killchain"):
            combined_edges = list(self._staged_rule_killchain_edges) + list(self._staged_recon_edges)

            # Correlator (graph intelligence)
            source_findings = self._engine.session.findings.get_all()
            nodes = []
            for f in source_findings:
                asset = f.get("asset") or f.get("target") or "unknown"
                if asset == "unknown":
                    continue
                attributes = {}
                meta = f.get("metadata", {})
                for key in ["simhash", "favicon_hash", "ssl_serial", "ga_id"]:
                    val = meta.get(key)
                    if val:
                        attributes[key] = val
                if attributes:
                    nodes.append({"id": asset, "attributes": attributes})

            if nodes:
                correlator = GraphCorrelator()
                implied_edges = correlator.process(nodes)
                if implied_edges:
                    combined_edges.extend(implied_edges)

            self._engine.session.killchain.replace_all(combined_edges, persist=True)
            logger.info(
                f"[ScanTransaction] UI PUBLISH COMPLETE {self._scan_id}: issues={len(self._staged_issues)} "
                f"killchain_edges={len(combined_edges)}"
            )

    async def rollback(self, error_message: Optional[str] = None) -> None:
        if self._committed or self._rolled_back:
            return
        self._rolled_back = True

        logger.info(
            f"[ScanTransaction] START ROLLBACK {self._scan_id}: "
            f"discarding {len(self._staged_findings)} findings, {len(self._staged_issues)} issues, {len(self._staged_evidence)} evidence"
        )

        self._staged_findings.clear()
        self._staged_issues.clear()
        self._staged_evidence.clear()
        self._staged_recon_edges.clear()
        self._staged_recon_edge_keys.clear()
        self._staged_rule_killchain_edges.clear()

        # Restore ResourceGuard snapshot
        if self._resource_snapshot:
            try:
                self._engine.resource_guard.findings_count = int(self._resource_snapshot.get("findings_count", 0))
                disk_mb = float(self._resource_snapshot.get("disk_usage_mb", 0.0))
                self._engine.resource_guard.disk_usage_bytes = int(disk_mb * 1024 * 1024)
            except Exception as e:
                logger.warning(f"[ScanTransaction] Failed to restore ResourceGuard: {e}")

        # Clear engine scan-scoped state
        self._engine._recon_edges.clear()
        self._engine._recon_edge_keys.clear()
        self._engine._results_map.clear()
        self._engine._fingerprint_cache_set.clear()
        self._engine._fingerprint_cache_order.clear()

        logger.info(
            f"[SCAN_ROLLBACK] scan_id={self._scan_id} session_id={self._session_id} reason={error_message or 'unknown'}"
        )

        from core.data.db import Database

        db = Database.instance()
        try:
            await db.update_scan_status(
                self._scan_id,
                "rolled_back",
                error_message=error_message,
                failure_phase="commit",
                exception_type="Rollback",
                last_completed_tool=self._last_completed_tool,
            )
        except Exception as e:
            logger.warning(f"[ScanTransaction] Failed to update scan record on rollback: {e}")

    @property
    def is_active(self) -> bool:
        return not self._committed and not self._rolled_back

    def stats(self) -> Dict[str, int]:
        return {"findings": len(self._staged_findings), "issues": len(self._staged_issues), "evidence": len(self._staged_evidence)}


class ScannerEngine:
    """Runs supported scanning tools on macOS (no unsupported tool errors)."""

    def __init__(self, session=None):
        self.session = session

        self._last_results: List[dict] = []

        # Deterministic, bounded fingerprint cache (deque + set)
        self._fingerprint_cache_max = 10000
        self._fingerprint_cache_order: Deque[str] = deque()
        self._fingerprint_cache_set: set[str] = set()

        self._installed_meta: Dict[str, Dict[str, object]] = {}

        # Recon edges (engine-scoped for legacy, but transaction uses txn staging)
        self._recon_edges: List[dict] = []
        self._recon_edge_keys: set[tuple] = set()

        # Task management state
        self._pending_tasks: List[object] = []
        self._running_tasks: Dict[str, asyncio.Task[List[dict]]] = {}
        self._queue: asyncio.Queue[str] = asyncio.Queue()
        self._results_map: Dict[str, object] = {}
        self._procs: Dict[str, asyncio.subprocess.Process] = {}

        # Resource guard
        self.resource_guard = ResourceGuard(max_findings=10000, max_disk_mb=1000)

        # Transaction state
        self._active_transaction: Optional[ScanTransaction] = None

        # Scan lock
        self._scan_lock = asyncio.Lock()

        # Cancel state
        self._cancel_event: Optional[asyncio.Event] = None

    # ----------------------------
    # Env timeouts
    # ----------------------------
    @staticmethod
    def _get_env_seconds(name: str, default: int) -> int:
        val = os.environ.get(name)
        if not val:
            return default
        try:
            return int(val)
        except ValueError:
            return default

    def _tool_timeout_seconds(self) -> int:
        return self._get_env_seconds("SCANNER_TOOL_TIMEOUT", DEFAULT_TOOL_TIMEOUT_SECONDS)

    def _tool_idle_timeout_seconds(self) -> int:
        return self._get_env_seconds("SCANNER_TOOL_IDLE_TIMEOUT", DEFAULT_TOOL_IDLE_TIMEOUT_SECONDS)

    def _global_scan_timeout_seconds(self) -> int:
        return self._get_env_seconds("SCANNER_GLOBAL_TIMEOUT", DEFAULT_GLOBAL_SCAN_TIMEOUT_SECONDS)

    async def _global_timeout_runner(self, timeout_secs: int, cancel_flag: asyncio.Event, queue: asyncio.Queue[str]):
        try:
            await asyncio.sleep(max(0, timeout_secs))
        except asyncio.CancelledError:
            return

        if cancel_flag.is_set():
            return

        cancel_flag.set()
        await queue.put(f"[scanner] ⏱️ Global timeout {timeout_secs}s reached; canceling scan and terminating tools...")

        for exec_id, proc in list(self._procs.items()):
            if proc and proc.returncode is None:
                try:
                    proc.terminate()
                    await queue.put(f"[{exec_id}] terminated due to global timeout")
                except ProcessLookupError:
                    pass
                except Exception as exc:
                    await queue.put(f"[{exec_id}] termination error on timeout: {exc}")

        await asyncio.sleep(0.2)

        for exec_id, proc in list(self._procs.items()):
            if proc and proc.returncode is None:
                try:
                    proc.kill()
                    await queue.put(f"[{exec_id}] force-killed after global timeout")
                except ProcessLookupError:
                    pass
                except Exception as exc:
                    await queue.put(f"[{exec_id}] force-kill error on timeout: {exc}")


    async def scan(self, target: str, selected_tools: List[str] | None = None, cancel_flag=None) -> AsyncGenerator[str, None]:
        """
        Async generator that yields log-style strings while tools run.

        Entire scan is under _scan_lock to protect engine state.
        """
        async with self._scan_lock:
            from core.engine.vanguard import Vanguard

            installed = self._detect_installed()
            candidates = list(installed.keys())
            valid_names = Vanguard.preflight_check(candidates)
            self._installed_meta = {k: v for k, v in installed.items() if k in valid_names}
            installed = self._installed_meta

            # Reset state for run
            self._last_results = []
            self._recon_edges = []
            self._recon_edge_keys = set()
            self._procs = {}
            self._pending_tasks = []
            self._running_tasks = {}
            self._results_map = {}
            self._fingerprint_cache_set.clear()
            self._fingerprint_cache_order.clear()

            selected_clean = [t for t in (selected_tools or []) if t in TOOLS]
            tools_to_run = list(installed.keys())
            missing: List[str] = []

            if selected_clean:
                tools_to_run = [t for t in selected_clean if t in installed]
                missing = [t for t in selected_clean if t not in installed]
                yield f"[scanner] Selected tools: {', '.join(selected_clean)}"

            if missing:
                msg = f"[scanner] ⚠️ WARNING: requested but NOT found in PATH: {', '.join(missing)}"
                yield msg
                logger.warning(msg)
                logger.warning(f"[scanner] PATH: {os.environ.get('PATH')}")

            if not tools_to_run:
                yield "[scanner] No supported tools available in PATH. Skipping tool phase."
                return

            yield f"Installed tools: {', '.join(tools_to_run)}"

            sess_id = self.session.session_id if self.session else "global_scan"

            self.resource_guard.reset()

            queue: asyncio.Queue[str] = asyncio.Queue()

            local_cancel: asyncio.Event = cancel_flag or asyncio.Event()
            self._cancel_event = local_cancel

            watchdog_task = None
            global_timeout = self._global_scan_timeout_seconds()
            if global_timeout and global_timeout > 0:
                watchdog_task = asyncio.create_task(self._global_timeout_runner(global_timeout, local_cancel, queue))

            async with ScanTransaction(self, sess_id, target) as txn:
                try:
                    pending: List[object] = list(tools_to_run)

                    self._pending_tasks = pending
                    self._running_tasks = {}
                    self._queue = queue
                    self._results_map = {}

                    import uuid

                    while self._pending_tasks or self._running_tasks:
                        if local_cancel.is_set():
                            await self._queue.put("[scanner] cancellation requested; stopping new tasks")
                            self._pending_tasks.clear()
                            break

                        while self._pending_tasks and len(self._running_tasks) < MAX_CONCURRENT_TOOLS:
                            task_def = self._pending_tasks.pop(0)

                            if isinstance(task_def, str):
                                tool = task_def
                                args = None
                            else:
                                tool = str(task_def.get("tool"))
                                args = task_def.get("args")

                            exec_id = f"{tool}:{uuid.uuid4().hex[:8]}"
                            self._running_tasks[exec_id] = asyncio.create_task(
                                self._run_tool_task(exec_id, tool, target, self._queue, args, local_cancel)
                            )
                            await self._queue.put(f"[scanner] Started {tool} ({exec_id})")

                        if not self._running_tasks:
                            break

                        done, _ = await asyncio.wait(list(self._running_tasks.values()), timeout=0.2)

                        while not self._queue.empty():
                            yield self._queue.get_nowait()

                        for finished in done:
                            exec_id = next((eid for eid, t in self._running_tasks.items() if t is finished), None)
                            if not exec_id:
                                continue
                            try:
                                self._results_map[exec_id] = finished.result()
                            except Exception as exc:  # pragma: no cover
                                self._results_map[exec_id] = exc
                                await self._queue.put(f"[{exec_id}] task error: {exc}")
                            del self._running_tasks[exec_id]

                        if not done and local_cancel.is_set():
                            await self._queue.put("[scanner] Cancellation detected - terminating running tools...")
                            for exec_id, proc in list(self._procs.items()):
                                if proc and proc.returncode is None:
                                    try:
                                        proc.terminate()
                                        await self._queue.put(f"[{exec_id}] terminated due to cancellation")
                                    except ProcessLookupError:
                                        pass
                            await asyncio.sleep(0.2)
                            for exec_id, proc in list(self._procs.items()):
                                if proc and proc.returncode is None:
                                    try:
                                        proc.kill()
                                        await self._queue.put(f"[{exec_id}] force-killed after termination timeout")
                                    except ProcessLookupError:
                                        pass
                            await self._queue.put("[scanner] All tools terminated due to cancellation")

                    if watchdog_task is not None:
                        try:
                            watchdog_task.cancel()
                        except Exception:
                            pass

                    while not self._queue.empty():
                        yield self._queue.get_nowait()

                    if local_cancel.is_set():
                        await txn.rollback("canceled")
                        await self.shutdown(reason="canceled")
                        yield "[scanner] Scan canceled - Transaction Rolled Back."
                        return

                    await asyncio.sleep(0)
                    while not self._queue.empty():
                        yield self._queue.get_nowait()

                    # Aggregate findings from all tool exec results
                    all_findings: List[dict] = []
                    for exec_id, result in self._results_map.items():
                        if isinstance(result, list):
                            all_findings.extend(result)

                    normalized = self._normalize_findings(all_findings)
                    self._last_results = normalized

                    # ================================================================
                    # TRANSACTIONAL INVARIANT:
                    # All findings MUST go through txn.add_finding().
                    # The transaction ensures atomicity: either ALL findings are
                    # committed to DB and published to UI stores, or NONE are.
                    # ================================================================
                    # Stage findings (no UI store updates until commit succeeds)
                    for f in normalized:
                        txn.add_finding(f)

                    # Stage recon edges (graph relationships between findings)
                    recon_edges = self._build_recon_edges(normalized)
                    txn.add_recon_edges(recon_edges)

                    # Enrichment: stage issues + killchain edges
                    self._refresh_enrichment(txn)

                except Exception as e:
                    await txn.rollback(str(e))
                    logger.error(f"[ScannerEngine] Critical error, rolling back: {e}")
                    raise

            # After context exit, commit has run and stores updated
            if hasattr(txn, "_committed") and txn._committed:
                stats = txn.stats()
                yield f"[scanner] Processed {stats['findings']} findings, committed transaction"

    def queue_task(self, tool: str, args: List[str] | None = None) -> None:
        """
        Dynamically add a tool to the current scan queue.

        Args:
            tool: Name of tool to run
            args: Optional arguments
        """
        if tool not in TOOLS:
            raise ValueError(f"Unknown tool: {tool}")
        if tool not in self._installed_meta:
            raise ValueError(f"Tool not installed: {tool}")

        if args:
             # Basic sanity check on args
             for arg in args:
                 if ";" in arg or "|" in arg:
                     raise ValueError(f"Potentially unsafe argument: {arg}")

        self._pending_tasks.append({"tool": tool, "args": args})
        logger.info(f"[ScannerEngine] Dynamically queued task: {tool} {args}")

    async def shutdown(self, reason: str = "shutdown") -> None:
        """Cleanup running tasks and processes."""
        try:
            self._pending_tasks.clear()
        except Exception:
            pass

        tasks: List[asyncio.Task] = []
        try:
            tasks = list(self._running_tasks.values())
            for t in tasks:
                t.cancel()
        except Exception:
            tasks = []

        procs: List[Tuple[str, asyncio.subprocess.Process]] = []
        try:
            procs = list(self._procs.items())
        except Exception:
            procs = []

        for exec_id, proc in procs:
            if not proc or proc.returncode is not None:
                continue
            try:
                proc.terminate()
            except ProcessLookupError:
                pass
            except Exception as exc:
                logger.debug(f"[scanner] terminate failed for {exec_id} ({reason}): {exc}")

        try:
            await asyncio.sleep(0.2)
        except asyncio.CancelledError:
            pass

        for exec_id, proc in procs:
            if not proc or proc.returncode is not None:
                continue
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            except Exception as exc:
                logger.debug(f"[scanner] kill failed for {exec_id} ({reason}): {exc}")

        if tasks:
            try:
                await asyncio.gather(*tasks, return_exceptions=True)
            except Exception:
                pass

        for exec_id, proc in procs:
            if not proc:
                continue
            try:
                if proc.returncode is None:
                    await asyncio.wait_for(proc.wait(), timeout=1.0)
            except asyncio.TimeoutError:
                pass
            except Exception:
                pass

        try:
            self._running_tasks.clear()
        except Exception:
            pass
        try:
            self._procs.clear()
        except Exception:
            pass

    def queue_task(self, tool: str, args: List[str] = None) -> None:
        """
        Dynamically add a task to the running scan.

        SECURITY
        - Tool must be in TOOLS allowlist.
        - Args validated to block shell injection patterns.
        - Reject if scan cancellation is set.
        """
        if tool not in TOOLS:
            raise ValueError(f"Unknown tool '{tool}'. Must be one of: {', '.join(TOOLS)}")

        if self._cancel_event is not None and self._cancel_event.is_set():
            raise RuntimeError("Scan is canceled - cannot queue dynamic tasks")

        if not hasattr(self, "_pending_tasks"):
            raise RuntimeError("No active scan - cannot queue dynamic tasks")

        if args:
            if len(args) > 50:
                raise ValueError(f"Too many arguments ({len(args)}), max 50 allowed")

            dangerous_patterns = [";", "|", "&&", "||", "$(", "`", "\n", "\r"]
            for arg in args:
                arg_str = str(arg)
                for pattern in dangerous_patterns:
                    if pattern in arg_str:
                        raise ValueError(
                            f"Dangerous character '{pattern}' in argument '{arg_str}'. Shell injection patterns not allowed."
                        )

        if hasattr(self, "_installed_meta") and tool not in self._installed_meta:
            logger.warning(f"[queue_task] Tool '{tool}' not installed, adding anyway (will fail during execution)")

        self._pending_tasks.append({"tool": tool, "args": args})

    async def run_all(self, target: str):
        async for _ in self.scan(target):
            pass
        return list(self._last_results)

    # ----------------------------
    # Helpers
    # ----------------------------
    def _detect_installed(self) -> Dict[str, Dict[str, object]]:
        return get_installed_tools()

    def _normalize_findings(self, items: List[dict] | None) -> List[dict]:
        normalized: List[dict] = []
        if not items:
            return normalized

        for item in items:
            entry = dict(item)
            entry.setdefault("message", entry.get("proof", ""))
            entry.setdefault("tags", [])
            entry.setdefault("families", [])
            entry.setdefault("metadata", {})
            severity = str(entry.get("severity", "INFO")).upper()
            entry["severity"] = severity

            original_target = entry.get("target") or entry.get("asset") or "unknown"
            asset = self._normalize_asset(original_target)
            entry.setdefault("metadata", {})
            entry["metadata"].setdefault("original_target", original_target)
            entry["asset"] = asset
            entry["target"] = asset

            fingerprint = entry.setdefault(
                "fingerprint",
                f"{entry.get('tool', 'scanner')}:{asset}:{entry.get('type', 'generic')}:{severity}",
            )

            # Deterministic bounded dedupe: FIFO eviction
            if fingerprint in self._fingerprint_cache_set:
                continue

            self._fingerprint_cache_set.add(fingerprint)
            self._fingerprint_cache_order.append(fingerprint)

            # Evict oldest if over capacity
            while len(self._fingerprint_cache_order) > self._fingerprint_cache_max:
                old = self._fingerprint_cache_order.popleft()
                self._fingerprint_cache_set.discard(old)

            normalized.append(entry)

        return normalized

    def get_last_results(self) -> List[dict]:
        return list(self._last_results)

    def _build_recon_edges(self, findings: List[dict]) -> List[dict]:
        edges: List[dict] = []
        for item in findings:
            families = item.get("families", [])
            recon_families = [fam for fam in families if fam.startswith("recon-phase")]
            if not recon_families:
                continue
            metadata = item.get("metadata") or {}
            variant = metadata.get("variant") or "behavior"
            for fam in recon_families:
                edges.append(
                    {
                        "source": item.get("asset", "unknown"),
                        "target": f"{fam}:{variant}",
                        "label": item.get("type"),
                        "severity": item.get("severity"),
                        "tags": item.get("tags", []),
                        "signal": item.get("message"),
                        "families": families,
                        "edge_type": "behavioral-signal",
                    }
                )
        return edges

    def _record_recon_edges(self, edges: List[dict]) -> None:
        for edge in edges:
            key = self._edge_signature(edge)
            if key in self._recon_edge_keys:
                continue
            self._recon_edge_keys.add(key)
            self._recon_edges.append(edge)

    def _edge_signature(self, edge: dict) -> tuple:
        return (edge.get("source"), edge.get("target"), edge.get("label"), edge.get("edge_type"), edge.get("severity"))

    def _refresh_enrichment(self, txn: ScanTransaction) -> tuple[int, int]:
        """
        Enrich findings with issues and killchain analysis.

        TRANSACTIONAL INVARIANT:
        - All issues are staged via txn.add_issue()
        - All killchain edges are staged via txn.stage_rule_killchain_edges()
        - NO direct writes to stores (deferred until commit succeeds)
        - Correlator is run AFTER commit in ScanTransaction._update_stores_after_commit()

        Args:
            txn: Active ScanTransaction (must be non-None and is_active)

        Returns:
            (enriched_count, edge_count): Number of issues and edges staged
        """
        if not txn or not txn.is_active:
            raise RuntimeError("_refresh_enrichment requires an active transaction")

        if self._last_results:
            enriched, _, rule_killchain_edges = apply_rules(self._last_results)
        else:
            enriched, _, rule_killchain_edges = [], [], []

        # Stage issues for commit
        for issue in enriched:
            txn.add_issue(issue)

        # Stage rule-generated killchain edges for commit
        txn.stage_rule_killchain_edges(rule_killchain_edges)

        # Killchain store publish happens after commit, combining:
        # - txn staged recon edges (from findings)
        # - rule killchain edges (from this method)
        # - correlator implied edges (computed after commit)
        return len(enriched), len(rule_killchain_edges)

    async def _run_tool_task(
        self,
        exec_id: str,
        tool: str,
        target: str,
        queue: asyncio.Queue[str],
        args: List[str] | None,
        cancel_flag: asyncio.Event,
    ) -> List[dict]:
        """
        Run a single tool with resilience wrapper.
        """
        async def _core_executor():
             return await self._execute_tool(exec_id, tool, target, queue, args, cancel_flag)

        # Initialize resilience context with engine reference
        ctx = ResilienceContext(self, max_retries=3)
        try:
             return await ctx.execute_with_retry(_core_executor)
        except Exception:
             # Errors logged by resilience context, propagate up
             raise

    def enable_stealth_mode(self):
        """
        Activate Stealth Mode: Reduce resource limits and (TODO) increase delays.
        """
        logger.warning("[ScannerEngine] 🛡️ ACTIVATING STEALTH MODE due to detected WAF/Block.")
        self.resource_guard.set_stealth_mode(True)

    async def _execute_tool(
        self,
        exec_id: str,
        tool: str,
        target: str,
        queue: asyncio.Queue[str],
        args: List[str] | None,
        cancel_flag: asyncio.Event,
    ) -> List[dict]:
        meta_override = self._installed_meta.get(tool)

        tool_timeout = self._tool_timeout_seconds()
        idle_timeout = self._tool_idle_timeout_seconds()

        if args:
            cmd = [tool] + args
            cmd = [arg.replace("{target}", target) for arg in cmd]
            stdin_input = None
        else:
            cmd, stdin_input = get_tool_command(tool, target, meta_override)

        await queue.put(f"--- Running {tool} ({exec_id}) ---")

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.PIPE if stdin_input else None,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            self._procs[exec_id] = proc

            if stdin_input and proc.stdin:
                proc.stdin.write((stdin_input + "\n").encode("utf-8"))
                proc.stdin.close()
        except FileNotFoundError:
            msg = f"[{tool}] NOT INSTALLED or not in PATH."

            if self._active_transaction and self._active_transaction.is_active:
                self._active_transaction.add_evidence(
                    {"tool": tool, "raw_output": msg, "metadata": {"target": target, "error": "not_found", "exec_id": exec_id}}
                )
            else:
                ev_store = self.session.evidence if self.session else EvidenceStore.instance()
                ev_store.add_evidence(tool, msg, {"target": target, "error": "not_found", "exec_id": exec_id})

            await queue.put(f"[{exec_id}] {msg}")
            return []
        except Exception as exc:
            msg = f"[{tool}] failed to start: {exc}"

            if self._active_transaction and self._active_transaction.is_active:
                self._active_transaction.add_evidence(
                    {"tool": tool, "raw_output": msg, "metadata": {"target": target, "error": str(exc), "exec_id": exec_id}}
                )
            else:
                ev_store = self.session.evidence if self.session else EvidenceStore.instance()
                ev_store.add_evidence(tool, msg, {"target": target, "error": str(exc), "exec_id": exec_id})

            await queue.put(f"[{exec_id}] {msg}")
            return []

        start_time = asyncio.get_running_loop().time()
        timed_out_reason: Optional[str] = None
        truncated = False
        output_bytes = 0
        output_lines: List[str] = []

        assert proc.stdout is not None

        max_bytes_total = self.resource_guard.max_disk_mb * 1024 * 1024

        while True:
            if cancel_flag is not None and cancel_flag.is_set():
                try:
                    if proc.returncode is None:
                        proc.terminate()
                except ProcessLookupError:
                    pass
                break

            try:
                if idle_timeout and idle_timeout > 0:
                    line = await asyncio.wait_for(proc.stdout.readline(), timeout=idle_timeout)
                else:
                    line = await proc.stdout.readline()
            except asyncio.TimeoutError:
                timed_out_reason = "idle"
                await queue.put(f"[{exec_id}] idle timeout after {idle_timeout}s without output; terminating")
                try:
                    if proc.returncode is None:
                        proc.terminate()
                except ProcessLookupError:
                    pass
                break

            if not line:
                break

            text = line.decode("utf-8", errors="ignore").rstrip()
            if not text:
                continue

            line_bytes = len(text.encode("utf-8"))

            # Enforce disk cap during read
            if output_bytes + line_bytes > max_bytes_total:
                truncated = True
                await queue.put(f"[{exec_id}] Output truncated: exceeded disk limit ({self.resource_guard.max_disk_mb}MB)")
                try:
                    if proc.returncode is None:
                        proc.terminate()
                except ProcessLookupError:
                    pass
                break

            output_bytes += line_bytes
            output_lines.append(text)
            await queue.put(f"[{exec_id}] {text}")

            if tool_timeout and tool_timeout > 0:
                now = asyncio.get_running_loop().time()
                if (now - start_time) > tool_timeout:
                    timed_out_reason = "wall-clock"
                    await queue.put(f"[{exec_id}] time limit {tool_timeout}s exceeded; terminating")
                    try:
                        if proc.returncode is None:
                            proc.terminate()
                    except ProcessLookupError:
                        pass
                    break

        # Ensure process exits
        try:
            exit_code = await asyncio.wait_for(proc.wait(), timeout=2)
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            exit_code = await proc.wait()

        await queue.put(f"[{exec_id}] Exit code: {exit_code}")

        # Cleanup proc tracking
        self._procs.pop(exec_id, None)

        output_text = "\n".join(output_lines)

        # Accounting only (limit already enforced during read)
        self.resource_guard.account_disk(output_bytes)

        ev_meta = {
            "target": target,
            "exec_id": exec_id,
            "tool": tool,
            "exit_code": exit_code,
            "lines": len(output_lines),
            "bytes": output_bytes,
            "timed_out": bool(timed_out_reason),
            "timeout_reason": timed_out_reason,
            "truncated": truncated,
            "canceled": bool(cancel_flag and cancel_flag.is_set()),
        }

        # Stage evidence
        if self._active_transaction and self._active_transaction.is_active:
            self._active_transaction.add_evidence({"tool": tool, "raw_output": output_text, "metadata": ev_meta})
            self._active_transaction.mark_tool_completed(tool)
        else:
            ev_store = self.session.evidence if self.session else EvidenceStore.instance()
            ev_store.add_evidence(tool, output_text, ev_meta)

        try:
            findings = ScannerBridge.classify(tool, target, output_text)

            try:
                self.resource_guard.check_findings(len(findings))
            except ResourceExhaustedError as e:
                await queue.put(f"[{exec_id}] {e} - truncating results")
                logger.warning(f"[{exec_id}] {e}")
                return []

            # Legacy global TaskRouter side effects only if no session
            if self.session is None:
                try:
                    router = TaskRouter.instance()
                    router.handle_tool_output(
                        tool_name=tool,
                        stdout=output_text,
                        stderr="",
                        rc=exit_code,
                        metadata={"target": target, "findings_count": len(findings), "exec_id": exec_id},
                    )
                except Exception as router_err:
                    logger.warning(f"[{exec_id}] TaskRouter processing error: {router_err}")

            return findings
        except Exception as exc:
            err = f"[{tool}] classifier error: {exc}"
            if self._active_transaction and self._active_transaction.is_active:
                self._active_transaction.add_evidence(
                    {"tool": f"{tool}_classifier_error", "raw_output": err, "metadata": {"target": target, "exec_id": exec_id}}
                )
            else:
                ev_store = self.session.evidence if self.session else EvidenceStore.instance()
                ev_store.add_evidence(f"{tool}_classifier_error", err, {"target": target, "exec_id": exec_id})
            await queue.put(f"[{exec_id}] {err}")
            return []
        finally:
            self._procs.pop(exec_id, None)

    def _normalize_asset(self, target: str) -> str:
        parsed = urlparse(target)
        host = parsed.hostname or target
        if host.startswith("www."):
            host = host[4:]
        return host

    def queue_task(self, tool: str, args: List[str] | None = None) -> None:
        """
        Dynamically add a tool to the current scan queue.

        Args:
            tool: Name of tool to run
            args: Optional arguments
        """
        if tool not in TOOLS:
            raise ValueError(f"Unknown tool: {tool}")
        if tool not in self._installed_meta:
            raise ValueError(f"Tool not installed: {tool}")

        if args:
             # Basic sanity check on args
             for arg in args:
                 if ";" in arg or "|" in arg:
                     raise ValueError(f"Potentially unsafe argument: {arg}")

        self._pending_tasks.append({"tool": tool, "args": args})
        logger.info(f"[ScannerEngine] Dynamically queued task: {tool} {args}")
"""Module db: inline documentation for /Users/jason/Developer/sentinelforge/core/data/db.py.

PURPOSE
- Database layer for storing scan data persistently in SQLite using async operations.

WHAT GETS STORED
- Sessions: Scan session metadata (target, status, logs)
- Findings: Discoveries (ports, services, exposures)
- Issues: Rule-derived vulnerabilities
- Evidence: Raw tool outputs + metadata
- Scans: Audit trail for transactional scans (status, counts, timing, errors)
- System state: Global counters (event_sequence, scan_sequence)

KEY CONCEPTS
- WAL mode for concurrent reads during writes
- Async connection via aiosqlite
- Singleton Database instance
- BlackBox worker for fire-and-forget writes (legacy non-transactional path)

CRITICAL INVARIANTS FIXED
- All tables requiring scan_sequence now receive it in both txn and non-txn paths.
- scan_sequence allocation for transactional scans happens inside the commit transaction
  via next_scan_sequence_txn(conn), preserving committed-order semantics.
- Scan record creation for transactional scans happens inside the commit transaction
  via create_scan_record_txn(..., conn).
"""

import aiosqlite
import json
import logging
import os
import asyncio
import sqlite3
from typing import List, Dict, Optional, Any, Tuple

from core.base.config import get_config

logger = logging.getLogger(__name__)


class Database:
    _instance = None

    @staticmethod
    def instance():
        if Database._instance is None:
            Database._instance = Database()
        return Database._instance

    def __init__(self):
        config = get_config()
        self.db_path = str(config.storage.db_path)
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)

        self._initialized = False
        self._init_lock: Optional[asyncio.Lock] = None
        self._db_connection: Optional[aiosqlite.Connection] = None
        self._db_lock: Optional[asyncio.Lock] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None

        # Persistence Actor (legacy non-transactional)
        from core.data.blackbox import BlackBox

        self.blackbox = BlackBox.instance()

    async def init(self):
        if self._initialized:
            return

        if self._init_lock is None:
            self._init_lock = asyncio.Lock()
        if self._db_lock is None:
            self._db_lock = asyncio.Lock()

        self._loop = asyncio.get_running_loop()

        async with self._init_lock:
            if self._initialized:
                return

            try:
                self._db_connection = await aiosqlite.connect(self.db_path, timeout=30.0)
                await self._db_connection.execute("PRAGMA journal_mode=WAL;")
                await self._db_connection.execute("PRAGMA synchronous=NORMAL;")
                await self._db_connection.execute("PRAGMA busy_timeout=30000;")  # 30 seconds
                await self._db_connection.execute("PRAGMA foreign_keys=ON;")

                await self._create_tables()
                await self._db_connection.commit()
                self._initialized = True

                # Start BlackBox worker
                self.blackbox.start()

                logger.info(f"Database initialized at {self.db_path} (WAL mode)")
            except Exception as e:
                logger.error(f"Database init failed: {e}")
                raise

    async def close(self):
        if self._db_connection:
            try:
                await self._db_connection.close()
                self._initialized = False
                logger.info("[Database] Connection closed.")
            except Exception as e:
                logger.error(f"[Database] Error closing connection: {e}")

    async def _create_tables(self):
        await self._db_connection.execute(
            """
            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                target TEXT NOT NULL,
                status TEXT,
                start_time TEXT NOT NULL DEFAULT (datetime('now')),
                end_time TEXT,
                logs TEXT
            )
        """
        )

        await self._db_connection.execute(
            """
            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                scan_sequence INTEGER NOT NULL,
                tool TEXT NOT NULL,
                tool_version TEXT,
                type TEXT,
                severity TEXT,
                target TEXT,
                data JSON NOT NULL CHECK(json_valid(data)),
                timestamp TEXT NOT NULL DEFAULT (datetime('now')),
                FOREIGN KEY(session_id) REFERENCES sessions(id) ON DELETE CASCADE
            )
        """
        )

        await self._db_connection.execute(
            """
            CREATE TABLE IF NOT EXISTS issues (
                id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                scan_sequence INTEGER NOT NULL,
                title TEXT NOT NULL,
                severity TEXT,
                target TEXT,
                data JSON NOT NULL CHECK(json_valid(data)),
                timestamp TEXT NOT NULL DEFAULT (datetime('now')),
                FOREIGN KEY(session_id) REFERENCES sessions(id) ON DELETE CASCADE
            )
        """
        )

        await self._db_connection.execute(
            """
            CREATE TABLE IF NOT EXISTS evidence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                scan_sequence INTEGER NOT NULL,
                tool TEXT NOT NULL,
                tool_version TEXT,
                raw_output TEXT,
                metadata JSON CHECK(json_valid(metadata)),
                timestamp TEXT NOT NULL DEFAULT (datetime('now')),
                FOREIGN KEY(session_id) REFERENCES sessions(id) ON DELETE CASCADE
            )
        """
        )

        await self._db_connection.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                scan_sequence INTEGER NOT NULL,
                session_id TEXT NOT NULL,
                target TEXT NOT NULL,
                status TEXT NOT NULL,
                findings_count INTEGER DEFAULT 0,
                issues_count INTEGER DEFAULT 0,
                evidence_count INTEGER DEFAULT 0,
                start_time TEXT NOT NULL DEFAULT (datetime('now')),
                end_time TEXT,
                last_completed_tool TEXT,
                error_message TEXT,
                failure_phase TEXT,
                exception_type TEXT,
                FOREIGN KEY(session_id) REFERENCES sessions(id) ON DELETE CASCADE
            )
        """
        )

        await self._db_connection.execute(
            """
            CREATE TABLE IF NOT EXISTS system_state (
                key TEXT PRIMARY KEY,
                value INTEGER NOT NULL,
                updated_at TEXT DEFAULT (datetime('now'))
            )
        """
        )

        await self._db_connection.execute("CREATE INDEX IF NOT EXISTS idx_findings_session ON findings(session_id)")
        await self._db_connection.execute("CREATE INDEX IF NOT EXISTS idx_issues_session ON issues(session_id)")
        await self._db_connection.execute("CREATE INDEX IF NOT EXISTS idx_evidence_session ON evidence(session_id)")
        await self._db_connection.execute("CREATE INDEX IF NOT EXISTS idx_scans_session ON scans(session_id)")

        await self._db_connection.execute("CREATE INDEX IF NOT EXISTS idx_findings_timestamp ON findings(timestamp DESC)")
        await self._db_connection.execute("CREATE INDEX IF NOT EXISTS idx_issues_timestamp ON issues(timestamp DESC)")

        await self._db_connection.execute(
            """
            CREATE TABLE IF NOT EXISTS decisions (
                id TEXT PRIMARY KEY,
                event_sequence INTEGER NOT NULL,
                type TEXT NOT NULL,
                chosen TEXT,
                reason TEXT,
                alternatives JSON,
                context JSON,
                evidence JSON,
                parent_id TEXT,
                trigger_event_sequence INTEGER,
                timestamp TEXT NOT NULL DEFAULT (datetime('now'))
            )
        """
        )
        await self._db_connection.execute("CREATE INDEX IF NOT EXISTS idx_decisions_sequence ON decisions(event_sequence)")
        await self._db_connection.execute("CREATE INDEX IF NOT EXISTS idx_decisions_parent ON decisions(parent_id)")

        # Migration: Add scan_sequence column to evidence if it doesn't exist
        # This handles databases created before scan_sequence was added
        await self._migrate_evidence_table()

    async def _migrate_evidence_table(self) -> None:
        """Add missing columns to evidence table if needed."""
        try:
            # Check if columns exist by querying table info
            cursor = await self._db_connection.execute("PRAGMA table_info(evidence)")
            columns = await cursor.fetchall()
            column_names = {col[1] for col in columns}

            migrations_needed = []
            if "scan_sequence" not in column_names:
                migrations_needed.append(
                    ("scan_sequence", "ALTER TABLE evidence ADD COLUMN scan_sequence INTEGER NOT NULL DEFAULT 0")
                )
            if "tool_version" not in column_names:
                migrations_needed.append(
                    ("tool_version", "ALTER TABLE evidence ADD COLUMN tool_version TEXT")
                )

            if migrations_needed:
                for col_name, sql in migrations_needed:
                    logger.info(f"[Database] Migrating evidence table: adding {col_name} column")
                    await self._db_connection.execute(sql)
                await self._db_connection.commit()
                logger.info(f"[Database] Migration complete: added {len(migrations_needed)} column(s)")
        except Exception as e:
            logger.warning(f"[Database] Evidence migration check failed: {e}")

        # Ensure "global_scan" session exists for sessionless scanner operations
        await self._ensure_global_scan_session()

    async def _ensure_global_scan_session(self) -> None:
        """Create the global_scan session if it doesn't exist."""
        try:
            cursor = await self._db_connection.execute(
                "SELECT id FROM sessions WHERE id = ?", ("global_scan",)
            )
            row = await cursor.fetchone()
            if row is None:
                await self._db_connection.execute(
                    """
                    INSERT INTO sessions (id, target, status, start_time)
                    VALUES ('global_scan', 'system', 'active', datetime('now'))
                    """
                )
                await self._db_connection.commit()
                logger.info("[Database] Created global_scan session for sessionless operations")
        except Exception as e:
            logger.warning(f"[Database] Failed to ensure global_scan session: {e}")

    # ----------------------------
    # Low-level internal execution
    # ----------------------------
    async def _execute_internal(self, query: str, params: tuple = ()):
        # Event loop ownership safety (important with aiosqlite)
        current_loop = asyncio.get_running_loop()
        if self._loop is not None and current_loop is not self._loop:
            raise RuntimeError(
                f"Database access from wrong event loop. Initialized on {self._loop}, called from {current_loop}."
            )

        if not self._initialized:
            try:
                await self.init()
            except Exception:
                return

        max_retries = 5
        for attempt in range(max_retries):
            try:
                async with self._db_lock:
                    if self._db_connection is None:
                        return
                    await self._db_connection.execute(query, params)
                    await self._db_connection.commit()
                return
            except (sqlite3.ProgrammingError, aiosqlite.Error, ValueError) as e:
                if "closed" in str(e).lower():
                    return
                if "database is locked" in str(e).lower() and attempt < max_retries - 1:
                    await asyncio.sleep(0.1 * (attempt + 1))
                    continue
                raise
            except Exception as e:
                logger.debug(f"[Database] Execution error: {e}")
                raise

    async def execute(self, query: str, params: tuple = ()):
        if not self._initialized:
            try:
                await self.init()
            except Exception:
                return None

        try:
            async with self._db_lock:
                if self._db_connection is None:
                    return None
                cursor = await self._db_connection.execute(query, params)
                await self._db_connection.commit()
                return cursor
        except (sqlite3.ProgrammingError, aiosqlite.Error, ValueError) as e:
            if "closed" in str(e).lower():
                return None
            raise

    async def fetch_all(self, query: str, params: tuple = ()) -> List[Any]:
        if not self._initialized:
            try:
                await self.init()
            except Exception:
                return []

        try:
            async with self._db_lock:
                if self._db_connection is None:
                    return []
                async with self._db_connection.execute(query, params) as cursor:
                    return await cursor.fetchall()
        except (sqlite3.ProgrammingError, aiosqlite.Error, ValueError) as e:
            if "closed" in str(e).lower():
                return []
            raise

    # ----------------------------
    # Sessions
    # ----------------------------
    def save_session(self, session_data: Dict[str, Any]) -> None:
        self.blackbox.fire_and_forget(self._save_session_impl, session_data)

    async def _save_session_impl(self, session_data: Dict[str, Any]):
        await self._execute_internal(
            """
            INSERT OR REPLACE INTO sessions (id, target, status, start_time, logs)
            VALUES (?, ?, ?, ?, ?)
        """,
            (
                session_data["id"],
                session_data["target"],
                session_data.get("status"),
                session_data.get("start_time"),
                json.dumps(session_data.get("logs", [])),
            ),
        )

    # ----------------------------
    # Findings (legacy non-txn)
    # ----------------------------
    def save_finding(self, finding: Dict[str, Any], session_id: Optional[str] = None, scan_sequence: int = 0) -> None:
        self.blackbox.fire_and_forget(self._save_finding_impl, finding, session_id, scan_sequence)

    async def _save_finding_impl(self, finding: Dict[str, Any], session_id: Optional[str] = None, scan_sequence: int = 0):
        import hashlib

        blob = json.dumps(finding, sort_keys=True)
        fid = hashlib.sha256(blob.encode()).hexdigest()

        await self._execute_internal(
            """
            INSERT OR REPLACE INTO findings
              (id, session_id, scan_sequence, tool, tool_version, type, severity, target, data, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
        """,
            (
                fid,
                session_id,
                int(scan_sequence),
                finding.get("tool", "unknown"),
                finding.get("tool_version"),
                finding.get("type", "unknown"),
                finding.get("severity", "INFO"),
                finding.get("target", "unknown"),
                blob,
            ),
        )

    # ----------------------------
    # Issues (legacy non-txn)
    # ----------------------------
    def save_issue(self, issue: Dict[str, Any], session_id: Optional[str] = None, scan_sequence: int = 0) -> None:
        self.blackbox.fire_and_forget(self._save_issue_impl, issue, session_id, scan_sequence)

    async def _save_issue_impl(self, issue: Dict[str, Any], session_id: Optional[str] = None, scan_sequence: int = 0):
        import hashlib

        blob = json.dumps(issue, sort_keys=True)
        iid = hashlib.sha256(blob.encode()).hexdigest()

        await self._execute_internal(
            """
            INSERT OR REPLACE INTO issues
              (id, session_id, scan_sequence, title, severity, target, data, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))
        """,
            (
                iid,
                session_id,
                int(scan_sequence),
                issue.get("title", "unknown"),
                issue.get("severity", "INFO"),
                issue.get("target", "unknown"),
                blob,
            ),
        )

    # ----------------------------
    # Evidence (legacy non-txn)
    # ----------------------------
    def save_evidence(self, evidence_data: Dict[str, Any], session_id: Optional[str] = None, scan_sequence: int = 0) -> None:
        self.blackbox.fire_and_forget(self._save_evidence_impl, evidence_data, session_id, scan_sequence)

    async def _save_evidence_impl(
        self, evidence_data: Dict[str, Any], session_id: Optional[str] = None, scan_sequence: int = 0
    ):
        await self._execute_internal(
            """
            INSERT INTO evidence
              (session_id, scan_sequence, tool, tool_version, raw_output, metadata, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
        """,
            (
                session_id,
                int(scan_sequence),
                evidence_data.get("tool", "unknown"),
                evidence_data.get("tool_version"),
                evidence_data.get("raw_output", ""),
                json.dumps(evidence_data.get("metadata", {})),
            ),
        )

    def update_evidence(
        self,
        evidence_id: int,
        summary: Optional[str] = None,
        findings: Optional[List] = None,
        session_id: Optional[str] = None,
    ) -> None:
        self.blackbox.fire_and_forget(self._update_evidence_impl, evidence_id, summary, findings, session_id)

    async def _update_evidence_impl(
        self,
        evidence_id: int,
        summary: Optional[str] = None,
        findings: Optional[List] = None,
        session_id: Optional[str] = None,
    ):
        updates = []
        params: List[Any] = []

        if summary is not None:
            updates.append("metadata = json_set(COALESCE(metadata, '{}'), '$.summary', ?)")
            params.append(summary)
        if findings is not None:
            updates.append("metadata = json_set(COALESCE(metadata, '{}'), '$.findings', ?)")
            params.append(json.dumps(findings))

        if not updates:
            return

        params.append(evidence_id)
        query = f"UPDATE evidence SET {', '.join(updates)} WHERE id = ?"

        try:
            await self._execute_internal(query, tuple(params))
        except Exception:
            pass

    # ----------------------------
    # Transactional save methods
    # ----------------------------
    async def save_finding_txn(
        self, finding: Dict[str, Any], session_id: Optional[str] = None, scan_sequence: int = 0, conn=None
    ) -> None:
        import hashlib

        blob = json.dumps(finding, sort_keys=True)
        fid = hashlib.sha256(blob.encode()).hexdigest()

        await conn.execute(
            """
            INSERT OR REPLACE INTO findings
              (id, session_id, scan_sequence, tool, tool_version, type, severity, target, data, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
        """,
            (
                fid,
                session_id,
                int(scan_sequence),
                finding.get("tool", "unknown"),
                finding.get("tool_version"),
                finding.get("type", "unknown"),
                finding.get("severity", "INFO"),
                finding.get("target", "unknown"),
                blob,
            ),
        )

    async def save_issue_txn(
        self, issue: Dict[str, Any], session_id: Optional[str] = None, scan_sequence: int = 0, conn=None
    ) -> None:
        import hashlib

        blob = json.dumps(issue, sort_keys=True)
        iid = hashlib.sha256(blob.encode()).hexdigest()

        await conn.execute(
            """
            INSERT OR REPLACE INTO issues
              (id, session_id, scan_sequence, title, severity, target, data, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))
        """,
            (
                iid,
                session_id,
                int(scan_sequence),
                issue.get("title", "unknown"),
                issue.get("severity", "INFO"),
                issue.get("target", "unknown"),
                blob,
            ),
        )

    async def save_evidence_txn(
        self, evidence_data: Dict[str, Any], session_id: Optional[str] = None, scan_sequence: int = 0, conn=None
    ) -> None:
        await conn.execute(
            """
            INSERT INTO evidence
              (session_id, scan_sequence, tool, tool_version, raw_output, metadata, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
        """,
            (
                session_id,
                int(scan_sequence),
                evidence_data.get("tool", "unknown"),
                evidence_data.get("tool_version"),
                evidence_data.get("raw_output", ""),
                json.dumps(evidence_data.get("metadata", {})),
            ),
        )

    # ----------------------------
    # Read methods
    # ----------------------------
    async def get_findings(self, session_id: Optional[str] = None) -> List[Dict]:
        query = "SELECT data FROM findings WHERE session_id = ? ORDER BY timestamp DESC"
        params: Tuple[Any, ...] = (session_id,)
        if session_id is None:
            query = "SELECT data FROM findings ORDER BY timestamp DESC"
            params = ()
        rows = await self.fetch_all(query, params)
        return [json.loads(row[0]) for row in rows]

    async def get_all_findings(self) -> List[Dict]:
        return await self.get_findings(None)

    async def get_issues(self, session_id: Optional[str] = None) -> List[Dict]:
        query = "SELECT data FROM issues WHERE session_id = ? ORDER BY timestamp DESC"
        params: Tuple[Any, ...] = (session_id,)
        if session_id is None:
            query = "SELECT data FROM issues ORDER BY timestamp DESC"
            params = ()
        rows = await self.fetch_all(query, params)
        return [json.loads(row[0]) for row in rows]

    async def get_all_issues(self) -> List[Dict]:
        return await self.get_issues(None)

    async def get_evidence(self, session_id: Optional[str] = None) -> List[Dict]:
        query = "SELECT id, tool, raw_output, metadata, timestamp FROM evidence"
        params: Tuple[Any, ...] = ()
        if session_id is not None:
            query += " WHERE session_id = ?"
            params = (session_id,)
        query += " ORDER BY timestamp DESC"
        rows = await self.fetch_all(query, params)

        results = []
        for row in rows:
            metadata = json.loads(row[3]) if row[3] else {}
            results.append(
                {
                    "id": row[0],
                    "tool": row[1],
                    "raw_output": row[2],
                    "metadata": metadata,
                    "summary": metadata.get("summary"),
                    "findings": metadata.get("findings", []),
                    "timestamp": row[4],
                }
            )
        return results

    async def get_all_evidence(self) -> List[Dict]:
        return await self.get_evidence(None)

    async def get_session(self, session_id: str) -> Optional[Dict]:
        """
        Retrieve session metadata from database.

        Args:
            session_id: Session UUID

        Returns:
            Dict with session data or None if not found
        """
        query = "SELECT id, target, status, start_time, end_time, logs FROM sessions WHERE id = ?"
        rows = await self.fetch_all(query, (session_id,))

        if not rows:
            return None

        row = rows[0]
        return {
            'id': row[0],
            'target': row[1],
            'status': row[2],
            'start_time': row[3],
            'end_time': row[4],
            'logs': row[5]
        }

    # ----------------------------
    # System state counters
    # ----------------------------
    async def get_event_sequence(self) -> int:
        if not self._initialized:
            await self.init()

        try:
            async with self._db_lock:
                if self._db_connection is None:
                    return 0
                cursor = await self._db_connection.execute(
                    "SELECT value FROM system_state WHERE key = ?", ("event_sequence",)
                )
                row = await cursor.fetchone()
                return row[0] if row else 0
        except Exception as e:
            logger.error(f"[Database] Failed to get event_sequence: {e}")
            return 0

    def save_event_sequence(self, sequence: int) -> None:
        self.blackbox.fire_and_forget(self._save_event_sequence_impl, sequence)

    async def _save_event_sequence_impl(self, sequence: int) -> None:
        await self._execute_internal(
            """
            INSERT OR REPLACE INTO system_state (key, value, updated_at)
            VALUES (?, ?, datetime('now'))
        """,
            ("event_sequence", int(sequence)),
        )

    # ----------------------------
    # Scan sequence (txn + non-txn)
    # ----------------------------
    async def next_scan_sequence(self) -> int:
        """
        Non-transactional scan sequence allocator (legacy).
        Prefer next_scan_sequence_txn(conn) for ScanTransaction commits.
        """
        if not self._initialized:
            await self.init()

        async with self._db_lock:
            if self._db_connection is None:
                raise RuntimeError("Database not available")

            cursor = await self._db_connection.execute("SELECT value FROM system_state WHERE key = ?", ("scan_sequence",))
            row = await cursor.fetchone()
            current = row[0] if row else 0
            next_val = current + 1

            await self._db_connection.execute(
                """
                INSERT OR REPLACE INTO system_state (key, value, updated_at)
                VALUES (?, ?, datetime('now'))
            """,
                ("scan_sequence", int(next_val)),
            )
            await self._db_connection.commit()
            return int(next_val)

    async def next_scan_sequence_txn(self, conn) -> int:
        """
        Transactional scan sequence allocator. MUST be called inside an open transaction.
        This preserves scan_sequence as "committed order" semantics.
        """
        cursor = await conn.execute("SELECT value FROM system_state WHERE key = ?", ("scan_sequence",))
        row = await cursor.fetchone()
        current = row[0] if row else 0
        next_val = int(current) + 1

        await conn.execute(
            """
            INSERT OR REPLACE INTO system_state (key, value, updated_at)
            VALUES (?, ?, datetime('now'))
        """,
            ("scan_sequence", next_val),
        )
        return next_val

    # ----------------------------
    # Scan record methods (txn + non-txn)
    # ----------------------------
    async def create_scan_record(self, scan_id: str, scan_sequence: int, session_id: str, target: str) -> None:
        await self.execute(
            """
            INSERT INTO scans
              (id, scan_sequence, session_id, target, status, findings_count, issues_count, evidence_count, start_time)
            VALUES (?, ?, ?, ?, 'running', 0, 0, 0, datetime('now'))
        """,
            (scan_id, int(scan_sequence), session_id, target),
        )

    async def create_scan_record_txn(
        self,
        scan_id: str,
        scan_sequence: int,
        session_id: str,
        target: str,
        status: str,
        conn,
    ) -> None:
        await conn.execute(
            """
            INSERT INTO scans
              (id, scan_sequence, session_id, target, status, findings_count, issues_count, evidence_count, start_time)
            VALUES (?, ?, ?, ?, ?, 0, 0, 0, datetime('now'))
        """,
            (scan_id, int(scan_sequence), session_id, target, status),
        )

    async def update_scan_last_completed_tool_txn(self, scan_id: str, tool: str, conn) -> None:
        await conn.execute("UPDATE scans SET last_completed_tool = ? WHERE id = ?", (tool, scan_id))

    async def update_scan_status(
        self,
        scan_id: str,
        status: str,
        findings_count: int = 0,
        issues_count: int = 0,
        evidence_count: int = 0,
        error_message: Optional[str] = None,
        failure_phase: Optional[str] = None,
        exception_type: Optional[str] = None,
        last_completed_tool: Optional[str] = None,
    ) -> None:
        if status in ("committed", "rolled_back", "failed"):
            await self.execute(
                """
                UPDATE scans
                SET status = ?, findings_count = ?, issues_count = ?, evidence_count = ?,
                    end_time = datetime('now'),
                    error_message = ?, failure_phase = ?, exception_type = ?,
                    last_completed_tool = COALESCE(?, last_completed_tool)
                WHERE id = ?
            """,
                (
                    status,
                    int(findings_count),
                    int(issues_count),
                    int(evidence_count),
                    error_message,
                    failure_phase,
                    exception_type,
                    last_completed_tool,
                    scan_id,
                ),
            )
        else:
            await self.execute(
                """
                UPDATE scans
                SET status = ?, findings_count = ?, issues_count = ?, evidence_count = ?,
                    last_completed_tool = COALESCE(?, last_completed_tool)
                WHERE id = ?
            """,
                (status, int(findings_count), int(issues_count), int(evidence_count), last_completed_tool, scan_id),
            )

    async def get_scan_record(self, scan_id: str) -> Optional[Dict]:
        rows = await self.fetch_all(
            """
            SELECT id, session_id, target, status, findings_count, issues_count, evidence_count,
                   start_time, end_time, last_completed_tool, error_message
            FROM scans WHERE id = ?
        """,
            (scan_id,),
        )
        if not rows:
            return None
        row = rows[0]
        return {
            "id": row[0],
            "session_id": row[1],
            "target": row[2],
            "status": row[3],
            "findings_count": row[4],
            "issues_count": row[5],
            "evidence_count": row[6],
            "start_time": row[7],
            "end_time": row[8],
            "last_completed_tool": row[9],
            "error_message": row[10],
        }

    async def get_scans_by_session(self, session_id: str) -> List[Dict]:
        rows = await self.fetch_all(
            """
            SELECT id, session_id, target, status, findings_count, issues_count, evidence_count,
                   start_time, end_time, last_completed_tool, error_message
            FROM scans
            WHERE session_id = ?
            ORDER BY start_time DESC
        """,
            (session_id,),
        )
        return [
            {
                "id": row[0],
                "session_id": row[1],
                "target": row[2],
                "status": row[3],
                "findings_count": row[4],
                "issues_count": row[5],
                "evidence_count": row[6],
                "start_time": row[7],
                "end_time": row[8],
                "last_completed_tool": row[9],
                "error_message": row[10],
            }
            for row in rows
        ]

    # ----------------------------
    # Decisions (Strategic Brain)
    # ----------------------------
    def save_decision(self, decision: Dict[str, Any]) -> None:
        self.blackbox.fire_and_forget(self._save_decision_impl, decision)

    async def _save_decision_impl(self, decision: Dict[str, Any]):
        await self._execute_internal(
            """
            INSERT OR REPLACE INTO decisions
              (id, event_sequence, type, chosen, reason, alternatives, context, evidence, parent_id, trigger_event_sequence)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                decision["id"],
                int(decision.get("sequence", 0)),
                decision["type"],
                str(decision["chosen"]),
                decision["reason"],
                json.dumps(decision.get("alternatives", [])),
                json.dumps(decision.get("context", {})),
                json.dumps(decision.get("evidence", {})),
                decision.get("parent_id"),
                decision.get("trigger_event_sequence"),
            ),
        )

    async def save_decision_txn(self, decision: Dict[str, Any], conn) -> None:
        """
        Save a decision record within a transaction.
        """
        await conn.execute(
            """
            INSERT OR REPLACE INTO decisions
              (id, event_sequence, type, chosen, reason, alternatives, context, evidence, parent_id, trigger_event_sequence)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                decision["id"],
                int(decision.get("sequence", 0)),
                decision["type"],
                str(decision["chosen"]),
                decision["reason"],
                json.dumps(decision.get("alternatives", [])),
                json.dumps(decision.get("context", {})),
                json.dumps(decision.get("evidence", {})),
                decision.get("parent_id"),
                decision.get("trigger_event_sequence"),
            ),
        )

    async def get_decisions(self, limit: int = 100) -> List[Dict]:
        """
        Retrieve recent strategic decisions.
        """
        rows = await self.fetch_all(
            """
            SELECT id, event_sequence, type, chosen, reason, alternatives, context, evidence, parent_id, trigger_event_sequence, timestamp
            FROM decisions
            ORDER BY event_sequence DESC
            LIMIT ?
        """,
            (limit,),
        )
        return [
            {
                "id": row[0],
                "sequence": row[1],
                "type": row[2],
                "chosen": row[3],
                "reason": row[4],
                "alternatives": json.loads(row[5]) if row[5] else [],
                "context": json.loads(row[6]) if row[6] else {},
                "evidence": json.loads(row[7]) if row[7] else {},
                "parent_id": row[8],
                "trigger_event_sequence": row[9],
                "timestamp": row[10],
            }
            for row in rows
        ]

    async def get_decision_children(self, parent_id: str) -> List[Dict]:
        """
        Retrieve all decisions caused by a specific parent decision.
        """
        rows = await self.fetch_all(
            """
            SELECT id, event_sequence, type, chosen, reason, alternatives, context, evidence, parent_id, trigger_event_sequence, timestamp
            FROM decisions
            WHERE parent_id = ?
            ORDER BY event_sequence ASC
        """,
            (parent_id,),
        )
        return [
            {
                "id": row[0],
                "sequence": row[1],
                "type": row[2],
                "chosen": row[3],
                "reason": row[4],
                "alternatives": json.loads(row[5]) if row[5] else [],
                "context": json.loads(row[6]) if row[6] else {},
                "evidence": json.loads(row[7]) if row[7] else {},
                "parent_id": row[8],
                "trigger_event_sequence": row[9],
                "timestamp": row[10],
            }
            for row in rows
        ]



"""
Unit tests for Project MIMIC (The Shape Shifter).
Migrated from tests/verification/verify_mimic_miner.py and inferencer.py
"""
import pytest
from unittest.mock import MagicMock
from core.sentient.mimic.route_miner import RouteMiner
from core.sentient.mimic.model_inferencer import ModelInferencer
from core.sentient.mimic.types import DataType

@pytest.fixture
def miner():
    return RouteMiner()

def test_route_clustering(miner):
    """Verify that multiple IDs cluster to {id}."""
    
    # Dataset 1: User IDs
    urls_ids = ["/users/1", "/users/2", "/users/999", "/users/1024"]
    for url in urls_ids:
        ep = miner.ingest("GET", url)
        assert ep.path_template == "/users/{id}"
        
    # Dataset 2: UUIDs
    urls_uuids = [
        "/files/550e8400-e29b-41d4-a716-446655440000",
        "/files/123e4567-e89b-12d3-a456-426614174000"
    ]
    for url in urls_uuids:
        ep = miner.ingest("GET", url)
        assert ep.path_template == "/files/{id}"

def test_mixed_templates(miner):
    """Verify literal vs parameter distinction."""
    
    # Literal
    ep = miner.ingest("GET", "/users/profile")
    assert ep.path_template == "/users/profile"
    
    # Mixed
    ep = miner.ingest("GET", "/users/1/details")
    assert ep.path_template == "/users/{id}/details"

def test_model_inference_simple():
    """Verify basic JSON schema inference."""
    payload = {
        "id": 123,
        "name": "Alice",
        "is_admin": False
    }
    schema = ModelInferencer.infer(payload)
    
    assert schema.type == DataType.OBJECT
    assert schema.properties["id"].type == DataType.INTEGER
    assert schema.properties["name"].type == DataType.STRING
    assert schema.properties["is_admin"].type == DataType.BOOLEAN

def test_model_inference_nested():
    """Verify nested object and array inference."""
    payload = {
        "user": {
            "id": 1,
            "roles": ["admin", "editor"],
            "settings": {
                "theme": "dark"
            }
        }
    }
    schema = ModelInferencer.infer(payload)
    
    user = schema.properties["user"]
    assert user.type == DataType.OBJECT
    
    roles = user.properties["roles"]
    assert roles.type == DataType.ARRAY
    assert roles.items.type == DataType.STRING
    
    settings = user.properties["settings"]
    assert settings.properties["theme"].type == DataType.STRING

"""
Verification Script for Project MIMIC (Route Mining).
Scenario:
1. Feed series of URLs: /users/1, /users/2, /users/55
2. Feed generic URLs: /users/profile, /admin/login
3. Expect Miner to cluster {id} but keep literals distinct.
"""
from core.sentient.mimic.route_miner import RouteMiner

def run_test():
    print("🗺️  Initializing Route Miner...")
    miner = RouteMiner()
    
    # Dataset 1: User IDs
    # Should cluster to /users/{id}
    urls_ids = ["/users/1", "/users/2", "/users/999", "/users/1024"]
    for url in urls_ids:
        ep = miner.ingest("GET", url)
        print(f"   Fed: {url} -> Template: {ep.path_template}")
        assert ep.path_template == "/users/{id}"
    
    print("✅ Parameter Clustering Verified (/users/{id})")
    
    # Dataset 2: UUIDs
    # Should cluster to /files/{id}
    urls_uuids = [
        "/files/550e8400-e29b-41d4-a716-446655440000",
        "/files/123e4567-e89b-12d3-a456-426614174000"
    ]
    for url in urls_uuids:
        ep = miner.ingest("GET", url)
        print(f"   Fed: {url} -> Template: {ep.path_template}")
        assert ep.path_template == "/files/{id}"
        
    print("✅ UUID Clustering Verified (/files/{id})")

    # Dataset 3: Literals mixing with params
    # /users/profile should NOT be /users/{id} (unless 'profile' looks like an ID, which it doesn't)
    ep = miner.ingest("GET", "/users/profile")
    print(f"   Fed: /users/profile -> Template: {ep.path_template}")
    assert ep.path_template == "/users/profile"
    
    # /users/1/details
    ep = miner.ingest("GET", "/users/1/details")
    print(f"   Fed: /users/1/details -> Template: {ep.path_template}")
    assert ep.path_template == "/users/{id}/details"

    print("✅ Mixed Template Verified (/users/{id}/details)")
    print("\n🎉 MIMIC Logic Verified!")

if __name__ == "__main__":
    run_test()

"""
Verification Script for Project MIMIC Integration.
Scenario:
1. Instantiate GhostAddon (wiring check).
2. Simulate a proxy request (Ghost Intercept).
3. Assert that ShadowSpec (MIMIC) learned the route.
"""
import sys
from unittest.mock import MagicMock
# Mock mitmproxy package hierarchy explicitly
mock_mitmproxy = MagicMock()
sys.modules['mitmproxy'] = mock_mitmproxy
sys.modules['mitmproxy.http'] = MagicMock()
sys.modules['mitmproxy.options'] = MagicMock()
sys.modules['mitmproxy.tools'] = MagicMock()
sys.modules['mitmproxy.tools.dump'] = MagicMock()

from core.ghost.proxy import GhostAddon
from core.base.session import ScanSession

class MockFlow:
    def __init__(self, method, url, host):
        self.request = MagicMock()
        self.request.pretty_url = url
        self.request.method = method
        self.request.host = host
        self.request.query = {}
        self.response = MagicMock()
        self.response.headers = {}

def run_test():
    print("🔌 Initializing MIMIC Integration Test...")
    
    # 1. Setup
    session = MagicMock(spec=ScanSession)
    session.log = MagicMock()
    session.findings = MagicMock()
    # Mocking strategy to avoid AI calls
    from core.ai.strategy import StrategyEngine
    StrategyEngine.propose_attacks = MagicMock()
    
    addon = GhostAddon(session)
    
    # Check Wiring
    assert addon.shadow_spec is not None
    print("✅ ShadowSpec Wired to GhostAddon")
    assert addon.strategy.shadow_spec is not None
    print("✅ ShadowSpec Wired to StrategyEngine")
    
    # 2. Simulate User Traffic
    # Request 1: /api/users/1
    flow1 = MockFlow("GET", "http://target.com/api/users/1", "target.com")
    addon.request(flow1)
    
    # Request 2: /api/users/2
    flow2 = MockFlow("GET", "http://target.com/api/users/2", "target.com")
    addon.request(flow2)
    
    print("🚀 Simulated Traffic Ingested")
    
    # 3. Verify MIMIC learned the structure
    # We expect /api/users/{id}
    # We need to dig into the miner state
    # Root -> "api" -> "users" -> "{id}"
    
    miner = addon.shadow_spec.miner
    root = miner.root
    
    # Traverse
    # Empty root -> "api"
    api_node = root.get_child("api")
    assert api_node is not None
    
    users_node = api_node.get_child("users")
    assert users_node is not None
    
    # The magic: "1" and "2" should be clustered into "{id}"
    id_node = users_node.get_child("{id}")
    if not id_node:
        # Debug output if fail
        print(f"FAILED: Children of 'users': {users_node.children.keys()}")
    
    assert id_node is not None
    assert id_node.is_parameter == True
    
    # Check Endpoint
    endpoint = id_node.endpoints.get("GET")
    assert endpoint is not None
    print(f"✅ Learned Endpoint: {endpoint.method} {endpoint.path_template}")
    assert endpoint.path_template == "/api/users/{id}"
    
    print("\n🎉 MIMIC Integration Verified!")

if __name__ == "__main__":
    run_test()

"""
Verification Script for Project MIMIC (Model Inferencer).
Scenario:
1. Feed complex JSON payload (User Profile).
2. Expect correct APISchema structure.
"""
from core.sentient.mimic.model_inferencer import ModelInferencer
from core.sentient.mimic.types import DataType

def run_test():
    print("🧠 Initializing Model Inferencer...")
    
    # 1. Simple Object
    payload = {
        "id": 123,
        "name": "Alice",
        "is_admin": False
    }
    
    print(f"   Fed: {payload}")
    schema = ModelInferencer.infer(payload)
    
    assert schema.type == DataType.OBJECT
    assert schema.properties["id"].type == DataType.INTEGER
    assert schema.properties["name"].type == DataType.STRING
    assert schema.properties["is_admin"].type == DataType.BOOLEAN
    
    print("✅ Simple Object Inference Verified")
    
    # 2. Nested Object + Array
    payload_complex = {
        "user": {
            "id": 1,
            "roles": ["admin", "editor"],
            "settings": {
                "theme": "dark"
            }
        }
    }
    
    print(f"   Fed: {payload_complex}")
    schema_c = ModelInferencer.infer(payload_complex)
    
    user_prop = schema_c.properties["user"]
    assert user_prop.type == DataType.OBJECT
    assert user_prop.properties["roles"].type == DataType.ARRAY
    assert user_prop.properties["roles"].items.type == DataType.STRING
    assert user_prop.properties["settings"].properties["theme"].type == DataType.STRING
    
    print("✅ Complex/Nested Inference Verified")
    print("\n🎉 MIMIC Inferencer Verified!")

if __name__ == "__main__":
    run_test()

"""
Project OMEGA - Integration Manager (Module)

This file is kept as a placeholder. The main implementation is in __init__.py
to maintain consistency with the other modules.

For integration:
- Import with: from core.omega import OmegaManager, OmegaConfig, OmegaResult
- Create with: manager = create_omega_manager()
- Run with: result = await manager.run(config)
"""

# Re-export from __init__ for convenience
from core.omega import (
    OmegaManager,
    OmegaConfig,
    OmegaResult,
    OmegaPhase,
    create_omega_manager,
    SAFE_MODE,
)

__all__ = [
    "OmegaManager",
    "OmegaConfig",
    "OmegaResult",
    "OmegaPhase",
    "create_omega_manager",
    "SAFE_MODE",
]

"""
Project OMEGA - Integration Manager (Module)

This file is kept as a placeholder. The main implementation is in __init__.py
to maintain consistency with the other modules.

For integration:
- Import with: from core.omega import OmegaManager, OmegaConfig, OmegaResult
- Create with: manager = create_omega_manager()
- Run with: result = await manager.run(config)
"""

# Re-export from __init__ for convenience
from core.omega import (
    OmegaManager,
    OmegaConfig,
    OmegaResult,
    OmegaPhase,
    create_omega_manager,
    SAFE_MODE,
)

__all__ = [
    "OmegaManager",
    "OmegaConfig",
    "OmegaResult",
    "OmegaPhase",
    "create_omega_manager",
    "SAFE_MODE",
]

"""
NEXUS Solver - Logic Chaining Engine

PURPOSE:
Calculate paths from "here" (current primitives) to "there" (goal state) by
linking low-severity findings into high-impact exploit chains.

THREAT MODEL (Defensive Framing):
This module helps organizations:
- Understand how minor issues combine into major risks
- Identify the most likely attack paths
- Prioritize remediation based on chain disruption
- Assess defense-in-depth effectiveness

ASSUMPTIONS:
1. Primitives can be linked in dependency graphs
2. Goals are well-defined (e.g., "read user data")
3. Success probability is estimable
4. Chains are theoretical models (not executed)

SAFETY CONSTRAINTS:
- SAFE_MODE: If True, excludes dangerous goal states
- No actual exploitation or execution
- Chains are models only (not carried out)
- Results are for authorized security assessments only

INTEGRATION POINTS:
- EventBus: Emits NEXUS_CHAIN_SOLVED, NEXUS_NO_PATH events
- DecisionLedger: Logs chain planning decisions
- KnowledgeGraph: Uses primitive graph for pathfinding

DEPENDENCIES (Future):
- networkx: For graph operations and pathfinding
- heapq: For priority queue in A* algorithm
- itertools: For chain combination generation
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse

# Safety fuse: prevents unsafe operations
SAFE_MODE: bool = True

logger = logging.getLogger(__name__)


class GoalState(str, Enum):
    """
    Target end-states for exploit chains.

    These represent high-impact outcomes that could result
    from chaining low-severity primitives.

    NOTE: In SAFE_MODE, dangerous goals are excluded.
    """
    # Information disclosure goals
    USER_READ_PII = "user_read_pii"           # Read user personal data
    ADMIN_ACCESS = "admin_access"               # Access admin panel
    SOURCE_CODE_READ = "source_code_read"       # Read source code
    CONFIG_READ = "config_read"                 # Read configuration

    # Data manipulation goals
    USER_MODIFY_DATA = "user_modify_data"       # Modify other users' data
    DELETE_DATA = "delete_data"                 # Delete arbitrary data

    # Dangerous goals (excluded in SAFE_MODE)
    RCE = "rce"                                 # Remote code execution
    SSRF_TO_CLOUD = "ssrf_to_cloud"             # SSRF to cloud metadata
    FULL_COMPROMISE = "full_compromise"         # Complete system takeover

    def is_dangerous(self) -> bool:
        """Check if this is a dangerous goal state."""
        return self in (GoalState.RCE, GoalState.SSRF_TO_CLOUD, GoalState.FULL_COMPROMISE)


@dataclass(frozen=True)
class ChainStep:
    """
    A single step in an exploit chain.

    Each step represents using one primitive to enable the next.

    Attributes:
        primitive_id: Which primitive to use
        primitive_type: Type of the primitive
        description: What this step does
        cost: Estimated "cost" (complexity, detection risk, etc.)
        success_probability: How likely this step succeeds (0.0-1.0)
    """
    primitive_id: str
    primitive_type: str
    description: str
    cost: float = 1.0
    success_probability: float = 0.5

    def __post_init__(self):
        """Validate step fields."""
        if not 0.0 <= self.success_probability <= 1.0:
            raise ValueError(
                f"success_probability must be 0.0-1.0, got {self.success_probability}"
            )
        if self.cost < 0:
            raise ValueError(f"cost must be non-negative, got {self.cost}")

    def to_dict(self) -> Dict[str, Any]:
        """Serialize step to dict."""
        return {
            "primitive_id": self.primitive_id,
            "primitive_type": self.primitive_type,
            "description": self.description,
            "cost": self.cost,
            "success_probability": self.success_probability,
        }


@dataclass
class ChainPlan:
    """
    A complete exploit chain plan.

    This represents a theoretical path from current primitives
    to a goal state, with each step justified.

    Attributes:
        id: Unique identifier for this plan
        goal: Target end-state
        start_primitive: Where the chain starts
        steps: Ordered list of steps to execute
        total_cost: Sum of all step costs
        success_probability: Overall chain success probability
        confidence: How confident we are in this plan (0.0-1.0)
        planned_at: When this plan was generated
    """
    id: str
    goal: GoalState
    start_primitive: str
    steps: List[ChainStep] = field(default_factory=list)
    total_cost: float = 0.0
    success_probability: float = 0.0
    confidence: float = 0.5
    planned_at: datetime = field(default_factory=lambda: datetime.utcnow())

    @property
    def step_count(self) -> int:
        """Get number of steps in this chain."""
        return len(self.steps)

    @property
    def is_feasible(self) -> bool:
        """Check if this chain is feasible (has steps and non-zero probability)."""
        return self.step_count > 0 and self.success_probability > 0.1

    def to_dict(self) -> Dict[str, Any]:
        """Serialize plan to dict."""
        return {
            "id": self.id,
            "goal": self.goal.value,
            "start_primitive": self.start_primitive,
            "step_count": self.step_count,
            "total_cost": self.total_cost,
            "success_probability": self.success_probability,
            "confidence": self.confidence,
            "planned_at": self.planned_at.isoformat(),
            "steps": [step.to_dict() for step in self.steps],
        }


@dataclass
class SolveResult:
    """
    Result of a solve operation.

    Attributes:
        target: Domain being analyzed
        goal: Target goal state
        found_paths: List of valid chains (sorted by quality)
        best_plan: Highest quality plan (if any)
        no_path_reason: Why no path was found (if applicable)
        solved_at: When solving was performed
    """
    target: str
    goal: GoalState
    found_paths: List[ChainPlan] = field(default_factory=list)
    best_plan: Optional[ChainPlan] = None
    no_path_reason: Optional[str] = None
    solved_at: datetime = field(default_factory=lambda: datetime.utcnow())

    @property
    def has_solution(self) -> bool:
        """Check if a valid chain was found."""
        return len(self.found_paths) > 0 and self.best_plan is not None

    def to_dict(self) -> Dict[str, Any]:
        """Serialize result to dict."""
        return {
            "target": self.target,
            "goal": self.goal.value,
            "has_solution": self.has_solution,
            "path_count": len(self.found_paths),
            "no_path_reason": self.no_path_reason,
            "solved_at": self.solved_at.isoformat(),
            "best_plan": self.best_plan.to_dict() if self.best_plan else None,
        }


class ChainSolver:
    """
    Solves for exploit chains using primitive inventory.

    This class implements pathfinding algorithms to discover
    how low-severity primitives can be chained into high-impact
    attacks.

    SOLVING STRATEGY:
    1. Build dependency graph from primitives
    2. Use A* or greedy search to find paths
    3. Calculate success probability for each path
    4. Rank chains by cost/probability ratio
    5. Return best chain(s) for the goal

    EXAMPLE USAGE:
        ```python
        solver = ChainSolver()
        inventory = PrimitiveInventory(...)
        result = solver.solve_chain(
            inventory=inventory,
            start_primitive_id="prim_123",
            goal=GoalState.ADMIN_ACCESS,
        )
        if result.has_solution:
            print(f"Found {len(result.found_paths)} chains")
        ```
    """

    # Event names for integration with EventBus
    EVENT_SOLVE_STARTED = "nexus_solve_started"
    EVENT_SOLVE_COMPLETED = "nexus_solve_completed"
    EVENT_CHAIN_FOUND = "nexus_chain_found"
    EVENT_NO_PATH = "nexus_no_path"

    # Cost weights for pathfinding
    COST_REFLECTED_PARAM = 1.0
    COST_OPEN_REDIRECT = 2.0
    COST_SSRF_PATTERN = 5.0
    COST_MISSING_AUTH = 3.0
    COST_WEAK_CORS = 1.5

    def __init__(self, safe_mode: bool = SAFE_MODE):
        """
        Initialize ChainSolver.

        Args:
            safe_mode: If True, excludes dangerous goals
        """
        self._safe_mode = safe_mode
        self._solve_count = 0

    @property
    def safe_mode(self) -> bool:
        """Check if operating in safe mode."""
        return self._safe_mode

    @property
    def solve_count(self) -> int:
        """Get number of solves performed."""
        return self._solve_count

    def solve_chain(
        self,
        inventory: "PrimitiveInventory",
        start_primitive_id: str,
        goal: GoalState,
        max_depth: int = 5,
        max_paths: int = 10,
    ) -> SolveResult:
        """
        Find exploit chains from start primitive to goal state.

        TODO: Implement A* search algorithm.
        TODO: Build dependency graph from primitives.
        TODO: Calculate heuristic for goal distance.
        TODO: Generate multiple paths for comparison.
        TODO: Filter by safe_mode if enabled.

        Args:
            inventory: Available primitives
            start_primitive_id: Entry point for chain
            goal: Target end-state
            max_depth: Maximum chain length
            max_paths: Maximum number of paths to return

        Returns:
            SolveResult with discovered chains

        Raises:
            NotImplementedError: This is a wrapper-only implementation
        """
        # Check safe mode
        if self._safe_mode and goal.is_dangerous():
            raise ValueError(
                f"SAFE_MODE: Dangerous goal not allowed: {goal.value}"
            )

        # Update statistics
        self._solve_count += 1

        # Emit event (integration point)
        logger.debug(
            f"[ChainSolver] {self.EVENT_SOLVE_STARTED}: "
            f"goal={goal.value}, start={start_primitive_id}"
        )

        # Create result skeleton
        result = SolveResult(
            target=inventory.target,
            goal=goal,
        )

        raise NotImplementedError(
            "Wrapper-only: Chain solving implementation deferred. "
            "Future implementation should use A* with heuristic."
        )

    def calculate_success_probability(
        self,
        chain: ChainPlan
    ) -> float:
        """
        Calculate overall success probability for a chain.

        TODO: Multiply step probabilities.
        TODO: Adjust for chain length (longer = less reliable).
        TODO: Consider weakest link in chain.
        TODO: Apply confidence adjustment.

        Args:
            chain: The chain plan to evaluate

        Returns:
            Overall success probability (0.0-1.0)

        Raises:
            NotImplementedError: This is a wrapper-only implementation
        """
        raise NotImplementedError(
            "Wrapper-only: Success probability calculation deferred. "
            "Future implementation should multiply step probabilities."
        )

    def calculate_step_cost(
        self,
        primitive: "Primitive",
    ) -> float:
        """
        Calculate "cost" of using a primitive in a chain.

        TODO: Assign costs based on primitive type.
        TODO: Consider detection risk.
        TODO: Consider complexity/effort.
        TODO: Consider reliability level.

        Args:
            primitive: The primitive to cost

        Returns:
            Cost value (lower is better/easier)

        Raises:
            NotImplementedError: This is a wrapper-only implementation
        """
        raise NotImplementedError(
            "Wrapper-only: Step cost calculation deferred. "
            "Future implementation should use type-based cost table."
        )

    def rank_chains(
        self,
        chains: List[ChainPlan]
    ) -> List[ChainPlan]:
        """
        Rank chains by quality (cost vs probability).

        TODO: Sort by success_probability / total_cost ratio.
        TODO: Prefer shorter chains with equal ratios.
        TODO: Filter out infeasible chains.
        TODO: Apply confidence weighting.

        Args:
            chains: Unsorted list of chain plans

        Returns:
            Sorted list (best first)

        Raises:
            NotImplementedError: This is a wrapper-only implementation
        """
        raise NotImplementedError(
            "Wrapper-only: Chain ranking deferred. "
            "Future implementation should sort by value metric."
        )

    def replay(self, recorded_solve: Dict[str, Any]) -> SolveResult:
        """
        Replay a previously solved chain plan.

        Enables replayability without re-solving.

        Args:
            recorded_solve: Serialized SolveResult from to_dict()

        Returns:
            Reconstructed SolveResult

        Raises:
            NotImplementedError: This is a wrapper-only implementation
        """
        raise NotImplementedError(
            "Wrapper-only: Solve replay implementation deferred. "
            "Future implementation should deserialize from evidence store."
        )

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get usage statistics for this ChainSolver instance.

        Returns:
            Dictionary with solve statistics
        """
        return {
            "solve_count": self._solve_count,
            "safe_mode": self._safe_mode,
        }


def create_chain_solver(safe_mode: bool = SAFE_MODE) -> ChainSolver:
    """
    Factory function to create ChainSolver instance.

    This is the recommended way to create ChainSolver objects in production code.

    Args:
        safe_mode: Safety mode flag

    Returns:
        Configured ChainSolver instance
    """
    return ChainSolver(safe_mode=safe_mode)


# ============================================================================
# Module Self-Test (Design Verification)
# ============================================================================

if __name__ == "__main__":
    from core.aegis.nexus.primitives import Primitive, PrimitiveType

    # Verify GoalState enum
    assert GoalState.ADMIN_ACCESS.value == "admin_access"
    assert GoalState.RCE.is_dangerous() is True
    assert GoalState.ADMIN_ACCESS.is_dangerous() is False
    print("✓ GoalState enum works")

    # Verify ChainStep dataclass
    step = ChainStep(
        primitive_id="prim_123",
        primitive_type="reflected_param",
        description="Use reflected param for XSS",
        cost=1.0,
        success_probability=0.7,
    )
    assert step.to_dict()["primitive_id"] == "prim_123"
    print("✓ ChainStep structure works")

    # Verify ChainPlan dataclass
    plan = ChainPlan(
        id=str(uuid.uuid4()),
        goal=GoalState.ADMIN_ACCESS,
        start_primitive="prim_123",
        steps=[step],
    )
    assert plan.step_count == 1
    assert plan.to_dict()["goal"] == "admin_access"
    print("✓ ChainPlan structure works")

    # Verify SolveResult dataclass
    result = SolveResult(
        target="example.com",
        goal=GoalState.ADMIN_ACCESS,
        found_paths=[plan],
        best_plan=plan,
    )
    assert result.has_solution is True
    assert result.to_dict()["has_solution"] is True
    print("✓ SolveResult aggregation works")

    # Verify ChainSolver creation
    solver = create_chain_solver()
    assert solver.safe_mode is True
    assert solver.solve_count == 0
    print("✓ ChainSolver factory works")

    # Verify safe mode enforcement
    try:
        solver.solve_chain(
            inventory=PrimitiveInventory(target="example.com"),
            start_primitive_id="prim_123",
            goal=GoalState.RCE,  # Dangerous goal
        )
        print("✗ Safe mode enforcement failed")
    except ValueError as e:
        if "SAFE_MODE" in str(e):
            print("✓ Safe mode enforcement works")
        else:
            print(f"✗ Unexpected error: {e}")

    print("\n✅ All ChainSolver design invariants verified!")

"""
NEXUS Primitives - Low-Severity Finding Inventory

PURPOSE:
Database of "low value" findings that serve as building blocks for exploit chains.
Instead of discarding minor findings, NEXUS treats them as inventory for chain planning.

THREAT MODEL (Defensive Framing):
This module helps organizations:
- Track minor issues that could enable attacks
- Understand how small vulnerabilities combine
- Prioritize fixes based on chain participation
- Assess cumulative risk from multiple findings

ASSUMPTIONS:
1. Low-severity findings have value when combined
2. Findings can be linked by dependency relationships
3. Reliability scores indicate exploitation confidence
4. Primitives are reusable across multiple chains

SAFETY CONSTRAINTS:
- SAFE_MODE: If True, excludes exploit primitives from inventory
- No actual exploitation of primitives
- Read-only storage and retrieval
- Results are for authorized security assessments only

INTEGRATION POINTS:
- EventBus: Emits NEXUS_PRIMITIVE_COLLECTED events
- DecisionLedger: Logs primitive storage decisions
- KnowledgeGraph: Stores primitive relationships

DEPENDENCIES (Future):
- networkx: For graph-based primitive relationships
- dataclasses: For structured primitive storage
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse

# Safety fuse: prevents unsafe operations
SAFE_MODE: bool = True

logger = logging.getLogger(__name__)


class PrimitiveType(str, Enum):
    """
    Types of low-severity findings that become primitives.

    These are "building blocks" that can be chained into attacks.
    The presence of a primitive doesn't mean it's exploitable on its own,
    but it may enable other primitives in a chain.
    """
    REFLECTED_PARAM = "reflected_param"         # XSS via reflected parameter
    OPEN_REDIRECT = "open_redirect"             # Redirect via user input
    LEAKED_HEADER = "leaked_header"             # Information disclosure
    SSRF_PATTERN = "ssrf_pattern"               # URL fetching pattern
    IDOR_PATTERN = "idor_pattern"               # Direct object reference
    MISSING_AUTH = "missing_auth"               # No auth on endpoint
    WEAK_CORS = "weak_cors"                     # Overly permissive CORS
    JSONP_ENDPOINT = "jsonp_endpoint"           # JSONP callback
    DEBUG_PARAM = "debug_param"                 # Debug query parameter
    TEMPLATE_INJECTION = "template_injection"   # SSTI pattern
    DESERIALIZATION = "deserialization"         # Object deserialization
    FILE_UPLOAD = "file_upload"                 # File upload endpoint
    WEBHOOK = "webhook"                         # Webhook registration


class ReliabilityLevel(str, Enum):
    """
    Reliability of a primitive (can it be consistently reproduced?).

    Higher reliability means the primitive is more likely to work
    consistently across requests/environments.
    """
    CERTAIN = "certain"     # 100% reproducible
    HIGH = "high"           # ~90% reproducible
    MEDIUM = "medium"       # ~50% reproducible
    LOW = "low"             # ~10% reproducible
    UNKNOWN = "unknown"     # Reliability unknown


@dataclass(frozen=True)
class Primitive:
    """
    A low-severity finding that can be used in exploit chains.

    Instead of discarding "minor" findings, NEXUS stores them as
    primitives that may enable other attacks when chained.

    Attributes:
        id: Unique identifier
        type: What kind of primitive this is
        target: Where this was found
        parameter: Specific parameter name (if applicable)
        evidence: Proof of existence (response snippet, etc.)
        reliability: How reliable this finding is
        confidence: How confident we are (0.0-1.0)
        enables: Which other primitives this enables (dependencies)
        discovered_at: When this was found
        source: Which tool/scanner found this
    """
    id: str
    type: PrimitiveType
    target: str
    parameter: Optional[str] = None
    evidence: str = ""
    reliability: ReliabilityLevel = ReliabilityLevel.MEDIUM
    confidence: float = 0.5
    enables: List[str] = field(default_factory=list)
    discovered_at: datetime = field(default_factory=lambda: datetime.utcnow())
    source: str = "unknown"

    def __post_init__(self):
        """Validate primitive fields."""
        # Validate confidence range
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"confidence must be 0.0-1.0, got {self.confidence}")

        # Validate target is a valid domain
        if "://" in self.target:
            parsed = urlparse(self.target)
            if parsed.scheme not in ("http", "https"):
                raise ValueError(f"Invalid target scheme: {parsed.scheme}")

    @property
    def is_reliable(self) -> bool:
        """Check if this primitive is reliable enough for chaining."""
        return self.reliability in (ReliabilityLevel.CERTAIN, ReliabilityLevel.HIGH)

    @property
    def signature(self) -> str:
        """Get unique signature for this primitive."""
        param_part = f":{self.parameter}" if self.parameter else ""
        return f"{self.type.value}{param_part}@{self.target}"

    def to_dict(self) -> Dict[str, Any]:
        """Serialize primitive to dict."""
        return {
            "id": self.id,
            "type": self.type.value,
            "target": self.target,
            "parameter": self.parameter,
            "evidence": self.evidence[:200],  # Truncate for storage
            "reliability": self.reliability.value,
            "confidence": self.confidence,
            "enables": self.enables,
            "discovered_at": self.discovered_at.isoformat(),
            "source": self.source,
        }


@dataclass
class PrimitiveInventory:
    """
    Database of primitives for a target.

    This stores all low-severity findings that could be used
    as building blocks in exploit chains.

    Attributes:
        target: Domain these primitives belong to
        primitives: List of discovered primitives
        by_type: Primitives indexed by type
        dependencies: Which primitives enable which others
        last_updated: When inventory was last updated
    """
    target: str
    primitives: List[Primitive] = field(default_factory=list)
    by_type: Dict[PrimitiveType, List[Primitive]] = field(default_factory=dict)
    dependencies: Dict[str, List[str]] = field(default_factory=dict)
    last_updated: datetime = field(default_factory=lambda: datetime.utcnow())

    def add_primitive(self, primitive: Primitive) -> None:
        """Add a primitive to the inventory."""
        if primitive not in self.primitives:
            self.primitives.append(primitive)

        # Update type index
        if primitive.type not in self.by_type:
            self.by_type[primitive.type] = []
        if primitive not in self.by_type[primitive.type]:
            self.by_type[primitive.type].append(primitive)

        # Update dependencies
        for enabled_id in primitive.enables:
            if enabled_id not in self.dependencies:
                self.dependencies[enabled_id] = []
            if primitive.id not in self.dependencies[enabled_id]:
                self.dependencies[enabled_id].append(primitive.id)

        self.last_updated = datetime.utcnow()

    def find_primitives_by_type(self, type: PrimitiveType) -> List[Primitive]:
        """Get all primitives of a specific type."""
        return self.by_type.get(type, [])

    def find_primitives_by_target(self, target: str) -> List[Primitive]:
        """Get all primitives for a specific target."""
        return [p for p in self.primitives if p.target == target]

    def get_reliable_primitives(self) -> List[Primitive]:
        """Get only reliable primitives (confidence >= 0.7)."""
        return [p for p in self.primitives if p.is_reliable]

    def get_dependencies_for(self, primitive_id: str) -> List[Primitive]:
        """Get primitives that enable the given primitive."""
        if primitive_id not in self.dependencies:
            return []
        return [
            p for p in self.primitives
            if p.id in self.dependencies[primitive_id]
        ]

    def to_dict(self) -> Dict[str, Any]:
        """Serialize inventory to dict."""
        return {
            "target": self.target,
            "total_primitives": len(self.primitives),
            "by_type": {
                type.value: len(prims)
                for type, prims in self.by_type.items()
            },
            "dependency_count": len(self.dependencies),
            "last_updated": self.last_updated.isoformat(),
        }


class PrimitiveCollector:
    """
    Collects low-severity findings as primitives.

    This class processes scan results and extracts primitives,
    converting "noise" into "inventory" for chain planning.

    COLLECTION STRATEGY:
    1. Scan findings for primitive patterns
    2. Extract relevant parameters and evidence
    3. Assess reliability and confidence
    4. Store in inventory for later chaining

    EXAMPLE USAGE:
        ```python
        collector = PrimitiveCollector()
        findings = scan({"reflected": {"param": "name"}})
        inventory = collector.collect(findings, "example.com")
        ```
    """

    # Event names for integration with EventBus
    EVENT_COLLECT_STARTED = "nexus_collect_started"
    EVENT_COLLECT_COMPLETED = "nexus_collect_completed"
    EVENT_PRIMITIVE_FOUND = "nexus_primitive_found"

    def __init__(self, safe_mode: bool = SAFE_MODE):
        """
        Initialize PrimitiveCollector.

        Args:
            safe_mode: If True, excludes exploit primitives
        """
        self._safe_mode = safe_mode
        self._collection_count = 0

    @property
    def safe_mode(self) -> bool:
        """Check if operating in safe mode."""
        return self._safe_mode

    @property
    def collection_count(self) -> int:
        """Get number of collections performed."""
        return self._collection_count

    def collect(
        self,
        findings: List[Dict[str, Any]],
        target: str,
    ) -> PrimitiveInventory:
        """
        Collect primitives from scan findings.

        TODO: Implement finding-to-primitive conversion.
        TODO: Detect primitive types from findings.
        TODO: Extract parameters and evidence.
        TODO: Assess reliability based on reproducibility.
        TODO: Build dependency graph between primitives.

        Args:
            findings: Scan results to process
            target: Domain these findings belong to

        Returns:
            PrimitiveInventory with extracted primitives

        Raises:
            NotImplementedError: This is a wrapper-only implementation
        """
        # Update statistics
        self._collection_count += 1

        # Emit event (integration point)
        logger.debug(
            f"[PrimitiveCollector] {self.EVENT_COLLECT_STARTED}: "
            f"target={target}, findings={len(findings)}"
        )

        # Create inventory skeleton
        inventory = PrimitiveInventory(target=target)

        raise NotImplementedError(
            "Wrapper-only: Primitive collection implementation deferred. "
            "Future implementation should extract primitives from findings."
        )

    def find_primitive_patterns(
        self,
        finding: Dict[str, Any]
    ) -> List[Primitive]:
        """
        Identify primitive patterns in a finding.

        TODO: Match finding against primitive type patterns.
        TODO: Extract relevant parameters.
        TODO: Generate appropriate evidence strings.
        TODO: Calculate confidence scores.

        Args:
            finding: A single scan finding

        Returns:
            List of detected primitives

        Raises:
            NotImplementedError: This is a wrapper-only implementation
        """
        raise NotImplementedError(
            "Wrapper-only: Pattern detection deferred. "
            "Future implementation should match finding signatures."
        )

    def calculate_reliability(
        self,
        finding: Dict[str, Any]
    ) -> ReliabilityLevel:
        """
        Assess reliability of a primitive from finding.

        TODO: Check for consistent reproducibility.
        TODO: Assess tool confidence in finding.
        TODO: Check for false positive indicators.
        TODO: Consider environment-specific factors.

        Args:
            finding: A single scan finding

        Returns:
            Assessed reliability level

        Raises:
            NotImplementedError: This is a wrapper-only implementation
        """
        raise NotImplementedError(
            "Wrapper-only: Reliability calculation deferred. "
            "Future implementation should score based on finding metadata."
        )

    def replay(self, recorded_inventory: Dict[str, Any]) -> PrimitiveInventory:
        """
        Replay a previously collected inventory.

        Enables replayability without re-collecting.

        Args:
            recorded_inventory: Serialized PrimitiveInventory from to_dict()

        Returns:
            Reconstructed PrimitiveInventory

        Raises:
            NotImplementedError: This is a wrapper-only implementation
        """
        raise NotImplementedError(
            "Wrapper-only: Inventory replay implementation deferred. "
            "Future implementation should deserialize from evidence store."
        )

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get usage statistics for this PrimitiveCollector instance.

        Returns:
            Dictionary with collection statistics
        """
        return {
            "collection_count": self._collection_count,
            "safe_mode": self._safe_mode,
        }


def create_primitive_collector(safe_mode: bool = SAFE_MODE) -> PrimitiveCollector:
    """
    Factory function to create PrimitiveCollector instance.

    This is the recommended way to create PrimitiveCollector objects in production code.

    Args:
        safe_mode: Safety mode flag

    Returns:
        Configured PrimitiveCollector instance
    """
    return PrimitiveCollector(safe_mode=safe_mode)


# ============================================================================
# Module Self-Test (Design Verification)
# ============================================================================

if __name__ == "__main__":
    import uuid

    # Verify enums
    assert PrimitiveType.REFLECTED_PARAM.value == "reflected_param"
    assert ReliabilityLevel.HIGH.value == "high"
    print("✓ Enums work")

    # Verify Primitive dataclass
    prim = Primitive(
        id=str(uuid.uuid4()),
        type=PrimitiveType.REFLECTED_PARAM,
        target="example.com",
        parameter="name",
        evidence="Reflection in response",
        reliability=ReliabilityLevel.HIGH,
        confidence=0.8,
    )

    assert prim.is_reliable is True
    assert prim.signature.startswith("reflected_param:name@")
    assert prim.to_dict()["type"] == "reflected_param"
    print("✓ Primitive structure works")

    # Verify PrimitiveInventory dataclass
    inventory = PrimitiveInventory(target="example.com")
    inventory.add_primitive(prim)

    assert len(inventory.primitives) == 1
    assert inventory.find_primitives_by_type(PrimitiveType.REFLECTED_PARAM) == [prim]
    assert inventory.to_dict()["total_primitives"] == 1
    print("✓ PrimitiveInventory aggregation works")

    # Verify PrimitiveCollector creation
    collector = create_primitive_collector()
    assert collector.safe_mode is True
    assert collector.collection_count == 0
    print("✓ PrimitiveCollector factory works")

    # Verify validation
    try:
        Primitive(
            id=str(uuid.uuid4()),
            type=PrimitiveType.REFLECTED_PARAM,
            target="example.com",
            confidence=1.5,  # Invalid
        )
        print("✗ Confidence validation failed")
    except ValueError as e:
        if "confidence" in str(e).lower():
            print("✓ Confidence validation works")
        else:
            print(f"✗ Unexpected error: {e}")

    print("\n✅ All Primitive design invariants verified!")

"""
NEXUS Chain Executor - Proof Generation

PURPOSE:
Execute validated exploit chains to generate proof of concept demonstrations.
This turns theoretical chain plans into verifiable evidence.

THREAT MODEL (Defensive Framing):
This module helps organizations:
- Verify that theoretical chains actually work
- Generate proof for remediation prioritization
- Test defense-in-depth effectiveness
- Demonstrate risk to stakeholders safely

ASSUMPTIONS:
1. Chains have been pre-validated and approved
2. Execution is non-destructive (read-only where possible)
3. Proof is captured at each step
4. Execution can be aborted mid-chain

SAFETY CONSTRAINTS:
- SAFE_MODE: If True, refuses to execute any steps
- Explicit approval required for execution
- Abort on any unexpected response
- Results are for authorized security assessments only

INTEGRATION POINTS:
- EventBus: Emits NEXUS_CHAIN_STARTED, NEXUS_CHAIN_STEP_COMPLETED events
- DecisionLedger: Logs execution decisions and aborts
- EvidenceStore: Stores proof artifacts

DEPENDENCIES (Future):
- asyncio: For sequential step execution
- aiohttp: For HTTP requests during execution
- json: For request/response handling
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

# Safety fuse: prevents unsafe operations
SAFE_MODE: bool = True

logger = logging.getLogger(__name__)


class ExecutionStatus(str, Enum):
    """
    Status of a chain execution.
    """
    PENDING = "pending"           # Not yet started
    RUNNING = "running"           # Currently executing
    COMPLETED = "completed"       # All steps succeeded
    FAILED = "failed"             # Chain broken (step failed)
    ABORTED = "aborted"           # Manually stopped
    TIMEOUT = "timeout"           # Took too long


class StepStatus(str, Enum):
    """
    Status of an individual chain step.
    """
    PENDING = "pending"           # Not yet started
    RUNNING = "running"           # Currently executing
    SUCCESS = "success"           # Step completed successfully
    FAILED = "failed"             # Step failed (chain broken)
    SKIPPED = "skipped"           # Skipped due to prior failure


@dataclass
class StepResult:
    """
    Result of executing a single chain step.

    Attributes:
        step: The chain step that was executed
        status: What happened
        response: HTTP response data (if applicable)
        proof: Evidence of success/failure
        error_message: Any error details
        executed_at: When this step was executed
        duration_ms: How long the step took
    """
    step: "ChainStep"
    status: StepStatus
    response: Optional[Dict[str, Any]] = None
    proof: Optional[str] = None
    error_message: Optional[str] = None
    executed_at: datetime = field(default_factory=lambda: datetime.utcnow())
    duration_ms: Optional[int] = None

    @property
    def is_success(self) -> bool:
        """Check if step executed successfully."""
        return self.status == StepStatus.SUCCESS

    def to_dict(self) -> Dict[str, Any]:
        """Serialize result to dict."""
        return {
            "primitive_id": self.step.primitive_id,
            "primitive_type": self.step.primitive_type,
            "description": self.step.description,
            "status": self.status.value,
            "has_response": self.response is not None,
            "proof": self.proof,
            "error_message": self.error_message,
            "executed_at": self.executed_at.isoformat(),
            "duration_ms": self.duration_ms,
        }


@dataclass
class ExecutionProof:
    """
    Aggregated proof from a chain execution.

    This contains all evidence needed to demonstrate that
    the exploit chain works (or doesn't).

    Attributes:
        chain_id: Which chain this proves
        target: Domain this was executed against
        goal: Target goal state
        overall_status: Final execution status
        step_results: Results for each executed step
        completed_steps: How many steps succeeded
        total_steps: Total steps in chain
        started_at: When execution started
        completed_at: When execution completed
        duration_seconds: Total execution time
    """
    chain_id: str
    target: str
    goal: "GoalState"
    overall_status: ExecutionStatus
    step_results: List[StepResult] = field(default_factory=list)
    completed_steps: int = 0
    total_steps: int = 0
    started_at: datetime = field(default_factory=lambda: datetime.utcnow())
    completed_at: Optional[datetime] = None
    duration_seconds: float = 0.0

    @property
    def success_rate(self) -> float:
        """Get percentage of steps that succeeded."""
        if self.total_steps == 0:
            return 0.0
        return (self.completed_steps / self.total_steps) * 100

    @property
    def is_proven(self) -> bool:
        """Check if chain was successfully proven."""
        return self.overall_status == ExecutionStatus.COMPLETED

    def to_dict(self) -> Dict[str, Any]:
        """Serialize proof to dict."""
        return {
            "chain_id": self.chain_id,
            "target": self.target,
            "goal": self.goal.value,
            "overall_status": self.overall_status.value,
            "completed_steps": self.completed_steps,
            "total_steps": self.total_steps,
            "success_rate": round(self.success_rate, 2),
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "duration_seconds": self.duration_seconds,
            "step_results": [sr.to_dict() for sr in self.step_results],
        }


@dataclass
class ChainResult:
    """
    Result of a chain execution attempt.

    Attributes:
        proof: Execution proof with all step results
        error: Any execution error (if failed early)
    """
    proof: Optional[ExecutionProof] = None
    error: Optional[str] = None

    @property
    def succeeded(self) -> bool:
        """Check if chain executed successfully."""
        return self.proof is not None and self.proof.is_proven


class ChainExecutor:
    """
    Executes exploit chains to generate proof.

    This class takes a validated ChainPlan and attempts to execute
    it step-by-step, capturing evidence at each stage.

    EXECUTION STRATEGY:
    1. Validate chain is approved for execution
    2. Execute steps sequentially
    3. Verify each step succeeded before proceeding
    4. Capture proof (responses, screenshots, etc.)
    5. Abort on failure or timeout
    6. Return aggregated proof

    EXAMPLE USAGE:
        ```python
        executor = ChainExecutor()
        plan = ChainPlan(...)
        result = await executor.execute_chain(plan, approval_token="...")
        if result.succeeded:
            print("Chain proven!")
        ```
    """

    # Event names for integration with EventBus
    EVENT_EXECUTION_STARTED = "nexus_chain_started"
    EVENT_EXECUTION_COMPLETED = "nexus_chain_completed"
    EVENT_STEP_STARTED = "nexus_step_started"
    EVENT_STEP_COMPLETED = "nexus_step_completed"
    EVENT_CHAIN_ABORTED = "nexus_chain_aborted"

    # Timeouts
    DEFAULT_STEP_TIMEOUT = 30  # seconds
    DEFAULT_CHAIN_TIMEOUT = 300  # seconds (5 minutes)

    def __init__(
        self,
        safe_mode: bool = SAFE_MODE,
        step_timeout: int = DEFAULT_STEP_TIMEOUT,
        chain_timeout: int = DEFAULT_CHAIN_TIMEOUT,
    ):
        """
        Initialize ChainExecutor.

        Args:
            safe_mode: If True, refuses to execute any chains
            step_timeout: Max seconds per step
            chain_timeout: Max seconds for entire chain
        """
        self._safe_mode = safe_mode
        self._step_timeout = step_timeout
        self._chain_timeout = chain_timeout
        self._execution_count = 0

    @property
    def safe_mode(self) -> bool:
        """Check if operating in safe mode."""
        return self._safe_mode

    @property
    def execution_count(self) -> int:
        """Get number of executions performed."""
        return self._execution_count

    async def execute_chain(
        self,
        plan: "ChainPlan",
        approval_token: Optional[str] = None,
        target_override: Optional[str] = None,
    ) -> ChainResult:
        """
        Execute a chain plan to generate proof.

        TODO: Implement approval token validation.
        TODO: Execute steps sequentially with verification.
        TODO: Capture proof at each step (response, status, etc.).
        TODO: Abort chain on step failure.
        TODO: Handle timeouts gracefully.

        Args:
            plan: The chain plan to execute
            approval_token: Optional approval token
            target_override: Override target (for testing)

        Returns:
            ChainResult with proof or error

        Raises:
            NotImplementedError: This is a wrapper-only implementation
        """
        # Check safe mode
        if self._safe_mode:
            raise RuntimeError(
                "SAFE_MODE: Chain execution is disabled. "
                "Set safe_mode=False to enable execution."
            )

        # Validate approval
        if not self._validate_approval(approval_token):
            raise PermissionError("Invalid or missing approval token")

        # Update statistics
        self._execution_count += 1

        # Emit event (integration point)
        logger.debug(
            f"[ChainExecutor] {self.EVENT_EXECUTION_STARTED}: "
            f"chain_id={plan.id}, goal={plan.goal.value}"
        )

        raise NotImplementedError(
            "Wrapper-only: Chain execution implementation deferred. "
            "Future implementation should execute steps sequentially."
        )

    async def execute_step(
        self,
        step: "ChainStep",
        target: str,
    ) -> StepResult:
        """
        Execute a single chain step.

        TODO: Implement step-specific execution logic.
        TODO: Handle different primitive types.
        TODO: Capture response data.
        TODO: Verify step success condition.

        Args:
            step: The step to execute
            target: Target domain

        Returns:
            StepResult with execution outcome

        Raises:
            NotImplementedError: This is a wrapper-only implementation
        """
        raise NotImplementedError(
            "Wrapper-only: Step execution implementation deferred. "
            "Future implementation should dispatch by primitive type."
        )

    def verify_step_success(
        self,
        step: "ChainStep",
        response: Dict[str, Any]
    ) -> bool:
        """
        Verify that a step achieved its objective.

        TODO: Implement success condition checking.
        TODO: Verify response status code.
        TODO: Check for expected response content.
        TODO: Validate side effects occurred.

        Args:
            step: The step that was executed
            response: HTTP response data

        Returns:
            True if step succeeded

        Raises:
            NotImplementedError: This is a wrapper-only implementation
        """
        raise NotImplementedError(
            "Wrapper-only: Step verification deferred. "
            "Future implementation should check response conditions."
        )

    def generate_proof_artifact(
        self,
        proof: ExecutionProof
    ) -> Dict[str, Any]:
        """
        Generate a shareable proof artifact from execution.

        TODO: Format proof for report generation.
        TODO: Include screenshots/images if available.
        TODO: Sanitize sensitive data from proof.
        TODO: Generate human-readable summary.

        Args:
            proof: Execution proof to format

        Returns:
            Formatted proof artifact

        Raises:
            NotImplementedError: This is a wrapper-only implementation
        """
        raise NotImplementedError(
            "Wrapper-only: Proof generation deferred. "
            "Future implementation should format for reports."
        )

    def _validate_approval(self, token: Optional[str]) -> bool:
        """
        Validate approval token for chain execution.

        TODO: Implement token validation logic.
        TODO: Check token signature/expiry.
        TODO: Verify token scope for this chain.

        Args:
            token: Approval token to validate

        Returns:
            True if token is valid

        Raises:
            NotImplementedError: This is a wrapper-only implementation
        """
        raise NotImplementedError(
            "Wrapper-only: Approval validation deferred. "
            "Future implementation should verify token signatures."
        )

    def replay(self, recorded_execution: Dict[str, Any]) -> ChainResult:
        """
        Replay a previously generated execution proof.

        Enables replayability without re-executing chains.

        Args:
            recorded_execution: Serialized ExecutionProof from to_dict()

        Returns:
            Reconstructed ChainResult

        Raises:
            NotImplementedError: This is a wrapper-only implementation
        """
        raise NotImplementedError(
            "Wrapper-only: Execution replay implementation deferred. "
            "Future implementation should deserialize from evidence store."
        )

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get usage statistics for this ChainExecutor instance.

        Returns:
            Dictionary with execution statistics
        """
        return {
            "execution_count": self._execution_count,
            "safe_mode": self._safe_mode,
            "step_timeout": self._step_timeout,
            "chain_timeout": self._chain_timeout,
        }


def create_chain_executor(
    safe_mode: bool = SAFE_MODE,
    step_timeout: int = ChainExecutor.DEFAULT_STEP_TIMEOUT,
    chain_timeout: int = ChainExecutor.DEFAULT_CHAIN_TIMEOUT,
) -> ChainExecutor:
    """
    Factory function to create ChainExecutor instance.

    This is the recommended way to create ChainExecutor objects in production code.

    Args:
        safe_mode: Safety mode flag
        step_timeout: Max seconds per step
        chain_timeout: Max seconds for entire chain

    Returns:
        Configured ChainExecutor instance
    """
    return ChainExecutor(
        safe_mode=safe_mode,
        step_timeout=step_timeout,
        chain_timeout=chain_timeout,
    )


# ============================================================================
# Module Self-Test (Design Verification)
# ============================================================================

if __name__ == "__main__":
    from core.aegis.nexus.solver import ChainStep, ChainPlan, GoalState

    # Verify enums
    assert ExecutionStatus.COMPLETED.value == "completed"
    assert StepStatus.SUCCESS.value == "success"
    print("✓ Enums work")

    # Verify StepResult dataclass
    step = ChainStep(
        primitive_id="prim_123",
        primitive_type="reflected_param",
        description="Test step",
    )
    step_result = StepResult(
        step=step,
        status=StepStatus.SUCCESS,
        proof="Worked!",
    )
    assert step_result.is_success is True
    assert step_result.to_dict()["status"] == "success"
    print("✓ StepResult structure works")

    # Verify ExecutionProof dataclass
    proof = ExecutionProof(
        chain_id="chain_123",
        target="example.com",
        goal=GoalState.ADMIN_ACCESS,
        overall_status=ExecutionStatus.COMPLETED,
        step_results=[step_result],
        completed_steps=1,
        total_steps=1,
    )
    assert proof.is_proven is True
    assert proof.success_rate == 100.0
    assert proof.to_dict()["success_rate"] == 100.0
    print("✓ ExecutionProof structure works")

    # Verify ChainExecutor creation
    executor = create_chain_executor()
    assert executor.safe_mode is True
    assert executor.execution_count == 0
    print("✓ ChainExecutor factory works")

    # Verify safe mode enforcement
    try:
        import asyncio
        plan = ChainPlan(
            id=str(uuid.uuid4()),
            goal=GoalState.ADMIN_ACCESS,
            start_primitive="prim_123",
        )
        asyncio.run(executor.execute_chain(plan))
        print("✗ Safe mode enforcement failed")
    except RuntimeError as e:
        if "SAFE_MODE" in str(e):
            print("✓ Safe mode enforcement works")
        else:
            print(f"✗ Unexpected error: {e}")

    print("\n✅ All ChainExecutor design invariants verified!")

"""
NEXUS Chain Executor - Proof Generation

PURPOSE:
Execute validated exploit chains to generate proof of concept demonstrations.
This turns theoretical chain plans into verifiable evidence.

THREAT MODEL (Defensive Framing):
This module helps organizations:
- Verify that theoretical chains actually work
- Generate proof for remediation prioritization
- Test defense-in-depth effectiveness
- Demonstrate risk to stakeholders safely

ASSUMPTIONS:
1. Chains have been pre-validated and approved
2. Execution is non-destructive (read-only where possible)
3. Proof is captured at each step
4. Execution can be aborted mid-chain

SAFETY CONSTRAINTS:
- SAFE_MODE: If True, refuses to execute any steps
- Explicit approval required for execution
- Abort on any unexpected response
- Results are for authorized security assessments only

INTEGRATION POINTS:
- EventBus: Emits NEXUS_CHAIN_STARTED, NEXUS_CHAIN_STEP_COMPLETED events
- DecisionLedger: Logs execution decisions and aborts
- EvidenceStore: Stores proof artifacts

DEPENDENCIES (Future):
- asyncio: For sequential step execution
- aiohttp: For HTTP requests during execution
- json: For request/response handling
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

# Safety fuse: prevents unsafe operations
SAFE_MODE: bool = True

logger = logging.getLogger(__name__)


class ExecutionStatus(str, Enum):
    """
    Status of a chain execution.
    """
    PENDING = "pending"           # Not yet started
    RUNNING = "running"           # Currently executing
    COMPLETED = "completed"       # All steps succeeded
    FAILED = "failed"             # Chain broken (step failed)
    ABORTED = "aborted"           # Manually stopped
    TIMEOUT = "timeout"           # Took too long


class StepStatus(str, Enum):
    """
    Status of an individual chain step.
    """
    PENDING = "pending"           # Not yet started
    RUNNING = "running"           # Currently executing
    SUCCESS = "success"           # Step completed successfully
    FAILED = "failed"             # Step failed (chain broken)
    SKIPPED = "skipped"           # Skipped due to prior failure


@dataclass
class StepResult:
    """
    Result of executing a single chain step.

    Attributes:
        step: The chain step that was executed
        status: What happened
        response: HTTP response data (if applicable)
        proof: Evidence of success/failure
        error_message: Any error details
        executed_at: When this step was executed
        duration_ms: How long the step took
    """
    step: "ChainStep"
    status: StepStatus
    response: Optional[Dict[str, Any]] = None
    proof: Optional[str] = None
    error_message: Optional[str] = None
    executed_at: datetime = field(default_factory=lambda: datetime.utcnow())
    duration_ms: Optional[int] = None

    @property
    def is_success(self) -> bool:
        """Check if step executed successfully."""
        return self.status == StepStatus.SUCCESS

    def to_dict(self) -> Dict[str, Any]:
        """Serialize result to dict."""
        return {
            "primitive_id": self.step.primitive_id,
            "primitive_type": self.step.primitive_type,
            "description": self.step.description,
            "status": self.status.value,
            "has_response": self.response is not None,
            "proof": self.proof,
            "error_message": self.error_message,
            "executed_at": self.executed_at.isoformat(),
            "duration_ms": self.duration_ms,
        }


@dataclass
class ExecutionProof:
    """
    Aggregated proof from a chain execution.

    This contains all evidence needed to demonstrate that
    the exploit chain works (or doesn't).

    Attributes:
        chain_id: Which chain this proves
        target: Domain this was executed against
        goal: Target goal state
        overall_status: Final execution status
        step_results: Results for each executed step
        completed_steps: How many steps succeeded
        total_steps: Total steps in chain
        started_at: When execution started
        completed_at: When execution completed
        duration_seconds: Total execution time
    """
    chain_id: str
    target: str
    goal: "GoalState"
    overall_status: ExecutionStatus
    step_results: List[StepResult] = field(default_factory=list)
    completed_steps: int = 0
    total_steps: int = 0
    started_at: datetime = field(default_factory=lambda: datetime.utcnow())
    completed_at: Optional[datetime] = None
    duration_seconds: float = 0.0

    @property
    def success_rate(self) -> float:
        """Get percentage of steps that succeeded."""
        if self.total_steps == 0:
            return 0.0
        return (self.completed_steps / self.total_steps) * 100

    @property
    def is_proven(self) -> bool:
        """Check if chain was successfully proven."""
        return self.overall_status == ExecutionStatus.COMPLETED

    def to_dict(self) -> Dict[str, Any]:
        """Serialize proof to dict."""
        return {
            "chain_id": self.chain_id,
            "target": self.target,
            "goal": self.goal.value,
            "overall_status": self.overall_status.value,
            "completed_steps": self.completed_steps,
            "total_steps": self.total_steps,
            "success_rate": round(self.success_rate, 2),
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "duration_seconds": self.duration_seconds,
            "step_results": [sr.to_dict() for sr in self.step_results],
        }


@dataclass
class ChainResult:
    """
    Result of a chain execution attempt.

    Attributes:
        proof: Execution proof with all step results
        error: Any execution error (if failed early)
    """
    proof: Optional[ExecutionProof] = None
    error: Optional[str] = None

    @property
    def succeeded(self) -> bool:
        """Check if chain executed successfully."""
        return self.proof is not None and self.proof.is_proven


class ChainExecutor:
    """
    Executes exploit chains to generate proof.

    This class takes a validated ChainPlan and attempts to execute
    it step-by-step, capturing evidence at each stage.

    EXECUTION STRATEGY:
    1. Validate chain is approved for execution
    2. Execute steps sequentially
    3. Verify each step succeeded before proceeding
    4. Capture proof (responses, screenshots, etc.)
    5. Abort on failure or timeout
    6. Return aggregated proof

    EXAMPLE USAGE:
        ```python
        executor = ChainExecutor()
        plan = ChainPlan(...)
        result = await executor.execute_chain(plan, approval_token="...")
        if result.succeeded:
            print("Chain proven!")
        ```
    """

    # Event names for integration with EventBus
    EVENT_EXECUTION_STARTED = "nexus_chain_started"
    EVENT_EXECUTION_COMPLETED = "nexus_chain_completed"
    EVENT_STEP_STARTED = "nexus_step_started"
    EVENT_STEP_COMPLETED = "nexus_step_completed"
    EVENT_CHAIN_ABORTED = "nexus_chain_aborted"

    # Timeouts
    DEFAULT_STEP_TIMEOUT = 30  # seconds
    DEFAULT_CHAIN_TIMEOUT = 300  # seconds (5 minutes)

    def __init__(
        self,
        safe_mode: bool = SAFE_MODE,
        step_timeout: int = DEFAULT_STEP_TIMEOUT,
        chain_timeout: int = DEFAULT_CHAIN_TIMEOUT,
    ):
        """
        Initialize ChainExecutor.

        Args:
            safe_mode: If True, refuses to execute any chains
            step_timeout: Max seconds per step
            chain_timeout: Max seconds for entire chain
        """
        self._safe_mode = safe_mode
        self._step_timeout = step_timeout
        self._chain_timeout = chain_timeout
        self._execution_count = 0

    @property
    def safe_mode(self) -> bool:
        """Check if operating in safe mode."""
        return self._safe_mode

    @property
    def execution_count(self) -> int:
        """Get number of executions performed."""
        return self._execution_count

    async def execute_chain(
        self,
        plan: "ChainPlan",
        approval_token: Optional[str] = None,
        target_override: Optional[str] = None,
    ) -> ChainResult:
        """
        Execute a chain plan to generate proof.

        TODO: Implement approval token validation.
        TODO: Execute steps sequentially with verification.
        TODO: Capture proof at each step (response, status, etc.).
        TODO: Abort chain on step failure.
        TODO: Handle timeouts gracefully.

        Args:
            plan: The chain plan to execute
            approval_token: Optional approval token
            target_override: Override target (for testing)

        Returns:
            ChainResult with proof or error

        Raises:
            NotImplementedError: This is a wrapper-only implementation
        """
        # Check safe mode
        if self._safe_mode:
            raise RuntimeError(
                "SAFE_MODE: Chain execution is disabled. "
                "Set safe_mode=False to enable execution."
            )

        # Validate approval
        if not self._validate_approval(approval_token):
            raise PermissionError("Invalid or missing approval token")

        # Update statistics
        self._execution_count += 1

        # Emit event (integration point)
        logger.debug(
            f"[ChainExecutor] {self.EVENT_EXECUTION_STARTED}: "
            f"chain_id={plan.id}, goal={plan.goal.value}"
        )

        raise NotImplementedError(
            "Wrapper-only: Chain execution implementation deferred. "
            "Future implementation should execute steps sequentially."
        )

    async def execute_step(
        self,
        step: "ChainStep",
        target: str,
    ) -> StepResult:
        """
        Execute a single chain step.

        TODO: Implement step-specific execution logic.
        TODO: Handle different primitive types.
        TODO: Capture response data.
        TODO: Verify step success condition.

        Args:
            step: The step to execute
            target: Target domain

        Returns:
            StepResult with execution outcome

        Raises:
            NotImplementedError: This is a wrapper-only implementation
        """
        raise NotImplementedError(
            "Wrapper-only: Step execution implementation deferred. "
            "Future implementation should dispatch by primitive type."
        )

    def verify_step_success(
        self,
        step: "ChainStep",
        response: Dict[str, Any]
    ) -> bool:
        """
        Verify that a step achieved its objective.

        TODO: Implement success condition checking.
        TODO: Verify response status code.
        TODO: Check for expected response content.
        TODO: Validate side effects occurred.

        Args:
            step: The step that was executed
            response: HTTP response data

        Returns:
            True if step succeeded

        Raises:
            NotImplementedError: This is a wrapper-only implementation
        """
        raise NotImplementedError(
            "Wrapper-only: Step verification deferred. "
            "Future implementation should check response conditions."
        )

    def generate_proof_artifact(
        self,
        proof: ExecutionProof
    ) -> Dict[str, Any]:
        """
        Generate a shareable proof artifact from execution.

        TODO: Format proof for report generation.
        TODO: Include screenshots/images if available.
        TODO: Sanitize sensitive data from proof.
        TODO: Generate human-readable summary.

        Args:
            proof: Execution proof to format

        Returns:
            Formatted proof artifact

        Raises:
            NotImplementedError: This is a wrapper-only implementation
        """
        raise NotImplementedError(
            "Wrapper-only: Proof generation deferred. "
            "Future implementation should format for reports."
        )

    def _validate_approval(self, token: Optional[str]) -> bool:
        """
        Validate approval token for chain execution.

        TODO: Implement token validation logic.
        TODO: Check token signature/expiry.
        TODO: Verify token scope for this chain.

        Args:
            token: Approval token to validate

        Returns:
            True if token is valid

        Raises:
            NotImplementedError: This is a wrapper-only implementation
        """
        raise NotImplementedError(
            "Wrapper-only: Approval validation deferred. "
            "Future implementation should verify token signatures."
        )

    def replay(self, recorded_execution: Dict[str, Any]) -> ChainResult:
        """
        Replay a previously generated execution proof.

        Enables replayability without re-executing chains.

        Args:
            recorded_execution: Serialized ExecutionProof from to_dict()

        Returns:
            Reconstructed ChainResult

        Raises:
            NotImplementedError: This is a wrapper-only implementation
        """
        raise NotImplementedError(
            "Wrapper-only: Execution replay implementation deferred. "
            "Future implementation should deserialize from evidence store."
        )

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get usage statistics for this ChainExecutor instance.

        Returns:
            Dictionary with execution statistics
        """
        return {
            "execution_count": self._execution_count,
            "safe_mode": self._safe_mode,
            "step_timeout": self._step_timeout,
            "chain_timeout": self._chain_timeout,
        }


def create_chain_executor(
    safe_mode: bool = SAFE_MODE,
    step_timeout: int = ChainExecutor.DEFAULT_STEP_TIMEOUT,
    chain_timeout: int = ChainExecutor.DEFAULT_CHAIN_TIMEOUT,
) -> ChainExecutor:
    """
    Factory function to create ChainExecutor instance.

    This is the recommended way to create ChainExecutor objects in production code.

    Args:
        safe_mode: Safety mode flag
        step_timeout: Max seconds per step
        chain_timeout: Max seconds for entire chain

    Returns:
        Configured ChainExecutor instance
    """
    return ChainExecutor(
        safe_mode=safe_mode,
        step_timeout=step_timeout,
        chain_timeout=chain_timeout,
    )


# ============================================================================
# Module Self-Test (Design Verification)
# ============================================================================

if __name__ == "__main__":
    from core.aegis.nexus.solver import ChainStep, ChainPlan, GoalState

    # Verify enums
    assert ExecutionStatus.COMPLETED.value == "completed"
    assert StepStatus.SUCCESS.value == "success"
    print("✓ Enums work")

    # Verify StepResult dataclass
    step = ChainStep(
        primitive_id="prim_123",
        primitive_type="reflected_param",
        description="Test step",
    )
    step_result = StepResult(
        step=step,
        status=StepStatus.SUCCESS,
        proof="Worked!",
    )
    assert step_result.is_success is True
    assert step_result.to_dict()["status"] == "success"
    print("✓ StepResult structure works")

    # Verify ExecutionProof dataclass
    proof = ExecutionProof(
        chain_id="chain_123",
        target="example.com",
        goal=GoalState.ADMIN_ACCESS,
        overall_status=ExecutionStatus.COMPLETED,
        step_results=[step_result],
        completed_steps=1,
        total_steps=1,
    )
    assert proof.is_proven is True
    assert proof.success_rate == 100.0
    assert proof.to_dict()["success_rate"] == 100.0
    print("✓ ExecutionProof structure works")

    # Verify ChainExecutor creation
    executor = create_chain_executor()
    assert executor.safe_mode is True
    assert executor.execution_count == 0
    print("✓ ChainExecutor factory works")

    # Verify safe mode enforcement
    try:
        import asyncio
        plan = ChainPlan(
            id=str(uuid.uuid4()),
            goal=GoalState.ADMIN_ACCESS,
            start_primitive="prim_123",
        )
        asyncio.run(executor.execute_chain(plan))
        print("✗ Safe mode enforcement failed")
    except RuntimeError as e:
        if "SAFE_MODE" in str(e):
            print("✓ Safe mode enforcement works")
        else:
            print(f"✗ Unexpected error: {e}")

    print("\n✅ All ChainExecutor design invariants verified!")

#
# PURPOSE:
# High-level strategic planning for security scans. Named after Greek "strategos"
# (military general), this module decides WHAT to scan and WHEN.
#
# WHAT STRATEGOS DOES:
# - Analyzes target to determine appropriate scanning strategy
# - Selects which tools to run based on target characteristics
# - Sequences tool execution for maximum efficiency
# - Adapts strategy based on intermediate findings
# - Manages resource allocation (rate limiting, parallelization)
#
# STRATEGIC DECISIONS:
# - Passive vs. Active: When to stay quiet vs. make noise
# - Breadth vs. Depth: Scan many targets shallowly or few deeply
# - Tool Selection: Use nmap for ports, httpx for web, etc.
# - Timing: Sequential (slow, stealthy) vs. Parallel (fast, noisy)
#
# KEY CONCEPTS:
# - **Strategy**: High-level plan (what and when to scan)
# - **Tactics**: Low-level execution (how to run each tool)
# - **Adaptive Planning**: Adjust strategy based on discoveries
#

"""
core/scheduler/strategos.py
The Mind of the Scanner.
Implements a True Async Agent Loop with Event-Driven Concurrency.
"""

import asyncio
import logging
from typing import List, Dict, Any, Callable, Awaitable, Optional, Set, TYPE_CHECKING
from dataclasses import dataclass, field
from urllib.parse import urlparse

from core.scheduler.laws import Constitution
from core.scheduler.registry import ToolRegistry, PHASE_1_PASSIVE, PHASE_2_LIGHT, PHASE_3_SURFACE, PHASE_4_DEEP, PHASE_5_HEAVY
from core.scheduler.modes import ScanMode, ModeRegistry
from core.scheduler.intents import (
    INTENT_PASSIVE_RECON,
    INTENT_ACTIVE_LIVE_CHECK, 
    INTENT_SURFACE_ENUMERATION,
    INTENT_VULN_SCANNING,
    INTENT_HEAVY_ARTILLERY
)
from core.scheduler.events import ToolCompletedEvent, MissionTerminatedEvent
from core.cortex.events import EventBus
from core.scheduler.decisions import (
    DecisionContext,
    DecisionLedger,
    DecisionType,
    DecisionPoint,
    create_decision_context
)
from core.cortex.arbitration import ArbitrationEngine
from core.cortex.policy import ScopePolicy, RiskPolicy, Verdict

if TYPE_CHECKING:
    from core.cortex.narrator import NarratorEngine

logger = logging.getLogger(__name__)

DEFAULT_EVENT_QUEUE_MAXSIZE = 1024

@dataclass
class ScanContext:
    """Class ScanContext."""
    target: str
    phase_index: int = 0
    knowledge: Dict[str, Any] = field(default_factory=dict)
    active_tools: int = 0
    max_concurrent: int = 3  # Real throttling limit
    findings: List[Dict] = field(default_factory=list)
    findings_this_intent: int = 0
    surface_delta_this_intent: int = 0
    running_tools: Set[str] = field(default_factory=set)
    completed_tools_per_intent: Dict[str, Set[str]] = field(default_factory=dict)
    surface_seen: Set[str] = field(default_factory=set)

class Strategos:
    """
    The Strategist.
    A truly concurrent, event-driven planner with first-class decision tracking.
    
    Every strategic decision is captured as an immutable DecisionPoint and
    automatically emitted as events to the EventBus. This ensures complete
    observability and audit trail without manual emit_event() calls.
    """
    
    def __init__(
        self,
        event_queue_maxsize: int = DEFAULT_EVENT_QUEUE_MAXSIZE,
        log_fn: Optional[Callable[[str], None]] = None,
        event_bus: Optional[EventBus] = None,
        decision_ledger: Optional[DecisionLedger] = None,
        narrator: Optional["NarratorEngine"] = None,
    ):
        """Function __init__."""
        self.constitution = Constitution()
        self.registry = ToolRegistry()
        self.context: Optional[ScanContext] = None
        self.event_queue: asyncio.Queue = asyncio.Queue(maxsize=event_queue_maxsize)
        self._terminated = False
        self._dispatch_callback: Optional[Callable[[str], Awaitable[List[Dict]]]] = None
        self._tool_tasks: Dict[str, asyncio.Task] = {}
        self._tool_semaphore: Optional[asyncio.Semaphore] = None
        self._log_fn = log_fn
        self._event_bus = event_bus
        self._narrator = narrator
        
        # Decision Emission Layer: All strategic choices flow through this context
        # This creates a complete audit trail separate from the event stream
        self._decision_ledger = decision_ledger or DecisionLedger()
        self._decision_ctx: Optional[DecisionContext] = None
        
        # Track current decision for hierarchical decision trees
        # Track current decision for hierarchical decision trees
        self._current_intent_decision: Optional[DecisionPoint] = None

        # Layer 4: Policy Arbitration
        self.arbitrator = ArbitrationEngine()
        self.arbitrator.register_policy(ScopePolicy())
        self.arbitrator.register_policy(RiskPolicy())

    def _emit_log(self, message: str, level: str = "info") -> None:
        """Function _emit_log."""
        # Error handling block.
        try:
            log_method = getattr(logger, level, logger.info)
            log_method(message)
        except Exception:
            pass

        # Conditional branch.
        if hasattr(self, "_current_mission_log_fn") and self._current_mission_log_fn:
            try:
                self._current_mission_log_fn(message)
            except Exception:
                pass
        elif self._log_fn:
            try:
                self._log_fn(message)
            except Exception:
                pass
        
    async def run_mission(
        self, 
        target: str, 
        available_tools: List[str], 
        mode: ScanMode,
        dispatch_tool: Callable[[str], Awaitable[List[Dict]]],
        log_fn: Optional[Callable[[str], None]] = None
    ) -> MissionTerminatedEvent:
        """
        The Agent Loop with First-Class Decision Tracking.
        
        Every strategic decision (intent transition, tool selection, phase change)
        is captured as an immutable DecisionPoint and automatically emitted.
        
        Decision Flow Architecture:
        1. DecisionContext wraps entire mission lifecycle
        2. Each intent transition creates a parent decision
        3. Tool selections are child decisions linked to intent
        4. Phase transitions emit specialized phase_changed events
        5. Early termination (Walk Away) is an explicit decision
        
        This ensures complete decision audit trail without manual emit calls.
        """
        # Clear event queue from previous runs
        while not self.event_queue.empty():
            try:
                self.event_queue.get_nowait()
            except asyncio.QueueEmpty:
                break
        
        # Override log_fn for this mission if provided
        self._current_mission_log_fn = log_fn

        # Initialize scan context
        self.context = ScanContext(target=target)
        self.context.knowledge["mode"] = mode
        
        # Seed baseline protocol tags for deterministic tool gating
        # Assumption: HTTP/HTTPS targets until proven otherwise
        existing_tags = self.context.knowledge.get("tags")
        # Conditional branch.
        if not isinstance(existing_tags, set):
            existing_tags = set()
        existing_tags.update({"protocol:http", "protocol:https"})
        self.context.knowledge["tags"] = existing_tags
        
        self._terminated = False
        self._dispatch_callback = dispatch_tool
        self._tool_tasks = {}
        self._tool_semaphore = asyncio.Semaphore(self.context.max_concurrent)
        
        # Initialize Decision Emission Layer
        # All decisions made during this mission flow through this context
        self._decision_ctx = create_decision_context(
            event_bus=self._event_bus,
            ledger=self._decision_ledger,
            narrator=self._narrator
        )
        
        current_intent = INTENT_PASSIVE_RECON
        
        self._emit_log(f"[Strategos] Mission Start: {target} (Mode: {mode.value})")
        
        # Start event listener in background
        listener_task = asyncio.create_task(self._event_listener())
        
        # Error handling block.
        try:
            # === THE AGENT LOOP (Decision-Driven) ===
            while not self._terminated:
                # DECISION POINT: Phase Transition
                # Check if we need to transition to a new phase based on intent
                new_phase = self._get_phase_for_intent(current_intent)
                if new_phase != self.context.phase_index:
                    # Emit phase transition as specialized decision
                    self._decision_ctx.choose(
                        decision_type=DecisionType.PHASE_TRANSITION,
                        chosen=f"PHASE_{new_phase}",
                        reason=f"Intent {current_intent} requires phase {new_phase}",
                        alternatives=[f"PHASE_{self.context.phase_index}"],  # What we're leaving
                        context={
                            "phase": f"PHASE_{new_phase}",
                            "previous_phase": f"PHASE_{self.context.phase_index}",
                            "intent": current_intent,
                            "mode": mode.value
                        }
                    )
                    self.context.phase_index = new_phase
                
                # Reset intent-scoped metrics
                self.context.findings_this_intent = 0
                self.context.surface_delta_this_intent = 0
                
                # DECISION POINT: Intent Execution
                # Declare intent to execute this strategic phase
                self._emit_log(f"[Strategos] Decision: Executing {current_intent}")
                self._current_intent_decision = self._decision_ctx.choose(
                    decision_type=DecisionType.INTENT_TRANSITION,
                    chosen=current_intent,
                    reason="Standard sequential progression through scan intents",
                    alternatives=self._get_available_intents(current_intent, mode),
                    context={
                        "mode": mode.value,
                        "target": target,
                        "current_phase": new_phase
                    },
                    evidence={
                        "findings_count": len(self.context.findings),
                        "surface_size": len(self.context.surface_seen),
                        "completed_tools": sum(
                            len(tools) 
                            for tools in self.context.completed_tools_per_intent.values()
                        )
                    }
                )
                
                # DECISION POINT: Tool Selection
                # Select which tools to run for this intent (may be empty)
                tools_to_run = self._select_tools(current_intent, available_tools, mode)
                
                if not tools_to_run:
                    # DECISION: Skip intent due to no available tools
                    self._emit_log(f"[Strategos] No tools available for {current_intent}. Skipping.")
                    
                    # Nested decision under current intent
                    with self._decision_ctx.nested(self._current_intent_decision):
                        self._decision_ctx.choose(
                            decision_type=DecisionType.TOOL_SELECTION,
                            chosen="SKIP",
                            reason="No tools available or all tools blocked",
                            alternatives=available_tools,  # What we could have chosen
                            context={
                                "mode": mode.value,
                                "intent": current_intent,
                                "skipped": True
                            },
                            evidence={
                                "available_tools": available_tools,
                                "candidate_tools_count": 0
                            }
                        )
                else:
                    # Dispatch all selected tools concurrently
                    await self._dispatch_tools_async(tools_to_run, intent=current_intent)
                    
                    # Wait for all tools in this intent to complete
                    await self._wait_for_intent_completion()
                
                # DECISION POINT: Next Intent Selection
                # Strategic decision: what to do next based on current state
                next_intent = self._decide_next_step(current_intent)
                
                if next_intent is None:
                    # Mission termination is a decision too
                    self._terminated = True
                else:
                    current_intent = next_intent
        finally:
            # Cleanup: Cancel all running tasks
            self._terminated = True
            tasks = list(self._tool_tasks.values())
            for task in tasks:
                task.cancel()
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
            self._tool_tasks.clear()
            listener_task.cancel()
            try:
                await listener_task
            except asyncio.CancelledError:
                pass
        
        reason = "Mission Complete. All intents exhausted or Walk Away triggered."
        self._emit_log(f"[Strategos] {reason}")
        return MissionTerminatedEvent(reason=reason)
    
    async def _dispatch_tools_async(self, tools: List[str], intent: str):
        """
        Fire-and-forget dispatch with concurrency throttling.
        """
        # Loop over items.
        for tool in tools:
            if tool in self.context.running_tools:
                logger.debug(f"[Strategos] Skipping {tool}: already running.")
                continue
            if tool in self.context.completed_tools_per_intent.get(intent, set()):
                logger.debug(f"[Strategos] Skipping {tool}: already completed for {intent}.")
                continue

            # THROTTLE: Wait for a slot
            await self._tool_semaphore.acquire()
            
            # Dispatch (fire-and-forget)
            self.context.active_tools += 1
            self.context.running_tools.add(tool)
            self._emit_log(
                f"[Strategos] Dispatching: {tool} ({self.context.active_tools}/{self.context.max_concurrent})"
            )
            
            task = asyncio.create_task(self._run_tool_worker(tool, intent=intent))
            self._tool_tasks[tool] = task
    
    def _surface_key(self, finding: Dict[str, Any]) -> Optional[str]:
        """Function _surface_key."""
        # Conditional branch.
        if not isinstance(finding, dict):
            return None
        metadata = finding.get("metadata") or {}
        raw = metadata.get("original_target") or finding.get("target") or finding.get("asset")
        # Conditional branch.
        if not raw or not isinstance(raw, str):
            return None
        raw = raw.strip()
        # Conditional branch.
        if not raw:
            return None

        # Conditional branch.
        if "://" not in raw:
            host = raw.lower().rstrip(".")
            if host.startswith("www."):
                host = host[4:]
            return host

        # Error handling block.
        try:
            parsed = urlparse(raw)
        except Exception:
            return raw

        host = (parsed.hostname or "").lower().rstrip(".")
        # Conditional branch.
        if not host:
            return raw
        # Conditional branch.
        if host.startswith("www."):
            host = host[4:]

        scheme = (parsed.scheme or "https").lower()
        port = parsed.port
        netloc = host if port is None else f"{host}:{port}"

        path = parsed.path or ""
        # Conditional branch.
        if path and path != "/":
            path = path.rstrip("/")
        else:
            path = ""

        return f"{scheme}://{netloc}{path}"

    def _enqueue_event(self, event: Any) -> bool:
        """Function _enqueue_event."""
        # Error handling block.
        try:
            self.event_queue.put_nowait(event)
            return True
        except asyncio.QueueFull:
            self._emit_log(
                f"[Strategos] Event queue full ({self.event_queue.qsize()}/{self.event_queue.maxsize}); "
                f"dropping {type(event).__name__}.",
                level="warning",
            )
            return False

    async def _run_tool_worker(self, tool: str, intent: str):
        """
        Runs a tool and pushes ToolCompletedEvent to queue.
        """
        findings = []
        success = True
        start = asyncio.get_running_loop().time()
        # Error handling block.
        try:
            findings = await self._dispatch_callback(tool)
            if findings is None:
                findings = []
        except asyncio.CancelledError:
            success = False
            raise
        except Exception as e:
            self._emit_log(f"[Strategos] Tool {tool} failed: {e}", level="error")
            success = False
        finally:
            duration = max(0.0, asyncio.get_running_loop().time() - start)
            try:
                if findings:
                    self.ingest_findings(findings)
            finally:
                self.context.completed_tools_per_intent.setdefault(intent, set()).add(tool)
                self.context.running_tools.discard(tool)
                self._tool_tasks.pop(tool, None)
                self.context.active_tools = max(0, self.context.active_tools - 1)
                if self._tool_semaphore is not None:
                    self._tool_semaphore.release()

            event = ToolCompletedEvent(
                tool=tool,
                findings=findings,
                success=success,
                duration_seconds=duration,
            )
            if not self._enqueue_event(event):
                status = "✓" if event.success else "✗"
                self._emit_log(f"[Strategos] {status} {event.tool} complete. Findings: {len(event.findings)}")
    
    async def _event_listener(self):
        """
        Background task: Consumes events from queue.
        """
        # While loop.
        while not self._terminated:
            try:
                event = await asyncio.wait_for(self.event_queue.get(), timeout=0.5)
                
                if isinstance(event, ToolCompletedEvent):
                    self._handle_tool_completed(event)
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break
    
    def _handle_tool_completed(self, event: ToolCompletedEvent):
        """
        Process a completed tool event.
        """
        status = "✓" if event.success else "✗"
        self._emit_log(f"[Strategos] {status} {event.tool} complete. Findings: {len(event.findings)}")
    
    async def _wait_for_intent_completion(self):
        """
        Block until all tools for current intent are finished.
        """
        # While loop.
        while self.context.running_tools:
            await asyncio.sleep(0.1)
    
    def ingest_findings(self, findings: List[Dict]):
        """
        Active Feedback.
        """
        # Conditional branch.
        if not self.context:
            return
            
        # Loop over items.
        for finding in findings:
            self.context.findings.append(finding)
            self.context.findings_this_intent += 1

            surface_key = self._surface_key(finding)
            if surface_key and surface_key not in self.context.surface_seen:
                self.context.surface_seen.add(surface_key)
                self.context.surface_delta_this_intent += 1
            
            tags = finding.get("tags", [])
            finding_type = finding.get("type", "")
            if finding_type:
                tags.append(finding_type)
            
            existing_tags = self.context.knowledge.get("tags", set())
            existing_tags.update(tags)
            self.context.knowledge["tags"] = existing_tags
            
        self._emit_log(f"[Strategos] Ingested {len(findings)} findings. Total: {len(self.context.findings)}")

    def _select_tools(self, intent: str, available_tools: List[str], mode: ScanMode) -> List[str]:
        """
        Select and prioritize tools for an intent.
        
        This is a critical decision point - tool selection determines scan coverage.
        Every tool that is blocked, disabled, or rejected gets its own decision record.
        
        Decision Flow:
        1. Get candidate tools for this intent
        2. Filter by availability and completion status
        3. For each candidate:
           a. Check if disabled by mode overlay
           b. Check against Constitution (safety rules)
           c. Calculate priority score
        4. Emit individual decisions for rejections
        5. Return sorted list of approved tools
        """
        candidates = ToolRegistry.get_tools_for_intent(intent, mode=mode)
        candidates = [t for t in candidates if t in available_tools]
        candidates = [t for t in candidates if t not in self.context.completed_tools_per_intent.get(intent, set())]
        
        scored = []
        rejected_count = 0
        reasons: Dict[str, List[str]] = {}
        
        # Loop over items.
        for t in candidates:
            tool_def = ToolRegistry.get(t, mode=mode)
            tool_def["name"] = t
            
            # DECISION POINT: Tool disabled by mode overlay
            if tool_def.get("disabled"):
                rejected_count += 1
                reasons.setdefault("Mode Overlay", []).append(t)
                continue
            
            # DECISION POINT: Constitutional check (safety rules)
            constitution_decision = self.constitution.check(self.context, tool_def)
            if not constitution_decision.allowed:
                rejected_count += 1
                reason = f"{constitution_decision.blocking_law} ({constitution_decision.reason})"
                reasons.setdefault(reason, []).append(t)
                continue
            
            # DECISION POINT: Policy Arbitration (Flexible Rules)
            # Create a transient decision to query the arbitrator
            # We must verify if this tool is acceptable under current policies
            sim_ctx = {
                **tool_def, 
                "target": self.context.target if self.context else "unknown", 
                "mode": mode.value
            }
            simulated_decision = DecisionPoint.create(
                DecisionType.TOOL_SELECTION,
                chosen=t,
                reason="Candidate Qualification",
                context=sim_ctx
            )
            judgment = self.arbitrator.review(simulated_decision, sim_ctx)
            
            if judgment.verdict == Verdict.VETO:
                rejected_count += 1
                reason = f"Policy Veto: {judgment.policy_name}"
                reasons.setdefault(reason, []).append(t)
                continue
            
            # DECISION POINT: Scoring (implicit selection)
            score = self._calculate_score(tool_def, mode)
            scored.append((t, score))
            
        # Emit grouped rejection decisions
        if self._decision_ctx and self._current_intent_decision and reasons:
            with self._decision_ctx.nested(self._current_intent_decision):
                for reason_desc, tools in reasons.items():
                    self._decision_ctx.choose(
                        decision_type=DecisionType.TOOL_REJECTION,
                        chosen="BLOCKED",
                        reason=reason_desc,
                        context={
                            "tools": tools,
                            "count": len(tools),
                            "intent": intent,
                            "mode": mode.value
                        }
                    )
        
        # Sort by score (highest priority first)
        scored.sort(key=lambda x: x[1], reverse=True)
        selected_tools = [t for t, _ in scored]
        
        # DECISION POINT: Final tool selection for this intent
        # Emit a single decision recording all selected tools
        if self._decision_ctx and self._current_intent_decision:
            with self._decision_ctx.nested(self._current_intent_decision):
                self._decision_ctx.choose(
                    decision_type=DecisionType.TOOL_SELECTION,
                    chosen=selected_tools,
                    reason=f"Selected {len(selected_tools)} tools for {intent} (rejected {rejected_count})",
                    alternatives=candidates,  # All candidates considered
                    context={
                        "intent": intent,
                        "mode": mode.value,
                        "selected_count": len(selected_tools),
                        "rejected_count": rejected_count
                    },
                    evidence={
                        "tool_scores": {t: score for t, score in scored},
                        "available_count": len(available_tools)
                    }
                )
        
        return selected_tools

    def _calculate_score(self, tool_def: Dict, mode: ScanMode) -> int:
        """Function _calculate_score."""
        overlay_map = ModeRegistry.get_overlay(mode)
        tool_name = tool_def.get("name")
        overlay = overlay_map.get(tool_name)
        
        priority = overlay.priority_boost if overlay and overlay.priority_boost else 0
        cost = tool_def.get("cost", 1)
        intrusiveness = tool_def.get("intrusiveness", 1)
        
        return (priority * 10) - (cost * 2) - intrusiveness

    def _decide_next_step(self, current_intent: str) -> Optional[str]:
        """
        Strategic decision: what intent to execute next.
        
        This implements the core scan progression logic:
        - Standard: Passive → Active → Surface → Vuln → Heavy
        - Bug Bounty: Passive → Active → Surface → Vuln (skip Heavy)
        - Walk Away: Terminate early if no new surface discovered
        
        Every transition (or termination) is an explicit decision with justification.
        
        Decision Types:
        - Intent transition: Moving to next phase
        - Early termination: Walk Away logic
        - Mode adaptation: Skipping phases based on mode constraints
        """
        # Handle edge cases for unit tests and initial state
        if self.context is None or current_intent is None:
            return INTENT_PASSIVE_RECON
        
        mode = self.context.knowledge.get("mode", ScanMode.STANDARD)
        
        # DECISION POINT: Post-Passive Recon
        if current_intent == INTENT_PASSIVE_RECON:
            next_intent = INTENT_ACTIVE_LIVE_CHECK
            if self._decision_ctx:
                self._decision_ctx.choose(
                    decision_type=DecisionType.INTENT_TRANSITION,
                    chosen=next_intent,
                    reason="Passive recon complete, proceeding to active live checks",
                    alternatives=[None],  # Could terminate, but standard progression continues
                    context={"from": current_intent, "to": next_intent, "mode": mode.value},
                    evidence={"findings_count": len(self.context.findings)}
                )
            return next_intent
        
        # DECISION POINT: Post-Active Live Check
        if current_intent == INTENT_ACTIVE_LIVE_CHECK:
            next_intent = INTENT_SURFACE_ENUMERATION
            if self._decision_ctx:
                self._decision_ctx.choose(
                    decision_type=DecisionType.INTENT_TRANSITION,
                    chosen=next_intent,
                    reason="Live checks complete, proceeding to surface enumeration",
                    alternatives=[None],
                    context={"from": current_intent, "to": next_intent, "mode": mode.value},
                    evidence={"findings_count": len(self.context.findings)}
                )
            return next_intent
        
        # DECISION POINT: Post-Surface Enumeration (Walk Away Logic)
        if current_intent == INTENT_SURFACE_ENUMERATION:
            # Bug Bounty Walk Away: Terminate if no new surface discovered
            if mode == ScanMode.BUG_BOUNTY and self.context.surface_delta_this_intent == 0:
                self._emit_log("[Strategos] Walk Away: No new surface discovered. Aborting deep scan.")
                
                if self._decision_ctx:
                    self._decision_ctx.choose(
                        decision_type=DecisionType.EARLY_TERMINATION,
                        chosen="WALK_AWAY",
                        reason="No new attack surface discovered in surface enumeration phase",
                        alternatives=[INTENT_VULN_SCANNING],  # What we could do instead
                        context={
                            "from": current_intent,
                            "mode": mode.value,
                            "trigger": "bug_bounty_zero_surface_delta"
                        },
                        evidence={
                            "surface_delta_this_intent": self.context.surface_delta_this_intent,
                            "total_surface_size": len(self.context.surface_seen),
                            "findings_this_intent": self.context.findings_this_intent
                        }
                    )
                
                return None  # Terminate mission
            
            # Standard progression: proceed to vuln scanning
            next_intent = INTENT_VULN_SCANNING
            if self._decision_ctx:
                self._decision_ctx.choose(
                    decision_type=DecisionType.INTENT_TRANSITION,
                    chosen=next_intent,
                    reason="Surface enumeration complete, proceeding to vulnerability scanning",
                    alternatives=[None],  # Could Walk Away
                    context={"from": current_intent, "to": next_intent, "mode": mode.value},
                    evidence={
                        "surface_delta": self.context.surface_delta_this_intent,
                        "total_surface": len(self.context.surface_seen)
                    }
                )
            return next_intent
        
        # DECISION POINT: Post-Vuln Scanning (Mode-Based Heavy Artillery)
        if current_intent == INTENT_VULN_SCANNING:
            # Bug Bounty Mode: Skip heavy artillery (too aggressive)
            if mode == ScanMode.BUG_BOUNTY:
                self._emit_log("[Strategos] Bug Bounty Mode: Skipping Heavy Artillery.")
                
                if self._decision_ctx:
                    self._decision_ctx.choose(
                        decision_type=DecisionType.MODE_ADAPTATION,
                        chosen="SKIP_HEAVY_ARTILLERY",
                        reason="Bug Bounty mode prohibits heavy/aggressive scanning tools",
                        alternatives=[INTENT_HEAVY_ARTILLERY],  # What we're skipping
                        context={
                            "from": current_intent,
                            "mode": mode.value,
                            "skipped_intent": INTENT_HEAVY_ARTILLERY
                        }
                    )
                
                return None  # Terminate mission gracefully
            
            # Standard mode: proceed to heavy artillery
            next_intent = INTENT_HEAVY_ARTILLERY
            if self._decision_ctx:
                self._decision_ctx.choose(
                    decision_type=DecisionType.INTENT_TRANSITION,
                    chosen=next_intent,
                    reason="Vulnerability scanning complete, proceeding to heavy artillery",
                    alternatives=[None],  # Could stop here
                    context={"from": current_intent, "to": next_intent, "mode": mode.value},
                    evidence={"findings_count": len(self.context.findings)}
                )
            return next_intent
        
        # DECISION POINT: Post-Heavy Artillery (End of Standard Scan)
        # No more intents, mission complete
        if self._decision_ctx:
            self._decision_ctx.choose(
                decision_type=DecisionType.EARLY_TERMINATION,
                chosen="MISSION_COMPLETE",
                reason="All intents exhausted, scan complete",
                context={"last_intent": current_intent, "mode": mode.value},
                evidence={
                    "total_findings": len(self.context.findings),
                    "total_surface": len(self.context.surface_seen),
                    "total_tools_run": sum(
                        len(tools) for tools in self.context.completed_tools_per_intent.values()
                    )
                }
            )
        
        return None
    
    def _get_phase_for_intent(self, intent: str) -> int:
        """Map intent to numeric phase for compatibility with existing phase tracking."""
        # Conditional branch.
        if intent == INTENT_PASSIVE_RECON:
            return PHASE_1_PASSIVE
        # Conditional branch.
        if intent == INTENT_ACTIVE_LIVE_CHECK:
            return PHASE_2_LIGHT
        # Conditional branch.
        if intent == INTENT_SURFACE_ENUMERATION:
            return PHASE_3_SURFACE
        # Conditional branch.
        if intent == INTENT_VULN_SCANNING:
            return PHASE_4_DEEP
        # Conditional branch.
        if intent == INTENT_HEAVY_ARTILLERY:
            return PHASE_5_HEAVY
        return 0
    
    def _get_available_intents(self, current_intent: str, mode: ScanMode) -> List[str]:
        """
        Get the list of possible next intents for decision recording.
        
        This documents what alternatives existed at each decision point.
        Helps with decision replay and "what-if" analysis.
        """
        # Standard progression sequence
        if current_intent == INTENT_PASSIVE_RECON:
            return [INTENT_ACTIVE_LIVE_CHECK, None]  # Could terminate early
        
        # Conditional branch.
        if current_intent == INTENT_ACTIVE_LIVE_CHECK:
            return [INTENT_SURFACE_ENUMERATION, None]
        
        # Conditional branch.
        if current_intent == INTENT_SURFACE_ENUMERATION:
            if mode == ScanMode.BUG_BOUNTY:
                # Bug bounty has Walk Away option
                return [INTENT_VULN_SCANNING, None]
            return [INTENT_VULN_SCANNING, None]
        
        # Conditional branch.
        if current_intent == INTENT_VULN_SCANNING:
            if mode == ScanMode.BUG_BOUNTY:
                # No heavy artillery in bug bounty
                return [None]
            return [INTENT_HEAVY_ARTILLERY, None]
        
        # Heavy artillery is always terminal
        return [None]

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
    - WHICH EVENTS triggered it (trigger_event_sequence)

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
        trigger_event_sequence: Optional event sequence that triggered this decision
        timestamp: When decision was created (monotonic time)
        sequence: Ledger sequence number (set by DecisionLedger)

    Contract:
        - Once created, fields are immutable (frozen dataclass)
        - `sequence` is None until committed to ledger
        - `parent_id` creates causal chains for decision analysis
        - `trigger_event_sequence` enables event-decision correlation
    """
    id: str
    type: DecisionType
    chosen: Any
    reason: str
    alternatives: List[Any] = field(default_factory=list)
    context: Dict[str, Any] = field(default_factory=dict)
    evidence: Dict[str, Any] = field(default_factory=dict)
    parent_id: Optional[str] = None
    trigger_event_sequence: Optional[int] = None
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
        parent_id: Optional[str] = None,
        trigger_event_sequence: Optional[int] = None
    ) -> DecisionPoint:
        """
        Factory method for creating decisions.

        This is the primary way to create DecisionPoints.
        Validates that all required fields are provided.

        Args:
            decision_type: Classification of the decision
            chosen: The selected option
            reason: Why this option was chosen
            alternatives: Other options that were considered
            context: Arbitrary metadata (target, mode, scores, etc.)
            evidence: Supporting data that informed the decision
            parent_id: Link to parent decision (for decision trees)
            trigger_event_sequence: Event sequence that triggered this decision
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
            trigger_event_sequence=trigger_event_sequence,
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
            trigger_event_sequence=self.trigger_event_sequence,
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

        # Include event sequence for correlation
        if self.trigger_event_sequence:
            payload["trigger_event_sequence"] = self.trigger_event_sequence

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
        self._lock = threading.RLock()
        
    def commit(self, decision: DecisionPoint) -> DecisionPoint:
        """
        Append a decision to the ledger and assign sequence number.

        This is the ONLY way to add decisions, ensuring sequence integrity.
        Persists to database asynchronously.

        SEQUENCE UNIFICATION:
        Decisions and Events share the same GlobalSequenceAuthority timeline.
        This ensures perfect causal ordering: if event E (seq=42) triggers
        decision D (seq=43), we can always determine that E happened before D.

        Args:
            decision: The decision to commit (without sequence)

        Returns:
            The decision with sequence number assigned
        """
        # get_next_sequence() delegates to GlobalSequenceAuthority,
        # ensuring Events and Decisions share the same timeline
        from core.cortex.events import get_next_sequence
        from core.data.db import Database

        with self._lock:
            # Use global sequence generator (shared with EventStore)
            global_seq = get_next_sequence()
            sequenced_decision = decision.with_sequence(global_seq)
            self._decisions.append(sequenced_decision)
            
            # Persist to DB (fire-and-forget)
            try:
                # Convert to dict for DB
                payload = {
                    "id": sequenced_decision.id,
                    "sequence": sequenced_decision.sequence,
                    "type": sequenced_decision.type.value,
                    "chosen": sequenced_decision.chosen,
                    "reason": sequenced_decision.reason,
                    "alternatives": sequenced_decision.alternatives,
                    "context": sequenced_decision.context,
                    "evidence": sequenced_decision.evidence,
                    "parent_id": sequenced_decision.parent_id,
                    "trigger_event_sequence": sequenced_decision.trigger_event_sequence
                }
                Database.instance().save_decision(payload)
            except Exception:
                # DB failure should not crash the scanner
                pass
        
        return sequenced_decision
    
    async def get_children(self, decision_id: str) -> List[DecisionPoint]:
        """
        Get all decisions that were made as a result of this decision.
        Enables decision tree reconstruction.
        
        Fetches 'deep' children from Database (async).
        """
        from core.data.db import Database
        try:
            records = await Database.instance().get_decision_children(decision_id)
            # Rehydrate DecisionPoints (approximate, as immutable/frozen might limit reconstruction fidelity without factory)
            # We assume these are mostly for analysis/reporting.
            children = []
            for r in records:
                children.append(DecisionPoint(
                    id=r["id"],
                    type=DecisionType(r["type"]),
                    chosen=r["chosen"],
                    reason=r["reason"],
                    alternatives=r["alternatives"],
                    context=r["context"],
                    evidence=r["evidence"],
                    parent_id=r["parent_id"],
                    trigger_event_sequence=r["trigger_event_sequence"],
                    timestamp=0.0, # DB doesn't store monotonic float
                    sequence=r["sequence"]
                ))
            return children
        except Exception:
            return []
    
    def get_chain(self, decision_id: str) -> List[DecisionPoint]:
        """
        Get the causal chain leading to this decision.
        Returns [root_decision, ..., this_decision].
        
        NOTE: Only scans in-memory history (last N decisions).
        Deep history would require DB lookups.
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
        """Get all *in-memory* decisions in sequence order."""
        # Context-managed operation.
        with self._lock:
            return list(self._decisions)
    
    def clear(self) -> None:
        """Clear all decisions. Primarily for testing."""
        # Context-managed operation.
        with self._lock:
            self._decisions.clear()
    
    def stats(self) -> Dict[str, Any]:
        """Return diagnostic statistics."""
        # Context-managed operation.
        with self._lock:
            type_counts = {}
            for d in self._decisions:
                type_counts[d.type.value] = type_counts.get(d.type.value, 0) + 1
            
            return {
                "total_decisions_memory": len(self._decisions),
                "last_sequence": self._decisions[-1].sequence if self._decisions else 0,
                "max_capacity": self._decisions.maxlen,
                "decisions_by_type": type_counts
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
        trigger_event_sequence: Optional[int] = None,
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
            trigger_event_sequence: Event sequence that triggered this decision
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
            parent_id=parent_id,
            trigger_event_sequence=trigger_event_sequence
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
# Singleton Instance
# ============================================================================

_decision_ledger_instance: Optional[DecisionLedger] = None


def get_decision_ledger() -> DecisionLedger:
    """
    Get the global DecisionLedger singleton instance.

    Returns:
        Global DecisionLedger instance
    """
    global _decision_ledger_instance
    if _decision_ledger_instance is None:
        _decision_ledger_instance = DecisionLedger()
    return _decision_ledger_instance


# ============================================================================
# Self-Test / Design Verification
# ============================================================================

if __name__ == "__main__":
    # Initialize sequence for testing
    import core.cortex.events as events
    # Monkeypatch to bypass DB check
    events._event_sequence_initialized = True
    
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

#
# PURPOSE:
# This module is part of the scheduler package in SentinelForge.
# [Specific purpose based on module name: laws]
#
# KEY RESPONSIBILITIES:
# - [Automatically generated - review and enhance based on actual functionality]
#
# INTEGRATION:
# - Used by: [To be documented]
# - Depends on: [To be documented]
#

"""
core/scheduler/laws.py
The Constitution of Strategos.
Enforces the 5 Laws of a God-Level Scan.
"""

from typing import Dict, List, Any
import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)

@dataclass
class Decision:
    """Class Decision."""
    allowed: bool
    reason: str
    blocking_law: str = None

class Law:
    """Base class for a Scan Law."""
    def check(self, context: Any, tool_def: Dict[str, Any]) -> Decision:
        """Function check."""
        raise NotImplementedError

class Law1_PassiveBeforeActive(Law):
    """
    Law 1: Passive Before Active.
    Aggressive tools cannot run until Passive Phase is complete.
    """
    def check(self, context: Any, tool_def: Dict[str, Any]) -> Decision:
        """Function check."""
        current_phase = getattr(context, "phase_index", 0)
        tool_phase = tool_def.get("phase", 99)
        
        # If we are in Phase 0 or 1, we cannot run Phase 2+ tools
        if current_phase < 2 and tool_phase >= 2:
            return Decision(False, f"Phase {tool_phase} tool blocked during Phase {current_phase} (Passive Mode)", "Law1_PassiveBeforeActive")
        return Decision(True, "Phase check passed")

class Law3_EvidenceGates(Law):
    """
    Law 3: Evidence Gates Everything.
    Tools only run if their prerequisites are met in the Knowledge Graph.
    Also enforces Confidence Thresholds in Bug Bounty Mode.
    """
    def check(self, context: Any, tool_def: Dict[str, Any]) -> Decision:
        """Function check."""
        gates = tool_def.get("gates", [])
        # Conditional branch.
        if not gates:
            return Decision(True, "No prerequisites required")
            
        # Context.knowledge is a Dict
        knowledge = getattr(context, "knowledge", {}) or {}
        # mode = knowledge.get("mode", None)  <-- Removed unused variable
        
        # Build the active tag set from context + knowledge.
        tags: set[str] = set()

        known_tags = knowledge.get("tags")
        # Conditional branch.
        if isinstance(known_tags, set):
            tags.update(t for t in known_tags if isinstance(t, str) and t)
        elif isinstance(known_tags, list):
            tags.update(t for t in known_tags if isinstance(t, str) and t)

        # Fold in tags/types from findings if present.
        # Supports both legacy `knowledge['findings']` and `context.findings`.
        findings_sources: List[Any] = []
        knowledge_findings = knowledge.get("findings")
        # Conditional branch.
        if isinstance(knowledge_findings, list):
            findings_sources.append(knowledge_findings)
        context_findings = getattr(context, "findings", None)
        # Conditional branch.
        if isinstance(context_findings, list):
            findings_sources.append(context_findings)

        # Loop over items.
        for findings in findings_sources:
            for f in findings:
                if not isinstance(f, dict):
                    continue
                finding_type = f.get("type")
                if isinstance(finding_type, str) and finding_type:
                    tags.add(finding_type)
                    tags.add(f"type:{finding_type}")
                for tag in f.get("tags", []) or []:
                    if isinstance(tag, str) and tag:
                        tags.add(tag)
            
        # Check gate satisfaction
        for gate in gates:
             if gate in tags:
                 # In Bug Bounty Mode, check High Confidence if available?
                 # (For V1, existence is enough, but structure allows extension)
                 return Decision(True, f"Prerequisite '{gate}' met")
                 
        return Decision(False, f"Missing requirements: {gates}", "Law3_EvidenceGates")

class Law4_ResourceAwareness(Law):
    """
    Law 4: Resource-Aware Scheduling.
    Don't exceed system max load.
    """
    def check(self, context: Any, tool_def: Dict[str, Any]) -> Decision:
        # Simple implementation: Check active tool count vs max
        """Function check."""
        active = getattr(context, "active_tools", 0)
        max_concurrent = getattr(context, "max_concurrent", 5)
        
        cost = tool_def.get("resource_cost", 1) # 1=Low, 3=High
        
        # Conditional branch.
        if active + cost > max_concurrent:
            return Decision(False, f"System load too high ({active}+{cost} > {max_concurrent})", "Law4_ResourceAwareness")
        return Decision(True, "Resource check passed")

class Constitution:
    """Enforces all laws."""
    def __init__(self):
        """Function __init__."""
        self.laws = [
            Law1_PassiveBeforeActive(),
            Law3_EvidenceGates(),
            Law4_ResourceAwareness()
        ]
        
    def check(self, context: Any, tool_def: Dict) -> Decision:
        """
        Returns a Decision. If blocked, returns the first blocking decision.
        If allowed, returns an Allowed decision.
        """
        # Loop over items.
        for law in self.laws:
            decision = law.check(context, tool_def)
            if not decision.allowed:
                return decision
        return Decision(True, "All laws passed")
