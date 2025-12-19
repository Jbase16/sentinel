# core/cortex/authority.py
"""
SCAN AUTHORITY: Single Source of Truth for Scan Lifecycle

This module implements a hierarchical Finite State Machine (FSM) that owns
all scan state. No other component may directly modify scan state - all
state changes flow through the Authority.

DESIGN PRINCIPLES:
1. **Single Source of Truth**: Authority is the ONLY source for "is scan running?"
2. **Hierarchical State**: Scan → Phase → Tool (nested FSMs)
3. **Justified Transitions**: Every state change has a recorded reason
4. **Event-Emitting**: All transitions emit events to EventBus
5. **Query-Friendly**: External code queries, never mutates directly

USAGE:
    from core.cortex.authority import ScanAuthority, get_scan_authority
    
    authority = get_scan_authority()
    
    # Start a scan (returns new state)
    authority.start_scan(target="http://example.com", session_id="abc")
    
    # Query state (pure read)
    if authority.is_running:
        print(f"Scan active: {authority.current_target}")
    
    # Tool lifecycle (nested FSM)
    authority.tool_started("nmap")
    authority.tool_completed("nmap", exit_code=0, findings_count=5)

WHY THIS IS BETTER THAN CONVENTIONAL APPROACHES:
- Conventional: `scan_running = True` scattered in 4+ places
  Problem: State can drift, no audit trail, race conditions
  
- This approach: Centralized FSM with immutable transitions
  Benefit: Always consistent, fully auditable, testable isolation
"""

from __future__ import annotations

import time
import threading
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Set, TYPE_CHECKING
import logging

if TYPE_CHECKING:
    from core.cortex.events import EventBus

logger = logging.getLogger(__name__)


# ============================================================================
# Scan States
# ============================================================================

class ScanState(str, Enum):
    """
    Top-level scan lifecycle states.
    
    State transition diagram:
    
        IDLE ──start──► STARTING ──ready──► RUNNING ──complete──► COMPLETING ──done──► COMPLETE
                                     │                                           │
                                     ├──pause──► PAUSED ──resume──┘             │
                                     │                                           │
                                     └──error──────────────────────────────────► FAILED
    """
    IDLE = "idle"              # No scan active
    STARTING = "starting"      # Scan initialization in progress
    RUNNING = "running"        # Scan actively executing tools
    PAUSED = "paused"          # Scan temporarily suspended
    COMPLETING = "completing"  # Scan finishing up (final reports)
    COMPLETE = "complete"      # Scan finished successfully
    FAILED = "failed"          # Scan terminated with error


class PhaseState(str, Enum):
    """Phases within a running scan."""
    PASSIVE_RECON = "passive_recon"
    ACTIVE_LIVE = "active_live"
    SURFACE_ENUM = "surface_enum"
    VULN_SCAN = "vuln_scan"
    HEAVY_ARTILLERY = "heavy_artillery"


# ============================================================================
# Transition Record
# ============================================================================

@dataclass(frozen=True)
class Transition:
    """
    Immutable record of a state transition.
    """
    from_state: ScanState
    to_state: ScanState
    reason: str
    timestamp: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)


# ============================================================================
# Tool State Tracker
# ============================================================================

@dataclass
class ToolState:
    """State of a single tool execution."""
    name: str
    started_at: float
    completed_at: Optional[float] = None
    exit_code: Optional[int] = None
    findings_count: int = 0
    
    @property
    def is_running(self) -> bool:
        return self.completed_at is None
    
    @property
    def duration(self) -> Optional[float]:
        if self.completed_at:
            return self.completed_at - self.started_at
        return None


# ============================================================================
# Scan Authority
# ============================================================================

class ScanAuthority:
    """
    The authoritative source of scan lifecycle state.
    
    Invariants:
    - Only one scan may be active at a time
    - State transitions are atomic (thread-safe)
    - All transitions emit events and are logged
    - External code MUST query state, never set it directly
    
    Thread Safety:
    - All state mutations are protected by RLock
    - Event emission happens outside the lock to prevent deadlock
    """
    
    def __init__(self, event_bus: Optional[EventBus] = None):
        """Initialize authority in IDLE state."""
        self._lock = threading.RLock()
        self._event_bus = event_bus
        
        # Core state
        self._state: ScanState = ScanState.IDLE
        self._session_id: Optional[str] = None
        self._target: Optional[str] = None
        self._phase: Optional[PhaseState] = None
        
        # Transition history (audit trail)
        self._transitions: List[Transition] = []
        
        # Tool tracking
        self._tools: Dict[str, ToolState] = {}  # name -> ToolState
        self._tool_order: List[str] = []  # Ordered list of started tools
        
        # Metrics
        self._started_at: Optional[float] = None
        self._completed_at: Optional[float] = None
        self._findings_count: int = 0
    
    # ================================================================
    # Query Methods (Read-Only, Thread-Safe)
    # ================================================================
    
    @property
    def state(self) -> ScanState:
        """Current scan state."""
        with self._lock:
            return self._state
    
    @property
    def is_running(self) -> bool:
        """True if scan is actively executing."""
        with self._lock:
            return self._state in (ScanState.STARTING, ScanState.RUNNING)
    
    @property
    def is_active(self) -> bool:
        """True if scan is in any non-idle state."""
        with self._lock:
            return self._state != ScanState.IDLE
    
    @property
    def is_paused(self) -> bool:
        """True if scan is paused."""
        with self._lock:
            return self._state == ScanState.PAUSED
    
    @property
    def current_target(self) -> Optional[str]:
        """Current scan target."""
        with self._lock:
            return self._target
    
    @property
    def current_session_id(self) -> Optional[str]:
        """Current session ID."""
        with self._lock:
            return self._session_id
    
    @property
    def current_phase(self) -> Optional[PhaseState]:
        """Current scan phase."""
        with self._lock:
            return self._phase
    
    @property
    def active_tools(self) -> List[str]:
        """List of currently running tool names."""
        with self._lock:
            return [name for name, ts in self._tools.items() if ts.is_running]
    
    @property
    def findings_count(self) -> int:
        """Total findings discovered in current scan."""
        with self._lock:
            return self._findings_count
    
    @property
    def duration(self) -> Optional[float]:
        """Duration of current scan in seconds."""
        with self._lock:
            if self._started_at is None:
                return None
            end = self._completed_at or time.time()
            return end - self._started_at
    
    @property
    def progress(self) -> Dict[str, Any]:
        """Get current scan progress snapshot."""
        with self._lock:
            return {
                "state": self._state.value,
                "target": self._target,
                "session_id": self._session_id,
                "phase": self._phase.value if self._phase else None,
                "tools_started": len(self._tool_order),
                "tools_running": len(self.active_tools),
                "findings_count": self._findings_count,
                "duration_seconds": self.duration,
            }
    
    # ================================================================
    # Mutation Methods (State Changes)
    # ================================================================
    
    def start_scan(
        self,
        target: str,
        session_id: str,
        allowed_tools: List[str],
        mode: str = "standard"
    ) -> bool:
        """
        Start a new scan.
        
        Returns True if scan started, False if already running.
        """
        with self._lock:
            if self._state not in (ScanState.IDLE, ScanState.COMPLETE, ScanState.FAILED):
                logger.warning(f"[Authority] Cannot start scan: already in state {self._state}")
                return False
            
            old_state = self._state
            self._state = ScanState.STARTING
            self._target = target
            self._session_id = session_id
            self._started_at = time.time()
            self._completed_at = None
            self._findings_count = 0
            self._tools.clear()
            self._tool_order.clear()
            
            transition = Transition(
                from_state=old_state,
                to_state=ScanState.STARTING,
                reason=f"Scan initiated for {target}",
                metadata={"target": target, "session_id": session_id, "mode": mode}
            )
            self._transitions.append(transition)
        
        # Emit outside lock
        self._emit_scan_started(target, session_id, allowed_tools)
        
        # Immediately transition to RUNNING
        self._transition_to(ScanState.RUNNING, "Initialization complete")
        return True
    
    def phase_changed(self, phase: PhaseState, previous: Optional[PhaseState] = None) -> None:
        """Record phase transition."""
        with self._lock:
            if self._state != ScanState.RUNNING:
                logger.warning(f"[Authority] Phase change ignored: not running")
                return
            
            self._phase = phase
        
        # Emit outside lock
        if self._event_bus:
            self._event_bus.emit_scan_phase_changed(
                phase=phase.value,
                previous_phase=previous.value if previous else None
            )
    
    def tool_started(self, tool: str, target: str, args: List[str] = None) -> None:
        """Record tool start."""
        with self._lock:
            if tool in self._tools and self._tools[tool].is_running:
                logger.warning(f"[Authority] Tool {tool} already running")
                return
            
            self._tools[tool] = ToolState(name=tool, started_at=time.time())
            self._tool_order.append(tool)
        
        # Emit outside lock
        if self._event_bus:
            self._event_bus.emit_tool_started(tool=tool, target=target, args=args or [])
    
    def tool_completed(self, tool: str, exit_code: int, findings_count: int) -> None:
        """Record tool completion."""
        with self._lock:
            if tool not in self._tools:
                logger.warning(f"[Authority] Tool {tool} was never started")
                return
            
            ts = self._tools[tool]
            ts.completed_at = time.time()
            ts.exit_code = exit_code
            ts.findings_count = findings_count
            self._findings_count += findings_count
        
        # Emit outside lock
        if self._event_bus:
            self._event_bus.emit_tool_completed(
                tool=tool,
                exit_code=exit_code,
                findings_count=findings_count
            )
    
    def complete_scan(self, status: str = "success") -> None:
        """Mark scan as complete."""
        self._transition_to(ScanState.COMPLETING, "Finalizing results")
        
        with self._lock:
            self._completed_at = time.time()
            findings = self._findings_count
            duration = self.duration
        
        # Emit outside lock
        if self._event_bus:
            self._event_bus.emit_scan_completed(
                status=status,
                findings_count=findings,
                duration_seconds=duration
            )
        
        self._transition_to(ScanState.COMPLETE, f"Scan completed: {status}")
    
    def fail_scan(self, error: str) -> None:
        """Mark scan as failed."""
        with self._lock:
            self._completed_at = time.time()
        
        # Emit outside lock
        if self._event_bus:
            self._event_bus.emit_scan_failed(error=error)
        
        self._transition_to(ScanState.FAILED, f"Scan failed: {error}")
    
    def pause_scan(self, reason: str = "User requested pause") -> None:
        """Pause the scan."""
        if self._state == ScanState.RUNNING:
            self._transition_to(ScanState.PAUSED, reason)
    
    def resume_scan(self) -> None:
        """Resume a paused scan."""
        if self._state == ScanState.PAUSED:
            self._transition_to(ScanState.RUNNING, "Scan resumed")
    
    def reset(self) -> None:
        """Reset to IDLE state (for testing or new session)."""
        with self._lock:
            self._state = ScanState.IDLE
            self._session_id = None
            self._target = None
            self._phase = None
            self._started_at = None
            self._completed_at = None
            self._findings_count = 0
            self._tools.clear()
            self._tool_order.clear()
            self._transitions.clear()
    
    # ================================================================
    # Internal Methods
    # ================================================================
    
    def _transition_to(self, new_state: ScanState, reason: str) -> None:
        """Internal state transition with logging."""
        with self._lock:
            old_state = self._state
            self._state = new_state
            
            transition = Transition(
                from_state=old_state,
                to_state=new_state,
                reason=reason
            )
            self._transitions.append(transition)
        
        logger.info(f"[Authority] {old_state.value} → {new_state.value}: {reason}")
    
    def _emit_scan_started(
        self,
        target: str,
        session_id: str,
        allowed_tools: List[str]
    ) -> None:
        """Emit scan_started event."""
        if self._event_bus:
            self._event_bus.emit_scan_started(
                target=target,
                session_id=session_id,
                allowed_tools=allowed_tools
            )
    
    # ================================================================
    # Audit Trail
    # ================================================================
    
    def get_transitions(self) -> List[Transition]:
        """Get full transition history."""
        with self._lock:
            return list(self._transitions)
    
    def get_tool_history(self) -> List[Dict[str, Any]]:
        """Get tool execution history."""
        with self._lock:
            return [
                {
                    "name": ts.name,
                    "started_at": ts.started_at,
                    "completed_at": ts.completed_at,
                    "exit_code": ts.exit_code,
                    "findings_count": ts.findings_count,
                    "duration": ts.duration,
                }
                for ts in self._tools.values()
            ]


# ============================================================================
# Module-Level Singleton
# ============================================================================

_authority: Optional[ScanAuthority] = None
_authority_lock = threading.Lock()


def get_scan_authority(event_bus: Optional[EventBus] = None) -> ScanAuthority:
    """
    Get the global ScanAuthority singleton.
    
    The first call with event_bus sets the bus for all future emission.
    Subsequent calls ignore the event_bus parameter.
    """
    global _authority
    if _authority is None:
        with _authority_lock:
            if _authority is None:
                _authority = ScanAuthority(event_bus=event_bus)
    return _authority


def reset_scan_authority() -> None:
    """Reset the singleton (for testing)."""
    global _authority
    if _authority:
        _authority.reset()
    _authority = None


# ============================================================================
# Self-Test
# ============================================================================

if __name__ == "__main__":
    print("Running ScanAuthority self-test...")
    
    authority = ScanAuthority()
    
    # Test initial state
    assert authority.state == ScanState.IDLE
    assert not authority.is_running
    print("✓ Initial state is IDLE")
    
    # Test scan start
    result = authority.start_scan(
        target="http://example.com",
        session_id="test-123",
        allowed_tools=["nmap", "httpx"]
    )
    assert result is True
    assert authority.is_running
    assert authority.current_target == "http://example.com"
    print("✓ Scan started successfully")
    
    # Test tool lifecycle
    authority.tool_started("nmap", target="http://example.com")
    assert "nmap" in authority.active_tools
    print("✓ Tool started")
    
    authority.tool_completed("nmap", exit_code=0, findings_count=5)
    assert "nmap" not in authority.active_tools
    assert authority.findings_count == 5
    print("✓ Tool completed")
    
    # Test scan completion
    authority.complete_scan()
    assert authority.state == ScanState.COMPLETE
    assert not authority.is_running
    print("✓ Scan completed")
    
    # Test cannot start while complete (should allow restart)
    result = authority.start_scan(
        target="http://test2.com",
        session_id="test-456",
        allowed_tools=[]
    )
    assert result is True  # Can restart after complete
    print("✓ Can restart after complete")
    
    # Test transition history
    transitions = authority.get_transitions()
    assert len(transitions) > 0
    print(f"✓ Recorded {len(transitions)} transitions")
    
    print("\n✅ All ScanAuthority tests passed!")
