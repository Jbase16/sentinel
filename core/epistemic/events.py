"""
Epistemic Events Module.

Defines the structure for events related to:
1. Contradictions (A says True, B says False)
2. Re-derivation (A was re-parsed, now says Maybe)
3. State Changes (Belief evolution)
"""

from dataclasses import dataclass, field
import time
from typing import Optional, Any, Dict
from enum import Enum

class ConflictType(str, Enum):
    DIRECT_CONTRADICTION = "direct_contradiction" # Open vs Closed
    STATE_MISMATCH = "state_mismatch"             # Service A vs Service B
    TEMPORAL_DRIFT = "temporal_drift"             # Was Open, Now Closed (maybe okay?)

@dataclass
class EpistemicConflict:
    """
    Event emitted when two observations disagree.
    """
    id: str
    source_a_id: str
    source_b_id: str
    conflict_type: ConflictType
    description: str
    timestamp: float = field(default_factory=time.time)

@dataclass
class FactRederived:
    """
    Event emitted when a Fact is re-calculated from the same Observation blob
    (e.g., after upgrading the parser).
    """
    observation_id: str
    old_fact_hash: str
    new_fact_hash: str
    diff_summary: str
    parser_version: str
    timestamp: float = field(default_factory=time.time)


class EventType(str, Enum):
    OBSERVED = "observed"
    PROMOTED = "promoted"
    SUPPRESSED = "suppressed"
    INVALIDATED = "invalidated"
    CONFLICT = "conflict"
    FACT_REDERIVED = "fact_rederived"


@dataclass(frozen=True)
class EpistemicEvent:
    """
    Immutable record of an epistemic change.
    The primary source of truth for the system history.
    """
    id: str
    event_type: EventType
    entity_id: str
    payload: Dict[str, Any]
    timestamp: float = field(default_factory=time.time)
    run_id: Optional[str] = None
    
@dataclass
class ConflictResolution:
    """
    Resolution of a specific conflict.
    """
    conflict_id: str
    resolution_observation_id: str
    outcome: str  # CONFIRMED_A | CONFIRMED_B | BOTH_INVALID
    timestamp: float = field(default_factory=time.time)
