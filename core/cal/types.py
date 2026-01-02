"""Module types: inline documentation for /Users/jason/Developer/sentinelforge/core/cal/types.py."""
#
# PURPOSE:
# Defines the immutable data structures that form the basis of CAL's argumentation logic.
#
# PHILOSOPHY:
# - Everything is Evidence-Based: You cannot assert a Claim without Evidence.
# - Validation is Explicit: Claims have a lifecycle (Pending -> Validated/Rejected).
# - Provenance is Critical: We must always know WHO said WHAT and WHEN.
#
# KEY TYPES:
# - Evidence: A fact about the world (e.g., "Nmap Output").
# - Claim: A hypothesis derived from evidence (e.g., "Port 80 is Open").
# - Provenance: Metadata about the source (Agent, Timestamp, Confidence).
#

from __future__ import annotations
import uuid
import time
from enum import Enum
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field

# ============================================================================
# Enums
# ============================================================================

class ValidationStatus(str, Enum):
    """The lifecycle state of a Claim."""
    PENDING = "pending"         # Newly asserted, not yet reviewed
    VALIDATED = "validated"     # Confirmed by a second source or logic rule
    REJECTED = "rejected"       # Proven false by contradictory evidence
    DISPUTED = "disputed"       # Conflicting evidence exists (needs Arbitration)
    UNKNOWN = "unknown"         # Insufficient evidence to decide

class Confidence(float, Enum):
    """Standard confidence levels for Evidence."""
    CERTAIN = 1.0           # Mathematical proof / Direct observation
    VERY_HIGH = 0.9         # Multi-tool confirmation
    HIGH = 0.8              # Reliable tool output
    MEDIUM = 0.5            # Heuristic / Pattern match
    LOW = 0.2               # Guess / Weak signal
    NONE = 0.0              # No confidence

# ============================================================================
# Core Primitives
# ============================================================================

@dataclass
class Provenance:
    """
    Metadata tracking the origin of a piece of information.
    Answers: "Who said this?"
    """
    source: str                     # e.g., "Scanner:Nmap", "Agent:ReasoningEngine"
    timestamp: float = field(default_factory=time.time)
    method: str = "automated"       # "automated", "manual", "inference"
    run_id: Optional[str] = None    # To correlate with specific execution runs

@dataclass
class Evidence:
    """
    An immutable fact collected from the environment.
    Evidence is the "Ground Truth" used to support or dispute Claims.
    """
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    content: Any = None             # The raw data (dict, string, bytes)
    description: str = ""           # Human-readable summary
    provenance: Provenance = field(default_factory=lambda: Provenance("system"))
    confidence: float = 1.0         # 0.0 to 1.0

    def to_dict(self) -> Dict:
        """Serialize for storage/transport."""
        return {
            "id": self.id,
            "content": self.content,
            "description": self.description,
            "provenance": {
                "source": self.provenance.source,
                "timestamp": self.provenance.timestamp
            },
            "confidence": self.confidence
        }

@dataclass
class Claim:
    """
    A hypothesis or assertion about the target system.
    Claims are NOT facts; they are arguments waiting to be validated.
    """
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    statement: str = ""             # e.g., "Host is vulnerable to XSS"
    
    # Argumentation Structure
    supported_by: List[Evidence] = field(default_factory=list)
    disputed_by: List[Evidence] = field(default_factory=list)
    
    # State
    status: ValidationStatus = ValidationStatus.PENDING
    confidence: float = 0.5         # Dynamic confidence score based on evidence
    metadata: Dict[str, Any] = field(default_factory=dict)

    def add_support(self, evidence: Evidence):
        """Add supporting evidence and boost confidence."""
        self.supported_by.append(evidence)
        # Simple Bayesian-like update (conceptual)
        self.confidence = min(1.0, self.confidence + (0.4 * evidence.confidence))
        if self.confidence > 0.8 and self.status == ValidationStatus.PENDING:
            self.status = ValidationStatus.VALIDATED

    def add_dispute(self, evidence: Evidence):
        """Add contradictory evidence and lower confidence."""
        self.disputed_by.append(evidence)
        self.confidence = max(0.0, self.confidence - (0.2 * evidence.confidence))
        if self.confidence < 0.2:
            self.status = ValidationStatus.REJECTED
        else:
            self.status = ValidationStatus.DISPUTED

    def to_dict(self) -> Dict:
        """Serialize."""
        return {
            "id": self.id,
            "statement": self.statement,
            "status": self.status,
            "confidence": self.confidence,
            "support_count": len(self.supported_by),
            "dispute_count": len(self.disputed_by),
            "metadata": self.metadata
        }
