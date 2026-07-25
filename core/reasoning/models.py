from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

@dataclass
class Confidence:
    """
    Monotonic, bounded confidence arithmetic.
    Range: [0.0, 1.0]
    """
    value: float = 0.0

    def __post_init__(self):
        self.value = max(0.0, min(1.0, self.value))

    def add(self, delta: float, reason: str = "") -> None:
        """Add positive evidence."""
        old = self.value
        self.value = max(0.0, min(1.0, self.value + delta))
        
    def decay(self, factor: float = 0.9, reason: str = "") -> None:
        """Apply decay or negative evidence."""
        self.value = max(0.0, min(1.0, self.value * factor))

    def __float__(self) -> float:
        return self.value
        
    def __str__(self) -> str:
        return f"{self.value:.2f}"

@dataclass
class Hypothesis:
    """
    In-memory representation of a probabilistic assertion.
    Strictly separated from KnowledgeGraph nodes.
    """
    hypothesis_id: str
    scan_id: str
    rule_id: str
    summary: str
    
    # Evidence tracking
    sources: Set[str] = field(default_factory=set) # IDs of supporting facts
    confidence: Confidence = field(default_factory=Confidence)
    explanation: List[str] = field(default_factory=list)
    
    # State
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    state: str = "active" # active, confirmed, refuted
    
    def add_evidence(self, source_id: str, confidence_delta: float, reason: str):
        if source_id in self.sources:
            return # No double counting
            
        self.sources.add(source_id)
        self.confidence.add(confidence_delta)
        self.explanation.append(f"[{time.strftime('%H:%M:%S')}] +{confidence_delta:.2f}: {reason} (Ref: {source_id})")
        self.updated_at = time.time()

    def refute(self, reason: str):
        self.state = "refuted"
        self.confidence.value = 0.0
        self.explanation.append(f"[{time.strftime('%H:%M:%S')}] REFUTED: {reason}")
        self.updated_at = time.time()
        
    def confirm(self, reason: str):
        self.state = "confirmed"
        self.confidence.value = 1.0
        self.explanation.append(f"[{time.strftime('%H:%M:%S')}] CONFIRMED: {reason}")
        self.updated_at = time.time()
