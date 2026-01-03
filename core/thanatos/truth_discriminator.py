"""
core/thanatos/truth_discriminator.py

Purpose:
    Defines the structural interfaces for the Truth Discriminator.
    This module implements "Adversarial Psychology" - detecting deception environments
    (Honeypots) by analyzing the 'uncanny valley' of server responses.

Safety:
    Wrapper-only. No honeypot detection logic active.
    Interfaces defined for metric collection.

Integration:
    - AnomalyClient/GhostProxy: Sources of response metrics.
    - DecisionLedger: Flags targets as 'DECEPTIVE'.
    - EventBus: Emits 'HONEYPOT_DETECTED'.
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Dict, List, Protocol

SAFE_MODE: bool = True

@dataclass(frozen=True)
class RealismMetrics:
    """The 'Vibe Check' metrics for a target."""
    timing_variance: float  # Jitter standard deviation
    error_uniqueness: float # Entropy of stack traces
    success_rate: float     # suspicious if 1.0
    
    def to_dict(self) -> Dict[str, Any]:
        raise NotImplementedError("Wrapper-only: implementation deferred")

class DeceptionScanner(Protocol):
    """Interface for analyzing server realism."""
    
    def update_metrics(self, response_time: float, response_body: bytes) -> None:
        """Feed the analyzer."""
        ...
    
    def get_verdict(self) -> float:
        """Return Probability of Honeypot (0.0 - 1.0)."""
        ...

class TruthService:
    """
    Main Service entry point for the Truth Discriminator.
    """

    def __init__(self):
        if not SAFE_MODE:
            raise RuntimeError("TruthService initiated in unsafe mode (Not Implemented)")

    async def analyze_session(self, session_id: str) -> float:
        """
        Analyze an entire session's traffic for deception markers.
        Returns realism score (1.0 = Real, 0.0 = Fake).
        """
        raise NotImplementedError("Wrapper-only: implementation deferred")

    async def replay(self, artifact: Dict[str, Any]) -> None:
        """Replay analysis on stored traffic metrics."""
        raise NotImplementedError("Wrapper-only: replay deferred")
