"""
core/thanatos/meta_observer.py

Purpose:
    Defines the structural interfaces for the Meta-Observer.
    This module implements "Existential Control" - a supervisor that monitors
    the primary agent for tunnel vision (low entropy) and forces
    context switching (Goal Reframing).

Safety:
    Wrapper-only. No intervention logic active.
    Interfaces defined for entropy monitoring.

Integration:
    - EventBus: Listens for tool outputs (to calculate entropy).
    - DecisionContext: Overrides current goals.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Dict, Protocol

SAFE_MODE: bool = True

@dataclass
class CognitiveState:
    """Snapshot of the agent's current focus and entropy."""
    current_goal: str
    entropy_score: float  # 0.0 (Bored) - 1.0 (Chaotic)
    time_in_state: float
    is_tunneled: bool

    def to_dict(self) -> Dict[str, Any]:
        raise NotImplementedError("Wrapper-only: implementation deferred")

class EntropyMonitor(Protocol):
    """Interface for calculating Shannon Entropy of agent actions."""
    
    def update(self, action_signature: str) -> None:
        """Add action to rolling window."""
        ...

    def get_entropy(self) -> float:
        """Calculate entropy of recent window."""
        ...

class ObserverService:
    """
    Main Service entry point for the Meta-Observer.
    """

    def __init__(self):
        if not SAFE_MODE:
            raise RuntimeError("ObserverService initiated in unsafe mode (Not Implemented)")

    async def check_state(self) -> CognitiveState:
        """Evaluate if the Hunter is bored or obsessed."""
        raise NotImplementedError("Wrapper-only: implementation deferred")

    async def trigger_intervention(self, reason: str) -> None:
        """Force a goal reframe."""
        raise NotImplementedError("Wrapper-only: implementation deferred")

    async def replay(self, artifact: Dict[str, Any]) -> None:
        """Replay a cognitive timeline."""
        raise NotImplementedError("Wrapper-only: replay deferred")
