"""
core/thanatos/ontology_breaker.py

Purpose:
    Defines the structural interfaces for the Ontology Breaker.
    This module generates "Heretic" protocol states - requests that violate
    conceptual axioms of the protocol (e.g., Infinite Content-Length).

Safety:
    Wrapper-only. No payload generation or network transmission.
    Guarded by SAFE_MODE.

Integration:
    - AnomalyClient: Consumes HereticRequest objects.
    - KnowledgeGraph: Stores discovered ontological flaws.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Protocol, Union

SAFE_MODE: bool = True

@dataclass(frozen=True)
class HereticRequest:
    """
    Represents a request that violates protocol axioms.
    Not a standard HTTP Request object.
    """
    method: str
    target: str
    headers: Dict[str, Union[str, int, float]]
    body: bytes
    axiom_violation_type: str  # e.g., "INTEGER_OVERFLOW", "VERB_INVENTION"

    def to_dict(self) -> Dict[str, Any]:
        """Serialize for storage/replay."""
        raise NotImplementedError("Wrapper-only: implementation deferred")

@dataclass
class HereticMutation:
    """
    Represents a raw byte-level mutation for socket fuzzing.
    Used by AnomalyClient.
    """
    raw_payload: bytes
    description: str = "Unknown Mutation"


class AxiomSynthesizer(Protocol):
    """Interface for generative logic that invents heretic states."""
    
    def generate_violation(self, base_request: Dict[str, Any], violation_type: str) -> HereticRequest:
        """Mutate a valid request into a heretic one."""
        ...

class OntologyBreakerService:
    """
    Main Service entry point for the Ontology Breaker.
    """

    def __init__(self):
        if not SAFE_MODE:
            raise RuntimeError("OntologyBreakerService initiated in unsafe mode (Not Implemented)")

    async def hallucinate_batch(self, seed_request: Dict[str, Any]) -> List[HereticRequest]:
        """
        Generate a batch of heretic requests from a seed.
        """
        raise NotImplementedError("Wrapper-only: implementation deferred")

    async def replay(self, artifact: Dict[str, Any]) -> None:
        """Replay a specific hallucination sequence."""
        raise NotImplementedError("Wrapper-only: replay deferred")

# Placeholder for registry integration
def register_ontology_breaker_hooks():
    """Stub for event system hookup."""
    pass
