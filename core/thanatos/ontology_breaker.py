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

SAFE_MODE: bool = False  # ACTIVATED

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
        return {
            "method": self.method,
            "target": self.target,
            "headers": self.headers,
            "body": self.body.decode('utf-8', errors='replace'),
            "axiom_violation_type": self.axiom_violation_type
        }

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

class StandardAxiomSynthesizer:
    """
    Default implementation of logic breaker.
    Generates specific ontological violations.
    """
    
    def generate_violation(self, base_request: Dict[str, Any], violation_type: str) -> HereticRequest:
        base_method = base_request.get("method", "GET")
        base_target = base_request.get("target", "/")
        base_headers = base_request.get("headers", {})
        base_body = base_request.get("body", b"")
        
        if violation_type == "VERB_INVENTION":
            # Violation: HTTP verbs are a closed set.
            # Heretic: Invent a verb that implies a privileged action.
            return HereticRequest(
                method="FORCE_ADMIN", # Heretic Verb
                target=base_target,
                headers=base_headers,
                body=base_body,
                axiom_violation_type="VERB_INVENTION"
            )
            
        elif violation_type == "INTEGER_OVERFLOW":
            # Violation: Quantities are bounded.
            # Heretic: Use values exceeding 64-bit integers.
            # We assume a header injection for this simple example.
            headers = base_headers.copy()
            headers["X-Quantity"] = "9223372036854775808" # MAX_INT64 + 1
            return HereticRequest(
                method=base_method,
                target=base_target,
                headers=headers,
                body=base_body,
                axiom_violation_type="INTEGER_OVERFLOW"
            )

        elif violation_type == "NULL_TERMINATOR_INJECTION":
             # Violation: HTTP headers are text.
             # Heretic: Inject null bytes to confuse C-based parsers.
             headers = base_headers.copy()
             headers["X-Injection"] = "Value\0Captured"
             return HereticRequest(
                 method=base_method,
                 target=base_target,
                 headers=headers,
                 body=base_body,
                 axiom_violation_type="NULL_TERMINATOR_INJECTION"
             )
             
        # Default fallback
        return HereticRequest(
            method=base_method,
            target=base_target,
            headers=base_headers,
            body=base_body,
            axiom_violation_type="UNKNOWN"
        )

class OntologyBreakerService:
    """
    Main Service entry point for the Ontology Breaker.
    """

    def __init__(self):
        self.synthesizer = StandardAxiomSynthesizer()

    async def hallucinate_batch(self, seed_request: Dict[str, Any]) -> List[HereticRequest]:
        """
        Generate a batch of heretic requests from a seed.
        """
        mutations = []
        violation_types = ["VERB_INVENTION", "INTEGER_OVERFLOW", "NULL_TERMINATOR_INJECTION"]
        
        for v_type in violation_types:
            mutation = self.synthesizer.generate_violation(seed_request, v_type)
            mutations.append(mutation)
            
        return mutations

    async def replay(self, artifact: Dict[str, Any]) -> None:
        """Replay a specific hallucination sequence."""
        # TODO: Implement replay logic using an HTTP client (raw socket preferred for heretic reqs)
        pass

# Placeholder for registry integration
def register_ontology_breaker_hooks():
    """Stub for event system hookup."""
    pass
