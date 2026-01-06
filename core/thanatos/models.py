from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


class InvariantDomain(str, Enum):
    ECONOMIC = "ECONOMIC"
    AUTHZ = "AUTHZ"
    STATE = "STATE"
    DATA = "DATA"


class InvariantClass(str, Enum):
    # Money + accounting
    NON_NEGATIVE_AMOUNT = "NON_NEGATIVE_AMOUNT"
    CONSERVATION_OF_VALUE = "CONSERVATION_OF_VALUE"          # debits == credits, etc.
    ROUNDING_STABILITY = "ROUNDING_STABILITY"                # cents don’t appear/disappear
    IDENTITY_BINDING = "IDENTITY_BINDING"                    # action bound to authenticated principal

    # State machines
    VALID_STATE_TRANSITION = "VALID_STATE_TRANSITION"        # cannot jump A->Z
    IDEMPOTENCY = "IDEMPOTENCY"                              # duplicates don’t double-apply
    TEMPORAL_ORDERING = "TEMPORAL_ORDERING"                  # created_at <= updated_at, etc.

    # Authorization / policy
    AUTHZ_BOUNDARY = "AUTHZ_BOUNDARY"                        # caller cannot do admin-only action
    AUTHZ_EFFECT_SCOPE = "AUTHZ_EFFECT_SCOPE"                # authorized caller cannot affect out-of-scope entities
    TENANT_ISOLATION = "TENANT_ISOLATION"                    # cross-tenant access is impossible
    DATA = "DATA"                                            # General data integrity (types, boundaries)


class MutationOpType(str, Enum):
    # Declarative “ideas”, not raw payloads
    SET_NUMERIC_BELOW_MIN = "SET_NUMERIC_BELOW_MIN"
    SET_NUMERIC_ABOVE_MAX = "SET_NUMERIC_ABOVE_MAX"
    DUPLICATE_IDEMPOTENCY_KEY = "DUPLICATE_IDEMPOTENCY_KEY"
    SWAP_STATE_TRANSITION = "SWAP_STATE_TRANSITION"
    REMOVE_REQUIRED_FIELD = "REMOVE_REQUIRED_FIELD"
    REPLAY_PREVIOUS_REQUEST = "REPLAY_PREVIOUS_REQUEST"
    CROSS_TENANT_REFERENCE = "CROSS_TENANT_REFERENCE"
    
    # New V1 Operators
    TYPE_JUGGLING = "TYPE_JUGGLING"
    BOUNDARY_VIOLATION = "BOUNDARY_VIOLATION"
    AUTH_CONFUSION = "AUTH_CONFUSION"
    UNICODE_STORM = "UNICODE_STORM"


@dataclass(frozen=True)
class MutationSpec:
    """
    Declarative mutation spec. No raw exploit bytes.
    """
    op: MutationOpType
    params: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class OracleSpec:
    """
    How to detect a breach.
    Should be evaluated by a harness/instrumentation layer.
    """
    name: str
    expected: Dict[str, Any] = field(default_factory=dict)
    forbidden: Dict[str, Any] = field(default_factory=dict)
    fallbacks: List[str] = field(default_factory=list) # e.g. ["check_audit_logs", "infer_from_side_effects"]
    notes: str = ""


@dataclass(frozen=True)
class BreachHypothesis:
    """
    A testable claim: “Invariant X can be violated by mutation Y on target Z”.
    """
    invariant: InvariantClass
    domain: InvariantDomain
    rationale: str
    required_signals: List[str] = field(default_factory=list)  # e.g., "ledger_delta", "authz_decision", "state_change"


@dataclass(frozen=True)
class HereticMutation:
    """
    A low-level, raw mutation ready for wire transmission.
    Used by AnomalyClient for socket-level fuzzing.
    """
    raw_payload: bytes
    description: str

@dataclass(frozen=True)
class TargetHandle:
    """
    Pointer into the BusinessModelGraph (Aegis), not a direct network locator.
    """
    node_id: str
    endpoint: str
    method: str
    value: float
    tags: Tuple[str, ...] = ()


@dataclass(frozen=True)
class LogicTestCase:
    """
    The safe replacement for “HereticRequest”.
    """
    id: str
    target: TargetHandle
    hypothesis: BreachHypothesis
    mutation: MutationSpec
    oracle: OracleSpec
    priority: float  # Scale 0.0-1.0. Semantics: Analyst Attention & Pressure Weight. Higher = Check this first.
    provenance: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "target": {
                "node_id": self.target.node_id,
                "endpoint": self.target.endpoint,
                "method": self.target.method,
                "value": self.target.value,
                "tags": list(self.target.tags),
            },
            "hypothesis": {
                "invariant": self.hypothesis.invariant.value,
                "domain": self.hypothesis.domain.value,
                "rationale": self.hypothesis.rationale,
                "required_signals": list(self.hypothesis.required_signals),
            },
            "mutation": {
                "op": self.mutation.op.value,
                "params": self.mutation.params,
            },
            "oracle": {
                "name": self.oracle.name,
                "expected": self.oracle.expected,
                "forbidden": self.oracle.forbidden,
                "fallbacks": self.oracle.fallbacks,
                "notes": self.oracle.notes,
            },
            "priority": self.priority,
            "provenance": self.provenance,
        }
