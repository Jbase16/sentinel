# core/contracts/__init__.py
"""
Contracts Package: Formal specifications for system boundaries.

This package contains machine-readable contracts that define the
authoritative behavior of system interfaces.

Modules:
    events: Event type taxonomy, field specs, and causal rules
"""

from core.contracts.events import (
    EventContract,
    EventType,
    EventSchema,
    FieldSpec,
    ContractViolation,
    validate_event,
    get_event_schema,
)

__all__ = [
    "EventContract",
    "EventType", 
    "EventSchema",
    "FieldSpec",
    "ContractViolation",
    "validate_event",
    "get_event_schema",
]
