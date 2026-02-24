from __future__ import annotations

import logging
from typing import Any, Dict, Protocol

import jsonschema

from .contracts.events import EventEnvelope
from .contracts.schemas import all_contract_schemas

logger = logging.getLogger(__name__)


class UnderlyingBus(Protocol):
    """
    Protocol matching Sentinel's actual internal event bus dispatcher, 
    so the StrictEventBus can inject the structural enforcement adapter pattern.
    """
    def emit(self, event_type: str, payload: Dict[str, Any]) -> None:
        ...


class StrictEventBus:
    """
    Zero-trust event bus adapter that enforces strict JSON Schema validation
    on all emitted events before piping them to the underlying system bus.
    """
    def __init__(self, underlying_bus: UnderlyingBus, strict_mode: bool = True) -> None:
        self._underlying_bus = underlying_bus
        self._strict_mode = strict_mode
        self._schemas = all_contract_schemas()
        self._envelope_schema = self._schemas.get("EventEnvelope")

        if not self._envelope_schema:
            raise RuntimeError("EventEnvelope schema goes inexplicably missing in StrictEventBus")

    def emit(self, event: EventEnvelope) -> None:
        # Dump using JSON logic so datetimes and nested models are primitives 
        dumped = event.model_dump(mode="json")

        try:
            # 1. Validate envelope strict structure
            jsonschema.validate(instance=dumped, schema=self._envelope_schema)

            # 2. Extract specific payload schema corresponding to this typing
            event_type = dumped["event_type"]
            payload = dumped.get("payload", {})

            if event_type in self._schemas:
                payload_schema = self._schemas[event_type]
                jsonschema.validate(instance=payload, schema=payload_schema)
            else:
                # If we don't have a specific schema locked down, log a severe warning
                logger.warning(f"[StrictEventBus] No structural payload schema registered for {event_type}")

        except jsonschema.ValidationError as e:
            logger.error(f"[StrictEventBus] Validation failed for {event.event_type}: {e.message}")
            if self._strict_mode:
                raise ValueError(f"Strict Event validation failure: {e.message}") from e

        # Forward the validated structural dictionary to the real system event bus
        self._underlying_bus.emit(dumped["event_type"], dumped)
