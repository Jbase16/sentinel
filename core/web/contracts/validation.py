from __future__ import annotations

import json
from typing import Any, Dict, Optional

from pydantic import BaseModel

from .errors import ContractViolation
from .events import EventEnvelope
from .schemas import all_contract_schemas


def validate_pydantic(model_cls: type[BaseModel], data: Dict[str, Any]) -> BaseModel:
    try:
        return model_cls.model_validate(data)
    except Exception as e:
        raise ContractViolation(f"Contract validation failed for {model_cls.__name__}: {e}") from e


def validate_event_envelope(data: Dict[str, Any]) -> EventEnvelope:
    return validate_pydantic(EventEnvelope, data)  # type: ignore[return-value]


def dump_schema(name: str) -> str:
    schemas = all_contract_schemas()
    if name not in schemas:
        raise KeyError(f"Unknown schema: {name}")
    return json.dumps(schemas[name], indent=2, sort_keys=True)


def dump_all_schemas() -> Dict[str, str]:
    schemas = all_contract_schemas()
    return {k: json.dumps(v, indent=2, sort_keys=True) for k, v in schemas.items()}
