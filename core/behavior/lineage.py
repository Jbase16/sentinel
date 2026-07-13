"""Exact, in-memory value lineage and transport-free plan rehydration.

This module connects a producer response field to a later consumer request field
only when the same semantic capability and exact value were observed, in order,
inside one isolated world. Public contracts contain hashes and locators only.
Raw values and request templates remain private to the in-memory ledger and are
never exposed by diagnostic serialization.
"""

from __future__ import annotations

import copy
import json
import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Iterable, Mapping, Optional, Sequence, Tuple
from urllib.parse import parse_qsl, unquote, urlsplit

from .compiler import (
    ANALYSIS_ONLY_MODE,
    BackwardPlan,
    Capability,
    OperationCatalogLimits,
    OperationContract,
    operation_contracts_from_records,
    value_capability_for_field_path,
)
from .normalize import normalize_exchange, stable_hash

_DYNAMIC_PATH_VALUE = re.compile(
    r"^(?:\d{4,}|[A-Za-z0-9_-]{16,128}|[0-9a-fA-F]{8}-[0-9a-fA-F-]{27,})$"
)
_PATH_ACTION_TERMS = frozenset(
    {
        "admin",
        "api",
        "complete",
        "create",
        "delete",
        "download",
        "export",
        "graphql",
        "import",
        "new",
        "recover",
        "reset",
        "status",
        "update",
        "upload",
        "v1",
        "v2",
        "v3",
        "verify",
    }
)
_SENSITIVE_CAPABILITY = re.compile(
    r"(?:^|[_.:-])(?:credential|key|secret|session|token)(?:$|[_.:-])",
    re.IGNORECASE,
)


class LocatorKind(str, Enum):
    REQUEST_JSON = "request_json"
    REQUEST_FORM = "request_form"
    REQUEST_PATH = "request_path"
    REQUEST_QUERY = "request_query"
    RESPONSE_JSON = "response_json"


@dataclass(frozen=True)
class ValueLocator:
    kind: LocatorKind
    pointer: str

    def __post_init__(self) -> None:
        if not isinstance(self.kind, LocatorKind):
            raise ValueError("locator kind must be a LocatorKind")
        if not self.pointer.startswith("/") or len(self.pointer) > 1_024:
            raise ValueError("locator pointer must be a bounded absolute pointer")
        if any(ord(character) < 0x20 for character in self.pointer):
            raise ValueError("locator pointer contains a control character")

    def to_dict(self) -> Dict[str, str]:
        return {"kind": self.kind.value, "pointer": self.pointer}


@dataclass(frozen=True)
class LineageLimits:
    max_occurrences: int = 32_768
    max_bindings: int = 16_384
    max_value_chars: int = 4_096

    def __post_init__(self) -> None:
        for name, value in vars(self).items():
            if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")


@dataclass(frozen=True)
class OperationObservation:
    operation_id: str
    source_ref: str
    world_ref: str
    record_index: int
    request_digest: str
    response_status: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "operation_id": self.operation_id,
            "source_ref": self.source_ref,
            "world_ref": self.world_ref,
            "record_index": self.record_index,
            "request_digest": self.request_digest,
            "response_status": self.response_status,
        }


@dataclass(frozen=True)
class LineageBinding:
    binding_id: str
    capability: Capability
    value_hash: str
    world_ref: str
    producer_operation_id: str
    producer_source_ref: str
    producer_locator: ValueLocator
    consumer_operation_id: str
    consumer_source_ref: str
    consumer_locator: ValueLocator
    sensitive: bool

    def to_dict(self) -> Dict[str, Any]:
        return {
            "binding_id": self.binding_id,
            "capability": self.capability.to_dict(),
            "value_hash": self.value_hash,
            "world_ref": self.world_ref,
            "producer_operation_id": self.producer_operation_id,
            "producer_source_ref": self.producer_source_ref,
            "producer_locator": self.producer_locator.to_dict(),
            "consumer_operation_id": self.consumer_operation_id,
            "consumer_source_ref": self.consumer_source_ref,
            "consumer_locator": self.consumer_locator.to_dict(),
            "sensitive": self.sensitive,
        }


@dataclass(frozen=True)
class RehydrationStepTemplate:
    operation_id: str
    source_ref: str
    world_ref: str
    request_digest: str

    def to_dict(self) -> Dict[str, str]:
        return {
            "operation_id": self.operation_id,
            "source_ref": self.source_ref,
            "world_ref": self.world_ref,
            "request_digest": self.request_digest,
        }


@dataclass(frozen=True)
class RehydrationRecipe:
    recipe_id: str
    plan_id: str
    capture_digest: str
    catalog_digest: str
    world_ref: str
    status: str
    steps: Tuple[RehydrationStepTemplate, ...]
    bindings: Tuple[LineageBinding, ...]
    validation_errors: Tuple[str, ...]
    execution_blockers: Tuple[str, ...]
    mode: str = ANALYSIS_ONLY_MODE
    executable: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": 1,
            "mode": self.mode,
            "executable": self.executable,
            "recipe_id": self.recipe_id,
            "plan_id": self.plan_id,
            "capture_digest": self.capture_digest,
            "catalog_digest": self.catalog_digest,
            "world_ref": self.world_ref,
            "status": self.status,
            "steps": [item.to_dict() for item in self.steps],
            "bindings": [item.to_dict() for item in self.bindings],
            "validation_errors": list(self.validation_errors),
            "execution_blockers": list(self.execution_blockers),
        }


@dataclass(frozen=True, repr=False)
class EphemeralRehydratedStep:
    """Raw request material held only in memory; deliberately not serializable."""

    operation_id: str
    source_ref: str
    request_digest: str
    method: str
    url: str
    headers: Mapping[str, Any]
    body: Any

    def __repr__(self) -> str:
        return (
            "EphemeralRehydratedStep("
            f"operation_id={self.operation_id!r}, source_ref={self.source_ref!r}, "
            f"request_digest={self.request_digest!r}, raw_request=REDACTED)"
        )

    def redacted_summary(self) -> Dict[str, str]:
        return {
            "operation_id": self.operation_id,
            "source_ref": self.source_ref,
            "request_digest": self.request_digest,
            "mode": ANALYSIS_ONLY_MODE,
        }


class RehydrationDenied(RuntimeError):
    """Raised before returning raw in-memory request material."""


@dataclass(frozen=True)
class _Occurrence:
    capability: Capability
    raw_value: str
    value_hash: str
    world_ref: str
    operation_id: str
    source_ref: str
    record_index: int
    locator: ValueLocator
    direction: str

    @property
    def key(self) -> tuple[str, str, str, str, str]:
        return (
            self.source_ref,
            self.direction,
            self.capability.key,
            self.locator.kind.value,
            self.locator.pointer,
        )


def _pointer(parts: Iterable[Any]) -> str:
    def escape(value: Any) -> str:
        return str(value).replace("~", "~0").replace("/", "~1")

    return "/" + "/".join(escape(item) for item in parts)


def _canonical(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {
            str(key): _canonical(child)
            for key, child in sorted(value.items(), key=lambda item: str(item[0]))
        }
    if isinstance(value, (list, tuple)):
        return [_canonical(item) for item in value]
    if isinstance(value, bytes):
        return {"bytes_hash": stable_hash("bytes", value.hex())}
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return {
        "type": type(value).__name__,
        "repr_hash": stable_hash("repr", repr(value)),
    }


def _capture_digest(records: Sequence[Mapping[str, Any]]) -> str:
    return stable_hash("capture_set", _canonical(records))


def _request_digest(record: Mapping[str, Any], capture_digest: str) -> str:
    return stable_hash(
        "request_template",
        {
            "capture_digest": capture_digest,
            "request": _canonical(
                {
                    "method": str(record.get("method") or "GET").upper(),
                    "url": record.get("url"),
                    "headers": record.get("headers")
                    or record.get("request_headers")
                    or {},
                    "body": record.get("request_body"),
                }
            ),
        },
    )


def _status(record: Mapping[str, Any]) -> int:
    try:
        return int(record.get("response_status") or record.get("status") or 0)
    except (TypeError, ValueError):
        return 0


def _raw_text(value: Any, *, limits: LineageLimits) -> Optional[str]:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        text = str(value)
    elif isinstance(value, str):
        text = value.strip()
    else:
        return None
    if (
        not text
        or len(text) > limits.max_value_chars
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in text)
    ):
        return None
    return text


def _body_value(record: Mapping[str, Any], field: str) -> Any:
    raw = record.get(field)
    if not isinstance(raw, str):
        return raw
    stripped = raw.lstrip()
    if not stripped.startswith(("{", "[")):
        return None
    try:
        return json.loads(raw)
    except (TypeError, ValueError):
        return None


def _json_occurrences(
    value: Any,
    *,
    kind: LocatorKind,
    world_ref: str,
    operation_id: str,
    source_ref: str,
    record_index: int,
    direction: str,
    limits: LineageLimits,
    semantic_path: Tuple[str, ...] = (),
    pointer_path: Tuple[Any, ...] = (),
) -> list[_Occurrence]:
    output: list[_Occurrence] = []
    if isinstance(value, Mapping):
        for key, child in value.items():
            next_semantic = (*semantic_path, str(key))
            next_pointer = (*pointer_path, key)
            capability = value_capability_for_field_path(next_semantic)
            raw_value = _raw_text(child, limits=limits)
            if capability is not None and raw_value is not None:
                output.append(
                    _Occurrence(
                        capability=capability,
                        raw_value=raw_value,
                        value_hash=stable_hash("lineage_value", raw_value),
                        world_ref=world_ref,
                        operation_id=operation_id,
                        source_ref=source_ref,
                        record_index=record_index,
                        locator=ValueLocator(kind, _pointer(next_pointer)),
                        direction=direction,
                    )
                )
            output.extend(
                _json_occurrences(
                    child,
                    kind=kind,
                    world_ref=world_ref,
                    operation_id=operation_id,
                    source_ref=source_ref,
                    record_index=record_index,
                    direction=direction,
                    limits=limits,
                    semantic_path=next_semantic,
                    pointer_path=next_pointer,
                )
            )
    elif isinstance(value, list):
        for index, child in enumerate(value):
            output.extend(
                _json_occurrences(
                    child,
                    kind=kind,
                    world_ref=world_ref,
                    operation_id=operation_id,
                    source_ref=source_ref,
                    record_index=record_index,
                    direction=direction,
                    limits=limits,
                    semantic_path=semantic_path,
                    pointer_path=(*pointer_path, index),
                )
            )
    return output


def _request_url_occurrences(
    record: Mapping[str, Any],
    *,
    world_ref: str,
    operation_id: str,
    source_ref: str,
    record_index: int,
    limits: LineageLimits,
) -> list[_Occurrence]:
    output: list[_Occurrence] = []
    parsed = urlsplit(str(record.get("url") or ""))
    decoded_segments = [unquote(item) for item in parsed.path.split("/") if item]
    for index, raw_value in enumerate(decoded_segments):
        if index == 0:
            continue
        parent = decoded_segments[index - 1]
        if raw_value.lower() in _PATH_ACTION_TERMS:
            continue
        if not (_DYNAMIC_PATH_VALUE.fullmatch(raw_value) or parent.lower().endswith("s")):
            continue
        capability = value_capability_for_field_path((parent, "id"))
        bounded = _raw_text(raw_value, limits=limits)
        if capability is None or bounded is None:
            continue
        output.append(
            _Occurrence(
                capability=capability,
                raw_value=bounded,
                value_hash=stable_hash("lineage_value", bounded),
                world_ref=world_ref,
                operation_id=operation_id,
                source_ref=source_ref,
                record_index=record_index,
                locator=ValueLocator(LocatorKind.REQUEST_PATH, f"/segments/{index}"),
                direction="consumer",
            )
        )
    query_counts: Dict[str, int] = {}
    for key, value in parse_qsl(parsed.query, keep_blank_values=True):
        capability = value_capability_for_field_path((key,))
        bounded = _raw_text(value, limits=limits)
        if capability is None or bounded is None:
            continue
        occurrence = query_counts.get(key, 0)
        query_counts[key] = occurrence + 1
        output.append(
            _Occurrence(
                capability=capability,
                raw_value=bounded,
                value_hash=stable_hash("lineage_value", bounded),
                world_ref=world_ref,
                operation_id=operation_id,
                source_ref=source_ref,
                record_index=record_index,
                locator=ValueLocator(
                    LocatorKind.REQUEST_QUERY,
                    _pointer((key, occurrence)),
                ),
                direction="consumer",
            )
        )
    return output


def _request_body_occurrences(
    record: Mapping[str, Any],
    *,
    world_ref: str,
    operation_id: str,
    source_ref: str,
    record_index: int,
    limits: LineageLimits,
) -> list[_Occurrence]:
    parsed = _body_value(record, "request_body")
    if isinstance(parsed, (Mapping, list)):
        return _json_occurrences(
            parsed,
            kind=LocatorKind.REQUEST_JSON,
            world_ref=world_ref,
            operation_id=operation_id,
            source_ref=source_ref,
            record_index=record_index,
            direction="consumer",
            limits=limits,
        )
    raw = record.get("request_body")
    headers = record.get("headers") or record.get("request_headers") or {}
    content_type = ""
    if isinstance(headers, Mapping):
        content_type = str(headers.get("content-type") or headers.get("Content-Type") or "")
    if not isinstance(raw, str) or "application/x-www-form-urlencoded" not in content_type.lower():
        return []
    output: list[_Occurrence] = []
    counts: Dict[str, int] = {}
    for key, value in parse_qsl(raw, keep_blank_values=True):
        capability = value_capability_for_field_path((key,))
        bounded = _raw_text(value, limits=limits)
        if capability is None or bounded is None:
            continue
        occurrence = counts.get(key, 0)
        counts[key] = occurrence + 1
        output.append(
            _Occurrence(
                capability=capability,
                raw_value=bounded,
                value_hash=stable_hash("lineage_value", bounded),
                world_ref=world_ref,
                operation_id=operation_id,
                source_ref=source_ref,
                record_index=record_index,
                locator=ValueLocator(
                    LocatorKind.REQUEST_FORM,
                    _pointer((key, occurrence)),
                ),
                direction="consumer",
            )
        )
    return output


class ValueLineageLedger:
    """Session-local lineage graph with a redacted public surface."""

    def __init__(
        self,
        records: Sequence[Mapping[str, Any]],
        *,
        world_id: str = "captured",
        catalog_limits: Optional[OperationCatalogLimits] = None,
        lineage_limits: Optional[LineageLimits] = None,
        operation_contracts: Optional[Sequence[OperationContract]] = None,
    ) -> None:
        self.lineage_limits = lineage_limits or LineageLimits()
        observed_operations = operation_contracts_from_records(
            records,
            world_id=world_id,
            limits=catalog_limits,
        )
        if operation_contracts is None:
            self.operations = observed_operations
        else:
            observed_by_id = {item.operation_id: item for item in observed_operations}
            supplied_by_id = {item.operation_id: item for item in operation_contracts}
            if len(supplied_by_id) != len(operation_contracts):
                raise ValueError("operation_contracts contains duplicate operation_id")
            if set(supplied_by_id) != set(observed_by_id):
                raise ValueError("operation_contracts must cover the exact observed catalog")
            for operation_id, supplied in supplied_by_id.items():
                observed = observed_by_id[operation_id]
                immutable_fields = (
                    supplied.label == observed.label,
                    supplied.requires == observed.requires,
                    supplied.produces == observed.produces,
                    supplied.observed_success == observed.observed_success,
                    supplied.source_refs == observed.source_refs,
                )
                if not all(immutable_fields):
                    raise ValueError(
                        "operation_contracts may enrich only safety, cost, ownership, "
                        "and cleanup metadata"
                    )
            self.operations = tuple(
                supplied_by_id[key] for key in sorted(supplied_by_id)
            )
        self.catalog_digest = stable_hash(
            "operation_catalog",
            [item.to_dict() for item in sorted(self.operations, key=lambda op: op.operation_id)],
        )
        self.capture_digest = _capture_digest(records)
        self._records: Dict[str, Dict[str, Any]] = {}
        observations: list[OperationObservation] = []
        occurrences: list[_Occurrence] = []
        for index, record in enumerate(records):
            try:
                exchange = normalize_exchange(
                    record,
                    source_id=str(record.get("id") or index),
                    world_id=str(record.get("persona_id") or world_id),
                )
            except (TypeError, ValueError):
                continue
            world_ref = exchange.world_id
            source_ref = exchange.source_id
            if source_ref in self._records:
                raise ValueError("capture contains duplicate source_ref")
            self._records[source_ref] = copy.deepcopy(dict(record))
            observations.append(
                OperationObservation(
                    operation_id=exchange.action_id,
                    source_ref=source_ref,
                    world_ref=world_ref,
                    record_index=index,
                    request_digest=_request_digest(record, self.capture_digest),
                    response_status=exchange.response_status,
                )
            )
            occurrences.extend(
                _request_url_occurrences(
                    record,
                    world_ref=world_ref,
                    operation_id=exchange.action_id,
                    source_ref=source_ref,
                    record_index=index,
                    limits=self.lineage_limits,
                )
            )
            occurrences.extend(
                _request_body_occurrences(
                    record,
                    world_ref=world_ref,
                    operation_id=exchange.action_id,
                    source_ref=source_ref,
                    record_index=index,
                    limits=self.lineage_limits,
                )
            )
            response = _body_value(record, "response_body")
            if 200 <= exchange.response_status < 300 and isinstance(response, (Mapping, list)):
                occurrences.extend(
                    _json_occurrences(
                        response,
                        kind=LocatorKind.RESPONSE_JSON,
                        world_ref=world_ref,
                        operation_id=exchange.action_id,
                        source_ref=source_ref,
                        record_index=index,
                        direction="producer",
                        limits=self.lineage_limits,
                    )
                )
            if len(occurrences) > self.lineage_limits.max_occurrences:
                raise ValueError("lineage exceeds max_occurrences")

        occurrences = [
            _Occurrence(
                capability=item.capability,
                raw_value=item.raw_value,
                value_hash=stable_hash(
                    "lineage_value",
                    {
                        "capture_digest": self.capture_digest,
                        "value": item.raw_value,
                    },
                ),
                world_ref=item.world_ref,
                operation_id=item.operation_id,
                source_ref=item.source_ref,
                record_index=item.record_index,
                locator=item.locator,
                direction=item.direction,
            )
            for item in occurrences
        ]
        self.observations = tuple(
            sorted(observations, key=lambda item: (item.record_index, item.source_ref))
        )
        self._occurrences = {item.key: item for item in occurrences}
        producers = [item for item in occurrences if item.direction == "producer"]
        consumers = [item for item in occurrences if item.direction == "consumer"]
        bindings: list[LineageBinding] = []
        ambiguous = 0
        for consumer in consumers:
            matches = [
                producer
                for producer in producers
                if producer.world_ref == consumer.world_ref
                and producer.capability == consumer.capability
                and producer.value_hash == consumer.value_hash
                and producer.record_index < consumer.record_index
            ]
            if len(matches) != 1:
                if len(matches) > 1:
                    ambiguous += 1
                continue
            producer = matches[0]
            descriptor = {
                "capability": consumer.capability.key,
                "value_hash": consumer.value_hash,
                "world_ref": consumer.world_ref,
                "producer_source_ref": producer.source_ref,
                "producer_locator": producer.locator.to_dict(),
                "consumer_source_ref": consumer.source_ref,
                "consumer_locator": consumer.locator.to_dict(),
            }
            bindings.append(
                LineageBinding(
                    binding_id=stable_hash("lineage_binding", descriptor),
                    capability=consumer.capability,
                    value_hash=consumer.value_hash,
                    world_ref=consumer.world_ref,
                    producer_operation_id=producer.operation_id,
                    producer_source_ref=producer.source_ref,
                    producer_locator=producer.locator,
                    consumer_operation_id=consumer.operation_id,
                    consumer_source_ref=consumer.source_ref,
                    consumer_locator=consumer.locator,
                    sensitive=bool(_SENSITIVE_CAPABILITY.search(consumer.capability.name)),
                )
            )
            if len(bindings) > self.lineage_limits.max_bindings:
                raise ValueError("lineage exceeds max_bindings")
        self.bindings = tuple(sorted(bindings, key=lambda item: item.binding_id))
        self.ambiguous_consumers = ambiguous

    def observations_for(
        self,
        operation_id: str,
        world_ref: str,
    ) -> Tuple[OperationObservation, ...]:
        return tuple(
            item
            for item in self.observations
            if item.operation_id == operation_id and item.world_ref == world_ref
        )

    def bindings_for(
        self,
        *,
        capability: Capability,
        consumer_operation_id: str,
        world_ref: str,
        producer_operation_ids: Sequence[str],
    ) -> Tuple[LineageBinding, ...]:
        allowed_producers = set(producer_operation_ids)
        return tuple(
            item
            for item in self.bindings
            if item.capability == capability
            and item.consumer_operation_id == consumer_operation_id
            and item.world_ref == world_ref
            and item.producer_operation_id in allowed_producers
        )

    def snapshot(self) -> Dict[str, Any]:
        return {
            "schema_version": 1,
            "mode": ANALYSIS_ONLY_MODE,
            "executable": False,
            "capture_digest": self.capture_digest,
            "catalog_digest": self.catalog_digest,
            "operations": len(self.operations),
            "observations": [item.to_dict() for item in self.observations],
            "bindings": [item.to_dict() for item in self.bindings],
            "ambiguous_consumers": self.ambiguous_consumers,
        }

    def _record(self, source_ref: str) -> Dict[str, Any]:
        record = self._records.get(source_ref)
        if record is None:
            raise RehydrationDenied("rehydration source capture is unavailable")
        return copy.deepcopy(record)

    def _rehydrate_observation(
        self,
        observation: OperationObservation,
    ) -> EphemeralRehydratedStep:
        record = self._record(observation.source_ref)
        if _request_digest(record, self.capture_digest) != observation.request_digest:
            raise RehydrationDenied("rehydration request template changed")
        raw_headers = record.get("headers") or record.get("request_headers") or {}
        headers = copy.deepcopy(dict(raw_headers)) if isinstance(raw_headers, Mapping) else {}
        return EphemeralRehydratedStep(
            operation_id=observation.operation_id,
            source_ref=observation.source_ref,
            request_digest=observation.request_digest,
            method=str(record.get("method") or "GET").upper(),
            url=str(record.get("url") or ""),
            headers=headers,
            body=copy.deepcopy(record.get("request_body")),
        )

    def _occurrence(self, binding: LineageBinding, *, producer: bool) -> _Occurrence:
        source_ref = binding.producer_source_ref if producer else binding.consumer_source_ref
        direction = "producer" if producer else "consumer"
        locator = binding.producer_locator if producer else binding.consumer_locator
        key = (
            source_ref,
            direction,
            binding.capability.key,
            locator.kind.value,
            locator.pointer,
        )
        occurrence = self._occurrences.get(key)
        if occurrence is None:
            raise RehydrationDenied("rehydration locator is stale or unsupported")
        return occurrence


def _recipe_payload(
    *,
    plan_id: str,
    capture_digest: str,
    catalog_digest: str,
    world_ref: str,
    status: str,
    steps: Sequence[RehydrationStepTemplate],
    bindings: Sequence[LineageBinding],
    validation_errors: Sequence[str],
    execution_blockers: Sequence[str],
) -> Dict[str, Any]:
    return {
        "plan_id": plan_id,
        "capture_digest": capture_digest,
        "catalog_digest": catalog_digest,
        "world_ref": world_ref,
        "status": status,
        "steps": [item.to_dict() for item in steps],
        "binding_ids": [item.binding_id for item in bindings],
        "validation_errors": list(validation_errors),
        "execution_blockers": list(execution_blockers),
    }


class PlanRehydrator:
    """Compile and validate exact capture recipes without a transport seam."""

    def __init__(self, ledger: ValueLineageLedger) -> None:
        self.ledger = ledger
        self.operations = {item.operation_id: item for item in ledger.operations}

    def build_recipe(self, plan: BackwardPlan, *, world_id: str) -> RehydrationRecipe:
        world_ref = stable_hash("world", str(world_id or "captured"))
        validation_errors: set[str] = set()
        execution_blockers: set[str] = set(plan.execution_blockers)
        if plan.status != "planned":
            validation_errors.add("plan_is_not_prerequisite_complete")
        if plan.catalog_digest != self.ledger.catalog_digest:
            validation_errors.add("plan_catalog_digest_mismatch")

        steps: list[RehydrationStepTemplate] = []
        for operation_id in plan.step_ids:
            observations = self.ledger.observations_for(operation_id, world_ref)
            if len(observations) != 1:
                reason = "missing" if not observations else "ambiguous"
                validation_errors.add(f"{reason}_step_capture:{operation_id}")
                continue
            observation = observations[0]
            steps.append(
                RehydrationStepTemplate(
                    operation_id=operation_id,
                    source_ref=observation.source_ref,
                    world_ref=world_ref,
                    request_digest=observation.request_digest,
                )
            )

        available = set(plan.initial_capabilities)
        selected_bindings: Dict[str, LineageBinding] = {}
        prior_operation_ids: list[str] = []
        for operation_id in plan.step_ids:
            operation = self.operations.get(operation_id)
            if operation is None:
                validation_errors.add(f"operation_contract_missing:{operation_id}")
                continue
            for capability in operation.requires:
                if capability in plan.initial_capabilities:
                    continue
                producers = [
                    producer_id
                    for producer_id in prior_operation_ids
                    if capability in self.operations[producer_id].produces
                ]
                if capability not in available or not producers:
                    validation_errors.add(
                        f"plan_capability_is_not_available:{operation_id}:{capability.key}"
                    )
                    continue
                matches = self.ledger.bindings_for(
                    capability=capability,
                    consumer_operation_id=operation_id,
                    world_ref=world_ref,
                    producer_operation_ids=producers,
                )
                if len(matches) != 1:
                    reason = "missing" if not matches else "ambiguous"
                    validation_errors.add(
                        f"{reason}_lineage:{operation_id}:{capability.key}"
                    )
                    continue
                selected_bindings[matches[0].binding_id] = matches[0]
                if matches[0].sensitive:
                    execution_blockers.add(
                        f"sensitive_capability_requires_vault:{capability.key}"
                    )
            if operation.requires_owned_state:
                execution_blockers.add(f"ownership_proof_required:{operation_id}")
            available.update(operation.produces)
            prior_operation_ids.append(operation_id)

        execution_blockers.add("analysis_only_no_execution_authority")
        ordered_bindings = tuple(
            selected_bindings[key] for key in sorted(selected_bindings)
        )
        ordered_steps = tuple(steps)
        errors = tuple(sorted(validation_errors))
        blockers = tuple(sorted(execution_blockers))
        status = "ready" if not errors else "blocked"
        payload = _recipe_payload(
            plan_id=plan.plan_id,
            capture_digest=self.ledger.capture_digest,
            catalog_digest=self.ledger.catalog_digest,
            world_ref=world_ref,
            status=status,
            steps=ordered_steps,
            bindings=ordered_bindings,
            validation_errors=errors,
            execution_blockers=blockers,
        )
        return RehydrationRecipe(
            recipe_id=stable_hash("rehydration_recipe", payload),
            plan_id=plan.plan_id,
            capture_digest=self.ledger.capture_digest,
            catalog_digest=self.ledger.catalog_digest,
            world_ref=world_ref,
            status=status,
            steps=ordered_steps,
            bindings=ordered_bindings,
            validation_errors=errors,
            execution_blockers=blockers,
        )

    def rehydrate_step(
        self,
        recipe: RehydrationRecipe,
        operation_id: str,
    ) -> EphemeralRehydratedStep:
        if recipe.status != "ready" or recipe.executable:
            raise RehydrationDenied("rehydration recipe is not analysis-ready")
        if recipe.capture_digest != self.ledger.capture_digest:
            raise RehydrationDenied("rehydration capture digest mismatch")
        if recipe.catalog_digest != self.ledger.catalog_digest:
            raise RehydrationDenied("rehydration catalog digest mismatch")
        payload = _recipe_payload(
            plan_id=recipe.plan_id,
            capture_digest=recipe.capture_digest,
            catalog_digest=recipe.catalog_digest,
            world_ref=recipe.world_ref,
            status=recipe.status,
            steps=recipe.steps,
            bindings=recipe.bindings,
            validation_errors=recipe.validation_errors,
            execution_blockers=recipe.execution_blockers,
        )
        if recipe.recipe_id != stable_hash("rehydration_recipe", payload):
            raise RehydrationDenied("rehydration recipe identity mismatch")
        known_bindings = {item.binding_id: item for item in self.ledger.bindings}
        for binding in recipe.bindings:
            if known_bindings.get(binding.binding_id) != binding:
                raise RehydrationDenied("rehydration binding is not ledger-backed")
            producer = self.ledger._occurrence(binding, producer=True)
            consumer = self.ledger._occurrence(binding, producer=False)
            if (
                producer.raw_value != consumer.raw_value
                or producer.value_hash != binding.value_hash
                or consumer.value_hash != binding.value_hash
            ):
                raise RehydrationDenied("rehydration value binding changed")
        templates = [item for item in recipe.steps if item.operation_id == operation_id]
        if len(templates) != 1:
            raise RehydrationDenied("rehydration step template is missing or ambiguous")
        template = templates[0]
        if template.world_ref != recipe.world_ref:
            raise RehydrationDenied("rehydration step world mismatch")
        observation = OperationObservation(
            operation_id=template.operation_id,
            source_ref=template.source_ref,
            world_ref=template.world_ref,
            record_index=-1,
            request_digest=template.request_digest,
            response_status=0,
        )
        return self.ledger._rehydrate_observation(observation)


__all__ = [
    "EphemeralRehydratedStep",
    "LineageBinding",
    "LineageLimits",
    "LocatorKind",
    "OperationObservation",
    "PlanRehydrator",
    "RehydrationDenied",
    "RehydrationRecipe",
    "RehydrationStepTemplate",
    "ValueLineageLedger",
    "ValueLocator",
]
