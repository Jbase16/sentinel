"""Passive, proof-backed ownership evidence for generalized request locators.

This module does not register ownership with :class:`ExecutionPolicy` and cannot
send target traffic.  It turns exact same-world value lineage into a redacted,
content-addressed claim only when the value came from a successful, structurally
safe owned create and was subsequently used by the same world in a successful
request.  Admission and execution remain separate R5A boundaries.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple
from urllib.parse import urlsplit

from core.safety.action_classifier import OWNED_CREATE, classify

from .lineage import (
    LineageLimits,
    LocatorKind,
    RehydrationDenied,
    ValueLineageLedger,
    ValueLocator,
)
from .normalize import stable_hash
from .safety_contracts import classification_body, is_proven_safe_owned_create_body


GENERALIZED_OWNERSHIP_MODE = "behavioral_generalized_ownership_v1"

_HASH_REF = re.compile(r"^[a-z][a-z0-9_]*:[0-9a-f]{64}$")
_METHOD = re.compile(r"^[A-Z]{3,16}$")
_SUPPORTED_CONSUMER_LOCATORS = frozenset(
    {
        LocatorKind.REQUEST_PATH,
        LocatorKind.REQUEST_QUERY,
        LocatorKind.REQUEST_JSON,
        LocatorKind.REQUEST_FORM,
    }
)


def _is_hash_ref(value: Any, prefix: Optional[str] = None) -> bool:
    if not isinstance(value, str) or _HASH_REF.fullmatch(value) is None:
        return False
    return prefix is None or value.startswith(f"{prefix}:")


class OwnershipLocatorKind(str, Enum):
    """Security-relevant object locations derived from captured requests."""

    PATH = "path"
    QUERY = "query"
    JSON = "json"
    FORM = "form"
    GRAPHQL_VARIABLE = "graphql_variable"


class OwnershipProtocol(str, Enum):
    HTTP = "http"
    GRAPHQL = "graphql"


def _use_payload(
    *,
    lineage_binding_id: str,
    operation_id: str,
    source_ref: str,
    request_digest: str,
    method: str,
    locator_kind: OwnershipLocatorKind,
    locator_pointer: str,
    protocol: OwnershipProtocol,
) -> Dict[str, Any]:
    return {
        "lineage_binding_id": lineage_binding_id,
        "operation_id": operation_id,
        "source_ref": source_ref,
        "request_digest": request_digest,
        "method": method,
        "locator_kind": locator_kind.value,
        "locator_pointer": locator_pointer,
        "protocol": protocol.value,
    }


@dataclass(frozen=True)
class OwnershipUseEvidence:
    """One successful same-owner request carrying an exact created object ID."""

    use_id: str
    lineage_binding_id: str
    operation_id: str
    source_ref: str
    request_digest: str
    method: str
    locator_kind: OwnershipLocatorKind
    locator_pointer: str
    protocol: OwnershipProtocol

    def __post_init__(self) -> None:
        payload = _use_payload(
            lineage_binding_id=self.lineage_binding_id,
            operation_id=self.operation_id,
            source_ref=self.source_ref,
            request_digest=self.request_digest,
            method=self.method,
            locator_kind=self.locator_kind,
            locator_pointer=self.locator_pointer,
            protocol=self.protocol,
        )
        if (
            not _is_hash_ref(self.use_id, "ownership_use")
            or self.use_id != stable_hash("ownership_use", payload)
            or not _is_hash_ref(self.lineage_binding_id, "lineage_binding")
            or not _is_hash_ref(self.operation_id, "action")
            or not _is_hash_ref(self.source_ref, "source_ref")
            or not _is_hash_ref(self.request_digest, "request_template")
            or _METHOD.fullmatch(self.method) is None
            or not isinstance(self.locator_kind, OwnershipLocatorKind)
            or not isinstance(self.protocol, OwnershipProtocol)
            or not self.locator_pointer.startswith("/")
            or len(self.locator_pointer) > 1_024
            or any(ord(character) < 0x20 for character in self.locator_pointer)
            or (
                self.locator_kind is OwnershipLocatorKind.GRAPHQL_VARIABLE
                and self.protocol is not OwnershipProtocol.GRAPHQL
            )
            or (
                self.locator_kind is not OwnershipLocatorKind.GRAPHQL_VARIABLE
                and self.protocol is not OwnershipProtocol.HTTP
            )
        ):
            raise ValueError("ownership use evidence contract is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "use_id": self.use_id,
            **_use_payload(
                lineage_binding_id=self.lineage_binding_id,
                operation_id=self.operation_id,
                source_ref=self.source_ref,
                request_digest=self.request_digest,
                method=self.method,
                locator_kind=self.locator_kind,
                locator_pointer=self.locator_pointer,
                protocol=self.protocol,
            ),
        }


def _evidence_payload(
    *,
    capture_digest: str,
    world_ref: str,
    capability_key: str,
    value_hash: str,
    create_operation_id: str,
    create_source_ref: str,
    create_request_digest: str,
    create_response_locator: ValueLocator,
    uses: Sequence[OwnershipUseEvidence],
) -> Dict[str, Any]:
    return {
        "capture_digest": capture_digest,
        "world_ref": world_ref,
        "capability_key": capability_key,
        "value_hash": value_hash,
        "create_operation_id": create_operation_id,
        "create_source_ref": create_source_ref,
        "create_request_digest": create_request_digest,
        "create_response_locator": create_response_locator.to_dict(),
        "use_ids": [item.use_id for item in uses],
    }


@dataclass(frozen=True)
class GeneralizedOwnershipEvidence:
    """Redacted proof that one world created and reused one response-returned ID."""

    evidence_id: str
    capture_digest: str
    world_ref: str
    capability_key: str
    value_hash: str
    create_operation_id: str
    create_source_ref: str
    create_request_digest: str
    create_response_locator: ValueLocator
    uses: Tuple[OwnershipUseEvidence, ...]
    mode: str = GENERALIZED_OWNERSHIP_MODE
    executable: bool = False

    def __post_init__(self) -> None:
        payload = _evidence_payload(
            capture_digest=self.capture_digest,
            world_ref=self.world_ref,
            capability_key=self.capability_key,
            value_hash=self.value_hash,
            create_operation_id=self.create_operation_id,
            create_source_ref=self.create_source_ref,
            create_request_digest=self.create_request_digest,
            create_response_locator=self.create_response_locator,
            uses=self.uses,
        )
        if (
            self.mode != GENERALIZED_OWNERSHIP_MODE
            or self.executable
            or not _is_hash_ref(self.evidence_id, "ownership_evidence")
            or self.evidence_id != stable_hash("ownership_evidence", payload)
            or not _is_hash_ref(self.capture_digest, "capture_set")
            or not _is_hash_ref(self.world_ref, "world")
            or not self.capability_key
            or len(self.capability_key) > 256
            or not _is_hash_ref(self.value_hash, "lineage_value")
            or not _is_hash_ref(self.create_operation_id, "action")
            or not _is_hash_ref(self.create_source_ref, "source_ref")
            or not _is_hash_ref(self.create_request_digest, "request_template")
            or self.create_response_locator.kind is not LocatorKind.RESPONSE_JSON
            or not self.uses
            or self.uses != tuple(sorted(self.uses, key=lambda item: item.use_id))
            or len({item.use_id for item in self.uses}) != len(self.uses)
        ):
            raise ValueError("generalized ownership evidence contract is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": 1,
            "mode": self.mode,
            "executable": self.executable,
            "evidence_id": self.evidence_id,
            "capture_digest": self.capture_digest,
            "world_ref": self.world_ref,
            "capability_key": self.capability_key,
            "value_hash": self.value_hash,
            "create_operation_id": self.create_operation_id,
            "create_source_ref": self.create_source_ref,
            "create_request_digest": self.create_request_digest,
            "create_response_locator": self.create_response_locator.to_dict(),
            "uses": [item.to_dict() for item in self.uses],
        }


@dataclass(frozen=True)
class OwnershipLocatorDiagnostics:
    records: int
    observed_operations: int
    exact_bindings: int
    accepted_bindings: int
    path_bindings: int
    query_bindings: int
    json_bindings: int
    form_bindings: int
    graphql_variable_bindings: int
    sensitive_bindings: int
    unsafe_create_bindings: int
    unsuccessful_use_bindings: int
    unsupported_locator_bindings: int
    ambiguous_consumers: int

    def __post_init__(self) -> None:
        if any(
            isinstance(value, bool) or not isinstance(value, int) or value < 0
            for value in vars(self).values()
        ):
            raise ValueError(
                "ownership locator diagnostics must be non-negative integers"
            )
        classified = (
            self.path_bindings
            + self.query_bindings
            + self.json_bindings
            + self.form_bindings
            + self.graphql_variable_bindings
        )
        if classified != self.accepted_bindings:
            raise ValueError("ownership locator diagnostics do not balance")

    def to_dict(self) -> Dict[str, int]:
        return dict(vars(self))


@dataclass(frozen=True)
class GeneralizedOwnershipIndex:
    status: str
    capture_digest: str
    catalog_digest: str
    evidence: Tuple[GeneralizedOwnershipEvidence, ...]
    diagnostics: OwnershipLocatorDiagnostics
    ledger: ValueLineageLedger = field(repr=False, compare=False)
    mode: str = GENERALIZED_OWNERSHIP_MODE
    executable: bool = False

    def __post_init__(self) -> None:
        expected_status = "ready" if self.evidence else "no_proven_ownership"
        if (
            self.status != expected_status
            or self.mode != GENERALIZED_OWNERSHIP_MODE
            or self.executable
            or self.capture_digest != self.ledger.capture_digest
            or self.catalog_digest != self.ledger.catalog_digest
            or self.evidence
            != tuple(sorted(self.evidence, key=lambda item: item.evidence_id))
            or len({item.evidence_id for item in self.evidence}) != len(self.evidence)
            or any(item.capture_digest != self.capture_digest for item in self.evidence)
        ):
            raise ValueError("generalized ownership index contract is invalid")

    def evidence_for_binding(
        self,
        lineage_binding_id: str,
    ) -> Optional[GeneralizedOwnershipEvidence]:
        matches = tuple(
            item
            for item in self.evidence
            if any(use.lineage_binding_id == lineage_binding_id for use in item.uses)
        )
        return matches[0] if len(matches) == 1 else None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": 1,
            "mode": self.mode,
            "executable": self.executable,
            "status": self.status,
            "capture_digest": self.capture_digest,
            "catalog_digest": self.catalog_digest,
            "evidence": [item.to_dict() for item in self.evidence],
            "diagnostics": self.diagnostics.to_dict(),
        }


@dataclass(frozen=True)
class _OwnershipKey:
    world_ref: str
    capability_key: str
    value_hash: str
    create_operation_id: str
    create_source_ref: str
    create_request_digest: str
    create_response_locator: ValueLocator


def _decode_pointer(pointer: str) -> Tuple[str, ...]:
    if not pointer.startswith("/"):
        return ()
    return tuple(
        token.replace("~1", "/").replace("~0", "~") for token in pointer[1:].split("/")
    )


def _json_body(body: Any) -> Any:
    if isinstance(body, (Mapping, list)):
        return body
    if not isinstance(body, str):
        return None
    stripped = body.lstrip()
    if not stripped.startswith(("{", "[")):
        return None
    try:
        return json.loads(body)
    except (TypeError, ValueError):
        return None


def _graphql_item(body: Any, pointer: str) -> Optional[Mapping[str, Any]]:
    tokens = _decode_pointer(pointer)
    if not tokens:
        return None
    parsed = _json_body(body)
    item: Any = parsed
    if isinstance(item, list):
        try:
            index = int(tokens[0])
        except (TypeError, ValueError):
            return None
        if index < 0 or index >= len(item):
            return None
        item = item[index]
        tokens = tokens[1:]
    if (
        not isinstance(item, Mapping)
        or len(tokens) < 2
        or tokens[0] != "variables"
        or not isinstance(item.get("variables"), Mapping)
    ):
        return None
    return item


def _is_graphql_variable(request: Any, locator: ValueLocator) -> bool:
    item = _graphql_item(request.body, locator.pointer)
    if item is None:
        return False
    path_tail = urlsplit(request.url).path.rstrip("/").rsplit("/", 1)[-1].lower()
    return bool(
        {"query", "operationName", "extensions"} & set(item)
        or path_tail in {"graphql", "gql"}
    )


def _ownership_locator(
    request: Any,
    locator: ValueLocator,
) -> Tuple[OwnershipLocatorKind, OwnershipProtocol]:
    if locator.kind is LocatorKind.REQUEST_PATH:
        return OwnershipLocatorKind.PATH, OwnershipProtocol.HTTP
    if locator.kind is LocatorKind.REQUEST_QUERY:
        return OwnershipLocatorKind.QUERY, OwnershipProtocol.HTTP
    if locator.kind is LocatorKind.REQUEST_FORM:
        return OwnershipLocatorKind.FORM, OwnershipProtocol.HTTP
    if locator.kind is LocatorKind.REQUEST_JSON:
        if _is_graphql_variable(request, locator):
            return OwnershipLocatorKind.GRAPHQL_VARIABLE, OwnershipProtocol.GRAPHQL
        return OwnershipLocatorKind.JSON, OwnershipProtocol.HTTP
    raise ValueError("ownership consumer locator is unsupported")


class GeneralizedOwnershipLocatorCompiler:
    """Compile redacted ownership evidence from already-captured exchanges only."""

    def __init__(self, *, lineage_limits: Optional[LineageLimits] = None) -> None:
        self.lineage_limits = lineage_limits

    def compile(
        self,
        records: Sequence[Mapping[str, Any]],
        *,
        world_id: str = "captured",
    ) -> GeneralizedOwnershipIndex:
        if isinstance(records, (str, bytes)) or any(
            not isinstance(item, Mapping) for item in records
        ):
            raise TypeError("ownership records must be a sequence of mappings")
        ledger = ValueLineageLedger(
            records,
            world_id=world_id,
            lineage_limits=self.lineage_limits,
        )
        observations = {item.source_ref: item for item in ledger.observations}
        operations = {item.operation_id: item for item in ledger.operations}
        groups: Dict[_OwnershipKey, list[OwnershipUseEvidence]] = {}
        counts = {kind: 0 for kind in OwnershipLocatorKind}
        sensitive_bindings = 0
        unsafe_create_bindings = 0
        unsuccessful_use_bindings = 0
        unsupported_locator_bindings = 0

        for binding in ledger.bindings:
            if binding.sensitive:
                sensitive_bindings += 1
                continue
            if (
                binding.producer_locator.kind is not LocatorKind.RESPONSE_JSON
                or binding.consumer_locator.kind not in _SUPPORTED_CONSUMER_LOCATORS
            ):
                unsupported_locator_bindings += 1
                continue
            producer_observation = observations.get(binding.producer_source_ref)
            consumer_observation = observations.get(binding.consumer_source_ref)
            producer_operation = operations.get(binding.producer_operation_id)
            consumer_operation = operations.get(binding.consumer_operation_id)
            if (
                producer_observation is None
                or producer_operation is None
                or not 200 <= producer_observation.response_status < 300
                or not producer_operation.observed_success
            ):
                unsafe_create_bindings += 1
                continue
            if (
                consumer_observation is None
                or consumer_operation is None
                or not 200 <= consumer_observation.response_status < 300
                or not consumer_operation.observed_success
            ):
                unsuccessful_use_bindings += 1
                continue
            try:
                create_request = ledger._rehydrate_observation(producer_observation)
                consumer_request = ledger._rehydrate_observation(consumer_observation)
            except RehydrationDenied:
                unsafe_create_bindings += 1
                continue
            if (
                create_request.method != "POST"
                or not is_proven_safe_owned_create_body(create_request.body)
                or classify(
                    create_request.method,
                    create_request.url,
                    classification_body(create_request.body),
                    hint=OWNED_CREATE,
                )
                != OWNED_CREATE
            ):
                unsafe_create_bindings += 1
                continue
            try:
                locator_kind, protocol = _ownership_locator(
                    consumer_request,
                    binding.consumer_locator,
                )
            except ValueError:
                unsupported_locator_bindings += 1
                continue
            method = consumer_request.method.upper()
            use_payload = _use_payload(
                lineage_binding_id=binding.binding_id,
                operation_id=binding.consumer_operation_id,
                source_ref=binding.consumer_source_ref,
                request_digest=consumer_observation.request_digest,
                method=method,
                locator_kind=locator_kind,
                locator_pointer=binding.consumer_locator.pointer,
                protocol=protocol,
            )
            use = OwnershipUseEvidence(
                use_id=stable_hash("ownership_use", use_payload),
                lineage_binding_id=binding.binding_id,
                operation_id=binding.consumer_operation_id,
                source_ref=binding.consumer_source_ref,
                request_digest=consumer_observation.request_digest,
                method=method,
                locator_kind=locator_kind,
                locator_pointer=binding.consumer_locator.pointer,
                protocol=protocol,
            )
            key = _OwnershipKey(
                world_ref=binding.world_ref,
                capability_key=binding.capability.key,
                value_hash=binding.value_hash,
                create_operation_id=binding.producer_operation_id,
                create_source_ref=binding.producer_source_ref,
                create_request_digest=producer_observation.request_digest,
                create_response_locator=binding.producer_locator,
            )
            groups.setdefault(key, []).append(use)
            counts[locator_kind] += 1

        evidence = []
        for key, raw_uses in groups.items():
            uses = tuple(sorted(raw_uses, key=lambda item: item.use_id))
            payload = _evidence_payload(
                capture_digest=ledger.capture_digest,
                world_ref=key.world_ref,
                capability_key=key.capability_key,
                value_hash=key.value_hash,
                create_operation_id=key.create_operation_id,
                create_source_ref=key.create_source_ref,
                create_request_digest=key.create_request_digest,
                create_response_locator=key.create_response_locator,
                uses=uses,
            )
            evidence.append(
                GeneralizedOwnershipEvidence(
                    evidence_id=stable_hash("ownership_evidence", payload),
                    capture_digest=ledger.capture_digest,
                    world_ref=key.world_ref,
                    capability_key=key.capability_key,
                    value_hash=key.value_hash,
                    create_operation_id=key.create_operation_id,
                    create_source_ref=key.create_source_ref,
                    create_request_digest=key.create_request_digest,
                    create_response_locator=key.create_response_locator,
                    uses=uses,
                )
            )
        ordered = tuple(sorted(evidence, key=lambda item: item.evidence_id))
        diagnostics = OwnershipLocatorDiagnostics(
            records=len(records),
            observed_operations=len(ledger.operations),
            exact_bindings=len(ledger.bindings),
            accepted_bindings=sum(counts.values()),
            path_bindings=counts[OwnershipLocatorKind.PATH],
            query_bindings=counts[OwnershipLocatorKind.QUERY],
            json_bindings=counts[OwnershipLocatorKind.JSON],
            form_bindings=counts[OwnershipLocatorKind.FORM],
            graphql_variable_bindings=counts[OwnershipLocatorKind.GRAPHQL_VARIABLE],
            sensitive_bindings=sensitive_bindings,
            unsafe_create_bindings=unsafe_create_bindings,
            unsuccessful_use_bindings=unsuccessful_use_bindings,
            unsupported_locator_bindings=unsupported_locator_bindings,
            ambiguous_consumers=ledger.ambiguous_consumers,
        )
        return GeneralizedOwnershipIndex(
            status="ready" if ordered else "no_proven_ownership",
            capture_digest=ledger.capture_digest,
            catalog_digest=ledger.catalog_digest,
            evidence=ordered,
            diagnostics=diagnostics,
            ledger=ledger,
        )


__all__ = [
    "GENERALIZED_OWNERSHIP_MODE",
    "GeneralizedOwnershipEvidence",
    "GeneralizedOwnershipIndex",
    "GeneralizedOwnershipLocatorCompiler",
    "OwnershipLocatorDiagnostics",
    "OwnershipLocatorKind",
    "OwnershipProtocol",
    "OwnershipUseEvidence",
]
