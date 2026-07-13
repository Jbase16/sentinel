"""Transport-free mining of exact owned create/read/cleanup lifecycles."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple

from core.safety.action_classifier import (
    OWNED_CREATE,
    OWNED_UPDATE_LOW_RISK,
    classify,
)

from .compiler import OperationContract, OperationSafety
from .lineage import (
    LineageBinding,
    LineageLimits,
    LocatorKind,
    OperationObservation,
    ValueLineageLedger,
)
from .normalize import stable_hash
from .safety_contracts import (
    classification_body,
    is_proven_safe_cleanup_body,
    is_proven_safe_owned_create_body,
)

LIFECYCLE_MINING_MODE = "behavioral_lifecycle_mining_v1"


def _is_hash_ref(value: Any, prefix: str) -> bool:
    if not isinstance(value, str) or not value.startswith(f"{prefix}:"):
        return False
    digest = value[len(prefix) + 1 :]
    return len(digest) == 64 and all(item in "0123456789abcdef" for item in digest)


@dataclass(frozen=True)
class OwnedLifecycleCandidate:
    lifecycle_id: str
    world_ref: str
    create_operation_id: str
    read_operation_ids: Tuple[str, ...]
    cleanup_operation_id: str
    capability_key: str
    read_binding_ids: Tuple[str, ...]
    cleanup_binding_id: str
    mode: str = LIFECYCLE_MINING_MODE
    executable: bool = False

    def __post_init__(self) -> None:
        if (
            self.mode != LIFECYCLE_MINING_MODE
            or self.executable
            or not _is_hash_ref(self.lifecycle_id, "owned_lifecycle")
            or not _is_hash_ref(self.world_ref, "world")
            or not self.read_operation_ids
            or len(set(self.read_operation_ids)) != len(self.read_operation_ids)
            or len(self.read_operation_ids) != len(self.read_binding_ids)
            or any(
                not _is_hash_ref(item, "lineage_binding")
                for item in (*self.read_binding_ids, self.cleanup_binding_id)
            )
            or not self.create_operation_id
            or not self.cleanup_operation_id
            or not self.capability_key
        ):
            raise ValueError("owned lifecycle candidate contract is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": 1,
            "mode": self.mode,
            "executable": self.executable,
            "lifecycle_id": self.lifecycle_id,
            "world_ref": self.world_ref,
            "create_operation_id": self.create_operation_id,
            "read_operation_ids": list(self.read_operation_ids),
            "cleanup_operation_id": self.cleanup_operation_id,
            "capability_key": self.capability_key,
            "read_binding_ids": list(self.read_binding_ids),
            "cleanup_binding_id": self.cleanup_binding_id,
        }


@dataclass(frozen=True)
class LifecycleMiningDiagnostics:
    records: int
    observed_operations: int
    exact_bindings: int
    path_bindings: int
    evidence_groups: int
    incomplete_groups: int
    ambiguous_cleanup_groups: int
    ambiguous_observation_groups: int
    role_conflict_groups: int

    def __post_init__(self) -> None:
        if any(
            isinstance(value, bool) or not isinstance(value, int) or value < 0
            for value in vars(self).values()
        ):
            raise ValueError("lifecycle mining diagnostics must be non-negative integers")

    def to_dict(self) -> Dict[str, int]:
        return dict(vars(self))


@dataclass(frozen=True)
class LifecycleMiningResult:
    status: str
    capture_digest: str
    catalog_digest: str
    candidates: Tuple[OwnedLifecycleCandidate, ...]
    diagnostics: LifecycleMiningDiagnostics
    ledger: ValueLineageLedger = field(repr=False, compare=False)
    mode: str = LIFECYCLE_MINING_MODE
    executable: bool = False

    def __post_init__(self) -> None:
        expected = "ready" if self.candidates else "no_proven_lifecycle"
        if (
            self.status != expected
            or self.mode != LIFECYCLE_MINING_MODE
            or self.executable
            or self.capture_digest != self.ledger.capture_digest
            or self.catalog_digest != self.ledger.catalog_digest
        ):
            raise ValueError("lifecycle mining result contract is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": 1,
            "mode": self.mode,
            "executable": self.executable,
            "status": self.status,
            "capture_digest": self.capture_digest,
            "catalog_digest": self.catalog_digest,
            "candidates": [item.to_dict() for item in self.candidates],
            "diagnostics": self.diagnostics.to_dict(),
        }


@dataclass(frozen=True)
class _EvidenceKey:
    producer_operation_id: str
    producer_source_ref: str
    producer_locator_kind: str
    producer_locator_pointer: str
    value_hash: str
    world_ref: str
    capability_key: str


@dataclass(frozen=True)
class _ProvisionalLifecycle:
    key: _EvidenceKey
    read_bindings: Tuple[LineageBinding, ...]
    cleanup_binding: LineageBinding


def _evidence_key(binding: LineageBinding) -> _EvidenceKey:
    return _EvidenceKey(
        producer_operation_id=binding.producer_operation_id,
        producer_source_ref=binding.producer_source_ref,
        producer_locator_kind=binding.producer_locator.kind.value,
        producer_locator_pointer=binding.producer_locator.pointer,
        value_hash=binding.value_hash,
        world_ref=binding.world_ref,
        capability_key=binding.capability.key,
    )


class LifecycleContractMiner:
    """Infer only exact, observed, same-world owned object lifecycles."""

    def __init__(
        self,
        *,
        lineage_limits: Optional[LineageLimits] = None,
    ) -> None:
        self.lineage_limits = lineage_limits

    @staticmethod
    def _observation_by_source(
        ledger: ValueLineageLedger,
    ) -> Dict[str, OperationObservation]:
        return {item.source_ref: item for item in ledger.observations}

    @staticmethod
    def _single_observation(
        ledger: ValueLineageLedger,
        operation_id: str,
        world_ref: str,
    ) -> Optional[OperationObservation]:
        matches = ledger.observations_for(operation_id, world_ref)
        return matches[0] if len(matches) == 1 else None

    @staticmethod
    def _request_for_binding(
        ledger: ValueLineageLedger,
        observations: Mapping[str, OperationObservation],
        binding: LineageBinding,
        *,
        producer: bool,
    ):
        source_ref = (
            binding.producer_source_ref if producer else binding.consumer_source_ref
        )
        observation = observations.get(source_ref)
        if observation is None:
            return None
        return ledger._rehydrate_observation(observation)

    def mine(
        self,
        records: Sequence[Mapping[str, Any]],
        *,
        world_id: str = "captured",
    ) -> LifecycleMiningResult:
        if isinstance(records, (str, bytes)) or any(
            not isinstance(item, Mapping) for item in records
        ):
            raise TypeError("lifecycle records must be a sequence of mappings")
        observed_ledger = ValueLineageLedger(
            records,
            world_id=world_id,
            lineage_limits=self.lineage_limits,
        )
        operations = {item.operation_id: item for item in observed_ledger.operations}
        observations = self._observation_by_source(observed_ledger)
        path_bindings = tuple(
            item
            for item in observed_ledger.bindings
            if not item.sensitive
            and item.producer_locator.kind == LocatorKind.RESPONSE_JSON
            and item.consumer_locator.kind == LocatorKind.REQUEST_PATH
        )
        reads_by_key: Dict[_EvidenceKey, list[LineageBinding]] = {}
        cleanup_by_key: Dict[_EvidenceKey, list[LineageBinding]] = {}
        for binding in path_bindings:
            producer_operation = operations.get(binding.producer_operation_id)
            consumer_operation = operations.get(binding.consumer_operation_id)
            producer_request = self._request_for_binding(
                observed_ledger,
                observations,
                binding,
                producer=True,
            )
            consumer_request = self._request_for_binding(
                observed_ledger,
                observations,
                binding,
                producer=False,
            )
            if (
                producer_operation is None
                or consumer_operation is None
                or producer_request is None
                or consumer_request is None
                or not producer_operation.observed_success
                or not consumer_operation.observed_success
                or producer_request.method != "POST"
                or not is_proven_safe_owned_create_body(producer_request.body)
                or classify(
                    producer_request.method,
                    producer_request.url,
                    classification_body(producer_request.body),
                    hint=OWNED_CREATE,
                )
                != OWNED_CREATE
            ):
                continue
            key = _evidence_key(binding)
            if (
                consumer_request.method == "GET"
                and consumer_operation.safety == OperationSafety.READ_ONLY
            ):
                reads_by_key.setdefault(key, []).append(binding)
                continue
            if (
                consumer_request.method in {"PATCH", "PUT"}
                and is_proven_safe_cleanup_body(consumer_request.body)
                and classify(
                    consumer_request.method,
                    consumer_request.url,
                    classification_body(consumer_request.body),
                    hint=OWNED_UPDATE_LOW_RISK,
                )
                == OWNED_UPDATE_LOW_RISK
            ):
                cleanup_by_key.setdefault(key, []).append(binding)

        evidence_keys = set(reads_by_key) | set(cleanup_by_key)
        provisional: list[_ProvisionalLifecycle] = []
        incomplete_groups = 0
        ambiguous_cleanup_groups = 0
        ambiguous_observation_groups = 0
        for key in sorted(
            evidence_keys,
            key=lambda item: (
                item.world_ref,
                item.producer_operation_id,
                item.capability_key,
                item.value_hash,
            ),
        ):
            read_bindings = reads_by_key.get(key, [])
            cleanup_bindings = cleanup_by_key.get(key, [])
            if not read_bindings or not cleanup_bindings:
                incomplete_groups += 1
                continue
            unique_cleanup = {item.binding_id: item for item in cleanup_bindings}
            cleanup_operations = {
                item.consumer_operation_id for item in unique_cleanup.values()
            }
            if len(unique_cleanup) != 1 or len(cleanup_operations) != 1:
                ambiguous_cleanup_groups += 1
                continue
            reads_by_operation: Dict[str, list[LineageBinding]] = {}
            for binding in read_bindings:
                reads_by_operation.setdefault(
                    binding.consumer_operation_id,
                    [],
                ).append(binding)
            if any(len(items) != 1 for items in reads_by_operation.values()):
                ambiguous_observation_groups += 1
                continue
            cleanup_binding = next(iter(unique_cleanup.values()))
            operation_ids = {
                key.producer_operation_id,
                cleanup_binding.consumer_operation_id,
                *reads_by_operation,
            }
            if any(
                self._single_observation(observed_ledger, operation_id, key.world_ref)
                is None
                for operation_id in operation_ids
            ):
                ambiguous_observation_groups += 1
                continue
            provisional.append(
                _ProvisionalLifecycle(
                    key=key,
                    read_bindings=tuple(
                        reads_by_operation[item][0]
                        for item in sorted(reads_by_operation)
                    ),
                    cleanup_binding=cleanup_binding,
                )
            )

        cleanup_targets: Dict[str, set[str]] = {}
        roles: Dict[str, set[str]] = {}
        for item in provisional:
            create_id = item.key.producer_operation_id
            cleanup_id = item.cleanup_binding.consumer_operation_id
            cleanup_targets.setdefault(create_id, set()).add(cleanup_id)
            roles.setdefault(create_id, set()).add("create")
            roles.setdefault(cleanup_id, set()).add("cleanup")
            for binding in item.read_bindings:
                roles.setdefault(binding.consumer_operation_id, set()).add("read")
        conflicting_operations = {
            operation_id for operation_id, values in roles.items() if len(values) != 1
        }
        conflicting_creates = {
            operation_id
            for operation_id, cleanup_ids in cleanup_targets.items()
            if len(cleanup_ids) != 1
        }
        accepted = tuple(
            item
            for item in provisional
            if item.key.producer_operation_id not in conflicting_creates
            and not (
                {
                    item.key.producer_operation_id,
                    item.cleanup_binding.consumer_operation_id,
                    *(binding.consumer_operation_id for binding in item.read_bindings),
                }
                & conflicting_operations
            )
        )
        role_conflict_groups = len(provisional) - len(accepted)

        enrichment: Dict[str, Dict[str, Any]] = {}
        for item in accepted:
            create_id = item.key.producer_operation_id
            cleanup_id = item.cleanup_binding.consumer_operation_id
            enrichment[create_id] = {
                "safety": OperationSafety.OWNED_REVERSIBLE_WRITE,
                "requires_owned_state": False,
                "cleanup_operation_id": cleanup_id,
            }
            enrichment[cleanup_id] = {
                "safety": OperationSafety.OWNED_REVERSIBLE_WRITE,
                "requires_owned_state": True,
                "cleanup_operation_id": None,
            }
            for binding in item.read_bindings:
                enrichment[binding.consumer_operation_id] = {
                    "safety": OperationSafety.READ_ONLY,
                    "requires_owned_state": True,
                    "cleanup_operation_id": None,
                }
        enriched_operations: list[OperationContract] = []
        for operation in observed_ledger.operations:
            values = enrichment.get(operation.operation_id)
            enriched_operations.append(
                replace(operation, **values) if values is not None else operation
            )
        ledger = ValueLineageLedger(
            records,
            world_id=world_id,
            lineage_limits=self.lineage_limits,
            operation_contracts=tuple(enriched_operations),
        )

        candidates: list[OwnedLifecycleCandidate] = []
        for item in accepted:
            read_pairs = sorted(
                (
                    binding.consumer_operation_id,
                    binding.binding_id,
                )
                for binding in item.read_bindings
            )
            payload = {
                "capture_digest": ledger.capture_digest,
                "catalog_digest": ledger.catalog_digest,
                "world_ref": item.key.world_ref,
                "create_operation_id": item.key.producer_operation_id,
                "read_operations": read_pairs,
                "cleanup_operation_id": item.cleanup_binding.consumer_operation_id,
                "cleanup_binding_id": item.cleanup_binding.binding_id,
                "capability_key": item.key.capability_key,
            }
            candidates.append(
                OwnedLifecycleCandidate(
                    lifecycle_id=stable_hash("owned_lifecycle", payload),
                    world_ref=item.key.world_ref,
                    create_operation_id=item.key.producer_operation_id,
                    read_operation_ids=tuple(pair[0] for pair in read_pairs),
                    cleanup_operation_id=item.cleanup_binding.consumer_operation_id,
                    capability_key=item.key.capability_key,
                    read_binding_ids=tuple(pair[1] for pair in read_pairs),
                    cleanup_binding_id=item.cleanup_binding.binding_id,
                )
            )
        ordered_candidates = tuple(
            sorted(candidates, key=lambda item: item.lifecycle_id)
        )
        diagnostics = LifecycleMiningDiagnostics(
            records=len(records),
            observed_operations=len(observed_ledger.operations),
            exact_bindings=len(observed_ledger.bindings),
            path_bindings=len(path_bindings),
            evidence_groups=len(evidence_keys),
            incomplete_groups=incomplete_groups,
            ambiguous_cleanup_groups=ambiguous_cleanup_groups,
            ambiguous_observation_groups=ambiguous_observation_groups,
            role_conflict_groups=role_conflict_groups,
        )
        return LifecycleMiningResult(
            status="ready" if ordered_candidates else "no_proven_lifecycle",
            capture_digest=ledger.capture_digest,
            catalog_digest=ledger.catalog_digest,
            candidates=ordered_candidates,
            diagnostics=diagnostics,
            ledger=ledger,
        )


__all__ = [
    "LIFECYCLE_MINING_MODE",
    "LifecycleContractMiner",
    "LifecycleMiningDiagnostics",
    "LifecycleMiningResult",
    "OwnedLifecycleCandidate",
]
