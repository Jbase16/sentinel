"""R5F2: passive, unwired owned shared-world provenance and freshness binding.

No production entry point imports this module. It adds no authority of any kind.
The evaluator runs a deterministic offline logical schedule, with no real
concurrency, threads, async execution, or clock. Its result is not independent
evidence of an observed target-side effect. Running-workflow effect proof and
native OCB-S22 are deferred to the active tail.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from .concurrency_invariant_contract import (
    MAX_CONCURRENCY_OPERATIONS,
    ConcurrencyDecision,
    ConcurrencyInvariantContract,
    ConcurrencyOutcome,
    ConcurrencyOwnedFixture,
    WorkflowSchedule,
    _fields,
    _hash_ref,
    _integer,
    _passive_flags,
    _revalidate,
    classify_schedule,
)
from .normalize import stable_hash

CONCURRENCY_INVARIANT_BINDING_MODE = "behavioral_concurrency_invariant_binding_v1"


class ConcurrencyBindingDenied(ValueError):
    """The offline schedule lacks exact owned, shared-world, fresh provenance."""


@dataclass(frozen=True)
class ConcurrencyCaptureProvenance:
    contract_ref: str
    world_binding_refs: tuple[str, str]
    actor_refs: tuple[str, str]
    resource_ref: str
    tenant_ref: str
    tenant_ownership_ref: str
    capture_generation_ref: str
    captured_at_index: int
    valid_until_index: int
    operation_ids: tuple[str, ...]
    source_evidence_refs: tuple[str, ...]

    def __post_init__(self) -> None:
        if (
            not _hash_ref(self.contract_ref, "concurrency_invariant_contract")
            or type(self.world_binding_refs) is not tuple
            or len(self.world_binding_refs) != 2
            or len(set(self.world_binding_refs)) != 2
            or any(
                not _hash_ref(ref, "experiment_world_binding")
                for ref in self.world_binding_refs
            )
            or type(self.actor_refs) is not tuple
            or len(self.actor_refs) != 2
            or len(set(self.actor_refs)) != 2
            or any(not _hash_ref(ref) for ref in self.actor_refs)
            or not _hash_ref(self.resource_ref)
            or not _hash_ref(self.tenant_ref, "owned_tenant")
            or not _hash_ref(self.tenant_ownership_ref, "ownership_proof")
            or not _hash_ref(
                self.capture_generation_ref, "concurrency_capture_generation"
            )
            or not _integer(self.captured_at_index)
            or not _integer(self.valid_until_index, 1)
            or self.valid_until_index <= self.captured_at_index
            or type(self.operation_ids) is not tuple
            or not 2 <= len(self.operation_ids) <= MAX_CONCURRENCY_OPERATIONS
            or len(set(self.operation_ids)) != len(self.operation_ids)
            or any(
                not _hash_ref(ref, "concurrency_operation_contract")
                for ref in self.operation_ids
            )
            or type(self.source_evidence_refs) is not tuple
            or len(self.source_evidence_refs) != len(self.operation_ids)
            or any(not _hash_ref(ref) for ref in self.source_evidence_refs)
        ):
            raise ConcurrencyBindingDenied("concurrency_capture_provenance_invalid")

    def _payload(self) -> dict[str, Any]:
        return {
            "contract_ref": self.contract_ref,
            "world_binding_refs": list(self.world_binding_refs),
            "actor_refs": list(self.actor_refs),
            "resource_ref": self.resource_ref,
            "tenant_ref": self.tenant_ref,
            "tenant_ownership_ref": self.tenant_ownership_ref,
            "capture_generation_ref": self.capture_generation_ref,
            "captured_at_index": self.captured_at_index,
            "valid_until_index": self.valid_until_index,
            "operation_ids": list(self.operation_ids),
            "source_evidence_refs": list(self.source_evidence_refs),
        }

    @property
    def capture_id(self) -> str:
        return stable_hash("concurrency_capture_provenance", self._payload())

    def to_dict(self) -> dict[str, Any]:
        return {"schema_version": 1, "capture_id": self.capture_id, **self._payload()}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> ConcurrencyCaptureProvenance:
        value = _fields(
            value,
            {
                "capture_id",
                "contract_ref",
                "world_binding_refs",
                "actor_refs",
                "resource_ref",
                "tenant_ref",
                "tenant_ownership_ref",
                "capture_generation_ref",
                "captured_at_index",
                "valid_until_index",
                "operation_ids",
                "source_evidence_refs",
            },
        )
        list_fields = (
            "world_binding_refs",
            "actor_refs",
            "operation_ids",
            "source_evidence_refs",
        )
        if any(type(value[field]) is not list for field in list_fields):
            raise ConcurrencyBindingDenied("concurrency_capture_serialization_invalid")
        result = cls(
            contract_ref=value["contract_ref"],
            world_binding_refs=tuple(value["world_binding_refs"]),
            actor_refs=tuple(value["actor_refs"]),
            resource_ref=value["resource_ref"],
            tenant_ref=value["tenant_ref"],
            tenant_ownership_ref=value["tenant_ownership_ref"],
            capture_generation_ref=value["capture_generation_ref"],
            captured_at_index=value["captured_at_index"],
            valid_until_index=value["valid_until_index"],
            operation_ids=tuple(value["operation_ids"]),
            source_evidence_refs=tuple(value["source_evidence_refs"]),
        )
        if value != result.to_dict():
            raise ConcurrencyBindingDenied("concurrency_capture_address_mismatch")
        return result


@dataclass(frozen=True)
class ConcurrencyInvariantBinding:
    binding_id: str
    fixture: ConcurrencyOwnedFixture
    capture: ConcurrencyCaptureProvenance
    mode: str = CONCURRENCY_INVARIANT_BINDING_MODE

    def _payload(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "fixture": self.fixture.to_dict(),
            "capture": self.capture.to_dict(),
            **_passive_flags(),
        }

    @classmethod
    def build(
        cls, *, fixture: ConcurrencyOwnedFixture, capture: ConcurrencyCaptureProvenance
    ) -> ConcurrencyInvariantBinding:
        if (
            type(fixture) is not ConcurrencyOwnedFixture
            or type(capture) is not ConcurrencyCaptureProvenance
        ):
            raise ConcurrencyBindingDenied("concurrency_binding_types_invalid")
        _revalidate(fixture)
        _revalidate(capture)
        payload = {
            "mode": CONCURRENCY_INVARIANT_BINDING_MODE,
            "fixture": fixture.to_dict(),
            "capture": capture.to_dict(),
            **_passive_flags(),
        }
        return cls(
            stable_hash("concurrency_invariant_binding", payload), fixture, capture
        )

    def __post_init__(self) -> None:
        if (
            type(self.fixture) is not ConcurrencyOwnedFixture
            or type(self.capture) is not ConcurrencyCaptureProvenance
        ):
            raise ConcurrencyBindingDenied("concurrency_binding_types_invalid")
        _revalidate(self.fixture)
        _revalidate(self.capture)
        contract = self.fixture.contract
        capture = self.capture
        if (
            self.mode != CONCURRENCY_INVARIANT_BINDING_MODE
            or not _hash_ref(self.binding_id, "concurrency_invariant_binding")
            or self.binding_id
            != stable_hash("concurrency_invariant_binding", self._payload())
            or capture.contract_ref != contract.contract_id
            or capture.world_binding_refs
            != tuple(world.binding_id for world in self.fixture.worlds)
            or capture.actor_refs
            != tuple(world.persona_ref for world in self.fixture.worlds)
            or capture.resource_ref != contract.resource_ref
            or capture.tenant_ref != contract.tenant_ref
            or capture.tenant_ownership_ref != contract.tenant_ownership_ref
            or capture.operation_ids
            != tuple(op.operation_id for op in contract.operations)
        ):
            raise ConcurrencyBindingDenied("concurrency_binding_provenance_mismatch")

    def to_dict(self) -> dict[str, Any]:
        return {"schema_version": 1, "binding_id": self.binding_id, **self._payload()}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> ConcurrencyInvariantBinding:
        value = _fields(
            value, {"binding_id", "fixture", "capture", "mode", *_passive_flags()}
        )
        result = cls(
            value["binding_id"],
            ConcurrencyOwnedFixture.from_dict(value["fixture"]),
            ConcurrencyCaptureProvenance.from_dict(value["capture"]),
            value["mode"],
        )
        if value != result.to_dict():
            raise ConcurrencyBindingDenied("concurrency_binding_serialization_invalid")
        return result


def validate_current_capture(
    binding: ConcurrencyInvariantBinding,
    current_capture: ConcurrencyCaptureProvenance,
    at_index: int,
) -> None:
    if (
        type(binding) is not ConcurrencyInvariantBinding
        or type(current_capture) is not ConcurrencyCaptureProvenance
    ):
        raise ConcurrencyBindingDenied("concurrency_offline_context_invalid")
    _revalidate(binding)
    _revalidate(current_capture)
    if (
        not _integer(at_index)
        or current_capture.capture_id != binding.capture.capture_id
        or not current_capture.captured_at_index
        <= at_index
        < current_capture.valid_until_index
    ):
        raise ConcurrencyBindingDenied(
            "concurrency_current_capture_stale_or_mismatched"
        )


@dataclass(frozen=True)
class ConcurrencyOfflineEvaluation:
    binding: ConcurrencyInvariantBinding
    current_capture: ConcurrencyCaptureProvenance
    schedule: WorkflowSchedule
    at_index: int
    decision: ConcurrencyDecision

    def __post_init__(self) -> None:
        validate_current_capture(self.binding, self.current_capture, self.at_index)
        if (
            type(self.schedule) is not WorkflowSchedule
            or type(self.decision) is not ConcurrencyDecision
        ):
            raise ConcurrencyBindingDenied("concurrency_offline_types_invalid")
        _revalidate(self.schedule)
        _revalidate(self.decision)
        contract = self.binding.fixture.contract
        if (
            self.schedule.contract != contract
            or self.decision
            != classify_schedule(contract, contract.initial_state, self.schedule)
            or self.decision.outcome is ConcurrencyOutcome.MALFORMED
        ):
            raise ConcurrencyBindingDenied("concurrency_offline_decision_mismatch")

    def _payload(self) -> dict[str, Any]:
        return {
            "binding": self.binding.to_dict(),
            "current_capture": self.current_capture.to_dict(),
            "schedule": self.schedule.to_dict(),
            "at_index": self.at_index,
            "decision": self.decision.to_dict(),
            "observed_target_effect": False,
            **_passive_flags(),
        }

    @property
    def evaluation_id(self) -> str:
        return stable_hash("concurrency_offline_evaluation", self._payload())

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "evaluation_id": self.evaluation_id,
            **self._payload(),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> ConcurrencyOfflineEvaluation:
        value = _fields(
            value,
            {
                "evaluation_id",
                "binding",
                "current_capture",
                "schedule",
                "at_index",
                "decision",
                "observed_target_effect",
                *_passive_flags(),
            },
        )
        result = cls(
            ConcurrencyInvariantBinding.from_dict(value["binding"]),
            ConcurrencyCaptureProvenance.from_dict(value["current_capture"]),
            WorkflowSchedule.from_dict(value["schedule"]),
            value["at_index"],
            ConcurrencyDecision.from_dict(value["decision"]),
        )
        if value != result.to_dict():
            raise ConcurrencyBindingDenied(
                "concurrency_offline_address_or_flags_mismatch"
            )
        return result


def evaluate_offline(
    binding: ConcurrencyInvariantBinding,
    current_capture: ConcurrencyCaptureProvenance,
    schedule: WorkflowSchedule,
    *,
    at_index: int,
) -> ConcurrencyOfflineEvaluation:
    validate_current_capture(binding, current_capture, at_index)
    contract: ConcurrencyInvariantContract = binding.fixture.contract
    return ConcurrencyOfflineEvaluation(
        binding,
        current_capture,
        schedule,
        at_index,
        classify_schedule(contract, contract.initial_state, schedule),
    )
