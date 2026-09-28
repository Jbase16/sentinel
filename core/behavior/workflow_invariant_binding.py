"""R5E2: passive/unwired owned-world, provenance and freshness binding.

Operator-supplied current-capture commitments bind every ordered operation to one
SDK owned account, tenant and origin. Freshness is an exact capture comparison plus
an inclusive/exclusive logical window at an operator-injected index; no clock or
target is consulted. Offline results are deterministic outcome evaluations, not
independent evidence of an observed target-side effect.

No production caller imports this layer. It adds no origin, identity, action class,
budget reservation, transport, or execution/finding/promotion authority. Disposable
fixtures create no target residue, require no cleanup, and have orphan-risk false.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any, Mapping

from .experiment_sdk import ExperimentWorldBinding, ExperimentWorldKind, _hash_ref
from .normalize import stable_hash
from .prerequisite_capture_freshness import _canonical_origin
from .workflow_invariant_contract import (
    MAX_WORKFLOW_OPERATIONS,
    WorkflowInvariantContract,
    WorkflowInvariantDecision,
    WorkflowInvariantOutcome,
    WorkflowOwnedFixture,
    _fields,
    _integer,
    classify_sequence,
)

WORKFLOW_INVARIANT_BINDING_MODE = "behavioral_workflow_invariant_binding_v1"


class WorkflowBindingDenied(ValueError):
    """Offline evidence does not bind one owned world with a fresh capture."""


@dataclass(frozen=True)
class WorkflowCaptureProvenance:
    contract_ref: str
    world_binding_ref: str
    account_ref: str
    tenant_ref: str
    tenant_ownership_ref: str
    origin_ref: str
    capture_generation_ref: str
    captured_at_index: int
    valid_until_index: int
    operation_ids: tuple[str, ...]
    source_evidence_refs: tuple[str, ...]

    def __post_init__(self) -> None:
        refs = (
            (self.contract_ref, "workflow_invariant_contract"),
            (self.world_binding_ref, "experiment_world_binding"),
            (self.account_ref, None),
            (self.tenant_ref, "owned_tenant"),
            (self.tenant_ownership_ref, "ownership_proof"),
            (self.origin_ref, "behavioral_capture_target"),
            (self.capture_generation_ref, "workflow_capture_generation"),
        )
        if (
            any(not _hash_ref(value, prefix) for value, prefix in refs)
            or not _integer(self.captured_at_index)
            or not _integer(self.valid_until_index, 1)
            or self.valid_until_index <= self.captured_at_index
            or type(self.operation_ids) is not tuple
            or type(self.source_evidence_refs) is not tuple
            or not 1 <= len(self.operation_ids) <= MAX_WORKFLOW_OPERATIONS
            or len(self.source_evidence_refs) != len(self.operation_ids)
            or len(set(self.operation_ids)) != len(self.operation_ids)
            or any(
                not _hash_ref(ref, "workflow_operation_contract")
                for ref in self.operation_ids
            )
            or any(not _hash_ref(ref) for ref in self.source_evidence_refs)
        ):
            raise WorkflowBindingDenied("workflow_capture_provenance_invalid")

    def _payload(self) -> dict[str, Any]:
        return {
            "contract_ref": self.contract_ref,
            "world_binding_ref": self.world_binding_ref,
            "account_ref": self.account_ref,
            "tenant_ref": self.tenant_ref,
            "tenant_ownership_ref": self.tenant_ownership_ref,
            "origin_ref": self.origin_ref,
            "capture_generation_ref": self.capture_generation_ref,
            "captured_at_index": self.captured_at_index,
            "valid_until_index": self.valid_until_index,
            "operation_ids": list(self.operation_ids),
            "source_evidence_refs": list(self.source_evidence_refs),
        }

    @property
    def capture_id(self) -> str:
        return stable_hash("workflow_capture_provenance", self._payload())

    def to_dict(self) -> dict[str, Any]:
        return {"schema_version": 1, "capture_id": self.capture_id, **self._payload()}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> WorkflowCaptureProvenance:
        value = _fields(
            value,
            {
                "capture_id",
                "contract_ref",
                "world_binding_ref",
                "account_ref",
                "tenant_ref",
                "tenant_ownership_ref",
                "origin_ref",
                "capture_generation_ref",
                "captured_at_index",
                "valid_until_index",
                "operation_ids",
                "source_evidence_refs",
            },
        )
        if (
            type(value["operation_ids"]) is not list
            or type(value["source_evidence_refs"]) is not list
        ):
            raise WorkflowBindingDenied("workflow_capture_serialization_invalid")
        result = cls(
            **{
                key: value[key]
                for key in value
                if key
                not in {
                    "schema_version",
                    "capture_id",
                    "operation_ids",
                    "source_evidence_refs",
                }
            },
            operation_ids=tuple(value["operation_ids"]),
            source_evidence_refs=tuple(value["source_evidence_refs"]),
        )
        if value["capture_id"] != result.capture_id:
            raise WorkflowBindingDenied("workflow_capture_address_mismatch")
        return result


@dataclass(frozen=True)
class WorkflowInvariantBinding:
    binding_id: str
    fixture: WorkflowOwnedFixture
    capture: WorkflowCaptureProvenance
    target_origin_ref: str
    mode: str = WORKFLOW_INVARIANT_BINDING_MODE

    def _payload(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "fixture": self.fixture.to_dict(),
            "capture": self.capture.to_dict(),
            "target_origin_ref": self.target_origin_ref,
            "target_requests_sent": 0,
            "backend_dispatch_authority": False,
            "promotion_authority": False,
            "executable": False,
        }

    @classmethod
    def build(
        cls,
        *,
        fixture: WorkflowOwnedFixture,
        capture: WorkflowCaptureProvenance,
        target_origin: str,
    ) -> WorkflowInvariantBinding:
        if (
            type(fixture) is not WorkflowOwnedFixture
            or type(capture) is not WorkflowCaptureProvenance
        ):
            raise WorkflowBindingDenied("workflow_binding_types_invalid")
        replace(fixture)
        replace(capture)
        origin_ref = stable_hash(
            "behavioral_capture_target", _canonical_origin(target_origin)
        )
        payload = {
            "mode": WORKFLOW_INVARIANT_BINDING_MODE,
            "fixture": fixture.to_dict(),
            "capture": capture.to_dict(),
            "target_origin_ref": origin_ref,
            "target_requests_sent": 0,
            "backend_dispatch_authority": False,
            "promotion_authority": False,
            "executable": False,
        }
        return cls(
            stable_hash("workflow_invariant_binding", payload),
            fixture,
            capture,
            origin_ref,
        )

    def __post_init__(self) -> None:
        if (
            type(self.fixture) is not WorkflowOwnedFixture
            or type(self.capture) is not WorkflowCaptureProvenance
        ):
            raise WorkflowBindingDenied("workflow_binding_types_invalid")
        replace(self.fixture)
        replace(self.capture)
        contract, world, capture = (
            self.fixture.contract,
            self.fixture.world,
            self.capture,
        )
        if (
            self.mode != WORKFLOW_INVARIANT_BINDING_MODE
            or self.binding_id
            != stable_hash("workflow_invariant_binding", self._payload())
            or not _hash_ref(self.binding_id, "workflow_invariant_binding")
            or not _hash_ref(self.target_origin_ref, "behavioral_capture_target")
            or capture.contract_ref != contract.contract_id
            or capture.world_binding_ref != world.binding_id
            or capture.account_ref != contract.account_ref
            or capture.tenant_ref != contract.tenant_ref
            or capture.tenant_ownership_ref != contract.tenant_ownership_ref
            or capture.origin_ref != self.target_origin_ref
            or capture.operation_ids
            != tuple(op.operation_id for op in contract.operations)
        ):
            raise WorkflowBindingDenied(
                "workflow_binding_identity_or_provenance_mismatch"
            )

    def to_dict(self) -> dict[str, Any]:
        return {"schema_version": 1, "binding_id": self.binding_id, **self._payload()}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> WorkflowInvariantBinding:
        value = _fields(
            value,
            {
                "binding_id",
                "mode",
                "fixture",
                "capture",
                "target_origin_ref",
                "target_requests_sent",
                "backend_dispatch_authority",
                "promotion_authority",
                "executable",
            },
        )
        raw_fixture = value["fixture"]
        if not isinstance(raw_fixture, Mapping) or not isinstance(
            raw_fixture.get("world"), Mapping
        ):
            raise WorkflowBindingDenied("workflow_fixture_serialization_invalid")
        raw_world = raw_fixture["world"]
        world = ExperimentWorldBinding(
            **{key: item for key, item in raw_world.items() if key != "kind"},
            kind=ExperimentWorldKind(raw_world["kind"]),
        )
        fixture = WorkflowOwnedFixture(
            contract=WorkflowInvariantContract.from_dict(raw_fixture["contract"]),
            world=world,
            world_tenant_ref=raw_fixture["tenant_ref"],
            world_tenant_ownership_ref=raw_fixture["tenant_ownership_ref"],
        )
        if stable_hash("workflow_fixture_record", raw_fixture) != stable_hash(
            "workflow_fixture_record", fixture.to_dict()
        ):
            raise WorkflowBindingDenied("workflow_fixture_serialization_invalid")
        result = cls(
            binding_id=value["binding_id"],
            fixture=fixture,
            capture=WorkflowCaptureProvenance.from_dict(value["capture"]),
            target_origin_ref=value["target_origin_ref"],
            mode=value["mode"],
        )
        if stable_hash("workflow_binding_record", value) != stable_hash(
            "workflow_binding_record", result.to_dict()
        ):
            raise WorkflowBindingDenied("workflow_binding_serialization_invalid")
        return result


def validate_current_capture(
    binding: WorkflowInvariantBinding,
    current_capture: WorkflowCaptureProvenance,
    at_index: int,
) -> None:
    """Recheck owned context, exact capture and logical freshness before evaluation."""
    if (
        type(binding) is not WorkflowInvariantBinding
        or type(current_capture) is not WorkflowCaptureProvenance
    ):
        raise WorkflowBindingDenied("workflow_offline_context_invalid")
    replace(binding)
    replace(current_capture)
    if (
        not _integer(at_index)
        or current_capture.capture_id != binding.capture.capture_id
        or not current_capture.captured_at_index
        <= at_index
        < current_capture.valid_until_index
    ):
        raise WorkflowBindingDenied("workflow_current_capture_stale_or_mismatched")


@dataclass(frozen=True)
class WorkflowOfflineEvaluation:
    binding: WorkflowInvariantBinding
    current_capture: WorkflowCaptureProvenance
    at_index: int
    decision: WorkflowInvariantDecision

    def __post_init__(self) -> None:
        validate_current_capture(self.binding, self.current_capture, self.at_index)
        if type(self.decision) is not WorkflowInvariantDecision:
            raise WorkflowBindingDenied("workflow_offline_decision_invalid")
        replace(self.decision)
        contract = self.binding.fixture.contract
        expected = classify_sequence(
            contract, contract.initial_state, contract.operations
        )
        if (
            self.decision != expected
            or self.decision.outcome is WorkflowInvariantOutcome.MALFORMED
        ):
            raise WorkflowBindingDenied("workflow_offline_decision_mismatch")

    def _payload(self) -> dict[str, Any]:
        return {
            "mode": WORKFLOW_INVARIANT_BINDING_MODE,
            "binding": self.binding.to_dict(),
            "current_capture": self.current_capture.to_dict(),
            "at_index": self.at_index,
            "decision": self.decision.to_dict(),
            "observed_target_effect": False,
            "target_requests_sent": 0,
            "executable": False,
            "promotion_authority": False,
        }

    @property
    def evaluation_id(self) -> str:
        return stable_hash("workflow_offline_evaluation", self._payload())

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "evaluation_id": self.evaluation_id,
            **self._payload(),
        }


def evaluate_offline(
    binding: WorkflowInvariantBinding,
    current_capture: WorkflowCaptureProvenance,
    *,
    at_index: int,
) -> WorkflowOfflineEvaluation:
    validate_current_capture(binding, current_capture, at_index)
    contract = binding.fixture.contract
    return WorkflowOfflineEvaluation(
        binding,
        current_capture,
        at_index,
        classify_sequence(contract, contract.initial_state, contract.operations),
    )
