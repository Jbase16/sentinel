"""Static admission manifests for graph-bound prerequisite experiments.

This boundary binds one R5B2 specification to the current signed authorization,
actor/world, execution policy, fresh-state obligations, cleanup obligations, and a
bounded request-unit plan.  It deliberately cannot provision state, reserve budget,
construct requests, invoke transport, dispatch a backend, or promote a finding.
"""

from __future__ import annotations

import copy
import re
from dataclasses import dataclass
from typing import Any, Dict, Optional, Sequence, Tuple
from urllib.parse import urlsplit

from core.cortex.execution_policy import PolicyExecutor
from core.foundry.authorization import AuthorizationEnvelope

from .experiment_admission import experiment_authority_context_ref
from .normalize import stable_hash
from .prerequisite_experiments import (
    GRAPH_BOUND_PREREQUISITE_REQUIRED_BLOCKERS,
    GraphBoundExperimentCompilationResult,
    GraphBoundPrerequisiteExperimentSpec,
    PrerequisiteCounterfactualFamily,
)

GRAPH_BOUND_PREREQUISITE_WORKFLOW = (
    "behavioral_graph_bound_prerequisite_experiment"
)
GRAPH_BOUND_MANIFEST_ADMISSION_MODE = (
    "behavioral_graph_bound_prerequisite_manifest_admission"
)
MAX_GRAPH_BOUND_MANIFEST_REQUEST_UNITS = 96

_HASH_REF = re.compile(r"^[a-z][a-z0-9_]*:[0-9a-f]{64}$")
_SEMANTIC = re.compile(r"^[a-z][a-z0-9_]{0,127}$")
_READY = "ready_for_explicit_execution_boundary"
_STATUSES = frozenset(
    {
        "not_requested",
        "source_blocked",
        "no_specifications",
        "authority_denied",
        "no_admissible_specifications",
        _READY,
    }
)
_INSTANCE_ROLES = (
    "counterfactual_treatment",
    "independent_control",
    "valid_baseline",
)
_PENDING_EXECUTION_BLOCKERS = (
    "atomic_budget_not_reserved",
    "cleanup_not_verified",
    "endpoint_budget_bindings_not_compiled",
    "explicit_execution_boundary_not_connected",
    "fresh_controlled_state_not_provisioned",
    "independent_effect_oracle_not_executed",
    "per_action_policy_preflight_not_completed",
    "single_use_receipt_not_acquired",
)
_BACKEND_BLOCKER_BY_FAMILY = {
    PrerequisiteCounterfactualFamily.OMISSION: "graph_omission_backend_required",
    PrerequisiteCounterfactualFamily.REORDERING: (
        "graph_reordering_backend_required"
    ),
}


class GraphBoundManifestAdmissionDenied(RuntimeError):
    """The current authority context cannot seal an R5B3a manifest."""


def _hash_ref(value: object, prefix: Optional[str] = None) -> bool:
    if not isinstance(value, str) or _HASH_REF.fullmatch(value) is None:
        return False
    return prefix is None or value.startswith(f"{prefix}:")


def _pending_execution_blockers(
    specification: GraphBoundPrerequisiteExperimentSpec,
) -> Tuple[str, ...]:
    backend_blocker = _BACKEND_BLOCKER_BY_FAMILY.get(specification.delta.family)
    if backend_blocker is None:
        raise ValueError("graph-bound experiment family has no backend contract")
    return tuple(sorted((*_PENDING_EXECUTION_BLOCKERS, backend_blocker)))


def _canonical_origin(value: str) -> str:
    if not isinstance(value, str):
        raise ValueError("graph-bound target origin must be a string")
    parts = urlsplit(value.strip())
    try:
        port = parts.port
    except ValueError as exc:
        raise ValueError("graph-bound target origin has an invalid port") from exc
    if (
        parts.scheme.lower() not in {"http", "https"}
        or not parts.hostname
        or parts.username is not None
        or parts.password is not None
        or parts.path not in {"", "/"}
        or parts.query
        or parts.fragment
    ):
        raise ValueError("graph-bound target origin is invalid")
    scheme = parts.scheme.lower()
    host = parts.hostname.lower()
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    default_port = (scheme == "http" and port == 80) or (
        scheme == "https" and port == 443
    )
    authority = host if port is None or default_port else f"{host}:{port}"
    return f"{scheme}://{authority}"


def _world_slot_payload(
    *,
    specification_id: str,
    actor_ref: str,
    role: str,
    lifecycle_ids: Sequence[str],
    cleanup_binding_ids: Sequence[str],
) -> Dict[str, Any]:
    planned_world_ref = stable_hash(
        "graph_bound_fresh_world",
        {
            "specification_id": specification_id,
            "actor_ref": actor_ref,
            "role": role,
        },
    )
    ownership_requirement_ref = stable_hash(
        "graph_bound_ownership_requirement",
        {
            "specification_id": specification_id,
            "actor_ref": actor_ref,
            "role": role,
            "lifecycle_ids": list(lifecycle_ids),
        },
    )
    return {
        "specification_id": specification_id,
        "actor_ref": actor_ref,
        "role": role,
        "planned_world_ref": planned_world_ref,
        "ownership_requirement_ref": ownership_requirement_ref,
        "lifecycle_ids": list(lifecycle_ids),
        "cleanup_binding_ids": list(cleanup_binding_ids),
        "ownership_proof_required": True,
        "freshness_attestation_required": True,
        "provisioned": False,
    }


@dataclass(frozen=True)
class GraphBoundFreshWorldSlot:
    slot_id: str
    specification_id: str
    actor_ref: str
    role: str
    planned_world_ref: str
    ownership_requirement_ref: str
    lifecycle_ids: Tuple[str, ...]
    cleanup_binding_ids: Tuple[str, ...]
    ownership_proof_required: bool = True
    freshness_attestation_required: bool = True
    provisioned: bool = False
    executable: bool = False

    @classmethod
    def build(
        cls,
        *,
        specification_id: str,
        actor_ref: str,
        role: str,
        lifecycle_ids: Sequence[str],
        cleanup_binding_ids: Sequence[str],
    ) -> "GraphBoundFreshWorldSlot":
        payload = _world_slot_payload(
            specification_id=specification_id,
            actor_ref=actor_ref,
            role=role,
            lifecycle_ids=lifecycle_ids,
            cleanup_binding_ids=cleanup_binding_ids,
        )
        return cls(
            slot_id=stable_hash("graph_bound_fresh_world_slot", payload),
            specification_id=specification_id,
            actor_ref=actor_ref,
            role=role,
            planned_world_ref=payload["planned_world_ref"],
            ownership_requirement_ref=payload["ownership_requirement_ref"],
            lifecycle_ids=tuple(lifecycle_ids),
            cleanup_binding_ids=tuple(cleanup_binding_ids),
        )

    def __post_init__(self) -> None:
        payload = _world_slot_payload(
            specification_id=self.specification_id,
            actor_ref=self.actor_ref,
            role=self.role,
            lifecycle_ids=self.lifecycle_ids,
            cleanup_binding_ids=self.cleanup_binding_ids,
        )
        if (
            self.slot_id != stable_hash("graph_bound_fresh_world_slot", payload)
            or not _hash_ref(
                self.specification_id,
                "graph_bound_prerequisite_experiment",
            )
            or not _hash_ref(self.actor_ref, "persona")
            or self.role not in _INSTANCE_ROLES
            or self.planned_world_ref != payload["planned_world_ref"]
            or self.ownership_requirement_ref
            != payload["ownership_requirement_ref"]
            or not self.lifecycle_ids
            or self.lifecycle_ids != tuple(sorted(set(self.lifecycle_ids)))
            or any(
                not _hash_ref(item, "owned_lifecycle")
                for item in self.lifecycle_ids
            )
            or not self.cleanup_binding_ids
            or self.cleanup_binding_ids
            != tuple(sorted(set(self.cleanup_binding_ids)))
            or any(
                not _hash_ref(item, "lineage_binding")
                for item in self.cleanup_binding_ids
            )
            or not self.ownership_proof_required
            or not self.freshness_attestation_required
            or self.provisioned
            or self.executable
        ):
            raise ValueError("graph-bound fresh-world slot contract is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "slot_id": self.slot_id,
            **_world_slot_payload(
                specification_id=self.specification_id,
                actor_ref=self.actor_ref,
                role=self.role,
                lifecycle_ids=self.lifecycle_ids,
                cleanup_binding_ids=self.cleanup_binding_ids,
            ),
            "executable": self.executable,
        }


def _budget_payload(
    *,
    specification_id: str,
    policy_ref: str,
    baseline_request_units: int,
    treatment_request_units: int,
    control_request_units: int,
    cleanup_request_units: int,
    cleanup_verification_request_units: int,
    total_request_units: int,
    policy_total_request_limit: int,
) -> Dict[str, Any]:
    return {
        "specification_id": specification_id,
        "policy_ref": policy_ref,
        "baseline_request_units": baseline_request_units,
        "treatment_request_units": treatment_request_units,
        "control_request_units": control_request_units,
        "cleanup_request_units": cleanup_request_units,
        "cleanup_verification_request_units": (
            cleanup_verification_request_units
        ),
        "total_request_units": total_request_units,
        "policy_total_request_limit": policy_total_request_limit,
        "manifest_request_ceiling": MAX_GRAPH_BOUND_MANIFEST_REQUEST_UNITS,
        "atomic_reservation_required": True,
        "endpoint_bindings_required": True,
        "reserved": False,
    }


@dataclass(frozen=True)
class GraphBoundRequestBudgetManifest:
    budget_id: str
    specification_id: str
    policy_ref: str
    baseline_request_units: int
    treatment_request_units: int
    control_request_units: int
    cleanup_request_units: int
    cleanup_verification_request_units: int
    total_request_units: int
    policy_total_request_limit: int
    manifest_request_ceiling: int = MAX_GRAPH_BOUND_MANIFEST_REQUEST_UNITS
    atomic_reservation_required: bool = True
    endpoint_bindings_required: bool = True
    reserved: bool = False
    executable: bool = False

    @classmethod
    def build(
        cls,
        *,
        specification: GraphBoundPrerequisiteExperimentSpec,
        policy_ref: str,
        policy_total_request_limit: int,
    ) -> "GraphBoundRequestBudgetManifest":
        if len(specification.cleanup.bindings) != 1:
            raise GraphBoundManifestAdmissionDenied(
                "graph_bound_multiple_cleanup_lifecycles_unsupported"
            )
        baseline_units = len(specification.delta.baseline_operation_ids)
        treatment_units = baseline_units
        if specification.delta.family is PrerequisiteCounterfactualFamily.OMISSION:
            treatment_units -= 1
        control_units = baseline_units
        cleanup_units = len(specification.cleanup.bindings) * len(_INSTANCE_ROLES)
        cleanup_verification_units = cleanup_units
        total_units = (
            baseline_units
            + treatment_units
            + control_units
            + cleanup_units
            + cleanup_verification_units
        )
        if (
            total_units > policy_total_request_limit
            or total_units > MAX_GRAPH_BOUND_MANIFEST_REQUEST_UNITS
        ):
            raise GraphBoundManifestAdmissionDenied(
                "graph_bound_manifest_request_budget_exceeded"
            )
        payload = _budget_payload(
            specification_id=specification.spec_id,
            policy_ref=policy_ref,
            baseline_request_units=baseline_units,
            treatment_request_units=treatment_units,
            control_request_units=control_units,
            cleanup_request_units=cleanup_units,
            cleanup_verification_request_units=cleanup_verification_units,
            total_request_units=total_units,
            policy_total_request_limit=policy_total_request_limit,
        )
        return cls(
            budget_id=stable_hash("graph_bound_request_budget", payload),
            specification_id=specification.spec_id,
            policy_ref=policy_ref,
            baseline_request_units=baseline_units,
            treatment_request_units=treatment_units,
            control_request_units=control_units,
            cleanup_request_units=cleanup_units,
            cleanup_verification_request_units=cleanup_verification_units,
            total_request_units=total_units,
            policy_total_request_limit=policy_total_request_limit,
        )

    def __post_init__(self) -> None:
        payload = _budget_payload(
            specification_id=self.specification_id,
            policy_ref=self.policy_ref,
            baseline_request_units=self.baseline_request_units,
            treatment_request_units=self.treatment_request_units,
            control_request_units=self.control_request_units,
            cleanup_request_units=self.cleanup_request_units,
            cleanup_verification_request_units=(
                self.cleanup_verification_request_units
            ),
            total_request_units=self.total_request_units,
            policy_total_request_limit=self.policy_total_request_limit,
        )
        unit_values = (
            self.baseline_request_units,
            self.treatment_request_units,
            self.control_request_units,
            self.cleanup_request_units,
            self.cleanup_verification_request_units,
            self.total_request_units,
            self.policy_total_request_limit,
            self.manifest_request_ceiling,
        )
        if (
            self.budget_id != stable_hash("graph_bound_request_budget", payload)
            or not _hash_ref(
                self.specification_id,
                "graph_bound_prerequisite_experiment",
            )
            or not _hash_ref(self.policy_ref, "graph_bound_experiment_policy")
            or any(
                isinstance(item, bool) or not isinstance(item, int) or item <= 0
                for item in unit_values
            )
            or self.total_request_units
            != (
                self.baseline_request_units
                + self.treatment_request_units
                + self.control_request_units
                + self.cleanup_request_units
                + self.cleanup_verification_request_units
            )
            or self.total_request_units > self.policy_total_request_limit
            or self.manifest_request_ceiling
            != MAX_GRAPH_BOUND_MANIFEST_REQUEST_UNITS
            or self.total_request_units > self.manifest_request_ceiling
            or not self.atomic_reservation_required
            or not self.endpoint_bindings_required
            or self.reserved
            or self.executable
        ):
            raise ValueError("graph-bound request-budget manifest is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "budget_id": self.budget_id,
            **_budget_payload(
                specification_id=self.specification_id,
                policy_ref=self.policy_ref,
                baseline_request_units=self.baseline_request_units,
                treatment_request_units=self.treatment_request_units,
                control_request_units=self.control_request_units,
                cleanup_request_units=self.cleanup_request_units,
                cleanup_verification_request_units=(
                    self.cleanup_verification_request_units
                ),
                total_request_units=self.total_request_units,
                policy_total_request_limit=self.policy_total_request_limit,
            ),
            "executable": self.executable,
        }


def _manifest_payload(
    *,
    compilation_result_id: str,
    lifecycle_capture_digest: str,
    specification: GraphBoundPrerequisiteExperimentSpec,
    target_ref: str,
    actor_ref: str,
    authorization_ref: str,
    authority_context_ref: str,
    policy_ref: str,
    world_slots: Sequence[GraphBoundFreshWorldSlot],
    budget: GraphBoundRequestBudgetManifest,
    pending_execution_blockers: Sequence[str],
) -> Dict[str, Any]:
    return {
        "compilation_result_id": compilation_result_id,
        "lifecycle_capture_digest": lifecycle_capture_digest,
        "specification_id": specification.spec_id,
        "state_machine_candidate_id": specification.state_machine_candidate_id,
        "prerequisite_graph_id": specification.prerequisite_graph_id,
        "support_rule_id": specification.support_rule_id,
        "delta_id": specification.delta.delta_id,
        "fresh_state_requirement_id": specification.fresh_state.requirement_id,
        "cleanup_requirement_id": specification.cleanup.cleanup_id,
        "oracle_requirement_id": specification.oracle.oracle_id,
        "target_ref": target_ref,
        "source_world_ref": specification.world_ref,
        "actor_ref": actor_ref,
        "authorization_ref": authorization_ref,
        "authority_context_ref": authority_context_ref,
        "policy_ref": policy_ref,
        "required_workflows": [GRAPH_BOUND_PREREQUISITE_WORKFLOW],
        "world_slots": [item.to_dict() for item in world_slots],
        "budget": budget.to_dict(),
        "pending_execution_blockers": list(pending_execution_blockers),
        "static_admission_ready": True,
        "dispatch_authority": False,
        "finding_authority": False,
        "target_requests_sent": 0,
        "executable": False,
    }


@dataclass(frozen=True)
class GraphBoundExperimentManifest:
    manifest_id: str
    compilation_result_id: str
    lifecycle_capture_digest: str
    specification: GraphBoundPrerequisiteExperimentSpec
    target_ref: str
    actor_ref: str
    authorization_ref: str
    authority_context_ref: str
    policy_ref: str
    world_slots: Tuple[GraphBoundFreshWorldSlot, ...]
    budget: GraphBoundRequestBudgetManifest
    pending_execution_blockers: Tuple[str, ...]
    static_admission_ready: bool = True
    dispatch_authority: bool = False
    finding_authority: bool = False
    target_requests_sent: int = 0
    executable: bool = False
    mode: str = GRAPH_BOUND_MANIFEST_ADMISSION_MODE

    def __post_init__(self) -> None:
        payload = _manifest_payload(
            compilation_result_id=self.compilation_result_id,
            lifecycle_capture_digest=self.lifecycle_capture_digest,
            specification=self.specification,
            target_ref=self.target_ref,
            actor_ref=self.actor_ref,
            authorization_ref=self.authorization_ref,
            authority_context_ref=self.authority_context_ref,
            policy_ref=self.policy_ref,
            world_slots=self.world_slots,
            budget=self.budget,
            pending_execution_blockers=self.pending_execution_blockers,
        )
        if (
            self.manifest_id != stable_hash("graph_bound_experiment_manifest", payload)
            or self.mode != GRAPH_BOUND_MANIFEST_ADMISSION_MODE
            or not _hash_ref(
                self.compilation_result_id,
                "graph_bound_experiment_compilation",
            )
            or not _hash_ref(self.lifecycle_capture_digest, "capture_set")
            or not isinstance(
                self.specification,
                GraphBoundPrerequisiteExperimentSpec,
            )
            or not _hash_ref(self.target_ref, "security_obligation_target")
            or not _hash_ref(self.actor_ref, "persona")
            or not _hash_ref(
                self.authorization_ref,
                "graph_bound_authorization",
            )
            or not _hash_ref(
                self.authority_context_ref,
                "experiment_authority_context",
            )
            or not _hash_ref(self.policy_ref, "graph_bound_experiment_policy")
            or len(self.world_slots) != len(_INSTANCE_ROLES)
            or tuple(item.role for item in self.world_slots) != _INSTANCE_ROLES
            or any(
                item.specification_id != self.specification.spec_id
                or item.actor_ref != self.actor_ref
                for item in self.world_slots
            )
            or len({item.slot_id for item in self.world_slots})
            != len(self.world_slots)
            or not isinstance(self.budget, GraphBoundRequestBudgetManifest)
            or self.budget.specification_id != self.specification.spec_id
            or self.budget.policy_ref != self.policy_ref
            or self.pending_execution_blockers
            != _pending_execution_blockers(self.specification)
            or any(
                _SEMANTIC.fullmatch(item) is None
                for item in self.pending_execution_blockers
            )
            or not self.static_admission_ready
            or self.dispatch_authority
            or self.finding_authority
            or self.target_requests_sent != 0
            or self.executable
        ):
            raise ValueError("graph-bound experiment manifest contract is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": 1,
            "mode": self.mode,
            "manifest_id": self.manifest_id,
            **_manifest_payload(
                compilation_result_id=self.compilation_result_id,
                lifecycle_capture_digest=self.lifecycle_capture_digest,
                specification=self.specification,
                target_ref=self.target_ref,
                actor_ref=self.actor_ref,
                authorization_ref=self.authorization_ref,
                authority_context_ref=self.authority_context_ref,
                policy_ref=self.policy_ref,
                world_slots=self.world_slots,
                budget=self.budget,
                pending_execution_blockers=self.pending_execution_blockers,
            ),
        }


@dataclass(frozen=True)
class GraphBoundManifestAdmissionDiagnostics:
    source_specifications: int
    manifests_compiled: int
    safety_blocked_specifications: int
    budget_blocked_specifications: int

    def __post_init__(self) -> None:
        values = (
            self.source_specifications,
            self.manifests_compiled,
            self.safety_blocked_specifications,
            self.budget_blocked_specifications,
        )
        if any(
            isinstance(item, bool) or not isinstance(item, int) or item < 0
            for item in values
        ) or self.manifests_compiled > self.source_specifications:
            raise ValueError("graph-bound admission diagnostics are invalid")

    def to_dict(self) -> Dict[str, int]:
        return {
            "source_specifications": self.source_specifications,
            "manifests_compiled": self.manifests_compiled,
            "safety_blocked_specifications": self.safety_blocked_specifications,
            "budget_blocked_specifications": self.budget_blocked_specifications,
        }


def _result_payload(
    *,
    status: str,
    compilation_result_id: str,
    target_ref: str,
    world_ref: str,
    authorization_ref: Optional[str],
    policy_ref: Optional[str],
    manifests: Sequence[GraphBoundExperimentManifest],
    blocker: Optional[str],
    diagnostics: GraphBoundManifestAdmissionDiagnostics,
) -> Dict[str, Any]:
    return {
        "status": status,
        "compilation_result_id": compilation_result_id,
        "target_ref": target_ref,
        "world_ref": world_ref,
        "authorization_ref": authorization_ref,
        "policy_ref": policy_ref,
        "manifests": [item.to_dict() for item in manifests],
        "blocker": blocker,
        "diagnostics": diagnostics.to_dict(),
        "static_admission_only": True,
        "dispatch_authority": False,
        "finding_authority": False,
        "target_requests_sent": 0,
        "executable": False,
    }


@dataclass(frozen=True)
class GraphBoundManifestAdmissionResult:
    result_id: str
    status: str
    compilation_result_id: str
    target_ref: str
    world_ref: str
    authorization_ref: Optional[str]
    policy_ref: Optional[str]
    manifests: Tuple[GraphBoundExperimentManifest, ...]
    blocker: Optional[str]
    diagnostics: GraphBoundManifestAdmissionDiagnostics
    static_admission_only: bool = True
    dispatch_authority: bool = False
    finding_authority: bool = False
    target_requests_sent: int = 0
    executable: bool = False
    mode: str = GRAPH_BOUND_MANIFEST_ADMISSION_MODE

    @classmethod
    def build(
        cls,
        *,
        status: str,
        compilation_result_id: str,
        target_ref: str,
        world_ref: str,
        authorization_ref: Optional[str],
        policy_ref: Optional[str],
        manifests: Sequence[GraphBoundExperimentManifest],
        blocker: Optional[str],
        diagnostics: GraphBoundManifestAdmissionDiagnostics,
    ) -> "GraphBoundManifestAdmissionResult":
        values = tuple(manifests)
        payload = _result_payload(
            status=status,
            compilation_result_id=compilation_result_id,
            target_ref=target_ref,
            world_ref=world_ref,
            authorization_ref=authorization_ref,
            policy_ref=policy_ref,
            manifests=values,
            blocker=blocker,
            diagnostics=diagnostics,
        )
        return cls(
            result_id=stable_hash("graph_bound_manifest_admission", payload),
            status=status,
            compilation_result_id=compilation_result_id,
            target_ref=target_ref,
            world_ref=world_ref,
            authorization_ref=authorization_ref,
            policy_ref=policy_ref,
            manifests=values,
            blocker=blocker,
            diagnostics=diagnostics,
        )

    def __post_init__(self) -> None:
        payload = _result_payload(
            status=self.status,
            compilation_result_id=self.compilation_result_id,
            target_ref=self.target_ref,
            world_ref=self.world_ref,
            authorization_ref=self.authorization_ref,
            policy_ref=self.policy_ref,
            manifests=self.manifests,
            blocker=self.blocker,
            diagnostics=self.diagnostics,
        )
        ready = self.status == _READY
        context_bound = self.authorization_ref is not None
        if (
            self.result_id
            != stable_hash("graph_bound_manifest_admission", payload)
            or self.mode != GRAPH_BOUND_MANIFEST_ADMISSION_MODE
            or self.status not in _STATUSES
            or not _hash_ref(
                self.compilation_result_id,
                "graph_bound_experiment_compilation",
            )
            or not _hash_ref(self.target_ref, "security_obligation_target")
            or not _hash_ref(self.world_ref, "world")
            or context_bound != (self.policy_ref is not None)
            or (
                self.authorization_ref is not None
                and not _hash_ref(
                    self.authorization_ref,
                    "graph_bound_authorization",
                )
            )
            or (
                self.policy_ref is not None
                and not _hash_ref(
                    self.policy_ref,
                    "graph_bound_experiment_policy",
                )
            )
            or ready != bool(self.manifests)
            or (ready and not context_bound)
            or tuple(sorted(self.manifests, key=lambda item: item.manifest_id))
            != self.manifests
            or any(
                item.compilation_result_id != self.compilation_result_id
                or item.target_ref != self.target_ref
                or item.authorization_ref != self.authorization_ref
                or item.policy_ref != self.policy_ref
                for item in self.manifests
            )
            or (self.blocker is None) != ready
            or (
                self.blocker is not None
                and _SEMANTIC.fullmatch(self.blocker) is None
            )
            or self.diagnostics.source_specifications
            < self.diagnostics.manifests_compiled
            or self.diagnostics.manifests_compiled != len(self.manifests)
            or not self.static_admission_only
            or self.dispatch_authority
            or self.finding_authority
            or self.target_requests_sent != 0
            or self.executable
        ):
            raise ValueError("graph-bound manifest admission result is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": 1,
            "mode": self.mode,
            "result_id": self.result_id,
            **_result_payload(
                status=self.status,
                compilation_result_id=self.compilation_result_id,
                target_ref=self.target_ref,
                world_ref=self.world_ref,
                authorization_ref=self.authorization_ref,
                policy_ref=self.policy_ref,
                manifests=self.manifests,
                blocker=self.blocker,
                diagnostics=self.diagnostics,
            ),
        }


class GraphBoundManifestAdmissionPlanner:
    """Seal R5B2 specifications under current authority without executing them."""

    @staticmethod
    def _result(
        *,
        status: str,
        compilation: GraphBoundExperimentCompilationResult,
        target_ref: str,
        world_ref: str,
        authorization_ref: Optional[str] = None,
        policy_ref: Optional[str] = None,
        manifests: Sequence[GraphBoundExperimentManifest] = (),
        blocker: Optional[str],
        safety_blocked: int = 0,
        budget_blocked: int = 0,
    ) -> GraphBoundManifestAdmissionResult:
        return GraphBoundManifestAdmissionResult.build(
            status=status,
            compilation_result_id=compilation.result_id,
            target_ref=target_ref,
            world_ref=world_ref,
            authorization_ref=authorization_ref,
            policy_ref=policy_ref,
            manifests=manifests,
            blocker=blocker,
            diagnostics=GraphBoundManifestAdmissionDiagnostics(
                source_specifications=len(compilation.specifications),
                manifests_compiled=len(manifests),
                safety_blocked_specifications=safety_blocked,
                budget_blocked_specifications=budget_blocked,
            ),
        )

    @staticmethod
    def _authority_refs(
        *,
        authorization: AuthorizationEnvelope,
        target_origin: str,
    ) -> Tuple[str, str]:
        try:
            copied = copy.deepcopy(authorization)
        except Exception as exc:
            raise GraphBoundManifestAdmissionDenied(
                "graph_bound_authorization_not_copyable"
            ) from exc
        if not copied.attestation_signature:
            raise GraphBoundManifestAdmissionDenied(
                "graph_bound_authorization_unsigned"
            )
        if not copied.signature_is_valid():
            raise GraphBoundManifestAdmissionDenied(
                "graph_bound_authorization_signature_invalid"
            )
        if copied.is_expired():
            raise GraphBoundManifestAdmissionDenied(
                "graph_bound_authorization_expired"
            )
        if not copied.disclosure_attestation or not copied.authorization_basis.strip():
            raise GraphBoundManifestAdmissionDenied(
                "graph_bound_authorization_attestation_incomplete"
            )
        try:
            copied.authorize_action(
                target_origin=target_origin,
                workflow=GRAPH_BOUND_PREREQUISITE_WORKFLOW,
            )
        except Exception as exc:
            raise GraphBoundManifestAdmissionDenied(
                "graph_bound_authorization_scope_or_workflow_denied"
            ) from exc
        authority_ref = experiment_authority_context_ref(
            copied,
            target_origin,
            (GRAPH_BOUND_PREREQUISITE_WORKFLOW,),
        )
        authorization_ref = stable_hash(
            "graph_bound_authorization",
            {
                "envelope_id": copied.envelope_id,
                "attestation_signature": copied.attestation_signature,
                "authority_context_ref": authority_ref,
            },
        )
        return authorization_ref, authority_ref

    @staticmethod
    def _policy_ref(executor: PolicyExecutor) -> str:
        digest = executor.policy.digest()
        if not isinstance(digest, str) or not digest:
            raise GraphBoundManifestAdmissionDenied(
                "graph_bound_execution_policy_digest_unavailable"
            )
        return stable_hash("graph_bound_experiment_policy", digest)

    @staticmethod
    def _world_slots(
        *,
        specification: GraphBoundPrerequisiteExperimentSpec,
        actor_ref: str,
    ) -> Tuple[GraphBoundFreshWorldSlot, ...]:
        lifecycle_ids = tuple(sorted(specification.fresh_state.lifecycle_ids))
        cleanup_binding_ids = tuple(
            sorted(item.cleanup_binding_id for item in specification.cleanup.bindings)
        )
        return tuple(
            GraphBoundFreshWorldSlot.build(
                specification_id=specification.spec_id,
                actor_ref=actor_ref,
                role=role,
                lifecycle_ids=lifecycle_ids,
                cleanup_binding_ids=cleanup_binding_ids,
            )
            for role in _INSTANCE_ROLES
        )

    def plan(
        self,
        *,
        compilation: GraphBoundExperimentCompilationResult,
        target_origin: str,
        target_ref: str,
        world_id: str,
        authorization: Optional[AuthorizationEnvelope] = None,
        executor: Optional[PolicyExecutor] = None,
        actor_persona_id: Optional[str] = None,
    ) -> GraphBoundManifestAdmissionResult:
        if not isinstance(compilation, GraphBoundExperimentCompilationResult):
            raise TypeError(
                "compilation must be a GraphBoundExperimentCompilationResult"
            )
        origin = _canonical_origin(target_origin)
        expected_target_ref = stable_hash("security_obligation_target", origin)
        if target_ref != expected_target_ref:
            raise ValueError("graph-bound admission target_ref mismatch")
        if not isinstance(world_id, str) or not world_id:
            raise ValueError("graph-bound admission world_id is required")
        world_ref = stable_hash("world", world_id)
        if any(item.world_ref != world_ref for item in compilation.specifications):
            raise ValueError("graph-bound admission source-world mismatch")

        context_values = (authorization, executor, actor_persona_id)
        if all(item is None for item in context_values):
            return self._result(
                status="not_requested",
                compilation=compilation,
                target_ref=target_ref,
                world_ref=world_ref,
                blocker="graph_bound_manifest_authority_context_not_requested",
            )
        if any(item is None for item in context_values):
            raise ValueError("graph-bound admission context must be complete")
        if not isinstance(authorization, AuthorizationEnvelope):
            raise TypeError("authorization must be an AuthorizationEnvelope")
        if not isinstance(executor, PolicyExecutor):
            raise TypeError("executor must be a PolicyExecutor")
        if actor_persona_id != world_id:
            raise ValueError("graph-bound admission actor/world mismatch")

        if compilation.status == "blocked":
            return self._result(
                status="source_blocked",
                compilation=compilation,
                target_ref=target_ref,
                world_ref=world_ref,
                blocker="graph_bound_source_compilation_blocked",
            )
        if not compilation.specifications:
            return self._result(
                status="no_specifications",
                compilation=compilation,
                target_ref=target_ref,
                world_ref=world_ref,
                blocker="graph_bound_source_has_no_specifications",
            )

        try:
            authorization_ref, authority_context_ref = self._authority_refs(
                authorization=authorization,
                target_origin=origin,
            )
            policy_ref = self._policy_ref(executor)
        except GraphBoundManifestAdmissionDenied as exc:
            return self._result(
                status="authority_denied",
                compilation=compilation,
                target_ref=target_ref,
                world_ref=world_ref,
                blocker=str(exc),
            )

        actor_ref = stable_hash("persona", actor_persona_id)
        manifests = []
        safety_blocked = 0
        budget_blocked = 0
        policy_limit = executor.policy.budget.max_total_requests
        for specification in compilation.specifications:
            if len(specification.cleanup.bindings) != 1:
                safety_blocked += 1
                continue
            backend_blocker = _BACKEND_BLOCKER_BY_FAMILY.get(
                specification.delta.family
            )
            expected_source_blockers = set(
                GRAPH_BOUND_PREREQUISITE_REQUIRED_BLOCKERS
            )
            if backend_blocker is not None:
                expected_source_blockers.add(backend_blocker)
            unresolved_source_blockers = set(
                specification.execution_blockers
            ) - expected_source_blockers
            if (
                backend_blocker is None
                or backend_blocker not in specification.execution_blockers
                or unresolved_source_blockers
            ):
                safety_blocked += 1
                continue
            try:
                budget = GraphBoundRequestBudgetManifest.build(
                    specification=specification,
                    policy_ref=policy_ref,
                    policy_total_request_limit=policy_limit,
                )
            except GraphBoundManifestAdmissionDenied:
                budget_blocked += 1
                continue
            slots = self._world_slots(
                specification=specification,
                actor_ref=actor_ref,
            )
            payload = _manifest_payload(
                compilation_result_id=compilation.result_id,
                lifecycle_capture_digest=compilation.lifecycle_capture_digest,
                specification=specification,
                target_ref=target_ref,
                actor_ref=actor_ref,
                authorization_ref=authorization_ref,
                authority_context_ref=authority_context_ref,
                policy_ref=policy_ref,
                world_slots=slots,
                budget=budget,
                pending_execution_blockers=_pending_execution_blockers(
                    specification
                ),
            )
            manifests.append(
                GraphBoundExperimentManifest(
                    manifest_id=stable_hash(
                        "graph_bound_experiment_manifest",
                        payload,
                    ),
                    compilation_result_id=compilation.result_id,
                    lifecycle_capture_digest=compilation.lifecycle_capture_digest,
                    specification=specification,
                    target_ref=target_ref,
                    actor_ref=actor_ref,
                    authorization_ref=authorization_ref,
                    authority_context_ref=authority_context_ref,
                    policy_ref=policy_ref,
                    world_slots=slots,
                    budget=budget,
                    pending_execution_blockers=(
                        _pending_execution_blockers(specification)
                    ),
                )
            )

        ordered = tuple(sorted(manifests, key=lambda item: item.manifest_id))
        if not ordered:
            return self._result(
                status="no_admissible_specifications",
                compilation=compilation,
                target_ref=target_ref,
                world_ref=world_ref,
                authorization_ref=authorization_ref,
                policy_ref=policy_ref,
                blocker="graph_bound_no_specification_passed_static_admission",
                safety_blocked=safety_blocked,
                budget_blocked=budget_blocked,
            )
        return self._result(
            status=_READY,
            compilation=compilation,
            target_ref=target_ref,
            world_ref=world_ref,
            authorization_ref=authorization_ref,
            policy_ref=policy_ref,
            manifests=ordered,
            blocker=None,
            safety_blocked=safety_blocked,
            budget_blocked=budget_blocked,
        )


__all__ = [
    "GRAPH_BOUND_MANIFEST_ADMISSION_MODE",
    "GRAPH_BOUND_PREREQUISITE_WORKFLOW",
    "MAX_GRAPH_BOUND_MANIFEST_REQUEST_UNITS",
    "GraphBoundExperimentManifest",
    "GraphBoundFreshWorldSlot",
    "GraphBoundManifestAdmissionDenied",
    "GraphBoundManifestAdmissionDiagnostics",
    "GraphBoundManifestAdmissionPlanner",
    "GraphBoundManifestAdmissionResult",
    "GraphBoundRequestBudgetManifest",
]
