"""Single-use claim admission for graph-bound prerequisite experiments.

R5B3b2a revalidates the current authority, capture, graph compilation, static
manifest, concrete request plan, policy decisions, and ordered budget sequence before
it performs two local side effects: reserving a durable receipt and atomically holding
the complete proof budget. This module has no transport or backend-dispatch surface;
its claimed handle can be consumed only by a separate default-off active boundary.
"""

from __future__ import annotations

import copy
import os
import re
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple
from urllib.parse import urlsplit

from core.cortex.execution_policy import PolicyExecutor
from core.foundry.authorization import AuthorizationEnvelope
from core.safety.proof_budget import ProofBudget

from .lifecycle import LifecycleMiningResult
from .normalize import stable_hash
from .prerequisite_admission import (
    GraphBoundExperimentManifest,
    GraphBoundManifestAdmissionPlanner,
    GraphBoundManifestAdmissionResult,
)
from .prerequisite_experiments import GraphBoundExperimentCompilationResult
from .prerequisite_request_binding import (
    GraphBoundPreparedRequestPlan,
    GraphBoundRequestBinder,
    GraphBoundRequestBindingResult,
)
from .receipts import (
    BehavioralReceiptContext,
    BehavioralReceiptStore,
    redacted_receipt_context,
    request_fingerprint,
)
from .state_machine import StateMachineLegalityResult

GRAPH_BOUND_EXECUTION_CLAIM_ENV = "SENTINELFORGE_BEHAVIOR_GRAPH_BOUND_EXECUTION_CLAIM"
GRAPH_BOUND_EXECUTION_CLAIM_MODE = "behavioral_graph_bound_execution_claim_v1"

_TRUE = frozenset({"1", "true", "yes", "on"})
_HASH_REF = re.compile(r"^[a-z][a-z0-9_]*:[0-9a-f]{64}$")
_BARE_HASH = re.compile(r"^[0-9a-f]{64}$")
_SEMANTIC = re.compile(r"^[a-z][a-z0-9_]{0,127}$")
_SUPPORTED_FAMILIES = frozenset({"omission", "reordering"})
_RUNTIME_STAGE_ORDER = {"provision": 0, "dispatch": 1, "cleanup": 2}
_RESOLVED_BLOCKERS = frozenset(
    {
        "atomic_budget_not_reserved",
        "single_use_receipt_not_acquired",
    }
)


class GraphBoundExecutionClaimDenied(RuntimeError):
    """The graph-bound claim failed before target execution was possible."""

    def __init__(self, reason: str, *, category: str = "admission") -> None:
        super().__init__(reason)
        self.category = category


def _hash_ref(value: object, prefix: Optional[str] = None) -> bool:
    return (
        isinstance(value, str)
        and _HASH_REF.fullmatch(value) is not None
        and (prefix is None or value.startswith(f"{prefix}:"))
    )


def _canonical_origin(value: str) -> str:
    parsed = urlsplit(str(value or "").strip())
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise GraphBoundExecutionClaimDenied(
            "graph_bound_execution_target_origin_invalid"
        )
    return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"


def _preview_payload(
    *,
    plan: GraphBoundPreparedRequestPlan,
    binding: GraphBoundRequestBindingResult,
    manifest: GraphBoundExperimentManifest,
    receipt_fingerprint_ref: str,
    remaining_execution_blockers: Sequence[str],
) -> Dict[str, Any]:
    return {
        "plan_id": plan.plan_id,
        "manifest_id": plan.manifest_id,
        "request_binding_result_id": binding.result_id,
        "admission_result_id": binding.admission_result_id,
        "compilation_result_id": binding.compilation_result_id,
        "target_ref": binding.target_ref,
        "world_ref": binding.world_ref,
        "actor_ref": manifest.actor_ref,
        "authorization_ref": manifest.authorization_ref,
        "authority_context_ref": manifest.authority_context_ref,
        "policy_ref": binding.policy_ref,
        "family": plan.family,
        "action_binding_ids": [item.binding_id for item in plan.request_bindings],
        "budget_binding_ids": [item.entry_id for item in plan.budget_bindings],
        "budget_preview_ref": plan.budget_preview_ref,
        "receipt_fingerprint_ref": receipt_fingerprint_ref,
        "total_request_units": len(plan.request_bindings),
        "remaining_execution_blockers": list(remaining_execution_blockers),
        "current_context_revalidated": True,
        "budget_reservation_allowed": True,
        "durable_receipt_reserved": False,
        "budget_reserved": False,
        "claim_available": False,
        "single_use_claim_acquired": False,
        "world_provisioning_authority": False,
        "backend_dispatch_authority": False,
        "finding_authority": False,
        "target_requests_sent": 0,
        "executable": False,
    }


@dataclass(frozen=True)
class GraphBoundExecutionClaimPreview:
    preview_id: str
    plan_id: str
    manifest_id: str
    request_binding_result_id: str
    admission_result_id: str
    compilation_result_id: str
    target_ref: str
    world_ref: str
    actor_ref: str
    authorization_ref: str
    authority_context_ref: str
    policy_ref: str
    family: str
    action_binding_ids: Tuple[str, ...]
    budget_binding_ids: Tuple[str, ...]
    budget_preview_ref: str
    receipt_fingerprint_ref: str
    total_request_units: int
    remaining_execution_blockers: Tuple[str, ...]
    current_context_revalidated: bool = True
    budget_reservation_allowed: bool = True
    durable_receipt_reserved: bool = False
    budget_reserved: bool = False
    claim_available: bool = False
    single_use_claim_acquired: bool = False
    world_provisioning_authority: bool = False
    backend_dispatch_authority: bool = False
    finding_authority: bool = False
    target_requests_sent: int = 0
    executable: bool = False
    mode: str = GRAPH_BOUND_EXECUTION_CLAIM_MODE

    @classmethod
    def build(
        cls,
        *,
        plan: GraphBoundPreparedRequestPlan,
        binding: GraphBoundRequestBindingResult,
        manifest: GraphBoundExperimentManifest,
        receipt_fingerprint_ref: str,
        remaining_execution_blockers: Sequence[str],
    ) -> "GraphBoundExecutionClaimPreview":
        blockers = tuple(remaining_execution_blockers)
        payload = _preview_payload(
            plan=plan,
            binding=binding,
            manifest=manifest,
            receipt_fingerprint_ref=receipt_fingerprint_ref,
            remaining_execution_blockers=blockers,
        )
        return cls(
            preview_id=stable_hash("graph_bound_execution_claim_preview", payload),
            plan_id=plan.plan_id,
            manifest_id=plan.manifest_id,
            request_binding_result_id=binding.result_id,
            admission_result_id=binding.admission_result_id,
            compilation_result_id=binding.compilation_result_id,
            target_ref=binding.target_ref,
            world_ref=binding.world_ref,
            actor_ref=manifest.actor_ref,
            authorization_ref=manifest.authorization_ref,
            authority_context_ref=manifest.authority_context_ref,
            policy_ref=binding.policy_ref or "",
            family=plan.family,
            action_binding_ids=tuple(item.binding_id for item in plan.request_bindings),
            budget_binding_ids=tuple(item.entry_id for item in plan.budget_bindings),
            budget_preview_ref=plan.budget_preview_ref,
            receipt_fingerprint_ref=receipt_fingerprint_ref,
            total_request_units=len(plan.request_bindings),
            remaining_execution_blockers=blockers,
        )

    def __post_init__(self) -> None:
        payload = {
            "plan_id": self.plan_id,
            "manifest_id": self.manifest_id,
            "request_binding_result_id": self.request_binding_result_id,
            "admission_result_id": self.admission_result_id,
            "compilation_result_id": self.compilation_result_id,
            "target_ref": self.target_ref,
            "world_ref": self.world_ref,
            "actor_ref": self.actor_ref,
            "authorization_ref": self.authorization_ref,
            "authority_context_ref": self.authority_context_ref,
            "policy_ref": self.policy_ref,
            "family": self.family,
            "action_binding_ids": list(self.action_binding_ids),
            "budget_binding_ids": list(self.budget_binding_ids),
            "budget_preview_ref": self.budget_preview_ref,
            "receipt_fingerprint_ref": self.receipt_fingerprint_ref,
            "total_request_units": self.total_request_units,
            "remaining_execution_blockers": list(self.remaining_execution_blockers),
            "current_context_revalidated": self.current_context_revalidated,
            "budget_reservation_allowed": self.budget_reservation_allowed,
            "durable_receipt_reserved": self.durable_receipt_reserved,
            "budget_reserved": self.budget_reserved,
            "claim_available": self.claim_available,
            "single_use_claim_acquired": self.single_use_claim_acquired,
            "world_provisioning_authority": self.world_provisioning_authority,
            "backend_dispatch_authority": self.backend_dispatch_authority,
            "finding_authority": self.finding_authority,
            "target_requests_sent": self.target_requests_sent,
            "executable": self.executable,
        }
        refs = (
            (self.plan_id, "graph_bound_prepared_request_plan"),
            (self.manifest_id, "graph_bound_experiment_manifest"),
            (
                self.request_binding_result_id,
                "graph_bound_request_binding_result",
            ),
            (self.admission_result_id, "graph_bound_manifest_admission"),
            (
                self.compilation_result_id,
                "graph_bound_experiment_compilation",
            ),
            (self.target_ref, "security_obligation_target"),
            (self.world_ref, "world"),
            (self.actor_ref, "persona"),
            (self.authorization_ref, "graph_bound_authorization"),
            (self.authority_context_ref, "experiment_authority_context"),
            (self.policy_ref, "graph_bound_experiment_policy"),
            (self.budget_preview_ref, "graph_bound_budget_preview"),
            (
                self.receipt_fingerprint_ref,
                "graph_bound_execution_claim_fingerprint",
            ),
        )
        invalid_flags = (
            not self.current_context_revalidated
            or not self.budget_reservation_allowed
            or self.durable_receipt_reserved
            or self.budget_reserved
            or self.claim_available
            or self.single_use_claim_acquired
            or self.world_provisioning_authority
            or self.backend_dispatch_authority
            or self.finding_authority
            or self.target_requests_sent != 0
            or self.executable
        )
        if (
            self.preview_id
            != stable_hash("graph_bound_execution_claim_preview", payload)
            or self.mode != GRAPH_BOUND_EXECUTION_CLAIM_MODE
            or any(not _hash_ref(value, prefix) for value, prefix in refs)
            or self.family not in _SUPPORTED_FAMILIES
            or not self.action_binding_ids
            or len(set(self.action_binding_ids)) != len(self.action_binding_ids)
            or any(
                not _hash_ref(item, "graph_bound_request_action")
                for item in self.action_binding_ids
            )
            or len(self.budget_binding_ids) != len(self.action_binding_ids)
            or len(set(self.budget_binding_ids)) != len(self.budget_binding_ids)
            or any(
                not _hash_ref(item, "graph_bound_endpoint_budget")
                for item in self.budget_binding_ids
            )
            or isinstance(self.total_request_units, bool)
            or self.total_request_units != len(self.action_binding_ids)
            or self.remaining_execution_blockers
            != tuple(sorted(set(self.remaining_execution_blockers)))
            or not self.remaining_execution_blockers
            or any(
                _SEMANTIC.fullmatch(item) is None
                for item in self.remaining_execution_blockers
            )
            or invalid_flags
        ):
            raise ValueError("graph-bound execution claim preview is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": 1,
            "mode": self.mode,
            "preview_id": self.preview_id,
            "plan_id": self.plan_id,
            "manifest_id": self.manifest_id,
            "request_binding_result_id": self.request_binding_result_id,
            "admission_result_id": self.admission_result_id,
            "compilation_result_id": self.compilation_result_id,
            "target_ref": self.target_ref,
            "world_ref": self.world_ref,
            "actor_ref": self.actor_ref,
            "authorization_ref": self.authorization_ref,
            "authority_context_ref": self.authority_context_ref,
            "policy_ref": self.policy_ref,
            "family": self.family,
            "action_binding_ids": list(self.action_binding_ids),
            "budget_binding_ids": list(self.budget_binding_ids),
            "budget_preview_ref": self.budget_preview_ref,
            "receipt_fingerprint_ref": self.receipt_fingerprint_ref,
            "total_request_units": self.total_request_units,
            "remaining_execution_blockers": list(self.remaining_execution_blockers),
            "current_context_revalidated": True,
            "budget_reservation_allowed": True,
            "durable_receipt_reserved": False,
            "budget_reserved": False,
            "claim_available": False,
            "single_use_claim_acquired": False,
            "world_provisioning_authority": False,
            "backend_dispatch_authority": False,
            "finding_authority": False,
            "target_requests_sent": 0,
            "executable": False,
        }


def _contract_payload(
    *,
    preview: GraphBoundExecutionClaimPreview,
    receipt_ref: str,
    budget_reservation_ref: str,
) -> Dict[str, Any]:
    payload = preview.to_dict()
    payload.pop("schema_version")
    payload.pop("mode")
    payload.update(
        {
            "receipt_ref": receipt_ref,
            "budget_reservation_ref": budget_reservation_ref,
            "durable_receipt_reserved": True,
            "budget_reserved": True,
            "claim_available": True,
        }
    )
    return payload


@dataclass(frozen=True)
class GraphBoundExecutionClaimContract:
    contract_id: str
    preview: GraphBoundExecutionClaimPreview
    receipt_ref: str
    budget_reservation_ref: str
    durable_receipt_reserved: bool = True
    budget_reserved: bool = True
    claim_available: bool = True
    single_use_claim_acquired: bool = False
    world_provisioning_authority: bool = False
    backend_dispatch_authority: bool = False
    finding_authority: bool = False
    target_requests_sent: int = 0
    executable: bool = False
    mode: str = GRAPH_BOUND_EXECUTION_CLAIM_MODE

    @classmethod
    def build(
        cls,
        *,
        preview: GraphBoundExecutionClaimPreview,
        receipt_id: str,
        budget_reservation_id: str,
    ) -> "GraphBoundExecutionClaimContract":
        receipt_ref = stable_hash("graph_bound_execution_receipt", receipt_id)
        budget_ref = stable_hash(
            "graph_bound_budget_reservation",
            budget_reservation_id,
        )
        payload = _contract_payload(
            preview=preview,
            receipt_ref=receipt_ref,
            budget_reservation_ref=budget_ref,
        )
        return cls(
            contract_id=stable_hash("graph_bound_execution_claim_contract", payload),
            preview=preview,
            receipt_ref=receipt_ref,
            budget_reservation_ref=budget_ref,
        )

    def __post_init__(self) -> None:
        payload = _contract_payload(
            preview=self.preview,
            receipt_ref=self.receipt_ref,
            budget_reservation_ref=self.budget_reservation_ref,
        )
        if (
            self.contract_id
            != stable_hash("graph_bound_execution_claim_contract", payload)
            or self.mode != GRAPH_BOUND_EXECUTION_CLAIM_MODE
            or not _hash_ref(self.receipt_ref, "graph_bound_execution_receipt")
            or not _hash_ref(
                self.budget_reservation_ref,
                "graph_bound_budget_reservation",
            )
            or not self.durable_receipt_reserved
            or not self.budget_reserved
            or not self.claim_available
            or self.single_use_claim_acquired
            or self.world_provisioning_authority
            or self.backend_dispatch_authority
            or self.finding_authority
            or self.target_requests_sent != 0
            or self.executable
        ):
            raise ValueError("graph-bound execution claim contract is invalid")

    @property
    def total_request_units(self) -> int:
        return self.preview.total_request_units

    @property
    def plan_id(self) -> str:
        return self.preview.plan_id

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": 1,
            "mode": self.mode,
            "contract_id": self.contract_id,
            **_contract_payload(
                preview=self.preview,
                receipt_ref=self.receipt_ref,
                budget_reservation_ref=self.budget_reservation_ref,
            ),
        }


@dataclass(frozen=True)
class GraphBoundExecutionClaimConfig:
    enabled: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.enabled, bool):
            raise ValueError("graph-bound execution claim enabled must be a boolean")

    @classmethod
    def from_environment(cls) -> "GraphBoundExecutionClaimConfig":
        return cls(
            enabled=(
                os.environ.get(GRAPH_BOUND_EXECUTION_CLAIM_ENV, "").strip().lower()
                in _TRUE
            )
        )


@dataclass(frozen=True, repr=False)
class _ClaimRuntimePlan:
    plan: GraphBoundPreparedRequestPlan = field(repr=False)
    terminal_operation_id: str
    actor_persona_id: str = field(repr=False)
    target_origin: str = field(repr=False)
    policy_ref: str
    authorization_ref: str
    authority_context_ref: str
    authorization: AuthorizationEnvelope = field(repr=False, compare=False)
    executor: PolicyExecutor = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        stages = tuple(
            (
                "cleanup"
                if item.phase == "cleanup"
                else (
                    "dispatch"
                    if item.operation_id == self.terminal_operation_id
                    else "provision"
                )
            )
            for item in self.plan.request_bindings
        )
        if (
            not _hash_ref(self.terminal_operation_id, "action")
            or self.plan.baseline_operation_ids[-1]
            != self.terminal_operation_id
            or self.plan.treatment_operation_ids[-1]
            != self.terminal_operation_id
            or stages
            != tuple(sorted(stages, key=_RUNTIME_STAGE_ORDER.__getitem__))
            or stages.count("dispatch") != 3
            or not self.actor_persona_id
            or _canonical_origin(self.target_origin) != self.target_origin
            or not _hash_ref(self.policy_ref, "graph_bound_experiment_policy")
            or not _hash_ref(self.authorization_ref, "graph_bound_authorization")
            or not _hash_ref(
                self.authority_context_ref,
                "experiment_authority_context",
            )
            or not isinstance(self.authorization, AuthorizationEnvelope)
            or not isinstance(self.executor, PolicyExecutor)
        ):
            raise ValueError("graph-bound claim runtime plan is invalid")


@dataclass(frozen=True, repr=False)
class _PreparedClaim:
    preview: GraphBoundExecutionClaimPreview
    fingerprint: str = field(repr=False)
    receipt_context: BehavioralReceiptContext = field(repr=False)
    actions: Tuple[Tuple[str, str], ...] = field(repr=False)
    runtime_plan: _ClaimRuntimePlan = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if (
            _BARE_HASH.fullmatch(self.fingerprint) is None
            or not self.actions
            or len(self.actions) != self.preview.total_request_units
            or any(not action or not endpoint for action, endpoint in self.actions)
            or self.runtime_plan.plan.plan_id != self.preview.plan_id
        ):
            raise ValueError("prepared graph-bound execution claim is invalid")


class _GraphBoundProvisioningAuthority:
    """Private bridge from a consumed claim to the active provisioning module."""

    def __init__(self, resources: "_ClaimResources") -> None:
        self._resources = resources
        self.runtime_plan = resources.runtime_plan

    @property
    def budget_reservation_id(self) -> str:
        return self._resources.budget_reservation_id

    @property
    def remaining_units(self) -> int:
        return self._resources.reserved_units

    @property
    def state(self) -> str:
        return self._resources.state

    def mark_provisioned(self) -> None:
        self._resources.mark_provisioned()

    def note_budget_units(self, count: int) -> None:
        self._resources.note_budget_units(count)

    def abort(self, *, expected_state: str, reason: str) -> int:
        return self._resources.abort(expected_state=expected_state, reason=reason)


class _ClaimResources:
    def __init__(
        self,
        *,
        budget: ProofBudget,
        budget_reservation_id: str,
        receipt_store: BehavioralReceiptStore,
        receipt_fingerprint: str,
        receipt_reservation_token: str,
        expected_units: int,
        runtime_plan: _ClaimRuntimePlan,
    ) -> None:
        self.budget = budget
        self.budget_reservation_id = budget_reservation_id
        self.receipt_store = receipt_store
        self.receipt_fingerprint = receipt_fingerprint
        self.expected_units = expected_units
        self.runtime_plan = runtime_plan
        self._receipt_reservation_token: Optional[str] = receipt_reservation_token
        self._authorized_budget_units = 0
        self._state = "active"
        self._lock = threading.RLock()
        if (
            isinstance(expected_units, bool)
            or expected_units <= 0
            or self.budget.reservation_remaining(budget_reservation_id)
            != expected_units
        ):
            raise ValueError("graph-bound execution budget reservation is incomplete")

    @property
    def state(self) -> str:
        with self._lock:
            return self._state

    @property
    def reserved_units(self) -> int:
        with self._lock:
            if self._state == "aborted":
                return 0
            return self.budget.reservation_remaining(self.budget_reservation_id)

    def claim(self) -> None:
        with self._lock:
            if self._state != "active":
                raise GraphBoundExecutionClaimDenied(
                    "graph_bound_execution_claim_not_available",
                    category="claim",
                )
            self._state = "claimed"

    def begin_provisioning(self) -> _GraphBoundProvisioningAuthority:
        with self._lock:
            if self._state != "claimed":
                raise GraphBoundExecutionClaimDenied(
                    "graph_bound_execution_claim_not_available_for_provisioning",
                    category="claim",
                )
            self._state = "provisioning"
            return _GraphBoundProvisioningAuthority(self)

    def mark_provisioned(self) -> None:
        with self._lock:
            if self._state != "provisioning":
                raise GraphBoundExecutionClaimDenied(
                    "graph_bound_execution_provisioning_state_mismatch",
                    category="claim",
                )
            self._state = "provisioned"

    def note_budget_units(self, count: int) -> None:
        if isinstance(count, bool) or not isinstance(count, int) or count <= 0:
            raise ValueError("graph-bound budget unit count is invalid")
        with self._lock:
            if self._state not in {"provisioning", "provisioned"}:
                raise GraphBoundExecutionClaimDenied(
                    "graph_bound_execution_budget_accounting_state_mismatch",
                    category="claim",
                )
            expected = self.expected_units - self._authorized_budget_units - count
            if (
                expected < 0
                or self.budget.reservation_remaining(self.budget_reservation_id)
                != expected
            ):
                raise GraphBoundExecutionClaimDenied(
                    "graph_bound_execution_budget_accounting_mismatch",
                    category="budget",
                )
            self._authorized_budget_units += count

    def abort(self, *, expected_state: str, reason: str) -> int:
        if _SEMANTIC.fullmatch(str(reason or "")) is None:
            raise ValueError("graph-bound execution abort reason is invalid")
        with self._lock:
            if self._state != expected_state:
                raise GraphBoundExecutionClaimDenied(
                    "graph_bound_execution_claim_state_mismatch",
                    category="claim",
                )
            token = self._receipt_reservation_token
            if token is None:
                raise GraphBoundExecutionClaimDenied(
                    "graph_bound_execution_receipt_token_unavailable",
                    category="receipt",
                )
            receipt_error: Optional[Exception] = None
            try:
                self.receipt_store.abort(
                    self.receipt_fingerprint,
                    reservation_token=token,
                    reason=reason,
                )
            except Exception as exc:  # pragma: no cover - defensive store seam
                receipt_error = exc
            expected_release = self.expected_units - self._authorized_budget_units
            released = self.budget.release_reservation(self.budget_reservation_id)
            self._receipt_reservation_token = None
            self._state = "aborted"
            if receipt_error is not None:
                raise GraphBoundExecutionClaimDenied(
                    "graph_bound_execution_budget_released_but_receipt_abort_failed",
                    category="receipt",
                ) from receipt_error
            if released != expected_release:
                raise GraphBoundExecutionClaimDenied(
                    "graph_bound_execution_budget_release_mismatch",
                    category="budget",
                )
            return released


class GraphBoundExecutionClaim:
    """One claimed lease with abort or internal provisioning handoff authority."""

    def __init__(
        self,
        contract: GraphBoundExecutionClaimContract,
        resources: _ClaimResources,
    ) -> None:
        self.contract = contract
        self._resources = resources

    @property
    def state(self) -> str:
        return self._resources.state

    @property
    def reserved_units(self) -> int:
        return self._resources.reserved_units

    def abort(self, reason: str = "graph_bound_execution_claim_aborted") -> int:
        return self._resources.abort(expected_state="claimed", reason=reason)

    def _begin_provisioning(self) -> _GraphBoundProvisioningAuthority:
        return self._resources.begin_provisioning()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "claim": self.contract.to_dict(),
            "claim_state": self.state,
            "reserved_request_units": self.reserved_units,
            "single_use_claim_acquired": self.state == "claimed",
            "world_provisioning_authority": False,
            "backend_dispatch_authority": False,
            "finding_authority": False,
            "target_requests_sent": 0,
            "executable": False,
        }


class GraphBoundExecutionClaimLease:
    """A reserved receipt and budget that can be claimed exactly once."""

    def __init__(
        self,
        contract: GraphBoundExecutionClaimContract,
        resources: _ClaimResources,
    ) -> None:
        self.contract = contract
        self._resources = resources

    @property
    def state(self) -> str:
        return self._resources.state

    @property
    def reserved_units(self) -> int:
        return self._resources.reserved_units

    def claim(self) -> GraphBoundExecutionClaim:
        self._resources.claim()
        return GraphBoundExecutionClaim(self.contract, self._resources)

    def abort(self, reason: str = "graph_bound_execution_lease_aborted") -> int:
        return self._resources.abort(expected_state="active", reason=reason)

    def to_dict(self) -> Dict[str, Any]:
        live = self.state in {"active", "claimed"}
        return {
            "claim": self.contract.to_dict(),
            "claim_state": self.state,
            "reserved_request_units": self.reserved_units,
            "durable_receipt_reserved": live,
            "budget_reserved": live,
            "single_use_claim_acquired": self.state == "claimed",
            "world_provisioning_authority": False,
            "backend_dispatch_authority": False,
            "finding_authority": False,
            "target_requests_sent": 0,
            "executable": False,
        }


class GraphBoundExecutionClaimAdmission:
    """Revalidate and reserve one explicit graph-bound prepared plan."""

    def __init__(
        self,
        records: Sequence[Mapping[str, Any]],
        *,
        target_origin: str,
        world_id: str,
        actor_persona_id: str,
        authorization: AuthorizationEnvelope,
        executor: PolicyExecutor,
        lifecycle: LifecycleMiningResult,
        state_machine: StateMachineLegalityResult,
        compilation: GraphBoundExperimentCompilationResult,
        admission: GraphBoundManifestAdmissionResult,
        request_binding: GraphBoundRequestBindingResult,
        plan_id: str,
        config: Optional[GraphBoundExecutionClaimConfig] = None,
        receipt_store: Optional[BehavioralReceiptStore] = None,
        admission_planner: Optional[GraphBoundManifestAdmissionPlanner] = None,
        request_binder: Optional[GraphBoundRequestBinder] = None,
    ) -> None:
        values = tuple(records)
        if any(not isinstance(item, Mapping) for item in values):
            raise TypeError("graph-bound execution records must contain mappings")
        try:
            self.records = copy.deepcopy(values)
        except Exception as exc:
            raise TypeError("graph-bound execution records must be copyable") from exc
        if not isinstance(authorization, AuthorizationEnvelope):
            raise TypeError("authorization must be an AuthorizationEnvelope")
        if not isinstance(executor, PolicyExecutor):
            raise TypeError("executor must be a PolicyExecutor")
        if not isinstance(lifecycle, LifecycleMiningResult):
            raise TypeError("lifecycle must be a LifecycleMiningResult")
        if not isinstance(state_machine, StateMachineLegalityResult):
            raise TypeError("state_machine must be a StateMachineLegalityResult")
        if not isinstance(compilation, GraphBoundExperimentCompilationResult):
            raise TypeError(
                "compilation must be a GraphBoundExperimentCompilationResult"
            )
        if not isinstance(admission, GraphBoundManifestAdmissionResult):
            raise TypeError("admission must be a GraphBoundManifestAdmissionResult")
        if not isinstance(request_binding, GraphBoundRequestBindingResult):
            raise TypeError("request_binding must be a GraphBoundRequestBindingResult")
        if not isinstance(plan_id, str) or not _hash_ref(
            plan_id,
            "graph_bound_prepared_request_plan",
        ):
            raise ValueError("graph-bound execution plan_id is invalid")
        if config is not None and not isinstance(
            config,
            GraphBoundExecutionClaimConfig,
        ):
            raise TypeError("config must be a GraphBoundExecutionClaimConfig")
        if receipt_store is not None and not isinstance(
            receipt_store,
            BehavioralReceiptStore,
        ):
            raise TypeError("receipt_store must be a BehavioralReceiptStore")

        self.target_origin = _canonical_origin(target_origin)
        self.world_id = str(world_id or "")
        self.actor_persona_id = str(actor_persona_id or "")
        if not self.world_id or self.actor_persona_id != self.world_id:
            raise ValueError("graph-bound execution actor/world mismatch")
        self.authorization = authorization
        self.executor = executor
        self.lifecycle = lifecycle
        self.state_machine = state_machine
        self.compilation = compilation
        self.admission = admission
        self.request_binding = request_binding
        self.plan_id = plan_id
        self.config = (
            config
            if config is not None
            else GraphBoundExecutionClaimConfig.from_environment()
        )
        self.receipt_store = receipt_store or BehavioralReceiptStore()
        self.admission_planner = (
            admission_planner or GraphBoundManifestAdmissionPlanner()
        )
        self.request_binder = request_binder or GraphBoundRequestBinder()

    def _prepare(self) -> _PreparedClaim:
        if not self.config.enabled:
            raise GraphBoundExecutionClaimDenied(
                "graph_bound_execution_claim_is_disabled",
                category="configuration",
            )
        try:
            authorization = copy.deepcopy(self.authorization)
        except Exception as exc:
            raise GraphBoundExecutionClaimDenied(
                "graph_bound_execution_authorization_not_copyable",
                category="authority",
            ) from exc

        target_ref = stable_hash(
            "security_obligation_target",
            self.target_origin,
        )
        if (
            self.admission.target_ref != target_ref
            or self.request_binding.target_ref != target_ref
        ):
            raise GraphBoundExecutionClaimDenied(
                "graph_bound_execution_target_context_mismatch"
            )
        fresh_admission = self.admission_planner.plan(
            compilation=self.compilation,
            target_origin=self.target_origin,
            target_ref=target_ref,
            world_id=self.world_id,
            authorization=authorization,
            executor=self.executor,
            actor_persona_id=self.actor_persona_id,
        )
        if fresh_admission.status != "ready_for_explicit_execution_boundary":
            raise GraphBoundExecutionClaimDenied(
                "graph_bound_execution_static_admission_not_ready",
                category="authority",
            )
        if fresh_admission.to_dict() != self.admission.to_dict():
            raise GraphBoundExecutionClaimDenied(
                "graph_bound_execution_static_admission_changed"
            )

        fresh_binding = self.request_binder.bind(
            self.records,
            target_origin=self.target_origin,
            world_id=self.world_id,
            lifecycle=self.lifecycle,
            state_machine=self.state_machine,
            compilation=self.compilation,
            admission=fresh_admission,
            executor=self.executor,
        )
        if fresh_binding.status != "ready_for_single_use_execution_claim":
            raise GraphBoundExecutionClaimDenied(
                "graph_bound_execution_request_binding_not_ready",
                category="revalidation",
            )
        if fresh_binding.to_dict() != self.request_binding.to_dict():
            raise GraphBoundExecutionClaimDenied(
                "graph_bound_execution_request_binding_changed",
                category="revalidation",
            )

        plans = tuple(
            item for item in fresh_binding.plans if item.plan_id == self.plan_id
        )
        if len(plans) != 1:
            raise GraphBoundExecutionClaimDenied(
                "graph_bound_execution_selected_plan_unavailable"
            )
        plan = plans[0]
        manifests = tuple(
            item
            for item in fresh_admission.manifests
            if item.manifest_id == plan.manifest_id
        )
        if len(manifests) != 1:
            raise GraphBoundExecutionClaimDenied(
                "graph_bound_execution_selected_manifest_unavailable"
            )
        manifest = manifests[0]
        if manifest.specification.spec_id != plan.specification_id:
            raise GraphBoundExecutionClaimDenied(
                "graph_bound_execution_specification_identity_mismatch"
            )

        raw_by_id = {item.binding_id: item for item in plan.ephemeral_requests}
        if set(raw_by_id) != {item.binding_id for item in plan.request_bindings}:
            raise GraphBoundExecutionClaimDenied(
                "graph_bound_execution_ephemeral_request_set_mismatch"
            )
        actions = tuple(
            (
                binding.action_class,
                raw_by_id[binding.binding_id].endpoint_key_value,
            )
            for binding in plan.request_bindings
        )
        budget = self.executor.policy.budget
        if not isinstance(budget, ProofBudget):
            raise GraphBoundExecutionClaimDenied(
                "graph_bound_execution_budget_type_invalid",
                category="budget",
            )
        allowed, _reason = budget.preview_reservation(actions)
        if not allowed:
            raise GraphBoundExecutionClaimDenied(
                "graph_bound_execution_budget_preview_denied",
                category="budget",
            )

        blocker_set = set(plan.remaining_execution_blockers)
        if not _RESOLVED_BLOCKERS.issubset(blocker_set):
            raise GraphBoundExecutionClaimDenied(
                "graph_bound_execution_claim_blocker_contract_mismatch"
            )
        remaining_blockers = tuple(
            item
            for item in plan.remaining_execution_blockers
            if item not in _RESOLVED_BLOCKERS
        )
        descriptor = {
            "schema_version": 1,
            "mode": GRAPH_BOUND_EXECUTION_CLAIM_MODE,
            "plan_id": plan.plan_id,
            "manifest_id": plan.manifest_id,
            "request_binding_result_id": fresh_binding.result_id,
            "admission_result_id": fresh_binding.admission_result_id,
            "compilation_result_id": fresh_binding.compilation_result_id,
            "target_ref": fresh_binding.target_ref,
            "world_ref": fresh_binding.world_ref,
            "actor_ref": manifest.actor_ref,
            "authorization_ref": manifest.authorization_ref,
            "authority_context_ref": manifest.authority_context_ref,
            "policy_ref": fresh_binding.policy_ref,
            "family": plan.family,
            "action_binding_ids": [item.binding_id for item in plan.request_bindings],
            "budget_binding_ids": [item.entry_id for item in plan.budget_bindings],
            "budget_preview_ref": plan.budget_preview_ref,
            "total_request_units": len(actions),
        }
        fingerprint = request_fingerprint(descriptor)
        fingerprint_ref = stable_hash(
            "graph_bound_execution_claim_fingerprint",
            fingerprint,
        )
        preview = GraphBoundExecutionClaimPreview.build(
            plan=plan,
            binding=fresh_binding,
            manifest=manifest,
            receipt_fingerprint_ref=fingerprint_ref,
            remaining_execution_blockers=remaining_blockers,
        )
        context = redacted_receipt_context(
            target_origin=self.target_origin,
            envelope_id=authorization.envelope_id,
            source_persona_id=self.actor_persona_id,
            peer_persona_id=self.actor_persona_id,
        )
        return _PreparedClaim(
            preview=preview,
            fingerprint=fingerprint,
            receipt_context=context,
            actions=actions,
            runtime_plan=_ClaimRuntimePlan(
                plan=plan,
                terminal_operation_id=manifest.specification.terminal_operation_id,
                actor_persona_id=self.actor_persona_id,
                target_origin=self.target_origin,
                policy_ref=preview.policy_ref,
                authorization_ref=preview.authorization_ref,
                authority_context_ref=preview.authority_context_ref,
                authorization=authorization,
                executor=self.executor,
            ),
        )

    def validate_preflight(self) -> GraphBoundExecutionClaimPreview:
        """Revalidate current inputs without reserving receipt or budget."""

        return self._prepare().preview

    def admit(self) -> GraphBoundExecutionClaimLease:
        """Reserve the durable receipt and complete ordered budget exactly once."""

        prepared = self._prepare()
        reservation = self.receipt_store.reserve(
            prepared.fingerprint,
            context=prepared.receipt_context,
        )
        if not reservation.created:
            raise GraphBoundExecutionClaimDenied(
                "graph_bound_execution_claim_replay_denied",
                category="receipt",
            )
        receipt_token = reservation.reservation_token
        if not receipt_token:
            raise GraphBoundExecutionClaimDenied(
                "graph_bound_execution_receipt_token_missing",
                category="receipt",
            )

        budget = self.executor.policy.budget
        budget_reservation_id, _reason = budget.try_reserve(prepared.actions)
        if budget_reservation_id is None:
            try:
                self.receipt_store.abort(
                    prepared.fingerprint,
                    reservation_token=receipt_token,
                    reason="graph_bound_budget_reservation_denied",
                )
            except Exception as exc:
                raise GraphBoundExecutionClaimDenied(
                    "graph_bound_execution_budget_denied_and_receipt_abort_failed",
                    category="receipt",
                ) from exc
            raise GraphBoundExecutionClaimDenied(
                "graph_bound_execution_budget_reservation_denied",
                category="budget",
            )
        if not budget.reservation_matches(
            budget_reservation_id,
            prepared.actions,
        ):
            budget.release_reservation(budget_reservation_id)
            try:
                self.receipt_store.abort(
                    prepared.fingerprint,
                    reservation_token=receipt_token,
                    reason="graph_bound_budget_identity_mismatch",
                )
            except Exception as exc:
                raise GraphBoundExecutionClaimDenied(
                    "graph_bound_execution_budget_released_but_receipt_abort_failed",
                    category="receipt",
                ) from exc
            raise GraphBoundExecutionClaimDenied(
                "graph_bound_execution_budget_reservation_identity_mismatch",
                category="budget",
            )

        try:
            contract = GraphBoundExecutionClaimContract.build(
                preview=prepared.preview,
                receipt_id=reservation.receipt.receipt_id,
                budget_reservation_id=budget_reservation_id,
            )
            resources = _ClaimResources(
                budget=budget,
                budget_reservation_id=budget_reservation_id,
                receipt_store=self.receipt_store,
                receipt_fingerprint=prepared.fingerprint,
                receipt_reservation_token=receipt_token,
                expected_units=prepared.preview.total_request_units,
                runtime_plan=prepared.runtime_plan,
            )
        except Exception as exc:
            budget.release_reservation(budget_reservation_id)
            try:
                self.receipt_store.abort(
                    prepared.fingerprint,
                    reservation_token=receipt_token,
                    reason="graph_bound_claim_contract_build_failed",
                )
            except Exception as abort_exc:
                raise GraphBoundExecutionClaimDenied(
                    "graph_bound_execution_budget_released_but_receipt_abort_failed",
                    category="receipt",
                ) from abort_exc
            raise GraphBoundExecutionClaimDenied(
                "graph_bound_execution_claim_contract_build_failed"
            ) from exc
        return GraphBoundExecutionClaimLease(contract, resources)


__all__ = [
    "GRAPH_BOUND_EXECUTION_CLAIM_ENV",
    "GRAPH_BOUND_EXECUTION_CLAIM_MODE",
    "GraphBoundExecutionClaim",
    "GraphBoundExecutionClaimAdmission",
    "GraphBoundExecutionClaimConfig",
    "GraphBoundExecutionClaimContract",
    "GraphBoundExecutionClaimDenied",
    "GraphBoundExecutionClaimLease",
    "GraphBoundExecutionClaimPreview",
]
