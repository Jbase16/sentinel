"""Atomic, single-use claim admission for R5C role experiments.

R5C4 consumes one exact R5C3 request binding, revalidates the current signed
authority, owned runtime state, policy, and request material, then performs two
local side effects as one fail-closed lifecycle: it reserves a durable receipt
before atomically holding the complete ordered proof budget.  The resulting
lease is claimable once and exposes no provisioning, transport, effect-oracle,
finding, or promotion surface.
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
from core.foundry.vault import PersonaVault
from core.safety.proof_budget import ProofBudget

from .experiment_sdk import ExperimentActionClass
from .normalize import stable_hash
from .receipts import (
    ABORTED,
    COMPLETED,
    BehavioralExecutionReceipt,
    BehavioralReceiptContext,
    BehavioralReceiptStore,
    redacted_receipt_context,
    request_fingerprint,
)
from .role_monotonicity import (
    RoleMonotonicityExperimentAdmission,
    RoleMonotonicityExperimentDenied,
    RoleMonotonicityExperimentProof,
)
from .role_request_binding import (
    RoleMonotonicityRequestBindingContract,
    RoleMonotonicityRequestBindingDenied,
    RoleMonotonicityRuntimeContext,
    RoleRuntimeActionAuthorityBinding,
    RoleRuntimeAuthorityValidator,
)


ROLE_MONOTONICITY_EXECUTION_CLAIM_ENV = (
    "SENTINELFORGE_BEHAVIOR_ROLE_MONOTONICITY_EXECUTION_CLAIM"
)
ROLE_MONOTONICITY_EXECUTION_CLAIM_MODE = (
    "behavioral_role_monotonicity_execution_claim_v1"
)

_TRUE = frozenset({"1", "true", "yes", "on"})
_HASH_REF = re.compile(r"^[a-z][a-z0-9_]*:[0-9a-f]{64}$")
_BARE_HASH = re.compile(r"^[0-9a-f]{64}$")
_RECEIPT_ID = re.compile(r"^behavioral-[0-9a-f]{64}$")
_SEMANTIC = re.compile(r"^[a-z][a-z0-9_]{0,127}$")
_PRIOR_EXECUTION_BLOCKERS = (
    "atomic_budget_reservation_required",
    "durable_execution_receipt_required",
    "effect_evaluation_required",
)
_RESOLVED_EXECUTION_BLOCKERS = (
    "atomic_budget_reservation_required",
    "durable_execution_receipt_required",
)
_REMAINING_EXECUTION_BLOCKERS = ("effect_evaluation_required",)


class RoleMonotonicityExecutionClaimDenied(RuntimeError):
    """The role claim failed before provisioning or target execution."""

    def __init__(
        self,
        reason: str,
        *,
        category: str = "admission",
        terminal_receipt: Optional[BehavioralExecutionReceipt] = None,
    ) -> None:
        super().__init__(reason)
        self.category = category
        if terminal_receipt is not None and (
            not isinstance(terminal_receipt, BehavioralExecutionReceipt)
            or terminal_receipt.state != ABORTED
        ):
            raise ValueError("role execution terminal receipt is invalid")
        self.terminal_receipt = terminal_receipt


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
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise RoleMonotonicityExecutionClaimDenied(
            "role_execution_target_origin_is_invalid",
            category="authority",
        )
    return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"


@dataclass(frozen=True)
class RoleMonotonicityExecutionClaimConfig:
    enabled: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.enabled, bool):
            raise ValueError("role execution claim enabled must be a boolean")

    @classmethod
    def from_environment(cls) -> "RoleMonotonicityExecutionClaimConfig":
        return cls(
            enabled=(
                os.environ.get(ROLE_MONOTONICITY_EXECUTION_CLAIM_ENV, "")
                .strip()
                .lower()
                in _TRUE
            )
        )


def _budget_unit_payload(
    *,
    ordinal: int,
    action_binding_id: str,
    request_material_fingerprint: str,
    action_class: str,
    endpoint_key_ref: str,
) -> Dict[str, Any]:
    return {
        "ordinal": ordinal,
        "action_binding_id": action_binding_id,
        "request_material_fingerprint": request_material_fingerprint,
        "action_class": action_class,
        "endpoint_key_ref": endpoint_key_ref,
        "request_units": 1,
    }


@dataclass(frozen=True)
class RoleMonotonicityReservedRequestUnit:
    unit_id: str
    ordinal: int
    action_binding_id: str
    request_material_fingerprint: str
    action_class: str
    endpoint_key_ref: str
    request_units: int = 1

    @classmethod
    def build(
        cls,
        action_binding: RoleRuntimeActionAuthorityBinding,
    ) -> "RoleMonotonicityReservedRequestUnit":
        if not isinstance(action_binding, RoleRuntimeActionAuthorityBinding):
            raise TypeError(
                "action_binding must be a RoleRuntimeActionAuthorityBinding"
            )
        request = action_binding.request_binding
        payload = _budget_unit_payload(
            ordinal=request.ordinal,
            action_binding_id=action_binding.binding_id,
            request_material_fingerprint=request.request_material_fingerprint,
            action_class=request.action_class.value,
            endpoint_key_ref=stable_hash(
                "experiment_endpoint_key",
                request.endpoint_key,
            ),
        )
        return cls(
            unit_id=stable_hash("role_monotonicity_reserved_request_unit", payload),
            ordinal=request.ordinal,
            action_binding_id=action_binding.binding_id,
            request_material_fingerprint=request.request_material_fingerprint,
            action_class=request.action_class.value,
            endpoint_key_ref=payload["endpoint_key_ref"],
        )

    def __post_init__(self) -> None:
        payload = _budget_unit_payload(
            ordinal=self.ordinal,
            action_binding_id=self.action_binding_id,
            request_material_fingerprint=self.request_material_fingerprint,
            action_class=self.action_class,
            endpoint_key_ref=self.endpoint_key_ref,
        )
        if (
            self.unit_id
            != stable_hash("role_monotonicity_reserved_request_unit", payload)
            or not _hash_ref(
                self.unit_id,
                "role_monotonicity_reserved_request_unit",
            )
            or isinstance(self.ordinal, bool)
            or not isinstance(self.ordinal, int)
            or self.ordinal < 0
            or not _hash_ref(
                self.action_binding_id,
                "role_runtime_action_authority",
            )
            or _BARE_HASH.fullmatch(self.request_material_fingerprint) is None
            or self.action_class
            not in {item.value for item in ExperimentActionClass}
            or not _hash_ref(
                self.endpoint_key_ref,
                "experiment_endpoint_key",
            )
            or self.request_units != 1
        ):
            raise ValueError("role reserved request unit is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "unit_id": self.unit_id,
            **_budget_unit_payload(
                ordinal=self.ordinal,
                action_binding_id=self.action_binding_id,
                request_material_fingerprint=self.request_material_fingerprint,
                action_class=self.action_class,
                endpoint_key_ref=self.endpoint_key_ref,
            ),
        }


def _preview_payload(
    *,
    request_binding: RoleMonotonicityRequestBindingContract,
    reserved_request_units: Sequence[RoleMonotonicityReservedRequestUnit],
    receipt_fingerprint_ref: str,
) -> Dict[str, Any]:
    return {
        "mode": ROLE_MONOTONICITY_EXECUTION_CLAIM_MODE,
        "request_binding": request_binding.to_dict(),
        "reserved_request_units": [
            item.to_dict() for item in reserved_request_units
        ],
        "receipt_fingerprint_ref": receipt_fingerprint_ref,
        "total_request_units": len(reserved_request_units),
        "resolved_execution_blockers": list(_RESOLVED_EXECUTION_BLOCKERS),
        "remaining_execution_blockers": list(_REMAINING_EXECUTION_BLOCKERS),
        "current_context_revalidated": True,
        "budget_reservation_allowed": True,
        "atomic_resource_lifecycle": True,
        "durable_receipt_reserved": False,
        "budget_reserved": False,
        "claim_available": False,
        "single_use_claim_acquired": False,
        "world_provisioning_authority": False,
        "backend_dispatch_authority": False,
        "effect_evaluation_authority": False,
        "finding_authority": False,
        "target_requests_sent": 0,
        "executable": False,
    }


@dataclass(frozen=True)
class RoleMonotonicityExecutionClaimPreview:
    preview_id: str
    request_binding: RoleMonotonicityRequestBindingContract
    reserved_request_units: Tuple[RoleMonotonicityReservedRequestUnit, ...]
    receipt_fingerprint_ref: str
    total_request_units: int
    resolved_execution_blockers: Tuple[str, ...] = _RESOLVED_EXECUTION_BLOCKERS
    remaining_execution_blockers: Tuple[str, ...] = _REMAINING_EXECUTION_BLOCKERS
    current_context_revalidated: bool = True
    budget_reservation_allowed: bool = True
    atomic_resource_lifecycle: bool = True
    durable_receipt_reserved: bool = False
    budget_reserved: bool = False
    claim_available: bool = False
    single_use_claim_acquired: bool = False
    world_provisioning_authority: bool = False
    backend_dispatch_authority: bool = False
    effect_evaluation_authority: bool = False
    finding_authority: bool = False
    target_requests_sent: int = 0
    executable: bool = False
    mode: str = ROLE_MONOTONICITY_EXECUTION_CLAIM_MODE

    @classmethod
    def build(
        cls,
        *,
        request_binding: RoleMonotonicityRequestBindingContract,
        reserved_request_units: Sequence[RoleMonotonicityReservedRequestUnit],
        receipt_fingerprint_ref: str,
    ) -> "RoleMonotonicityExecutionClaimPreview":
        units = tuple(reserved_request_units)
        payload = _preview_payload(
            request_binding=request_binding,
            reserved_request_units=units,
            receipt_fingerprint_ref=receipt_fingerprint_ref,
        )
        return cls(
            preview_id=stable_hash(
                "role_monotonicity_execution_claim_preview",
                payload,
            ),
            request_binding=request_binding,
            reserved_request_units=units,
            receipt_fingerprint_ref=receipt_fingerprint_ref,
            total_request_units=len(units),
        )

    def __post_init__(self) -> None:
        if not isinstance(
            self.request_binding,
            RoleMonotonicityRequestBindingContract,
        ) or any(
            not isinstance(item, RoleMonotonicityReservedRequestUnit)
            for item in self.reserved_request_units
        ):
            raise TypeError("role execution claim preview contains invalid bindings")
        expected_units = tuple(
            RoleMonotonicityReservedRequestUnit.build(item)
            for item in self.request_binding.action_bindings
        )
        payload = _preview_payload(
            request_binding=self.request_binding,
            reserved_request_units=self.reserved_request_units,
            receipt_fingerprint_ref=self.receipt_fingerprint_ref,
        )
        if (
            self.preview_id
            != stable_hash("role_monotonicity_execution_claim_preview", payload)
            or not _hash_ref(
                self.preview_id,
                "role_monotonicity_execution_claim_preview",
            )
            or self.reserved_request_units != expected_units
            or tuple(item.ordinal for item in self.reserved_request_units)
            != tuple(range(len(self.reserved_request_units)))
            or self.total_request_units != len(self.reserved_request_units)
            or self.total_request_units != len(
                self.request_binding.action_bindings
            )
            or not _hash_ref(
                self.receipt_fingerprint_ref,
                "role_monotonicity_execution_claim_fingerprint",
            )
            or self.request_binding.remaining_execution_blockers
            != _PRIOR_EXECUTION_BLOCKERS
            or self.resolved_execution_blockers != _RESOLVED_EXECUTION_BLOCKERS
            or self.remaining_execution_blockers
            != _REMAINING_EXECUTION_BLOCKERS
            or not self.current_context_revalidated
            or not self.budget_reservation_allowed
            or not self.atomic_resource_lifecycle
            or self.durable_receipt_reserved
            or self.budget_reserved
            or self.claim_available
            or self.single_use_claim_acquired
            or self.world_provisioning_authority
            or self.backend_dispatch_authority
            or self.effect_evaluation_authority
            or self.finding_authority
            or self.target_requests_sent != 0
            or self.executable
            or self.mode != ROLE_MONOTONICITY_EXECUTION_CLAIM_MODE
        ):
            raise ValueError("role execution claim preview is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": 1,
            "preview_id": self.preview_id,
            **_preview_payload(
                request_binding=self.request_binding,
                reserved_request_units=self.reserved_request_units,
                receipt_fingerprint_ref=self.receipt_fingerprint_ref,
            ),
        }


def _contract_payload(
    *,
    preview: RoleMonotonicityExecutionClaimPreview,
    receipt_ref: str,
    receipt_lineage_ref: str,
    budget_reservation_ref: str,
) -> Dict[str, Any]:
    return {
        "mode": ROLE_MONOTONICITY_EXECUTION_CLAIM_MODE,
        "preview": preview.to_dict(),
        "receipt_ref": receipt_ref,
        "receipt_lineage_ref": receipt_lineage_ref,
        "budget_reservation_ref": budget_reservation_ref,
        "resolved_execution_blockers": list(_RESOLVED_EXECUTION_BLOCKERS),
        "remaining_execution_blockers": list(_REMAINING_EXECUTION_BLOCKERS),
        "atomic_resource_lifecycle": True,
        "durable_receipt_reserved": True,
        "budget_reserved": True,
        "claim_available": True,
        "single_use_claim_acquired": False,
        "world_provisioning_authority": False,
        "backend_dispatch_authority": False,
        "effect_evaluation_authority": False,
        "finding_authority": False,
        "target_requests_sent": 0,
        "executable": False,
    }


def _durable_receipt_lineage_ref(
    *,
    preview: RoleMonotonicityExecutionClaimPreview,
    receipt_ref: str,
) -> str:
    binding = preview.request_binding
    return stable_hash(
        "role_monotonicity_execution_receipt_lineage",
        {
            "request_binding_id": binding.binding_id,
            "prior_receipt_lineage_ref": binding.receipt_lineage_ref,
            "receipt_context_ref": binding.receipt_context_ref,
            "receipt_fingerprint_ref": preview.receipt_fingerprint_ref,
            "receipt_ref": receipt_ref,
            "durable_receipt_created": True,
        },
    )


@dataclass(frozen=True)
class RoleMonotonicityExecutionClaimContract:
    contract_id: str
    preview: RoleMonotonicityExecutionClaimPreview
    receipt_ref: str
    receipt_lineage_ref: str
    budget_reservation_ref: str
    resolved_execution_blockers: Tuple[str, ...] = _RESOLVED_EXECUTION_BLOCKERS
    remaining_execution_blockers: Tuple[str, ...] = _REMAINING_EXECUTION_BLOCKERS
    atomic_resource_lifecycle: bool = True
    durable_receipt_reserved: bool = True
    budget_reserved: bool = True
    claim_available: bool = True
    single_use_claim_acquired: bool = False
    world_provisioning_authority: bool = False
    backend_dispatch_authority: bool = False
    effect_evaluation_authority: bool = False
    finding_authority: bool = False
    target_requests_sent: int = 0
    executable: bool = False
    mode: str = ROLE_MONOTONICITY_EXECUTION_CLAIM_MODE

    @classmethod
    def build(
        cls,
        *,
        preview: RoleMonotonicityExecutionClaimPreview,
        receipt_id: str,
        budget_reservation_id: str,
    ) -> "RoleMonotonicityExecutionClaimContract":
        if _RECEIPT_ID.fullmatch(str(receipt_id or "")) is None:
            raise ValueError("role execution receipt id is invalid")
        if not isinstance(budget_reservation_id, str) or not budget_reservation_id:
            raise ValueError("role execution budget reservation id is invalid")
        receipt_ref = stable_hash(
            "role_monotonicity_execution_receipt",
            receipt_id,
        )
        budget_ref = stable_hash(
            "role_monotonicity_budget_reservation",
            budget_reservation_id,
        )
        lineage_ref = _durable_receipt_lineage_ref(
            preview=preview,
            receipt_ref=receipt_ref,
        )
        payload = _contract_payload(
            preview=preview,
            receipt_ref=receipt_ref,
            receipt_lineage_ref=lineage_ref,
            budget_reservation_ref=budget_ref,
        )
        return cls(
            contract_id=stable_hash(
                "role_monotonicity_execution_claim_contract",
                payload,
            ),
            preview=preview,
            receipt_ref=receipt_ref,
            receipt_lineage_ref=lineage_ref,
            budget_reservation_ref=budget_ref,
        )

    def __post_init__(self) -> None:
        if not isinstance(
            self.preview,
            RoleMonotonicityExecutionClaimPreview,
        ):
            raise TypeError("preview must be a role execution claim preview")
        payload = _contract_payload(
            preview=self.preview,
            receipt_ref=self.receipt_ref,
            receipt_lineage_ref=self.receipt_lineage_ref,
            budget_reservation_ref=self.budget_reservation_ref,
        )
        if (
            self.contract_id
            != stable_hash(
                "role_monotonicity_execution_claim_contract",
                payload,
            )
            or not _hash_ref(
                self.contract_id,
                "role_monotonicity_execution_claim_contract",
            )
            or not _hash_ref(
                self.receipt_ref,
                "role_monotonicity_execution_receipt",
            )
            or not _hash_ref(
                self.receipt_lineage_ref,
                "role_monotonicity_execution_receipt_lineage",
            )
            or self.receipt_lineage_ref
            != _durable_receipt_lineage_ref(
                preview=self.preview,
                receipt_ref=self.receipt_ref,
            )
            or not _hash_ref(
                self.budget_reservation_ref,
                "role_monotonicity_budget_reservation",
            )
            or self.resolved_execution_blockers != _RESOLVED_EXECUTION_BLOCKERS
            or self.remaining_execution_blockers
            != _REMAINING_EXECUTION_BLOCKERS
            or not self.atomic_resource_lifecycle
            or not self.durable_receipt_reserved
            or not self.budget_reserved
            or not self.claim_available
            or self.single_use_claim_acquired
            or self.world_provisioning_authority
            or self.backend_dispatch_authority
            or self.effect_evaluation_authority
            or self.finding_authority
            or self.target_requests_sent != 0
            or self.executable
            or self.mode != ROLE_MONOTONICITY_EXECUTION_CLAIM_MODE
        ):
            raise ValueError("role execution claim contract is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": 1,
            "contract_id": self.contract_id,
            **_contract_payload(
                preview=self.preview,
                receipt_ref=self.receipt_ref,
                receipt_lineage_ref=self.receipt_lineage_ref,
                budget_reservation_ref=self.budget_reservation_ref,
            ),
        }


@dataclass(frozen=True, repr=False)
class _RoleClaimRuntimePlan:
    request_binding: RoleMonotonicityRequestBindingContract
    proof: RoleMonotonicityExperimentProof
    runtime: RoleMonotonicityRuntimeContext = field(repr=False, compare=False)
    executor: PolicyExecutor = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if (
            not isinstance(
                self.request_binding,
                RoleMonotonicityRequestBindingContract,
            )
            or not isinstance(self.proof, RoleMonotonicityExperimentProof)
            or not isinstance(self.runtime, RoleMonotonicityRuntimeContext)
            or not isinstance(self.executor, PolicyExecutor)
        ):
            raise ValueError("role execution claim runtime plan is invalid")
        action_ids = {
            item.request_binding.action_id
            for item in self.request_binding.action_bindings
        }
        if (
            self.proof.proof_id != self.request_binding.proof_id
            or self.proof.oracle.oracle_id != self.request_binding.oracle_id
            or self.runtime.run_ref != self.request_binding.run_ref
            or self.runtime.tenant_ref != self.request_binding.tenant_ref
            or self.runtime.active_generation_ref
            != self.request_binding.active_generation_ref
            or self.runtime.revoked_generation_ref
            != self.request_binding.revoked_generation_ref
            or self.runtime.membership_observation_binding
            != self.request_binding.membership_observation_binding
            or self.runtime.effect_observation_binding
            != self.request_binding.effect_observation_binding
            or set(self.runtime.runtime_actions) != action_ids
            or self.executor.policy.digest()
            != self.request_binding.execution_policy_digest
        ):
            raise ValueError("role execution claim runtime plan is invalid")


@dataclass(frozen=True)
class _PreparedRoleClaim:
    preview: RoleMonotonicityExecutionClaimPreview
    fingerprint: str
    receipt_context: BehavioralReceiptContext
    actions: Tuple[Tuple[str, str], ...] = field(repr=False, compare=False)
    runtime_plan: _RoleClaimRuntimePlan = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if (
            not isinstance(
                self.preview,
                RoleMonotonicityExecutionClaimPreview,
            )
            or not isinstance(self.receipt_context, BehavioralReceiptContext)
            or len(self.actions) != self.preview.total_request_units
            or any(
                not isinstance(item, tuple)
                or len(item) != 2
                or not all(isinstance(value, str) and value for value in item)
                for item in self.actions
            )
            or stable_hash(
                "role_monotonicity_execution_claim_fingerprint",
                self.fingerprint,
            )
            != self.preview.receipt_fingerprint_ref
            or self.runtime_plan.request_binding.binding_id
            != self.preview.request_binding.binding_id
        ):
            raise ValueError("prepared role execution claim is invalid")


class _RoleMembershipLifecycleAuthority:
    """Private handoff from one claimed lease to the bounded R5C5 probe."""

    def __init__(self, resources: "_RoleMonotonicityClaimResources") -> None:
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

    @property
    def receipt_id(self) -> str:
        return self._resources.receipt_id

    @property
    def terminal_receipt(self) -> Optional[BehavioralExecutionReceipt]:
        return self._resources.terminal_receipt

    def note_budget_units(self, count: int) -> None:
        self._resources.note_budget_units(count)

    def abort(
        self,
        *,
        reason: str,
        terminal_evidence: Optional[Mapping[str, Any]] = None,
    ) -> int:
        return self._resources.abort(
            expected_state="membership_lifecycle",
            reason=reason,
            terminal_evidence=terminal_evidence,
        )


class _RoleEffectEvaluationAuthority:
    """Private handoff from one fresh R5C4 claim to the bounded R5C6 run."""

    def __init__(self, resources: "_RoleMonotonicityClaimResources") -> None:
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

    @property
    def receipt_id(self) -> str:
        return self._resources.receipt_id

    @property
    def terminal_receipt(self) -> Optional[BehavioralExecutionReceipt]:
        return self._resources.terminal_receipt

    def note_budget_units(self, count: int) -> None:
        self._resources.note_budget_units(count)

    def abort(
        self,
        *,
        reason: str,
        terminal_evidence: Optional[Mapping[str, Any]] = None,
    ) -> int:
        return self._resources.abort(
            expected_state="effect_evaluation",
            reason=reason,
            terminal_evidence=terminal_evidence,
        )

    def finish(
        self,
        *,
        outcome: Mapping[str, Any],
    ) -> BehavioralExecutionReceipt:
        return self._resources.finish(
            expected_state="effect_evaluation",
            outcome=outcome,
        )


class _RoleMonotonicityClaimResources:
    def __init__(
        self,
        *,
        budget: ProofBudget,
        budget_reservation_id: str,
        receipt_store: BehavioralReceiptStore,
        receipt_fingerprint: str,
        receipt_reservation_token: str,
        expected_units: int,
        runtime_plan: _RoleClaimRuntimePlan,
    ) -> None:
        if (
            not isinstance(expected_units, int)
            or isinstance(expected_units, bool)
            or expected_units <= 0
            or not isinstance(runtime_plan, _RoleClaimRuntimePlan)
            or budget.reservation_remaining(budget_reservation_id)
            != expected_units
        ):
            raise ValueError("role execution claim resources are invalid")
        self.budget = budget
        self.budget_reservation_id = budget_reservation_id
        self.receipt_store = receipt_store
        self.receipt_fingerprint = receipt_fingerprint
        self._receipt_reservation_token: Optional[str] = (
            receipt_reservation_token
        )
        self.expected_units = expected_units
        self.runtime_plan = runtime_plan
        self._authorized_budget_units = 0
        self._lock = threading.RLock()
        self._state = "active"
        self._terminal_receipt: Optional[BehavioralExecutionReceipt] = None

    @property
    def state(self) -> str:
        with self._lock:
            return self._state

    @property
    def reserved_units(self) -> int:
        with self._lock:
            return self.budget.reservation_remaining(
                self.budget_reservation_id
            )

    @property
    def terminal_receipt(self) -> Optional[BehavioralExecutionReceipt]:
        with self._lock:
            return self._terminal_receipt

    @property
    def receipt_id(self) -> str:
        return f"behavioral-{self.receipt_fingerprint}"

    def claim(self) -> None:
        with self._lock:
            if self._state != "active":
                raise RoleMonotonicityExecutionClaimDenied(
                    "role_execution_claim_is_not_available",
                    category="lifecycle",
                )
            self._state = "claimed"

    def begin_membership_lifecycle(self) -> _RoleMembershipLifecycleAuthority:
        with self._lock:
            if self._state != "claimed":
                raise RoleMonotonicityExecutionClaimDenied(
                    "role_execution_claim_is_not_available_for_membership_lifecycle",
                    category="lifecycle",
                )
            self._state = "membership_lifecycle"
            return _RoleMembershipLifecycleAuthority(self)

    def begin_effect_evaluation(self) -> _RoleEffectEvaluationAuthority:
        with self._lock:
            if self._state != "claimed":
                raise RoleMonotonicityExecutionClaimDenied(
                    "role_execution_claim_is_not_available_for_effect_evaluation",
                    category="lifecycle",
                )
            self._state = "effect_evaluation"
            return _RoleEffectEvaluationAuthority(self)

    def note_budget_units(self, count: int) -> None:
        if isinstance(count, bool) or not isinstance(count, int) or count <= 0:
            raise ValueError("role execution budget unit count is invalid")
        with self._lock:
            if self._state not in {
                "membership_lifecycle",
                "effect_evaluation",
            }:
                raise RoleMonotonicityExecutionClaimDenied(
                    "role_execution_budget_accounting_state_mismatch",
                    category="lifecycle",
                )
            expected = self.expected_units - self._authorized_budget_units - count
            if (
                expected < 0
                or self.budget.reservation_remaining(
                    self.budget_reservation_id
                )
                != expected
            ):
                raise RoleMonotonicityExecutionClaimDenied(
                    "role_execution_budget_accounting_mismatch",
                    category="budget",
                )
            self._authorized_budget_units += count

    def finish(
        self,
        *,
        expected_state: str,
        outcome: Mapping[str, Any],
    ) -> BehavioralExecutionReceipt:
        if not isinstance(outcome, Mapping):
            raise TypeError("role execution outcome must be a mapping")
        with self._lock:
            if self._state != expected_state:
                raise RoleMonotonicityExecutionClaimDenied(
                    "role_execution_claim_state_mismatch",
                    category="lifecycle",
                )
            if (
                self._authorized_budget_units != self.expected_units
                or self.budget.reservation_remaining(
                    self.budget_reservation_id
                )
                != 0
            ):
                raise RoleMonotonicityExecutionClaimDenied(
                    "role_execution_budget_not_fully_consumed",
                    category="budget",
                )
            token = self._receipt_reservation_token
            if token is None:
                raise RoleMonotonicityExecutionClaimDenied(
                    "role_execution_receipt_token_unavailable",
                    category="receipt",
                )
            try:
                terminal = self.receipt_store.complete(
                    self.receipt_fingerprint,
                    reservation_token=token,
                    outcome=outcome,
                )
            except Exception as exc:
                try:
                    current = self.receipt_store.load(self.receipt_fingerprint)
                except Exception as load_exc:
                    raise RoleMonotonicityExecutionClaimDenied(
                        "role_execution_receipt_completion_failed",
                        category="receipt",
                    ) from load_exc
                if current is None or current.state != COMPLETED:
                    raise RoleMonotonicityExecutionClaimDenied(
                        "role_execution_receipt_completion_failed",
                        category="receipt",
                    ) from exc
                terminal = current
            self._receipt_reservation_token = None
            self._terminal_receipt = terminal
            self._state = "completed"
            return terminal

    def abort(
        self,
        *,
        expected_state: str,
        reason: str,
        terminal_evidence: Optional[Mapping[str, Any]] = None,
    ) -> int:
        if _SEMANTIC.fullmatch(str(reason or "")) is None:
            raise ValueError("role execution abort reason is invalid")
        with self._lock:
            if self._state != expected_state:
                raise RoleMonotonicityExecutionClaimDenied(
                    "role_execution_claim_state_mismatch",
                    category="lifecycle",
                )
            token = self._receipt_reservation_token
            if token is None:
                raise RoleMonotonicityExecutionClaimDenied(
                    "role_execution_receipt_token_unavailable",
                    category="receipt",
                )
            receipt_error: Optional[BaseException] = None
            terminal_receipt: Optional[BehavioralExecutionReceipt] = None
            try:
                abort_kwargs: Dict[str, Any] = {
                    "reservation_token": token,
                    "reason": reason,
                }
                if terminal_evidence is not None:
                    abort_kwargs["terminal_evidence"] = terminal_evidence
                terminal_receipt = self.receipt_store.abort(
                    self.receipt_fingerprint,
                    **abort_kwargs,
                )
            except Exception as exc:
                receipt_error = exc
            expected_release = (
                self.expected_units - self._authorized_budget_units
            )
            released = self.budget.release_reservation(
                self.budget_reservation_id
            )
            self._receipt_reservation_token = None
            self._terminal_receipt = terminal_receipt
            self._state = "aborted"
            if receipt_error is not None:
                raise RoleMonotonicityExecutionClaimDenied(
                    "role_execution_budget_released_but_receipt_abort_failed",
                    category="receipt",
                ) from receipt_error
            if released != expected_release:
                raise RoleMonotonicityExecutionClaimDenied(
                    "role_execution_budget_release_mismatch",
                    category="budget",
                    terminal_receipt=terminal_receipt,
                )
            return released


class RoleMonotonicityExecutionClaim:
    """Claimed one-use handle with no provisioning or execution method."""

    def __init__(
        self,
        contract: RoleMonotonicityExecutionClaimContract,
        resources: _RoleMonotonicityClaimResources,
    ) -> None:
        self.contract = contract
        self._resources = resources

    @property
    def state(self) -> str:
        return self._resources.state

    @property
    def reserved_units(self) -> int:
        return self._resources.reserved_units

    @property
    def terminal_receipt(self) -> Optional[BehavioralExecutionReceipt]:
        return self._resources.terminal_receipt

    def abort(self, reason: str = "role_execution_claim_aborted") -> int:
        return self._resources.abort(expected_state="claimed", reason=reason)

    def _begin_membership_lifecycle(
        self,
    ) -> _RoleMembershipLifecycleAuthority:
        return self._resources.begin_membership_lifecycle()

    def _begin_effect_evaluation(
        self,
    ) -> _RoleEffectEvaluationAuthority:
        return self._resources.begin_effect_evaluation()

    def to_dict(self) -> Dict[str, Any]:
        live = self.state == "claimed"
        return {
            "claim": self.contract.to_dict(),
            "claim_state": self.state,
            "reserved_request_units": self.reserved_units,
            "durable_receipt_reserved": live,
            "budget_reserved": live,
            "single_use_claim_acquired": live,
            "world_provisioning_authority": False,
            "backend_dispatch_authority": False,
            "effect_evaluation_authority": False,
            "finding_authority": False,
            "target_requests_sent": 0,
            "executable": False,
        }


class RoleMonotonicityExecutionClaimLease:
    """Atomic receipt and budget reservation claimable or abortable once."""

    def __init__(
        self,
        contract: RoleMonotonicityExecutionClaimContract,
        resources: _RoleMonotonicityClaimResources,
    ) -> None:
        self.contract = contract
        self._resources = resources

    @property
    def state(self) -> str:
        return self._resources.state

    @property
    def reserved_units(self) -> int:
        return self._resources.reserved_units

    @property
    def terminal_receipt(self) -> Optional[BehavioralExecutionReceipt]:
        return self._resources.terminal_receipt

    def claim(self) -> RoleMonotonicityExecutionClaim:
        self._resources.claim()
        return RoleMonotonicityExecutionClaim(self.contract, self._resources)

    def abort(self, reason: str = "role_execution_lease_aborted") -> int:
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
            "effect_evaluation_authority": False,
            "finding_authority": False,
            "target_requests_sent": 0,
            "executable": False,
        }


class RoleMonotonicityExecutionClaimAdmission:
    """Revalidate and atomically reserve one exact R5C3 request binding."""

    def __init__(
        self,
        *,
        proof: RoleMonotonicityExperimentProof,
        request_binding: RoleMonotonicityRequestBindingContract,
        target_origin: str,
        authorization: AuthorizationEnvelope,
        executor: PolicyExecutor,
        persona_vault: PersonaVault,
        runtime: RoleMonotonicityRuntimeContext,
        authority_validator: RoleRuntimeAuthorityValidator,
        config: Optional[RoleMonotonicityExecutionClaimConfig] = None,
        receipt_store: Optional[BehavioralReceiptStore] = None,
    ) -> None:
        if not isinstance(proof, RoleMonotonicityExperimentProof):
            raise TypeError("proof must be a RoleMonotonicityExperimentProof")
        if not isinstance(
            request_binding,
            RoleMonotonicityRequestBindingContract,
        ):
            raise TypeError(
                "request_binding must be a RoleMonotonicityRequestBindingContract"
            )
        if not isinstance(authorization, AuthorizationEnvelope):
            raise TypeError("authorization must be an AuthorizationEnvelope")
        if not isinstance(executor, PolicyExecutor):
            raise TypeError("executor must be a PolicyExecutor")
        if not isinstance(persona_vault, PersonaVault):
            raise TypeError("persona_vault must be a PersonaVault")
        if not isinstance(runtime, RoleMonotonicityRuntimeContext):
            raise TypeError("runtime must be a RoleMonotonicityRuntimeContext")
        if not callable(authority_validator):
            raise TypeError("authority_validator must be callable")
        if config is not None and not isinstance(
            config,
            RoleMonotonicityExecutionClaimConfig,
        ):
            raise TypeError("config must be a RoleMonotonicityExecutionClaimConfig")
        if receipt_store is not None and not isinstance(
            receipt_store,
            BehavioralReceiptStore,
        ):
            raise TypeError("receipt_store must be a BehavioralReceiptStore")
        try:
            self.request_binding = copy.deepcopy(request_binding)
        except Exception as exc:
            raise TypeError("request binding must be safely copyable") from exc
        self.proof = proof
        self.target_origin = _canonical_origin(target_origin)
        self.authorization = authorization
        self.executor = executor
        self.persona_vault = persona_vault
        self.runtime = runtime
        self.authority_validator = authority_validator
        self.config = (
            config
            if config is not None
            else RoleMonotonicityExecutionClaimConfig.from_environment()
        )
        self.receipt_store = receipt_store or BehavioralReceiptStore()

    def _prepare(self) -> _PreparedRoleClaim:
        if not self.config.enabled:
            raise RoleMonotonicityExecutionClaimDenied(
                "role_execution_claim_is_disabled",
                category="configuration",
            )
        try:
            authorization = copy.deepcopy(self.authorization)
        except Exception as exc:
            raise RoleMonotonicityExecutionClaimDenied(
                "role_execution_authorization_is_not_copyable",
                category="authority",
            ) from exc
        try:
            fresh_binding = RoleMonotonicityExperimentAdmission(
                proof=self.proof,
                target_origin=self.target_origin,
                authorization=authorization,
            ).bind_requests(
                executor=self.executor,
                persona_vault=self.persona_vault,
                runtime=self.runtime,
                authority_validator=self.authority_validator,
            )
        except (
            RoleMonotonicityExperimentDenied,
            RoleMonotonicityRequestBindingDenied,
        ) as exc:
            raise RoleMonotonicityExecutionClaimDenied(
                "role_execution_current_request_revalidation_denied",
                category="revalidation",
            ) from exc
        if fresh_binding.to_dict() != self.request_binding.to_dict():
            raise RoleMonotonicityExecutionClaimDenied(
                "role_execution_request_binding_changed",
                category="revalidation",
            )
        if fresh_binding.remaining_execution_blockers != _PRIOR_EXECUTION_BLOCKERS:
            raise RoleMonotonicityExecutionClaimDenied(
                "role_execution_blocker_contract_mismatch"
            )

        budget = self.executor.policy.budget
        if not isinstance(budget, ProofBudget):
            raise RoleMonotonicityExecutionClaimDenied(
                "role_execution_budget_type_is_invalid",
                category="budget",
            )
        reserved_units = tuple(
            RoleMonotonicityReservedRequestUnit.build(item)
            for item in fresh_binding.action_bindings
        )
        actions = tuple(
            (
                item.request_binding.action_class.value,
                item.request_binding.endpoint_key,
            )
            for item in fresh_binding.action_bindings
        )
        try:
            budget_allowed, budget_reason = budget.preview_reservation(actions)
        except Exception as exc:
            raise RoleMonotonicityExecutionClaimDenied(
                "role_execution_budget_preview_failed",
                category="budget",
            ) from exc
        if not budget_allowed:
            raise RoleMonotonicityExecutionClaimDenied(
                f"role_execution_budget_preview_denied:{budget_reason}",
                category="budget",
            )

        descriptor = {
            "schema_version": 1,
            "mode": ROLE_MONOTONICITY_EXECUTION_CLAIM_MODE,
            "request_binding": fresh_binding.to_dict(),
            "reserved_request_units": [
                item.to_dict() for item in reserved_units
            ],
            "total_request_units": len(reserved_units),
            "resolved_execution_blockers": list(
                _RESOLVED_EXECUTION_BLOCKERS
            ),
            "remaining_execution_blockers": list(
                _REMAINING_EXECUTION_BLOCKERS
            ),
        }
        try:
            fingerprint = request_fingerprint(descriptor)
        except (TypeError, ValueError) as exc:
            raise RoleMonotonicityExecutionClaimDenied(
                "role_execution_claim_identity_is_not_deterministic"
            ) from exc
        fingerprint_ref = stable_hash(
            "role_monotonicity_execution_claim_fingerprint",
            fingerprint,
        )
        preview = RoleMonotonicityExecutionClaimPreview.build(
            request_binding=fresh_binding,
            reserved_request_units=reserved_units,
            receipt_fingerprint_ref=fingerprint_ref,
        )
        context = redacted_receipt_context(
            target_origin=self.target_origin,
            envelope_id=authorization.envelope_id,
            source_persona_id=self.runtime.higher_persona_id,
            peer_persona_id=self.runtime.lower_persona_id,
        )
        if stable_hash(
            "role_monotonicity_receipt_context",
            context.to_dict(),
        ) != fresh_binding.receipt_context_ref:
            raise RoleMonotonicityExecutionClaimDenied(
                "role_execution_receipt_context_changed",
                category="receipt",
            )
        return _PreparedRoleClaim(
            preview=preview,
            fingerprint=fingerprint,
            receipt_context=context,
            actions=actions,
            runtime_plan=_RoleClaimRuntimePlan(
                request_binding=fresh_binding,
                proof=self.proof,
                runtime=copy.deepcopy(self.runtime),
                executor=self.executor,
            ),
        )

    def validate_preflight(self) -> RoleMonotonicityExecutionClaimPreview:
        """Revalidate current inputs without reserving receipt or budget."""

        return self._prepare().preview

    def _abort_receipt(
        self,
        *,
        fingerprint: str,
        receipt_token: str,
        reason: str,
        failure_reason: str,
    ) -> BehavioralExecutionReceipt:
        try:
            return self.receipt_store.abort(
                fingerprint,
                reservation_token=receipt_token,
                reason=reason,
            )
        except Exception as exc:
            raise RoleMonotonicityExecutionClaimDenied(
                failure_reason,
                category="receipt",
            ) from exc

    def _rollback_budget_and_receipt(
        self,
        *,
        prepared: _PreparedRoleClaim,
        budget: ProofBudget,
        budget_reservation_id: str,
        receipt_token: str,
        reason: str,
    ) -> BehavioralExecutionReceipt:
        released = budget.release_reservation(budget_reservation_id)
        terminal = self._abort_receipt(
            fingerprint=prepared.fingerprint,
            receipt_token=receipt_token,
            reason=reason,
            failure_reason=(
                "role_execution_budget_released_but_receipt_abort_failed"
            ),
        )
        if released != prepared.preview.total_request_units:
            raise RoleMonotonicityExecutionClaimDenied(
                "role_execution_budget_rollback_mismatch",
                category="budget",
                terminal_receipt=terminal,
            )
        return terminal

    def admit(self) -> RoleMonotonicityExecutionClaimLease:
        """Reserve the durable receipt, then the exact ordered budget, once."""

        prepared = self._prepare()
        try:
            reservation = self.receipt_store.reserve(
                prepared.fingerprint,
                context=prepared.receipt_context,
            )
        except Exception as exc:
            raise RoleMonotonicityExecutionClaimDenied(
                "role_execution_receipt_reservation_failed",
                category="receipt",
            ) from exc
        if not reservation.created:
            if reservation.receipt.context != prepared.receipt_context:
                raise RoleMonotonicityExecutionClaimDenied(
                    "role_execution_receipt_context_mismatch",
                    category="receipt",
                )
            raise RoleMonotonicityExecutionClaimDenied(
                "role_execution_claim_replay_denied",
                category="receipt",
                terminal_receipt=(
                    reservation.receipt
                    if reservation.receipt.state == ABORTED
                    else None
                ),
            )
        receipt_token = reservation.reservation_token
        if not receipt_token:
            raise RoleMonotonicityExecutionClaimDenied(
                "role_execution_receipt_reservation_token_is_missing",
                category="receipt",
            )

        budget = self.executor.policy.budget
        try:
            budget_reservation_id, budget_reason = budget.try_reserve(
                prepared.actions
            )
        except Exception as exc:
            terminal = self._abort_receipt(
                fingerprint=prepared.fingerprint,
                receipt_token=receipt_token,
                reason="role_execution_budget_failed",
                failure_reason=(
                    "role_execution_budget_failed_and_receipt_abort_failed"
                ),
            )
            raise RoleMonotonicityExecutionClaimDenied(
                "role_execution_budget_reservation_failed",
                category="budget",
                terminal_receipt=terminal,
            ) from exc
        if budget_reservation_id is None:
            terminal = self._abort_receipt(
                fingerprint=prepared.fingerprint,
                receipt_token=receipt_token,
                reason="role_execution_budget_denied",
                failure_reason=(
                    "role_execution_budget_denied_and_receipt_abort_failed"
                ),
            )
            raise RoleMonotonicityExecutionClaimDenied(
                f"role_execution_budget_reservation_denied:{budget_reason}",
                category="budget",
                terminal_receipt=terminal,
            )
        try:
            reservation_matches = budget.reservation_matches(
                budget_reservation_id,
                prepared.actions,
            )
        except Exception:
            reservation_matches = False
        if not reservation_matches:
            terminal = self._rollback_budget_and_receipt(
                prepared=prepared,
                budget=budget,
                budget_reservation_id=budget_reservation_id,
                receipt_token=receipt_token,
                reason="role_execution_budget_identity_mismatch",
            )
            raise RoleMonotonicityExecutionClaimDenied(
                "role_execution_budget_reservation_identity_mismatch",
                category="budget",
                terminal_receipt=terminal,
            )

        try:
            contract = RoleMonotonicityExecutionClaimContract.build(
                preview=prepared.preview,
                receipt_id=reservation.receipt.receipt_id,
                budget_reservation_id=budget_reservation_id,
            )
            resources = _RoleMonotonicityClaimResources(
                budget=budget,
                budget_reservation_id=budget_reservation_id,
                receipt_store=self.receipt_store,
                receipt_fingerprint=prepared.fingerprint,
                receipt_reservation_token=receipt_token,
                expected_units=prepared.preview.total_request_units,
                runtime_plan=prepared.runtime_plan,
            )
        except Exception as exc:
            terminal = self._rollback_budget_and_receipt(
                prepared=prepared,
                budget=budget,
                budget_reservation_id=budget_reservation_id,
                receipt_token=receipt_token,
                reason="role_execution_contract_failed",
            )
            raise RoleMonotonicityExecutionClaimDenied(
                "role_execution_claim_contract_construction_failed",
                terminal_receipt=terminal,
            ) from exc
        return RoleMonotonicityExecutionClaimLease(contract, resources)


__all__ = [
    "ROLE_MONOTONICITY_EXECUTION_CLAIM_ENV",
    "ROLE_MONOTONICITY_EXECUTION_CLAIM_MODE",
    "RoleMonotonicityExecutionClaim",
    "RoleMonotonicityExecutionClaimAdmission",
    "RoleMonotonicityExecutionClaimConfig",
    "RoleMonotonicityExecutionClaimContract",
    "RoleMonotonicityExecutionClaimDenied",
    "RoleMonotonicityExecutionClaimLease",
    "RoleMonotonicityExecutionClaimPreview",
    "RoleMonotonicityReservedRequestUnit",
]
