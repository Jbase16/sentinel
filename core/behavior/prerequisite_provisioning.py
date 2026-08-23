"""Claim-consuming fresh-world provisioning for graph-bound experiments.

R5B3b2b consumes one sealed graph-bound claim and executes only the ordered
prerequisite prefix for the valid-baseline, counterfactual-treatment, and
independent-control worlds. Runtime response values replace captured lineage
values in memory. Terminal experiment actions are deliberately not dispatched.
"""

from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass, field
from typing import Any, Dict, Mapping, NoReturn, Optional, Sequence, Tuple

from core.cortex.execution_policy import CandidateAction, DENIED_STATUS
from core.safety.action_classifier import OWNED_CREATE
from core.safety.proof_budget import endpoint_key

from .experiment_admission import experiment_authority_context_ref
from .lineage import EphemeralRehydratedStep, LineageBinding, LocatorKind
from .normalize import stable_hash
from .prerequisite_admission import GRAPH_BOUND_PREREQUISITE_WORKFLOW
from .prerequisite_execution_claim import (
    GraphBoundExecutionClaim,
    GraphBoundExecutionClaimDenied,
    _GraphBoundProvisioningAuthority,
)
from .prerequisite_request_binding import (
    GraphBoundRequestActionBinding,
    _request_template_ref,
)
from .runtime import _apply_binding, _extract_runtime_value

GRAPH_BOUND_FRESH_WORLD_PROVISIONING_ENV = (
    "SENTINELFORGE_BEHAVIOR_GRAPH_BOUND_FRESH_WORLD_PROVISIONING"
)
GRAPH_BOUND_FRESH_WORLD_PROVISIONING_MODE = (
    "behavioral_graph_bound_fresh_world_provisioning_v1"
)

_TRUE = frozenset({"1", "true", "yes", "on"})
_WORLD_ROLES = (
    "valid_baseline",
    "counterfactual_treatment",
    "independent_control",
)


class GraphBoundFreshWorldProvisioningDenied(RuntimeError):
    """Provisioning failed closed before any terminal experiment dispatch."""

    def __init__(
        self,
        reason: str,
        *,
        category: str = "provisioning",
        orphaned_owned_state_possible: bool = False,
        cleanup: Optional["GraphBoundProvisioningCleanupResult"] = None,
    ) -> None:
        super().__init__(reason)
        self.category = category
        self.orphaned_owned_state_possible = orphaned_owned_state_possible
        self.cleanup = cleanup


@dataclass(frozen=True)
class GraphBoundFreshWorldProvisioningConfig:
    enabled: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.enabled, bool):
            raise TypeError("graph-bound provisioning enabled must be boolean")

    @classmethod
    def from_environment(cls) -> "GraphBoundFreshWorldProvisioningConfig":
        return cls(
            enabled=str(
                os.getenv(GRAPH_BOUND_FRESH_WORLD_PROVISIONING_ENV, "")
            ).strip().lower()
            in _TRUE
        )


@dataclass(frozen=True)
class GraphBoundProvisionedWorld:
    world_ref: str
    claim_contract_id: str
    world_slot_id: str
    world_role: str
    requests_sent: int
    creates_completed: int
    runtime_values_bound: int
    ownership_registered: bool = True
    freshness_attested: bool = True

    @classmethod
    def build(
        cls,
        *,
        claim_contract_id: str,
        world_slot_id: str,
        world_role: str,
        requests_sent: int,
        creates_completed: int,
        runtime_values_bound: int,
    ) -> "GraphBoundProvisionedWorld":
        payload = {
            "claim_contract_id": claim_contract_id,
            "world_slot_id": world_slot_id,
            "world_role": world_role,
            "requests_sent": requests_sent,
            "creates_completed": creates_completed,
            "runtime_values_bound": runtime_values_bound,
            "ownership_registered": True,
            "freshness_attested": True,
        }
        return cls(
            world_ref=stable_hash("graph_bound_provisioned_world", payload),
            claim_contract_id=claim_contract_id,
            world_slot_id=world_slot_id,
            world_role=world_role,
            requests_sent=requests_sent,
            creates_completed=creates_completed,
            runtime_values_bound=runtime_values_bound,
        )

    def __post_init__(self) -> None:
        payload = {
            "claim_contract_id": self.claim_contract_id,
            "world_slot_id": self.world_slot_id,
            "world_role": self.world_role,
            "requests_sent": self.requests_sent,
            "creates_completed": self.creates_completed,
            "runtime_values_bound": self.runtime_values_bound,
            "ownership_registered": True,
            "freshness_attested": True,
        }
        if (
            self.world_ref
            != stable_hash("graph_bound_provisioned_world", payload)
            or not self.claim_contract_id.startswith(
                "graph_bound_execution_claim_contract:"
            )
            or not self.world_slot_id.startswith("graph_bound_fresh_world_slot:")
            or self.world_role not in _WORLD_ROLES
            or any(
                isinstance(value, bool) or not isinstance(value, int) or value <= 0
                for value in (
                    self.requests_sent,
                    self.creates_completed,
                    self.runtime_values_bound,
                )
            )
            or not self.ownership_registered
            or not self.freshness_attested
        ):
            raise ValueError("graph-bound provisioned world is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "world_ref": self.world_ref,
            "claim_contract_id": self.claim_contract_id,
            "world_slot_id": self.world_slot_id,
            "world_role": self.world_role,
            "requests_sent": self.requests_sent,
            "creates_completed": self.creates_completed,
            "runtime_values_bound": self.runtime_values_bound,
            "ownership_registered": self.ownership_registered,
            "freshness_attested": self.freshness_attested,
        }


@dataclass(frozen=True)
class GraphBoundFreshWorldProvisioningEvidence:
    provisioning_id: str
    claim_contract_id: str
    plan_id: str
    family: str
    worlds: Tuple[GraphBoundProvisionedWorld, ...]
    provisioning_request_units: int
    remaining_request_units: int
    target_requests_sent: int
    runtime_lineage_substituted: bool = True
    terminal_actions_dispatched: int = 0
    cleanup_required: bool = True
    backend_dispatch_authority: bool = False
    finding_authority: bool = False
    executable: bool = False
    mode: str = GRAPH_BOUND_FRESH_WORLD_PROVISIONING_MODE

    @classmethod
    def build(
        cls,
        *,
        claim_contract_id: str,
        plan_id: str,
        family: str,
        worlds: Sequence[GraphBoundProvisionedWorld],
        provisioning_request_units: int,
        remaining_request_units: int,
    ) -> "GraphBoundFreshWorldProvisioningEvidence":
        values = tuple(worlds)
        payload = {
            "claim_contract_id": claim_contract_id,
            "plan_id": plan_id,
            "family": family,
            "worlds": [item.to_dict() for item in values],
            "provisioning_request_units": provisioning_request_units,
            "remaining_request_units": remaining_request_units,
            "runtime_lineage_substituted": True,
            "terminal_actions_dispatched": 0,
            "cleanup_required": True,
            "backend_dispatch_authority": False,
            "finding_authority": False,
            "target_requests_sent": provisioning_request_units,
            "executable": False,
            "mode": GRAPH_BOUND_FRESH_WORLD_PROVISIONING_MODE,
        }
        return cls(
            provisioning_id=stable_hash(
                "graph_bound_fresh_world_provisioning",
                payload,
            ),
            claim_contract_id=claim_contract_id,
            plan_id=plan_id,
            family=family,
            worlds=values,
            provisioning_request_units=provisioning_request_units,
            remaining_request_units=remaining_request_units,
            target_requests_sent=provisioning_request_units,
        )

    def __post_init__(self) -> None:
        payload = {
            "claim_contract_id": self.claim_contract_id,
            "plan_id": self.plan_id,
            "family": self.family,
            "worlds": [item.to_dict() for item in self.worlds],
            "provisioning_request_units": self.provisioning_request_units,
            "remaining_request_units": self.remaining_request_units,
            "runtime_lineage_substituted": self.runtime_lineage_substituted,
            "terminal_actions_dispatched": self.terminal_actions_dispatched,
            "cleanup_required": self.cleanup_required,
            "backend_dispatch_authority": self.backend_dispatch_authority,
            "finding_authority": self.finding_authority,
            "target_requests_sent": self.target_requests_sent,
            "executable": self.executable,
            "mode": self.mode,
        }
        if (
            self.provisioning_id
            != stable_hash(
                "graph_bound_fresh_world_provisioning",
                payload,
            )
            or not self.claim_contract_id.startswith(
                "graph_bound_execution_claim_contract:"
            )
            or not self.plan_id.startswith("graph_bound_prepared_request_plan:")
            or self.family not in {"omission", "reordering"}
            or tuple(item.world_role for item in self.worlds) != _WORLD_ROLES
            or self.provisioning_request_units != self.target_requests_sent
            or self.provisioning_request_units <= 0
            or self.remaining_request_units <= 0
            or not self.runtime_lineage_substituted
            or self.terminal_actions_dispatched != 0
            or not self.cleanup_required
            or self.backend_dispatch_authority
            or self.finding_authority
            or self.executable
            or self.mode != GRAPH_BOUND_FRESH_WORLD_PROVISIONING_MODE
        ):
            raise ValueError("graph-bound provisioning evidence is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": 1,
            "mode": self.mode,
            "provisioning_id": self.provisioning_id,
            "claim_contract_id": self.claim_contract_id,
            "plan_id": self.plan_id,
            "family": self.family,
            "worlds": [item.to_dict() for item in self.worlds],
            "provisioning_request_units": self.provisioning_request_units,
            "remaining_request_units": self.remaining_request_units,
            "runtime_lineage_substituted": self.runtime_lineage_substituted,
            "terminal_actions_dispatched": self.terminal_actions_dispatched,
            "cleanup_required": self.cleanup_required,
            "backend_dispatch_authority": self.backend_dispatch_authority,
            "finding_authority": self.finding_authority,
            "target_requests_sent": self.target_requests_sent,
            "executable": self.executable,
        }


@dataclass(frozen=True)
class GraphBoundProvisioningCleanupResult:
    status: str
    cleanup_steps_attempted: int
    cleanup_steps_completed: int
    ownership_grants_removed: int
    orphaned_owned_state_possible: bool
    receipt_state: str = "aborted"
    remaining_request_units: int = 0
    terminal_actions_dispatched: int = 0
    finding_authority: bool = False

    def __post_init__(self) -> None:
        if (
            self.status not in {"cleaned", "cleanup_failed"}
            or any(
                isinstance(value, bool) or not isinstance(value, int) or value < 0
                for value in (
                    self.cleanup_steps_attempted,
                    self.cleanup_steps_completed,
                    self.ownership_grants_removed,
                )
            )
            or self.cleanup_steps_completed > self.cleanup_steps_attempted
            or self.ownership_grants_removed > self.cleanup_steps_completed
            or (self.status == "cleaned")
            != (
                self.cleanup_steps_attempted == self.cleanup_steps_completed
                and not self.orphaned_owned_state_possible
            )
            or self.receipt_state != "aborted"
            or self.remaining_request_units != 0
            or self.terminal_actions_dispatched != 0
            or self.finding_authority
        ):
            raise ValueError("graph-bound provisioning cleanup result is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "cleanup_steps_attempted": self.cleanup_steps_attempted,
            "cleanup_steps_completed": self.cleanup_steps_completed,
            "ownership_grants_removed": self.ownership_grants_removed,
            "orphaned_owned_state_possible": self.orphaned_owned_state_possible,
            "receipt_state": self.receipt_state,
            "remaining_request_units": self.remaining_request_units,
            "terminal_actions_dispatched": self.terminal_actions_dispatched,
            "finding_authority": self.finding_authority,
        }


@dataclass(frozen=True, repr=False)
class _RuntimeEntry:
    binding: GraphBoundRequestActionBinding
    request: EphemeralRehydratedStep
    input_bindings: Tuple[LineageBinding, ...] = ()
    output_bindings: Tuple[LineageBinding, ...] = ()


@dataclass(frozen=True, repr=False)
class _CreatedState:
    world_slot_id: str
    operation_id: str
    create_url: str = ""
    object_id: Any = None


@dataclass
class _ProvisioningState:
    runtime_values: Dict[Tuple[str, str], Any] = field(default_factory=dict)
    created: Dict[Tuple[str, str], _CreatedState] = field(default_factory=dict)
    requests_by_role: Dict[str, int] = field(
        default_factory=lambda: {role: 0 for role in _WORLD_ROLES}
    )
    creates_by_role: Dict[str, int] = field(
        default_factory=lambda: {role: 0 for role in _WORLD_ROLES}
    )
    values_by_role: Dict[str, int] = field(
        default_factory=lambda: {role: 0 for role in _WORLD_ROLES}
    )
    orphaned: bool = False


def _candidate(
    entry: _RuntimeEntry,
    request: EphemeralRehydratedStep,
    *,
    actor_persona_id: str,
    reservation_id: str,
) -> CandidateAction:
    cleanup = entry.binding.phase == "cleanup"
    return CandidateAction(
        method=request.method,
        url=request.url,
        body=request.body,
        hint=entry.binding.action_class,
        actor_persona_id=actor_persona_id,
        target_owner_persona_id=(actor_persona_id if cleanup else None),
        target_is_researcher_owned=(True if cleanup else None),
        expected_side_effect=entry.binding.expected_side_effect,
        proof_goal="graph_bound_fresh_world_provisioning",
        budget_reservation_id=reservation_id,
    )


@dataclass(frozen=True)
class GraphBoundFreshWorldProvisioningResult:
    evidence: GraphBoundFreshWorldProvisioningEvidence
    cleanup: GraphBoundProvisioningCleanupResult
    provenance_ref: str
    status: str = "completed"
    receipt_state: str = "aborted"
    remaining_request_units: int = 0
    backend_dispatch_authority: bool = False
    finding_authority: bool = False
    executable: bool = False

    def __post_init__(self) -> None:
        if (
            self.status != "completed"
            or self.cleanup.status != "cleaned"
            or self.cleanup.orphaned_owned_state_possible
            or not self.provenance_ref.startswith(
                "graph_bound_provisioning_provenance:"
            )
            or self.receipt_state != "aborted"
            or self.remaining_request_units != 0
            or self.backend_dispatch_authority
            or self.finding_authority
            or self.executable
        ):
            raise ValueError("graph-bound provisioning result is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "provisioning": self.evidence.to_dict(),
            "cleanup": self.cleanup.to_dict(),
            "provenance_ref": self.provenance_ref,
            "receipt_state": self.receipt_state,
            "remaining_request_units": self.remaining_request_units,
            "backend_dispatch_authority": self.backend_dispatch_authority,
            "finding_authority": self.finding_authority,
            "target_requests_sent": (
                self.evidence.target_requests_sent
                + self.cleanup.cleanup_steps_completed
            ),
            "executable": self.executable,
        }


def _runtime_entries(runtime_plan: Any) -> Tuple[
    Tuple[_RuntimeEntry, ...],
    Tuple[_RuntimeEntry, ...],
    Tuple[_RuntimeEntry, ...],
]:
    plan = runtime_plan.plan
    raw_by_id = {item.binding_id: item for item in plan.ephemeral_requests}
    entries = tuple(
        _RuntimeEntry(
            binding=item,
            request=raw_by_id[item.binding_id].request,
            input_bindings=raw_by_id[item.binding_id].input_bindings,
            output_bindings=raw_by_id[item.binding_id].output_bindings,
        )
        for item in plan.request_bindings
    )
    if any(
        _request_template_ref(item.request)
        != item.binding.request_template_ref
        or stable_hash(
            "graph_bound_endpoint_key",
            endpoint_key(item.request.url),
        )
        != item.binding.endpoint_key_ref
        for item in entries
    ):
        raise GraphBoundFreshWorldProvisioningDenied(
            "graph_bound_provisioning_request_identity_changed",
            category="plan",
        )
    provision = tuple(
        item
        for item in entries
        if item.binding.phase != "cleanup"
        and item.binding.operation_id != runtime_plan.terminal_operation_id
    )
    dispatch = tuple(
        item
        for item in entries
        if item.binding.phase != "cleanup"
        and item.binding.operation_id == runtime_plan.terminal_operation_id
    )
    cleanup = tuple(item for item in entries if item.binding.phase == "cleanup")
    cleanup_role_counts = {
        role: sum(item.binding.world_role == role for item in cleanup)
        for role in _WORLD_ROLES
    }
    if (
        entries != (*provision, *dispatch, *cleanup)
        or tuple(item.binding.world_role for item in dispatch) != _WORLD_ROLES
        or not cleanup
        or len(set(cleanup_role_counts.values())) != 1
        or 0 in cleanup_role_counts.values()
        or any(item.binding.action_class == OWNED_CREATE for item in dispatch)
        or not provision
    ):
        raise GraphBoundFreshWorldProvisioningDenied(
            "graph_bound_provisioning_stage_contract_mismatch",
            category="plan",
        )
    return provision, dispatch, cleanup


def _validate_runtime_authority(runtime_plan: Any) -> None:
    authorization = runtime_plan.authorization
    if (
        not authorization.attestation_signature
        or not authorization.signature_is_valid()
        or authorization.is_expired()
        or not authorization.disclosure_attestation
        or not authorization.authorization_basis.strip()
    ):
        raise GraphBoundFreshWorldProvisioningDenied(
            "graph_bound_provisioning_authority_is_not_current",
            category="authority",
        )
    try:
        authorization.authorize_action(
            target_origin=runtime_plan.target_origin,
            workflow=GRAPH_BOUND_PREREQUISITE_WORKFLOW,
        )
    except Exception as exc:
        raise GraphBoundFreshWorldProvisioningDenied(
            "graph_bound_provisioning_scope_or_workflow_denied",
            category="authority",
        ) from exc
    authority_context_ref = experiment_authority_context_ref(
        authorization,
        runtime_plan.target_origin,
        (GRAPH_BOUND_PREREQUISITE_WORKFLOW,),
    )
    authorization_ref = stable_hash(
        "graph_bound_authorization",
        {
            "envelope_id": authorization.envelope_id,
            "attestation_signature": authorization.attestation_signature,
            "authority_context_ref": authority_context_ref,
        },
    )
    if (
        authority_context_ref != runtime_plan.authority_context_ref
        or authorization_ref != runtime_plan.authorization_ref
    ):
        raise GraphBoundFreshWorldProvisioningDenied(
            "graph_bound_provisioning_authority_context_changed",
            category="authority",
        )
    if (
        stable_hash(
            "graph_bound_experiment_policy",
            runtime_plan.executor.policy.digest(),
        )
        != runtime_plan.policy_ref
        or runtime_plan.executor.provenance is None
    ):
        raise GraphBoundFreshWorldProvisioningDenied(
            "graph_bound_provisioning_policy_context_changed",
            category="policy",
        )


def _rehydrate(
    entry: _RuntimeEntry,
    runtime_values: Mapping[Tuple[str, str], Any],
) -> EphemeralRehydratedStep:
    request = entry.request
    for binding in entry.input_bindings:
        key = (entry.binding.world_slot_id, binding.binding_id)
        if key not in runtime_values:
            raise GraphBoundFreshWorldProvisioningDenied(
                "graph_bound_runtime_dependency_value_unavailable",
                category="lineage",
            )
        try:
            request = _apply_binding(request, binding, runtime_values[key])
        except Exception as exc:
            raise GraphBoundFreshWorldProvisioningDenied(
                "graph_bound_runtime_lineage_substitution_failed",
                category="lineage",
            ) from exc
    if endpoint_key(request.url) != endpoint_key(entry.request.url):
        raise GraphBoundFreshWorldProvisioningDenied(
            "graph_bound_runtime_substitution_changed_endpoint_budget_key",
            category="budget",
        )
    return request


async def _cleanup_and_abort(
    *,
    authority: _GraphBoundProvisioningAuthority,
    dispatch_entries: Sequence[_RuntimeEntry],
    cleanup_entries: Sequence[_RuntimeEntry],
    runtime_values: Mapping[Tuple[str, str], Any],
    created: Mapping[Tuple[str, str], _CreatedState],
    expected_state: str,
    reason: str,
    orphaned: bool,
) -> GraphBoundProvisioningCleanupResult:
    runtime = authority.runtime_plan
    executor = runtime.executor
    budget = executor.policy.budget
    reservation_id = authority.budget_reservation_id
    cleanup_count = len(cleanup_entries)
    before_cleanup = budget.reservation_remaining(reservation_id)
    skip_count = before_cleanup - cleanup_count
    if skip_count < 0:
        orphaned = True
    elif skip_count:
        skipped = budget.skip_reservation_entries(reservation_id, skip_count)
        authority.note_budget_units(skipped)

    attempted = 0
    completed = 0
    grants_removed = 0
    for entry in cleanup_entries:
        create_key = next(
            (
                key
                for key in created
                if key[0] == entry.binding.world_slot_id
                and any(
                    binding.producer_operation_id == key[1]
                    for binding in entry.input_bindings
                )
            ),
            None,
        )
        if create_key is None:
            if budget.reservation_remaining(reservation_id):
                skipped = budget.skip_reservation_entries(reservation_id, 1)
                authority.note_budget_units(skipped)
            continue
        attempted += 1
        consumed = False
        try:
            request = _rehydrate(entry, runtime_values)
            registry = executor.policy.ownership_registry
            if registry is None or not registry.is_owned(request.url):
                raise GraphBoundFreshWorldProvisioningDenied(
                    "graph_bound_cleanup_target_not_registered",
                    category="ownership",
                )
            before = budget.reservation_remaining(reservation_id)
            status, _response = await executor.send_action(
                _candidate(
                    entry,
                    request,
                    actor_persona_id=runtime.actor_persona_id,
                    reservation_id=reservation_id,
                ),
                headers=dict(request.headers),
            )
            consumed_units = before - budget.reservation_remaining(reservation_id)
            if consumed_units:
                authority.note_budget_units(consumed_units)
            consumed = consumed_units > 0
            if consumed_units != 1:
                raise GraphBoundFreshWorldProvisioningDenied(
                    "graph_bound_cleanup_budget_consumption_mismatch",
                    category="budget",
                )
            if status == DENIED_STATUS or not 200 <= int(status) < 300:
                raise GraphBoundFreshWorldProvisioningDenied(
                    "graph_bound_cleanup_request_failed",
                    category="cleanup",
                )
            completed += 1
            state = created[create_key]
            if registry.unregister_created_value(
                state.create_url,
                state.object_id,
                actor_persona=runtime.actor_persona_id,
            ):
                grants_removed += 1
            else:
                orphaned = True
        except Exception:
            orphaned = True
            if not consumed and budget.reservation_remaining(reservation_id):
                skipped = budget.skip_reservation_entries(reservation_id, 1)
                authority.note_budget_units(skipped)

    try:
        authority.abort(expected_state=expected_state, reason=reason)
    except GraphBoundExecutionClaimDenied as exc:
        raise GraphBoundFreshWorldProvisioningDenied(
            str(exc),
            category=exc.category,
            orphaned_owned_state_possible=True,
        ) from exc
    result = GraphBoundProvisioningCleanupResult(
        status=(
            "cleaned"
            if attempted == completed and not orphaned
            else "cleanup_failed"
        ),
        cleanup_steps_attempted=attempted,
        cleanup_steps_completed=completed,
        ownership_grants_removed=grants_removed,
        orphaned_owned_state_possible=orphaned,
    )
    return result


def _require_owned_dependencies(
    *,
    entry: _RuntimeEntry,
    state: _ProvisioningState,
    create_operation_ids: frozenset[str],
    runtime_plan: Any,
) -> None:
    dependencies = tuple(
        state.created.get(
            (
                entry.binding.world_slot_id,
                binding.producer_operation_id,
            )
        )
        for binding in entry.input_bindings
        if binding.producer_operation_id in create_operation_ids
    )
    registry = runtime_plan.executor.policy.ownership_registry
    if dependencies and (
        registry is None
        or any(item is None for item in dependencies)
        or any(
            not registry.is_created_value_owned(
                item.create_url,
                item.object_id,
                actor_persona=runtime_plan.actor_persona_id,
            )
            for item in dependencies
            if item is not None
        )
    ):
        raise GraphBoundFreshWorldProvisioningDenied(
            "graph_bound_provisioning_target_not_registered",
            category="ownership",
        )


def _extract_entry_values(
    *,
    entry: _RuntimeEntry,
    response: Any,
    state: _ProvisioningState,
) -> Tuple[Tuple[LineageBinding, Any], ...]:
    produced = []
    for binding in entry.output_bindings:
        try:
            value = _extract_runtime_value(response, binding)
        except Exception as exc:
            if entry.binding.action_class == OWNED_CREATE:
                state.orphaned = True
            raise GraphBoundFreshWorldProvisioningDenied(
                "graph_bound_runtime_value_extraction_failed",
                category="lineage",
                orphaned_owned_state_possible=state.orphaned,
            ) from exc
        state.runtime_values[
            (entry.binding.world_slot_id, binding.binding_id)
        ] = value
        produced.append((binding, value))
    state.values_by_role[entry.binding.world_role] += len(produced)
    return tuple(produced)


def _register_fresh_create(
    *,
    entry: _RuntimeEntry,
    request: EphemeralRehydratedStep,
    produced_values: Sequence[Tuple[LineageBinding, Any]],
    state: _ProvisioningState,
    runtime_plan: Any,
) -> None:
    path_values = {
        str(value)
        for binding, value in produced_values
        if binding.consumer_locator.kind == LocatorKind.REQUEST_PATH
    }
    reused_capture = any(
        stable_hash(
            "lineage_value",
            {
                "capture_digest": runtime_plan.plan.lifecycle_capture_digest,
                "value": str(value),
            },
        )
        == binding.value_hash
        for binding, value in produced_values
        if binding.consumer_locator.kind == LocatorKind.REQUEST_PATH
    )
    if reused_capture:
        state.orphaned = True
        raise GraphBoundFreshWorldProvisioningDenied(
            "graph_bound_create_reused_captured_identifier",
            category="freshness",
            orphaned_owned_state_possible=True,
        )
    if len(path_values) != 1:
        state.orphaned = True
        raise GraphBoundFreshWorldProvisioningDenied(
            "graph_bound_create_id_missing_or_ambiguous",
            category="lineage",
            orphaned_owned_state_possible=True,
        )
    object_id = next(iter(path_values))
    if any(
        str(item.object_id) == object_id
        and item.operation_id == entry.binding.operation_id
        for item in state.created.values()
    ):
        state.orphaned = True
        raise GraphBoundFreshWorldProvisioningDenied(
            "graph_bound_fresh_world_identifier_reused",
            category="freshness",
            orphaned_owned_state_possible=True,
        )
    registry = runtime_plan.executor.policy.ownership_registry
    if registry is None or registry.register_created_value(
        request.url,
        object_id,
        actor_persona=runtime_plan.actor_persona_id,
    ) is None:
        state.orphaned = True
        raise GraphBoundFreshWorldProvisioningDenied(
            "graph_bound_create_ownership_registration_failed",
            category="ownership",
            orphaned_owned_state_possible=True,
        )
    state.created[
        (entry.binding.world_slot_id, entry.binding.operation_id)
    ] = _CreatedState(
        world_slot_id=entry.binding.world_slot_id,
        operation_id=entry.binding.operation_id,
        create_url=request.url,
        object_id=object_id,
    )
    state.creates_by_role[entry.binding.world_role] += 1


async def _execute_provisioning_prefix(
    *,
    authority: _GraphBoundProvisioningAuthority,
    provision_entries: Sequence[_RuntimeEntry],
    state: _ProvisioningState,
) -> None:
    runtime = authority.runtime_plan
    executor = runtime.executor
    budget = executor.policy.budget
    reservation_id = authority.budget_reservation_id
    create_operation_ids = frozenset(
        item.binding.operation_id
        for item in provision_entries
        if item.binding.action_class == OWNED_CREATE
    )
    for entry in provision_entries:
        request = _rehydrate(entry, state.runtime_values)
        _require_owned_dependencies(
            entry=entry,
            state=state,
            create_operation_ids=create_operation_ids,
            runtime_plan=runtime,
        )
        before = budget.reservation_remaining(reservation_id)
        status, response = await executor.send_action(
            _candidate(
                entry,
                request,
                actor_persona_id=runtime.actor_persona_id,
                reservation_id=reservation_id,
            ),
            headers=dict(request.headers),
        )
        consumed_units = before - budget.reservation_remaining(reservation_id)
        if consumed_units:
            authority.note_budget_units(consumed_units)
        if consumed_units != 1:
            raise GraphBoundFreshWorldProvisioningDenied(
                "graph_bound_provisioning_request_not_consumed",
                category="policy",
            )
        if status == DENIED_STATUS or not 200 <= int(status) < 300:
            raise GraphBoundFreshWorldProvisioningDenied(
                "graph_bound_provisioning_request_failed",
                category="transport",
            )
        state.requests_by_role[entry.binding.world_role] += 1
        produced_values = _extract_entry_values(
            entry=entry,
            response=response,
            state=state,
        )
        if entry.binding.action_class == OWNED_CREATE:
            _register_fresh_create(
                entry=entry,
                request=request,
                produced_values=produced_values,
                state=state,
                runtime_plan=runtime,
            )


def _build_provisioning_evidence(
    *,
    claim_contract_id: str,
    authority: _GraphBoundProvisioningAuthority,
    provision_entries: Sequence[_RuntimeEntry],
    dispatch_entries: Sequence[_RuntimeEntry],
    cleanup_entries: Sequence[_RuntimeEntry],
    state: _ProvisioningState,
) -> GraphBoundFreshWorldProvisioningEvidence:
    if any(
        state.requests_by_role[role] <= 0
        or state.creates_by_role[role] <= 0
        or state.values_by_role[role] <= 0
        for role in _WORLD_ROLES
    ):
        raise GraphBoundFreshWorldProvisioningDenied(
            "graph_bound_fresh_world_provisioning_incomplete",
            category="freshness",
        )
    for entry in dispatch_entries:
        _rehydrate(entry, state.runtime_values)
    expected_remaining = len(dispatch_entries) + len(cleanup_entries)
    if authority.remaining_units != expected_remaining:
        raise GraphBoundFreshWorldProvisioningDenied(
            "graph_bound_provisioning_budget_boundary_mismatch",
            category="budget",
        )
    worlds = tuple(
        GraphBoundProvisionedWorld.build(
            claim_contract_id=claim_contract_id,
            world_slot_id=next(
                item.binding.world_slot_id
                for item in provision_entries
                if item.binding.world_role == role
            ),
            world_role=role,
            requests_sent=state.requests_by_role[role],
            creates_completed=state.creates_by_role[role],
            runtime_values_bound=state.values_by_role[role],
        )
        for role in _WORLD_ROLES
    )
    runtime = authority.runtime_plan
    return GraphBoundFreshWorldProvisioningEvidence.build(
        claim_contract_id=claim_contract_id,
        plan_id=runtime.plan.plan_id,
        family=runtime.plan.family,
        worlds=worlds,
        provisioning_request_units=len(provision_entries),
        remaining_request_units=expected_remaining,
    )


async def _complete_provisioning_probe(
    *,
    authority: _GraphBoundProvisioningAuthority,
    evidence: GraphBoundFreshWorldProvisioningEvidence,
    dispatch_entries: Sequence[_RuntimeEntry],
    cleanup_entries: Sequence[_RuntimeEntry],
    state: _ProvisioningState,
) -> GraphBoundFreshWorldProvisioningResult:
    authority.mark_provisioned()
    cleanup = await _cleanup_and_abort(
        authority=authority,
        dispatch_entries=dispatch_entries,
        cleanup_entries=cleanup_entries,
        runtime_values=state.runtime_values,
        created=state.created,
        expected_state="provisioned",
        reason="graph_bound_provisioning_probe_completed",
        orphaned=False,
    )
    if cleanup.status != "cleaned":
        raise GraphBoundFreshWorldProvisioningDenied(
            "graph_bound_provisioning_cleanup_failed",
            category="cleanup",
            orphaned_owned_state_possible=cleanup.orphaned_owned_state_possible,
            cleanup=cleanup,
        )
    sink = authority.runtime_plan.executor.provenance
    if sink is None or not sink.verify() or not sink.root():
        raise GraphBoundFreshWorldProvisioningDenied(
            "graph_bound_provisioning_provenance_invalid",
            category="provenance",
            cleanup=cleanup,
        )
    return GraphBoundFreshWorldProvisioningResult(
        evidence=evidence,
        cleanup=cleanup,
        provenance_ref=stable_hash(
            "graph_bound_provisioning_provenance",
            sink.root(),
        ),
    )


async def _raise_after_provisioning_failure(
    *,
    authority: _GraphBoundProvisioningAuthority,
    dispatch_entries: Sequence[_RuntimeEntry],
    cleanup_entries: Sequence[_RuntimeEntry],
    state: _ProvisioningState,
    error: Exception,
) -> NoReturn:
    if authority.state == "aborted":
        if isinstance(error, GraphBoundFreshWorldProvisioningDenied):
            raise error
        raise GraphBoundFreshWorldProvisioningDenied(
            "graph_bound_provisioning_cleanup_terminalization_failed",
            category="cleanup",
            orphaned_owned_state_possible=True,
        ) from error
    if authority.state == "provisioned":
        try:
            authority.abort(
                expected_state="provisioned",
                reason="graph_bound_provisioning_cleanup_failed",
            )
        except Exception as abort_error:
            raise GraphBoundFreshWorldProvisioningDenied(
                "graph_bound_provisioning_cleanup_receipt_abort_failed",
                category="receipt",
                orphaned_owned_state_possible=True,
            ) from abort_error
        raise GraphBoundFreshWorldProvisioningDenied(
            "graph_bound_provisioning_cleanup_terminalization_failed",
            category="cleanup",
            orphaned_owned_state_possible=True,
        ) from error
    try:
        cleanup = await _cleanup_and_abort(
            authority=authority,
            dispatch_entries=dispatch_entries,
            cleanup_entries=cleanup_entries,
            runtime_values=state.runtime_values,
            created=state.created,
            expected_state="provisioning",
            reason="graph_bound_provisioning_failed",
            orphaned=(
                state.orphaned
                or getattr(error, "orphaned_owned_state_possible", False)
            ),
        )
    except Exception as cleanup_error:
        raise GraphBoundFreshWorldProvisioningDenied(
            "graph_bound_provisioning_cleanup_terminalization_failed",
            category="cleanup",
            orphaned_owned_state_possible=True,
        ) from cleanup_error
    if isinstance(error, GraphBoundFreshWorldProvisioningDenied):
        raise GraphBoundFreshWorldProvisioningDenied(
            str(error),
            category=error.category,
            orphaned_owned_state_possible=(
                error.orphaned_owned_state_possible
                or cleanup.orphaned_owned_state_possible
            ),
            cleanup=cleanup,
        ) from error
    raise GraphBoundFreshWorldProvisioningDenied(
        "graph_bound_provisioning_transport_error",
        category="transport",
        orphaned_owned_state_possible=(
            state.orphaned or cleanup.orphaned_owned_state_possible
        ),
        cleanup=cleanup,
    ) from error


class GraphBoundFreshWorldProvisioner:
    """Default-off active boundary for the non-terminal provisioning prefix."""

    def __init__(
        self,
        claim: GraphBoundExecutionClaim,
        *,
        config: Optional[GraphBoundFreshWorldProvisioningConfig] = None,
    ) -> None:
        if not isinstance(claim, GraphBoundExecutionClaim):
            raise TypeError("claim must be a GraphBoundExecutionClaim")
        if config is not None and not isinstance(
            config,
            GraphBoundFreshWorldProvisioningConfig,
        ):
            raise TypeError(
                "config must be a GraphBoundFreshWorldProvisioningConfig"
            )
        self.claim = claim
        self.config = config or GraphBoundFreshWorldProvisioningConfig.from_environment()
        self._lock = asyncio.Lock()
        self._consumed = False

    async def provision(self) -> GraphBoundFreshWorldProvisioningResult:
        async with self._lock:
            if self._consumed:
                raise GraphBoundFreshWorldProvisioningDenied(
                    "graph_bound_provisioner_already_consumed",
                    category="claim",
                )
            if not self.config.enabled:
                raise GraphBoundFreshWorldProvisioningDenied(
                    "graph_bound_fresh_world_provisioning_is_disabled",
                    category="configuration",
                )
            self._consumed = True
            try:
                authority = self.claim._begin_provisioning()
            except GraphBoundExecutionClaimDenied as exc:
                raise GraphBoundFreshWorldProvisioningDenied(
                    str(exc),
                    category=exc.category,
                ) from exc

            runtime = authority.runtime_plan
            try:
                _validate_runtime_authority(runtime)
                provision, dispatch, cleanup = _runtime_entries(runtime)
            except Exception as exc:
                try:
                    authority.abort(
                        expected_state="provisioning",
                        reason="graph_bound_provisioning_plan_invalid",
                    )
                except Exception as abort_exc:
                    raise GraphBoundFreshWorldProvisioningDenied(
                        "graph_bound_provisioning_plan_abort_failed",
                        category="receipt",
                    ) from abort_exc
                if isinstance(exc, GraphBoundFreshWorldProvisioningDenied):
                    raise
                raise GraphBoundFreshWorldProvisioningDenied(
                    "graph_bound_provisioning_stage_contract_invalid",
                    category="plan",
                ) from exc
            state = _ProvisioningState()
            try:
                await _execute_provisioning_prefix(
                    authority=authority,
                    provision_entries=provision,
                    state=state,
                )
                evidence = _build_provisioning_evidence(
                    claim_contract_id=self.claim.contract.contract_id,
                    authority=authority,
                    provision_entries=provision,
                    dispatch_entries=dispatch,
                    cleanup_entries=cleanup,
                    state=state,
                )
                return await _complete_provisioning_probe(
                    authority=authority,
                    evidence=evidence,
                    dispatch_entries=dispatch,
                    cleanup_entries=cleanup,
                    state=state,
                )
            except Exception as exc:
                await _raise_after_provisioning_failure(
                    authority=authority,
                    dispatch_entries=dispatch,
                    cleanup_entries=cleanup,
                    state=state,
                    error=exc,
                )


__all__ = [
    "GRAPH_BOUND_FRESH_WORLD_PROVISIONING_ENV",
    "GRAPH_BOUND_FRESH_WORLD_PROVISIONING_MODE",
    "GraphBoundFreshWorldProvisioner",
    "GraphBoundFreshWorldProvisioningConfig",
    "GraphBoundFreshWorldProvisioningDenied",
    "GraphBoundFreshWorldProvisioningEvidence",
    "GraphBoundFreshWorldProvisioningResult",
    "GraphBoundProvisionedWorld",
    "GraphBoundProvisioningCleanupResult",
]
