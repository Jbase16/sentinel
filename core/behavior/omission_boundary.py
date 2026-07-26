"""Default-off fresh-state execution for one compiled omission experiment.

The compiler remains transport-free and analysis-only.  This module is the
separate active boundary that can discharge its two-fresh-owned-state and
execution-authority blockers for the narrow read-only prerequisite subset.
It is deliberately absent from package exports, routers, schedulers, and UI.
"""

from __future__ import annotations

import asyncio
import copy
import hmac
import os
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from core.cortex.execution_policy import (
    DENIED_STATUS,
    CandidateAction,
    PolicyExecutor,
)
from core.foundry.authorization import AuthorizationEnvelope
from core.safety.action_classifier import (
    OWNED_CREATE,
    OWNED_UPDATE_LOW_RISK,
    SAFE_READ,
    classify,
)
from core.safety.proof_budget import ProofBudget, endpoint_key
from core.safety.proof_mode import ProofMode

from .admission import COMPILED_ADMISSION_ENV
from .compiler import (
    BackwardExploitCompiler,
    CompilerLimits,
    OperationCatalogLimits,
    OperationSafety,
    high_value_goals,
)
from .lifecycle import LifecycleContractMiner, OwnedLifecycleCandidate
from .lineage import (
    EphemeralRehydratedStep,
    LineageBinding,
    LocatorKind,
    PlanRehydrator,
    RehydrationRecipe,
    ValueLineageLedger,
)
from .normalize import normalize_exchange, stable_hash
from .omission import (
    MinimizedOmissionCompiler,
    MinimizedOmissionExperiment,
)
from .receipts import (
    COMPLETED,
    BehavioralReceiptContext,
    BehavioralReceiptStore,
    ReceiptStoreError,
    redacted_fresh_omission_outcome,
    redacted_receipt_context,
    request_fingerprint,
)
from .runtime import (
    CONTROLLED_SEQUENCE_WORKFLOW,
    ControlledSequenceDenied,
    _apply_binding,
    _extract_runtime_value,
    _origin,
)
from .safety_contracts import (
    classification_body,
    is_proven_safe_cleanup_body,
    is_proven_safe_owned_create_body,
)
from .scheduler import PRIMARY_ENV
from .state_machine import (
    MAX_STATE_MACHINE_PLAN_STEPS,
    MAX_STATE_MACHINE_RECORDS,
    MAX_STATE_MACHINE_SEARCH_STATES,
    StateMachineLegalityMiner,
)

FRESH_OMISSION_ENV = "SENTINELFORGE_BEHAVIOR_OMISSION_EXECUTION"
FRESH_OMISSION_MODE = "behavioral_fresh_omission_boundary_v1"
FRESH_OMISSION_WORKFLOW = "behavioral_state_machine_omission"
_TRUE = frozenset({"1", "true", "yes", "on"})
_HASH_REF = re.compile(r"^[a-z][a-z0-9_]*:[0-9a-f]{64}$")
_SEMANTIC = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_SAFE_EXECUTION_BLOCKERS = frozenset(
    {
        "analysis_only_no_execution_authority",
        "requires_two_fresh_owned_states",
    }
)
_COMPARISON_STATUSES = frozenset(
    {
        "not_completed",
        "exact_match",
        "response_mismatch",
        "omission_rejected",
        "inconclusive_truncated",
    }
)


def _hash_ref(value: Any, prefix: str) -> bool:
    return (
        isinstance(value, str)
        and value.startswith(f"{prefix}:")
        and _HASH_REF.fullmatch(value) is not None
    )


class FreshOmissionDenied(RuntimeError):
    """The compiled omission cannot enter the active fresh-state boundary."""


class _OmissionAbort(RuntimeError):
    def __init__(self, code: str, *, orphan_possible: bool = False) -> None:
        super().__init__(code)
        self.code = code
        self.orphan_possible = orphan_possible


@dataclass(frozen=True)
class FreshOmissionConfig:
    enabled: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.enabled, bool):
            raise ValueError("fresh omission enabled must be a boolean")

    @classmethod
    def from_environment(cls) -> "FreshOmissionConfig":
        primary = os.environ.get(PRIMARY_ENV, "").strip().lower() in _TRUE
        compiled = os.environ.get(COMPILED_ADMISSION_ENV, "").strip().lower() in _TRUE
        omission = os.environ.get(FRESH_OMISSION_ENV, "").strip().lower() in _TRUE
        return cls(enabled=primary and compiled and omission)


@dataclass(frozen=True)
class FreshOmissionBoundaryResult:
    boundary_id: str
    experiment_id: str
    lifecycle_id: str
    terminal_operation_id: str
    status: str
    comparison_status: str
    baseline_reference_match: bool
    baseline_terminal_success: bool
    omission_terminal_success: bool
    baseline_terminal_truncated: bool
    omission_terminal_truncated: bool
    terminal_body_match: bool
    requests_attempted: int
    requests_sent: int
    baseline_steps_attempted: int
    baseline_steps_completed: int
    omission_steps_attempted: int
    omission_steps_completed: int
    creates_attempted: int
    creates_completed: int
    cleanup_steps_attempted: int
    cleanup_steps_completed: int
    policy_denials: int
    orphaned_owned_state_possible: bool
    provenance_root: str
    budget_snapshot: Dict[str, int]
    restraint: Dict[str, Any]
    provenance: Dict[str, Any]
    error_code: Optional[str] = None
    mode: str = FRESH_OMISSION_MODE
    finding_authority: bool = False
    executable: bool = True

    def __post_init__(self) -> None:
        counters = (
            self.requests_attempted,
            self.requests_sent,
            self.baseline_steps_attempted,
            self.baseline_steps_completed,
            self.omission_steps_attempted,
            self.omission_steps_completed,
            self.creates_attempted,
            self.creates_completed,
            self.cleanup_steps_attempted,
            self.cleanup_steps_completed,
            self.policy_denials,
        )
        budget_keys = {
            "total_requests",
            "cross_object_reads",
            "privilege_mutations",
            "creates",
            "endpoints_touched",
        }
        if (
            self.mode != FRESH_OMISSION_MODE
            or not self.executable
            or self.finding_authority
            or not _hash_ref(self.boundary_id, "fresh_omission_boundary")
            or not _hash_ref(self.experiment_id, "omission_experiment")
            or not _hash_ref(self.lifecycle_id, "owned_lifecycle")
            or not _hash_ref(self.terminal_operation_id, "action")
            or self.status not in {"completed", "aborted", "cleanup_failed"}
            or self.comparison_status not in _COMPARISON_STATUSES
            or any(
                isinstance(value, bool) or not isinstance(value, int) or value < 0
                for value in counters
            )
            or self.requests_sent > self.requests_attempted
            or self.requests_attempted
            != self.baseline_steps_attempted
            + self.omission_steps_attempted
            + self.cleanup_steps_attempted
            or self.baseline_steps_completed > self.baseline_steps_attempted
            or self.omission_steps_completed > self.omission_steps_attempted
            or self.creates_completed > self.creates_attempted
            or self.creates_attempted > 2
            or self.cleanup_steps_completed > self.cleanup_steps_attempted
            or self.cleanup_steps_attempted > 2
            or not isinstance(self.orphaned_owned_state_possible, bool)
            or not isinstance(self.provenance_root, str)
            or len(self.provenance_root) != 64
            or any(
                character not in "0123456789abcdef"
                for character in self.provenance_root
            )
            or not isinstance(self.budget_snapshot, dict)
            or set(self.budget_snapshot) != budget_keys
            or any(
                isinstance(value, bool) or not isinstance(value, int) or value < 0
                for value in self.budget_snapshot.values()
            )
            or self.budget_snapshot["total_requests"] != self.requests_sent
            or self.budget_snapshot["cross_object_reads"] != 0
            or self.budget_snapshot["privilege_mutations"] != 0
            or self.budget_snapshot["creates"] > 2
            or self.budget_snapshot["endpoints_touched"]
            > self.budget_snapshot["total_requests"]
            or (
                self.error_code is not None
                and (
                    not isinstance(self.error_code, str)
                    or _SEMANTIC.fullmatch(self.error_code) is None
                )
            )
        ):
            raise ValueError("fresh omission result contract is invalid")
        if self.status == "completed" and (
            self.error_code is not None
            or self.orphaned_owned_state_possible
            or not self.baseline_reference_match
            or self.creates_completed != 2
            or self.cleanup_steps_completed != 2
            or self.comparison_status == "not_completed"
        ):
            raise ValueError("fresh omission completed result is inconsistent")
        if self.status == "aborted" and self.error_code is None:
            raise ValueError("fresh omission aborted result requires an error")
        if self.status == "cleanup_failed" and (
            self.error_code != "fresh_omission_cleanup_failed"
            or not self.orphaned_owned_state_possible
            or self.cleanup_steps_completed == self.cleanup_steps_attempted
        ):
            raise ValueError("fresh omission cleanup failure is inconsistent")
        if self.comparison_status == "exact_match" and (
            not self.baseline_reference_match
            or not self.baseline_terminal_success
            or not self.omission_terminal_success
            or self.baseline_terminal_truncated
            or self.omission_terminal_truncated
            or not self.terminal_body_match
        ):
            raise ValueError("fresh omission exact comparison is inconsistent")

    @property
    def finding(self) -> None:
        return None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": 1,
            "boundary_id": self.boundary_id,
            "experiment_id": self.experiment_id,
            "lifecycle_id": self.lifecycle_id,
            "terminal_operation_id": self.terminal_operation_id,
            "status": self.status,
            "comparison_status": self.comparison_status,
            "baseline_reference_match": self.baseline_reference_match,
            "baseline_terminal_success": self.baseline_terminal_success,
            "omission_terminal_success": self.omission_terminal_success,
            "baseline_terminal_truncated": self.baseline_terminal_truncated,
            "omission_terminal_truncated": self.omission_terminal_truncated,
            "terminal_body_match": self.terminal_body_match,
            "requests_attempted": self.requests_attempted,
            "requests_sent": self.requests_sent,
            "baseline_steps_attempted": self.baseline_steps_attempted,
            "baseline_steps_completed": self.baseline_steps_completed,
            "omission_steps_attempted": self.omission_steps_attempted,
            "omission_steps_completed": self.omission_steps_completed,
            "creates_attempted": self.creates_attempted,
            "creates_completed": self.creates_completed,
            "cleanup_steps_attempted": self.cleanup_steps_attempted,
            "cleanup_steps_completed": self.cleanup_steps_completed,
            "policy_denials": self.policy_denials,
            "orphaned_owned_state_possible": self.orphaned_owned_state_possible,
            "provenance_root": self.provenance_root,
            "budget_snapshot": dict(self.budget_snapshot),
            "restraint": copy.deepcopy(self.restraint),
            "provenance": copy.deepcopy(self.provenance),
            "error_code": self.error_code,
            "mode": self.mode,
            "finding_authority": self.finding_authority,
            "executable": self.executable,
            "finding": None,
        }


@dataclass(frozen=True)
class _TerminalEvidence:
    status: int
    body_hash: Optional[str]
    success: bool
    truncated: bool


@dataclass(frozen=True)
class _FreshObject:
    value: str = field(repr=False)
    cleanup_request: EphemeralRehydratedStep = field(repr=False)


@dataclass
class _LegProgress:
    owned_object: Optional[_FreshObject] = field(
        default=None,
        repr=False,
    )
    terminal_evidence: Optional[_TerminalEvidence] = None
    attempted: int = 0
    completed: int = 0
    create_attempted: bool = False
    create_completed: bool = False


@dataclass(frozen=True)
class _OmissionPreflight:
    boundary_id: str
    experiment: MinimizedOmissionExperiment
    lifecycle: OwnedLifecycleCandidate
    recipe: RehydrationRecipe = field(repr=False, compare=False)
    ledger: ValueLineageLedger = field(repr=False, compare=False)
    requests: Mapping[str, EphemeralRehydratedStep] = field(
        repr=False,
        compare=False,
    )
    cleanup_request: EphemeralRehydratedStep = field(repr=False, compare=False)
    cleanup_binding: LineageBinding = field(repr=False, compare=False)
    bindings: Tuple[LineageBinding, ...] = field(repr=False, compare=False)
    reserved_actions: Tuple[Tuple[str, str], ...] = field(
        repr=False,
        compare=False,
    )


class _ReservationCursor:
    def __init__(
        self,
        budget: ProofBudget,
        reservation_id: str,
        *,
        total_slots: int,
    ) -> None:
        self.budget = budget
        self.reservation_id = reservation_id
        self.total_slots = total_slots
        self.index = 0
        self.attempted = 0
        self.sent = 0

    async def send(
        self,
        expected_index: int,
        executor: PolicyExecutor,
        action: CandidateAction,
        *,
        headers: Dict[str, Any],
    ) -> Tuple[int, Any]:
        if expected_index != self.index:
            raise FreshOmissionDenied("fresh_omission_reservation_order_changed")
        self.attempted += 1
        remaining_before = self.budget.reservation_remaining(self.reservation_id)
        total_before = self.budget.snapshot()["total_requests"]
        try:
            result = await executor.send_action(action, headers=headers)
        except BaseException:
            remaining_after = self.budget.reservation_remaining(self.reservation_id)
            if remaining_after == remaining_before:
                self.budget.skip_reservation_entries(self.reservation_id, 1)
            self.sent += max(
                0,
                self.budget.snapshot()["total_requests"] - total_before,
            )
            self.index += 1
            raise
        remaining_after = self.budget.reservation_remaining(self.reservation_id)
        if remaining_after == remaining_before:
            self.budget.skip_reservation_entries(self.reservation_id, 1)
        self.sent += max(
            0,
            self.budget.snapshot()["total_requests"] - total_before,
        )
        self.index += 1
        return result

    def skip_until(self, target_index: int) -> None:
        if target_index < self.index or target_index > self.total_slots:
            raise FreshOmissionDenied("fresh_omission_reservation_skip_is_invalid")
        count = target_index - self.index
        if count:
            self.budget.skip_reservation_entries(self.reservation_id, count)
            self.index = target_index


def _validate_authorization(
    envelope: AuthorizationEnvelope,
    target_origin: str,
) -> None:
    if not envelope.attestation_signature:
        raise FreshOmissionDenied("fresh_omission_authorization_is_unsigned")
    expected = copy.deepcopy(envelope).sign()
    if not hmac.compare_digest(envelope.attestation_signature, expected):
        raise FreshOmissionDenied("fresh_omission_authorization_signature_mismatch")
    try:
        envelope.authorize_action(
            target_origin=target_origin,
            workflow=CONTROLLED_SEQUENCE_WORKFLOW,
        )
        envelope.authorize_action(
            target_origin=target_origin,
            workflow=FRESH_OMISSION_WORKFLOW,
        )
    except Exception as exc:
        raise FreshOmissionDenied("fresh_omission_authorization_denied") from exc


def _remove_query_binding(
    request: EphemeralRehydratedStep,
    binding: LineageBinding,
) -> EphemeralRehydratedStep:
    if binding.consumer_locator.kind != LocatorKind.REQUEST_QUERY:
        raise FreshOmissionDenied("fresh_omission_binding_is_not_query")
    pointer = binding.consumer_locator.pointer
    if not pointer.startswith("/"):
        raise FreshOmissionDenied("fresh_omission_query_pointer_is_invalid")
    tokens = tuple(
        item.replace("~1", "/").replace("~0", "~") for item in pointer[1:].split("/")
    )
    if len(tokens) != 2:
        raise FreshOmissionDenied("fresh_omission_query_pointer_is_invalid")
    key = tokens[0]
    try:
        desired = int(tokens[1])
    except (TypeError, ValueError) as exc:
        raise FreshOmissionDenied("fresh_omission_query_occurrence_is_invalid") from exc
    if desired < 0:
        raise FreshOmissionDenied("fresh_omission_query_occurrence_is_invalid")
    parsed = urlsplit(request.url)
    output = []
    seen = 0
    removed = False
    for current_key, current_value in parse_qsl(
        parsed.query,
        keep_blank_values=True,
    ):
        if current_key == key:
            if seen == desired:
                removed = True
            else:
                output.append((current_key, current_value))
            seen += 1
        else:
            output.append((current_key, current_value))
    if not removed:
        raise FreshOmissionDenied("fresh_omission_query_binding_is_missing")
    url = urlunsplit(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            urlencode(output),
            parsed.fragment,
        )
    )
    return EphemeralRehydratedStep(
        operation_id=request.operation_id,
        source_ref=request.source_ref,
        request_digest=request.request_digest,
        method=request.method,
        url=url,
        headers=copy.deepcopy(dict(request.headers)),
        body=copy.deepcopy(request.body),
    )


def _terminal_evidence(
    *,
    request: EphemeralRehydratedStep,
    status: int,
    response: Any,
) -> _TerminalEvidence:
    truncated = bool(getattr(response, "body_truncated", False))
    exchange = normalize_exchange(
        {
            "method": request.method,
            "url": request.url,
            "response_status": status,
            "response_body": response,
            "response_body_truncated": truncated,
        },
        source_id=request.source_ref,
        world_id="live_fresh_omission",
    )
    return _TerminalEvidence(
        status=int(status),
        body_hash=exchange.response_body_hash,
        success=200 <= int(status) < 300,
        truncated=truncated,
    )


class FreshOmissionBoundaryExecutor:
    """Execute one safe two-object baseline-versus-omission comparison."""

    def __init__(
        self,
        records: Sequence[Mapping[str, Any]],
        *,
        world_id: str,
        target_origin: str,
        authorization: AuthorizationEnvelope,
        actor_persona_id: str,
        executor: PolicyExecutor,
        experiment: MinimizedOmissionExperiment,
        config: Optional[FreshOmissionConfig] = None,
    ) -> None:
        if isinstance(records, (str, bytes)) or any(
            not isinstance(item, Mapping) for item in records
        ):
            raise TypeError("fresh omission records must be mappings")
        if not isinstance(experiment, MinimizedOmissionExperiment):
            raise TypeError("fresh omission experiment contract is required")
        self.records = tuple(records)
        self.world_id = str(world_id)
        self.target_origin = _origin(target_origin)
        self.authorization = authorization
        self.actor_persona_id = str(actor_persona_id)
        self.executor = executor
        self.experiment = experiment
        self.config = config or FreshOmissionConfig.from_environment()
        self._lock = asyncio.Lock()
        self._consumed = False

    def _validate_policy(
        self,
        reserved_actions: Sequence[Tuple[str, str]],
    ) -> None:
        policy = self.executor.policy
        budget = policy.budget
        counts = Counter(endpoint for _action, endpoint in reserved_actions)
        expected_per_endpoint = max(counts.values(), default=0)
        if (
            policy.mode != ProofMode.BOUNTY_SAFE
            or policy.scope_filter is None
            or policy.ownership_registry is None
            or self.executor.provenance is None
            or budget.max_total_requests != len(reserved_actions)
            or budget.max_requests_per_endpoint != expected_per_endpoint
            or budget.max_cross_object_reads != 0
            or budget.max_privilege_mutations != 0
            or budget.max_creates != 2
            or budget.allow_delete
            or budget.allow_real_user_data_access
            or any(budget.snapshot().values())
        ):
            raise FreshOmissionDenied(
                "fresh_omission_requires_exact_unused_bounty_safe_policy"
            )

    def _preflight(self) -> _OmissionPreflight:
        if not self.config.enabled:
            raise FreshOmissionDenied("fresh_omission_execution_is_disabled")
        if not self.world_id or not self.actor_persona_id:
            raise FreshOmissionDenied("fresh_omission_actor_world_is_required")
        if self.world_id != self.actor_persona_id:
            raise FreshOmissionDenied("fresh_omission_actor_world_mismatch")
        if len(self.records) > MAX_STATE_MACHINE_RECORDS:
            raise FreshOmissionDenied("fresh_omission_record_bound_exceeded")
        _validate_authorization(self.authorization, self.target_origin)
        if set(self.experiment.execution_blockers) != _SAFE_EXECUTION_BLOCKERS:
            raise FreshOmissionDenied(
                "fresh_omission_experiment_has_unsafe_execution_blockers"
            )

        lifecycle_result = LifecycleContractMiner().mine(
            self.records,
            world_id=self.world_id,
        )
        state_machine = StateMachineLegalityMiner().mine(
            self.records,
            world_id=self.world_id,
        )
        compiled = MinimizedOmissionCompiler().compile(
            self.records,
            world_id=self.world_id,
            lifecycle=lifecycle_result,
            state_machine=state_machine,
        )
        exact_experiments = tuple(
            item
            for item in compiled.experiments
            if item.experiment_id == self.experiment.experiment_id
            and item == self.experiment
        )
        if len(exact_experiments) != 1:
            raise FreshOmissionDenied("fresh_omission_experiment_does_not_reconstruct")
        lifecycle_matches = tuple(
            item
            for item in lifecycle_result.candidates
            if item.lifecycle_id == self.experiment.lifecycle_id
            and item.world_ref == self.experiment.world_ref
            and self.experiment.terminal_operation_id in item.read_operation_ids
        )
        if len(lifecycle_matches) != 1:
            raise FreshOmissionDenied("fresh_omission_lifecycle_is_not_exact")
        lifecycle = lifecycle_matches[0]

        ledger = ValueLineageLedger(
            self.records,
            world_id=self.world_id,
            catalog_limits=OperationCatalogLimits(
                max_records=MAX_STATE_MACHINE_RECORDS,
            ),
        )
        goals = tuple(
            item
            for item in high_value_goals(ledger.operations)
            if item.terminal_operation_id == self.experiment.terminal_operation_id
        )
        if len(goals) != 1:
            raise FreshOmissionDenied("fresh_omission_terminal_goal_is_not_exact")
        plan = BackwardExploitCompiler(
            ledger.operations,
            limits=CompilerLimits(
                max_search_states=MAX_STATE_MACHINE_SEARCH_STATES,
                max_plan_steps=MAX_STATE_MACHINE_PLAN_STEPS,
            ),
        ).compile(goals[0])
        recipe = PlanRehydrator(ledger).build_recipe(
            plan,
            world_id=self.world_id,
        )
        if (
            plan.status != "planned"
            or plan.plan_id != self.experiment.plan_id
            or plan.step_ids != self.experiment.baseline_operation_ids
            or recipe.status != "ready"
            or recipe.recipe_id != self.experiment.recipe_id
            or tuple(item.operation_id for item in recipe.steps)
            != self.experiment.baseline_operation_ids
            or recipe.world_ref != self.experiment.world_ref
        ):
            raise FreshOmissionDenied("fresh_omission_plan_or_recipe_changed")

        operations = {item.operation_id: item for item in ledger.operations}
        rehydrator = PlanRehydrator(ledger)
        requests = {
            operation_id: rehydrator.rehydrate_step(recipe, operation_id)
            for operation_id in self.experiment.baseline_operation_ids
        }
        create = operations.get(lifecycle.create_operation_id)
        create_request = requests.get(lifecycle.create_operation_id)
        if (
            create is None
            or create_request is None
            or self.experiment.baseline_operation_ids[0]
            != lifecycle.create_operation_id
            or create_request.method != "POST"
            or not is_proven_safe_owned_create_body(create_request.body)
            or classify(
                create_request.method,
                create_request.url,
                classification_body(create_request.body),
                hint=OWNED_CREATE,
            )
            != OWNED_CREATE
        ):
            raise FreshOmissionDenied("fresh_omission_create_contract_is_unsafe")

        for operation_id in self.experiment.baseline_operation_ids[1:]:
            operation = operations.get(operation_id)
            request = requests.get(operation_id)
            if (
                operation is None
                or request is None
                or _origin(request.url) != self.target_origin
                or urlsplit(request.url).fragment
                or operation.safety != OperationSafety.READ_ONLY
                or request.method != "GET"
                or classify(
                    request.method,
                    request.url,
                    classification_body(request.body),
                    hint=SAFE_READ,
                )
                != SAFE_READ
            ):
                raise FreshOmissionDenied(
                    "fresh_omission_prerequisite_or_terminal_is_not_read_only"
                )
        if (
            _origin(create_request.url) != self.target_origin
            or urlsplit(create_request.url).fragment
        ):
            raise FreshOmissionDenied("fresh_omission_create_origin_changed")

        omitted_binding_matches = tuple(
            item
            for item in recipe.bindings
            if item.binding_id == self.experiment.omitted_binding_id
            and item.producer_operation_id
            == self.experiment.omitted_prerequisite_operation_id
            and item.consumer_operation_id == self.experiment.terminal_operation_id
            and item.consumer_locator.kind == LocatorKind.REQUEST_QUERY
            and item.consumer_locator.pointer
            == self.experiment.consumer_locator_pointer
            and item.sensitive
        )
        if len(omitted_binding_matches) != 1:
            raise FreshOmissionDenied("fresh_omission_binding_is_not_exact")

        create_path_bindings: Dict[str, LineageBinding] = {}
        for operation_id in self.experiment.baseline_operation_ids[1:]:
            matches = tuple(
                item
                for item in recipe.bindings
                if item.producer_operation_id == lifecycle.create_operation_id
                and item.consumer_operation_id == operation_id
                and item.consumer_locator.kind == LocatorKind.REQUEST_PATH
            )
            if len(matches) != 1:
                raise FreshOmissionDenied(
                    "fresh_omission_owned_path_lineage_is_not_exact"
                )
            create_path_bindings[operation_id] = matches[0]
        producer_locators = {
            item.producer_locator for item in create_path_bindings.values()
        }
        if len(producer_locators) != 1:
            raise FreshOmissionDenied("fresh_omission_owned_identifier_changed")

        lifecycle_bindings = {
            item.binding_id: item for item in lifecycle_result.ledger.bindings
        }
        cleanup_binding = lifecycle_bindings.get(lifecycle.cleanup_binding_id)
        cleanup_observations = lifecycle_result.ledger.observations_for(
            lifecycle.cleanup_operation_id,
            lifecycle.world_ref,
        )
        if cleanup_binding is None or len(cleanup_observations) != 1:
            raise FreshOmissionDenied("fresh_omission_cleanup_lineage_is_not_exact")
        cleanup_request = lifecycle_result.ledger._rehydrate_observation(
            cleanup_observations[0]
        )
        if (
            cleanup_binding.producer_operation_id != lifecycle.create_operation_id
            or cleanup_binding.producer_locator not in producer_locators
            or cleanup_binding.consumer_locator.kind != LocatorKind.REQUEST_PATH
            or _origin(cleanup_request.url) != self.target_origin
            or urlsplit(cleanup_request.url).fragment
            or cleanup_request.method not in {"PATCH", "PUT"}
            or not is_proven_safe_cleanup_body(cleanup_request.body)
            or classify(
                cleanup_request.method,
                cleanup_request.url,
                classification_body(cleanup_request.body),
                hint=OWNED_UPDATE_LOW_RISK,
            )
            != OWNED_UPDATE_LOW_RISK
        ):
            raise FreshOmissionDenied("fresh_omission_cleanup_contract_is_unsafe")

        bindings = {
            item.binding_id: item for item in (*recipe.bindings, cleanup_binding)
        }
        order = {
            operation_id: index
            for index, operation_id in enumerate(self.experiment.baseline_operation_ids)
        }
        for binding in recipe.bindings:
            producer_index = order.get(binding.producer_operation_id)
            consumer_index = order.get(binding.consumer_operation_id)
            if (
                producer_index is None
                or consumer_index is None
                or producer_index >= consumer_index
            ):
                raise FreshOmissionDenied("fresh_omission_lineage_order_changed")
        if any(
            item.producer_operation_id
            == self.experiment.omitted_prerequisite_operation_id
            and item.binding_id != self.experiment.omitted_binding_id
            for item in recipe.bindings
        ):
            raise FreshOmissionDenied(
                "fresh_omission_skipped_step_has_retained_dependencies"
            )

        baseline_actions = tuple(
            (
                OWNED_CREATE
                if operation_id == lifecycle.create_operation_id
                else SAFE_READ,
                endpoint_key(requests[operation_id].url),
            )
            for operation_id in self.experiment.baseline_operation_ids
        )
        omission_actions = tuple(
            (
                OWNED_CREATE
                if operation_id == lifecycle.create_operation_id
                else SAFE_READ,
                endpoint_key(requests[operation_id].url),
            )
            for operation_id in self.experiment.omission_operation_ids
        )
        cleanup_actions = (
            (OWNED_UPDATE_LOW_RISK, endpoint_key(cleanup_request.url)),
            (OWNED_UPDATE_LOW_RISK, endpoint_key(cleanup_request.url)),
        )
        reserved_actions = (*baseline_actions, *omission_actions, *cleanup_actions)
        self._validate_policy(reserved_actions)

        for action_class, operation_id in (
            *(
                (
                    OWNED_CREATE
                    if item == lifecycle.create_operation_id
                    else SAFE_READ,
                    item,
                )
                for item in self.experiment.baseline_operation_ids
            ),
            *(
                (
                    OWNED_CREATE
                    if item == lifecycle.create_operation_id
                    else SAFE_READ,
                    item,
                )
                for item in self.experiment.omission_operation_ids
            ),
        ):
            request = requests[operation_id]
            decision = self.executor.policy.evaluate_action(
                CandidateAction(
                    method=request.method,
                    url=request.url,
                    body=classification_body(request.body),
                    hint=action_class,
                    actor_persona_id=self.actor_persona_id,
                    expected_side_effect=(
                        "create_owned_test_object"
                        if action_class == OWNED_CREATE
                        else "none"
                    ),
                    proof_goal="fresh_state_prerequisite_omission",
                )
            )
            if not decision.allowed:
                raise FreshOmissionDenied(
                    f"fresh_omission_policy_preflight_denied:{decision.reason}"
                )
        cleanup_decision = self.executor.policy.evaluate_action(
            CandidateAction(
                method=cleanup_request.method,
                url=cleanup_request.url,
                body=classification_body(cleanup_request.body),
                hint=OWNED_UPDATE_LOW_RISK,
                actor_persona_id=self.actor_persona_id,
                target_owner_persona_id=self.actor_persona_id,
                target_is_researcher_owned=True,
                expected_side_effect="cleanup_owned_test_object",
                proof_goal="cleanup_fresh_state_prerequisite_omission",
            )
        )
        if not cleanup_decision.allowed:
            raise FreshOmissionDenied(
                "fresh_omission_cleanup_policy_preflight_denied:"
                f"{cleanup_decision.reason}"
            )

        payload = {
            "mode": FRESH_OMISSION_MODE,
            "experiment_id": self.experiment.experiment_id,
            "lifecycle_id": lifecycle.lifecycle_id,
            "plan_id": plan.plan_id,
            "recipe_id": recipe.recipe_id,
            "capture_digest": recipe.capture_digest,
            "catalog_digest": recipe.catalog_digest,
            "target_ref": stable_hash(
                "fresh_omission_target",
                self.target_origin,
            ),
            "authorization_ref": stable_hash(
                "fresh_omission_authorization",
                {
                    "envelope_id": self.authorization.envelope_id,
                    "signature": self.authorization.attestation_signature,
                },
            ),
            "actor_ref": stable_hash(
                "fresh_omission_actor",
                self.actor_persona_id,
            ),
            "policy_digest": self.executor.policy.digest(),
            "reserved_actions": [
                {
                    "class": action_class,
                    "endpoint_ref": stable_hash(
                        "fresh_omission_endpoint",
                        endpoint,
                    ),
                }
                for action_class, endpoint in reserved_actions
            ],
        }
        return _OmissionPreflight(
            boundary_id=stable_hash("fresh_omission_boundary", payload),
            experiment=self.experiment,
            lifecycle=lifecycle,
            recipe=recipe,
            ledger=ledger,
            requests=requests,
            cleanup_request=cleanup_request,
            cleanup_binding=cleanup_binding,
            bindings=tuple(bindings[key] for key in sorted(bindings)),
            reserved_actions=tuple(reserved_actions),
        )

    def validate_preflight(self) -> str:
        """Return the stable boundary identity without traffic or reservation."""

        return self._preflight().boundary_id

    async def _claim(self, expected_boundary_id: Optional[str]) -> _OmissionPreflight:
        async with self._lock:
            if self._consumed:
                raise FreshOmissionDenied("fresh_omission_executor_already_consumed")
            preflight = self._preflight()
            if (
                expected_boundary_id is not None
                and preflight.boundary_id != expected_boundary_id
            ):
                raise FreshOmissionDenied("fresh_omission_boundary_identity_changed")
            self._consumed = True
            return preflight

    async def _run_leg(
        self,
        preflight: _OmissionPreflight,
        cursor: _ReservationCursor,
        operation_ids: Sequence[str],
        *,
        omit_binding: bool,
        progress: _LegProgress,
        disallowed_object_value: Optional[str] = None,
    ) -> None:
        bindings_by_consumer: Dict[str, list[LineageBinding]] = {}
        bindings_by_producer: Dict[str, list[LineageBinding]] = {}
        for binding in preflight.bindings:
            bindings_by_consumer.setdefault(
                binding.consumer_operation_id,
                [],
            ).append(binding)
            bindings_by_producer.setdefault(
                binding.producer_operation_id,
                [],
            ).append(binding)
        values: Dict[str, Any] = {}
        for operation_id in operation_ids:
            request = preflight.requests[operation_id]
            is_create = operation_id == preflight.lifecycle.create_operation_id
            is_terminal = operation_id == preflight.experiment.terminal_operation_id
            for binding in bindings_by_consumer.get(operation_id, ()):
                if (
                    omit_binding
                    and binding.binding_id == preflight.experiment.omitted_binding_id
                ):
                    request = _remove_query_binding(request, binding)
                    continue
                if binding.binding_id not in values:
                    raise _OmissionAbort(
                        "fresh_omission_dependency_value_is_unavailable",
                        orphan_possible=progress.owned_object is not None,
                    )
                try:
                    request = _apply_binding(
                        request,
                        binding,
                        values[binding.binding_id],
                    )
                except ControlledSequenceDenied as exc:
                    raise _OmissionAbort(
                        "fresh_omission_runtime_binding_failed",
                        orphan_possible=progress.owned_object is not None,
                    ) from exc
            original = preflight.requests[operation_id]
            if endpoint_key(request.url) != endpoint_key(original.url):
                raise _OmissionAbort(
                    "fresh_omission_binding_changed_endpoint",
                    orphan_possible=progress.owned_object is not None,
                )
            if not is_create and progress.owned_object is None:
                raise _OmissionAbort("fresh_omission_owned_object_is_unavailable")
            action_class = OWNED_CREATE if is_create else SAFE_READ
            progress.attempted += 1
            if is_create:
                progress.create_attempted = True
            try:
                status, response = await cursor.send(
                    cursor.index,
                    self.executor,
                    CandidateAction(
                        method=request.method,
                        url=request.url,
                        body=request.body,
                        hint=action_class,
                        actor_persona_id=self.actor_persona_id,
                        target_owner_persona_id=(
                            None if is_create else self.actor_persona_id
                        ),
                        target_is_researcher_owned=(None if is_create else True),
                        expected_side_effect=(
                            "create_owned_test_object" if is_create else "none"
                        ),
                        proof_goal="fresh_state_prerequisite_omission",
                        budget_reservation_id=cursor.reservation_id,
                    ),
                    headers=dict(request.headers),
                )
            except Exception as exc:
                raise _OmissionAbort(
                    "fresh_omission_transport_error",
                    orphan_possible=(progress.owned_object is not None or is_create),
                ) from exc
            if status == DENIED_STATUS:
                raise _OmissionAbort(
                    "fresh_omission_policy_denied",
                    orphan_possible=progress.owned_object is not None,
                )
            if not is_terminal and not 200 <= int(status) < 300:
                raise _OmissionAbort(
                    "fresh_omission_setup_step_returned_non_2xx",
                    orphan_possible=(progress.owned_object is not None or is_create),
                )

            for binding in bindings_by_producer.get(operation_id, ()):
                try:
                    values[binding.binding_id] = _extract_runtime_value(
                        response,
                        binding,
                    )
                except ControlledSequenceDenied as exc:
                    raise _OmissionAbort(
                        "fresh_omission_runtime_value_is_unavailable",
                        orphan_possible=(
                            progress.owned_object is not None or is_create
                        ),
                    ) from exc
            if is_create:
                path_values = {
                    str(values[item.binding_id])
                    for item in bindings_by_producer.get(operation_id, ())
                    if item.consumer_locator.kind == LocatorKind.REQUEST_PATH
                    and item.binding_id in values
                }
                if len(path_values) != 1:
                    raise _OmissionAbort(
                        "fresh_omission_create_identifier_is_ambiguous",
                        orphan_possible=True,
                    )
                value = next(iter(path_values))
                registry = self.executor.policy.ownership_registry
                if (
                    registry is None
                    or registry.register_created_value(
                        request.url,
                        value,
                        actor_persona=self.actor_persona_id,
                    )
                    is None
                ):
                    raise _OmissionAbort(
                        "fresh_omission_ownership_registration_failed",
                        orphan_possible=True,
                    )
                try:
                    cleanup = _apply_binding(
                        preflight.cleanup_request,
                        preflight.cleanup_binding,
                        values[preflight.cleanup_binding.binding_id],
                    )
                except (KeyError, ControlledSequenceDenied) as exc:
                    raise _OmissionAbort(
                        "fresh_omission_cleanup_binding_failed",
                        orphan_possible=True,
                    ) from exc
                if endpoint_key(cleanup.url) != endpoint_key(
                    preflight.cleanup_request.url
                ):
                    raise _OmissionAbort(
                        "fresh_omission_cleanup_endpoint_changed",
                        orphan_possible=True,
                    )
                progress.owned_object = _FreshObject(
                    value=value,
                    cleanup_request=cleanup,
                )
                progress.create_completed = True
                if (
                    disallowed_object_value is not None
                    and hmac.compare_digest(value, disallowed_object_value)
                ):
                    raise _OmissionAbort(
                        "fresh_omission_identifiers_are_not_distinct",
                        orphan_possible=True,
                    )
            if is_terminal:
                progress.terminal_evidence = _terminal_evidence(
                    request=request,
                    status=int(status),
                    response=response,
                )
            progress.completed += 1
        if progress.owned_object is None or progress.terminal_evidence is None:
            raise _OmissionAbort(
                "fresh_omission_leg_did_not_reach_terminal",
                orphan_possible=progress.owned_object is not None,
            )

    async def _cleanup(
        self,
        owned_object: _FreshObject,
        cursor: _ReservationCursor,
    ) -> None:
        request = owned_object.cleanup_request
        registry = self.executor.policy.ownership_registry
        if registry is None or registry.owner_of(request.url) != self.actor_persona_id:
            raise _OmissionAbort(
                "fresh_omission_cleanup_target_is_not_owned",
                orphan_possible=True,
            )
        try:
            status, _response = await cursor.send(
                cursor.index,
                self.executor,
                CandidateAction(
                    method=request.method,
                    url=request.url,
                    body=request.body,
                    hint=OWNED_UPDATE_LOW_RISK,
                    actor_persona_id=self.actor_persona_id,
                    target_owner_persona_id=self.actor_persona_id,
                    target_is_researcher_owned=True,
                    expected_side_effect="cleanup_owned_test_object",
                    proof_goal="cleanup_fresh_state_prerequisite_omission",
                    budget_reservation_id=cursor.reservation_id,
                ),
                headers=dict(request.headers),
            )
        except Exception as exc:
            raise _OmissionAbort(
                "fresh_omission_cleanup_transport_error",
                orphan_possible=True,
            ) from exc
        if status == DENIED_STATUS or not 200 <= int(status) < 300:
            raise _OmissionAbort(
                "fresh_omission_cleanup_failed",
                orphan_possible=True,
            )

    async def execute(
        self,
        *,
        expected_boundary_id: Optional[str] = None,
    ) -> FreshOmissionBoundaryResult:
        preflight = await self._claim(expected_boundary_id)
        budget = self.executor.policy.budget
        reservation_id, reason = budget.try_reserve(preflight.reserved_actions)
        if reservation_id is None:
            raise FreshOmissionDenied(
                f"fresh_omission_budget_reservation_denied:{reason}"
            )
        cursor = _ReservationCursor(
            budget,
            reservation_id,
            total_slots=len(preflight.reserved_actions),
        )
        cleanup_start = len(preflight.experiment.baseline_operation_ids) + len(
            preflight.experiment.omission_operation_ids
        )
        baseline = _LegProgress()
        omission = _LegProgress()
        cleanup_attempted = 0
        cleanup_completed = 0
        orphan_possible = False
        error_code = None
        comparison_status = "not_completed"
        try:
            try:
                await self._run_leg(
                    preflight,
                    cursor,
                    preflight.experiment.baseline_operation_ids,
                    omit_binding=False,
                    progress=baseline,
                )
                baseline_evidence = baseline.terminal_evidence
                assert baseline_evidence is not None
                reference = preflight.experiment.oracle
                if (
                    baseline_evidence.status != reference.reference_response_status
                    or baseline_evidence.body_hash
                    != reference.reference_response_body_hash
                    or baseline_evidence.truncated
                    or not baseline_evidence.success
                ):
                    raise _OmissionAbort(
                        "fresh_omission_baseline_reference_mismatch",
                        orphan_possible=True,
                    )

                await self._run_leg(
                    preflight,
                    cursor,
                    preflight.experiment.omission_operation_ids,
                    omit_binding=True,
                    progress=omission,
                    disallowed_object_value=(
                        baseline.owned_object.value
                        if baseline.owned_object is not None
                        else None
                    ),
                )
                omission_evidence = omission.terminal_evidence
                assert omission_evidence is not None
                if omission_evidence.truncated:
                    comparison_status = "inconclusive_truncated"
                elif not omission_evidence.success:
                    comparison_status = "omission_rejected"
                elif omission_evidence.body_hash == baseline_evidence.body_hash:
                    comparison_status = "exact_match"
                else:
                    comparison_status = "response_mismatch"
            except _OmissionAbort as exc:
                error_code = exc.code
                orphan_possible = orphan_possible or exc.orphan_possible
            except Exception:
                error_code = "fresh_omission_unexpected_execution_error"
                orphan_possible = (
                    baseline.owned_object is not None
                    or omission.owned_object is not None
                )
        finally:
            try:
                cursor.skip_until(cleanup_start)
                cleaned_values = set()
                for owned_object in (
                    omission.owned_object,
                    baseline.owned_object,
                ):
                    if owned_object is None:
                        cursor.skip_until(cursor.index + 1)
                        continue
                    if owned_object.value in cleaned_values:
                        cursor.skip_until(cursor.index + 1)
                        continue
                    cleaned_values.add(owned_object.value)
                    cleanup_attempted += 1
                    try:
                        await self._cleanup(owned_object, cursor)
                    except _OmissionAbort:
                        orphan_possible = True
                    else:
                        cleanup_completed += 1
            finally:
                budget.release_reservation(reservation_id)

        creates_attempted = int(baseline.create_attempted) + int(
            omission.create_attempted
        )
        creates_completed = int(baseline.create_completed) + int(
            omission.create_completed
        )
        unique_created_values = {
            item.value
            for item in (baseline.owned_object, omission.owned_object)
            if item is not None
        }
        orphan_possible = (
            creates_attempted > creates_completed
            or cleanup_completed < len(unique_created_values)
        )
        cleanup_failed = cleanup_attempted != cleanup_completed
        if cleanup_failed:
            status = "cleanup_failed"
            error_code = "fresh_omission_cleanup_failed"
        elif (
            baseline.terminal_evidence is not None
            and omission.terminal_evidence is not None
            and comparison_status != "not_completed"
            and error_code is None
        ):
            status = "completed"
        else:
            status = "aborted"
            error_code = error_code or "fresh_omission_execution_aborted"
        baseline_reference_match = bool(
            baseline.terminal_evidence is not None
            and baseline.terminal_evidence.status
            == preflight.experiment.oracle.reference_response_status
            and baseline.terminal_evidence.body_hash
            == preflight.experiment.oracle.reference_response_body_hash
            and not baseline.terminal_evidence.truncated
            and baseline.terminal_evidence.success
        )
        body_match = bool(
            baseline.terminal_evidence is not None
            and omission.terminal_evidence is not None
            and baseline.terminal_evidence.body_hash is not None
            and baseline.terminal_evidence.body_hash
            == omission.terminal_evidence.body_hash
        )
        sink = self.executor.provenance
        restraint = self.executor.restraint_summary()
        restraint["fresh_owned_objects_created"] = creates_completed
        restraint["fresh_owned_objects_cleaned"] = cleanup_completed
        restraint["omitted_prerequisites"] = (
            1 if omission.terminal_evidence is not None else 0
        )
        restraint["finding_authority"] = False
        return FreshOmissionBoundaryResult(
            boundary_id=preflight.boundary_id,
            experiment_id=preflight.experiment.experiment_id,
            lifecycle_id=preflight.lifecycle.lifecycle_id,
            terminal_operation_id=preflight.experiment.terminal_operation_id,
            status=status,
            comparison_status=comparison_status,
            baseline_reference_match=baseline_reference_match,
            baseline_terminal_success=bool(
                baseline.terminal_evidence and baseline.terminal_evidence.success
            ),
            omission_terminal_success=bool(
                omission.terminal_evidence and omission.terminal_evidence.success
            ),
            baseline_terminal_truncated=bool(
                baseline.terminal_evidence and baseline.terminal_evidence.truncated
            ),
            omission_terminal_truncated=bool(
                omission.terminal_evidence and omission.terminal_evidence.truncated
            ),
            terminal_body_match=body_match,
            requests_attempted=cursor.attempted,
            requests_sent=cursor.sent,
            baseline_steps_attempted=baseline.attempted,
            baseline_steps_completed=baseline.completed,
            omission_steps_attempted=omission.attempted,
            omission_steps_completed=omission.completed,
            creates_attempted=creates_attempted,
            creates_completed=creates_completed,
            cleanup_steps_attempted=cleanup_attempted,
            cleanup_steps_completed=cleanup_completed,
            policy_denials=len(self.executor.skipped),
            orphaned_owned_state_possible=orphan_possible,
            provenance_root=(sink.root() if sink is not None else "") or "",
            budget_snapshot=budget.snapshot(),
            restraint=restraint,
            provenance=(sink.summary() if sink is not None else {}),
            error_code=error_code,
        )


@dataclass(frozen=True)
class FreshOmissionAdmissionResult:
    status: str
    receipt_id: str
    reused: bool
    execution: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "receipt": {
                "receipt_id": self.receipt_id,
                "state": COMPLETED,
                "reused": self.reused,
            },
            "execution": copy.deepcopy(self.execution),
        }


class FreshOmissionAdmission:
    """Reserve durable identity before one fresh omission boundary can run."""

    def __init__(
        self,
        boundary: FreshOmissionBoundaryExecutor,
        *,
        receipt_store: Optional[BehavioralReceiptStore] = None,
    ) -> None:
        if not isinstance(boundary, FreshOmissionBoundaryExecutor):
            raise TypeError("fresh omission boundary executor is required")
        self.boundary = boundary
        self.receipt_store = receipt_store or BehavioralReceiptStore()

    def _context(self) -> BehavioralReceiptContext:
        boundary = self.boundary
        return redacted_receipt_context(
            target_origin=boundary.target_origin,
            envelope_id=boundary.authorization.envelope_id,
            source_persona_id=boundary.actor_persona_id,
            peer_persona_id=boundary.actor_persona_id,
        )

    def _descriptor(self, boundary_id: str) -> Dict[str, Any]:
        boundary = self.boundary
        experiment = boundary.experiment
        return {
            "schema_version": 1,
            "mode": FRESH_OMISSION_MODE,
            "boundary_id": boundary_id,
            "experiment_id": experiment.experiment_id,
            "lifecycle_id": experiment.lifecycle_id,
            "plan_id": experiment.plan_id,
            "recipe_id": experiment.recipe_id,
            "world_ref": experiment.world_ref,
            "target_origin": boundary.target_origin,
            "envelope_id": boundary.authorization.envelope_id,
            "authorization_signature": (boundary.authorization.attestation_signature),
            "actor_persona_id": boundary.actor_persona_id,
            "policy_digest": boundary.executor.policy.digest(),
        }

    def _identity(self) -> Tuple[str, str]:
        boundary_id = self.boundary.validate_preflight()
        try:
            fingerprint = request_fingerprint(self._descriptor(boundary_id))
        except (TypeError, ValueError) as exc:
            raise FreshOmissionDenied(
                "fresh_omission_admission_is_not_deterministic"
            ) from exc
        return boundary_id, fingerprint

    def validate_preflight(self) -> str:
        _boundary_id, fingerprint = self._identity()
        return fingerprint

    @staticmethod
    def _cached_result(
        receipt_id: str,
        outcome: Mapping[str, Any],
    ) -> FreshOmissionAdmissionResult:
        if outcome.get("kind") != "fresh_omission_boundary":
            raise FreshOmissionDenied("fresh_omission_receipt_kind_mismatch")
        return FreshOmissionAdmissionResult(
            status="already_executed",
            receipt_id=receipt_id,
            reused=True,
            execution=copy.deepcopy(dict(outcome)),
        )

    async def execute(self) -> FreshOmissionAdmissionResult:
        boundary_id, fingerprint = self._identity()
        context = self._context()
        try:
            reservation = self.receipt_store.reserve(
                fingerprint,
                context=context,
            )
        except (OSError, ReceiptStoreError) as exc:
            raise FreshOmissionDenied(
                "fresh_omission_receipt_store_unavailable"
            ) from exc
        if not reservation.created:
            if reservation.receipt.context != context:
                raise FreshOmissionDenied("fresh_omission_receipt_context_mismatch")
            if (
                reservation.receipt.state == COMPLETED
                and reservation.receipt.outcome is not None
            ):
                return self._cached_result(
                    reservation.receipt.receipt_id,
                    reservation.receipt.outcome,
                )
            raise FreshOmissionDenied("fresh_omission_is_already_reserved_or_terminal")
        token = reservation.reservation_token
        if token is None:
            raise FreshOmissionDenied("fresh_omission_reservation_token_is_unavailable")
        try:
            result = await self.boundary.execute(
                expected_boundary_id=boundary_id,
            )
        except Exception:
            try:
                self.receipt_store.abort(
                    fingerprint,
                    reservation_token=token,
                    reason="fresh_omission_execution_error",
                )
            except (OSError, ReceiptStoreError) as receipt_exc:
                raise FreshOmissionDenied(
                    "fresh_omission_failed_and_receipt_could_not_finalize"
                ) from receipt_exc
            raise
        outcome = redacted_fresh_omission_outcome(result.to_dict())
        try:
            completed = self.receipt_store.complete(
                fingerprint,
                reservation_token=token,
                outcome=outcome,
            )
        except (OSError, ReceiptStoreError) as exc:
            raise FreshOmissionDenied(
                "fresh_omission_completed_but_receipt_could_not_finalize"
            ) from exc
        if completed.outcome is None:
            raise FreshOmissionDenied("fresh_omission_receipt_outcome_is_missing")
        return FreshOmissionAdmissionResult(
            status=result.status,
            receipt_id=completed.receipt_id,
            reused=False,
            execution=copy.deepcopy(completed.outcome),
        )


__all__ = [
    "FRESH_OMISSION_ENV",
    "FRESH_OMISSION_MODE",
    "FRESH_OMISSION_WORKFLOW",
    "FreshOmissionAdmission",
    "FreshOmissionAdmissionResult",
    "FreshOmissionBoundaryExecutor",
    "FreshOmissionBoundaryResult",
    "FreshOmissionConfig",
    "FreshOmissionDenied",
]
