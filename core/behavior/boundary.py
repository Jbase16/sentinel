"""Atomic fresh-owned-state authorization proof over two research personas.

This coordinator consumes two symmetric, proof-carrying owned lifecycle bundles.
It creates one fresh object per persona, delegates the three read legs to the
established BOLA oracle, and then executes both proven cleanup operations. Every
request crosses the existing policy seam under one pre-reserved budget.
"""

from __future__ import annotations

import asyncio
import json
import os
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Tuple

from core.cortex.execution_policy import DENIED_STATUS, CandidateAction, PolicyExecutor
from core.foundry.vault import ResearchPersona
from core.safety.action_classifier import (
    CROSS_OBJECT_READ,
    OWNED_CREATE,
    OWNED_UPDATE_LOW_RISK,
    SAFE_READ,
)
from core.safety.proof_budget import ProofBudget, endpoint_key
from core.safety.proof_mode import ProofMode
from core.wraith import bola_replay

from .active import AUTHORITATIVE_ENGINE, validate_controlled_capture_context
from .admission import COMPILED_ADMISSION_ENV
from .factory import OwnedExperimentInventory, PreparedOwnedExperiment
from .lineage import EphemeralRehydratedStep, LineageBinding, LocatorKind
from .normalize import stable_hash
from .runtime import (
    ControlledRuntimeSequenceExecutor,
    ControlledSequenceDenied,
    _CleanupStep,
    _Preflight,
    _RuntimeStep,
    _apply_binding,
    _extract_runtime_value,
)
from .scheduler import PRIMARY_ENV

FRESH_OWNED_BOUNDARY_MODE = "behavioral_fresh_owned_boundary_v1"
_TRUE = frozenset({"1", "true", "yes", "on"})
_EXPECTED_BUDGET = {
    "max_total_requests": 7,
    "max_requests_per_endpoint": 5,
    "max_cross_object_reads": 1,
    "max_privilege_mutations": 0,
    "max_creates": 2,
}


def _hash_ref(value: Any, prefix: str) -> bool:
    if not isinstance(value, str) or not value.startswith(f"{prefix}:"):
        return False
    digest = value[len(prefix) + 1 :]
    return len(digest) == 64 and all(
        character in "0123456789abcdef" for character in digest
    )


class FreshOwnedBoundaryDenied(RuntimeError):
    """The paired owned lifecycle cannot enter the fresh boundary oracle."""


class _BoundaryAbort(RuntimeError):
    def __init__(self, code: str, *, orphan_possible: bool = False) -> None:
        super().__init__(code)
        self.code = code
        self.orphan_possible = orphan_possible


@dataclass(frozen=True)
class FreshOwnedBoundaryConfig:
    enabled: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.enabled, bool):
            raise ValueError("fresh owned boundary enabled must be a boolean")

    @classmethod
    def from_environment(cls) -> "FreshOwnedBoundaryConfig":
        primary = os.environ.get(PRIMARY_ENV, "").strip().lower() in _TRUE
        compiled = (
            os.environ.get(COMPILED_ADMISSION_ENV, "").strip().lower() in _TRUE
        )
        return cls(enabled=primary and compiled)


@dataclass(frozen=True)
class FreshOwnedBoundaryResult:
    boundary_id: str
    experiment_id: str
    lifecycle_id: str
    terminal_operation_id: str
    peer_experiment_id: str
    legacy_verdict: bola_replay.OpVerdict = field(repr=False, compare=False)
    requests_attempted: int
    requests_sent: int
    creates_attempted: int
    creates_completed: int
    proof_legs_attempted: int
    proof_legs_sent: int
    cleanup_steps_attempted: int
    cleanup_steps_completed: int
    policy_denials: int
    orphaned_owned_state_possible: bool
    provenance_root: str
    budget_snapshot: Dict[str, int]
    restraint: Dict[str, Any]
    provenance: Dict[str, Any]
    status: str = "completed"
    error_code: Optional[str] = None
    mode: str = FRESH_OWNED_BOUNDARY_MODE
    authoritative_engine: str = AUTHORITATIVE_ENGINE

    def __post_init__(self) -> None:
        counters = (
            self.requests_attempted,
            self.requests_sent,
            self.creates_attempted,
            self.creates_completed,
            self.proof_legs_attempted,
            self.proof_legs_sent,
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
        budget_valid = (
            isinstance(self.budget_snapshot, dict)
            and set(self.budget_snapshot) == budget_keys
            and all(
                not isinstance(value, bool)
                and isinstance(value, int)
                and value >= 0
                for value in self.budget_snapshot.values()
            )
        )
        if (
            self.mode != FRESH_OWNED_BOUNDARY_MODE
            or self.authoritative_engine != AUTHORITATIVE_ENGINE
            or not _hash_ref(self.boundary_id, "fresh_owned_boundary")
            or not _hash_ref(self.experiment_id, "owned_experiment")
            or not _hash_ref(self.peer_experiment_id, "owned_experiment")
            or not _hash_ref(self.lifecycle_id, "owned_lifecycle")
            or not _hash_ref(self.terminal_operation_id, "action")
            or not isinstance(self.legacy_verdict, bola_replay.OpVerdict)
            or any(
                isinstance(value, bool) or not isinstance(value, int) or value < 0
                for value in counters
            )
            or self.requests_sent > self.requests_attempted
            or self.requests_attempted
            != self.creates_attempted
            + self.proof_legs_attempted
            + self.cleanup_steps_attempted
            or self.creates_completed > self.creates_attempted
            or self.creates_attempted > 2
            or self.proof_legs_sent > self.proof_legs_attempted
            or self.proof_legs_attempted > 3
            or self.cleanup_steps_completed > self.cleanup_steps_attempted
            or self.cleanup_steps_attempted > 2
            or self.status not in {"completed", "aborted", "cleanup_failed"}
            or (self.status == "completed" and self.error_code is not None)
            or (self.status != "completed" and self.error_code is None)
            or (
                self.status == "completed"
                and (
                    self.creates_completed != 2
                    or self.cleanup_steps_completed != 2
                    or self.orphaned_owned_state_possible
                )
            )
            or (
                self.status == "cleanup_failed"
                and (
                    self.error_code != "fresh_boundary_cleanup_failed"
                    or not self.orphaned_owned_state_possible
                    or self.cleanup_steps_completed == self.cleanup_steps_attempted
                )
            )
            or (self.legacy_verdict.verdict == "BOLA_CONFIRMED")
            != (self.legacy_verdict.finding is not None)
            or not isinstance(self.orphaned_owned_state_possible, bool)
            or not isinstance(self.provenance_root, str)
            or len(self.provenance_root) != 64
            or any(
                character not in "0123456789abcdef"
                for character in self.provenance_root
            )
            or not isinstance(self.restraint, dict)
            or not isinstance(self.provenance, dict)
            or not budget_valid
            or self.budget_snapshot["total_requests"] != self.requests_sent
            or self.budget_snapshot["cross_object_reads"] > 1
            or self.budget_snapshot["privilege_mutations"] != 0
            or self.budget_snapshot["creates"] > 2
            or self.budget_snapshot["endpoints_touched"]
            > self.budget_snapshot["total_requests"]
        ):
            raise ValueError("fresh owned boundary result is invalid")

    @property
    def finding(self) -> Any:
        return self.legacy_verdict.finding

    def to_dict(self) -> Dict[str, Any]:
        return {
            "kind": "fresh_owned_boundary",
            "mode": self.mode,
            "boundary_id": self.boundary_id,
            "experiment_id": self.experiment_id,
            "lifecycle_id": self.lifecycle_id,
            "terminal_operation_id": self.terminal_operation_id,
            "peer_experiment_id": self.peer_experiment_id,
            "status": self.status,
            "authoritative_engine": self.authoritative_engine,
            "legacy_verdict": self.legacy_verdict.verdict,
            "legacy_detail": self.legacy_verdict.detail,
            "finding_confirmed": self.finding is not None,
            "requests_attempted": self.requests_attempted,
            "requests_sent": self.requests_sent,
            "creates_attempted": self.creates_attempted,
            "creates_completed": self.creates_completed,
            "proof_legs_attempted": self.proof_legs_attempted,
            "proof_legs_sent": self.proof_legs_sent,
            "cleanup_steps_attempted": self.cleanup_steps_attempted,
            "cleanup_steps_completed": self.cleanup_steps_completed,
            "policy_denials": self.policy_denials,
            "orphaned_owned_state_possible": self.orphaned_owned_state_possible,
            "provenance_root": self.provenance_root,
            "budget_snapshot": dict(self.budget_snapshot),
            "error_code": self.error_code,
            "restraint": dict(self.restraint),
            "provenance": dict(self.provenance),
        }


@dataclass(frozen=True)
class _LifecycleContract:
    experiment: PreparedOwnedExperiment
    runtime: ControlledRuntimeSequenceExecutor = field(repr=False, compare=False)
    preflight: _Preflight = field(repr=False, compare=False)
    create: _RuntimeStep = field(repr=False, compare=False)
    read: _RuntimeStep = field(repr=False, compare=False)
    cleanup: _CleanupStep = field(repr=False, compare=False)
    read_binding: LineageBinding = field(repr=False, compare=False)


@dataclass(frozen=True)
class _BoundaryPair:
    boundary_id: str
    source: _LifecycleContract
    peer: _LifecycleContract


@dataclass(frozen=True)
class _FreshObject:
    value: str = field(repr=False)
    read_request: EphemeralRehydratedStep = field(repr=False)
    cleanup_request: EphemeralRehydratedStep = field(repr=False)


class _ReservationCursor:
    def __init__(self, budget: ProofBudget, reservation_id: str) -> None:
        self.budget = budget
        self.reservation_id = reservation_id
        self.index = 0
        self.attempted = 0
        self.sent = 0

    async def send(
        self,
        expected_index: int,
        executor: PolicyExecutor,
        action: CandidateAction,
        *,
        headers: Dict[str, str],
    ) -> Tuple[int, Any]:
        if expected_index != self.index:
            raise FreshOwnedBoundaryDenied("fresh_boundary_reservation_order_changed")
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
        if target_index < self.index or target_index > 7:
            raise FreshOwnedBoundaryDenied("fresh_boundary_reservation_skip_is_invalid")
        count = target_index - self.index
        if count:
            self.budget.skip_reservation_entries(self.reservation_id, count)
            self.index = target_index


def _response_body(value: Any) -> str:
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, sort_keys=True)
    except (TypeError, ValueError):
        return str(value)


def _manifest_shape(experiment: PreparedOwnedExperiment) -> Tuple[Any, ...]:
    manifest = experiment.bundle.manifest
    return (
        manifest.terminal_operation_id,
        tuple(
            (step.operation_id, step.role, step.hint, step.expected_side_effect)
            for step in manifest.steps
        ),
    )


def _lifecycle_contract(
    experiment: PreparedOwnedExperiment,
    preflight: _Preflight,
) -> _LifecycleContract:
    main = preflight.main_steps
    cleanup = preflight.cleanup_steps
    if (
        len(main) != 2
        or len(cleanup) != 1
        or main[0].intent.hint != OWNED_CREATE
        or main[1].intent.hint != SAFE_READ
        or cleanup[0].step.intent.hint != OWNED_UPDATE_LOW_RISK
        or main[1].operation.operation_id != experiment.terminal_operation_id
        or cleanup[0].create_operation_id != main[0].operation.operation_id
    ):
        raise FreshOwnedBoundaryDenied("fresh_boundary_lifecycle_shape_is_unsupported")
    read_bindings = tuple(
        binding
        for binding in preflight.all_bindings
        if binding.producer_operation_id == main[0].operation.operation_id
        and binding.consumer_operation_id == main[1].operation.operation_id
        and binding.consumer_locator.kind == LocatorKind.REQUEST_PATH
    )
    if len(read_bindings) != 1:
        raise FreshOwnedBoundaryDenied(
            "fresh_boundary_read_lineage_is_missing_or_ambiguous"
        )
    read_binding = read_bindings[0]
    if (
        cleanup[0].binding.producer_operation_id
        != main[0].operation.operation_id
        or cleanup[0].binding.producer_locator != read_binding.producer_locator
    ):
        raise FreshOwnedBoundaryDenied("fresh_boundary_cleanup_lineage_changed")
    return _LifecycleContract(
        experiment=experiment,
        runtime=experiment.bundle.runtime,
        preflight=preflight,
        create=main[0],
        read=main[1],
        cleanup=cleanup[0],
        read_binding=read_binding,
    )


class _FreshBoundaryReplayTransport:
    def __init__(
        self,
        *,
        cursor: _ReservationCursor,
        source: _LifecycleContract,
        peer: _LifecycleContract,
        source_object: _FreshObject,
        peer_object: _FreshObject,
    ) -> None:
        self.cursor = cursor
        self.source = source
        self.peer = peer
        self.source_object = source_object
        self.peer_object = peer_object
        self.attempted = 0
        self.sent = 0

    async def send(
        self,
        persona: str,
        request: bola_replay.ReplayRequest,
    ) -> bola_replay.ReplayResponse:
        sequence = (
            (
                self.source.runtime,
                self.source_object,
                self.source.runtime.actor_persona_id,
                self.source.runtime.actor_persona_id,
                SAFE_READ,
            ),
            (
                self.peer.runtime,
                self.peer_object,
                self.peer.runtime.actor_persona_id,
                self.peer.runtime.actor_persona_id,
                SAFE_READ,
            ),
            (
                self.peer.runtime,
                self.source_object,
                self.peer.runtime.actor_persona_id,
                self.source.runtime.actor_persona_id,
                CROSS_OBJECT_READ,
            ),
        )
        if self.attempted >= len(sequence):
            raise _BoundaryAbort("fresh_boundary_proof_leg_budget_exceeded")
        runtime, owned_object, expected_persona, owner_persona, hint = sequence[
            self.attempted
        ]
        if (
            persona != expected_persona
            or request.method.upper() != "GET"
            or request.url != owned_object.read_request.url
        ):
            raise _BoundaryAbort("fresh_boundary_oracle_request_changed")
        self.attempted += 1
        sent_before = self.cursor.sent
        try:
            status, response = await self.cursor.send(
                self.attempted + 1,
                runtime.executor,
                CandidateAction(
                    method=request.method,
                    url=request.url,
                    body=request.body,
                    hint=hint,
                    actor_persona_id=expected_persona,
                    target_owner_persona_id=owner_persona,
                    target_is_researcher_owned=True,
                    expected_side_effect="none",
                    proof_goal="fresh_owned_authorization_boundary",
                    budget_reservation_id=self.cursor.reservation_id,
                ),
                headers=dict(request.headers),
            )
        except _BoundaryAbort:
            raise
        except Exception as exc:
            raise _BoundaryAbort("fresh_boundary_proof_transport_error") from exc
        self.sent += self.cursor.sent - sent_before
        replay = bola_replay.ReplayResponse(
            status=int(status),
            body=_response_body(response),
            body_truncated=bool(getattr(response, "body_truncated", False)),
        )
        if hint == SAFE_READ and (
            status == DENIED_STATUS
            or not 200 <= int(status) < 300
            or bola_replay.is_denied_response(replay)
        ):
            raise _BoundaryAbort("fresh_boundary_baseline_is_not_usable")
        if hint == CROSS_OBJECT_READ and status == DENIED_STATUS:
            raise _BoundaryAbort("fresh_boundary_cross_probe_policy_denied")
        return replay


class FreshOwnedBoundaryExecutor:
    """Execute one exact symmetric owned lifecycle through the BOLA oracle."""

    def __init__(
        self,
        *,
        source_inventory: OwnedExperimentInventory,
        peer_inventory: OwnedExperimentInventory,
        source_persona: ResearchPersona,
        peer_persona: ResearchPersona,
        config: Optional[FreshOwnedBoundaryConfig] = None,
    ) -> None:
        if not isinstance(source_inventory, OwnedExperimentInventory) or not isinstance(
            peer_inventory,
            OwnedExperimentInventory,
        ):
            raise TypeError("fresh boundary requires owned experiment inventories")
        self.source_inventory = source_inventory
        self.peer_inventory = peer_inventory
        self.source_persona = source_persona
        self.peer_persona = peer_persona
        self.config = config or FreshOwnedBoundaryConfig.from_environment()
        self._lock = asyncio.Lock()
        self._consumed = False

    @staticmethod
    def _validate_budget(budget: ProofBudget) -> None:
        actual = {key: getattr(budget, key) for key in _EXPECTED_BUDGET}
        if (
            actual != _EXPECTED_BUDGET
            or budget.allow_delete
            or budget.allow_real_user_data_access
        ):
            raise FreshOwnedBoundaryDenied(
                "fresh_boundary_requires_exact_bounty_safe_budget"
            )

    def _pair(self, experiment_id: str) -> _BoundaryPair:
        if not self.config.enabled:
            raise FreshOwnedBoundaryDenied("fresh_owned_boundary_is_disabled")
        source_matches = tuple(
            item
            for item in self.source_inventory.experiments
            if item.experiment_id == experiment_id
        )
        if len(source_matches) != 1:
            raise FreshOwnedBoundaryDenied(
                "fresh_boundary_source_experiment_is_not_exact"
            )
        source_experiment = source_matches[0]
        shape = _manifest_shape(source_experiment)
        peer_matches = tuple(
            item
            for item in self.peer_inventory.experiments
            if _manifest_shape(item) == shape
        )
        if len(peer_matches) != 1:
            raise FreshOwnedBoundaryDenied(
                "fresh_boundary_peer_experiment_is_missing_or_ambiguous"
            )
        peer_experiment = peer_matches[0]
        source_runtime = source_experiment.bundle.runtime
        peer_runtime = peer_experiment.bundle.runtime
        validate_controlled_capture_context(
            target_origin=source_runtime.target_origin,
            authorization=source_runtime.authorization,
            source_persona=self.source_persona,
            peer_persona=self.peer_persona,
        )
        if (
            source_runtime.actor_persona_id != self.source_persona.persona_id
            or peer_runtime.actor_persona_id != self.peer_persona.persona_id
            or source_runtime.target_origin != peer_runtime.target_origin
            or source_runtime.authorization.envelope_id
            != peer_runtime.authorization.envelope_id
            or source_runtime.authorization.attestation_signature
            != peer_runtime.authorization.attestation_signature
            or source_runtime.executor.policy is not peer_runtime.executor.policy
            or source_runtime.executor.provenance is None
            or source_runtime.executor.provenance
            is not peer_runtime.executor.provenance
            or source_runtime.executor.policy.mode != ProofMode.BOUNTY_SAFE
            or source_runtime.executor.policy.ownership_registry is None
        ):
            raise FreshOwnedBoundaryDenied(
                "fresh_boundary_execution_context_is_not_shared"
            )
        self._validate_budget(source_runtime.executor.policy.budget)
        source_preflight = source_runtime._preflight()
        peer_preflight = peer_runtime._preflight()
        source = _lifecycle_contract(source_experiment, source_preflight)
        peer = _lifecycle_contract(peer_experiment, peer_preflight)
        if (
            tuple(step.operation_id for step in source_experiment.bundle.manifest.steps)
            != tuple(step.operation_id for step in peer_experiment.bundle.manifest.steps)
            or endpoint_key(source.create.request.url)
            != endpoint_key(peer.create.request.url)
            or endpoint_key(source.read.request.url)
            != endpoint_key(peer.read.request.url)
            or endpoint_key(source.cleanup.step.request.url)
            != endpoint_key(peer.cleanup.step.request.url)
        ):
            raise FreshOwnedBoundaryDenied("fresh_boundary_lifecycle_pair_changed")
        payload = {
            "mode": FRESH_OWNED_BOUNDARY_MODE,
            "source_experiment_id": source_experiment.experiment_id,
            "peer_experiment_id": peer_experiment.experiment_id,
            "source_sequence_id": source_preflight.sequence_id,
            "peer_sequence_id": peer_preflight.sequence_id,
            "target_ref": source_experiment.bundle.manifest.target_ref,
            "authorization_ref": source_experiment.bundle.manifest.authorization_ref,
            "policy_digest": source_runtime.executor.policy.digest(),
        }
        return _BoundaryPair(
            boundary_id=stable_hash("fresh_owned_boundary", payload),
            source=source,
            peer=peer,
        )

    def supported_experiment_ids(self) -> Tuple[str, ...]:
        if not self.config.enabled:
            return ()
        supported = []
        for experiment in self.source_inventory.experiments:
            try:
                self._pair(experiment.experiment_id)
            except FreshOwnedBoundaryDenied:
                continue
            supported.append(experiment.experiment_id)
        return tuple(sorted(supported))

    def validate_preflight(self, experiment_id: str) -> str:
        return self._pair(experiment_id).boundary_id

    @staticmethod
    async def _create_object(
        lifecycle: _LifecycleContract,
        cursor: _ReservationCursor,
        index: int,
    ) -> _FreshObject:
        runtime = lifecycle.runtime
        request = lifecycle.create.request
        try:
            status, response = await cursor.send(
                index,
                runtime.executor,
                CandidateAction(
                    method=request.method,
                    url=request.url,
                    body=request.body,
                    hint=OWNED_CREATE,
                    actor_persona_id=runtime.actor_persona_id,
                    expected_side_effect="create_owned_test_object",
                    proof_goal="fresh_owned_authorization_boundary",
                    budget_reservation_id=cursor.reservation_id,
                ),
                headers=dict(request.headers),
            )
        except Exception as exc:
            raise _BoundaryAbort(
                "fresh_boundary_create_transport_error",
                orphan_possible=True,
            ) from exc
        if status == DENIED_STATUS:
            raise _BoundaryAbort("fresh_boundary_create_policy_denied")
        if not 200 <= int(status) < 300:
            raise _BoundaryAbort(
                "fresh_boundary_create_returned_non_2xx",
                orphan_possible=True,
            )
        try:
            value = _extract_runtime_value(response, lifecycle.read_binding)
        except ControlledSequenceDenied as exc:
            raise _BoundaryAbort(
                "fresh_boundary_create_identifier_is_unavailable",
                orphan_possible=True,
            ) from exc
        registry = runtime.executor.policy.ownership_registry
        if registry is None or registry.register_created_value(
            request.url,
            value,
            actor_persona=runtime.actor_persona_id,
        ) is None:
            raise _BoundaryAbort(
                "fresh_boundary_ownership_registration_failed",
                orphan_possible=True,
            )
        read_request = _apply_binding(
            lifecycle.read.request,
            lifecycle.read_binding,
            value,
        )
        cleanup_request = _apply_binding(
            lifecycle.cleanup.step.request,
            lifecycle.cleanup.binding,
            value,
        )
        if (
            endpoint_key(read_request.url) != endpoint_key(lifecycle.read.request.url)
            or endpoint_key(cleanup_request.url)
            != endpoint_key(lifecycle.cleanup.step.request.url)
            or registry.owner_of(read_request.url) != runtime.actor_persona_id
        ):
            raise _BoundaryAbort(
                "fresh_boundary_runtime_binding_changed",
                orphan_possible=True,
            )
        return _FreshObject(str(value), read_request, cleanup_request)

    @staticmethod
    async def _cleanup_object(
        lifecycle: _LifecycleContract,
        owned_object: _FreshObject,
        cursor: _ReservationCursor,
        index: int,
    ) -> None:
        runtime = lifecycle.runtime
        request = owned_object.cleanup_request
        registry = runtime.executor.policy.ownership_registry
        if registry is None or registry.owner_of(request.url) != runtime.actor_persona_id:
            cursor.skip_until(index + 1)
            raise _BoundaryAbort(
                "fresh_boundary_cleanup_target_is_not_owned",
                orphan_possible=True,
            )
        try:
            status, _response = await cursor.send(
                index,
                runtime.executor,
                CandidateAction(
                    method=request.method,
                    url=request.url,
                    body=request.body,
                    hint=OWNED_UPDATE_LOW_RISK,
                    actor_persona_id=runtime.actor_persona_id,
                    target_owner_persona_id=runtime.actor_persona_id,
                    target_is_researcher_owned=True,
                    expected_side_effect="cleanup_owned_test_object",
                    proof_goal="cleanup_fresh_owned_authorization_boundary",
                    budget_reservation_id=cursor.reservation_id,
                ),
                headers=dict(request.headers),
            )
        except Exception as exc:
            raise _BoundaryAbort(
                "fresh_boundary_cleanup_transport_error",
                orphan_possible=True,
            ) from exc
        if status == DENIED_STATUS or not 200 <= int(status) < 300:
            raise _BoundaryAbort(
                "fresh_boundary_cleanup_failed",
                orphan_possible=True,
            )

    async def execute(self, experiment_id: str) -> FreshOwnedBoundaryResult:
        async with self._lock:
            if self._consumed:
                raise FreshOwnedBoundaryDenied(
                    "fresh_owned_boundary_executor_already_consumed"
                )
            pair = self._pair(experiment_id)
            source_preflight = await pair.source.runtime._claim_preflight(
                expected_sequence_id=pair.source.preflight.sequence_id,
            )
            peer_preflight = await pair.peer.runtime._claim_preflight(
                expected_sequence_id=pair.peer.preflight.sequence_id,
            )
            pair = _BoundaryPair(
                pair.boundary_id,
                _lifecycle_contract(pair.source.experiment, source_preflight),
                _lifecycle_contract(pair.peer.experiment, peer_preflight),
            )
            self._consumed = True

        budget = pair.source.runtime.executor.policy.budget
        reserved_actions = (
            (OWNED_CREATE, endpoint_key(pair.source.create.request.url)),
            (OWNED_CREATE, endpoint_key(pair.peer.create.request.url)),
            (SAFE_READ, endpoint_key(pair.source.read.request.url)),
            (SAFE_READ, endpoint_key(pair.peer.read.request.url)),
            (CROSS_OBJECT_READ, endpoint_key(pair.source.read.request.url)),
            (
                OWNED_UPDATE_LOW_RISK,
                endpoint_key(pair.peer.cleanup.step.request.url),
            ),
            (
                OWNED_UPDATE_LOW_RISK,
                endpoint_key(pair.source.cleanup.step.request.url),
            ),
        )
        reservation_id, reason = budget.try_reserve(reserved_actions)
        if reservation_id is None:
            raise FreshOwnedBoundaryDenied(
                f"fresh_boundary_budget_reservation_denied:{reason}"
            )
        cursor = _ReservationCursor(budget, reservation_id)
        source_object = None
        peer_object = None
        creates_attempted = 0
        creates_completed = 0
        cleanup_attempted = 0
        cleanup_completed = 0
        proof_attempted = 0
        proof_sent = 0
        orphan_possible = False
        error_code = None
        proof_completed = False
        verdict = bola_replay.OpVerdict(
            pair.source.read.operation.label,
            "ERROR",
            "fresh boundary proof did not complete",
        )
        try:
            try:
                creates_attempted += 1
                source_object = await self._create_object(pair.source, cursor, 0)
                creates_completed += 1
                creates_attempted += 1
                peer_object = await self._create_object(pair.peer, cursor, 1)
                creates_completed += 1

                if source_object.value == peer_object.value:
                    raise _BoundaryAbort("fresh_boundary_identifiers_are_not_distinct")
                source_op = bola_replay.ObjectScopedOp(
                    kind="rest",
                    label=pair.source.read.operation.label,
                    method="GET",
                    url=source_object.read_request.url,
                    raw_body=None,
                    id_where="fresh owned path lineage",
                    headers=dict(source_object.read_request.headers),
                )
                peer_op = bola_replay.ObjectScopedOp(
                    kind="rest",
                    label=pair.peer.read.operation.label,
                    method="GET",
                    url=peer_object.read_request.url,
                    raw_body=None,
                    id_where="fresh owned path lineage",
                    headers=dict(peer_object.read_request.headers),
                )
                transport = _FreshBoundaryReplayTransport(
                    cursor=cursor,
                    source=pair.source,
                    peer=pair.peer,
                    source_object=source_object,
                    peer_object=peer_object,
                )
                try:
                    verdict = await bola_replay.classify_operation(
                        peer_op,
                        pair.peer.runtime.actor_persona_id,
                        pair.source.runtime.actor_persona_id,
                        peer_object.value,
                        source_object.value,
                        transport,
                        victim_op=source_op,
                    )
                    proof_completed = True
                finally:
                    proof_attempted = transport.attempted
                    proof_sent = transport.sent
            except _BoundaryAbort as exc:
                error_code = exc.code
                orphan_possible = orphan_possible or exc.orphan_possible
            except Exception:
                error_code = "fresh_boundary_unexpected_proof_error"
        finally:
            try:
                cursor.skip_until(5)
                for index, lifecycle, owned_object in (
                    (5, pair.peer, peer_object),
                    (6, pair.source, source_object),
                ):
                    if owned_object is None:
                        cursor.skip_until(index + 1)
                        continue
                    cleanup_attempted += 1
                    try:
                        await self._cleanup_object(
                            lifecycle,
                            owned_object,
                            cursor,
                            index,
                        )
                    except _BoundaryAbort:
                        orphan_possible = True
                    else:
                        cleanup_completed += 1
            finally:
                budget.release_reservation(reservation_id)

        cleanup_failed = cleanup_attempted != cleanup_completed
        if cleanup_failed:
            status = "cleanup_failed"
            error_code = "fresh_boundary_cleanup_failed"
        elif proof_completed:
            status = "completed"
            error_code = None
        else:
            status = "aborted"
            error_code = error_code or "fresh_boundary_proof_aborted"
        source_executor = pair.source.runtime.executor
        peer_executor = pair.peer.runtime.executor
        sink = source_executor.provenance
        restraint = source_executor.restraint_summary()
        restraint["policy_denials"] = len(source_executor.skipped) + len(
            peer_executor.skipped
        )
        restraint["fresh_owned_objects_created"] = creates_completed
        restraint["fresh_owned_objects_cleaned"] = cleanup_completed
        restraint["stopped_after_terminal_verdict"] = proof_completed
        return FreshOwnedBoundaryResult(
            boundary_id=pair.boundary_id,
            experiment_id=pair.source.experiment.experiment_id,
            lifecycle_id=pair.source.experiment.lifecycle_id,
            terminal_operation_id=pair.source.experiment.terminal_operation_id,
            peer_experiment_id=pair.peer.experiment.experiment_id,
            legacy_verdict=verdict,
            requests_attempted=cursor.attempted,
            requests_sent=cursor.sent,
            creates_attempted=creates_attempted,
            creates_completed=creates_completed,
            proof_legs_attempted=proof_attempted,
            proof_legs_sent=proof_sent,
            cleanup_steps_attempted=cleanup_attempted,
            cleanup_steps_completed=cleanup_completed,
            policy_denials=len(source_executor.skipped) + len(peer_executor.skipped),
            orphaned_owned_state_possible=orphan_possible,
            provenance_root=(sink.root() if sink is not None else "") or "",
            budget_snapshot=budget.snapshot(),
            restraint=restraint,
            provenance=(sink.summary() if sink is not None else {}),
            status=status,
            error_code=error_code,
        )


__all__ = [
    "FRESH_OWNED_BOUNDARY_MODE",
    "FreshOwnedBoundaryConfig",
    "FreshOwnedBoundaryDenied",
    "FreshOwnedBoundaryExecutor",
    "FreshOwnedBoundaryResult",
]
