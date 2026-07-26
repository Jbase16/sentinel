"""Default-off confirmation of one fresh prerequisite-omission comparison.

This boundary adds one independent, fresh-object control to the evidence-only
comparison in :mod:`core.behavior.omission_boundary`.  It reuses the live,
server-issued capability from the baseline object against a third fresh object.
Only a rejected wrong-object capability plus a successful missing-capability
request can prove the narrow fail-open finding represented here.
"""

from __future__ import annotations

import copy
import hmac
import os
import re
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple

from core.cortex.execution_policy import PolicyExecutor
from core.foundry.authorization import AuthorizationEnvelope

from .admission import COMPILED_ADMISSION_ENV
from .normalize import stable_hash
from .omission import MinimizedOmissionExperiment
from .omission_boundary import (
    FRESH_OMISSION_ENV,
    FRESH_OMISSION_WORKFLOW,
    FreshOmissionBoundaryExecutor,
    FreshOmissionDenied,
    _LegProgress,
    _OmissionAbort,
    _OmissionPreflight,
    _ReservationCursor,
)
from .receipts import (
    COMPLETED,
    BehavioralReceiptContext,
    BehavioralReceiptStore,
    ReceiptStoreError,
    redacted_fresh_omission_confirmation_outcome,
    redacted_receipt_context,
    request_fingerprint,
)
from .runtime import CONTROLLED_SEQUENCE_WORKFLOW
from .scheduler import PRIMARY_ENV

FRESH_OMISSION_CONFIRMATION_ENV = "SENTINELFORGE_BEHAVIOR_OMISSION_CONFIRMATION"
FRESH_OMISSION_CONFIRMATION_MODE = "behavioral_fresh_omission_confirmation_v1"
FRESH_OMISSION_CONFIRMATION_WORKFLOW = "behavioral_state_machine_omission_confirmation"
_TRUE = frozenset({"1", "true", "yes", "on"})
_HASH_REF = re.compile(r"^[a-z][a-z0-9_]*:[0-9a-f]{64}$")
_SEMANTIC = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_CONTROL_REJECTION_STATUSES = frozenset({400, 401, 403, 422})
_CONFIRMATION_STATUSES = frozenset(
    {
        "not_completed",
        "confirmed_fail_open",
        "omission_rejected",
        "response_mismatch",
        "inconclusive_truncated",
        "control_accepted",
        "control_inconclusive",
        "inconclusive_cleanup_failed",
    }
)


def _hash_ref(value: Any, prefix: str) -> bool:
    return (
        isinstance(value, str)
        and value.startswith(f"{prefix}:")
        and _HASH_REF.fullmatch(value) is not None
    )


@dataclass(frozen=True)
class FreshOmissionConfirmationConfig:
    enabled: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.enabled, bool):
            raise ValueError("fresh omission confirmation enabled must be boolean")

    @classmethod
    def from_environment(cls) -> "FreshOmissionConfirmationConfig":
        required = (
            PRIMARY_ENV,
            COMPILED_ADMISSION_ENV,
            FRESH_OMISSION_ENV,
            FRESH_OMISSION_CONFIRMATION_ENV,
        )
        return cls(
            enabled=all(
                os.environ.get(name, "").strip().lower() in _TRUE for name in required
            )
        )


@dataclass(frozen=True)
class OmissionCapabilityFinding:
    finding_id: str
    confirmation_id: str
    experiment_id: str
    terminal_operation_id: str
    lifecycle_id: str
    provenance_root: str
    proof_kind: str = "known_valid_wrong_object_capability_rejected"
    finding_authority: bool = True

    def __post_init__(self) -> None:
        payload = {
            "confirmation_id": self.confirmation_id,
            "experiment_id": self.experiment_id,
            "terminal_operation_id": self.terminal_operation_id,
            "lifecycle_id": self.lifecycle_id,
            "provenance_root": self.provenance_root,
            "proof_kind": self.proof_kind,
        }
        if (
            self.finding_id != stable_hash("omission_capability_finding", payload)
            or not _hash_ref(
                self.confirmation_id,
                "fresh_omission_confirmation",
            )
            or not _hash_ref(self.experiment_id, "omission_experiment")
            or not _hash_ref(self.terminal_operation_id, "action")
            or not _hash_ref(self.lifecycle_id, "owned_lifecycle")
            or not isinstance(self.provenance_root, str)
            or len(self.provenance_root) != 64
            or any(
                character not in "0123456789abcdef"
                for character in self.provenance_root
            )
            or self.proof_kind != "known_valid_wrong_object_capability_rejected"
            or not self.finding_authority
        ):
            raise ValueError("omission capability finding contract is invalid")

    @classmethod
    def build(
        cls,
        *,
        confirmation_id: str,
        experiment_id: str,
        terminal_operation_id: str,
        lifecycle_id: str,
        provenance_root: str,
    ) -> "OmissionCapabilityFinding":
        payload = {
            "confirmation_id": confirmation_id,
            "experiment_id": experiment_id,
            "terminal_operation_id": terminal_operation_id,
            "lifecycle_id": lifecycle_id,
            "provenance_root": provenance_root,
            "proof_kind": "known_valid_wrong_object_capability_rejected",
        }
        return cls(
            finding_id=stable_hash("omission_capability_finding", payload),
            confirmation_id=confirmation_id,
            experiment_id=experiment_id,
            terminal_operation_id=terminal_operation_id,
            lifecycle_id=lifecycle_id,
            provenance_root=provenance_root,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": 1,
            "finding_id": self.finding_id,
            "confirmation_id": self.confirmation_id,
            "experiment_id": self.experiment_id,
            "terminal_operation_id": self.terminal_operation_id,
            "lifecycle_id": self.lifecycle_id,
            "provenance_root": self.provenance_root,
            "proof_kind": self.proof_kind,
            "finding_authority": self.finding_authority,
        }

    def to_finding(self) -> Dict[str, Any]:
        return {
            "id": self.finding_id,
            "type": "State-machine prerequisite enforcement failure",
            "severity": "MEDIUM",
            "tool": "behavioral_omission_confirmation",
            "target": self.terminal_operation_id,
            "message": (
                "A fresh owned operation reproduced the captured successful "
                "response after an object-bound prerequisite capability was "
                "omitted; an independently fresh wrong-object control rejected "
                "the same known-valid capability."
            ),
            "tags": [
                "verified",
                "business_logic",
                "state_machine",
                "prerequisite_omission",
            ],
            "families": ["confirmed_vuln"],
            "metadata": {
                "vuln_class": "business_logic",
                "subtype": "prerequisite_omission_fail_open",
                "finding_id": self.finding_id,
                "confirmation_id": self.confirmation_id,
                "experiment_id": self.experiment_id,
                "terminal_operation_id": self.terminal_operation_id,
                "lifecycle_id": self.lifecycle_id,
                "proof_kind": self.proof_kind,
                "finding_authority": self.finding_authority,
                "intended_invariant": (
                    "The terminal operation must reject a request that omits "
                    "its required object-bound capability."
                ),
                "observed_violation": (
                    "The omission reproduced the successful baseline while a "
                    "known-valid capability from another fresh object was "
                    "rejected as object-bound."
                ),
                "evidence": self.to_dict(),
            },
        }


@dataclass(frozen=True)
class FreshOmissionConfirmationResult:
    confirmation_id: str
    experiment_id: str
    lifecycle_id: str
    terminal_operation_id: str
    status: str
    confirmation_status: str
    baseline_reference_match: bool
    baseline_terminal_success: bool
    omission_terminal_success: bool
    control_terminal_success: bool
    baseline_terminal_truncated: bool
    omission_terminal_truncated: bool
    control_terminal_truncated: bool
    terminal_body_match: bool
    capability_object_binding_proven: bool
    control_response_status: Optional[int]
    requests_attempted: int
    requests_sent: int
    baseline_steps_attempted: int
    baseline_steps_completed: int
    omission_steps_attempted: int
    omission_steps_completed: int
    control_steps_attempted: int
    control_steps_completed: int
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
    finding: Optional[OmissionCapabilityFinding] = None
    error_code: Optional[str] = None
    mode: str = FRESH_OMISSION_CONFIRMATION_MODE
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
            self.control_steps_attempted,
            self.control_steps_completed,
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
            self.mode != FRESH_OMISSION_CONFIRMATION_MODE
            or not self.executable
            or not _hash_ref(
                self.confirmation_id,
                "fresh_omission_confirmation",
            )
            or not _hash_ref(self.experiment_id, "omission_experiment")
            or not _hash_ref(self.lifecycle_id, "owned_lifecycle")
            or not _hash_ref(self.terminal_operation_id, "action")
            or self.status not in {"completed", "aborted", "cleanup_failed"}
            or self.confirmation_status not in _CONFIRMATION_STATUSES
            or any(
                isinstance(value, bool) or not isinstance(value, int) or value < 0
                for value in counters
            )
            or self.requests_sent > self.requests_attempted
            or self.requests_attempted
            != self.baseline_steps_attempted
            + self.omission_steps_attempted
            + self.control_steps_attempted
            + self.cleanup_steps_attempted
            or self.baseline_steps_completed > self.baseline_steps_attempted
            or self.omission_steps_completed > self.omission_steps_attempted
            or self.control_steps_completed > self.control_steps_attempted
            or self.creates_completed > self.creates_attempted
            or self.creates_attempted > 3
            or self.cleanup_steps_completed > self.cleanup_steps_attempted
            or self.cleanup_steps_attempted > 3
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
            or self.budget_snapshot["creates"] > 3
            or self.budget_snapshot["endpoints_touched"]
            > self.budget_snapshot["total_requests"]
            or (
                self.control_response_status is not None
                and (
                    isinstance(self.control_response_status, bool)
                    or not isinstance(self.control_response_status, int)
                    or not 100 <= self.control_response_status <= 599
                )
            )
            or (
                self.error_code is not None
                and (
                    not isinstance(self.error_code, str)
                    or _SEMANTIC.fullmatch(self.error_code) is None
                )
            )
            or self.finding_authority != (self.finding is not None)
        ):
            raise ValueError("fresh omission confirmation result is invalid")
        if self.status == "completed" and (
            self.error_code is not None
            or self.orphaned_owned_state_possible
            or not self.baseline_reference_match
            or self.creates_completed < 2
            or self.cleanup_steps_completed != self.creates_completed
            or self.confirmation_status == "not_completed"
        ):
            raise ValueError("completed omission confirmation is inconsistent")
        if self.status == "aborted" and self.error_code is None:
            raise ValueError("aborted omission confirmation requires an error")
        if self.status == "cleanup_failed" and (
            self.error_code != "fresh_omission_confirmation_cleanup_failed"
            or not self.orphaned_owned_state_possible
            or self.finding_authority
        ):
            raise ValueError("omission confirmation cleanup failure is inconsistent")
        if self.confirmation_status == "confirmed_fail_open" and (
            self.status != "completed"
            or not self.baseline_reference_match
            or not self.baseline_terminal_success
            or not self.omission_terminal_success
            or self.control_terminal_success
            or self.baseline_terminal_truncated
            or self.omission_terminal_truncated
            or self.control_terminal_truncated
            or not self.terminal_body_match
            or not self.capability_object_binding_proven
            or self.control_response_status not in _CONTROL_REJECTION_STATUSES
            or self.creates_completed != 3
            or self.cleanup_steps_completed != 3
            or not self.finding_authority
            or self.finding is None
        ):
            raise ValueError("confirmed omission finding is inconsistent")
        if self.confirmation_status != "confirmed_fail_open" and (
            self.capability_object_binding_proven
            or self.finding_authority
            or self.finding is not None
        ):
            raise ValueError("unconfirmed omission result cannot carry a finding")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": 1,
            "confirmation_id": self.confirmation_id,
            "experiment_id": self.experiment_id,
            "lifecycle_id": self.lifecycle_id,
            "terminal_operation_id": self.terminal_operation_id,
            "status": self.status,
            "confirmation_status": self.confirmation_status,
            "baseline_reference_match": self.baseline_reference_match,
            "baseline_terminal_success": self.baseline_terminal_success,
            "omission_terminal_success": self.omission_terminal_success,
            "control_terminal_success": self.control_terminal_success,
            "baseline_terminal_truncated": self.baseline_terminal_truncated,
            "omission_terminal_truncated": self.omission_terminal_truncated,
            "control_terminal_truncated": self.control_terminal_truncated,
            "terminal_body_match": self.terminal_body_match,
            "capability_object_binding_proven": (self.capability_object_binding_proven),
            "control_response_status": self.control_response_status,
            "requests_attempted": self.requests_attempted,
            "requests_sent": self.requests_sent,
            "baseline_steps_attempted": self.baseline_steps_attempted,
            "baseline_steps_completed": self.baseline_steps_completed,
            "omission_steps_attempted": self.omission_steps_attempted,
            "omission_steps_completed": self.omission_steps_completed,
            "control_steps_attempted": self.control_steps_attempted,
            "control_steps_completed": self.control_steps_completed,
            "creates_attempted": self.creates_attempted,
            "creates_completed": self.creates_completed,
            "cleanup_steps_attempted": self.cleanup_steps_attempted,
            "cleanup_steps_completed": self.cleanup_steps_completed,
            "policy_denials": self.policy_denials,
            "orphaned_owned_state_possible": (self.orphaned_owned_state_possible),
            "provenance_root": self.provenance_root,
            "budget_snapshot": dict(self.budget_snapshot),
            "restraint": copy.deepcopy(self.restraint),
            "provenance": copy.deepcopy(self.provenance),
            "finding": self.finding.to_dict() if self.finding else None,
            "error_code": self.error_code,
            "mode": self.mode,
            "finding_authority": self.finding_authority,
            "executable": self.executable,
        }


class FreshOmissionConfirmationExecutor(FreshOmissionBoundaryExecutor):
    """Confirm one fail-open using three distinct fresh controlled objects."""

    boundary_mode = FRESH_OMISSION_CONFIRMATION_MODE
    boundary_hash_prefix = "fresh_omission_confirmation"
    required_workflows = (
        CONTROLLED_SEQUENCE_WORKFLOW,
        FRESH_OMISSION_WORKFLOW,
        FRESH_OMISSION_CONFIRMATION_WORKFLOW,
    )
    expected_creates = 3
    proof_goal = "confirm_fresh_state_prerequisite_omission"
    cleanup_proof_goal = "cleanup_fresh_state_omission_confirmation"

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
        config: Optional[FreshOmissionConfirmationConfig] = None,
    ) -> None:
        super().__init__(
            records,
            world_id=world_id,
            target_origin=target_origin,
            authorization=authorization,
            actor_persona_id=actor_persona_id,
            executor=executor,
            experiment=experiment,
            config=config or FreshOmissionConfirmationConfig.from_environment(),
        )

    def _reserved_actions(
        self,
        *,
        baseline_actions: Sequence[Tuple[str, str]],
        omission_actions: Sequence[Tuple[str, str]],
        cleanup_action: Tuple[str, str],
    ) -> Tuple[Tuple[str, str], ...]:
        return (
            *baseline_actions,
            *omission_actions,
            *omission_actions,
            cleanup_action,
            cleanup_action,
            cleanup_action,
        )

    @staticmethod
    def _baseline_capability(
        preflight: _OmissionPreflight,
        baseline: _LegProgress,
    ) -> Any:
        capability = baseline.omitted_capability
        owned = baseline.owned_object
        if (
            owned is None
            or capability is None
            or isinstance(capability, (dict, list, tuple, set, bool))
            or not isinstance(capability, (str, int))
            or hmac.compare_digest(str(capability), owned.value)
        ):
            raise _OmissionAbort(
                "fresh_omission_confirmation_capability_is_invalid",
                orphan_possible=owned is not None,
            )
        if preflight.experiment.omitted_binding_id not in {
            item.binding_id for item in preflight.bindings
        }:
            raise _OmissionAbort(
                "fresh_omission_confirmation_binding_is_missing",
                orphan_possible=True,
            )
        return capability

    async def execute(
        self,
        *,
        expected_boundary_id: Optional[str] = None,
    ) -> FreshOmissionConfirmationResult:
        preflight = await self._claim(expected_boundary_id)
        budget = self.executor.policy.budget
        reservation_id, reason = budget.try_reserve(preflight.reserved_actions)
        if reservation_id is None:
            raise FreshOmissionDenied(
                f"fresh_omission_confirmation_budget_denied:{reason}"
            )
        cursor = _ReservationCursor(
            budget,
            reservation_id,
            total_slots=len(preflight.reserved_actions),
        )
        cleanup_start = len(preflight.experiment.baseline_operation_ids) + 2 * len(
            preflight.experiment.omission_operation_ids
        )
        baseline = _LegProgress()
        omission = _LegProgress()
        control = _LegProgress()
        cleanup_attempted = 0
        cleanup_completed = 0
        error_code = None
        confirmation_status = "not_completed"
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
                capability = self._baseline_capability(preflight, baseline)

                await self._run_leg(
                    preflight,
                    cursor,
                    preflight.experiment.omission_operation_ids,
                    omit_binding=True,
                    progress=omission,
                    disallowed_object_values=(
                        (baseline.owned_object.value,)
                        if baseline.owned_object is not None
                        else ()
                    ),
                )
                omission_evidence = omission.terminal_evidence
                assert omission_evidence is not None
                if omission_evidence.truncated:
                    confirmation_status = "inconclusive_truncated"
                elif not omission_evidence.success:
                    confirmation_status = "omission_rejected"
                elif omission_evidence.body_hash != baseline_evidence.body_hash:
                    confirmation_status = "response_mismatch"
                else:
                    await self._run_leg(
                        preflight,
                        cursor,
                        preflight.experiment.omission_operation_ids,
                        omit_binding=False,
                        progress=control,
                        disallowed_object_values=tuple(
                            item.value
                            for item in (
                                baseline.owned_object,
                                omission.owned_object,
                            )
                            if item is not None
                        ),
                        binding_overrides={
                            preflight.experiment.omitted_binding_id: capability
                        },
                    )
                    control_evidence = control.terminal_evidence
                    assert control_evidence is not None
                    if control_evidence.truncated:
                        confirmation_status = "inconclusive_truncated"
                    elif (
                        not control_evidence.success
                        and control_evidence.status in _CONTROL_REJECTION_STATUSES
                    ):
                        confirmation_status = "confirmed_fail_open"
                    elif control_evidence.success:
                        confirmation_status = "control_accepted"
                    else:
                        confirmation_status = "control_inconclusive"
            except _OmissionAbort as exc:
                error_code = exc.code
            except Exception:
                error_code = "fresh_omission_confirmation_unexpected_execution_error"
        finally:
            try:
                cursor.skip_until(cleanup_start)
                cleaned_values = set()
                for owned_object in (
                    control.owned_object,
                    omission.owned_object,
                    baseline.owned_object,
                ):
                    if owned_object is None or owned_object.value in cleaned_values:
                        cursor.skip_until(cursor.index + 1)
                        continue
                    cleaned_values.add(owned_object.value)
                    cleanup_attempted += 1
                    try:
                        await self._cleanup(owned_object, cursor)
                    except _OmissionAbort:
                        continue
                    else:
                        cleanup_completed += 1
            finally:
                budget.release_reservation(reservation_id)

        legs = (baseline, omission, control)
        creates_attempted = sum(int(item.create_attempted) for item in legs)
        creates_completed = sum(int(item.create_completed) for item in legs)
        unique_created_values = {
            item.owned_object.value for item in legs if item.owned_object is not None
        }
        orphan_possible = (
            creates_attempted > creates_completed
            or cleanup_completed < len(unique_created_values)
        )
        cleanup_failed = cleanup_attempted != cleanup_completed
        if cleanup_failed:
            status = "cleanup_failed"
            error_code = "fresh_omission_confirmation_cleanup_failed"
            if confirmation_status == "confirmed_fail_open":
                confirmation_status = "inconclusive_cleanup_failed"
        elif (
            baseline.terminal_evidence is not None
            and omission.terminal_evidence is not None
            and confirmation_status != "not_completed"
            and error_code is None
        ):
            status = "completed"
        else:
            status = "aborted"
            error_code = error_code or "fresh_omission_confirmation_aborted"

        baseline_evidence = baseline.terminal_evidence
        omission_evidence = omission.terminal_evidence
        control_evidence = control.terminal_evidence
        baseline_reference_match = bool(
            baseline_evidence is not None
            and baseline_evidence.status
            == preflight.experiment.oracle.reference_response_status
            and baseline_evidence.body_hash
            == preflight.experiment.oracle.reference_response_body_hash
            and not baseline_evidence.truncated
            and baseline_evidence.success
        )
        body_match = bool(
            baseline_evidence is not None
            and omission_evidence is not None
            and baseline_evidence.body_hash is not None
            and baseline_evidence.body_hash == omission_evidence.body_hash
        )
        capability_binding_proven = bool(
            status == "completed"
            and confirmation_status == "confirmed_fail_open"
            and control_evidence is not None
            and not control_evidence.truncated
            and not control_evidence.success
            and control_evidence.status in _CONTROL_REJECTION_STATUSES
            and creates_completed == 3
            and cleanup_completed == 3
        )
        sink = self.executor.provenance
        provenance_root = (sink.root() if sink is not None else "") or ""
        finding = (
            OmissionCapabilityFinding.build(
                confirmation_id=preflight.boundary_id,
                experiment_id=preflight.experiment.experiment_id,
                terminal_operation_id=(preflight.experiment.terminal_operation_id),
                lifecycle_id=preflight.lifecycle.lifecycle_id,
                provenance_root=provenance_root,
            )
            if capability_binding_proven
            else None
        )
        restraint = self.executor.restraint_summary()
        restraint["fresh_owned_objects_created"] = creates_completed
        restraint["fresh_owned_objects_cleaned"] = cleanup_completed
        restraint["omitted_prerequisites"] = 1 if omission_evidence is not None else 0
        restraint["wrong_object_capability_controls"] = (
            1 if control_evidence is not None else 0
        )
        restraint["finding_authority"] = finding is not None
        return FreshOmissionConfirmationResult(
            confirmation_id=preflight.boundary_id,
            experiment_id=preflight.experiment.experiment_id,
            lifecycle_id=preflight.lifecycle.lifecycle_id,
            terminal_operation_id=preflight.experiment.terminal_operation_id,
            status=status,
            confirmation_status=confirmation_status,
            baseline_reference_match=baseline_reference_match,
            baseline_terminal_success=bool(
                baseline_evidence and baseline_evidence.success
            ),
            omission_terminal_success=bool(
                omission_evidence and omission_evidence.success
            ),
            control_terminal_success=bool(
                control_evidence and control_evidence.success
            ),
            baseline_terminal_truncated=bool(
                baseline_evidence and baseline_evidence.truncated
            ),
            omission_terminal_truncated=bool(
                omission_evidence and omission_evidence.truncated
            ),
            control_terminal_truncated=bool(
                control_evidence and control_evidence.truncated
            ),
            terminal_body_match=body_match,
            capability_object_binding_proven=capability_binding_proven,
            control_response_status=(
                control_evidence.status if control_evidence is not None else None
            ),
            requests_attempted=cursor.attempted,
            requests_sent=cursor.sent,
            baseline_steps_attempted=baseline.attempted,
            baseline_steps_completed=baseline.completed,
            omission_steps_attempted=omission.attempted,
            omission_steps_completed=omission.completed,
            control_steps_attempted=control.attempted,
            control_steps_completed=control.completed,
            creates_attempted=creates_attempted,
            creates_completed=creates_completed,
            cleanup_steps_attempted=cleanup_attempted,
            cleanup_steps_completed=cleanup_completed,
            policy_denials=len(self.executor.skipped),
            orphaned_owned_state_possible=orphan_possible,
            provenance_root=provenance_root,
            budget_snapshot=budget.snapshot(),
            restraint=restraint,
            provenance=(sink.summary() if sink is not None else {}),
            finding=finding,
            error_code=error_code,
            finding_authority=finding is not None,
        )


@dataclass(frozen=True)
class FreshOmissionConfirmationAdmissionResult:
    status: str
    receipt_id: str
    reused: bool
    execution: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "receipt_id": self.receipt_id,
            "reused": self.reused,
            "execution": copy.deepcopy(self.execution),
        }


class FreshOmissionConfirmationAdmission:
    """Reserve durable identity before one confirmation boundary can run."""

    def __init__(
        self,
        boundary: FreshOmissionConfirmationExecutor,
        *,
        receipt_store: Optional[BehavioralReceiptStore] = None,
    ) -> None:
        if not isinstance(boundary, FreshOmissionConfirmationExecutor):
            raise TypeError("fresh omission confirmation executor is required")
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

    def _descriptor(self, confirmation_id: str) -> Dict[str, Any]:
        boundary = self.boundary
        experiment = boundary.experiment
        return {
            "schema_version": 1,
            "mode": FRESH_OMISSION_CONFIRMATION_MODE,
            "confirmation_id": confirmation_id,
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
        confirmation_id = self.boundary.validate_preflight()
        try:
            fingerprint = request_fingerprint(self._descriptor(confirmation_id))
        except (TypeError, ValueError) as exc:
            raise FreshOmissionDenied(
                "fresh_omission_confirmation_admission_is_not_deterministic"
            ) from exc
        return confirmation_id, fingerprint

    def validate_preflight(self) -> str:
        _confirmation_id, fingerprint = self._identity()
        return fingerprint

    @staticmethod
    def _cached_result(
        receipt_id: str,
        outcome: Mapping[str, Any],
    ) -> FreshOmissionConfirmationAdmissionResult:
        if outcome.get("kind") != "fresh_omission_confirmation":
            raise FreshOmissionDenied(
                "fresh_omission_confirmation_receipt_kind_mismatch"
            )
        return FreshOmissionConfirmationAdmissionResult(
            status="already_executed",
            receipt_id=receipt_id,
            reused=True,
            execution=copy.deepcopy(dict(outcome)),
        )

    async def execute(self) -> FreshOmissionConfirmationAdmissionResult:
        confirmation_id, fingerprint = self._identity()
        context = self._context()
        try:
            reservation = self.receipt_store.reserve(
                fingerprint,
                context=context,
            )
        except (OSError, ReceiptStoreError) as exc:
            raise FreshOmissionDenied(
                "fresh_omission_confirmation_receipt_store_unavailable"
            ) from exc
        if not reservation.created:
            if reservation.receipt.context != context:
                raise FreshOmissionDenied(
                    "fresh_omission_confirmation_receipt_context_mismatch"
                )
            if (
                reservation.receipt.state == COMPLETED
                and reservation.receipt.outcome is not None
            ):
                return self._cached_result(
                    reservation.receipt.receipt_id,
                    reservation.receipt.outcome,
                )
            raise FreshOmissionDenied(
                "fresh_omission_confirmation_is_already_reserved_or_terminal"
            )
        token = reservation.reservation_token
        if token is None:
            raise FreshOmissionDenied(
                "fresh_omission_confirmation_reservation_token_unavailable"
            )
        try:
            result = await self.boundary.execute(
                expected_boundary_id=confirmation_id,
            )
        except Exception:
            try:
                self.receipt_store.abort(
                    fingerprint,
                    reservation_token=token,
                    reason="fresh_omission_confirmation_execution_error",
                )
            except (OSError, ReceiptStoreError) as receipt_exc:
                raise FreshOmissionDenied(
                    "fresh_omission_confirmation_receipt_finalize_failed"
                ) from receipt_exc
            raise
        outcome = redacted_fresh_omission_confirmation_outcome(result.to_dict())
        try:
            completed = self.receipt_store.complete(
                fingerprint,
                reservation_token=token,
                outcome=outcome,
            )
        except (OSError, ReceiptStoreError) as exc:
            raise FreshOmissionDenied(
                "fresh_omission_confirmation_completion_not_persisted"
            ) from exc
        if completed.outcome is None:
            raise FreshOmissionDenied(
                "fresh_omission_confirmation_receipt_outcome_missing"
            )
        return FreshOmissionConfirmationAdmissionResult(
            status=result.status,
            receipt_id=completed.receipt_id,
            reused=False,
            execution=copy.deepcopy(completed.outcome),
        )


__all__ = [
    "FRESH_OMISSION_CONFIRMATION_ENV",
    "FRESH_OMISSION_CONFIRMATION_MODE",
    "FRESH_OMISSION_CONFIRMATION_WORKFLOW",
    "FreshOmissionConfirmationAdmission",
    "FreshOmissionConfirmationAdmissionResult",
    "FreshOmissionConfirmationConfig",
    "FreshOmissionConfirmationExecutor",
    "FreshOmissionConfirmationResult",
    "OmissionCapabilityFinding",
]
