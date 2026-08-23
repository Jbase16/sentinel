"""Separately admitted execution for graph-bound prerequisite experiments.

R5B3b2c consumes one graph-bound claim, provisions three fresh owned worlds,
dispatches only the sealed terminal actions, evaluates the bounded omission or
reordering observation, verifies cleanup through pre-reserved reads, and
terminalizes the durable receipt. Raw runtime identifiers, request material,
and response bodies never enter public artifacts.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple

from core.cortex.execution_policy import CandidateAction, DENIED_STATUS
from core.safety.action_classifier import OWNED_CREATE

from .normalize import _body_hash, stable_hash
from .prerequisite_execution_claim import (
    GraphBoundExecutionClaim,
    GraphBoundExecutionClaimDenied,
    _GraphBoundProvisioningAuthority,
)
from .prerequisite_provisioning import (
    GRAPH_BOUND_FRESH_WORLD_PROVISIONING_ENV,
    GraphBoundFreshWorldProvisioningDenied,
    GraphBoundFreshWorldProvisioningEvidence,
    _CreatedState,
    _ProvisioningState,
    _RuntimeEntry,
    _build_provisioning_evidence,
    _execute_provisioning_prefix,
    _rehydrate,
    _require_owned_dependencies,
    _runtime_entries,
    _runtime_override_inequality_attestation,
    _validate_runtime_authority,
)

GRAPH_BOUND_PREREQUISITE_EXECUTION_ENV = (
    "SENTINELFORGE_BEHAVIOR_GRAPH_BOUND_PREREQUISITE_EXECUTION"
)
GRAPH_BOUND_PREREQUISITE_EXECUTION_MODE = (
    "behavioral_graph_bound_prerequisite_execution_v1"
)
GRAPH_BOUND_PREREQUISITE_EXECUTION_KIND = (
    "graph_bound_prerequisite_execution"
)

_TRUE = frozenset({"1", "true", "yes", "on"})
_WORLD_ROLES = (
    "valid_baseline",
    "counterfactual_treatment",
    "independent_control",
)
_CLEANUP_TERMINAL_STATUSES = frozenset({404, 410})
_PREREQUISITE_REJECTION_STATUSES = frozenset(
    {400, 401, 403, 404, 409, 410, 422}
)
_PROVENANCE_ROOT = re.compile(r"^[0-9a-f]{64}$")


class GraphBoundPrerequisiteExecutionDenied(RuntimeError):
    """The experiment failed closed after its single-use claim was selected."""

    def __init__(
        self,
        reason: str,
        *,
        category: str = "execution",
        cleanup: Optional["GraphBoundExperimentCleanupResult"] = None,
    ) -> None:
        super().__init__(reason)
        self.category = category
        self.cleanup = cleanup
        self.orphaned_owned_state_possible = bool(
            cleanup is not None and cleanup.orphaned_owned_state_possible
        )


@dataclass(frozen=True)
class GraphBoundPrerequisiteExecutionConfig:
    enabled: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.enabled, bool):
            raise TypeError("graph-bound prerequisite execution enabled must be boolean")

    @classmethod
    def from_environment(cls) -> "GraphBoundPrerequisiteExecutionConfig":
        dispatch_enabled = str(
            os.getenv(GRAPH_BOUND_PREREQUISITE_EXECUTION_ENV, "")
        ).strip().lower() in _TRUE
        provisioning_enabled = str(
            os.getenv(GRAPH_BOUND_FRESH_WORLD_PROVISIONING_ENV, "")
        ).strip().lower() in _TRUE
        return cls(enabled=dispatch_enabled and provisioning_enabled)


class GraphBoundPrerequisiteOracleVerdict(str, Enum):
    CONFIRMED = "confirmed"
    REFUTED = "refuted"
    INCONCLUSIVE = "inconclusive"


@dataclass(frozen=True)
class GraphBoundTerminalObservation:
    evidence_ref: str
    request_binding_id: str
    world_role: str
    status: int
    body_hash: Optional[str]
    reference_match: bool
    runtime_binding_override_ref: Optional[str]
    runtime_value_inequality_ref: Optional[str]

    @classmethod
    def build(
        cls,
        *,
        entry: _RuntimeEntry,
        status: int,
        response: Any,
        reference_status: int,
        reference_body_hash: str,
        runtime_value_inequality_ref: Optional[str],
    ) -> "GraphBoundTerminalObservation":
        body_hash = _body_hash(response)
        reference_match = (
            status == reference_status and body_hash == reference_body_hash
        )
        override_ref = (
            stable_hash(
                "graph_bound_runtime_binding_override",
                {
                    "request_binding_id": entry.binding.binding_id,
                    "binding_id": entry.binding.runtime_override_binding_id,
                    "source_world_slot_id": (
                        entry.binding.runtime_override_source_world_slot_id
                    ),
                    "destination_world_slot_id": (
                        entry.binding.world_slot_id
                    ),
                    "source_create_operation_id": (
                        entry.binding.runtime_override_source_create_operation_id
                    ),
                },
            )
            if entry.binding.runtime_override_binding_id is not None
            else None
        )
        payload = {
            "request_binding_id": entry.binding.binding_id,
            "world_role": entry.binding.world_role,
            "status": status,
            "body_hash": body_hash,
            "reference_match": reference_match,
            "runtime_binding_override_ref": override_ref,
            "runtime_value_inequality_ref": runtime_value_inequality_ref,
        }
        return cls(
            evidence_ref=stable_hash(
                "graph_bound_terminal_observation",
                payload,
            ),
            request_binding_id=entry.binding.binding_id,
            world_role=entry.binding.world_role,
            status=status,
            body_hash=body_hash,
            reference_match=reference_match,
            runtime_binding_override_ref=override_ref,
            runtime_value_inequality_ref=runtime_value_inequality_ref,
        )

    def __post_init__(self) -> None:
        payload = {
            "request_binding_id": self.request_binding_id,
            "world_role": self.world_role,
            "status": self.status,
            "body_hash": self.body_hash,
            "reference_match": self.reference_match,
            "runtime_binding_override_ref": self.runtime_binding_override_ref,
            "runtime_value_inequality_ref": self.runtime_value_inequality_ref,
        }
        if (
            self.evidence_ref
            != stable_hash("graph_bound_terminal_observation", payload)
            or not self.request_binding_id.startswith(
                "graph_bound_request_action:"
            )
            or self.world_role not in _WORLD_ROLES
            or isinstance(self.status, bool)
            or not isinstance(self.status, int)
            or self.status < 100
            or self.status > 599
            or (
                self.body_hash is not None
                and not self.body_hash.startswith("sha256:")
            )
            or not isinstance(self.reference_match, bool)
            or (
                self.runtime_binding_override_ref is not None
                and not self.runtime_binding_override_ref.startswith(
                    "graph_bound_runtime_binding_override:"
                )
            )
            or (self.runtime_binding_override_ref is not None)
            != (self.runtime_value_inequality_ref is not None)
            or (
                self.runtime_value_inequality_ref is not None
                and not self.runtime_value_inequality_ref.startswith(
                    "graph_bound_runtime_value_inequality_attestation:"
                )
            )
        ):
            raise ValueError("graph-bound terminal observation is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "evidence_ref": self.evidence_ref,
            "request_binding_id": self.request_binding_id,
            "world_role": self.world_role,
            "status": self.status,
            "body_hash": self.body_hash,
            "reference_match": self.reference_match,
            "runtime_binding_override_ref": self.runtime_binding_override_ref,
            "runtime_value_inequality_ref": self.runtime_value_inequality_ref,
        }


@dataclass(frozen=True)
class GraphBoundPrerequisiteOracleEvaluation:
    evaluation_id: str
    oracle_requirement_id: str
    plan_id: str
    reference_state_id: str
    family: str
    verdict: GraphBoundPrerequisiteOracleVerdict
    terminal_evidence_refs: Tuple[str, ...]
    uncertainty_reasons: Tuple[str, ...]
    valid_baseline_observed: bool
    independent_control_observed: bool
    treatment_reference_effect_observed: bool
    independent_effect_witness_observed: bool
    effect_witness_ref: Optional[str]
    runtime_value_inequality_ref: Optional[str]
    finding_candidate_ref: Optional[str]
    adversarial_triage_required: bool = True
    promotion_authority: bool = False
    finding_authority: bool = False

    def __post_init__(self) -> None:
        payload = {
            "oracle_requirement_id": self.oracle_requirement_id,
            "plan_id": self.plan_id,
            "reference_state_id": self.reference_state_id,
            "family": self.family,
            "verdict": self.verdict.value,
            "terminal_evidence_refs": list(self.terminal_evidence_refs),
            "uncertainty_reasons": list(self.uncertainty_reasons),
            "valid_baseline_observed": self.valid_baseline_observed,
            "independent_control_observed": self.independent_control_observed,
            "treatment_reference_effect_observed": (
                self.treatment_reference_effect_observed
            ),
            "independent_effect_witness_observed": (
                self.independent_effect_witness_observed
            ),
            "effect_witness_ref": self.effect_witness_ref,
            "runtime_value_inequality_ref": self.runtime_value_inequality_ref,
            "finding_candidate_ref": self.finding_candidate_ref,
            "adversarial_triage_required": self.adversarial_triage_required,
            "promotion_authority": self.promotion_authority,
            "finding_authority": self.finding_authority,
        }

        confirmed = self.verdict is GraphBoundPrerequisiteOracleVerdict.CONFIRMED
        refuted = self.verdict is GraphBoundPrerequisiteOracleVerdict.REFUTED
        inconclusive = (
            self.verdict is GraphBoundPrerequisiteOracleVerdict.INCONCLUSIVE
        )
        if (
            self.evaluation_id
            != stable_hash("graph_bound_prerequisite_oracle_evaluation", payload)
            or not self.oracle_requirement_id.startswith(
                "prerequisite_effect_oracle_requirement:"
            )
            or not self.plan_id.startswith("graph_bound_prepared_request_plan:")
            or not self.reference_state_id.startswith("state:")
            or self.family not in {"omission", "reordering"}
            or len(self.terminal_evidence_refs) != 3
            or len(set(self.terminal_evidence_refs)) != 3
            or any(
                not item.startswith("graph_bound_terminal_observation:")
                for item in self.terminal_evidence_refs
            )
            or self.uncertainty_reasons
            != tuple(sorted(set(self.uncertainty_reasons)))
            or any(not item for item in self.uncertainty_reasons)
            or any(
                not isinstance(value, bool)
                for value in (
                    self.valid_baseline_observed,
                    self.independent_control_observed,
                    self.treatment_reference_effect_observed,
                    self.independent_effect_witness_observed,
                )
            )
            or confirmed
            != (
                self.family == "omission"
                and self.valid_baseline_observed
                and self.independent_control_observed
                and self.treatment_reference_effect_observed
                and self.independent_effect_witness_observed
                and self.effect_witness_ref is not None
                and not self.uncertainty_reasons
                and self.finding_candidate_ref is not None
            )
            or refuted
            != (
                self.valid_baseline_observed
                and self.independent_control_observed
                and not self.treatment_reference_effect_observed
                and (
                    self.family == "reordering"
                    or (
                        self.independent_effect_witness_observed
                        and self.effect_witness_ref is not None
                    )
                )
                and not self.uncertainty_reasons
            )
            or inconclusive != bool(self.uncertainty_reasons)
            or (
                self.effect_witness_ref is not None
                and not self.effect_witness_ref.startswith(
                    "graph_bound_independent_effect_witness:"
                )
            )
            or (self.effect_witness_ref is not None)
            != (self.runtime_value_inequality_ref is not None)
            or (
                self.runtime_value_inequality_ref is not None
                and not self.runtime_value_inequality_ref.startswith(
                    "graph_bound_runtime_value_inequality_attestation:"
                )
            )
            or (self.finding_candidate_ref is not None) != confirmed
            or (
                self.finding_candidate_ref is not None
                and not self.finding_candidate_ref.startswith(
                    "graph_bound_prerequisite_candidate:"
                )
            )
            or not self.adversarial_triage_required
            or self.promotion_authority
            or self.finding_authority
        ):
            raise ValueError("graph-bound prerequisite oracle evaluation is invalid")

    @classmethod
    def build(
        cls,
        *,
        oracle_requirement_id: str,
        plan_id: str,
        reference_state_id: str,
        family: str,
        observations: Sequence[GraphBoundTerminalObservation],
    ) -> "GraphBoundPrerequisiteOracleEvaluation":
        values = tuple(observations)
        by_role = {item.world_role: item for item in values}
        if tuple(item.world_role for item in values) != _WORLD_ROLES:
            raise ValueError("graph-bound terminal observation order is invalid")
        baseline = by_role["valid_baseline"]
        treatment = by_role["counterfactual_treatment"]
        control = by_role["independent_control"]
        witness_observed = bool(
            family == "omission"
            and control.runtime_binding_override_ref is not None
            and control.runtime_value_inequality_ref is not None
            and control.status in _PREREQUISITE_REJECTION_STATUSES
        )
        control_observed = (
            witness_observed if family == "omission" else control.reference_match
        )
        effect_witness_ref = (
            stable_hash(
                "graph_bound_independent_effect_witness",
                {
                    "oracle_requirement_id": oracle_requirement_id,
                    "plan_id": plan_id,
                    "reference_state_id": reference_state_id,
                    "terminal_evidence_ref": control.evidence_ref,
                    "runtime_binding_override_ref": (
                        control.runtime_binding_override_ref
                    ),
                    "runtime_value_inequality_ref": (
                        control.runtime_value_inequality_ref
                    ),
                    "rejection_status": control.status,
                },
            )
            if witness_observed
            else None
        )
        uncertainty = set()
        verdict = GraphBoundPrerequisiteOracleVerdict.INCONCLUSIVE
        if not baseline.reference_match:
            uncertainty.add("valid_baseline_reference_mismatch")
        if not control_observed:
            uncertainty.add(
                "independent_effect_witness_unavailable"
                if family == "omission"
                else "independent_control_reference_mismatch"
            )
        if not uncertainty:
            if treatment.reference_match and family == "omission":
                verdict = GraphBoundPrerequisiteOracleVerdict.CONFIRMED
            elif treatment.reference_match and family == "reordering":
                uncertainty.add("reordering_security_effect_not_defined")
            elif treatment.status in _PREREQUISITE_REJECTION_STATUSES:
                verdict = GraphBoundPrerequisiteOracleVerdict.REFUTED
            else:
                uncertainty.add("treatment_effect_is_not_conclusive")
        reasons = tuple(sorted(uncertainty))
        candidate_ref = (
            stable_hash(
                "graph_bound_prerequisite_candidate",
                {
                    "oracle_requirement_id": oracle_requirement_id,
                    "plan_id": plan_id,
                    "family": family,
                    "terminal_evidence_refs": [
                        item.evidence_ref for item in values
                    ],
                    "effect_witness_ref": effect_witness_ref,
                    "verdict": verdict.value,
                },
            )
            if verdict is GraphBoundPrerequisiteOracleVerdict.CONFIRMED
            else None
        )
        payload = {
            "oracle_requirement_id": oracle_requirement_id,
            "plan_id": plan_id,
            "reference_state_id": reference_state_id,
            "family": family,
            "verdict": verdict.value,
            "terminal_evidence_refs": [item.evidence_ref for item in values],
            "uncertainty_reasons": list(reasons),
            "valid_baseline_observed": baseline.reference_match,
            "independent_control_observed": control_observed,
            "treatment_reference_effect_observed": treatment.reference_match,
            "independent_effect_witness_observed": witness_observed,
            "effect_witness_ref": effect_witness_ref,
            "runtime_value_inequality_ref": (
                control.runtime_value_inequality_ref
                if witness_observed
                else None
            ),
            "finding_candidate_ref": candidate_ref,
            "adversarial_triage_required": True,
            "promotion_authority": False,
            "finding_authority": False,
        }
        return cls(
            evaluation_id=stable_hash(
                "graph_bound_prerequisite_oracle_evaluation",
                payload,
            ),
            oracle_requirement_id=oracle_requirement_id,
            plan_id=plan_id,
            reference_state_id=reference_state_id,
            family=family,
            verdict=verdict,
            terminal_evidence_refs=tuple(
                item.evidence_ref for item in values
            ),
            uncertainty_reasons=reasons,
            valid_baseline_observed=baseline.reference_match,
            independent_control_observed=control_observed,
            treatment_reference_effect_observed=treatment.reference_match,
            independent_effect_witness_observed=witness_observed,
            effect_witness_ref=effect_witness_ref,
            runtime_value_inequality_ref=(
                control.runtime_value_inequality_ref
                if witness_observed
                else None
            ),
            finding_candidate_ref=candidate_ref,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "evaluation_id": self.evaluation_id,
            "oracle_requirement_id": self.oracle_requirement_id,
            "plan_id": self.plan_id,
            "reference_state_id": self.reference_state_id,
            "family": self.family,
            "verdict": self.verdict.value,
            "terminal_evidence_refs": list(self.terminal_evidence_refs),
            "uncertainty_reasons": list(self.uncertainty_reasons),
            "valid_baseline_observed": self.valid_baseline_observed,
            "independent_control_observed": (
                self.independent_control_observed
            ),
            "treatment_reference_effect_observed": (
                self.treatment_reference_effect_observed
            ),
            "independent_effect_witness_observed": (
                self.independent_effect_witness_observed
            ),
            "effect_witness_ref": self.effect_witness_ref,
            "runtime_value_inequality_ref": self.runtime_value_inequality_ref,
            "finding_candidate_ref": self.finding_candidate_ref,
            "adversarial_triage_required": (
                self.adversarial_triage_required
            ),
            "promotion_authority": self.promotion_authority,
            "finding_authority": self.finding_authority,
        }

@dataclass(frozen=True)
class GraphBoundExperimentCleanupResult:
    status: str
    cleanup_steps_attempted: int
    cleanup_steps_completed: int
    cleanup_verifications_attempted: int
    cleanup_verifications_completed: int
    ownership_grants_removed: int
    cleanup_evidence_refs: Tuple[str, ...]
    orphaned_owned_state_possible: bool

    def __post_init__(self) -> None:
        counts = (
            self.cleanup_steps_attempted,
            self.cleanup_steps_completed,
            self.cleanup_verifications_attempted,
            self.cleanup_verifications_completed,
            self.ownership_grants_removed,
        )
        complete = (
            self.cleanup_steps_attempted
            == self.cleanup_steps_completed
            == self.cleanup_verifications_attempted
            == self.cleanup_verifications_completed
            == self.ownership_grants_removed
            == 3
        )
        if (
            self.status not in {"verified", "failed", "uncertain"}
            or any(
                isinstance(value, bool)
                or not isinstance(value, int)
                or value < 0
                for value in counts
            )
            or self.cleanup_steps_completed > self.cleanup_steps_attempted
            or self.cleanup_verifications_completed
            > self.cleanup_verifications_attempted
            or self.ownership_grants_removed
            > self.cleanup_verifications_completed
            or (self.status == "verified") != complete
            or (self.status == "verified")
            == self.orphaned_owned_state_possible
            or self.cleanup_evidence_refs
            != tuple(sorted(set(self.cleanup_evidence_refs)))
            or any(
                not item.startswith("graph_bound_cleanup_evidence:")
                for item in self.cleanup_evidence_refs
            )
        ):
            raise ValueError("graph-bound cleanup result is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "cleanup_steps_attempted": self.cleanup_steps_attempted,
            "cleanup_steps_completed": self.cleanup_steps_completed,
            "cleanup_verifications_attempted": (
                self.cleanup_verifications_attempted
            ),
            "cleanup_verifications_completed": (
                self.cleanup_verifications_completed
            ),
            "ownership_grants_removed": self.ownership_grants_removed,
            "cleanup_evidence_refs": list(self.cleanup_evidence_refs),
            "orphaned_owned_state_possible": (
                self.orphaned_owned_state_possible
            ),
        }


@dataclass(frozen=True)
class GraphBoundPrerequisiteExecutionResult:
    receipt_id: str
    claim_contract_id: str
    plan_id: str
    family: str
    provisioning: GraphBoundFreshWorldProvisioningEvidence
    terminal_observations: Tuple[GraphBoundTerminalObservation, ...]
    oracle: GraphBoundPrerequisiteOracleEvaluation
    cleanup: GraphBoundExperimentCleanupResult
    provenance_root: str
    target_requests_sent: int
    finding_confirmed: bool
    status: str
    receipt_state: str = "completed"
    promotion_authority: bool = False
    finding_authority: bool = False

    def __post_init__(self) -> None:
        observations = self.terminal_observations
        expected_candidate_ref = (
            stable_hash(
                "graph_bound_prerequisite_candidate",
                {
                    "oracle_requirement_id": self.oracle.oracle_requirement_id,
                    "plan_id": self.plan_id,
                    "family": self.family,
                    "terminal_evidence_refs": [
                        item.evidence_ref for item in observations
                    ],
                    "effect_witness_ref": self.oracle.effect_witness_ref,
                    "verdict": self.oracle.verdict.value,
                },
            )
            if self.finding_confirmed
            else None
        )
        expected_requests = (
            self.provisioning.provisioning_request_units
            + len(observations)
            + self.cleanup.cleanup_steps_attempted
            + self.cleanup.cleanup_verifications_attempted
        )
        if (
            not self.receipt_id.startswith("behavioral-")
            or not self.claim_contract_id.startswith(
                "graph_bound_execution_claim_contract:"
            )
            or not self.plan_id.startswith("graph_bound_prepared_request_plan:")
            or self.family not in {"omission", "reordering"}
            or self.provisioning.claim_contract_id != self.claim_contract_id
            or self.provisioning.plan_id != self.plan_id
            or self.provisioning.family != self.family
            or tuple(item.world_role for item in observations) != _WORLD_ROLES
            or self.oracle.family != self.family
            or self.oracle.plan_id != self.plan_id
            or self.oracle.terminal_evidence_refs
            != tuple(item.evidence_ref for item in observations)
            or self.cleanup.status != "verified"
            or self.cleanup.orphaned_owned_state_possible
            or _PROVENANCE_ROOT.fullmatch(self.provenance_root) is None
            or isinstance(self.target_requests_sent, bool)
            or self.target_requests_sent != expected_requests
            or self.finding_confirmed
            != (
                self.family == "omission"
                and self.oracle.verdict
                is GraphBoundPrerequisiteOracleVerdict.CONFIRMED
                and self.oracle.independent_effect_witness_observed
            )
            or self.oracle.finding_candidate_ref != expected_candidate_ref
            or self.status != self.oracle.verdict.value
            or self.receipt_state != "completed"
            or self.promotion_authority
            or self.finding_authority
        ):
            raise ValueError("graph-bound prerequisite execution result is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "kind": GRAPH_BOUND_PREREQUISITE_EXECUTION_KIND,
            "mode": GRAPH_BOUND_PREREQUISITE_EXECUTION_MODE,
            "status": self.status,
            "receipt_id": self.receipt_id,
            "receipt_state": self.receipt_state,
            "claim_contract_id": self.claim_contract_id,
            "plan_id": self.plan_id,
            "family": self.family,
            "provisioning": self.provisioning.to_dict(),
            "terminal_observations": [
                item.to_dict() for item in self.terminal_observations
            ],
            "oracle": self.oracle.to_dict(),
            "oracle_verdict": self.oracle.verdict.value,
            "cleanup": self.cleanup.to_dict(),
            "provenance_root": self.provenance_root,
            "target_requests_sent": self.target_requests_sent,
            "finding_candidate_ref": self.oracle.finding_candidate_ref,
            "finding_confirmed": self.finding_confirmed,
            "adversarial_triage_required": True,
            "promotion_authority": self.promotion_authority,
            "finding_authority": self.finding_authority,
        }


    def execution_response(self) -> Dict[str, Any]:
        """Return the flat receipt-safe response used by one-click orchestration."""

        return {
            "schema_version": 1,
            "kind": GRAPH_BOUND_PREREQUISITE_EXECUTION_KIND,
            "mode": GRAPH_BOUND_PREREQUISITE_EXECUTION_MODE,
            "status": self.status,
            "receipt_id": self.receipt_id,
            "receipt_state": self.receipt_state,
            "claim_contract_id": self.claim_contract_id,
            "plan_id": self.plan_id,
            "family": self.family,
            "provisioning_id": self.provisioning.provisioning_id,
            "oracle_requirement_id": self.oracle.oracle_requirement_id,
            "reference_state_id": self.oracle.reference_state_id,
            "oracle_evaluation_id": self.oracle.evaluation_id,
            "oracle_verdict": self.oracle.verdict.value,
            "effect_witness_ref": self.oracle.effect_witness_ref,
            "runtime_value_inequality_ref": (
                self.oracle.runtime_value_inequality_ref
            ),
            "terminal_evidence_refs": [
                item.evidence_ref for item in self.terminal_observations
            ],
            "cleanup_evidence_refs": list(self.cleanup.cleanup_evidence_refs),
            "cleanup_status": self.cleanup.status,
            "cleanup_steps_attempted": self.cleanup.cleanup_steps_attempted,
            "cleanup_steps_completed": self.cleanup.cleanup_steps_completed,
            "cleanup_verifications_attempted": (
                self.cleanup.cleanup_verifications_attempted
            ),
            "cleanup_verifications_completed": (
                self.cleanup.cleanup_verifications_completed
            ),
            "ownership_grants_removed": self.cleanup.ownership_grants_removed,
            "target_requests_sent": self.target_requests_sent,
            "orphaned_owned_state_possible": (
                self.cleanup.orphaned_owned_state_possible
            ),
            "provenance_root": self.provenance_root,
            "finding_candidate_ref": self.oracle.finding_candidate_ref,
            "finding_confirmed": self.finding_confirmed,
            "finding": None,
            "adversarial_triage_required": True,
            "promotion_authority": False,
            "finding_authority": False,
        }


def _candidate(
    *,
    authority: _GraphBoundProvisioningAuthority,
    entry: _RuntimeEntry,
    request: Any,
    proof_goal: str,
) -> CandidateAction:
    runtime = authority.runtime_plan
    owned_target = entry.binding.action_class != OWNED_CREATE
    return CandidateAction(
        method=request.method,
        url=request.url,
        body=request.body,
        hint=entry.binding.action_class,
        actor_persona_id=runtime.actor_persona_id,
        target_owner_persona_id=(
            runtime.actor_persona_id if owned_target else None
        ),
        target_is_researcher_owned=(True if owned_target else None),
        expected_side_effect=entry.binding.expected_side_effect,
        proof_goal=proof_goal,
        budget_reservation_id=authority.budget_reservation_id,
    )


def _skip_current(authority: _GraphBoundProvisioningAuthority) -> None:
    budget = authority.runtime_plan.executor.policy.budget
    skipped = budget.skip_reservation_entries(
        authority.budget_reservation_id,
        1,
    )
    if skipped != 1:
        raise GraphBoundPrerequisiteExecutionDenied(
            "graph_bound_execution_budget_skip_mismatch",
            category="budget",
        )
    authority.note_budget_units(skipped)


async def _send(
    *,
    authority: _GraphBoundProvisioningAuthority,
    entry: _RuntimeEntry,
    request: Any,
    proof_goal: str,
) -> Tuple[int, Any]:
    runtime = authority.runtime_plan
    budget = runtime.executor.policy.budget
    before = budget.reservation_remaining(authority.budget_reservation_id)
    try:
        status, response = await runtime.executor.send_action(
            _candidate(
                authority=authority,
                entry=entry,
                request=request,
                proof_goal=proof_goal,
            ),
            headers=dict(request.headers),
        )
    except BaseException:
        after = budget.reservation_remaining(authority.budget_reservation_id)
        if after == before:
            _skip_current(authority)
        elif before - after == 1:
            authority.note_budget_units(1)
        else:
            raise GraphBoundPrerequisiteExecutionDenied(
                "graph_bound_execution_budget_consumption_mismatch",
                category="budget",
            )
        raise
    after = budget.reservation_remaining(authority.budget_reservation_id)
    consumed = before - after
    if status == DENIED_STATUS and consumed == 0:
        _skip_current(authority)
        raise GraphBoundPrerequisiteExecutionDenied(
            "graph_bound_execution_policy_denied",
            category="policy",
        )
    if consumed != 1:
        raise GraphBoundPrerequisiteExecutionDenied(
            "graph_bound_execution_budget_consumption_mismatch",
            category="budget",
        )
    authority.note_budget_units(consumed)
    return int(status), response


def _created_key(
    *,
    entry: _RuntimeEntry,
    created: Mapping[Tuple[str, str], _CreatedState],
) -> Optional[Tuple[str, str]]:
    return next(
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


def _cleanup_marker_observed(response: Any, cleanup_body: Any) -> bool:
    expected = cleanup_body
    if isinstance(expected, str):
        try:
            expected = json.loads(expected)
        except (TypeError, ValueError):
            return False
    actual = response
    if not isinstance(actual, Mapping):
        actual = getattr(response, "body", None)
    if isinstance(actual, str):
        try:
            actual = json.loads(actual)
        except (TypeError, ValueError):
            return False
    if not isinstance(actual, Mapping) or not isinstance(expected, Mapping):
        return False
    normalized = {str(key).lower(): value for key, value in actual.items()}
    return all(
        normalized.get(str(key).lower()) == value
        for key, value in expected.items()
    )


async def _cleanup_and_verify(
    *,
    authority: _GraphBoundProvisioningAuthority,
    cleanup_entries: Sequence[_RuntimeEntry],
    cleanup_verification_entries: Sequence[_RuntimeEntry],
    state: _ProvisioningState,
) -> Tuple[
    GraphBoundExperimentCleanupResult,
    Optional[asyncio.CancelledError],
]:
    runtime = authority.runtime_plan
    budget = runtime.executor.policy.budget
    reservation_id = authority.budget_reservation_id
    suffix_units = len(cleanup_entries) + len(cleanup_verification_entries)
    remaining = budget.reservation_remaining(reservation_id)
    if remaining < suffix_units:
        raise GraphBoundPrerequisiteExecutionDenied(
            "graph_bound_cleanup_budget_boundary_mismatch",
            category="budget",
        )
    if remaining > suffix_units:
        skipped = budget.skip_reservation_entries(
            reservation_id,
            remaining - suffix_units,
        )
        authority.note_budget_units(skipped)

    cleanup_attempted = 0
    cleanup_completed = 0
    verification_attempted = 0
    verification_completed = 0
    grants_removed = 0
    evidence_refs = []
    cleanup_bodies: Dict[str, Any] = {}
    orphaned = False
    cancellation: Optional[asyncio.CancelledError] = None

    for entry in cleanup_entries:
        create_key = _created_key(entry=entry, created=state.created)
        if create_key is None:
            _skip_current(authority)
            continue
        cleanup_attempted += 1
        status: Optional[int] = None
        try:
            request = _rehydrate(entry, state.runtime_values)
            registry = runtime.executor.policy.ownership_registry
            if registry is None or not registry.is_owned(request.url):
                raise GraphBoundPrerequisiteExecutionDenied(
                    "graph_bound_cleanup_target_not_registered",
                    category="ownership",
                )
            status, _response = await _send(
                authority=authority,
                entry=entry,
                request=request,
                proof_goal="graph_bound_prerequisite_cleanup",
            )
            cleanup_bodies[entry.binding.world_role] = request.body
            if 200 <= status < 300:
                cleanup_completed += 1
            else:
                orphaned = True
        except asyncio.CancelledError as exc:
            cancellation = cancellation or exc
            orphaned = True
        except Exception:
            orphaned = True
        evidence_refs.append(
            stable_hash(
                "graph_bound_cleanup_evidence",
                {
                    "binding_id": entry.binding.binding_id,
                    "world_role": entry.binding.world_role,
                    "stage": "cleanup",
                    "status": status,
                },
            )
        )

    for entry in cleanup_verification_entries:
        create_key = _created_key(entry=entry, created=state.created)
        if create_key is None:
            _skip_current(authority)
            continue
        verification_attempted += 1
        status: Optional[int] = None
        verified = False
        try:
            request = _rehydrate(entry, state.runtime_values)
            _require_owned_dependencies(
                entry=entry,
                state=state,
                create_operation_ids=frozenset(
                    key[1] for key in state.created
                ),
                runtime_plan=runtime,
            )
            status, response = await _send(
                authority=authority,
                entry=entry,
                request=request,
                proof_goal="graph_bound_prerequisite_cleanup_verification",
            )
            truncated = bool(getattr(response, "body_truncated", False))
            verified = not truncated and (
                status in _CLEANUP_TERMINAL_STATUSES
                or (
                    200 <= status < 300
                    and _cleanup_marker_observed(
                        response,
                        cleanup_bodies.get(entry.binding.world_role),
                    )
                )
            )
            if verified:
                verification_completed += 1
                registry = runtime.executor.policy.ownership_registry
                created = state.created[create_key]
                if registry is not None and registry.unregister_created_value(
                    created.create_url,
                    created.object_id,
                    actor_persona=runtime.actor_persona_id,
                ):
                    grants_removed += 1
                else:
                    verified = False
                    orphaned = True
            else:
                orphaned = True
        except asyncio.CancelledError as exc:
            cancellation = cancellation or exc
            orphaned = True
        except Exception:
            orphaned = True
        evidence_refs.append(
            stable_hash(
                "graph_bound_cleanup_evidence",
                {
                    "binding_id": entry.binding.binding_id,
                    "world_role": entry.binding.world_role,
                    "stage": "cleanup_verification",
                    "status": status,
                    "verified": verified,
                },
            )
        )

    if budget.reservation_remaining(reservation_id) != 0:
        orphaned = True
        remaining = budget.reservation_remaining(reservation_id)
        skipped = budget.skip_reservation_entries(reservation_id, remaining)
        if skipped:
            authority.note_budget_units(skipped)
    verified_all = (
        cleanup_attempted
        == cleanup_completed
        == verification_attempted
        == verification_completed
        == grants_removed
        == 3
        and not orphaned
    )
    return (
        GraphBoundExperimentCleanupResult(
            status=("verified" if verified_all else "uncertain"),
            cleanup_steps_attempted=cleanup_attempted,
            cleanup_steps_completed=cleanup_completed,
            cleanup_verifications_attempted=verification_attempted,
            cleanup_verifications_completed=verification_completed,
            ownership_grants_removed=grants_removed,
            cleanup_evidence_refs=tuple(sorted(evidence_refs)),
            orphaned_owned_state_possible=not verified_all,
        ),
        cancellation,
    )


def _execution_outcome(
    *,
    claim: GraphBoundExecutionClaim,
    authority: _GraphBoundProvisioningAuthority,
    provisioning: GraphBoundFreshWorldProvisioningEvidence,
    observations: Sequence[GraphBoundTerminalObservation],
    oracle: GraphBoundPrerequisiteOracleEvaluation,
    cleanup: GraphBoundExperimentCleanupResult,
    provenance_root: str,
    target_requests_sent: int,
) -> Dict[str, Any]:
    finding_confirmed = (
        oracle.verdict is GraphBoundPrerequisiteOracleVerdict.CONFIRMED
        and authority.runtime_plan.plan.family == "omission"
    )
    return {
        "kind": GRAPH_BOUND_PREREQUISITE_EXECUTION_KIND,
        "mode": GRAPH_BOUND_PREREQUISITE_EXECUTION_MODE,
        "status": oracle.verdict.value,
        "receipt_state": "completed",
        "claim_contract_id": claim.contract.contract_id,
        "plan_id": authority.runtime_plan.plan.plan_id,
        "family": authority.runtime_plan.plan.family,
        "provisioning_id": provisioning.provisioning_id,
        "oracle_requirement_id": authority.runtime_plan.oracle_requirement_id,
        "reference_state_id": authority.runtime_plan.reference_state_id,
        "oracle_evaluation_id": oracle.evaluation_id,
        "oracle_verdict": oracle.verdict.value,
        "effect_witness_ref": oracle.effect_witness_ref,
        "runtime_value_inequality_ref": oracle.runtime_value_inequality_ref,
        "terminal_evidence_refs": [
            item.evidence_ref for item in observations
        ],
        "cleanup_evidence_refs": list(cleanup.cleanup_evidence_refs),
        "cleanup_status": cleanup.status,
        "cleanup_steps_attempted": cleanup.cleanup_steps_attempted,
        "cleanup_steps_completed": cleanup.cleanup_steps_completed,
        "cleanup_verifications_attempted": (
            cleanup.cleanup_verifications_attempted
        ),
        "cleanup_verifications_completed": (
            cleanup.cleanup_verifications_completed
        ),
        "ownership_grants_removed": cleanup.ownership_grants_removed,
        "orphaned_owned_state_possible": (
            cleanup.orphaned_owned_state_possible
        ),
        "provenance_root": provenance_root,
        "target_requests_sent": target_requests_sent,
        "finding_candidate_ref": oracle.finding_candidate_ref,
        "finding_confirmed": finding_confirmed,
        "adversarial_triage_required": True,
        "promotion_authority": False,
        "finding_authority": False,
    }


class GraphBoundPrerequisiteExperimentExecutor:
    """One-use R5B3b2c coordinator; importing it grants no authority."""

    def __init__(
        self,
        claim: GraphBoundExecutionClaim,
        *,
        config: Optional[GraphBoundPrerequisiteExecutionConfig] = None,
    ) -> None:
        if not isinstance(claim, GraphBoundExecutionClaim):
            raise TypeError("claim must be a GraphBoundExecutionClaim")
        if config is not None and not isinstance(
            config,
            GraphBoundPrerequisiteExecutionConfig,
        ):
            raise TypeError(
                "config must be a GraphBoundPrerequisiteExecutionConfig"
            )
        self.claim = claim
        self.config = (
            config
            if config is not None
            else GraphBoundPrerequisiteExecutionConfig.from_environment()
        )
        self._lock = asyncio.Lock()
        self._consumed = False

    async def _abort_after_failure(
        self,
        *,
        authority: _GraphBoundProvisioningAuthority,
        cleanup_entries: Sequence[_RuntimeEntry],
        cleanup_verification_entries: Sequence[_RuntimeEntry],
        state: _ProvisioningState,
        error: BaseException,
    ) -> GraphBoundExperimentCleanupResult:
        try:
            cleanup, cleanup_cancellation = await _cleanup_and_verify(
                authority=authority,
                cleanup_entries=cleanup_entries,
                cleanup_verification_entries=cleanup_verification_entries,
                state=state,
            )
        except BaseException as cleanup_error:
            cleanup = GraphBoundExperimentCleanupResult(
                status="uncertain",
                cleanup_steps_attempted=0,
                cleanup_steps_completed=0,
                cleanup_verifications_attempted=0,
                cleanup_verifications_completed=0,
                ownership_grants_removed=0,
                cleanup_evidence_refs=(),
                orphaned_owned_state_possible=True,
            )
            cleanup_cancellation = (
                cleanup_error
                if isinstance(cleanup_error, asyncio.CancelledError)
                else None
            )
        if authority.state not in {"aborted", "completed"}:
            reason = (
                "graph_bound_experiment_orphan_risk"
                if cleanup.orphaned_owned_state_possible
                else "graph_bound_experiment_execution_failed"
            )
            try:
                authority.abort(
                    expected_state=authority.state,
                    reason=reason,
                )
            except GraphBoundExecutionClaimDenied as exc:
                raise GraphBoundPrerequisiteExecutionDenied(
                    str(exc),
                    category=exc.category,
                    cleanup=cleanup,
                ) from exc
        if isinstance(error, asyncio.CancelledError):
            raise error
        if cleanup_cancellation is not None:
            raise cleanup_cancellation
        if isinstance(error, GraphBoundPrerequisiteExecutionDenied):
            raise GraphBoundPrerequisiteExecutionDenied(
                str(error),
                category=error.category,
                cleanup=cleanup,
            ) from error
        if isinstance(error, GraphBoundFreshWorldProvisioningDenied):
            raise GraphBoundPrerequisiteExecutionDenied(
                str(error),
                category=error.category,
                cleanup=cleanup,
            ) from error
        raise GraphBoundPrerequisiteExecutionDenied(
            "graph_bound_prerequisite_execution_failed",
            cleanup=cleanup,
        ) from error

    async def execute(self) -> GraphBoundPrerequisiteExecutionResult:
        async with self._lock:
            if self._consumed:
                raise GraphBoundPrerequisiteExecutionDenied(
                    "graph_bound_prerequisite_executor_already_consumed",
                    category="claim",
                )
            if not self.config.enabled:
                raise GraphBoundPrerequisiteExecutionDenied(
                    "graph_bound_prerequisite_execution_is_disabled",
                    category="configuration",
                )
            self._consumed = True
            try:
                authority = self.claim._begin_provisioning()
            except GraphBoundExecutionClaimDenied as exc:
                raise GraphBoundPrerequisiteExecutionDenied(
                    str(exc),
                    category=exc.category,
                ) from exc

            state = _ProvisioningState()
            try:
                _validate_runtime_authority(authority.runtime_plan)
                provision, dispatch, cleanup_entries, verification_entries = (
                    _runtime_entries(authority.runtime_plan)
                )
                await _execute_provisioning_prefix(
                    authority=authority,
                    provision_entries=provision,
                    state=state,
                )
                provisioning = _build_provisioning_evidence(
                    claim_contract_id=self.claim.contract.contract_id,
                    authority=authority,
                    provision_entries=provision,
                    dispatch_entries=dispatch,
                    cleanup_entries=cleanup_entries,
                    cleanup_verification_entries=verification_entries,
                    state=state,
                )
                authority.mark_provisioned()
                _validate_runtime_authority(authority.runtime_plan)
                authority.begin_execution()
            except BaseException as exc:
                await self._abort_after_failure(
                    authority=authority,
                    cleanup_entries=(
                        cleanup_entries if "cleanup_entries" in locals() else ()
                    ),
                    cleanup_verification_entries=(
                        verification_entries
                        if "verification_entries" in locals()
                        else ()
                    ),
                    state=state,
                    error=exc,
                )

            observations = []
            terminal_error: Optional[BaseException] = None
            create_operation_ids = frozenset(key[1] for key in state.created)
            try:
                for entry in dispatch:
                    runtime_value_inequality_ref = (
                        _runtime_override_inequality_attestation(
                            entry,
                            state.runtime_values,
                        )
                    )
                    request = _rehydrate(entry, state.runtime_values)
                    _require_owned_dependencies(
                        entry=entry,
                        state=state,
                        create_operation_ids=create_operation_ids,
                        runtime_plan=authority.runtime_plan,
                    )
                    status, response = await _send(
                        authority=authority,
                        entry=entry,
                        request=request,
                        proof_goal="graph_bound_prerequisite_terminal",
                    )
                    if bool(getattr(response, "body_truncated", False)):
                        raise GraphBoundPrerequisiteExecutionDenied(
                            "graph_bound_terminal_response_truncated",
                            category="oracle",
                        )
                    observations.append(
                        GraphBoundTerminalObservation.build(
                            entry=entry,
                            status=status,
                            response=response,
                            reference_status=(
                                authority.runtime_plan.reference_response_status
                            ),
                            reference_body_hash=(
                                authority.runtime_plan.reference_response_body_hash
                            ),
                            runtime_value_inequality_ref=(
                                runtime_value_inequality_ref
                            ),
                        )
                    )
                observations = sorted(
                    observations,
                    key=lambda item: _WORLD_ROLES.index(item.world_role),
                )
                oracle = GraphBoundPrerequisiteOracleEvaluation.build(
                    oracle_requirement_id=(
                        authority.runtime_plan.oracle_requirement_id
                    ),
                    plan_id=authority.runtime_plan.plan.plan_id,
                    reference_state_id=(
                        authority.runtime_plan.reference_state_id
                    ),
                    family=authority.runtime_plan.plan.family,
                    observations=observations,
                )
            except BaseException as exc:
                terminal_error = exc

            try:
                cleanup, cleanup_cancellation = await _cleanup_and_verify(
                    authority=authority,
                    cleanup_entries=cleanup_entries,
                    cleanup_verification_entries=verification_entries,
                    state=state,
                )
            except BaseException as cleanup_error:
                cleanup = GraphBoundExperimentCleanupResult(
                    status="uncertain",
                    cleanup_steps_attempted=0,
                    cleanup_steps_completed=0,
                    cleanup_verifications_attempted=0,
                    cleanup_verifications_completed=0,
                    ownership_grants_removed=0,
                    cleanup_evidence_refs=(),
                    orphaned_owned_state_possible=True,
                )
                cleanup_cancellation = (
                    cleanup_error
                    if isinstance(cleanup_error, asyncio.CancelledError)
                    else None
                )
                if terminal_error is None:
                    terminal_error = cleanup_error
            if cleanup_cancellation is not None:
                terminal_error = cleanup_cancellation
            if terminal_error is not None:
                reason = (
                    "graph_bound_experiment_orphan_risk"
                    if cleanup.orphaned_owned_state_possible
                    else "graph_bound_experiment_terminal_failed"
                )
                try:
                    authority.abort(
                        expected_state=authority.state,
                        reason=reason,
                    )
                except GraphBoundExecutionClaimDenied as exc:
                    raise GraphBoundPrerequisiteExecutionDenied(
                        str(exc),
                        category=exc.category,
                        cleanup=cleanup,
                    ) from exc
                if isinstance(terminal_error, asyncio.CancelledError):
                    raise terminal_error
                if isinstance(
                    terminal_error,
                    GraphBoundPrerequisiteExecutionDenied,
                ):
                    raise GraphBoundPrerequisiteExecutionDenied(
                        str(terminal_error),
                        category=terminal_error.category,
                        cleanup=cleanup,
                    ) from terminal_error
                raise GraphBoundPrerequisiteExecutionDenied(
                    "graph_bound_prerequisite_terminal_failed",
                    cleanup=cleanup,
                ) from terminal_error
            if cleanup.status != "verified":
                try:
                    authority.abort(
                        expected_state=authority.state,
                        reason="graph_bound_experiment_cleanup_unverified",
                    )
                except GraphBoundExecutionClaimDenied as exc:
                    raise GraphBoundPrerequisiteExecutionDenied(
                        str(exc),
                        category=exc.category,
                        cleanup=cleanup,
                    ) from exc
                raise GraphBoundPrerequisiteExecutionDenied(
                    "graph_bound_experiment_cleanup_unverified",
                    category="cleanup",
                    cleanup=cleanup,
                )

            sink = authority.runtime_plan.executor.provenance
            provenance_root = sink.root() if sink is not None else None
            if (
                sink is None
                or not sink.verify()
                or not isinstance(provenance_root, str)
                or _PROVENANCE_ROOT.fullmatch(provenance_root) is None
            ):
                try:
                    authority.abort(
                        expected_state=authority.state,
                        reason="graph_bound_experiment_provenance_invalid",
                    )
                except GraphBoundExecutionClaimDenied as exc:
                    raise GraphBoundPrerequisiteExecutionDenied(
                        str(exc),
                        category=exc.category,
                        cleanup=cleanup,
                    ) from exc
                raise GraphBoundPrerequisiteExecutionDenied(
                    "graph_bound_experiment_provenance_invalid",
                    category="provenance",
                    cleanup=cleanup,
                )

            target_requests_sent = (
                provisioning.provisioning_request_units
                + len(observations)
                + cleanup.cleanup_steps_attempted
                + cleanup.cleanup_verifications_attempted
            )
            outcome = _execution_outcome(
                claim=self.claim,
                authority=authority,
                provisioning=provisioning,
                observations=observations,
                oracle=oracle,
                cleanup=cleanup,
                provenance_root=provenance_root,
                target_requests_sent=target_requests_sent,
            )
            try:
                receipt = authority.complete(outcome=outcome)
            except GraphBoundExecutionClaimDenied as exc:
                abort_error: Optional[GraphBoundExecutionClaimDenied] = None
                if authority.state not in {"aborted", "completed"}:
                    try:
                        authority.abort(
                            expected_state=authority.state,
                            reason="graph_bound_experiment_receipt_completion_failed",
                        )
                    except GraphBoundExecutionClaimDenied as abort_exc:
                        abort_error = abort_exc
                if authority.state not in {"aborted", "completed"}:
                    raise GraphBoundPrerequisiteExecutionDenied(
                        "graph_bound_experiment_receipt_terminalization_failed",
                        category="receipt",
                        cleanup=cleanup,
                    ) from abort_error
                raise GraphBoundPrerequisiteExecutionDenied(
                    str(exc),
                    category=exc.category,
                    cleanup=cleanup,
                ) from exc
            finding_confirmed = bool(outcome["finding_confirmed"])
            return GraphBoundPrerequisiteExecutionResult(
                receipt_id=receipt.receipt_id,
                claim_contract_id=self.claim.contract.contract_id,
                plan_id=authority.runtime_plan.plan.plan_id,
                family=authority.runtime_plan.plan.family,
                provisioning=provisioning,
                terminal_observations=tuple(observations),
                oracle=oracle,
                cleanup=cleanup,
                provenance_root=provenance_root,
                target_requests_sent=target_requests_sent,
                finding_confirmed=finding_confirmed,
                status=oracle.verdict.value,
            )


__all__ = [
    "GRAPH_BOUND_PREREQUISITE_EXECUTION_ENV",
    "GRAPH_BOUND_PREREQUISITE_EXECUTION_KIND",
    "GRAPH_BOUND_PREREQUISITE_EXECUTION_MODE",
    "GraphBoundExperimentCleanupResult",
    "GraphBoundPrerequisiteExecutionConfig",
    "GraphBoundPrerequisiteExecutionDenied",
    "GraphBoundPrerequisiteExecutionResult",
    "GraphBoundPrerequisiteExperimentExecutor",
    "GraphBoundPrerequisiteOracleEvaluation",
    "GraphBoundPrerequisiteOracleVerdict",
    "GraphBoundTerminalObservation",
]
