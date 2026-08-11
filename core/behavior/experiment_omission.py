"""R4C2 adapter for one admitted prerequisite-omission experiment.

The adapter consumes an R4B claim through the existing fresh-state confirmation
backend.  It preserves the valid baseline, single omitted binding, wrong-object
control, researcher-owned state, cleanup, and independent cleanup verification.
Every output remains non-promoting and requires adversarial triage.
"""

from __future__ import annotations

import asyncio
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple

from core.cortex.execution_policy import CandidateAction
from core.foundry.vault import PersonaVault
from core.replay.models import MerkleBlock
from core.safety.proof_budget import endpoint_key

from .experiment_admission import (
    ExperimentRuntimeActionBinding,
    ExperimentRuntimeWorldBinding,
    ProofExperimentAdmissionClaim,
    ProofExperimentAdmissionDenied,
    experiment_authority_context_ref,
)
from .experiment_sdk import (
    CleanupOutcome,
    ExistingBackendKind,
    ExperimentActionClass,
    ExperimentControlKind,
    ExperimentOracleEvaluation,
    ExperimentPhase,
    ExperimentWorldKind,
    MutationExpectation,
    OracleVerdict,
    ProofExperimentManifest,
)
from .normalize import stable_hash
from .omission_confirmation import (
    AdmittedFreshOmissionExecutionResult,
    FreshOmissionConfirmationExecutor,
)
from .payout_goals import ProofTopology, SecurityProperty


PROOF_EXPERIMENT_OMISSION_ENV = (
    "SENTINELFORGE_BEHAVIOR_PROOF_EXPERIMENT_OMISSION"
)
PROOF_EXPERIMENT_OMISSION_MODE = "behavioral_proof_experiment_omission_v1"

_TRUE = frozenset({"1", "true", "yes", "on"})
_HASH_REF = re.compile(r"^[a-z][a-z0-9_]*:[0-9a-f]{64}$")
_RECEIPT_ID = re.compile(r"^behavioral-[0-9a-f]{64}$")
_CONCLUSIVE_CONFIRMATIONS = frozenset(
    {"confirmed_fail_open", "omission_rejected"}
)
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
    return bool(
        isinstance(value, str)
        and value.startswith(f"{prefix}:")
        and _HASH_REF.fullmatch(value) is not None
    )


class AdmittedOmissionExperimentDenied(RuntimeError):
    """The admitted omission identity or current runtime no longer matches."""


@dataclass(frozen=True)
class AdmittedOmissionExperimentConfig:
    enabled: bool = False

    @classmethod
    def from_environment(cls) -> "AdmittedOmissionExperimentConfig":
        return cls(
            enabled=(
                os.environ.get(PROOF_EXPERIMENT_OMISSION_ENV, "")
                .strip()
                .lower()
                in _TRUE
            )
        )


@dataclass(frozen=True)
class AdmittedOmissionExperimentResult:
    manifest_id: str
    admission_id: str
    receipt_id: str
    status: str
    legacy_verdict: str
    oracle_evaluation: ExperimentOracleEvaluation
    requests_attempted: int
    requests_sent: int
    policy_denials: int
    reserved_units_released: int
    total_request_units: int
    creates_attempted: int
    creates_completed: int
    cleanup_steps_attempted: int
    cleanup_steps_completed: int
    cleanup_verifications_attempted: int
    cleanup_verifications_completed: int
    orphaned_owned_state_possible: bool
    finding_candidate_ref: Optional[str]
    provenance_root: str
    mode: str = PROOF_EXPERIMENT_OMISSION_MODE
    adversarial_triage_required: bool = True
    promotion_authority: bool = False
    finding_authority: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.oracle_evaluation, ExperimentOracleEvaluation):
            raise ValueError("admitted omission result contract is invalid")
        expected_status = (
            "aborted"
            if self.oracle_evaluation.verdict is OracleVerdict.INCONCLUSIVE
            else "completed"
        )
        counters = (
            self.requests_attempted,
            self.requests_sent,
            self.policy_denials,
            self.reserved_units_released,
            self.total_request_units,
            self.creates_attempted,
            self.creates_completed,
            self.cleanup_steps_attempted,
            self.cleanup_steps_completed,
            self.cleanup_verifications_attempted,
            self.cleanup_verifications_completed,
        )
        if (
            self.mode != PROOF_EXPERIMENT_OMISSION_MODE
            or not _hash_ref(self.manifest_id, "proof_experiment_manifest")
            or not _hash_ref(self.admission_id, "proof_experiment_admission")
            or not isinstance(self.receipt_id, str)
            or _RECEIPT_ID.fullmatch(self.receipt_id) is None
            or self.status != expected_status
            or self.legacy_verdict not in _CONFIRMATION_STATUSES
            or self.oracle_evaluation.manifest_id != self.manifest_id
            or self.oracle_evaluation.backend_receipt_ref
            != stable_hash("behavioral_receipt", self.receipt_id)
            or self.provenance_root != self.oracle_evaluation.provenance_root
            or any(
                isinstance(value, bool) or not isinstance(value, int) or value < 0
                for value in counters
            )
            or self.requests_sent > self.requests_attempted
            or self.requests_sent + self.reserved_units_released
            != self.total_request_units
            or not 0 < self.total_request_units <= 64
            or self.creates_completed > self.creates_attempted
            or self.creates_attempted > 3
            or self.cleanup_steps_completed > self.cleanup_steps_attempted
            or self.cleanup_steps_attempted > 3
            or self.cleanup_verifications_completed
            > self.cleanup_verifications_attempted
            or self.cleanup_verifications_attempted > 3
            or self.policy_denials > self.requests_attempted
            or not isinstance(self.orphaned_owned_state_possible, bool)
            or (
                self.finding_candidate_ref is not None
                and not _hash_ref(
                    self.finding_candidate_ref,
                    "proof_experiment_finding_candidate",
                )
            )
            or (
                self.oracle_evaluation.verdict is OracleVerdict.CONFIRMED
                and (
                    self.legacy_verdict != "confirmed_fail_open"
                    or self.finding_candidate_ref is None
                )
            )
            or (
                self.oracle_evaluation.verdict is OracleVerdict.REFUTED
                and self.legacy_verdict != "omission_rejected"
            )
            or (
                self.oracle_evaluation.verdict is not OracleVerdict.CONFIRMED
                and self.finding_candidate_ref is not None
            )
            or not self.oracle_evaluation.cleanup_required
            or not self.adversarial_triage_required
            or self.promotion_authority
            or self.finding_authority
        ):
            raise ValueError("admitted omission result contract is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": 1,
            "mode": self.mode,
            "manifest_id": self.manifest_id,
            "admission_id": self.admission_id,
            "receipt_id": self.receipt_id,
            "status": self.status,
            "legacy_verdict": self.legacy_verdict,
            "oracle_evaluation": self.oracle_evaluation.to_dict(),
            "requests_attempted": self.requests_attempted,
            "requests_sent": self.requests_sent,
            "policy_denials": self.policy_denials,
            "reserved_units_released": self.reserved_units_released,
            "total_request_units": self.total_request_units,
            "creates_attempted": self.creates_attempted,
            "creates_completed": self.creates_completed,
            "cleanup_steps_attempted": self.cleanup_steps_attempted,
            "cleanup_steps_completed": self.cleanup_steps_completed,
            "cleanup_verifications_attempted": (
                self.cleanup_verifications_attempted
            ),
            "cleanup_verifications_completed": (
                self.cleanup_verifications_completed
            ),
            "orphaned_owned_state_possible": (
                self.orphaned_owned_state_possible
            ),
            "finding_candidate_ref": self.finding_candidate_ref,
            "provenance_root": self.provenance_root,
            "adversarial_triage_required": self.adversarial_triage_required,
            "promotion_authority": self.promotion_authority,
            "finding_authority": self.finding_authority,
        }


@dataclass(frozen=True)
class _OmissionAdapterPreflight:
    boundary_id: str
    actions: Tuple[CandidateAction, ...]
    action_bindings: Tuple[ExperimentRuntimeActionBinding, ...]
    execution_policy_digest: str
    budget_reservation_id: str = field(repr=False, compare=False)
    runtime_claim_token: str = field(repr=False, compare=False)


class AdmittedOmissionExperimentExecutor:
    """Consume one R4B claim through the fresh-state omission backend."""

    def __init__(
        self,
        *,
        manifest: ProofExperimentManifest,
        claim: ProofExperimentAdmissionClaim,
        backend: FreshOmissionConfirmationExecutor,
        persona_vault: PersonaVault,
        world_attestation_refs: Sequence[str],
        config: Optional[AdmittedOmissionExperimentConfig] = None,
    ) -> None:
        if not isinstance(manifest, ProofExperimentManifest):
            raise TypeError("manifest must be a ProofExperimentManifest")
        if not isinstance(claim, ProofExperimentAdmissionClaim):
            raise TypeError("claim must be a ProofExperimentAdmissionClaim")
        if not isinstance(backend, FreshOmissionConfirmationExecutor):
            raise TypeError("backend must be a FreshOmissionConfirmationExecutor")
        if not isinstance(persona_vault, PersonaVault):
            raise TypeError("persona_vault must be a PersonaVault")
        refs = tuple(sorted(set(world_attestation_refs)))
        if refs != tuple(world_attestation_refs) or any(
            not isinstance(item, str) or not _HASH_REF.fullmatch(item)
            for item in refs
        ):
            raise ValueError("world_attestation_refs must be canonical hash refs")
        self.manifest = manifest
        self.claim = claim
        self.backend = backend
        self.persona_vault = persona_vault
        self.world_attestation_refs = refs
        self.config = config or AdmittedOmissionExperimentConfig.from_environment()
        self._lock = asyncio.Lock()
        self._consumed = False

    def _validate_manifest_shape(self) -> None:
        experiment = self.backend.experiment
        actions = self.manifest.actions
        baseline_count = len(experiment.baseline_operation_ids)
        omission_count = len(experiment.omission_operation_ids)
        cleanup_start = baseline_count + 2 * omission_count
        verification_start = cleanup_start + 3
        lifecycle = self.backend._preflight(
            admitted=True,
            cleanup_verification_count=3,
        ).lifecycle
        expected_operations = (
            *experiment.baseline_operation_ids,
            *experiment.omission_operation_ids,
            *experiment.omission_operation_ids,
            *(lifecycle.cleanup_operation_id for _ in range(3)),
            *(experiment.terminal_operation_id for _ in range(3)),
        )
        expected_phases = (
            *(ExperimentPhase.CONTROL for _ in range(baseline_count)),
            *(ExperimentPhase.TREATMENT for _ in range(omission_count)),
            *(ExperimentPhase.WITNESS for _ in range(omission_count)),
            *(ExperimentPhase.CLEANUP for _ in range(3)),
            *(ExperimentPhase.CLEANUP_VERIFICATION for _ in range(3)),
        )
        create_operation = experiment.baseline_operation_ids[0]
        expected_classes = tuple(
            (
                ExperimentActionClass.OWNED_CREATE
                if operation_id == create_operation
                else (
                    ExperimentActionClass.OWNED_UPDATE_LOW_RISK
                    if phase is ExperimentPhase.CLEANUP
                    else ExperimentActionClass.SAFE_READ
                )
            )
            for operation_id, phase in zip(
                expected_operations,
                expected_phases,
                strict=True,
            )
        )
        world_bindings = self.manifest.world_manifest.bindings
        if len(world_bindings) != 1:
            raise AdmittedOmissionExperimentDenied(
                "omission_manifest_world_topology_mismatch"
            )
        world = world_bindings[0]
        if (
            self.manifest.backend.backend
            is not ExistingBackendKind.PREREQUISITE_OMISSION
            or self.manifest.backend.source_contract_ref != experiment.experiment_id
            or self.manifest.world_manifest.requirement.topology
            is not ProofTopology.CONTROLLED_LIFECYCLE
            or world.kind is not ExperimentWorldKind.OWNED_ACCOUNT
            or world.slot != "actor"
            or world.world_ref != experiment.world_ref
            or world.lifecycle_ref != experiment.lifecycle_id
            or tuple(item.operation_id for item in actions) != expected_operations
            or tuple(item.phase for item in actions) != expected_phases
            or tuple(item.action_class for item in actions) != expected_classes
            or any(item.world_binding_id != world.binding_id for item in actions)
            or self.manifest.oracle.security_property
            is not SecurityProperty.PREREQUISITE_ENFORCEMENT
            or self.manifest.oracle.comparison_kind
            != "fresh_prerequisite_omission"
        ):
            raise AdmittedOmissionExperimentDenied(
                "omission_manifest_backend_contract_mismatch"
            )

        create_indices = tuple(
            index
            for index, action in enumerate(actions)
            if action.action_class is ExperimentActionClass.OWNED_CREATE
        )
        expected_create_indices = (
            0,
            baseline_count,
            baseline_count + omission_count,
        )
        if (
            create_indices != expected_create_indices
            or any(
                actions[index].mutation is not MutationExpectation.OWNED_CREATE
                for index in create_indices
            )
            or any(
                actions[index].mutation is not MutationExpectation.CLEANUP
                for index in range(cleanup_start, verification_start)
            )
            or any(
                actions[index].mutation is not MutationExpectation.NONE
                for index in (
                    *(
                        value
                        for value in range(cleanup_start)
                        if value not in create_indices
                    ),
                    *range(verification_start, len(actions)),
                )
            )
        ):
            raise AdmittedOmissionExperimentDenied(
                "omission_manifest_mutation_contract_mismatch"
            )

        controls = self.manifest.controls
        baseline_ids = tuple(
            item.action_id for item in actions[:baseline_count]
        )
        treatment_ids = tuple(
            item.action_id
            for item in actions[baseline_count : baseline_count + omission_count]
        )
        witness_ids = tuple(
            item.action_id
            for item in actions[
                baseline_count + omission_count : cleanup_start
            ]
        )
        if (
            len(controls) != 1
            or controls[0].kind is not ExperimentControlKind.VALID_SEQUENCE_BASELINE
            or set(controls[0].action_ids) != set(baseline_ids)
            or controls[0].world_binding_ids != (world.binding_id,)
            or self.manifest.oracle.control_ids != (controls[0].control_id,)
            or set(self.manifest.oracle.treatment_action_ids) != set(treatment_ids)
            or set(self.manifest.oracle.witness_action_ids) != set(witness_ids)
        ):
            raise AdmittedOmissionExperimentDenied(
                "omission_manifest_control_topology_mismatch"
            )

        expected_cleanup = {
            (
                actions[expected_create_indices[2]].action_id,
                actions[cleanup_start].action_id,
                actions[verification_start].action_id,
            ),
            (
                actions[expected_create_indices[1]].action_id,
                actions[cleanup_start + 1].action_id,
                actions[verification_start + 1].action_id,
            ),
            (
                actions[expected_create_indices[0]].action_id,
                actions[cleanup_start + 2].action_id,
                actions[verification_start + 2].action_id,
            ),
        }
        actual_cleanup = {
            (
                item.mutation_action_id,
                item.cleanup_action_id,
                item.verification_action_id,
            )
            for item in self.manifest.cleanup.bindings
        }
        if (
            not self.manifest.cleanup.required
            or actual_cleanup != expected_cleanup
        ):
            raise AdmittedOmissionExperimentDenied(
                "omission_manifest_cleanup_topology_mismatch"
            )

    def _preflight(self) -> _OmissionAdapterPreflight:
        if not self.config.enabled:
            raise AdmittedOmissionExperimentDenied(
                "proof_experiment_omission_is_disabled"
            )
        if self.claim.state != "claimed":
            raise AdmittedOmissionExperimentDenied(
                "proof_experiment_omission_claim_is_not_active"
            )
        contract = self.claim.contract
        if (
            contract.manifest_id != self.manifest.manifest_id
            or contract.backend is not ExistingBackendKind.PREREQUISITE_OMISSION
            or contract.required_workflows != self.backend.required_workflows
            or contract.authority_context_ref != self.manifest.authority_context_ref
            or contract.budget_id != self.manifest.budget.budget_id
            or contract.total_request_units != len(self.manifest.actions)
        ):
            raise AdmittedOmissionExperimentDenied(
                "proof_experiment_omission_claim_identity_mismatch"
            )
        self._validate_manifest_shape()
        boundary_id = self.backend.validate_admitted_preflight()
        expected_context = experiment_authority_context_ref(
            self.backend.authorization,
            self.backend.target_origin,
            self.backend.required_workflows,
        )
        if expected_context != contract.authority_context_ref:
            raise AdmittedOmissionExperimentDenied(
                "proof_experiment_omission_authority_changed"
            )
        sink = self.backend.executor.provenance
        if sink is None or not sink.verify():
            raise AdmittedOmissionExperimentDenied(
                "proof_experiment_omission_provenance_is_invalid"
            )
        execution_policy_digest = self.backend.executor.policy.digest()
        if execution_policy_digest != contract.execution_policy_digest:
            raise AdmittedOmissionExperimentDenied(
                "proof_experiment_omission_policy_changed"
            )
        persona = self.persona_vault.get_persona(self.backend.actor_persona_id)
        if persona is None or persona.persona_id != self.backend.actor_persona_id:
            raise AdmittedOmissionExperimentDenied(
                "proof_experiment_omission_persona_is_not_in_vault"
            )
        world = self.manifest.world_manifest.bindings[0]
        if self.world_attestation_refs != (self.backend.experiment.lifecycle_id,):
            raise AdmittedOmissionExperimentDenied(
                "proof_experiment_omission_lifecycle_attestation_changed"
            )
        runtime_world = ExperimentRuntimeWorldBinding.bind(
            manifest_binding=world,
            runtime_identity=self.backend.actor_persona_id,
            authorization=self.backend.authorization,
            attestation_refs=self.world_attestation_refs,
        )
        if (runtime_world.runtime_binding_id,) != contract.world_binding_ids:
            raise AdmittedOmissionExperimentDenied(
                "proof_experiment_omission_world_identity_changed"
            )

        actions = self.backend.preview_admitted_actions()
        runtime_worlds = {
            world.binding_id: (
                self.backend.actor_persona_id,
                ExperimentWorldKind.OWNED_ACCOUNT,
            )
        }
        bindings = tuple(
            ExperimentRuntimeActionBinding.bind(
                action=manifest_action,
                candidate=runtime_action,
                target_origin=self.backend.target_origin,
                runtime_worlds=runtime_worlds,
            )
            for manifest_action, runtime_action in zip(
                self.manifest.actions,
                actions,
                strict=True,
            )
        )
        if tuple(
            item.runtime_action_binding_id for item in bindings
        ) != contract.action_binding_ids:
            raise AdmittedOmissionExperimentDenied(
                "proof_experiment_omission_action_identity_changed"
            )
        budget_reservation_id, _, runtime_claim_token = (
            self.claim._runtime_credentials(
                manifest_id=self.manifest.manifest_id,
                execution_policy_digest=execution_policy_digest,
            )
        )
        return _OmissionAdapterPreflight(
            boundary_id=boundary_id,
            actions=actions,
            action_bindings=bindings,
            execution_policy_digest=execution_policy_digest,
            budget_reservation_id=budget_reservation_id,
            runtime_claim_token=runtime_claim_token,
        )

    @staticmethod
    def _block_matches_action(
        block: MerkleBlock,
        action: CandidateAction,
        action_class: str,
    ) -> bool:
        payload = getattr(block, "payload", None)
        if not isinstance(payload, Mapping):
            return False
        path = str(payload.get("url_path") or "")
        expected_path_key = endpoint_key(action.url).split("/", 1)[-1]
        actual_path_key = endpoint_key(path).lstrip("/")
        return bool(
            payload.get("method") == str(action.method).upper()
            and actual_path_key == expected_path_key
            and payload.get("action_class") == action_class
            and payload.get("actor_persona_id") == action.actor_persona_id
            and payload.get("target_owner_persona_id")
            == action.target_owner_persona_id
            and payload.get("target_is_researcher_owned")
            is action.target_is_researcher_owned
        )

    def _action_evidence(
        self,
        *,
        preflight: _OmissionAdapterPreflight,
        execution: AdmittedFreshOmissionExecutionResult,
        new_blocks: Sequence[MerkleBlock],
    ) -> Tuple[
        Tuple[str, ...],
        Tuple[str, ...],
        Tuple[str, ...],
        Tuple[str, ...],
        bool,
    ]:
        references: Dict[int, str] = {}
        attempted = iter(execution.attempted_ordinals)
        current = next(attempted, None)
        complete = len(new_blocks) == execution.requests_attempted
        for block in new_blocks:
            matched = None
            while current is not None:
                manifest_action = self.manifest.actions[current]
                if self._block_matches_action(
                    block,
                    preflight.actions[current],
                    manifest_action.action_class.value,
                ):
                    matched = current
                    current = next(attempted, None)
                    break
                complete = False
                current = next(attempted, None)
            if matched is None:
                complete = False
                continue
            references[matched] = stable_hash(
                "proof_experiment_action_evidence",
                {
                    "runtime_action_binding_id": preflight.action_bindings[
                        matched
                    ].runtime_action_binding_id,
                    "provenance_block_id": block.id,
                },
            )
        if current is not None or next(attempted, None) is not None:
            complete = False

        def phase_refs(*phases: ExperimentPhase) -> Tuple[str, ...]:
            return tuple(
                references[index]
                for index, action in enumerate(self.manifest.actions)
                if action.phase in phases and index in references
            )

        return (
            phase_refs(ExperimentPhase.CONTROL),
            phase_refs(ExperimentPhase.TREATMENT),
            phase_refs(ExperimentPhase.WITNESS),
            phase_refs(
                ExperimentPhase.CLEANUP,
                ExperimentPhase.CLEANUP_VERIFICATION,
            ),
            complete,
        )

    def _finding_candidate_ref(
        self,
        execution: AdmittedFreshOmissionExecutionResult,
    ) -> str:
        return stable_hash(
            "proof_experiment_finding_candidate",
            {
                "confirmation_id": execution.confirmation_id,
                "experiment_id": execution.experiment_id,
                "proof_kind": "known_valid_wrong_object_capability_rejected",
                "control_response_status": execution.control_response_status,
                "provenance_root": execution.provenance_root,
            },
        )

    def _evaluate(
        self,
        *,
        preflight: _OmissionAdapterPreflight,
        execution: AdmittedFreshOmissionExecutionResult,
        new_blocks: Sequence[MerkleBlock],
    ) -> Tuple[ExperimentOracleEvaluation, Optional[str], str]:
        controls, treatment, witnesses, cleanup, evidence_complete = (
            self._action_evidence(
                preflight=preflight,
                execution=execution,
                new_blocks=new_blocks,
            )
        )
        cleanup_complete = bool(
            execution.creates_completed > 0
            and execution.creates_attempted == execution.creates_completed
            and execution.cleanup_steps_completed == execution.creates_completed
            and execution.cleanup_verifications_completed
            == execution.creates_completed
            and not execution.orphaned_owned_state_possible
        )
        cleanup_outcome = (
            CleanupOutcome.COMPLETE
            if cleanup_complete
            else CleanupOutcome.UNCERTAIN
        )
        uncertainty = set()
        if execution.status != "completed":
            uncertainty.add("backend_sequence_aborted")
        if execution.requests_attempted != execution.action_slots:
            uncertainty.add("incomplete_target_sequence")
        if execution.requests_sent != execution.action_slots:
            uncertainty.add("incomplete_target_traffic")
        if execution.creates_completed != 3:
            uncertainty.add("fresh_state_incomplete")
        if not cleanup_complete:
            uncertainty.add("cleanup_unverified")
        if execution.policy_denials:
            uncertainty.add("policy_execution_denied")
        if not evidence_complete:
            uncertainty.add("provenance_incomplete")
        sink = self.backend.executor.provenance
        assert sink is not None
        if not sink.verify():
            uncertainty.add("provenance_integrity_failed")
        if execution.confirmation_status not in _CONCLUSIVE_CONFIRMATIONS:
            uncertainty.add("legacy_oracle_inconclusive")
        if execution.confirmation_status == "omission_rejected" and not witnesses:
            uncertainty.add("independent_witness_missing")

        if uncertainty:
            verdict = OracleVerdict.INCONCLUSIVE
            status = "aborted"
        elif execution.confirmation_status == "confirmed_fail_open":
            verdict = OracleVerdict.CONFIRMED
            status = "completed"
        else:
            verdict = OracleVerdict.REFUTED
            status = "completed"
        provenance_root = stable_hash(
            "provenance",
            {
                "admission_id": self.claim.contract.admission_id,
                "merkle_root": execution.provenance_root,
                "events": len(new_blocks),
            },
        )
        evaluation = ExperimentOracleEvaluation.build(
            manifest=self.manifest,
            verdict=verdict,
            backend_receipt_ref=stable_hash(
                "behavioral_receipt",
                self.claim.contract.receipt_id,
            ),
            control_evidence_refs=controls,
            treatment_evidence_refs=treatment,
            witness_evidence_refs=witnesses,
            cleanup_evidence_refs=cleanup,
            provenance_root=provenance_root,
            cleanup_outcome=cleanup_outcome,
            uncertainty_reasons=tuple(sorted(uncertainty)),
        )
        candidate_ref = (
            self._finding_candidate_ref(execution)
            if verdict is OracleVerdict.CONFIRMED
            else None
        )
        return evaluation, candidate_ref, status

    def _abort_claim(
        self,
        reason: str,
        *,
        runtime_claim_token: Optional[str] = None,
    ) -> None:
        try:
            if runtime_claim_token is not None:
                if self.claim.state != "executing":
                    return
                self.claim._abort_runtime(
                    runtime_claim_token=runtime_claim_token,
                    reason=reason,
                )
            elif self.claim.state == "claimed":
                self.claim.abort(reason)
        except (ProofExperimentAdmissionDenied, OSError) as exc:
            raise AdmittedOmissionExperimentDenied(
                "proof_experiment_omission_abort_failed"
            ) from exc

    async def execute(self) -> AdmittedOmissionExperimentResult:
        async with self._lock:
            if self._consumed:
                raise AdmittedOmissionExperimentDenied(
                    "proof_experiment_omission_executor_already_consumed"
                )
            self._consumed = True
            try:
                preflight = self._preflight()
            except Exception as exc:
                self._abort_claim("proof_experiment_omission_preflight_denied")
                if isinstance(exc, AdmittedOmissionExperimentDenied):
                    raise
                raise AdmittedOmissionExperimentDenied(
                    "proof_experiment_omission_preflight_failed"
                ) from exc

            sink = self.backend.executor.provenance
            assert sink is not None
            block_start = len(sink.action_blocks)
            try:
                execution = await self.backend.execute_admitted(
                    expected_actions=preflight.actions,
                    budget_reservation_id=preflight.budget_reservation_id,
                    expected_boundary_id=preflight.boundary_id,
                )
            except Exception as exc:
                self._abort_claim(
                    "proof_experiment_omission_backend_failed",
                    runtime_claim_token=preflight.runtime_claim_token,
                )
                raise AdmittedOmissionExperimentDenied(
                    "proof_experiment_omission_backend_failed"
                ) from exc

            try:
                new_blocks = tuple(sink.action_blocks[block_start:])
                evaluation, candidate_ref, status = self._evaluate(
                    preflight=preflight,
                    execution=execution,
                    new_blocks=new_blocks,
                )
                terminal_release = self.claim.reserved_units
                released_units = (
                    execution.reserved_units_released + terminal_release
                )
                outcome = {
                    "kind": "proof_experiment_omission",
                    "status": status,
                    "manifest_id": self.manifest.manifest_id,
                    "admission_id": self.claim.contract.admission_id,
                    "evaluation_id": evaluation.evaluation_id,
                    "oracle_id": evaluation.oracle_id,
                    "oracle_verdict": evaluation.verdict.value,
                    "backend_receipt_ref": evaluation.backend_receipt_ref,
                    "legacy_verdict": execution.confirmation_status,
                    "control_evidence_refs": list(
                        evaluation.control_evidence_refs
                    ),
                    "treatment_evidence_refs": list(
                        evaluation.treatment_evidence_refs
                    ),
                    "witness_evidence_refs": list(
                        evaluation.witness_evidence_refs
                    ),
                    "cleanup_evidence_refs": list(
                        evaluation.cleanup_evidence_refs
                    ),
                    "cleanup_outcome": evaluation.cleanup_outcome.value,
                    "provenance_root": evaluation.provenance_root,
                    "uncertainty_reasons": list(evaluation.uncertainty_reasons),
                    "requests_attempted": execution.requests_attempted,
                    "requests_sent": execution.requests_sent,
                    "policy_denials": execution.policy_denials,
                    "reserved_units_released": released_units,
                    "total_request_units": (
                        self.manifest.budget.total_request_units
                    ),
                    "creates_attempted": execution.creates_attempted,
                    "creates_completed": execution.creates_completed,
                    "cleanup_steps_attempted": (
                        execution.cleanup_steps_attempted
                    ),
                    "cleanup_steps_completed": (
                        execution.cleanup_steps_completed
                    ),
                    "cleanup_verifications_attempted": (
                        execution.cleanup_verifications_attempted
                    ),
                    "cleanup_verifications_completed": (
                        execution.cleanup_verifications_completed
                    ),
                    "orphaned_owned_state_possible": (
                        execution.orphaned_owned_state_possible
                    ),
                    "finding_candidate_ref": candidate_ref,
                    "adversarial_triage_required": True,
                    "promotion_authority": False,
                    "finding_authority": False,
                }
            except Exception as exc:
                self._abort_claim(
                    "proof_experiment_omission_evaluation_failed",
                    runtime_claim_token=preflight.runtime_claim_token,
                )
                raise AdmittedOmissionExperimentDenied(
                    "proof_experiment_omission_evaluation_failed"
                ) from exc
            try:
                receipt = self.claim._complete_runtime(
                    manifest_id=self.manifest.manifest_id,
                    execution_policy_digest=preflight.execution_policy_digest,
                    outcome=outcome,
                    expected_released_units=terminal_release,
                    runtime_claim_token=preflight.runtime_claim_token,
                )
            except Exception as exc:
                self._abort_claim(
                    "proof_experiment_omission_receipt_failed",
                    runtime_claim_token=preflight.runtime_claim_token,
                )
                raise AdmittedOmissionExperimentDenied(
                    "proof_experiment_omission_receipt_failed"
                ) from exc
            return AdmittedOmissionExperimentResult(
                manifest_id=self.manifest.manifest_id,
                admission_id=self.claim.contract.admission_id,
                receipt_id=receipt.receipt_id,
                status=status,
                legacy_verdict=execution.confirmation_status,
                oracle_evaluation=evaluation,
                requests_attempted=execution.requests_attempted,
                requests_sent=execution.requests_sent,
                policy_denials=execution.policy_denials,
                reserved_units_released=released_units,
                total_request_units=self.manifest.budget.total_request_units,
                creates_attempted=execution.creates_attempted,
                creates_completed=execution.creates_completed,
                cleanup_steps_attempted=execution.cleanup_steps_attempted,
                cleanup_steps_completed=execution.cleanup_steps_completed,
                cleanup_verifications_attempted=(
                    execution.cleanup_verifications_attempted
                ),
                cleanup_verifications_completed=(
                    execution.cleanup_verifications_completed
                ),
                orphaned_owned_state_possible=(
                    execution.orphaned_owned_state_possible
                ),
                finding_candidate_ref=candidate_ref,
                provenance_root=evaluation.provenance_root,
            )


__all__ = [
    "PROOF_EXPERIMENT_OMISSION_ENV",
    "PROOF_EXPERIMENT_OMISSION_MODE",
    "AdmittedOmissionExperimentConfig",
    "AdmittedOmissionExperimentDenied",
    "AdmittedOmissionExperimentExecutor",
    "AdmittedOmissionExperimentResult",
]
