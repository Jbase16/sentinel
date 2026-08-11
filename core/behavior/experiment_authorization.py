"""R4C1 execution adapter for one admitted object-authorization experiment.

This explicit-only, default-off boundary is the sole bridge from an R4B claim to
the existing :class:`ControlledAuthorizationExecutor`.  It rehydrates the exact
four-action manifest (peer control, source control, counterfactual, independent
witness), rebinds every world and request to the current runtime, and delegates
all target traffic to the existing policy/provenance seam.  Its oracle evaluation
has no finding or promotion authority.
"""

from __future__ import annotations

import asyncio
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple
from urllib.parse import urlsplit

from core.cortex.execution_policy import CandidateAction
from core.foundry.vault import PersonaVault
from core.replay.models import MerkleBlock
from core.safety.action_classifier import CROSS_OBJECT_READ

from .active import (
    CONTROLLED_WORKFLOW,
    ControlledAuthorizationExecutor,
    ControlledExecutionResult,
)
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
from .payout_goals import SecurityProperty
from .proposals import AuthorizationExperimentProposal


PROOF_EXPERIMENT_AUTHORIZATION_ENV = (
    "SENTINELFORGE_BEHAVIOR_PROOF_EXPERIMENT_AUTHORIZATION"
)
PROOF_EXPERIMENT_AUTHORIZATION_MODE = (
    "behavioral_proof_experiment_authorization_v1"
)

_TRUE = frozenset({"1", "true", "yes", "on"})
_CONCLUSIVE_LEGACY = frozenset({"BOLA_CONFIRMED", "DENIED", "NO_CROSS_READ"})
_LEGACY_VERDICTS = _CONCLUSIVE_LEGACY | frozenset({"AMBIGUOUS", "ERROR"})
_HASH_REF = re.compile(r"^[a-z][a-z0-9_]*:[0-9a-f]{64}$")
_RECEIPT_ID = re.compile(r"^behavioral-[0-9a-f]{64}$")


class AdmittedAuthorizationExperimentDenied(RuntimeError):
    """The claim or live runtime no longer matches the admitted experiment."""


@dataclass(frozen=True)
class AdmittedAuthorizationExperimentConfig:
    enabled: bool = False

    @classmethod
    def from_environment(cls) -> "AdmittedAuthorizationExperimentConfig":
        enabled = (
            os.environ.get(PROOF_EXPERIMENT_AUTHORIZATION_ENV, "").strip().lower()
            in _TRUE
        )
        return cls(enabled=enabled)


@dataclass(frozen=True)
class AdmittedAuthorizationExperimentResult:
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
    finding_candidate_ref: Optional[str]
    provenance_root: str
    mode: str = PROOF_EXPERIMENT_AUTHORIZATION_MODE
    adversarial_triage_required: bool = True
    promotion_authority: bool = False
    finding_authority: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.oracle_evaluation, ExperimentOracleEvaluation):
            raise ValueError(
                "admitted authorization experiment result contract is invalid"
            )
        expected_status = (
            "aborted"
            if self.oracle_evaluation.verdict is OracleVerdict.INCONCLUSIVE
            else "completed"
        )
        if (
            self.mode != PROOF_EXPERIMENT_AUTHORIZATION_MODE
            or not isinstance(self.manifest_id, str)
            or _HASH_REF.fullmatch(self.manifest_id) is None
            or not self.manifest_id.startswith("proof_experiment_manifest:")
            or not isinstance(self.admission_id, str)
            or _HASH_REF.fullmatch(self.admission_id) is None
            or not self.admission_id.startswith("proof_experiment_admission:")
            or not isinstance(self.receipt_id, str)
            or _RECEIPT_ID.fullmatch(self.receipt_id) is None
            or self.status != expected_status
            or self.legacy_verdict not in _LEGACY_VERDICTS
            or self.oracle_evaluation.manifest_id != self.manifest_id
            or self.oracle_evaluation.backend_receipt_ref
            != stable_hash("behavioral_receipt", self.receipt_id)
            or self.provenance_root != self.oracle_evaluation.provenance_root
            or any(
                isinstance(item, bool) or not isinstance(item, int) or item < 0
                for item in (
                    self.requests_attempted,
                    self.requests_sent,
                    self.policy_denials,
                    self.reserved_units_released,
                )
            )
            or self.requests_attempted > 4
            or self.requests_sent > self.requests_attempted
            or self.policy_denials > self.requests_attempted
            or self.requests_sent + self.reserved_units_released != 4
            or (self.legacy_verdict == "BOLA_CONFIRMED")
            != (self.finding_candidate_ref is not None)
            or (
                self.finding_candidate_ref is not None
                and (
                    not isinstance(self.finding_candidate_ref, str)
                    or _HASH_REF.fullmatch(self.finding_candidate_ref) is None
                    or not self.finding_candidate_ref.startswith(
                        "proof_experiment_finding_candidate:"
                    )
                )
            )
            or (
                self.oracle_evaluation.verdict is OracleVerdict.CONFIRMED
                and self.legacy_verdict != "BOLA_CONFIRMED"
            )
            or (
                self.oracle_evaluation.verdict is OracleVerdict.REFUTED
                and self.legacy_verdict not in {"DENIED", "NO_CROSS_READ"}
            )
            or not self.adversarial_triage_required
            or self.promotion_authority
            or self.finding_authority
        ):
            raise ValueError(
                "admitted authorization experiment result contract is invalid"
            )

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
            "finding_candidate_ref": self.finding_candidate_ref,
            "provenance_root": self.provenance_root,
            "adversarial_triage_required": self.adversarial_triage_required,
            "promotion_authority": self.promotion_authority,
            "finding_authority": self.finding_authority,
        }


@dataclass(frozen=True)
class _AuthorizationPreflight:
    actions: Tuple[CandidateAction, ...]
    action_bindings: Tuple[ExperimentRuntimeActionBinding, ...]
    execution_policy_digest: str
    budget_reservation_id: str = field(repr=False, compare=False)
    runtime_claim_token: str = field(repr=False, compare=False)


def _path(value: str) -> str:
    return urlsplit(value).path or value


class AdmittedAuthorizationExperimentExecutor:
    """Consume one R4B claim through the established authorization backend."""

    def __init__(
        self,
        *,
        manifest: ProofExperimentManifest,
        claim: ProofExperimentAdmissionClaim,
        backend: ControlledAuthorizationExecutor,
        persona_vault: PersonaVault,
        config: Optional[AdmittedAuthorizationExperimentConfig] = None,
    ) -> None:
        if not isinstance(manifest, ProofExperimentManifest):
            raise TypeError("manifest must be a ProofExperimentManifest")
        if not isinstance(claim, ProofExperimentAdmissionClaim):
            raise TypeError("claim must be a ProofExperimentAdmissionClaim")
        if not isinstance(backend, ControlledAuthorizationExecutor):
            raise TypeError("backend must be a ControlledAuthorizationExecutor")
        if not isinstance(persona_vault, PersonaVault):
            raise TypeError("persona_vault must be a PersonaVault")
        self.manifest = manifest
        self.claim = claim
        self.backend = backend
        self.persona_vault = persona_vault
        self.config = config or AdmittedAuthorizationExperimentConfig.from_environment()
        self._lock = asyncio.Lock()
        self._consumed = False

    def _validate_manifest_shape(
        self, proposal: AuthorizationExperimentProposal
    ) -> None:
        actions = self.manifest.actions
        if (
            self.manifest.backend.backend
            is not ExistingBackendKind.OBJECT_AUTHORIZATION
            or self.manifest.backend.source_contract_ref != proposal.proposal_id
            or len(actions) != 4
            or tuple(item.phase for item in actions)
            != (
                ExperimentPhase.CONTROL,
                ExperimentPhase.CONTROL,
                ExperimentPhase.TREATMENT,
                ExperimentPhase.WITNESS,
            )
            or tuple(item.action_class for item in actions)
            != (
                ExperimentActionClass.SAFE_READ,
                ExperimentActionClass.SAFE_READ,
                ExperimentActionClass.CROSS_OBJECT_READ,
                ExperimentActionClass.SAFE_READ,
            )
            or any(item.mutation is not MutationExpectation.NONE for item in actions)
            or any(item.operation_id != proposal.action_id for item in actions)
            or self.manifest.cleanup.required
            or self.manifest.cleanup.bindings
            or self.manifest.oracle.security_property
            is not SecurityProperty.OBJECT_AUTHORIZATION
            or self.manifest.oracle.comparison_kind != "owned_object_counterfactual"
            or self.manifest.oracle.treatment_action_ids != (actions[2].action_id,)
            or self.manifest.oracle.witness_action_ids != (actions[3].action_id,)
        ):
            raise AdmittedAuthorizationExperimentDenied(
                "authorization_manifest_backend_contract_mismatch"
            )

        controls = {item.kind: item for item in self.manifest.controls}
        if (
            set(controls)
            != {
                ExperimentControlKind.OWNER_BASELINE,
                ExperimentControlKind.PEER_BASELINE,
            }
            or controls[ExperimentControlKind.PEER_BASELINE].action_ids
            != (actions[0].action_id,)
            or controls[ExperimentControlKind.OWNER_BASELINE].action_ids
            != (actions[1].action_id,)
            or actions[0].world_binding_id is None
            or actions[1].world_binding_id is None
            or actions[0].world_binding_id == actions[1].world_binding_id
            or actions[2].world_binding_id != actions[1].world_binding_id
            or actions[3].world_binding_id != actions[0].world_binding_id
        ):
            raise AdmittedAuthorizationExperimentDenied(
                "authorization_manifest_control_topology_mismatch"
            )

    def _bind_worlds(
        self,
    ) -> Mapping[str, Tuple[str, ExperimentWorldKind]]:
        actions = self.manifest.actions
        source_id = self.backend.source_persona.persona_id
        peer_id = self.backend.peer_persona.persona_id
        source_binding_id = actions[1].world_binding_id
        peer_binding_id = actions[0].world_binding_id
        assert source_binding_id is not None and peer_binding_id is not None
        runtime_ids = {
            source_binding_id: source_id,
            peer_binding_id: peer_id,
        }
        manifest_bindings = {
            item.binding_id: item for item in self.manifest.world_manifest.bindings
        }
        if set(manifest_bindings) != set(runtime_ids):
            raise AdmittedAuthorizationExperimentDenied(
                "authorization_runtime_world_set_mismatch"
            )
        for persona_id in (source_id, peer_id):
            persona = self.persona_vault.get_persona(persona_id)
            if persona is None or persona.persona_id != persona_id:
                raise AdmittedAuthorizationExperimentDenied(
                    "authorization_runtime_persona_is_not_in_vault"
                )

        values = []
        runtime_worlds: Dict[str, Tuple[str, ExperimentWorldKind]] = {}
        for binding_id, runtime_id in runtime_ids.items():
            binding = manifest_bindings[binding_id]
            if binding.kind is not ExperimentWorldKind.OWNED_ACCOUNT:
                raise AdmittedAuthorizationExperimentDenied(
                    "authorization_runtime_requires_owned_account_worlds"
                )
            values.append(
                ExperimentRuntimeWorldBinding.bind(
                    manifest_binding=binding,
                    runtime_identity=runtime_id,
                    authorization=self.backend.authorization,
                )
            )
            runtime_worlds[binding_id] = (runtime_id, binding.kind)
        actual_ids = tuple(sorted(item.runtime_binding_id for item in values))
        if actual_ids != self.claim.contract.world_binding_ids:
            raise AdmittedAuthorizationExperimentDenied(
                "authorization_runtime_world_identity_changed"
            )
        return runtime_worlds

    def _preflight(
        self,
        proposal: AuthorizationExperimentProposal,
        source_records: Sequence[Mapping[str, Any]],
        peer_records: Sequence[Mapping[str, Any]],
    ) -> _AuthorizationPreflight:
        if not self.config.enabled:
            raise AdmittedAuthorizationExperimentDenied(
                "proof_experiment_authorization_is_disabled"
            )
        if self.claim.state != "claimed":
            raise AdmittedAuthorizationExperimentDenied(
                "proof_experiment_authorization_claim_is_not_active"
            )
        contract = self.claim.contract
        if (
            contract.manifest_id != self.manifest.manifest_id
            or contract.backend is not ExistingBackendKind.OBJECT_AUTHORIZATION
            or contract.required_workflows != (CONTROLLED_WORKFLOW,)
            or contract.authority_context_ref != self.manifest.authority_context_ref
            or contract.budget_id != self.manifest.budget.budget_id
            or contract.total_request_units != 4
        ):
            raise AdmittedAuthorizationExperimentDenied(
                "proof_experiment_authorization_claim_identity_mismatch"
            )
        self._validate_manifest_shape(proposal)
        self.backend.validate_preflight()
        expected_context = experiment_authority_context_ref(
            self.backend.authorization,
            self.backend.target_origin,
            (CONTROLLED_WORKFLOW,),
        )
        if expected_context != contract.authority_context_ref:
            raise AdmittedAuthorizationExperimentDenied(
                "proof_experiment_authorization_authority_changed"
            )

        source_executor = self.backend.executors[self.backend.source_persona.persona_id]
        sink = source_executor.provenance
        if sink is None or not sink.verify():
            raise AdmittedAuthorizationExperimentDenied(
                "proof_experiment_authorization_provenance_is_invalid"
            )
        execution_policy_digest = source_executor.policy.digest()
        if execution_policy_digest != contract.execution_policy_digest:
            raise AdmittedAuthorizationExperimentDenied(
                "proof_experiment_authorization_policy_changed"
            )

        runtime_worlds = self._bind_worlds()
        actions = self.backend.preview_admitted_actions(
            proposal,
            source_records,
            peer_records,
        )
        bindings = tuple(
            ExperimentRuntimeActionBinding.bind(
                action=manifest_action,
                candidate=runtime_action,
                target_origin=self.backend.target_origin,
                runtime_worlds=runtime_worlds,
            )
            for manifest_action, runtime_action in zip(
                self.manifest.actions, actions, strict=True
            )
        )
        if tuple(
            item.runtime_action_binding_id for item in bindings
        ) != contract.action_binding_ids:
            raise AdmittedAuthorizationExperimentDenied(
                "proof_experiment_authorization_action_identity_changed"
            )
        treatment = actions[2]
        registry = source_executor.policy.ownership_registry
        if (
            treatment.hint != CROSS_OBJECT_READ
            or registry is None
            or registry.owner_of(treatment.url)
            != self.backend.peer_persona.persona_id
        ):
            raise AdmittedAuthorizationExperimentDenied(
                "proof_experiment_authorization_owner_proof_changed"
            )
        (
            budget_reservation_id,
            _,
            runtime_claim_token,
        ) = self.claim._runtime_credentials(
            manifest_id=self.manifest.manifest_id,
            execution_policy_digest=execution_policy_digest,
        )
        return _AuthorizationPreflight(
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
        return bool(
            isinstance(payload, Mapping)
            and payload.get("method") == str(action.method).upper()
            and payload.get("url_path") == _path(str(action.url))
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
        preflight: _AuthorizationPreflight,
        execution: ControlledExecutionResult,
        new_blocks: Sequence[MerkleBlock],
    ) -> Tuple[Tuple[str, ...], Tuple[str, ...], Tuple[str, ...], bool]:
        references = []
        complete = len(new_blocks) == execution.requests_attempted
        for index, block in enumerate(new_blocks[:4]):
            action = preflight.actions[index]
            manifest_action = self.manifest.actions[index]
            if not self._block_matches_action(
                block,
                action,
                manifest_action.action_class.value,
            ):
                complete = False
                continue
            references.append(
                (
                    index,
                    stable_hash(
                        "proof_experiment_action_evidence",
                        {
                            "runtime_action_binding_id": preflight.action_bindings[
                                index
                            ].runtime_action_binding_id,
                            "provenance_block_id": block.id,
                        },
                    ),
                )
            )
        by_index = dict(references)
        controls = tuple(
            by_index[index] for index in (0, 1) if index in by_index
        )
        treatment = ((by_index[2],) if 2 in by_index else ())
        witnesses = ((by_index[3],) if 3 in by_index else ())
        return controls, treatment, witnesses, complete

    @staticmethod
    def _finding_candidate_ref(
        execution: ControlledExecutionResult,
    ) -> Optional[str]:
        finding = execution.finding
        if finding is None:
            return None
        return stable_hash(
            "proof_experiment_finding_candidate",
            {
                "proposal_id": execution.proposal_id,
                "legacy_verdict": execution.legacy_verdict.verdict,
                "object_ref": finding.object_ref,
                "method": finding.method,
                "victim_ref": stable_hash("experiment_victim", finding.victim),
                "semantic_evidence_ref": stable_hash(
                    "experiment_semantic_evidence",
                    {
                        "leaked": list(finding.leaked),
                        "evidence": finding.evidence,
                    },
                ),
            },
        )

    def _evaluate(
        self,
        *,
        preflight: _AuthorizationPreflight,
        execution: ControlledExecutionResult,
        new_blocks: Sequence[MerkleBlock],
        policy_denials: int,
    ) -> Tuple[ExperimentOracleEvaluation, Optional[str], str]:
        controls, treatment, witnesses, evidence_complete = self._action_evidence(
            preflight=preflight,
            execution=execution,
            new_blocks=new_blocks,
        )
        uncertainty = set()
        if execution.status != "completed" or execution.requests_attempted != 4:
            uncertainty.add("backend_sequence_aborted")
        if execution.requests_sent != 4:
            uncertainty.add("incomplete_target_sequence")
        if not execution.independent_witness_valid:
            uncertainty.add("independent_witness_failed")
        if policy_denials:
            uncertainty.add("policy_execution_denied")
        if not evidence_complete:
            uncertainty.add("provenance_incomplete")
        source_executor = self.backend.executors[self.backend.source_persona.persona_id]
        sink = source_executor.provenance
        assert sink is not None
        if not sink.verify():
            uncertainty.add("provenance_integrity_failed")
        if execution.legacy_verdict.verdict not in _CONCLUSIVE_LEGACY:
            uncertainty.add("legacy_oracle_inconclusive")

        if uncertainty:
            verdict = OracleVerdict.INCONCLUSIVE
            status = "aborted"
        elif execution.legacy_verdict.verdict == "BOLA_CONFIRMED":
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
        receipt_ref = stable_hash(
            "behavioral_receipt",
            self.claim.contract.receipt_id,
        )
        evaluation = ExperimentOracleEvaluation.build(
            manifest=self.manifest,
            verdict=verdict,
            backend_receipt_ref=receipt_ref,
            control_evidence_refs=controls,
            treatment_evidence_refs=treatment,
            witness_evidence_refs=witnesses,
            cleanup_evidence_refs=(),
            provenance_root=provenance_root,
            cleanup_outcome=CleanupOutcome.NOT_REQUIRED,
            uncertainty_reasons=tuple(sorted(uncertainty)),
        )
        return evaluation, self._finding_candidate_ref(execution), status

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
            else:
                if self.claim.state != "claimed":
                    return
                self.claim.abort(reason)
        except (ProofExperimentAdmissionDenied, OSError) as exc:
            raise AdmittedAuthorizationExperimentDenied(
                "proof_experiment_authorization_abort_failed"
            ) from exc

    async def execute(
        self,
        proposal: AuthorizationExperimentProposal,
        source_records: Sequence[Mapping[str, Any]],
        peer_records: Sequence[Mapping[str, Any]],
    ) -> AdmittedAuthorizationExperimentResult:
        async with self._lock:
            if self._consumed:
                raise AdmittedAuthorizationExperimentDenied(
                    "proof_experiment_authorization_executor_already_consumed"
                )
            self._consumed = True
            try:
                preflight = self._preflight(
                    proposal,
                    source_records,
                    peer_records,
                )
            except Exception as exc:
                self._abort_claim(
                    "proof_experiment_authorization_preflight_denied"
                )
                if isinstance(exc, AdmittedAuthorizationExperimentDenied):
                    raise
                raise AdmittedAuthorizationExperimentDenied(
                    "proof_experiment_authorization_preflight_failed"
                ) from exc

            source_executor = self.backend.executors[
                self.backend.source_persona.persona_id
            ]
            peer_executor = self.backend.executors[
                self.backend.peer_persona.persona_id
            ]
            sink = source_executor.provenance
            assert sink is not None
            block_start = len(sink.action_blocks)
            denial_start = len(source_executor.skipped) + len(peer_executor.skipped)
            try:
                execution = await self.backend.execute_admitted(
                    proposal,
                    source_records,
                    peer_records,
                    expected_actions=preflight.actions,
                    budget_reservation_id=preflight.budget_reservation_id,
                )
            except Exception as exc:
                self._abort_claim(
                    "proof_experiment_authorization_backend_failed",
                    runtime_claim_token=preflight.runtime_claim_token,
                )
                raise AdmittedAuthorizationExperimentDenied(
                    "proof_experiment_authorization_backend_failed"
                ) from exc

            try:
                new_blocks = tuple(sink.action_blocks[block_start:])
                policy_denials = max(
                    0,
                    len(source_executor.skipped)
                    + len(peer_executor.skipped)
                    - denial_start,
                )
                evaluation, candidate_ref, status = self._evaluate(
                    preflight=preflight,
                    execution=execution,
                    new_blocks=new_blocks,
                    policy_denials=policy_denials,
                )
                released_units = self.claim.reserved_units
                outcome = {
                    "kind": "proof_experiment_authorization",
                    "status": status,
                    "manifest_id": self.manifest.manifest_id,
                    "admission_id": self.claim.contract.admission_id,
                    "evaluation_id": evaluation.evaluation_id,
                    "oracle_id": evaluation.oracle_id,
                    "oracle_verdict": evaluation.verdict.value,
                    "backend_receipt_ref": evaluation.backend_receipt_ref,
                    "legacy_verdict": execution.legacy_verdict.verdict,
                    "control_evidence_refs": list(
                        evaluation.control_evidence_refs
                    ),
                    "treatment_evidence_refs": list(
                        evaluation.treatment_evidence_refs
                    ),
                    "witness_evidence_refs": list(
                        evaluation.witness_evidence_refs
                    ),
                    "provenance_root": evaluation.provenance_root,
                    "uncertainty_reasons": list(evaluation.uncertainty_reasons),
                    "requests_attempted": execution.requests_attempted,
                    "requests_sent": execution.requests_sent,
                    "policy_denials": policy_denials,
                    "reserved_units_released": released_units,
                    "finding_candidate_ref": candidate_ref,
                    "adversarial_triage_required": True,
                    "promotion_authority": False,
                    "finding_authority": False,
                }
            except Exception as exc:
                self._abort_claim(
                    "proof_experiment_authorization_evaluation_failed",
                    runtime_claim_token=preflight.runtime_claim_token,
                )
                raise AdmittedAuthorizationExperimentDenied(
                    "proof_experiment_authorization_evaluation_failed"
                ) from exc
            try:
                receipt = self.claim._complete_runtime(
                    manifest_id=self.manifest.manifest_id,
                    execution_policy_digest=preflight.execution_policy_digest,
                    outcome=outcome,
                    expected_released_units=released_units,
                    runtime_claim_token=preflight.runtime_claim_token,
                )
            except Exception as exc:
                self._abort_claim(
                    "proof_experiment_authorization_receipt_failed",
                    runtime_claim_token=preflight.runtime_claim_token,
                )
                raise AdmittedAuthorizationExperimentDenied(
                    "proof_experiment_authorization_receipt_failed"
                ) from exc
            return AdmittedAuthorizationExperimentResult(
                manifest_id=self.manifest.manifest_id,
                admission_id=self.claim.contract.admission_id,
                receipt_id=receipt.receipt_id,
                status=status,
                legacy_verdict=execution.legacy_verdict.verdict,
                oracle_evaluation=evaluation,
                requests_attempted=execution.requests_attempted,
                requests_sent=execution.requests_sent,
                policy_denials=policy_denials,
                reserved_units_released=released_units,
                finding_candidate_ref=candidate_ref,
                provenance_root=evaluation.provenance_root,
            )


__all__ = [
    "PROOF_EXPERIMENT_AUTHORIZATION_ENV",
    "PROOF_EXPERIMENT_AUTHORIZATION_MODE",
    "AdmittedAuthorizationExperimentConfig",
    "AdmittedAuthorizationExperimentDenied",
    "AdmittedAuthorizationExperimentExecutor",
    "AdmittedAuthorizationExperimentResult",
]
