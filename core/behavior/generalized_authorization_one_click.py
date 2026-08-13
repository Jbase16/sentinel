"""Ordinary one-click selection and dispatch for the R5A authorization proof.

Selection is deterministic and traffic-free.  Dispatch remains separately
gated by the existing R4 admission and R5A3b execution switches, consumes one
R4 claim, and returns evidence only.  It never promotes a finding.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple

from core.cortex.execution_policy import PolicyExecutor
from core.foundry.authorization import AuthorizationEnvelope
from core.foundry.vault import PersonaVault
from core.safety.ownership_locator import (
    OwnedRequestLocatorKind,
    extract_locator_value,
)

from .active import CROSS_OBJECT_READ, ControlledAuthorizationExecutor
from .compiler import OperationContract, OperationSafety
from .constraints import ConstraintLedgerBuilder
from .experiment_admission import (
    GeneralizedExperimentAdmission,
    ProofExperimentAdmissionConfig,
    ProofExperimentAdmissionDenied,
    experiment_authority_context_ref,
    experiment_endpoint_ref,
    experiment_ownership_ref,
    experiment_persona_ref,
)
from .experiment_generalized_authorization import (
    GeneralizedAuthorizationExecutionConfig,
    GeneralizedAuthorizationExecutionDenied,
    GeneralizedAuthorizationExecutionPlanner,
    GeneralizedAuthorizationExperimentExecutor,
    GeneralizedAuthorizationExperimentResult,
    validate_generalized_read_semantics,
)
from .experiment_sdk import (
    ExistingBackendAdapter,
    ExperimentAction,
    ExperimentActionClass,
    ExperimentCleanupContract,
    ExperimentControl,
    ExperimentControlKind,
    ExperimentOracleContract,
    ExperimentPhase,
    ExperimentWorldBinding,
    ExperimentWorldKind,
    ExperimentWorldManifest,
    MutationExpectation,
    ProofExperimentCompiler,
    ProofExperimentManifest,
)
from .normalize import stable_hash
from .ownership_experiment import (
    OBJECT_AUTHORIZATION_WORKFLOW,
    GeneralizedOwnershipExperimentAdmission,
    GeneralizedOwnershipExperimentCompiler,
    GeneralizedOwnershipExperimentDenied,
    GeneralizedOwnershipExperimentProof,
    OwnershipExperimentAdmissionContract,
)
from .ownership_locators import (
    GeneralizedOwnershipEvidence,
    GeneralizedOwnershipIndex,
    GeneralizedOwnershipLocatorCompiler,
    OwnershipUseEvidence,
)
from .payout_goals import (
    PayoutGoalCandidate,
    PayoutGoalPlan,
    ProofTopology,
    SecurityProperty,
    SecurityWitnessGoal,
    WorldRequirement,
)
from .proposals import (
    AuthorizationExperimentProposal,
    MutationLocator,
    ProposalLeg,
)
from .receipts import BehavioralReceiptStore
from .replanning import ConstraintReplanner


GENERALIZED_AUTHORIZATION_ONE_CLICK_MODE = (
    "behavioral_generalized_authorization_one_click_v1"
)


class GeneralizedAuthorizationOneClickDenied(RuntimeError):
    """One-click selection or its explicitly enabled dispatch failed closed."""


@dataclass(frozen=True)
class GeneralizedAuthorizationOneClickConfig:
    max_pair_candidates: int = 64
    max_pair_inspections: int = 4_096

    def __post_init__(self) -> None:
        if (
            isinstance(self.max_pair_candidates, bool)
            or not isinstance(self.max_pair_candidates, int)
            or not 1 <= self.max_pair_candidates <= 512
        ):
            raise ValueError("max_pair_candidates must be between 1 and 512")
        if (
            isinstance(self.max_pair_inspections, bool)
            or not isinstance(self.max_pair_inspections, int)
            or not 1 <= self.max_pair_inspections <= 65_536
        ):
            raise ValueError("max_pair_inspections must be between 1 and 65536")


@dataclass(frozen=True)
class GeneralizedAuthorizationOneClickRun:
    status: str
    candidate_pairs: int
    rejected_pairs: int
    dropped_for_bound: int
    selected_pair_ref: Optional[str] = None
    payout_candidate_id: Optional[str] = None
    manifest_id: Optional[str] = None
    ownership_proof_id: Optional[str] = None
    ownership_admission_id: Optional[str] = None
    disabled_gates: Tuple[str, ...] = ()
    execution: Optional[GeneralizedAuthorizationExperimentResult] = field(
        default=None,
        repr=False,
        compare=False,
    )
    mode: str = GENERALIZED_AUTHORIZATION_ONE_CLICK_MODE
    finding_authority: bool = False
    promotion_authority: bool = False

    def __post_init__(self) -> None:
        counts = (
            self.candidate_pairs,
            self.rejected_pairs,
            self.dropped_for_bound,
        )
        selected_refs = (
            self.selected_pair_ref,
            self.payout_candidate_id,
            self.manifest_id,
            self.ownership_proof_id,
            self.ownership_admission_id,
        )
        has_selection = all(isinstance(item, str) for item in selected_refs)
        if (
            self.mode != GENERALIZED_AUTHORIZATION_ONE_CLICK_MODE
            or self.finding_authority
            or self.promotion_authority
            or any(
                isinstance(item, bool) or not isinstance(item, int) or item < 0
                for item in counts
            )
            or self.status
            not in {
                "no_eligible_candidate",
                "selected_execution_disabled",
                "completed",
                "aborted",
            }
            or self.disabled_gates
            != tuple(dict.fromkeys(self.disabled_gates))
            or any(not isinstance(item, str) or not item for item in self.disabled_gates)
            or (
                self.status == "no_eligible_candidate"
                and (any(item is not None for item in selected_refs) or self.execution)
            )
            or (
                self.status == "selected_execution_disabled"
                and (not has_selection or not self.disabled_gates or self.execution)
            )
            or (
                self.status in {"completed", "aborted"}
                and (
                    not has_selection
                    or self.disabled_gates
                    or self.execution is None
                    or self.execution.status != self.status
                )
            )
            or (
                has_selection
                and (
                    not self.selected_pair_ref.startswith(
                        "generalized_authorization_pair:"
                    )
                    or not self.payout_candidate_id.startswith(
                        "payout_goal_candidate:"
                    )
                    or not self.manifest_id.startswith(
                        "proof_experiment_manifest:"
                    )
                    or not self.ownership_proof_id.startswith(
                        "ownership_experiment_proof:"
                    )
                    or not self.ownership_admission_id.startswith(
                        "ownership_experiment_admission:"
                    )
                )
            )
        ):
            raise ValueError(
                "generalized authorization one-click run contract is invalid"
            )

    @property
    def dispatched(self) -> bool:
        return self.execution is not None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": 1,
            "mode": self.mode,
            "status": self.status,
            "candidate_pairs": self.candidate_pairs,
            "rejected_pairs": self.rejected_pairs,
            "dropped_for_bound": self.dropped_for_bound,
            "selected_pair_ref": self.selected_pair_ref,
            "payout_candidate_id": self.payout_candidate_id,
            "manifest_id": self.manifest_id,
            "ownership_proof_id": self.ownership_proof_id,
            "ownership_admission_id": self.ownership_admission_id,
            "disabled_gates": list(self.disabled_gates),
            "dispatched": self.dispatched,
            "execution": self.execution.to_dict() if self.execution else None,
            "finding_authority": False,
            "promotion_authority": False,
        }

    def execution_response(self) -> Dict[str, Any]:
        """Return the exact receipt-safe response for an executed selection."""

        if self.execution is None:
            raise GeneralizedAuthorizationOneClickDenied(
                "generalized_authorization_one_click_was_not_dispatched"
            )
        result = self.execution
        evaluation = result.oracle_evaluation
        return {
            "schema_version": 1,
            "kind": "proof_experiment_generalized_authorization",
            "mode": result.mode,
            "status": result.status,
            "manifest_id": result.manifest_id,
            "admission_id": result.admission_id,
            "evaluation_id": evaluation.evaluation_id,
            "oracle_id": evaluation.oracle_id,
            "oracle_verdict": evaluation.verdict.value,
            "backend_receipt_ref": evaluation.backend_receipt_ref,
            "legacy_verdict": result.legacy_verdict,
            "control_evidence_refs": list(evaluation.control_evidence_refs),
            "treatment_evidence_refs": list(
                evaluation.treatment_evidence_refs
            ),
            "witness_evidence_refs": list(evaluation.witness_evidence_refs),
            "provenance_root": result.provenance_root,
            "uncertainty_reasons": list(evaluation.uncertainty_reasons),
            "requests_attempted": result.requests_attempted,
            "requests_sent": result.requests_sent,
            "policy_denials": result.policy_denials,
            "reserved_units_released": result.reserved_units_released,
            "finding_candidate_ref": result.finding_candidate_ref,
            "ownership_proof_id": result.ownership_proof_id,
            "ownership_admission_id": result.ownership_admission_id,
            "locator_proof_ref": result.locator_proof_ref,
            "runtime_authority_ref": result.runtime_authority_ref,
            "execution_plan_ref": result.execution_plan_ref,
            "transport_context_ref": result.transport_context_ref,
            "one_click_selection": self.to_dict(),
            "finding": None,
            "adversarial_triage_required": True,
            "promotion_authority": False,
            "finding_authority": False,
        }


@dataclass(frozen=True)
class _PairCandidate:
    pair_ref: str
    actor_index: GeneralizedOwnershipIndex = field(repr=False, compare=False)
    owner_index: GeneralizedOwnershipIndex = field(repr=False, compare=False)
    actor_evidence: GeneralizedOwnershipEvidence = field(
        repr=False,
        compare=False,
    )
    owner_evidence: GeneralizedOwnershipEvidence = field(
        repr=False,
        compare=False,
    )
    actor_use: OwnershipUseEvidence = field(repr=False, compare=False)
    owner_use: OwnershipUseEvidence = field(repr=False, compare=False)
    payout_candidate: PayoutGoalCandidate = field(repr=False, compare=False)
    operation: OperationContract = field(repr=False, compare=False)
    endpoint_ref: str


@dataclass(frozen=True)
class _CompiledSelection:
    pair: _PairCandidate
    manifest: ProofExperimentManifest
    proof: GeneralizedOwnershipExperimentProof
    ownership_admission: OwnershipExperimentAdmissionContract


class GeneralizedAuthorizationOneClickDispatcher:
    """Select one payout-ranked R5A pair and optionally dispatch it once."""

    def __init__(
        self,
        *,
        target_origin: str,
        authorization: AuthorizationEnvelope,
        backend: ControlledAuthorizationExecutor,
        persona_vault: PersonaVault,
        receipt_store: BehavioralReceiptStore,
        admission_config: Optional[ProofExperimentAdmissionConfig] = None,
        execution_config: Optional[GeneralizedAuthorizationExecutionConfig] = None,
        config: GeneralizedAuthorizationOneClickConfig = (
            GeneralizedAuthorizationOneClickConfig()
        ),
    ) -> None:
        if not isinstance(authorization, AuthorizationEnvelope):
            raise TypeError("authorization must be an AuthorizationEnvelope")
        if not isinstance(backend, ControlledAuthorizationExecutor):
            raise TypeError("backend must be a ControlledAuthorizationExecutor")
        if not isinstance(persona_vault, PersonaVault):
            raise TypeError("persona_vault must be a PersonaVault")
        if not isinstance(receipt_store, BehavioralReceiptStore):
            raise TypeError("receipt_store must be a BehavioralReceiptStore")
        if not isinstance(config, GeneralizedAuthorizationOneClickConfig):
            raise TypeError("config must be a GeneralizedAuthorizationOneClickConfig")
        self.target_origin = target_origin
        self.authorization = authorization
        self.backend = backend
        self.persona_vault = persona_vault
        self.receipt_store = receipt_store
        self.admission_config = (
            admission_config or ProofExperimentAdmissionConfig.from_environment()
        )
        self.execution_config = (
            execution_config
            or GeneralizedAuthorizationExecutionConfig.from_environment()
        )
        self.config = config
        self.locator_compiler = GeneralizedOwnershipLocatorCompiler()

    @staticmethod
    def _operation_map(
        operations: Sequence[OperationContract],
    ) -> Dict[str, OperationContract]:
        values: Dict[str, OperationContract] = {}
        for operation in operations:
            if not isinstance(operation, OperationContract):
                raise TypeError("operations must contain OperationContract values")
            existing = values.get(operation.operation_id)
            if existing is None:
                values[operation.operation_id] = operation
                continue
            existing_contract = existing.to_dict()
            operation_contract = operation.to_dict()
            existing_contract.pop("source_refs", None)
            operation_contract.pop("source_refs", None)
            if existing_contract != operation_contract:
                raise GeneralizedAuthorizationOneClickDenied(
                    "generalized_authorization_operation_is_ambiguous"
                )
            values[operation.operation_id] = replace(
                existing,
                source_refs=tuple(
                    sorted(set(existing.source_refs) | set(operation.source_refs))
                ),
            )
        return values

    @staticmethod
    def _payout_map(plan: PayoutGoalPlan) -> Dict[str, PayoutGoalCandidate]:
        values: Dict[str, PayoutGoalCandidate] = {}
        for candidate in plan.candidates:
            operation_id = candidate.goal.terminal_operation_id
            blocker_codes = {item.code for item in candidate.blockers}
            generalized_backend_satisfies_blockers = blocker_codes == {
                "proof_backend_unavailable"
            }
            if (
                candidate.status == "admissible"
                or generalized_backend_satisfies_blockers
            ) and operation_id not in values:
                values[operation_id] = candidate
        return values

    @staticmethod
    def _observation_index(index: GeneralizedOwnershipIndex, source_ref: str) -> int:
        matches = tuple(
            item for item in index.ledger.observations if item.source_ref == source_ref
        )
        if len(matches) != 1:
            raise GeneralizedOwnershipExperimentDenied(
                "generalized_ownership_observation_is_missing_or_ambiguous"
            )
        return matches[0].record_index

    def _pairs(
        self,
        *,
        actor_records: Sequence[Mapping[str, Any]],
        owner_records: Sequence[Mapping[str, Any]],
        payout_goal_plan: PayoutGoalPlan,
        operations: Sequence[OperationContract],
    ) -> Tuple[Tuple[_PairCandidate, ...], int, int]:
        actor_id = self.backend.source_persona.persona_id
        owner_id = self.backend.peer_persona.persona_id
        actor_index = self.locator_compiler.compile(
            actor_records,
            world_id=actor_id,
        )
        owner_index = self.locator_compiler.compile(
            owner_records,
            world_id=owner_id,
        )
        operation_map = self._operation_map(operations)
        payout_map = self._payout_map(payout_goal_plan)
        owner_by_shape = {}
        for owner_evidence in owner_index.evidence:
            for owner_use in owner_evidence.uses:
                key = (
                    owner_evidence.capability_key,
                    owner_evidence.create_operation_id,
                    owner_use.operation_id,
                    owner_use.method,
                    owner_use.locator_kind,
                    owner_use.locator_pointer,
                    owner_use.protocol,
                )
                owner_by_shape.setdefault(key, []).append(
                    (owner_evidence, owner_use)
                )
        for values in owner_by_shape.values():
            values.sort(key=lambda item: (item[0].evidence_id, item[1].use_id))

        actor_uses = []
        for actor_evidence in actor_index.evidence:
            for actor_use in actor_evidence.uses:
                operation = operation_map.get(actor_use.operation_id)
                payout_candidate = payout_map.get(actor_use.operation_id)
                if operation is None or payout_candidate is None:
                    continue
                key = (
                    actor_evidence.capability_key,
                    actor_evidence.create_operation_id,
                    actor_use.operation_id,
                    actor_use.method,
                    actor_use.locator_kind,
                    actor_use.locator_pointer,
                    actor_use.protocol,
                )
                if key in owner_by_shape:
                    actor_uses.append(
                        (
                            payout_candidate,
                            operation,
                            actor_evidence,
                            actor_use,
                            key,
                        )
                    )
        actor_uses.sort(
            key=lambda item: (
                -item[0].score,
                item[3].locator_kind.value,
                item[3].locator_pointer,
                item[2].evidence_id,
                item[3].use_id,
            )
        )
        total_matches = sum(
            len(owner_by_shape[item[4]]) for item in actor_uses
        )
        pairs = []
        rejected = 0
        inspected = 0
        stop = False
        for (
            payout_candidate,
            operation,
            actor_evidence,
            actor_use,
            key,
        ) in actor_uses:
            for owner_evidence, owner_use in owner_by_shape[key]:
                if (
                    inspected >= self.config.max_pair_inspections
                    or len(pairs) >= self.config.max_pair_candidates
                ):
                    stop = True
                    break
                inspected += 1
                try:
                    actor_request = actor_index.rehydrate_use(
                        evidence_id=actor_evidence.evidence_id,
                        use_id=actor_use.use_id,
                    )
                    owner_request = owner_index.rehydrate_use(
                        evidence_id=owner_evidence.evidence_id,
                        use_id=owner_use.use_id,
                    )
                    actor_kind = OwnedRequestLocatorKind(
                        actor_use.locator_kind.value
                    )
                    owner_kind = OwnedRequestLocatorKind(
                        owner_use.locator_kind.value
                    )
                    validate_generalized_read_semantics(
                        method=actor_request.method,
                        body=actor_request.body,
                        kind=actor_kind,
                        pointer=actor_use.locator_pointer,
                        protocol=actor_use.protocol,
                    )
                    validate_generalized_read_semantics(
                        method=owner_request.method,
                        body=owner_request.body,
                        kind=owner_kind,
                        pointer=owner_use.locator_pointer,
                        protocol=owner_use.protocol,
                    )
                    actor_value = extract_locator_value(
                        kind=actor_kind,
                        pointer=actor_use.locator_pointer,
                        url=actor_request.url,
                        body=actor_request.body,
                    )
                    owner_value = extract_locator_value(
                        kind=owner_kind,
                        pointer=owner_use.locator_pointer,
                        url=owner_request.url,
                        body=owner_request.body,
                    )
                    actor_endpoint = experiment_endpoint_ref(
                        actor_request.method,
                        actor_request.url,
                    )
                    owner_endpoint = experiment_endpoint_ref(
                        owner_request.method,
                        owner_request.url,
                    )
                except (TypeError, ValueError, RuntimeError):
                    rejected += 1
                    continue
                if actor_value == owner_value or actor_endpoint != owner_endpoint:
                    rejected += 1
                    continue
                pair_ref = stable_hash(
                    "generalized_authorization_pair",
                    {
                        "actor_evidence_id": actor_evidence.evidence_id,
                        "actor_use_id": actor_use.use_id,
                        "owner_evidence_id": owner_evidence.evidence_id,
                        "owner_use_id": owner_use.use_id,
                        "payout_candidate_id": payout_candidate.candidate_id,
                        "endpoint_ref": actor_endpoint,
                    },
                )
                pairs.append(
                    _PairCandidate(
                        pair_ref=pair_ref,
                        actor_index=actor_index,
                        owner_index=owner_index,
                        actor_evidence=actor_evidence,
                        owner_evidence=owner_evidence,
                        actor_use=actor_use,
                        owner_use=owner_use,
                        payout_candidate=payout_candidate,
                        operation=operation,
                        endpoint_ref=actor_endpoint,
                    )
                )
            if stop:
                break
        ordered = tuple(
            sorted(
                pairs,
                key=lambda item: (
                    -item.payout_candidate.score,
                    item.actor_use.locator_kind.value,
                    item.actor_use.locator_pointer,
                    item.pair_ref,
                ),
            )
        )
        dropped = max(0, total_matches - inspected)
        return ordered, rejected, dropped

    def _compile_manifest(
        self,
        pair: _PairCandidate,
        *,
        payout_goal_plan: PayoutGoalPlan,
    ) -> ProofExperimentManifest:
        actor_id = self.backend.source_persona.persona_id
        owner_id = self.backend.peer_persona.persona_id
        actor_world = ExperimentWorldBinding.build(
            slot="actor",
            kind=ExperimentWorldKind.OWNED_ACCOUNT,
            world_ref=pair.actor_evidence.world_ref,
            persona_ref=experiment_persona_ref(actor_id),
            ownership_ref=experiment_ownership_ref(
                self.authorization,
                actor_id,
            ),
        )
        owner_world = ExperimentWorldBinding.build(
            slot="peer",
            kind=ExperimentWorldKind.OWNED_ACCOUNT,
            world_ref=pair.owner_evidence.world_ref,
            persona_ref=experiment_persona_ref(owner_id),
            ownership_ref=experiment_ownership_ref(
                self.authorization,
                owner_id,
            ),
        )
        proposal_id = stable_hash(
            "authorization_proposal",
            {
                "pair_ref": pair.pair_ref,
                "operation_id": pair.actor_use.operation_id,
                "actor_world_ref": actor_world.world_ref,
                "owner_world_ref": owner_world.world_ref,
            },
        )
        proposal = AuthorizationExperimentProposal(
            proposal_id=proposal_id,
            action_id=pair.actor_use.operation_id,
            operation_label=pair.operation.label,
            source_ref=pair.actor_use.source_ref,
            source_record_index=self._observation_index(
                pair.actor_index,
                pair.actor_use.source_ref,
            ),
            risk_class=CROSS_OBJECT_READ,
            mutations=(
                MutationLocator(
                    location_kind=pair.actor_use.locator_kind.value,
                    pointer=pair.actor_use.locator_pointer,
                    semantic_key=pair.actor_evidence.capability_key,
                    source_value_hash=pair.actor_evidence.value_hash,
                    replacement_value_hash=pair.owner_evidence.value_hash,
                ),
            ),
            legs=(
                ProposalLeg(
                    "peer_baseline",
                    owner_world.world_ref,
                    "peer_observed_value",
                ),
                ProposalLeg(
                    "source_baseline",
                    actor_world.world_ref,
                    "source_observed_value",
                ),
                ProposalLeg(
                    "counterfactual",
                    actor_world.world_ref,
                    "peer_observed_value",
                ),
            ),
        )
        backend = ExistingBackendAdapter.authorization(proposal)
        operation = OperationContract(
            operation_id=pair.operation.operation_id,
            label=pair.operation.label,
            requires=pair.operation.requires,
            produces=pair.operation.produces,
            safety=OperationSafety.READ_ONLY,
            cost=pair.operation.cost,
            observed_success=True,
            source_refs=tuple(
                sorted(
                    set(pair.operation.source_refs)
                    | {pair.actor_use.source_ref, pair.owner_use.source_ref}
                )
            ),
            requires_owned_state=pair.operation.requires_owned_state,
        )
        goal = SecurityWitnessGoal.build(
            operation=operation,
            sink=pair.payout_candidate.goal.sink,
            security_property=SecurityProperty.OBJECT_AUTHORIZATION,
            evidence_refs=backend.source_evidence_refs,
        )
        requirement = WorldRequirement(
            ProofTopology.PAIRED_OWNED_ACCOUNTS,
            2,
            required_workflows=(OBJECT_AUTHORIZATION_WORKFLOW,),
        )
        candidate = PayoutGoalCandidate.build(
            goal=goal,
            world_requirement=requirement,
            backend="object_authorization",
            score=pair.payout_candidate.score,
            blockers=(),
        )
        replan = ConstraintReplanner((operation,)).compile_witness(
            goal,
            ledger=ConstraintLedgerBuilder().build(),
            initial_capabilities=operation.requires,
        )
        evidence = backend.source_evidence_refs
        actions = (
            ExperimentAction.build(
                ordinal=0,
                phase=ExperimentPhase.CONTROL,
                operation_id=operation.operation_id,
                world_binding_id=owner_world.binding_id,
                action_class=ExperimentActionClass.SAFE_READ,
                endpoint_ref=pair.endpoint_ref,
                mutation=MutationExpectation.NONE,
                evidence_refs=evidence,
            ),
            ExperimentAction.build(
                ordinal=1,
                phase=ExperimentPhase.CONTROL,
                operation_id=operation.operation_id,
                world_binding_id=actor_world.binding_id,
                action_class=ExperimentActionClass.SAFE_READ,
                endpoint_ref=pair.endpoint_ref,
                mutation=MutationExpectation.NONE,
                evidence_refs=evidence,
            ),
            ExperimentAction.build(
                ordinal=2,
                phase=ExperimentPhase.TREATMENT,
                operation_id=operation.operation_id,
                world_binding_id=actor_world.binding_id,
                action_class=ExperimentActionClass.CROSS_OBJECT_READ,
                endpoint_ref=pair.endpoint_ref,
                mutation=MutationExpectation.NONE,
                evidence_refs=evidence,
            ),
            ExperimentAction.build(
                ordinal=3,
                phase=ExperimentPhase.WITNESS,
                operation_id=operation.operation_id,
                world_binding_id=owner_world.binding_id,
                action_class=ExperimentActionClass.SAFE_READ,
                endpoint_ref=pair.endpoint_ref,
                mutation=MutationExpectation.NONE,
                evidence_refs=evidence,
            ),
        )
        controls = (
            ExperimentControl.build(
                kind=ExperimentControlKind.PEER_BASELINE,
                action_ids=(actions[0].action_id,),
                world_binding_ids=(owner_world.binding_id,),
            ),
            ExperimentControl.build(
                kind=ExperimentControlKind.OWNER_BASELINE,
                action_ids=(actions[1].action_id,),
                world_binding_ids=(actor_world.binding_id,),
            ),
        )
        oracle = ExperimentOracleContract.build(
            goal=goal,
            control_ids=tuple(item.control_id for item in controls),
            treatment_action_ids=(actions[2].action_id,),
            witness_action_ids=(actions[3].action_id,),
            comparison_kind="owned_object_counterfactual",
        )
        return ProofExperimentCompiler().compile(
            candidate=candidate,
            replan=replan,
            world_manifest=ExperimentWorldManifest.build(
                requirement=requirement,
                bindings=(actor_world, owner_world),
            ),
            backend=backend,
            actions=actions,
            controls=controls,
            oracle=oracle,
            cleanup=ExperimentCleanupContract.build(),
            target_ref=payout_goal_plan.target_ref,
            authority_context_ref=experiment_authority_context_ref(
                self.authorization,
                self.target_origin,
                (OBJECT_AUTHORIZATION_WORKFLOW,),
            ),
            provenance_refs=(
                payout_goal_plan.plan_id,
                pair.pair_ref,
                pair.actor_evidence.evidence_id,
                pair.owner_evidence.evidence_id,
            ),
        )

    def _compile_selection(
        self,
        pair: _PairCandidate,
        *,
        actor_records: Sequence[Mapping[str, Any]],
        owner_records: Sequence[Mapping[str, Any]],
        payout_goal_plan: PayoutGoalPlan,
    ) -> _CompiledSelection:
        manifest = self._compile_manifest(pair, payout_goal_plan=payout_goal_plan)
        proof = GeneralizedOwnershipExperimentCompiler().compile(
            manifest=manifest,
            actor_records=actor_records,
            target_owner_records=owner_records,
            actor_lineage_binding_id=pair.actor_use.lineage_binding_id,
            target_owner_lineage_binding_id=pair.owner_use.lineage_binding_id,
        )
        ownership_admission = GeneralizedOwnershipExperimentAdmission(
            proof=proof,
            manifest=manifest,
            target_origin=self.target_origin,
            authorization=self.authorization,
            actor_records=actor_records,
            target_owner_records=owner_records,
        ).admit()
        return _CompiledSelection(
            pair=pair,
            manifest=manifest,
            proof=proof,
            ownership_admission=ownership_admission,
        )

    def _register_owner_capture(self, selection: _CompiledSelection) -> None:
        pair = selection.pair
        owner_request = pair.owner_index.rehydrate_use(
            evidence_id=pair.owner_evidence.evidence_id,
            use_id=pair.owner_use.use_id,
        )
        owner_value = extract_locator_value(
            kind=OwnedRequestLocatorKind(pair.owner_use.locator_kind.value),
            pointer=pair.owner_use.locator_pointer,
            url=owner_request.url,
            body=owner_request.body,
        )
        observations = tuple(
            item
            for item in pair.owner_index.ledger.observations
            if item.source_ref == pair.owner_evidence.create_source_ref
            and item.operation_id == pair.owner_evidence.create_operation_id
            and item.request_digest == pair.owner_evidence.create_request_digest
        )
        if len(observations) != 1:
            raise GeneralizedAuthorizationOneClickDenied(
                "generalized_authorization_owner_create_is_ambiguous"
            )
        create_request = pair.owner_index.ledger._rehydrate_observation(
            observations[0]
        )
        source_executor = self.backend.executors[
            self.backend.source_persona.persona_id
        ]
        registry = source_executor.policy.ownership_registry
        if registry is None or registry.register_admitted_capture_value(
            create_request.url,
            owner_value,
            actor_persona=self.backend.peer_persona.persona_id,
            source_proof_ref=selection.proof.proof_id,
            source_role_binding_ref=(
                selection.proof.target_owner.role_binding_id
            ),
            capture_digest=selection.proof.target_owner.capture_digest,
        ) is None:
            raise GeneralizedAuthorizationOneClickDenied(
                "generalized_authorization_capture_ownership_registration_failed"
            )

    async def run(
        self,
        *,
        actor_records: Sequence[Mapping[str, Any]],
        owner_records: Sequence[Mapping[str, Any]],
        payout_goal_plan: PayoutGoalPlan,
        operations: Sequence[OperationContract],
    ) -> GeneralizedAuthorizationOneClickRun:
        if not isinstance(payout_goal_plan, PayoutGoalPlan):
            raise TypeError("payout_goal_plan must be a PayoutGoalPlan")
        try:
            pairs, rejected, dropped = self._pairs(
                actor_records=actor_records,
                owner_records=owner_records,
                payout_goal_plan=payout_goal_plan,
                operations=operations,
            )
        except (TypeError, ValueError, RuntimeError) as exc:
            raise GeneralizedAuthorizationOneClickDenied(
                "generalized_authorization_one_click_selection_failed"
            ) from exc
        selection = None
        for pair in pairs:
            try:
                selection = self._compile_selection(
                    pair,
                    actor_records=actor_records,
                    owner_records=owner_records,
                    payout_goal_plan=payout_goal_plan,
                )
            except (GeneralizedOwnershipExperimentDenied, TypeError, ValueError):
                rejected += 1
                continue
            break
        if selection is None:
            return GeneralizedAuthorizationOneClickRun(
                status="no_eligible_candidate",
                candidate_pairs=len(pairs),
                rejected_pairs=rejected,
                dropped_for_bound=dropped,
            )
        disabled = tuple(
            gate
            for gate, enabled in (
                ("proof_experiment_admission", self.admission_config.enabled),
                (
                    "generalized_authorization_execution",
                    self.execution_config.enabled,
                ),
            )
            if not enabled
        )
        common = {
            "candidate_pairs": len(pairs),
            "rejected_pairs": rejected,
            "dropped_for_bound": dropped,
            "selected_pair_ref": selection.pair.pair_ref,
            "payout_candidate_id": (
                selection.pair.payout_candidate.candidate_id
            ),
            "manifest_id": selection.manifest.manifest_id,
            "ownership_proof_id": selection.proof.proof_id,
            "ownership_admission_id": selection.ownership_admission.admission_id,
        }
        if disabled:
            return GeneralizedAuthorizationOneClickRun(
                status="selected_execution_disabled",
                disabled_gates=disabled,
                **common,
            )

        try:
            self._register_owner_capture(selection)
            planner = GeneralizedAuthorizationExecutionPlanner(
                manifest=selection.manifest,
                ownership_proof=selection.proof,
                ownership_admission=selection.ownership_admission,
                backend=self.backend,
            )
            prepared = planner.prepare(
                actor_records=actor_records,
                target_owner_records=owner_records,
            )
            source_executor = self.backend.executors[
                self.backend.source_persona.persona_id
            ]
            if not isinstance(source_executor, PolicyExecutor):
                raise GeneralizedAuthorizationOneClickDenied(
                    "generalized_authorization_source_executor_is_invalid"
                )
            lease = GeneralizedExperimentAdmission(
                manifest=selection.manifest,
                target_origin=self.target_origin,
                authorization=self.authorization,
                executor=source_executor,
                runtime_actions=prepared.runtime_actions,
                runtime_world_ids={
                    selection.proof.actor.world_binding_id: (
                        self.backend.source_persona.persona_id
                    ),
                    selection.proof.target_owner.world_binding_id: (
                        self.backend.peer_persona.persona_id
                    ),
                },
                persona_vault=self.persona_vault,
                locator_ownership_proofs=(
                    prepared.locator_ownership_proofs
                ),
                config=self.admission_config,
                receipt_store=self.receipt_store,
            ).admit()
            claim = lease.claim()
            try:
                executor = GeneralizedAuthorizationExperimentExecutor(
                    manifest=selection.manifest,
                    claim=claim,
                    prepared=prepared,
                    ownership_proof=selection.proof,
                    ownership_admission=selection.ownership_admission,
                    backend=self.backend,
                    persona_vault=self.persona_vault,
                    config=self.execution_config,
                )
            except Exception:
                claim.abort(
                    "generalized_authorization_one_click_executor_rejected"
                )
                raise
            execution = await executor.execute(
                actor_records=actor_records,
                target_owner_records=owner_records,
            )
        except (
            GeneralizedAuthorizationExecutionDenied,
            GeneralizedAuthorizationOneClickDenied,
            GeneralizedOwnershipExperimentDenied,
            ProofExperimentAdmissionDenied,
            TypeError,
            ValueError,
        ) as exc:
            raise GeneralizedAuthorizationOneClickDenied(
                "generalized_authorization_one_click_dispatch_denied"
            ) from exc
        return GeneralizedAuthorizationOneClickRun(
            status=execution.status,
            execution=execution,
            **common,
        )


__all__ = [
    "GENERALIZED_AUTHORIZATION_ONE_CLICK_MODE",
    "GeneralizedAuthorizationOneClickConfig",
    "GeneralizedAuthorizationOneClickDenied",
    "GeneralizedAuthorizationOneClickDispatcher",
    "GeneralizedAuthorizationOneClickRun",
]
