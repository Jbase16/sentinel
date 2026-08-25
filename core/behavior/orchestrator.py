"""Deterministic shadow orchestration over the behavioral evidence frontier.

This module composes existing passive contracts into one closed-loop decision
artifact.  It has no transport and cannot admit or execute an experiment.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from itertools import islice
from typing import Any, Dict, Iterable, Mapping, Optional, Sequence, Tuple

from core.cortex.execution_policy import PolicyExecutor
from core.foundry.authorization import AuthorizationEnvelope

from .affordances import ClientArtifact, LatentAffordanceMiner, LatentAffordanceResult
from .closure import (
    SUBSUMED,
    UPHELD,
    ObligationDisposition,
    SecurityClosureCertificate,
    SecurityClosureEvaluator,
)
from .factory import (
    OwnedExperimentFactory,
    OwnedExperimentFactoryDenied,
    OwnedExperimentInventory,
)
from .interaction_admission import (
    InteractionAdmissionResult,
    InteractionIntentSelector,
    interaction_frontier_ref,
)
from .interactions import InteractionIntentCatalog, InteractionIntentMiner
from .lifecycle import LifecycleContractMiner, LifecycleMiningResult
from .normalize import stable_hash
from .omission import (
    MinimizedOmissionCompiler,
    OmissionCompilationResult,
)
from .obligations import OPEN, SecurityObligationGraph, SecurityObligationGraphBuilder
from .payout_goals import (
    GoalPlanningContext,
    PayoutGoalCandidate,
    PayoutGoalPlan,
    PayoutGoalTopologyPlanner,
)
from .proposals import (
    CROSS_OBJECT_READ,
    AuthorizationExperimentProposal,
    ProposalBatch,
    compile_authorization_proposals,
)
from .prerequisite_experiments import (
    GraphBoundExperimentCompilationResult,
    GraphBoundPrerequisiteExperimentCompiler,
)
from .prerequisite_admission import (
    GraphBoundManifestAdmissionPlanner,
    GraphBoundManifestAdmissionResult,
)
from .prerequisite_request_binding import (
    GraphBoundRequestBinder,
    GraphBoundRequestBindingResult,
)
from .semantic_catalog import (
    TargetSemanticCatalog,
    TargetSemanticCatalogBuilder,
)
from .state_machine import (
    StateMachineLegalityMiner,
    StateMachineLegalityResult,
)

BEHAVIORAL_SHADOW_ORCHESTRATOR_MODE = "behavioral_closed_loop_shadow_v1"

_HASH_REF = re.compile(r"^[a-z][a-z0-9_]*:[0-9a-f]{64}$")
_SEMANTIC = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_INVENTORY_STATUSES = frozenset({"not_requested", "ready", "no_ready_experiments", "blocked"})
_RESOLUTION_KINDS = frozenset(
    {
        "authorization_proposal",
        "owned_experiment",
        "omission_experiment",
        "unavailable",
    }
)
_GRAPHQL_READ = re.compile(r"^\s*(?:query\b|\{)", re.IGNORECASE)
_GRAPHQL_WRITE = re.compile(r"\b(?:mutation|subscription)\b", re.IGNORECASE)


def _hash_ref(value: Any, prefix: Optional[str] = None) -> bool:
    return (
        isinstance(value, str)
        and _HASH_REF.fullmatch(value) is not None
        and (prefix is None or value.startswith(f"{prefix}:"))
    )


def _frontier_signal(value: str) -> bool:
    return _SEMANTIC.fullmatch(value) is not None or _hash_ref(
        value,
        "interaction_intent",
    )


def _run_identity_payload(
    *,
    lifecycle: LifecycleMiningResult,
    proposals: Optional[ProposalBatch],
    affordances: LatentAffordanceResult,
    state_machine: StateMachineLegalityResult,
    omissions: OmissionCompilationResult,
    prerequisite_experiments: GraphBoundExperimentCompilationResult,
    prerequisite_admission: GraphBoundManifestAdmissionResult,
    prerequisite_requests: GraphBoundRequestBindingResult,
    interactions: InteractionIntentCatalog,
    interaction_admission: InteractionAdmissionResult,
    experiment_stage: "OwnedExperimentShadowStage",
    semantic_catalog: TargetSemanticCatalog,
    payout_goal_plan: PayoutGoalPlan,
    graph: SecurityObligationGraph,
    closure: SecurityClosureCertificate,
    ranked_frontier: Sequence["RankedSecurityObligation"],
    ranked_dropped: int,
) -> Dict[str, Any]:
    return {
        "mode": BEHAVIORAL_SHADOW_ORCHESTRATOR_MODE,
        "lifecycle_capture_digest": lifecycle.capture_digest,
        "proposal_digest": stable_hash(
            "behavioral_shadow_proposals",
            proposals.to_dict() if proposals is not None else None,
        ),
        "affordance_capture_digest": affordances.capture_digest,
        "affordance_artifact_digest": affordances.artifact_digest,
        "state_machine_result_id": state_machine.result_id,
        "omission_result_id": omissions.result_id,
        "prerequisite_experiment_result_id": prerequisite_experiments.result_id,
        "prerequisite_admission_result_id": prerequisite_admission.result_id,
        "prerequisite_request_result_id": prerequisite_requests.result_id,
        "interaction_catalog_id": interactions.catalog_id,
        "interaction_admission_result_id": interaction_admission.result_id,
        "experiment_stage": experiment_stage.to_dict(),
        "semantic_catalog_id": semantic_catalog.catalog_id,
        "payout_goal_plan_id": payout_goal_plan.plan_id,
        "graph_digest": graph.graph_digest,
        "closure_certificate_id": closure.certificate_id,
        "ranked_frontier": [item.to_dict() for item in ranked_frontier],
        "ranked_dropped": ranked_dropped,
    }


@dataclass(frozen=True)
class ShadowOrchestratorConfig:
    max_records_per_world: int = 20_000
    max_ranked_obligations: int = 512

    def __post_init__(self) -> None:
        for name, value in vars(self).items():
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")


@dataclass(frozen=True)
class OwnedExperimentShadowContext:
    """Sensitive compiler inputs that are never serialized by the shadow run."""

    authorization: AuthorizationEnvelope = field(repr=False, compare=False)
    actor_persona_id: str = field(repr=False)
    executor: PolicyExecutor = field(repr=False, compare=False)
    peer_persona_id: Optional[str] = field(default=None, repr=False)
    prerequisite_executor: Optional[PolicyExecutor] = field(
        default=None,
        repr=False,
        compare=False,
    )
    role_world_ids: Tuple[str, ...] = field(default=(), repr=False)

    def __post_init__(self) -> None:
        if (
            not isinstance(self.authorization, AuthorizationEnvelope)
            or not isinstance(self.executor, PolicyExecutor)
            or (
                self.prerequisite_executor is not None
                and not isinstance(self.prerequisite_executor, PolicyExecutor)
            )
            or not isinstance(self.actor_persona_id, str)
            or not self.actor_persona_id
            or (
                self.peer_persona_id is not None
                and (
                    not isinstance(self.peer_persona_id, str)
                    or not self.peer_persona_id
                    or self.peer_persona_id == self.actor_persona_id
                )
            )
            or not isinstance(self.role_world_ids, tuple)
            or (
                self.role_world_ids
                and (
                    self.peer_persona_id is None
                    or len(self.role_world_ids) != 2
                    or len(set(self.role_world_ids)) != 2
                    or set(self.role_world_ids)
                    != {
                        self.actor_persona_id,
                        self.peer_persona_id,
                    }
                )
            )
        ):
            raise ValueError("owned experiment shadow context is invalid")


@dataclass(frozen=True)
class OwnedExperimentShadowStage:
    status: str
    inventory: Optional[OwnedExperimentInventory] = field(
        default=None,
        repr=False,
        compare=False,
    )
    blocker: Optional[str] = None

    def __post_init__(self) -> None:
        if self.inventory is not None:
            expected = self.inventory.status
        elif self.blocker is not None:
            expected = "blocked"
        else:
            expected = "not_requested"
        if (
            self.status != expected
            or self.status not in _INVENTORY_STATUSES
            or (self.blocker is not None and _SEMANTIC.fullmatch(self.blocker) is None)
        ):
            raise ValueError("owned experiment shadow stage is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "blocker": self.blocker,
            "inventory": self.inventory.to_dict() if self.inventory is not None else None,
        }


@dataclass(frozen=True)
class RankedSecurityObligation:
    obligation_id: str
    kind: str
    risk_class: str
    score: int
    actionable: bool
    resolution_kind: str
    resolution_ref: Optional[str]
    signals: Tuple[str, ...]

    def __post_init__(self) -> None:
        resolution_valid = (
            self.resolution_kind == "unavailable" and self.resolution_ref is None
        ) or (
            self.resolution_kind == "authorization_proposal"
            and _hash_ref(self.resolution_ref, "authorization_proposal")
        ) or (
            self.resolution_kind == "owned_experiment"
            and _hash_ref(self.resolution_ref, "owned_experiment")
        ) or (
            self.resolution_kind == "omission_experiment"
            and _hash_ref(self.resolution_ref, "omission_experiment")
        )
        if (
            not _hash_ref(self.obligation_id, "security_obligation")
            or _SEMANTIC.fullmatch(self.kind) is None
            or self.risk_class not in {"control", "read", "state_mutation", "unknown"}
            or isinstance(self.score, bool)
            or not isinstance(self.score, int)
            or self.score < 0
            or not isinstance(self.actionable, bool)
            or self.resolution_kind not in _RESOLUTION_KINDS
            or not resolution_valid
            or self.actionable
            != (
                self.resolution_kind
                in {
                    "authorization_proposal",
                    "owned_experiment",
                    "omission_experiment",
                }
            )
            or tuple(sorted(set(self.signals))) != self.signals
            or any(not _frontier_signal(item) for item in self.signals)
        ):
            raise ValueError("ranked security obligation contract is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "obligation_id": self.obligation_id,
            "kind": self.kind,
            "risk_class": self.risk_class,
            "score": self.score,
            "actionable": self.actionable,
            "resolution_kind": self.resolution_kind,
            "resolution_ref": self.resolution_ref,
            "signals": list(self.signals),
        }


@dataclass(frozen=True)
class BehavioralShadowRun:
    run_id: str
    status: str
    lifecycle: LifecycleMiningResult = field(repr=False, compare=False)
    proposals: Optional[ProposalBatch] = field(repr=False, compare=False)
    affordances: LatentAffordanceResult = field(repr=False, compare=False)
    state_machine: StateMachineLegalityResult = field(repr=False, compare=False)
    omissions: OmissionCompilationResult = field(repr=False, compare=False)
    prerequisite_experiments: GraphBoundExperimentCompilationResult = field(
        repr=False,
        compare=False,
    )
    prerequisite_admission: GraphBoundManifestAdmissionResult = field(
        repr=False,
        compare=False,
    )
    prerequisite_requests: GraphBoundRequestBindingResult = field(
        repr=False,
        compare=False,
    )
    interactions: InteractionIntentCatalog = field(repr=False, compare=False)
    interaction_admission: InteractionAdmissionResult = field(
        repr=False,
        compare=False,
    )
    experiment_stage: OwnedExperimentShadowStage = field(repr=False, compare=False)
    semantic_catalog: TargetSemanticCatalog = field(repr=False, compare=False)
    payout_goal_plan: PayoutGoalPlan = field(repr=False, compare=False)
    graph: SecurityObligationGraph = field(repr=False, compare=False)
    closure: SecurityClosureCertificate = field(repr=False, compare=False)
    ranked_frontier: Tuple[RankedSecurityObligation, ...]
    ranked_dropped: int
    mode: str = BEHAVIORAL_SHADOW_ORCHESTRATOR_MODE
    executable: bool = False

    def __post_init__(self) -> None:
        payload = self._identity_payload()
        ranked_ids = [item.obligation_id for item in self.ranked_frontier]
        interaction_intent_ids = {
            item.intent_id for item in self.interactions.intents
        }
        state_candidate_graphs = {
            item.candidate_id: item.prerequisite_graph.graph_id
            for item in self.state_machine.candidates
        }
        prerequisite_manifest_ids = {
            item.manifest_id for item in self.prerequisite_admission.manifests
        }
        admitted_interaction = self.interaction_admission.admission
        if (
            self.run_id != stable_hash("behavioral_shadow_run", payload)
            or self.status != self.closure.status
            or self.mode != BEHAVIORAL_SHADOW_ORCHESTRATOR_MODE
            or self.executable
            or self.graph.target_ref != self.closure.target_ref
            or self.semantic_catalog.target_ref != self.graph.target_ref
            or self.semantic_catalog.executable
            or self.payout_goal_plan.target_ref != self.graph.target_ref
            or self.payout_goal_plan.graph_digest != self.graph.graph_digest
            or self.payout_goal_plan.executable
            or (
                any(item.actionable for item in self.ranked_frontier)
                and BehavioralShadowOrchestrator._selected_payout_candidate(
                    self.payout_goal_plan
                )
                is None
            )
            or self.prerequisite_experiments.state_machine_result_id
            != self.state_machine.result_id
            or self.prerequisite_experiments.lifecycle_capture_digest
            != self.lifecycle.capture_digest
            or self.prerequisite_experiments.executable
            or self.prerequisite_experiments.finding_authority
            or self.prerequisite_admission.compilation_result_id
            != self.prerequisite_experiments.result_id
            or self.prerequisite_admission.target_ref != self.graph.target_ref
            or self.prerequisite_admission.executable
            or self.prerequisite_admission.dispatch_authority
            or self.prerequisite_admission.finding_authority
            or self.prerequisite_admission.target_requests_sent != 0
            or self.prerequisite_requests.admission_result_id
            != self.prerequisite_admission.result_id
            or self.prerequisite_requests.compilation_result_id
            != self.prerequisite_experiments.result_id
            or self.prerequisite_requests.target_ref != self.graph.target_ref
            or self.prerequisite_requests.executable
            or self.prerequisite_requests.budget_reserved
            or self.prerequisite_requests.dispatch_authority
            or self.prerequisite_requests.finding_authority
            or self.prerequisite_requests.target_requests_sent != 0
            or any(
                item.manifest_id not in prerequisite_manifest_ids
                for item in self.prerequisite_requests.plans
            )
            or any(
                state_candidate_graphs.get(item.state_machine_candidate_id)
                != item.prerequisite_graph_id
                for item in self.prerequisite_experiments.specifications
            )
            or self.interaction_admission.catalog_id
            != self.interactions.catalog_id
            or self.interaction_admission.frontier_ref
            != interaction_frontier_ref(
                [item.to_dict() for item in self.ranked_frontier]
            )
            or (
                admitted_interaction is not None
                and (
                    admitted_interaction.intent_id not in interaction_intent_ids
                    or admitted_interaction.obligation_id not in ranked_ids
                )
            )
            or len(ranked_ids) != len(set(ranked_ids))
            or isinstance(self.ranked_dropped, bool)
            or not isinstance(self.ranked_dropped, int)
            or self.ranked_dropped < 0
            or len(self.ranked_frontier) + self.ranked_dropped != self.closure.open_count
            or any(item.obligation_id not in self.closure.unresolved_ids for item in self.ranked_frontier)
            or tuple(
                sorted(
                    self.ranked_frontier,
                    key=lambda item: (
                        not item.actionable,
                        -item.score,
                        item.kind,
                        item.obligation_id,
                    ),
                )
            )
            != self.ranked_frontier
        ):
            raise ValueError("behavioral shadow run contract is invalid")

    @property
    def selected(self) -> Optional[RankedSecurityObligation]:
        if self.ranked_frontier and self.ranked_frontier[0].actionable:
            return self.ranked_frontier[0]
        return None

    def _identity_payload(self) -> Dict[str, Any]:
        return _run_identity_payload(
            lifecycle=self.lifecycle,
            proposals=self.proposals,
            affordances=self.affordances,
            state_machine=self.state_machine,
            omissions=self.omissions,
            prerequisite_experiments=self.prerequisite_experiments,
            prerequisite_admission=self.prerequisite_admission,
            prerequisite_requests=self.prerequisite_requests,
            interactions=self.interactions,
            interaction_admission=self.interaction_admission,
            experiment_stage=self.experiment_stage,
            semantic_catalog=self.semantic_catalog,
            payout_goal_plan=self.payout_goal_plan,
            graph=self.graph,
            closure=self.closure,
            ranked_frontier=self.ranked_frontier,
            ranked_dropped=self.ranked_dropped,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": 1,
            "mode": self.mode,
            "executable": self.executable,
            "run_id": self.run_id,
            "status": self.status,
            "selected": self.selected.to_dict() if self.selected is not None else None,
            "ranked_frontier": [item.to_dict() for item in self.ranked_frontier],
            "ranked_dropped": self.ranked_dropped,
            "lifecycle": self.lifecycle.to_dict(),
            "proposals": self.proposals.to_dict() if self.proposals is not None else None,
            "affordances": self.affordances.to_dict(),
            "state_machine": self.state_machine.to_dict(),
            "omissions": self.omissions.to_dict(),
            "prerequisite_experiments": self.prerequisite_experiments.to_dict(),
            "prerequisite_admission": self.prerequisite_admission.to_dict(),
            "prerequisite_requests": self.prerequisite_requests.to_dict(),
            "interactions": self.interactions.to_dict(),
            "interaction_admission": self.interaction_admission.to_dict(),
            "experiment_stage": self.experiment_stage.to_dict(),
            "semantic_catalog": self.semantic_catalog.to_dict(),
            "payout_goal_plan": self.payout_goal_plan.to_dict(),
            "obligation_graph": self.graph.to_dict(),
            "closure": self.closure.to_dict(),
        }


class BehavioralShadowOrchestrator:
    """Build and rank one bounded evidence frontier without target I/O."""

    _KIND_SCORE = {
        "authorization_counterexample": 500,
        "ownership_boundary": 460,
        "capability_confinement": 440,
        "latent_operation_confirmation": 400,
        "state_machine_legality": 480,
        "state_machine_control": 100,
        "owned_control": 100,
    }
    _RISK_SCORE = {"state_mutation": 70, "read": 50, "unknown": 20, "control": 0}

    def __init__(
        self,
        *,
        config: ShadowOrchestratorConfig = ShadowOrchestratorConfig(),
        lifecycle_miner: Optional[LifecycleContractMiner] = None,
        affordance_miner: Optional[LatentAffordanceMiner] = None,
        state_machine_miner: Optional[StateMachineLegalityMiner] = None,
        omission_compiler: Optional[MinimizedOmissionCompiler] = None,
        prerequisite_experiment_compiler: Optional[
            GraphBoundPrerequisiteExperimentCompiler
        ] = None,
        prerequisite_admission_planner: Optional[
            GraphBoundManifestAdmissionPlanner
        ] = None,
        prerequisite_request_binder: Optional[GraphBoundRequestBinder] = None,
        interaction_miner: Optional[InteractionIntentMiner] = None,
        interaction_selector: Optional[InteractionIntentSelector] = None,
        experiment_factory: Optional[OwnedExperimentFactory] = None,
        semantic_catalog_builder: Optional[TargetSemanticCatalogBuilder] = None,
        payout_goal_planner: Optional[PayoutGoalTopologyPlanner] = None,
        graph_builder: Optional[SecurityObligationGraphBuilder] = None,
        closure_evaluator: Optional[SecurityClosureEvaluator] = None,
    ) -> None:
        if not isinstance(config, ShadowOrchestratorConfig):
            raise TypeError("config must be a ShadowOrchestratorConfig")
        self.config = config
        self.lifecycle_miner = lifecycle_miner or LifecycleContractMiner()
        self.affordance_miner = affordance_miner or LatentAffordanceMiner()
        self.state_machine_miner = (
            state_machine_miner or StateMachineLegalityMiner()
        )
        self.omission_compiler = omission_compiler or MinimizedOmissionCompiler()
        self.prerequisite_experiment_compiler = (
            prerequisite_experiment_compiler
            or GraphBoundPrerequisiteExperimentCompiler()
        )
        self.prerequisite_admission_planner = (
            prerequisite_admission_planner
            or GraphBoundManifestAdmissionPlanner()
        )
        self.prerequisite_request_binder = (
            prerequisite_request_binder or GraphBoundRequestBinder()
        )
        self.interaction_miner = interaction_miner or InteractionIntentMiner()
        self.interaction_selector = (
            interaction_selector or InteractionIntentSelector()
        )
        self.experiment_factory = experiment_factory or OwnedExperimentFactory()
        self.semantic_catalog_builder = (
            semantic_catalog_builder or TargetSemanticCatalogBuilder()
        )
        self.payout_goal_planner = payout_goal_planner or PayoutGoalTopologyPlanner()
        self.graph_builder = graph_builder or SecurityObligationGraphBuilder()
        self.closure_evaluator = closure_evaluator or SecurityClosureEvaluator()

    @staticmethod
    def _experiment_stage(
        records: Sequence[Mapping[str, Any]],
        *,
        target_origin: str,
        context: Optional[OwnedExperimentShadowContext],
        factory: OwnedExperimentFactory,
    ) -> OwnedExperimentShadowStage:
        if context is None:
            return OwnedExperimentShadowStage("not_requested")
        try:
            inventory = factory.build(
                records,
                target_origin=target_origin,
                authorization=context.authorization,
                actor_persona_id=context.actor_persona_id,
                executor=context.executor,
            )
        except OwnedExperimentFactoryDenied as exc:
            blocker = str(exc)
            if _SEMANTIC.fullmatch(blocker) is None:
                blocker = "factory_preflight_denied"
            return OwnedExperimentShadowStage("blocked", blocker=blocker)
        return OwnedExperimentShadowStage(inventory.status, inventory=inventory)

    @staticmethod
    def _proposal_read_semantics_proven(
        proposal: AuthorizationExperimentProposal,
        records: Sequence[Mapping[str, Any]],
    ) -> bool:
        if not 0 <= proposal.source_record_index < len(records):
            return False
        record = records[proposal.source_record_index]
        raw_body = record.get("request_body")
        if isinstance(raw_body, str) and raw_body:
            try:
                parsed = json.loads(raw_body)
            except (TypeError, ValueError):
                parsed = None
            items = parsed if isinstance(parsed, list) else [parsed]
            graphql_items = [item for item in items if isinstance(item, Mapping)]
            matching = [
                item
                for item in graphql_items
                if str(item.get("operationName") or "graphql_operation")
                == proposal.operation_label
            ]
            if matching:
                if len(matching) != 1:
                    return False
                query = matching[0].get("query")
                return (
                    isinstance(query, str)
                    and bool(query.strip())
                    and _GRAPHQL_READ.search(query) is not None
                    and _GRAPHQL_WRITE.search(query) is None
                )
        return str(record.get("method") or "GET").upper() == "GET"

    @staticmethod
    def _resolution_maps(
        *,
        records: Sequence[Mapping[str, Any]],
        payout_goal_plan: PayoutGoalPlan,
        proposals: Optional[ProposalBatch],
        experiment_stage: OwnedExperimentShadowStage,
        omissions: OmissionCompilationResult,
    ) -> Tuple[Dict[str, str], Dict[str, str], Dict[str, str]]:
        selected = BehavioralShadowOrchestrator._selected_payout_candidate(
            payout_goal_plan
        )
        if selected is None:
            return {}, {}, {}
        terminal_operation_id = selected.goal.terminal_operation_id
        selected_evidence = set(selected.goal.evidence_refs)

        proposal_by_subject: Dict[str, str] = {}
        if proposals is not None and selected.backend == "object_authorization":
            for proposal in proposals.proposals:
                # The established controlled authorization executor currently
                # admits only proven reads. Mutation proposals remain on the
                # obligation frontier but cannot be advertised as resolvable.
                if (
                    proposal.risk_class != CROSS_OBJECT_READ
                    or proposal.action_id != terminal_operation_id
                    or proposal.proposal_id not in selected_evidence
                    or not BehavioralShadowOrchestrator._proposal_read_semantics_proven(
                        proposal,
                        records,
                    )
                ):
                    continue
                subject_ref = stable_hash(
                    "security_subject",
                    {"proposal_id": proposal.proposal_id, "action_id": proposal.action_id},
                )
                proposal_by_subject[subject_ref] = proposal.proposal_id

        experiment_by_subject: Dict[str, str] = {}
        inventory = experiment_stage.inventory
        if inventory is not None:
            for experiment in inventory.experiments:
                if experiment.terminal_operation_id != terminal_operation_id:
                    continue
                subject_ref = stable_hash(
                    "security_subject",
                    {
                        "lifecycle_id": experiment.lifecycle_id,
                        "read_operation_id": experiment.terminal_operation_id,
                    },
                )
                experiment_by_subject[subject_ref] = experiment.experiment_id
        omission_by_subject = (
            {
                experiment.subject_ref: experiment.experiment_id
                for experiment in omissions.experiments
                if experiment.terminal_operation_id == terminal_operation_id
                and experiment.experiment_id in selected_evidence
            }
            if selected.backend == "prerequisite_omission"
            else {}
        )
        return proposal_by_subject, experiment_by_subject, omission_by_subject

    @staticmethod
    def _selected_payout_candidate(
        plan: PayoutGoalPlan,
    ) -> Optional[PayoutGoalCandidate]:
        selected = plan.selected
        context = plan.context
        if (
            plan.status != "ready"
            or selected is None
            or selected.status != "admissible"
            or selected.blockers
            or context.selected_world_ref is None
            or context.authorization_ref is None
            or not context.authorization_approved
            or not context.origin_authorized
            or selected.backend not in context.available_backends
        ):
            return None
        return selected

    def _rank_frontier(
        self,
        *,
        records: Sequence[Mapping[str, Any]],
        graph: SecurityObligationGraph,
        closure: SecurityClosureCertificate,
        dispositions: Sequence[ObligationDisposition],
        payout_goal_plan: PayoutGoalPlan,
        proposals: Optional[ProposalBatch],
        experiment_stage: OwnedExperimentShadowStage,
        omissions: OmissionCompilationResult,
    ) -> Tuple[Tuple[RankedSecurityObligation, ...], int]:
        (
            proposal_by_subject,
            experiment_by_subject,
            omission_by_subject,
        ) = self._resolution_maps(
            records=records,
            payout_goal_plan=payout_goal_plan,
            proposals=proposals,
            experiment_stage=experiment_stage,
            omissions=omissions,
        )
        disposition_status = {item.obligation_id: item.status for item in dispositions}
        final_status = {
            item.obligation_id: disposition_status.get(item.obligation_id, item.status)
            for item in graph.obligations
        }
        unresolved = set(closure.unresolved_ids)
        selected_payout = self._selected_payout_candidate(payout_goal_plan)
        ranked = []
        for obligation in graph.obligations:
            if obligation.obligation_id not in unresolved or obligation.status != OPEN:
                continue
            prerequisites_ready = all(
                final_status.get(item) in {UPHELD, SUBSUMED}
                for item in obligation.prerequisite_ids
            )
            resolution_kind = "unavailable"
            resolution_ref = None
            if prerequisites_ready and obligation.subject_ref in proposal_by_subject:
                resolution_kind = "authorization_proposal"
                resolution_ref = proposal_by_subject[obligation.subject_ref]
            elif prerequisites_ready and obligation.subject_ref in experiment_by_subject:
                resolution_kind = "owned_experiment"
                resolution_ref = experiment_by_subject[obligation.subject_ref]
            elif prerequisites_ready and obligation.subject_ref in omission_by_subject:
                resolution_kind = "omission_experiment"
                resolution_ref = omission_by_subject[obligation.subject_ref]

            signals = {"unresolved_frontier"}
            if selected_payout is None:
                signals.add("payout_goal_unselected")
            elif resolution_kind == "unavailable":
                signals.add("payout_goal_mismatch")
            else:
                signals.add("payout_goal_selected")
            if prerequisites_ready:
                signals.add("prerequisites_upheld")
            else:
                signals.add("prerequisites_open")
            if resolution_kind == "authorization_proposal":
                signals.add("paired_world_proposal_ready")
            elif resolution_kind == "owned_experiment":
                signals.add("proof_carrying_experiment_ready")
            elif resolution_kind == "omission_experiment":
                signals.add("omission_proof_compiled")
                signals.add("omission_confirmation_eligible")
            else:
                signals.add("no_safe_resolution_path")
            if obligation.source_kind == "interaction_asymmetry":
                intent_refs = tuple(
                    ref
                    for ref in obligation.evidence_refs
                    if _hash_ref(ref, "interaction_intent")
                )
                if len(intent_refs) != 1:
                    raise ValueError(
                        "interaction asymmetry obligation has no exact intent binding"
                    )
                signals.add(intent_refs[0])

            actionable = resolution_kind in {
                "authorization_proposal",
                "owned_experiment",
                "omission_experiment",
            }
            score = (
                self._KIND_SCORE.get(obligation.kind, 250)
                + self._RISK_SCORE[obligation.risk_class]
                + (200 if actionable else 0)
                + (60 if resolution_kind == "owned_experiment" else 0)
                + (selected_payout.score if actionable and selected_payout else 0)
                + min(32, len(obligation.evidence_refs) * 4)
            )
            ranked.append(
                RankedSecurityObligation(
                    obligation_id=obligation.obligation_id,
                    kind=obligation.kind,
                    risk_class=obligation.risk_class,
                    score=score,
                    actionable=actionable,
                    resolution_kind=resolution_kind,
                    resolution_ref=resolution_ref,
                    signals=tuple(sorted(signals)),
                )
            )
        ranked.sort(
            key=lambda item: (
                not item.actionable,
                -item.score,
                item.kind,
                item.obligation_id,
            )
        )
        dropped = max(0, len(ranked) - self.config.max_ranked_obligations)
        return tuple(ranked[: self.config.max_ranked_obligations]), dropped

    def run(
        self,
        records: Sequence[Mapping[str, Any]],
        *,
        target_origin: str,
        world_id: str = "captured",
        peer_records: Sequence[Mapping[str, Any]] = (),
        peer_world_id: str = "peer",
        artifacts: Sequence[ClientArtifact] = (),
        controls: Sequence[Mapping[str, Any]] = (),
        peer_controls: Sequence[Mapping[str, Any]] = (),
        interaction_page_url: Optional[str] = None,
        experiment_context: Optional[OwnedExperimentShadowContext] = None,
        dispositions: Iterable[ObligationDisposition] = (),
        previous_graph: Optional[SecurityObligationGraph] = None,
        derivation_round: int = 1,
    ) -> BehavioralShadowRun:
        if isinstance(records, (str, bytes)) or isinstance(peer_records, (str, bytes)):
            raise TypeError("behavioral shadow records must be sequences of mappings")
        if any(not isinstance(item, Mapping) for item in (*records, *peer_records)):
            raise TypeError("behavioral shadow records must contain mappings")
        if isinstance(controls, (str, bytes)) or isinstance(
            peer_controls, (str, bytes)
        ):
            raise TypeError("behavioral shadow controls must be sequences")
        if len(records) > self.config.max_records_per_world or len(peer_records) > self.config.max_records_per_world:
            raise ValueError("behavioral shadow records exceed per-world limit")
        if not isinstance(world_id, str) or not world_id:
            raise ValueError("world_id must be non-empty")
        if peer_records and (
            not isinstance(peer_world_id, str)
            or not peer_world_id
            or peer_world_id == world_id
        ):
            raise ValueError("peer_world_id must identify a distinct non-empty world")
        if experiment_context is not None and experiment_context.actor_persona_id != world_id:
            raise ValueError("experiment context actor does not match world_id")
        if (
            experiment_context is not None
            and experiment_context.peer_persona_id is not None
            and experiment_context.peer_persona_id != peer_world_id
        ):
            raise ValueError("experiment context peer does not match peer_world_id")

        primary_records = tuple(records)
        secondary_records = tuple(peer_records)
        artifact_values = tuple(artifacts)
        lifecycle = self.lifecycle_miner.mine(primary_records, world_id=world_id)
        proposals = (
            compile_authorization_proposals(
                primary_records,
                secondary_records,
                source_world=world_id,
                peer_world=peer_world_id,
            )
            if secondary_records
            else None
        )
        affordances = self.affordance_miner.mine(
            primary_records,
            artifact_values,
            target_origin=target_origin,
            world_id=world_id,
        )
        state_machine = self.state_machine_miner.mine(
            primary_records,
            world_id=world_id,
        )
        omissions = self.omission_compiler.compile(
            primary_records,
            world_id=world_id,
            lifecycle=lifecycle,
            state_machine=state_machine,
        )
        prerequisite_experiments = self.prerequisite_experiment_compiler.compile(
            primary_records,
            world_id=world_id,
            lifecycle=lifecycle,
            state_machine=state_machine,
        )
        interactions = self.interaction_miner.mine(
            controls,
            target_origin=target_origin,
            world_id=world_id,
            peer_controls=peer_controls,
            peer_world_id=peer_world_id,
            page_url=interaction_page_url,
        )
        experiment_stage = self._experiment_stage(
            primary_records,
            target_origin=target_origin,
            context=experiment_context,
            factory=self.experiment_factory,
        )
        graph = self.graph_builder.build(
            target_origin=target_origin,
            lifecycle=lifecycle,
            proposals=proposals,
            affordances=affordances,
            state_machine=state_machine,
            omissions=omissions,
            interactions=interactions,
            interaction_source_world_ref=stable_hash("world", world_id),
        )
        prerequisite_executor = (
            experiment_context.prerequisite_executor
            if experiment_context is not None
            and experiment_context.prerequisite_executor is not None
            else (
                experiment_context.executor
                if experiment_context is not None
                else None
            )
        )
        prerequisite_admission = self.prerequisite_admission_planner.plan(
            compilation=prerequisite_experiments,
            target_origin=target_origin,
            target_ref=graph.target_ref,
            world_id=world_id,
            authorization=(
                experiment_context.authorization
                if experiment_context is not None
                else None
            ),
            executor=prerequisite_executor,
            actor_persona_id=(
                experiment_context.actor_persona_id
                if experiment_context is not None
                else None
            ),
        )
        prerequisite_requests = self.prerequisite_request_binder.bind(
            primary_records,
            target_origin=target_origin,
            world_id=world_id,
            lifecycle=lifecycle,
            state_machine=state_machine,
            compilation=prerequisite_experiments,
            admission=prerequisite_admission,
            executor=prerequisite_executor,
        )
        semantic_catalog = self.semantic_catalog_builder.build(
            primary_records,
            target_ref=graph.target_ref,
            target_origin=target_origin,
            world_id=world_id,
            peer_records=secondary_records,
            peer_world_id=peer_world_id,
            artifacts=artifact_values,
            affordances=affordances,
            interactions=interactions,
            lifecycle=lifecycle,
        )
        if isinstance(dispositions, (str, bytes)):
            raise TypeError("dispositions must contain ObligationDisposition values")
        disposition_values = tuple(islice(dispositions, len(graph.obligations) + 1))
        if len(disposition_values) > len(graph.obligations):
            raise ValueError("dispositions exceed graph obligation count")
        closure = self.closure_evaluator.evaluate(
            graph,
            dispositions=disposition_values,
            previous_graph=previous_graph,
            derivation_round=derivation_round,
        )
        unresolved_ids = set(closure.unresolved_ids)
        frontier_evidence_refs = tuple(
            sorted(
                {
                    evidence_ref
                    for obligation in graph.obligations
                    if obligation.obligation_id in unresolved_ids
                    for evidence_ref in obligation.evidence_refs
                }
            )
        )
        available_backends = []
        graph_bound_omission_plans = tuple(
            item
            for item in prerequisite_requests.plans
            if item.family == "omission"
        )
        # The generalized locator-bound authorization adapter can validate
        # paired captures that the narrower legacy proposal compiler cannot
        # represent (for example form and GraphQL locator shapes).  Declaring
        # the backend available grants no authority; exact pair compilation and
        # PolicyExecutor admission remain mandatory downstream.
        if secondary_records:
            available_backends.append("object_authorization")
        if graph_bound_omission_plans:
            available_backends.append("graph_bound_prerequisite")
        if omissions.experiments:
            available_backends.append("prerequisite_omission")
        owned_world_ids = ()
        role_world_ids = ()
        authorization = None
        if experiment_context is not None:
            authorization = experiment_context.authorization
            owned_world_ids = (experiment_context.actor_persona_id,)
            if experiment_context.peer_persona_id is not None:
                owned_world_ids = (*owned_world_ids, experiment_context.peer_persona_id)
            role_world_ids = experiment_context.role_world_ids
            if role_world_ids:
                # Role worlds are an explicit, mutually exclusive execution
                # profile. Passive reconstruction can still describe other
                # properties, but those backends must not influence the payout
                # selection consumed by the role dispatcher.
                available_backends = ["authority_monotonicity"]
        graph_bound_terminal_ids = (
            ()
            if role_world_ids
            else tuple(
                sorted(
                    {
                        item.baseline_operation_ids[-1]
                        for item in graph_bound_omission_plans
                    }
                )
            )
        )
        payout_context = GoalPlanningContext.build(
            target_ref=graph.target_ref,
            target_origin=target_origin,
            authorization=authorization,
            selected_world_id=world_id,
            owned_world_ids=owned_world_ids,
            role_world_ids=role_world_ids,
            lifecycle_available=bool(state_machine.candidates),
            available_backends=available_backends,
            graph_bound_prerequisite_terminal_ids=graph_bound_terminal_ids,
        )
        payout_goal_plan = self.payout_goal_planner.plan(
            semantic_catalog.planner_operations(
                world_ref=stable_hash("world", world_id),
            ),
            graph=graph,
            context=payout_context,
            frontier_evidence_refs=frontier_evidence_refs,
            proposals=proposals,
            state_machine=state_machine,
            omissions=omissions,
        )
        ranked, ranked_dropped = self._rank_frontier(
            records=primary_records,
            graph=graph,
            closure=closure,
            dispositions=disposition_values,
            payout_goal_plan=payout_goal_plan,
            proposals=proposals,
            experiment_stage=experiment_stage,
            omissions=omissions,
        )
        interaction_policy = (
            experiment_context.executor.policy
            if experiment_context is not None
            else None
        )
        interaction_admission = self.interaction_selector.select(
            interactions,
            tuple(item.to_dict() for item in ranked),
            world_id=world_id,
            policy_digest=(
                interaction_policy.digest()
                if interaction_policy is not None
                else None
            ),
            budget_snapshot=(
                interaction_policy.budget.snapshot()
                if interaction_policy is not None
                else None
            ),
            max_total_requests=(
                interaction_policy.budget.max_total_requests
                if interaction_policy is not None
                else None
            ),
        )
        return BehavioralShadowRun(
            run_id=stable_hash(
                "behavioral_shadow_run",
                _run_identity_payload(
                    lifecycle=lifecycle,
                    proposals=proposals,
                    affordances=affordances,
                    state_machine=state_machine,
                    omissions=omissions,
                    prerequisite_experiments=prerequisite_experiments,
                    prerequisite_admission=prerequisite_admission,
                    prerequisite_requests=prerequisite_requests,
                    interactions=interactions,
                    interaction_admission=interaction_admission,
                    experiment_stage=experiment_stage,
                    semantic_catalog=semantic_catalog,
                    payout_goal_plan=payout_goal_plan,
                    graph=graph,
                    closure=closure,
                    ranked_frontier=ranked,
                    ranked_dropped=ranked_dropped,
                ),
            ),
            status=closure.status,
            lifecycle=lifecycle,
            proposals=proposals,
            affordances=affordances,
            state_machine=state_machine,
            omissions=omissions,
            prerequisite_experiments=prerequisite_experiments,
            prerequisite_admission=prerequisite_admission,
            prerequisite_requests=prerequisite_requests,
            interactions=interactions,
            interaction_admission=interaction_admission,
            experiment_stage=experiment_stage,
            semantic_catalog=semantic_catalog,
            payout_goal_plan=payout_goal_plan,
            graph=graph,
            closure=closure,
            ranked_frontier=ranked,
            ranked_dropped=ranked_dropped,
        )


__all__ = [
    "BEHAVIORAL_SHADOW_ORCHESTRATOR_MODE",
    "BehavioralShadowOrchestrator",
    "BehavioralShadowRun",
    "OwnedExperimentShadowContext",
    "OwnedExperimentShadowStage",
    "RankedSecurityObligation",
    "ShadowOrchestratorConfig",
]
