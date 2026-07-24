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
from .lifecycle import LifecycleContractMiner, LifecycleMiningResult
from .normalize import stable_hash
from .obligations import OPEN, SecurityObligationGraph, SecurityObligationGraphBuilder
from .proposals import (
    CROSS_OBJECT_READ,
    AuthorizationExperimentProposal,
    ProposalBatch,
    compile_authorization_proposals,
)
from .state_machine import (
    StateMachineLegalityMiner,
    StateMachineLegalityResult,
)

BEHAVIORAL_SHADOW_ORCHESTRATOR_MODE = "behavioral_closed_loop_shadow_v1"

_HASH_REF = re.compile(r"^[a-z][a-z0-9_]*:[0-9a-f]{64}$")
_SEMANTIC = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_INVENTORY_STATUSES = frozenset({"not_requested", "ready", "no_ready_experiments", "blocked"})
_RESOLUTION_KINDS = frozenset({"authorization_proposal", "owned_experiment", "unavailable"})
_GRAPHQL_READ = re.compile(r"^\s*(?:query\b|\{)", re.IGNORECASE)
_GRAPHQL_WRITE = re.compile(r"\b(?:mutation|subscription)\b", re.IGNORECASE)


def _hash_ref(value: Any, prefix: Optional[str] = None) -> bool:
    return (
        isinstance(value, str)
        and _HASH_REF.fullmatch(value) is not None
        and (prefix is None or value.startswith(f"{prefix}:"))
    )


def _run_identity_payload(
    *,
    lifecycle: LifecycleMiningResult,
    proposals: Optional[ProposalBatch],
    affordances: LatentAffordanceResult,
    state_machine: StateMachineLegalityResult,
    experiment_stage: "OwnedExperimentShadowStage",
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
        "experiment_stage": experiment_stage.to_dict(),
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

    def __post_init__(self) -> None:
        if (
            not isinstance(self.authorization, AuthorizationEnvelope)
            or not isinstance(self.executor, PolicyExecutor)
            or not isinstance(self.actor_persona_id, str)
            or not self.actor_persona_id
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
            or self.actionable != (self.resolution_kind != "unavailable")
            or tuple(sorted(set(self.signals))) != self.signals
            or any(_SEMANTIC.fullmatch(item) is None for item in self.signals)
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
    experiment_stage: OwnedExperimentShadowStage = field(repr=False, compare=False)
    graph: SecurityObligationGraph = field(repr=False, compare=False)
    closure: SecurityClosureCertificate = field(repr=False, compare=False)
    ranked_frontier: Tuple[RankedSecurityObligation, ...]
    ranked_dropped: int
    mode: str = BEHAVIORAL_SHADOW_ORCHESTRATOR_MODE
    executable: bool = False

    def __post_init__(self) -> None:
        payload = self._identity_payload()
        ranked_ids = [item.obligation_id for item in self.ranked_frontier]
        if (
            self.run_id != stable_hash("behavioral_shadow_run", payload)
            or self.status != self.closure.status
            or self.mode != BEHAVIORAL_SHADOW_ORCHESTRATOR_MODE
            or self.executable
            or self.graph.target_ref != self.closure.target_ref
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
            experiment_stage=self.experiment_stage,
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
            "experiment_stage": self.experiment_stage.to_dict(),
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
        experiment_factory: Optional[OwnedExperimentFactory] = None,
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
        self.experiment_factory = experiment_factory or OwnedExperimentFactory()
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
        proposals: Optional[ProposalBatch],
        experiment_stage: OwnedExperimentShadowStage,
    ) -> Tuple[Dict[str, str], Dict[str, str]]:
        proposal_by_subject: Dict[str, str] = {}
        if proposals is not None:
            for proposal in proposals.proposals:
                # The established controlled authorization executor currently
                # admits only proven reads. Mutation proposals remain on the
                # obligation frontier but cannot be advertised as resolvable.
                if (
                    proposal.risk_class != CROSS_OBJECT_READ
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
                subject_ref = stable_hash(
                    "security_subject",
                    {
                        "lifecycle_id": experiment.lifecycle_id,
                        "read_operation_id": experiment.terminal_operation_id,
                    },
                )
                experiment_by_subject[subject_ref] = experiment.experiment_id
        return proposal_by_subject, experiment_by_subject

    def _rank_frontier(
        self,
        *,
        records: Sequence[Mapping[str, Any]],
        graph: SecurityObligationGraph,
        closure: SecurityClosureCertificate,
        dispositions: Sequence[ObligationDisposition],
        proposals: Optional[ProposalBatch],
        experiment_stage: OwnedExperimentShadowStage,
    ) -> Tuple[Tuple[RankedSecurityObligation, ...], int]:
        proposal_by_subject, experiment_by_subject = self._resolution_maps(
            records=records,
            proposals=proposals,
            experiment_stage=experiment_stage,
        )
        disposition_status = {item.obligation_id: item.status for item in dispositions}
        final_status = {
            item.obligation_id: disposition_status.get(item.obligation_id, item.status)
            for item in graph.obligations
        }
        unresolved = set(closure.unresolved_ids)
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

            signals = {"unresolved_frontier"}
            if prerequisites_ready:
                signals.add("prerequisites_upheld")
            else:
                signals.add("prerequisites_open")
            if resolution_kind == "authorization_proposal":
                signals.add("paired_world_proposal_ready")
            elif resolution_kind == "owned_experiment":
                signals.add("proof_carrying_experiment_ready")
            else:
                signals.add("no_safe_resolution_path")

            actionable = resolution_kind != "unavailable"
            score = (
                self._KIND_SCORE.get(obligation.kind, 250)
                + self._RISK_SCORE[obligation.risk_class]
                + (200 if actionable else 0)
                + (60 if resolution_kind == "owned_experiment" else 0)
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
        experiment_context: Optional[OwnedExperimentShadowContext] = None,
        dispositions: Iterable[ObligationDisposition] = (),
        previous_graph: Optional[SecurityObligationGraph] = None,
        derivation_round: int = 1,
    ) -> BehavioralShadowRun:
        if isinstance(records, (str, bytes)) or isinstance(peer_records, (str, bytes)):
            raise TypeError("behavioral shadow records must be sequences of mappings")
        if any(not isinstance(item, Mapping) for item in (*records, *peer_records)):
            raise TypeError("behavioral shadow records must contain mappings")
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
        ranked, ranked_dropped = self._rank_frontier(
            records=primary_records,
            graph=graph,
            closure=closure,
            dispositions=disposition_values,
            proposals=proposals,
            experiment_stage=experiment_stage,
        )
        return BehavioralShadowRun(
            run_id=stable_hash(
                "behavioral_shadow_run",
                _run_identity_payload(
                    lifecycle=lifecycle,
                    proposals=proposals,
                    affordances=affordances,
                    state_machine=state_machine,
                    experiment_stage=experiment_stage,
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
            experiment_stage=experiment_stage,
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
