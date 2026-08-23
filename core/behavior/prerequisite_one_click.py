"""Least-authority ordinary-click dispatch for graph-bound prerequisite proof."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple

from core.cortex.execution_policy import PolicyExecutor
from core.foundry.authorization import AuthorizationEnvelope

from .lifecycle import LifecycleMiningResult
from .normalize import stable_hash
from .obligations import SecurityObligationGraph
from .payout_goals import PayoutGoalPlan, ProofTopology, SecurityProperty
from .prerequisite_capture_freshness import (
    GraphBoundCaptureFreshnessBinding,
)
from .prerequisite_contracts import GRAPH_BOUND_PREREQUISITE_WORKFLOW
from .prerequisite_admission import GraphBoundManifestAdmissionPlanner
from .prerequisite_execution import (
    GRAPH_BOUND_PREREQUISITE_EXECUTION_ENV,
    GraphBoundPrerequisiteExecutionConfig,
    GraphBoundPrerequisiteExecutionDenied,
    GraphBoundPrerequisiteExecutionResult,
    GraphBoundPrerequisiteExperimentExecutor,
)
from .prerequisite_execution_claim import (
    GRAPH_BOUND_EXECUTION_CLAIM_ENV,
    GraphBoundExecutionClaimAdmission,
    GraphBoundExecutionClaimConfig,
)
from .prerequisite_experiments import GraphBoundExperimentCompilationResult
from .prerequisite_provisioning import GRAPH_BOUND_FRESH_WORLD_PROVISIONING_ENV
from .prerequisite_request_binding import (
    GraphBoundPreparedRequestPlan,
    GraphBoundRequestBinder,
)
from .receipts import (
    BehavioralReceiptStore,
    redacted_graph_bound_prerequisite_execution_outcome,
)
from .state_machine import StateMachineLegalityResult


GRAPH_BOUND_PREREQUISITE_ONE_CLICK_MODE = (
    "behavioral_graph_bound_prerequisite_one_click_v1"
)
GRAPH_BOUND_PREREQUISITE_BACKEND = "graph_bound_prerequisite"


class GraphBoundPrerequisiteOneClickDenied(RuntimeError):
    """The selected graph-bound ordinary-click proof failed closed."""


class GraphBoundPrerequisiteOneClickInternalError(RuntimeError):
    """Graph coordination failed after admission and requires operator review."""


@dataclass(frozen=True)
class GraphBoundPrerequisiteFindingCandidate:
    """Strict adapter from a completed positive receipt to a finding payload."""

    finding_id: str
    claim_contract_id: str
    plan_id: str
    provisioning_id: str
    oracle_requirement_id: str
    reference_state_id: str
    oracle_evaluation_id: str
    effect_witness_ref: str
    runtime_value_inequality_ref: str
    terminal_evidence_refs: Tuple[str, ...]
    cleanup_evidence_refs: Tuple[str, ...]
    provenance_root: str
    payout_goal_plan_id: str
    payout_candidate_id: str
    payout_goal_id: str
    payout_terminal_operation_id: str
    specification_id: str
    graph_target_ref: str
    graph_digest: str
    selection_ref: str
    proof_kind: str = "graph_bound_prerequisite_omission_fail_open"
    finding_authority: bool = True

    @classmethod
    def from_completed_outcome(
        cls,
        outcome: Mapping[str, Any],
    ) -> "GraphBoundPrerequisiteFindingCandidate":
        candidate_outcome = dict(outcome)
        if (
            candidate_outcome.get("status") == "already_executed"
            and candidate_outcome.get("oracle_verdict")
            in {"confirmed", "refuted", "inconclusive"}
        ):
            candidate_outcome["status"] = candidate_outcome["oracle_verdict"]
        redacted = redacted_graph_bound_prerequisite_execution_outcome(
            candidate_outcome
        )
        if (
            redacted["family"] != "omission"
            or redacted["status"] != "confirmed"
            or redacted["finding_confirmed"] is not True
            or redacted["cleanup_status"] != "verified"
            or redacted["orphaned_owned_state_possible"] is not False
            or not isinstance(redacted["finding_candidate_ref"], str)
            or not isinstance(redacted["effect_witness_ref"], str)
            or not isinstance(redacted["runtime_value_inequality_ref"], str)
            or not isinstance(redacted.get("selection_ref"), str)
        ):
            raise GraphBoundPrerequisiteOneClickDenied(
                "graph_bound_completed_outcome_is_not_finding_eligible"
            )
        return cls(
            finding_id=redacted["finding_candidate_ref"],
            claim_contract_id=redacted["claim_contract_id"],
            plan_id=redacted["plan_id"],
            provisioning_id=redacted["provisioning_id"],
            oracle_requirement_id=redacted["oracle_requirement_id"],
            reference_state_id=redacted["reference_state_id"],
            oracle_evaluation_id=redacted["oracle_evaluation_id"],
            effect_witness_ref=redacted["effect_witness_ref"],
            runtime_value_inequality_ref=redacted[
                "runtime_value_inequality_ref"
            ],
            terminal_evidence_refs=tuple(redacted["terminal_evidence_refs"]),
            cleanup_evidence_refs=tuple(redacted["cleanup_evidence_refs"]),
            provenance_root=redacted["provenance_root"],
            payout_goal_plan_id=redacted["payout_goal_plan_id"],
            payout_candidate_id=redacted["payout_candidate_id"],
            payout_goal_id=redacted["payout_goal_id"],
            payout_terminal_operation_id=redacted[
                "payout_terminal_operation_id"
            ],
            specification_id=redacted["specification_id"],
            graph_target_ref=redacted["graph_target_ref"],
            graph_digest=redacted["graph_digest"],
            selection_ref=redacted["selection_ref"],
        )

    def __post_init__(self) -> None:
        payload = {
            "oracle_requirement_id": self.oracle_requirement_id,
            "plan_id": self.plan_id,
            "family": "omission",
            "terminal_evidence_refs": list(self.terminal_evidence_refs),
            "effect_witness_ref": self.effect_witness_ref,
            "verdict": "confirmed",
        }
        selection_payload = {
            "payout_goal_plan_id": self.payout_goal_plan_id,
            "payout_candidate_id": self.payout_candidate_id,
            "payout_goal_id": self.payout_goal_id,
            "payout_terminal_operation_id": self.payout_terminal_operation_id,
            "specification_id": self.specification_id,
            "plan_id": self.plan_id,
            "graph_target_ref": self.graph_target_ref,
            "graph_digest": self.graph_digest,
        }
        if (
            self.finding_id
            != stable_hash("graph_bound_prerequisite_candidate", payload)
            or len(self.terminal_evidence_refs) != 3
            or len(self.cleanup_evidence_refs) != 6
            or self.selection_ref
            != stable_hash("graph_bound_one_click_selection", selection_payload)
            or self.proof_kind != "graph_bound_prerequisite_omission_fail_open"
            or not self.finding_authority
        ):
            raise ValueError("graph-bound prerequisite finding candidate is invalid")

    def to_finding(self) -> Dict[str, Any]:
        selection_payload = {
            "payout_goal_plan_id": self.payout_goal_plan_id,
            "payout_candidate_id": self.payout_candidate_id,
            "payout_goal_id": self.payout_goal_id,
            "payout_terminal_operation_id": self.payout_terminal_operation_id,
            "specification_id": self.specification_id,
            "plan_id": self.plan_id,
            "graph_target_ref": self.graph_target_ref,
            "graph_digest": self.graph_digest,
        }
        return {
            "id": self.finding_id,
            "type": "State-machine prerequisite enforcement failure",
            "severity": "MEDIUM",
            "tool": "behavioral_graph_bound_prerequisite",
            "target": self.plan_id,
            "message": (
                "Three fresh owned worlds reproduced the captured terminal "
                "effect after an object-bound prerequisite was omitted, while "
                "an independently valid cross-world capability was rejected."
            ),
            "tags": [
                "verified",
                "business_logic",
                "state_machine",
                "graph_bound_prerequisite",
                "prerequisite_omission",
            ],
            "families": ["confirmed_vuln"],
            "metadata": {
                "vuln_class": "business_logic",
                "subtype": self.proof_kind,
                "finding_candidate_ref": self.finding_id,
                "claim_contract_id": self.claim_contract_id,
                "plan_id": self.plan_id,
                "provisioning_id": self.provisioning_id,
                "oracle_requirement_id": self.oracle_requirement_id,
                "reference_state_id": self.reference_state_id,
                "oracle_evaluation_id": self.oracle_evaluation_id,
                "effect_witness_ref": self.effect_witness_ref,
                "runtime_value_inequality_ref": (
                    self.runtime_value_inequality_ref
                ),
                "terminal_evidence_refs": list(self.terminal_evidence_refs),
                "cleanup_evidence_refs": list(self.cleanup_evidence_refs),
                "provenance_root": self.provenance_root,
                **selection_payload,
                "selection_ref": self.selection_ref,
                "cleanup_status": "verified",
                "orphaned_owned_state_possible": False,
                "adversarial_triage_required": True,
                "promotion_authority": False,
                "submission_authority": False,
            },
        }


@dataclass(frozen=True)
class GraphBoundPrerequisiteOneClickRun:
    status: str
    payout_candidate_id: Optional[str] = None
    specification_id: Optional[str] = None
    plan_id: Optional[str] = None
    payout_goal_plan_id: Optional[str] = None
    payout_goal_id: Optional[str] = None
    payout_terminal_operation_id: Optional[str] = None
    graph_target_ref: Optional[str] = None
    graph_digest: Optional[str] = None
    selection_ref: Optional[str] = None
    disabled_gates: Tuple[str, ...] = ()
    execution: Optional[GraphBoundPrerequisiteExecutionResult] = field(
        default=None,
        repr=False,
        compare=False,
    )
    finding: Optional[GraphBoundPrerequisiteFindingCandidate] = None
    mode: str = GRAPH_BOUND_PREREQUISITE_ONE_CLICK_MODE
    promotion_authority: bool = False
    finding_authority: bool = False

    def __post_init__(self) -> None:
        completed_refs = (
            self.payout_candidate_id,
            self.specification_id,
            self.plan_id,
            self.payout_goal_plan_id,
            self.payout_goal_id,
            self.payout_terminal_operation_id,
            self.graph_target_ref,
            self.graph_digest,
            self.selection_ref,
        )
        if (
            self.mode != GRAPH_BOUND_PREREQUISITE_ONE_CLICK_MODE
            or self.status
            not in {
                "no_eligible_candidate",
                "selected_execution_disabled",
                "selected_plan_unavailable",
                "completed",
            }
            or self.promotion_authority
            or self.finding_authority
            or (self.status == "no_eligible_candidate" and any(completed_refs))
            or (
                self.status in {
                    "selected_execution_disabled",
                    "selected_plan_unavailable",
                }
                and not isinstance(self.payout_candidate_id, str)
            )
            or (
                self.status in {
                    "selected_execution_disabled",
                    "selected_plan_unavailable",
                }
                and any(completed_refs[1:])
            )
            or (self.status == "completed" and not all(completed_refs))
            or (self.status == "selected_execution_disabled")
            != bool(self.disabled_gates)
            or (self.status == "completed") != (self.execution is not None)
            or (self.finding is not None)
            != (
                self.execution is not None
                and self.execution.finding_confirmed
            )
        ):
            raise ValueError("graph-bound prerequisite one-click run is invalid")

    @property
    def selected(self) -> bool:
        return self.payout_candidate_id is not None

    @property
    def dispatched(self) -> bool:
        return self.status == "completed" and self.execution is not None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": 1,
            "mode": self.mode,
            "status": self.status,
            "payout_candidate_id": self.payout_candidate_id,
            "specification_id": self.specification_id,
            "plan_id": self.plan_id,
            "payout_goal_plan_id": self.payout_goal_plan_id,
            "payout_goal_id": self.payout_goal_id,
            "payout_terminal_operation_id": self.payout_terminal_operation_id,
            "graph_target_ref": self.graph_target_ref,
            "graph_digest": self.graph_digest,
            "selection_ref": self.selection_ref,
            "disabled_gates": list(self.disabled_gates),
            "dispatched": self.dispatched,
            "finding_candidate_ref": (
                self.finding.finding_id if self.finding is not None else None
            ),
            "promotion_authority": False,
            "finding_authority": False,
        }

    def execution_response(self) -> Dict[str, Any]:
        if self.execution is None:
            raise GraphBoundPrerequisiteOneClickDenied(
                "graph_bound_one_click_execution_is_missing"
            )
        response = self.execution.execution_response()
        response.update(
            {
                "payout_goal_plan_id": self.payout_goal_plan_id,
                "payout_candidate_id": self.payout_candidate_id,
                "payout_goal_id": self.payout_goal_id,
                "payout_terminal_operation_id": (
                    self.payout_terminal_operation_id
                ),
                "specification_id": self.specification_id,
                "graph_target_ref": self.graph_target_ref,
                "graph_digest": self.graph_digest,
                "selection_ref": self.selection_ref,
            }
        )
        response["graph_bound_prerequisite_one_click"] = self.to_dict()
        response["finding"] = (
            self.finding.to_finding() if self.finding is not None else None
        )
        return response


class GraphBoundPrerequisiteOneClickDispatcher:
    """Select and execute one graph-bound payout plan without legacy fallback."""

    def __init__(
        self,
        *,
        target_origin: str,
        world_id: str,
        actor_persona_id: str,
        authorization: AuthorizationEnvelope,
        executor: PolicyExecutor,
        receipt_store: BehavioralReceiptStore,
        claim_config: Optional[GraphBoundExecutionClaimConfig] = None,
        execution_config: Optional[GraphBoundPrerequisiteExecutionConfig] = None,
        claim_gate_enabled: Optional[bool] = None,
        provisioning_gate_enabled: Optional[bool] = None,
        execution_gate_enabled: Optional[bool] = None,
    ) -> None:
        if not isinstance(authorization, AuthorizationEnvelope):
            raise TypeError("authorization must be an AuthorizationEnvelope")
        if not isinstance(executor, PolicyExecutor):
            raise TypeError("executor must be a PolicyExecutor")
        if not isinstance(receipt_store, BehavioralReceiptStore):
            raise TypeError("receipt_store must be a BehavioralReceiptStore")
        self.target_origin = target_origin
        self.world_id = world_id
        self.actor_persona_id = actor_persona_id
        self.authorization = authorization
        self.executor = executor
        self.receipt_store = receipt_store
        self.claim_config = (
            claim_config or GraphBoundExecutionClaimConfig.from_environment()
        )
        self.execution_config = (
            execution_config
            or GraphBoundPrerequisiteExecutionConfig.from_environment()
        )
        explicit_gate_values = (
            claim_gate_enabled,
            provisioning_gate_enabled,
            execution_gate_enabled,
        )
        if any(
            value is not None and not isinstance(value, bool)
            for value in explicit_gate_values
        ):
            raise TypeError("graph-bound gate states must be booleans")
        self.claim_gate_enabled = (
            self.claim_config.enabled
            if claim_gate_enabled is None
            else claim_gate_enabled
        )
        self.provisioning_gate_enabled = (
            self.execution_config.enabled
            if provisioning_gate_enabled is None
            else provisioning_gate_enabled
        )
        self.execution_gate_enabled = (
            self.execution_config.enabled
            if execution_gate_enabled is None
            else execution_gate_enabled
        )
        if self.claim_config.enabled != self.claim_gate_enabled or (
            self.execution_config.enabled
            != (
                self.provisioning_gate_enabled
                and self.execution_gate_enabled
            )
        ):
            raise ValueError("graph-bound gate config does not match gate states")

    def _disabled_gates(self) -> Tuple[str, ...]:
        disabled = []
        if not self.claim_gate_enabled:
            disabled.append(GRAPH_BOUND_EXECUTION_CLAIM_ENV)
        if not self.provisioning_gate_enabled:
            disabled.append(GRAPH_BOUND_FRESH_WORLD_PROVISIONING_ENV)
        if not self.execution_gate_enabled:
            disabled.append(GRAPH_BOUND_PREREQUISITE_EXECUTION_ENV)
        return tuple(disabled)

    @staticmethod
    def _selected_plan(
        *,
        payout_goal_plan: PayoutGoalPlan,
        plans: Sequence[GraphBoundPreparedRequestPlan],
    ) -> Optional[GraphBoundPreparedRequestPlan]:
        selected = payout_goal_plan.selected
        if selected is None:
            return None
        terminal_operation_id = selected.goal.terminal_operation_id
        eligible = tuple(
            plan
            for plan in plans
            if plan.family == "omission"
            and plan.baseline_operation_ids
            and plan.baseline_operation_ids[-1] == terminal_operation_id
        )
        return eligible[0] if len(eligible) == 1 else None

    async def run(
        self,
        records: Sequence[Mapping[str, Any]],
        *,
        lifecycle: LifecycleMiningResult,
        state_machine: StateMachineLegalityResult,
        compilation: GraphBoundExperimentCompilationResult,
        payout_goal_plan: PayoutGoalPlan,
        graph: SecurityObligationGraph,
        capture_freshness: Optional[GraphBoundCaptureFreshnessBinding] = None,
    ) -> GraphBoundPrerequisiteOneClickRun:
        if not isinstance(payout_goal_plan, PayoutGoalPlan):
            raise TypeError("payout_goal_plan must be a PayoutGoalPlan")
        if not isinstance(graph, SecurityObligationGraph):
            raise TypeError("graph must be a SecurityObligationGraph")
        context = payout_goal_plan.context
        expected_authorization_ref = stable_hash(
            "payout_goal_authorization",
            {
                "envelope_id": self.authorization.envelope_id,
                "attestation_signature": self.authorization.attestation_signature,
            },
        )
        if (
            payout_goal_plan.target_ref != graph.target_ref
            or payout_goal_plan.graph_digest != graph.graph_digest
            or context.target_ref != graph.target_ref
            or graph.target_ref
            != stable_hash("security_obligation_target", self.target_origin)
            or context.selected_world_ref != stable_hash("world", self.world_id)
            or context.authorization_ref != expected_authorization_ref
            or context.authorization_approved is not True
            or context.origin_authorized is not True
            or context.allowed_workflows
            != tuple(sorted(set(self.authorization.allowed_workflows)))
        ):
            raise GraphBoundPrerequisiteOneClickDenied(
                "graph_bound_one_click_payout_graph_context_mismatch"
            )
        selected = payout_goal_plan.selected
        if (
            payout_goal_plan.status != "ready"
            or selected is None
            or selected.status != "admissible"
            or selected.blockers
            or selected.backend != GRAPH_BOUND_PREREQUISITE_BACKEND
            or selected.goal.security_property
            is not SecurityProperty.PREREQUISITE_ENFORCEMENT
            or selected.world_requirement.topology
            is not ProofTopology.CONTROLLED_LIFECYCLE
        ):
            return GraphBoundPrerequisiteOneClickRun(
                status="no_eligible_candidate"
            )
        if (
            GRAPH_BOUND_PREREQUISITE_BACKEND not in context.available_backends
            or selected.goal.terminal_operation_id
            not in context.graph_bound_prerequisite_terminal_ids
            or selected.world_requirement.required_workflows
            != (GRAPH_BOUND_PREREQUISITE_WORKFLOW,)
        ):
            raise GraphBoundPrerequisiteOneClickDenied(
                "graph_bound_one_click_payout_terminal_context_mismatch"
            )

        disabled_gates = self._disabled_gates()
        if disabled_gates:
            return GraphBoundPrerequisiteOneClickRun(
                status="selected_execution_disabled",
                payout_candidate_id=selected.candidate_id,
                disabled_gates=disabled_gates,
            )
        if not isinstance(
            capture_freshness,
            GraphBoundCaptureFreshnessBinding,
        ):
            raise GraphBoundPrerequisiteOneClickDenied(
                "graph_bound_one_click_capture_freshness_is_required"
            )

        admission = GraphBoundManifestAdmissionPlanner().plan(
            compilation=compilation,
            target_origin=self.target_origin,
            target_ref=graph.target_ref,
            world_id=self.world_id,
            authorization=self.authorization,
            executor=self.executor,
            actor_persona_id=self.actor_persona_id,
        )
        binding = GraphBoundRequestBinder().bind(
            records,
            target_origin=self.target_origin,
            world_id=self.world_id,
            lifecycle=lifecycle,
            state_machine=state_machine,
            compilation=compilation,
            admission=admission,
            executor=self.executor,
        )
        plan = self._selected_plan(
            payout_goal_plan=payout_goal_plan,
            plans=binding.plans,
        )
        if plan is None:
            return GraphBoundPrerequisiteOneClickRun(
                status="selected_plan_unavailable",
                payout_candidate_id=selected.candidate_id,
            )

        claim = GraphBoundExecutionClaimAdmission(
            records,
            target_origin=self.target_origin,
            world_id=self.world_id,
            actor_persona_id=self.actor_persona_id,
            authorization=self.authorization,
            executor=self.executor,
            lifecycle=lifecycle,
            state_machine=state_machine,
            compilation=compilation,
            admission=admission,
            request_binding=binding,
            capture_freshness=capture_freshness,
            plan_id=plan.plan_id,
            config=self.claim_config,
            receipt_store=self.receipt_store,
        ).admit().claim()
        try:
            execution = await GraphBoundPrerequisiteExperimentExecutor(
                claim,
                config=self.execution_config,
            ).execute()
            selection_payload = {
                "payout_goal_plan_id": payout_goal_plan.plan_id,
                "payout_candidate_id": selected.candidate_id,
                "payout_goal_id": selected.goal.goal_id,
                "payout_terminal_operation_id": (
                    selected.goal.terminal_operation_id
                ),
                "specification_id": plan.specification_id,
                "plan_id": plan.plan_id,
                "graph_target_ref": graph.target_ref,
                "graph_digest": graph.graph_digest,
            }
            selection_ref = stable_hash(
                "graph_bound_one_click_selection",
                selection_payload,
            )
            outcome = execution.execution_response()
            outcome.update({**selection_payload, "selection_ref": selection_ref})
            finding = (
                GraphBoundPrerequisiteFindingCandidate.from_completed_outcome(
                    outcome
                )
                if execution.finding_confirmed
                else None
            )
            return GraphBoundPrerequisiteOneClickRun(
                status="completed",
                payout_candidate_id=selected.candidate_id,
                specification_id=plan.specification_id,
                plan_id=plan.plan_id,
                payout_goal_plan_id=payout_goal_plan.plan_id,
                payout_goal_id=selected.goal.goal_id,
                payout_terminal_operation_id=(
                    selected.goal.terminal_operation_id
                ),
                graph_target_ref=graph.target_ref,
                graph_digest=graph.graph_digest,
                selection_ref=selection_ref,
                execution=execution,
                finding=finding,
            )
        except asyncio.CancelledError:
            if claim.state == "claimed":
                claim.abort("graph_bound_one_click_cancelled_before_dispatch")
            raise
        except Exception as exc:
            if claim.state == "claimed":
                try:
                    claim.abort("graph_bound_one_click_failed_before_dispatch")
                except Exception as abort_exc:
                    raise GraphBoundPrerequisiteOneClickInternalError(
                        "graph_bound_one_click_claim_terminalization_failed"
                    ) from abort_exc
            if isinstance(
                exc,
                (
                    GraphBoundPrerequisiteExecutionDenied,
                    GraphBoundPrerequisiteOneClickDenied,
                ),
            ):
                raise
            raise GraphBoundPrerequisiteOneClickInternalError(
                "graph_bound_one_click_coordination_failed"
            ) from exc


__all__ = [
    "GRAPH_BOUND_PREREQUISITE_BACKEND",
    "GRAPH_BOUND_PREREQUISITE_ONE_CLICK_MODE",
    "GraphBoundPrerequisiteFindingCandidate",
    "GraphBoundPrerequisiteOneClickDenied",
    "GraphBoundPrerequisiteOneClickDispatcher",
    "GraphBoundPrerequisiteOneClickInternalError",
    "GraphBoundPrerequisiteOneClickRun",
]
