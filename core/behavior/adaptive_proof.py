"""Receipt-bound handoff from adaptive safe reads to an existing proof oracle.

This module has no transport and grants no execution authority. It can only seal
the exact proof plan selected from the final shadow produced by a completed
adaptive interaction chain. The selected resolver must still rederive the plan
and pass all of its existing workflow, policy, ownership, cleanup, and budget
gates before any request is sent.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, Mapping

from .interaction_adaptive import InteractionAdaptiveRunResult
from .normalize import stable_hash
from .obligations import OPEN
from .orchestrator import BehavioralShadowRun
from .resolver import ClosedLoopResolverPlan

ADAPTIVE_PROOF_HANDOFF_MODE = "behavioral_adaptive_proof_handoff_v1"
_HASH_REF = re.compile(r"^[a-z][a-z0-9_]*:[0-9a-f]{64}$")
_RECEIPT_ID = re.compile(r"^behavioral-[0-9a-f]{64}$")
_ORACLE_KINDS = {
    "authorization_proposal": "controlled_authorization_oracle",
    "owned_experiment": "fresh_owned_boundary_oracle",
    "omission_experiment": "fresh_omission_confirmation_oracle",
}


class AdaptiveProofHandoffDenied(ValueError):
    """The adaptive evidence cannot be bound to one exact existing proof plan."""


def _hash_ref(value: Any, prefix: str) -> bool:
    return (
        isinstance(value, str)
        and value.startswith(f"{prefix}:")
        and _HASH_REF.fullmatch(value) is not None
    )


def _payload(
    *,
    initial_shadow_id: str,
    adaptive_controller_id: str,
    adaptive_root_receipt_id: str,
    adaptive_root_transition_id: str,
    adaptive_root_after_state_id: str,
    adaptive_root_chain_ref: str,
    adaptive_final_chain_ref: str,
    adaptive_final_browser_state_id: str,
    adaptive_transition_count: int,
    final_shadow_id: str,
    final_graph_digest: str,
    final_closure_id: str,
    target_ref: str,
    world_ref: str,
    policy_ref: str,
    budget_ref: str,
    plan_id: str,
    obligation_id: str,
    resolution_kind: str,
    resolution_ref: str,
    frontier_index: int,
    rank_score: int,
    oracle_kind: str,
) -> Dict[str, Any]:
    return {
        "mode": ADAPTIVE_PROOF_HANDOFF_MODE,
        "status": "ready",
        "initial_shadow_id": initial_shadow_id,
        "adaptive_controller_id": adaptive_controller_id,
        "adaptive_root_receipt_id": adaptive_root_receipt_id,
        "adaptive_root_transition_id": adaptive_root_transition_id,
        "adaptive_root_after_state_id": adaptive_root_after_state_id,
        "adaptive_root_chain_ref": adaptive_root_chain_ref,
        "adaptive_final_chain_ref": adaptive_final_chain_ref,
        "adaptive_final_browser_state_id": adaptive_final_browser_state_id,
        "adaptive_transition_count": adaptive_transition_count,
        "final_shadow_id": final_shadow_id,
        "final_graph_digest": final_graph_digest,
        "final_closure_id": final_closure_id,
        "target_ref": target_ref,
        "world_ref": world_ref,
        "policy_ref": policy_ref,
        "budget_ref": budget_ref,
        "plan_id": plan_id,
        "obligation_id": obligation_id,
        "resolution_kind": resolution_kind,
        "resolution_ref": resolution_ref,
        "frontier_index": frontier_index,
        "rank_score": rank_score,
        "oracle_kind": oracle_kind,
        "target_requests_sent": 0,
        "executable": False,
    }


@dataclass(frozen=True)
class AdaptiveProofHandoff:
    handoff_id: str
    initial_shadow_id: str
    adaptive_controller_id: str
    adaptive_root_receipt_id: str
    adaptive_root_transition_id: str
    adaptive_root_after_state_id: str
    adaptive_root_chain_ref: str
    adaptive_final_chain_ref: str
    adaptive_final_browser_state_id: str
    adaptive_transition_count: int
    final_shadow_id: str
    final_graph_digest: str
    final_closure_id: str
    target_ref: str
    world_ref: str
    policy_ref: str
    budget_ref: str
    plan_id: str
    obligation_id: str
    resolution_kind: str
    resolution_ref: str
    frontier_index: int
    rank_score: int
    oracle_kind: str
    mode: str = ADAPTIVE_PROOF_HANDOFF_MODE
    status: str = "ready"
    target_requests_sent: int = 0
    executable: bool = False

    def __post_init__(self) -> None:
        payload = _payload(
            initial_shadow_id=self.initial_shadow_id,
            adaptive_controller_id=self.adaptive_controller_id,
            adaptive_root_receipt_id=self.adaptive_root_receipt_id,
            adaptive_root_transition_id=self.adaptive_root_transition_id,
            adaptive_root_after_state_id=self.adaptive_root_after_state_id,
            adaptive_root_chain_ref=self.adaptive_root_chain_ref,
            adaptive_final_chain_ref=self.adaptive_final_chain_ref,
            adaptive_final_browser_state_id=self.adaptive_final_browser_state_id,
            adaptive_transition_count=self.adaptive_transition_count,
            final_shadow_id=self.final_shadow_id,
            final_graph_digest=self.final_graph_digest,
            final_closure_id=self.final_closure_id,
            target_ref=self.target_ref,
            world_ref=self.world_ref,
            policy_ref=self.policy_ref,
            budget_ref=self.budget_ref,
            plan_id=self.plan_id,
            obligation_id=self.obligation_id,
            resolution_kind=self.resolution_kind,
            resolution_ref=self.resolution_ref,
            frontier_index=self.frontier_index,
            rank_score=self.rank_score,
            oracle_kind=self.oracle_kind,
        )
        if (
            self.handoff_id != stable_hash("adaptive_proof_handoff", payload)
            or self.mode != ADAPTIVE_PROOF_HANDOFF_MODE
            or self.status != "ready"
            or self.target_requests_sent != 0
            or self.executable
            or not _hash_ref(self.initial_shadow_id, "behavioral_shadow_run")
            or not _hash_ref(
                self.adaptive_controller_id,
                "interaction_adaptive_controller",
            )
            or _RECEIPT_ID.fullmatch(self.adaptive_root_receipt_id) is None
            or not _hash_ref(
                self.adaptive_root_transition_id,
                "browser_state_transition",
            )
            or not _hash_ref(
                self.adaptive_root_after_state_id,
                "browser_state",
            )
            or not _hash_ref(
                self.adaptive_root_chain_ref,
                "interaction_adaptive_chain",
            )
            or not _hash_ref(
                self.adaptive_final_chain_ref,
                "interaction_adaptive_chain",
            )
            or not _hash_ref(
                self.adaptive_final_browser_state_id,
                "browser_state",
            )
            or isinstance(self.adaptive_transition_count, bool)
            or not isinstance(self.adaptive_transition_count, int)
            or not 2 <= self.adaptive_transition_count <= 4
            or not _hash_ref(self.final_shadow_id, "behavioral_shadow_run")
            or not _hash_ref(
                self.final_graph_digest,
                "security_obligation_graph",
            )
            or not _hash_ref(
                self.final_closure_id,
                "security_closure_certificate",
            )
            or not _hash_ref(self.target_ref, "interaction_target")
            or not _hash_ref(self.world_ref, "world")
            or not _hash_ref(self.policy_ref, "interaction_policy")
            or not _hash_ref(self.budget_ref, "interaction_action_budget")
            or not _hash_ref(self.plan_id, "closed_loop_resolver_plan")
            or not _hash_ref(self.obligation_id, "security_obligation")
            or self.resolution_kind not in _ORACLE_KINDS
            or not _hash_ref(self.resolution_ref, self.resolution_kind)
            or self.oracle_kind != _ORACLE_KINDS[self.resolution_kind]
            or isinstance(self.frontier_index, bool)
            or not isinstance(self.frontier_index, int)
            or self.frontier_index < 0
            or isinstance(self.rank_score, bool)
            or not isinstance(self.rank_score, int)
            or self.rank_score < 0
        ):
            raise ValueError("adaptive proof handoff contract is invalid")

    @classmethod
    def create(
        cls,
        *,
        initial_shadow: BehavioralShadowRun,
        adaptive: InteractionAdaptiveRunResult,
        final_shadow: BehavioralShadowRun,
        plan: ClosedLoopResolverPlan,
    ) -> "AdaptiveProofHandoff":
        if (
            not isinstance(initial_shadow, BehavioralShadowRun)
            or not isinstance(adaptive, InteractionAdaptiveRunResult)
            or not isinstance(final_shadow, BehavioralShadowRun)
            or not isinstance(plan, ClosedLoopResolverPlan)
        ):
            raise TypeError("adaptive proof handoff inputs are invalid")
        if any(item.actionable for item in initial_shadow.ranked_frontier):
            raise AdaptiveProofHandoffDenied(
                "adaptive_proof_handoff_initial_frontier_was_already_actionable"
            )
        selected = plan.selected
        final_state = adaptive.final_transition.after_state
        final_transition = adaptive.final_transition.transition
        if (
            selected is None
            or adaptive.final_state is not final_shadow
            or plan.shadow_run_id != final_shadow.run_id
            or adaptive.final_transition.transition_count
            != adaptive.steps[-1].step_index
            or adaptive.final_transition.transition_count < 2
            or final_transition.decision != "stop"
            or adaptive.steps[-1].chain_ref != adaptive.chain_ref
            or initial_shadow.run_id == final_shadow.run_id
        ):
            raise AdaptiveProofHandoffDenied(
                "adaptive_proof_handoff_chain_or_plan_is_not_final"
            )
        selected_matches = tuple(
            item
            for index, item in enumerate(final_shadow.ranked_frontier)
            if index == selected.frontier_index
            and item.obligation_id == selected.obligation_id
            and item.actionable
            and item.resolution_kind == selected.resolution_kind
            and item.resolution_ref == selected.resolution_ref
            and item.score == selected.rank_score
        )
        obligation_matches = tuple(
            item
            for item in final_shadow.graph.obligations
            if item.obligation_id == selected.obligation_id
            and item.status == OPEN
            and item.obligation_id in final_shadow.closure.unresolved_ids
        )
        if len(selected_matches) != 1 or len(obligation_matches) != 1:
            raise AdaptiveProofHandoffDenied(
                "adaptive_proof_handoff_obligation_is_not_exactly_open"
            )
        values = {
            "initial_shadow_id": initial_shadow.run_id,
            "adaptive_controller_id": adaptive.controller_id,
            "adaptive_root_receipt_id": adaptive.root_receipt_id,
            "adaptive_root_transition_id": adaptive.root_transition_id,
            "adaptive_root_after_state_id": adaptive.root_after_state_id,
            "adaptive_root_chain_ref": adaptive.root_chain_ref,
            "adaptive_final_chain_ref": adaptive.chain_ref,
            "adaptive_final_browser_state_id": final_state.state_id,
            "adaptive_transition_count": (
                adaptive.final_transition.transition_count
            ),
            "final_shadow_id": final_shadow.run_id,
            "final_graph_digest": final_shadow.graph.graph_digest,
            "final_closure_id": final_shadow.closure.certificate_id,
            "target_ref": final_state.target_ref,
            "world_ref": final_state.world_ref,
            "policy_ref": final_state.policy_ref,
            "budget_ref": final_state.budget_ref,
            "plan_id": plan.plan_id,
            "obligation_id": selected.obligation_id,
            "resolution_kind": selected.resolution_kind,
            "resolution_ref": selected.resolution_ref,
            "frontier_index": selected.frontier_index,
            "rank_score": selected.rank_score,
            "oracle_kind": _ORACLE_KINDS[selected.resolution_kind],
        }
        payload = _payload(**values)
        return cls(
            handoff_id=stable_hash("adaptive_proof_handoff", payload),
            **values,
        )

    def validates_plan(self, plan: ClosedLoopResolverPlan) -> bool:
        if not isinstance(plan, ClosedLoopResolverPlan):
            return False
        selected = plan.selected
        return bool(
            selected is not None
            and plan.plan_id == self.plan_id
            and plan.shadow_run_id == self.final_shadow_id
            and selected.obligation_id == self.obligation_id
            and selected.resolution_kind == self.resolution_kind
            and selected.resolution_ref == self.resolution_ref
            and selected.frontier_index == self.frontier_index
            and selected.rank_score == self.rank_score
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": 1,
            "handoff_id": self.handoff_id,
            **_payload(
                initial_shadow_id=self.initial_shadow_id,
                adaptive_controller_id=self.adaptive_controller_id,
                adaptive_root_receipt_id=self.adaptive_root_receipt_id,
                adaptive_root_transition_id=self.adaptive_root_transition_id,
                adaptive_root_after_state_id=self.adaptive_root_after_state_id,
                adaptive_root_chain_ref=self.adaptive_root_chain_ref,
                adaptive_final_chain_ref=self.adaptive_final_chain_ref,
                adaptive_final_browser_state_id=(
                    self.adaptive_final_browser_state_id
                ),
                adaptive_transition_count=self.adaptive_transition_count,
                final_shadow_id=self.final_shadow_id,
                final_graph_digest=self.final_graph_digest,
                final_closure_id=self.final_closure_id,
                target_ref=self.target_ref,
                world_ref=self.world_ref,
                policy_ref=self.policy_ref,
                budget_ref=self.budget_ref,
                plan_id=self.plan_id,
                obligation_id=self.obligation_id,
                resolution_kind=self.resolution_kind,
                resolution_ref=self.resolution_ref,
                frontier_index=self.frontier_index,
                rank_score=self.rank_score,
                oracle_kind=self.oracle_kind,
            ),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "AdaptiveProofHandoff":
        if not isinstance(value, Mapping):
            raise ValueError("serialized adaptive proof handoff is invalid")
        expected = {
            "schema_version",
            "handoff_id",
            *set(
                _payload(
                    initial_shadow_id="",
                    adaptive_controller_id="",
                    adaptive_root_receipt_id="",
                    adaptive_root_transition_id="",
                    adaptive_root_after_state_id="",
                    adaptive_root_chain_ref="",
                    adaptive_final_chain_ref="",
                    adaptive_final_browser_state_id="",
                    adaptive_transition_count=0,
                    final_shadow_id="",
                    final_graph_digest="",
                    final_closure_id="",
                    target_ref="",
                    world_ref="",
                    policy_ref="",
                    budget_ref="",
                    plan_id="",
                    obligation_id="",
                    resolution_kind="",
                    resolution_ref="",
                    frontier_index=0,
                    rank_score=0,
                    oracle_kind="",
                )
            ),
        }
        if set(value) != expected or value.get("schema_version") != 1:
            raise ValueError("serialized adaptive proof handoff fields are invalid")
        fields = {
            key: value[key]
            for key in cls.__dataclass_fields__
            if key in value
        }
        return cls(**fields)


__all__ = [
    "ADAPTIVE_PROOF_HANDOFF_MODE",
    "AdaptiveProofHandoff",
    "AdaptiveProofHandoffDenied",
]
