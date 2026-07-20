"""One-step execution authority for the behavioral obligation frontier.

The shadow orchestrator decides what security question should be answered next.
This module may dispatch exactly one frontier item, but only when an existing
controlled resolver can produce a terminal security verdict for that item.
Prepared owned-state sequences remain visible but are not mistaken for boundary
proofs.
"""

from __future__ import annotations

import copy
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple

from .active import ControlledAuthorizationExecutor, ControlledExecutionResult
from .normalize import stable_hash
from .orchestrator import BehavioralShadowRun, RankedSecurityObligation
from .proposals import AuthorizationExperimentProposal

CLOSED_LOOP_RESOLVER_MODE = "behavioral_closed_loop_resolver_v1"
CLOSED_LOOP_RESOLVER_ENV = "SENTINELFORGE_BEHAVIOR_PRIMARY"
_TRUE = frozenset({"1", "true", "yes", "on"})
_HASH_REF = re.compile(r"^[a-z][a-z0-9_]*:[0-9a-f]{64}$")


class ClosedLoopResolverDenied(RuntimeError):
    """The selected frontier item could not be bound to its exact resolver."""


@dataclass(frozen=True)
class ClosedLoopResolverConfig:
    enabled: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.enabled, bool):
            raise ValueError("closed-loop resolver enabled must be a boolean")

    @classmethod
    def from_environment(cls) -> "ClosedLoopResolverConfig":
        enabled = os.environ.get(CLOSED_LOOP_RESOLVER_ENV, "").strip().lower() in _TRUE
        return cls(enabled=enabled)


@dataclass(frozen=True)
class ClosedLoopResolverDiagnostics:
    frontier_items: int
    ranked_dropped: int
    actionable_items: int
    outcome_bearing_items: int
    deferred_preparatory_items: int
    unavailable_items: int

    def __post_init__(self) -> None:
        values = tuple(vars(self).values())
        if (
            any(
                isinstance(value, bool) or not isinstance(value, int) or value < 0
                for value in values
            )
            or self.frontier_items != self.actionable_items + self.unavailable_items
        ):
            raise ValueError("closed-loop resolver diagnostics are inconsistent")
        if self.actionable_items != (
            self.outcome_bearing_items + self.deferred_preparatory_items
        ):
            raise ValueError("closed-loop resolver action accounting is inconsistent")

    def to_dict(self) -> Dict[str, int]:
        return dict(vars(self))


@dataclass(frozen=True)
class ClosedLoopResolverSelection:
    obligation_id: str
    proposal_id: str
    frontier_index: int
    rank_score: int
    proposal: AuthorizationExperimentProposal = field(repr=False, compare=False)
    resolution_kind: str = "authorization_proposal"

    def __post_init__(self) -> None:
        if (
            not isinstance(self.proposal, AuthorizationExperimentProposal)
            or self.proposal.proposal_id != self.proposal_id
            or not self.obligation_id.startswith("security_obligation:")
            or _HASH_REF.fullmatch(self.obligation_id) is None
            or not self.proposal_id.startswith("authorization_proposal:")
            or _HASH_REF.fullmatch(self.proposal_id) is None
            or isinstance(self.frontier_index, bool)
            or not isinstance(self.frontier_index, int)
            or self.frontier_index < 0
            or isinstance(self.rank_score, bool)
            or not isinstance(self.rank_score, int)
            or self.rank_score < 0
            or self.resolution_kind != "authorization_proposal"
        ):
            raise ValueError("closed-loop resolver selection is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "obligation_id": self.obligation_id,
            "resolution_kind": self.resolution_kind,
            "resolution_ref": self.proposal_id,
            "frontier_index": self.frontier_index,
            "rank_score": self.rank_score,
        }


def _plan_payload(
    *,
    shadow_run_id: str,
    selected: Optional[ClosedLoopResolverSelection],
    ranked: Sequence[RankedSecurityObligation],
    diagnostics: ClosedLoopResolverDiagnostics,
) -> Dict[str, Any]:
    return {
        "mode": CLOSED_LOOP_RESOLVER_MODE,
        "shadow_run_id": shadow_run_id,
        "selected": selected.to_dict() if selected is not None else None,
        "ranked": [item.to_dict() for item in ranked],
        "diagnostics": diagnostics.to_dict(),
    }


@dataclass(frozen=True)
class ClosedLoopResolverPlan:
    plan_id: str
    shadow_run_id: str
    selected: Optional[ClosedLoopResolverSelection]
    ranked: Tuple[RankedSecurityObligation, ...]
    diagnostics: ClosedLoopResolverDiagnostics
    mode: str = CLOSED_LOOP_RESOLVER_MODE

    def __post_init__(self) -> None:
        payload = _plan_payload(
            shadow_run_id=self.shadow_run_id,
            selected=self.selected,
            ranked=self.ranked,
            diagnostics=self.diagnostics,
        )
        actionable_items = tuple(item for item in self.ranked if item.actionable)
        outcome_indices = tuple(
            index
            for index, item in enumerate(self.ranked)
            if item.actionable and item.resolution_kind == "authorization_proposal"
        )
        deferred_items = tuple(
            item
            for item in actionable_items
            if item.resolution_kind == "owned_experiment"
        )
        selected_matches = ()
        if self.selected is not None:
            selected_matches = tuple(
                item
                for index, item in enumerate(self.ranked)
                if index == self.selected.frontier_index
                and item.obligation_id == self.selected.obligation_id
                and item.actionable
                and item.resolution_kind == self.selected.resolution_kind
                and item.resolution_ref == self.selected.proposal_id
                and item.score == self.selected.rank_score
            )
        if (
            self.mode != CLOSED_LOOP_RESOLVER_MODE
            or self.plan_id != stable_hash("closed_loop_resolver_plan", payload)
            or not self.shadow_run_id.startswith("behavioral_shadow_run:")
            or _HASH_REF.fullmatch(self.shadow_run_id) is None
            or len(selected_matches) != (1 if self.selected is not None else 0)
            or len(self.ranked) != self.diagnostics.frontier_items
            or len(actionable_items) != self.diagnostics.actionable_items
            or len(outcome_indices) != self.diagnostics.outcome_bearing_items
            or len(deferred_items) != self.diagnostics.deferred_preparatory_items
            or len(self.ranked) - len(actionable_items)
            != self.diagnostics.unavailable_items
            or bool(outcome_indices) != (self.selected is not None)
            or (
                self.selected is not None
                and self.selected.frontier_index != outcome_indices[0]
            )
        ):
            raise ValueError("closed-loop resolver plan is invalid")

    def to_dict(self) -> Dict[str, Any]:
        selected = self.selected
        return {
            "schema_version": 1,
            "plan_id": self.plan_id,
            **_plan_payload(
                shadow_run_id=self.shadow_run_id,
                selected=selected,
                ranked=self.ranked,
                diagnostics=self.diagnostics,
            ),
            # Retained for the existing receipt and Swift response contracts.
            "selected_proposal_id": selected.proposal_id if selected else None,
            "selected_obligation_id": selected.obligation_id if selected else None,
        }


@dataclass(frozen=True)
class ClosedLoopResolverRun:
    status: str
    plan: ClosedLoopResolverPlan
    execution: Optional[ControlledExecutionResult] = None

    def __post_init__(self) -> None:
        if self.execution is None:
            if self.status not in {"disabled", "no_executable_candidate"}:
                raise ValueError("closed-loop resolver inactive status is invalid")
        elif (
            self.plan.selected is None
            or self.execution.proposal_id != self.plan.selected.proposal_id
            or self.status != self.execution.status
        ):
            raise ValueError("closed-loop resolver execution is inconsistent")

    @property
    def finding(self) -> Optional[Dict[str, Any]]:
        if self.execution is None or self.execution.finding is None:
            return None
        finding = copy.deepcopy(self.execution.finding.to_finding())
        metadata = finding.setdefault("metadata", {})
        selected = self.plan.selected
        assert selected is not None
        resolver_metadata = {
            "mode": self.plan.mode,
            "plan_id": self.plan.plan_id,
            "shadow_run_id": self.plan.shadow_run_id,
            "obligation_id": selected.obligation_id,
            "proposal_id": selected.proposal_id,
            "frontier_index": selected.frontier_index,
            "rank_score": selected.rank_score,
            "authoritative_verdict_engine": self.execution.authoritative_engine,
        }
        metadata["behavioral_closed_loop_resolver"] = resolver_metadata
        # Compatibility for existing report/UI consumers. Selection authority is
        # the obligation plan above, not BehavioralPrimaryScheduler.
        metadata["behavioral_primary_planner"] = {
            "mode": self.plan.mode,
            "proposal_id": selected.proposal_id,
            "rank_score": selected.rank_score,
            "authoritative_verdict_engine": self.execution.authoritative_engine,
        }
        metadata["proof_mode"] = "bounty_safe"
        metadata["restraint"] = dict(self.execution.restraint)
        metadata["sentinel_provenance_root"] = self.execution.provenance_root
        metadata["sentinel_provenance"] = dict(self.execution.provenance)
        return finding

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "plan": self.plan.to_dict(),
            "execution": self.execution.to_dict() if self.execution else None,
            "finding": self.finding,
        }


class SingleStepObligationResolver:
    """Dispatch one exact, outcome-bearing resolver from a shadow frontier."""

    def __init__(
        self,
        config: Optional[ClosedLoopResolverConfig] = None,
    ) -> None:
        self.config = config or ClosedLoopResolverConfig.from_environment()

    @staticmethod
    def _proposals_by_id(
        shadow_run: BehavioralShadowRun,
    ) -> Mapping[str, AuthorizationExperimentProposal]:
        if shadow_run.proposals is None:
            return {}
        proposals: Dict[str, AuthorizationExperimentProposal] = {}
        for proposal in shadow_run.proposals.proposals:
            if proposal.proposal_id in proposals:
                raise ClosedLoopResolverDenied("shadow_proposal_identity_is_ambiguous")
            proposals[proposal.proposal_id] = proposal
        return proposals

    def plan(self, shadow_run: BehavioralShadowRun) -> ClosedLoopResolverPlan:
        if not isinstance(shadow_run, BehavioralShadowRun):
            raise TypeError("shadow_run must be a BehavioralShadowRun")
        proposals = self._proposals_by_id(shadow_run)
        selected = None
        actionable = 0
        outcome_bearing = 0
        deferred = 0
        unavailable = 0
        for index, item in enumerate(shadow_run.ranked_frontier):
            if not item.actionable:
                unavailable += 1
                continue
            actionable += 1
            if item.resolution_kind == "owned_experiment":
                # The compiled sequence proves setup/cleanup behavior only. Until
                # a cross-principal oracle consumes its fresh state, execution
                # cannot resolve the ownership-boundary obligation.
                deferred += 1
                continue
            if item.resolution_kind != "authorization_proposal":
                raise ClosedLoopResolverDenied(
                    "frontier_resolution_kind_is_unsupported"
                )
            proposal = proposals.get(str(item.resolution_ref))
            if proposal is None:
                raise ClosedLoopResolverDenied("frontier_resolution_ref_is_unbound")
            outcome_bearing += 1
            if selected is None:
                selected = ClosedLoopResolverSelection(
                    obligation_id=item.obligation_id,
                    proposal_id=proposal.proposal_id,
                    frontier_index=index,
                    rank_score=item.score,
                    proposal=proposal,
                )

        diagnostics = ClosedLoopResolverDiagnostics(
            frontier_items=len(shadow_run.ranked_frontier),
            ranked_dropped=shadow_run.ranked_dropped,
            actionable_items=actionable,
            outcome_bearing_items=outcome_bearing,
            deferred_preparatory_items=deferred,
            unavailable_items=unavailable,
        )
        if selected is None and shadow_run.ranked_dropped:
            raise ClosedLoopResolverDenied(
                "outcome_bearing_selection_blocked_by_rank_bound"
            )
        payload = _plan_payload(
            shadow_run_id=shadow_run.run_id,
            selected=selected,
            ranked=shadow_run.ranked_frontier,
            diagnostics=diagnostics,
        )
        return ClosedLoopResolverPlan(
            plan_id=stable_hash("closed_loop_resolver_plan", payload),
            shadow_run_id=shadow_run.run_id,
            selected=selected,
            ranked=shadow_run.ranked_frontier,
            diagnostics=diagnostics,
        )

    async def run(
        self,
        shadow_run: BehavioralShadowRun,
        source_records: Sequence[Mapping[str, Any]],
        peer_records: Sequence[Mapping[str, Any]],
        *,
        controlled_executor: Optional[ControlledAuthorizationExecutor] = None,
    ) -> ClosedLoopResolverRun:
        plan = self.plan(shadow_run)
        if not self.config.enabled:
            return ClosedLoopResolverRun("disabled", plan)
        if plan.selected is None:
            return ClosedLoopResolverRun("no_executable_candidate", plan)
        if not isinstance(controlled_executor, ControlledAuthorizationExecutor):
            raise ClosedLoopResolverDenied(
                "enabled_closed_loop_resolver_requires_controlled_executor"
            )
        execution = await controlled_executor.execute(
            plan.selected.proposal,
            source_records,
            peer_records,
        )
        return ClosedLoopResolverRun(execution.status, plan, execution)


__all__ = [
    "CLOSED_LOOP_RESOLVER_ENV",
    "CLOSED_LOOP_RESOLVER_MODE",
    "ClosedLoopResolverConfig",
    "ClosedLoopResolverDenied",
    "ClosedLoopResolverDiagnostics",
    "ClosedLoopResolverPlan",
    "ClosedLoopResolverRun",
    "ClosedLoopResolverSelection",
    "SingleStepObligationResolver",
]
