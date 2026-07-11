"""Autonomous primary planning for paired-world authorization experiments.

The behavioral engine chooses the experiment. The established BOLA oracle still
decides the verdict. This module deliberately has no network client and never
calls the legacy multi-operation ``hunt`` path, preventing duplicate execution.
"""

from __future__ import annotations

import copy
import json
import os
import re
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple

from core.foundry.vault import ResearchPersona

from .active import ControlledAuthorizationExecutor, ControlledExecutionResult
from .proposals import (
    CROSS_OBJECT_READ,
    AuthorizationExperimentProposal,
    ProposalBatch,
    compile_authorization_proposals,
)

PRIMARY_ENV = "SENTINELFORGE_BEHAVIOR_PRIMARY"
PRIMARY_PLANNER_MODE = "behavioral_primary_planner"
_TRUE = frozenset({"1", "true", "yes", "on"})
_GRAPHQL_READ = re.compile(r"^\s*(?:query\b|\{)", re.IGNORECASE)
_GRAPHQL_WRITE = re.compile(r"\b(?:mutation|subscription)\b", re.IGNORECASE)


class PrimaryPlannerError(RuntimeError):
    """Raised when an enabled scheduler lacks its controlled execution seam."""


@dataclass(frozen=True)
class PrimaryPlannerConfig:
    enabled: bool = False
    max_ranked_candidates: int = 128

    def __post_init__(self) -> None:
        if not isinstance(self.max_ranked_candidates, int) or self.max_ranked_candidates <= 0:
            raise ValueError("max_ranked_candidates must be a positive integer")

    @classmethod
    def from_environment(cls) -> "PrimaryPlannerConfig":
        enabled = os.environ.get(PRIMARY_ENV, "").strip().lower() in _TRUE
        return cls(enabled=enabled)


@dataclass(frozen=True)
class RankedAuthorizationCandidate:
    proposal: AuthorizationExperimentProposal
    score: int
    signals: Tuple[str, ...]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "proposal_id": self.proposal.proposal_id,
            "operation_label": self.proposal.operation_label,
            "risk_class": self.proposal.risk_class,
            "score": self.score,
            "signals": list(self.signals),
        }


@dataclass(frozen=True)
class PrimaryPlannerPlan:
    batch: ProposalBatch
    ranked: Tuple[RankedAuthorizationCandidate, ...]
    diagnostics: Dict[str, Any]
    mode: str = PRIMARY_PLANNER_MODE

    @property
    def selected(self) -> Optional[RankedAuthorizationCandidate]:
        return self.ranked[0] if self.ranked else None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "mode": self.mode,
            "selected_proposal_id": (
                self.selected.proposal.proposal_id if self.selected else None
            ),
            "ranked": [candidate.to_dict() for candidate in self.ranked],
            "diagnostics": dict(self.diagnostics),
        }


@dataclass(frozen=True)
class PrimaryPlannerRun:
    status: str
    plan: PrimaryPlannerPlan
    execution: Optional[ControlledExecutionResult] = None

    @property
    def finding(self) -> Optional[Dict[str, Any]]:
        if self.execution is None or self.execution.finding is None:
            return None
        finding = copy.deepcopy(self.execution.finding.to_finding())
        metadata = finding.setdefault("metadata", {})
        selected = self.plan.selected
        metadata["behavioral_primary_planner"] = {
            "mode": self.plan.mode,
            "proposal_id": selected.proposal.proposal_id if selected else None,
            "rank_score": selected.score if selected else None,
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


def _graphql_items(record: Mapping[str, Any]) -> Tuple[Mapping[str, Any], ...]:
    raw = record.get("request_body")
    if not isinstance(raw, str) or not raw:
        return ()
    try:
        parsed = json.loads(raw)
    except (TypeError, ValueError):
        return ()
    items = parsed if isinstance(parsed, list) else [parsed]
    return tuple(item for item in items if isinstance(item, Mapping))


def _proves_read_semantics(
    proposal: AuthorizationExperimentProposal, record: Mapping[str, Any]
) -> bool:
    items = _graphql_items(record)
    if items:
        matches = [
            item
            for item in items
            if str(item.get("operationName") or "graphql_operation")
            == proposal.operation_label
        ]
        if len(matches) != 1:
            return False
        query = matches[0].get("query")
        return (
            isinstance(query, str)
            and bool(query.strip())
            and _GRAPHQL_READ.search(query) is not None
            and _GRAPHQL_WRITE.search(query) is None
        )
    return str(record.get("method") or "GET").upper() == "GET"


def _record_has_operation(record: Mapping[str, Any], operation_label: str) -> bool:
    items = _graphql_items(record)
    if items:
        return any(
            str(item.get("operationName") or "graphql_operation") == operation_label
            for item in items
        )
    method = str(record.get("method") or "GET").upper()
    url = str(record.get("url") or "")
    return operation_label.startswith(f"{method} ") and bool(url)


def _response_status(record: Mapping[str, Any]) -> int:
    try:
        return int(record.get("response_status") or record.get("status") or 0)
    except (TypeError, ValueError):
        return 0


def _rank(
    proposal: AuthorizationExperimentProposal,
    source_record: Mapping[str, Any],
    peer_records: Sequence[Mapping[str, Any]],
) -> RankedAuthorizationCandidate:
    score = 100
    signals = ["read_semantics_proven", "gate_b_capture_bound"]
    peer_record = next(
        (record for record in peer_records if _record_has_operation(record, proposal.operation_label)),
        None,
    )
    source_status = _response_status(source_record)
    peer_status = _response_status(peer_record or {})
    if 200 <= source_status < 300 and 200 <= peer_status < 300:
        score += 30
        signals.append("paired_2xx_baselines")
    source_body = source_record.get("response_body")
    peer_body = peer_record.get("response_body") if peer_record else None
    if (
        isinstance(source_body, str)
        and isinstance(peer_body, str)
        and source_body
        and peer_body
        and source_body != peer_body
    ):
        score += 25
        signals.append("cross_world_response_difference")
    location_kinds = {mutation.location_kind for mutation in proposal.mutations}
    if location_kinds & {"json_body", "url_path", "url_query"}:
        score += 15
        signals.append("direct_resource_locator")
    score += max(0, 8 - len(proposal.mutations))
    return RankedAuthorizationCandidate(proposal, score, tuple(signals))


class BehavioralPrimaryScheduler:
    """Choose and execute one highest-confidence authorization experiment."""

    def __init__(self, config: Optional[PrimaryPlannerConfig] = None) -> None:
        self.config = config or PrimaryPlannerConfig.from_environment()

    def plan(
        self,
        source_records: Sequence[Mapping[str, Any]],
        peer_records: Sequence[Mapping[str, Any]],
        *,
        source_persona: ResearchPersona,
        peer_persona: ResearchPersona,
    ) -> PrimaryPlannerPlan:
        batch = compile_authorization_proposals(
            source_records,
            peer_records,
            source_world=source_persona.persona_id,
            peer_world=peer_persona.persona_id,
        )
        ranked = []
        rejected = {"non_read_risk": 0, "unproven_read_semantics": 0}
        for proposal in batch.proposals:
            if proposal.risk_class != CROSS_OBJECT_READ:
                rejected["non_read_risk"] += 1
                continue
            record = source_records[proposal.source_record_index]
            if not _proves_read_semantics(proposal, record):
                rejected["unproven_read_semantics"] += 1
                continue
            ranked.append(_rank(proposal, record, peer_records))
        ranked.sort(
            key=lambda candidate: (
                -candidate.score,
                candidate.proposal.operation_label,
                candidate.proposal.proposal_id,
            )
        )
        dropped_for_bound = max(0, len(ranked) - self.config.max_ranked_candidates)
        ranked = ranked[: self.config.max_ranked_candidates]
        return PrimaryPlannerPlan(
            batch=batch,
            ranked=tuple(ranked),
            diagnostics={
                "proposal_count": len(batch.proposals),
                "eligible_count": len(ranked),
                "rejected": rejected,
                "dropped_for_rank_bound": dropped_for_bound,
            },
        )

    async def run(
        self,
        source_records: Sequence[Mapping[str, Any]],
        peer_records: Sequence[Mapping[str, Any]],
        *,
        source_persona: ResearchPersona,
        peer_persona: ResearchPersona,
        controlled_executor: Optional[ControlledAuthorizationExecutor] = None,
    ) -> PrimaryPlannerRun:
        plan = self.plan(
            source_records,
            peer_records,
            source_persona=source_persona,
            peer_persona=peer_persona,
        )
        if not self.config.enabled:
            return PrimaryPlannerRun("disabled", plan)
        if plan.selected is None:
            return PrimaryPlannerRun("no_executable_candidate", plan)
        if controlled_executor is None:
            raise PrimaryPlannerError("enabled_primary_planner_requires_controlled_executor")
        execution = await controlled_executor.execute(
            plan.selected.proposal,
            source_records,
            peer_records,
        )
        return PrimaryPlannerRun(execution.status, plan, execution)
