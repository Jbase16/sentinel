"""Passive derivation of state-machine legality questions.

This module connects the existing backward exploit compiler to the security
frontier without granting execution or finding authority. A relation candidate
exists only when a high-value terminal operation has a compiler-derived
prerequisite chain whose exact successful observations occurred once, in order,
inside the same captured world.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple

from .compiler import (
    BackwardExploitCompiler,
    CompilerLimits,
    OperationCatalogLimits,
    OperationContract,
    OperationSafety,
    high_value_goals,
)
from .lineage import PlanRehydrator, ValueLineageLedger
from .normalize import normalize_exchange, stable_hash

STATE_MACHINE_LEGALITY_MODE = "behavioral_state_machine_legality_v1"
MAX_STATE_MACHINE_RECORDS = 4_096
MAX_STATE_MACHINE_GOALS = 64
MAX_STATE_MACHINE_CANDIDATES = 64
MAX_STATE_MACHINE_SEARCH_STATES = 1_024
MAX_STATE_MACHINE_PLAN_STEPS = 16
MAX_STATE_MACHINE_LINEAGE_BINDINGS = 32

_HASH_REF = re.compile(r"^[a-z][a-z0-9_]*:[0-9a-f]{64}$")
_SEMANTIC = re.compile(r"^[a-z][a-z0-9_]{0,63}$")


def _hash_ref(value: Any, prefix: Optional[str] = None) -> bool:
    return (
        isinstance(value, str)
        and _HASH_REF.fullmatch(value) is not None
        and (prefix is None or value.startswith(f"{prefix}:"))
    )


@dataclass(frozen=True)
class StateMachineLegalityLimits:
    max_records: int = MAX_STATE_MACHINE_RECORDS
    max_goals: int = MAX_STATE_MACHINE_GOALS
    max_candidates: int = MAX_STATE_MACHINE_CANDIDATES
    max_search_states_per_goal: int = MAX_STATE_MACHINE_SEARCH_STATES
    max_plan_steps: int = MAX_STATE_MACHINE_PLAN_STEPS
    max_lineage_bindings_per_candidate: int = (
        MAX_STATE_MACHINE_LINEAGE_BINDINGS
    )

    def __post_init__(self) -> None:
        for name, value in vars(self).items():
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
        fixed_ceilings = {
            "max_records": MAX_STATE_MACHINE_RECORDS,
            "max_goals": MAX_STATE_MACHINE_GOALS,
            "max_candidates": MAX_STATE_MACHINE_CANDIDATES,
            "max_search_states_per_goal": MAX_STATE_MACHINE_SEARCH_STATES,
        }
        for name, ceiling in fixed_ceilings.items():
            if getattr(self, name) > ceiling:
                raise ValueError(f"{name} exceeds the state-machine contract")
        if self.max_plan_steps > MAX_STATE_MACHINE_PLAN_STEPS:
            raise ValueError(
                "max_plan_steps exceeds the state-machine contract"
            )
        if (
            self.max_lineage_bindings_per_candidate
            > MAX_STATE_MACHINE_LINEAGE_BINDINGS
        ):
            raise ValueError(
                "max_lineage_bindings_per_candidate exceeds the contract"
            )


def _candidate_identity_payload(
    *,
    world_ref: str,
    terminal_operation_id: str,
    prerequisite_operation_ids: Sequence[str],
    plan_id: str,
    catalog_digest: str,
    recipe_id: str,
    lineage_binding_ids: Sequence[str],
    evidence_digest: str,
    risk_class: str,
) -> Dict[str, Any]:
    return {
        "world_ref": world_ref,
        "terminal_operation_id": terminal_operation_id,
        "prerequisite_operation_ids": list(prerequisite_operation_ids),
        "plan_id": plan_id,
        "catalog_digest": catalog_digest,
        "recipe_id": recipe_id,
        "lineage_binding_ids": list(lineage_binding_ids),
        "evidence_digest": evidence_digest,
        "risk_class": risk_class,
    }


@dataclass(frozen=True)
class StateMachineLegalityCandidate:
    candidate_id: str
    world_ref: str
    terminal_operation_id: str
    prerequisite_operation_ids: Tuple[str, ...]
    plan_id: str
    catalog_digest: str
    recipe_id: str
    source_refs: Tuple[str, ...]
    lineage_binding_ids: Tuple[str, ...]
    evidence_digest: str
    risk_class: str
    mode: str = STATE_MACHINE_LEGALITY_MODE
    executable: bool = False

    def __post_init__(self) -> None:
        identity = _candidate_identity_payload(
            world_ref=self.world_ref,
            terminal_operation_id=self.terminal_operation_id,
            prerequisite_operation_ids=self.prerequisite_operation_ids,
            plan_id=self.plan_id,
            catalog_digest=self.catalog_digest,
            recipe_id=self.recipe_id,
            lineage_binding_ids=self.lineage_binding_ids,
            evidence_digest=self.evidence_digest,
            risk_class=self.risk_class,
        )
        expected_evidence = stable_hash(
            "state_machine_legality_evidence",
            {
                "source_refs": list(self.source_refs),
                "recipe_id": self.recipe_id,
                "lineage_binding_ids": list(self.lineage_binding_ids),
            },
        )
        if (
            self.candidate_id
            != stable_hash("state_machine_legality_candidate", identity)
            or self.mode != STATE_MACHINE_LEGALITY_MODE
            or self.executable
            or not _hash_ref(self.world_ref, "world")
            or not _hash_ref(self.terminal_operation_id, "action")
            or not self.prerequisite_operation_ids
            or len(set(self.prerequisite_operation_ids))
            != len(self.prerequisite_operation_ids)
            or any(
                not _hash_ref(item, "action")
                for item in self.prerequisite_operation_ids
            )
            or self.terminal_operation_id in self.prerequisite_operation_ids
            or not _hash_ref(self.plan_id, "backward_plan")
            or not _hash_ref(self.catalog_digest, "operation_catalog")
            or not _hash_ref(self.recipe_id, "rehydration_recipe")
            or not self.source_refs
            or len(self.source_refs) > MAX_STATE_MACHINE_PLAN_STEPS
            or len(self.source_refs)
            != len(self.prerequisite_operation_ids) + 1
            or len(set(self.source_refs)) != len(self.source_refs)
            or any(not _hash_ref(item, "source_ref") for item in self.source_refs)
            or not self.lineage_binding_ids
            or len(self.lineage_binding_ids)
            > MAX_STATE_MACHINE_LINEAGE_BINDINGS
            or tuple(sorted(set(self.lineage_binding_ids)))
            != self.lineage_binding_ids
            or any(
                not _hash_ref(item, "lineage_binding")
                for item in self.lineage_binding_ids
            )
            or self.evidence_digest != expected_evidence
            or self.risk_class not in {"read", "state_mutation"}
        ):
            raise ValueError("state-machine legality candidate contract is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "world_ref": self.world_ref,
            "terminal_operation_id": self.terminal_operation_id,
            "prerequisite_operation_ids": list(self.prerequisite_operation_ids),
            "plan_id": self.plan_id,
            "catalog_digest": self.catalog_digest,
            "recipe_id": self.recipe_id,
            "source_refs": list(self.source_refs),
            "lineage_binding_ids": list(self.lineage_binding_ids),
            "evidence_digest": self.evidence_digest,
            "risk_class": self.risk_class,
            "mode": self.mode,
            "executable": self.executable,
        }


@dataclass(frozen=True)
class StateMachineLegalityDiagnostics:
    records: int
    normalized_records: int
    invalid_records: int
    operations: int
    high_value_goals: int
    goals_analyzed: int
    goals_blocked: int
    terminal_only_goals: int
    ordered_chains: int
    lineage_rejections: int
    ambiguous_chains: int
    cross_world_rejections: int
    duplicate_candidates: int
    dropped_goals: int
    dropped_candidates: int

    def __post_init__(self) -> None:
        if any(
            isinstance(value, bool) or not isinstance(value, int) or value < 0
            for value in vars(self).values()
        ):
            raise ValueError(
                "state-machine legality diagnostics must be non-negative integers"
            )

    @property
    def incomplete_work(self) -> int:
        return self.invalid_records + self.dropped_goals + self.dropped_candidates

    def to_dict(self) -> Dict[str, int]:
        return dict(vars(self))


def _result_payload(
    *,
    status: str,
    capture_digest: str,
    catalog_digest: str,
    candidates: Sequence[StateMachineLegalityCandidate],
    diagnostics: StateMachineLegalityDiagnostics,
    blocker: Optional[str],
) -> Dict[str, Any]:
    return {
        "mode": STATE_MACHINE_LEGALITY_MODE,
        "status": status,
        "capture_digest": capture_digest,
        "catalog_digest": catalog_digest,
        "candidates": [item.to_dict() for item in candidates],
        "diagnostics": diagnostics.to_dict(),
        "blocker": blocker,
    }


@dataclass(frozen=True)
class StateMachineLegalityResult:
    result_id: str
    status: str
    capture_digest: str
    catalog_digest: str
    candidates: Tuple[StateMachineLegalityCandidate, ...]
    diagnostics: StateMachineLegalityDiagnostics
    blocker: Optional[str] = None
    mode: str = STATE_MACHINE_LEGALITY_MODE
    executable: bool = False

    def __post_init__(self) -> None:
        payload = _result_payload(
            status=self.status,
            capture_digest=self.capture_digest,
            catalog_digest=self.catalog_digest,
            candidates=self.candidates,
            diagnostics=self.diagnostics,
            blocker=self.blocker,
        )
        expected_status = (
            "blocked"
            if self.blocker is not None
            else ("ready" if self.candidates else "no_candidates")
        )
        candidate_ids = [item.candidate_id for item in self.candidates]
        if (
            self.result_id != stable_hash("state_machine_legality_result", payload)
            or self.status != expected_status
            or self.mode != STATE_MACHINE_LEGALITY_MODE
            or self.executable
            or not _hash_ref(self.capture_digest, "state_machine_capture")
            or not _hash_ref(self.catalog_digest, "operation_catalog")
            or candidate_ids != sorted(set(candidate_ids))
            or len(self.candidates) > MAX_STATE_MACHINE_CANDIDATES
            or any(
                item.catalog_digest != self.catalog_digest
                for item in self.candidates
            )
            or self.diagnostics.ordered_chains < len(self.candidates)
            or self.diagnostics.goals_analyzed
            + self.diagnostics.dropped_goals
            != self.diagnostics.high_value_goals
            or (
                self.blocker != "record_limit_exceeded"
                and self.diagnostics.normalized_records
                + self.diagnostics.invalid_records
                != self.diagnostics.records
            )
            or (
                self.blocker is not None
                and _SEMANTIC.fullmatch(self.blocker) is None
            )
        ):
            raise ValueError("state-machine legality result contract is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": 1,
            "result_id": self.result_id,
            **_result_payload(
                status=self.status,
                capture_digest=self.capture_digest,
                catalog_digest=self.catalog_digest,
                candidates=self.candidates,
                diagnostics=self.diagnostics,
                blocker=self.blocker,
            ),
            "executable": self.executable,
        }


@dataclass(frozen=True)
class _Observation:
    index: int
    source_ref: str
    world_ref: str
    operation_id: str
    state_id: str
    successful: bool
    request_body_hash: Optional[str]
    response_body_hash: Optional[str]

    def digest_payload(self) -> Dict[str, Any]:
        return dict(vars(self))


class StateMachineLegalityMiner:
    """Compile exact observed prerequisite chains into passive relations."""

    def __init__(
        self,
        limits: StateMachineLegalityLimits = StateMachineLegalityLimits(),
    ) -> None:
        if not isinstance(limits, StateMachineLegalityLimits):
            raise TypeError("limits must be StateMachineLegalityLimits")
        self.limits = limits

    @staticmethod
    def _observations(
        records: Sequence[Mapping[str, Any]],
        *,
        world_id: str,
    ) -> Tuple[Tuple[_Observation, ...], Dict[str, str], int]:
        observations = []
        world_ids: Dict[str, str] = {}
        invalid = 0
        for index, record in enumerate(records):
            raw_world_id = str(record.get("persona_id") or world_id)
            try:
                exchange = normalize_exchange(
                    record,
                    source_id=str(record.get("id") or index),
                    world_id=raw_world_id,
                )
            except (TypeError, ValueError):
                invalid += 1
                continue
            observations.append(
                _Observation(
                    index=index,
                    source_ref=exchange.source_id,
                    world_ref=exchange.world_id,
                    operation_id=exchange.action_id,
                    state_id=exchange.state_id,
                    successful=200 <= exchange.response_status < 300,
                    request_body_hash=exchange.request_body_hash,
                    response_body_hash=exchange.response_body_hash,
                )
            )
            world_ids[exchange.world_id] = raw_world_id
        return tuple(observations), world_ids, invalid

    @staticmethod
    def _exact_ordered_chains(
        step_ids: Sequence[str],
        observations: Sequence[_Observation],
    ) -> Tuple[Tuple[str, Tuple[str, ...]], ...]:
        by_operation: Dict[str, Dict[str, list[_Observation]]] = {}
        for observation in observations:
            by_operation.setdefault(observation.operation_id, {}).setdefault(
                observation.world_ref,
                [],
            ).append(observation)
        worlds = set.intersection(
            *(
                set(by_operation.get(operation_id, {}))
                for operation_id in step_ids
            )
        )
        chains = []
        for world_ref in sorted(worlds):
            selected = [
                by_operation[operation_id][world_ref]
                for operation_id in step_ids
            ]
            if any(
                len(items) != 1 or not items[0].successful
                for items in selected
            ):
                continue
            ordered = tuple(items[0] for items in selected)
            if tuple(item.index for item in ordered) != tuple(
                sorted(item.index for item in ordered)
            ):
                continue
            evidence_refs = tuple(item.source_ref for item in ordered)
            if len(set(evidence_refs)) != len(evidence_refs):
                continue
            chains.append((world_ref, evidence_refs))
        return tuple(chains)

    @staticmethod
    def _risk_class(operation: OperationContract) -> str:
        return (
            "read"
            if operation.safety == OperationSafety.READ_ONLY
            else "state_mutation"
        )

    @staticmethod
    def _blocked_result(
        *,
        capture_digest: str,
        records: int,
        normalized_records: int,
        invalid_records: int,
        blocker: str,
    ) -> StateMachineLegalityResult:
        catalog_digest = stable_hash("operation_catalog", [])
        diagnostics = StateMachineLegalityDiagnostics(
            records=records,
            normalized_records=normalized_records,
            invalid_records=invalid_records,
            operations=0,
            high_value_goals=0,
            goals_analyzed=0,
            goals_blocked=0,
            terminal_only_goals=0,
            ordered_chains=0,
            lineage_rejections=0,
            ambiguous_chains=0,
            cross_world_rejections=0,
            duplicate_candidates=0,
            dropped_goals=0,
            dropped_candidates=0,
        )
        payload = _result_payload(
            status="blocked",
            capture_digest=capture_digest,
            catalog_digest=catalog_digest,
            candidates=(),
            diagnostics=diagnostics,
            blocker=blocker,
        )
        return StateMachineLegalityResult(
            result_id=stable_hash("state_machine_legality_result", payload),
            status="blocked",
            capture_digest=capture_digest,
            catalog_digest=catalog_digest,
            candidates=(),
            diagnostics=diagnostics,
            blocker=blocker,
        )

    def mine(
        self,
        records: Sequence[Mapping[str, Any]],
        *,
        world_id: str = "captured",
    ) -> StateMachineLegalityResult:
        if isinstance(records, (str, bytes)) or any(
            not isinstance(item, Mapping) for item in records
        ):
            raise TypeError("state-machine records must be a sequence of mappings")
        record_values = tuple(records)
        if len(record_values) > self.limits.max_records:
            return self._blocked_result(
                capture_digest=stable_hash(
                    "state_machine_capture",
                    {
                        "records": len(record_values),
                        "blocker": "record_limit_exceeded",
                    },
                ),
                records=len(record_values),
                normalized_records=0,
                invalid_records=0,
                blocker="record_limit_exceeded",
            )
        observations, world_ids, invalid_records = self._observations(
            record_values,
            world_id=world_id,
        )
        capture_digest = stable_hash(
            "state_machine_capture",
            {
                "records": len(record_values),
                "observations": [
                    item.digest_payload() for item in observations
                ],
                "invalid_records": invalid_records,
            },
        )
        try:
            ledger = ValueLineageLedger(
                record_values,
                world_id=world_id,
                catalog_limits=OperationCatalogLimits(
                    max_records=self.limits.max_records,
                ),
            )
            operations = ledger.operations
            compiler = BackwardExploitCompiler(
                operations,
                limits=CompilerLimits(
                    max_search_states=self.limits.max_search_states_per_goal,
                    max_plan_steps=self.limits.max_plan_steps,
                ),
            )
        except ValueError:
            return self._blocked_result(
                capture_digest=capture_digest,
                records=len(record_values),
                normalized_records=len(observations),
                invalid_records=invalid_records,
                blocker="relation_limits_exceeded",
            )

        operation_by_id = {
            operation.operation_id: operation for operation in operations
        }
        goals = high_value_goals(operations)
        selected_goals = goals[: self.limits.max_goals]
        dropped_goals = len(goals) - len(selected_goals)
        candidates: Dict[str, StateMachineLegalityCandidate] = {}
        goals_blocked = 0
        terminal_only_goals = 0
        ordered_chains = 0
        lineage_rejections = 0
        ambiguous_chains = 0
        cross_world_rejections = 0
        duplicate_candidates = 0
        dropped_candidates = 0
        rehydrator = PlanRehydrator(ledger)

        for goal in selected_goals:
            plan = compiler.compile(goal)
            if plan.status != "planned":
                goals_blocked += 1
                continue
            if len(plan.step_ids) <= 1:
                terminal_only_goals += 1
                continue
            chains = self._exact_ordered_chains(plan.step_ids, observations)
            step_worlds = [
                {
                    item.world_ref
                    for item in observations
                    if item.operation_id == operation_id
                }
                for operation_id in plan.step_ids
            ]
            if not chains:
                if step_worlds and all(step_worlds) and not set.intersection(
                    *step_worlds
                ):
                    cross_world_rejections += 1
                else:
                    ambiguous_chains += 1
                continue
            terminal = operation_by_id[plan.terminal_operation_id]
            for world_ref, source_refs in chains:
                ordered_chains += 1
                raw_world_id = world_ids.get(world_ref)
                if raw_world_id is None:
                    lineage_rejections += 1
                    continue
                recipe = rehydrator.build_recipe(
                    plan,
                    world_id=raw_world_id,
                )
                if (
                    recipe.status != "ready"
                    or tuple(item.source_ref for item in recipe.steps)
                    != source_refs
                    or not recipe.bindings
                ):
                    lineage_rejections += 1
                    continue
                lineage_binding_ids = tuple(
                    sorted(item.binding_id for item in recipe.bindings)
                )
                if (
                    len(lineage_binding_ids)
                    > self.limits.max_lineage_bindings_per_candidate
                ):
                    dropped_candidates += 1
                    continue
                evidence_digest = stable_hash(
                    "state_machine_legality_evidence",
                    {
                        "source_refs": list(source_refs),
                        "recipe_id": recipe.recipe_id,
                        "lineage_binding_ids": list(lineage_binding_ids),
                    },
                )
                identity = _candidate_identity_payload(
                    world_ref=world_ref,
                    terminal_operation_id=plan.terminal_operation_id,
                    prerequisite_operation_ids=plan.step_ids[:-1],
                    plan_id=plan.plan_id,
                    catalog_digest=plan.catalog_digest,
                    recipe_id=recipe.recipe_id,
                    lineage_binding_ids=lineage_binding_ids,
                    evidence_digest=evidence_digest,
                    risk_class=self._risk_class(terminal),
                )
                candidate = StateMachineLegalityCandidate(
                    candidate_id=stable_hash(
                        "state_machine_legality_candidate",
                        identity,
                    ),
                    world_ref=world_ref,
                    terminal_operation_id=plan.terminal_operation_id,
                    prerequisite_operation_ids=plan.step_ids[:-1],
                    plan_id=plan.plan_id,
                    catalog_digest=plan.catalog_digest,
                    recipe_id=recipe.recipe_id,
                    source_refs=source_refs,
                    lineage_binding_ids=lineage_binding_ids,
                    evidence_digest=evidence_digest,
                    risk_class=self._risk_class(terminal),
                )
                if candidate.candidate_id in candidates:
                    duplicate_candidates += 1
                    continue
                if len(candidates) >= self.limits.max_candidates:
                    dropped_candidates += 1
                    continue
                candidates[candidate.candidate_id] = candidate

        ordered_candidates = tuple(candidates[key] for key in sorted(candidates))
        diagnostics = StateMachineLegalityDiagnostics(
            records=len(record_values),
            normalized_records=len(observations),
            invalid_records=invalid_records,
            operations=len(operations),
            high_value_goals=len(goals),
            goals_analyzed=len(selected_goals),
            goals_blocked=goals_blocked,
            terminal_only_goals=terminal_only_goals,
            ordered_chains=ordered_chains,
            lineage_rejections=lineage_rejections,
            ambiguous_chains=ambiguous_chains,
            cross_world_rejections=cross_world_rejections,
            duplicate_candidates=duplicate_candidates,
            dropped_goals=dropped_goals,
            dropped_candidates=dropped_candidates,
        )
        status = "ready" if ordered_candidates else "no_candidates"
        payload = _result_payload(
            status=status,
            capture_digest=capture_digest,
            catalog_digest=compiler.catalog_digest,
            candidates=ordered_candidates,
            diagnostics=diagnostics,
            blocker=None,
        )
        return StateMachineLegalityResult(
            result_id=stable_hash("state_machine_legality_result", payload),
            status=status,
            capture_digest=capture_digest,
            catalog_digest=compiler.catalog_digest,
            candidates=ordered_candidates,
            diagnostics=diagnostics,
        )


__all__ = [
    "STATE_MACHINE_LEGALITY_MODE",
    "StateMachineLegalityCandidate",
    "StateMachineLegalityDiagnostics",
    "StateMachineLegalityLimits",
    "StateMachineLegalityMiner",
    "StateMachineLegalityResult",
]
