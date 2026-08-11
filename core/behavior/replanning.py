"""Deterministic, passive replanning over evidence-backed constraints."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, Optional, Sequence, Tuple

from .compiler import (
    BackwardExploitCompiler,
    BackwardGoal,
    BackwardPlan,
    Capability,
    CompilerLimits,
    CompilerPolicy,
    OperationContract,
)
from .constraints import ConstraintLedger, PrerequisiteConstraint
from .normalize import stable_hash
from .payout_goals import SecurityWitnessGoal


CONSTRAINT_REPLANNER_MODE = "constraint_replanning_analysis_only"

_HASH_REF = re.compile(r"^[a-z][a-z0-9_]*:[0-9a-f]{64}$")
_SEMANTIC = re.compile(r"^[a-z][a-z0-9_.:-]{0,191}$")


def _hash_ref(value: object, prefix: Optional[str] = None) -> bool:
    return (
        isinstance(value, str)
        and _HASH_REF.fullmatch(value) is not None
        and (prefix is None or value.startswith(f"{prefix}:"))
    )


def _unique_capabilities(values: Sequence[Capability]) -> Tuple[Capability, ...]:
    if any(not isinstance(item, Capability) for item in values):
        raise TypeError("initial_capabilities must contain Capability values")
    return tuple(sorted(set(values), key=lambda item: item.key))


def _limits_payload(value: object) -> Dict[str, int]:
    return {key: int(item) for key, item in vars(value).items()}


@dataclass(frozen=True)
class ConstraintReplanLimits:
    max_generations: int = 16
    max_lineage_entries: int = 32
    max_disproved_assumptions: int = 256

    def __post_init__(self) -> None:
        for name, value in vars(self).items():
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")


def _attempt_payload(
    *,
    plan_id: str,
    step_ids: Sequence[str],
    applied_assertion_ids: Sequence[str],
) -> Dict[str, Any]:
    return {
        "plan_id": plan_id,
        "step_ids": list(step_ids),
        "applied_assertion_ids": list(applied_assertion_ids),
    }


@dataclass(frozen=True)
class ConstraintPlanAttempt:
    attempt_id: str
    generation: int
    plan_id: str
    ledger_id: str
    step_ids: Tuple[str, ...]
    applied_assertion_ids: Tuple[str, ...]

    @classmethod
    def build(
        cls,
        *,
        generation: int,
        plan: BackwardPlan,
        ledger_id: str,
        applied_assertion_ids: Sequence[str],
    ) -> "ConstraintPlanAttempt":
        assertions = tuple(sorted(set(applied_assertion_ids)))
        payload = _attempt_payload(
            plan_id=plan.plan_id,
            step_ids=plan.step_ids,
            applied_assertion_ids=assertions,
        )
        return cls(
            attempt_id=stable_hash("constraint_plan_attempt", payload),
            generation=generation,
            plan_id=plan.plan_id,
            ledger_id=ledger_id,
            step_ids=plan.step_ids,
            applied_assertion_ids=assertions,
        )

    def __post_init__(self) -> None:
        payload = _attempt_payload(
            plan_id=self.plan_id,
            step_ids=self.step_ids,
            applied_assertion_ids=self.applied_assertion_ids,
        )
        if (
            self.attempt_id != stable_hash("constraint_plan_attempt", payload)
            or isinstance(self.generation, bool)
            or not isinstance(self.generation, int)
            or self.generation < 0
            or not _hash_ref(self.plan_id, "backward_plan")
            or not _hash_ref(self.ledger_id, "constraint_ledger")
            or self.step_ids != tuple(self.step_ids)
            or any(_SEMANTIC.fullmatch(item) is None for item in self.step_ids)
            or self.applied_assertion_ids
            != tuple(sorted(set(self.applied_assertion_ids)))
            or any(
                not _hash_ref(item, "constraint_assertion")
                for item in self.applied_assertion_ids
            )
        ):
            raise ValueError("constraint plan attempt contract is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "attempt_id": self.attempt_id,
            "generation": self.generation,
            "plan_id": self.plan_id,
            "ledger_id": self.ledger_id,
            "step_ids": list(self.step_ids),
            "applied_assertion_ids": list(self.applied_assertion_ids),
        }


def _assumption_payload(
    *,
    prior_attempt_id: str,
    prior_plan_id: str,
    constraint: PrerequisiteConstraint,
) -> Dict[str, Any]:
    return {
        "prior_attempt_id": prior_attempt_id,
        "prior_plan_id": prior_plan_id,
        "assertion_id": constraint.assertion_id,
        "constraint_id": constraint.constraint_id,
        "operation_id": constraint.operation_id,
        "required_capability": constraint.required_capability.to_dict(),
        "signal_ids": list(constraint.signal_ids),
        "evidence_refs": list(constraint.evidence_refs),
    }


@dataclass(frozen=True)
class DisprovedPlanAssumption:
    assumption_id: str
    prior_attempt_id: str
    prior_plan_id: str
    assertion_id: str
    constraint_id: str
    operation_id: str
    required_capability: Capability
    signal_ids: Tuple[str, ...]
    evidence_refs: Tuple[str, ...]

    @classmethod
    def build(
        cls,
        *,
        prior_attempt: ConstraintPlanAttempt,
        constraint: PrerequisiteConstraint,
    ) -> "DisprovedPlanAssumption":
        payload = _assumption_payload(
            prior_attempt_id=prior_attempt.attempt_id,
            prior_plan_id=prior_attempt.plan_id,
            constraint=constraint,
        )
        return cls(
            assumption_id=stable_hash("disproved_plan_assumption", payload),
            prior_attempt_id=prior_attempt.attempt_id,
            prior_plan_id=prior_attempt.plan_id,
            assertion_id=constraint.assertion_id,
            constraint_id=constraint.constraint_id,
            operation_id=constraint.operation_id,
            required_capability=constraint.required_capability,
            signal_ids=constraint.signal_ids,
            evidence_refs=constraint.evidence_refs,
        )

    def __post_init__(self) -> None:
        constraint = _ConstraintProjection(
            assertion_id=self.assertion_id,
            constraint_id=self.constraint_id,
            operation_id=self.operation_id,
            required_capability=self.required_capability,
            signal_ids=self.signal_ids,
            evidence_refs=self.evidence_refs,
        )
        payload = _assumption_payload(
            prior_attempt_id=self.prior_attempt_id,
            prior_plan_id=self.prior_plan_id,
            constraint=constraint,
        )
        if (
            self.assumption_id != stable_hash("disproved_plan_assumption", payload)
            or not _hash_ref(self.prior_attempt_id, "constraint_plan_attempt")
            or not _hash_ref(self.prior_plan_id, "backward_plan")
            or not _hash_ref(self.assertion_id, "constraint_assertion")
            or not _hash_ref(self.constraint_id, "prerequisite_constraint")
            or _SEMANTIC.fullmatch(self.operation_id) is None
            or self.signal_ids != tuple(sorted(set(self.signal_ids)))
            or any(not _hash_ref(item, "constraint_signal") for item in self.signal_ids)
            or self.evidence_refs != tuple(sorted(set(self.evidence_refs)))
            or any(not _hash_ref(item) for item in self.evidence_refs)
        ):
            raise ValueError("disproved plan assumption contract is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "assumption_id": self.assumption_id,
            "prior_attempt_id": self.prior_attempt_id,
            "prior_plan_id": self.prior_plan_id,
            "assertion_id": self.assertion_id,
            "constraint_id": self.constraint_id,
            "operation_id": self.operation_id,
            "required_capability": self.required_capability.to_dict(),
            "signal_ids": list(self.signal_ids),
            "evidence_refs": list(self.evidence_refs),
        }


@dataclass(frozen=True)
class _ConstraintProjection:
    """Internal shape used only to revalidate a serialized assumption payload."""

    assertion_id: str
    constraint_id: str
    operation_id: str
    required_capability: Capability
    signal_ids: Tuple[str, ...]
    evidence_refs: Tuple[str, ...]


def _result_payload(
    *,
    status: str,
    goal_id: str,
    terminal_operation_id: str,
    root_evidence_refs: Sequence[str],
    accepted_ledger_id: str,
    observed_ledger_id: str,
    generation: int,
    plan: BackwardPlan,
    applied_constraint_ids: Sequence[str],
    applied_assertion_ids: Sequence[str],
    hypothesis_constraint_ids: Sequence[str],
    lineage: Sequence[ConstraintPlanAttempt],
    disproved_assumptions: Sequence[DisprovedPlanAssumption],
    blockers: Sequence[str],
    policy_digest: str,
    compiler_limits_digest: str,
    replan_limits_digest: str,
) -> Dict[str, Any]:
    return {
        "mode": CONSTRAINT_REPLANNER_MODE,
        "status": status,
        "goal_id": goal_id,
        "terminal_operation_id": terminal_operation_id,
        "root_evidence_refs": list(root_evidence_refs),
        "accepted_ledger_id": accepted_ledger_id,
        "observed_ledger_id": observed_ledger_id,
        "generation": generation,
        "plan": plan.to_dict(),
        "applied_constraint_ids": list(applied_constraint_ids),
        "applied_assertion_ids": list(applied_assertion_ids),
        "hypothesis_constraint_ids": list(hypothesis_constraint_ids),
        "lineage": [item.to_dict() for item in lineage],
        "disproved_assumptions": [item.to_dict() for item in disproved_assumptions],
        "blockers": list(blockers),
        "policy_digest": policy_digest,
        "compiler_limits_digest": compiler_limits_digest,
        "replan_limits_digest": replan_limits_digest,
    }


@dataclass(frozen=True)
class ConstraintReplanResult:
    result_id: str
    status: str
    goal_id: str
    terminal_operation_id: str
    root_evidence_refs: Tuple[str, ...]
    accepted_ledger_id: str
    observed_ledger_id: str
    generation: int
    plan: BackwardPlan
    applied_constraint_ids: Tuple[str, ...]
    applied_assertion_ids: Tuple[str, ...]
    hypothesis_constraint_ids: Tuple[str, ...]
    lineage: Tuple[ConstraintPlanAttempt, ...]
    disproved_assumptions: Tuple[DisprovedPlanAssumption, ...]
    blockers: Tuple[str, ...]
    policy_digest: str
    compiler_limits_digest: str
    replan_limits_digest: str
    mode: str = CONSTRAINT_REPLANNER_MODE
    executable: bool = False

    def __post_init__(self) -> None:
        payload = _result_payload(
            status=self.status,
            goal_id=self.goal_id,
            terminal_operation_id=self.terminal_operation_id,
            root_evidence_refs=self.root_evidence_refs,
            accepted_ledger_id=self.accepted_ledger_id,
            observed_ledger_id=self.observed_ledger_id,
            generation=self.generation,
            plan=self.plan,
            applied_constraint_ids=self.applied_constraint_ids,
            applied_assertion_ids=self.applied_assertion_ids,
            hypothesis_constraint_ids=self.hypothesis_constraint_ids,
            lineage=self.lineage,
            disproved_assumptions=self.disproved_assumptions,
            blockers=self.blockers,
            policy_digest=self.policy_digest,
            compiler_limits_digest=self.compiler_limits_digest,
            replan_limits_digest=self.replan_limits_digest,
        )
        expected_status = "blocked" if self.blockers or self.plan.status != "planned" else "ready"
        if (
            self.mode != CONSTRAINT_REPLANNER_MODE
            or self.executable
            or self.result_id != stable_hash("constraint_replan_result", payload)
            or self.status != expected_status
            or self.goal_id != self.plan.goal_id
            or self.terminal_operation_id != self.plan.terminal_operation_id
            or self.root_evidence_refs != tuple(sorted(set(self.root_evidence_refs)))
            or not self.root_evidence_refs
            or any(not _hash_ref(item) for item in self.root_evidence_refs)
            or not _hash_ref(self.accepted_ledger_id, "constraint_ledger")
            or not _hash_ref(self.observed_ledger_id, "constraint_ledger")
            or isinstance(self.generation, bool)
            or not isinstance(self.generation, int)
            or self.generation < 0
            or self.policy_digest != self.plan.policy_digest
            or not _hash_ref(self.compiler_limits_digest, "compiler_limits")
            or not _hash_ref(self.replan_limits_digest, "constraint_replan_limits")
            or self.applied_constraint_ids
            != tuple(sorted(set(self.applied_constraint_ids)))
            or any(
                not _hash_ref(item, "prerequisite_constraint")
                for item in self.applied_constraint_ids
            )
            or self.applied_assertion_ids
            != tuple(sorted(set(self.applied_assertion_ids)))
            or any(
                not _hash_ref(item, "constraint_assertion")
                for item in self.applied_assertion_ids
            )
            or self.hypothesis_constraint_ids
            != tuple(sorted(set(self.hypothesis_constraint_ids)))
            or any(
                not _hash_ref(item, "prerequisite_constraint")
                for item in self.hypothesis_constraint_ids
            )
            or not self.lineage
            or self.generation != self.lineage[-1].generation
            or self.lineage[-1].plan_id != self.plan.plan_id
            or self.lineage[-1].ledger_id != self.accepted_ledger_id
            or self.lineage[-1].applied_assertion_ids != self.applied_assertion_ids
            or any(item.generation != index for index, item in enumerate(self.lineage))
            or len({item.attempt_id for item in self.lineage}) != len(self.lineage)
            or self.disproved_assumptions
            != tuple(sorted(set(self.disproved_assumptions), key=lambda item: item.assumption_id))
            or self.blockers != tuple(sorted(set(self.blockers)))
            or any(_SEMANTIC.fullmatch(item) is None for item in self.blockers)
            or "analysis_only_no_execution_authority" not in self.plan.execution_blockers
        ):
            raise ValueError("constraint replan result contract is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": 1,
            "result_id": self.result_id,
            "executable": self.executable,
            **_result_payload(
                status=self.status,
                goal_id=self.goal_id,
                terminal_operation_id=self.terminal_operation_id,
                root_evidence_refs=self.root_evidence_refs,
                accepted_ledger_id=self.accepted_ledger_id,
                observed_ledger_id=self.observed_ledger_id,
                generation=self.generation,
                plan=self.plan,
                applied_constraint_ids=self.applied_constraint_ids,
                applied_assertion_ids=self.applied_assertion_ids,
                hypothesis_constraint_ids=self.hypothesis_constraint_ids,
                lineage=self.lineage,
                disproved_assumptions=self.disproved_assumptions,
                blockers=self.blockers,
                policy_digest=self.policy_digest,
                compiler_limits_digest=self.compiler_limits_digest,
                replan_limits_digest=self.replan_limits_digest,
            ),
        }


class ConstraintReplanner:
    """Recompile one payout goal without changing policy or execution authority."""

    def __init__(
        self,
        operations: Sequence[OperationContract],
        *,
        policy: Optional[CompilerPolicy] = None,
        compiler_limits: Optional[CompilerLimits] = None,
        replan_limits: ConstraintReplanLimits = ConstraintReplanLimits(),
    ) -> None:
        if any(not isinstance(item, OperationContract) for item in operations):
            raise TypeError("operations must contain OperationContract values")
        if not isinstance(replan_limits, ConstraintReplanLimits):
            raise TypeError("replan_limits must be ConstraintReplanLimits")
        self.operations = tuple(sorted(operations, key=lambda item: item.operation_id))
        if len({item.operation_id for item in self.operations}) != len(self.operations):
            raise ValueError("operations must have unique operation_id values")
        self.operation_ids = frozenset(item.operation_id for item in self.operations)
        self.policy = policy or CompilerPolicy()
        self.compiler_limits = compiler_limits or CompilerLimits()
        self.replan_limits = replan_limits
        if not isinstance(self.policy, CompilerPolicy):
            raise TypeError("policy must be a CompilerPolicy")
        if not isinstance(self.compiler_limits, CompilerLimits):
            raise TypeError("compiler_limits must be CompilerLimits")
        self.policy_digest = BackwardExploitCompiler(
            self.operations,
            policy=self.policy,
            limits=self.compiler_limits,
        ).policy_digest
        self.compiler_limits_digest = stable_hash(
            "compiler_limits",
            _limits_payload(self.compiler_limits),
        )
        self.replan_limits_digest = stable_hash(
            "constraint_replan_limits",
            _limits_payload(self.replan_limits),
        )

    def compile_witness(
        self,
        goal: SecurityWitnessGoal,
        *,
        ledger: ConstraintLedger,
        initial_capabilities: Sequence[Capability] = (),
        previous: Optional[ConstraintReplanResult] = None,
    ) -> ConstraintReplanResult:
        if not isinstance(goal, SecurityWitnessGoal):
            raise TypeError("goal must be a SecurityWitnessGoal")
        backward_goal = BackwardGoal(
            goal_id=goal.goal_id,
            terminal_operation_id=goal.terminal_operation_id,
        )
        return self._compile(
            goal=backward_goal,
            root_evidence_refs=goal.evidence_refs,
            ledger=ledger,
            initial_capabilities=initial_capabilities,
            previous=previous,
        )

    def compile_goal(
        self,
        goal: BackwardGoal,
        *,
        root_evidence_refs: Sequence[str],
        ledger: ConstraintLedger,
        initial_capabilities: Sequence[Capability] = (),
        previous: Optional[ConstraintReplanResult] = None,
    ) -> ConstraintReplanResult:
        if not isinstance(goal, BackwardGoal):
            raise TypeError("goal must be a BackwardGoal")
        return self._compile(
            goal=goal,
            root_evidence_refs=root_evidence_refs,
            ledger=ledger,
            initial_capabilities=initial_capabilities,
            previous=previous,
        )

    def _compile(
        self,
        *,
        goal: BackwardGoal,
        root_evidence_refs: Sequence[str],
        ledger: ConstraintLedger,
        initial_capabilities: Sequence[Capability],
        previous: Optional[ConstraintReplanResult],
    ) -> ConstraintReplanResult:
        if not isinstance(ledger, ConstraintLedger):
            raise TypeError("ledger must be a ConstraintLedger")
        evidence_refs = tuple(sorted(set(root_evidence_refs)))
        if not evidence_refs or any(not _hash_ref(item) for item in evidence_refs):
            raise ValueError("root_evidence_refs must contain content-addressed evidence")
        initial = _unique_capabilities(initial_capabilities)
        if previous is not None:
            self._validate_previous(
                previous=previous,
                goal=goal,
                evidence_refs=evidence_refs,
                initial=initial,
            )

        hypotheses = tuple(item.constraint_id for item in ledger.hypotheses)
        if ledger.blockers:
            return self._blocked_without_new_attempt(
                goal=goal,
                evidence_refs=evidence_refs,
                ledger=ledger,
                initial=initial,
                previous=previous,
                hypotheses=hypotheses,
                blockers=("constraint_ledger_blocked", *ledger.blockers),
            )

        facts = tuple(ledger.facts)
        unknown = tuple(item for item in facts if item.operation_id not in self.operation_ids)
        if unknown:
            return self._blocked_without_new_attempt(
                goal=goal,
                evidence_refs=evidence_refs,
                ledger=ledger,
                initial=initial,
                previous=previous,
                hypotheses=hypotheses,
                blockers=("constraint_operation_unavailable",),
            )

        applied_constraint_ids = tuple(sorted(item.constraint_id for item in facts))
        applied_assertion_ids = tuple(sorted(item.assertion_id for item in facts))
        new_facts = facts
        assumptions: Tuple[DisprovedPlanAssumption, ...] = ()
        generation = 0
        prior_lineage: Tuple[ConstraintPlanAttempt, ...] = ()
        prior_assumptions: Tuple[DisprovedPlanAssumption, ...] = ()
        if previous is not None:
            previous_assertions = set(previous.applied_assertion_ids)
            current_assertions = set(applied_assertion_ids)
            if not previous_assertions <= current_assertions:
                return self._blocked_without_new_attempt(
                    goal=goal,
                    evidence_refs=evidence_refs,
                    ledger=ledger,
                    initial=initial,
                    previous=previous,
                    hypotheses=hypotheses,
                    blockers=("constraint_fact_regression",),
                )
            new_facts = tuple(
                item for item in facts if item.assertion_id not in previous_assertions
            )
            if not new_facts:
                return self._blocked_without_new_attempt(
                    goal=goal,
                    evidence_refs=evidence_refs,
                    ledger=ledger,
                    initial=initial,
                    previous=previous,
                    hypotheses=hypotheses,
                    blockers=("no_new_constraint_fact",),
                )
            if any(item.operation_id not in previous.plan.step_ids for item in new_facts):
                return self._blocked_without_new_attempt(
                    goal=goal,
                    evidence_refs=evidence_refs,
                    ledger=ledger,
                    initial=initial,
                    previous=previous,
                    hypotheses=hypotheses,
                    blockers=("constraint_not_on_previous_plan",),
                )
            if previous.generation >= self.replan_limits.max_generations:
                return self._blocked_without_new_attempt(
                    goal=goal,
                    evidence_refs=evidence_refs,
                    ledger=ledger,
                    initial=initial,
                    previous=previous,
                    hypotheses=hypotheses,
                    blockers=("replan_generation_limit_exceeded",),
                )
            generation = previous.generation + 1
            prior_lineage = previous.lineage
            prior_assumptions = previous.disproved_assumptions
            assumptions = tuple(
                DisprovedPlanAssumption.build(
                    prior_attempt=previous.lineage[-1],
                    constraint=item,
                )
                for item in new_facts
            )
            if (
                len(prior_assumptions) + len(assumptions)
                > self.replan_limits.max_disproved_assumptions
            ):
                return self._blocked_without_new_attempt(
                    goal=goal,
                    evidence_refs=evidence_refs,
                    ledger=ledger,
                    initial=initial,
                    previous=previous,
                    hypotheses=hypotheses,
                    blockers=("disproved_assumption_limit_exceeded",),
                )

        constrained_operations = self._apply_facts(facts)
        plan = BackwardExploitCompiler(
            constrained_operations,
            policy=self.policy,
            limits=self.compiler_limits,
        ).compile(goal, initial_capabilities=initial)
        if plan.policy_digest != self.policy_digest:
            raise ValueError("compiler policy digest drifted during replanning")

        attempt = ConstraintPlanAttempt.build(
            generation=generation,
            plan=plan,
            ledger_id=ledger.ledger_id,
            applied_assertion_ids=applied_assertion_ids,
        )
        if any(item.attempt_id == attempt.attempt_id for item in prior_lineage):
            return self._blocked_without_new_attempt(
                goal=goal,
                evidence_refs=evidence_refs,
                ledger=ledger,
                initial=initial,
                previous=previous,
                hypotheses=hypotheses,
                blockers=("repeated_disproved_plan",),
            )
        if len(prior_lineage) + 1 > self.replan_limits.max_lineage_entries:
            return self._blocked_without_new_attempt(
                goal=goal,
                evidence_refs=evidence_refs,
                ledger=ledger,
                initial=initial,
                previous=previous,
                hypotheses=hypotheses,
                blockers=("plan_lineage_limit_exceeded",),
            )

        blockers = set()
        if plan.search_exhausted:
            blockers.add("constraint_search_bound_exhausted")
        if any(
            item.startswith("cyclic_or_unreachable:") for item in plan.execution_blockers
        ):
            blockers.add("constraint_cycle_or_unreachable")
        if plan.status != "planned":
            blockers.add("replanned_goal_blocked")
        lineage = (*prior_lineage, attempt)
        disproved = tuple(
            sorted(
                {*prior_assumptions, *assumptions},
                key=lambda item: item.assumption_id,
            )
        )
        return self._result(
            goal=goal,
            evidence_refs=evidence_refs,
            ledger=ledger,
            generation=generation,
            plan=plan,
            applied_constraint_ids=applied_constraint_ids,
            applied_assertion_ids=applied_assertion_ids,
            hypotheses=hypotheses,
            lineage=lineage,
            assumptions=disproved,
            blockers=tuple(sorted(blockers)),
        )

    def _validate_previous(
        self,
        *,
        previous: ConstraintReplanResult,
        goal: BackwardGoal,
        evidence_refs: Tuple[str, ...],
        initial: Tuple[Capability, ...],
    ) -> None:
        if not isinstance(previous, ConstraintReplanResult):
            raise TypeError("previous must be a ConstraintReplanResult")
        if (
            previous.goal_id != goal.goal_id
            or previous.terminal_operation_id != goal.terminal_operation_id
            or previous.root_evidence_refs != evidence_refs
            or previous.plan.initial_capabilities != initial
            or previous.policy_digest != self.policy_digest
            or previous.compiler_limits_digest != self.compiler_limits_digest
            or previous.replan_limits_digest != self.replan_limits_digest
        ):
            raise ValueError("previous replan result does not match this planning context")

    def _apply_facts(
        self,
        facts: Sequence[PrerequisiteConstraint],
    ) -> Tuple[OperationContract, ...]:
        required: Dict[str, set[Capability]] = {}
        for fact in facts:
            required.setdefault(fact.operation_id, set()).add(fact.required_capability)
        return tuple(
            OperationContract(
                operation_id=operation.operation_id,
                label=operation.label,
                requires=tuple((*operation.requires, *required.get(operation.operation_id, ()))),
                produces=operation.produces,
                safety=operation.safety,
                cost=operation.cost,
                observed_success=operation.observed_success,
                source_refs=operation.source_refs,
                requires_owned_state=operation.requires_owned_state,
                cleanup_operation_id=operation.cleanup_operation_id,
            )
            for operation in self.operations
        )

    def _blocked_without_new_attempt(
        self,
        *,
        goal: BackwardGoal,
        evidence_refs: Tuple[str, ...],
        ledger: ConstraintLedger,
        initial: Tuple[Capability, ...],
        previous: Optional[ConstraintReplanResult],
        hypotheses: Tuple[str, ...],
        blockers: Sequence[str],
    ) -> ConstraintReplanResult:
        if previous is None:
            plan = BackwardExploitCompiler(
                self.operations,
                policy=self.policy,
                limits=self.compiler_limits,
            ).compile(goal, initial_capabilities=initial)
            attempt = ConstraintPlanAttempt.build(
                generation=0,
                plan=plan,
                ledger_id=ledger.ledger_id,
                applied_assertion_ids=(),
            )
            return self._result(
                goal=goal,
                evidence_refs=evidence_refs,
                ledger=ledger,
                generation=0,
                plan=plan,
                applied_constraint_ids=(),
                applied_assertion_ids=(),
                hypotheses=hypotheses,
                lineage=(attempt,),
                assumptions=(),
                blockers=tuple(sorted(set(blockers))),
            )
        return self._result(
            goal=goal,
            evidence_refs=evidence_refs,
            ledger=ledger,
            generation=previous.generation,
            plan=previous.plan,
            applied_constraint_ids=previous.applied_constraint_ids,
            applied_assertion_ids=previous.applied_assertion_ids,
            hypotheses=hypotheses,
            lineage=previous.lineage,
            assumptions=previous.disproved_assumptions,
            blockers=tuple(sorted(set((*previous.blockers, *blockers)))),
            accepted_ledger_id=previous.accepted_ledger_id,
        )

    def _result(
        self,
        *,
        goal: BackwardGoal,
        evidence_refs: Tuple[str, ...],
        ledger: ConstraintLedger,
        generation: int,
        plan: BackwardPlan,
        applied_constraint_ids: Tuple[str, ...],
        applied_assertion_ids: Tuple[str, ...],
        hypotheses: Tuple[str, ...],
        lineage: Tuple[ConstraintPlanAttempt, ...],
        assumptions: Tuple[DisprovedPlanAssumption, ...],
        blockers: Tuple[str, ...],
        accepted_ledger_id: Optional[str] = None,
    ) -> ConstraintReplanResult:
        accepted_ledger = accepted_ledger_id or ledger.ledger_id
        status = "blocked" if blockers or plan.status != "planned" else "ready"
        payload = _result_payload(
            status=status,
            goal_id=goal.goal_id,
            terminal_operation_id=goal.terminal_operation_id,
            root_evidence_refs=evidence_refs,
            accepted_ledger_id=accepted_ledger,
            observed_ledger_id=ledger.ledger_id,
            generation=generation,
            plan=plan,
            applied_constraint_ids=applied_constraint_ids,
            applied_assertion_ids=applied_assertion_ids,
            hypothesis_constraint_ids=hypotheses,
            lineage=lineage,
            disproved_assumptions=assumptions,
            blockers=blockers,
            policy_digest=self.policy_digest,
            compiler_limits_digest=self.compiler_limits_digest,
            replan_limits_digest=self.replan_limits_digest,
        )
        return ConstraintReplanResult(
            result_id=stable_hash("constraint_replan_result", payload),
            status=status,
            goal_id=goal.goal_id,
            terminal_operation_id=goal.terminal_operation_id,
            root_evidence_refs=evidence_refs,
            accepted_ledger_id=accepted_ledger,
            observed_ledger_id=ledger.ledger_id,
            generation=generation,
            plan=plan,
            applied_constraint_ids=applied_constraint_ids,
            applied_assertion_ids=applied_assertion_ids,
            hypothesis_constraint_ids=hypotheses,
            lineage=lineage,
            disproved_assumptions=assumptions,
            blockers=blockers,
            policy_digest=self.policy_digest,
            compiler_limits_digest=self.compiler_limits_digest,
            replan_limits_digest=self.replan_limits_digest,
        )


__all__ = [
    "CONSTRAINT_REPLANNER_MODE",
    "ConstraintPlanAttempt",
    "ConstraintReplanLimits",
    "ConstraintReplanResult",
    "ConstraintReplanner",
    "DisprovedPlanAssumption",
]
