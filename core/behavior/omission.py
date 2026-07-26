"""Compile minimized, analysis-only prerequisite-omission experiments.

The compiler accepts only an exact state-machine legality candidate whose
terminal read consumes one unambiguous sensitive query capability produced by
one prerequisite. It emits a redacted two-leg comparison oracle but performs no
request mutation, target I/O, admission, execution, or finding confirmation.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple
from urllib.parse import parse_qsl, urlsplit

from .compiler import (
    BackwardExploitCompiler,
    CompilerLimits,
    OperationCatalogLimits,
    OperationSafety,
    high_value_goals,
)
from .lifecycle import LifecycleMiningResult, OwnedLifecycleCandidate
from .lineage import LineageBinding, LocatorKind, PlanRehydrator, ValueLineageLedger
from .normalize import normalize_exchange, stable_hash
from .state_machine import (
    MAX_STATE_MACHINE_PLAN_STEPS,
    MAX_STATE_MACHINE_RECORDS,
    MAX_STATE_MACHINE_SEARCH_STATES,
    StateMachineLegalityCandidate,
    StateMachineLegalityResult,
    state_machine_subject_ref,
)

MINIMIZED_OMISSION_MODE = "behavioral_minimized_omission_v1"
MAX_OMISSION_EXPERIMENTS = 16

_HASH_REF = re.compile(r"^[a-z][a-z0-9_]*:[0-9a-f]{64}$")
_BODY_HASH = re.compile(r"^sha256:[0-9a-f]{64}$")
_SEMANTIC = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_CAPABILITY = re.compile(r"^[a-z][a-z0-9_.-]{0,63}:[a-z][a-z0-9_.:-]{0,127}$")
_QUERY_POINTER = re.compile(r"^/(?:[^/~]|~[01])+/0$")

_MUTATION_KIND = "remove_request_query_binding"
_COMPARISON_KIND = "exact_success_body_match"
_BASELINE_REQUIREMENT = "captured_state_match"
_REQUIRED_BLOCKERS = frozenset(
    {
        "analysis_only_no_execution_authority",
        "requires_two_fresh_owned_states",
    }
)


def _hash_ref(value: Any, prefix: Optional[str] = None) -> bool:
    return (
        isinstance(value, str)
        and _HASH_REF.fullmatch(value) is not None
        and (prefix is None or value.startswith(f"{prefix}:"))
    )


def _decode_query_pointer(pointer: str) -> Optional[str]:
    if _QUERY_POINTER.fullmatch(pointer) is None:
        return None
    encoded = pointer[1:-2]
    return encoded.replace("~1", "/").replace("~0", "~")


@dataclass(frozen=True)
class OmissionComparisonOracle:
    oracle_id: str
    reference_state_id: str
    reference_response_status: int
    reference_response_body_hash: str
    baseline_requirement: str = _BASELINE_REQUIREMENT
    comparison_kind: str = _COMPARISON_KIND
    require_success: bool = True
    require_non_truncated: bool = True
    finding_authority: bool = False
    executable: bool = False

    def __post_init__(self) -> None:
        payload = {
            "reference_state_id": self.reference_state_id,
            "reference_response_status": self.reference_response_status,
            "reference_response_body_hash": self.reference_response_body_hash,
            "baseline_requirement": self.baseline_requirement,
            "comparison_kind": self.comparison_kind,
            "require_success": self.require_success,
            "require_non_truncated": self.require_non_truncated,
            "finding_authority": self.finding_authority,
            "executable": self.executable,
        }
        if (
            self.oracle_id != stable_hash("omission_comparison_oracle", payload)
            or not _hash_ref(self.reference_state_id, "state")
            or isinstance(self.reference_response_status, bool)
            or not isinstance(self.reference_response_status, int)
            or not 200 <= self.reference_response_status < 300
            or _BODY_HASH.fullmatch(self.reference_response_body_hash) is None
            or self.baseline_requirement != _BASELINE_REQUIREMENT
            or self.comparison_kind != _COMPARISON_KIND
            or not self.require_success
            or not self.require_non_truncated
            or self.finding_authority
            or self.executable
        ):
            raise ValueError("omission comparison oracle contract is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "oracle_id": self.oracle_id,
            "reference_state_id": self.reference_state_id,
            "reference_response_status": self.reference_response_status,
            "reference_response_body_hash": self.reference_response_body_hash,
            "baseline_requirement": self.baseline_requirement,
            "comparison_kind": self.comparison_kind,
            "require_success": self.require_success,
            "require_non_truncated": self.require_non_truncated,
            "finding_authority": self.finding_authority,
            "executable": self.executable,
        }


def _experiment_identity_payload(
    *,
    state_machine_candidate_id: str,
    subject_ref: str,
    lifecycle_id: str,
    world_ref: str,
    terminal_operation_id: str,
    prerequisite_operation_ids: Sequence[str],
    omitted_prerequisite_operation_id: str,
    baseline_operation_ids: Sequence[str],
    omission_operation_ids: Sequence[str],
    plan_id: str,
    recipe_id: str,
    omitted_binding_id: str,
    capability_key: str,
    consumer_locator_pointer: str,
    baseline_source_ref: str,
    oracle: OmissionComparisonOracle,
    execution_blockers: Sequence[str],
) -> Dict[str, Any]:
    return {
        "state_machine_candidate_id": state_machine_candidate_id,
        "subject_ref": subject_ref,
        "lifecycle_id": lifecycle_id,
        "world_ref": world_ref,
        "terminal_operation_id": terminal_operation_id,
        "prerequisite_operation_ids": list(prerequisite_operation_ids),
        "omitted_prerequisite_operation_id": omitted_prerequisite_operation_id,
        "baseline_operation_ids": list(baseline_operation_ids),
        "omission_operation_ids": list(omission_operation_ids),
        "plan_id": plan_id,
        "recipe_id": recipe_id,
        "omitted_binding_id": omitted_binding_id,
        "capability_key": capability_key,
        "mutation_kind": _MUTATION_KIND,
        "consumer_locator_kind": LocatorKind.REQUEST_QUERY.value,
        "consumer_locator_pointer": consumer_locator_pointer,
        "baseline_source_ref": baseline_source_ref,
        "oracle": oracle.to_dict(),
        "execution_blockers": list(execution_blockers),
    }


@dataclass(frozen=True)
class MinimizedOmissionExperiment:
    experiment_id: str
    state_machine_candidate_id: str
    subject_ref: str
    lifecycle_id: str
    world_ref: str
    terminal_operation_id: str
    prerequisite_operation_ids: Tuple[str, ...]
    omitted_prerequisite_operation_id: str
    baseline_operation_ids: Tuple[str, ...]
    omission_operation_ids: Tuple[str, ...]
    plan_id: str
    recipe_id: str
    omitted_binding_id: str
    capability_key: str
    consumer_locator_pointer: str
    baseline_source_ref: str
    oracle: OmissionComparisonOracle
    execution_blockers: Tuple[str, ...]
    mutation_kind: str = _MUTATION_KIND
    consumer_locator_kind: str = LocatorKind.REQUEST_QUERY.value
    mode: str = MINIMIZED_OMISSION_MODE
    finding_authority: bool = False
    executable: bool = False

    def __post_init__(self) -> None:
        payload = _experiment_identity_payload(
            state_machine_candidate_id=self.state_machine_candidate_id,
            subject_ref=self.subject_ref,
            lifecycle_id=self.lifecycle_id,
            world_ref=self.world_ref,
            terminal_operation_id=self.terminal_operation_id,
            prerequisite_operation_ids=self.prerequisite_operation_ids,
            omitted_prerequisite_operation_id=self.omitted_prerequisite_operation_id,
            baseline_operation_ids=self.baseline_operation_ids,
            omission_operation_ids=self.omission_operation_ids,
            plan_id=self.plan_id,
            recipe_id=self.recipe_id,
            omitted_binding_id=self.omitted_binding_id,
            capability_key=self.capability_key,
            consumer_locator_pointer=self.consumer_locator_pointer,
            baseline_source_ref=self.baseline_source_ref,
            oracle=self.oracle,
            execution_blockers=self.execution_blockers,
        )
        if (
            self.experiment_id != stable_hash("omission_experiment", payload)
            or not _hash_ref(
                self.state_machine_candidate_id,
                "state_machine_legality_candidate",
            )
            or not _hash_ref(self.subject_ref, "security_subject")
            or not _hash_ref(self.lifecycle_id, "owned_lifecycle")
            or not _hash_ref(self.world_ref, "world")
            or not _hash_ref(self.terminal_operation_id, "action")
            or not self.prerequisite_operation_ids
            or len(set(self.prerequisite_operation_ids))
            != len(self.prerequisite_operation_ids)
            or any(
                not _hash_ref(item, "action")
                for item in self.prerequisite_operation_ids
            )
            or self.omitted_prerequisite_operation_id
            not in self.prerequisite_operation_ids
            or self.baseline_operation_ids
            != (*self.prerequisite_operation_ids, self.terminal_operation_id)
            or self.omission_operation_ids
            != tuple(
                item
                for item in self.baseline_operation_ids
                if item != self.omitted_prerequisite_operation_id
            )
            or len(self.baseline_operation_ids) != len(self.omission_operation_ids) + 1
            or self.terminal_operation_id not in self.omission_operation_ids
            or not _hash_ref(self.plan_id, "backward_plan")
            or not _hash_ref(self.recipe_id, "rehydration_recipe")
            or not _hash_ref(self.omitted_binding_id, "lineage_binding")
            or _CAPABILITY.fullmatch(self.capability_key) is None
            or self.mutation_kind != _MUTATION_KIND
            or self.consumer_locator_kind != LocatorKind.REQUEST_QUERY.value
            or _decode_query_pointer(self.consumer_locator_pointer) is None
            or not _hash_ref(self.baseline_source_ref, "source_ref")
            or not isinstance(self.oracle, OmissionComparisonOracle)
            or tuple(sorted(set(self.execution_blockers))) != self.execution_blockers
            or not _REQUIRED_BLOCKERS <= set(self.execution_blockers)
            or any(
                _SEMANTIC.fullmatch(item) is None for item in self.execution_blockers
            )
            or self.mode != MINIMIZED_OMISSION_MODE
            or self.finding_authority
            or self.executable
        ):
            raise ValueError("minimized omission experiment contract is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "experiment_id": self.experiment_id,
            "state_machine_candidate_id": self.state_machine_candidate_id,
            "subject_ref": self.subject_ref,
            "lifecycle_id": self.lifecycle_id,
            "world_ref": self.world_ref,
            "terminal_operation_id": self.terminal_operation_id,
            "prerequisite_operation_ids": list(self.prerequisite_operation_ids),
            "omitted_prerequisite_operation_id": (
                self.omitted_prerequisite_operation_id
            ),
            "baseline_operation_ids": list(self.baseline_operation_ids),
            "omission_operation_ids": list(self.omission_operation_ids),
            "plan_id": self.plan_id,
            "recipe_id": self.recipe_id,
            "omitted_binding_id": self.omitted_binding_id,
            "capability_key": self.capability_key,
            "mutation_kind": self.mutation_kind,
            "consumer_locator_kind": self.consumer_locator_kind,
            "consumer_locator_pointer": self.consumer_locator_pointer,
            "baseline_source_ref": self.baseline_source_ref,
            "oracle": self.oracle.to_dict(),
            "execution_blockers": list(self.execution_blockers),
            "mode": self.mode,
            "finding_authority": self.finding_authority,
            "executable": self.executable,
        }


@dataclass(frozen=True)
class OmissionCompilationDiagnostics:
    state_candidates: int
    candidates_examined: int
    experiments_compiled: int
    no_owned_lifecycle: int
    reconstruction_mismatches: int
    invalid_baselines: int
    no_eligible_omission: int
    ambiguous_omissions: int
    duplicate_experiments: int
    dropped_experiments: int

    def __post_init__(self) -> None:
        if any(
            isinstance(value, bool) or not isinstance(value, int) or value < 0
            for value in vars(self).values()
        ):
            raise ValueError(
                "omission compilation diagnostics must be non-negative integers"
            )
        if self.candidates_examined != self.state_candidates:
            raise ValueError("all state candidates must be examined")
        if self.experiments_compiled + self.dropped_experiments > self.state_candidates:
            raise ValueError("omission experiment accounting exceeds candidates")

    @property
    def incomplete_work(self) -> int:
        return self.reconstruction_mismatches + self.dropped_experiments

    def to_dict(self) -> Dict[str, int]:
        return dict(vars(self))


def _result_payload(
    *,
    status: str,
    state_machine_result_id: str,
    lifecycle_capture_digest: str,
    catalog_digest: str,
    experiments: Sequence[MinimizedOmissionExperiment],
    diagnostics: OmissionCompilationDiagnostics,
    blocker: Optional[str],
) -> Dict[str, Any]:
    return {
        "mode": MINIMIZED_OMISSION_MODE,
        "status": status,
        "state_machine_result_id": state_machine_result_id,
        "lifecycle_capture_digest": lifecycle_capture_digest,
        "catalog_digest": catalog_digest,
        "experiments": [item.to_dict() for item in experiments],
        "diagnostics": diagnostics.to_dict(),
        "blocker": blocker,
    }


@dataclass(frozen=True)
class OmissionCompilationResult:
    result_id: str
    status: str
    state_machine_result_id: str
    lifecycle_capture_digest: str
    catalog_digest: str
    experiments: Tuple[MinimizedOmissionExperiment, ...]
    diagnostics: OmissionCompilationDiagnostics
    blocker: Optional[str] = None
    mode: str = MINIMIZED_OMISSION_MODE
    finding_authority: bool = False
    executable: bool = False

    def __post_init__(self) -> None:
        payload = _result_payload(
            status=self.status,
            state_machine_result_id=self.state_machine_result_id,
            lifecycle_capture_digest=self.lifecycle_capture_digest,
            catalog_digest=self.catalog_digest,
            experiments=self.experiments,
            diagnostics=self.diagnostics,
            blocker=self.blocker,
        )
        expected_status = (
            "blocked"
            if self.blocker is not None
            else ("ready" if self.experiments else "no_experiments")
        )
        ids = [item.experiment_id for item in self.experiments]
        subjects = [item.subject_ref for item in self.experiments]
        if (
            self.result_id != stable_hash("omission_compilation_result", payload)
            or self.status != expected_status
            or not _hash_ref(
                self.state_machine_result_id,
                "state_machine_legality_result",
            )
            or not _hash_ref(self.lifecycle_capture_digest, "capture_set")
            or not _hash_ref(self.catalog_digest, "operation_catalog")
            or ids != sorted(set(ids))
            or len(subjects) != len(set(subjects))
            or len(self.experiments) > MAX_OMISSION_EXPERIMENTS
            or self.diagnostics.experiments_compiled != len(self.experiments)
            or (self.blocker is not None and _SEMANTIC.fullmatch(self.blocker) is None)
            or self.mode != MINIMIZED_OMISSION_MODE
            or self.finding_authority
            or self.executable
        ):
            raise ValueError("omission compilation result contract is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": 1,
            "result_id": self.result_id,
            **_result_payload(
                status=self.status,
                state_machine_result_id=self.state_machine_result_id,
                lifecycle_capture_digest=self.lifecycle_capture_digest,
                catalog_digest=self.catalog_digest,
                experiments=self.experiments,
                diagnostics=self.diagnostics,
                blocker=self.blocker,
            ),
            "finding_authority": self.finding_authority,
            "executable": self.executable,
        }


class MinimizedOmissionCompiler:
    """Compile exactly one query-capability omission per accepted relation."""

    @staticmethod
    def _oracle(
        record: Mapping[str, Any],
        *,
        source_id: str,
        world_id: str,
    ) -> Optional[OmissionComparisonOracle]:
        try:
            exchange = normalize_exchange(
                record,
                source_id=source_id,
                world_id=world_id,
            )
        except (TypeError, ValueError):
            return None
        if (
            exchange.method != "GET"
            or not 200 <= exchange.response_status < 300
            or exchange.response_truncated
            or exchange.response_body_hash is None
        ):
            return None
        payload = {
            "reference_state_id": exchange.state_id,
            "reference_response_status": exchange.response_status,
            "reference_response_body_hash": exchange.response_body_hash,
            "baseline_requirement": _BASELINE_REQUIREMENT,
            "comparison_kind": _COMPARISON_KIND,
            "require_success": True,
            "require_non_truncated": True,
            "finding_authority": False,
            "executable": False,
        }
        return OmissionComparisonOracle(
            oracle_id=stable_hash("omission_comparison_oracle", payload),
            reference_state_id=exchange.state_id,
            reference_response_status=exchange.response_status,
            reference_response_body_hash=exchange.response_body_hash,
        )

    @staticmethod
    def _owned_lifecycle(
        candidate: StateMachineLegalityCandidate,
        lifecycle: LifecycleMiningResult,
    ) -> Optional[OwnedLifecycleCandidate]:
        matches = [
            item
            for item in lifecycle.candidates
            if item.world_ref == candidate.world_ref
            and candidate.terminal_operation_id in item.read_operation_ids
            and item.create_operation_id in candidate.prerequisite_operation_ids
        ]
        return matches[0] if len(matches) == 1 else None

    @staticmethod
    def _query_is_unique(record: Mapping[str, Any], binding: LineageBinding) -> bool:
        key = _decode_query_pointer(binding.consumer_locator.pointer)
        if key is None:
            return False
        pairs = parse_qsl(
            urlsplit(str(record.get("url") or "/")).query,
            keep_blank_values=True,
        )
        return sum(pair_key == key for pair_key, _ in pairs) == 1

    def compile(
        self,
        records: Sequence[Mapping[str, Any]],
        *,
        world_id: str,
        lifecycle: LifecycleMiningResult,
        state_machine: StateMachineLegalityResult,
    ) -> OmissionCompilationResult:
        if isinstance(records, (str, bytes)) or any(
            not isinstance(item, Mapping) for item in records
        ):
            raise TypeError("omission records must be a sequence of mappings")
        if not isinstance(world_id, str) or not world_id:
            raise ValueError("world_id must be non-empty")
        if not isinstance(lifecycle, LifecycleMiningResult):
            raise TypeError("lifecycle must be a LifecycleMiningResult")
        if not isinstance(state_machine, StateMachineLegalityResult):
            raise TypeError("state_machine must be a StateMachineLegalityResult")

        record_values = tuple(records)
        if state_machine.status == "blocked":
            diagnostics = OmissionCompilationDiagnostics(
                state_candidates=0,
                candidates_examined=0,
                experiments_compiled=0,
                no_owned_lifecycle=0,
                reconstruction_mismatches=0,
                invalid_baselines=0,
                no_eligible_omission=0,
                ambiguous_omissions=0,
                duplicate_experiments=0,
                dropped_experiments=0,
            )
            payload = _result_payload(
                status="blocked",
                state_machine_result_id=state_machine.result_id,
                lifecycle_capture_digest=lifecycle.capture_digest,
                catalog_digest=state_machine.catalog_digest,
                experiments=(),
                diagnostics=diagnostics,
                blocker="state_machine_analysis_blocked",
            )
            return OmissionCompilationResult(
                result_id=stable_hash("omission_compilation_result", payload),
                status="blocked",
                state_machine_result_id=state_machine.result_id,
                lifecycle_capture_digest=lifecycle.capture_digest,
                catalog_digest=state_machine.catalog_digest,
                experiments=(),
                diagnostics=diagnostics,
                blocker="state_machine_analysis_blocked",
            )

        ledger = ValueLineageLedger(
            record_values,
            world_id=world_id,
            catalog_limits=OperationCatalogLimits(
                max_records=MAX_STATE_MACHINE_RECORDS,
            ),
        )
        compiler = BackwardExploitCompiler(
            ledger.operations,
            limits=CompilerLimits(
                max_search_states=MAX_STATE_MACHINE_SEARCH_STATES,
                max_plan_steps=MAX_STATE_MACHINE_PLAN_STEPS,
            ),
        )
        goals = {
            item.terminal_operation_id: item
            for item in high_value_goals(ledger.operations)
        }
        operations = {item.operation_id: item for item in ledger.operations}
        observations = {item.source_ref: item for item in ledger.observations}
        records_by_source: Dict[str, Tuple[Mapping[str, Any], str]] = {}
        raw_world_ids: Dict[str, set[str]] = {}
        for index, record in enumerate(record_values):
            raw_world = str(record.get("persona_id") or world_id)
            try:
                exchange = normalize_exchange(
                    record,
                    source_id=str(record.get("id") or index),
                    world_id=raw_world,
                )
            except (TypeError, ValueError):
                continue
            records_by_source[exchange.source_id] = (
                record,
                str(record.get("id") or index),
            )
            raw_world_ids.setdefault(exchange.world_id, set()).add(raw_world)

        experiments: Dict[str, MinimizedOmissionExperiment] = {}
        no_owned_lifecycle = 0
        reconstruction_mismatches = 0
        invalid_baselines = 0
        no_eligible_omission = 0
        ambiguous_omissions = 0
        duplicate_experiments = 0
        dropped_experiments = 0
        rehydrator = PlanRehydrator(ledger)

        blocker = None
        for candidate in state_machine.candidates:
            owned = self._owned_lifecycle(candidate, lifecycle)
            if owned is None:
                no_owned_lifecycle += 1
                continue
            goal = goals.get(candidate.terminal_operation_id)
            raw_worlds = raw_world_ids.get(candidate.world_ref, set())
            if goal is None or len(raw_worlds) != 1:
                reconstruction_mismatches += 1
                continue
            plan = compiler.compile(goal)
            if (
                plan.status != "planned"
                or plan.plan_id != candidate.plan_id
                or plan.catalog_digest != candidate.catalog_digest
                or plan.step_ids[:-1] != candidate.prerequisite_operation_ids
            ):
                reconstruction_mismatches += 1
                continue
            raw_world = next(iter(raw_worlds))
            recipe = rehydrator.build_recipe(plan, world_id=raw_world)
            binding_ids = tuple(sorted(item.binding_id for item in recipe.bindings))
            if (
                recipe.status != "ready"
                or recipe.recipe_id != candidate.recipe_id
                or tuple(item.source_ref for item in recipe.steps)
                != candidate.source_refs
                or binding_ids != candidate.lineage_binding_ids
            ):
                reconstruction_mismatches += 1
                continue
            baseline_source_ref = candidate.source_refs[-1]
            baseline_entry = records_by_source.get(baseline_source_ref)
            terminal_observation = observations.get(baseline_source_ref)
            terminal_operation = operations.get(candidate.terminal_operation_id)
            if (
                baseline_entry is None
                or terminal_observation is None
                or terminal_observation.operation_id != candidate.terminal_operation_id
                or terminal_operation is None
                or terminal_operation.safety != OperationSafety.READ_ONLY
                or candidate.risk_class != "read"
            ):
                invalid_baselines += 1
                continue
            baseline_record, baseline_source_id = baseline_entry
            oracle = self._oracle(
                baseline_record,
                source_id=baseline_source_id,
                world_id=raw_world,
            )
            if oracle is None:
                invalid_baselines += 1
                continue
            omission_choices = [
                binding
                for binding in recipe.bindings
                if binding.consumer_operation_id == candidate.terminal_operation_id
                and binding.producer_operation_id
                in candidate.prerequisite_operation_ids
                and binding.producer_operation_id != owned.create_operation_id
                and binding.consumer_source_ref == baseline_source_ref
                and binding.consumer_locator.kind == LocatorKind.REQUEST_QUERY
                and binding.sensitive
                and self._query_is_unique(baseline_record, binding)
            ]
            if not omission_choices:
                no_eligible_omission += 1
                continue
            if len(omission_choices) != 1:
                ambiguous_omissions += 1
                continue
            binding = omission_choices[0]
            if tuple(
                related.binding_id
                for related in recipe.bindings
                if related.producer_operation_id == binding.producer_operation_id
            ) != (binding.binding_id,):
                no_eligible_omission += 1
                continue
            blockers = set(_REQUIRED_BLOCKERS)
            prerequisite_operations = [
                operations[item]
                for item in candidate.prerequisite_operation_ids
                if item in operations and item != owned.create_operation_id
            ]
            if any(
                item.safety
                not in {
                    OperationSafety.READ_ONLY,
                    OperationSafety.OWNED_REVERSIBLE_WRITE,
                }
                for item in prerequisite_operations
            ):
                blockers.add("prerequisite_execution_safety_unproven")
            ordered_blockers = tuple(sorted(blockers))
            identity = _experiment_identity_payload(
                state_machine_candidate_id=candidate.candidate_id,
                subject_ref=state_machine_subject_ref(candidate),
                lifecycle_id=owned.lifecycle_id,
                world_ref=candidate.world_ref,
                terminal_operation_id=candidate.terminal_operation_id,
                prerequisite_operation_ids=candidate.prerequisite_operation_ids,
                omitted_prerequisite_operation_id=binding.producer_operation_id,
                baseline_operation_ids=plan.step_ids,
                omission_operation_ids=tuple(
                    item
                    for item in plan.step_ids
                    if item != binding.producer_operation_id
                ),
                plan_id=candidate.plan_id,
                recipe_id=candidate.recipe_id,
                omitted_binding_id=binding.binding_id,
                capability_key=binding.capability.key,
                consumer_locator_pointer=binding.consumer_locator.pointer,
                baseline_source_ref=baseline_source_ref,
                oracle=oracle,
                execution_blockers=ordered_blockers,
            )
            experiment = MinimizedOmissionExperiment(
                experiment_id=stable_hash("omission_experiment", identity),
                state_machine_candidate_id=candidate.candidate_id,
                subject_ref=state_machine_subject_ref(candidate),
                lifecycle_id=owned.lifecycle_id,
                world_ref=candidate.world_ref,
                terminal_operation_id=candidate.terminal_operation_id,
                prerequisite_operation_ids=candidate.prerequisite_operation_ids,
                omitted_prerequisite_operation_id=binding.producer_operation_id,
                baseline_operation_ids=plan.step_ids,
                omission_operation_ids=tuple(
                    item
                    for item in plan.step_ids
                    if item != binding.producer_operation_id
                ),
                plan_id=candidate.plan_id,
                recipe_id=candidate.recipe_id,
                omitted_binding_id=binding.binding_id,
                capability_key=binding.capability.key,
                consumer_locator_pointer=binding.consumer_locator.pointer,
                baseline_source_ref=baseline_source_ref,
                oracle=oracle,
                execution_blockers=ordered_blockers,
            )
            if experiment.experiment_id in experiments:
                duplicate_experiments += 1
                continue
            if len(experiments) >= MAX_OMISSION_EXPERIMENTS:
                dropped_experiments += 1
                continue
            experiments[experiment.experiment_id] = experiment

        ordered = tuple(experiments[key] for key in sorted(experiments))
        diagnostics = OmissionCompilationDiagnostics(
            state_candidates=len(state_machine.candidates),
            candidates_examined=len(state_machine.candidates),
            experiments_compiled=len(ordered),
            no_owned_lifecycle=no_owned_lifecycle,
            reconstruction_mismatches=reconstruction_mismatches,
            invalid_baselines=invalid_baselines,
            no_eligible_omission=no_eligible_omission,
            ambiguous_omissions=ambiguous_omissions,
            duplicate_experiments=duplicate_experiments,
            dropped_experiments=dropped_experiments,
        )
        status = (
            "blocked"
            if blocker is not None
            else ("ready" if ordered else "no_experiments")
        )
        payload = _result_payload(
            status=status,
            state_machine_result_id=state_machine.result_id,
            lifecycle_capture_digest=lifecycle.capture_digest,
            catalog_digest=compiler.catalog_digest,
            experiments=ordered,
            diagnostics=diagnostics,
            blocker=blocker,
        )
        return OmissionCompilationResult(
            result_id=stable_hash("omission_compilation_result", payload),
            status=status,
            state_machine_result_id=state_machine.result_id,
            lifecycle_capture_digest=lifecycle.capture_digest,
            catalog_digest=compiler.catalog_digest,
            experiments=ordered,
            diagnostics=diagnostics,
            blocker=blocker,
        )


__all__ = [
    "MAX_OMISSION_EXPERIMENTS",
    "MINIMIZED_OMISSION_MODE",
    "MinimizedOmissionCompiler",
    "MinimizedOmissionExperiment",
    "OmissionComparisonOracle",
    "OmissionCompilationDiagnostics",
    "OmissionCompilationResult",
]
