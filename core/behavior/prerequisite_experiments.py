"""Passive R5B graph-bound prerequisite experiment specifications.

This compiler turns an exact observed prerequisite DAG into a sealed description
of one counterfactual delta.  It does not mutate a request, provision fresh
state, reserve budget, admit execution, contact a target, or claim a finding.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple

from .compiler import (
    BackwardExploitCompiler,
    CompilerLimits,
    OperationCatalogLimits,
    OperationSafety,
    high_value_goals,
)
from .lifecycle import LifecycleMiningResult, OwnedLifecycleCandidate
from .lineage import LocatorKind, PlanRehydrator, ValueLineageLedger
from .normalize import normalize_exchange, stable_hash
from .prerequisite_graph import (
    ObservedPrerequisiteGraph,
    ObservedPrerequisiteRelation,
)
from .state_machine import (
    MAX_STATE_MACHINE_PLAN_STEPS,
    MAX_STATE_MACHINE_RECORDS,
    MAX_STATE_MACHINE_SEARCH_STATES,
    StateMachineLegalityCandidate,
    StateMachineLegalityResult,
)

GRAPH_BOUND_PREREQUISITE_EXPERIMENT_MODE = (
    "behavioral_graph_bound_prerequisite_experiment_v1"
)
MAX_GRAPH_BOUND_EXPERIMENT_SPECS = 64

_HASH_REF = re.compile(r"^[a-z][a-z0-9_]*:[0-9a-f]{64}$")
_SEMANTIC = re.compile(r"^[a-z][a-z0-9_.:-]{0,127}$")
_CAPABILITY = re.compile(
    r"^[a-z][a-z0-9_.-]{0,63}:[a-z][a-z0-9_.:-]{0,127}$"
)
_BODY_HASH = re.compile(r"^sha256:[0-9a-f]{64}$")
_GRAPH_SHAPES = ("branching", "branching_joining", "joining", "linear")
_SUPPORTED_LOCATORS = frozenset(
    {LocatorKind.REQUEST_FORM, LocatorKind.REQUEST_JSON, LocatorKind.REQUEST_QUERY}
)
_INSTANCE_ROLES = (
    "counterfactual_treatment",
    "independent_control",
    "valid_baseline",
)
_REQUIRED_BLOCKERS = frozenset(
    {
        "analysis_only_no_execution_authority",
        "experiment_admission_required",
        "fresh_controlled_state_required",
        "graph_bound_manifest_required",
        "independent_effect_oracle_required",
    }
)


def _hash_ref(value: Any, prefix: Optional[str] = None) -> bool:
    return (
        isinstance(value, str)
        and _HASH_REF.fullmatch(value) is not None
        and (prefix is None or value.startswith(f"{prefix}:"))
    )


class PrerequisiteCounterfactualFamily(str, Enum):
    OMISSION = "omission"
    REORDERING = "reordering"
    REPLAY = "replay"
    STALE_STATE = "stale_state"


def _support_rule_payload(
    *,
    graph_shape: str,
    family: PrerequisiteCounterfactualFamily,
    status: str,
    conditions: Sequence[str],
    blocker: Optional[str],
) -> Dict[str, Any]:
    return {
        "graph_shape": graph_shape,
        "family": family.value,
        "status": status,
        "conditions": list(conditions),
        "blocker": blocker,
        "support_level": "specification_only",
        "executable": False,
    }


@dataclass(frozen=True)
class PrerequisiteTopologySupportRule:
    rule_id: str
    graph_shape: str
    family: PrerequisiteCounterfactualFamily
    status: str
    conditions: Tuple[str, ...]
    blocker: Optional[str]
    support_level: str = "specification_only"
    executable: bool = False

    @classmethod
    def build(
        cls,
        *,
        graph_shape: str,
        family: PrerequisiteCounterfactualFamily,
        status: str,
        conditions: Sequence[str] = (),
        blocker: Optional[str] = None,
    ) -> "PrerequisiteTopologySupportRule":
        values = tuple(sorted(set(conditions)))
        payload = _support_rule_payload(
            graph_shape=graph_shape,
            family=family,
            status=status,
            conditions=values,
            blocker=blocker,
        )
        return cls(
            rule_id=stable_hash("prerequisite_topology_support_rule", payload),
            graph_shape=graph_shape,
            family=family,
            status=status,
            conditions=values,
            blocker=blocker,
        )

    def __post_init__(self) -> None:
        payload = _support_rule_payload(
            graph_shape=self.graph_shape,
            family=self.family,
            status=self.status,
            conditions=self.conditions,
            blocker=self.blocker,
        )
        if (
            self.rule_id
            != stable_hash("prerequisite_topology_support_rule", payload)
            or self.graph_shape not in _GRAPH_SHAPES
            or not isinstance(self.family, PrerequisiteCounterfactualFamily)
            or self.status not in {"supported", "deferred"}
            or self.conditions != tuple(sorted(set(self.conditions)))
            or any(_SEMANTIC.fullmatch(item) is None for item in self.conditions)
            or (self.status == "supported") != (self.blocker is None)
            or (
                self.blocker is not None
                and _SEMANTIC.fullmatch(self.blocker) is None
            )
            or self.support_level != "specification_only"
            or self.executable
        ):
            raise ValueError("prerequisite topology support rule is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            **_support_rule_payload(
                graph_shape=self.graph_shape,
                family=self.family,
                status=self.status,
                conditions=self.conditions,
                blocker=self.blocker,
            ),
        }


def prerequisite_topology_support_matrix(
) -> Tuple[PrerequisiteTopologySupportRule, ...]:
    """Return the immutable R5B2 specification support matrix."""

    supported = {
        ("linear", PrerequisiteCounterfactualFamily.OMISSION): (
            "direct_terminal_relation",
            "isolated_producer_output",
            "removable_consumer_locator",
        ),
        ("joining", PrerequisiteCounterfactualFamily.OMISSION): (
            "direct_terminal_relation",
            "isolated_producer_output",
            "removable_consumer_locator",
        ),
        ("branching_joining", PrerequisiteCounterfactualFamily.OMISSION): (
            "direct_terminal_relation",
            "isolated_producer_output",
            "removable_consumer_locator",
        ),
        ("joining", PrerequisiteCounterfactualFamily.REORDERING): (
            "adjacent_operations",
            "common_downstream_consumer",
            "no_dependency_path",
        ),
        ("branching_joining", PrerequisiteCounterfactualFamily.REORDERING): (
            "adjacent_operations",
            "common_downstream_consumer",
            "no_dependency_path",
        ),
    }
    rules = []
    for graph_shape in _GRAPH_SHAPES:
        for family in PrerequisiteCounterfactualFamily:
            conditions = supported.get((graph_shape, family))
            if conditions is not None:
                rules.append(
                    PrerequisiteTopologySupportRule.build(
                        graph_shape=graph_shape,
                        family=family,
                        status="supported",
                        conditions=(
                            *conditions,
                            "fresh_three_instance_control",
                            "owned_lifecycle_cleanup",
                        ),
                    )
                )
                continue
            if family is PrerequisiteCounterfactualFamily.REPLAY:
                blocker = "reserved_for_capability_freshness_oracle"
            elif family is PrerequisiteCounterfactualFamily.STALE_STATE:
                blocker = "post_cleanup_effect_oracle_not_defined"
            elif graph_shape == "branching":
                blocker = "branch_only_delta_not_supported"
            else:
                blocker = "topology_family_not_supported"
            rules.append(
                PrerequisiteTopologySupportRule.build(
                    graph_shape=graph_shape,
                    family=family,
                    status="deferred",
                    blocker=blocker,
                )
            )
    return tuple(sorted(rules, key=lambda item: item.rule_id))


def _fresh_state_payload(
    *,
    world_ref: str,
    lifecycle_ids: Sequence[str],
    baseline_source_ref: str,
    reference_state_id: str,
    reference_response_status: int,
    reference_response_body_hash: str,
) -> Dict[str, Any]:
    return {
        "world_ref": world_ref,
        "lifecycle_ids": list(lifecycle_ids),
        "baseline_source_ref": baseline_source_ref,
        "reference_state_id": reference_state_id,
        "reference_response_status": reference_response_status,
        "reference_response_body_hash": reference_response_body_hash,
        "instance_roles": list(_INSTANCE_ROLES),
        "fresh_instance_count": len(_INSTANCE_ROLES),
        "distinct_owned_instances_required": True,
        "recreate_full_prerequisite_graph": True,
        "reference_state_match_required": True,
        "non_truncated_required": True,
        "executable": False,
    }


@dataclass(frozen=True)
class FreshControlledStateRequirement:
    requirement_id: str
    world_ref: str
    lifecycle_ids: Tuple[str, ...]
    baseline_source_ref: str
    reference_state_id: str
    reference_response_status: int
    reference_response_body_hash: str
    instance_roles: Tuple[str, ...] = _INSTANCE_ROLES
    fresh_instance_count: int = len(_INSTANCE_ROLES)
    distinct_owned_instances_required: bool = True
    recreate_full_prerequisite_graph: bool = True
    reference_state_match_required: bool = True
    non_truncated_required: bool = True
    executable: bool = False

    @classmethod
    def build(
        cls,
        *,
        world_ref: str,
        lifecycle_ids: Sequence[str],
        baseline_source_ref: str,
        reference_state_id: str,
        reference_response_status: int,
        reference_response_body_hash: str,
    ) -> "FreshControlledStateRequirement":
        lifecycles = tuple(sorted(set(lifecycle_ids)))
        payload = _fresh_state_payload(
            world_ref=world_ref,
            lifecycle_ids=lifecycles,
            baseline_source_ref=baseline_source_ref,
            reference_state_id=reference_state_id,
            reference_response_status=reference_response_status,
            reference_response_body_hash=reference_response_body_hash,
        )
        return cls(
            requirement_id=stable_hash("fresh_controlled_state_requirement", payload),
            world_ref=world_ref,
            lifecycle_ids=lifecycles,
            baseline_source_ref=baseline_source_ref,
            reference_state_id=reference_state_id,
            reference_response_status=reference_response_status,
            reference_response_body_hash=reference_response_body_hash,
        )

    def __post_init__(self) -> None:
        payload = _fresh_state_payload(
            world_ref=self.world_ref,
            lifecycle_ids=self.lifecycle_ids,
            baseline_source_ref=self.baseline_source_ref,
            reference_state_id=self.reference_state_id,
            reference_response_status=self.reference_response_status,
            reference_response_body_hash=self.reference_response_body_hash,
        )
        if (
            self.requirement_id
            != stable_hash("fresh_controlled_state_requirement", payload)
            or not _hash_ref(self.world_ref, "world")
            or not self.lifecycle_ids
            or self.lifecycle_ids != tuple(sorted(set(self.lifecycle_ids)))
            or any(
                not _hash_ref(item, "owned_lifecycle")
                for item in self.lifecycle_ids
            )
            or not _hash_ref(self.baseline_source_ref, "source_ref")
            or not _hash_ref(self.reference_state_id, "state")
            or isinstance(self.reference_response_status, bool)
            or not isinstance(self.reference_response_status, int)
            or not 200 <= self.reference_response_status < 300
            or _BODY_HASH.fullmatch(self.reference_response_body_hash) is None
            or self.instance_roles != _INSTANCE_ROLES
            or self.fresh_instance_count != len(_INSTANCE_ROLES)
            or not self.distinct_owned_instances_required
            or not self.recreate_full_prerequisite_graph
            or not self.reference_state_match_required
            or not self.non_truncated_required
            or self.executable
        ):
            raise ValueError("fresh controlled state requirement is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "requirement_id": self.requirement_id,
            **_fresh_state_payload(
                world_ref=self.world_ref,
                lifecycle_ids=self.lifecycle_ids,
                baseline_source_ref=self.baseline_source_ref,
                reference_state_id=self.reference_state_id,
                reference_response_status=self.reference_response_status,
                reference_response_body_hash=self.reference_response_body_hash,
            ),
        }


def _cleanup_binding_payload(
    *,
    lifecycle_id: str,
    create_operation_id: str,
    cleanup_operation_id: str,
    cleanup_binding_id: str,
) -> Dict[str, str]:
    return {
        "lifecycle_id": lifecycle_id,
        "create_operation_id": create_operation_id,
        "cleanup_operation_id": cleanup_operation_id,
        "cleanup_binding_id": cleanup_binding_id,
    }


@dataclass(frozen=True)
class ControlledLifecycleCleanupBinding:
    binding_id: str
    lifecycle_id: str
    create_operation_id: str
    cleanup_operation_id: str
    cleanup_binding_id: str

    @classmethod
    def from_lifecycle(
        cls,
        lifecycle: OwnedLifecycleCandidate,
    ) -> "ControlledLifecycleCleanupBinding":
        if not isinstance(lifecycle, OwnedLifecycleCandidate):
            raise TypeError("lifecycle must be an OwnedLifecycleCandidate")
        payload = _cleanup_binding_payload(
            lifecycle_id=lifecycle.lifecycle_id,
            create_operation_id=lifecycle.create_operation_id,
            cleanup_operation_id=lifecycle.cleanup_operation_id,
            cleanup_binding_id=lifecycle.cleanup_binding_id,
        )
        return cls(
            binding_id=stable_hash("controlled_lifecycle_cleanup_binding", payload),
            lifecycle_id=lifecycle.lifecycle_id,
            create_operation_id=lifecycle.create_operation_id,
            cleanup_operation_id=lifecycle.cleanup_operation_id,
            cleanup_binding_id=lifecycle.cleanup_binding_id,
        )

    def __post_init__(self) -> None:
        payload = _cleanup_binding_payload(
            lifecycle_id=self.lifecycle_id,
            create_operation_id=self.create_operation_id,
            cleanup_operation_id=self.cleanup_operation_id,
            cleanup_binding_id=self.cleanup_binding_id,
        )
        if (
            self.binding_id
            != stable_hash("controlled_lifecycle_cleanup_binding", payload)
            or not _hash_ref(self.lifecycle_id, "owned_lifecycle")
            or not _hash_ref(self.create_operation_id, "action")
            or not _hash_ref(self.cleanup_operation_id, "action")
            or not _hash_ref(self.cleanup_binding_id, "lineage_binding")
            or self.create_operation_id == self.cleanup_operation_id
        ):
            raise ValueError("controlled lifecycle cleanup binding is invalid")

    def to_dict(self) -> Dict[str, str]:
        return {
            "binding_id": self.binding_id,
            **_cleanup_binding_payload(
                lifecycle_id=self.lifecycle_id,
                create_operation_id=self.create_operation_id,
                cleanup_operation_id=self.cleanup_operation_id,
                cleanup_binding_id=self.cleanup_binding_id,
            ),
        }


def _cleanup_requirement_payload(
    bindings: Sequence[ControlledLifecycleCleanupBinding],
) -> Dict[str, Any]:
    return {
        "bindings": [item.to_dict() for item in bindings],
        "instances_per_lifecycle": len(_INSTANCE_ROLES),
        "cleanup_each_fresh_instance": True,
        "independent_verification_required": True,
        "stop_on_uncertain_cleanup": True,
        "required": True,
        "executable": False,
    }


@dataclass(frozen=True)
class GraphCleanupRequirement:
    cleanup_id: str
    bindings: Tuple[ControlledLifecycleCleanupBinding, ...]
    instances_per_lifecycle: int = len(_INSTANCE_ROLES)
    cleanup_each_fresh_instance: bool = True
    independent_verification_required: bool = True
    stop_on_uncertain_cleanup: bool = True
    required: bool = True
    executable: bool = False

    @classmethod
    def build(
        cls,
        lifecycles: Sequence[OwnedLifecycleCandidate],
    ) -> "GraphCleanupRequirement":
        values = tuple(
            sorted(
                (
                    ControlledLifecycleCleanupBinding.from_lifecycle(item)
                    for item in lifecycles
                ),
                key=lambda item: item.binding_id,
            )
        )
        payload = _cleanup_requirement_payload(values)
        return cls(
            cleanup_id=stable_hash("graph_cleanup_requirement", payload),
            bindings=values,
        )

    def __post_init__(self) -> None:
        payload = _cleanup_requirement_payload(self.bindings)
        if (
            self.cleanup_id != stable_hash("graph_cleanup_requirement", payload)
            or not self.bindings
            or self.bindings
            != tuple(sorted(self.bindings, key=lambda item: item.binding_id))
            or len({item.lifecycle_id for item in self.bindings})
            != len(self.bindings)
            or self.instances_per_lifecycle != len(_INSTANCE_ROLES)
            or not self.cleanup_each_fresh_instance
            or not self.independent_verification_required
            or not self.stop_on_uncertain_cleanup
            or not self.required
            or self.executable
        ):
            raise ValueError("graph cleanup requirement is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cleanup_id": self.cleanup_id,
            **_cleanup_requirement_payload(self.bindings),
        }


def _oracle_payload(
    *,
    family: PrerequisiteCounterfactualFamily,
    reference_state_id: str,
) -> Dict[str, Any]:
    return {
        "family": family.value,
        "security_property": "prerequisite_enforcement",
        "reference_state_id": reference_state_id,
        "comparison_kind": "fresh_controlled_terminal_effect",
        "valid_baseline_required": True,
        "independent_control_required": True,
        "independent_effect_witness_required": True,
        "single_counterfactual_delta_required": True,
        "response_difference_sufficient": False,
        "adversarial_triage_required": True,
        "finding_authority": False,
        "executable": False,
    }


@dataclass(frozen=True)
class PrerequisiteEffectOracleRequirement:
    oracle_id: str
    family: PrerequisiteCounterfactualFamily
    reference_state_id: str
    security_property: str = "prerequisite_enforcement"
    comparison_kind: str = "fresh_controlled_terminal_effect"
    valid_baseline_required: bool = True
    independent_control_required: bool = True
    independent_effect_witness_required: bool = True
    single_counterfactual_delta_required: bool = True
    response_difference_sufficient: bool = False
    adversarial_triage_required: bool = True
    finding_authority: bool = False
    executable: bool = False

    @classmethod
    def build(
        cls,
        *,
        family: PrerequisiteCounterfactualFamily,
        reference_state_id: str,
    ) -> "PrerequisiteEffectOracleRequirement":
        payload = _oracle_payload(
            family=family,
            reference_state_id=reference_state_id,
        )
        return cls(
            oracle_id=stable_hash("prerequisite_effect_oracle_requirement", payload),
            family=family,
            reference_state_id=reference_state_id,
        )

    def __post_init__(self) -> None:
        payload = _oracle_payload(
            family=self.family,
            reference_state_id=self.reference_state_id,
        )
        if (
            self.oracle_id
            != stable_hash("prerequisite_effect_oracle_requirement", payload)
            or self.family
            not in {
                PrerequisiteCounterfactualFamily.OMISSION,
                PrerequisiteCounterfactualFamily.REORDERING,
            }
            or not _hash_ref(self.reference_state_id, "state")
            or self.security_property != "prerequisite_enforcement"
            or self.comparison_kind != "fresh_controlled_terminal_effect"
            or not self.valid_baseline_required
            or not self.independent_control_required
            or not self.independent_effect_witness_required
            or not self.single_counterfactual_delta_required
            or self.response_difference_sufficient
            or not self.adversarial_triage_required
            or self.finding_authority
            or self.executable
        ):
            raise ValueError("prerequisite effect oracle requirement is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "oracle_id": self.oracle_id,
            **_oracle_payload(
                family=self.family,
                reference_state_id=self.reference_state_id,
            ),
        }


def _delta_payload(
    *,
    family: PrerequisiteCounterfactualFamily,
    mutation_kind: str,
    baseline_operation_ids: Sequence[str],
    treatment_operation_ids: Sequence[str],
    target_operation_ids: Sequence[str],
    target_relation_ids: Sequence[str],
    target_binding_ids: Sequence[str],
    capability_key: Optional[str],
    consumer_locator_kind: Optional[str],
    consumer_locator_pointer: Optional[str],
) -> Dict[str, Any]:
    return {
        "family": family.value,
        "mutation_kind": mutation_kind,
        "baseline_operation_ids": list(baseline_operation_ids),
        "treatment_operation_ids": list(treatment_operation_ids),
        "target_operation_ids": list(target_operation_ids),
        "target_relation_ids": list(target_relation_ids),
        "target_binding_ids": list(target_binding_ids),
        "capability_key": capability_key,
        "consumer_locator_kind": consumer_locator_kind,
        "consumer_locator_pointer": consumer_locator_pointer,
        "delta_count": 1,
        "executable": False,
    }


@dataclass(frozen=True)
class GraphCounterfactualDelta:
    delta_id: str
    family: PrerequisiteCounterfactualFamily
    mutation_kind: str
    baseline_operation_ids: Tuple[str, ...]
    treatment_operation_ids: Tuple[str, ...]
    target_operation_ids: Tuple[str, ...]
    target_relation_ids: Tuple[str, ...]
    target_binding_ids: Tuple[str, ...]
    capability_key: Optional[str]
    consumer_locator_kind: Optional[str]
    consumer_locator_pointer: Optional[str]
    delta_count: int = 1
    executable: bool = False

    @classmethod
    def build(
        cls,
        *,
        family: PrerequisiteCounterfactualFamily,
        mutation_kind: str,
        baseline_operation_ids: Sequence[str],
        treatment_operation_ids: Sequence[str],
        target_operation_ids: Sequence[str],
        target_relation_ids: Sequence[str],
        target_binding_ids: Sequence[str],
        capability_key: Optional[str] = None,
        consumer_locator_kind: Optional[str] = None,
        consumer_locator_pointer: Optional[str] = None,
    ) -> "GraphCounterfactualDelta":
        baseline = tuple(baseline_operation_ids)
        treatment = tuple(treatment_operation_ids)
        operations = tuple(target_operation_ids)
        relations = tuple(sorted(set(target_relation_ids)))
        bindings = tuple(sorted(set(target_binding_ids)))
        payload = _delta_payload(
            family=family,
            mutation_kind=mutation_kind,
            baseline_operation_ids=baseline,
            treatment_operation_ids=treatment,
            target_operation_ids=operations,
            target_relation_ids=relations,
            target_binding_ids=bindings,
            capability_key=capability_key,
            consumer_locator_kind=consumer_locator_kind,
            consumer_locator_pointer=consumer_locator_pointer,
        )
        return cls(
            delta_id=stable_hash("graph_counterfactual_delta", payload),
            family=family,
            mutation_kind=mutation_kind,
            baseline_operation_ids=baseline,
            treatment_operation_ids=treatment,
            target_operation_ids=operations,
            target_relation_ids=relations,
            target_binding_ids=bindings,
            capability_key=capability_key,
            consumer_locator_kind=consumer_locator_kind,
            consumer_locator_pointer=consumer_locator_pointer,
        )

    def __post_init__(self) -> None:
        payload = _delta_payload(
            family=self.family,
            mutation_kind=self.mutation_kind,
            baseline_operation_ids=self.baseline_operation_ids,
            treatment_operation_ids=self.treatment_operation_ids,
            target_operation_ids=self.target_operation_ids,
            target_relation_ids=self.target_relation_ids,
            target_binding_ids=self.target_binding_ids,
            capability_key=self.capability_key,
            consumer_locator_kind=self.consumer_locator_kind,
            consumer_locator_pointer=self.consumer_locator_pointer,
        )
        common_invalid = (
            self.delta_id != stable_hash("graph_counterfactual_delta", payload)
            or not self.baseline_operation_ids
            or len(set(self.baseline_operation_ids))
            != len(self.baseline_operation_ids)
            or any(
                not _hash_ref(item, "action")
                for item in (
                    *self.baseline_operation_ids,
                    *self.treatment_operation_ids,
                    *self.target_operation_ids,
                )
            )
            or self.target_relation_ids
            != tuple(sorted(set(self.target_relation_ids)))
            or any(
                not _hash_ref(item, "observed_prerequisite_relation")
                for item in self.target_relation_ids
            )
            or self.target_binding_ids
            != tuple(sorted(set(self.target_binding_ids)))
            or any(
                not _hash_ref(item, "lineage_binding")
                for item in self.target_binding_ids
            )
            or self.delta_count != 1
            or self.executable
        )
        omission_invalid = False
        reordering_invalid = False
        if self.family is PrerequisiteCounterfactualFamily.OMISSION:
            omitted = self.target_operation_ids[0] if self.target_operation_ids else None
            omission_invalid = (
                self.mutation_kind != "omit_isolated_prerequisite"
                or len(self.target_operation_ids) != 1
                or len(self.target_relation_ids) != 1
                or len(self.target_binding_ids) != 1
                or len(self.baseline_operation_ids)
                != len(self.treatment_operation_ids) + 1
                or omitted not in self.baseline_operation_ids
                or omitted in self.treatment_operation_ids
                or self.treatment_operation_ids
                != tuple(
                    item for item in self.baseline_operation_ids if item != omitted
                )
                or self.capability_key is None
                or _CAPABILITY.fullmatch(self.capability_key) is None
                or self.consumer_locator_kind
                not in {item.value for item in _SUPPORTED_LOCATORS}
                or not isinstance(self.consumer_locator_pointer, str)
                or not self.consumer_locator_pointer.startswith("/")
                or len(self.consumer_locator_pointer) > 1_024
            )
        elif self.family is PrerequisiteCounterfactualFamily.REORDERING:
            if len(self.target_operation_ids) == 2:
                first, second = self.target_operation_ids
                index = self.baseline_operation_ids.index(first) if first in self.baseline_operation_ids else -2
                expected = list(self.baseline_operation_ids)
                if index >= 0 and index + 1 < len(expected) and expected[index + 1] == second:
                    expected[index], expected[index + 1] = expected[index + 1], expected[index]
                else:
                    expected = []
            else:
                expected = []
            reordering_invalid = (
                self.mutation_kind != "swap_adjacent_independent_prerequisites"
                or len(self.target_operation_ids) != 2
                or len(self.target_relation_ids) < 2
                or len(self.target_binding_ids) < 2
                or tuple(expected) != self.treatment_operation_ids
                or set(self.baseline_operation_ids)
                != set(self.treatment_operation_ids)
                or self.capability_key is not None
                or self.consumer_locator_kind is not None
                or self.consumer_locator_pointer is not None
            )
        else:
            omission_invalid = True
        if common_invalid or omission_invalid or reordering_invalid:
            raise ValueError("graph counterfactual delta is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "delta_id": self.delta_id,
            **_delta_payload(
                family=self.family,
                mutation_kind=self.mutation_kind,
                baseline_operation_ids=self.baseline_operation_ids,
                treatment_operation_ids=self.treatment_operation_ids,
                target_operation_ids=self.target_operation_ids,
                target_relation_ids=self.target_relation_ids,
                target_binding_ids=self.target_binding_ids,
                capability_key=self.capability_key,
                consumer_locator_kind=self.consumer_locator_kind,
                consumer_locator_pointer=self.consumer_locator_pointer,
            ),
        }


def _spec_payload(
    *,
    state_machine_candidate_id: str,
    prerequisite_graph_id: str,
    graph_shape: str,
    support_rule_id: str,
    world_ref: str,
    terminal_operation_id: str,
    delta: GraphCounterfactualDelta,
    fresh_state: FreshControlledStateRequirement,
    cleanup: GraphCleanupRequirement,
    oracle: PrerequisiteEffectOracleRequirement,
    execution_blockers: Sequence[str],
) -> Dict[str, Any]:
    return {
        "state_machine_candidate_id": state_machine_candidate_id,
        "prerequisite_graph_id": prerequisite_graph_id,
        "graph_shape": graph_shape,
        "support_rule_id": support_rule_id,
        "world_ref": world_ref,
        "terminal_operation_id": terminal_operation_id,
        "delta": delta.to_dict(),
        "fresh_state": fresh_state.to_dict(),
        "cleanup": cleanup.to_dict(),
        "oracle": oracle.to_dict(),
        "execution_blockers": list(execution_blockers),
        "mode": GRAPH_BOUND_PREREQUISITE_EXPERIMENT_MODE,
        "admission_ready": False,
        "finding_authority": False,
        "executable": False,
    }


@dataclass(frozen=True)
class GraphBoundPrerequisiteExperimentSpec:
    spec_id: str
    state_machine_candidate_id: str
    prerequisite_graph_id: str
    graph_shape: str
    support_rule_id: str
    world_ref: str
    terminal_operation_id: str
    delta: GraphCounterfactualDelta
    fresh_state: FreshControlledStateRequirement
    cleanup: GraphCleanupRequirement
    oracle: PrerequisiteEffectOracleRequirement
    execution_blockers: Tuple[str, ...]
    mode: str = GRAPH_BOUND_PREREQUISITE_EXPERIMENT_MODE
    admission_ready: bool = False
    finding_authority: bool = False
    executable: bool = False

    @classmethod
    def build(
        cls,
        *,
        candidate: StateMachineLegalityCandidate,
        support_rule: PrerequisiteTopologySupportRule,
        delta: GraphCounterfactualDelta,
        fresh_state: FreshControlledStateRequirement,
        cleanup: GraphCleanupRequirement,
        execution_blockers: Sequence[str],
    ) -> "GraphBoundPrerequisiteExperimentSpec":
        if (
            support_rule.status != "supported"
            or support_rule.graph_shape != candidate.prerequisite_graph.shape
            or support_rule.family is not delta.family
        ):
            raise ValueError("support rule does not admit this graph specification")
        blockers = tuple(sorted(set(execution_blockers)))
        oracle = PrerequisiteEffectOracleRequirement.build(
            family=delta.family,
            reference_state_id=fresh_state.reference_state_id,
        )
        payload = _spec_payload(
            state_machine_candidate_id=candidate.candidate_id,
            prerequisite_graph_id=candidate.prerequisite_graph.graph_id,
            graph_shape=candidate.prerequisite_graph.shape,
            support_rule_id=support_rule.rule_id,
            world_ref=candidate.world_ref,
            terminal_operation_id=candidate.terminal_operation_id,
            delta=delta,
            fresh_state=fresh_state,
            cleanup=cleanup,
            oracle=oracle,
            execution_blockers=blockers,
        )
        return cls(
            spec_id=stable_hash("graph_bound_prerequisite_experiment", payload),
            state_machine_candidate_id=candidate.candidate_id,
            prerequisite_graph_id=candidate.prerequisite_graph.graph_id,
            graph_shape=candidate.prerequisite_graph.shape,
            support_rule_id=support_rule.rule_id,
            world_ref=candidate.world_ref,
            terminal_operation_id=candidate.terminal_operation_id,
            delta=delta,
            fresh_state=fresh_state,
            cleanup=cleanup,
            oracle=oracle,
            execution_blockers=blockers,
        )

    def __post_init__(self) -> None:
        payload = _spec_payload(
            state_machine_candidate_id=self.state_machine_candidate_id,
            prerequisite_graph_id=self.prerequisite_graph_id,
            graph_shape=self.graph_shape,
            support_rule_id=self.support_rule_id,
            world_ref=self.world_ref,
            terminal_operation_id=self.terminal_operation_id,
            delta=self.delta,
            fresh_state=self.fresh_state,
            cleanup=self.cleanup,
            oracle=self.oracle,
            execution_blockers=self.execution_blockers,
        )
        if (
            self.spec_id
            != stable_hash("graph_bound_prerequisite_experiment", payload)
            or not _hash_ref(
                self.state_machine_candidate_id,
                "state_machine_legality_candidate",
            )
            or not _hash_ref(
                self.prerequisite_graph_id,
                "observed_prerequisite_graph",
            )
            or self.graph_shape not in _GRAPH_SHAPES
            or not _hash_ref(
                self.support_rule_id,
                "prerequisite_topology_support_rule",
            )
            or not _hash_ref(self.world_ref, "world")
            or not _hash_ref(self.terminal_operation_id, "action")
            or not isinstance(self.delta, GraphCounterfactualDelta)
            or self.delta.baseline_operation_ids[-1]
            != self.terminal_operation_id
            or not isinstance(self.fresh_state, FreshControlledStateRequirement)
            or self.fresh_state.world_ref != self.world_ref
            or not isinstance(self.cleanup, GraphCleanupRequirement)
            or {
                item.lifecycle_id for item in self.cleanup.bindings
            }
            != set(self.fresh_state.lifecycle_ids)
            or not isinstance(self.oracle, PrerequisiteEffectOracleRequirement)
            or self.oracle.family is not self.delta.family
            or self.oracle.reference_state_id != self.fresh_state.reference_state_id
            or self.execution_blockers
            != tuple(sorted(set(self.execution_blockers)))
            or not _REQUIRED_BLOCKERS <= set(self.execution_blockers)
            or any(
                _SEMANTIC.fullmatch(item) is None
                for item in self.execution_blockers
            )
            or self.mode != GRAPH_BOUND_PREREQUISITE_EXPERIMENT_MODE
            or self.admission_ready
            or self.finding_authority
            or self.executable
        ):
            raise ValueError("graph-bound prerequisite experiment is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": 1,
            "spec_id": self.spec_id,
            **_spec_payload(
                state_machine_candidate_id=self.state_machine_candidate_id,
                prerequisite_graph_id=self.prerequisite_graph_id,
                graph_shape=self.graph_shape,
                support_rule_id=self.support_rule_id,
                world_ref=self.world_ref,
                terminal_operation_id=self.terminal_operation_id,
                delta=self.delta,
                fresh_state=self.fresh_state,
                cleanup=self.cleanup,
                oracle=self.oracle,
                execution_blockers=self.execution_blockers,
            ),
        }


@dataclass(frozen=True)
class GraphBoundExperimentDiagnostics:
    state_candidates: int
    candidates_examined: int
    specifications_compiled: int
    omission_specifications: int
    reordering_specifications: int
    no_owned_lifecycle: int
    reconstruction_mismatches: int
    invalid_baselines: int
    unsafe_candidates: int
    deferred_family_checks: int
    unsupported_locator_relations: int
    non_isolated_relations: int
    duplicate_specifications: int
    dropped_specifications: int

    def __post_init__(self) -> None:
        if any(
            isinstance(value, bool) or not isinstance(value, int) or value < 0
            for value in vars(self).values()
        ):
            raise ValueError("graph-bound diagnostics must be non-negative integers")
        if self.candidates_examined != self.state_candidates:
            raise ValueError("all state candidates must be examined")
        if (
            self.omission_specifications + self.reordering_specifications
            != self.specifications_compiled
        ):
            raise ValueError("graph-bound specification family accounting is invalid")

    @property
    def incomplete_work(self) -> int:
        return self.reconstruction_mismatches + self.dropped_specifications

    def to_dict(self) -> Dict[str, int]:
        return dict(vars(self))


def _result_payload(
    *,
    status: str,
    state_machine_result_id: str,
    lifecycle_capture_digest: str,
    matrix_digest: str,
    support_matrix: Sequence[PrerequisiteTopologySupportRule],
    specifications: Sequence[GraphBoundPrerequisiteExperimentSpec],
    diagnostics: GraphBoundExperimentDiagnostics,
    blocker: Optional[str],
) -> Dict[str, Any]:
    return {
        "mode": GRAPH_BOUND_PREREQUISITE_EXPERIMENT_MODE,
        "status": status,
        "state_machine_result_id": state_machine_result_id,
        "lifecycle_capture_digest": lifecycle_capture_digest,
        "matrix_digest": matrix_digest,
        "support_matrix": [item.to_dict() for item in support_matrix],
        "specifications": [item.to_dict() for item in specifications],
        "diagnostics": diagnostics.to_dict(),
        "blocker": blocker,
        "finding_authority": False,
        "executable": False,
    }


@dataclass(frozen=True)
class GraphBoundExperimentCompilationResult:
    result_id: str
    status: str
    state_machine_result_id: str
    lifecycle_capture_digest: str
    matrix_digest: str
    support_matrix: Tuple[PrerequisiteTopologySupportRule, ...]
    specifications: Tuple[GraphBoundPrerequisiteExperimentSpec, ...]
    diagnostics: GraphBoundExperimentDiagnostics
    blocker: Optional[str] = None
    mode: str = GRAPH_BOUND_PREREQUISITE_EXPERIMENT_MODE
    finding_authority: bool = False
    executable: bool = False

    def __post_init__(self) -> None:
        payload = _result_payload(
            status=self.status,
            state_machine_result_id=self.state_machine_result_id,
            lifecycle_capture_digest=self.lifecycle_capture_digest,
            matrix_digest=self.matrix_digest,
            support_matrix=self.support_matrix,
            specifications=self.specifications,
            diagnostics=self.diagnostics,
            blocker=self.blocker,
        )
        expected_matrix = prerequisite_topology_support_matrix()
        expected_matrix_digest = stable_hash(
            "prerequisite_topology_support_matrix",
            [item.to_dict() for item in expected_matrix],
        )
        expected_status = (
            "blocked"
            if self.blocker is not None
            else ("ready" if self.specifications else "no_specifications")
        )
        spec_ids = [item.spec_id for item in self.specifications]
        if (
            self.result_id
            != stable_hash("graph_bound_experiment_compilation", payload)
            or self.status != expected_status
            or not _hash_ref(
                self.state_machine_result_id,
                "state_machine_legality_result",
            )
            or not _hash_ref(self.lifecycle_capture_digest, "capture_set")
            or self.support_matrix != expected_matrix
            or self.matrix_digest != expected_matrix_digest
            or spec_ids != sorted(set(spec_ids))
            or len(self.specifications) > MAX_GRAPH_BOUND_EXPERIMENT_SPECS
            or self.diagnostics.specifications_compiled
            != len(self.specifications)
            or (
                self.blocker is not None
                and _SEMANTIC.fullmatch(self.blocker) is None
            )
            or self.mode != GRAPH_BOUND_PREREQUISITE_EXPERIMENT_MODE
            or self.finding_authority
            or self.executable
        ):
            raise ValueError("graph-bound experiment compilation result is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": 1,
            "result_id": self.result_id,
            **_result_payload(
                status=self.status,
                state_machine_result_id=self.state_machine_result_id,
                lifecycle_capture_digest=self.lifecycle_capture_digest,
                matrix_digest=self.matrix_digest,
                support_matrix=self.support_matrix,
                specifications=self.specifications,
                diagnostics=self.diagnostics,
                blocker=self.blocker,
            ),
        }


def _has_path(graph: ObservedPrerequisiteGraph, source: str, target: str) -> bool:
    successors: Dict[str, set[str]] = {}
    for relation in graph.relations:
        successors.setdefault(relation.producer_operation_id, set()).add(
            relation.consumer_operation_id
        )
    frontier = list(successors.get(source, ()))
    visited = set()
    while frontier:
        operation_id = frontier.pop()
        if operation_id == target:
            return True
        if operation_id in visited:
            continue
        visited.add(operation_id)
        frontier.extend(successors.get(operation_id, ()))
    return False


class GraphBoundPrerequisiteExperimentCompiler:
    """Compile exact graph deltas and requirements without executing them."""

    def __init__(self, *, max_specifications: int = MAX_GRAPH_BOUND_EXPERIMENT_SPECS):
        if (
            isinstance(max_specifications, bool)
            or not isinstance(max_specifications, int)
            or max_specifications <= 0
            or max_specifications > MAX_GRAPH_BOUND_EXPERIMENT_SPECS
        ):
            raise ValueError("max_specifications exceeds the R5B2 contract")
        self.max_specifications = max_specifications
        self.support_matrix = prerequisite_topology_support_matrix()
        self.rules = {
            (item.graph_shape, item.family): item for item in self.support_matrix
        }
        self.matrix_digest = stable_hash(
            "prerequisite_topology_support_matrix",
            [item.to_dict() for item in self.support_matrix],
        )

    def _result(
        self,
        *,
        state_machine_result_id: str,
        lifecycle_capture_digest: str,
        specifications: Sequence[GraphBoundPrerequisiteExperimentSpec],
        diagnostics: GraphBoundExperimentDiagnostics,
        blocker: Optional[str] = None,
    ) -> GraphBoundExperimentCompilationResult:
        values = tuple(sorted(specifications, key=lambda item: item.spec_id))
        status = "blocked" if blocker else ("ready" if values else "no_specifications")
        payload = _result_payload(
            status=status,
            state_machine_result_id=state_machine_result_id,
            lifecycle_capture_digest=lifecycle_capture_digest,
            matrix_digest=self.matrix_digest,
            support_matrix=self.support_matrix,
            specifications=values,
            diagnostics=diagnostics,
            blocker=blocker,
        )
        return GraphBoundExperimentCompilationResult(
            result_id=stable_hash("graph_bound_experiment_compilation", payload),
            status=status,
            state_machine_result_id=state_machine_result_id,
            lifecycle_capture_digest=lifecycle_capture_digest,
            matrix_digest=self.matrix_digest,
            support_matrix=self.support_matrix,
            specifications=values,
            diagnostics=diagnostics,
            blocker=blocker,
        )

    @staticmethod
    def _matching_lifecycles(
        candidate: StateMachineLegalityCandidate,
        lifecycle: LifecycleMiningResult,
    ) -> Tuple[OwnedLifecycleCandidate, ...]:
        return tuple(
            item
            for item in lifecycle.candidates
            if item.world_ref == candidate.world_ref
            and candidate.terminal_operation_id in item.read_operation_ids
            and item.create_operation_id in candidate.prerequisite_graph.operation_ids
        )

    def compile(
        self,
        records: Sequence[Mapping[str, Any]],
        *,
        world_id: str,
        lifecycle: LifecycleMiningResult,
        state_machine: StateMachineLegalityResult,
    ) -> GraphBoundExperimentCompilationResult:
        if isinstance(records, (str, bytes)) or any(
            not isinstance(item, Mapping) for item in records
        ):
            raise TypeError("graph-bound records must be a sequence of mappings")
        if not isinstance(world_id, str) or not world_id:
            raise ValueError("world_id must be non-empty")
        if not isinstance(lifecycle, LifecycleMiningResult):
            raise TypeError("lifecycle must be a LifecycleMiningResult")
        if not isinstance(state_machine, StateMachineLegalityResult):
            raise TypeError("state_machine must be a StateMachineLegalityResult")

        empty_diagnostics = dict(
            state_candidates=0,
            candidates_examined=0,
            specifications_compiled=0,
            omission_specifications=0,
            reordering_specifications=0,
            no_owned_lifecycle=0,
            reconstruction_mismatches=0,
            invalid_baselines=0,
            unsafe_candidates=0,
            deferred_family_checks=0,
            unsupported_locator_relations=0,
            non_isolated_relations=0,
            duplicate_specifications=0,
            dropped_specifications=0,
        )
        if state_machine.status == "blocked":
            return self._result(
                state_machine_result_id=state_machine.result_id,
                lifecycle_capture_digest=lifecycle.capture_digest,
                specifications=(),
                diagnostics=GraphBoundExperimentDiagnostics(**empty_diagnostics),
                blocker="state_machine_analysis_blocked",
            )

        record_values = tuple(records)
        try:
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
        except ValueError:
            return self._result(
                state_machine_result_id=state_machine.result_id,
                lifecycle_capture_digest=lifecycle.capture_digest,
                specifications=(),
                diagnostics=GraphBoundExperimentDiagnostics(**empty_diagnostics),
                blocker="graph_reconstruction_limits_exceeded",
            )

        goals = {
            item.terminal_operation_id: item
            for item in high_value_goals(ledger.operations)
        }
        bindings = {item.binding_id: item for item in ledger.bindings}
        observations = {item.source_ref: item for item in ledger.observations}
        normalized_by_source = {}
        state_ids_by_source = {}
        successful_sources = set()
        raw_worlds: Dict[str, set[str]] = {}
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
            normalized_by_source[exchange.source_id] = exchange
            state_ids_by_source[exchange.source_id] = exchange.state_id
            if 200 <= exchange.response_status < 300:
                successful_sources.add(exchange.source_id)
            raw_worlds.setdefault(exchange.world_id, set()).add(raw_world)

        enriched_operations = {
            item.operation_id: item for item in lifecycle.ledger.operations
        }
        specifications: Dict[str, GraphBoundPrerequisiteExperimentSpec] = {}
        no_owned_lifecycle = 0
        reconstruction_mismatches = 0
        invalid_baselines = 0
        unsafe_candidates = 0
        deferred_family_checks = 0
        unsupported_locator_relations = 0
        non_isolated_relations = 0
        duplicate_specifications = 0
        dropped_specifications = 0
        omission_specifications = 0
        reordering_specifications = 0
        rehydrator = PlanRehydrator(ledger)

        def retain(specification: GraphBoundPrerequisiteExperimentSpec) -> None:
            nonlocal duplicate_specifications, dropped_specifications
            nonlocal omission_specifications, reordering_specifications
            if specification.spec_id in specifications:
                duplicate_specifications += 1
                return
            if len(specifications) >= self.max_specifications:
                dropped_specifications += 1
                return
            specifications[specification.spec_id] = specification
            if (
                specification.delta.family
                is PrerequisiteCounterfactualFamily.OMISSION
            ):
                omission_specifications += 1
            else:
                reordering_specifications += 1

        for candidate in state_machine.candidates:
            owned_lifecycles = self._matching_lifecycles(candidate, lifecycle)
            if not owned_lifecycles:
                no_owned_lifecycle += 1
                continue
            raw_world_values = raw_worlds.get(candidate.world_ref, set())
            goal = goals.get(candidate.terminal_operation_id)
            if len(raw_world_values) != 1 or goal is None:
                reconstruction_mismatches += 1
                continue
            plan = compiler.compile(goal)
            if (
                plan.status != "planned"
                or plan.plan_id != candidate.plan_id
                or plan.step_ids
                != (*candidate.prerequisite_operation_ids, candidate.terminal_operation_id)
            ):
                reconstruction_mismatches += 1
                continue
            recipe = rehydrator.build_recipe(
                plan,
                world_id=next(iter(raw_world_values)),
            )
            recipe_binding_ids = tuple(
                sorted(item.binding_id for item in recipe.bindings)
            )
            if (
                recipe.status != "ready"
                or recipe.recipe_id != candidate.recipe_id
                or tuple(item.source_ref for item in recipe.steps)
                != candidate.source_refs
                or recipe_binding_ids != candidate.lineage_binding_ids
                or any(item not in bindings for item in recipe_binding_ids)
            ):
                reconstruction_mismatches += 1
                continue
            relation_evidence_matches = all(
                (
                    binding := bindings.get(relation.lineage_binding_id)
                ) is not None
                and binding.capability == relation.capability
                and binding.world_ref == relation.world_ref
                and binding.producer_operation_id
                == relation.producer_operation_id
                and binding.producer_source_ref == relation.producer_source_ref
                and binding.consumer_operation_id
                == relation.consumer_operation_id
                and binding.consumer_source_ref == relation.consumer_source_ref
                and state_ids_by_source.get(binding.producer_source_ref)
                == relation.producer_state_id
                and state_ids_by_source.get(binding.consumer_source_ref)
                == relation.consumer_state_id
                and binding.producer_source_ref in successful_sources
                and binding.consumer_source_ref in successful_sources
                for relation in candidate.prerequisite_graph.relations
            )
            if not relation_evidence_matches:
                reconstruction_mismatches += 1
                continue
            try:
                reconstructed_graph = ObservedPrerequisiteGraph.build(
                    world_ref=candidate.world_ref,
                    terminal_operation_id=candidate.terminal_operation_id,
                    operation_ids=plan.step_ids,
                    relations=candidate.prerequisite_graph.relations,
                )
            except (TypeError, ValueError):
                reconstruction_mismatches += 1
                continue
            if reconstructed_graph != candidate.prerequisite_graph:
                reconstruction_mismatches += 1
                continue

            baseline_source_ref = candidate.source_refs[-1]
            baseline_exchange = normalized_by_source.get(baseline_source_ref)
            baseline_observation = observations.get(baseline_source_ref)
            if (
                baseline_exchange is None
                or baseline_observation is None
                or baseline_observation.operation_id
                != candidate.terminal_operation_id
                or baseline_exchange.method not in {"GET", "HEAD"}
                or not 200 <= baseline_exchange.response_status < 300
                or baseline_exchange.response_truncated
                or baseline_exchange.response_body_hash is None
            ):
                invalid_baselines += 1
                continue

            operation_values = [
                enriched_operations.get(item) for item in plan.step_ids
            ]
            if any(
                item is not None
                and item.safety
                in {OperationSafety.DESTRUCTIVE, OperationSafety.EXTERNAL_EFFECT}
                for item in operation_values
            ):
                unsafe_candidates += 1
                continue
            blockers = set(_REQUIRED_BLOCKERS)
            if any(
                item is None or item.safety is OperationSafety.UNKNOWN
                for item in operation_values
            ):
                blockers.add("operation_safety_unproven")
            lifecycle_create_ids = {
                item.create_operation_id for item in owned_lifecycles
            }
            state_changing_ids = {
                observation.operation_id
                for observation in observations.values()
                if observation.source_ref in candidate.source_refs
                and normalized_by_source.get(observation.source_ref) is not None
                and normalized_by_source[observation.source_ref].method
                not in {"GET", "HEAD", "OPTIONS"}
            }
            if not state_changing_ids <= lifecycle_create_ids:
                blockers.add("complete_cleanup_not_proven")

            fresh_state = FreshControlledStateRequirement.build(
                world_ref=candidate.world_ref,
                lifecycle_ids=(item.lifecycle_id for item in owned_lifecycles),
                baseline_source_ref=baseline_source_ref,
                reference_state_id=baseline_exchange.state_id,
                reference_response_status=baseline_exchange.response_status,
                reference_response_body_hash=baseline_exchange.response_body_hash,
            )
            cleanup = GraphCleanupRequirement.build(owned_lifecycles)
            graph = candidate.prerequisite_graph
            baseline_operations = plan.step_ids
            outgoing: Dict[str, list[ObservedPrerequisiteRelation]] = {}
            for relation in graph.relations:
                outgoing.setdefault(relation.producer_operation_id, []).append(
                    relation
                )

            omission_rule = self.rules[(
                graph.shape,
                PrerequisiteCounterfactualFamily.OMISSION,
            )]
            if omission_rule.status == "supported":
                for relation in graph.relations:
                    if (
                        relation.consumer_operation_id
                        != candidate.terminal_operation_id
                        or relation.producer_operation_id in lifecycle_create_ids
                    ):
                        continue
                    producer_relations = outgoing.get(
                        relation.producer_operation_id,
                        [],
                    )
                    if len(producer_relations) != 1:
                        non_isolated_relations += 1
                        continue
                    binding = bindings.get(relation.lineage_binding_id)
                    if (
                        binding is None
                        or binding.consumer_source_ref != baseline_source_ref
                        or binding.consumer_locator.kind not in _SUPPORTED_LOCATORS
                    ):
                        unsupported_locator_relations += 1
                        continue
                    delta = GraphCounterfactualDelta.build(
                        family=PrerequisiteCounterfactualFamily.OMISSION,
                        mutation_kind="omit_isolated_prerequisite",
                        baseline_operation_ids=baseline_operations,
                        treatment_operation_ids=tuple(
                            item
                            for item in baseline_operations
                            if item != relation.producer_operation_id
                        ),
                        target_operation_ids=(relation.producer_operation_id,),
                        target_relation_ids=(relation.relation_id,),
                        target_binding_ids=(relation.lineage_binding_id,),
                        capability_key=relation.capability.key,
                        consumer_locator_kind=binding.consumer_locator.kind.value,
                        consumer_locator_pointer=binding.consumer_locator.pointer,
                    )
                    retain(
                        GraphBoundPrerequisiteExperimentSpec.build(
                            candidate=candidate,
                            support_rule=omission_rule,
                            delta=delta,
                            fresh_state=fresh_state,
                            cleanup=cleanup,
                            execution_blockers=(
                                *blockers,
                                "graph_omission_backend_required",
                            ),
                        )
                    )
            else:
                deferred_family_checks += 1

            reordering_rule = self.rules[(
                graph.shape,
                PrerequisiteCounterfactualFamily.REORDERING,
            )]
            if reordering_rule.status == "supported":
                prerequisites = baseline_operations[:-1]
                for index, (first, second) in enumerate(
                    zip(prerequisites, prerequisites[1:])
                ):
                    if _has_path(graph, first, second) or _has_path(
                        graph,
                        second,
                        first,
                    ):
                        continue
                    first_consumers = {
                        item.consumer_operation_id
                        for item in outgoing.get(first, ())
                    }
                    second_consumers = {
                        item.consumer_operation_id
                        for item in outgoing.get(second, ())
                    }
                    common_consumers = first_consumers & second_consumers
                    if not common_consumers:
                        continue
                    consumer = min(common_consumers)
                    target_relations = tuple(
                        item
                        for item in graph.relations
                        if item.producer_operation_id in {first, second}
                        and item.consumer_operation_id == consumer
                    )
                    if {item.producer_operation_id for item in target_relations} != {
                        first,
                        second,
                    }:
                        continue
                    treatment = list(baseline_operations)
                    treatment[index], treatment[index + 1] = (
                        treatment[index + 1],
                        treatment[index],
                    )
                    delta = GraphCounterfactualDelta.build(
                        family=PrerequisiteCounterfactualFamily.REORDERING,
                        mutation_kind=(
                            "swap_adjacent_independent_prerequisites"
                        ),
                        baseline_operation_ids=baseline_operations,
                        treatment_operation_ids=treatment,
                        target_operation_ids=(first, second),
                        target_relation_ids=tuple(
                            item.relation_id for item in target_relations
                        ),
                        target_binding_ids=tuple(
                            item.lineage_binding_id for item in target_relations
                        ),
                    )
                    retain(
                        GraphBoundPrerequisiteExperimentSpec.build(
                            candidate=candidate,
                            support_rule=reordering_rule,
                            delta=delta,
                            fresh_state=fresh_state,
                            cleanup=cleanup,
                            execution_blockers=(
                                *blockers,
                                "graph_reordering_backend_required",
                            ),
                        )
                    )
            else:
                deferred_family_checks += 1

        ordered = tuple(specifications[key] for key in sorted(specifications))
        diagnostics = GraphBoundExperimentDiagnostics(
            state_candidates=len(state_machine.candidates),
            candidates_examined=len(state_machine.candidates),
            specifications_compiled=len(ordered),
            omission_specifications=omission_specifications,
            reordering_specifications=reordering_specifications,
            no_owned_lifecycle=no_owned_lifecycle,
            reconstruction_mismatches=reconstruction_mismatches,
            invalid_baselines=invalid_baselines,
            unsafe_candidates=unsafe_candidates,
            deferred_family_checks=deferred_family_checks,
            unsupported_locator_relations=unsupported_locator_relations,
            non_isolated_relations=non_isolated_relations,
            duplicate_specifications=duplicate_specifications,
            dropped_specifications=dropped_specifications,
        )
        return self._result(
            state_machine_result_id=state_machine.result_id,
            lifecycle_capture_digest=lifecycle.capture_digest,
            specifications=ordered,
            diagnostics=diagnostics,
        )


__all__ = [
    "GRAPH_BOUND_PREREQUISITE_EXPERIMENT_MODE",
    "GraphBoundExperimentCompilationResult",
    "GraphBoundExperimentDiagnostics",
    "GraphBoundPrerequisiteExperimentCompiler",
    "GraphBoundPrerequisiteExperimentSpec",
    "GraphCleanupRequirement",
    "GraphCounterfactualDelta",
    "PrerequisiteCounterfactualFamily",
    "PrerequisiteEffectOracleRequirement",
    "PrerequisiteTopologySupportRule",
    "FreshControlledStateRequirement",
    "prerequisite_topology_support_matrix",
]
