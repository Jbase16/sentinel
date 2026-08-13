"""Exact-lineage prerequisite graphs for passive lifecycle analysis.

The graph preserves dependencies that a linear execution recipe necessarily
flattens.  Every edge is backed by one same-world value-lineage binding between
two captured successful operations.  The graph proves observed data flow only;
it does not claim that the target enforces the prerequisite and it exposes no
transport, admission, execution, or finding authority.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Sequence, Tuple

from .compiler import Capability
from .lineage import LineageBinding
from .normalize import stable_hash

OBSERVED_PREREQUISITE_GRAPH_MODE = "behavioral_observed_prerequisite_graph_v1"
MAX_OBSERVED_PREREQUISITE_OPERATIONS = 32
MAX_OBSERVED_PREREQUISITE_RELATIONS = 32

_HASH_REF = re.compile(r"^[a-z][a-z0-9_]*:[0-9a-f]{64}$")
_SHAPES = frozenset({"linear", "branching", "joining", "branching_joining"})
_EVIDENCE_BASIS = "exact_value_lineage"


def _hash_ref(value: Any, prefix: str) -> bool:
    return (
        isinstance(value, str)
        and _HASH_REF.fullmatch(value) is not None
        and value.startswith(f"{prefix}:")
    )


def _relation_payload(
    *,
    capability: Capability,
    lineage_binding_id: str,
    world_ref: str,
    producer_operation_id: str,
    producer_source_ref: str,
    producer_state_id: str,
    consumer_operation_id: str,
    consumer_source_ref: str,
    consumer_state_id: str,
) -> Dict[str, Any]:
    return {
        "capability": capability.to_dict(),
        "lineage_binding_id": lineage_binding_id,
        "world_ref": world_ref,
        "producer_operation_id": producer_operation_id,
        "producer_source_ref": producer_source_ref,
        "producer_state_id": producer_state_id,
        "consumer_operation_id": consumer_operation_id,
        "consumer_source_ref": consumer_source_ref,
        "consumer_state_id": consumer_state_id,
        "evidence_basis": _EVIDENCE_BASIS,
        "necessity_proven": False,
        "enforcement_proven": False,
        "finding_authority": False,
        "executable": False,
    }


@dataclass(frozen=True)
class ObservedPrerequisiteRelation:
    """One exact observed value flow between two captured operations."""

    relation_id: str
    capability: Capability
    lineage_binding_id: str
    world_ref: str
    producer_operation_id: str
    producer_source_ref: str
    producer_state_id: str
    consumer_operation_id: str
    consumer_source_ref: str
    consumer_state_id: str
    evidence_basis: str = _EVIDENCE_BASIS
    necessity_proven: bool = False
    enforcement_proven: bool = False
    finding_authority: bool = False
    executable: bool = False

    @classmethod
    def from_binding(
        cls,
        binding: LineageBinding,
        *,
        producer_state_id: str,
        consumer_state_id: str,
    ) -> "ObservedPrerequisiteRelation":
        if not isinstance(binding, LineageBinding):
            raise TypeError("binding must be a LineageBinding")
        payload = _relation_payload(
            capability=binding.capability,
            lineage_binding_id=binding.binding_id,
            world_ref=binding.world_ref,
            producer_operation_id=binding.producer_operation_id,
            producer_source_ref=binding.producer_source_ref,
            producer_state_id=producer_state_id,
            consumer_operation_id=binding.consumer_operation_id,
            consumer_source_ref=binding.consumer_source_ref,
            consumer_state_id=consumer_state_id,
        )
        return cls(
            relation_id=stable_hash("observed_prerequisite_relation", payload),
            capability=binding.capability,
            lineage_binding_id=binding.binding_id,
            world_ref=binding.world_ref,
            producer_operation_id=binding.producer_operation_id,
            producer_source_ref=binding.producer_source_ref,
            producer_state_id=producer_state_id,
            consumer_operation_id=binding.consumer_operation_id,
            consumer_source_ref=binding.consumer_source_ref,
            consumer_state_id=consumer_state_id,
        )

    def __post_init__(self) -> None:
        if not isinstance(self.capability, Capability):
            raise ValueError("observed prerequisite capability is invalid")
        payload = _relation_payload(
            capability=self.capability,
            lineage_binding_id=self.lineage_binding_id,
            world_ref=self.world_ref,
            producer_operation_id=self.producer_operation_id,
            producer_source_ref=self.producer_source_ref,
            producer_state_id=self.producer_state_id,
            consumer_operation_id=self.consumer_operation_id,
            consumer_source_ref=self.consumer_source_ref,
            consumer_state_id=self.consumer_state_id,
        )
        if (
            self.relation_id
            != stable_hash("observed_prerequisite_relation", payload)
            or not _hash_ref(self.lineage_binding_id, "lineage_binding")
            or not _hash_ref(self.world_ref, "world")
            or not _hash_ref(self.producer_operation_id, "action")
            or not _hash_ref(self.producer_source_ref, "source_ref")
            or not _hash_ref(self.producer_state_id, "state")
            or not _hash_ref(self.consumer_operation_id, "action")
            or not _hash_ref(self.consumer_source_ref, "source_ref")
            or not _hash_ref(self.consumer_state_id, "state")
            or self.producer_operation_id == self.consumer_operation_id
            or self.producer_source_ref == self.consumer_source_ref
            or self.evidence_basis != _EVIDENCE_BASIS
            or self.necessity_proven
            or self.enforcement_proven
            or self.finding_authority
            or self.executable
        ):
            raise ValueError("observed prerequisite relation contract is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "relation_id": self.relation_id,
            **_relation_payload(
                capability=self.capability,
                lineage_binding_id=self.lineage_binding_id,
                world_ref=self.world_ref,
                producer_operation_id=self.producer_operation_id,
                producer_source_ref=self.producer_source_ref,
                producer_state_id=self.producer_state_id,
                consumer_operation_id=self.consumer_operation_id,
                consumer_source_ref=self.consumer_source_ref,
                consumer_state_id=self.consumer_state_id,
            ),
        }


def _derive_topology(
    *,
    operation_ids: Sequence[str],
    terminal_operation_id: str,
    relations: Sequence[ObservedPrerequisiteRelation],
) -> Dict[str, Any]:
    operations = tuple(sorted(set(operation_ids)))
    relation_inputs = tuple(relations)
    if any(
        not isinstance(item, ObservedPrerequisiteRelation)
        for item in relation_inputs
    ):
        raise ValueError("observed prerequisite relations are invalid")
    relation_values = tuple(
        sorted(relation_inputs, key=lambda item: item.relation_id)
    )
    if (
        not operations
        or len(operations) != len(operation_ids)
        or len(operations) > MAX_OBSERVED_PREREQUISITE_OPERATIONS
        or terminal_operation_id not in operations
        or not relation_values
        or len(relation_values) > MAX_OBSERVED_PREREQUISITE_RELATIONS
        or len({item.relation_id for item in relation_values})
        != len(relation_values)
        or any(not _hash_ref(item, "action") for item in operations)
        or not _hash_ref(terminal_operation_id, "action")
        or any(
            item.producer_operation_id not in operations
            or item.consumer_operation_id not in operations
            for item in relation_values
        )
    ):
        raise ValueError("observed prerequisite graph inputs are invalid")

    successors = {operation_id: set() for operation_id in operations}
    predecessors = {operation_id: set() for operation_id in operations}
    for relation in relation_values:
        successors[relation.producer_operation_id].add(
            relation.consumer_operation_id
        )
        predecessors[relation.consumer_operation_id].add(
            relation.producer_operation_id
        )
    if successors[terminal_operation_id]:
        raise ValueError("terminal operation cannot produce a prerequisite edge")

    pending_predecessors = {
        operation_id: set(values)
        for operation_id, values in predecessors.items()
    }
    ready = sorted(
        operation_id
        for operation_id, values in pending_predecessors.items()
        if not values
    )
    topological_order = []
    while ready:
        operation_id = ready.pop(0)
        topological_order.append(operation_id)
        for successor in sorted(successors[operation_id]):
            pending_predecessors[successor].discard(operation_id)
            if (
                not pending_predecessors[successor]
                and successor not in topological_order
                and successor not in ready
            ):
                ready.append(successor)
                ready.sort()
    if len(topological_order) != len(operations):
        raise ValueError("observed prerequisite graph must be acyclic")

    connected_to_terminal = {terminal_operation_id}
    frontier = [terminal_operation_id]
    while frontier:
        consumer = frontier.pop()
        for producer in predecessors[consumer]:
            if producer not in connected_to_terminal:
                connected_to_terminal.add(producer)
                frontier.append(producer)
    if connected_to_terminal != set(operations):
        raise ValueError("every prerequisite operation must reach the terminal")

    roots = tuple(
        operation_id
        for operation_id in operations
        if not predecessors[operation_id]
    )
    direct_terminal = tuple(sorted(predecessors[terminal_operation_id]))
    branches = tuple(
        operation_id
        for operation_id in operations
        if len(successors[operation_id]) > 1
    )
    joins = tuple(
        operation_id
        for operation_id in operations
        if len(predecessors[operation_id]) > 1
    )
    if not roots or not direct_terminal:
        raise ValueError("observed prerequisite graph is incomplete")

    depth = {operation_id: 1 for operation_id in roots}
    for operation_id in topological_order:
        operation_depth = depth.get(operation_id)
        if operation_depth is None:
            raise ValueError("observed prerequisite graph depth is unresolved")
        for successor in successors[operation_id]:
            depth[successor] = max(
                depth.get(successor, 0),
                operation_depth + 1,
            )
    max_depth = depth[terminal_operation_id]
    if branches and joins:
        shape = "branching_joining"
    elif branches:
        shape = "branching"
    elif joins:
        shape = "joining"
    else:
        shape = "linear"
    return {
        "world_ref": relation_values[0].world_ref,
        "operation_ids": operations,
        "relations": relation_values,
        "root_operation_ids": roots,
        "direct_terminal_prerequisite_operation_ids": direct_terminal,
        "branch_operation_ids": branches,
        "join_operation_ids": joins,
        "max_depth": max_depth,
        "shape": shape,
    }


def _graph_payload(
    *,
    world_ref: str,
    terminal_operation_id: str,
    topology: Mapping[str, Any],
) -> Dict[str, Any]:
    return {
        "world_ref": world_ref,
        "terminal_operation_id": terminal_operation_id,
        "operation_ids": list(topology["operation_ids"]),
        "relations": [item.to_dict() for item in topology["relations"]],
        "root_operation_ids": list(topology["root_operation_ids"]),
        "direct_terminal_prerequisite_operation_ids": list(
            topology["direct_terminal_prerequisite_operation_ids"]
        ),
        "branch_operation_ids": list(topology["branch_operation_ids"]),
        "join_operation_ids": list(topology["join_operation_ids"]),
        "max_depth": topology["max_depth"],
        "shape": topology["shape"],
        "mode": OBSERVED_PREREQUISITE_GRAPH_MODE,
        "evidence_basis": _EVIDENCE_BASIS,
        "necessity_proven": False,
        "enforcement_proven": False,
        "finding_authority": False,
        "executable": False,
    }


@dataclass(frozen=True)
class ObservedPrerequisiteGraph:
    """A content-addressed prerequisite DAG backed only by exact lineage."""

    graph_id: str
    world_ref: str
    terminal_operation_id: str
    operation_ids: Tuple[str, ...]
    relations: Tuple[ObservedPrerequisiteRelation, ...]
    root_operation_ids: Tuple[str, ...]
    direct_terminal_prerequisite_operation_ids: Tuple[str, ...]
    branch_operation_ids: Tuple[str, ...]
    join_operation_ids: Tuple[str, ...]
    max_depth: int
    shape: str
    mode: str = OBSERVED_PREREQUISITE_GRAPH_MODE
    evidence_basis: str = _EVIDENCE_BASIS
    necessity_proven: bool = False
    enforcement_proven: bool = False
    finding_authority: bool = False
    executable: bool = False

    @classmethod
    def build(
        cls,
        *,
        world_ref: str,
        terminal_operation_id: str,
        operation_ids: Sequence[str],
        relations: Sequence[ObservedPrerequisiteRelation],
    ) -> "ObservedPrerequisiteGraph":
        topology = _derive_topology(
            operation_ids=operation_ids,
            terminal_operation_id=terminal_operation_id,
            relations=relations,
        )
        if world_ref != topology["world_ref"] or any(
            item.world_ref != world_ref for item in topology["relations"]
        ):
            raise ValueError("prerequisite graph cannot cross captured worlds")
        payload = _graph_payload(
            world_ref=world_ref,
            terminal_operation_id=terminal_operation_id,
            topology=topology,
        )
        return cls(
            graph_id=stable_hash("observed_prerequisite_graph", payload),
            world_ref=world_ref,
            terminal_operation_id=terminal_operation_id,
            operation_ids=topology["operation_ids"],
            relations=topology["relations"],
            root_operation_ids=topology["root_operation_ids"],
            direct_terminal_prerequisite_operation_ids=topology[
                "direct_terminal_prerequisite_operation_ids"
            ],
            branch_operation_ids=topology["branch_operation_ids"],
            join_operation_ids=topology["join_operation_ids"],
            max_depth=topology["max_depth"],
            shape=topology["shape"],
        )

    def __post_init__(self) -> None:
        topology = _derive_topology(
            operation_ids=self.operation_ids,
            terminal_operation_id=self.terminal_operation_id,
            relations=self.relations,
        )
        payload = _graph_payload(
            world_ref=self.world_ref,
            terminal_operation_id=self.terminal_operation_id,
            topology=topology,
        )
        if (
            self.graph_id != stable_hash("observed_prerequisite_graph", payload)
            or not _hash_ref(self.world_ref, "world")
            or self.world_ref != topology["world_ref"]
            or any(
                item.world_ref != self.world_ref
                for item in topology["relations"]
            )
            or self.operation_ids != topology["operation_ids"]
            or self.relations != topology["relations"]
            or self.root_operation_ids != topology["root_operation_ids"]
            or self.direct_terminal_prerequisite_operation_ids
            != topology["direct_terminal_prerequisite_operation_ids"]
            or self.branch_operation_ids != topology["branch_operation_ids"]
            or self.join_operation_ids != topology["join_operation_ids"]
            or self.max_depth != topology["max_depth"]
            or self.shape != topology["shape"]
            or self.shape not in _SHAPES
            or self.mode != OBSERVED_PREREQUISITE_GRAPH_MODE
            or self.evidence_basis != _EVIDENCE_BASIS
            or self.necessity_proven
            or self.enforcement_proven
            or self.finding_authority
            or self.executable
        ):
            raise ValueError("observed prerequisite graph contract is invalid")

    @property
    def is_multi_prerequisite(self) -> bool:
        return len(self.operation_ids) > 2

    @property
    def is_non_linear(self) -> bool:
        return self.shape != "linear"

    def to_dict(self) -> Dict[str, Any]:
        topology = {
            "operation_ids": self.operation_ids,
            "relations": self.relations,
            "root_operation_ids": self.root_operation_ids,
            "direct_terminal_prerequisite_operation_ids": (
                self.direct_terminal_prerequisite_operation_ids
            ),
            "branch_operation_ids": self.branch_operation_ids,
            "join_operation_ids": self.join_operation_ids,
            "max_depth": self.max_depth,
            "shape": self.shape,
        }
        return {
            "schema_version": 1,
            "graph_id": self.graph_id,
            **_graph_payload(
                world_ref=self.world_ref,
                terminal_operation_id=self.terminal_operation_id,
                topology=topology,
            ),
        }


def compile_observed_prerequisite_graph(
    bindings: Sequence[LineageBinding],
    *,
    state_ids_by_source_ref: Mapping[str, str],
    successful_source_refs: Sequence[str],
    operation_ids: Sequence[str],
    terminal_operation_id: str,
) -> ObservedPrerequisiteGraph:
    """Compile one exact passive graph without retaining captured values."""

    if isinstance(bindings, (str, bytes)) or any(
        not isinstance(item, LineageBinding) for item in bindings
    ):
        raise TypeError("bindings must contain LineageBinding values")
    if not isinstance(state_ids_by_source_ref, Mapping):
        raise TypeError("state_ids_by_source_ref must be a mapping")
    if isinstance(successful_source_refs, (str, bytes)):
        raise TypeError("successful_source_refs must be a sequence")
    successful_refs = set(successful_source_refs)
    if any(not _hash_ref(item, "source_ref") for item in successful_refs):
        raise ValueError("successful_source_refs contains an invalid reference")
    binding_values = tuple(bindings)
    if (
        not binding_values
        or len(binding_values) > MAX_OBSERVED_PREREQUISITE_RELATIONS
    ):
        raise ValueError("observed prerequisite relation count is invalid")
    relations = []
    for binding in binding_values:
        producer_state_id = state_ids_by_source_ref.get(
            binding.producer_source_ref
        )
        consumer_state_id = state_ids_by_source_ref.get(
            binding.consumer_source_ref
        )
        if producer_state_id is None or consumer_state_id is None:
            raise ValueError("lineage binding is missing an observed state")
        if not {
            binding.producer_source_ref,
            binding.consumer_source_ref,
        } <= successful_refs:
            raise ValueError("prerequisite relation requires successful observations")
        relations.append(
            ObservedPrerequisiteRelation.from_binding(
                binding,
                producer_state_id=producer_state_id,
                consumer_state_id=consumer_state_id,
            )
        )
    worlds = {item.world_ref for item in relations}
    if len(worlds) != 1:
        raise ValueError("prerequisite graph cannot cross captured worlds")
    return ObservedPrerequisiteGraph.build(
        world_ref=next(iter(worlds)),
        terminal_operation_id=terminal_operation_id,
        operation_ids=operation_ids,
        relations=relations,
    )


__all__ = [
    "MAX_OBSERVED_PREREQUISITE_OPERATIONS",
    "MAX_OBSERVED_PREREQUISITE_RELATIONS",
    "OBSERVED_PREREQUISITE_GRAPH_MODE",
    "ObservedPrerequisiteGraph",
    "ObservedPrerequisiteRelation",
    "compile_observed_prerequisite_graph",
]
