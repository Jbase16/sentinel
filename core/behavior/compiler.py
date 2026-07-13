"""Deterministic, analysis-only backward prerequisite compiler.

The compiler answers one narrow question: given a terminal operation and a set
of capabilities already available, which observed operations could manufacture
the terminal operation's missing prerequisites?  It performs no I/O, retains no
raw values, and never authorizes execution.  A later phase may rehydrate a plan
only after every step passes the existing policy, ownership, provenance, and
cleanup gates.
"""

from __future__ import annotations

import heapq
import json
import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Iterable, Mapping, Optional, Sequence, Tuple

from .normalize import normalize_exchange, stable_hash

ANALYSIS_ONLY_MODE = "analysis_only"

_SEMANTIC_NAME = re.compile(r"^[a-z][a-z0-9_.:-]{0,127}$")
_CAPABILITY_FIELD = re.compile(
    r"(?:^|[_-])(?:account|address|artifact|asset|business|callback|cart|"
    r"document|entity|file|id|ids|invoice|job|key|member|membership|object|"
    r"order|organization|organisation|owner|project|resource|result|session|"
    r"team|tenant|token|url|user|uuid)(?:$|[_-])|(?:id|ids|key|token|url)$",
    re.IGNORECASE,
)
_HIGH_VALUE_OPERATION = re.compile(
    r"(?:^|[^a-z0-9])(?:admin|backup|billing|credential|delete|download|export|"
    r"impersonate|invite|key|membership|payout|permission|recover|reset|role|"
    r"secret|token|transfer|webhook|withdraw)(?:[^a-z0-9]|$)",
    re.IGNORECASE,
)
_GRAPHQL_OPERATION = re.compile(r"^[_A-Za-z][_0-9A-Za-z]{0,127}$")
_SOURCE_REF = re.compile(r"^source_ref:[0-9a-f]{64}$")
_SAFE_PATH_TERMS = frozenset(
    {
        "admin",
        "api",
        "artifact",
        "artifacts",
        "asset",
        "assets",
        "backup",
        "backups",
        "billing",
        "callback",
        "callbacks",
        "cart",
        "carts",
        "complete",
        "config",
        "create",
        "delete",
        "document",
        "documents",
        "download",
        "export",
        "file",
        "files",
        "graphql",
        "import",
        "invoice",
        "invoices",
        "invite",
        "invites",
        "job",
        "jobs",
        "key",
        "keys",
        "member",
        "members",
        "membership",
        "memberships",
        "new",
        "order",
        "orders",
        "organization",
        "organizations",
        "payout",
        "payouts",
        "permission",
        "permissions",
        "project",
        "projects",
        "recover",
        "reset",
        "resource",
        "resources",
        "result",
        "results",
        "role",
        "roles",
        "session",
        "sessions",
        "settings",
        "status",
        "team",
        "teams",
        "tenant",
        "tenants",
        "token",
        "tokens",
        "transfer",
        "update",
        "upload",
        "user",
        "users",
        "v1",
        "v2",
        "v3",
        "verify",
        "webhook",
        "webhooks",
        "withdraw",
    }
)


class CapabilityKind(str, Enum):
    """Semantic facts that can be required or produced by an operation."""

    CONTEXT = "context"
    RESOURCE = "resource"
    STATE = "state"
    VALUE = "value"
    WITNESS = "witness"


class OperationSafety(str, Enum):
    """Static execution posture; this module still never executes a step."""

    READ_ONLY = "read_only"
    OWNED_REVERSIBLE_WRITE = "owned_reversible_write"
    EXTERNAL_EFFECT = "external_effect"
    DESTRUCTIVE = "destructive"
    UNKNOWN = "unknown"


def _semantic_name(value: str, *, field_name: str) -> str:
    separated = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", str(value).strip())
    normalized = re.sub(r"[^a-z0-9_.:-]+", "_", separated.lower()).strip("_")
    if not normalized or not _SEMANTIC_NAME.fullmatch(normalized):
        raise ValueError(f"{field_name} must be a bounded semantic name")
    return normalized


@dataclass(frozen=True)
class Capability:
    kind: CapabilityKind
    name: str

    def __post_init__(self) -> None:
        if not isinstance(self.kind, CapabilityKind):
            raise ValueError("capability kind must be a CapabilityKind")
        object.__setattr__(self, "name", _semantic_name(self.name, field_name="capability name"))

    @property
    def key(self) -> str:
        return f"{self.kind.value}:{self.name}"

    def to_dict(self) -> Dict[str, str]:
        return {"kind": self.kind.value, "name": self.name, "key": self.key}


def _unique_capabilities(values: Iterable[Capability]) -> Tuple[Capability, ...]:
    return tuple(sorted(set(values), key=lambda item: item.key))


@dataclass(frozen=True)
class OperationContract:
    """Redacted transformation learned from one or more captured exchanges."""

    operation_id: str
    label: str
    requires: Tuple[Capability, ...]
    produces: Tuple[Capability, ...]
    safety: OperationSafety = OperationSafety.UNKNOWN
    cost: int = 1
    observed_success: bool = False
    source_refs: Tuple[str, ...] = ()
    requires_owned_state: bool = False
    cleanup_operation_id: Optional[str] = None

    def __post_init__(self) -> None:
        normalized_operation_id = _semantic_name(
            self.operation_id,
            field_name="operation_id",
        )
        object.__setattr__(self, "operation_id", normalized_operation_id)
        if not self.label or len(self.label) > 256:
            raise ValueError("operation label must be present and bounded")
        if not isinstance(self.cost, int) or isinstance(self.cost, bool) or self.cost <= 0:
            raise ValueError("operation cost must be a positive integer")
        if not isinstance(self.safety, OperationSafety):
            raise ValueError("operation safety must be an OperationSafety")
        if self.cleanup_operation_id is not None:
            object.__setattr__(
                self,
                "cleanup_operation_id",
                _semantic_name(
                    self.cleanup_operation_id,
                    field_name="cleanup_operation_id",
                ),
            )
        object.__setattr__(self, "requires", _unique_capabilities(self.requires))
        object.__setattr__(self, "produces", _unique_capabilities(self.produces))
        object.__setattr__(self, "source_refs", tuple(sorted(set(self.source_refs))))
        if any(
            not isinstance(value, str) or not _SOURCE_REF.fullmatch(value)
            for value in self.source_refs
        ):
            raise ValueError("source_refs must contain only redacted source_ref hashes")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "operation_id": self.operation_id,
            "label": self.label,
            "requires": [item.to_dict() for item in self.requires],
            "produces": [item.to_dict() for item in self.produces],
            "safety": self.safety.value,
            "cost": self.cost,
            "observed_success": self.observed_success,
            "source_refs": list(self.source_refs),
            "requires_owned_state": self.requires_owned_state,
            "cleanup_operation_id": self.cleanup_operation_id,
        }


@dataclass(frozen=True)
class BackwardGoal:
    """A terminal operation plus the outputs that make its result meaningful."""

    goal_id: str
    terminal_operation_id: str
    required_outputs: Tuple[Capability, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "goal_id",
            _semantic_name(self.goal_id, field_name="goal_id"),
        )
        object.__setattr__(
            self,
            "terminal_operation_id",
            _semantic_name(
                self.terminal_operation_id,
                field_name="terminal_operation_id",
            ),
        )
        object.__setattr__(self, "required_outputs", _unique_capabilities(self.required_outputs))


@dataclass(frozen=True)
class CompilerLimits:
    max_operations: int = 4_096
    max_search_states: int = 16_384
    max_plan_steps: int = 32

    def __post_init__(self) -> None:
        for name, value in vars(self).items():
            if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")


@dataclass(frozen=True)
class OperationCatalogLimits:
    max_records: int = 4_096
    max_body_chars: int = 2 * 1024 * 1024
    max_total_body_chars: int = 16 * 1024 * 1024
    max_operations: int = 4_096
    max_capabilities_per_operation: int = 512

    def __post_init__(self) -> None:
        for name, value in vars(self).items():
            if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")


@dataclass(frozen=True)
class CompilerPolicy:
    """Static planning policy, not an execution authorization."""

    allowed_safety: Tuple[OperationSafety, ...] = (
        OperationSafety.READ_ONLY,
        OperationSafety.OWNED_REVERSIBLE_WRITE,
    )
    require_observed_success: bool = True
    require_cleanup_for_writes: bool = True

    def __post_init__(self) -> None:
        if not self.allowed_safety:
            raise ValueError("allowed_safety cannot be empty")
        if any(not isinstance(value, OperationSafety) for value in self.allowed_safety):
            raise ValueError("allowed_safety values must be OperationSafety members")
        object.__setattr__(self, "allowed_safety", tuple(dict.fromkeys(self.allowed_safety)))


@dataclass(frozen=True)
class BackwardPlan:
    goal_id: str
    terminal_operation_id: str
    status: str
    step_ids: Tuple[str, ...]
    missing_capabilities: Tuple[Capability, ...]
    execution_blockers: Tuple[str, ...]
    explored_states: int
    search_exhausted: bool
    catalog_digest: str
    policy_digest: str
    plan_id: str
    mode: str = ANALYSIS_ONLY_MODE
    executable: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": 1,
            "mode": self.mode,
            "executable": self.executable,
            "plan_id": self.plan_id,
            "goal_id": self.goal_id,
            "terminal_operation_id": self.terminal_operation_id,
            "status": self.status,
            "step_ids": list(self.step_ids),
            "missing_capabilities": [item.to_dict() for item in self.missing_capabilities],
            "execution_blockers": list(self.execution_blockers),
            "explored_states": self.explored_states,
            "search_exhausted": self.search_exhausted,
            "catalog_digest": self.catalog_digest,
            "policy_digest": self.policy_digest,
        }


def _execution_blockers(
    steps: Sequence[OperationContract],
    *,
    policy: CompilerPolicy,
) -> Tuple[str, ...]:
    blockers: set[str] = set()
    allowed = set(policy.allowed_safety)
    for operation in steps:
        if operation.safety not in allowed:
            blockers.add(f"safety:{operation.operation_id}:{operation.safety.value}")
        if policy.require_observed_success and not operation.observed_success:
            blockers.add(f"unobserved_success:{operation.operation_id}")
        if operation.requires_owned_state:
            blockers.add(f"ownership_rehydration_required:{operation.operation_id}")
        if (
            policy.require_cleanup_for_writes
            and operation.safety == OperationSafety.OWNED_REVERSIBLE_WRITE
            and operation.cleanup_operation_id is None
        ):
            blockers.add(f"cleanup_required:{operation.operation_id}")
    blockers.add("analysis_only_no_execution_authority")
    return tuple(sorted(blockers))


def _ordered_steps(
    selected: frozenset[str],
    *,
    terminal: OperationContract,
    operations: Mapping[str, OperationContract],
    initial: frozenset[Capability],
) -> tuple[Optional[Tuple[str, ...]], Tuple[Capability, ...]]:
    available = set(initial)
    remaining = set(selected)
    ordered: list[str] = []
    while remaining:
        ready = [
            operations[operation_id]
            for operation_id in remaining
            if set(operations[operation_id].requires) <= available
        ]
        if not ready:
            missing = {
                capability
                for operation_id in remaining
                for capability in operations[operation_id].requires
                if capability not in available
            }
            return None, _unique_capabilities(missing)
        operation = min(ready, key=lambda item: (item.cost, item.operation_id))
        ordered.append(operation.operation_id)
        available.update(operation.produces)
        remaining.remove(operation.operation_id)
    terminal_missing = set(terminal.requires) - available
    if terminal_missing:
        return None, _unique_capabilities(terminal_missing)
    return tuple((*ordered, terminal.operation_id)), ()


class BackwardExploitCompiler:
    """Bounded best-first search over typed operation prerequisites."""

    def __init__(
        self,
        operations: Sequence[OperationContract],
        *,
        policy: Optional[CompilerPolicy] = None,
        limits: Optional[CompilerLimits] = None,
    ) -> None:
        self.policy = policy or CompilerPolicy()
        self.limits = limits or CompilerLimits()
        if len(operations) > self.limits.max_operations:
            raise ValueError("operation catalog exceeds max_operations")
        by_id: Dict[str, OperationContract] = {}
        for operation in operations:
            if operation.operation_id in by_id:
                raise ValueError(f"duplicate operation_id: {operation.operation_id}")
            by_id[operation.operation_id] = operation
        self.operations = by_id
        self.catalog_digest = stable_hash(
            "operation_catalog",
            [by_id[key].to_dict() for key in sorted(by_id)],
        )
        self.policy_digest = stable_hash(
            "compiler_policy",
            {
                "allowed_safety": sorted(item.value for item in self.policy.allowed_safety),
                "require_observed_success": self.policy.require_observed_success,
                "require_cleanup_for_writes": self.policy.require_cleanup_for_writes,
                "limits": vars(self.limits),
            },
        )
        producers: Dict[Capability, list[OperationContract]] = {}
        for operation in operations:
            for capability in operation.produces:
                producers.setdefault(capability, []).append(operation)
        self.producers = {
            capability: tuple(
                sorted(
                    candidates,
                    key=lambda item: (
                        item.safety not in self.policy.allowed_safety,
                        not item.observed_success,
                        item.cost,
                        item.operation_id,
                    ),
                )
            )
            for capability, candidates in producers.items()
        }

    def _priority(self, selected: frozenset[str]) -> tuple[Any, ...]:
        operations = [self.operations[item] for item in selected]
        unsafe = sum(item.safety not in self.policy.allowed_safety for item in operations)
        unobserved = sum(not item.observed_success for item in operations)
        return (
            unsafe,
            unobserved,
            len(selected),
            sum(item.cost for item in operations),
            tuple(sorted(selected)),
        )

    def compile(
        self,
        goal: BackwardGoal,
        *,
        initial_capabilities: Sequence[Capability] = (),
    ) -> BackwardPlan:
        terminal = self.operations.get(goal.terminal_operation_id)
        if terminal is None:
            return self._blocked(
                goal,
                step_ids=(),
                missing=(),
                blockers=("terminal_operation_not_found",),
                explored_states=0,
                exhausted=False,
            )
        missing_outputs = set(goal.required_outputs) - set(terminal.produces)
        if missing_outputs:
            return self._blocked(
                goal,
                step_ids=(terminal.operation_id,),
                missing=_unique_capabilities(missing_outputs),
                blockers=("terminal_does_not_produce_required_output",),
                explored_states=0,
                exhausted=False,
            )

        initial = frozenset(initial_capabilities)
        queue: list[tuple[Any, int, frozenset[str]]] = []
        serial = 0
        start: frozenset[str] = frozenset()
        heapq.heappush(queue, (self._priority(start), serial, start))
        visited: set[frozenset[str]] = set()
        explored = 0
        dead_missing: set[Capability] = set()
        dead_blockers: set[str] = set()
        best_partial: Tuple[str, ...] = (terminal.operation_id,)

        while queue and explored < self.limits.max_search_states:
            _priority, _serial, selected = heapq.heappop(queue)
            if selected in visited:
                continue
            visited.add(selected)
            explored += 1
            ordered, missing = _ordered_steps(
                selected,
                terminal=terminal,
                operations=self.operations,
                initial=initial,
            )
            if ordered is not None:
                steps = tuple(self.operations[item] for item in ordered)
                blockers = _execution_blockers(steps, policy=self.policy)
                payload = {
                    "goal_id": goal.goal_id,
                    "terminal_operation_id": goal.terminal_operation_id,
                    "step_ids": ordered,
                    "initial_capabilities": sorted(item.key for item in initial),
                    "catalog_digest": self.catalog_digest,
                    "policy_digest": self.policy_digest,
                }
                return BackwardPlan(
                    goal_id=goal.goal_id,
                    terminal_operation_id=goal.terminal_operation_id,
                    status="planned",
                    step_ids=ordered,
                    missing_capabilities=(),
                    execution_blockers=blockers,
                    explored_states=explored,
                    search_exhausted=False,
                    catalog_digest=self.catalog_digest,
                    policy_digest=self.policy_digest,
                    plan_id=stable_hash("backward_plan", payload),
                )

            if len(selected) + 1 >= self.limits.max_plan_steps:
                dead_missing.update(missing)
                dead_blockers.add("max_plan_steps_reached")
                continue
            target = min(missing, key=lambda item: item.key)
            candidates = [
                item
                for item in self.producers.get(target, ())
                if item.operation_id != terminal.operation_id
                and item.operation_id not in selected
            ]
            if not candidates:
                dead_missing.add(target)
                if target not in self.producers:
                    dead_blockers.add(f"no_producer:{target.key}")
                else:
                    dead_blockers.add(f"cyclic_or_unreachable:{target.key}")
                continue
            best_partial = tuple((*sorted(selected), terminal.operation_id))
            for candidate in candidates:
                next_selected = frozenset((*selected, candidate.operation_id))
                if next_selected in visited:
                    continue
                serial += 1
                heapq.heappush(
                    queue,
                    (self._priority(next_selected), serial, next_selected),
                )

        exhausted = bool(queue) and explored >= self.limits.max_search_states
        if exhausted:
            dead_blockers.add("max_search_states_reached")
        if not dead_blockers:
            dead_blockers.add("no_prerequisite_plan")
        return self._blocked(
            goal,
            step_ids=best_partial,
            missing=_unique_capabilities(dead_missing),
            blockers=tuple(sorted(dead_blockers)),
            explored_states=explored,
            exhausted=exhausted,
        )

    def _blocked(
        self,
        goal: BackwardGoal,
        *,
        step_ids: Tuple[str, ...],
        missing: Tuple[Capability, ...],
        blockers: Tuple[str, ...],
        explored_states: int,
        exhausted: bool,
    ) -> BackwardPlan:
        payload = {
            "goal_id": goal.goal_id,
            "terminal_operation_id": goal.terminal_operation_id,
            "step_ids": step_ids,
            "missing": [item.key for item in missing],
            "blockers": list(blockers),
            "catalog_digest": self.catalog_digest,
            "policy_digest": self.policy_digest,
        }
        return BackwardPlan(
            goal_id=goal.goal_id,
            terminal_operation_id=goal.terminal_operation_id,
            status="blocked",
            step_ids=step_ids,
            missing_capabilities=missing,
            execution_blockers=tuple(sorted(set((*blockers, "analysis_only_no_execution_authority")))),
            explored_states=explored_states,
            search_exhausted=exhausted,
            catalog_digest=self.catalog_digest,
            policy_digest=self.policy_digest,
            plan_id=stable_hash("backward_plan", payload),
        )


def _shape_capabilities(shape: Mapping[str, Any]) -> Tuple[Capability, ...]:
    output: set[Capability] = set()

    def capability_name(path: Tuple[str, ...]) -> str:
        leaf = path[-1]
        if leaf in {"id", "ids", "key", "token", "url", "uuid"} and len(path) >= 2:
            parent = path[-2]
            if parent.endswith("s") and len(parent) > 1:
                parent = parent[:-1]
            return f"{parent}_{leaf}"
        return leaf

    def walk(value: Any, path: Tuple[str, ...] = ()) -> None:
        if not isinstance(value, Mapping):
            return
        if value.get("kind") == "object":
            fields = value.get("fields")
            if isinstance(fields, Mapping):
                for key, child in fields.items():
                    field = _semantic_name(str(key), field_name="shape field")
                    next_path = (*path, field)
                    if _CAPABILITY_FIELD.search(field):
                        output.add(Capability(CapabilityKind.VALUE, capability_name(next_path)))
                    walk(child, next_path)
        elif value.get("kind") == "array":
            variants = value.get("item_variants")
            if isinstance(variants, list):
                for child in variants:
                    walk(child, path)

    walk(shape)
    return _unique_capabilities(output)


def _path_capabilities(path_template: str) -> Tuple[Capability, ...]:
    segments = [segment for segment in path_template.split("/") if segment]
    output: set[Capability] = set()
    for index, segment in enumerate(segments):
        if segment != "{id}":
            continue
        parent = segments[index - 1] if index else "resource"
        singular = parent[:-1] if parent.endswith("s") and len(parent) > 1 else parent
        output.add(Capability(CapabilityKind.VALUE, f"{singular}_id"))
    return _unique_capabilities(output)


def _graphql_label(record: Mapping[str, Any]) -> Optional[str]:
    raw = record.get("request_body")
    if not isinstance(raw, str) or not raw:
        return None
    try:
        parsed = json.loads(raw)
    except (TypeError, ValueError):
        return None
    if isinstance(parsed, list):
        items = parsed
    else:
        items = [parsed]
    names = {
        str(item.get("operationName") or item.get("operation_name") or "").strip()
        for item in items
        if isinstance(item, Mapping)
    }
    names.discard("")
    if len(names) != 1:
        return None
    name = next(iter(names))
    return name if _GRAPHQL_OPERATION.fullmatch(name) else None


def _redacted_rest_label(method: str, path_template: str) -> str:
    segments: list[str] = []
    for raw_segment in path_template.split("/"):
        if not raw_segment:
            continue
        segment = raw_segment.lower()
        if segment in {"{id}", "{value}"}:
            segments.append(segment)
        elif segment in _SAFE_PATH_TERMS:
            segments.append(segment)
        else:
            segments.append("{value}")
    path = "/" + "/".join(segments) if segments else "/"
    return f"{method} {path}"


def operation_contracts_from_records(
    records: Sequence[Mapping[str, Any]],
    *,
    world_id: str = "captured",
    limits: Optional[OperationCatalogLimits] = None,
) -> Tuple[OperationContract, ...]:
    """Build redacted operation contracts from already-captured exchanges.

    The adapter intentionally infers only semantic field names and path slots.
    Non-read operations remain ``UNKNOWN`` safety and therefore blocked by the
    default compiler policy.  No raw identifier, token, URL value, or body is
    retained in the returned catalog.
    """

    active_limits = limits or OperationCatalogLimits()
    if len(records) > active_limits.max_records:
        raise ValueError("record catalog exceeds max_records")
    total_body_chars = 0
    for record in records:
        for field in ("request_body", "response_body"):
            body = record.get(field)
            if not isinstance(body, str):
                continue
            if len(body) > active_limits.max_body_chars:
                raise ValueError(f"{field} exceeds max_body_chars")
            total_body_chars += len(body)
            if total_body_chars > active_limits.max_total_body_chars:
                raise ValueError("record catalog exceeds max_total_body_chars")

    grouped: Dict[str, Dict[str, Any]] = {}
    for index, record in enumerate(records):
        try:
            exchange = normalize_exchange(
                record,
                source_id=str(record.get("id") or index),
                world_id=str(record.get("persona_id") or world_id),
            )
        except (TypeError, ValueError):
            continue
        graphql_name = _graphql_label(record)
        label = graphql_name or _redacted_rest_label(
            exchange.method,
            exchange.path_template,
        )
        requires = set(_path_capabilities(exchange.path_template))
        requires.update(_shape_capabilities(exchange.request_shape))
        requires.update(
            Capability(CapabilityKind.VALUE, key)
            for key in exchange.query_keys
            if _CAPABILITY_FIELD.search(key)
        )
        produces = set(_shape_capabilities(exchange.response_shape))
        if 200 <= exchange.response_status < 300:
            produces.add(Capability(CapabilityKind.STATE, f"response.{exchange.state_id[-16:]}"))
        safety = (
            OperationSafety.READ_ONLY
            if exchange.method in {"GET", "HEAD", "OPTIONS"}
            else OperationSafety.UNKNOWN
        )
        existing = grouped.get(exchange.action_id)
        if existing is None:
            grouped[exchange.action_id] = {
                "label": label,
                "requires": requires,
                "produces": produces,
                "safety": safety,
                "observed_success": 200 <= exchange.response_status < 300,
                "source_refs": {exchange.source_id},
            }
        else:
            existing["requires"].update(requires)
            existing["produces"].update(produces)
            existing["observed_success"] = bool(
                existing["observed_success"] or 200 <= exchange.response_status < 300
            )
            existing["source_refs"].add(exchange.source_id)

        if len(grouped) > active_limits.max_operations:
            raise ValueError("operation catalog exceeds max_operations")

    for value in grouped.values():
        if (
            len(value["requires"]) > active_limits.max_capabilities_per_operation
            or len(value["produces"]) > active_limits.max_capabilities_per_operation
        ):
            raise ValueError("operation exceeds max_capabilities_per_operation")

    return tuple(
        OperationContract(
            operation_id=operation_id,
            label=value["label"],
            requires=tuple(value["requires"]),
            produces=tuple(value["produces"]),
            safety=value["safety"],
            observed_success=bool(value["observed_success"]),
            source_refs=tuple(value["source_refs"]),
        )
        for operation_id, value in sorted(grouped.items())
    )


def high_value_goals(operations: Sequence[OperationContract]) -> Tuple[BackwardGoal, ...]:
    """Return deterministic terminal goals without claiming vulnerability."""

    return tuple(
        BackwardGoal(
            goal_id=stable_hash("backward_goal", operation.operation_id),
            terminal_operation_id=operation.operation_id,
        )
        for operation in sorted(operations, key=lambda item: item.operation_id)
        if _HIGH_VALUE_OPERATION.search(
            re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", operation.label)
        )
    )


__all__ = [
    "ANALYSIS_ONLY_MODE",
    "BackwardExploitCompiler",
    "BackwardGoal",
    "BackwardPlan",
    "Capability",
    "CapabilityKind",
    "CompilerLimits",
    "CompilerPolicy",
    "OperationContract",
    "OperationCatalogLimits",
    "OperationSafety",
    "high_value_goals",
    "operation_contracts_from_records",
]
