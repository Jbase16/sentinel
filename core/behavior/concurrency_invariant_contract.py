"""R5F1: passive, unwired concurrency-invariant contracts and logical replay.

No production entry point imports this module. It adds no authority of any kind.
The evaluator runs a deterministic offline logical schedule, with no real
concurrency, threads, async execution, or clock. Its result is not independent
evidence of an observed target-side effect. Running-workflow effect proof and
native OCB-S22 are deferred to the active tail.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum
from itertools import permutations
from typing import Any, Mapping

from .experiment_sdk import ExperimentWorldBinding, ExperimentWorldKind, _hash_ref
from .normalize import stable_hash
from .payout_goals import ProofTopology

MAX_ACTORS = 6
MAX_CONCURRENCY_OPERATIONS = 12
MAX_SCHEDULE_STEPS = 2 * MAX_CONCURRENCY_OPERATIONS
MAX_RESOURCE_VALUE = 2**63 - 1
CONCURRENCY_INVARIANT_CONTRACT_MODE = "behavioral_concurrency_invariant_contract_v1"


def _integer(
    value: object, minimum: int = 0, maximum: int = MAX_RESOURCE_VALUE
) -> bool:
    return type(value) is int and minimum <= value <= maximum


def _fields(value: object, expected: set[str]) -> Mapping[str, Any]:
    if (
        not isinstance(value, Mapping)
        or set(value) != expected | {"schema_version"}
        or type(value.get("schema_version")) is not int
        or value["schema_version"] != 1
    ):
        raise ValueError("concurrency serialization is invalid")
    return value


def _revalidate(value: Any) -> None:
    """Rebuild and discard a frozen value to rerun its validation."""
    replace(value)


def _passive_flags() -> dict[str, bool | int]:
    return {
        "target_requests_sent": 0,
        "executable": False,
        "promotion_authority": False,
        "finding_authority": False,
        "backend_dispatch_authority": False,
        "budget_reserved": False,
        "orphan_risk": False,
        "disposable": True,
        "reversible": True,
        "cleanup_required": False,
    }


class SharedStateSchema(str, Enum):
    AGGREGATE_LIMIT = "aggregate_limit_v1"


class ConcurrencyInvariantPredicate(str, Enum):
    CONSUMED_WITHIN_LIMIT = "consumed_within_declared_limit"


class ConcurrencyGuard(str, Enum):
    PER_OPERATION_CAP = "per_operation_cap"
    PER_OPERATION_AND_AGGREGATE_CAP = "per_operation_and_aggregate_cap"


class ConcurrencyGuardMode(str, Enum):
    OBSERVE_TIME_ONLY = "observe_time_only"
    COMMIT_TIME_CAS = "commit_time_cas"


class ConcurrencyTransition(str, Enum):
    CONSUME = "consume"


class StepKind(str, Enum):
    OBSERVE = "observe"
    COMMIT = "commit"


class ConcurrencyOutcome(str, Enum):
    INVARIANT_HELD = "invariant_held"
    INVARIANT_VIOLATED = "invariant_violated"
    OPERATION_REFUSED = "operation_refused"
    MALFORMED = "malformed"


class CommitRefusal(str, Enum):
    OBSERVE_GUARD = "observe_guard_refused"
    CAS_VERSION = "cas_version_mismatch"
    COMMIT_AGGREGATE = "commit_aggregate_refused"
    RESOURCE_VALUE = "resource_value_exhausted"


@dataclass(frozen=True)
class SharedWorkflowState:
    consumed: int
    declared_limit: int
    per_op_cap: int
    version: int = 0
    schema: SharedStateSchema = SharedStateSchema.AGGREGATE_LIMIT

    def __post_init__(self) -> None:
        if (
            self.schema is not SharedStateSchema.AGGREGATE_LIMIT
            or not _integer(self.consumed)
            or not _integer(self.declared_limit)
            or not _integer(self.per_op_cap, 1)
            or not _integer(self.version)
        ):
            raise ValueError("concurrency shared state is invalid")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "schema": self.schema.value,
            "consumed": self.consumed,
            "declared_limit": self.declared_limit,
            "per_op_cap": self.per_op_cap,
            "version": self.version,
        }

    @property
    def state_id(self) -> str:
        return stable_hash("concurrency_shared_state", self.to_dict())

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> SharedWorkflowState:
        value = _fields(
            value, {"schema", "consumed", "declared_limit", "per_op_cap", "version"}
        )
        return cls(
            consumed=value["consumed"],
            declared_limit=value["declared_limit"],
            per_op_cap=value["per_op_cap"],
            version=value["version"],
            schema=SharedStateSchema(value["schema"]),
        )


def evaluate_invariant(
    predicate: ConcurrencyInvariantPredicate, terminal_state: SharedWorkflowState
) -> bool:
    """Read only the terminal shared state, independently of guard and commit."""
    if predicate is not ConcurrencyInvariantPredicate.CONSUMED_WITHIN_LIMIT:
        raise ValueError("unsupported concurrency invariant")
    if type(terminal_state) is not SharedWorkflowState:
        raise ValueError("invalid terminal shared state")
    _revalidate(terminal_state)
    return terminal_state.consumed <= terminal_state.declared_limit


@dataclass(frozen=True)
class ConcurrencyOperation:
    operation_ref: str
    actor_ref: str
    op_index: int
    amount: int
    guard_mode: ConcurrencyGuardMode
    guard: ConcurrencyGuard = ConcurrencyGuard.PER_OPERATION_AND_AGGREGATE_CAP
    transition: ConcurrencyTransition = ConcurrencyTransition.CONSUME
    single_application: bool = True

    def __post_init__(self) -> None:
        if (
            not _hash_ref(self.operation_ref, "concurrency_operation")
            or not _hash_ref(self.actor_ref)
            or not _integer(self.op_index, 0, MAX_CONCURRENCY_OPERATIONS - 1)
            or not _integer(self.amount, 1)
            or type(self.guard_mode) is not ConcurrencyGuardMode
            or type(self.guard) is not ConcurrencyGuard
            or self.transition is not ConcurrencyTransition.CONSUME
            or self.single_application is not True
        ):
            raise ValueError("concurrency operation is invalid")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "operation_ref": self.operation_ref,
            "actor_ref": self.actor_ref,
            "op_index": self.op_index,
            "amount": self.amount,
            "guard_mode": self.guard_mode.value,
            "guard": self.guard.value,
            "transition": self.transition.value,
            "single_application": self.single_application,
        }

    @property
    def operation_id(self) -> str:
        return stable_hash("concurrency_operation_contract", self.to_dict())

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> ConcurrencyOperation:
        value = _fields(
            value,
            {
                "operation_ref",
                "actor_ref",
                "op_index",
                "amount",
                "guard_mode",
                "guard",
                "transition",
                "single_application",
            },
        )
        return cls(
            operation_ref=value["operation_ref"],
            actor_ref=value["actor_ref"],
            op_index=value["op_index"],
            amount=value["amount"],
            guard_mode=ConcurrencyGuardMode(value["guard_mode"]),
            guard=ConcurrencyGuard(value["guard"]),
            transition=ConcurrencyTransition(value["transition"]),
            single_application=value["single_application"],
        )


def operation_guard(
    state: SharedWorkflowState, operation: ConcurrencyOperation
) -> bool:
    """Evaluate only the operation's declared guard against the observed state."""
    if (
        type(state) is not SharedWorkflowState
        or type(operation) is not ConcurrencyOperation
    ):
        raise ValueError("invalid concurrency guard inputs")
    _revalidate(state)
    _revalidate(operation)
    return operation.amount <= state.per_op_cap and (
        operation.guard is ConcurrencyGuard.PER_OPERATION_CAP
        or state.consumed + operation.amount <= state.declared_limit
    )


def apply_commit(
    state: SharedWorkflowState,
    operation: ConcurrencyOperation,
    observation: tuple[int, bool],
) -> SharedWorkflowState | CommitRefusal:
    """Apply the carried observation; CAS additionally checks the current state."""
    if (
        type(state) is not SharedWorkflowState
        or type(operation) is not ConcurrencyOperation
        or type(observation) is not tuple
        or len(observation) != 2
        or not _integer(observation[0])
        or type(observation[1]) is not bool
    ):
        raise ValueError("invalid concurrency commit inputs")
    _revalidate(state)
    _revalidate(operation)
    observed_version, guard_passed = observation
    if not guard_passed:
        return CommitRefusal.OBSERVE_GUARD
    if operation.guard_mode is ConcurrencyGuardMode.COMMIT_TIME_CAS:
        if state.version != observed_version:
            return CommitRefusal.CAS_VERSION
        if state.consumed + operation.amount > state.declared_limit:
            return CommitRefusal.COMMIT_AGGREGATE
    if (
        state.consumed + operation.amount > MAX_RESOURCE_VALUE
        or state.version == MAX_RESOURCE_VALUE
    ):
        return CommitRefusal.RESOURCE_VALUE
    return replace(
        state, consumed=state.consumed + operation.amount, version=state.version + 1
    )


@dataclass(frozen=True)
class ConcurrencyInvariantContract:
    contract_id: str
    resource_ref: str
    tenant_ref: str
    tenant_ownership_ref: str
    initial_state: SharedWorkflowState
    operations: tuple[ConcurrencyOperation, ...]
    max_actors: int
    invariant: ConcurrencyInvariantPredicate = (
        ConcurrencyInvariantPredicate.CONSUMED_WITHIN_LIMIT
    )
    state_schema: SharedStateSchema = SharedStateSchema.AGGREGATE_LIMIT
    mode: str = CONCURRENCY_INVARIANT_CONTRACT_MODE

    def _payload(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "resource_ref": self.resource_ref,
            "tenant_ref": self.tenant_ref,
            "tenant_ownership_ref": self.tenant_ownership_ref,
            "initial_state": self.initial_state.to_dict(),
            "operations": [op.to_dict() for op in self.operations],
            "max_actors": self.max_actors,
            "invariant": self.invariant.value,
            "state_schema": self.state_schema.value,
        }

    @classmethod
    def build(
        cls,
        *,
        resource_ref: str,
        tenant_ref: str,
        tenant_ownership_ref: str,
        initial_state: SharedWorkflowState,
        operations: tuple[ConcurrencyOperation, ...],
        max_actors: int = MAX_ACTORS,
        invariant: ConcurrencyInvariantPredicate = ConcurrencyInvariantPredicate.CONSUMED_WITHIN_LIMIT,
        state_schema: SharedStateSchema = SharedStateSchema.AGGREGATE_LIMIT,
    ) -> ConcurrencyInvariantContract:
        if (
            type(initial_state) is not SharedWorkflowState
            or type(operations) is not tuple
            or any(type(op) is not ConcurrencyOperation for op in operations)
            or type(invariant) is not ConcurrencyInvariantPredicate
            or type(state_schema) is not SharedStateSchema
        ):
            raise ValueError("invalid concurrency contract inputs")
        payload = {
            "mode": CONCURRENCY_INVARIANT_CONTRACT_MODE,
            "resource_ref": resource_ref,
            "tenant_ref": tenant_ref,
            "tenant_ownership_ref": tenant_ownership_ref,
            "initial_state": initial_state.to_dict(),
            "operations": [op.to_dict() for op in operations],
            "max_actors": max_actors,
            "invariant": invariant.value,
            "state_schema": state_schema.value,
        }
        return cls(
            stable_hash("concurrency_invariant_contract", payload),
            resource_ref,
            tenant_ref,
            tenant_ownership_ref,
            initial_state,
            operations,
            max_actors,
            invariant,
            state_schema,
        )

    def __post_init__(self) -> None:
        if (
            type(self.initial_state) is not SharedWorkflowState
            or type(self.operations) is not tuple
            or not 2 <= len(self.operations) <= MAX_CONCURRENCY_OPERATIONS
            or self.invariant is not ConcurrencyInvariantPredicate.CONSUMED_WITHIN_LIMIT
            or self.state_schema is not SharedStateSchema.AGGREGATE_LIMIT
            or self.mode != CONCURRENCY_INVARIANT_CONTRACT_MODE
        ):
            raise ValueError("concurrency contract is invalid")
        _revalidate(self.initial_state)
        for operation in self.operations:
            if type(operation) is not ConcurrencyOperation:
                raise ValueError("invalid concurrency operation type")
            _revalidate(operation)
        actors = {op.actor_ref for op in self.operations}
        if (
            not _hash_ref(self.resource_ref)
            or not _hash_ref(self.tenant_ref, "owned_tenant")
            or not _hash_ref(self.tenant_ownership_ref, "ownership_proof")
            or not _integer(self.max_actors, 2, MAX_ACTORS)
            or not 2 <= len(actors) <= self.max_actors
            or not evaluate_invariant(self.invariant, self.initial_state)
            or len({op.operation_ref for op in self.operations}) != len(self.operations)
            or any(
                tuple(op.op_index for op in self.operations if op.actor_ref == actor)
                != tuple(range(sum(op.actor_ref == actor for op in self.operations)))
                for actor in actors
            )
            or not _hash_ref(self.contract_id, "concurrency_invariant_contract")
            or self.contract_id
            != stable_hash("concurrency_invariant_contract", self._payload())
        ):
            raise ValueError("concurrency contract is invalid")

    def to_dict(self) -> dict[str, Any]:
        return {"schema_version": 1, "contract_id": self.contract_id, **self._payload()}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> ConcurrencyInvariantContract:
        value = _fields(
            value,
            {
                "contract_id",
                "mode",
                "resource_ref",
                "tenant_ref",
                "tenant_ownership_ref",
                "initial_state",
                "operations",
                "max_actors",
                "invariant",
                "state_schema",
            },
        )
        if type(value["operations"]) is not list:
            raise ValueError("invalid concurrency operations serialization")
        return cls(
            contract_id=value["contract_id"],
            resource_ref=value["resource_ref"],
            tenant_ref=value["tenant_ref"],
            tenant_ownership_ref=value["tenant_ownership_ref"],
            initial_state=SharedWorkflowState.from_dict(value["initial_state"]),
            operations=tuple(
                ConcurrencyOperation.from_dict(op) for op in value["operations"]
            ),
            max_actors=value["max_actors"],
            invariant=ConcurrencyInvariantPredicate(value["invariant"]),
            state_schema=SharedStateSchema(value["state_schema"]),
            mode=value["mode"],
        )


@dataclass(frozen=True)
class MicroStep:
    actor_ref: str
    operation_ref: str
    step_kind: StepKind

    def __post_init__(self) -> None:
        if (
            not _hash_ref(self.actor_ref)
            or not _hash_ref(self.operation_ref, "concurrency_operation")
            or type(self.step_kind) is not StepKind
        ):
            raise ValueError("invalid concurrency micro-step")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "actor_ref": self.actor_ref,
            "operation_ref": self.operation_ref,
            "step_kind": self.step_kind.value,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> MicroStep:
        value = _fields(value, {"actor_ref", "operation_ref", "step_kind"})
        return cls(
            value["actor_ref"], value["operation_ref"], StepKind(value["step_kind"])
        )


@dataclass(frozen=True)
class WorkflowSchedule:
    contract: ConcurrencyInvariantContract
    steps: tuple[MicroStep, ...]

    def __post_init__(self) -> None:
        if (
            type(self.contract) is not ConcurrencyInvariantContract
            or type(self.steps) is not tuple
        ):
            raise ValueError("invalid concurrency schedule types")
        _revalidate(self.contract)
        if (
            len(self.steps) != 2 * len(self.contract.operations)
            or len(self.steps) > MAX_SCHEDULE_STEPS
        ):
            raise ValueError("invalid concurrency schedule length")
        operations = {op.operation_ref: op for op in self.contract.operations}
        actual_by_actor: dict[str, list[tuple[str, StepKind]]] = {}
        for step in self.steps:
            if type(step) is not MicroStep:
                raise ValueError("invalid concurrency step type")
            _revalidate(step)
            operation = operations.get(step.operation_ref)
            if operation is None or step.actor_ref != operation.actor_ref:
                raise ValueError("concurrency schedule operation mismatch")
            actual_by_actor.setdefault(step.actor_ref, []).append(
                (step.operation_ref, step.step_kind)
            )
        for actor in {op.actor_ref for op in self.contract.operations}:
            expected = [
                (op.operation_ref, kind)
                for op in self.contract.operations
                if op.actor_ref == actor
                for kind in (StepKind.OBSERVE, StepKind.COMMIT)
            ]
            if actual_by_actor.get(actor) != expected:
                raise ValueError("concurrency schedule violates actor program order")

    def _payload(self) -> dict[str, Any]:
        return {
            "contract": self.contract.to_dict(),
            "steps": [step.to_dict() for step in self.steps],
            **_passive_flags(),
        }

    @property
    def schedule_id(self) -> str:
        return stable_hash("concurrency_workflow_schedule", self._payload())

    def to_dict(self) -> dict[str, Any]:
        return {"schema_version": 1, "schedule_id": self.schedule_id, **self._payload()}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> WorkflowSchedule:
        value = _fields(value, {"schedule_id", "contract", "steps", *_passive_flags()})
        if type(value["steps"]) is not list:
            raise ValueError("invalid concurrency steps serialization")
        result = cls(
            ConcurrencyInvariantContract.from_dict(value["contract"]),
            tuple(MicroStep.from_dict(step) for step in value["steps"]),
        )
        if value != result.to_dict():
            raise ValueError("concurrency schedule address or flags mismatch")
        return result


def serial_schedules(
    contract: ConcurrencyInvariantContract,
) -> tuple[WorkflowSchedule, ...]:
    if type(contract) is not ConcurrencyInvariantContract:
        raise ValueError("invalid concurrency contract")
    _revalidate(contract)
    actors = tuple(dict.fromkeys(op.actor_ref for op in contract.operations))
    return tuple(
        WorkflowSchedule(
            contract,
            tuple(
                MicroStep(actor, op.operation_ref, kind)
                for actor in actor_order
                for op in contract.operations
                if op.actor_ref == actor
                for kind in (StepKind.OBSERVE, StepKind.COMMIT)
            ),
        )
        for actor_order in permutations(actors)
    )


def _simulate(
    contract: ConcurrencyInvariantContract, schedule: WorkflowSchedule
) -> tuple[ConcurrencyOutcome, SharedWorkflowState, tuple[str, ...], int | None, str]:
    state = contract.initial_state
    operations = {op.operation_ref: op for op in contract.operations}
    observations: dict[str, tuple[int, bool]] = {}
    applied: list[str] = []
    refused_index: int | None = None
    refused_reason = ""
    for index, step in enumerate(schedule.steps):
        operation = operations[step.operation_ref]
        if step.step_kind is StepKind.OBSERVE:
            observations[step.operation_ref] = (
                state.version,
                operation_guard(state, operation),
            )
        else:
            result = apply_commit(
                state, operation, observations.pop(step.operation_ref)
            )
            if type(result) is SharedWorkflowState:
                state = result
                applied.append(step.operation_ref)
            elif refused_index is None:
                refused_index, refused_reason = index, result.value
    if not evaluate_invariant(contract.invariant, state):
        outcome = ConcurrencyOutcome.INVARIANT_VIOLATED
        reason = outcome.value
    elif refused_index is not None:
        outcome = ConcurrencyOutcome.OPERATION_REFUSED
        reason = refused_reason
    else:
        outcome = ConcurrencyOutcome.INVARIANT_HELD
        reason = outcome.value
    return outcome, state, tuple(applied), refused_index, reason


def is_serializable_safe(contract: ConcurrencyInvariantContract) -> bool:
    """Require every complete, non-interleaved actor order to preserve the invariant."""
    return all(
        _simulate(contract, schedule)[0] is not ConcurrencyOutcome.INVARIANT_VIOLATED
        for schedule in serial_schedules(contract)
    )


@dataclass(frozen=True)
class ConcurrencyDecision:
    contract: ConcurrencyInvariantContract | None
    schedule: WorkflowSchedule | None
    outcome: ConcurrencyOutcome
    terminal_state: SharedWorkflowState | None
    applied_operation_refs: tuple[str, ...]
    refused_index: int | None
    reason_code: str
    race_confirmed: bool

    def __post_init__(self) -> None:
        if (
            type(self.outcome) is not ConcurrencyOutcome
            or type(self.applied_operation_refs) is not tuple
        ):
            raise ValueError("invalid concurrency decision")
        if self.outcome is ConcurrencyOutcome.MALFORMED:
            if (
                self.contract is not None
                or self.schedule is not None
                or self.terminal_state is not None
                or self.applied_operation_refs
                or self.refused_index is not None
                or self.reason_code != "invalid_input"
                or self.race_confirmed is not False
            ):
                raise ValueError("malformed decision must contain no untrusted data")
            return
        if (
            type(self.contract) is not ConcurrencyInvariantContract
            or type(self.schedule) is not WorkflowSchedule
            or type(self.terminal_state) is not SharedWorkflowState
            or type(self.race_confirmed) is not bool
        ):
            raise ValueError("invalid concurrency decision context")
        _revalidate(self.contract)
        _revalidate(self.schedule)
        _revalidate(self.terminal_state)
        if self.schedule.contract != self.contract:
            raise ValueError("concurrency decision contract mismatch")
        expected = _simulate(self.contract, self.schedule)
        if (
            self.outcome,
            self.terminal_state,
            self.applied_operation_refs,
            self.refused_index,
            self.reason_code,
        ) != expected or self.race_confirmed != (
            self.outcome is ConcurrencyOutcome.INVARIANT_VIOLATED
            and is_serializable_safe(self.contract)
        ):
            raise ValueError("concurrency decision does not match replay")

    def _payload(self) -> dict[str, Any]:
        return {
            "contract": self.contract.to_dict() if self.contract is not None else None,
            "schedule": self.schedule.to_dict() if self.schedule is not None else None,
            "outcome": self.outcome.value,
            "terminal_state": self.terminal_state.to_dict()
            if self.terminal_state is not None
            else None,
            "applied_operation_refs": list(self.applied_operation_refs),
            "refused_index": self.refused_index,
            "reason_code": self.reason_code,
            "race_confirmed": self.race_confirmed,
            **_passive_flags(),
        }

    @property
    def decision_id(self) -> str:
        return stable_hash("concurrency_invariant_decision", self._payload())

    def to_dict(self) -> dict[str, Any]:
        return {"schema_version": 1, "decision_id": self.decision_id, **self._payload()}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> ConcurrencyDecision:
        value = _fields(
            value,
            {
                "decision_id",
                "contract",
                "schedule",
                "outcome",
                "terminal_state",
                "applied_operation_refs",
                "refused_index",
                "reason_code",
                "race_confirmed",
                *_passive_flags(),
            },
        )
        if type(value["applied_operation_refs"]) is not list:
            raise ValueError("invalid concurrency decision serialization")
        result = cls(
            contract=ConcurrencyInvariantContract.from_dict(value["contract"])
            if value["contract"] is not None
            else None,
            schedule=WorkflowSchedule.from_dict(value["schedule"])
            if value["schedule"] is not None
            else None,
            outcome=ConcurrencyOutcome(value["outcome"]),
            terminal_state=SharedWorkflowState.from_dict(value["terminal_state"])
            if value["terminal_state"] is not None
            else None,
            applied_operation_refs=tuple(value["applied_operation_refs"]),
            refused_index=value["refused_index"],
            reason_code=value["reason_code"],
            race_confirmed=value["race_confirmed"],
        )
        if value != result.to_dict():
            raise ValueError("concurrency decision address or flags mismatch")
        return result


def classify_schedule(
    contract: ConcurrencyInvariantContract,
    initial_state: SharedWorkflowState,
    schedule: WorkflowSchedule,
) -> ConcurrencyDecision:
    try:
        if (
            type(contract) is not ConcurrencyInvariantContract
            or type(initial_state) is not SharedWorkflowState
            or type(schedule) is not WorkflowSchedule
        ):
            raise ValueError("invalid concurrency classifier input types")
        _revalidate(contract)
        _revalidate(initial_state)
        _revalidate(schedule)
        if initial_state != contract.initial_state or schedule.contract != contract:
            raise ValueError("concurrency classifier context mismatch")
    except (TypeError, ValueError, AttributeError, KeyError):
        return ConcurrencyDecision(
            None,
            None,
            ConcurrencyOutcome.MALFORMED,
            None,
            (),
            None,
            "invalid_input",
            False,
        )
    outcome, state, applied, refused_index, reason = _simulate(contract, schedule)
    race = outcome is ConcurrencyOutcome.INVARIANT_VIOLATED and is_serializable_safe(
        contract
    )
    return ConcurrencyDecision(
        contract, schedule, outcome, state, applied, refused_index, reason, race
    )


def replay_schedule(
    contract: ConcurrencyInvariantContract,
    initial_state: SharedWorkflowState,
    schedule: WorkflowSchedule,
) -> ConcurrencyDecision:
    """Cooperatively replay explicit micro-steps in exactly their listed order."""
    return classify_schedule(contract, initial_state, schedule)


@dataclass(frozen=True)
class ConcurrencyOwnedFixture:
    contract: ConcurrencyInvariantContract
    worlds: tuple[ExperimentWorldBinding, ExperimentWorldBinding]
    world_tenant_ref: str
    world_tenant_ownership_ref: str
    topology: ProofTopology = ProofTopology.PAIRED_OWNED_ACCOUNTS

    def __post_init__(self) -> None:
        if (
            type(self.contract) is not ConcurrencyInvariantContract
            or type(self.worlds) is not tuple
            or len(self.worlds) != 2
            or any(type(world) is not ExperimentWorldBinding for world in self.worlds)
        ):
            raise ValueError("invalid concurrency fixture types")
        _revalidate(self.contract)
        for world in self.worlds:
            _revalidate(world)
        actors = {op.actor_ref for op in self.contract.operations}
        if (
            len(actors) != 2
            or self.topology is not ProofTopology.PAIRED_OWNED_ACCOUNTS
            or {world.persona_ref for world in self.worlds} != actors
            or len({world.slot for world in self.worlds}) != 2
            or len({world.world_ref for world in self.worlds}) != 2
            or any(
                world.kind is not ExperimentWorldKind.OWNED_ACCOUNT
                or world.role_ref is not None
                or world.lifecycle_ref is not None
                or world.callback_ref is not None
                or world.fresh is not False
                or world.ownership_ref != self.contract.tenant_ownership_ref
                for world in self.worlds
            )
            or self.world_tenant_ref != self.contract.tenant_ref
            or self.world_tenant_ownership_ref != self.contract.tenant_ownership_ref
        ):
            raise ValueError("concurrency fixture ownership mismatch")

    def _payload(self) -> dict[str, Any]:
        return {
            "contract": self.contract.to_dict(),
            "worlds": [world.to_dict() for world in self.worlds],
            "tenant_ref": self.world_tenant_ref,
            "tenant_ownership_ref": self.world_tenant_ownership_ref,
            "topology": self.topology.value,
            **_passive_flags(),
        }

    @property
    def fixture_id(self) -> str:
        return stable_hash("concurrency_owned_fixture", self._payload())

    def to_dict(self) -> dict[str, Any]:
        return {"schema_version": 1, "fixture_id": self.fixture_id, **self._payload()}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> ConcurrencyOwnedFixture:
        value = _fields(
            value,
            {
                "fixture_id",
                "contract",
                "worlds",
                "tenant_ref",
                "tenant_ownership_ref",
                "topology",
                *_passive_flags(),
            },
        )
        if type(value["worlds"]) is not list or len(value["worlds"]) != 2:
            raise ValueError("invalid concurrency worlds serialization")
        worlds = tuple(
            ExperimentWorldBinding(
                **{key: item for key, item in world.items() if key != "kind"},
                kind=ExperimentWorldKind(world["kind"]),
            )
            for world in value["worlds"]
        )
        result = cls(
            ConcurrencyInvariantContract.from_dict(value["contract"]),
            worlds,
            value["tenant_ref"],
            value["tenant_ownership_ref"],
            ProofTopology(value["topology"]),
        )
        if value != result.to_dict():
            raise ValueError("concurrency fixture address or flags mismatch")
        return result
