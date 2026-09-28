"""R5E1: passive, unwired workflow contracts and deterministic outcome evaluation.

Only sequential aggregate-limit consumes are admitted. Predicates and transitions
are typed data, never executable input. The invariant evaluator reads terminal
state independently of transition logic. This is a deterministic outcome evaluator,
not independent evidence of an observed target-side effect.

No production entry point imports this module. It adds no origin, identity, action
class, budget reservation, transport, finding, or execution authority. Fixtures
create no state: disposable/reversible, no cleanup claimed, orphan-risk false.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum
from typing import Any, Mapping

from .experiment_sdk import ExperimentWorldBinding, ExperimentWorldKind, _hash_ref
from .normalize import stable_hash
from .payout_goals import ProofTopology

WORKFLOW_INVARIANT_CONTRACT_MODE = "behavioral_workflow_invariant_contract_v1"
MAX_WORKFLOW_OPERATIONS = 64
MAX_RESOURCE_VALUE = 2**63 - 1


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
        raise ValueError("workflow serialization is invalid")
    return value


def _revalidate(value: Any) -> None:
    """Defensively re-run a frozen dataclass's ``__post_init__`` validation.

    ``dataclasses.replace`` with no field overrides rebuilds the instance, which
    re-invokes ``__post_init__``; the rebuilt copy is intentionally discarded. This
    guards a nested dataclass that may have reached this object without passing its
    own checked constructor, re-raising that dataclass's error if it is now invalid.
    """
    replace(value)


class WorkflowStateSchema(str, Enum):
    AGGREGATE_LIMIT = "aggregate_limit_v1"


class WorkflowInvariantPredicate(str, Enum):
    CONSUMED_WITHIN_LIMIT = "consumed_within_declared_limit"


class WorkflowPrecondition(str, Enum):
    PER_OPERATION_CAP = "per_operation_cap"
    PER_OPERATION_AND_AGGREGATE_CAP = "per_operation_and_aggregate_cap"


class WorkflowTransition(str, Enum):
    CONSUME = "consume"


class WorkflowInvariantOutcome(str, Enum):
    INVARIANT_HELD = "invariant_held"
    INVARIANT_VIOLATED = "invariant_violated"
    OPERATION_REFUSED = "operation_refused"
    MALFORMED = "malformed"


@dataclass(frozen=True)
class WorkflowState:
    consumed: int
    declared_limit: int
    per_op_cap: int
    schema: WorkflowStateSchema = WorkflowStateSchema.AGGREGATE_LIMIT

    def __post_init__(self) -> None:
        if (
            self.schema is not WorkflowStateSchema.AGGREGATE_LIMIT
            or not _integer(self.consumed)
            or not _integer(self.declared_limit)
            or not _integer(self.per_op_cap, 1)
        ):
            raise ValueError("workflow state is invalid")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "schema": self.schema.value,
            "consumed": self.consumed,
            "declared_limit": self.declared_limit,
            "per_op_cap": self.per_op_cap,
        }

    @property
    def state_id(self) -> str:
        return stable_hash("workflow_state", self.to_dict())

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> WorkflowState:
        value = _fields(value, {"schema", "consumed", "declared_limit", "per_op_cap"})
        return cls(
            consumed=value["consumed"],
            declared_limit=value["declared_limit"],
            per_op_cap=value["per_op_cap"],
            schema=WorkflowStateSchema(value["schema"]),
        )


def evaluate_invariant(
    predicate: WorkflowInvariantPredicate, terminal_state: WorkflowState
) -> bool:
    """Pure terminal-state oracle; does not call a guard or transition function."""
    if predicate is not WorkflowInvariantPredicate.CONSUMED_WITHIN_LIMIT:
        raise ValueError("unsupported workflow invariant")
    if type(terminal_state) is not WorkflowState:
        raise ValueError("invalid terminal state")
    _revalidate(terminal_state)
    return terminal_state.consumed <= terminal_state.declared_limit


@dataclass(frozen=True)
class WorkflowOperation:
    operation_ref: str
    index: int
    account_ref: str
    amount: int
    precondition: WorkflowPrecondition
    transition: WorkflowTransition = WorkflowTransition.CONSUME
    single_application: bool = True

    def __post_init__(self) -> None:
        if (
            not _hash_ref(self.operation_ref, "workflow_operation")
            or not _hash_ref(self.account_ref)
            or not _integer(self.index, 0, MAX_WORKFLOW_OPERATIONS - 1)
            or not _integer(self.amount)
            or type(self.precondition) is not WorkflowPrecondition
            or self.transition is not WorkflowTransition.CONSUME
            or self.single_application is not True
        ):
            raise ValueError("workflow operation is invalid")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "operation_ref": self.operation_ref,
            "index": self.index,
            "account_ref": self.account_ref,
            "amount": self.amount,
            "precondition": self.precondition.value,
            "transition": self.transition.value,
            "single_application": self.single_application,
        }

    @property
    def operation_id(self) -> str:
        return stable_hash("workflow_operation_contract", self.to_dict())

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> WorkflowOperation:
        value = _fields(
            value,
            {
                "operation_ref",
                "index",
                "account_ref",
                "amount",
                "precondition",
                "transition",
                "single_application",
            },
        )
        return cls(
            operation_ref=value["operation_ref"],
            index=value["index"],
            account_ref=value["account_ref"],
            amount=value["amount"],
            precondition=WorkflowPrecondition(value["precondition"]),
            transition=WorkflowTransition(value["transition"]),
            single_application=value["single_application"],
        )


def operation_precondition(state: WorkflowState, operation: WorkflowOperation) -> bool:
    """Evaluate only the operation's declared guard, independently of the oracle."""
    _revalidate(state)
    _revalidate(operation)
    return operation.amount <= state.per_op_cap and (
        operation.precondition is WorkflowPrecondition.PER_OPERATION_CAP
        or state.consumed + operation.amount <= state.declared_limit
    )


def transition_state(
    state: WorkflowState, operation: WorkflowOperation
) -> WorkflowState:
    """Pure consume semantics; the caller must first satisfy the declared guard."""
    if not operation_precondition(state, operation):
        raise ValueError("workflow operation precondition refused")
    return replace(state, consumed=state.consumed + operation.amount)


@dataclass(frozen=True)
class WorkflowInvariantContract:
    contract_id: str
    workflow_ref: str
    account_ref: str
    tenant_ref: str
    tenant_ownership_ref: str
    initial_state: WorkflowState
    operations: tuple[WorkflowOperation, ...]
    max_operations: int
    invariant: WorkflowInvariantPredicate = (
        WorkflowInvariantPredicate.CONSUMED_WITHIN_LIMIT
    )
    state_schema: WorkflowStateSchema = WorkflowStateSchema.AGGREGATE_LIMIT
    mode: str = WORKFLOW_INVARIANT_CONTRACT_MODE

    def _payload(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "workflow_ref": self.workflow_ref,
            "account_ref": self.account_ref,
            "tenant_ref": self.tenant_ref,
            "tenant_ownership_ref": self.tenant_ownership_ref,
            "state_schema": self.state_schema.value,
            "initial_state": self.initial_state.to_dict(),
            "operations": [operation.to_dict() for operation in self.operations],
            "max_operations": self.max_operations,
            "invariant": self.invariant.value,
        }

    @classmethod
    def build(
        cls,
        *,
        workflow_ref: str,
        account_ref: str,
        tenant_ref: str,
        tenant_ownership_ref: str,
        initial_state: WorkflowState,
        operations: tuple[WorkflowOperation, ...],
        max_operations: int,
        invariant: WorkflowInvariantPredicate = WorkflowInvariantPredicate.CONSUMED_WITHIN_LIMIT,
        state_schema: WorkflowStateSchema = WorkflowStateSchema.AGGREGATE_LIMIT,
    ) -> WorkflowInvariantContract:
        if (
            type(initial_state) is not WorkflowState
            or type(operations) is not tuple
            or any(type(op) is not WorkflowOperation for op in operations)
        ):
            raise ValueError("invalid workflow state or operation types")
        if (
            type(invariant) is not WorkflowInvariantPredicate
            or type(state_schema) is not WorkflowStateSchema
        ):
            raise ValueError("invalid workflow predicate or schema")
        payload = {
            "mode": WORKFLOW_INVARIANT_CONTRACT_MODE,
            "workflow_ref": workflow_ref,
            "account_ref": account_ref,
            "tenant_ref": tenant_ref,
            "tenant_ownership_ref": tenant_ownership_ref,
            "state_schema": state_schema.value,
            "initial_state": initial_state.to_dict(),
            "operations": [op.to_dict() for op in operations],
            "max_operations": max_operations,
            "invariant": invariant.value,
        }
        return cls(
            contract_id=stable_hash("workflow_invariant_contract", payload),
            workflow_ref=workflow_ref,
            account_ref=account_ref,
            tenant_ref=tenant_ref,
            tenant_ownership_ref=tenant_ownership_ref,
            initial_state=initial_state,
            operations=operations,
            max_operations=max_operations,
            invariant=invariant,
            state_schema=state_schema,
        )

    def __post_init__(self) -> None:
        if (
            type(self.initial_state) is not WorkflowState
            or type(self.operations) is not tuple
            or not 1 <= len(self.operations) <= MAX_WORKFLOW_OPERATIONS
            or self.state_schema is not WorkflowStateSchema.AGGREGATE_LIMIT
            or self.invariant is not WorkflowInvariantPredicate.CONSUMED_WITHIN_LIMIT
            or self.mode != WORKFLOW_INVARIANT_CONTRACT_MODE
        ):
            raise ValueError("workflow invariant contract is invalid")
        _revalidate(self.initial_state)
        for operation in self.operations:
            if type(operation) is not WorkflowOperation:
                raise ValueError("invalid workflow operation type")
            _revalidate(operation)
        if (
            not _hash_ref(self.workflow_ref, "workflow")
            or not _hash_ref(self.account_ref)
            or not _hash_ref(self.tenant_ref, "owned_tenant")
            or not _hash_ref(self.tenant_ownership_ref, "ownership_proof")
            or not _integer(self.max_operations, 1, MAX_WORKFLOW_OPERATIONS)
            or not evaluate_invariant(self.invariant, self.initial_state)
            or tuple(op.index for op in self.operations)
            != tuple(range(len(self.operations)))
            or len({op.operation_ref for op in self.operations}) != len(self.operations)
            or any(op.account_ref != self.account_ref for op in self.operations)
            or not _hash_ref(self.contract_id, "workflow_invariant_contract")
            or self.contract_id
            != stable_hash("workflow_invariant_contract", self._payload())
        ):
            raise ValueError("workflow invariant contract is invalid")

    def to_dict(self) -> dict[str, Any]:
        return {"schema_version": 1, "contract_id": self.contract_id, **self._payload()}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> WorkflowInvariantContract:
        value = _fields(
            value,
            {
                "contract_id",
                "workflow_ref",
                "account_ref",
                "tenant_ref",
                "tenant_ownership_ref",
                "initial_state",
                "operations",
                "max_operations",
                "invariant",
                "state_schema",
                "mode",
            },
        )
        if not isinstance(value["operations"], list) or not _hash_ref(
            value["contract_id"], "workflow_invariant_contract"
        ):
            raise ValueError("invalid workflow contract serialization")
        return cls(
            contract_id=value["contract_id"],
            workflow_ref=value["workflow_ref"],
            account_ref=value["account_ref"],
            tenant_ref=value["tenant_ref"],
            tenant_ownership_ref=value["tenant_ownership_ref"],
            initial_state=WorkflowState.from_dict(value["initial_state"]),
            operations=tuple(
                WorkflowOperation.from_dict(op) for op in value["operations"]
            ),
            max_operations=value["max_operations"],
            invariant=WorkflowInvariantPredicate(value["invariant"]),
            state_schema=WorkflowStateSchema(value["state_schema"]),
            mode=value["mode"],
        )


def _owned_world(world: object) -> ExperimentWorldBinding:
    if type(world) is not ExperimentWorldBinding:
        raise ValueError("workflow requires an SDK owned account")
    _revalidate(world)
    if (
        world.kind is not ExperimentWorldKind.OWNED_ACCOUNT
        or world.slot != "actor"
        or world.role_ref is not None
        or world.lifecycle_ref is not None
        or world.callback_ref is not None
        or world.fresh is not False
        or not _hash_ref(world.ownership_ref, "ownership_proof")
    ):
        raise ValueError("workflow requires one unqualified owned account")
    return world


@dataclass(frozen=True)
class WorkflowOwnedFixture:
    contract: WorkflowInvariantContract
    world: ExperimentWorldBinding
    world_tenant_ref: str
    world_tenant_ownership_ref: str
    topology: ProofTopology = ProofTopology.SINGLE_OWNED_ACCOUNT

    def __post_init__(self) -> None:
        if type(self.contract) is not WorkflowInvariantContract:
            raise ValueError("invalid workflow contract type")
        _revalidate(self.contract)
        world = _owned_world(self.world)
        if (
            not _hash_ref(self.contract.contract_id, "workflow_invariant_contract")
            or self.topology is not ProofTopology.SINGLE_OWNED_ACCOUNT
            or world.persona_ref != self.contract.account_ref
            or self.world_tenant_ref != self.contract.tenant_ref
            or self.world_tenant_ownership_ref != self.contract.tenant_ownership_ref
        ):
            raise ValueError("workflow fixture ownership binding mismatch")

    def _payload(self) -> dict[str, Any]:
        return {
            "contract": self.contract.to_dict(),
            "world": self.world.to_dict(),
            "tenant_ref": self.world_tenant_ref,
            "tenant_ownership_ref": self.world_tenant_ownership_ref,
            "topology": self.topology.value,
            "disposable": True,
            "reversible": True,
            "cleanup_required": False,
            "residue_created": False,
            "orphan_risk": False,
            "target_requests_sent": 0,
            "budget_reserved": False,
            "backend_dispatch_authority": False,
            "finding_authority": False,
            "executable": False,
        }

    @property
    def fixture_id(self) -> str:
        return stable_hash("workflow_owned_fixture", self._payload())

    def to_dict(self) -> dict[str, Any]:
        return {"schema_version": 1, "fixture_id": self.fixture_id, **self._payload()}


@dataclass(frozen=True)
class WorkflowInvariantDecision:
    contract_ref: str | None
    outcome: WorkflowInvariantOutcome
    terminal_state: WorkflowState | None
    applied_operation_refs: tuple[str, ...]
    refused_index: int | None
    reason_code: str

    def __post_init__(self) -> None:
        if (
            type(self.outcome) is not WorkflowInvariantOutcome
            or type(self.applied_operation_refs) is not tuple
        ):
            raise ValueError("invalid workflow decision")
        malformed = self.outcome is WorkflowInvariantOutcome.MALFORMED
        if malformed:
            if self.to_dict_payload() != {
                "contract_ref": None,
                "outcome": "malformed",
                "terminal_state": None,
                "applied_operation_refs": [],
                "refused_index": None,
                "reason_code": "invalid_input",
            }:
                raise ValueError("malformed decision must contain no untrusted data")
            return
        if type(self.terminal_state) is not WorkflowState:
            raise ValueError("invalid workflow terminal state")
        _revalidate(self.terminal_state)
        refused = self.outcome is WorkflowInvariantOutcome.OPERATION_REFUSED
        if (
            not _hash_ref(self.contract_ref, "workflow_invariant_contract")
            or any(
                not _hash_ref(ref, "workflow_operation")
                for ref in self.applied_operation_refs
            )
            or len(self.applied_operation_refs) > MAX_WORKFLOW_OPERATIONS
            or len(set(self.applied_operation_refs)) != len(self.applied_operation_refs)
            or (
                refused
                and (
                    not _integer(self.refused_index, 0, MAX_WORKFLOW_OPERATIONS - 1)
                    or self.refused_index != len(self.applied_operation_refs)
                )
            )
            or (not refused and self.refused_index is not None)
            or (
                refused
                and self.reason_code
                not in {
                    "precondition_refused",
                    "sequence_budget_exhausted",
                    "resource_value_exhausted",
                }
            )
            or (not refused and self.reason_code != self.outcome.value)
            or (
                not refused
                and evaluate_invariant(
                    WorkflowInvariantPredicate.CONSUMED_WITHIN_LIMIT,
                    self.terminal_state,
                )
                != (self.outcome is WorkflowInvariantOutcome.INVARIANT_HELD)
            )
        ):
            raise ValueError("invalid workflow decision")

    def to_dict_payload(self) -> dict[str, Any]:
        return {
            "contract_ref": self.contract_ref,
            "outcome": self.outcome.value,
            "terminal_state": self.terminal_state.to_dict()
            if self.terminal_state is not None
            else None,
            "applied_operation_refs": list(self.applied_operation_refs),
            "refused_index": self.refused_index,
            "reason_code": self.reason_code,
        }

    @property
    def decision_id(self) -> str:
        return stable_hash("workflow_invariant_decision", self.to_dict_payload())

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "decision_id": self.decision_id,
            **self.to_dict_payload(),
        }


def classify_sequence(
    contract: WorkflowInvariantContract,
    initial_state: WorkflowState,
    operations: tuple[WorkflowOperation, ...],
) -> WorkflowInvariantDecision:
    """Evaluate the exact complete declared sequence; malformed inputs fail closed."""
    try:
        if (
            type(contract) is not WorkflowInvariantContract
            or type(initial_state) is not WorkflowState
            or type(operations) is not tuple
        ):
            raise ValueError("invalid sequence types")
        _revalidate(contract)
        _revalidate(initial_state)
        if (
            not _hash_ref(contract.contract_id, "workflow_invariant_contract")
            or initial_state != contract.initial_state
            or operations != contract.operations
        ):
            raise ValueError("sequence does not match declared contract")
        for operation in operations:
            _revalidate(operation)
    except (TypeError, ValueError, AttributeError):
        return WorkflowInvariantDecision(
            None, WorkflowInvariantOutcome.MALFORMED, None, (), None, "invalid_input"
        )
    state = initial_state
    applied: tuple[str, ...] = ()
    for operation in operations:
        reason = None
        if len(applied) >= contract.max_operations:
            reason = "sequence_budget_exhausted"
        elif not operation_precondition(state, operation):
            reason = "precondition_refused"
        elif state.consumed + operation.amount > MAX_RESOURCE_VALUE:
            reason = "resource_value_exhausted"
        if reason is not None:
            return WorkflowInvariantDecision(
                contract.contract_id,
                WorkflowInvariantOutcome.OPERATION_REFUSED,
                state,
                applied,
                operation.index,
                reason,
            )
        state = transition_state(state, operation)
        applied += (operation.operation_ref,)
    held = evaluate_invariant(contract.invariant, state)
    outcome = (
        WorkflowInvariantOutcome.INVARIANT_HELD
        if held
        else WorkflowInvariantOutcome.INVARIANT_VIOLATED
    )
    return WorkflowInvariantDecision(
        contract.contract_id, outcome, state, applied, None, outcome.value
    )
