"""R5E7 controlled-target, gate, confinement, cleanup, and unwired proofs."""

import ast
from dataclasses import FrozenInstanceError, replace
import json
from pathlib import Path

import pytest

from core.behavior import workflow_invariant_contract as contract_module
from core.behavior import workflow_invariant_effect as effect_module
from core.behavior import workflow_invariant_effect_transport as module
from core.behavior import workflow_invariant_ledger as ledger_module
from core.behavior.normalize import stable_hash
from core.behavior.workflow_invariant_contract import (
    MAX_RESOURCE_VALUE,
    WorkflowInvariantOutcome,
    WorkflowInvariantPredicate,
)
from core.behavior.workflow_invariant_effect import (
    WorkflowEffectCorrespondence,
    WorkflowEffectOutcome,
    observed_effect_oracle,
)
from core.behavior.workflow_invariant_effect_transport import (
    WORKFLOW_EFFECT_EXECUTION_ENV,
    WorkflowEffectExecutionConfig,
    WorkflowEffectTransport,
    WorkflowEffectTransportResult,
    WorkflowEffectTransportSpec,
    run_workflow_effect_transport,
)
from core.contracts.architecture_ids import IdentifierRegistry, default_registry_path
from tests.unit.test_behavior_workflow_invariant_binding import ORIGIN, binding
from tests.unit.test_behavior_workflow_invariant_effect import (
    test_effect_is_unwired_and_has_no_production_or_transport_imports as effect_import_audit,
)
from tests.unit.test_behavior_workflow_invariant_evidence import (
    test_all_five_layers_are_unwired_and_have_no_target_imports as spine_import_audit,
)

_HONESTY = (
    "Phase 2 exercises a production-shaped, admission-gated (default-off), origin-confined "
    "transport with verified compensating cleanup, through an injected client against a "
    "controlled owned target. It is not evidence of an effect against a live running "
    "workflow, it is not wired into any production caller, and it carries no "
    "finding-promotion or durable-receipt authority and no OCB-S21/native claim."
)
_FORBIDDEN = {
    "httpx",
    "requests",
    "socket",
    "asyncio",
    "subprocess",
    "time",
    "foundry",
    "submission_candidate",
    "capability_effect_promotion",
}


class OwnedTargetClient:
    """In-suite resource owner; reads requests and its own state, never model labels."""

    def __init__(
        self,
        initial,
        *,
        aggregate_cap=False,
        operation_transform=None,
        cleanup_reply="verified",
        fail_operation=False,
    ):
        self.consumed = initial.consumed
        self.initial_consumed = initial.consumed
        self.declared_limit = initial.declared_limit
        self.per_op_cap = initial.per_op_cap
        self.aggregate_cap = aggregate_cap
        self.operation_transform = operation_transform
        self.cleanup_reply = cleanup_reply
        self.fail_operation = fail_operation
        self.requests = []

    def issue(self, request):
        request = dict(request)
        self.requests.append(request)
        if request["kind"] == "cleanup":
            if self.cleanup_reply == "exception":
                raise RuntimeError("injected cleanup failure")
            if self.cleanup_reply == "malformed":
                return {"cleanup_verified": "yes"}
            if self.cleanup_reply == "failed":
                return {
                    "specification_id": request["specification_id"],
                    "binding_ref": request["binding_ref"],
                    "cleanup_verified": False,
                    "orphaned_owned_state_possible": True,
                    "consumed": self.consumed,
                    "declared_limit": self.declared_limit,
                }
            if self.cleanup_reply == "verified_but_dirty":
                return {
                    "specification_id": request["specification_id"],
                    "binding_ref": request["binding_ref"],
                    "cleanup_verified": True,
                    "orphaned_owned_state_possible": False,
                    "consumed": self.consumed,
                    "declared_limit": self.declared_limit,
                }
            self.consumed = request["restore_consumed"]
            return {
                "specification_id": request["specification_id"],
                "binding_ref": request["binding_ref"],
                "cleanup_verified": True,
                "orphaned_owned_state_possible": False,
                "consumed": self.consumed,
                "declared_limit": self.declared_limit,
            }
        if self.fail_operation:
            raise RuntimeError("injected operation failure")
        amount = request["amount"]
        accepted = (
            amount <= self.per_op_cap
            and self.consumed + amount <= MAX_RESOURCE_VALUE
            and (
                not self.aggregate_cap or self.consumed + amount <= self.declared_limit
            )
        )
        if accepted:
            self.consumed += amount
        response = {
            "binding_ref": request["binding_ref"],
            "operation_ref": request["operation_ref"],
            "operation_id": request["operation_id"],
            "index": request["index"],
            "status": "accepted" if accepted else "refused",
            "consumed": self.consumed,
            "declared_limit": self.declared_limit,
        }
        return (
            self.operation_transform(response) if self.operation_transform else response
        )


def setup(*, secure=False, amounts=(6, 6), budget=4, **client_options):
    bound = binding(secure=secure, amounts=amounts, budget=budget)
    spec = WorkflowEffectTransportSpec(
        bound.binding_id,
        ORIGIN,
        tuple(
            f"{ORIGIN}/consume/{operation.index}"
            for operation in bound.fixture.contract.operations
        ),
        f"{ORIGIN}/cleanup",
    )
    client = OwnedTargetClient(
        bound.fixture.contract.initial_state,
        aggregate_cap=secure,
        **client_options,
    )
    return bound, spec, client


def run(bound, spec, client, *, config=None):
    return run_workflow_effect_transport(
        spec,
        bound,
        bound.capture if bound is not None else None,
        client,
        config=config,
        at_index=10,
    )


def assert_invalid(result, attempts):
    assert result.correspondence is WorkflowEffectCorrespondence.INVALID_EVIDENCE
    assert result.evidence is None
    assert result.operation_attempts == attempts


def test_gate_unset_is_inert_before_even_validating_inputs(monkeypatch):
    monkeypatch.delenv(WORKFLOW_EFFECT_EXECUTION_ENV, raising=False)
    bound, spec, client = setup()
    result = run(bound, spec, client)
    assert_invalid(result, 0)
    assert result.admitted is False
    assert result.admission_gate_enabled is False
    assert result.cleanup_attempts == 0
    assert result.compensating_cleanup_verified is False
    assert client.requests == []
    assert client.consumed == client.initial_consumed
    assert run(None, None, client).to_dict() == result.to_dict()


@pytest.mark.parametrize(
    "value,enabled",
    [
        ("1", True),
        ("TrUe", True),
        ("yes", True),
        ("on", True),
        ("off", False),
        ("", False),
    ],
)
def test_gate_environment_parsing(monkeypatch, value, enabled):
    monkeypatch.setenv(WORKFLOW_EFFECT_EXECUTION_ENV, value)
    assert WorkflowEffectExecutionConfig.from_environment().enabled is enabled


def test_truthy_environment_admits_confined_execution_and_cleanup(monkeypatch):
    monkeypatch.setenv(WORKFLOW_EFFECT_EXECUTION_ENV, "1")
    bound, spec, client = setup()
    result = run(bound, spec, client)
    assert result.correspondence is WorkflowEffectCorrespondence.COHERENT
    assert result.compensating_cleanup_verified
    assert [item["kind"] for item in client.requests] == [
        "operation",
        "operation",
        "cleanup",
    ]


@pytest.mark.parametrize("invalid", ["spec", "binding", "capture", "client", "index"])
def test_malformed_admission_context_stops_before_dispatch(invalid):
    bound, spec, client = setup()
    capture, at_index = bound.capture, 10
    if invalid == "spec":
        spec = spec.to_dict()
    elif invalid == "binding":
        bound = bound.to_dict()
    elif invalid == "capture":
        capture = replace(
            capture,
            capture_generation_ref=stable_hash("workflow_capture_generation", "other"),
        )
    elif invalid == "client":
        client = object()
    else:
        at_index = 20
    result = run_workflow_effect_transport(
        spec,
        bound,
        capture,
        client,
        config=WorkflowEffectExecutionConfig(True),
        at_index=at_index,
    )
    assert_invalid(result, 0)
    assert result.admission_gate_enabled and not result.admitted
    if invalid != "client":
        assert client.requests == []


@pytest.mark.parametrize(
    "secure,amounts,consumed,oracle,model,statuses",
    [
        (
            False,
            (6, 6),
            12,
            WorkflowEffectOutcome.EFFECT_OBSERVED_VIOLATION,
            WorkflowInvariantOutcome.INVARIANT_VIOLATED,
            ("accepted", "accepted"),
        ),
        (
            True,
            (6, 6),
            6,
            WorkflowEffectOutcome.EFFECT_ABSENT,
            WorkflowInvariantOutcome.OPERATION_REFUSED,
            ("accepted", "refused"),
        ),
        (
            True,
            (4, 6),
            10,
            WorkflowEffectOutcome.EFFECT_ABSENT,
            WorkflowInvariantOutcome.INVARIANT_HELD,
            ("accepted", "accepted"),
        ),
    ],
)
def test_canonical_twins_and_secure_boundary(
    secure, amounts, consumed, oracle, model, statuses
):
    bound, spec, client = setup(secure=secure, amounts=amounts)
    result = run(bound, spec, client, config=WorkflowEffectExecutionConfig(True))
    assert result.admitted and result.admission_gate_enabled
    assert result.correspondence is WorkflowEffectCorrespondence.COHERENT
    assert result.evidence.model.decision.outcome is model
    assert result.evidence.oracle_outcome is oracle
    assert result.evidence.observed_terminal_state.consumed == consumed
    assert client.consumed == client.initial_consumed
    assert (
        tuple(response.status.value for response in result.evidence.responses)
        == statuses
    )
    assert result.operation_attempts == len(statuses)
    assert result.cleanup_attempts == 1
    assert result.compensating_cleanup_verified is True
    assert [item["kind"] for item in client.requests] == ["operation"] * len(
        statuses
    ) + ["cleanup"]
    assert [item["url"] for item in client.requests] == list(
        spec.operation_urls[: len(statuses)]
    ) + [spec.cleanup_url]
    assert all(item["method"] == "POST" for item in client.requests)
    payload = result.to_dict()
    assert payload["target_origin_confined"] is True
    assert payload["admission_gate_enabled"] is True
    assert payload["compensating_cleanup_verified"] is True
    for key in (
        "real_workflow_effect_observed",
        "wired_into_production",
        "finding_authority",
        "promotion_authority",
    ):
        assert payload[key] is False


@pytest.mark.parametrize("location", ["operation", "cleanup"])
def test_origin_escape_is_refused_before_dispatch(location):
    bound, spec, client = setup()
    if location == "operation":
        object.__setattr__(
            spec,
            "operation_urls",
            ("https://elsewhere.test/consume", *spec.operation_urls[1:]),
        )
    else:
        object.__setattr__(spec, "cleanup_url", "https://elsewhere.test/cleanup")
    result = run(bound, spec, client, config=WorkflowEffectExecutionConfig(True))
    assert_invalid(result, 0)
    assert result.admission_gate_enabled and not result.admitted
    assert client.requests == []
    with pytest.raises(ValueError, match="leaves the authorized target origin"):
        WorkflowEffectTransportSpec(
            bound.binding_id,
            ORIGIN,
            ("https://elsewhere.test/consume", *spec.operation_urls[1:]),
            f"{ORIGIN}/cleanup",
        )


def test_spec_origin_must_match_owned_binding_before_dispatch():
    bound, spec, client = setup()
    foreign = WorkflowEffectTransportSpec(
        bound.binding_id,
        "https://another-owned.example.test",
        tuple(f"https://another-owned.example.test/consume/{i}" for i in range(2)),
        "https://another-owned.example.test/cleanup",
    )
    result = run(bound, foreign, client, config=WorkflowEffectExecutionConfig(True))
    assert_invalid(result, 0)
    assert client.requests == []


@pytest.mark.parametrize(
    "failure", ["malformed", "failed", "exception", "verified_but_dirty"]
)
def test_cleanup_failure_withholds_even_coherent_e6_evidence(failure):
    bound, spec, client = setup(cleanup_reply=failure)
    result = run(bound, spec, client, config=WorkflowEffectExecutionConfig(True))
    assert_invalid(result, 2)
    assert result.admitted and result.cleanup_attempts == 1
    assert result.compensating_cleanup_verified is False
    assert [item["kind"] for item in client.requests] == [
        "operation",
        "operation",
        "cleanup",
    ]
    if failure == "verified_but_dirty":
        assert client.consumed == 12


def test_cleanup_endpoint_must_be_distinct_before_dispatch():
    bound, spec, client = setup()
    with pytest.raises(ValueError, match="cleanup endpoint must be distinct"):
        replace(spec, cleanup_url=spec.operation_urls[0])
    object.__setattr__(spec, "cleanup_url", spec.operation_urls[0])
    result = run(bound, spec, client, config=WorkflowEffectExecutionConfig(True))
    assert_invalid(result, 0)
    assert client.requests == []


@pytest.mark.parametrize(
    "secure,amounts,reported", [(False, (6, 6), 10), (True, (4, 6), 12)]
)
def test_divergent_observation_fails_closed_in_both_directions(
    secure, amounts, reported
):
    def contradict(response):
        return (
            {**response, "consumed": reported} if response["index"] == 1 else response
        )

    bound, spec, client = setup(
        secure=secure, amounts=amounts, operation_transform=contradict
    )
    result = run(bound, spec, client, config=WorkflowEffectExecutionConfig(True))
    assert_invalid(result, 2)
    assert result.compensating_cleanup_verified
    assert client.consumed == client.initial_consumed


def test_malformed_observation_stops_operations_then_still_cleans_up():
    bound, spec, client = setup(operation_transform=lambda response: {"consumed": 6})
    result = run(bound, spec, client, config=WorkflowEffectExecutionConfig(True))
    assert_invalid(result, 1)
    assert result.compensating_cleanup_verified
    assert [item["kind"] for item in client.requests] == ["operation", "cleanup"]


def test_operation_exception_still_attempts_cleanup_once():
    bound, spec, client = setup(fail_operation=True)
    result = run(bound, spec, client, config=WorkflowEffectExecutionConfig(True))
    assert_invalid(result, 1)
    assert result.compensating_cleanup_verified
    assert [item["kind"] for item in client.requests] == ["operation", "cleanup"]


def test_transport_and_client_do_not_read_model_channel(monkeypatch):
    bound, spec, client = setup()
    transport = WorkflowEffectTransport(spec, client)

    def fail(*_, **__):
        pytest.fail("transport or client consulted the model channel")

    for owner, names in (
        (
            contract_module,
            (
                "classify_sequence",
                "evaluate_invariant",
                "operation_precondition",
                "transition_state",
            ),
        ),
        (
            ledger_module,
            (
                "classify_sequence",
                "operation_precondition",
                "transition_state",
                "evaluate_operation",
            ),
        ),
        (effect_module, ("classify_sequence", "evaluate_operation")),
        (module, ("classify_sequence",)),
    ):
        for name in names:
            monkeypatch.setattr(owner, name, fail)
    response = transport.attempt_operation(bound, bound.fixture.contract.operations[0])
    assert response.state.consumed == 6
    assert (
        observed_effect_oracle(
            WorkflowInvariantPredicate.CONSUMED_WITHIN_LIMIT, response.state
        )
        is WorkflowEffectOutcome.EFFECT_ABSENT
    )
    assert transport.cleanup(bound)
    assert client.consumed == client.initial_consumed


def test_maximum_budget_is_ordered_and_never_exceeds_one_cleanup():
    bound, spec, client = setup(secure=True, amounts=(0,) * 64, budget=64)
    result = run(bound, spec, client, config=WorkflowEffectExecutionConfig(True))
    assert result.correspondence is WorkflowEffectCorrespondence.COHERENT
    assert result.operation_attempts == bound.fixture.contract.max_operations == 64
    assert result.cleanup_attempts == 1
    assert len(client.requests) == 65
    assert [item["index"] for item in client.requests[:-1]] == list(range(64))
    assert client.requests[-1]["kind"] == "cleanup"


def test_config_spec_and_result_are_frozen_content_addressed_roundtrips():
    bound, spec, client = setup()
    config = WorkflowEffectExecutionConfig(True)
    result = run(bound, spec, client, config=config)
    for value, cls, field in (
        (config, WorkflowEffectExecutionConfig, "enabled"),
        (spec, WorkflowEffectTransportSpec, "target_origin"),
        (result, WorkflowEffectTransportResult, "admitted"),
    ):
        assert cls.from_dict(json.loads(json.dumps(value.to_dict()))) == value
        with pytest.raises(FrozenInstanceError):
            setattr(value, field, None)
    assert spec.specification_id == stable_hash(
        "workflow_effect_transport_specification", spec._payload()
    )
    assert result.result_id == stable_hash(
        "workflow_effect_transport_result", result._payload()
    )
    denied = run(None, None, client, config=WorkflowEffectExecutionConfig())
    assert WorkflowEffectTransportResult.from_dict(denied.to_dict()) == denied


@pytest.mark.parametrize("kind", ["config", "spec", "result"])
def test_each_address_mismatch_is_refused(kind):
    bound, spec, client = setup()
    values = {
        "config": (
            WorkflowEffectExecutionConfig(True),
            WorkflowEffectExecutionConfig,
            "config_id",
        ),
        "spec": (spec, WorkflowEffectTransportSpec, "specification_id"),
        "result": (
            run(bound, spec, client, config=WorkflowEffectExecutionConfig(True)),
            WorkflowEffectTransportResult,
            "result_id",
        ),
    }
    value, cls, address = values[kind]
    payload = value.to_dict()
    payload[address] = stable_hash("forged", kind)
    with pytest.raises(ValueError, match="address_mismatch"):
        cls.from_dict(payload)


@pytest.mark.parametrize(
    "kind,field,value",
    [
        ("config", "enabled", "true"),
        ("spec", "target_origin", "https://foreign.example.test"),
        (
            "spec",
            "operation_urls",
            ["https://elsewhere.test/op", f"{ORIGIN}/consume/1"],
        ),
        ("spec", "cleanup_url", f"{ORIGIN}/consume/0"),
        ("result", "finding_authority", True),
        ("result", "compensating_cleanup_verified", False),
        ("result", "effect_evidence", None),
        ("result", "target_origin_confined", False),
    ],
)
def test_serialized_tampering_is_refused(kind, field, value):
    bound, spec, client = setup()
    objects = {
        "config": (WorkflowEffectExecutionConfig(True), WorkflowEffectExecutionConfig),
        "spec": (spec, WorkflowEffectTransportSpec),
        "result": (
            run(bound, spec, client, config=WorkflowEffectExecutionConfig(True)),
            WorkflowEffectTransportResult,
        ),
    }
    obj, cls = objects[kind]
    payload = obj.to_dict()
    payload[field] = value
    with pytest.raises(ValueError):
        cls.from_dict(payload)


def _import_references(tree):
    references = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            references.update((node.module or "").split("."))
            references.update(alias.name for alias in node.names)
        elif isinstance(node, ast.Import):
            references.update(
                part for alias in node.names for part in alias.name.split(".")
            )
    return references


def test_transport_is_unwired_and_has_no_forbidden_imports():
    repository = Path(__file__).resolve().parents[2]
    path = repository / "core/behavior/workflow_invariant_effect_transport.py"
    tree = ast.parse(path.read_text())
    assert not _import_references(tree) & _FORBIDDEN
    os_attributes = {
        node.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id == "os"
    }
    assert os_attributes == {"environ"}
    family = {
        f"workflow_invariant_{suffix}"
        for suffix in (
            "contract",
            "binding",
            "ledger",
            "store",
            "evidence",
            "effect",
            "effect_transport",
            "effect_one_click",
        )
    }
    consumers = []
    for candidate in (repository / "core").rglob("*.py"):
        if candidate.stem in family:
            continue
        if "workflow_invariant_effect_transport" in _import_references(
            ast.parse(candidate.read_text())
        ):
            consumers.append(str(candidate))
    assert consumers == []


@pytest.mark.parametrize(
    "stem", ["unrelated_consumer", "workflow_invariant_effect_transport_extra", "workflow_invariant_effect_one_click_extra"]
)
@pytest.mark.parametrize(
    "audit,imported",
    [
        (spine_import_audit, "workflow_invariant_contract"),
        (effect_import_audit, "workflow_invariant_effect"),
        (
            test_transport_is_unwired_and_has_no_forbidden_imports,
            "workflow_invariant_effect_transport",
        ),
    ],
)
def test_all_three_audits_reject_other_consumers(monkeypatch, stem, audit, imported):
    repository = Path(__file__).resolve().parents[2]
    added = repository / "core/behavior" / f"{stem}.py"
    original_rglob, original_read = Path.rglob, Path.read_text

    def with_consumer(path, pattern):
        yield from original_rglob(path, pattern)
        if path == repository / "core":
            yield added

    def read(path, *args, **kwargs):
        if path == added:
            return f"from core.behavior import {imported}\n"
        return original_read(path, *args, **kwargs)

    monkeypatch.setattr(Path, "rglob", with_consumer)
    monkeypatch.setattr(Path, "read_text", read)
    with pytest.raises(AssertionError):
        audit()


@pytest.mark.parametrize("forbidden", sorted(_FORBIDDEN))
def test_transport_import_audit_rejects_each_forbidden_surface(monkeypatch, forbidden):
    path = Path(module.__file__)
    original_read = Path.read_text

    def read(candidate, *args, **kwargs):
        source = original_read(candidate, *args, **kwargs)
        return source + f"\nimport {forbidden}\n" if candidate == path else source

    monkeypatch.setattr(Path, "read_text", read)
    with pytest.raises(AssertionError):
        test_transport_is_unwired_and_has_no_forbidden_imports()


def test_registry_and_verbatim_honesty_statement():
    repository = Path(__file__).resolve().parents[2]
    registry = IdentifierRegistry.load(default_registry_path(repository))
    assert "R5E7" in registry.canonical_ids
    records = json.loads(default_registry_path(repository).read_text())["canonical_ids"]
    assert [record for record in records if record["id"] == "R5E7"] == [
        {
            "id": "R5E7",
            "kind": "slice",
            "description": "Bounded, admission-gated (default-off), origin-confined workflow-effect transport with verified compensating cleanup; unwired (no production caller)",
        }
    ]
    assert _HONESTY in module.__doc__
