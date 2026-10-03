"""R5F7 controlled-target, gate, confinement, cleanup, and unwired proofs."""

import ast
from dataclasses import FrozenInstanceError, replace
import json
from pathlib import Path

import pytest

from core.behavior import concurrency_invariant_contract as contract_module
from core.behavior import concurrency_invariant_effect as effect_module
from core.behavior import concurrency_invariant_effect_transport as module
from core.behavior import concurrency_invariant_ledger as ledger_module
from core.behavior.concurrency_invariant_contract import (
    MAX_CONCURRENCY_OPERATIONS,
    MAX_RESOURCE_VALUE,
    MAX_SCHEDULE_STEPS,
    ConcurrencyGuard,
    ConcurrencyGuardMode,
    ConcurrencyOutcome,
    MicroStep,
    StepKind,
    WorkflowSchedule,
)
from core.behavior.concurrency_invariant_effect import (
    ConcurrencyEffectCorrespondence,
    ConcurrencyEffectOutcome,
    observed_effect_oracle,
)
from core.behavior.concurrency_invariant_effect_transport import (
    CONCURRENCY_EFFECT_EXECUTION_ENV,
    ConcurrencyEffectExecutionConfig,
    ConcurrencyEffectTransport,
    ConcurrencyEffectTransportResult,
    ConcurrencyEffectTransportSpec,
    run_concurrency_effect_transport,
)
from core.behavior.normalize import stable_hash
from core.contracts.architecture_ids import IdentifierRegistry, default_registry_path
from tests.unit.test_behavior_concurrency_invariant_binding import binding
from tests.unit.test_behavior_concurrency_invariant_effect import (
    _bind_fixture,
    _fixture_with,
    test_effect_is_unwired_and_has_only_allowed_imports as effect_import_audit,
)
from tests.unit.test_behavior_concurrency_invariant_evidence import (
    test_all_five_unwired_and_no_forbidden_primitives as spine_import_audit,
)
from tests.unit.test_behavior_concurrency_invariant_contract import case

REPOSITORY = Path(__file__).resolve().parents[2]
ORIGIN = "https://owned.example.test"
_HONESTY = (
    "Origin confinement is self-referential to the declared authorized origin; "
    "proving that origin belongs to the owned target this binding represents is "
    "deferred to F8 (the real client + Foundry composition against the real owned "
    "target), exactly as E's real target binding was established only at E8."
)
_FORBIDDEN = {
    "threading",
    "asyncio",
    "multiprocessing",
    "concurrent",
    "queue",
    "socket",
    "ssl",
    "http",
    "httpx",
    "requests",
    "urllib3",
    "subprocess",
    "signal",
    "time",
    "datetime",
    "random",
    "secrets",
    "foundry",
    "submission_candidate",
    "capability_effect_promotion",
}


class OwnedTargetClient:
    """In-suite resource/CAS enforcer; reads requests and state, never model labels."""

    def __init__(
        self,
        contract,
        *,
        commit_transform=None,
        cleanup_reply="verified",
        fail_commit=False,
    ):
        initial = contract.initial_state
        self.initial_consumed = initial.consumed
        self.consumed = initial.consumed
        self.declared_limit = initial.declared_limit
        self.per_op_cap = initial.per_op_cap
        self.version = initial.version
        self.operations = {op.operation_ref: op for op in contract.operations}
        self.snapshots = {}
        self.requests = []
        self.commit_transform = commit_transform
        self.cleanup_reply = cleanup_reply
        self.fail_commit = fail_commit

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
        operation = self.operations[request["operation_ref"]]
        assert request["operation_id"] == operation.operation_id
        assert request["amount"] == operation.amount
        if request["kind"] == "observe":
            guard_passed = operation.amount <= self.per_op_cap and (
                operation.guard is ConcurrencyGuard.PER_OPERATION_CAP
                or self.consumed + operation.amount <= self.declared_limit
            )
            self.snapshots[operation.operation_ref] = (self.version, guard_passed)
            return {"observed": True}  # The transport discards this acknowledgment.
        if self.fail_commit:
            raise RuntimeError("injected commit failure")
        observed_version, guard_passed = self.snapshots.pop(operation.operation_ref)
        accepted = guard_passed
        if operation.guard_mode is ConcurrencyGuardMode.COMMIT_TIME_CAS:
            accepted = (
                accepted
                and self.version == observed_version
                and self.consumed + operation.amount <= self.declared_limit
            )
        accepted = (
            accepted
            and self.consumed + operation.amount <= MAX_RESOURCE_VALUE
            and self.version < MAX_RESOURCE_VALUE
        )
        if accepted:
            self.consumed += operation.amount
            self.version += 1
        response = {
            "binding_ref": request["binding_ref"],
            "operation_ref": request["operation_ref"],
            "operation_id": request["operation_id"],
            "index": request["index"],
            "status": "accepted" if accepted else "refused",
            "consumed": self.consumed,
            "declared_limit": self.declared_limit,
        }
        return self.commit_transform(response) if self.commit_transform else response


def setup(*, secure=False, limit=1, **client_options):
    bound, schedule = binding(secure=secure, limit=limit)
    spec = ConcurrencyEffectTransportSpec(
        bound.binding_id,
        ORIGIN,
        tuple(
            f"{ORIGIN}/consume/{index}"
            for index, _ in enumerate(bound.fixture.contract.operations)
        ),
        f"{ORIGIN}/cleanup",
    )
    client = OwnedTargetClient(bound.fixture.contract, **client_options)
    return bound, schedule, spec, client


def run(bound, schedule, spec, client, *, config=None, capture=None, at_index=10):
    return run_concurrency_effect_transport(
        spec,
        bound,
        bound.capture if capture is None and bound is not None else capture,
        schedule,
        client,
        config=config,
        at_index=at_index,
    )


def assert_invalid(result, attempts):
    assert result.correspondence is ConcurrencyEffectCorrespondence.INVALID_EVIDENCE
    assert result.evidence is None
    assert result.step_attempts == attempts


def test_gate_unset_is_inert_before_even_validating_inputs(monkeypatch):
    monkeypatch.delenv(CONCURRENCY_EFFECT_EXECUTION_ENV, raising=False)
    bound, schedule, spec, client = setup()
    result = run(bound, schedule, spec, client)
    assert_invalid(result, 0)
    assert result.admission_gate_enabled is False and result.admitted is False
    assert result.cleanup_attempts == 0
    assert result.compensating_cleanup_verified is False
    assert client.requests == []
    assert run(None, None, None, client).to_dict() == result.to_dict()


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
    monkeypatch.setenv(CONCURRENCY_EFFECT_EXECUTION_ENV, value)
    assert ConcurrencyEffectExecutionConfig.from_environment().enabled is enabled


def test_truthy_environment_admits_confined_execution_and_cleanup(monkeypatch):
    monkeypatch.setenv(CONCURRENCY_EFFECT_EXECUTION_ENV, "1")
    bound, schedule, spec, client = setup()
    result = run(bound, schedule, spec, client)
    assert result.correspondence is ConcurrencyEffectCorrespondence.COHERENT
    assert result.compensating_cleanup_verified
    assert [item["kind"] for item in client.requests] == [
        "observe",
        "observe",
        "commit",
        "commit",
        "cleanup",
    ]


@pytest.mark.parametrize("invalid", ["spec", "binding", "capture", "client", "index"])
def test_malformed_admission_context_stops_before_dispatch(invalid):
    bound, schedule, spec, client = setup()
    capture, at_index = bound.capture, 10
    if invalid == "spec":
        spec = spec.to_dict()
    elif invalid == "binding":
        bound = bound.to_dict()
    elif invalid == "capture":
        capture = replace(
            capture,
            capture_generation_ref=stable_hash(
                "concurrency_capture_generation", "other"
            ),
        )
    elif invalid == "client":
        client = object()
    else:
        at_index = 20
    result = run_concurrency_effect_transport(
        spec,
        bound,
        capture,
        schedule,
        client,
        config=ConcurrencyEffectExecutionConfig(True),
        at_index=at_index,
    )
    assert_invalid(result, 0)
    assert result.admission_gate_enabled and not result.admitted
    if invalid != "client":
        assert client.requests == []


@pytest.mark.parametrize(
    "secure,limit,consumed,oracle,outcome,race,statuses",
    [
        (
            False,
            1,
            2,
            ConcurrencyEffectOutcome.EFFECT_OBSERVED_VIOLATION,
            ConcurrencyOutcome.INVARIANT_VIOLATED,
            True,
            ("accepted", "accepted"),
        ),
        (
            True,
            1,
            1,
            ConcurrencyEffectOutcome.EFFECT_ABSENT,
            ConcurrencyOutcome.OPERATION_REFUSED,
            False,
            ("accepted", "refused"),
        ),
        (
            False,
            2,
            2,
            ConcurrencyEffectOutcome.EFFECT_ABSENT,
            ConcurrencyOutcome.INVARIANT_HELD,
            False,
            ("accepted", "accepted"),
        ),
    ],
)
def test_canonical_twins_and_secure_boundary(
    secure, limit, consumed, oracle, outcome, race, statuses
):
    bound, schedule, spec, client = setup(secure=secure, limit=limit)
    result = run(
        bound, schedule, spec, client, config=ConcurrencyEffectExecutionConfig(True)
    )
    assert result.admitted and result.admission_gate_enabled
    assert result.correspondence is ConcurrencyEffectCorrespondence.COHERENT
    assert result.evidence.model.decision.outcome is outcome
    assert result.evidence.model.decision.race_confirmed is race
    assert result.evidence.oracle_outcome is oracle
    assert result.evidence.observed_terminal_state.consumed == consumed
    assert client.consumed == client.initial_consumed
    assert (
        tuple(response.status.value for response in result.evidence.responses)
        == statuses
    )
    assert [response.index for response in result.evidence.responses] == [2, 3]
    assert result.step_attempts == len(schedule.steps) == 4
    assert result.cleanup_attempts == 1 and result.compensating_cleanup_verified
    assert [item["kind"] for item in client.requests] == [
        "observe",
        "observe",
        "commit",
        "commit",
        "cleanup",
    ]
    assert [item["url"] for item in client.requests] == [
        spec.operation_urls[0],
        spec.operation_urls[1],
        spec.operation_urls[0],
        spec.operation_urls[1],
        spec.cleanup_url,
    ]
    assert all(item["method"] == "POST" for item in client.requests)
    payload = result.to_dict()
    assert payload["target_origin_confined"] is True
    assert payload["owned_target_origin_bound"] is False
    assert payload["admission_gate_enabled"] is True
    assert payload["compensating_cleanup_verified"] is True
    for key in (
        "real_concurrency_effect_observed",
        "wired_into_production",
        "finding_authority",
        "promotion_authority",
    ):
        assert payload[key] is False


@pytest.mark.parametrize("location", ["operation", "cleanup"])
def test_origin_escape_is_refused_before_dispatch(location):
    bound, schedule, spec, client = setup()
    if location == "operation":
        object.__setattr__(
            spec,
            "operation_urls",
            ("https://elsewhere.test/consume", *spec.operation_urls[1:]),
        )
    else:
        object.__setattr__(spec, "cleanup_url", "https://elsewhere.test/cleanup")
    result = run(
        bound, schedule, spec, client, config=ConcurrencyEffectExecutionConfig(True)
    )
    assert_invalid(result, 0)
    assert result.admission_gate_enabled and not result.admitted
    assert client.requests == []
    with pytest.raises(ValueError, match="leaves the authorized target origin"):
        ConcurrencyEffectTransportSpec(
            bound.binding_id,
            ORIGIN,
            ("https://elsewhere.test/consume", f"{ORIGIN}/consume/1"),
            f"{ORIGIN}/cleanup",
        )


def test_spec_binding_ref_must_match_owned_binding_before_dispatch():
    bound, schedule, _, client = setup()
    other, _ = binding(secure=True)
    foreign = ConcurrencyEffectTransportSpec(
        other.binding_id,
        ORIGIN,
        (f"{ORIGIN}/consume/0", f"{ORIGIN}/consume/1"),
        f"{ORIGIN}/cleanup",
    )
    result = run(
        bound, schedule, foreign, client, config=ConcurrencyEffectExecutionConfig(True)
    )
    assert_invalid(result, 0)
    assert result.admission_gate_enabled and not result.admitted
    assert client.requests == []


@pytest.mark.parametrize(
    "failure", ["malformed", "failed", "exception", "verified_but_dirty"]
)
def test_cleanup_failure_withholds_even_coherent_f6_evidence(failure):
    bound, schedule, spec, client = setup(cleanup_reply=failure)
    result = run(
        bound, schedule, spec, client, config=ConcurrencyEffectExecutionConfig(True)
    )
    assert_invalid(result, 4)
    assert result.admitted and result.cleanup_attempts == 1
    assert result.compensating_cleanup_verified is False
    assert [item["kind"] for item in client.requests] == [
        "observe",
        "observe",
        "commit",
        "commit",
        "cleanup",
    ]
    if failure == "verified_but_dirty":
        assert client.consumed == 2


def test_cleanup_endpoint_must_be_distinct_before_dispatch():
    bound, schedule, spec, client = setup()
    with pytest.raises(ValueError, match="cleanup endpoint must be distinct"):
        replace(spec, cleanup_url=spec.operation_urls[0])
    object.__setattr__(spec, "cleanup_url", spec.operation_urls[0])
    result = run(
        bound, schedule, spec, client, config=ConcurrencyEffectExecutionConfig(True)
    )
    assert_invalid(result, 0)
    assert client.requests == []


@pytest.mark.parametrize("secure,limit,reported", [(False, 1, 1), (False, 2, 3)])
def test_divergent_observation_fails_closed_in_both_directions(secure, limit, reported):
    def contradict(response):
        return (
            {**response, "consumed": reported} if response["index"] == 3 else response
        )

    bound, schedule, spec, client = setup(
        secure=secure, limit=limit, commit_transform=contradict
    )
    result = run(
        bound, schedule, spec, client, config=ConcurrencyEffectExecutionConfig(True)
    )
    assert_invalid(result, 4)
    assert result.compensating_cleanup_verified
    assert client.consumed == client.initial_consumed


def test_malformed_observation_stops_operations_then_still_cleans_up():
    bound, schedule, spec, client = setup(
        commit_transform=lambda response: {"consumed": 1}
    )
    result = run(
        bound, schedule, spec, client, config=ConcurrencyEffectExecutionConfig(True)
    )
    assert_invalid(result, 3)
    assert result.compensating_cleanup_verified
    assert [item["kind"] for item in client.requests] == [
        "observe",
        "observe",
        "commit",
        "cleanup",
    ]


def test_operation_exception_still_attempts_cleanup_once():
    bound, schedule, spec, client = setup(fail_commit=True)
    result = run(
        bound, schedule, spec, client, config=ConcurrencyEffectExecutionConfig(True)
    )
    assert_invalid(result, 3)
    assert result.compensating_cleanup_verified
    assert [item["kind"] for item in client.requests] == [
        "observe",
        "observe",
        "commit",
        "cleanup",
    ]


def test_transport_and_client_do_not_read_model_channel(monkeypatch):
    bound, schedule, spec, client = setup()
    transport = ConcurrencyEffectTransport(spec, client)
    transport._bind(bound)

    def fail(*_, **__):
        pytest.fail("transport or client consulted the model channel")

    for owner, names in (
        (
            contract_module,
            (
                "classify_schedule",
                "replay_schedule",
                "operation_guard",
                "apply_commit",
                "serial_schedules",
                "is_serializable_safe",
                "evaluate_invariant",
            ),
        ),
        (ledger_module, ("evaluate_schedule", "replay_schedule")),
        (effect_module, ("evaluate_schedule",)),
        (module, ("evaluate_schedule",)),
    ):
        for name in names:
            monkeypatch.setattr(owner, name, fail)
    operations = {op.operation_ref: op for op in bound.fixture.contract.operations}
    responses = [
        transport.step(bound, micro_step, operations[micro_step.operation_ref])
        for micro_step in schedule.steps
    ]
    assert responses[:2] == [None, None]
    assert responses[-1].state.consumed == 2
    assert (
        observed_effect_oracle(bound.fixture.contract.invariant, responses[-1].state)
        is ConcurrencyEffectOutcome.EFFECT_OBSERVED_VIOLATION
    )
    assert transport.cleanup(bound)
    assert client.consumed == client.initial_consumed


def test_maximum_budget_is_ordered_and_never_exceeds_one_cleanup():
    base, _ = case(limit=MAX_CONCURRENCY_OPERATIONS)
    operations = tuple(
        replace(
            original,
            operation_ref=stable_hash(
                "concurrency_operation", f"{actor_index}-{index}"
            ),
            op_index=index,
        )
        for actor_index, original in enumerate(base.contract.operations)
        for index in range(MAX_CONCURRENCY_OPERATIONS // 2)
    )
    fixture = _fixture_with(base, operations=operations)
    bound = _bind_fixture(fixture)
    schedule = WorkflowSchedule(
        fixture.contract,
        tuple(
            MicroStep(operation.actor_ref, operation.operation_ref, kind)
            for operation in operations
            for kind in (StepKind.OBSERVE, StepKind.COMMIT)
        ),
    )
    spec = ConcurrencyEffectTransportSpec(
        bound.binding_id,
        ORIGIN,
        tuple(f"{ORIGIN}/consume/{index}" for index in range(len(operations))),
        f"{ORIGIN}/cleanup",
    )
    client = OwnedTargetClient(fixture.contract)
    result = run(
        bound, schedule, spec, client, config=ConcurrencyEffectExecutionConfig(True)
    )
    assert result.correspondence is ConcurrencyEffectCorrespondence.COHERENT
    assert result.step_attempts == MAX_SCHEDULE_STEPS == 24
    assert result.cleanup_attempts == 1
    assert len(client.requests) == MAX_SCHEDULE_STEPS + 1 == 25
    assert [item["index"] for item in client.requests[:-1]] == list(
        range(MAX_SCHEDULE_STEPS)
    )
    assert [item["kind"] for item in client.requests[:-1]] == [
        kind for _ in operations for kind in ("observe", "commit")
    ]
    assert [item["url"] for item in client.requests] == [
        url for url in spec.operation_urls for _ in (0, 1)
    ] + [spec.cleanup_url]
    assert client.requests[-1]["kind"] == "cleanup"


def test_config_spec_and_result_are_frozen_content_addressed_roundtrips():
    bound, schedule, spec, client = setup()
    config = ConcurrencyEffectExecutionConfig(True)
    result = run(bound, schedule, spec, client, config=config)
    for value, cls, field in (
        (config, ConcurrencyEffectExecutionConfig, "enabled"),
        (spec, ConcurrencyEffectTransportSpec, "target_origin"),
        (result, ConcurrencyEffectTransportResult, "admitted"),
    ):
        assert cls.from_dict(json.loads(json.dumps(value.to_dict()))) == value
        with pytest.raises(FrozenInstanceError):
            setattr(value, field, None)
    assert spec.specification_id == stable_hash(
        "concurrency_effect_transport_specification", spec._payload()
    )
    assert result.result_id == stable_hash(
        "concurrency_effect_transport_result", result._payload()
    )
    flags = result.to_dict()
    assert flags["target_origin_confined"] is True
    for key in (
        "owned_target_origin_bound",
        "real_concurrency_effect_observed",
        "wired_into_production",
        "finding_authority",
        "promotion_authority",
    ):
        assert flags[key] is False
    denied = run(None, None, None, client, config=ConcurrencyEffectExecutionConfig())
    assert ConcurrencyEffectTransportResult.from_dict(denied.to_dict()) == denied


@pytest.mark.parametrize("kind", ["config", "spec", "result"])
def test_each_address_mismatch_is_refused(kind):
    bound, schedule, spec, client = setup()
    values = {
        "config": (
            ConcurrencyEffectExecutionConfig(True),
            ConcurrencyEffectExecutionConfig,
            "config_id",
        ),
        "spec": (spec, ConcurrencyEffectTransportSpec, "specification_id"),
        "result": (
            run(
                bound,
                schedule,
                spec,
                client,
                config=ConcurrencyEffectExecutionConfig(True),
            ),
            ConcurrencyEffectTransportResult,
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
        ("result", "promotion_authority", True),
        ("result", "real_concurrency_effect_observed", True),
        ("result", "wired_into_production", True),
        ("result", "compensating_cleanup_verified", False),
        ("result", "effect_evidence", None),
        ("result", "target_origin_confined", False),
        ("result", "owned_target_origin_bound", True),
    ],
)
def test_serialized_tampering_is_refused(kind, field, value):
    bound, schedule, spec, client = setup()
    objects = {
        "config": (
            ConcurrencyEffectExecutionConfig(True),
            ConcurrencyEffectExecutionConfig,
        ),
        "spec": (spec, ConcurrencyEffectTransportSpec),
        "result": (
            run(
                bound,
                schedule,
                spec,
                client,
                config=ConcurrencyEffectExecutionConfig(True),
            ),
            ConcurrencyEffectTransportResult,
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


def _assert_transport_imports(tree):
    assert not _import_references(tree) & _FORBIDDEN
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            assert all(
                not alias.name.startswith("urllib")
                and (alias.name == "os" or not alias.name.startswith("os."))
                for alias in node.names
            )
        elif isinstance(node, ast.ImportFrom) and (node.module or "").startswith(
            "urllib"
        ):
            assert node.module == "urllib.parse"
            assert {alias.name for alias in node.names} == {"urlsplit"}
        elif isinstance(node, ast.ImportFrom) and (node.module or "").startswith("os"):
            assert node.module == "os"
            assert {alias.name for alias in node.names} == {"environ"}
    os_attributes = {
        node.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id == "os"
    }
    assert os_attributes == {"environ"}


def test_transport_is_unwired_and_has_no_forbidden_imports():
    path = REPOSITORY / "core/behavior/concurrency_invariant_effect_transport.py"
    _assert_transport_imports(ast.parse(path.read_text()))
    family = {
        f"concurrency_invariant_{suffix}"
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
    for candidate in (REPOSITORY / "core").rglob("*.py"):
        if candidate.stem in family:
            continue
        if "concurrency_invariant_effect_transport" in _import_references(
            ast.parse(candidate.read_text())
        ):
            consumers.append(str(candidate))
    assert consumers == []


@pytest.mark.parametrize(
    "stem", ["unrelated_consumer", "concurrency_invariant_effect_transport_extra", "concurrency_invariant_effect_one_click_extra"]
)
@pytest.mark.parametrize(
    "audit,imported",
    [
        (spine_import_audit, "concurrency_invariant_contract"),
        (effect_import_audit, "concurrency_invariant_effect"),
        (
            test_transport_is_unwired_and_has_no_forbidden_imports,
            "concurrency_invariant_effect_transport",
        ),
    ],
)
def test_all_three_audits_reject_other_consumers(monkeypatch, stem, audit, imported):
    added = REPOSITORY / "core/behavior" / f"{stem}.py"
    original_rglob, original_read = Path.rglob, Path.read_text

    def with_consumer(path, pattern):
        yield from original_rglob(path, pattern)
        if path == REPOSITORY / "core":
            yield added

    def read(path, *args, **kwargs):
        if path == added:
            return f"from core.behavior import {imported}\n"
        return original_read(path, *args, **kwargs)

    monkeypatch.setattr(Path, "rglob", with_consumer)
    monkeypatch.setattr(Path, "read_text", read)
    with pytest.raises(AssertionError):
        audit()


@pytest.mark.parametrize(
    "forbidden",
    sorted(_FORBIDDEN)
    + [
        "urllib.request",
        "os.open",
        "from os import system",
        "from urllib.request import urlopen",
    ],
)
def test_transport_import_audit_rejects_each_forbidden_surface(monkeypatch, forbidden):
    path = Path(module.__file__)
    original_read = Path.read_text

    def read(candidate, *args, **kwargs):
        source = original_read(candidate, *args, **kwargs)
        injected = forbidden if forbidden.startswith("from ") else f"import {forbidden}"
        return source + f"\n{injected}\n" if candidate == path else source

    monkeypatch.setattr(Path, "read_text", read)
    with pytest.raises(AssertionError):
        test_transport_is_unwired_and_has_no_forbidden_imports()


def test_registry_and_verbatim_honesty_statement():
    registry = IdentifierRegistry.load(default_registry_path(REPOSITORY))
    assert "R5F7" in registry.canonical_ids
    records = json.loads(default_registry_path(REPOSITORY).read_text())["canonical_ids"]
    assert [record for record in records if record["id"] == "R5F7"] == [
        {
            "id": "R5F7",
            "kind": "slice",
            "description": "Bounded, admission-gated (default-off), origin-confined concurrency-effect transport with verified compensating cleanup; unwired (no production caller)",
        }
    ]
    assert _HONESTY in module.__doc__
    docstring = " ".join(module.__doc__.split())
    assert (
        "It is not evidence of an effect against a live running target, it is not "
        "wired into any production caller, and it carries no finding-promotion "
        "or durable-receipt authority and no OCB-S22/native claim."
    ) in docstring
