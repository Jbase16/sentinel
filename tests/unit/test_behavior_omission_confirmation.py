"""Three-fresh-object omission confirmation tests using in-memory transports."""

from __future__ import annotations

import ast
import json
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

import core.behavior as behavior_package
import core.behavior.omission_confirmation as confirmation_module
from core.behavior.feedback import ReceiptDispositionAdapter, ReceiptFeedbackDenied
from core.behavior.lifecycle import LifecycleContractMiner
from core.behavior.obligations import (
    BLOCKED,
    UPHELD,
    VIOLATED,
    SecurityObligationGraphBuilder,
)
from core.behavior.omission import MinimizedOmissionCompiler
from core.behavior.omission_confirmation import (
    FRESH_OMISSION_CONFIRMATION_ENV,
    FRESH_OMISSION_CONFIRMATION_WORKFLOW,
    FreshOmissionConfirmationAdmission,
    FreshOmissionConfirmationConfig,
    FreshOmissionConfirmationExecutor,
)
from core.behavior.omission_boundary import (
    FRESH_OMISSION_WORKFLOW,
    FreshOmissionDenied,
)
from core.behavior.receipts import BehavioralReceiptStore
from core.behavior.runtime import CONTROLLED_SEQUENCE_WORKFLOW
from core.behavior.state_machine import StateMachineLegalityMiner
from core.cortex.execution_policy import ExecutionPolicy, PolicyExecutor
from core.foundry.authorization import AuthorizationEnvelope
from core.safety.ownership_registry import OwnershipRegistry
from core.safety.proof_budget import ProofBudget
from core.safety.provenance import ProvenanceSink

ORIGIN = "https://api.example.test"
CAPTURED_ID = "workflow_7fa9f13a2b4c5d6e"
CAPTURED_TOKEN = "token_4a5b6c7d8e9f0123"
BASELINE_ID = "workflow_fresh_baseline_8b9c0d1e2f3a"
OMISSION_ID = "workflow_fresh_omission_5b6c7d8e9f0a"
CONTROL_ID = "workflow_fresh_control_2c3d4e5f6a7b"
BASELINE_TOKEN = "token_fresh_baseline_12345678"
REFERENCE_BODY = {"status": "ready", "artifact": "controlled"}


def _records():
    return (
        {
            "id": "create-workflow",
            "persona_id": "alice",
            "method": "POST",
            "url": f"{ORIGIN}/api/workflows",
            "request_headers": {"x-csrf-token": "csrf-alice"},
            "request_body": '{"label":"controlled"}',
            "response_status": 201,
            "response_body": json.dumps({"workflowId": CAPTURED_ID}),
        },
        {
            "id": "fetch-export-capability",
            "persona_id": "alice",
            "method": "GET",
            "url": f"{ORIGIN}/api/workflows/{CAPTURED_ID}/export-token",
            "request_headers": {"x-csrf-token": "csrf-alice"},
            "response_status": 200,
            "response_body": json.dumps({"exportToken": CAPTURED_TOKEN}),
        },
        {
            "id": "export-workflow",
            "persona_id": "alice",
            "method": "GET",
            "url": (
                f"{ORIGIN}/api/workflows/{CAPTURED_ID}/export"
                f"?format=json&exportToken={CAPTURED_TOKEN}"
            ),
            "request_headers": {"x-csrf-token": "csrf-alice"},
            "response_status": 200,
            "response_body": json.dumps(REFERENCE_BODY),
        },
        {
            "id": "cleanup-workflow",
            "persona_id": "alice",
            "method": "PATCH",
            "url": f"{ORIGIN}/api/workflows/{CAPTURED_ID}",
            "request_headers": {"x-csrf-token": "csrf-alice"},
            "request_body": '{"archived":true}',
            "response_status": 200,
            "response_body": '{"archived":true}',
        },
    )


def _experiment():
    records = _records()
    lifecycle = LifecycleContractMiner().mine(records, world_id="alice")
    state_machine = StateMachineLegalityMiner().mine(
        records,
        world_id="alice",
    )
    result = MinimizedOmissionCompiler().compile(
        records,
        world_id="alice",
        lifecycle=lifecycle,
        state_machine=state_machine,
    )
    assert len(result.experiments) == 1
    return result.experiments[0]


def _graph():
    records = _records()
    lifecycle = LifecycleContractMiner().mine(records, world_id="alice")
    state_machine = StateMachineLegalityMiner().mine(
        records,
        world_id="alice",
    )
    omissions = MinimizedOmissionCompiler().compile(
        records,
        world_id="alice",
        lifecycle=lifecycle,
        state_machine=state_machine,
    )
    return SecurityObligationGraphBuilder().build(
        target_origin=ORIGIN,
        lifecycle=lifecycle,
        state_machine=state_machine,
        omissions=omissions,
    )


def _authorization(*, include_confirmation: bool = True):
    workflows = [
        CONTROLLED_SEQUENCE_WORKFLOW,
        FRESH_OMISSION_WORKFLOW,
    ]
    if include_confirmation:
        workflows.append(FRESH_OMISSION_CONFIRMATION_WORKFLOW)
    envelope = AuthorizationEnvelope(
        envelope_id="fresh-omission-confirmation-envelope",
        researcher_identity="researcher",
        target_handle="example",
        authorized_origins=[ORIGIN],
        authorization_basis="authorized fresh omission confirmation test",
        disclosure_attestation=True,
        allowed_workflows=workflows,
        created_at=1_780_000_000.0,
        expires_at=1_900_000_000.0,
    )
    envelope.sign()
    return envelope


def _boundary(raw_send, *, authorization=None, budget=None, enabled=True):
    policy = ExecutionPolicy(
        "bounty_safe",
        scope_filter=lambda url: url.startswith(ORIGIN),
        budget=budget
        or ProofBudget(
            max_total_requests=10,
            max_requests_per_endpoint=3,
            max_cross_object_reads=0,
            max_privilege_mutations=0,
            max_creates=3,
            allow_delete=False,
            allow_real_user_data_access=False,
        ),
        ownership_registry=OwnershipRegistry(),
    )
    provenance = ProvenanceSink()
    provenance.record_context(
        target=ORIGIN,
        proof_mode="bounty_safe",
        policy_digest=policy.digest(),
    )
    executor = PolicyExecutor(raw_send, policy, provenance=provenance)
    boundary = FreshOmissionConfirmationExecutor(
        _records(),
        world_id="alice",
        target_origin=ORIGIN,
        authorization=authorization or _authorization(),
        actor_persona_id="alice",
        executor=executor,
        experiment=_experiment(),
        config=FreshOmissionConfirmationConfig(enabled=enabled),
    )
    return boundary, executor


@pytest.mark.asyncio
async def test_known_valid_wrong_object_rejection_confirms_fail_open():
    calls = []
    creates = iter((BASELINE_ID, OMISSION_ID, CONTROL_ID))

    async def raw(method, url, body=None, **kwargs):
        calls.append((method, url, body, kwargs))
        path = urlsplit(url).path
        query = parse_qs(urlsplit(url).query)
        if method == "POST":
            return 201, {"workflowId": next(creates)}
        if method == "PATCH":
            return 200, {"archived": True}
        if path.endswith("/export-token"):
            return 200, {"exportToken": BASELINE_TOKEN}
        if path == f"/api/workflows/{CONTROL_ID}/export":
            assert query["exportToken"] == [BASELINE_TOKEN]
            return 403, {"error": "capability belongs to another workflow"}
        if path.endswith("/export"):
            return 200, dict(REFERENCE_BODY)
        raise AssertionError(f"unexpected request: {method} {url}")

    boundary, executor = _boundary(raw)
    confirmation_id = boundary.validate_preflight()

    result = await boundary.execute(expected_boundary_id=confirmation_id)

    assert result.status == "completed"
    assert result.confirmation_status == "confirmed_fail_open"
    assert result.capability_object_binding_proven is True
    assert result.finding_authority is True
    assert result.finding is not None
    assert result.finding.confirmation_id == confirmation_id
    assert result.control_response_status == 403
    assert result.requests_attempted == result.requests_sent == 10
    assert result.baseline_steps_completed == 3
    assert result.omission_steps_completed == 2
    assert result.control_steps_completed == 2
    assert result.creates_completed == 3
    assert result.cleanup_steps_completed == 3
    assert [(method, urlsplit(url).path) for method, url, *_ in calls] == [
        ("POST", "/api/workflows"),
        ("GET", f"/api/workflows/{BASELINE_ID}/export-token"),
        ("GET", f"/api/workflows/{BASELINE_ID}/export"),
        ("POST", "/api/workflows"),
        ("GET", f"/api/workflows/{OMISSION_ID}/export"),
        ("POST", "/api/workflows"),
        ("GET", f"/api/workflows/{CONTROL_ID}/export"),
        ("PATCH", f"/api/workflows/{CONTROL_ID}"),
        ("PATCH", f"/api/workflows/{OMISSION_ID}"),
        ("PATCH", f"/api/workflows/{BASELINE_ID}"),
    ]
    assert parse_qs(urlsplit(calls[2][1]).query)["exportToken"] == [BASELINE_TOKEN]
    assert "exportToken" not in parse_qs(urlsplit(calls[4][1]).query)
    assert parse_qs(urlsplit(calls[6][1]).query)["exportToken"] == [BASELINE_TOKEN]
    assert executor.policy.budget.snapshot() == {
        "total_requests": 10,
        "cross_object_reads": 0,
        "privilege_mutations": 0,
        "creates": 3,
        "endpoints_touched": 4,
    }
    serialized = json.dumps(result.to_dict(), sort_keys=True)
    for secret in (
        ORIGIN,
        CAPTURED_ID,
        CAPTURED_TOKEN,
        BASELINE_ID,
        OMISSION_ID,
        CONTROL_ID,
        BASELINE_TOKEN,
        "alice",
        "controlled",
    ):
        assert secret not in serialized


@pytest.mark.asyncio
async def test_control_acceptance_prevents_finding_authority():
    creates = iter((BASELINE_ID, OMISSION_ID, CONTROL_ID))

    async def raw(method, url, body=None, **kwargs):
        if method == "POST":
            return 201, {"workflowId": next(creates)}
        if method == "PATCH":
            return 200, {"archived": True}
        if urlsplit(url).path.endswith("/export-token"):
            return 200, {"exportToken": BASELINE_TOKEN}
        return 200, dict(REFERENCE_BODY)

    boundary, _executor = _boundary(raw)
    result = await boundary.execute()

    assert result.status == "completed"
    assert result.confirmation_status == "control_accepted"
    assert result.capability_object_binding_proven is False
    assert result.finding_authority is False
    assert result.finding is None
    assert result.requests_sent == 10
    assert result.cleanup_steps_completed == 3


@pytest.mark.asyncio
async def test_omission_mismatch_suppresses_control_and_releases_its_budget():
    calls = []
    creates = iter((BASELINE_ID, OMISSION_ID))

    async def raw(method, url, body=None, **kwargs):
        calls.append((method, url))
        if method == "POST":
            return 201, {"workflowId": next(creates)}
        if method == "PATCH":
            return 200, {"archived": True}
        if urlsplit(url).path.endswith("/export-token"):
            return 200, {"exportToken": BASELINE_TOKEN}
        if OMISSION_ID in url:
            return 200, {"status": "ready", "artifact": "different"}
        return 200, dict(REFERENCE_BODY)

    boundary, _executor = _boundary(raw)
    result = await boundary.execute()

    assert result.status == "completed"
    assert result.confirmation_status == "response_mismatch"
    assert result.control_steps_attempted == 0
    assert result.creates_completed == 2
    assert result.cleanup_steps_completed == 2
    assert result.requests_sent == 7
    assert result.finding is None
    assert all(CONTROL_ID not in url for _method, url in calls)


@pytest.mark.parametrize("control_status", (404, 500))
@pytest.mark.asyncio
async def test_unqualified_control_rejection_is_inconclusive_not_a_finding(
    control_status,
):
    creates = iter((BASELINE_ID, OMISSION_ID, CONTROL_ID))

    async def raw(method, url, body=None, **kwargs):
        if method == "POST":
            return 201, {"workflowId": next(creates)}
        if method == "PATCH":
            return 200, {"archived": True}
        if urlsplit(url).path.endswith("/export-token"):
            return 200, {"exportToken": BASELINE_TOKEN}
        if CONTROL_ID in url:
            return control_status, {"error": "unqualified rejection"}
        return 200, dict(REFERENCE_BODY)

    boundary, _executor = _boundary(raw)
    result = await boundary.execute()

    assert result.status == "completed"
    assert result.confirmation_status == "control_inconclusive"
    assert result.control_response_status == control_status
    assert result.finding_authority is False
    assert result.finding is None


@pytest.mark.asyncio
async def test_cleanup_failure_revokes_otherwise_confirmed_finding():
    creates = iter((BASELINE_ID, OMISSION_ID, CONTROL_ID))

    async def raw(method, url, body=None, **kwargs):
        path = urlsplit(url).path
        if method == "POST":
            return 201, {"workflowId": next(creates)}
        if method == "PATCH":
            if CONTROL_ID in url:
                return 500, {"error": "cleanup failed"}
            return 200, {"archived": True}
        if path.endswith("/export-token"):
            return 200, {"exportToken": BASELINE_TOKEN}
        if CONTROL_ID in url:
            return 403, {"error": "wrong workflow"}
        return 200, dict(REFERENCE_BODY)

    boundary, _executor = _boundary(raw)
    result = await boundary.execute()

    assert result.status == "cleanup_failed"
    assert result.confirmation_status == "inconclusive_cleanup_failed"
    assert result.error_code == "fresh_omission_confirmation_cleanup_failed"
    assert result.orphaned_owned_state_possible is True
    assert result.finding_authority is False
    assert result.finding is None


@pytest.mark.asyncio
async def test_admission_receipt_is_redacted_and_suppresses_duplicate_traffic(
    tmp_path,
):
    calls = []
    creates = iter((BASELINE_ID, OMISSION_ID, CONTROL_ID))

    async def raw(method, url, body=None, **kwargs):
        calls.append((method, url))
        if method == "POST":
            return 201, {"workflowId": next(creates)}
        if method == "PATCH":
            return 200, {"archived": True}
        if urlsplit(url).path.endswith("/export-token"):
            return 200, {"exportToken": BASELINE_TOKEN}
        if CONTROL_ID in url:
            return 403, {"error": "wrong workflow"}
        return 200, dict(REFERENCE_BODY)

    store = BehavioralReceiptStore(tmp_path)
    boundary, _executor = _boundary(raw)
    first = await FreshOmissionConfirmationAdmission(
        boundary,
        receipt_store=store,
    ).execute()

    assert first.status == "completed"
    assert first.reused is False
    assert first.execution["kind"] == "fresh_omission_confirmation"
    assert first.execution["finding_authority"] is True
    assert first.execution["finding_ref"].startswith("omission_capability_finding:")
    assert first.execution["finding"] is None
    assert len(calls) == 10
    receipt = store.load(first.receipt_id.removeprefix("behavioral-"))
    assert receipt is not None
    graph = _graph()
    feedback = ReceiptDispositionAdapter().adapt(
        graph,
        (receipt,),
        expected_context=receipt.context,
    )
    assert feedback.status == "ready"
    assert feedback.diagnostics.dispositions_created == 1
    disposition = feedback.dispositions[0]
    assert disposition.status == VIOLATED
    assert disposition.reason_code == "omission_capability_fail_open_confirmed"
    assert disposition.evidence_refs == tuple(
        sorted(
            (
                f"behavioral_receipt:{receipt.fingerprint}",
                first.execution["finding_ref"],
            )
        )
    )

    assert receipt.outcome is not None
    original_experiment_id = receipt.outcome["experiment_id"]
    receipt.outcome["experiment_id"] = "omission_experiment:" + "9" * 64
    with pytest.raises(
        ReceiptFeedbackDenied,
        match="no_exact_open_omission_obligation",
    ):
        ReceiptDispositionAdapter().adapt(
            graph,
            (receipt,),
            expected_context=receipt.context,
        )
    receipt.outcome["experiment_id"] = original_experiment_id

    receipt.outcome.update(
        {
            "confirmation_status": "omission_rejected",
            "omission_terminal_success": False,
            "control_terminal_success": False,
            "terminal_body_match": False,
            "capability_object_binding_proven": False,
            "control_response_status": None,
            "requests_attempted": 7,
            "requests_sent": 7,
            "control_steps_attempted": 0,
            "control_steps_completed": 0,
            "creates_attempted": 2,
            "creates_completed": 2,
            "cleanup_steps_attempted": 2,
            "cleanup_steps_completed": 2,
            "budget_snapshot": {
                "total_requests": 7,
                "cross_object_reads": 0,
                "privilege_mutations": 0,
                "creates": 2,
                "endpoints_touched": 4,
            },
            "finding_authority": False,
            "finding_ref": None,
        }
    )
    upheld = ReceiptDispositionAdapter().adapt(
        graph,
        (receipt,),
        expected_context=receipt.context,
    )
    assert upheld.dispositions[0].status == UPHELD
    assert upheld.dispositions[0].reason_code == "omission_prerequisite_enforced"

    receipt.outcome.update(
        {
            "confirmation_status": "control_accepted",
            "omission_terminal_success": True,
            "control_terminal_success": True,
            "terminal_body_match": True,
            "control_response_status": 200,
            "requests_attempted": 10,
            "requests_sent": 10,
            "control_steps_attempted": 2,
            "control_steps_completed": 2,
            "creates_attempted": 3,
            "creates_completed": 3,
            "cleanup_steps_attempted": 3,
            "cleanup_steps_completed": 3,
            "budget_snapshot": {
                "total_requests": 10,
                "cross_object_reads": 0,
                "privilege_mutations": 0,
                "creates": 3,
                "endpoints_touched": 4,
            },
        }
    )
    blocked = ReceiptDispositionAdapter().adapt(
        graph,
        (receipt,),
        expected_context=receipt.context,
    )
    assert blocked.dispositions[0].status == BLOCKED
    assert blocked.dispositions[0].reason_code == (
        "omission_capability_control_accepted"
    )

    async def forbidden(*_args, **_kwargs):
        raise AssertionError("completed receipt must suppress duplicate traffic")

    duplicate, _executor = _boundary(forbidden)
    second = await FreshOmissionConfirmationAdmission(
        duplicate,
        receipt_store=store,
    ).execute()

    assert second.status == "already_executed"
    assert second.reused is True
    assert second.execution == first.execution
    persisted = next(tmp_path.glob("behavioral-*.json")).read_text()
    for secret in (
        ORIGIN,
        CAPTURED_ID,
        CAPTURED_TOKEN,
        BASELINE_ID,
        OMISSION_ID,
        CONTROL_ID,
        BASELINE_TOKEN,
        "alice",
        "controlled",
    ):
        assert secret not in persisted


def test_confirmation_requires_separate_gate_workflow_and_exact_budget():
    calls = []

    async def forbidden(*args, **kwargs):
        calls.append((args, kwargs))
        raise AssertionError("preflight rejection must have zero traffic")

    disabled, _executor = _boundary(forbidden, enabled=False)
    with pytest.raises(FreshOmissionDenied, match="is_disabled"):
        disabled.validate_preflight()

    unsigned_for_confirmation, _executor = _boundary(
        forbidden,
        authorization=_authorization(include_confirmation=False),
    )
    with pytest.raises(FreshOmissionDenied, match="authorization_denied"):
        unsigned_for_confirmation.validate_preflight()

    wrong_budget, _executor = _boundary(
        forbidden,
        budget=ProofBudget(
            max_total_requests=10,
            max_requests_per_endpoint=3,
            max_cross_object_reads=0,
            max_privilege_mutations=0,
            max_creates=2,
            allow_delete=False,
            allow_real_user_data_access=False,
        ),
    )
    with pytest.raises(FreshOmissionDenied, match="exact_unused"):
        wrong_budget.validate_preflight()

    assert calls == []


def test_environment_gate_requires_all_four_flags(monkeypatch):
    from core.behavior.admission import COMPILED_ADMISSION_ENV
    from core.behavior.omission_boundary import FRESH_OMISSION_ENV
    from core.behavior.scheduler import PRIMARY_ENV

    names = (
        PRIMARY_ENV,
        COMPILED_ADMISSION_ENV,
        FRESH_OMISSION_ENV,
        FRESH_OMISSION_CONFIRMATION_ENV,
    )
    for name in names:
        monkeypatch.setenv(name, "true")
    assert FreshOmissionConfirmationConfig.from_environment().enabled is True

    for missing in names:
        monkeypatch.delenv(missing)
        assert FreshOmissionConfirmationConfig.from_environment().enabled is False
        monkeypatch.setenv(missing, "true")


def test_confirmation_stays_explicit_only_without_network_dependency():
    tree = ast.parse(Path(confirmation_module.__file__).read_text())
    imported_roots = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported_roots.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported_roots.add(node.module.split(".", 1)[0])

    assert not imported_roots & {
        "aiohttp",
        "httpx",
        "requests",
        "socket",
        "urllib3",
        "websockets",
    }
    assert not hasattr(
        behavior_package,
        "FreshOmissionConfirmationExecutor",
    )
