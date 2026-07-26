"""Fresh omission boundary tests using in-memory transports only."""

from __future__ import annotations

import ast
import json
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

import core.behavior as behavior_package
import core.behavior.omission_boundary as omission_boundary_module
from core.behavior.admission import COMPILED_ADMISSION_ENV
from core.behavior.lifecycle import LifecycleContractMiner
from core.behavior.omission import MinimizedOmissionCompiler
from core.behavior.omission_boundary import (
    FRESH_OMISSION_ENV,
    FRESH_OMISSION_WORKFLOW,
    FreshOmissionAdmission,
    FreshOmissionBoundaryExecutor,
    FreshOmissionConfig,
    FreshOmissionDenied,
)
from core.behavior.receipts import BehavioralReceiptStore
from core.behavior.runtime import CONTROLLED_SEQUENCE_WORKFLOW
from core.behavior.scheduler import PRIMARY_ENV
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
BASELINE_TOKEN = "token_fresh_baseline_12345678"
REFERENCE_BODY = {"status": "ready", "artifact": "controlled"}


def _records(*, state_changing_prerequisite: bool = False):
    prerequisite_method = "POST" if state_changing_prerequisite else "GET"
    prerequisite_path = "approve" if state_changing_prerequisite else "export-token"
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
            "method": prerequisite_method,
            "url": (f"{ORIGIN}/api/workflows/{CAPTURED_ID}/{prerequisite_path}"),
            "request_headers": {"x-csrf-token": "csrf-alice"},
            "request_body": "{}" if prerequisite_method == "POST" else None,
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


def _experiment(records=None):
    values = tuple(records or _records())
    lifecycle = LifecycleContractMiner().mine(values, world_id="alice")
    state_machine = StateMachineLegalityMiner().mine(values, world_id="alice")
    result = MinimizedOmissionCompiler().compile(
        values,
        world_id="alice",
        lifecycle=lifecycle,
        state_machine=state_machine,
    )
    assert len(result.experiments) == 1
    return result.experiments[0]


def _authorization(*, workflows=None):
    envelope = AuthorizationEnvelope(
        envelope_id="fresh-omission-envelope",
        researcher_identity="researcher",
        target_handle="example",
        authorized_origins=[ORIGIN],
        authorization_basis="authorized fresh omission test",
        disclosure_attestation=True,
        allowed_workflows=list(
            workflows or (CONTROLLED_SEQUENCE_WORKFLOW, FRESH_OMISSION_WORKFLOW)
        ),
        created_at=1_780_000_000.0,
        expires_at=1_900_000_000.0,
    )
    envelope.sign()
    return envelope


def _policy_executor(raw_send, *, budget=None):
    policy = ExecutionPolicy(
        "bounty_safe",
        scope_filter=lambda url: url.startswith(ORIGIN),
        budget=budget
        or ProofBudget(
            max_total_requests=7,
            max_requests_per_endpoint=2,
            max_cross_object_reads=0,
            max_privilege_mutations=0,
            max_creates=2,
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
    return PolicyExecutor(raw_send, policy, provenance=provenance)


def _boundary(
    raw_send,
    *,
    records=None,
    authorization=None,
    budget=None,
    enabled=True,
):
    values = tuple(records or _records())
    executor = _policy_executor(raw_send, budget=budget)
    boundary = FreshOmissionBoundaryExecutor(
        values,
        world_id="alice",
        target_origin=ORIGIN,
        authorization=authorization or _authorization(),
        actor_persona_id="alice",
        executor=executor,
        experiment=_experiment(values),
        config=FreshOmissionConfig(enabled=enabled),
    )
    return boundary, executor


@pytest.mark.asyncio
async def test_fresh_omission_runs_exact_baseline_and_omission_then_cleans_both():
    calls = []
    creates = iter((BASELINE_ID, OMISSION_ID))

    async def raw(method, url, body=None, **kwargs):
        calls.append((method, url, body, kwargs))
        path = urlsplit(url).path
        if method == "POST":
            return 201, {"workflowId": next(creates)}
        if method == "PATCH":
            return 200, {"archived": True}
        if path.endswith("/export-token"):
            return 200, {"exportToken": BASELINE_TOKEN}
        if path.endswith("/export"):
            return 200, dict(REFERENCE_BODY)
        raise AssertionError(f"unexpected request: {method} {url}")

    boundary, executor = _boundary(raw)
    preflight_id = boundary.validate_preflight()

    result = await boundary.execute(expected_boundary_id=preflight_id)

    assert result.boundary_id == preflight_id
    assert result.status == "completed"
    assert result.comparison_status == "exact_match"
    assert result.baseline_reference_match is True
    assert result.terminal_body_match is True
    assert result.finding_authority is False
    assert result.finding is None
    assert result.requests_attempted == result.requests_sent == 7
    assert result.baseline_steps_attempted == result.baseline_steps_completed == 3
    assert result.omission_steps_attempted == result.omission_steps_completed == 2
    assert result.creates_attempted == result.creates_completed == 2
    assert result.cleanup_steps_attempted == result.cleanup_steps_completed == 2
    assert [(method, urlsplit(url).path) for method, url, *_rest in calls] == [
        ("POST", "/api/workflows"),
        ("GET", f"/api/workflows/{BASELINE_ID}/export-token"),
        ("GET", f"/api/workflows/{BASELINE_ID}/export"),
        ("POST", "/api/workflows"),
        ("GET", f"/api/workflows/{OMISSION_ID}/export"),
        ("PATCH", f"/api/workflows/{OMISSION_ID}"),
        ("PATCH", f"/api/workflows/{BASELINE_ID}"),
    ]
    baseline_query = parse_qs(urlsplit(calls[2][1]).query)
    omission_query = parse_qs(urlsplit(calls[4][1]).query)
    assert baseline_query == {
        "format": ["json"],
        "exportToken": [BASELINE_TOKEN],
    }
    assert omission_query == {"format": ["json"]}
    assert all(call[3]["headers"]["x-csrf-token"] == "csrf-alice" for call in calls)
    assert executor.policy.budget.snapshot() == {
        "total_requests": 7,
        "cross_object_reads": 0,
        "privilege_mutations": 0,
        "creates": 2,
        "endpoints_touched": 4,
    }
    serialized = json.dumps(result.to_dict(), sort_keys=True)
    for raw_value in (
        ORIGIN,
        CAPTURED_ID,
        CAPTURED_TOKEN,
        BASELINE_ID,
        OMISSION_ID,
        BASELINE_TOKEN,
        "alice",
        "controlled",
    ):
        assert raw_value not in serialized


@pytest.mark.asyncio
async def test_admission_reserves_before_traffic_and_reuses_completed_receipt(tmp_path):
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
        return 200, dict(REFERENCE_BODY)

    store = BehavioralReceiptStore(tmp_path)
    first_boundary, _executor = _boundary(raw)
    admission = FreshOmissionAdmission(first_boundary, receipt_store=store)
    fingerprint = admission.validate_preflight()

    first = await admission.execute()

    assert first.status == "completed"
    assert first.reused is False
    assert first.execution["kind"] == "fresh_omission_boundary"
    assert first.execution["finding_authority"] is False
    receipt = store.load(fingerprint)
    assert receipt is not None
    assert receipt.state == "completed"
    assert receipt.outcome == first.execution
    assert len(calls) == 7

    async def forbidden(*_args, **_kwargs):
        raise AssertionError("a completed omission receipt must suppress traffic")

    second_boundary, _executor = _boundary(forbidden)
    second = await FreshOmissionAdmission(
        second_boundary,
        receipt_store=store,
    ).execute()

    assert second.status == "already_executed"
    assert second.reused is True
    assert second.receipt_id == first.receipt_id
    persisted = next(tmp_path.glob("behavioral-*.json")).read_text()
    for raw_value in (
        ORIGIN,
        CAPTURED_ID,
        CAPTURED_TOKEN,
        BASELINE_ID,
        OMISSION_ID,
        BASELINE_TOKEN,
        "alice",
        "controlled",
    ):
        assert raw_value not in persisted


def test_disabled_missing_workflow_and_unsafe_prerequisite_have_zero_traffic():
    calls = []

    async def forbidden(*args, **kwargs):
        calls.append((args, kwargs))
        raise AssertionError("denied preflight must not send traffic")

    disabled, _executor = _boundary(forbidden, enabled=False)
    with pytest.raises(FreshOmissionDenied, match="is_disabled"):
        disabled.validate_preflight()

    missing_workflow, _executor = _boundary(
        forbidden,
        authorization=_authorization(workflows=[CONTROLLED_SEQUENCE_WORKFLOW]),
    )
    with pytest.raises(FreshOmissionDenied, match="authorization_denied"):
        missing_workflow.validate_preflight()

    unsafe_records = _records(state_changing_prerequisite=True)
    unsafe, _executor = _boundary(forbidden, records=unsafe_records)
    with pytest.raises(FreshOmissionDenied, match="unsafe_execution_blockers"):
        unsafe.validate_preflight()

    assert calls == []


def test_boundary_requires_exact_unused_policy_budget():
    async def forbidden(*_args, **_kwargs):
        raise AssertionError("preflight must not send traffic")

    boundary, _executor = _boundary(
        forbidden,
        budget=ProofBudget(
            max_total_requests=8,
            max_requests_per_endpoint=2,
            max_cross_object_reads=0,
            max_privilege_mutations=0,
            max_creates=2,
            allow_delete=False,
            allow_real_user_data_access=False,
        ),
    )

    with pytest.raises(FreshOmissionDenied, match="exact_unused"):
        boundary.validate_preflight()


@pytest.mark.asyncio
async def test_baseline_drift_aborts_before_omission_and_still_cleans():
    calls = []

    async def raw(method, url, body=None, **kwargs):
        calls.append((method, url))
        if method == "POST":
            return 201, {"workflowId": BASELINE_ID}
        if method == "PATCH":
            return 200, {"archived": True}
        if urlsplit(url).path.endswith("/export-token"):
            return 200, {"exportToken": BASELINE_TOKEN}
        return 200, {"status": "changed", "artifact": "controlled"}

    boundary, _executor = _boundary(raw)

    result = await boundary.execute()

    assert result.status == "aborted"
    assert result.error_code == "fresh_omission_baseline_reference_mismatch"
    assert result.comparison_status == "not_completed"
    assert result.creates_completed == 1
    assert result.cleanup_steps_attempted == result.cleanup_steps_completed == 1
    assert result.orphaned_owned_state_possible is False
    assert [(method, urlsplit(url).path) for method, url in calls] == [
        ("POST", "/api/workflows"),
        ("GET", f"/api/workflows/{BASELINE_ID}/export-token"),
        ("GET", f"/api/workflows/{BASELINE_ID}/export"),
        ("PATCH", f"/api/workflows/{BASELINE_ID}"),
    ]


@pytest.mark.asyncio
async def test_setup_failure_after_create_preserves_progress_and_still_cleans():
    calls = []

    async def raw(method, url, body=None, **kwargs):
        calls.append((method, url))
        if method == "POST":
            return 201, {"workflowId": BASELINE_ID}
        if method == "PATCH":
            return 200, {"archived": True}
        return 500, {"error": "capability unavailable"}

    boundary, _executor = _boundary(raw)

    result = await boundary.execute()

    assert result.status == "aborted"
    assert result.error_code == "fresh_omission_setup_step_returned_non_2xx"
    assert result.requests_attempted == result.requests_sent == 3
    assert result.baseline_steps_attempted == 2
    assert result.baseline_steps_completed == 1
    assert result.creates_attempted == result.creates_completed == 1
    assert result.cleanup_steps_attempted == result.cleanup_steps_completed == 1
    assert result.orphaned_owned_state_possible is False
    assert [(method, urlsplit(url).path) for method, url in calls] == [
        ("POST", "/api/workflows"),
        ("GET", f"/api/workflows/{BASELINE_ID}/export-token"),
        ("PATCH", f"/api/workflows/{BASELINE_ID}"),
    ]


@pytest.mark.asyncio
async def test_idempotent_create_cannot_fake_two_fresh_objects():
    calls = []

    async def raw(method, url, body=None, **kwargs):
        calls.append((method, url))
        if method == "POST":
            return 201, {"workflowId": BASELINE_ID}
        if method == "PATCH":
            return 200, {"archived": True}
        if urlsplit(url).path.endswith("/export-token"):
            return 200, {"exportToken": BASELINE_TOKEN}
        return 200, dict(REFERENCE_BODY)

    boundary, _executor = _boundary(raw)

    result = await boundary.execute()

    assert result.status == "aborted"
    assert result.error_code == "fresh_omission_identifiers_are_not_distinct"
    assert result.comparison_status == "not_completed"
    assert result.creates_attempted == result.creates_completed == 2
    assert result.cleanup_steps_attempted == result.cleanup_steps_completed == 1
    assert result.orphaned_owned_state_possible is False
    assert [(method, urlsplit(url).path) for method, url in calls] == [
        ("POST", "/api/workflows"),
        ("GET", f"/api/workflows/{BASELINE_ID}/export-token"),
        ("GET", f"/api/workflows/{BASELINE_ID}/export"),
        ("POST", "/api/workflows"),
        ("PATCH", f"/api/workflows/{BASELINE_ID}"),
    ]


@pytest.mark.asyncio
async def test_cleanup_failure_is_never_hidden_by_exact_comparison():
    creates = iter((BASELINE_ID, OMISSION_ID))

    async def raw(method, url, body=None, **kwargs):
        if method == "POST":
            return 201, {"workflowId": next(creates)}
        if method == "PATCH":
            if OMISSION_ID in url:
                return 500, {"error": "cleanup failed"}
            return 200, {"archived": True}
        if urlsplit(url).path.endswith("/export-token"):
            return 200, {"exportToken": BASELINE_TOKEN}
        return 200, dict(REFERENCE_BODY)

    boundary, _executor = _boundary(raw)

    result = await boundary.execute()

    assert result.comparison_status == "exact_match"
    assert result.status == "cleanup_failed"
    assert result.error_code == "fresh_omission_cleanup_failed"
    assert result.cleanup_steps_attempted == 2
    assert result.cleanup_steps_completed == 1
    assert result.orphaned_owned_state_possible is True
    assert result.finding is None


def test_environment_gate_requires_primary_compiled_and_omission(monkeypatch):
    monkeypatch.setenv(FRESH_OMISSION_ENV, "true")
    monkeypatch.delenv(PRIMARY_ENV, raising=False)
    monkeypatch.delenv(COMPILED_ADMISSION_ENV, raising=False)
    assert FreshOmissionConfig.from_environment().enabled is False

    monkeypatch.setenv(PRIMARY_ENV, "true")
    monkeypatch.setenv(COMPILED_ADMISSION_ENV, "true")
    assert FreshOmissionConfig.from_environment().enabled is True


def test_boundary_stays_explicit_only_without_direct_network_dependency():
    tree = ast.parse(Path(omission_boundary_module.__file__).read_text())
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
    assert not hasattr(behavior_package, "FreshOmissionBoundaryExecutor")
