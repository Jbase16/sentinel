"""Fresh-owned-state boundary oracle tests using in-memory transports only."""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

import core.behavior as behavior_package
import core.behavior.boundary as boundary_module
from core.behavior.active import BoundedResponseText, CONTROLLED_WORKFLOW
from core.behavior.boundary import (
    FreshOwnedBoundaryConfig,
    FreshOwnedBoundaryDenied,
    FreshOwnedBoundaryExecutor,
)
from core.behavior.factory import OwnedExperimentFactory
from core.behavior.runtime import CONTROLLED_SEQUENCE_WORKFLOW, ControlledSequenceDenied
from core.cortex.execution_policy import ExecutionPolicy, PolicyExecutor
from core.foundry.authorization import AuthorizationEnvelope
from core.foundry.vault import ResearchPersona
from core.safety.ownership_registry import OwnershipRegistry
from core.safety.proof_budget import ProofBudget
from core.safety.provenance import ProvenanceSink

ORIGIN = "https://api.example.test"
SOURCE_CAPTURED_ID = "note_source_7fa9f13a2b4c"
PEER_CAPTURED_ID = "note_peer_4a5b6c7d8e9f0"
SOURCE_FRESH_ID = "note_fresh_source_8b9c0d1e2f3a4"
PEER_FRESH_ID = "note_fresh_peer_5b6c7d8e9f0a1"


def _records(persona_id, object_id, marker):
    return (
        {
            "persona_id": persona_id,
            "method": "POST",
            "url": f"{ORIGIN}/api/notes",
            "request_headers": {"x-csrf-token": f"csrf-{persona_id}"},
            "request_body": '{"title":"controlled lifecycle marker"}',
            "response_status": 201,
            "response_body": json.dumps({"noteId": object_id}),
        },
        {
            "persona_id": persona_id,
            "method": "GET",
            "url": f"{ORIGIN}/api/notes/{object_id}",
            "request_headers": {"x-csrf-token": f"csrf-{persona_id}"},
            "response_status": 200,
            "response_body": json.dumps({"owner": marker}),
        },
        {
            "persona_id": persona_id,
            "method": "PATCH",
            "url": f"{ORIGIN}/api/notes/{object_id}",
            "request_headers": {"x-csrf-token": f"csrf-{persona_id}"},
            "request_body": '{"archived":true}',
            "response_status": 200,
            "response_body": '{"archived":true}',
        },
    )


def _authorization():
    envelope = AuthorizationEnvelope(
        envelope_id="fresh-owned-boundary-envelope",
        researcher_identity="researcher",
        target_handle="example",
        authorized_origins=[ORIGIN],
        authorization_basis="authorized fresh owned boundary test",
        disclosure_attestation=True,
        allowed_workflows=[CONTROLLED_WORKFLOW, CONTROLLED_SEQUENCE_WORKFLOW],
        created_at=1_780_000_000.0,
        expires_at=1_900_000_000.0,
    )
    envelope.sign()
    return envelope


def _personas():
    return (
        ResearchPersona(
            persona_id="alice",
            label="Alice",
            email="alice@research.example",
        ),
        ResearchPersona(
            persona_id="bob",
            label="Bob",
            email="bob@research.example",
        ),
    )


def _executor(raw_send, policy, provenance):
    return PolicyExecutor(raw_send, policy, provenance=provenance)


def _boundary(source_raw, peer_raw, *, budget=None, peer_records=None, enabled=True):
    source_persona, peer_persona = _personas()
    policy = ExecutionPolicy(
        "bounty_safe",
        scope_filter=lambda url: url.startswith(ORIGIN),
        budget=budget
        or ProofBudget(
            max_total_requests=7,
            max_requests_per_endpoint=5,
            max_cross_object_reads=1,
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
    source_executor = _executor(source_raw, policy, provenance)
    peer_executor = _executor(peer_raw, policy, provenance)
    authorization = _authorization()
    source_inventory = OwnedExperimentFactory().build(
        _records("alice", SOURCE_CAPTURED_ID, "alice-private-marker"),
        target_origin=ORIGIN,
        authorization=authorization,
        actor_persona_id="alice",
        executor=source_executor,
    )
    peer_inventory = OwnedExperimentFactory().build(
        peer_records
        if peer_records is not None
        else _records("bob", PEER_CAPTURED_ID, "bob-private-marker"),
        target_origin=ORIGIN,
        authorization=authorization,
        actor_persona_id="bob",
        executor=peer_executor,
    )
    boundary = FreshOwnedBoundaryExecutor(
        source_inventory=source_inventory,
        peer_inventory=peer_inventory,
        source_persona=source_persona,
        peer_persona=peer_persona,
        config=FreshOwnedBoundaryConfig(enabled=enabled),
    )
    return boundary, source_inventory, peer_inventory, policy


@pytest.mark.asyncio
async def test_fresh_boundary_creates_two_controls_proves_cross_read_and_cleans_both():
    calls = []

    async def source_raw(method, url, body=None, **kwargs):
        calls.append(("alice", method, url, body, kwargs))
        if method == "POST":
            return 201, {"noteId": SOURCE_FRESH_ID}
        if method == "PATCH":
            return 200, {"archived": True}
        return 200, {"owner": "alice-fresh-private-marker"}

    async def peer_raw(method, url, body=None, **kwargs):
        calls.append(("bob", method, url, body, kwargs))
        if method == "POST":
            return 201, {"noteId": PEER_FRESH_ID}
        if method == "PATCH":
            return 200, {"archived": True}
        if SOURCE_FRESH_ID in url:
            return 200, {"owner": "alice-fresh-private-marker"}
        return 200, {"owner": "bob-fresh-private-marker"}

    boundary, source_inventory, _peer_inventory, policy = _boundary(
        source_raw,
        peer_raw,
    )
    experiment_id = source_inventory.experiments[0].experiment_id
    preflight_id = boundary.validate_preflight(experiment_id)

    result = await boundary.execute(experiment_id)

    assert result.boundary_id == preflight_id
    assert result.status == "completed"
    assert result.legacy_verdict.verdict == "BOLA_CONFIRMED"
    assert result.finding is not None
    assert result.requests_attempted == result.requests_sent == 7
    assert result.creates_attempted == result.creates_completed == 2
    assert result.proof_legs_attempted == result.proof_legs_sent == 3
    assert result.cleanup_steps_attempted == result.cleanup_steps_completed == 2
    assert result.orphaned_owned_state_possible is False
    assert [(persona, method) for persona, method, *_rest in calls] == [
        ("alice", "POST"),
        ("bob", "POST"),
        ("alice", "GET"),
        ("bob", "GET"),
        ("bob", "GET"),
        ("bob", "PATCH"),
        ("alice", "PATCH"),
    ]
    assert calls[4][2].endswith(SOURCE_FRESH_ID)
    assert calls[0][4]["headers"]["x-csrf-token"] == "csrf-alice"
    assert calls[1][4]["headers"]["x-csrf-token"] == "csrf-bob"
    assert policy.budget.snapshot() == {
        "total_requests": 7,
        "cross_object_reads": 1,
        "privilege_mutations": 0,
        "creates": 2,
        "endpoints_touched": 2,
    }
    serialized = json.dumps(result.to_dict(), sort_keys=True)
    for raw in (
        ORIGIN,
        SOURCE_CAPTURED_ID,
        PEER_CAPTURED_ID,
        SOURCE_FRESH_ID,
        PEER_FRESH_ID,
        "alice-fresh-private-marker",
        "bob-fresh-private-marker",
    ):
        assert raw not in serialized


@pytest.mark.asyncio
async def test_cross_read_denial_is_upheld_evidence_and_cleanup_still_runs():
    calls = []

    async def source_raw(method, url, body=None, **kwargs):
        calls.append(("alice", method, url))
        if method == "POST":
            return 201, {"noteId": SOURCE_FRESH_ID}
        if method == "PATCH":
            return 200, {}
        return 200, {"owner": "alice-fresh-private-marker"}

    async def peer_raw(method, url, body=None, **kwargs):
        calls.append(("bob", method, url))
        if method == "POST":
            return 201, {"noteId": PEER_FRESH_ID}
        if method == "PATCH":
            return 200, {}
        if SOURCE_FRESH_ID in url:
            return 403, {"error": "forbidden"}
        return 200, {"owner": "bob-fresh-private-marker"}

    boundary, source_inventory, _peer_inventory, _policy = _boundary(
        source_raw,
        peer_raw,
    )
    result = await boundary.execute(source_inventory.experiments[0].experiment_id)

    assert result.status == "completed"
    assert result.legacy_verdict.verdict == "DENIED"
    assert result.finding is None
    assert result.cleanup_steps_completed == 2
    assert len(calls) == 7


@pytest.mark.asyncio
async def test_truncated_owner_baseline_aborts_proof_but_cleans_both_objects():
    async def source_raw(method, url, body=None, **kwargs):
        if method == "POST":
            return 201, {"noteId": SOURCE_FRESH_ID}
        if method == "PATCH":
            return 200, {}
        return 200, BoundedResponseText(
            '{"owner":"alice-fresh-private-marker"}',
            body_truncated=True,
        )

    async def peer_raw(method, url, body=None, **kwargs):
        if method == "POST":
            return 201, {"noteId": PEER_FRESH_ID}
        return 200, {}

    boundary, source_inventory, _peer_inventory, _policy = _boundary(
        source_raw,
        peer_raw,
    )
    result = await boundary.execute(source_inventory.experiments[0].experiment_id)

    assert result.status == "completed"
    assert result.legacy_verdict.verdict == "AMBIGUOUS"
    assert result.proof_legs_attempted == 2
    assert result.cleanup_steps_completed == 2


@pytest.mark.asyncio
async def test_cleanup_failure_is_never_hidden_by_a_confirmed_finding():
    async def source_raw(method, url, body=None, **kwargs):
        if method == "POST":
            return 201, {"noteId": SOURCE_FRESH_ID}
        if method == "PATCH":
            return 500, {"error": "cleanup failed"}
        return 200, {"owner": "alice-fresh-private-marker"}

    async def peer_raw(method, url, body=None, **kwargs):
        if method == "POST":
            return 201, {"noteId": PEER_FRESH_ID}
        if method == "PATCH":
            return 200, {}
        if SOURCE_FRESH_ID in url:
            return 200, {"owner": "alice-fresh-private-marker"}
        return 200, {"owner": "bob-fresh-private-marker"}

    boundary, source_inventory, _peer_inventory, _policy = _boundary(
        source_raw,
        peer_raw,
    )
    result = await boundary.execute(source_inventory.experiments[0].experiment_id)

    assert result.legacy_verdict.verdict == "BOLA_CONFIRMED"
    assert result.status == "cleanup_failed"
    assert result.error_code == "fresh_boundary_cleanup_failed"
    assert result.cleanup_steps_attempted == 2
    assert result.cleanup_steps_completed == 1
    assert result.orphaned_owned_state_possible is True


def test_disabled_or_unpaired_boundary_has_no_execution_authority():
    calls = []

    async def forbidden(*args, **kwargs):
        calls.append((args, kwargs))
        raise AssertionError("preflight must not send traffic")

    disabled, source_inventory, _peer_inventory, _policy = _boundary(
        forbidden,
        forbidden,
        enabled=False,
    )
    assert disabled.supported_experiment_ids() == ()
    with pytest.raises(FreshOwnedBoundaryDenied, match="is_disabled"):
        disabled.validate_preflight(source_inventory.experiments[0].experiment_id)

    unpaired, source_inventory, _peer_inventory, _policy = _boundary(
        forbidden,
        forbidden,
        peer_records=(),
    )
    assert unpaired.supported_experiment_ids() == ()
    with pytest.raises(FreshOwnedBoundaryDenied, match="peer_experiment"):
        unpaired.validate_preflight(source_inventory.experiments[0].experiment_id)
    assert calls == []


def test_boundary_requires_exact_seven_request_shared_budget():
    async def forbidden(*_args, **_kwargs):
        raise AssertionError("preflight must not send traffic")

    boundary, source_inventory, _peer_inventory, _policy = _boundary(
        forbidden,
        forbidden,
        budget=ProofBudget(
            max_total_requests=8,
            max_requests_per_endpoint=5,
            max_cross_object_reads=1,
            max_privilege_mutations=0,
            max_creates=2,
            allow_real_user_data_access=False,
        ),
    )

    with pytest.raises(FreshOwnedBoundaryDenied, match="exact_bounty_safe_budget"):
        boundary.validate_preflight(source_inventory.experiments[0].experiment_id)


@pytest.mark.asyncio
async def test_claimed_lifecycle_cannot_be_executed_again_standalone():
    async def source_raw(method, url, body=None, **kwargs):
        if method == "POST":
            return 201, {"noteId": SOURCE_FRESH_ID}
        return 200, {}

    async def peer_raw(method, url, body=None, **kwargs):
        if method == "POST":
            return 201, {"noteId": PEER_FRESH_ID}
        return 200, {}

    boundary, source_inventory, _peer_inventory, _policy = _boundary(
        source_raw,
        peer_raw,
    )
    source_runtime = source_inventory.experiments[0].bundle.runtime
    await boundary.execute(source_inventory.experiments[0].experiment_id)

    with pytest.raises(ControlledSequenceDenied, match="already_consumed"):
        await source_runtime.execute()


def test_boundary_stays_explicit_only_and_has_no_direct_network_dependency():
    tree = ast.parse(Path(boundary_module.__file__).read_text())
    imported_roots = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported_roots.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported_roots.add(node.module.split(".", 1)[0])

    assert not imported_roots & {"httpx", "requests", "socket", "urllib3", "websockets"}
    assert not hasattr(behavior_package, "FreshOwnedBoundaryExecutor")
