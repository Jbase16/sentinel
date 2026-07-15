"""Owned-experiment factory tests; every path remains transport-free."""

from __future__ import annotations

import json
from dataclasses import replace

import core.behavior as behavior_package

from core.behavior.admission import COMPILED_ADMISSION_ENV
from core.behavior.factory import (
    OwnedExperimentFactory,
    OwnedExperimentFactoryConfig,
)
from core.behavior.lifecycle import LifecycleContractMiner
from core.cortex.execution_policy import ExecutionPolicy, PolicyExecutor
from core.foundry.authorization import AuthorizationEnvelope
from core.safety.ownership_registry import OwnershipRegistry
from core.safety.proof_budget import ProofBudget
from core.safety.provenance import ProvenanceSink

ORIGIN = "https://api.example.test"
NOTE_ID = "note_7fa9f13a2b4c5d6e"
PROJECT_ID = "project_4a5b6c7d8e9f0123"


def _records(*, include_export: bool = False):
    records = [
        {
            "id": "create-note",
            "persona_id": "alice",
            "method": "POST",
            "url": f"{ORIGIN}/api/notes",
            "request_body": '{"title":"controlled lifecycle marker"}',
            "response_status": 201,
            "response_body": json.dumps({"noteId": NOTE_ID}),
        },
        {
            "id": "read-note",
            "persona_id": "alice",
            "method": "GET",
            "url": f"{ORIGIN}/api/notes/{NOTE_ID}",
            "response_status": 200,
            "response_body": '{"title":"controlled lifecycle marker"}',
        },
    ]
    if include_export:
        records.append(
            {
                "id": "export-note",
                "persona_id": "alice",
                "method": "GET",
                "url": f"{ORIGIN}/api/notes/{NOTE_ID}/export",
                "response_status": 200,
                "response_body": '{"format":"text"}',
            }
        )
    records.append(
        {
            "id": "cleanup-note",
            "persona_id": "alice",
            "method": "PATCH",
            "url": f"{ORIGIN}/api/notes/{NOTE_ID}",
            "request_body": '{"archived":true}',
            "response_status": 200,
            "response_body": '{"archived":true}',
        }
    )
    return tuple(records)


def _bob_project_records():
    return (
        {
            "id": "create-project",
            "persona_id": "bob",
            "method": "POST",
            "url": f"{ORIGIN}/api/projects",
            "request_body": '{"name":"controlled project"}',
            "response_status": 201,
            "response_body": json.dumps({"projectId": PROJECT_ID}),
        },
        {
            "id": "read-project",
            "persona_id": "bob",
            "method": "GET",
            "url": f"{ORIGIN}/api/projects/{PROJECT_ID}",
            "response_status": 200,
            "response_body": '{"name":"controlled project"}',
        },
        {
            "id": "cleanup-project",
            "persona_id": "bob",
            "method": "PATCH",
            "url": f"{ORIGIN}/api/projects/{PROJECT_ID}",
            "request_body": '{"active":false}',
            "response_status": 200,
            "response_body": '{"active":false}',
        },
    )


def _authorization():
    envelope = AuthorizationEnvelope(
        envelope_id="factory-envelope",
        researcher_identity="researcher",
        target_handle="example",
        authorized_origins=[ORIGIN],
        authorization_basis="Authorized owned experiment test",
        disclosure_attestation=True,
        allowed_workflows=["behavioral_compiled_owned_sequence"],
        created_at=1_800_000_000.0,
        expires_at=1_900_000_000.0,
    )
    envelope.sign()
    return envelope


def _executor(raw_send):
    policy = ExecutionPolicy(
        "bounty_safe",
        scope_filter=lambda url: url.startswith(ORIGIN),
        budget=ProofBudget(
            max_total_requests=3,
            max_requests_per_endpoint=3,
            max_creates=1,
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


def _build(records, raw_send, *, factory=None):
    executor = _executor(raw_send)
    inventory = (factory or OwnedExperimentFactory()).build(
        records,
        target_origin=ORIGIN,
        authorization=_authorization(),
        actor_persona_id="alice",
        executor=executor,
    )
    return inventory, executor


def test_factory_builds_one_default_off_manifest_for_each_owned_read(monkeypatch):
    calls = []

    async def raw(method, url, body=None, **kwargs):
        calls.append((method, url))
        return 200, {}

    monkeypatch.setenv(COMPILED_ADMISSION_ENV, "true")
    inventory, executor = _build(_records(include_export=True), raw)

    assert inventory.status == "ready"
    assert len(inventory.experiments) == 2
    assert inventory.diagnostics.read_candidates == 2
    assert inventory.diagnostics.ready_experiments == 2
    assert (
        len({item.bundle.manifest.manifest_id for item in inventory.experiments}) == 2
    )
    assert all(
        item.bundle.admission.config.enabled is False for item in inventory.experiments
    )
    assert calls == []
    assert executor.policy.budget.snapshot()["total_requests"] == 0


def test_factory_inventory_is_deterministic_and_strictly_redacted():
    async def raw(method, url, body=None, **kwargs):
        raise AssertionError("factory must not invoke transport")

    first, _ = _build(_records(include_export=True), raw)
    second, _ = _build(_records(include_export=True), raw)

    assert first.to_dict() == second.to_dict()
    serialized = json.dumps(first.to_dict(), sort_keys=True)
    for raw_value in (ORIGIN, NOTE_ID, "controlled lifecycle marker", "alice"):
        assert raw_value not in serialized


def test_factory_rejects_other_worlds_without_discarding_actor_experiments():
    async def raw(method, url, body=None, **kwargs):
        raise AssertionError("factory must not invoke transport")

    inventory, _ = _build((*_records(), *_bob_project_records()), raw)

    assert inventory.status == "ready"
    assert len(inventory.experiments) == 1
    assert inventory.diagnostics.lifecycle_candidates == 2
    assert inventory.diagnostics.rejected_worlds == 1
    assert inventory.diagnostics.candidate_attempts == 1


def test_factory_deduplicates_identical_manifest_candidates():
    mined = LifecycleContractMiner().mine(_records(), world_id="alice")

    class DuplicateMiner:
        def mine(self, records, *, world_id):
            candidate = mined.candidates[0]
            return replace(mined, candidates=(candidate, candidate))

    async def raw(method, url, body=None, **kwargs):
        raise AssertionError("factory must not invoke transport")

    factory = OwnedExperimentFactory(miner=DuplicateMiner())  # type: ignore[arg-type]
    inventory, _ = _build(_records(), raw, factory=factory)

    assert len(inventory.experiments) == 1
    assert inventory.diagnostics.candidate_attempts == 2
    assert inventory.diagnostics.duplicate_manifests == 1


def test_factory_rejects_a_plan_that_does_not_use_its_candidate_create():
    mined = LifecycleContractMiner().mine(_records(), world_id="alice")
    candidate = mined.candidates[0]
    mismatched = replace(
        candidate,
        create_operation_id=candidate.cleanup_operation_id,
    )

    class MismatchedMiner:
        def mine(self, records, *, world_id):
            return replace(mined, candidates=(mismatched,))

    async def raw(method, url, body=None, **kwargs):
        raise AssertionError("factory must not invoke transport")

    factory = OwnedExperimentFactory(miner=MismatchedMiner())  # type: ignore[arg-type]
    inventory, _ = _build(_records(), raw, factory=factory)

    assert inventory.status == "no_ready_experiments"
    assert inventory.experiments == ()
    assert inventory.diagnostics.rejected_plans == 1


def test_factory_enforces_candidate_bound_before_compilation():
    async def raw(method, url, body=None, **kwargs):
        raise AssertionError("factory must not invoke transport")

    factory = OwnedExperimentFactory(
        config=OwnedExperimentFactoryConfig(max_experiments=1)
    )
    inventory, _ = _build(_records(include_export=True), raw, factory=factory)

    assert len(inventory.experiments) == 1
    assert inventory.diagnostics.candidate_attempts == 1
    assert inventory.diagnostics.dropped_for_bound == 1


def test_factory_is_not_exported_from_passive_behavior_package():
    assert not hasattr(behavior_package, "OwnedExperimentFactory")


def test_factory_config_rejects_unbounded_values():
    for value in (True, 0, 4_097):
        try:
            OwnedExperimentFactoryConfig(max_experiments=value)  # type: ignore[arg-type]
        except ValueError:
            pass
        else:
            raise AssertionError(f"expected max_experiments={value!r} to be rejected")
