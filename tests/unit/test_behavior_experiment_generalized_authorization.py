"""R5A3b generalized authorization execution; all traffic is in-memory."""

from __future__ import annotations

import ast
import copy
import json
from dataclasses import replace
from pathlib import Path

import pytest

import core.behavior as behavior_package
import core.behavior.experiment_generalized_authorization as generalized_module
from core.behavior.active import ControlledAuthorizationExecutor
from core.behavior.experiment_admission import (
    GeneralizedExperimentAdmission,
    ProofExperimentAdmissionConfig,
    ProofExperimentAdmissionDenied,
)
from core.behavior.experiment_generalized_authorization import (
    GeneralizedAuthorizationExecutionConfig,
    GeneralizedAuthorizationExecutionDenied,
    GeneralizedAuthorizationExecutionPlanner,
    GeneralizedAuthorizationExperimentExecutor,
)
from core.behavior.experiment_sdk import OracleVerdict
from core.behavior.ownership_experiment import (
    GeneralizedOwnershipExperimentAdmission,
    GeneralizedOwnershipExperimentCompiler,
)
from core.behavior.ownership_locators import (
    OwnershipLocatorKind,
    OwnershipProtocol,
)
from core.behavior.receipts import ABORTED, COMPLETED, BehavioralReceiptStore
from core.cortex.execution_policy import ExecutionPolicy, PolicyExecutor
from core.foundry.vault import PersonaVault
from core.safety.ownership_locator import (
    OwnedRequestLocatorKind,
    extract_locator_value,
)
from core.safety.ownership_registry import OwnershipRegistry
from core.safety.proof_budget import ProofBudget
from core.safety.provenance import ProvenanceSink
from tests.unit import test_behavior_ownership_experiment as r5a2_fixtures


ORIGIN = "https://api.example.test"
ACTOR_OBJECT = "document_3333333333333333"
OWNER_OBJECT = "document_4444444444444444"


class _Target:
    def __init__(self, *, denied: bool = False) -> None:
        self.denied = denied
        self.actor_id = ""
        self.owner_id = ""
        self.kind = OwnedRequestLocatorKind.PATH
        self.pointer = "/segments/0"
        self.calls = []

    async def send(self, persona_id, method, url, body=None, **kwargs):
        value = extract_locator_value(
            kind=self.kind,
            pointer=self.pointer,
            url=url,
            body=body,
        )
        self.calls.append((persona_id, method, url, body, kwargs, value))
        if persona_id == self.actor_id and value == OWNER_OBJECT:
            if self.denied:
                return 403, {"error": "forbidden"}
            return 200, {
                "documentId": OWNER_OBJECT,
                "privateMarker": "OwnerPrivateMarkerR5A3b",
            }
        if value == OWNER_OBJECT:
            return 200, {
                "documentId": OWNER_OBJECT,
                "privateMarker": "OwnerPrivateMarkerR5A3b",
            }
        return 200, {
            "documentId": ACTOR_OBJECT,
            "privateMarker": "ActorPrivateMarkerR5A3b",
        }


def _context(
    tmp_path,
    monkeypatch,
    *,
    kind=OwnershipLocatorKind.PATH,
    enabled=True,
    target=None,
):
    monkeypatch.setenv(
        "SENTINELFORGE_PERSONA_VAULT",
        str(tmp_path / "personas"),
    )
    vault = PersonaVault()
    actor = vault.add_persona(
        label="R5A3b actor",
        email="actor-r5a3b@example.test",
    )
    owner = vault.add_persona(
        label="R5A3b owner",
        email="owner-r5a3b@example.test",
    )
    monkeypatch.setattr(r5a2_fixtures, "ACTOR_WORLD", actor.persona_id)
    monkeypatch.setattr(r5a2_fixtures, "OWNER_WORLD", owner.persona_id)
    monkeypatch.setattr(r5a2_fixtures, "ACTOR_ID", ACTOR_OBJECT)
    monkeypatch.setattr(r5a2_fixtures, "OWNER_ID", OWNER_OBJECT)

    envelope = r5a2_fixtures._envelope()
    actor_records = r5a2_fixtures._records(
        kind,
        persona_id=actor.persona_id,
        object_id=ACTOR_OBJECT,
    )
    owner_records = r5a2_fixtures._records(
        kind,
        persona_id=owner.persona_id,
        object_id=OWNER_OBJECT,
    )
    manifest, actor_binding_id, owner_binding_id = r5a2_fixtures._manifest(
        kind=kind,
        actor_records=actor_records,
        owner_records=owner_records,
        envelope=envelope,
    )
    proof = GeneralizedOwnershipExperimentCompiler().compile(
        manifest=manifest,
        actor_records=actor_records,
        target_owner_records=owner_records,
        actor_lineage_binding_id=actor_binding_id,
        target_owner_lineage_binding_id=owner_binding_id,
    )
    ownership_admission = GeneralizedOwnershipExperimentAdmission(
        proof=proof,
        manifest=manifest,
        target_origin=ORIGIN,
        authorization=envelope,
        actor_records=actor_records,
        target_owner_records=owner_records,
    ).admit()

    registry = OwnershipRegistry()
    registry.register_created_value(
        f"{ORIGIN}/api/documents",
        OWNER_OBJECT,
        actor_persona=owner.persona_id,
    )
    budget = ProofBudget(
        max_total_requests=10,
        max_requests_per_endpoint=4,
        max_cross_object_reads=1,
        max_privilege_mutations=0,
        max_creates=0,
        allow_delete=False,
        allow_real_user_data_access=False,
    )
    policy = ExecutionPolicy(
        "bounty_safe",
        scope_filter=lambda url: str(url).startswith(f"{ORIGIN}/"),
        budget=budget,
        ownership_registry=registry,
    )
    sink = ProvenanceSink()
    live_target = target or _Target()
    live_target.actor_id = actor.persona_id
    live_target.owner_id = owner.persona_id
    live_target.kind = OwnedRequestLocatorKind(kind.value)
    live_target.pointer = proof.actor.locator_pointer

    def make_executor(persona_id):
        async def raw(method, url, body=None, **kwargs):
            return await live_target.send(
                persona_id,
                method,
                url,
                body,
                **kwargs,
            )

        return PolicyExecutor(raw, policy, sink)

    executors = {
        actor.persona_id: make_executor(actor.persona_id),
        owner.persona_id: make_executor(owner.persona_id),
    }
    backend = ControlledAuthorizationExecutor(
        target_origin=ORIGIN,
        authorization=envelope,
        source_persona=actor,
        peer_persona=owner,
        executors=executors,
    )
    planner = GeneralizedAuthorizationExecutionPlanner(
        manifest=manifest,
        ownership_proof=proof,
        ownership_admission=ownership_admission,
        backend=backend,
    )
    prepared = planner.prepare(
        actor_records=actor_records,
        target_owner_records=owner_records,
    )
    store = BehavioralReceiptStore(tmp_path / "receipts")
    lease = GeneralizedExperimentAdmission(
        manifest=manifest,
        target_origin=ORIGIN,
        authorization=envelope,
        executor=executors[actor.persona_id],
        runtime_actions=prepared.runtime_actions,
        runtime_world_ids={
            proof.actor.world_binding_id: actor.persona_id,
            proof.target_owner.world_binding_id: owner.persona_id,
        },
        persona_vault=vault,
        locator_ownership_proofs=prepared.locator_ownership_proofs,
        config=ProofExperimentAdmissionConfig(enabled=True),
        receipt_store=store,
    ).admit()
    claim = lease.claim()
    adapter = GeneralizedAuthorizationExperimentExecutor(
        manifest=manifest,
        claim=claim,
        prepared=prepared,
        ownership_proof=proof,
        ownership_admission=ownership_admission,
        backend=backend,
        persona_vault=vault,
        config=GeneralizedAuthorizationExecutionConfig(enabled=enabled),
    )
    return {
        "adapter": adapter,
        "prepared": prepared,
        "actor_records": actor_records,
        "owner_records": owner_records,
        "target": live_target,
        "claim": claim,
        "budget": budget,
        "store": store,
        "registry": registry,
        "owner": owner,
        "sink": sink,
        "backend": backend,
        "manifest": manifest,
        "envelope": envelope,
        "proof": proof,
        "ownership_admission": ownership_admission,
        "executors": executors,
        "vault": vault,
    }


def test_r5a3b_is_explicit_only_and_has_no_direct_transport_surface():
    assert not hasattr(
        behavior_package,
        "GeneralizedAuthorizationExperimentExecutor",
    )
    tree = ast.parse(Path(generalized_module.__file__).read_text())
    imported_roots = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported_roots.update(
                alias.name.split(".", 1)[0] for alias in node.names
            )
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported_roots.add(node.module.split(".", 1)[0])
    assert not imported_roots & {"httpx", "requests", "socket", "urllib3"}
    assert not any(
        isinstance(node, ast.Attribute) and node.attr == "raw_send"
        for node in ast.walk(tree)
    )


def test_mutating_or_unproven_post_is_rejected_before_planning():
    with pytest.raises(
        GeneralizedAuthorizationExecutionDenied,
        match="graphql_read_is_unproven",
    ):
        generalized_module.validate_generalized_read_semantics(
            method="POST",
            body=json.dumps({
                "query": "mutation ChangeDocument { changeDocument { id } }",
                "variables": {"documentId": ACTOR_OBJECT},
            }),
            kind=OwnedRequestLocatorKind.GRAPHQL_VARIABLE,
            pointer="/variables/documentId",
            protocol=OwnershipProtocol.GRAPHQL,
        )
    with pytest.raises(
        GeneralizedAuthorizationExecutionDenied,
        match="request_is_not_proven_read_only",
    ):
        generalized_module.validate_generalized_read_semantics(
            method="POST",
            body=json.dumps({"documentId": ACTOR_OBJECT}),
            kind=OwnedRequestLocatorKind.JSON,
            pointer="/documentId",
            protocol=OwnershipProtocol.HTTP,
        )


@pytest.mark.parametrize("kind", tuple(OwnershipLocatorKind))
@pytest.mark.asyncio
async def test_every_locator_executes_one_bound_four_read_counterexample(
    tmp_path,
    monkeypatch,
    kind,
):
    context = _context(tmp_path, monkeypatch, kind=kind)
    public = json.dumps(context["prepared"].to_dict(), sort_keys=True)

    assert ACTOR_OBJECT not in public
    assert OWNER_OBJECT not in public
    assert context["prepared"].target_requests_sent == 0
    assert context["prepared"].execution_authority is False

    result = await context["adapter"].execute(
        actor_records=context["actor_records"],
        target_owner_records=context["owner_records"],
    )

    assert result.status == "completed"
    assert result.legacy_verdict == "BOLA_CONFIRMED"
    assert result.oracle_evaluation.verdict is OracleVerdict.CONFIRMED
    assert result.requests_attempted == result.requests_sent == 4
    assert result.finding_candidate_ref is not None
    assert result.finding_authority is False
    assert result.promotion_authority is False
    assert [item[-1] for item in context["target"].calls] == [
        OWNER_OBJECT,
        ACTOR_OBJECT,
        OWNER_OBJECT,
        OWNER_OBJECT,
    ]
    treatment = context["sink"].action_blocks[2].payload
    assert treatment["ownership_proof_ref"] == result.locator_proof_ref
    assert treatment["runtime_authority_ref"] == result.runtime_authority_ref
    assert treatment["source_admission_ref"] == result.ownership_admission_id
    assert treatment["source_plan_ref"] == result.execution_plan_ref
    assert treatment["transport_context_ref"] == result.transport_context_ref
    assert context["claim"].state == "completed"
    assert context["budget"].snapshot()["total_requests"] == 4
    receipt = context["store"].load(
        context["claim"].contract.receipt_fingerprint
    )
    assert receipt is not None and receipt.state == COMPLETED
    assert receipt.outcome is not None
    assert receipt.outcome["kind"] == (
        "proof_experiment_generalized_authorization"
    )
    assert receipt.outcome["finding_authority"] is False


@pytest.mark.asyncio
async def test_default_off_aborts_claim_without_target_traffic(
    tmp_path,
    monkeypatch,
):
    context = _context(tmp_path, monkeypatch, enabled=False)

    with pytest.raises(
        GeneralizedAuthorizationExecutionDenied,
        match="execution_is_disabled",
    ):
        await context["adapter"].execute(
            actor_records=context["actor_records"],
            target_owner_records=context["owner_records"],
        )

    assert context["target"].calls == []
    assert context["claim"].state == "aborted"
    assert context["claim"].reserved_units == 0
    receipt = context["store"].load(
        context["claim"].contract.receipt_fingerprint
    )
    assert receipt is not None and receipt.state == ABORTED


@pytest.mark.asyncio
async def test_target_denial_is_refuted_and_still_gets_owner_witness(
    tmp_path,
    monkeypatch,
):
    context = _context(tmp_path, monkeypatch, target=_Target(denied=True))

    result = await context["adapter"].execute(
        actor_records=context["actor_records"],
        target_owner_records=context["owner_records"],
    )

    assert result.status == "completed"
    assert result.legacy_verdict == "DENIED"
    assert result.oracle_evaluation.verdict is OracleVerdict.REFUTED
    assert result.finding_candidate_ref is None
    assert result.requests_sent == 4


@pytest.mark.asyncio
async def test_capture_drift_aborts_before_traffic_and_replay_is_denied(
    tmp_path,
    monkeypatch,
):
    context = _context(tmp_path, monkeypatch)
    changed = copy.deepcopy(list(context["actor_records"]))
    changed[1]["request_headers"] = {"X-CSRF-Token": "changed"}

    with pytest.raises(GeneralizedAuthorizationExecutionDenied):
        await context["adapter"].execute(
            actor_records=changed,
            target_owner_records=context["owner_records"],
        )

    assert context["target"].calls == []
    assert context["claim"].state == "aborted"
    with pytest.raises(
        GeneralizedAuthorizationExecutionDenied,
        match="already_consumed",
    ):
        await context["adapter"].execute(
            actor_records=context["actor_records"],
            target_owner_records=context["owner_records"],
        )


@pytest.mark.asyncio
async def test_registry_ambiguity_after_admission_aborts_before_traffic(
    tmp_path,
    monkeypatch,
):
    context = _context(tmp_path, monkeypatch, kind=OwnershipLocatorKind.JSON)
    context["registry"].register_created_value(
        f"{ORIGIN}/api/other-documents",
        OWNER_OBJECT,
        actor_persona=context["owner"].persona_id,
    )

    with pytest.raises(
        GeneralizedAuthorizationExecutionDenied,
        match="locator_proof_denied",
    ):
        await context["adapter"].execute(
            actor_records=context["actor_records"],
            target_owner_records=context["owner_records"],
        )

    assert context["target"].calls == []
    assert context["claim"].state == "aborted"


def test_json_treatment_needs_locator_proof_at_r4_admission(
    tmp_path,
    monkeypatch,
):
    context = _context(tmp_path, monkeypatch, kind=OwnershipLocatorKind.JSON)
    context["claim"].abort("test_rebuild_without_locator_proof")

    with pytest.raises(
        ProofExperimentAdmissionDenied,
        match="cross_object_owner_proof_mismatch",
    ):
        GeneralizedExperimentAdmission(
            manifest=context["manifest"],
            target_origin=ORIGIN,
            authorization=context["envelope"],
            executor=context["executors"][
                context["backend"].source_persona.persona_id
            ],
            runtime_actions=context["prepared"].runtime_actions,
            runtime_world_ids={
                context["proof"].actor.world_binding_id: (
                    context["backend"].source_persona.persona_id
                ),
                context["proof"].target_owner.world_binding_id: (
                    context["owner"].persona_id
                ),
            },
            persona_vault=context["vault"],
            config=ProofExperimentAdmissionConfig(enabled=True),
            receipt_store=BehavioralReceiptStore(
                tmp_path / "receipts-without-locator"
            ),
        ).admit()


@pytest.mark.asyncio
async def test_runtime_permit_allows_exact_treatment_once_only(
    tmp_path,
    monkeypatch,
):
    context = _context(tmp_path, monkeypatch, kind=OwnershipLocatorKind.FORM)
    preflight = context["adapter"]._generalized_preflight(
        actor_records=context["actor_records"],
        target_owner_records=context["owner_records"],
    )
    action = replace(
        preflight.authorization.actions[2],
        budget_reservation_id=(
            preflight.authorization.budget_reservation_id
        ),
    )
    executor = context["executors"][
        context["backend"].source_persona.persona_id
    ]
    owner_executor = context["executors"][
        context["backend"].peer_persona.persona_id
    ]
    owner_control = replace(
        preflight.authorization.actions[0],
        budget_reservation_id=(
            preflight.authorization.budget_reservation_id
        ),
    )
    actor_control = replace(
        preflight.authorization.actions[1],
        budget_reservation_id=(
            preflight.authorization.budget_reservation_id
        ),
    )
    assert (await owner_executor.send_action(owner_control))[0] == 200
    assert (await executor.send_action(actor_control))[0] == 200

    changed = replace(action, url=f"{ORIGIN}/api/documents/export?documentId=x")
    denied_status, denied_body = await executor.send_locator_action(
        changed,
        preflight.plan.locator_proof,
        runtime_permit=preflight.runtime_permit,
        headers=dict(preflight.plan._headers[2]),
    )
    assert denied_status == 0
    assert "identity_mismatch" in denied_body["_policy_denied"]
    assert len(context["target"].calls) == 2

    header_status, header_body = await executor.send_locator_action(
        action,
        preflight.plan.locator_proof,
        runtime_permit=preflight.runtime_permit,
        headers={"Content-Type": "application/json"},
    )
    assert header_status == 0
    assert "identity_mismatch" in header_body["_policy_denied"]
    assert len(context["target"].calls) == 2

    first_status, _ = await executor.send_locator_action(
        action,
        preflight.plan.locator_proof,
        runtime_permit=preflight.runtime_permit,
        headers=dict(preflight.plan._headers[2]),
    )
    second_status, second_body = await executor.send_locator_action(
        action,
        preflight.plan.locator_proof,
        runtime_permit=preflight.runtime_permit,
        headers=dict(preflight.plan._headers[2]),
    )

    assert first_status == 200
    assert second_status == 0
    assert "already_consumed" in second_body["_policy_denied"]
    assert len(context["target"].calls) == 3
    released = context["claim"]._abort_runtime(
        runtime_claim_token=preflight.authorization.runtime_claim_token,
        reason="test_runtime_permit_complete",
    )
    assert released == 1
