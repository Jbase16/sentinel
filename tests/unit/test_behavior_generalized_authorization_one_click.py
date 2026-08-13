"""R5A4 ordinary one-click selection and dispatch; traffic stays in memory."""

from __future__ import annotations

import pytest

from core.behavior.active import ControlledAuthorizationExecutor
from core.behavior.experiment_admission import ProofExperimentAdmissionConfig
from core.behavior.experiment_generalized_authorization import (
    GeneralizedAuthorizationExecutionConfig,
)
from core.behavior.generalized_authorization_one_click import (
    GeneralizedAuthorizationOneClickConfig,
    GeneralizedAuthorizationOneClickDispatcher,
)
from core.behavior.orchestrator import (
    BehavioralShadowOrchestrator,
    OwnedExperimentShadowContext,
)
from core.behavior.ownership_locators import (
    GeneralizedOwnershipLocatorCompiler,
    OwnershipLocatorKind,
)
from core.behavior.receipts import BehavioralReceiptStore, redacted_outcome
from core.cortex.execution_policy import ExecutionPolicy, PolicyExecutor
from core.foundry.vault import PersonaVault
from core.safety.ownership_locator import (
    LocatorOwnershipDenied,
    OwnedRequestLocatorKind,
    extract_locator_value,
)
from core.safety.ownership_registry import OwnershipRegistry
from core.safety.proof_budget import ProofBudget
from core.safety.provenance import ProvenanceSink
from tests.unit import test_behavior_ownership_experiment as r5a2_fixtures


ACTOR_OBJECT = "document_5555555555555555"
OWNER_OBJECT = "document_6666666666666666"


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
        if persona_id == self.actor_id and value == OWNER_OBJECT and self.denied:
            return 403, {"error": "forbidden"}
        marker = (
            "OwnerPrivateMarkerR5A4"
            if value == OWNER_OBJECT
            else "ActorPrivateMarkerR5A4"
        )
        return 200, {"documentId": value, "privateMarker": marker}


def _context(
    tmp_path,
    monkeypatch,
    *,
    kind=OwnershipLocatorKind.PATH,
    admission_enabled=True,
    execution_enabled=True,
    denied=False,
    extra_export=False,
    one_click_config=None,
):
    monkeypatch.setenv(
        "SENTINELFORGE_PERSONA_VAULT",
        str(tmp_path / "personas"),
    )
    vault = PersonaVault()
    actor = vault.add_persona(label="R5A4 actor", email="actor-r5a4@example.test")
    owner = vault.add_persona(label="R5A4 owner", email="owner-r5a4@example.test")
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
    if extra_export:
        actor_records = (
            *actor_records,
            r5a2_fixtures._use_record(
                OwnershipLocatorKind.QUERY,
                persona_id=actor.persona_id,
                object_id=ACTOR_OBJECT,
            ),
        )
        owner_records = (
            *owner_records,
            r5a2_fixtures._use_record(
                OwnershipLocatorKind.QUERY,
                persona_id=owner.persona_id,
                object_id=OWNER_OBJECT,
            ),
        )
    actor_index = GeneralizedOwnershipLocatorCompiler().compile(
        actor_records,
        world_id=actor.persona_id,
    )
    expected_kind = OwnershipLocatorKind.QUERY if extra_export else kind
    actor_use = next(
        use
        for evidence in actor_index.evidence
        for use in evidence.uses
        if use.locator_kind is expected_kind
    )
    target = _Target(denied=denied)
    target.actor_id = actor.persona_id
    target.owner_id = owner.persona_id
    target.kind = OwnedRequestLocatorKind(expected_kind.value)
    target.pointer = actor_use.locator_pointer
    registry = OwnershipRegistry()
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
        scope_filter=lambda url: str(url).startswith(
            f"{r5a2_fixtures.ORIGIN}/"
        ),
        budget=budget,
        ownership_registry=registry,
    )
    provenance = ProvenanceSink()

    def make_executor(persona_id):
        async def raw(method, url, body=None, **kwargs):
            return await target.send(persona_id, method, url, body, **kwargs)

        return PolicyExecutor(raw, policy, provenance)

    executors = {
        actor.persona_id: make_executor(actor.persona_id),
        owner.persona_id: make_executor(owner.persona_id),
    }
    backend = ControlledAuthorizationExecutor(
        target_origin=r5a2_fixtures.ORIGIN,
        authorization=envelope,
        source_persona=actor,
        peer_persona=owner,
        executors=executors,
    )
    shadow = BehavioralShadowOrchestrator().run(
        actor_records,
        target_origin=r5a2_fixtures.ORIGIN,
        world_id=actor.persona_id,
        peer_records=owner_records,
        peer_world_id=owner.persona_id,
        experiment_context=OwnedExperimentShadowContext(
            authorization=envelope,
            actor_persona_id=actor.persona_id,
            executor=executors[actor.persona_id],
            peer_persona_id=owner.persona_id,
        ),
    )
    dispatcher = GeneralizedAuthorizationOneClickDispatcher(
        target_origin=r5a2_fixtures.ORIGIN,
        authorization=envelope,
        backend=backend,
        persona_vault=vault,
        receipt_store=BehavioralReceiptStore(tmp_path / "receipts"),
        admission_config=ProofExperimentAdmissionConfig(
            enabled=admission_enabled
        ),
        execution_config=GeneralizedAuthorizationExecutionConfig(
            enabled=execution_enabled
        ),
        config=(
            one_click_config or GeneralizedAuthorizationOneClickConfig()
        ),
    )
    return {
        "dispatcher": dispatcher,
        "actor_records": actor_records,
        "owner_records": owner_records,
        "shadow": shadow,
        "target": target,
        "budget": budget,
        "registry": registry,
    }


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", tuple(OwnershipLocatorKind))
async def test_one_click_selects_and_dispatches_every_locator(
    tmp_path,
    monkeypatch,
    kind,
):
    context = _context(tmp_path, monkeypatch, kind=kind)
    shadow = context["shadow"]
    run = await context["dispatcher"].run(
        actor_records=context["actor_records"],
        owner_records=context["owner_records"],
        payout_goal_plan=shadow.payout_goal_plan,
        operations=shadow.semantic_catalog.planner_operations(),
    )

    assert run.status == "completed"
    assert run.dispatched is True
    assert run.candidate_pairs == 1
    assert run.rejected_pairs == 0
    assert len(context["target"].calls) == 4
    assert [item[0] for item in context["target"].calls] == [
        context["target"].owner_id,
        context["target"].actor_id,
        context["target"].actor_id,
        context["target"].owner_id,
    ]
    response = run.execution_response()
    assert response["kind"] == "proof_experiment_generalized_authorization"
    assert response["oracle_verdict"] == "confirmed"
    assert response["finding"] is None
    assert response["finding_authority"] is False
    assert response["promotion_authority"] is False
    assert redacted_outcome(response)["kind"] == response["kind"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("admission_enabled", "execution_enabled", "disabled_gate"),
    (
        (False, True, "proof_experiment_admission"),
        (True, False, "generalized_authorization_execution"),
    ),
)
async def test_one_click_selection_is_passive_when_a_gate_is_disabled(
    tmp_path,
    monkeypatch,
    admission_enabled,
    execution_enabled,
    disabled_gate,
):
    context = _context(
        tmp_path,
        monkeypatch,
        admission_enabled=admission_enabled,
        execution_enabled=execution_enabled,
    )
    shadow = context["shadow"]
    run = await context["dispatcher"].run(
        actor_records=context["actor_records"],
        owner_records=context["owner_records"],
        payout_goal_plan=shadow.payout_goal_plan,
        operations=shadow.semantic_catalog.planner_operations(),
    )

    assert run.status == "selected_execution_disabled"
    assert run.dispatched is False
    assert run.disabled_gates == (disabled_gate,)
    assert context["target"].calls == []
    assert context["budget"].snapshot()["total_requests"] == 0
    assert context["registry"]._owned == {}


@pytest.mark.asyncio
async def test_one_click_does_not_dispatch_without_a_payout_ranked_operation(
    tmp_path,
    monkeypatch,
):
    context = _context(tmp_path, monkeypatch)
    shadow = context["shadow"]
    run = await context["dispatcher"].run(
        actor_records=context["actor_records"],
        owner_records=context["owner_records"],
        payout_goal_plan=shadow.payout_goal_plan,
        operations=(),
    )

    assert run.status == "no_eligible_candidate"
    assert run.dispatched is False
    assert context["target"].calls == []
    assert context["registry"]._owned == {}


@pytest.mark.asyncio
async def test_one_click_prefers_the_higher_value_export_operation(
    tmp_path,
    monkeypatch,
):
    context = _context(
        tmp_path,
        monkeypatch,
        extra_export=True,
        one_click_config=GeneralizedAuthorizationOneClickConfig(
            max_pair_candidates=1,
        ),
    )
    shadow = context["shadow"]
    run = await context["dispatcher"].run(
        actor_records=context["actor_records"],
        owner_records=context["owner_records"],
        payout_goal_plan=shadow.payout_goal_plan,
        operations=shadow.semantic_catalog.planner_operations(),
    )

    assert run.status == "completed"
    assert run.candidate_pairs == 1
    assert run.dropped_for_bound == 1
    assert all("/api/documents/export?" in call[2] for call in context["target"].calls)


def test_admitted_capture_registry_entry_is_bound_to_the_r5_proof():
    registry = OwnershipRegistry()
    owner = "1" * 32
    actor = "2" * 32
    object_id = "document_7777777777777777"
    proof_ref = "ownership_experiment_proof:" + "a" * 64
    role_ref = "ownership_experiment_role:" + "b" * 64
    assert registry.register_admitted_capture_value(
        "https://api.example.test/api/documents",
        object_id,
        actor_persona=owner,
        source_proof_ref=proof_ref,
        source_role_binding_ref=role_ref,
        capture_digest="capture_set:" + "c" * 64,
    ) is not None

    with pytest.raises(
        LocatorOwnershipDenied,
        match="locator_ownership_admitted_capture_binding_mismatch",
    ):
        registry.issue_locator_proof(
            source_proof_ref="ownership_experiment_proof:" + "d" * 64,
            source_role_binding_ref=role_ref,
            actor_persona_id=actor,
            target_owner_persona_id=owner,
            method="GET",
            url=f"https://api.example.test/api/documents/{object_id}",
            body=None,
            locator_kind=OwnedRequestLocatorKind.PATH,
            locator_pointer="/segments/2",
        )
