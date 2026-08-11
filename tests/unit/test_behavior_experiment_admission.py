"""R4B atomic proof-experiment admission tests; no target transport is used."""

from __future__ import annotations

import json
from dataclasses import replace

import pytest

import core.behavior as behavior_package

from core.behavior.compiler import OperationContract, OperationSafety
from core.behavior.constraints import ConstraintLedgerBuilder
from core.behavior.experiment_admission import (
    PROOF_EXPERIMENT_ADMISSION_MODE,
    GeneralizedExperimentAdmission,
    ProofExperimentAdmissionConfig,
    ProofExperimentAdmissionDenied,
    experiment_authority_context_ref,
    experiment_endpoint_ref,
    experiment_ownership_ref,
    experiment_persona_ref,
)
from core.behavior.experiment_sdk import (
    ExistingBackendAdapter,
    ExperimentAction,
    ExperimentActionClass,
    ExperimentCleanupContract,
    ExperimentControl,
    ExperimentControlKind,
    ExperimentOracleContract,
    ExperimentPhase,
    ExperimentWorldBinding,
    ExperimentWorldKind,
    ExperimentWorldManifest,
    MutationExpectation,
    ProofExperimentCompiler,
)
from core.behavior.normalize import stable_hash
from core.behavior.payout_goals import (
    PayoutGoalCandidate,
    PayoutSink,
    ProofTopology,
    SecurityProperty,
    SecurityWitnessGoal,
    WorldRequirement,
)
from core.behavior.proposals import (
    AuthorizationExperimentProposal,
    MutationLocator,
    ProposalLeg,
)
from core.behavior.receipts import ABORTED, RESERVED, BehavioralReceiptStore
from core.behavior.replanning import ConstraintReplanner
from core.cortex.execution_policy import CandidateAction, ExecutionPolicy, PolicyExecutor
from core.foundry.authorization import AuthorizationEnvelope
from core.foundry.vault import PersonaVault
from core.safety.action_classifier import SAFE_READ
from core.safety.ownership_registry import OwnershipRegistry
from core.safety.proof_budget import ProofBudget, endpoint_key
from core.safety.proof_mode import ProofMode
from core.safety.provenance import ProvenanceSink


ORIGIN = "https://api.example.test"
OWNER_URL = f"{ORIGIN}/api/documents/document_123"
PEER_URL = f"{ORIGIN}/api/documents/document_456"
WORKFLOW = "behavioral_object_authorization"
PROOF_GOAL = "prove_owned_object_authorization"


def _envelope(*, workflows=(WORKFLOW,)) -> AuthorizationEnvelope:
    envelope = AuthorizationEnvelope(
        envelope_id="r4b-envelope",
        researcher_identity="researcher@example.test",
        target_handle="example-program",
        authorized_origins=[ORIGIN],
        authorization_basis="Public bug bounty authorization",
        disclosure_attestation=True,
        allowed_workflows=list(workflows),
        max_accounts_per_service=2,
    )
    envelope.sign()
    return envelope


def _owned_world(
    *,
    slot: str,
    persona_id: str,
    envelope: AuthorizationEnvelope,
) -> ExperimentWorldBinding:
    return ExperimentWorldBinding.build(
        slot=slot,
        kind=ExperimentWorldKind.OWNED_ACCOUNT,
        world_ref=stable_hash("world", persona_id),
        persona_ref=experiment_persona_ref(persona_id),
        ownership_ref=experiment_ownership_ref(envelope, persona_id),
    )


def _manifest(
    *,
    envelope: AuthorizationEnvelope,
    actor_id: str,
    peer_id: str,
    authority_context_ref=None,
):
    proposal_id = stable_hash("authorization_proposal", "r4b-proposal")
    operation_id = stable_hash("action", "read-private-document")
    source_ref = stable_hash("source_ref", "r4b-controlled-capture")
    actor = _owned_world(slot="actor", persona_id=actor_id, envelope=envelope)
    peer = _owned_world(slot="peer", persona_id=peer_id, envelope=envelope)
    proposal = AuthorizationExperimentProposal(
        proposal_id=proposal_id,
        action_id=operation_id,
        operation_label="Read private document",
        source_ref=source_ref,
        source_record_index=0,
        risk_class="safe_read",
        mutations=(
            MutationLocator(
                location_kind="request_path",
                pointer="/document_id",
                semantic_key="document_id",
                source_value_hash=stable_hash("mutation_value", "owner-document"),
                replacement_value_hash=stable_hash("mutation_value", "peer-document"),
            ),
        ),
        legs=(
            ProposalLeg("peer_baseline", peer.world_ref, "peer_observed_value"),
            ProposalLeg("source_baseline", actor.world_ref, "source_observed_value"),
            ProposalLeg("counterfactual", actor.world_ref, "peer_observed_value"),
        ),
    )
    backend = ExistingBackendAdapter.authorization(proposal)
    terminal = OperationContract(
        operation_id=operation_id,
        label="Read private document",
        requires=(),
        produces=(),
        safety=OperationSafety.READ_ONLY,
        observed_success=True,
    )
    goal = SecurityWitnessGoal.build(
        operation=terminal,
        sink=PayoutSink.FILE_ACCESS,
        security_property=SecurityProperty.OBJECT_AUTHORIZATION,
        evidence_refs=(proposal_id, source_ref),
    )
    requirement = WorldRequirement(
        ProofTopology.PAIRED_OWNED_ACCOUNTS,
        2,
        required_workflows=(WORKFLOW,),
    )
    candidate = PayoutGoalCandidate.build(
        goal=goal,
        world_requirement=requirement,
        backend="object_authorization",
        score=100,
        blockers=(),
    )
    replan = ConstraintReplanner((terminal,)).compile_witness(
        goal,
        ledger=ConstraintLedgerBuilder().build(),
    )
    world_manifest = ExperimentWorldManifest.build(
        requirement=requirement,
        bindings=(actor, peer),
    )
    evidence = (proposal_id, source_ref)
    endpoint_ref = experiment_endpoint_ref("GET", OWNER_URL)
    owner_control_action = ExperimentAction.build(
        ordinal=0,
        phase=ExperimentPhase.CONTROL,
        operation_id=operation_id,
        world_binding_id=actor.binding_id,
        action_class=ExperimentActionClass.SAFE_READ,
        endpoint_ref=endpoint_ref,
        mutation=MutationExpectation.NONE,
        evidence_refs=evidence,
    )
    peer_control_action = ExperimentAction.build(
        ordinal=1,
        phase=ExperimentPhase.CONTROL,
        operation_id=operation_id,
        world_binding_id=peer.binding_id,
        action_class=ExperimentActionClass.SAFE_READ,
        endpoint_ref=endpoint_ref,
        mutation=MutationExpectation.NONE,
        evidence_refs=evidence,
    )
    treatment_action = ExperimentAction.build(
        ordinal=2,
        phase=ExperimentPhase.TREATMENT,
        operation_id=operation_id,
        world_binding_id=peer.binding_id,
        action_class=ExperimentActionClass.CROSS_OBJECT_READ,
        endpoint_ref=endpoint_ref,
        mutation=MutationExpectation.NONE,
        evidence_refs=evidence,
    )
    witness_action = ExperimentAction.build(
        ordinal=3,
        phase=ExperimentPhase.WITNESS,
        operation_id=operation_id,
        world_binding_id=actor.binding_id,
        action_class=ExperimentActionClass.SAFE_READ,
        endpoint_ref=endpoint_ref,
        mutation=MutationExpectation.NONE,
        evidence_refs=evidence,
    )
    controls = (
        ExperimentControl.build(
            kind=ExperimentControlKind.OWNER_BASELINE,
            action_ids=(owner_control_action.action_id,),
            world_binding_ids=(actor.binding_id,),
        ),
        ExperimentControl.build(
            kind=ExperimentControlKind.PEER_BASELINE,
            action_ids=(peer_control_action.action_id,),
            world_binding_ids=(peer.binding_id,),
        ),
    )
    oracle = ExperimentOracleContract.build(
        goal=goal,
        control_ids=tuple(item.control_id for item in controls),
        treatment_action_ids=(treatment_action.action_id,),
        witness_action_ids=(witness_action.action_id,),
        comparison_kind="owned_object_counterfactual",
    )
    actions = (
        owner_control_action,
        peer_control_action,
        treatment_action,
        witness_action,
    )
    manifest = ProofExperimentCompiler().compile(
        candidate=candidate,
        replan=replan,
        world_manifest=world_manifest,
        backend=backend,
        actions=actions,
        controls=controls,
        oracle=oracle,
        cleanup=ExperimentCleanupContract.build(),
        target_ref=stable_hash("security_obligation_target", ORIGIN),
        authority_context_ref=(
            authority_context_ref
            or experiment_authority_context_ref(
                envelope,
                ORIGIN,
                (WORKFLOW,),
            )
        ),
        provenance_refs=(stable_hash("provenance", "r4b-manifest"),),
    )
    return manifest, actor, peer


def _runtime_actions(manifest, *, actor_id: str, peer_id: str):
    owner_control, peer_control, treatment, witness = manifest.actions
    return {
        owner_control.action_id: CandidateAction(
            method="GET",
            url=OWNER_URL,
            hint=SAFE_READ,
            actor_persona_id=actor_id,
            expected_side_effect="none",
            proof_goal=PROOF_GOAL,
        ),
        peer_control.action_id: CandidateAction(
            method="GET",
            url=PEER_URL,
            hint=SAFE_READ,
            actor_persona_id=peer_id,
            expected_side_effect="none",
            proof_goal=PROOF_GOAL,
        ),
        treatment.action_id: CandidateAction(
            method="GET",
            url=OWNER_URL,
            hint=ExperimentActionClass.CROSS_OBJECT_READ.value,
            actor_persona_id=peer_id,
            target_owner_persona_id=actor_id,
            target_is_researcher_owned=True,
            expected_side_effect="none",
            proof_goal=PROOF_GOAL,
        ),
        witness.action_id: CandidateAction(
            method="GET",
            url=OWNER_URL,
            hint=SAFE_READ,
            actor_persona_id=actor_id,
            expected_side_effect="none",
            proof_goal=PROOF_GOAL,
        ),
    }


def _context(tmp_path, monkeypatch, *, max_requests_per_endpoint=5):
    monkeypatch.setenv("SENTINELFORGE_PERSONA_VAULT", str(tmp_path / "personas"))
    vault = PersonaVault()
    actor = vault.add_persona(
        label="R4B Alice",
        email="alice-r4b@example.test",
    )
    peer = vault.add_persona(
        label="R4B Bob",
        email="bob-r4b@example.test",
    )
    envelope = _envelope()
    manifest, actor_world, peer_world = _manifest(
        envelope=envelope,
        actor_id=actor.persona_id,
        peer_id=peer.persona_id,
    )
    budget = ProofBudget(
        max_total_requests=20,
        max_requests_per_endpoint=max_requests_per_endpoint,
        max_cross_object_reads=1,
        max_privilege_mutations=2,
        max_creates=4,
        allow_delete=False,
        allow_real_user_data_access=False,
    )
    ownership = OwnershipRegistry()
    ownership.register_created_value(
        f"{ORIGIN}/api/documents",
        "document_123",
        actor_persona=actor.persona_id,
    )
    policy = ExecutionPolicy(
        ProofMode.BOUNTY_SAFE,
        scope_filter=lambda url: str(url).startswith(f"{ORIGIN}/"),
        budget=budget,
        ownership_registry=ownership,
    )
    transport_calls = []

    async def forbidden_transport(*args, **kwargs):
        transport_calls.append((args, kwargs))
        raise AssertionError("R4B must not call transport")

    executor = PolicyExecutor(
        forbidden_transport,
        policy,
        ProvenanceSink(),
    )
    store = BehavioralReceiptStore(tmp_path / "receipts")
    coordinator = GeneralizedExperimentAdmission(
        manifest=manifest,
        target_origin=ORIGIN,
        authorization=envelope,
        executor=executor,
        runtime_actions=_runtime_actions(
            manifest,
            actor_id=actor.persona_id,
            peer_id=peer.persona_id,
        ),
        runtime_world_ids={
            actor_world.binding_id: actor.persona_id,
            peer_world.binding_id: peer.persona_id,
        },
        persona_vault=vault,
        config=ProofExperimentAdmissionConfig(enabled=True),
        receipt_store=store,
    )
    return {
        "coordinator": coordinator,
        "manifest": manifest,
        "envelope": envelope,
        "executor": executor,
        "budget": budget,
        "vault": vault,
        "actor": actor,
        "peer": peer,
        "actor_world": actor_world,
        "peer_world": peer_world,
        "store": store,
        "transport_calls": transport_calls,
    }


def test_atomic_admission_binds_authority_worlds_requests_budget_and_receipt(
    tmp_path,
    monkeypatch,
):
    context = _context(tmp_path, monkeypatch)
    coordinator = context["coordinator"]

    fingerprint = coordinator.validate_preflight()
    assert len(fingerprint) == 64
    assert coordinator.validate_preflight() == fingerprint
    assert context["budget"].snapshot()["total_requests"] == 0
    assert context["transport_calls"] == []

    lease = coordinator.admit()
    contract = lease.contract
    assert contract.mode == PROOF_EXPERIMENT_ADMISSION_MODE
    assert contract.manifest_id == context["manifest"].manifest_id
    assert contract.atomic_budget_reserved is True
    assert contract.single_use_claim_available is True
    assert contract.backend_dispatch_authority is False
    assert contract.ambient_authority is False
    assert contract.finding_authority is False
    assert contract.target_requests_sent == 0
    assert contract.executable is False
    assert contract.total_request_units == 4
    assert context["store"].load(fingerprint).state == RESERVED
    assert context["transport_calls"] == []

    with pytest.raises(ProofExperimentAdmissionDenied):
        coordinator.admit()
    assert context["store"].load(fingerprint).state == RESERVED

    claim = lease.claim()
    assert claim.state == "claimed"
    assert claim.reserved_units == 4
    with pytest.raises(ProofExperimentAdmissionDenied, match="not_claimable"):
        lease.claim()

    assert claim.abort() == 4
    assert claim.state == "aborted"
    assert context["store"].load(fingerprint).state == ABORTED
    assert context["budget"].snapshot()["total_requests"] == 0
    assert context["transport_calls"] == []

    context["envelope"].envelope_id = "renamed-r4b-envelope"
    with pytest.raises(ProofExperimentAdmissionDenied, match="context_mismatch"):
        coordinator.admit()


def test_budget_sequence_is_all_or_nothing_and_failed_admission_is_durable(
    tmp_path,
    monkeypatch,
):
    context = _context(
        tmp_path,
        monkeypatch,
        max_requests_per_endpoint=3,
    )
    fingerprint = context["coordinator"].validate_preflight()

    with pytest.raises(ProofExperimentAdmissionDenied, match="budget_reservation_denied"):
        context["coordinator"].admit()

    receipt = context["store"].load(fingerprint)
    assert receipt.state == ABORTED
    assert receipt.abort_reason == "proof_experiment_budget_reservation_denied"
    reservation_id, reason = context["budget"].try_reserve(
        ((SAFE_READ, endpoint_key(OWNER_URL)),)
    )
    assert reason == "ok"
    assert reservation_id is not None
    assert context["budget"].release_reservation(reservation_id) == 1
    assert context["transport_calls"] == []


def test_request_endpoint_actor_and_structural_substitution_fail_before_receipt(
    tmp_path,
    monkeypatch,
):
    context = _context(tmp_path, monkeypatch)
    original = context["coordinator"]
    actions = dict(original.runtime_actions)
    treatment = context["manifest"].actions[2]

    actions[treatment.action_id] = replace(
        actions[treatment.action_id],
        url=f"{ORIGIN}/api/admin/users/user_999",
    )
    changed_endpoint = GeneralizedExperimentAdmission(
        manifest=context["manifest"],
        target_origin=ORIGIN,
        authorization=context["envelope"],
        executor=context["executor"],
        runtime_actions=actions,
        runtime_world_ids=original.runtime_world_ids,
        persona_vault=context["vault"],
        config=ProofExperimentAdmissionConfig(enabled=True),
        receipt_store=context["store"],
    )
    with pytest.raises(ProofExperimentAdmissionDenied, match="endpoint_mismatch"):
        changed_endpoint.admit()

    actions = dict(original.runtime_actions)
    actions[treatment.action_id] = replace(
        actions[treatment.action_id],
        actor_persona_id=context["actor"].persona_id,
    )
    changed_actor = GeneralizedExperimentAdmission(
        manifest=context["manifest"],
        target_origin=ORIGIN,
        authorization=context["envelope"],
        executor=context["executor"],
        runtime_actions=actions,
        runtime_world_ids=original.runtime_world_ids,
        persona_vault=context["vault"],
        config=ProofExperimentAdmissionConfig(enabled=True),
        receipt_store=context["store"],
    )
    with pytest.raises(ProofExperimentAdmissionDenied, match="actor_world_mismatch"):
        changed_actor.admit()

    owner_control = context["manifest"].actions[0]
    actions = dict(original.runtime_actions)
    actions[owner_control.action_id] = replace(
        actions[owner_control.action_id],
        method="DELETE",
    )
    destructive = GeneralizedExperimentAdmission(
        manifest=context["manifest"],
        target_origin=ORIGIN,
        authorization=context["envelope"],
        executor=context["executor"],
        runtime_actions=actions,
        runtime_world_ids=original.runtime_world_ids,
        persona_vault=context["vault"],
        config=ProofExperimentAdmissionConfig(enabled=True),
        receipt_store=context["store"],
    )
    with pytest.raises(
        ProofExperimentAdmissionDenied,
        match="structural_classification_mismatch",
    ):
        destructive.admit()

    assert not (tmp_path / "receipts").exists()
    assert context["transport_calls"] == []


def test_signed_scope_workflow_context_and_vault_are_revalidated_live(
    tmp_path,
    monkeypatch,
):
    context = _context(tmp_path, monkeypatch)
    original = context["coordinator"]

    wrong_manifest, wrong_actor_world, wrong_peer_world = _manifest(
        envelope=context["envelope"],
        actor_id=context["actor"].persona_id,
        peer_id=context["peer"].persona_id,
        authority_context_ref=stable_hash(
            "experiment_authority_context",
            "wrong-authority",
        ),
    )
    wrong_context = GeneralizedExperimentAdmission(
        manifest=wrong_manifest,
        target_origin=ORIGIN,
        authorization=context["envelope"],
        executor=context["executor"],
        runtime_actions=_runtime_actions(
            wrong_manifest,
            actor_id=context["actor"].persona_id,
            peer_id=context["peer"].persona_id,
        ),
        runtime_world_ids={
            wrong_actor_world.binding_id: context["actor"].persona_id,
            wrong_peer_world.binding_id: context["peer"].persona_id,
        },
        persona_vault=context["vault"],
        config=ProofExperimentAdmissionConfig(enabled=True),
        receipt_store=context["store"],
    )
    with pytest.raises(ProofExperimentAdmissionDenied, match="context_mismatch"):
        wrong_context.admit()

    context["envelope"].allowed_workflows = []
    with pytest.raises(ProofExperimentAdmissionDenied, match="signature_mismatch"):
        original.admit()
    assert context["budget"].snapshot()["total_requests"] == 0

    fresh = _context(tmp_path / "fresh", monkeypatch)
    fresh["vault"].remove_persona(fresh["peer"].persona_id)
    with pytest.raises(ProofExperimentAdmissionDenied, match="not_in_vault"):
        fresh["coordinator"].admit()
    assert fresh["transport_calls"] == []

    swapped = _context(tmp_path / "swapped", monkeypatch)
    runtime_worlds = dict(swapped["coordinator"].runtime_world_ids)
    runtime_worlds[swapped["actor_world"].binding_id] = swapped["peer"].persona_id
    swapped_coordinator = GeneralizedExperimentAdmission(
        manifest=swapped["manifest"],
        target_origin=ORIGIN,
        authorization=swapped["envelope"],
        executor=swapped["executor"],
        runtime_actions=swapped["coordinator"].runtime_actions,
        runtime_world_ids=runtime_worlds,
        persona_vault=swapped["vault"],
        config=ProofExperimentAdmissionConfig(enabled=True),
        receipt_store=swapped["store"],
    )
    with pytest.raises(ProofExperimentAdmissionDenied, match="world_ref_mismatch"):
        swapped_coordinator.admit()
    assert swapped["transport_calls"] == []


def test_admission_is_default_off_and_requires_complete_bounty_safe_policy(
    tmp_path,
    monkeypatch,
):
    context = _context(tmp_path, monkeypatch)
    disabled = GeneralizedExperimentAdmission(
        manifest=context["manifest"],
        target_origin=ORIGIN,
        authorization=context["envelope"],
        executor=context["executor"],
        runtime_actions=context["coordinator"].runtime_actions,
        runtime_world_ids=context["coordinator"].runtime_world_ids,
        persona_vault=context["vault"],
        config=ProofExperimentAdmissionConfig(enabled=False),
        receipt_store=context["store"],
    )
    with pytest.raises(ProofExperimentAdmissionDenied, match="is_disabled"):
        disabled.admit()

    incomplete_executor = PolicyExecutor(
        context["executor"].raw_send,
        ExecutionPolicy(ProofMode.BOUNTY_SAFE),
        None,
    )
    incomplete = GeneralizedExperimentAdmission(
        manifest=context["manifest"],
        target_origin=ORIGIN,
        authorization=context["envelope"],
        executor=incomplete_executor,
        runtime_actions=context["coordinator"].runtime_actions,
        runtime_world_ids=context["coordinator"].runtime_world_ids,
        persona_vault=context["vault"],
        config=ProofExperimentAdmissionConfig(enabled=True),
        receipt_store=context["store"],
    )
    with pytest.raises(ProofExperimentAdmissionDenied, match="complete_bounty_safe"):
        incomplete.admit()
    assert context["transport_calls"] == []


def test_admission_module_remains_explicit_only_and_transportless(tmp_path, monkeypatch):
    assert not hasattr(behavior_package, "GeneralizedExperimentAdmission")
    module = __import__(
        "core.behavior.experiment_admission",
        fromlist=["GeneralizedExperimentAdmission"],
    )
    assert not hasattr(module, "MutatingTransport")
    assert not hasattr(module.GeneralizedExperimentAdmission, "execute")

    context = _context(tmp_path, monkeypatch)
    lease = context["coordinator"].admit()
    serialized = lease.to_dict()
    encoded = json.dumps(serialized, sort_keys=True)
    assert serialized["backend_dispatch_authority"] is False
    assert serialized["target_requests_sent"] == 0
    assert ORIGIN not in encoded
    assert OWNER_URL not in encoded
    assert context["actor"].persona_id not in encoded
    assert context["peer"].persona_id not in encoded
    assert context["transport_calls"] == []
    assert lease.abort() == 4
