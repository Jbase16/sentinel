"""Generalized passive proof-experiment SDK tests; no target traffic is used."""

from __future__ import annotations

import json
from dataclasses import replace

import pytest

import core.behavior as behavior_package

from core.behavior.compiler import OperationContract, OperationSafety
from core.behavior.constraints import ConstraintLedgerBuilder
from core.behavior.experiment_sdk import (
    PROOF_EXPERIMENT_SDK_MODE,
    CleanupBinding,
    CleanupOutcome,
    ExistingBackendAdapter,
    ExistingBackendKind,
    ExperimentAction,
    ExperimentActionClass,
    ExperimentCleanupContract,
    ExperimentControl,
    ExperimentControlKind,
    ExperimentOracleContract,
    ExperimentOracleEvaluation,
    ExperimentPhase,
    ExperimentWorldBinding,
    ExperimentWorldKind,
    ExperimentWorldManifest,
    MutationExpectation,
    OracleVerdict,
    ProofExperimentCompiler,
)
from core.behavior.lifecycle import LifecycleContractMiner
from core.behavior.normalize import stable_hash
from core.behavior.omission import MinimizedOmissionCompiler
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
from core.behavior.replanning import ConstraintReplanner
from core.behavior.state_machine import StateMachineLegalityMiner


TARGET_REF = stable_hash("security_obligation_target", "https://api.example.test")
AUTHORITY_CONTEXT_REF = stable_hash(
    "experiment_authority_context",
    {"envelope": "required-but-not-admitted"},
)
PROVENANCE_REF = stable_hash("provenance", {"capture": "r4a"})
ENDPOINT_REF = stable_hash("experiment_endpoint", "/api/documents/{document_id}")


def _owned_binding(
    slot: str,
    suffix: str,
    *,
    role: str | None = None,
    lifecycle: bool = False,
) -> ExperimentWorldBinding:
    return ExperimentWorldBinding.build(
        slot=slot,
        kind=ExperimentWorldKind.OWNED_ACCOUNT,
        world_ref=stable_hash("world", suffix),
        persona_ref=stable_hash("experiment_persona", suffix),
        ownership_ref=stable_hash("ownership_proof", suffix),
        role_ref=(stable_hash("experiment_role", role) if role is not None else None),
        lifecycle_ref=(
            stable_hash("experiment_lifecycle", suffix) if lifecycle else None
        ),
    )


def _anonymous_binding() -> ExperimentWorldBinding:
    return ExperimentWorldBinding.build(
        slot="anonymous",
        kind=ExperimentWorldKind.FRESH_ANONYMOUS,
        world_ref=stable_hash("world", "fresh-anonymous"),
        fresh=True,
    )


def _callback_binding() -> ExperimentWorldBinding:
    return ExperimentWorldBinding.build(
        slot="callback",
        kind=ExperimentWorldKind.CALLBACK_RECEIVER,
        world_ref=stable_hash("world", "callback"),
        callback_ref=stable_hash("callback_receiver", "owned-r4a"),
    )


WORLD_CASES = (
    (
        WorldRequirement(ProofTopology.ZERO_PERSONA_ANONYMOUS, 0),
        (),
        0,
    ),
    (
        WorldRequirement(
            ProofTopology.FRESH_ANONYMOUS,
            0,
            requires_fresh_anonymous=True,
        ),
        (_anonymous_binding(),),
        1,
    ),
    (
        WorldRequirement(ProofTopology.SINGLE_OWNED_ACCOUNT, 1),
        (_owned_binding("actor", "single"),),
        1,
    ),
    (
        WorldRequirement(ProofTopology.PAIRED_OWNED_ACCOUNTS, 2),
        (
            _owned_binding("actor", "alice"),
            _owned_binding("peer", "bob"),
        ),
        2,
    ),
    (
        WorldRequirement(
            ProofTopology.OWNED_ROLE_DIFFERENTIAL,
            2,
            required_role_worlds=2,
        ),
        (
            _owned_binding("high_role", "admin", role="admin"),
            _owned_binding("low_role", "member", role="member"),
        ),
        2,
    ),
    (
        WorldRequirement(
            ProofTopology.CONTROLLED_LIFECYCLE,
            1,
            requires_controlled_lifecycle=True,
        ),
        (_owned_binding("actor", "lifecycle", lifecycle=True),),
        1,
    ),
    (
        WorldRequirement(
            ProofTopology.CALLBACK_RECEIVER,
            0,
            requires_callback_receiver=True,
        ),
        (_callback_binding(),),
        1,
    ),
)


@pytest.mark.parametrize("requirement,bindings,expected_count", WORLD_CASES)
def test_every_topology_has_one_exact_non_interchangeable_world_shape(
    requirement,
    bindings,
    expected_count,
):
    first = ExperimentWorldManifest.build(
        requirement=requirement,
        bindings=tuple(reversed(bindings)),
    )
    second = ExperimentWorldManifest.build(
        requirement=requirement,
        bindings=bindings,
    )

    assert first == second
    assert len(first.bindings) == expected_count
    assert first.requirement.topology is requirement.topology


def test_zero_one_and_two_world_manifests_cannot_be_interchanged_or_forged():
    single_requirement = WorldRequirement(ProofTopology.SINGLE_OWNED_ACCOUNT, 1)
    paired = (
        _owned_binding("actor", "alice"),
        _owned_binding("peer", "bob"),
    )
    with pytest.raises(ValueError, match="slots"):
        ExperimentWorldManifest.build(
            requirement=single_requirement,
            bindings=paired,
        )

    same_role = stable_hash("experiment_role", "same")
    high = ExperimentWorldBinding.build(
        slot="high_role",
        kind=ExperimentWorldKind.OWNED_ACCOUNT,
        world_ref=stable_hash("world", "high"),
        persona_ref=stable_hash("experiment_persona", "high"),
        ownership_ref=stable_hash("ownership_proof", "high"),
        role_ref=same_role,
    )
    low = ExperimentWorldBinding.build(
        slot="low_role",
        kind=ExperimentWorldKind.OWNED_ACCOUNT,
        world_ref=stable_hash("world", "low"),
        persona_ref=stable_hash("experiment_persona", "low"),
        ownership_ref=stable_hash("ownership_proof", "low"),
        role_ref=same_role,
    )
    with pytest.raises(ValueError):
        ExperimentWorldManifest.build(
            requirement=WorldRequirement(
                ProofTopology.OWNED_ROLE_DIFFERENTIAL,
                2,
                required_role_worlds=2,
            ),
            bindings=(high, low),
        )


def _authorization_context():
    proposal_id = stable_hash("authorization_proposal", "r4a-proposal")
    operation_id = stable_hash("action", "read-document")
    source_ref = stable_hash("source_ref", "r4a-capture")
    actor = _owned_binding("actor", "alice")
    peer = _owned_binding("peer", "bob")
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
                source_value_hash=stable_hash("mutation_value", "alice-document"),
                replacement_value_hash=stable_hash("mutation_value", "bob-document"),
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
        required_workflows=("behavioral_object_authorization",),
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
    owner_control_action = ExperimentAction.build(
        ordinal=0,
        phase=ExperimentPhase.CONTROL,
        operation_id=operation_id,
        world_binding_id=actor.binding_id,
        action_class=ExperimentActionClass.SAFE_READ,
        endpoint_ref=ENDPOINT_REF,
        mutation=MutationExpectation.NONE,
        evidence_refs=evidence,
    )
    peer_control_action = ExperimentAction.build(
        ordinal=1,
        phase=ExperimentPhase.CONTROL,
        operation_id=operation_id,
        world_binding_id=peer.binding_id,
        action_class=ExperimentActionClass.SAFE_READ,
        endpoint_ref=ENDPOINT_REF,
        mutation=MutationExpectation.NONE,
        evidence_refs=evidence,
    )
    treatment_action = ExperimentAction.build(
        ordinal=2,
        phase=ExperimentPhase.TREATMENT,
        operation_id=operation_id,
        world_binding_id=peer.binding_id,
        action_class=ExperimentActionClass.CROSS_OBJECT_READ,
        endpoint_ref=ENDPOINT_REF,
        mutation=MutationExpectation.NONE,
        evidence_refs=evidence,
    )
    witness_action = ExperimentAction.build(
        ordinal=3,
        phase=ExperimentPhase.WITNESS,
        operation_id=operation_id,
        world_binding_id=actor.binding_id,
        action_class=ExperimentActionClass.SAFE_READ,
        endpoint_ref=ENDPOINT_REF,
        mutation=MutationExpectation.NONE,
        evidence_refs=evidence,
    )
    owner_control = ExperimentControl.build(
        kind=ExperimentControlKind.OWNER_BASELINE,
        action_ids=(owner_control_action.action_id,),
        world_binding_ids=(actor.binding_id,),
    )
    peer_control = ExperimentControl.build(
        kind=ExperimentControlKind.PEER_BASELINE,
        action_ids=(peer_control_action.action_id,),
        world_binding_ids=(peer.binding_id,),
    )
    actions = (
        owner_control_action,
        peer_control_action,
        treatment_action,
        witness_action,
    )
    controls = (owner_control, peer_control)
    oracle = ExperimentOracleContract.build(
        goal=goal,
        control_ids=tuple(item.control_id for item in controls),
        treatment_action_ids=(treatment_action.action_id,),
        witness_action_ids=(witness_action.action_id,),
        comparison_kind="owned_object_counterfactual",
    )
    return {
        "proposal": proposal,
        "backend": backend,
        "goal": goal,
        "candidate": candidate,
        "replan": replan,
        "world_manifest": world_manifest,
        "actor": actor,
        "peer": peer,
        "actions": actions,
        "controls": controls,
        "oracle": oracle,
        "cleanup": ExperimentCleanupContract.build(),
    }


def _compile(context, **overrides):
    values = {
        "candidate": context["candidate"],
        "replan": context["replan"],
        "world_manifest": context["world_manifest"],
        "backend": context["backend"],
        "actions": context["actions"],
        "controls": context["controls"],
        "oracle": context["oracle"],
        "cleanup": context["cleanup"],
        "target_ref": TARGET_REF,
        "authority_context_ref": AUTHORITY_CONTEXT_REF,
        "provenance_refs": (PROVENANCE_REF,),
    }
    values.update(overrides)
    return ProofExperimentCompiler().compile(**values)


def test_object_authorization_compiles_to_one_sealed_non_executable_manifest():
    context = _authorization_context()
    first = _compile(context)
    second = _compile(
        context,
        actions=tuple(reversed(context["actions"])),
        controls=tuple(reversed(context["controls"])),
    )

    assert first == second
    assert first.mode == PROOF_EXPERIMENT_SDK_MODE
    assert first.executable is False
    assert first.finding_authority is False
    assert first.target_requests_sent == 0
    assert first.policy_digest == context["replan"].policy_digest
    assert first.budget.total_request_units == len(first.actions) == 4
    assert tuple(item.action_id for item in first.budget.claims) == tuple(
        item.action_id for item in first.actions
    )
    assert first.budget.atomic_reservation_required is True
    assert first.budget.reserved is False
    assert {
        "analysis_only_no_execution_authority",
        "atomic_budget_reservation_required",
        "backend_specific_admission_required",
        "durable_execution_receipt_required",
    } <= set(first.execution_blockers)
    assert first.oracle.finding_authority is False
    assert first.oracle.adversarial_triage_required is True


def test_manifest_rejects_a_world_topology_or_goal_operation_substitution():
    context = _authorization_context()
    single = ExperimentWorldManifest.build(
        requirement=WorldRequirement(ProofTopology.SINGLE_OWNED_ACCOUNT, 1),
        bindings=(_owned_binding("actor", "single"),),
    )
    with pytest.raises(ValueError, match="do not align"):
        _compile(context, world_manifest=single)

    actions = list(context["actions"])
    actions[2] = ExperimentAction.build(
        ordinal=2,
        phase=ExperimentPhase.TREATMENT,
        operation_id="unrelated_operation",
        world_binding_id=context["peer"].binding_id,
        action_class=ExperimentActionClass.CROSS_OBJECT_READ,
        endpoint_ref=ENDPOINT_REF,
        mutation=MutationExpectation.NONE,
        evidence_refs=context["goal"].evidence_refs,
    )
    oracle = ExperimentOracleContract.build(
        goal=context["goal"],
        control_ids=tuple(item.control_id for item in context["controls"]),
        treatment_action_ids=(actions[2].action_id,),
        witness_action_ids=(actions[3].action_id,),
        comparison_kind="owned_object_counterfactual",
    )
    with pytest.raises(ValueError, match="payout goal operation"):
        _compile(context, actions=actions, oracle=oracle)


def test_controls_partition_actions_and_bind_their_exact_worlds():
    context = _authorization_context()
    owner_action, peer_action, treatment, witness = context["actions"]

    wrong_world_control = ExperimentControl.build(
        kind=ExperimentControlKind.OWNER_BASELINE,
        action_ids=(owner_action.action_id,),
        world_binding_ids=(context["peer"].binding_id,),
    )
    wrong_world_controls = (wrong_world_control, context["controls"][1])
    wrong_world_oracle = ExperimentOracleContract.build(
        goal=context["goal"],
        control_ids=tuple(item.control_id for item in wrong_world_controls),
        treatment_action_ids=(treatment.action_id,),
        witness_action_ids=(witness.action_id,),
        comparison_kind="owned_object_counterfactual",
    )
    with pytest.raises(ValueError, match="exactly match"):
        _compile(
            context,
            controls=wrong_world_controls,
            oracle=wrong_world_oracle,
        )

    overlapping_control = ExperimentControl.build(
        kind=ExperimentControlKind.NEGATIVE_CONTROL,
        action_ids=(owner_action.action_id, peer_action.action_id),
        world_binding_ids=(context["actor"].binding_id, context["peer"].binding_id),
    )
    overlapping_controls = (context["controls"][0], overlapping_control)
    overlapping_oracle = ExperimentOracleContract.build(
        goal=context["goal"],
        control_ids=tuple(item.control_id for item in overlapping_controls),
        treatment_action_ids=(treatment.action_id,),
        witness_action_ids=(witness.action_id,),
        comparison_kind="owned_object_counterfactual",
    )
    with pytest.raises(ValueError, match="exactly one control"):
        _compile(
            context,
            controls=overlapping_controls,
            oracle=overlapping_oracle,
        )


def test_existing_authorization_adapter_refuses_weakened_backend_guards():
    proposal = _authorization_context()["proposal"]
    contract = ExistingBackendAdapter.authorization(proposal)

    assert contract.backend is ExistingBackendKind.OBJECT_AUTHORIZATION
    assert contract.inherits_authority is False
    assert contract.finding_authority is False
    assert contract.executable is False
    assert {
        "ownership_proof",
        "peer_baseline",
        "source_baseline",
        "counterfactual_response",
        "durable_receipt",
        "adversarial_triage",
    } <= set(contract.required_guards)

    weakened = replace(proposal, requires_policy_reclassification=False)
    with pytest.raises(ValueError, match="guards are incomplete"):
        ExistingBackendAdapter.authorization(weakened)


OMISSION_ORIGIN = "https://api.example.test"
WORKFLOW_ID = "workflow_7fa9f13a2b4c5d6e"
EXPORT_TOKEN = "token_4a5b6c7d8e9f0123"


def _omission_records():
    return (
        {
            "id": "create-workflow",
            "persona_id": "alice",
            "method": "POST",
            "url": f"{OMISSION_ORIGIN}/api/workflows",
            "request_body": '{"label":"controlled"}',
            "response_status": 201,
            "response_body": json.dumps({"workflowId": WORKFLOW_ID}),
        },
        {
            "id": "approve-workflow",
            "persona_id": "alice",
            "method": "POST",
            "url": f"{OMISSION_ORIGIN}/api/workflows/{WORKFLOW_ID}/approve",
            "request_body": "{}",
            "response_status": 200,
            "response_body": json.dumps({"exportToken": EXPORT_TOKEN}),
        },
        {
            "id": "export-workflow",
            "persona_id": "alice",
            "method": "GET",
            "url": (
                f"{OMISSION_ORIGIN}/api/workflows/{WORKFLOW_ID}/export"
                f"?exportToken={EXPORT_TOKEN}"
            ),
            "response_status": 200,
            "response_body": '{"status":"ready","artifact":"controlled"}',
        },
        {
            "id": "cleanup-workflow",
            "persona_id": "alice",
            "method": "PATCH",
            "url": f"{OMISSION_ORIGIN}/api/workflows/{WORKFLOW_ID}",
            "request_body": '{"archived":true}',
            "response_status": 200,
            "response_body": '{"archived":true}',
        },
    )


def test_existing_omission_backend_conforms_without_losing_stronger_checks():
    records = _omission_records()
    lifecycle = LifecycleContractMiner().mine(records, world_id="alice")
    state_machine = StateMachineLegalityMiner().mine(records, world_id="alice")
    result = MinimizedOmissionCompiler().compile(
        records,
        world_id="alice",
        lifecycle=lifecycle,
        state_machine=state_machine,
    )
    experiment = result.experiments[0]

    contract = ExistingBackendAdapter.omission(experiment)

    assert contract.backend is ExistingBackendKind.PREREQUISITE_OMISSION
    assert set(experiment.execution_blockers) == set(
        contract.inherited_execution_blockers
    )
    assert {
        "captured_state_match",
        "exact_success_body_match",
        "single_prerequisite_delta",
        "non_truncated_baseline",
        "cleanup_proof",
        "durable_receipt",
        "adversarial_triage",
    } <= set(contract.required_guards)
    assert contract.inherits_authority is False
    assert contract.finding_authority is False


def _mutation_contract(context):
    actor = context["actor"]
    peer = context["peer"]
    evidence = context["goal"].evidence_refs
    setup = ExperimentAction.build(
        ordinal=0,
        phase=ExperimentPhase.SETUP,
        operation_id="create_controlled_fixture",
        world_binding_id=actor.binding_id,
        action_class=ExperimentActionClass.OWNED_CREATE,
        endpoint_ref=ENDPOINT_REF,
        mutation=MutationExpectation.OWNED_CREATE,
        evidence_refs=evidence,
    )
    owner_control_action = ExperimentAction.build(
        ordinal=1,
        phase=ExperimentPhase.CONTROL,
        operation_id=context["goal"].terminal_operation_id,
        world_binding_id=actor.binding_id,
        action_class=ExperimentActionClass.SAFE_READ,
        endpoint_ref=ENDPOINT_REF,
        mutation=MutationExpectation.NONE,
        evidence_refs=evidence,
    )
    peer_control_action = ExperimentAction.build(
        ordinal=2,
        phase=ExperimentPhase.CONTROL,
        operation_id=context["goal"].terminal_operation_id,
        world_binding_id=peer.binding_id,
        action_class=ExperimentActionClass.SAFE_READ,
        endpoint_ref=ENDPOINT_REF,
        mutation=MutationExpectation.NONE,
        evidence_refs=evidence,
    )
    treatment = ExperimentAction.build(
        ordinal=3,
        phase=ExperimentPhase.TREATMENT,
        operation_id=context["goal"].terminal_operation_id,
        world_binding_id=peer.binding_id,
        action_class=ExperimentActionClass.CROSS_OBJECT_READ,
        endpoint_ref=ENDPOINT_REF,
        mutation=MutationExpectation.NONE,
        evidence_refs=evidence,
    )
    witness = ExperimentAction.build(
        ordinal=4,
        phase=ExperimentPhase.WITNESS,
        operation_id=context["goal"].terminal_operation_id,
        world_binding_id=actor.binding_id,
        action_class=ExperimentActionClass.SAFE_READ,
        endpoint_ref=ENDPOINT_REF,
        mutation=MutationExpectation.NONE,
        evidence_refs=evidence,
    )
    cleanup_action = ExperimentAction.build(
        ordinal=5,
        phase=ExperimentPhase.CLEANUP,
        operation_id="cleanup_controlled_fixture",
        world_binding_id=actor.binding_id,
        action_class=ExperimentActionClass.OWNED_UPDATE_LOW_RISK,
        endpoint_ref=ENDPOINT_REF,
        mutation=MutationExpectation.CLEANUP,
        evidence_refs=evidence,
    )
    cleanup_verification = ExperimentAction.build(
        ordinal=6,
        phase=ExperimentPhase.CLEANUP_VERIFICATION,
        operation_id="verify_controlled_fixture_cleanup",
        world_binding_id=actor.binding_id,
        action_class=ExperimentActionClass.SAFE_READ,
        endpoint_ref=ENDPOINT_REF,
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
        goal=context["goal"],
        control_ids=tuple(item.control_id for item in controls),
        treatment_action_ids=(treatment.action_id,),
        witness_action_ids=(witness.action_id,),
        comparison_kind="owned_object_counterfactual",
    )
    cleanup = ExperimentCleanupContract.build(
        (
            CleanupBinding.build(
                mutation_action_id=setup.action_id,
                cleanup_action_id=cleanup_action.action_id,
                verification_action_id=cleanup_verification.action_id,
            ),
        )
    )
    return (
        (
            setup,
            owner_control_action,
            peer_control_action,
            treatment,
            witness,
            cleanup_action,
            cleanup_verification,
        ),
        controls,
        oracle,
        cleanup,
    )


def test_mutation_requires_complete_cleanup_and_budget_coverage():
    context = _authorization_context()
    actions, controls, oracle, cleanup = _mutation_contract(context)

    with pytest.raises(ValueError, match="cleanup"):
        _compile(
            context,
            actions=actions,
            controls=controls,
            oracle=oracle,
            cleanup=ExperimentCleanupContract.build(),
        )

    manifest = _compile(
        context,
        actions=actions,
        controls=controls,
        oracle=oracle,
        cleanup=cleanup,
    )
    assert manifest.cleanup.required is True
    assert manifest.budget.total_request_units == 7
    assert "cleanup_execution_required" in manifest.execution_blockers
    assert manifest.budget.claims[-1].action_id == actions[-1].action_id

    with pytest.raises(ValueError):
        replace(
            manifest.budget,
            claims=manifest.budget.claims[:-1],
            total_request_units=6,
        )


def test_cleanup_actions_and_verifications_cannot_be_reused():
    first_mutation = stable_hash("proof_experiment_action", "first-mutation")
    second_mutation = stable_hash("proof_experiment_action", "second-mutation")
    shared_cleanup = stable_hash("proof_experiment_action", "shared-cleanup")
    shared_verification = stable_hash(
        "proof_experiment_action",
        "shared-verification",
    )
    bindings = tuple(
        CleanupBinding.build(
            mutation_action_id=mutation,
            cleanup_action_id=shared_cleanup,
            verification_action_id=shared_verification,
        )
        for mutation in (first_mutation, second_mutation)
    )

    with pytest.raises(ValueError, match="cleanup contract"):
        ExperimentCleanupContract.build(bindings)


def test_oracle_evaluation_can_confirm_only_for_adversarial_triage():
    manifest = _compile(_authorization_context())
    receipt_ref = stable_hash("behavioral_receipt", "r4a-runtime")
    control_ref = stable_hash("control_evidence", "owner-and-peer")
    treatment_ref = stable_hash("treatment_evidence", "counterfactual")
    witness_ref = stable_hash("witness_evidence", "independent-read")
    provenance_root = stable_hash("provenance", "r4a-runtime")

    evaluation = ExperimentOracleEvaluation.build(
        manifest=manifest,
        verdict=OracleVerdict.CONFIRMED,
        backend_receipt_ref=receipt_ref,
        control_evidence_refs=(control_ref,),
        treatment_evidence_refs=(treatment_ref,),
        witness_evidence_refs=(witness_ref,),
        cleanup_evidence_refs=(),
        provenance_root=provenance_root,
        cleanup_outcome=CleanupOutcome.NOT_REQUIRED,
    )

    assert evaluation.verdict is OracleVerdict.CONFIRMED
    assert evaluation.adversarial_triage_required is True
    assert evaluation.promotion_authority is False
    assert evaluation.finding_authority is False
    assert evaluation.executable is False
    assert "finding" not in evaluation.to_dict()

    with pytest.raises(ValueError, match="cannot support"):
        ExperimentOracleEvaluation.build(
            manifest=manifest,
            verdict=OracleVerdict.CONFIRMED,
            backend_receipt_ref=receipt_ref,
            control_evidence_refs=(control_ref,),
            treatment_evidence_refs=(treatment_ref,),
            witness_evidence_refs=(witness_ref,),
            cleanup_evidence_refs=(),
            provenance_root=provenance_root,
            cleanup_outcome=CleanupOutcome.UNCERTAIN,
        )

    inconclusive = ExperimentOracleEvaluation.build(
        manifest=manifest,
        verdict=OracleVerdict.INCONCLUSIVE,
        backend_receipt_ref=receipt_ref,
        control_evidence_refs=(),
        treatment_evidence_refs=(),
        witness_evidence_refs=(),
        cleanup_evidence_refs=(),
        provenance_root=provenance_root,
        cleanup_outcome=CleanupOutcome.NOT_REQUIRED,
        uncertainty_reasons=("target_effect_uncertain",),
    )
    assert inconclusive.verdict is OracleVerdict.INCONCLUSIVE
    assert inconclusive.uncertainty_reasons == ("target_effect_uncertain",)


def test_sdk_is_explicit_only_and_has_no_transport_or_execution_authority():
    assert not hasattr(behavior_package, "ProofExperimentCompiler")
    module = __import__(
        "core.behavior.experiment_sdk",
        fromlist=["ProofExperimentCompiler"],
    )
    for forbidden in ("requests", "httpx", "urllib", "PolicyExecutor"):
        assert not hasattr(module, forbidden)

    manifest = _compile(_authorization_context())
    serialized = json.dumps(manifest.to_dict(), sort_keys=True)
    assert '"target_requests_sent": 0' in serialized
    assert '"executable": false' in serialized
    assert '"finding_authority": false' in serialized
