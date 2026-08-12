"""R5A2 passive ownership experiment binding and admission tests."""

from __future__ import annotations

import ast
import json
from dataclasses import replace
from pathlib import Path

import pytest

import core.behavior as behavior_package
import core.behavior.ownership_experiment as ownership_experiment_module
from core.behavior.compiler import OperationContract, OperationSafety
from core.behavior.constraints import ConstraintLedgerBuilder
from core.behavior.experiment_admission import (
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
from core.behavior.ownership_experiment import (
    OWNERSHIP_EXPERIMENT_ADMISSION_MODE,
    OWNERSHIP_EXPERIMENT_BINDING_MODE,
    GeneralizedOwnershipExperimentAdmission,
    GeneralizedOwnershipExperimentCompiler,
    GeneralizedOwnershipExperimentDenied,
    OwnershipExperimentRole,
)
from core.behavior.ownership_locators import (
    GeneralizedOwnershipLocatorCompiler,
    OwnershipLocatorKind,
)
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
from core.foundry.authorization import AuthorizationEnvelope


ORIGIN = "https://api.example.test"
ACTOR_WORLD = "actor-r5a2"
OWNER_WORLD = "owner-r5a2"
ACTOR_ID = "document_1111111111111111"
OWNER_ID = "document_2222222222222222"
WORKFLOW = "behavioral_object_authorization"


def _envelope() -> AuthorizationEnvelope:
    envelope = AuthorizationEnvelope(
        envelope_id="r5a2-envelope",
        researcher_identity="researcher@example.test",
        target_handle="example-program",
        authorized_origins=[ORIGIN],
        authorization_basis="Public bug bounty authorization",
        disclosure_attestation=True,
        allowed_workflows=[WORKFLOW],
        max_accounts_per_service=2,
    )
    envelope.sign()
    return envelope


def _use_record(kind: OwnershipLocatorKind, *, persona_id: str, object_id: str):
    base = {
        "id": f"{kind.value}-use",
        "persona_id": persona_id,
        "response_status": 200,
        "response_body": json.dumps({"ok": True}),
    }
    if kind is OwnershipLocatorKind.PATH:
        return {
            **base,
            "method": "GET",
            "url": f"{ORIGIN}/api/documents/{object_id}",
        }
    if kind is OwnershipLocatorKind.QUERY:
        return {
            **base,
            "method": "GET",
            "url": f"{ORIGIN}/api/documents/export?documentId={object_id}",
        }
    if kind is OwnershipLocatorKind.JSON:
        return {
            **base,
            "method": "GET",
            "url": f"{ORIGIN}/api/documents/lookup",
            "request_body": json.dumps({"documentId": object_id}),
        }
    if kind is OwnershipLocatorKind.FORM:
        return {
            **base,
            "method": "GET",
            "url": f"{ORIGIN}/api/documents/lookup-form",
            "request_headers": {"Content-Type": "application/x-www-form-urlencoded"},
            "request_body": f"documentId={object_id}",
        }
    if kind is OwnershipLocatorKind.GRAPHQL_VARIABLE:
        return {
            **base,
            "method": "POST",
            "url": f"{ORIGIN}/graphql",
            "request_body": json.dumps(
                {
                    "operationName": "GetDocument",
                    "query": (
                        "query GetDocument($documentId: ID!) "
                        "{ document(id: $documentId) { title } }"
                    ),
                    "variables": {"documentId": object_id},
                }
            ),
        }
    raise AssertionError(f"unsupported test locator: {kind}")


def _records(
    kind: OwnershipLocatorKind,
    *,
    persona_id: str,
    object_id: str,
):
    return (
        {
            "id": "create-document",
            "persona_id": persona_id,
            "method": "POST",
            "url": f"{ORIGIN}/api/documents",
            "request_body": json.dumps({"title": "controlled ownership marker"}),
            "response_status": 201,
            "response_body": json.dumps({"documentId": object_id}),
        },
        _use_record(kind, persona_id=persona_id, object_id=object_id),
    )


def _selection(records, kind):
    index = GeneralizedOwnershipLocatorCompiler().compile(records)
    matches = [
        use
        for evidence in index.evidence
        for use in evidence.uses
        if use.locator_kind is kind
    ]
    assert len(matches) == 1
    return index, matches[0]


def _world(*, slot, persona_id, envelope):
    return ExperimentWorldBinding.build(
        slot=slot,
        kind=ExperimentWorldKind.OWNED_ACCOUNT,
        world_ref=stable_hash("world", persona_id),
        persona_ref=experiment_persona_ref(persona_id),
        ownership_ref=experiment_ownership_ref(envelope, persona_id),
    )


def _manifest(
    *,
    kind: OwnershipLocatorKind,
    actor_records,
    owner_records,
    envelope,
    provenance_tag="base",
    witness_on_actor=False,
    extra_action_evidence=False,
):
    actor_index, actor_use = _selection(actor_records, kind)
    owner_index, owner_use = _selection(owner_records, kind)
    assert actor_use.operation_id == owner_use.operation_id
    actor_observation = next(
        item
        for item in actor_index.ledger.observations
        if item.source_ref == actor_use.source_ref
    )
    actor_request = actor_index.ledger._rehydrate_observation(actor_observation)
    endpoint_ref = experiment_endpoint_ref(actor_request.method, actor_request.url)
    actor_world = _world(
        slot="actor",
        persona_id=ACTOR_WORLD,
        envelope=envelope,
    )
    owner_world = _world(
        slot="peer",
        persona_id=OWNER_WORLD,
        envelope=envelope,
    )
    proposal_id = stable_hash(
        "authorization_proposal",
        {
            "kind": kind.value,
            "operation_id": actor_use.operation_id,
            "actor_capture": actor_index.capture_digest,
            "owner_capture": owner_index.capture_digest,
        },
    )
    proposal = AuthorizationExperimentProposal(
        proposal_id=proposal_id,
        action_id=actor_use.operation_id,
        operation_label="GetDocument",
        source_ref=actor_use.source_ref,
        source_record_index=1,
        risk_class="CROSS_OBJECT_READ",
        mutations=(
            MutationLocator(
                location_kind=kind.value,
                pointer=actor_use.locator_pointer,
                semantic_key="document_id",
                source_value_hash=stable_hash("observed_value", ACTOR_ID),
                replacement_value_hash=stable_hash("observed_value", OWNER_ID),
            ),
        ),
        legs=(
            ProposalLeg(
                "peer_baseline",
                owner_world.world_ref,
                "peer_observed_value",
            ),
            ProposalLeg(
                "source_baseline",
                actor_world.world_ref,
                "source_observed_value",
            ),
            ProposalLeg(
                "counterfactual",
                actor_world.world_ref,
                "peer_observed_value",
            ),
        ),
    )
    backend = ExistingBackendAdapter.authorization(proposal)
    operation = OperationContract(
        operation_id=actor_use.operation_id,
        label="GetDocument",
        requires=(),
        produces=(),
        safety=OperationSafety.READ_ONLY,
        observed_success=True,
    )
    goal = SecurityWitnessGoal.build(
        operation=operation,
        sink=PayoutSink.FILE_ACCESS,
        security_property=SecurityProperty.OBJECT_AUTHORIZATION,
        evidence_refs=backend.source_evidence_refs,
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
    replan = ConstraintReplanner((operation,)).compile_witness(
        goal,
        ledger=ConstraintLedgerBuilder().build(),
    )
    evidence = backend.source_evidence_refs
    if extra_action_evidence:
        evidence = (*evidence, stable_hash("provenance", "extra-action-evidence"))
    actions = (
        ExperimentAction.build(
            ordinal=0,
            phase=ExperimentPhase.CONTROL,
            operation_id=actor_use.operation_id,
            world_binding_id=owner_world.binding_id,
            action_class=ExperimentActionClass.SAFE_READ,
            endpoint_ref=endpoint_ref,
            mutation=MutationExpectation.NONE,
            evidence_refs=evidence,
        ),
        ExperimentAction.build(
            ordinal=1,
            phase=ExperimentPhase.CONTROL,
            operation_id=actor_use.operation_id,
            world_binding_id=actor_world.binding_id,
            action_class=ExperimentActionClass.SAFE_READ,
            endpoint_ref=endpoint_ref,
            mutation=MutationExpectation.NONE,
            evidence_refs=evidence,
        ),
        ExperimentAction.build(
            ordinal=2,
            phase=ExperimentPhase.TREATMENT,
            operation_id=actor_use.operation_id,
            world_binding_id=actor_world.binding_id,
            action_class=ExperimentActionClass.CROSS_OBJECT_READ,
            endpoint_ref=endpoint_ref,
            mutation=MutationExpectation.NONE,
            evidence_refs=evidence,
        ),
        ExperimentAction.build(
            ordinal=3,
            phase=ExperimentPhase.WITNESS,
            operation_id=actor_use.operation_id,
            world_binding_id=(
                actor_world.binding_id if witness_on_actor else owner_world.binding_id
            ),
            action_class=ExperimentActionClass.SAFE_READ,
            endpoint_ref=endpoint_ref,
            mutation=MutationExpectation.NONE,
            evidence_refs=evidence,
        ),
    )
    controls = (
        ExperimentControl.build(
            kind=ExperimentControlKind.PEER_BASELINE,
            action_ids=(actions[0].action_id,),
            world_binding_ids=(owner_world.binding_id,),
        ),
        ExperimentControl.build(
            kind=ExperimentControlKind.OWNER_BASELINE,
            action_ids=(actions[1].action_id,),
            world_binding_ids=(actor_world.binding_id,),
        ),
    )
    oracle = ExperimentOracleContract.build(
        goal=goal,
        control_ids=tuple(item.control_id for item in controls),
        treatment_action_ids=(actions[2].action_id,),
        witness_action_ids=(actions[3].action_id,),
        comparison_kind="owned_object_counterfactual",
    )
    manifest = ProofExperimentCompiler().compile(
        candidate=candidate,
        replan=replan,
        world_manifest=ExperimentWorldManifest.build(
            requirement=requirement,
            bindings=(actor_world, owner_world),
        ),
        backend=backend,
        actions=actions,
        controls=controls,
        oracle=oracle,
        cleanup=ExperimentCleanupContract.build(),
        target_ref=stable_hash("security_obligation_target", ORIGIN),
        authority_context_ref=experiment_authority_context_ref(
            envelope,
            ORIGIN,
            (WORKFLOW,),
        ),
        provenance_refs=(stable_hash("provenance", provenance_tag),),
    )
    return manifest, actor_use.lineage_binding_id, owner_use.lineage_binding_id


def _context(kind=OwnershipLocatorKind.PATH, **manifest_options):
    envelope = _envelope()
    actor_records = _records(kind, persona_id=ACTOR_WORLD, object_id=ACTOR_ID)
    owner_records = _records(kind, persona_id=OWNER_WORLD, object_id=OWNER_ID)
    manifest, actor_binding_id, owner_binding_id = _manifest(
        kind=kind,
        actor_records=actor_records,
        owner_records=owner_records,
        envelope=envelope,
        **manifest_options,
    )
    compiler = GeneralizedOwnershipExperimentCompiler()
    proof = compiler.compile(
        manifest=manifest,
        actor_records=actor_records,
        target_owner_records=owner_records,
        actor_lineage_binding_id=actor_binding_id,
        target_owner_lineage_binding_id=owner_binding_id,
    )
    return {
        "envelope": envelope,
        "actor_records": actor_records,
        "owner_records": owner_records,
        "manifest": manifest,
        "actor_binding_id": actor_binding_id,
        "owner_binding_id": owner_binding_id,
        "proof": proof,
        "compiler": compiler,
    }


@pytest.mark.parametrize("kind", tuple(OwnershipLocatorKind))
def test_compiler_seals_every_generalized_locator_without_execution_authority(kind):
    context = _context(kind)
    proof = context["proof"]

    assert proof.mode == OWNERSHIP_EXPERIMENT_BINDING_MODE
    assert proof.manifest_id == context["manifest"].manifest_id
    assert proof.actor.role is OwnershipExperimentRole.ACTOR
    assert proof.target_owner.role is OwnershipExperimentRole.TARGET_OWNER
    assert proof.actor.locator_kind is kind
    assert proof.target_owner.locator_kind is kind
    assert proof.actor.locator_pointer == proof.target_owner.locator_pointer
    assert proof.actor.operation_id == proof.target_owner.operation_id
    assert proof.actor.endpoint_ref == proof.target_owner.endpoint_ref
    assert proof.actor.value_hash != proof.target_owner.value_hash
    assert proof.target_requests_sent == 0
    assert proof.ownership_registry_writes == 0
    assert proof.budget_reserved is False
    assert proof.backend_dispatch_authority is False
    assert proof.finding_authority is False
    assert proof.executable is False


@pytest.mark.parametrize("kind", tuple(OwnershipLocatorKind))
def test_admission_reconstructs_current_capture_for_every_locator(kind):
    context = _context(kind)

    contract = GeneralizedOwnershipExperimentAdmission(
        proof=context["proof"],
        manifest=context["manifest"],
        target_origin=ORIGIN,
        authorization=context["envelope"],
        actor_records=context["actor_records"],
        target_owner_records=context["owner_records"],
    ).admit()

    assert contract.mode == OWNERSHIP_EXPERIMENT_ADMISSION_MODE
    assert contract.proof_id == context["proof"].proof_id
    assert contract.capture_revalidated is True
    assert contract.target_requests_sent == 0
    assert contract.ownership_registry_writes == 0
    assert contract.budget_reserved is False
    assert contract.single_use_claim_available is False
    assert contract.backend_dispatch_authority is False
    assert contract.finding_authority is False
    assert contract.executable is False


def test_proof_and_admission_are_deterministic_and_publicly_redacted():
    first = _context(OwnershipLocatorKind.GRAPHQL_VARIABLE)
    second_proof = first["compiler"].compile(
        manifest=first["manifest"],
        actor_records=first["actor_records"],
        target_owner_records=first["owner_records"],
        actor_lineage_binding_id=first["actor_binding_id"],
        target_owner_lineage_binding_id=first["owner_binding_id"],
    )
    first_contract = GeneralizedOwnershipExperimentAdmission(
        proof=first["proof"],
        manifest=first["manifest"],
        target_origin=ORIGIN,
        authorization=first["envelope"],
        actor_records=first["actor_records"],
        target_owner_records=first["owner_records"],
    ).admit()
    second_contract = GeneralizedOwnershipExperimentAdmission(
        proof=second_proof,
        manifest=first["manifest"],
        target_origin=ORIGIN,
        authorization=first["envelope"],
        actor_records=first["actor_records"],
        target_owner_records=first["owner_records"],
    ).admit()
    serialized = json.dumps(first["proof"].to_dict(), sort_keys=True)

    assert first["proof"].to_dict() == second_proof.to_dict()
    assert first_contract.to_dict() == second_contract.to_dict()
    for raw_value in (
        ORIGIN,
        ACTOR_WORLD,
        OWNER_WORLD,
        ACTOR_ID,
        OWNER_ID,
        "controlled ownership marker",
    ):
        assert raw_value not in serialized


def test_actor_and_owner_must_prove_the_same_locator_and_operation():
    actor_records = _records(
        OwnershipLocatorKind.PATH,
        persona_id=ACTOR_WORLD,
        object_id=ACTOR_ID,
    )
    owner_records = _records(
        OwnershipLocatorKind.QUERY,
        persona_id=OWNER_WORLD,
        object_id=OWNER_ID,
    )
    envelope = _envelope()
    manifest, actor_binding_id, _ = _manifest(
        kind=OwnershipLocatorKind.PATH,
        actor_records=actor_records,
        owner_records=_records(
            OwnershipLocatorKind.PATH,
            persona_id=OWNER_WORLD,
            object_id=OWNER_ID,
        ),
        envelope=envelope,
    )
    _, owner_use = _selection(owner_records, OwnershipLocatorKind.QUERY)

    with pytest.raises(
        GeneralizedOwnershipExperimentDenied,
        match="counterfactual_pair_is_not_equivalent",
    ):
        GeneralizedOwnershipExperimentCompiler().compile(
            manifest=manifest,
            actor_records=actor_records,
            target_owner_records=owner_records,
            actor_lineage_binding_id=actor_binding_id,
            target_owner_lineage_binding_id=owner_use.lineage_binding_id,
        )


def test_same_object_value_on_both_sides_is_not_a_counterfactual():
    kind = OwnershipLocatorKind.PATH
    envelope = _envelope()
    actor_records = _records(kind, persona_id=ACTOR_WORLD, object_id=ACTOR_ID)
    owner_records = _records(kind, persona_id=OWNER_WORLD, object_id=ACTOR_ID)
    manifest, actor_binding_id, owner_binding_id = _manifest(
        kind=kind,
        actor_records=actor_records,
        owner_records=owner_records,
        envelope=envelope,
    )

    with pytest.raises(
        GeneralizedOwnershipExperimentDenied,
        match="counterfactual_pair_is_not_equivalent",
    ):
        GeneralizedOwnershipExperimentCompiler().compile(
            manifest=manifest,
            actor_records=actor_records,
            target_owner_records=owner_records,
            actor_lineage_binding_id=actor_binding_id,
            target_owner_lineage_binding_id=owner_binding_id,
        )


def test_witness_must_be_bound_to_the_target_owner_world():
    kind = OwnershipLocatorKind.PATH
    envelope = _envelope()
    actor_records = _records(kind, persona_id=ACTOR_WORLD, object_id=ACTOR_ID)
    owner_records = _records(kind, persona_id=OWNER_WORLD, object_id=OWNER_ID)
    manifest, actor_binding_id, owner_binding_id = _manifest(
        kind=kind,
        actor_records=actor_records,
        owner_records=owner_records,
        envelope=envelope,
        witness_on_actor=True,
    )

    with pytest.raises(
        GeneralizedOwnershipExperimentDenied,
        match="relations_do_not_match_capture",
    ):
        GeneralizedOwnershipExperimentCompiler().compile(
            manifest=manifest,
            actor_records=actor_records,
            target_owner_records=owner_records,
            actor_lineage_binding_id=actor_binding_id,
            target_owner_lineage_binding_id=owner_binding_id,
        )


def test_manifest_actions_cannot_carry_unbound_evidence():
    kind = OwnershipLocatorKind.PATH
    envelope = _envelope()
    actor_records = _records(kind, persona_id=ACTOR_WORLD, object_id=ACTOR_ID)
    owner_records = _records(kind, persona_id=OWNER_WORLD, object_id=OWNER_ID)
    manifest, actor_binding_id, owner_binding_id = _manifest(
        kind=kind,
        actor_records=actor_records,
        owner_records=owner_records,
        envelope=envelope,
        extra_action_evidence=True,
    )

    with pytest.raises(
        GeneralizedOwnershipExperimentDenied,
        match="relations_do_not_match_capture",
    ):
        GeneralizedOwnershipExperimentCompiler().compile(
            manifest=manifest,
            actor_records=actor_records,
            target_owner_records=owner_records,
            actor_lineage_binding_id=actor_binding_id,
            target_owner_lineage_binding_id=owner_binding_id,
        )


def test_admission_rejects_capture_drift_instead_of_selecting_a_new_object():
    context = _context()
    changed_owner_records = _records(
        OwnershipLocatorKind.PATH,
        persona_id=OWNER_WORLD,
        object_id="document_3333333333333333",
    )

    with pytest.raises(
        GeneralizedOwnershipExperimentDenied,
        match="lineage_binding_is_missing_or_ambiguous",
    ):
        GeneralizedOwnershipExperimentAdmission(
            proof=context["proof"],
            manifest=context["manifest"],
            target_origin=ORIGIN,
            authorization=context["envelope"],
            actor_records=context["actor_records"],
            target_owner_records=changed_owner_records,
        ).admit()


def test_admission_rejects_a_different_valid_manifest():
    context = _context()
    other_manifest, _, _ = _manifest(
        kind=OwnershipLocatorKind.PATH,
        actor_records=context["actor_records"],
        owner_records=context["owner_records"],
        envelope=context["envelope"],
        provenance_tag="different-valid-manifest",
    )

    with pytest.raises(
        GeneralizedOwnershipExperimentDenied,
        match="manifest_identity_mismatch",
    ):
        GeneralizedOwnershipExperimentAdmission(
            proof=context["proof"],
            manifest=other_manifest,
            target_origin=ORIGIN,
            authorization=context["envelope"],
            actor_records=context["actor_records"],
            target_owner_records=context["owner_records"],
        ).admit()


def test_admission_rejects_capture_records_from_another_origin():
    context = _context()
    changed_actor_records = list(context["actor_records"])
    changed_actor_records[0] = {
        **changed_actor_records[0],
        "url": "https://outside.example.test/api/documents",
    }

    with pytest.raises(
        GeneralizedOwnershipExperimentDenied,
        match="capture_origin_mismatch",
    ):
        GeneralizedOwnershipExperimentAdmission(
            proof=context["proof"],
            manifest=context["manifest"],
            target_origin=ORIGIN,
            authorization=context["envelope"],
            actor_records=changed_actor_records,
            target_owner_records=context["owner_records"],
        ).admit()


def test_admission_rejects_unsigned_or_replaced_authority():
    context = _context()
    unsigned = _envelope()
    unsigned.attestation_signature = None
    with pytest.raises(
        GeneralizedOwnershipExperimentDenied,
        match="authorization_is_unsigned",
    ):
        GeneralizedOwnershipExperimentAdmission(
            proof=context["proof"],
            manifest=context["manifest"],
            target_origin=ORIGIN,
            authorization=unsigned,
            actor_records=context["actor_records"],
            target_owner_records=context["owner_records"],
        ).admit()

    replacement = _envelope()
    replacement.researcher_identity = "different-researcher@example.test"
    replacement.sign()
    with pytest.raises(
        GeneralizedOwnershipExperimentDenied,
        match="authority_context_mismatch",
    ):
        GeneralizedOwnershipExperimentAdmission(
            proof=context["proof"],
            manifest=context["manifest"],
            target_origin=ORIGIN,
            authorization=replacement,
            actor_records=context["actor_records"],
            target_owner_records=context["owner_records"],
        ).admit()


def test_contracts_reject_content_address_tampering():
    context = _context()
    proof = context["proof"]

    with pytest.raises(ValueError, match="role binding"):
        replace(proof.actor, locator_pointer="/different")
    with pytest.raises(ValueError, match="experiment proof"):
        replace(proof, treatment_action_id=proof.witness_action_id)


def test_r5a2_is_explicit_only_and_has_no_transport_or_policy_surface():
    assert not hasattr(behavior_package, "GeneralizedOwnershipExperimentCompiler")
    tree = ast.parse(Path(ownership_experiment_module.__file__).read_text())
    imported_roots = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported_roots.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported_roots.add(node.module.split(".", 1)[0])

    assert not imported_roots & {
        "httpx",
        "requests",
        "socket",
        "urllib3",
    }
    source = Path(ownership_experiment_module.__file__).read_text()
    assert "PolicyExecutor" not in source
    assert "OwnershipRegistry" not in source
    assert "ProofBudget" not in source
