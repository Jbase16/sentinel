"""R4C2 admitted omission tests; every target exchange is an in-memory fake."""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlsplit

import pytest

from core.behavior.compiler import OperationContract, OperationSafety
from core.behavior.constraints import ConstraintLedgerBuilder
from core.behavior.experiment_admission import (
    GeneralizedExperimentAdmission,
    ProofExperimentAdmissionConfig,
    experiment_authority_context_ref,
    experiment_endpoint_ref,
    experiment_ownership_ref,
    experiment_persona_ref,
)
from core.behavior.experiment_omission import (
    AdmittedOmissionExperimentConfig,
    AdmittedOmissionExperimentDenied,
    AdmittedOmissionExperimentExecutor,
)
from core.behavior.experiment_sdk import (
    CleanupBinding,
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
    OracleVerdict,
    ProofExperimentCompiler,
)
from core.behavior.lifecycle import LifecycleContractMiner
from core.behavior.normalize import stable_hash
from core.behavior.omission import MinimizedOmissionCompiler
from core.behavior.omission_confirmation import (
    FRESH_OMISSION_CONFIRMATION_WORKFLOW,
    FreshOmissionConfirmationConfig,
    FreshOmissionConfirmationExecutor,
)
from core.behavior.omission_boundary import FRESH_OMISSION_WORKFLOW
from core.behavior.payout_goals import (
    PayoutGoalCandidate,
    PayoutSink,
    ProofTopology,
    SecurityProperty,
    SecurityWitnessGoal,
    WorldRequirement,
)
from core.behavior.receipts import ABORTED, COMPLETED, BehavioralReceiptStore
from core.behavior.replanning import ConstraintReplanner
from core.behavior.runtime import CONTROLLED_SEQUENCE_WORKFLOW
from core.behavior.state_machine import StateMachineLegalityMiner
from core.cortex.execution_policy import ExecutionPolicy, PolicyExecutor
from core.foundry.authorization import AuthorizationEnvelope
from core.foundry.vault import PersonaVault
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
WORKFLOWS = (
    CONTROLLED_SEQUENCE_WORKFLOW,
    FRESH_OMISSION_WORKFLOW,
    FRESH_OMISSION_CONFIRMATION_WORKFLOW,
)


def _records(persona_id: str = "alice"):
    return (
        {
            "id": "create-workflow",
            "persona_id": persona_id,
            "method": "POST",
            "url": f"{ORIGIN}/api/workflows",
            "request_headers": {"x-csrf-token": "csrf-alice"},
            "request_body": '{"label":"controlled"}',
            "response_status": 201,
            "response_body": json.dumps({"workflowId": CAPTURED_ID}),
        },
        {
            "id": "fetch-export-capability",
            "persona_id": persona_id,
            "method": "GET",
            "url": f"{ORIGIN}/api/workflows/{CAPTURED_ID}/export-token",
            "request_headers": {"x-csrf-token": "csrf-alice"},
            "response_status": 200,
            "response_body": json.dumps({"exportToken": CAPTURED_TOKEN}),
        },
        {
            "id": "export-workflow",
            "persona_id": persona_id,
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
            "persona_id": persona_id,
            "method": "PATCH",
            "url": f"{ORIGIN}/api/workflows/{CAPTURED_ID}",
            "request_headers": {"x-csrf-token": "csrf-alice"},
            "request_body": '{"archived":true}',
            "response_status": 200,
            "response_body": '{"archived":true}',
        },
    )


def _experiment(records=None, *, world_id: str = "alice"):
    records = tuple(records or _records(world_id))
    lifecycle = LifecycleContractMiner().mine(records, world_id=world_id)
    state_machine = StateMachineLegalityMiner().mine(records, world_id=world_id)
    result = MinimizedOmissionCompiler().compile(
        records,
        world_id=world_id,
        lifecycle=lifecycle,
        state_machine=state_machine,
    )
    assert len(result.experiments) == 1
    return result.experiments[0]


def _envelope() -> AuthorizationEnvelope:
    envelope = AuthorizationEnvelope(
        envelope_id="r4c2-envelope",
        researcher_identity="researcher@example.test",
        target_handle="example-program",
        authorized_origins=[ORIGIN],
        authorization_basis="Public bug bounty authorization",
        disclosure_attestation=True,
        allowed_workflows=list(WORKFLOWS),
        max_accounts_per_service=1,
    )
    envelope.sign()
    return envelope


class _Target:
    def __init__(
        self,
        *,
        fail_cleanup_verification_for: str | None = None,
        uncertain_first_create: bool = False,
    ) -> None:
        self.fail_cleanup_verification_for = fail_cleanup_verification_for
        self.uncertain_first_create = uncertain_first_create
        self.creates = iter((BASELINE_ID, OMISSION_ID, CONTROL_ID))
        self.archived: set[str] = set()
        self.calls = []

    async def send(self, method, url, body=None, **kwargs):
        self.calls.append((method, url, body, kwargs))
        path = urlsplit(url).path
        parts = path.split("/")
        object_id = parts[3] if len(parts) > 3 else None
        if method == "POST":
            if self.uncertain_first_create and len(self.calls) == 1:
                return 201, {"accepted": True}
            return 201, {"workflowId": next(self.creates)}
        if method == "PATCH":
            assert object_id is not None
            self.archived.add(object_id)
            return 200, {"archived": True}
        if object_id in self.archived:
            if object_id == self.fail_cleanup_verification_for:
                return 200, dict(REFERENCE_BODY)
            return 200, {"archived": True}
        if path.endswith("/export-token"):
            return 200, {"exportToken": BASELINE_TOKEN}
        if object_id == CONTROL_ID and path.endswith("/export"):
            return 403, {"error": "capability belongs to another workflow"}
        if path.endswith("/export"):
            return 200, dict(REFERENCE_BODY)
        raise AssertionError(f"unexpected request: {method} {url}")


def _compile_manifest(
    *,
    experiment,
    backend_contract,
    runtime_actions,
    world,
    envelope,
    records,
    world_id,
):
    operation = OperationContract(
        operation_id=experiment.terminal_operation_id,
        label="export_workflow",
        requires=(),
        produces=(),
        safety=OperationSafety.READ_ONLY,
        observed_success=True,
    )
    goal = SecurityWitnessGoal.build(
        operation=operation,
        sink=PayoutSink.EXPORT_DOWNLOAD,
        security_property=SecurityProperty.PREREQUISITE_ENFORCEMENT,
        evidence_refs=backend_contract.source_evidence_refs,
    )
    requirement = WorldRequirement(
        ProofTopology.CONTROLLED_LIFECYCLE,
        1,
        requires_controlled_lifecycle=True,
        required_workflows=WORKFLOWS,
    )
    candidate = PayoutGoalCandidate.build(
        goal=goal,
        world_requirement=requirement,
        backend="prerequisite_omission",
        score=100,
        blockers=(),
    )
    replan = ConstraintReplanner((operation,)).compile_witness(
        goal,
        ledger=ConstraintLedgerBuilder().build(),
    )
    baseline_count = len(experiment.baseline_operation_ids)
    omission_count = len(experiment.omission_operation_ids)
    cleanup_start = baseline_count + 2 * omission_count
    phases = (
        *(ExperimentPhase.CONTROL for _ in range(baseline_count)),
        *(ExperimentPhase.TREATMENT for _ in range(omission_count)),
        *(ExperimentPhase.WITNESS for _ in range(omission_count)),
        *(ExperimentPhase.CLEANUP for _ in range(3)),
        *(ExperimentPhase.CLEANUP_VERIFICATION for _ in range(3)),
    )
    lifecycle = LifecycleContractMiner().mine(
        records,
        world_id=world_id,
    )
    cleanup_operation_id = lifecycle.candidates[0].cleanup_operation_id
    operation_ids = (
        *experiment.baseline_operation_ids,
        *experiment.omission_operation_ids,
        *experiment.omission_operation_ids,
        *(cleanup_operation_id for _ in range(3)),
        *(experiment.terminal_operation_id for _ in range(3)),
    )
    manifest_actions = tuple(
        ExperimentAction.build(
            ordinal=index,
            phase=phase,
            operation_id=operation_id,
            world_binding_id=world.binding_id,
            action_class=ExperimentActionClass(runtime_action.hint),
            endpoint_ref=experiment_endpoint_ref(
                runtime_action.method,
                runtime_action.url,
            ),
            mutation=(
                MutationExpectation.CLEANUP
                if phase is ExperimentPhase.CLEANUP
                else (
                    MutationExpectation.OWNED_CREATE
                    if runtime_action.hint == "OWNED_CREATE"
                    else MutationExpectation.NONE
                )
            ),
            evidence_refs=backend_contract.source_evidence_refs,
        )
        for index, (phase, operation_id, runtime_action) in enumerate(
            zip(phases, operation_ids, runtime_actions, strict=True)
        )
    )
    control = ExperimentControl.build(
        kind=ExperimentControlKind.VALID_SEQUENCE_BASELINE,
        action_ids=tuple(
            item.action_id for item in manifest_actions[:baseline_count]
        ),
        world_binding_ids=(world.binding_id,),
    )
    oracle = ExperimentOracleContract.build(
        goal=goal,
        control_ids=(control.control_id,),
        treatment_action_ids=tuple(
            item.action_id
            for item in manifest_actions[
                baseline_count : baseline_count + omission_count
            ]
        ),
        witness_action_ids=tuple(
            item.action_id
            for item in manifest_actions[
                baseline_count + omission_count : cleanup_start
            ]
        ),
        comparison_kind="fresh_prerequisite_omission",
    )
    create_indices = (
        0,
        baseline_count,
        baseline_count + omission_count,
    )
    verification_start = cleanup_start + 3
    cleanup = ExperimentCleanupContract.build(
        tuple(
            CleanupBinding.build(
                mutation_action_id=manifest_actions[create_index].action_id,
                cleanup_action_id=manifest_actions[cleanup_index].action_id,
                verification_action_id=manifest_actions[verification_index].action_id,
            )
            for create_index, cleanup_index, verification_index in (
                (create_indices[2], cleanup_start, verification_start),
                (create_indices[1], cleanup_start + 1, verification_start + 1),
                (create_indices[0], cleanup_start + 2, verification_start + 2),
            )
        )
    )
    return ProofExperimentCompiler().compile(
        candidate=candidate,
        replan=replan,
        world_manifest=ExperimentWorldManifest.build(
            requirement=requirement,
            bindings=(world,),
        ),
        backend=backend_contract,
        actions=manifest_actions,
        controls=(control,),
        oracle=oracle,
        cleanup=cleanup,
        target_ref=stable_hash("security_obligation_target", ORIGIN),
        authority_context_ref=experiment_authority_context_ref(
            envelope,
            ORIGIN,
            WORKFLOWS,
        ),
        provenance_refs=(stable_hash("provenance", "r4c2-manifest"),),
    )


def _context(
    tmp_path: Path,
    monkeypatch,
    *,
    target: _Target | None = None,
    enabled: bool = True,
):
    monkeypatch.setenv("SENTINELFORGE_PERSONA_VAULT", str(tmp_path / "personas"))
    vault = PersonaVault()
    persona = vault.add_persona(
        label="R4C2 actor",
        email="actor-r4c2@example.test",
    )
    records = _records(persona.persona_id)
    experiment = _experiment(records, world_id=persona.persona_id)
    envelope = _envelope()
    budget = ProofBudget(
        max_total_requests=13,
        max_requests_per_endpoint=6,
        max_cross_object_reads=0,
        max_privilege_mutations=0,
        max_creates=3,
        allow_delete=False,
        allow_real_user_data_access=False,
    )
    policy = ExecutionPolicy(
        "bounty_safe",
        scope_filter=lambda url: str(url).startswith(f"{ORIGIN}/"),
        budget=budget,
        ownership_registry=OwnershipRegistry(),
    )
    sink = ProvenanceSink()
    sink.record_context(
        target=ORIGIN,
        proof_mode="bounty_safe",
        policy_digest=policy.digest(),
    )
    live_target = target or _Target()
    executor = PolicyExecutor(live_target.send, policy, provenance=sink)
    backend = FreshOmissionConfirmationExecutor(
        records,
        world_id=persona.persona_id,
        target_origin=ORIGIN,
        authorization=envelope,
        actor_persona_id=persona.persona_id,
        executor=executor,
        experiment=experiment,
        config=FreshOmissionConfirmationConfig(enabled=True),
    )
    runtime_actions = backend.preview_admitted_actions()
    backend_contract = ExistingBackendAdapter.omission(experiment)
    world = ExperimentWorldBinding.build(
        slot="actor",
        kind=ExperimentWorldKind.OWNED_ACCOUNT,
        world_ref=experiment.world_ref,
        persona_ref=experiment_persona_ref(persona.persona_id),
        ownership_ref=experiment_ownership_ref(envelope, persona.persona_id),
        lifecycle_ref=experiment.lifecycle_id,
    )
    manifest = _compile_manifest(
        experiment=experiment,
        backend_contract=backend_contract,
        runtime_actions=runtime_actions,
        world=world,
        envelope=envelope,
        records=records,
        world_id=persona.persona_id,
    )
    store = BehavioralReceiptStore(tmp_path / "receipts")
    attestation_refs = (experiment.lifecycle_id,)
    lease = GeneralizedExperimentAdmission(
        manifest=manifest,
        target_origin=ORIGIN,
        authorization=envelope,
        executor=executor,
        runtime_actions={
            manifest_action.action_id: runtime_action
            for manifest_action, runtime_action in zip(
                manifest.actions,
                runtime_actions,
                strict=True,
            )
        },
        runtime_world_ids={world.binding_id: persona.persona_id},
        persona_vault=vault,
        world_attestation_refs={world.binding_id: attestation_refs},
        world_attestation_validator=lambda binding, runtime_id, refs: (
            binding.lifecycle_ref == experiment.lifecycle_id
            and runtime_id == persona.persona_id
            and refs == attestation_refs
        ),
        config=ProofExperimentAdmissionConfig(enabled=True),
        receipt_store=store,
    ).admit()
    claim = lease.claim()
    adapter = AdmittedOmissionExperimentExecutor(
        manifest=manifest,
        claim=claim,
        backend=backend,
        persona_vault=vault,
        world_attestation_refs=attestation_refs,
        config=AdmittedOmissionExperimentConfig(enabled=enabled),
    )
    return {
        "adapter": adapter,
        "claim": claim,
        "manifest": manifest,
        "store": store,
        "target": live_target,
        "budget": budget,
    }


@pytest.mark.asyncio
async def test_admitted_omission_confirms_then_verifies_all_cleanup(
    tmp_path,
    monkeypatch,
):
    context = _context(tmp_path, monkeypatch)

    result = await context["adapter"].execute()

    assert result.status == "completed"
    assert result.legacy_verdict == "confirmed_fail_open"
    assert result.oracle_evaluation.verdict is OracleVerdict.CONFIRMED
    assert result.oracle_evaluation.cleanup_outcome.value == "complete"
    assert result.requests_attempted == result.requests_sent == 13
    assert result.reserved_units_released == 0
    assert result.creates_completed == 3
    assert result.cleanup_steps_completed == 3
    assert result.cleanup_verifications_completed == 3
    assert result.orphaned_owned_state_possible is False
    assert result.finding_candidate_ref is not None
    assert result.finding_authority is False
    assert context["claim"].state == "completed"
    assert context["claim"].reserved_units == 0
    assert [method for method, *_ in context["target"].calls] == [
        "POST",
        "GET",
        "GET",
        "POST",
        "GET",
        "POST",
        "GET",
        "PATCH",
        "PATCH",
        "PATCH",
        "GET",
        "GET",
        "GET",
    ]
    receipt = context["store"].load(
        context["claim"].contract.receipt_fingerprint
    )
    assert receipt is not None and receipt.state == COMPLETED
    assert receipt.outcome is not None
    assert receipt.outcome["kind"] == "proof_experiment_omission"
    assert receipt.outcome["finding_authority"] is False
    serialized = json.dumps(receipt.outcome, sort_keys=True)
    for secret in (
        ORIGIN,
        CAPTURED_ID,
        CAPTURED_TOKEN,
        BASELINE_ID,
        OMISSION_ID,
        CONTROL_ID,
        BASELINE_TOKEN,
        "csrf-alice",
    ):
        assert secret not in serialized


@pytest.mark.asyncio
async def test_cleanup_verification_failure_is_inconclusive_and_non_promoting(
    tmp_path,
    monkeypatch,
):
    context = _context(
        tmp_path,
        monkeypatch,
        target=_Target(fail_cleanup_verification_for=CONTROL_ID),
    )

    result = await context["adapter"].execute()

    assert result.status == "aborted"
    assert result.oracle_evaluation.verdict is OracleVerdict.INCONCLUSIVE
    assert result.oracle_evaluation.cleanup_outcome.value == "uncertain"
    assert "cleanup_unverified" in result.oracle_evaluation.uncertainty_reasons
    assert result.cleanup_verifications_completed == 2
    assert result.orphaned_owned_state_possible is True
    assert result.finding_candidate_ref is None
    assert result.finding_authority is False
    assert context["claim"].state == "completed"


@pytest.mark.asyncio
async def test_uncertain_create_stops_treatment_and_preserves_orphan_warning(
    tmp_path,
    monkeypatch,
):
    context = _context(
        tmp_path,
        monkeypatch,
        target=_Target(uncertain_first_create=True),
    )

    result = await context["adapter"].execute()

    assert result.status == "aborted"
    assert result.oracle_evaluation.verdict is OracleVerdict.INCONCLUSIVE
    assert result.requests_attempted == result.requests_sent == 1
    assert result.reserved_units_released == 12
    assert result.creates_attempted == 1
    assert result.creates_completed == 0
    assert result.orphaned_owned_state_possible is True
    assert len(context["target"].calls) == 1
    assert result.finding_candidate_ref is None


@pytest.mark.asyncio
async def test_disabled_adapter_aborts_claim_before_target_traffic(
    tmp_path,
    monkeypatch,
):
    context = _context(tmp_path, monkeypatch, enabled=False)

    with pytest.raises(
        AdmittedOmissionExperimentDenied,
        match="proof_experiment_omission_is_disabled",
    ):
        await context["adapter"].execute()

    assert context["target"].calls == []
    assert context["claim"].state == "aborted"
    receipt = context["store"].load(
        context["claim"].contract.receipt_fingerprint
    )
    assert receipt is not None and receipt.state == ABORTED
