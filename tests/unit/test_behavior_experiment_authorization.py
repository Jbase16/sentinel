"""R4C1 admitted authorization execution tests; all traffic uses in-memory fakes."""

from __future__ import annotations

import ast
from dataclasses import replace
from pathlib import Path

import pytest

import core.behavior as behavior_package
import core.behavior.experiment_authorization as authorization_module
from core.behavior.active import ControlledAuthorizationExecutor
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
from core.behavior.experiment_authorization import (
    AdmittedAuthorizationExperimentConfig,
    AdmittedAuthorizationExperimentDenied,
    AdmittedAuthorizationExperimentExecutor,
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
    OracleVerdict,
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
from core.behavior.proposals import compile_authorization_proposals
from core.behavior.receipts import ABORTED, COMPLETED, BehavioralReceiptStore
from core.behavior.replanning import ConstraintReplanner
from core.cortex.execution_policy import ExecutionPolicy, PolicyExecutor
from core.foundry.authorization import AuthorizationEnvelope
from core.foundry.vault import PersonaVault
from core.safety.ownership_registry import OwnershipRegistry
from core.safety.proof_budget import ProofBudget
from core.safety.provenance import ProvenanceSink


ORIGIN = "https://api.example.test"
SOURCE_OBJECT = "RlLB9Tjpk7YfkTaBB0SpzA"
PEER_OBJECT = "9QsBs4y23m6HH4aB38ffkA"
SOURCE_URL = f"{ORIGIN}/v1/documents/{SOURCE_OBJECT}"
PEER_URL = f"{ORIGIN}/v1/documents/{PEER_OBJECT}"
WORKFLOW = "behavioral_object_authorization"


class _Target:
    def __init__(
        self,
        *,
        attack_denied: bool = False,
        first_status: int = 200,
        witness_status: int = 200,
    ):
        self.attack_denied = attack_denied
        self.first_status = first_status
        self.witness_status = witness_status
        self.source_persona_id = None
        self.calls = []

    async def send(self, persona_id, method, url, body=None, **kwargs):
        self.calls.append((persona_id, method, url, body, kwargs))
        if len(self.calls) == 1 and self.first_status != 200:
            return self.first_status, {"error": "stale session"}
        if len(self.calls) == 4 and self.witness_status != 200:
            return self.witness_status, {"error": "witness unavailable"}
        if persona_id == self.source_persona_id and url == PEER_URL:
            if self.attack_denied:
                return 403, {"error": "forbidden"}
            return 200, {"privateMarker": "PeerPrivateMarker", "id": PEER_OBJECT}
        if url == PEER_URL:
            return 200, {"privateMarker": "PeerPrivateMarker", "id": PEER_OBJECT}
        return 200, {"privateMarker": "SourcePrivateMarker", "id": SOURCE_OBJECT}


def _envelope() -> AuthorizationEnvelope:
    envelope = AuthorizationEnvelope(
        envelope_id="r4c1-envelope",
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


def _world(*, slot, persona_id, envelope):
    return ExperimentWorldBinding.build(
        slot=slot,
        kind=ExperimentWorldKind.OWNED_ACCOUNT,
        world_ref=stable_hash("world", persona_id),
        persona_ref=experiment_persona_ref(persona_id),
        ownership_ref=experiment_ownership_ref(envelope, persona_id),
    )


def _compile_manifest(*, proposal, actions, source_world, peer_world, envelope):
    backend = ExistingBackendAdapter.authorization(proposal)
    operation = OperationContract(
        operation_id=proposal.action_id,
        label=proposal.operation_label,
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
    manifest_actions = (
        ExperimentAction.build(
            ordinal=0,
            phase=ExperimentPhase.CONTROL,
            operation_id=proposal.action_id,
            world_binding_id=peer_world.binding_id,
            action_class=ExperimentActionClass.SAFE_READ,
            endpoint_ref=experiment_endpoint_ref(actions[0].method, actions[0].url),
            mutation=MutationExpectation.NONE,
            evidence_refs=evidence,
        ),
        ExperimentAction.build(
            ordinal=1,
            phase=ExperimentPhase.CONTROL,
            operation_id=proposal.action_id,
            world_binding_id=source_world.binding_id,
            action_class=ExperimentActionClass.SAFE_READ,
            endpoint_ref=experiment_endpoint_ref(actions[1].method, actions[1].url),
            mutation=MutationExpectation.NONE,
            evidence_refs=evidence,
        ),
        ExperimentAction.build(
            ordinal=2,
            phase=ExperimentPhase.TREATMENT,
            operation_id=proposal.action_id,
            world_binding_id=source_world.binding_id,
            action_class=ExperimentActionClass.CROSS_OBJECT_READ,
            endpoint_ref=experiment_endpoint_ref(actions[2].method, actions[2].url),
            mutation=MutationExpectation.NONE,
            evidence_refs=evidence,
        ),
        ExperimentAction.build(
            ordinal=3,
            phase=ExperimentPhase.WITNESS,
            operation_id=proposal.action_id,
            world_binding_id=peer_world.binding_id,
            action_class=ExperimentActionClass.SAFE_READ,
            endpoint_ref=experiment_endpoint_ref(actions[3].method, actions[3].url),
            mutation=MutationExpectation.NONE,
            evidence_refs=evidence,
        ),
    )
    controls = (
        ExperimentControl.build(
            kind=ExperimentControlKind.PEER_BASELINE,
            action_ids=(manifest_actions[0].action_id,),
            world_binding_ids=(peer_world.binding_id,),
        ),
        ExperimentControl.build(
            kind=ExperimentControlKind.OWNER_BASELINE,
            action_ids=(manifest_actions[1].action_id,),
            world_binding_ids=(source_world.binding_id,),
        ),
    )
    oracle = ExperimentOracleContract.build(
        goal=goal,
        control_ids=tuple(item.control_id for item in controls),
        treatment_action_ids=(manifest_actions[2].action_id,),
        witness_action_ids=(manifest_actions[3].action_id,),
        comparison_kind="owned_object_counterfactual",
    )
    return ProofExperimentCompiler().compile(
        candidate=candidate,
        replan=replan,
        world_manifest=ExperimentWorldManifest.build(
            requirement=requirement,
            bindings=(source_world, peer_world),
        ),
        backend=backend,
        actions=manifest_actions,
        controls=controls,
        oracle=oracle,
        cleanup=ExperimentCleanupContract.build(),
        target_ref=stable_hash("security_obligation_target", ORIGIN),
        authority_context_ref=experiment_authority_context_ref(
            envelope,
            ORIGIN,
            (WORKFLOW,),
        ),
        provenance_refs=(stable_hash("provenance", "r4c1-manifest"),),
    )


def _context(tmp_path, monkeypatch, *, target=None, enabled=True):
    monkeypatch.setenv("SENTINELFORGE_PERSONA_VAULT", str(tmp_path / "personas"))
    vault = PersonaVault()
    source = vault.add_persona(
        label="R4C1 source",
        email="source-r4c1@example.test",
    )
    peer = vault.add_persona(
        label="R4C1 peer",
        email="peer-r4c1@example.test",
    )
    source_records = [{"method": "GET", "url": SOURCE_URL}]
    peer_records = [{"method": "GET", "url": PEER_URL}]
    batch = compile_authorization_proposals(
        source_records,
        peer_records,
        source_world=source.persona_id,
        peer_world=peer.persona_id,
    )
    proposal = batch.proposals[0]
    envelope = _envelope()
    registry = OwnershipRegistry()
    registry.register_created_value(
        f"{ORIGIN}/v1/documents",
        PEER_OBJECT,
        actor_persona=peer.persona_id,
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
    live_target.source_persona_id = source.persona_id

    def make_executor(persona_id):
        async def raw(method, url, body=None, **kwargs):
            return await live_target.send(persona_id, method, url, body, **kwargs)

        return PolicyExecutor(raw, policy, sink)

    executors = {
        source.persona_id: make_executor(source.persona_id),
        peer.persona_id: make_executor(peer.persona_id),
    }
    backend = ControlledAuthorizationExecutor(
        target_origin=ORIGIN,
        authorization=envelope,
        source_persona=source,
        peer_persona=peer,
        executors=executors,
    )
    runtime_actions = backend.preview_admitted_actions(
        proposal,
        source_records,
        peer_records,
    )
    source_world = _world(
        slot="actor",
        persona_id=source.persona_id,
        envelope=envelope,
    )
    peer_world = _world(
        slot="peer",
        persona_id=peer.persona_id,
        envelope=envelope,
    )
    manifest = _compile_manifest(
        proposal=proposal,
        actions=runtime_actions,
        source_world=source_world,
        peer_world=peer_world,
        envelope=envelope,
    )
    store = BehavioralReceiptStore(tmp_path / "receipts")
    lease = GeneralizedExperimentAdmission(
        manifest=manifest,
        target_origin=ORIGIN,
        authorization=envelope,
        executor=executors[source.persona_id],
        runtime_actions={
            manifest_action.action_id: runtime_action
            for manifest_action, runtime_action in zip(
                manifest.actions,
                runtime_actions,
                strict=True,
            )
        },
        runtime_world_ids={
            source_world.binding_id: source.persona_id,
            peer_world.binding_id: peer.persona_id,
        },
        persona_vault=vault,
        config=ProofExperimentAdmissionConfig(enabled=True),
        receipt_store=store,
    ).admit()
    claim = lease.claim()
    adapter = AdmittedAuthorizationExperimentExecutor(
        manifest=manifest,
        claim=claim,
        backend=backend,
        persona_vault=vault,
        config=AdmittedAuthorizationExperimentConfig(enabled=enabled),
    )
    return {
        "adapter": adapter,
        "proposal": proposal,
        "source_records": source_records,
        "peer_records": peer_records,
        "target": live_target,
        "claim": claim,
        "budget": budget,
        "store": store,
        "manifest": manifest,
        "registry": registry,
        "source": source,
    }


def test_r4c1_is_explicit_only_and_has_no_direct_transport_surface():
    assert not hasattr(behavior_package, "AdmittedAuthorizationExperimentExecutor")
    tree = ast.parse(Path(authorization_module.__file__).read_text())
    imported_roots = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported_roots.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported_roots.add(node.module.split(".", 1)[0])
    assert not imported_roots & {"httpx", "requests", "socket", "urllib3"}
    assert not any(
        isinstance(node, ast.Attribute) and node.attr == "raw_send"
        for node in ast.walk(tree)
    )


@pytest.mark.asyncio
async def test_default_off_aborts_claim_without_target_traffic(tmp_path, monkeypatch):
    context = _context(tmp_path, monkeypatch, enabled=False)

    with pytest.raises(
        AdmittedAuthorizationExperimentDenied,
        match="authorization_is_disabled",
    ):
        await context["adapter"].execute(
            context["proposal"],
            context["source_records"],
            context["peer_records"],
        )

    assert context["target"].calls == []
    assert context["claim"].state == "aborted"
    assert context["claim"].reserved_units == 0
    receipt = context["store"].load(context["claim"].contract.receipt_fingerprint)
    assert receipt is not None and receipt.state == ABORTED


@pytest.mark.asyncio
async def test_confirmed_sequence_uses_four_reserved_actions_and_non_promoting_receipt(
    tmp_path, monkeypatch
):
    context = _context(tmp_path, monkeypatch)

    result = await context["adapter"].execute(
        context["proposal"],
        context["source_records"],
        context["peer_records"],
    )

    assert result.status == "completed"
    assert result.legacy_verdict == "BOLA_CONFIRMED"
    assert result.oracle_evaluation.verdict is OracleVerdict.CONFIRMED
    assert result.requests_attempted == result.requests_sent == 4
    assert result.reserved_units_released == 0
    assert result.finding_candidate_ref is not None
    assert result.finding_authority is False
    assert result.promotion_authority is False
    assert result.adversarial_triage_required is True
    with pytest.raises(ValueError, match="result contract is invalid"):
        replace(result, finding_authority=True)
    assert [item[2] for item in context["target"].calls] == [
        PEER_URL,
        SOURCE_URL,
        PEER_URL,
        PEER_URL,
    ]
    assert context["claim"].state == "completed"
    assert context["budget"].snapshot()["total_requests"] == 4
    receipt = context["store"].load(context["claim"].contract.receipt_fingerprint)
    assert receipt is not None and receipt.state == COMPLETED
    assert receipt.outcome is not None
    assert receipt.outcome["oracle_verdict"] == "confirmed"
    assert receipt.outcome["finding_authority"] is False


@pytest.mark.asyncio
async def test_target_denial_is_a_refuted_oracle_not_a_finding(tmp_path, monkeypatch):
    context = _context(tmp_path, monkeypatch, target=_Target(attack_denied=True))

    result = await context["adapter"].execute(
        context["proposal"],
        context["source_records"],
        context["peer_records"],
    )

    assert result.status == "completed"
    assert result.legacy_verdict == "DENIED"
    assert result.oracle_evaluation.verdict is OracleVerdict.REFUTED
    assert result.finding_candidate_ref is None
    assert result.requests_sent == 4


@pytest.mark.asyncio
async def test_failed_baseline_is_durable_inconclusive_and_releases_unused_budget(
    tmp_path, monkeypatch
):
    context = _context(tmp_path, monkeypatch, target=_Target(first_status=401))

    result = await context["adapter"].execute(
        context["proposal"],
        context["source_records"],
        context["peer_records"],
    )

    assert result.status == "aborted"
    assert result.oracle_evaluation.verdict is OracleVerdict.INCONCLUSIVE
    assert "backend_sequence_aborted" in result.oracle_evaluation.uncertainty_reasons
    assert result.requests_attempted == result.requests_sent == 1
    assert result.reserved_units_released == 3
    assert context["claim"].state == "completed"
    assert context["claim"].reserved_units == 0
    receipt = context["store"].load(context["claim"].contract.receipt_fingerprint)
    assert receipt is not None and receipt.state == COMPLETED
    assert receipt.outcome is not None
    assert receipt.outcome["oracle_verdict"] == "inconclusive"


@pytest.mark.asyncio
async def test_failed_independent_witness_downgrades_legacy_confirmation(
    tmp_path, monkeypatch
):
    context = _context(tmp_path, monkeypatch, target=_Target(witness_status=500))

    result = await context["adapter"].execute(
        context["proposal"],
        context["source_records"],
        context["peer_records"],
    )

    assert result.legacy_verdict == "BOLA_CONFIRMED"
    assert result.oracle_evaluation.verdict is OracleVerdict.INCONCLUSIVE
    assert "independent_witness_failed" in result.oracle_evaluation.uncertainty_reasons
    assert result.finding_candidate_ref is not None
    assert result.finding_authority is False
    assert result.requests_sent == 4


@pytest.mark.asyncio
async def test_runtime_capture_drift_aborts_before_transport_and_replay_is_denied(
    tmp_path, monkeypatch
):
    context = _context(tmp_path, monkeypatch)
    changed = [{"method": "GET", "url": f"{ORIGIN}/v1/documents/123456789"}]

    with pytest.raises(AdmittedAuthorizationExperimentDenied):
        await context["adapter"].execute(
            context["proposal"],
            changed,
            context["peer_records"],
        )
    assert context["target"].calls == []
    assert context["claim"].state == "aborted"

    with pytest.raises(
        AdmittedAuthorizationExperimentDenied,
        match="already_consumed",
    ):
        await context["adapter"].execute(
            context["proposal"],
            context["source_records"],
            context["peer_records"],
        )


@pytest.mark.asyncio
async def test_changed_ownership_proof_aborts_before_transport(tmp_path, monkeypatch):
    context = _context(tmp_path, monkeypatch)
    context["registry"].register_created_value(
        f"{ORIGIN}/v1/documents",
        PEER_OBJECT,
        actor_persona=context["source"].persona_id,
    )

    with pytest.raises(
        AdmittedAuthorizationExperimentDenied,
        match="owner_proof_changed",
    ):
        await context["adapter"].execute(
            context["proposal"],
            context["source_records"],
            context["peer_records"],
        )
    assert context["target"].calls == []
    assert context["claim"].state == "aborted"


@pytest.mark.asyncio
async def test_execution_policy_digest_drift_aborts_before_transport(
    tmp_path, monkeypatch
):
    context = _context(tmp_path, monkeypatch)
    context["budget"].max_total_requests += 1

    with pytest.raises(
        AdmittedAuthorizationExperimentDenied,
        match="policy_changed",
    ):
        await context["adapter"].execute(
            context["proposal"],
            context["source_records"],
            context["peer_records"],
        )
    assert context["target"].calls == []
    assert context["claim"].state == "aborted"


@pytest.mark.asyncio
async def test_second_adapter_cannot_abort_an_already_owned_runtime_claim(
    tmp_path, monkeypatch
):
    context = _context(tmp_path, monkeypatch)
    claim = context["claim"]
    _, _, runtime_claim_token = claim._runtime_credentials(
        manifest_id=context["manifest"].manifest_id,
        execution_policy_digest=claim.contract.execution_policy_digest,
    )

    with pytest.raises(
        AdmittedAuthorizationExperimentDenied,
        match="claim_is_not_active",
    ):
        await context["adapter"].execute(
            context["proposal"],
            context["source_records"],
            context["peer_records"],
        )

    assert context["target"].calls == []
    assert claim.state == "executing"
    assert claim.reserved_units == 4
    assert claim._abort_runtime(
        runtime_claim_token=runtime_claim_token,
        reason="proof_experiment_test_runtime_owner_cleanup",
    ) == 4
    assert claim.state == "aborted"
