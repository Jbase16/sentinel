"""R5E8 gated PolicyExecutor composition and Foundry consumer proofs."""

from __future__ import annotations

import asyncio
import ast
import json
from pathlib import Path

import pytest

from core.behavior.experiment_admission import (
    experiment_authority_context_ref,
    experiment_ownership_ref,
    experiment_persona_ref,
)
from core.behavior.active import CONTROLLED_WORKFLOW
from core.behavior.experiment_sdk import ExperimentWorldBinding, ExperimentWorldKind
from core.behavior.normalize import stable_hash
from core.behavior.prerequisite_capture_freshness import (
    graph_bound_capture_artifact_ref,
)
from core.behavior.workflow_invariant_binding import (
    WorkflowCaptureProvenance,
    WorkflowInvariantBinding,
)
from core.behavior.workflow_invariant_contract import (
    WorkflowInvariantContract,
    WorkflowOperation,
    WorkflowOwnedFixture,
    WorkflowPrecondition,
    WorkflowState,
)
from core.cortex.execution_policy import ExecutionPolicy, PolicyExecutor
from core.foundry.authorization import create_envelope
from core.foundry.vault import PersonaVault
from core.safety.proof_budget import ProofBudget
from tests.import_contract import find_module_consumers, source_imports_module


ORIGIN = "https://owned.example.test"
WORKFLOW = "behavioral_workflow_effect"


def _module():
    from core.behavior import workflow_invariant_effect_one_click

    return workflow_invariant_effect_one_click


class OwnedTarget:
    def __init__(self, *, secure=False, cleanup="verified"):
        self.secure = secure
        self.cleanup = cleanup
        self.consumed = 0
        self.calls = []
        self.loops = []

    async def send(self, method, url, body=None, **kwargs):
        assert method == "POST"
        assert kwargs.get("_redirect_mode") == "manual"
        self.loops.append(asyncio.get_running_loop())
        self.calls.append((url, dict(body)))
        if body["kind"] == "cleanup":
            if self.cleanup == "exception":
                raise RuntimeError("injected cleanup failure")
            if self.cleanup == "malformed":
                return 200, {"cleanup_verified": "yes"}
            if self.cleanup == "failed":
                return 200, {
                    "specification_id": body["specification_id"],
                    "binding_ref": body["binding_ref"],
                    "cleanup_verified": False,
                    "orphaned_owned_state_possible": True,
                    "consumed": self.consumed,
                    "declared_limit": 10,
                }
            if self.cleanup != "verified_but_dirty":
                self.consumed = body["restore_consumed"]
            return 200, {
                "specification_id": body["specification_id"],
                "binding_ref": body["binding_ref"],
                "cleanup_verified": True,
                "orphaned_owned_state_possible": False,
                "consumed": self.consumed,
                "declared_limit": 10,
            }
        accepted = not self.secure or self.consumed + body["amount"] <= 10
        if accepted:
            self.consumed += body["amount"]
        return 200, {
            "binding_ref": body["binding_ref"],
            "operation_ref": body["operation_ref"],
            "operation_id": body["operation_id"],
            "index": body["index"],
            "status": "accepted" if accepted else "refused",
            "consumed": self.consumed,
            "declared_limit": 10,
        }


class TrackingExecutor(PolicyExecutor):
    def __init__(self, target):
        super().__init__(
            target.send,
            ExecutionPolicy(
                "bounty_safe",
                scope_filter=lambda url: url.startswith(f"{ORIGIN}/"),
                budget=ProofBudget(
                    max_total_requests=4,
                    max_requests_per_endpoint=3,
                    max_cross_object_reads=0,
                    max_privilege_mutations=0,
                    max_creates=0,
                    allow_delete=False,
                    allow_real_user_data_access=False,
                ),
            ),
        )
        self.claims = 0
        self.sends = 0

    def claim_proposal_action(self, action):
        self.claims += 1
        return super().claim_proposal_action(action)

    async def send_claimed_action(self, action, claim, **kwargs):
        self.sends += 1
        return await super().send_claimed_action(action, claim, **kwargs)


def _case(tmp_path, monkeypatch, *, secure=False, amounts=(6, 6), cleanup="verified"):
    module = _module()
    monkeypatch.setenv("SENTINELFORGE_PERSONA_VAULT", str(tmp_path / "personas"))
    monkeypatch.setenv("SENTINELFORGE_AUTHZ_STORE", str(tmp_path / "auth"))
    vault = PersonaVault()
    persona = vault.add_persona(label="workflow-owner", email="owner@research.example")
    envelope = create_envelope(
        researcher_identity="researcher",
        target_handle="owned-workflow",
        authorized_origins=[ORIGIN],
        authorization_basis="controlled owned workflow",
        allowed_workflows=[CONTROLLED_WORKFLOW, WORKFLOW],
        disclosure_attestation=True,
    )
    records = ({"id": "capture", "url": f"{ORIGIN}/state", "method": "GET"},)
    world = ExperimentWorldBinding.build(
        slot="actor",
        kind=ExperimentWorldKind.OWNED_ACCOUNT,
        world_ref=stable_hash("world", persona.persona_id),
        persona_ref=experiment_persona_ref(persona.persona_id),
        ownership_ref=experiment_ownership_ref(envelope, persona.persona_id),
    )
    authority_ref = experiment_authority_context_ref(envelope, ORIGIN, (WORKFLOW,))
    tenant_ref = stable_hash(
        "owned_tenant",
        {"authority_ref": authority_ref, "persona_ref": world.persona_ref},
    )
    tenant_ownership_ref = stable_hash(
        "ownership_proof",
        {
            "attestation_signature": envelope.attestation_signature,
            "tenant_ref": tenant_ref,
        },
    )
    operations = tuple(
        WorkflowOperation(
            operation_ref=stable_hash("workflow_operation", {"index": i}),
            index=i,
            account_ref=world.persona_ref,
            amount=amount,
            precondition=(
                WorkflowPrecondition.PER_OPERATION_AND_AGGREGATE_CAP
                if secure
                else WorkflowPrecondition.PER_OPERATION_CAP
            ),
        )
        for i, amount in enumerate(amounts)
    )
    contract = WorkflowInvariantContract.build(
        workflow_ref=stable_hash("workflow", "owned"),
        account_ref=world.persona_ref,
        tenant_ref=tenant_ref,
        tenant_ownership_ref=tenant_ownership_ref,
        initial_state=WorkflowState(0, 10, 6),
        operations=operations,
        max_operations=len(operations),
    )
    fixture = WorkflowOwnedFixture(contract, world, tenant_ref, tenant_ownership_ref)
    evidence_ref = graph_bound_capture_artifact_ref(
        records, target_origin=ORIGIN, world_id=world.binding_id
    )
    capture = WorkflowCaptureProvenance(
        contract_ref=contract.contract_id,
        world_binding_ref=world.binding_id,
        account_ref=world.persona_ref,
        tenant_ref=tenant_ref,
        tenant_ownership_ref=tenant_ownership_ref,
        origin_ref=stable_hash("behavioral_capture_target", ORIGIN),
        capture_generation_ref=stable_hash("workflow_capture_generation", "current"),
        captured_at_index=10,
        valid_until_index=20,
        operation_ids=tuple(op.operation_id for op in operations),
        source_evidence_refs=(evidence_ref,) * len(operations),
    )
    binding = WorkflowInvariantBinding.build(
        fixture=fixture, capture=capture, target_origin=ORIGIN
    )
    mapping = {
        "schema_version": 1,
        "binding": binding.to_dict(),
        "current_capture": capture.to_dict(),
        "at_index": 10,
        "operation_urls": [f"{ORIGIN}/consume/{i}" for i in range(len(operations))],
        "cleanup_url": f"{ORIGIN}/cleanup",
    }
    specification = module.WorkflowEffectOneClickSpecification.from_mapping(
        mapping, target_origin=ORIGIN
    )
    target = OwnedTarget(secure=secure, cleanup=cleanup)
    executor = TrackingExecutor(target)
    return (
        module,
        specification,
        mapping,
        target,
        executor,
        vault,
        envelope,
        persona,
        records,
    )


def _dispatcher(case, *, enabled):
    module, specification, _, _, executor, vault, envelope, persona, records = case
    return module.WorkflowEffectOneClickDispatcher(
        target_origin=ORIGIN,
        persona_id=persona.persona_id,
        specification=specification,
        authorization=envelope,
        executor=executor,
        persona_vault=vault,
        evidence_records=records,
        config=module.WorkflowEffectExecutionConfig(enabled=enabled),
    )


def test_gate_off_never_constructs_client_or_touches_executor(tmp_path, monkeypatch):
    case = _case(tmp_path, monkeypatch)
    module, specification, _, target, executor, *_ = case
    monkeypatch.delenv(module.WORKFLOW_EFFECT_EXECUTION_ENV, raising=False)
    monkeypatch.setattr(
        module,
        "PolicyExecutorWorkflowEffectClient",
        lambda **_: pytest.fail("client constructed"),
    )
    run = asyncio.run(_dispatcher(case, enabled=False).run())
    assert run == module.WorkflowEffectOneClickRun.disabled(specification)
    assert run.selected and not run.dispatched
    assert run.to_dict()["disabled_gates"] == [module.WORKFLOW_EFFECT_EXECUTION_ENV]
    assert target.calls == [] and executor.claims == executor.sends == 0


def test_origin_escape_refused_before_dispatch(tmp_path, monkeypatch):
    case = _case(tmp_path, monkeypatch)
    module, _, mapping, target, executor, *_ = case
    mapping["operation_urls"][0] = "https://foreign.example.test/consume/0"
    with pytest.raises(ValueError, match="origin"):
        module.WorkflowEffectOneClickSpecification.from_mapping(
            mapping, target_origin=ORIGIN
        )
    assert target.calls == [] and executor.claims == executor.sends == 0


@pytest.mark.parametrize(
    "cleanup", ["malformed", "failed", "exception", "verified_but_dirty"]
)
def test_cleanup_failure_withholds_evidence_and_candidate(
    tmp_path, monkeypatch, cleanup
):
    case = _case(tmp_path, monkeypatch, cleanup=cleanup)
    _, _, _, target, _, *_ = case
    run = asyncio.run(_dispatcher(case, enabled=True).run())
    assert run.result.evidence is None
    assert run.candidate is None
    assert run.to_dict()["finding_authority"] is False
    assert run.to_dict()["promotion_authority"] is False
    assert len([call for call in target.calls if call[1]["kind"] == "cleanup"]) == 1


def test_exactly_one_consumer_audit_rejects_an_extra_import(monkeypatch):
    path = Path(__file__).resolve().parents[2]
    added = path / "core/behavior/workflow_invariant_effect_one_click_extra.py"
    original_rglob, original_read = Path.rglob, Path.read_text

    def with_extra(candidate, pattern):
        yield from original_rglob(candidate, pattern)
        if candidate == path / "core":
            yield added

    def read(candidate, *args, **kwargs):
        if candidate == added:
            return "from core.behavior import workflow_invariant_effect_one_click\n"
        return original_read(candidate, *args, **kwargs)

    monkeypatch.setattr(Path, "rglob", with_extra)
    monkeypatch.setattr(Path, "read_text", read)
    with pytest.raises(AssertionError):
        test_exactly_one_core_consumer_and_no_lab_import()


def test_exactly_one_core_consumer_and_no_lab_import():
    module = _module()
    repository = Path(__file__).resolve().parents[2]
    consumers = sorted(
        path.relative_to(repository).as_posix()
        for path in find_module_consumers(
            (repository / "core").rglob("*.py"),
            "core.behavior.workflow_invariant_effect_one_click",
            repository_root=repository,
            exclude=(Path(module.__file__).resolve(),),
        )
    )
    assert consumers == ["core/server/routers/foundry.py"]
    lab_root = repository.parent / "sentinel-visual-acceptance-lab"
    if lab_root.is_dir():
        assert not [
            path
            for path in lab_root.rglob("*.py")
            if ".venv" not in path.parts
            and any(
                source_imports_module(path.read_text(), name)
                for name in ("core", "sentinelforge")
            )
        ]


@pytest.mark.parametrize(
    "secure,amounts,observed,candidate",
    [
        (False, (6, 6), "effect_observed_violation", True),
        (True, (6, 6), "effect_absent", False),
        (False, (4, 6), "effect_absent", False),
    ],
)
def test_hermetic_twins_and_boundary_have_no_promotion_authority(
    tmp_path, monkeypatch, secure, amounts, observed, candidate
):
    case = _case(tmp_path, monkeypatch, secure=secure, amounts=amounts)
    module, _, _, target, executor, *_ = case

    async def dispatch():
        caller_loop = asyncio.get_running_loop()
        return caller_loop, await _dispatcher(case, enabled=True).run()

    caller_loop, run = asyncio.run(dispatch())
    assert run.dispatched and run.result.evidence is not None
    assert run.result.evidence.oracle_outcome.value == observed
    assert (run.candidate is not None) is candidate
    assert run.result.compensating_cleanup_verified
    assert [body["kind"] for _, body in target.calls] == [
        "operation",
        "operation",
        "cleanup",
    ]
    assert target.consumed == 0
    assert executor.claims == executor.sends == len(target.calls)
    assert all(loop is not caller_loop for loop in target.loops)
    assert len(set(target.loops)) == len(target.calls)
    assert run.to_dict()["finding_authority"] is False
    assert run.to_dict()["promotion_authority"] is False
    assert run.execution_response()["finding"] is None
    assert run.execution_response()["finding_confirmed"] is False
    if candidate:
        assert run.candidate.to_dict()["adversarial_triage_required"] is True
        assert run.candidate.to_dict()["real_workflow_effect_observed"] is False
        assert run.candidate.to_dict()["wired_into_production"] is False
    assert (
        module.WorkflowEffectOneClickRun.from_dict(
            json.loads(json.dumps(run.to_dict()))
        )
        == run
    )


def test_specification_and_disabled_run_round_trip(tmp_path, monkeypatch):
    case = _case(tmp_path, monkeypatch)
    module, spec, *_ = case
    assert (
        module.WorkflowEffectOneClickSpecification.from_dict(
            json.loads(json.dumps(spec.to_dict()))
        )
        == spec
    )
    disabled = module.WorkflowEffectOneClickRun.disabled(spec)
    assert module.WorkflowEffectOneClickRun.from_dict(disabled.to_dict()) == disabled
    with pytest.raises(module.WorkflowEffectOneClickDenied):
        disabled.execution_response()


@pytest.mark.parametrize(
    "path,value",
    [
        (("finding_authority",), True),
        (("promotion_authority",), True),
        (("real_workflow_effect_observed",), True),
        (("wired_into_production",), True),
        (("specification_id",), "workflow_effect_one_click_specification:forged"),
        (("result", "compensating_cleanup_verified"), False),
        (("result", "effect_evidence"), None),
        (("candidate", "finding_authority"), True),
    ],
)
def test_serialized_authority_or_cleanup_tampering_is_refused(
    tmp_path, monkeypatch, path, value
):
    case = _case(tmp_path, monkeypatch)
    module = case[0]
    run = asyncio.run(_dispatcher(case, enabled=True).run())
    payload = json.loads(json.dumps(run.to_dict()))
    field = payload
    for key in path[:-1]:
        field = field[key]
    field[path[-1]] = value
    with pytest.raises((TypeError, ValueError)):
        module.WorkflowEffectOneClickRun.from_dict(payload)


def test_real_client_does_not_read_model_channel(tmp_path, monkeypatch):
    case = _case(tmp_path, monkeypatch)
    module, spec, _, target, executor, *_ = case
    client = module.PolicyExecutorWorkflowEffectClient(
        executor=executor, specification=spec, persona_id=case[7].persona_id
    )
    operation = spec.binding.fixture.contract.operations[0]

    def forbidden(*args, **kwargs):
        pytest.fail("client consulted a modeled transition")

    from core.behavior import workflow_invariant_contract as contract_module
    from core.behavior import workflow_invariant_ledger as ledger_module

    for owner, names in (
        (
            contract_module,
            ("classify_sequence", "evaluate_invariant", "transition_state"),
        ),
        (
            ledger_module,
            ("classify_sequence", "evaluate_operation", "transition_state"),
        ),
    ):
        for name in names:
            monkeypatch.setattr(owner, name, forbidden)
    response = client.issue(
        {
            "mode": module.WORKFLOW_EFFECT_EXECUTION_MODE,
            "kind": "operation",
            "method": "POST",
            "url": spec.transport_spec.operation_urls[0],
            "specification_id": spec.transport_spec.specification_id,
            "binding_ref": spec.binding.binding_id,
            "operation_ref": operation.operation_ref,
            "operation_id": operation.operation_id,
            "index": 0,
            "amount": operation.amount,
        }
    )
    assert response["consumed"] == 6
    assert len(target.calls) == 1


def test_direct_client_call_on_server_loop_is_refused_before_claim(
    tmp_path, monkeypatch
):
    case = _case(tmp_path, monkeypatch)
    module, spec, _, target, executor, *_ = case
    client = module.PolicyExecutorWorkflowEffectClient(
        executor=executor, specification=spec, persona_id=case[7].persona_id
    )

    async def misuse():
        with pytest.raises(module.WorkflowEffectOneClickDenied):
            client.issue({})

    asyncio.run(misuse())
    assert executor.claims == executor.sends == 0
    assert target.calls == []


def test_cancellation_waits_for_worker_cleanup(tmp_path, monkeypatch):
    from threading import Event

    case = _case(tmp_path, monkeypatch)
    target, executor = case[3], case[4]
    started = Event()
    original_send = executor.raw_send

    async def delayed_send(method, url, body=None, **kwargs):
        if body["kind"] == "operation" and body["index"] == 0:
            started.set()
            await asyncio.sleep(0.05)
        return await original_send(method, url, body, **kwargs)

    executor.raw_send = delayed_send

    async def drive():
        task = asyncio.create_task(_dispatcher(case, enabled=True).run())
        assert await asyncio.to_thread(started.wait, 2)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(drive())
    assert [body["kind"] for _, body in target.calls] == [
        "operation",
        "operation",
        "cleanup",
    ]
    assert target.consumed == 0


def test_module_transport_safety_and_exact_exports():
    module = _module()
    source = Path(module.__file__).read_text()
    tree = ast.parse(source)
    imported = {
        alias.name.split(".", 1)[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {
        (node.module or "").split(".", 1)[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
    }
    assert not {"httpx", "requests", "socket", "subprocess", "urllib3"} & imported
    assert "PolicyExecutor" in source
    assert ".claim_proposal_action(" in source
    assert ".send_claimed_action(" in source
    assert "capability_effect_promotion" not in source
    assert module.__all__ == [
        "WORKFLOW_EFFECT_ONE_CLICK_MODE",
        "PolicyExecutorWorkflowEffectClient",
        "WorkflowEffectOneClickSpecification",
        "WorkflowEffectOneClickDispatcher",
        "WorkflowEffectOneClickRun",
        "WorkflowEffectFindingCandidate",
        "WorkflowEffectOneClickDenied",
    ]


def test_foundry_gate_off_is_inert(tmp_path, monkeypatch):
    case = _case(tmp_path, monkeypatch)
    module, _, mapping, target, _, vault, envelope, persona, records = case
    peer = vault.add_persona(label="peer", email="peer@research.example")
    from core.server.routers.foundry import (
        RunBehavioralAuthorizationRequest,
        run_behavioral_authorization_endpoint,
    )
    from core.wraith.bola_replay import SNDReplayTransport

    request = RunBehavioralAuthorizationRequest(
        target_origin=ORIGIN,
        envelope_id=envelope.envelope_id,
        source_persona_id=persona.persona_id,
        peer_persona_id=peer.persona_id,
        source_records=list(records),
        peer_records=[{"id": "peer-capture", "url": f"{ORIGIN}/peer", "method": "GET"}],
        workflow_effect=mapping,
    )
    monkeypatch.delenv(module.WORKFLOW_EFFECT_EXECUTION_ENV, raising=False)

    async def forbidden(*args, **kwargs):
        pytest.fail("gate-off Foundry path reached target transport")

    monkeypatch.setattr(SNDReplayTransport, "send", forbidden)
    monkeypatch.setattr(
        module,
        "PolicyExecutorWorkflowEffectClient",
        lambda **_: pytest.fail("client constructed"),
    )
    response = asyncio.run(run_behavioral_authorization_endpoint(request, _=True))
    selected = response["workflow_invariant_effect_one_click"]
    assert response["status"] == "no_executable_candidate"
    assert selected["status"] == "selected_execution_disabled"
    assert selected["disabled_gates"] == [module.WORKFLOW_EFFECT_EXECUTION_ENV]
    assert target.calls == []


def test_foundry_enabled_path_dispatches_only_through_fake_policy_executor(
    tmp_path, monkeypatch
):
    case = _case(tmp_path, monkeypatch)
    module, _, mapping, target, _, vault, envelope, persona, records = case
    peer = vault.add_persona(label="peer", email="peer@research.example")
    from core.server.routers.foundry import (
        RunBehavioralAuthorizationRequest,
        run_behavioral_authorization_endpoint,
    )
    from core.wraith.bola_replay import ReplayResponse, SNDReplayTransport

    request = RunBehavioralAuthorizationRequest(
        target_origin=ORIGIN,
        envelope_id=envelope.envelope_id,
        source_persona_id=persona.persona_id,
        peer_persona_id=peer.persona_id,
        source_records=list(records),
        peer_records=[{"id": "peer-capture", "url": f"{ORIGIN}/peer", "method": "GET"}],
        workflow_effect=mapping,
    )
    monkeypatch.setenv("SENTINELFORGE_BEHAVIOR_PRIMARY", "1")
    monkeypatch.setenv(module.WORKFLOW_EFFECT_EXECUTION_ENV, "1")

    async def fake_send(_transport, persona_id, replay_request):
        assert persona_id == persona.persona_id
        body = json.loads(replay_request.body)
        status, response = await target.send(
            replay_request.method,
            replay_request.url,
            body,
            _redirect_mode=replay_request.redirect_mode,
        )
        return ReplayResponse(status, json.dumps(response))

    monkeypatch.setattr(SNDReplayTransport, "send", fake_send)
    response = asyncio.run(run_behavioral_authorization_endpoint(request, _=True))
    assert response["kind"] == "workflow_invariant_effect_one_click"
    assert response["finding"] is None
    assert response["finding_confirmed"] is False
    assert response["promotion_authority"] is False
    assert response["workflow_invariant_effect_one_click"]["candidate"] is not None
    assert [body["kind"] for _, body in target.calls] == [
        "operation",
        "operation",
        "cleanup",
    ]


def test_scan_profile_and_ordinary_click_pass_through_workflow_effect(
    tmp_path, monkeypatch
):
    case = _case(tmp_path, monkeypatch)
    _, _, mapping, _, _, vault, envelope, persona, _ = case
    peer = vault.add_persona(label="peer", email="peer@research.example")
    from core.server.ordinary_orchestration import (
        OrdinaryClickFamily,
        _applicable,
        _request_for_family,
    )
    from core.server.routers.foundry import RunBehavioralAuthorizationFromURLRequest
    from core.server.routers.scans import BehavioralOneClickProfile

    profile = BehavioralOneClickProfile(
        mode="workflow_effect",
        completion="behavioral_phase_only",
        envelope_id=envelope.envelope_id,
        source_persona_id=persona.persona_id,
        peer_persona_id=peer.persona_id,
        workflow_effect=mapping,
    )
    assert profile.workflow_effect == mapping
    with pytest.raises(ValueError):
        BehavioralOneClickProfile(
            mode="workflow_effect",
            completion="continue_scan",
            envelope_id=envelope.envelope_id,
            source_persona_id=persona.persona_id,
            peer_persona_id=peer.persona_id,
            workflow_effect=mapping,
        )
    request = RunBehavioralAuthorizationFromURLRequest(
        target_url=f"{ORIGIN}/app",
        envelope_id=envelope.envelope_id,
        source_persona_id=persona.persona_id,
        peer_persona_id=peer.persona_id,
        workflow_effect=mapping,
    )
    assert _applicable(request, OrdinaryClickFamily.D)
    delegated = _request_for_family(
        request, OrdinaryClickFamily.D, assessment_session_id="session"
    )
    assert delegated.workflow_effect == mapping
    assert delegated.capability_effect is None


def test_from_url_gate_off_returns_before_capture(tmp_path, monkeypatch):
    case = _case(tmp_path, monkeypatch)
    module, _, mapping, _, _, vault, envelope, persona, _ = case
    peer = vault.add_persona(label="peer", email="peer@research.example")
    from core.server.routers import driver as driver_module
    from core.server.routers.foundry import (
        RunBehavioralAuthorizationFromURLRequest,
        run_behavioral_authorization_from_url_endpoint,
    )

    request = RunBehavioralAuthorizationFromURLRequest(
        target_url=f"{ORIGIN}/app",
        envelope_id=envelope.envelope_id,
        source_persona_id=persona.persona_id,
        peer_persona_id=peer.persona_id,
        workflow_effect=mapping,
    )
    monkeypatch.setenv("SENTINELFORGE_BEHAVIOR_PRIMARY", "1")
    monkeypatch.delenv(module.WORKFLOW_EFFECT_EXECUTION_ENV, raising=False)

    async def forbidden(*args, **kwargs):
        pytest.fail("gate-off URL path reached browser capture")

    monkeypatch.setattr(driver_module, "capture_persona_pair", forbidden)
    response = asyncio.run(
        run_behavioral_authorization_from_url_endpoint(request, _=True)
    )
    assert response["status"] == "no_executable_candidate"
    assert response["workflow_invariant_effect_one_click"]["status"] == (
        "selected_execution_disabled"
    )


def test_from_url_enabled_reaches_inner_foundry_with_hermetic_capture(
    tmp_path, monkeypatch
):
    case = _case(tmp_path, monkeypatch)
    module, _, mapping, target, _, vault, envelope, persona, records = case
    peer = vault.add_persona(label="peer", email="peer@research.example")
    peer_records = ({"id": "peer-capture", "url": f"{ORIGIN}/peer", "method": "GET"},)
    from core.server.routers import driver
    from core.server.routers.foundry import (
        RunBehavioralAuthorizationFromURLRequest,
        run_behavioral_authorization_from_url_endpoint,
    )
    from core.wraith.bola_replay import ReplayResponse, SNDReplayTransport

    request = RunBehavioralAuthorizationFromURLRequest(
        target_url=f"{ORIGIN}/app",
        envelope_id=envelope.envelope_id,
        source_persona_id=persona.persona_id,
        peer_persona_id=peer.persona_id,
        workflow_effect=mapping,
    )
    monkeypatch.setenv("SENTINELFORGE_BEHAVIOR_PRIMARY", "1")
    monkeypatch.setenv(module.WORKFLOW_EFFECT_EXECUTION_ENV, "1")
    captures = []

    async def capture_pair(**kwargs):
        captures.append(kwargs)
        return (
            driver.PersonaCaptureArtifact(
                persona_id=persona.persona_id,
                path="/private/workflow-source.jsonl",
                records=records,
                captured_bytes=10,
                limit_reached=False,
                page_url=f"{ORIGIN}/app",
            ),
            driver.PersonaCaptureArtifact(
                persona_id=peer.persona_id,
                path="/private/workflow-peer.jsonl",
                records=peer_records,
                captured_bytes=10,
                limit_reached=False,
                page_url=f"{ORIGIN}/app",
            ),
            (),
        )

    async def fake_send(_transport, persona_id, replay_request):
        assert persona_id == persona.persona_id
        status, response = await target.send(
            replay_request.method,
            replay_request.url,
            json.loads(replay_request.body),
            _redirect_mode=replay_request.redirect_mode,
        )
        return ReplayResponse(status, json.dumps(response))

    async def validate_windows(persona_ids):
        assert tuple(persona_ids) == (persona.persona_id, peer.persona_id)

    monkeypatch.setattr(driver, "capture_persona_pair", capture_pair)
    monkeypatch.setattr(driver, "validate_persona_windows", validate_windows)
    monkeypatch.setattr(SNDReplayTransport, "send", fake_send)
    response = asyncio.run(
        run_behavioral_authorization_from_url_endpoint(request, _=True)
    )
    assert len(captures) == 1
    assert response["kind"] == "workflow_invariant_effect_one_click"
    assert response["finding"] is None
    assert response["workflow_invariant_effect_one_click"]["candidate"] is not None
    assert [body["kind"] for _, body in target.calls] == [
        "operation",
        "operation",
        "cleanup",
    ]
