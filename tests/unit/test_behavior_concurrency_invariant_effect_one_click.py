"""R5F8 gated PolicyExecutor composition and Foundry consumer proofs."""

from __future__ import annotations

import asyncio
import ast
import json
from pathlib import Path

import pytest
from fastapi import HTTPException

from core.behavior.active import CONTROLLED_WORKFLOW
from core.behavior.concurrency_invariant_binding import (
    ConcurrencyCaptureProvenance,
    ConcurrencyInvariantBinding,
)
from core.behavior.concurrency_invariant_contract import (
    ConcurrencyGuardMode,
    ConcurrencyInvariantContract,
    ConcurrencyOperation,
    ConcurrencyOwnedFixture,
    MicroStep,
    SharedWorkflowState,
    StepKind,
    WorkflowSchedule,
)
from core.behavior.experiment_admission import experiment_persona_ref
from core.behavior.experiment_sdk import ExperimentWorldBinding, ExperimentWorldKind
from core.behavior.normalize import stable_hash
from core.cortex.execution_policy import ExecutionPolicy, PolicyExecutor
from core.foundry.authorization import create_envelope
from core.foundry.vault import PersonaVault
from core.safety.proof_budget import ProofBudget
from tests.import_contract import find_module_consumers
from tests.unit.test_behavior_concurrency_invariant_effect_transport import (
    ORIGIN,
    OwnedTargetClient,
)

WORKFLOW = "behavioral_concurrency_effect"
KINDS = ["observe", "observe", "commit", "commit", "cleanup"]


def _module():
    from core.behavior import concurrency_invariant_effect_one_click

    return concurrency_invariant_effect_one_click


class OwnedTarget:
    def __init__(self, contract, *, cleanup="verified"):
        self.client = OwnedTargetClient(contract, cleanup_reply=cleanup)
        self.loops = []

    @property
    def calls(self):
        return self.client.requests

    @property
    def consumed(self):
        return self.client.consumed

    async def send(self, method, url, body=None, **kwargs):
        assert method == "POST"
        assert kwargs.get("_redirect_mode") == "manual"
        self.loops.append(asyncio.get_running_loop())
        request = {"method": method, "url": url, **dict(body)}
        return 200, self.client.issue(request)


class TrackingExecutor(PolicyExecutor):
    def __init__(self, target, *, limit):
        super().__init__(
            target.send,
            ExecutionPolicy(
                "bounty_safe",
                scope_filter=lambda url: url.startswith(f"{ORIGIN}/"),
                budget=ProofBudget(
                    max_total_requests=limit,
                    max_requests_per_endpoint=limit,
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


def _case(tmp_path, monkeypatch, *, secure=False, limit=1, budget=5, cleanup="verified"):
    module = _module()
    monkeypatch.setenv("SENTINELFORGE_PERSONA_VAULT", str(tmp_path / "personas"))
    monkeypatch.setenv("SENTINELFORGE_AUTHZ_STORE", str(tmp_path / "auth"))
    vault = PersonaVault()
    source = vault.add_persona(label="source", email="source@research.example")
    peer = vault.add_persona(label="peer", email="peer@research.example")
    envelope = create_envelope(
        researcher_identity="researcher",
        target_handle="owned-concurrency",
        authorized_origins=[ORIGIN],
        authorization_basis="controlled owned concurrency",
        allowed_workflows=[CONTROLLED_WORKFLOW, WORKFLOW],
        disclosure_attestation=True,
    )
    ownership = stable_hash("ownership_proof", "concurrency")
    tenant = stable_hash("owned_tenant", "concurrency")
    worlds = tuple(
        ExperimentWorldBinding.build(
            slot=f"actor_{label}",
            kind=ExperimentWorldKind.OWNED_ACCOUNT,
            world_ref=stable_hash("world", persona.persona_id),
            persona_ref=experiment_persona_ref(persona.persona_id),
            ownership_ref=ownership,
        )
        for label, persona in zip(("a", "b"), (source, peer))
    )
    operations = tuple(
        ConcurrencyOperation(
            operation_ref=stable_hash("concurrency_operation", persona.persona_id),
            actor_ref=world.persona_ref,
            op_index=0,
            amount=1,
            guard_mode=(
                ConcurrencyGuardMode.COMMIT_TIME_CAS
                if secure
                else ConcurrencyGuardMode.OBSERVE_TIME_ONLY
            ),
        )
        for world, persona in zip(worlds, (source, peer))
    )
    contract = ConcurrencyInvariantContract.build(
        resource_ref=stable_hash("owned_resource", "shared-cap"),
        tenant_ref=tenant,
        tenant_ownership_ref=ownership,
        initial_state=SharedWorkflowState(0, limit, 1),
        operations=operations,
        max_actors=2,
    )
    fixture = ConcurrencyOwnedFixture(contract, worlds, tenant, ownership)
    schedule = WorkflowSchedule(
        contract,
        (
            MicroStep(worlds[0].persona_ref, operations[0].operation_ref, StepKind.OBSERVE),
            MicroStep(worlds[1].persona_ref, operations[1].operation_ref, StepKind.OBSERVE),
            MicroStep(worlds[0].persona_ref, operations[0].operation_ref, StepKind.COMMIT),
            MicroStep(worlds[1].persona_ref, operations[1].operation_ref, StepKind.COMMIT),
        ),
    )
    capture = ConcurrencyCaptureProvenance(
        contract_ref=contract.contract_id,
        world_binding_refs=tuple(world.binding_id for world in worlds),
        actor_refs=tuple(world.persona_ref for world in worlds),
        resource_ref=contract.resource_ref,
        tenant_ref=tenant,
        tenant_ownership_ref=ownership,
        capture_generation_ref=stable_hash("concurrency_capture_generation", "current"),
        captured_at_index=10,
        valid_until_index=20,
        operation_ids=tuple(op.operation_id for op in operations),
        source_evidence_refs=tuple(
            stable_hash("source_evidence", i) for i in range(len(operations))
        ),
    )
    binding = ConcurrencyInvariantBinding.build(fixture=fixture, capture=capture)
    records = ({"id": "capture", "url": f"{ORIGIN}/state", "method": "GET"},)
    mapping = {
        "schema_version": 1,
        "binding": binding.to_dict(),
        "current_capture": capture.to_dict(),
        "schedule": schedule.to_dict(),
        "at_index": 10,
        "operation_urls": [f"{ORIGIN}/consume/{i}" for i in range(len(operations))],
        "cleanup_url": f"{ORIGIN}/cleanup",
    }
    specification = module.ConcurrencyEffectOneClickSpecification.from_mapping(
        mapping, target_origin=ORIGIN
    )
    target = OwnedTarget(contract, cleanup=cleanup)
    executor = TrackingExecutor(target, limit=budget)
    return module, specification, mapping, target, executor, vault, envelope, source, peer, records


def _dispatcher(case, *, enabled):
    module, specification, _, _, executor, vault, envelope, source, _, records = case
    return module.ConcurrencyEffectOneClickDispatcher(
        target_origin=ORIGIN,
        persona_id=source.persona_id,
        specification=specification,
        authorization=envelope,
        executor=executor,
        persona_vault=vault,
        evidence_records=records,
        config=module.ConcurrencyEffectExecutionConfig(enabled=enabled),
    )


def _assert_no_authority(value):
    assert value["owned_target_origin_bound"] is False
    assert value["finding_authority"] is False
    assert value["promotion_authority"] is False
    assert value["real_concurrency_effect_observed"] is False
    assert value["wired_into_production"] is False


def test_gate_off_is_inert(tmp_path, monkeypatch):
    case = _case(tmp_path, monkeypatch)
    module, spec, _, target, executor, *_ = case
    monkeypatch.setattr(
        module,
        "PolicyExecutorConcurrencyEffectClient",
        lambda **_: pytest.fail("client constructed"),
    )
    run = asyncio.run(_dispatcher(case, enabled=False).run())
    assert run == module.ConcurrencyEffectOneClickRun.disabled(spec)
    assert run.selected and not run.dispatched
    assert run.status == "selected_execution_disabled"
    assert run.to_dict()["disabled_gates"] == [module.CONCURRENCY_EFFECT_EXECUTION_ENV]
    _assert_no_authority(run.to_dict())
    assert target.calls == [] and executor.claims == executor.sends == 0


@pytest.mark.parametrize("secure,candidate", [(False, True), (True, False)])
def test_twins_dispatch_all_steps_and_verified_cleanup(tmp_path, monkeypatch, secure, candidate):
    case = _case(tmp_path, monkeypatch, secure=secure)
    module, _, _, target, executor, *_ = case

    async def dispatch():
        caller_loop = asyncio.get_running_loop()
        return caller_loop, await _dispatcher(case, enabled=True).run()

    caller_loop, run = asyncio.run(dispatch())
    assert run.status == "completed" and run.dispatched
    assert run.result.admitted and run.result.compensating_cleanup_verified
    assert run.result.evidence is not None
    assert (run.candidate is not None) is candidate
    assert run.result.evidence.oracle_outcome.value == (
        "effect_observed_violation" if candidate else "effect_absent"
    )
    assert [call["kind"] for call in target.calls] == KINDS
    assert target.consumed == 0
    assert executor.claims == executor.sends == 5
    assert all(loop is not caller_loop for loop in target.loops)
    assert len(set(target.loops)) == 5
    response = run.execution_response()
    assert response["kind"] == "concurrency_invariant_effect_one_click"
    assert response["finding"] is None and response["finding_confirmed"] is False
    _assert_no_authority(run.to_dict())
    _assert_no_authority(run.result.to_dict())
    _assert_no_authority(response)
    if candidate:
        _assert_no_authority(run.candidate.to_dict())
        assert run.candidate.to_dict()["adversarial_triage_required"] is True
    assert module.ConcurrencyEffectOneClickRun.from_dict(
        json.loads(json.dumps(run.to_dict()))
    ) == run


@pytest.mark.parametrize("secure", [False, True])
def test_two_n_plus_one_budget_admits_full_twin_but_two_n_does_not(
    tmp_path, monkeypatch, secure
):
    admitted = _case(tmp_path / "full", monkeypatch, secure=secure, budget=5)
    run = asyncio.run(_dispatcher(admitted, enabled=True).run())
    assert run.result.compensating_cleanup_verified
    assert len(admitted[3].calls) == 5
    throttled = _case(tmp_path / "short", monkeypatch, secure=secure, budget=4)
    short_run = asyncio.run(_dispatcher(throttled, enabled=True).run())
    assert not short_run.result.compensating_cleanup_verified
    assert short_run.result.evidence is None
    assert len(throttled[3].calls) == 4


@pytest.mark.parametrize("cleanup", ["malformed", "failed", "exception", "verified_but_dirty"])
def test_cleanup_failure_withholds_evidence(tmp_path, monkeypatch, cleanup):
    case = _case(tmp_path, monkeypatch, cleanup=cleanup)
    run = asyncio.run(_dispatcher(case, enabled=True).run())
    assert run.result.cleanup_attempts == 1
    assert not run.result.compensating_cleanup_verified
    assert run.result.evidence is None and run.candidate is None
    _assert_no_authority(run.to_dict())


def test_specification_schedule_round_trip_and_escape_refusal(tmp_path, monkeypatch):
    case = _case(tmp_path, monkeypatch)
    module, spec, mapping, target, executor, *_ = case
    assert module.ConcurrencyEffectOneClickSpecification.from_dict(
        json.loads(json.dumps(spec.to_dict()))
    ) == spec
    forged = json.loads(json.dumps(spec.to_dict()))
    forged["owned_target_origin_bound"] = True
    with pytest.raises(ValueError):
        module.ConcurrencyEffectOneClickSpecification.from_dict(forged)
    disabled = module.ConcurrencyEffectOneClickRun.disabled(spec)
    assert module.ConcurrencyEffectOneClickRun.from_dict(disabled.to_dict()) == disabled
    with pytest.raises(module.ConcurrencyEffectOneClickDenied):
        disabled.execution_response()
    mapping["schedule"]["steps"][0]["operation_ref"] = stable_hash(
        "concurrency_operation", "foreign"
    )
    with pytest.raises(ValueError):
        module.ConcurrencyEffectOneClickSpecification.from_mapping(
            mapping, target_origin=ORIGIN
        )
    assert target.calls == [] and executor.claims == executor.sends == 0


def test_origin_escape_and_paired_identity_mismatch_refused(tmp_path, monkeypatch):
    case = _case(tmp_path, monkeypatch)
    module, spec, mapping, target, executor, vault, envelope, source, peer, records = case
    mapping["operation_urls"][0] = "https://foreign.example.test/consume/0"
    with pytest.raises(ValueError, match="origin"):
        module.ConcurrencyEffectOneClickSpecification.from_mapping(
            mapping, target_origin=ORIGIN
        )
    with pytest.raises(module.ConcurrencyEffectOneClickDenied):
        module.ConcurrencyEffectOneClickDispatcher(
            target_origin=ORIGIN,
            persona_id=peer.persona_id,
            specification=spec,
            authorization=envelope,
            executor=executor,
            persona_vault=vault,
            evidence_records=records,
            config=module.ConcurrencyEffectExecutionConfig(enabled=True),
        )
    assert target.calls == [] and executor.claims == executor.sends == 0


@pytest.mark.parametrize(
    "path,value",
    [
        (("finding_authority",), True),
        (("promotion_authority",), True),
        (("real_concurrency_effect_observed",), True),
        (("wired_into_production",), True),
        (("owned_target_origin_bound",), True),
        (("result", "owned_target_origin_bound"), True),
        (("candidate", "owned_target_origin_bound"), True),
        (("result", "compensating_cleanup_verified"), False),
        (("result", "effect_evidence"), None),
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
        module.ConcurrencyEffectOneClickRun.from_dict(payload)


def test_direct_client_call_on_running_loop_is_refused(tmp_path, monkeypatch):
    case = _case(tmp_path, monkeypatch)
    module, spec, _, target, executor, _, _, source, _, _ = case
    client = module.PolicyExecutorConcurrencyEffectClient(
        executor=executor, specification=spec, persona_id=source.persona_id
    )

    async def misuse():
        with pytest.raises(module.ConcurrencyEffectOneClickDenied):
            client.issue({})

    asyncio.run(misuse())
    assert executor.claims == executor.sends == 0 and target.calls == []


def test_module_safety_and_exact_core_consumer():
    module = _module()
    repository = Path(__file__).resolve().parents[2]
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
    assert ".claim_proposal_action(" in source and ".send_claimed_action(" in source
    consumers = sorted(
        path.relative_to(repository).as_posix()
        for path in find_module_consumers(
            (repository / "core").rglob("*.py"),
            "core.behavior.concurrency_invariant_effect_one_click",
            repository_root=repository,
            exclude=(Path(module.__file__).resolve(),),
        )
    )
    assert consumers == ["core/server/routers/foundry.py"]
    assert module.__all__ == [
        "CONCURRENCY_EFFECT_ONE_CLICK_MODE",
        "PolicyExecutorConcurrencyEffectClient",
        "ConcurrencyEffectOneClickSpecification",
        "ConcurrencyEffectOneClickDispatcher",
        "ConcurrencyEffectOneClickRun",
        "ConcurrencyEffectFindingCandidate",
        "ConcurrencyEffectOneClickDenied",
    ]


def test_scan_and_ordinary_click_pass_through(tmp_path, monkeypatch):
    case = _case(tmp_path, monkeypatch)
    _, _, mapping, _, _, _, envelope, source, peer, _ = case
    from core.server.ordinary_orchestration import (
        OrdinaryClickFamily,
        _applicable,
        _request_for_family,
    )
    from core.server.routers.foundry import RunBehavioralAuthorizationFromURLRequest
    from core.server.routers.scans import BehavioralOneClickProfile

    profile = BehavioralOneClickProfile(
        mode="concurrency_effect",
        completion="behavioral_phase_only",
        envelope_id=envelope.envelope_id,
        source_persona_id=source.persona_id,
        peer_persona_id=peer.persona_id,
        concurrency_effect=mapping,
    )
    assert profile.concurrency_effect == mapping
    with pytest.raises(ValueError, match="mutually exclusive"):
        BehavioralOneClickProfile(
            mode="concurrency_effect",
            completion="behavioral_phase_only",
            envelope_id=envelope.envelope_id,
            source_persona_id=source.persona_id,
            peer_persona_id=peer.persona_id,
            concurrency_effect=mapping,
            workflow_effect=mapping,
        )
    with pytest.raises(ValueError):
        BehavioralOneClickProfile(
            mode="concurrency_effect",
            completion="continue_scan",
            envelope_id=envelope.envelope_id,
            source_persona_id=source.persona_id,
            peer_persona_id=peer.persona_id,
            concurrency_effect=mapping,
        )
    request = RunBehavioralAuthorizationFromURLRequest(
        target_url=f"{ORIGIN}/app",
        envelope_id=envelope.envelope_id,
        source_persona_id=source.persona_id,
        peer_persona_id=peer.persona_id,
        concurrency_effect=mapping,
    )
    assert _applicable(request, OrdinaryClickFamily.D)
    delegated = _request_for_family(
        request, OrdinaryClickFamily.D, assessment_session_id="session"
    )
    assert delegated.concurrency_effect == mapping


def test_foundry_gate_off_is_inert(tmp_path, monkeypatch):
    case = _case(tmp_path, monkeypatch)
    module, _, mapping, target, _, _, envelope, source, peer, records = case
    from core.server.routers.foundry import (
        RunBehavioralAuthorizationRequest,
        run_behavioral_authorization_endpoint,
    )
    from core.wraith.bola_replay import SNDReplayTransport

    request = RunBehavioralAuthorizationRequest(
        target_origin=ORIGIN,
        envelope_id=envelope.envelope_id,
        source_persona_id=source.persona_id,
        peer_persona_id=peer.persona_id,
        source_records=list(records),
        peer_records=[{"id": "peer-capture", "url": f"{ORIGIN}/peer", "method": "GET"}],
        concurrency_effect=mapping,
    )
    monkeypatch.delenv(module.CONCURRENCY_EFFECT_EXECUTION_ENV, raising=False)

    async def forbidden(*args, **kwargs):
        pytest.fail("gate-off Foundry path reached target transport")

    monkeypatch.setattr(SNDReplayTransport, "send", forbidden)
    response = asyncio.run(run_behavioral_authorization_endpoint(request, _=True))
    selected = response["concurrency_invariant_effect_one_click"]
    assert response["status"] == "no_executable_candidate"
    assert selected["status"] == "selected_execution_disabled"
    _assert_no_authority(selected)
    assert target.calls == []


def test_foundry_enabled_path_uses_full_five_request_budget(tmp_path, monkeypatch):
    case = _case(tmp_path, monkeypatch)
    module, _, mapping, target, _, _, envelope, source, peer, records = case
    from core.server.routers.foundry import (
        RunBehavioralAuthorizationRequest,
        run_behavioral_authorization_endpoint,
    )
    from core.wraith.bola_replay import ReplayResponse, SNDReplayTransport

    request = RunBehavioralAuthorizationRequest(
        target_origin=ORIGIN,
        envelope_id=envelope.envelope_id,
        source_persona_id=source.persona_id,
        peer_persona_id=peer.persona_id,
        source_records=list(records),
        peer_records=[{"id": "peer-capture", "url": f"{ORIGIN}/peer", "method": "GET"}],
        concurrency_effect=mapping,
    )
    monkeypatch.setenv("SENTINELFORGE_BEHAVIOR_PRIMARY", "1")
    monkeypatch.setenv(module.CONCURRENCY_EFFECT_EXECUTION_ENV, "1")

    async def fake_send(_transport, persona_id, replay_request):
        assert persona_id == source.persona_id
        status, body = await target.send(
            replay_request.method,
            replay_request.url,
            json.loads(replay_request.body),
            _redirect_mode=replay_request.redirect_mode,
        )
        return ReplayResponse(status, json.dumps(body))

    monkeypatch.setattr(SNDReplayTransport, "send", fake_send)
    response = asyncio.run(run_behavioral_authorization_endpoint(request, _=True))
    assert response["kind"] == "concurrency_invariant_effect_one_click"
    assert response["finding"] is None and response["finding_confirmed"] is False
    selected = response["concurrency_invariant_effect_one_click"]
    assert selected["candidate"] is not None
    _assert_no_authority(selected)
    assert [call["kind"] for call in target.calls] == KINDS


def test_from_url_gate_off_returns_before_capture(tmp_path, monkeypatch):
    case = _case(tmp_path, monkeypatch)
    module, _, mapping, _, _, _, envelope, source, peer, _ = case
    from core.server.routers import driver
    from core.server.routers.foundry import (
        RunBehavioralAuthorizationFromURLRequest,
        run_behavioral_authorization_from_url_endpoint,
    )

    request = RunBehavioralAuthorizationFromURLRequest(
        target_url=f"{ORIGIN}/app",
        envelope_id=envelope.envelope_id,
        source_persona_id=source.persona_id,
        peer_persona_id=peer.persona_id,
        concurrency_effect=mapping,
    )
    monkeypatch.setenv("SENTINELFORGE_BEHAVIOR_PRIMARY", "1")
    monkeypatch.delenv(module.CONCURRENCY_EFFECT_EXECUTION_ENV, raising=False)

    async def forbidden(*args, **kwargs):
        pytest.fail("gate-off URL path reached browser capture")

    monkeypatch.setattr(driver, "capture_persona_pair", forbidden)
    response = asyncio.run(run_behavioral_authorization_from_url_endpoint(request, _=True))
    assert response["status"] == "no_executable_candidate"
    selected = response["concurrency_invariant_effect_one_click"]
    assert selected["status"] == "selected_execution_disabled"
    _assert_no_authority(selected)


@pytest.mark.parametrize("from_url", [False, True])
def test_foundry_rejects_selected_pair_mismatch_before_traffic(
    tmp_path, monkeypatch, from_url
):
    case = _case(tmp_path, monkeypatch)
    module, _, mapping, target, _, _, envelope, source, peer, records = case
    from core.server.routers import driver
    from core.server.routers.foundry import (
        RunBehavioralAuthorizationFromURLRequest,
        RunBehavioralAuthorizationRequest,
        run_behavioral_authorization_endpoint,
        run_behavioral_authorization_from_url_endpoint,
    )

    monkeypatch.setenv("SENTINELFORGE_BEHAVIOR_PRIMARY", "1")
    monkeypatch.setenv(module.CONCURRENCY_EFFECT_EXECUTION_ENV, "1")

    async def forbidden(*args, **kwargs):
        pytest.fail("mismatched pair reached capture")

    monkeypatch.setattr(driver, "capture_persona_pair", forbidden)
    if from_url:
        request = RunBehavioralAuthorizationFromURLRequest(
            target_url=f"{ORIGIN}/app",
            envelope_id=envelope.envelope_id,
            source_persona_id=peer.persona_id,
            peer_persona_id=source.persona_id,
            concurrency_effect=mapping,
        )
        run = run_behavioral_authorization_from_url_endpoint
    else:
        request = RunBehavioralAuthorizationRequest(
            target_origin=ORIGIN,
            envelope_id=envelope.envelope_id,
            source_persona_id=peer.persona_id,
            peer_persona_id=source.persona_id,
            source_records=list(records),
            peer_records=[{"id": "peer", "url": f"{ORIGIN}/peer", "method": "GET"}],
            concurrency_effect=mapping,
        )
        run = run_behavioral_authorization_endpoint
    with pytest.raises(HTTPException) as caught:
        asyncio.run(run(request, _=True))
    assert caught.value.status_code == 409
    assert caught.value.detail == "concurrency_effect_owned_persona_mismatch"
    assert target.calls == []


def test_from_url_enabled_reaches_inner_foundry(tmp_path, monkeypatch):
    case = _case(tmp_path, monkeypatch)
    module, _, mapping, target, _, _, envelope, source, peer, records = case
    from core.server.routers import driver
    from core.server.routers.foundry import (
        RunBehavioralAuthorizationFromURLRequest,
        run_behavioral_authorization_from_url_endpoint,
    )
    from core.wraith.bola_replay import ReplayResponse, SNDReplayTransport

    peer_records = ({"id": "peer-capture", "url": f"{ORIGIN}/peer", "method": "GET"},)
    request = RunBehavioralAuthorizationFromURLRequest(
        target_url=f"{ORIGIN}/app",
        envelope_id=envelope.envelope_id,
        source_persona_id=source.persona_id,
        peer_persona_id=peer.persona_id,
        concurrency_effect=mapping,
    )
    monkeypatch.setenv("SENTINELFORGE_BEHAVIOR_PRIMARY", "1")
    monkeypatch.setenv(module.CONCURRENCY_EFFECT_EXECUTION_ENV, "1")

    async def capture_pair(**kwargs):
        return (
            driver.PersonaCaptureArtifact(
                persona_id=source.persona_id,
                path="/private/concurrency-source.jsonl",
                records=records,
                captured_bytes=10,
                limit_reached=False,
                page_url=f"{ORIGIN}/app",
            ),
            driver.PersonaCaptureArtifact(
                persona_id=peer.persona_id,
                path="/private/concurrency-peer.jsonl",
                records=peer_records,
                captured_bytes=10,
                limit_reached=False,
                page_url=f"{ORIGIN}/app",
            ),
            (),
        )

    async def validate_windows(persona_ids):
        assert tuple(persona_ids) == (source.persona_id, peer.persona_id)

    async def fake_send(_transport, persona_id, replay_request):
        assert persona_id == source.persona_id
        status, body = await target.send(
            replay_request.method,
            replay_request.url,
            json.loads(replay_request.body),
            _redirect_mode=replay_request.redirect_mode,
        )
        return ReplayResponse(status, json.dumps(body))

    monkeypatch.setattr(driver, "capture_persona_pair", capture_pair)
    monkeypatch.setattr(driver, "validate_persona_windows", validate_windows)
    monkeypatch.setattr(SNDReplayTransport, "send", fake_send)
    response = asyncio.run(run_behavioral_authorization_from_url_endpoint(request, _=True))
    assert response["kind"] == "concurrency_invariant_effect_one_click"
    assert response["finding"] is None
    assert [call["kind"] for call in target.calls] == KINDS
