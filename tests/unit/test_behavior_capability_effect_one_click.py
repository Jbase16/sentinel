"""R5D9 concrete capability-effect transport and one-click composition tests."""

from __future__ import annotations

import ast
import asyncio
from dataclasses import replace
import json
from pathlib import Path

import pytest

import core.behavior.capability_effect_one_click as one_click_module
from core.behavior.capability_effect_evaluation import (
    CAPABILITY_EFFECT_EXECUTION_ENV,
    CapabilityEffectExecutionConfig,
    CapabilityEffectExecutionDenied,
    CapabilityEffectOracleVerdict,
)
from core.behavior.capability_effect_one_click import (
    CAPABILITY_EFFECT_ONE_CLICK_MODE,
    CAPABILITY_EFFECT_WORKFLOW,
    CapabilityEffectFindingCandidate,
    CapabilityEffectOneClickDenied,
    CapabilityEffectOneClickDispatcher,
    CapabilityEffectOneClickRun,
    CapabilityEffectOneClickSpecification,
    PolicyExecutorCapabilityEffectTransport,
)
from core.behavior.capability_execution_receipt import CapabilityExecutionOutcome
from core.cortex.execution_policy import ExecutionPolicy, PolicyExecutor
from core.foundry.authorization import create_envelope
from core.foundry.vault import PersonaVault
from core.safety.proof_budget import ProofBudget


ORIGIN = "https://api.example.test"
RAW_EFFECT = "owned-export-created"
RAW_RESOURCE = "raw-resource-content-must-not-survive"
RAW_SESSION = "raw-session-material-must-not-survive"
OBSERVATION_KINDS = (
    "no_capability_baseline",
    "valid_capability_effect_witness",
    "replayed_capability_probe",
    "expired_capability_probe",
    "inadmissible_capability_probe",
)
EXPECTED_OUTCOMES = {
    "no_capability_baseline": CapabilityExecutionOutcome.EXECUTION_REFUSED_NOT_LIVE,
    "valid_capability_effect_witness": CapabilityExecutionOutcome.EXECUTION_COMPLETED,
    "replayed_capability_probe": (
        CapabilityExecutionOutcome.EXECUTION_REFUSED_ALREADY_CONSUMED
    ),
    "expired_capability_probe": CapabilityExecutionOutcome.EXECUTION_REFUSED_EXPIRED,
    "inadmissible_capability_probe": (
        CapabilityExecutionOutcome.EXECUTION_REFUSED_INADMISSIBLE
    ),
}


class _ControlledTarget:
    def __init__(
        self,
        *,
        leak_replay: bool = False,
        witness_effect: bool = True,
        cleanup_verified: bool = True,
        fail_phase: str | None = None,
        invalid_phase: str | None = None,
        cleanup_raises: bool = False,
    ) -> None:
        self.leak_replay = leak_replay
        self.witness_effect = witness_effect
        self.cleanup_verified = cleanup_verified
        self.fail_phase = fail_phase
        self.invalid_phase = invalid_phase
        self.cleanup_raises = cleanup_raises
        self.calls = []
        self._valid_resource_ref = None
        self._consumed = False

    async def send(self, method, url, body=None, **_kwargs):
        assert method == "POST"
        assert isinstance(body, dict)
        self.calls.append((url, dict(body)))
        if url.endswith("/capability-cleanup"):
            if self.cleanup_raises:
                raise RuntimeError("controlled cleanup failure")
            assert body["mode"] == CAPABILITY_EFFECT_ONE_CLICK_MODE
            assert body["capability_ref"].startswith("issued_capability_contract:")
            return 200, {
                "cleanup_verified": self.cleanup_verified,
                "orphaned_owned_state_possible": not self.cleanup_verified,
                "target_projection_observed": True,
            }

        kind = body["observation_kind"]
        if kind == self.fail_phase:
            raise RuntimeError("controlled target failure")
        if kind == self.invalid_phase:
            return 200, {"access_decision": "unknown"}

        runtime = body["runtime"]
        observed = float(runtime["observed_epoch"])
        admitted = float(runtime["admitted_at_epoch"])
        expires = float(runtime["expires_at_epoch"])
        presentation = body["presentation"]
        effect = {
            "effect": RAW_EFFECT,
            "resource": RAW_RESOURCE,
            "session": RAW_SESSION,
        }
        if kind == "no_capability_baseline":
            assert body["capability_ref"] is None
            assert presentation is None
            assert observed < admitted
            return 403, {
                "access_decision": "denied",
                "effect": None,
                "target_projection_observed": True,
            }
        assert body["capability_ref"].startswith("issued_capability_contract:")
        assert presentation["schema_version"] == 1
        if kind == "valid_capability_effect_witness":
            assert admitted <= observed < expires
            assert self._consumed is False
            self._valid_resource_ref = presentation["resource_ref"]
            self._consumed = True
            return 200, {
                "access_decision": "allowed",
                "effect": effect if self.witness_effect else None,
                "target_projection_observed": True,
            }
        if kind == "replayed_capability_probe":
            assert self._consumed is True
            assert presentation["resource_ref"] == self._valid_resource_ref
            return (
                (
                    200,
                    {
                        "access_decision": "allowed",
                        "effect": effect,
                        "target_projection_observed": True,
                    },
                )
                if self.leak_replay
                else (
                    403,
                    {
                        "access_decision": "denied",
                        "effect": None,
                        "target_projection_observed": True,
                    },
                )
            )
        if kind == "expired_capability_probe":
            assert observed >= expires
            assert presentation["resource_ref"] == self._valid_resource_ref
            return 403, {
                "access_decision": "denied",
                "effect": None,
                "target_projection_observed": True,
            }
        assert kind == "inadmissible_capability_probe"
        assert admitted <= observed < expires
        assert presentation["resource_ref"] != self._valid_resource_ref
        return 403, {
            "access_decision": "denied",
            "effect": None,
            "target_projection_observed": True,
        }


class _TrackingPolicyExecutor(PolicyExecutor):
    def __init__(self, raw_send, policy):
        super().__init__(raw_send, policy)
        self.claim_calls = 0
        self.claimed_send_calls = 0

    def claim_proposal_action(self, action):
        self.claim_calls += 1
        return super().claim_proposal_action(action)

    async def send_claimed_action(self, action, claim, **kwargs):
        self.claimed_send_calls += 1
        return await super().send_claimed_action(action, claim, **kwargs)


def _specification_mapping():
    return {
        "schema_version": 1,
        "run_id": "owned-capability-effect-run-001",
        "target_url": f"{ORIGIN}/api/capability-effect",
        "cleanup_url": f"{ORIGIN}/api/capability-cleanup",
    }


def _evidence(persona_id):
    return (
        {
            "id": "capability-source-evidence",
            "persona_id": persona_id,
            "method": "GET",
            "url": f"{ORIGIN}/api/capability-seed",
            "response_status": 200,
            "response_body": '{"available":true}',
        },
    )


def _setup(
    tmp_path,
    monkeypatch,
    target=None,
    *,
    enabled=True,
    signed_workflow=True,
):
    monkeypatch.setenv("SENTINELFORGE_PERSONA_VAULT", str(tmp_path / "personas"))
    monkeypatch.setenv("SENTINELFORGE_AUTHZ_STORE", str(tmp_path / "authorizations"))
    vault = PersonaVault()
    persona = vault.add_persona(
        label="capability-owner",
        email="capability-owner@research.example",
    )
    envelope = create_envelope(
        researcher_identity="researcher",
        target_handle="controlled-capability-target",
        authorized_origins=[ORIGIN],
        authorization_basis="owned capability-effect verification",
        allowed_workflows=(
            [CAPABILITY_EFFECT_WORKFLOW] if signed_workflow else ["different_workflow"]
        ),
        disclosure_attestation=True,
    )
    specification = CapabilityEffectOneClickSpecification.from_mapping(
        _specification_mapping(),
        target_origin=ORIGIN,
    )
    controlled = target or _ControlledTarget()
    policy = ExecutionPolicy(
        "bounty_safe",
        scope_filter=lambda url: str(url).startswith(f"{ORIGIN}/"),
        budget=ProofBudget(
            max_total_requests=6,
            max_requests_per_endpoint=5,
            max_cross_object_reads=0,
            max_privilege_mutations=0,
            max_creates=0,
            allow_delete=False,
            allow_real_user_data_access=False,
        ),
    )
    executor = _TrackingPolicyExecutor(controlled.send, policy)
    dispatcher = CapabilityEffectOneClickDispatcher(
        target_origin=ORIGIN,
        persona_id=persona.persona_id,
        specification=specification,
        authorization=envelope,
        executor=executor,
        persona_vault=vault,
        evidence_records=_evidence(persona.persona_id),
        config=CapabilityEffectExecutionConfig(enabled=enabled),
        clock=lambda: 150.0,
    )
    return dispatcher, controlled, executor, specification


def _run(dispatcher):
    return asyncio.run(dispatcher.run())


def test_specification_is_exact_origin_bound_and_publicly_redacted():
    raw = _specification_mapping()
    specification = CapabilityEffectOneClickSpecification.from_mapping(
        raw,
        target_origin=ORIGIN,
    )

    assert specification.specification_id.startswith(
        "capability_effect_one_click_specification:"
    )
    assert specification.target_request_ref.startswith(
        "capability_effect_target_request:"
    )
    assert specification.cleanup_request_ref.startswith(
        "capability_effect_cleanup_request:"
    )
    assert raw["run_id"] not in json.dumps(specification.to_dict(), sort_keys=True)
    assert raw["target_url"] not in json.dumps(specification.to_dict(), sort_keys=True)
    assert raw["cleanup_url"] not in repr(specification)

    changed = dict(raw)
    changed["target_url"] = "https://outside.example.test/api/capability-effect"
    with pytest.raises(ValueError, match="leaves the authorized target origin"):
        CapabilityEffectOneClickSpecification.from_mapping(
            changed,
            target_origin=ORIGIN,
        )

    changed = dict(raw)
    changed["cleanup_url"] = raw["target_url"]
    with pytest.raises(ValueError, match="cleanup endpoint must be distinct"):
        CapabilityEffectOneClickSpecification.from_mapping(
            changed,
            target_origin=ORIGIN,
        )


def test_default_off_dispatcher_returns_disabled_run_without_target_traffic(
    tmp_path,
    monkeypatch,
):
    dispatcher, target, executor, specification = _setup(
        tmp_path,
        monkeypatch,
        enabled=False,
        signed_workflow=False,
    )

    result = _run(dispatcher)

    assert result == CapabilityEffectOneClickRun.disabled(specification)
    assert result.status == "selected_execution_disabled"
    assert result.disabled_gates == (CAPABILITY_EFFECT_EXECUTION_ENV,)
    assert result.dispatched is False
    assert result.finding_authority is False
    assert target.calls == []
    assert executor.restraint_summary()["requests_sent"] == 0


def test_secure_controlled_target_confirms_exact_matrix_and_verified_cleanup(
    tmp_path,
    monkeypatch,
):
    dispatcher, target, executor, _ = _setup(tmp_path, monkeypatch)

    result = _run(dispatcher)

    assert result.status == "completed"
    assert result.execution.oracle.verdict is (
        CapabilityEffectOracleVerdict.CONFIRMED_ONE_TIME_AUTHORIZED_EFFECT
    )
    assert (
        result.execution.receipt_id
        == result.execution.effect_observations[1].receipt_ref
    )
    assert {
        item.observation_kind: item.receipt_outcome
        for item in result.execution.effect_observations
    } == EXPECTED_OUTCOMES
    assert result.execution.cleanup.status == "verified"
    assert result.execution.cleanup.target_requests_sent == 6
    assert executor.restraint_summary()["requests_sent"] == 6
    assert executor.claim_calls == 1
    assert executor.claimed_send_calls == 1
    assert executor._proposal_claims == {}
    assert [body.get("observation_kind", "cleanup") for _, body in target.calls] == [
        *OBSERVATION_KINDS,
        "cleanup",
    ]
    assert result.candidate is not None
    assert result.candidate.promotion_authority is False
    assert result.candidate.finding_authority is False
    response = result.execution_response()
    assert response["finding"] is None
    assert response["finding_confirmed"] is False
    assert response["finding_candidate"]["adversarial_triage_required"] is True
    assert response["promotion_authority"] is False
    assert response["finding_authority"] is False


def test_leaking_controlled_target_is_refuted_by_the_same_r5d8_oracle(
    tmp_path,
    monkeypatch,
):
    target = _ControlledTarget(leak_replay=True)
    dispatcher, target, executor, _ = _setup(
        tmp_path,
        monkeypatch,
        target,
    )

    result = _run(dispatcher)

    assert result.execution.oracle.verdict is CapabilityEffectOracleVerdict.REFUTED
    assert result.execution.execution_effect_authority is False
    assert result.candidate is None
    assert result.execution.cleanup.status == "verified"
    assert executor.restraint_summary()["requests_sent"] == 6
    assert len(target.calls) == 6


def test_receipts_are_evaluated_after_each_real_policy_dispatch(
    tmp_path,
    monkeypatch,
):
    target = _ControlledTarget()
    observed_call_counts = []
    real_evaluator = one_click_module.evaluate_capability_execution

    def tracked_evaluator(*args, **kwargs):
        observed_call_counts.append(len(target.calls))
        return real_evaluator(*args, **kwargs)

    monkeypatch.setattr(
        one_click_module,
        "evaluate_capability_execution",
        tracked_evaluator,
    )
    dispatcher, _, _, _ = _setup(tmp_path, monkeypatch, target)

    _run(dispatcher)

    # The first five evaluations mint phase receipts only after the matching
    # target outcome. Later calls are exact deterministic revalidations for
    # cleanup/request binding and do not remint an outcome by hand.
    assert observed_call_counts[:5] == [1, 2, 3, 4, 5]


def test_raw_effect_resource_and_session_values_never_survive_public_or_object_state(
    tmp_path,
    monkeypatch,
):
    dispatcher, target, _executor, _ = _setup(tmp_path, monkeypatch)

    result = _run(dispatcher)
    encoded = json.dumps(result.to_dict(), sort_keys=True)
    representations = f"{result!r}\n{dispatcher!r}"

    for raw in (RAW_EFFECT, RAW_RESOURCE, RAW_SESSION):
        assert raw not in encoded
        assert raw not in representations
        assert all(
            raw not in json.dumps(body, sort_keys=True) for _, body in target.calls
        )
    assert result.execution.oracle.authorized_effect_ref.startswith(
        "capability_protected_effect:"
    )


def test_missing_witness_effect_is_refuted_without_creating_a_candidate(
    tmp_path,
    monkeypatch,
):
    dispatcher, _, _, _ = _setup(
        tmp_path,
        monkeypatch,
        _ControlledTarget(witness_effect=False),
    )

    result = _run(dispatcher)

    assert result.execution.oracle.verdict is CapabilityEffectOracleVerdict.REFUTED
    assert result.candidate is None


def test_unverified_real_cleanup_denies_even_a_confirmed_oracle(
    tmp_path,
    monkeypatch,
):
    dispatcher, target, _, _ = _setup(
        tmp_path,
        monkeypatch,
        _ControlledTarget(cleanup_verified=False),
    )

    with pytest.raises(
        CapabilityEffectExecutionDenied,
        match="capability_effect_cleanup_unverified",
    ) as denied:
        _run(dispatcher)

    assert denied.value.oracle.verdict is (
        CapabilityEffectOracleVerdict.CONFIRMED_ONE_TIME_AUTHORIZED_EFFECT
    )
    assert denied.value.cleanup.status == "uncertain"
    assert denied.value.cleanup.orphaned_owned_state_possible is True
    assert len(target.calls) == 6


def test_cleanup_transport_exception_becomes_uncertain_orphan_risk(
    tmp_path,
    monkeypatch,
):
    dispatcher, target, _, _ = _setup(
        tmp_path,
        monkeypatch,
        _ControlledTarget(cleanup_raises=True),
    )

    with pytest.raises(
        CapabilityEffectExecutionDenied,
        match="capability_effect_cleanup_unverified",
    ) as denied:
        _run(dispatcher)

    assert denied.value.cleanup.status == "uncertain"
    assert denied.value.cleanup.target_request_may_have_been_sent is True
    assert denied.value.cleanup.orphaned_owned_state_possible is True
    assert len(target.calls) == 6


def test_preparation_failure_still_performs_real_cleanup_and_fails_closed(
    tmp_path,
    monkeypatch,
):
    dispatcher, target, _, _ = _setup(
        tmp_path,
        monkeypatch,
        _ControlledTarget(fail_phase="valid_capability_effect_witness"),
    )

    with pytest.raises(
        CapabilityEffectOneClickDenied,
        match="capability_effect_preparation_failed",
    ) as denied:
        _run(dispatcher)

    assert denied.value.cleanup.status == "verified"
    assert denied.value.cleanup.target_requests_sent == 2
    assert [body.get("observation_kind", "cleanup") for _, body in target.calls] == [
        "no_capability_baseline",
        "valid_capability_effect_witness",
        "cleanup",
    ]


def test_invalid_target_projection_fails_after_verified_cleanup(
    tmp_path,
    monkeypatch,
):
    dispatcher, target, _, _ = _setup(
        tmp_path,
        monkeypatch,
        _ControlledTarget(invalid_phase="replayed_capability_probe"),
    )

    with pytest.raises(
        CapabilityEffectExecutionDenied,
        match="capability_effect_execution_failed",
    ) as denied:
        _run(dispatcher)

    assert denied.value.cleanup.status == "verified"
    assert denied.value.target_request_possible is True
    assert len(target.calls) == 4


def test_missing_signed_capability_workflow_denies_before_target_traffic(
    tmp_path,
    monkeypatch,
):
    target = _ControlledTarget()

    with pytest.raises(
        CapabilityEffectOneClickDenied,
        match="capability_effect_authorization_denied",
    ):
        _setup(
            tmp_path,
            monkeypatch,
            target,
            signed_workflow=False,
        )

    assert target.calls == []


def test_candidate_and_run_revalidate_content_addressed_results(
    tmp_path,
    monkeypatch,
):
    result = _run(_setup(tmp_path, monkeypatch)[0])

    rebuilt = CapabilityEffectFindingCandidate.from_result(result.execution)
    assert rebuilt == result.candidate
    with pytest.raises(ValueError, match="finding candidate is invalid"):
        replace(rebuilt, result_id="capability_effect_execution_result:" + "0" * 64)
    with pytest.raises(ValueError, match="one-click run is invalid"):
        replace(result, finding_authority=True)


def test_run_rejects_a_valid_candidate_from_a_different_execution(
    tmp_path,
    monkeypatch,
):
    first = _run(_setup(tmp_path / "first", monkeypatch)[0])
    second = _run(_setup(tmp_path / "second", monkeypatch)[0])

    assert first.candidate != second.candidate
    with pytest.raises(ValueError, match="one-click run is invalid"):
        replace(first, candidate=second.candidate)


def test_transport_is_concrete_policy_adapter_with_no_new_http_client():
    source_path = Path(one_click_module.__file__)
    source = source_path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported_modules = {
        alias.name.split(".", 1)[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    imported_from = {
        (node.module or "").split(".", 1)[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
    }

    assert not {"httpx", "requests", "socket", "subprocess", "urllib3"} & (
        imported_modules | imported_from
    )
    assert PolicyExecutorCapabilityEffectTransport.__dict__["dispatch"]
    assert PolicyExecutorCapabilityEffectTransport.__dict__["cleanup"]
    assert "PolicyExecutor" in source
    assert "ProposalExecutionClaim(" not in source
    assert ".claim_proposal_action(" in source
    assert ".send_claimed_action(" in source


def test_new_module_has_exactly_one_core_consumer_and_no_lab_import():
    source_path = Path(one_click_module.__file__).resolve()
    repository_root = Path(__file__).resolve().parents[2]
    production_consumers = sorted(
        path.relative_to(repository_root).as_posix()
        for path in (repository_root / "core").rglob("*.py")
        if path.resolve() != source_path
        and "capability_effect_one_click" in path.read_text(encoding="utf-8")
    )
    assert production_consumers == ["core/server/routers/foundry.py"]

    lab_root = repository_root.parent / "sentinel-visual-acceptance-lab"
    lab_consumers = []
    if lab_root.is_dir():
        for path in lab_root.rglob("*.py"):
            if ".venv" in path.parts:
                continue
            source = path.read_text(encoding="utf-8")
            tree = ast.parse(source)
            import_roots = {
                alias.name.split(".", 1)[0]
                for node in ast.walk(tree)
                if isinstance(node, ast.Import)
                for alias in node.names
            } | {
                (node.module or "").split(".", 1)[0]
                for node in ast.walk(tree)
                if isinstance(node, ast.ImportFrom)
            }
            if (
                "capability_effect_one_click" in source
                or {"core", "sentinelforge"} & import_roots
            ):
                lab_consumers.append(path)
    assert lab_consumers == []


def test_module_exports_exact_operator_surface():
    assert one_click_module.__all__ == [
        "CAPABILITY_EFFECT_ONE_CLICK_MODE",
        "CAPABILITY_EFFECT_WORKFLOW",
        "CapabilityEffectFindingCandidate",
        "CapabilityEffectOneClickDenied",
        "CapabilityEffectOneClickDispatcher",
        "CapabilityEffectOneClickRun",
        "CapabilityEffectOneClickSpecification",
        "PolicyExecutorCapabilityEffectTransport",
    ]
    assert CAPABILITY_EFFECT_ONE_CLICK_MODE == (
        "behavioral_capability_effect_one_click_v1"
    )
