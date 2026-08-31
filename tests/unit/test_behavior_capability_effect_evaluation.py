"""R5D8 injected capability-effect executor and independent oracle tests."""

from __future__ import annotations

import ast
import asyncio
from dataclasses import replace
import inspect
import json
from pathlib import Path

import pytest

import core.behavior.capability_effect_evaluation as effect_module
from core.behavior.capability_consumption_ledger import ConsumptionOutcome
from core.behavior.capability_contract import CapabilityOutcome
from core.behavior.capability_effect_evaluation import (
    CAPABILITY_EFFECT_EXECUTION_ENV,
    CAPABILITY_EFFECT_EXECUTION_MODE,
    CapabilityCleanupResult,
    CapabilityEffectExecutionConfig,
    CapabilityEffectExecutionDenied,
    CapabilityEffectExperimentExecutor,
    CapabilityEffectObservation,
    CapabilityEffectOracleEvaluation,
    CapabilityEffectOracleVerdict,
    CapabilityEffectTransport,
)
from core.behavior.capability_execution_receipt import (
    CapabilityExecutionOutcome,
)
from core.behavior.normalize import stable_hash
from tests.unit.test_behavior_capability_execution_receipt import (
    ADMITTED_AT,
    EXPIRES_AT,
    _evaluate,
)


EFFECT_VALUE = {
    "effect": "owned-export-created",
    "resource": "raw-value-must-not-survive",
}
OBSERVATION_KINDS = (
    "no_capability_baseline",
    "valid_capability_effect_witness",
    "replayed_capability_probe",
    "expired_capability_probe",
    "inadmissible_capability_probe",
)
EXPECTED_OUTCOMES = {
    "no_capability_baseline": (CapabilityExecutionOutcome.EXECUTION_REFUSED_NOT_LIVE),
    "valid_capability_effect_witness": (CapabilityExecutionOutcome.EXECUTION_COMPLETED),
    "replayed_capability_probe": (
        CapabilityExecutionOutcome.EXECUTION_REFUSED_ALREADY_CONSUMED
    ),
    "expired_capability_probe": (CapabilityExecutionOutcome.EXECUTION_REFUSED_EXPIRED),
    "inadmissible_capability_probe": (
        CapabilityExecutionOutcome.EXECUTION_REFUSED_INADMISSIBLE
    ),
}


def _receipts(suffix: str = "effect-oracle"):
    values = {
        "no_capability_baseline": _evaluate(
            suffix=suffix,
            now=ADMITTED_AT - 1.0,
        ),
        "valid_capability_effect_witness": _evaluate(
            suffix=suffix,
            now=150.0,
        ),
        "replayed_capability_probe": _evaluate(
            suffix=suffix,
            consumption_outcome=ConsumptionOutcome.REPLAYED_PRESENTATION,
            now=150.0,
        ),
        "expired_capability_probe": _evaluate(
            suffix=suffix,
            now=EXPIRES_AT,
        ),
        "inadmissible_capability_probe": _evaluate(
            suffix=suffix,
            logical_outcome=CapabilityOutcome.WRONG_BINDING,
            now=150.0,
        ),
    }
    assert {item.capability_ref for item in values.values()} == {
        values["valid_capability_effect_witness"].capability_ref
    }
    assert {
        kind: receipt.outcome for kind, receipt in values.items()
    } == EXPECTED_OUTCOMES
    return values


class _TwinTransport:
    def __init__(
        self,
        receipts,
        *,
        leak_kind: str | None = None,
        witness_effect: bool = True,
        missing_projection_kind: str | None = None,
        wrong_receipt_kind: str | None = None,
        wrong_receipt=None,
        dispatch_raises_at: int | None = None,
        cancel_at: int | None = None,
        cleanup_status: str = "verified",
        cleanup_raises: bool = False,
    ) -> None:
        self.receipts = receipts
        self.leak_kind = leak_kind
        self.witness_effect = witness_effect
        self.missing_projection_kind = missing_projection_kind
        self.wrong_receipt_kind = wrong_receipt_kind
        self.wrong_receipt = wrong_receipt
        self.dispatch_raises_at = dispatch_raises_at
        self.cancel_at = cancel_at
        self.cleanup_status = cleanup_status
        self.cleanup_raises = cleanup_raises
        self.calls = []
        self.cleanup_calls = []

    async def dispatch(self, request):
        self.calls.append(dict(request))
        if self.cancel_at == len(self.calls):
            raise asyncio.CancelledError()
        if self.dispatch_raises_at == len(self.calls):
            raise RuntimeError("simulated transport failure")

        kind = request["observation_kind"]
        receipt = self.receipts[kind]
        if kind == self.wrong_receipt_kind:
            receipt = self.wrong_receipt
        if kind == self.missing_projection_kind:
            return 200, {
                "terminal_receipt": receipt,
                "access_decision": "unknown",
                "effect": None,
                "target_projection_observed": False,
            }
        if kind == "valid_capability_effect_witness":
            return 200, {
                "terminal_receipt": receipt,
                "access_decision": "allowed",
                "effect": EFFECT_VALUE if self.witness_effect else None,
                "target_projection_observed": True,
            }
        if kind == self.leak_kind:
            return 200, {
                "terminal_receipt": receipt,
                "access_decision": "allowed",
                "effect": EFFECT_VALUE,
                "target_projection_observed": True,
            }
        return 403, {
            "terminal_receipt": receipt,
            "access_decision": "denied",
            "effect": None,
            "target_projection_observed": True,
        }

    async def cleanup(self, request):
        self.cleanup_calls.append(dict(request))
        if self.cleanup_raises:
            raise RuntimeError("simulated cleanup failure")
        requests_sent = len(self.calls) + 1
        if self.cleanup_status == "verified":
            return CapabilityCleanupResult(
                status="verified",
                target_requests_sent=requests_sent,
                target_request_may_have_been_sent=False,
                orphaned_owned_state_possible=False,
            )
        if self.cleanup_status == "uncertain":
            return CapabilityCleanupResult(
                status="uncertain",
                target_requests_sent=requests_sent,
                target_request_may_have_been_sent=False,
                orphaned_owned_state_possible=True,
            )
        return CapabilityCleanupResult(
            status="unattempted",
            target_requests_sent=0,
            target_request_may_have_been_sent=False,
            orphaned_owned_state_possible=False,
        )


def _executor(transport, receipts=None, *, enabled=True):
    values = receipts or _receipts()
    return CapabilityEffectExperimentExecutor(
        values["valid_capability_effect_witness"],
        transport=transport,
        config=CapabilityEffectExecutionConfig(enabled=enabled),
    )


def _run(transport, receipts=None, *, enabled=True):
    return asyncio.run(_executor(transport, receipts, enabled=enabled).execute())


@pytest.mark.parametrize(
    "raw,expected",
    (
        ("1", True),
        ("TRUE", True),
        (" yes ", True),
        ("On", True),
        ("0", False),
        ("false", False),
        ("", False),
    ),
)
def test_config_is_default_off_and_uses_only_explicit_truthy_values(
    monkeypatch,
    raw,
    expected,
):
    monkeypatch.setenv(CAPABILITY_EFFECT_EXECUTION_ENV, raw)
    assert CapabilityEffectExecutionConfig.from_environment().enabled is expected


def test_default_config_is_disabled_when_environment_is_absent(monkeypatch):
    monkeypatch.delenv(CAPABILITY_EFFECT_EXECUTION_ENV, raising=False)
    assert CapabilityEffectExecutionConfig().enabled is False
    assert CapabilityEffectExecutionConfig.from_environment().enabled is False


def test_secure_twin_confirms_exact_one_time_effect_and_verified_cleanup():
    receipts = _receipts("secure")
    transport = _TwinTransport(receipts)

    result = _run(transport, receipts)

    assert result.oracle.verdict is (
        CapabilityEffectOracleVerdict.CONFIRMED_ONE_TIME_AUTHORIZED_EFFECT
    )
    assert result.execution_effect_authority is True
    assert result.oracle.finding_candidate_ref is not None
    assert result.oracle.promotion_authority is False
    assert result.oracle.finding_authority is False
    assert result.oracle.adversarial_triage_required is True
    assert result.cleanup.status == "verified"
    assert result.cleanup.target_requests_sent == 6
    assert result.cleanup.target_request_may_have_been_sent is False
    assert result.cleanup.orphaned_owned_state_possible is False
    assert [call["observation_kind"] for call in transport.calls] == list(
        OBSERVATION_KINDS
    )
    assert len(transport.cleanup_calls) == 1
    assert (
        tuple(item.observation_kind for item in result.effect_observations)
        == OBSERVATION_KINDS
    )
    assert (
        sum(item.protected_effect_observed for item in result.effect_observations) == 1
    )


def test_vulnerable_twin_leak_duplicates_effect_and_is_refuted():
    receipts = _receipts("vulnerable")
    transport = _TwinTransport(
        receipts,
        leak_kind="replayed_capability_probe",
    )

    result = _run(transport, receipts)

    assert result.oracle.verdict is CapabilityEffectOracleVerdict.REFUTED
    assert result.execution_effect_authority is False
    assert result.oracle.finding_candidate_ref is None
    assert len(transport.calls) == 5
    assert len(transport.cleanup_calls) == 1
    replay = result.effect_observations[2]
    assert replay.receipt_outcome is (
        CapabilityExecutionOutcome.EXECUTION_REFUSED_ALREADY_CONSUMED
    )
    assert replay.protected_effect_observed is True


@pytest.mark.parametrize(
    "leak_kind",
    (
        "no_capability_baseline",
        "replayed_capability_probe",
        "expired_capability_probe",
        "inadmissible_capability_probe",
    ),
)
def test_effect_in_any_refusal_phase_is_refuted(leak_kind):
    receipts = _receipts(f"leak-{leak_kind}")
    result = _run(_TwinTransport(receipts, leak_kind=leak_kind), receipts)

    assert result.oracle.verdict is CapabilityEffectOracleVerdict.REFUTED
    assert result.execution_effect_authority is False


def test_missing_authorized_effect_is_refuted():
    receipts = _receipts("missing-effect")
    result = _run(_TwinTransport(receipts, witness_effect=False), receipts)

    assert result.oracle.verdict is CapabilityEffectOracleVerdict.REFUTED
    assert result.oracle.authorized_effect_observed_once is False
    assert result.execution_effect_authority is False


def test_missing_projection_is_inconclusive_after_verified_cleanup():
    receipts = _receipts("inconclusive")
    transport = _TwinTransport(
        receipts,
        missing_projection_kind="expired_capability_probe",
    )

    with pytest.raises(
        CapabilityEffectExecutionDenied,
        match="capability_effect_oracle_inconclusive",
    ) as denied:
        _run(transport, receipts)

    assert denied.value.category == "oracle"
    assert denied.value.oracle.verdict is CapabilityEffectOracleVerdict.INCONCLUSIVE
    assert denied.value.cleanup.status == "verified"
    assert denied.value.target_request_possible is True
    assert len(transport.calls) == 5
    assert len(transport.cleanup_calls) == 1


def test_all_five_observations_bind_the_exact_r5d6_outcomes():
    receipts = _receipts("receipt-bindings")
    transport = _TwinTransport(receipts)
    result = _run(transport, receipts)

    assert {
        item.observation_kind: item.receipt_outcome
        for item in result.effect_observations
    } == EXPECTED_OUTCOMES
    assert [call["expected_receipt_outcome"] for call in transport.calls] == [
        EXPECTED_OUTCOMES[kind].value for kind in OBSERVATION_KINDS
    ]


def test_dispatch_requests_bind_only_typed_owned_world_and_receipt_refs():
    receipts = _receipts("request-binding")
    transport = _TwinTransport(receipts)

    result = _run(transport, receipts)

    for request in transport.calls:
        assert request["mode"] == CAPABILITY_EFFECT_EXECUTION_MODE
        assert request["capability_ref"] == result.capability_ref
        assert request["witness_receipt_ref"] == result.receipt_id
        assert request["observation_binding_id"] == result.observation_binding_id
        assert request["owned_world_ref"].startswith("world:")
        assert request["owned_persona_ref"].startswith("experiment_persona:")
        assert request["ownership_ref"].startswith("ownership_proof:")
    assert EFFECT_VALUE["resource"] not in json.dumps(transport.calls)


def test_raw_effect_value_is_hashed_and_never_retained_in_public_result():
    receipts = _receipts("redaction")
    result = _run(_TwinTransport(receipts), receipts)
    encoded = json.dumps(result.to_dict(), sort_keys=True)

    assert EFFECT_VALUE["effect"] not in encoded
    assert EFFECT_VALUE["resource"] not in encoded
    assert EFFECT_VALUE["effect"] not in repr(result)
    assert result.oracle.authorized_effect_ref.startswith(
        "capability_protected_effect:"
    )


def test_disabled_executor_refuses_before_dispatch_or_cleanup():
    receipts = _receipts("disabled")
    transport = _TwinTransport(receipts)

    with pytest.raises(
        CapabilityEffectExecutionDenied,
        match="capability_effect_execution_is_disabled",
    ) as denied:
        _run(transport, receipts, enabled=False)

    assert denied.value.category == "configuration"
    assert denied.value.cleanup.status == "unattempted"
    assert denied.value.target_request_possible is False
    assert transport.calls == []
    assert transport.cleanup_calls == []


def test_executor_is_single_use_and_does_not_repeat_transport():
    receipts = _receipts("single-use")
    transport = _TwinTransport(receipts)
    executor = _executor(transport, receipts)

    first = asyncio.run(executor.execute())
    with pytest.raises(
        CapabilityEffectExecutionDenied,
        match="capability_effect_executor_already_consumed",
    ) as denied:
        asyncio.run(executor.execute())

    assert first.execution_effect_authority is True
    assert denied.value.cleanup.status == "unattempted"
    assert len(transport.calls) == 5
    assert len(transport.cleanup_calls) == 1


def test_concurrent_reuse_allows_exactly_one_execution():
    receipts = _receipts("concurrent-use")
    transport = _TwinTransport(receipts)
    executor = _executor(transport, receipts)

    async def run_twice():
        return await asyncio.gather(
            executor.execute(),
            executor.execute(),
            return_exceptions=True,
        )

    outcomes = asyncio.run(run_twice())

    assert (
        sum(isinstance(item, CapabilityEffectExecutionDenied) for item in outcomes) == 1
    )
    assert sum(not isinstance(item, BaseException) for item in outcomes) == 1
    assert len(transport.calls) == 5
    assert len(transport.cleanup_calls) == 1


def test_noncompleted_gate_receipt_is_refused_without_target_request():
    receipts = _receipts("refused-gate")
    refusal = receipts["expired_capability_probe"]
    transport = _TwinTransport(receipts)
    executor = CapabilityEffectExperimentExecutor(
        refusal,
        transport=transport,
        config=CapabilityEffectExecutionConfig(enabled=True),
    )

    with pytest.raises(
        CapabilityEffectExecutionDenied,
        match="capability_effect_execution_receipt_not_completed",
    ) as denied:
        asyncio.run(executor.execute())

    assert denied.value.terminal_receipt == refusal
    assert denied.value.terminal_receipt.outcome is (
        CapabilityExecutionOutcome.EXECUTION_REFUSED_EXPIRED
    )
    assert denied.value.cleanup.status == "unattempted"
    assert transport.calls == []
    assert transport.cleanup_calls == []


def test_forged_in_memory_gate_receipt_is_revalidated_before_dispatch():
    receipts = _receipts("forged-gate")
    witness = receipts["valid_capability_effect_witness"]
    transport = _TwinTransport(receipts)
    executor = _executor(transport, receipts)
    object.__setattr__(
        witness,
        "outcome",
        CapabilityExecutionOutcome.EXECUTION_REFUSED_EXPIRED,
    )

    with pytest.raises(
        CapabilityEffectExecutionDenied,
        match="capability_effect_execution_receipt_invalid",
    ) as denied:
        asyncio.run(executor.execute())

    assert denied.value.cleanup.status == "unattempted"
    assert denied.value.terminal_receipt is None
    assert transport.calls == []
    assert transport.cleanup_calls == []


def test_executor_requires_exact_receipt_and_transport_contract():
    receipts = _receipts("types")
    transport = _TwinTransport(receipts)

    with pytest.raises(TypeError, match="exact CapabilityExecutionReceipt"):
        CapabilityEffectExperimentExecutor(object(), transport=transport)
    with pytest.raises(TypeError, match="dispatch and cleanup"):
        CapabilityEffectExperimentExecutor(
            receipts["valid_capability_effect_witness"],
            transport=object(),
        )


def test_wrong_refusal_receipt_fails_closed_after_cleanup():
    receipts = _receipts("wrong-refusal")
    transport = _TwinTransport(
        receipts,
        wrong_receipt_kind="replayed_capability_probe",
        wrong_receipt=receipts["expired_capability_probe"],
    )

    with pytest.raises(
        CapabilityEffectExecutionDenied,
        match="capability_effect_transport_response_invalid",
    ) as denied:
        _run(transport, receipts)

    assert denied.value.category == "transport"
    assert denied.value.cleanup.status == "verified"
    assert denied.value.terminal_receipt.outcome is (
        CapabilityExecutionOutcome.EXECUTION_REFUSED_EXPIRED
    )
    assert len(transport.calls) == 3
    assert len(transport.cleanup_calls) == 1


def test_different_completed_receipt_cannot_replace_exact_witness_gate():
    receipts = _receipts("wrong-witness")
    second_completion = _evaluate(suffix="wrong-witness", now=151.0)
    transport = _TwinTransport(
        receipts,
        wrong_receipt_kind="valid_capability_effect_witness",
        wrong_receipt=second_completion,
    )

    with pytest.raises(
        CapabilityEffectExecutionDenied,
        match="capability_effect_transport_response_invalid",
    ) as denied:
        _run(transport, receipts)

    assert denied.value.cleanup.status == "verified"
    assert denied.value.terminal_receipt is None
    assert len(transport.calls) == 2
    assert len(transport.cleanup_calls) == 1


def test_transport_exception_still_runs_cleanup_and_fails_closed():
    receipts = _receipts("dispatch-failure")
    transport = _TwinTransport(receipts, dispatch_raises_at=3)

    with pytest.raises(
        CapabilityEffectExecutionDenied,
        match="capability_effect_execution_failed",
    ) as denied:
        _run(transport, receipts)

    assert denied.value.category == "execution"
    assert denied.value.cleanup.status == "verified"
    assert denied.value.target_request_possible is True
    assert denied.value.oracle is None
    assert len(transport.calls) == 3
    assert len(transport.cleanup_calls) == 1


def test_cancellation_still_runs_cleanup_and_becomes_a_terminal_denial():
    receipts = _receipts("dispatch-cancellation")
    transport = _TwinTransport(receipts, cancel_at=3)

    with pytest.raises(
        CapabilityEffectExecutionDenied,
        match="capability_effect_execution_failed",
    ) as denied:
        _run(transport, receipts)

    assert denied.value.cleanup.status == "verified"
    assert denied.value.target_request_possible is True
    assert len(transport.calls) == 3
    assert len(transport.cleanup_calls) == 1


def test_uncertain_cleanup_denies_even_a_confirmed_oracle():
    receipts = _receipts("uncertain-cleanup")
    transport = _TwinTransport(receipts, cleanup_status="uncertain")

    with pytest.raises(
        CapabilityEffectExecutionDenied,
        match="capability_effect_cleanup_unverified",
    ) as denied:
        _run(transport, receipts)

    assert denied.value.category == "cleanup"
    assert denied.value.oracle.verdict is (
        CapabilityEffectOracleVerdict.CONFIRMED_ONE_TIME_AUTHORIZED_EFFECT
    )
    assert denied.value.cleanup.status == "uncertain"
    assert denied.value.cleanup.orphaned_owned_state_possible is True
    assert len(transport.cleanup_calls) == 1


def test_cleanup_exception_becomes_uncertain_orphan_risk():
    receipts = _receipts("cleanup-exception")
    transport = _TwinTransport(receipts, cleanup_raises=True)

    with pytest.raises(
        CapabilityEffectExecutionDenied,
        match="capability_effect_cleanup_unverified",
    ) as denied:
        _run(transport, receipts)

    assert denied.value.cleanup.status == "uncertain"
    assert denied.value.cleanup.target_request_may_have_been_sent is True
    assert denied.value.cleanup.orphaned_owned_state_possible is True
    assert denied.value.oracle.verdict is (
        CapabilityEffectOracleVerdict.CONFIRMED_ONE_TIME_AUTHORIZED_EFFECT
    )
    assert len(transport.cleanup_calls) == 1


def test_unattempted_cleanup_after_dispatch_is_rejected_as_uncertain():
    receipts = _receipts("skipped-cleanup")
    transport = _TwinTransport(receipts, cleanup_status="unattempted")

    with pytest.raises(
        CapabilityEffectExecutionDenied,
        match="capability_effect_cleanup_unverified",
    ) as denied:
        _run(transport, receipts)

    assert denied.value.cleanup.status == "uncertain"
    assert denied.value.cleanup.orphaned_owned_state_possible is True
    assert len(transport.cleanup_calls) == 1


@pytest.mark.parametrize(
    "status,decision,effect,projection",
    (
        (403, "denied", EFFECT_VALUE, True),
        (500, "allowed", EFFECT_VALUE, True),
        (200, "allowed", EFFECT_VALUE, False),
        (200, "denied", None, True),
    ),
)
def test_observation_consistency_rejects_impossible_effect_claims(
    status,
    decision,
    effect,
    projection,
):
    receipts = _receipts("observation-consistency")
    receipt = receipts["valid_capability_effect_witness"]
    world = receipt._liveness_decision._admission._contract._owned_world

    with pytest.raises(ValueError, match="capability effect observation"):
        CapabilityEffectObservation.build(
            terminal_receipt=receipt,
            observation_binding=world,
            response_ref=stable_hash("capability_effect_target_response", "x"),
            observation_kind="valid_capability_effect_witness",
            access_decision=decision,
            response_status=status,
            effect=effect,
            target_projection_observed=projection,
        )


def test_oracle_is_content_addressed_pure_and_order_sensitive():
    receipts = _receipts("pure-oracle")
    result = _run(_TwinTransport(receipts), receipts)
    world = receipts[
        "valid_capability_effect_witness"
    ]._liveness_decision._admission._contract._owned_world

    rebuilt = CapabilityEffectOracleEvaluation.build(
        oracle_id=result.oracle.oracle_id,
        observation_binding=world,
        observations=result.effect_observations,
    )

    assert rebuilt == result.oracle
    assert rebuilt.evaluation_id.startswith("capability_effect_oracle_evaluation:")
    with pytest.raises(ValueError, match="observation order"):
        CapabilityEffectOracleEvaluation.build(
            oracle_id=result.oracle.oracle_id,
            observation_binding=world,
            observations=tuple(reversed(result.effect_observations)),
        )


def test_content_addressed_records_reject_public_tampering():
    receipts = _receipts("tamper")
    result = _run(_TwinTransport(receipts), receipts)

    with pytest.raises(ValueError, match="observation is invalid"):
        replace(
            result.effect_observations[0],
            response_status=404,
        )
    with pytest.raises(ValueError, match="oracle evaluation is invalid"):
        replace(
            result.oracle,
            verdict=CapabilityEffectOracleVerdict.REFUTED,
        )
    with pytest.raises(ValueError, match="execution result is invalid"):
        replace(result, execution_effect_authority=False)


def test_denial_accepts_only_valid_r5d6_refusal_terminal_receipts():
    receipts = _receipts("denial-terminal")
    refusal = receipts["inadmissible_capability_probe"]

    denied = CapabilityEffectExecutionDenied(
        "capability_effect_probe_refused",
        category="receipt",
        terminal_receipt=refusal,
    )
    assert denied.terminal_receipt == refusal

    with pytest.raises(ValueError, match="terminal receipt is invalid"):
        CapabilityEffectExecutionDenied(
            "capability_effect_probe_refused",
            category="receipt",
            terminal_receipt=receipts["valid_capability_effect_witness"],
        )


@pytest.mark.parametrize(
    "values",
    (
        {
            "status": "verified",
            "target_requests_sent": 1,
            "target_request_may_have_been_sent": True,
            "orphaned_owned_state_possible": False,
        },
        {
            "status": "uncertain",
            "target_requests_sent": 1,
            "target_request_may_have_been_sent": False,
            "orphaned_owned_state_possible": False,
        },
        {
            "status": "unattempted",
            "target_requests_sent": 1,
            "target_request_may_have_been_sent": False,
            "orphaned_owned_state_possible": False,
        },
    ),
)
def test_cleanup_contract_rejects_inconsistent_status(values):
    with pytest.raises(ValueError, match="cleanup result is invalid"):
        CapabilityCleanupResult(**values)


def test_transport_is_a_protocol_and_module_has_no_client_or_clock_import():
    source_path = Path(effect_module.__file__)
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

    assert not {
        "httpx",
        "requests",
        "socket",
        "subprocess",
        "time",
    } & (imported_modules | imported_from)
    assert getattr(CapabilityEffectTransport, "_is_protocol", False) is True
    assert "dispatch" in CapabilityEffectTransport.__dict__
    assert "cleanup" in CapabilityEffectTransport.__dict__
    assert inspect.iscoroutinefunction(CapabilityEffectTransport.dispatch)
    assert inspect.iscoroutinefunction(CapabilityEffectTransport.cleanup)
    assert "http://" not in source
    assert "https://" not in source


def test_module_is_production_unwired_and_exports_exact_public_surface():
    source_path = Path(effect_module.__file__)
    repository_root = Path(__file__).resolve().parents[2]
    production_consumers = [
        path
        for path in (repository_root / "core").rglob("*.py")
        if path != source_path
        and "capability_effect_evaluation" in path.read_text(encoding="utf-8")
    ]

    assert production_consumers == []
    assert effect_module.__all__ == [
        "CAPABILITY_EFFECT_EXECUTION_ENV",
        "CAPABILITY_EFFECT_EXECUTION_MODE",
        "CapabilityCleanupResult",
        "CapabilityEffectExecutionConfig",
        "CapabilityEffectExecutionDenied",
        "CapabilityEffectExecutionResult",
        "CapabilityEffectExperimentExecutor",
        "CapabilityEffectObservation",
        "CapabilityEffectOracleEvaluation",
        "CapabilityEffectOracleVerdict",
        "CapabilityEffectTransport",
    ]
    assert CAPABILITY_EFFECT_EXECUTION_MODE == (
        "behavioral_capability_effect_execution_v1"
    )
