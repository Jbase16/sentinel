"""R5F2 exact owned shared-world binding and logical freshness proofs."""

from copy import deepcopy
from dataclasses import replace

import pytest

from core.behavior.concurrency_invariant_binding import (
    ConcurrencyBindingDenied,
    ConcurrencyCaptureProvenance,
    ConcurrencyInvariantBinding,
    ConcurrencyOfflineEvaluation,
    evaluate_offline,
    validate_current_capture,
)
from core.behavior.concurrency_invariant_contract import ConcurrencyOutcome
from core.behavior.normalize import stable_hash
from tests.unit.test_behavior_concurrency_invariant_contract import case


def binding(*, secure=False, limit=1):
    fixture, schedule = case(secure=secure, limit=limit)
    contract = fixture.contract
    capture = ConcurrencyCaptureProvenance(
        contract_ref=contract.contract_id,
        world_binding_refs=tuple(world.binding_id for world in fixture.worlds),
        actor_refs=tuple(world.persona_ref for world in fixture.worlds),
        resource_ref=contract.resource_ref,
        tenant_ref=contract.tenant_ref,
        tenant_ownership_ref=contract.tenant_ownership_ref,
        capture_generation_ref=stable_hash("concurrency_capture_generation", "first"),
        captured_at_index=10,
        valid_until_index=20,
        operation_ids=tuple(op.operation_id for op in contract.operations),
        source_evidence_refs=tuple(
            stable_hash("source_evidence", i) for i in range(len(contract.operations))
        ),
    )
    return ConcurrencyInvariantBinding.build(fixture=fixture, capture=capture), schedule


@pytest.mark.parametrize(
    "secure,limit,outcome,race",
    [
        (False, 1, ConcurrencyOutcome.INVARIANT_VIOLATED, True),
        (True, 1, ConcurrencyOutcome.OPERATION_REFUSED, False),
        (False, 2, ConcurrencyOutcome.INVARIANT_HELD, False),
    ],
)
def test_offline_binding_twins(secure, limit, outcome, race):
    bound, schedule = binding(secure=secure, limit=limit)
    result = evaluate_offline(bound, bound.capture, schedule, at_index=10)
    assert result.decision.outcome is outcome
    assert result.decision.race_confirmed is race
    assert result.to_dict()["observed_target_effect"] is False
    assert result.to_dict()["target_requests_sent"] == 0
    assert ConcurrencyOfflineEvaluation.from_dict(result.to_dict()) == result


def test_freshness_and_exact_owned_binding_fail_closed():
    bound, schedule = binding()
    validate_current_capture(bound, bound.capture, 19)
    for index in (9, 20, True):
        with pytest.raises(ConcurrencyBindingDenied):
            evaluate_offline(bound, bound.capture, schedule, at_index=index)
    changed = replace(
        bound.capture,
        capture_generation_ref=stable_hash("concurrency_capture_generation", "other"),
    )
    with pytest.raises(ConcurrencyBindingDenied):
        evaluate_offline(bound, changed, schedule, at_index=11)
    with pytest.raises(ConcurrencyBindingDenied):
        ConcurrencyInvariantBinding.build(
            fixture=bound.fixture,
            capture=replace(
                bound.capture, resource_ref=stable_hash("owned_resource", "other")
            ),
        )
    with pytest.raises(ConcurrencyBindingDenied):
        ConcurrencyInvariantBinding.build(
            fixture=bound.fixture,
            capture=replace(
                bound.capture, actor_refs=tuple(reversed(bound.capture.actor_refs))
            ),
        )


def test_capture_binding_and_evaluation_round_trip_and_tamper_refusal():
    bound, schedule = binding()
    result = evaluate_offline(bound, bound.capture, schedule, at_index=11)
    assert (
        ConcurrencyCaptureProvenance.from_dict(bound.capture.to_dict()) == bound.capture
    )
    assert ConcurrencyInvariantBinding.from_dict(bound.to_dict()) == bound
    assert ConcurrencyOfflineEvaluation.from_dict(result.to_dict()) == result
    capture_value = deepcopy(bound.capture.to_dict())
    capture_value["capture_id"] = stable_hash("concurrency_capture_provenance", "wrong")
    with pytest.raises(ConcurrencyBindingDenied):
        ConcurrencyCaptureProvenance.from_dict(capture_value)
    binding_value = deepcopy(bound.to_dict())
    binding_value["finding_authority"] = True
    with pytest.raises(ConcurrencyBindingDenied):
        ConcurrencyInvariantBinding.from_dict(binding_value)
    evaluation_value = deepcopy(result.to_dict())
    evaluation_value["observed_target_effect"] = True
    with pytest.raises(ConcurrencyBindingDenied):
        ConcurrencyOfflineEvaluation.from_dict(evaluation_value)
