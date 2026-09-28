"""R5E2 owned context and operator-supplied current-capture proof."""

from dataclasses import replace
import json

import pytest

from core.behavior.normalize import stable_hash
from core.behavior.workflow_invariant_binding import (
    WorkflowBindingDenied,
    WorkflowCaptureProvenance,
    WorkflowInvariantBinding,
    evaluate_offline,
)
from core.behavior.workflow_invariant_contract import WorkflowInvariantOutcome
from tests.unit.test_behavior_workflow_invariant_contract import fixture

ORIGIN = "https://owned.example.test"


def capture(owned=None, **changes):
    owned = owned or fixture()
    values = {
        "contract_ref": owned.contract.contract_id,
        "world_binding_ref": owned.world.binding_id,
        "account_ref": owned.contract.account_ref,
        "tenant_ref": owned.contract.tenant_ref,
        "tenant_ownership_ref": owned.contract.tenant_ownership_ref,
        "origin_ref": stable_hash("behavioral_capture_target", ORIGIN),
        "capture_generation_ref": stable_hash(
            "workflow_capture_generation", "current-1"
        ),
        "captured_at_index": 10,
        "valid_until_index": 20,
        "operation_ids": tuple(op.operation_id for op in owned.contract.operations),
        "source_evidence_refs": tuple(
            stable_hash("source_evidence", {"index": op.index, "capture": 1})
            for op in owned.contract.operations
        ),
    }
    return WorkflowCaptureProvenance(**{**values, **changes})


def binding(**values):
    owned = fixture(**values)
    return WorkflowInvariantBinding.build(
        fixture=owned, capture=capture(owned), target_origin=ORIGIN
    )


@pytest.mark.parametrize(
    "secure,outcome",
    [
        (False, WorkflowInvariantOutcome.INVARIANT_VIOLATED),
        (True, WorkflowInvariantOutcome.OPERATION_REFUSED),
    ],
)
def test_twins_evaluate_offline_with_owned_fresh_binding(secure, outcome):
    bound = binding(secure=secure)
    result = evaluate_offline(bound, bound.capture, at_index=10)
    assert result.decision.outcome is outcome
    assert result.to_dict()["observed_target_effect"] is False
    assert result.to_dict()["promotion_authority"] is False
    assert evaluate_offline(bound, bound.capture, at_index=10) == result


def test_serialization_preserves_exact_owned_binding():
    bound = binding()
    assert (
        WorkflowInvariantBinding.from_dict(json.loads(json.dumps(bound.to_dict())))
        == bound
    )
    assert WorkflowCaptureProvenance.from_dict(bound.capture.to_dict()) == bound.capture


@pytest.mark.parametrize(
    "field,prefix",
    [
        ("contract_ref", "workflow_invariant_contract"),
        ("world_binding_ref", "experiment_world_binding"),
        ("account_ref", "experiment_persona"),
        ("tenant_ref", "owned_tenant"),
        ("tenant_ownership_ref", "ownership_proof"),
        ("origin_ref", "behavioral_capture_target"),
    ],
)
def test_binding_refuses_cross_context_capture(field, prefix):
    owned = fixture()
    wrong = capture(owned, **{field: stable_hash(prefix, "other")})
    with pytest.raises(WorkflowBindingDenied):
        WorkflowInvariantBinding.build(
            fixture=owned, capture=wrong, target_origin=ORIGIN
        )


@pytest.mark.parametrize("at_index", [9, 20, 21, -1, True, 10.0])
def test_stale_and_invalid_current_index_refused(at_index):
    bound = binding()
    with pytest.raises(WorkflowBindingDenied):
        evaluate_offline(bound, bound.capture, at_index=at_index)


@pytest.mark.parametrize(
    "field", ["capture_generation_ref", "source_evidence_refs", "operation_ids"]
)
def test_changed_current_capture_refused_even_inside_fresh_window(field):
    bound = binding()
    changes = {
        "capture_generation_ref": stable_hash("workflow_capture_generation", "rotated"),
        "source_evidence_refs": tuple(
            stable_hash("source_evidence", {"changed": i}) for i in range(2)
        ),
        "operation_ids": bound.capture.operation_ids[::-1],
    }
    changed = replace(bound.capture, **{field: changes[field]})
    with pytest.raises(WorkflowBindingDenied):
        evaluate_offline(bound, changed, at_index=11)


@pytest.mark.parametrize(
    "mutation",
    [
        "forged_binding",
        "forged_capture",
        "authority",
        "missing_source",
        "boolean_window",
    ],
)
def test_forged_malformed_serialization_refused(mutation):
    bound = binding()
    value = bound.to_dict()
    if mutation == "forged_binding":
        value["binding_id"] = stable_hash("workflow_invariant_binding", "forged")
    elif mutation == "forged_capture":
        value["capture"]["capture_id"] = stable_hash(
            "workflow_capture_provenance", "forged"
        )
    elif mutation == "authority":
        value["executable"] = True
    elif mutation == "missing_source":
        value["capture"]["source_evidence_refs"] = []
    else:
        value["capture"]["captured_at_index"] = True
    with pytest.raises(ValueError):
        WorkflowInvariantBinding.from_dict(value)


def test_forged_runtime_context_revalidated_before_offline_result():
    bound = binding()
    object.__setattr__(
        bound.fixture.world, "persona_ref", stable_hash("experiment_persona", "bob")
    )
    with pytest.raises(ValueError):
        evaluate_offline(bound, bound.capture, at_index=10)


def test_refreshed_capture_needs_a_new_binding():
    bound = binding()
    refreshed = replace(
        bound.capture,
        capture_generation_ref=stable_hash("workflow_capture_generation", "current-2"),
        captured_at_index=20,
        valid_until_index=30,
    )
    renewed = WorkflowInvariantBinding.build(
        fixture=bound.fixture, capture=refreshed, target_origin=ORIGIN
    )
    assert renewed.binding_id != bound.binding_id
    assert (
        evaluate_offline(renewed, refreshed, at_index=20).decision.outcome
        is WorkflowInvariantOutcome.INVARIANT_VIOLATED
    )
