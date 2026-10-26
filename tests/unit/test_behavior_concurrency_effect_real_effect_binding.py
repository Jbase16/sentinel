"""Post-hoc real-concurrency-effect binding of completed one-click runs."""

import asyncio
from dataclasses import replace
import json

import pytest

from core.behavior.owned_origin_binding_evidence import OwnedOriginBindingEvidence
from core.behavior.real_concurrency_effect_evidence import (
    RealConcurrencyEffectEvidence,
    corroborates,
)
from tests.unit.test_behavior_concurrency_invariant_effect_one_click import (
    _case,
    _dispatcher,
)


AUTHORITY_FLAGS = (
    "finding_authority",
    "promotion_authority",
    "wired_into_production",
)


def _evidence(
    specification,
    *,
    observed_origin=None,
    resource_ref=None,
    declared_limit=None,
):
    contract = specification.binding.fixture.contract
    selected_limit = (
        contract.initial_state.declared_limit
        if declared_limit is None
        else declared_limit
    )
    return RealConcurrencyEffectEvidence.build(
        observed_origin=observed_origin
        if observed_origin is not None
        else specification.transport_spec.target_origin,
        resource_ref=resource_ref
        if resource_ref is not None
        else contract.resource_ref,
        declared_limit=selected_limit,
        observed_consumed=selected_limit + 1,
        commit_receipt_ids=("behavioral-" + "a" * 64, "behavioral-" + "b" * 64),
        cleanup_receipt_id="behavioral-" + "c" * 64,
        overlap_proof_ref="concurrency_overlap:" + "d" * 64,
        proof_ref="real_concurrency_effect:" + "e" * 64,
        artifact_ref="sha256:" + "f" * 64,
        proof_mode="behavioral_real_concurrency_effect_v1",
        observed_at_epoch=100.0,
        runtime_evidence_classification="controlled_owned_lab",
    )


def _owned_evidence(origin):
    return OwnedOriginBindingEvidence.build(
        proven_origin=origin,
        source_receipt_id="behavioral-" + "1" * 64,
        acquisition_receipt_id="behavioral-" + "2" * 64,
        proof_ref="owned_read_proof:" + "3" * 64,
        artifact_ref="sha256:" + "4" * 64,
        proof_mode="behavioral_owned_read_proof_v1",
        observed_at_epoch=100.0,
        runtime_evidence_classification="controlled_owned_lab",
    )


def _assert_no_authority(value):
    for flag in AUTHORITY_FLAGS:
        assert value[flag] is False


def test_corroborating_evidence_crosses_only_real_effect_flag(tmp_path, monkeypatch):
    case = _case(tmp_path, monkeypatch, secure=False)
    module, specification, _, target, executor, *_ = case
    run = asyncio.run(_dispatcher(case, enabled=True).run())
    assert run.candidate is not None
    assert run.real_concurrency_effect_observed is False
    assert run.candidate.real_effect_binding is None
    assert run.candidate.to_dict()["real_concurrency_effect_binding"] is None

    calls_before = list(target.calls)
    counts_before = (executor.claims, executor.sends)
    evidence = _evidence(specification)
    contract = specification.binding.fixture.contract
    assert corroborates(
        evidence,
        confined_origin=specification.transport_spec.target_origin,
        resource_ref=contract.resource_ref,
        declared_limit=contract.initial_state.declared_limit,
    )

    bound = module.bind_real_concurrency_effect(run, evidence, specification)
    assert bound is not run
    assert bound.real_concurrency_effect_observed is True
    assert bound.candidate.real_concurrency_effect_observed is True
    assert bound.candidate.real_effect_binding is not None
    assert bound.candidate.real_effect_binding.corroborated is True
    assert bound.candidate.real_effect_binding.confined_origin == (
        specification.transport_spec.target_origin
    )
    assert bound.candidate.real_effect_binding.resource_ref == contract.resource_ref
    assert (
        bound.candidate.real_effect_binding.declared_limit
        == contract.initial_state.declared_limit
    )
    assert bound.candidate.candidate_id == run.candidate.candidate_id
    assert bound.owned_target_origin_bound is False
    assert bound.candidate.owned_target_origin_bound is False
    assert bound.candidate.origin_binding is None
    assert bound.result.to_dict()["real_concurrency_effect_observed"] is False
    response = bound.execution_response()
    assert response["real_concurrency_effect_observed"] is True
    for value in (bound.to_dict(), bound.candidate.to_dict(), response):
        _assert_no_authority(value)
    assert target.calls == calls_before
    assert (executor.claims, executor.sends) == counts_before


@pytest.mark.parametrize("mismatch", ["origin", "resource_ref", "declared_limit"])
def test_non_corroborating_evidence_records_honest_false(
    tmp_path, monkeypatch, mismatch
):
    case = _case(tmp_path, monkeypatch, secure=False)
    module, specification, *_ = case
    run = asyncio.run(_dispatcher(case, enabled=True).run())
    contract = specification.binding.fixture.contract
    changes = {}
    if mismatch == "origin":
        changes["observed_origin"] = "https://foreign.example.test"
    elif mismatch == "resource_ref":
        changes["resource_ref"] = "owned_resource:" + "0" * 64
    else:
        changes["declared_limit"] = contract.initial_state.declared_limit + 1
    evidence = _evidence(specification, **changes)

    assert not corroborates(
        evidence,
        confined_origin=specification.transport_spec.target_origin,
        resource_ref=contract.resource_ref,
        declared_limit=contract.initial_state.declared_limit,
    )
    bound = module.bind_real_concurrency_effect(run, evidence, specification)
    assert bound.real_concurrency_effect_observed is False
    assert bound.candidate.real_concurrency_effect_observed is False
    assert bound.candidate.real_effect_binding is not None
    assert bound.candidate.real_effect_binding.corroborated is False
    assert bound.candidate.candidate_id == run.candidate.candidate_id
    assert module.ConcurrencyEffectOneClickRun.from_dict(bound.to_dict()) == bound


def test_round_trip_recomputes_real_and_both_bindings(tmp_path, monkeypatch):
    case = _case(tmp_path, monkeypatch, secure=False)
    module, specification, *_ = case
    run = asyncio.run(_dispatcher(case, enabled=True).run())
    evidence = _evidence(specification)
    bound = module.bind_real_concurrency_effect(run, evidence, specification)
    payload = json.loads(json.dumps(bound.to_dict()))
    assert module.ConcurrencyEffectOneClickRun.from_dict(payload) == bound

    effect_binding = bound.candidate.real_effect_binding
    assert effect_binding is not None
    owned_candidate = module.ConcurrencyEffectFindingCandidate.from_result_with_binding(
        run.result,
        _owned_evidence(specification.transport_spec.target_origin),
        specification.transport_spec.target_origin,
    )
    both = replace(
        owned_candidate,
        real_concurrency_effect_observed=effect_binding.corroborated,
        real_effect_binding=effect_binding,
    )
    both_payload = json.loads(json.dumps(both.to_dict()))
    rebuilt = module.ConcurrencyEffectFindingCandidate.from_dict(
        both_payload, run.result
    )
    assert rebuilt.to_dict() == both_payload
    assert rebuilt.owned_target_origin_bound is True
    assert rebuilt.real_concurrency_effect_observed is True


def test_round_trip_refuses_forged_real_effect_binding(tmp_path, monkeypatch):
    case = _case(tmp_path, monkeypatch, secure=False)
    module, specification, *_ = case
    run = asyncio.run(_dispatcher(case, enabled=True).run())
    bound = module.bind_real_concurrency_effect(
        run, _evidence(specification), specification
    )
    payload = json.loads(json.dumps(bound.to_dict()))

    for change in (
        "run_flag",
        "candidate_flag",
        "candidate_flag_integer",
        "missing_binding",
        "bad_evidence",
        "foreign_resource",
    ):
        forged = json.loads(json.dumps(payload))
        if change == "run_flag":
            forged["real_concurrency_effect_observed"] = False
        elif change == "candidate_flag":
            forged["candidate"]["real_concurrency_effect_observed"] = False
        elif change == "candidate_flag_integer":
            forged["candidate"]["real_concurrency_effect_observed"] = 1
        elif change == "missing_binding":
            forged["candidate"]["real_concurrency_effect_binding"] = None
        elif change == "bad_evidence":
            forged["candidate"]["real_concurrency_effect_binding"][
                "real_concurrency_effect_evidence"
            ]["evidence_root"] = "0" * 64
        else:
            forged["candidate"]["real_concurrency_effect_binding"][
                "resource_ref"
            ] = "owned_resource:" + "0" * 64
        with pytest.raises((TypeError, ValueError)):
            module.ConcurrencyEffectOneClickRun.from_dict(forged)


def test_binding_guards_and_non_candidates_return_unchanged(tmp_path, monkeypatch):
    case = _case(tmp_path, monkeypatch, secure=False)
    module, specification, *_ = case
    run = asyncio.run(_dispatcher(case, enabled=True).run())
    evidence = _evidence(specification)

    other_path = tmp_path / "other"
    other_path.mkdir()
    other_specification = _case(other_path, monkeypatch, secure=False)[1]
    assert other_specification.specification_id != specification.specification_id
    with pytest.raises(ValueError, match="does not match"):
        module.bind_real_concurrency_effect(run, evidence, other_specification)

    for arguments in (
        (object(), evidence, specification),
        (run, object(), specification),
        (run, evidence, object()),
    ):
        with pytest.raises(TypeError):
            module.bind_real_concurrency_effect(*arguments)

    disabled = module.ConcurrencyEffectOneClickRun.disabled(specification)
    assert (
        module.bind_real_concurrency_effect(disabled, evidence, specification)
        is disabled
    )
    assert disabled.real_concurrency_effect_observed is False

    secure_case = _case(tmp_path / "secure", monkeypatch, secure=True)
    secure_run = asyncio.run(_dispatcher(secure_case, enabled=True).run())
    assert secure_run.candidate is None
    assert (
        module.bind_real_concurrency_effect(
            secure_run, _evidence(secure_case[1]), secure_case[1]
        )
        is secure_run
    )


def test_dispatcher_remains_unbound_and_crossings_do_not_compose(
    tmp_path, monkeypatch
):
    case = _case(tmp_path, monkeypatch, secure=False)
    module, specification, *_ = case
    run = asyncio.run(_dispatcher(case, enabled=True).run())
    assert run.real_concurrency_effect_observed is False
    assert run.candidate.real_concurrency_effect_observed is False
    assert run.candidate.real_effect_binding is None
    assert run.to_dict()["real_concurrency_effect_observed"] is False
    assert run.execution_response()["real_concurrency_effect_observed"] is False

    origin_bound = module.bind_owned_origin(
        run,
        _owned_evidence(specification.transport_spec.target_origin),
        specification,
    )
    assert origin_bound.owned_target_origin_bound is True
    assert origin_bound.real_concurrency_effect_observed is False
    assert origin_bound.candidate.real_effect_binding is None

    effect_bound = module.bind_real_concurrency_effect(
        run, _evidence(specification), specification
    )
    assert effect_bound.real_concurrency_effect_observed is True
    assert effect_bound.owned_target_origin_bound is False
    assert effect_bound.candidate.origin_binding is None
