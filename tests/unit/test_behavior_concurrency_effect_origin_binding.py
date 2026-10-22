"""Post-hoc owned-origin binding of completed concurrency one-click runs."""

import asyncio
import json

import pytest

from core.behavior.owned_origin_binding_evidence import (
    OwnedOriginBindingEvidence,
    binds_to,
)
from tests.unit.test_behavior_concurrency_invariant_effect_one_click import (
    ORIGIN,
    _case,
    _dispatcher,
)


AUTHORITY_FLAGS = (
    "finding_authority",
    "promotion_authority",
    "real_concurrency_effect_observed",
    "wired_into_production",
)


def _evidence(origin=ORIGIN):
    return OwnedOriginBindingEvidence.build(
        proven_origin=origin,
        source_receipt_id="behavioral-" + "a" * 64,
        acquisition_receipt_id="behavioral-" + "b" * 64,
        proof_ref="owned_read_proof:" + "c" * 64,
        artifact_ref="sha256:" + "d" * 64,
        proof_mode="behavioral_owned_read_proof_v1",
        observed_at_epoch=100.0,
        runtime_evidence_classification="controlled_owned_lab",
    )


def _assert_no_authority(value):
    for flag in AUTHORITY_FLAGS:
        assert value[flag] is False


def test_dispatcher_remains_unbound_and_binding_crosses_only_on_match(
    tmp_path, monkeypatch
):
    case = _case(tmp_path, monkeypatch, secure=False)
    module, spec, _, target, executor, *_ = case
    run = asyncio.run(_dispatcher(case, enabled=True).run())
    assert run.candidate is not None
    assert run.owned_target_origin_bound is False
    assert run.candidate.origin_binding is None
    assert run.candidate.to_dict()["owned_origin_binding"] is None
    assert run.to_dict()["owned_target_origin_bound"] is False
    _assert_no_authority(run.to_dict())
    _assert_no_authority(run.candidate.to_dict())

    calls_before = list(target.calls)
    counts_before = (executor.claims, executor.sends)
    evidence = _evidence()
    bound = module.bind_owned_origin(run, evidence, spec)
    assert bound is not run
    assert binds_to(evidence, spec.transport_spec.target_origin) is True
    assert bound.owned_target_origin_bound is True
    assert bound.candidate.owned_target_origin_bound is True
    assert bound.candidate.candidate_id == run.candidate.candidate_id
    assert bound.to_dict()["owned_target_origin_bound"] is True
    assert bound.candidate.to_dict()["owned_origin_binding"] is not None
    response = bound.execution_response()
    assert response["owned_target_origin_bound"] is True
    for value in (bound.to_dict(), bound.candidate.to_dict(), response):
        _assert_no_authority(value)
    assert bound.result.to_dict()["owned_target_origin_bound"] is False
    assert spec.to_dict()["owned_target_origin_bound"] is False
    assert target.calls == calls_before
    assert (executor.claims, executor.sends) == counts_before


def test_non_matching_origin_records_honest_false(tmp_path, monkeypatch):
    case = _case(tmp_path, monkeypatch, secure=False)
    module, spec, *_ = case
    run = asyncio.run(_dispatcher(case, enabled=True).run())
    evidence = _evidence("https://app.sentinel-lab.test")
    bound = module.bind_owned_origin(run, evidence, spec)
    assert binds_to(evidence, spec.transport_spec.target_origin) is False
    assert bound.owned_target_origin_bound is False
    assert bound.candidate.owned_target_origin_bound is False
    assert bound.candidate.origin_binding is not None
    assert bound.candidate.candidate_id == run.candidate.candidate_id
    assert module.ConcurrencyEffectOneClickRun.from_dict(bound.to_dict()) == bound


def test_round_trip_recomputes_binding_and_refuses_forged_flags(tmp_path, monkeypatch):
    case = _case(tmp_path, monkeypatch, secure=False)
    module, spec, *_ = case
    run = asyncio.run(_dispatcher(case, enabled=True).run())
    bound = module.bind_owned_origin(run, _evidence(), spec)
    payload = json.loads(json.dumps(bound.to_dict()))
    assert module.ConcurrencyEffectOneClickRun.from_dict(payload) == bound

    for change in (
        "run_flag",
        "candidate_flag",
        "candidate_flag_integer",
        "missing_binding",
        "bad_evidence",
        "wrong_origin_evidence",
    ):
        forged = json.loads(json.dumps(payload))
        if change == "run_flag":
            forged["owned_target_origin_bound"] = False
        elif change == "candidate_flag":
            forged["candidate"]["owned_target_origin_bound"] = False
        elif change == "candidate_flag_integer":
            forged["candidate"]["owned_target_origin_bound"] = 1
        elif change == "missing_binding":
            forged["candidate"]["owned_origin_binding"] = None
        elif change == "bad_evidence":
            forged["candidate"]["owned_origin_binding"]["proven_origin_evidence"][
                "evidence_root"
            ] = "0" * 64
        else:
            forged["candidate"]["owned_origin_binding"]["proven_origin_evidence"] = (
                _evidence("https://app.sentinel-lab.test").to_dict()
            )
        with pytest.raises((TypeError, ValueError)):
            module.ConcurrencyEffectOneClickRun.from_dict(forged)


def test_specification_mismatch_and_invalid_inputs_are_refused(tmp_path, monkeypatch):
    case = _case(tmp_path, monkeypatch, secure=False)
    module, spec, *_ = case
    run = asyncio.run(_dispatcher(case, enabled=True).run())
    other_path = tmp_path / "other"
    other_path.mkdir()
    other_spec = _case(other_path, monkeypatch, secure=False)[1]
    assert other_spec.specification_id != spec.specification_id
    with pytest.raises(ValueError, match="does not match"):
        module.bind_owned_origin(run, _evidence(), other_spec)
    for arguments in (
        (object(), _evidence(), spec),
        (run, object(), spec),
        (run, _evidence(), object()),
    ):
        with pytest.raises(TypeError):
            module.bind_owned_origin(*arguments)


def test_non_candidate_and_disabled_runs_cannot_bind(tmp_path, monkeypatch):
    case = _case(tmp_path, monkeypatch, secure=True)
    module, spec, *_ = case
    secure_run = asyncio.run(_dispatcher(case, enabled=True).run())
    assert secure_run.candidate is None
    assert module.bind_owned_origin(secure_run, _evidence(), spec) is secure_run
    assert secure_run.owned_target_origin_bound is False

    disabled = module.ConcurrencyEffectOneClickRun.disabled(spec)
    assert module.bind_owned_origin(disabled, _evidence(), spec) is disabled
    assert disabled.candidate is None
    assert disabled.owned_target_origin_bound is False
