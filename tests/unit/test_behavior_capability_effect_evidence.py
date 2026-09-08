"""R5D10 durable capability-effect evidence and replay-leak predicate tests."""

from __future__ import annotations

from copy import deepcopy
import hashlib
import json

import pytest

import tests.unit.test_behavior_capability_effect_evaluation as r5d8_fixtures
from core.behavior.capability_effect_evidence import (
    CAPABILITY_EFFECT_ADAPTER_CONTRACT_VERSION,
    CAPABILITY_EFFECT_EVIDENCE_MAX_BYTES,
    CapabilityEffectEvidence,
    CapabilityEffectExecutionPolicySnapshot,
    CapabilityEffectProducerIdentity,
    build_capability_effect_evidence,
    evaluate_replay_leak,
    replay_leak_finding_material,
)
from core.behavior.capability_effect_evaluation import CapabilityEffectOracleVerdict
from core.behavior.normalize import stable_hash
from core.identity.context import AssessmentIdentityContext, CredentialFreshness


ORIGIN = "https://controlled.example.test"
ROOT_DOMAIN = b"sentinelforge:capability-effect-evidence:v1\x00"
TOP_LEVEL_FIELDS = {
    "schema_version",
    "adapter_contract_version",
    "evidence_root",
    "source_execution_id",
    "source_receipt_id",
    "execution_admission_ref",
    "assessment_session_id",
    "identity_binding",
    "target_origin",
    "specification_ref",
    "operation_ref",
    "capability_ref",
    "experiment_world_ref",
    "observations",
    "terminal_receipts",
    "oracle",
    "oracle_evaluation_ref",
    "cleanup",
    "execution_policy",
    "conduct_provenance_root",
    "producer_identity",
    "observed_at_epoch",
    "runtime_evidence_classification",
}
OBSERVATION_FIELDS = {
    "schema_version",
    "observation_id",
    "receipt_ref",
    "capability_ref",
    "observation_binding_id",
    "response_ref",
    "observation_kind",
    "receipt_outcome",
    "access_decision",
    "response_status",
    "effect_ref",
    "protected_effect_observed",
    "target_projection_observed",
}
TERMINAL_RECEIPT_FIELDS = {
    "schema_version",
    "receipt_id",
    "capability_ref",
    "liveness_ref",
    "consumption_ref",
    "observed_epoch",
    "outcome",
    "mode",
    "target_dispatch_authority",
    "execution_effect_authority",
    "finding_promotion_authority",
    "target_cleanup_authority",
}


def _canonical_bytes(value):
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _independent_root(value):
    preimage = deepcopy(value)
    preimage.pop("evidence_root", None)
    return hashlib.sha256(ROOT_DOMAIN + _canonical_bytes(preimage)).hexdigest()


def _identity(session_id="session-r5d10", *, persona_id):
    return AssessmentIdentityContext(
        session_id=session_id,
        authorization_envelope_id="authorization-r5d10",
        authorization_envelope_ref=f"authorization_envelope:{'1' * 64}",
        target_origin=ORIGIN,
        target_reset_epoch=0,
        world_id=persona_id,
        persona_id=persona_id,
        target_actor_id="actor:unresolved",
        tenant_id="tenant:unresolved",
        credential_source_ref="credential:unresolved",
        credential_epoch=0,
        credential_freshness=CredentialFreshness.UNKNOWN,
        resource_id=stable_hash("resource", "r5d10"),
        representation_id=stable_hash("representation", "r5d10"),
    ).to_dict()


def _policy(**overrides):
    values = {
        "policy_ref": stable_hash(
            "capability_effect_execution_policy",
            {"fixture": "r5d10"},
        ),
        "primary_execution_gate_enabled": True,
        "capability_effect_execution_gate_enabled": True,
        "authorization_admitted": True,
        "persona_admitted": True,
        "ownership_admitted": True,
        "origin_admitted": True,
        "policy_admitted": True,
        "budget_admitted": True,
        "receipt_admitted": True,
        "cleanup_required": True,
    }
    values.update(overrides)
    return CapabilityEffectExecutionPolicySnapshot.build(**values)


def _producer(source_state="clean"):
    return CapabilityEffectProducerIdentity.build(
        producer_name="sentinelforge",
        build_id="r5d10-test-build",
        build_sha="a" * 40 if source_state != "unknown" else "unknown",
        source_state=source_state,
    )


def _evidence_from_result(
    result,
    *,
    persona_id,
    policy=None,
    session_id="session-r5d10",
):
    export = result.evidence_export()
    return build_capability_effect_evidence(
        execution_export=export,
        source_receipt_id=f"behavioral-{'2' * 64}",
        execution_admission_ref=stable_hash(
            "capability_effect_execution_admission",
            {"fixture": "r5d10"},
        ),
        assessment_session_id=session_id,
        identity_binding=_identity(
            session_id,
            persona_id=persona_id,
        ),
        target_origin=ORIGIN,
        specification_ref=stable_hash(
            "capability_effect_one_click_specification",
            {"fixture": "r5d10"},
        ),
        operation_ref=stable_hash(
            "capability_operation",
            {"fixture": "r5d10"},
        ),
        execution_policy=policy or _policy(),
        conduct_provenance_root="3" * 64,
        producer_identity=_producer(),
        observed_at_epoch=1_788_800_000.25,
        runtime_evidence_classification="controlled_in_memory_twin",
    )


def _run_result(*, leak_kind=None, transport=None, suffix="r5d10"):
    receipts = r5d8_fixtures._receipts(suffix)
    twin = transport or r5d8_fixtures._TwinTransport(
        receipts,
        leak_kind=leak_kind,
    )
    return r5d8_fixtures._run(twin, receipts), twin


def test_vulnerable_result_exports_and_round_trips_without_changing_matrix():
    result, twin = _run_result(
        leak_kind="replayed_capability_probe",
        suffix="r5d10-vulnerable",
    )
    export = result.evidence_export()

    assert result.oracle.verdict is CapabilityEffectOracleVerdict.REFUTED
    assert [call["observation_kind"] for call in twin.calls] == list(
        r5d8_fixtures.OBSERVATION_KINDS
    )
    assert len(twin.calls) == 5
    assert len(twin.cleanup_calls) == 1
    assert export["experiment_world_ref"].startswith("world:")
    assert len(export["terminal_receipts"]) == 5

    evidence = _evidence_from_result(
        result,
        persona_id="r5d6-r5d10-vulnerable",
    )
    value = evidence.to_dict()

    assert set(value) == TOP_LEVEL_FIELDS
    assert all(set(item) == OBSERVATION_FIELDS for item in value["observations"])
    assert all(
        set(item) == TERMINAL_RECEIPT_FIELDS for item in value["terminal_receipts"]
    )
    assert evidence.evidence_root == _independent_root(value)
    assert len(evidence.evidence_root) == 64
    assert not evidence.evidence_root.startswith("sha256:")
    assert CapabilityEffectEvidence.from_mapping(value) == evidence
    assert (
        CapabilityEffectEvidence.from_json_bytes(evidence.to_json_bytes()) == evidence
    )
    assert evidence.to_json_bytes() == _canonical_bytes(value)
    assert len(evidence.to_json_bytes()) < CAPABILITY_EFFECT_EVIDENCE_MAX_BYTES

    evaluation = evaluate_replay_leak(evidence)
    assert evaluation.eligible is True
    assert evaluation.reason_code == "eligible_replay_leak"
    assert evaluation.failed_clauses == ()
    material = replay_leak_finding_material(evidence)
    assert material == replay_leak_finding_material(evidence)
    assert material["title"] == (
        "Protected effect exposed by replay after capability consumption"
    )
    assert material["confirmation_level"] == "confirmed"
    assert material["severity"] == "medium"
    assert material["metadata"]["impact_assessment"] == "unassessed"
    assert material["metadata"]["evidence_trust_boundary"] == (
        "authenticated_local_execution_producer"
    )
    serialized_material = _canonical_bytes(material)
    for forbidden in (
        b"promotion_gate",
        b"promotion_enabled",
        b"retry_count",
        b"processing_timestamp",
        b"finding_confirmed",
    ):
        assert forbidden not in serialized_material
    assert len(twin.calls) == 5
    assert len(twin.cleanup_calls) == 1


def test_secure_completed_evidence_is_retained_but_not_a_replay_leak():
    result, twin = _run_result(suffix="r5d10-secure")
    evidence = _evidence_from_result(result, persona_id="r5d6-r5d10-secure")

    assert result.oracle.verdict is (
        CapabilityEffectOracleVerdict.CONFIRMED_ONE_TIME_AUTHORIZED_EFFECT
    )
    assert len(twin.calls) == 5
    assert len(twin.cleanup_calls) == 1
    evaluation = evaluate_replay_leak(evidence)
    assert evaluation.eligible is False
    assert evaluation.reason_code == "secure_one_time_authorized_effect"
    assert 5 in evaluation.failed_clauses
    with pytest.raises(ValueError, match="not a replay leak"):
        replay_leak_finding_material(evidence)


@pytest.mark.parametrize(
    "effect",
    (False, 0, "", [], {}),
    ids=("false", "zero", "empty-string", "empty-list", "empty-object"),
)
def test_false_zero_and_empty_effects_remain_present(monkeypatch, effect):
    monkeypatch.setattr(r5d8_fixtures, "EFFECT_VALUE", effect)
    suffix = f"r5d10-presence-{type(effect).__name__}"
    result, _ = _run_result(
        leak_kind="replayed_capability_probe",
        suffix=suffix,
    )
    evidence = _evidence_from_result(result, persona_id=f"r5d6-{suffix}")

    witness, replay = evidence.observations[1:3]
    assert witness["effect_ref"] is not None
    assert replay["effect_ref"] == witness["effect_ref"]
    assert evaluate_replay_leak(evidence).eligible is True


class _ChangedReplayTransport(r5d8_fixtures._TwinTransport):
    def __init__(self, receipts, *, replay_effect):
        super().__init__(receipts, leak_kind="replayed_capability_probe")
        self.replay_effect = replay_effect

    async def dispatch(self, request):
        status, response = await super().dispatch(request)
        if request["observation_kind"] == "replayed_capability_probe":
            response = {**response, "effect": self.replay_effect}
        return status, response


def test_nonmatching_refuted_shapes_fail_the_exact_bounded_claim():
    receipts = r5d8_fixtures._receipts("r5d10-different-effect")
    different = _ChangedReplayTransport(
        receipts,
        replay_effect={"effect": "different"},
    )
    result = r5d8_fixtures._run(different, receipts)
    mismatch = evaluate_replay_leak(
        _evidence_from_result(
            result,
            persona_id="r5d6-r5d10-different-effect",
        )
    )
    assert mismatch.eligible is False
    assert mismatch.reason_code == "replay_effect_reference_mismatch"

    receipts = r5d8_fixtures._receipts("r5d10-replay-without-effect")
    absent = _ChangedReplayTransport(receipts, replay_effect=None)
    result = r5d8_fixtures._run(absent, receipts)
    missing = evaluate_replay_leak(
        _evidence_from_result(
            result,
            persona_id="r5d6-r5d10-replay-without-effect",
        )
    )
    assert missing.eligible is False
    assert missing.reason_code == "replay_protected_effect_missing"

    baseline_result, _ = _run_result(
        leak_kind="no_capability_baseline",
        suffix="r5d10-baseline-leak",
    )
    baseline = evaluate_replay_leak(
        _evidence_from_result(
            baseline_result,
            persona_id="r5d6-r5d10-baseline-leak",
        )
    )
    assert baseline.eligible is False
    assert 7 in baseline.failed_clauses
    assert 8 in baseline.failed_clauses


def test_completed_refuted_result_with_uncertainty_is_retained_but_not_promoted():
    receipts = r5d8_fixtures._receipts("r5d10-refuted-uncertain")
    twin = r5d8_fixtures._TwinTransport(
        receipts,
        leak_kind="no_capability_baseline",
        missing_projection_kind="replayed_capability_probe",
    )
    result = r5d8_fixtures._run(twin, receipts)

    assert result.oracle.verdict is CapabilityEffectOracleVerdict.REFUTED
    assert result.oracle.uncertainty_reasons
    evidence = _evidence_from_result(
        result,
        persona_id="r5d6-r5d10-refuted-uncertain",
    )
    evaluation = evaluate_replay_leak(evidence)

    assert (
        CapabilityEffectEvidence.from_json_bytes(evidence.to_json_bytes()) == evidence
    )
    assert evaluation.eligible is False
    assert 5 in evaluation.failed_clauses
    assert 9 in evaluation.failed_clauses


def test_execution_policy_is_strict_and_false_gate_fails_clause_eleven():
    result, _ = _run_result(
        leak_kind="replayed_capability_probe",
        suffix="r5d10-gate",
    )
    evidence = _evidence_from_result(
        result,
        persona_id="r5d6-r5d10-gate",
        policy=_policy(budget_admitted=False),
    )
    evaluation = evaluate_replay_leak(evidence)

    assert evaluation.eligible is False
    assert evaluation.reason_code == "source_validation_failed"
    assert evaluation.failed_clauses == (11,)
    policy = evidence.to_dict()["execution_policy"]
    assert "promotion_gate" not in policy
    assert (
        CapabilityEffectExecutionPolicySnapshot.from_mapping(policy).to_dict() == policy
    )

    unknown = {**policy, "promotion_gate": False}
    with pytest.raises(ValueError, match="fields"):
        CapabilityEffectExecutionPolicySnapshot.from_mapping(unknown)


@pytest.mark.parametrize("source_state", ("clean", "dirty", "unknown"))
def test_producer_build_identity_is_explicit_and_content_addressed(source_state):
    producer = _producer(source_state)
    assert CapabilityEffectProducerIdentity.from_mapping(producer.to_dict()) == producer
    if source_state == "unknown":
        assert producer.build_sha == "unknown"
    else:
        assert producer.build_sha == "a" * 40


def test_bytes_parser_rejects_noncanonical_duplicate_oversize_and_bad_types():
    result, _ = _run_result(
        leak_kind="replayed_capability_probe",
        suffix="r5d10-parser",
    )
    evidence = _evidence_from_result(result, persona_id="r5d6-r5d10-parser")
    encoded = evidence.to_json_bytes()

    with pytest.raises(TypeError, match="must be bytes"):
        CapabilityEffectEvidence.from_json_bytes(encoded.decode())
    with pytest.raises(ValueError, match="not canonical"):
        CapabilityEffectEvidence.from_json_bytes(b" " + encoded)
    with pytest.raises(ValueError, match="not canonical"):
        CapabilityEffectEvidence.from_json_bytes(
            json.dumps(evidence.to_dict(), ensure_ascii=False).encode()
        )
    with pytest.raises(ValueError, match="duplicate"):
        CapabilityEffectEvidence.from_json_bytes(
            encoded.replace(b"{", b'{"schema_version":1,', 1)
        )
    with pytest.raises(ValueError, match="256 KiB"):
        CapabilityEffectEvidence.from_json_bytes(
            b"{" + b" " * CAPABILITY_EFFECT_EVIDENCE_MAX_BYTES
        )
    with pytest.raises(ValueError, match="JSON is invalid"):
        CapabilityEffectEvidence.from_json_bytes(b"\xff")
    with pytest.raises(ValueError, match="invalid JSON constant"):
        CapabilityEffectEvidence.from_json_bytes(b'{"value":NaN}')


def test_mapping_parser_rejects_unknown_missing_bad_root_and_effect_flags():
    result, _ = _run_result(
        leak_kind="replayed_capability_probe",
        suffix="r5d10-mapping-parser",
    )
    value = _evidence_from_result(
        result,
        persona_id="r5d6-r5d10-mapping-parser",
    ).to_dict()

    unknown = {**value, "promotion_gate": False}
    unknown["evidence_root"] = _independent_root(unknown)
    with pytest.raises(ValueError, match="fields"):
        CapabilityEffectEvidence.from_mapping(unknown)

    missing = deepcopy(value)
    missing.pop("operation_ref")
    missing["evidence_root"] = _independent_root(missing)
    with pytest.raises(ValueError, match="fields"):
        CapabilityEffectEvidence.from_mapping(missing)

    bad_root = {**value, "evidence_root": "f" * 64}
    with pytest.raises(ValueError, match="root does not match"):
        CapabilityEffectEvidence.from_mapping(bad_root)

    bad_bool = deepcopy(value)
    bad_bool["observations"][2]["protected_effect_observed"] = 1
    bad_bool["evidence_root"] = _independent_root(bad_bool)
    with pytest.raises(ValueError, match="must be boolean"):
        CapabilityEffectEvidence.from_mapping(bad_bool)

    bad_number = deepcopy(value)
    bad_number["observations"][2]["response_status"] = True
    bad_number["evidence_root"] = _independent_root(bad_number)
    with pytest.raises(ValueError, match="response status"):
        CapabilityEffectEvidence.from_mapping(bad_number)

    wrong_ref = deepcopy(value)
    wrong_ref["capability_ref"] = stable_hash("world", "wrong-prefix")
    wrong_ref["evidence_root"] = _independent_root(wrong_ref)
    with pytest.raises(ValueError, match="capability ref"):
        CapabilityEffectEvidence.from_mapping(wrong_ref)

    substituted_world = deepcopy(value)
    substituted_world["experiment_world_ref"] = stable_hash(
        "world", "substituted-world"
    )
    substituted_world["evidence_root"] = _independent_root(substituted_world)
    with pytest.raises(ValueError, match="world ref does not match identity"):
        CapabilityEffectEvidence.from_mapping(substituted_world)

    widened_traffic = deepcopy(value)
    widened_traffic["cleanup"]["target_requests_sent"] = 7
    widened_traffic["evidence_root"] = _independent_root(widened_traffic)
    with pytest.raises(ValueError, match="cleanup"):
        CapabilityEffectEvidence.from_mapping(widened_traffic)


def test_unicode_strings_are_preserved_without_global_normalization():
    result, _ = _run_result(
        leak_kind="replayed_capability_probe",
        suffix="r5d10-unicode",
    )
    composed = _evidence_from_result(
        result,
        persona_id="r5d6-r5d10-unicode",
        session_id="session-\u00e9",
    )
    decomposed = _evidence_from_result(
        result,
        persona_id="r5d6-r5d10-unicode",
        session_id="session-e\u0301",
    )

    assert composed.assessment_session_id == "session-\u00e9"
    assert decomposed.assessment_session_id == "session-e\u0301"
    assert composed.evidence_root != decomposed.evidence_root
    assert b"\\u00e9" not in composed.to_json_bytes()
    assert (
        CapabilityEffectEvidence.from_json_bytes(composed.to_json_bytes()) == composed
    )


def test_raw_effect_and_promotion_gate_state_never_enter_evidence_or_finding(
    monkeypatch,
):
    secret = "R5D10-RAW-SECRET-CANARY-4a64df"
    monkeypatch.setattr(
        r5d8_fixtures,
        "EFFECT_VALUE",
        {"raw_secret": secret},
    )
    result, _ = _run_result(
        leak_kind="replayed_capability_probe",
        suffix="r5d10-redaction",
    )
    evidence = _evidence_from_result(result, persona_id="r5d6-r5d10-redaction")
    material = replay_leak_finding_material(evidence)

    assert secret not in evidence.to_json_bytes().decode()
    assert secret not in repr(evidence)
    assert secret not in _canonical_bytes(material).decode()
    before = evidence.evidence_root
    monkeypatch.setenv("SENTINELFORGE_BEHAVIOR_CAPABILITY_FINDING_PROMOTION", "1")
    assert evidence.evidence_root == before
    assert replay_leak_finding_material(evidence) == material
    assert (
        CAPABILITY_EFFECT_ADAPTER_CONTRACT_VERSION in evidence.to_json_bytes().decode()
    )
