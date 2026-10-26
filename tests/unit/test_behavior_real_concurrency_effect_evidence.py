"""The C1 real-concurrency effect evidence is dormant and authority-free."""

import json

import pytest

from core.behavior.real_concurrency_effect_evidence import (
    REAL_CONCURRENCY_EFFECT_EVIDENCE_MAX_BYTES,
    RealConcurrencyEffectEligibility,
    RealConcurrencyEffectEvidence,
    RealConcurrencyEffectEvidenceError,
    _evidence_root,
    corroborates,
    evaluate_real_concurrency_effect_eligibility,
)


ORIGIN = "https://app.sentinel-lab.test"
RESOURCE_REF = "owned_resource:" + "a" * 64
COMMIT_RECEIPT_IDS = (
    "behavioral-" + "b" * 64,
    "behavioral-" + "c" * 64,
)
CLEANUP_RECEIPT_ID = "behavioral-" + "d" * 64
OVERLAP_PROOF_REF = "concurrency_overlap:" + "e" * 64
PROOF_REF = "real_concurrency_effect:" + "f" * 64
ARTIFACT_REF = "sha256:" + "0" * 64


def _sample(**changes):
    fields = {
        "observed_origin": ORIGIN,
        "resource_ref": RESOURCE_REF,
        "declared_limit": 10,
        "observed_consumed": 11,
        "commit_receipt_ids": COMMIT_RECEIPT_IDS,
        "cleanup_receipt_id": CLEANUP_RECEIPT_ID,
        "overlap_proof_ref": OVERLAP_PROOF_REF,
        "proof_ref": PROOF_REF,
        "artifact_ref": ARTIFACT_REF,
        "proof_mode": "behavioral_real_concurrency_effect_v1",
        "observed_at_epoch": 100.0,
        "runtime_evidence_classification": "controlled_owned_lab",
    }
    fields.update(changes)
    return RealConcurrencyEffectEvidence.build(**fields)


def _forged(evidence, *, refresh_root=True, **changes):
    """Bypass constructor guards to check each eligibility clause independently."""

    fields = evidence.to_dict()
    fields["commit_receipt_ids"] = tuple(fields["commit_receipt_ids"])
    fields.update(changes)
    if refresh_root:
        preimage = dict(fields)
        preimage.pop("evidence_root")
        if type(preimage["commit_receipt_ids"]) is tuple:
            preimage["commit_receipt_ids"] = list(preimage["commit_receipt_ids"])
        fields["evidence_root"] = _evidence_root(preimage)
    forged = object.__new__(RealConcurrencyEffectEvidence)
    for name, value in fields.items():
        object.__setattr__(forged, name, value)
    return forged


def test_sample_round_trip_and_eligibility():
    evidence = _sample()
    payload = evidence.to_dict()
    assert list(payload) == [
        "schema_version",
        "evidence_root",
        "observed_origin",
        "resource_ref",
        "declared_limit",
        "observed_consumed",
        "commit_receipt_ids",
        "cleanup_receipt_id",
        "overlap_proof_ref",
        "proof_ref",
        "artifact_ref",
        "proof_mode",
        "observed_at_epoch",
        "runtime_evidence_classification",
    ]
    assert payload["commit_receipt_ids"] == list(COMMIT_RECEIPT_IDS)
    assert evidence.commit_receipt_ids == COMMIT_RECEIPT_IDS
    assert RealConcurrencyEffectEvidence.from_mapping(payload) == evidence
    encoded = evidence.to_json_bytes()
    assert len(encoded) < REAL_CONCURRENCY_EFFECT_EVIDENCE_MAX_BYTES
    assert RealConcurrencyEffectEvidence.from_json_bytes(encoded) == evidence
    assert evaluate_real_concurrency_effect_eligibility(evidence) == (
        RealConcurrencyEffectEligibility(
            eligible=True,
            reason_code="eligible_real_concurrency_effect",
            failed_clauses=(),
        )
    )


@pytest.mark.parametrize(
    "field,value,message",
    [
        ("schema_version", 2, "version"),
        ("schema_version", True, "version"),
        ("evidence_root", "0" * 63, "root"),
        ("evidence_root", "1" * 64, "root mismatches"),
        ("observed_origin", ORIGIN + "/", "not canonical"),
        ("observed_origin", ORIGIN + "/resource", "not canonical"),
        ("resource_ref", "sha256:" + "a" * 64, "resource ref"),
        ("declared_limit", 0, "declared limit"),
        ("declared_limit", 2**63, "declared limit"),
        ("declared_limit", True, "declared limit"),
        ("observed_consumed", 10, "observed consumed"),
        ("observed_consumed", 9, "observed consumed"),
        ("observed_consumed", True, "observed consumed"),
        ("commit_receipt_ids", [COMMIT_RECEIPT_IDS[0]], "commit receipt"),
        (
            "commit_receipt_ids",
            [*COMMIT_RECEIPT_IDS, "behavioral-" + "1" * 64],
            "commit receipt",
        ),
        (
            "commit_receipt_ids",
            [COMMIT_RECEIPT_IDS[0], COMMIT_RECEIPT_IDS[0]],
            "commit receipt",
        ),
        (
            "commit_receipt_ids",
            [COMMIT_RECEIPT_IDS[0], "behavioral_receipt:" + "1" * 64],
            "commit receipt",
        ),
        ("commit_receipt_ids", COMMIT_RECEIPT_IDS, "commit receipt"),
        ("cleanup_receipt_id", "behavioral_receipt:" + "1" * 64, "cleanup receipt"),
        ("overlap_proof_ref", "sha256:" + "1" * 64, "overlap proof ref"),
        ("proof_ref", "sha256:" + "1" * 64, "proof ref"),
        ("artifact_ref", "real_concurrency_effect:" + "1" * 64, "artifact ref"),
        ("proof_mode", "other", "proof mode"),
        ("observed_at_epoch", 0.0, "observation time"),
        ("observed_at_epoch", -1.0, "observation time"),
        ("observed_at_epoch", float("nan"), "observation time"),
        ("observed_at_epoch", float("inf"), "observation time"),
        ("observed_at_epoch", 100, "observation time"),
        ("runtime_evidence_classification", "live", "runtime evidence"),
    ],
)
def test_post_init_rejects_malformed_field(field, value, message):
    payload = _sample().to_dict()
    payload[field] = value
    with pytest.raises(RealConcurrencyEffectEvidenceError, match=message):
        RealConcurrencyEffectEvidence.from_mapping(payload)


def test_exact_fields_and_canonical_json_guards():
    evidence = _sample()
    payload = evidence.to_dict()
    with pytest.raises(RealConcurrencyEffectEvidenceError, match="fields"):
        RealConcurrencyEffectEvidence.from_mapping({**payload, "extra": True})
    missing = dict(payload)
    missing.pop("proof_ref")
    with pytest.raises(RealConcurrencyEffectEvidenceError, match="fields"):
        RealConcurrencyEffectEvidence.from_mapping(missing)

    encoded = evidence.to_json_bytes()
    reordered = json.dumps(
        dict(reversed(tuple(payload.items()))),
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    for noncanonical in (encoded + b"\n", reordered):
        with pytest.raises(RealConcurrencyEffectEvidenceError, match="not canonical"):
            RealConcurrencyEffectEvidence.from_json_bytes(noncanonical)
    duplicate = encoded.replace(
        b'"schema_version":1', b'"schema_version":1,"schema_version":1', 1
    )
    with pytest.raises(RealConcurrencyEffectEvidenceError, match="duplicate"):
        RealConcurrencyEffectEvidence.from_json_bytes(duplicate)
    for constant in (b"NaN", b"Infinity", b"-Infinity"):
        invalid = encoded.replace(
            b'"observed_at_epoch":100.0', b'"observed_at_epoch":' + constant
        )
        with pytest.raises(RealConcurrencyEffectEvidenceError, match="constant"):
            RealConcurrencyEffectEvidence.from_json_bytes(invalid)
    with pytest.raises(RealConcurrencyEffectEvidenceError, match="oversized"):
        RealConcurrencyEffectEvidence.from_json_bytes(
            b" " * (REAL_CONCURRENCY_EFFECT_EVIDENCE_MAX_BYTES + 1)
        )
    with pytest.raises(RealConcurrencyEffectEvidenceError, match="JSON is invalid"):
        RealConcurrencyEffectEvidence.from_json_bytes(b"\xff")
    with pytest.raises(TypeError, match="must be bytes"):
        RealConcurrencyEffectEvidence.from_json_bytes(encoded.decode("utf-8"))


def test_corroborates_requires_matching_context_and_typed_evidence():
    evidence = _sample()
    assert corroborates(
        evidence,
        confined_origin=ORIGIN,
        resource_ref=RESOURCE_REF,
        declared_limit=10,
    )
    assert not corroborates(
        evidence,
        confined_origin="https://other.sentinel-lab.test",
        resource_ref=RESOURCE_REF,
        declared_limit=10,
    )
    assert not corroborates(
        evidence,
        confined_origin=ORIGIN + "/",
        resource_ref=RESOURCE_REF,
        declared_limit=10,
    )
    assert not corroborates(
        evidence,
        confined_origin=ORIGIN,
        resource_ref="owned_resource:" + "1" * 64,
        declared_limit=10,
    )
    assert not corroborates(
        evidence,
        confined_origin=ORIGIN,
        resource_ref=RESOURCE_REF,
        declared_limit=11,
    )
    assert not corroborates(
        evidence,
        confined_origin=123,
        resource_ref=RESOURCE_REF,
        declared_limit=10,
    )
    assert not corroborates(
        evidence,
        confined_origin=ORIGIN,
        resource_ref=123,
        declared_limit=10,
    )
    assert not corroborates(
        evidence,
        confined_origin=ORIGIN,
        resource_ref=RESOURCE_REF,
        declared_limit=True,
    )
    assert not corroborates(
        object(),
        confined_origin=ORIGIN,
        resource_ref=RESOURCE_REF,
        declared_limit=10,
    )
    forged = _forged(evidence, observed_consumed=10)
    assert not corroborates(
        forged,
        confined_origin=ORIGIN,
        resource_ref=RESOURCE_REF,
        declared_limit=10,
    )


@pytest.mark.parametrize(
    "changes,reason,clause",
    [
        ({"proof_mode": "other"}, "proof_mode_mismatch", 1),
        ({"observed_origin": ORIGIN + "/"}, "observed_origin_not_canonical", 2),
        ({"resource_ref": "sha256:" + "1" * 64}, "refs_malformed", 3),
        ({"overlap_proof_ref": "sha256:" + "1" * 64}, "refs_malformed", 3),
        ({"proof_ref": "sha256:" + "1" * 64}, "refs_malformed", 3),
        ({"artifact_ref": "owned_resource:" + "1" * 64}, "refs_malformed", 3),
        (
            {"commit_receipt_ids": (COMMIT_RECEIPT_IDS[0],)},
            "receipts_malformed",
            4,
        ),
        (
            {
                "commit_receipt_ids": (
                    COMMIT_RECEIPT_IDS[0],
                    COMMIT_RECEIPT_IDS[0],
                )
            },
            "receipts_malformed",
            4,
        ),
        (
            {"cleanup_receipt_id": "behavioral_receipt:" + "1" * 64},
            "receipts_malformed",
            4,
        ),
        (
            {"runtime_evidence_classification": "unknown"},
            "runtime_classification_not_honest",
            5,
        ),
        (
            {"observed_consumed": 10},
            "source_validation_failed",
            6,
        ),
        (
            {"declared_limit": 0},
            "source_validation_failed",
            6,
        ),
        (
            {"observed_at_epoch": 0.0},
            "source_validation_failed",
            6,
        ),
    ],
)
def test_eligibility_rederives_each_clause(changes, reason, clause):
    evidence = _forged(_sample(), **changes)
    assert evaluate_real_concurrency_effect_eligibility(evidence) == (
        RealConcurrencyEffectEligibility(
            eligible=False,
            reason_code=reason,
            failed_clauses=(clause,),
        )
    )


def test_unknown_runtime_is_valid_but_ineligible():
    evidence = _sample(runtime_evidence_classification="unknown")
    assert evaluate_real_concurrency_effect_eligibility(
        evidence
    ).failed_clauses == (5,)


def test_eligibility_detects_tampered_root_and_reports_all_failed_clauses():
    evidence = _forged(_sample(), refresh_root=False, evidence_root="1" * 64)
    assert evaluate_real_concurrency_effect_eligibility(evidence) == (
        RealConcurrencyEffectEligibility(False, "source_validation_failed", (6,))
    )
    evidence = _forged(
        _sample(),
        proof_mode="other",
        observed_origin=ORIGIN + "/",
    )
    assert evaluate_real_concurrency_effect_eligibility(evidence) == (
        RealConcurrencyEffectEligibility(False, "proof_mode_mismatch", (1, 2))
    )
    with pytest.raises(TypeError, match="typed evidence"):
        evaluate_real_concurrency_effect_eligibility(object())


def test_eligibility_record_validates_its_fields():
    with pytest.raises(TypeError, match="boolean"):
        RealConcurrencyEffectEligibility(1, "eligible_real_concurrency_effect", ())
    with pytest.raises(RealConcurrencyEffectEvidenceError, match="reason code"):
        RealConcurrencyEffectEligibility(False, "NotSemantic", (1,))
    with pytest.raises(ValueError, match="failed clauses"):
        RealConcurrencyEffectEligibility(False, "proof_mode_mismatch", (7,))
    with pytest.raises(ValueError, match="failed clauses"):
        RealConcurrencyEffectEligibility(False, "proof_mode_mismatch", [1])
