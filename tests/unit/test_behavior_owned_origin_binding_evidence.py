"""The A1a owned-origin binding is a dormant, authority-free contract."""

import pytest

from core.behavior.owned_origin_binding_evidence import (
    OWNED_ORIGIN_BINDING_EVIDENCE_MAX_BYTES,
    OwnedOriginBindingEligibility,
    OwnedOriginBindingEvidence,
    OwnedOriginBindingEvidenceError,
    _evidence_root,
    binds_to,
    evaluate_owned_origin_binding_eligibility,
)


ORIGIN = "https://app.sentinel-lab.test"
SOURCE_RECEIPT_ID = (
    "behavioral-350b8f0b666c5fbdcf3644ec1ea18791"
    "b1f5c367e24d1774a8c64fb0f4fd681e"
)
ACQUISITION_RECEIPT_ID = (
    "behavioral-bf7f97b3e96533f5a67f5f921889937"
    "c18f501c9a5fc3ec2f9e917690cb76381"
)
PROOF_REF = (
    "owned_read_proof:0110f9dc34b1d9e213a6297766037c6a"
    "5fceb96eeb9baac8bc84dd07dca04f61"
)
ARTIFACT_REF = (
    "sha256:f3acf632e6618147e45b4abc005dd596"
    "1de0e4969842b71831c1d26d523b4df9"
)


def _sample(**changes):
    fields = {
        "proven_origin": ORIGIN,
        "source_receipt_id": SOURCE_RECEIPT_ID,
        "acquisition_receipt_id": ACQUISITION_RECEIPT_ID,
        "proof_ref": PROOF_REF,
        "artifact_ref": ARTIFACT_REF,
        "proof_mode": "behavioral_owned_read_proof_v1",
        "observed_at_epoch": 100.0,
        "runtime_evidence_classification": "controlled_owned_lab",
    }
    fields.update(changes)
    return OwnedOriginBindingEvidence.build(**fields)


def _forged(evidence, *, refresh_root=True, **changes):
    """Bypass constructor guards to check each eligibility clause independently."""

    fields = evidence.to_dict()
    fields.update(changes)
    if refresh_root:
        preimage = dict(fields)
        preimage.pop("evidence_root")
        fields["evidence_root"] = _evidence_root(preimage)
    forged = object.__new__(OwnedOriginBindingEvidence)
    for name, value in fields.items():
        object.__setattr__(forged, name, value)
    return forged


def test_real_a1b_fixture_round_trip_and_eligibility():
    evidence = _sample()
    payload = evidence.to_dict()
    assert set(payload) == {
        "schema_version",
        "evidence_root",
        "proven_origin",
        "source_receipt_id",
        "acquisition_receipt_id",
        "proof_ref",
        "artifact_ref",
        "proof_mode",
        "observed_at_epoch",
        "runtime_evidence_classification",
    }
    assert evidence.source_receipt_id == SOURCE_RECEIPT_ID
    assert evidence.acquisition_receipt_id == ACQUISITION_RECEIPT_ID
    assert evidence.proof_ref == PROOF_REF
    assert evidence.artifact_ref == ARTIFACT_REF
    assert OwnedOriginBindingEvidence.from_mapping(payload) == evidence
    encoded = evidence.to_json_bytes()
    assert len(encoded) < OWNED_ORIGIN_BINDING_EVIDENCE_MAX_BYTES
    assert OwnedOriginBindingEvidence.from_json_bytes(encoded) == evidence
    assert evaluate_owned_origin_binding_eligibility(evidence) == (
        OwnedOriginBindingEligibility(
            eligible=True,
            reason_code="eligible_owned_origin_binding",
            failed_clauses=(),
        )
    )


@pytest.mark.parametrize(
    "field,value,message",
    [
        ("schema_version", 2, "version"),
        ("schema_version", True, "version"),
        ("evidence_root", "0" * 63, "root"),
        ("evidence_root", "0" * 64, "root mismatches"),
        ("proven_origin", ORIGIN + "/", "not canonical"),
        ("proven_origin", ORIGIN + "/pricing", "not canonical"),
        ("source_receipt_id", "behavioral_receipt:" + "a" * 64, "source receipt"),
        ("acquisition_receipt_id", "behavioral_receipt:" + "a" * 64, "acquisition receipt"),
        ("proof_ref", "sha256:" + "a" * 64, "proof ref"),
        ("artifact_ref", "owned_read_proof:" + "a" * 64, "artifact ref"),
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
    with pytest.raises(OwnedOriginBindingEvidenceError, match=message):
        OwnedOriginBindingEvidence.from_mapping(payload)


def test_exact_fields_and_canonical_json_guards():
    evidence = _sample()
    payload = evidence.to_dict()
    with pytest.raises(OwnedOriginBindingEvidenceError, match="fields"):
        OwnedOriginBindingEvidence.from_mapping({**payload, "extra": True})
    missing = dict(payload)
    missing.pop("proof_ref")
    with pytest.raises(OwnedOriginBindingEvidenceError, match="fields"):
        OwnedOriginBindingEvidence.from_mapping(missing)

    encoded = evidence.to_json_bytes()
    reordered = b"{" + b",".join(reversed(encoded[1:-1].split(b","))) + b"}"
    for noncanonical in (encoded + b"\n", reordered):
        with pytest.raises(OwnedOriginBindingEvidenceError, match="not canonical"):
            OwnedOriginBindingEvidence.from_json_bytes(noncanonical)
    duplicate = encoded.replace(
        b'"schema_version":1', b'"schema_version":1,"schema_version":1', 1
    )
    with pytest.raises(OwnedOriginBindingEvidenceError, match="duplicate"):
        OwnedOriginBindingEvidence.from_json_bytes(duplicate)
    for constant in (b"NaN", b"Infinity", b"-Infinity"):
        invalid = encoded.replace(b'"observed_at_epoch":100.0', b'"observed_at_epoch":' + constant)
        with pytest.raises(OwnedOriginBindingEvidenceError, match="constant"):
            OwnedOriginBindingEvidence.from_json_bytes(invalid)
    with pytest.raises(OwnedOriginBindingEvidenceError, match="oversized"):
        OwnedOriginBindingEvidence.from_json_bytes(
            b" " * (OWNED_ORIGIN_BINDING_EVIDENCE_MAX_BYTES + 1)
        )
    with pytest.raises(OwnedOriginBindingEvidenceError, match="JSON is invalid"):
        OwnedOriginBindingEvidence.from_json_bytes(b"\xff")
    with pytest.raises(TypeError, match="must be bytes"):
        OwnedOriginBindingEvidence.from_json_bytes(encoded.decode("utf-8"))


def test_binds_to_requires_the_same_canonical_origin_and_typed_evidence():
    evidence = _sample()
    assert binds_to(evidence, ORIGIN) is True
    assert binds_to(evidence, "https://other.sentinel-lab.test") is False
    assert binds_to(evidence, ORIGIN + "/") is False
    assert binds_to(evidence, ORIGIN + "/pricing") is False
    assert binds_to(evidence, 123) is False
    assert binds_to(object(), ORIGIN) is False


@pytest.mark.parametrize(
    "changes,reason,clause",
    [
        ({"proof_mode": "other"}, "proof_mode_mismatch", 1),
        ({"proven_origin": ORIGIN + "/"}, "proven_origin_not_canonical", 2),
        ({"source_receipt_id": "behavioral_receipt:" + "a" * 64}, "receipt_ids_malformed", 3),
        ({"acquisition_receipt_id": "behavioral_receipt:" + "a" * 64}, "receipt_ids_malformed", 3),
        ({"proof_ref": "sha256:" + "a" * 64}, "proof_or_artifact_ref_malformed", 4),
        ({"artifact_ref": "owned_read_proof:" + "a" * 64}, "proof_or_artifact_ref_malformed", 4),
        ({"runtime_evidence_classification": "unknown"}, "runtime_classification_not_honest", 5),
        ({"observed_at_epoch": 0.0}, "source_validation_failed", 6),
    ],
)
def test_eligibility_rederives_each_clause(changes, reason, clause):
    evidence = _forged(_sample(), **changes)
    assert evaluate_owned_origin_binding_eligibility(evidence) == (
        OwnedOriginBindingEligibility(
            eligible=False,
            reason_code=reason,
            failed_clauses=(clause,),
        )
    )


def test_unknown_runtime_is_valid_but_ineligible():
    evidence = _sample(runtime_evidence_classification="unknown")
    assert evaluate_owned_origin_binding_eligibility(evidence).failed_clauses == (5,)


def test_eligibility_detects_tampered_root_and_reports_all_failed_clauses():
    evidence = _forged(_sample(), refresh_root=False, evidence_root="0" * 64)
    assert evaluate_owned_origin_binding_eligibility(evidence) == (
        OwnedOriginBindingEligibility(False, "source_validation_failed", (6,))
    )
    evidence = _forged(_sample(), proof_mode="other", proven_origin=ORIGIN + "/")
    assert evaluate_owned_origin_binding_eligibility(evidence) == (
        OwnedOriginBindingEligibility(False, "proof_mode_mismatch", (1, 2))
    )
    with pytest.raises(TypeError, match="typed evidence"):
        evaluate_owned_origin_binding_eligibility(object())


def test_eligibility_record_validates_its_fields():
    with pytest.raises(TypeError, match="boolean"):
        OwnedOriginBindingEligibility(1, "eligible_owned_origin_binding", ())
    with pytest.raises(OwnedOriginBindingEvidenceError, match="reason code"):
        OwnedOriginBindingEligibility(False, "NotSemantic", (1,))
    with pytest.raises(ValueError, match="failed clauses"):
        OwnedOriginBindingEligibility(False, "proof_mode_mismatch", (7,))
