"""Canonical, authority-free evidence for one owned-read proof's proven origin.

This record attests explicit proof identifiers and a caller-supplied canonical
origin. It does not consult a receipt store, lab oracle, candidate, or run.
``correlation_ids`` belong to a future A2 oracle/ledger cross-check, not this
unwired record. The owned-read-proof result has no producer/build-identity
block, and this contract has no downstream consumer needing one.

Neither eligibility nor origin equality grants authority or changes an
origin-binding authority flag.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import math
import re
from typing import Any, Mapping, Tuple

from core.base.scope import canonical_origin


OWNED_ORIGIN_BINDING_EVIDENCE_SCHEMA_VERSION = 1
OWNED_ORIGIN_BINDING_EVIDENCE_MAX_BYTES = 64 * 1024
_ROOT_DOMAIN = b"sentinelforge:owned-origin-binding-evidence:v1\x00"

_BARE_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_TYPED_SHA256 = re.compile(r"^([a-z][a-z0-9_]{0,127}):([0-9a-f]{64})$")
_BEHAVIORAL_RECEIPT = re.compile(r"^behavioral-[0-9a-f]{64}$")
_SEMANTIC = re.compile(r"^[a-z][a-z0-9_]{0,63}$")

_PROOF_MODE = "behavioral_owned_read_proof_v1"
_RUNTIME_CLASSIFICATIONS = frozenset(
    {"controlled_in_memory_twin", "controlled_owned_lab", "unknown"}
)
_HONEST_CLASSIFICATIONS = frozenset(
    {"controlled_in_memory_twin", "controlled_owned_lab"}
)
_FIELDS = frozenset(
    {
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
)


class OwnedOriginBindingEvidenceError(ValueError):
    """An owned-origin-binding evidence record is invalid."""


def _exact(value: object, fields: frozenset[str], label: str) -> Mapping[str, Any]:
    if (
        not isinstance(value, Mapping)
        or set(value) != fields
        or any(type(key) is not str for key in value)
    ):
        raise OwnedOriginBindingEvidenceError(f"{label} fields are invalid")
    return value


def _bounded(value: object, label: str, maximum: int) -> str:
    if (
        type(value) is not str
        or not value
        or len(value) > maximum
        or value != value.strip()
        or any(ord(character) < 0x20 for character in value)
    ):
        raise OwnedOriginBindingEvidenceError(f"{label} is invalid")
    return value


def _semantic(value: object, label: str) -> str:
    if type(value) is not str or _SEMANTIC.fullmatch(value) is None:
        raise OwnedOriginBindingEvidenceError(f"{label} is invalid")
    return value


def _typed_ref(value: object, prefix: str, label: str) -> str:
    if type(value) is not str:
        raise OwnedOriginBindingEvidenceError(f"{label} is invalid")
    match = _TYPED_SHA256.fullmatch(value)
    if match is None or match.group(1) != prefix:
        raise OwnedOriginBindingEvidenceError(f"{label} is invalid")
    return value


def _behavioral_receipt(value: object, label: str) -> str:
    if type(value) is not str or _BEHAVIORAL_RECEIPT.fullmatch(value) is None:
        raise OwnedOriginBindingEvidenceError(f"{label} is invalid")
    return value


def _canonical_json_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise OwnedOriginBindingEvidenceError(
            "owned origin binding evidence is not JSON-safe"
        ) from exc


def _evidence_root(payload: Mapping[str, Any]) -> str:
    return hashlib.sha256(
        _ROOT_DOMAIN + _canonical_json_bytes(dict(payload))
    ).hexdigest()


@dataclass(frozen=True)
class OwnedOriginBindingEvidence:
    schema_version: int
    evidence_root: str
    proven_origin: str
    source_receipt_id: str
    acquisition_receipt_id: str
    proof_ref: str
    artifact_ref: str
    proof_mode: str
    observed_at_epoch: float
    runtime_evidence_classification: str

    @classmethod
    def build(
        cls,
        *,
        proven_origin: str,
        source_receipt_id: str,
        acquisition_receipt_id: str,
        proof_ref: str,
        artifact_ref: str,
        proof_mode: str,
        observed_at_epoch: float,
        runtime_evidence_classification: str,
    ) -> OwnedOriginBindingEvidence:
        payload = {
            "schema_version": OWNED_ORIGIN_BINDING_EVIDENCE_SCHEMA_VERSION,
            "proven_origin": proven_origin,
            "source_receipt_id": source_receipt_id,
            "acquisition_receipt_id": acquisition_receipt_id,
            "proof_ref": proof_ref,
            "artifact_ref": artifact_ref,
            "proof_mode": proof_mode,
            "observed_at_epoch": observed_at_epoch,
            "runtime_evidence_classification": runtime_evidence_classification,
        }
        return cls(evidence_root=_evidence_root(payload), **payload)

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> OwnedOriginBindingEvidence:
        source = _exact(value, _FIELDS, "owned origin binding evidence")
        return cls(**dict(source))

    @classmethod
    def from_json_bytes(cls, value: bytes) -> OwnedOriginBindingEvidence:
        if type(value) is not bytes:
            raise TypeError("owned origin binding evidence JSON must be bytes")
        if len(value) > OWNED_ORIGIN_BINDING_EVIDENCE_MAX_BYTES:
            raise OwnedOriginBindingEvidenceError(
                "owned origin binding evidence is oversized"
            )

        def reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for key, child in pairs:
                if key in result:
                    raise OwnedOriginBindingEvidenceError(
                        "owned origin binding evidence has duplicate keys"
                    )
                result[key] = child
            return result

        def reject_constant(value: str) -> None:
            raise OwnedOriginBindingEvidenceError(f"invalid JSON constant: {value}")

        try:
            parsed = json.loads(
                value.decode("utf-8", errors="strict"),
                object_pairs_hook=reject_duplicate_pairs,
                parse_constant=reject_constant,
            )
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise OwnedOriginBindingEvidenceError(
                "owned origin binding evidence JSON is invalid"
            ) from exc
        evidence = cls.from_mapping(parsed)
        if value != evidence.to_json_bytes():
            raise OwnedOriginBindingEvidenceError(
                "owned origin binding evidence JSON is not canonical"
            )
        return evidence

    def __post_init__(self) -> None:
        if type(self.schema_version) is not int or self.schema_version != 1:
            raise OwnedOriginBindingEvidenceError(
                "owned origin binding evidence version is invalid"
            )
        if type(self.evidence_root) is not str or not _BARE_SHA256.fullmatch(
            self.evidence_root
        ):
            raise OwnedOriginBindingEvidenceError(
                "owned origin binding evidence root is invalid"
            )
        origin = _bounded(self.proven_origin, "proven origin", 2048)
        parsed = canonical_origin(origin)
        if parsed is None or parsed.as_url() != origin:
            raise OwnedOriginBindingEvidenceError("proven origin is not canonical")
        _behavioral_receipt(self.source_receipt_id, "source receipt id")
        _behavioral_receipt(self.acquisition_receipt_id, "acquisition receipt id")
        _typed_ref(self.proof_ref, "owned_read_proof", "proof ref")
        _typed_ref(self.artifact_ref, "sha256", "artifact ref")
        if type(self.proof_mode) is not str or self.proof_mode != _PROOF_MODE:
            raise OwnedOriginBindingEvidenceError("proof mode is invalid")
        if (
            type(self.observed_at_epoch) is not float
            or not math.isfinite(self.observed_at_epoch)
            or self.observed_at_epoch <= 0
        ):
            raise OwnedOriginBindingEvidenceError("observation time is invalid")
        if (
            type(self.runtime_evidence_classification) is not str
            or self.runtime_evidence_classification not in _RUNTIME_CLASSIFICATIONS
        ):
            raise OwnedOriginBindingEvidenceError(
                "runtime evidence classification is invalid"
            )
        payload = self.to_dict()
        payload.pop("evidence_root")
        if self.evidence_root != _evidence_root(payload):
            raise OwnedOriginBindingEvidenceError("evidence root mismatches")
        self.to_json_bytes()

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "evidence_root": self.evidence_root,
            "proven_origin": self.proven_origin,
            "source_receipt_id": self.source_receipt_id,
            "acquisition_receipt_id": self.acquisition_receipt_id,
            "proof_ref": self.proof_ref,
            "artifact_ref": self.artifact_ref,
            "proof_mode": self.proof_mode,
            "observed_at_epoch": self.observed_at_epoch,
            "runtime_evidence_classification": self.runtime_evidence_classification,
        }

    def to_json_bytes(self) -> bytes:
        encoded = _canonical_json_bytes(self.to_dict())
        if len(encoded) > OWNED_ORIGIN_BINDING_EVIDENCE_MAX_BYTES:
            raise OwnedOriginBindingEvidenceError(
                "owned origin binding evidence is oversized"
            )
        return encoded


def binds_to(evidence: OwnedOriginBindingEvidence, confined_origin: str) -> bool:
    """Pure canonical-equality: does this proof's proven origin equal a confined origin?

    This grants NO authority. It is the seam a FUTURE A2 candidate-derivation
    would call (with ``specification.transport_spec.target_origin``) before it
    could consider an origin-binding authority decision. A1a wires none of that.
    """

    if type(evidence) is not OwnedOriginBindingEvidence or type(confined_origin) is not str:
        return False
    left = canonical_origin(evidence.proven_origin)
    right = canonical_origin(confined_origin)
    return (
        left is not None
        and right is not None
        and right.as_url() == confined_origin
        and left.as_url() == right.as_url()
    )


@dataclass(frozen=True)
class OwnedOriginBindingEligibility:
    eligible: bool
    reason_code: str
    failed_clauses: Tuple[int, ...]

    def __post_init__(self) -> None:
        if type(self.eligible) is not bool:
            raise TypeError("owned origin binding eligibility must be boolean")
        _semantic(self.reason_code, "owned origin binding reason code")
        if any(
            type(item) is not int or not 1 <= item <= 6
            for item in self.failed_clauses
        ):
            raise ValueError("owned origin binding failed clauses are invalid")


def evaluate_owned_origin_binding_eligibility(
    evidence: OwnedOriginBindingEvidence,
) -> OwnedOriginBindingEligibility:
    """Purely evaluate whether this attestation is a well-formed, honest owned-read binding.

    Authority-free: an ``eligible`` record is only well-formed, honest-runtime,
    and self-consistent. It confirms no finding, grants no promotion, sets no
    flag, and wires nothing.
    """

    if type(evidence) is not OwnedOriginBindingEvidence:
        raise TypeError("owned origin binding eligibility requires typed evidence")
    proof_ref = _TYPED_SHA256.fullmatch(evidence.proof_ref)
    artifact_ref = _TYPED_SHA256.fullmatch(evidence.artifact_ref)
    proven_origin = canonical_origin(evidence.proven_origin)
    preimage = evidence.to_dict()
    preimage.pop("evidence_root")
    clause_1 = evidence.proof_mode == _PROOF_MODE
    clause_2 = (
        proven_origin is not None
        and proven_origin.as_url() == evidence.proven_origin
    )
    clause_3 = bool(
        _BEHAVIORAL_RECEIPT.fullmatch(evidence.source_receipt_id)
        and _BEHAVIORAL_RECEIPT.fullmatch(evidence.acquisition_receipt_id)
    )
    clause_4 = bool(
        proof_ref is not None
        and proof_ref.group(1) == "owned_read_proof"
        and artifact_ref is not None
        and artifact_ref.group(1) == "sha256"
    )
    clause_5 = evidence.runtime_evidence_classification in _HONEST_CLASSIFICATIONS
    clause_6 = (
        math.isfinite(evidence.observed_at_epoch)
        and evidence.observed_at_epoch > 0
        and evidence.evidence_root == _evidence_root(preimage)
    )
    clauses = (clause_1, clause_2, clause_3, clause_4, clause_5, clause_6)
    failed = tuple(index for index, passed in enumerate(clauses, 1) if not passed)
    if not failed:
        return OwnedOriginBindingEligibility(
            eligible=True,
            reason_code="eligible_owned_origin_binding",
            failed_clauses=(),
        )
    reasons = {
        1: "proof_mode_mismatch",
        2: "proven_origin_not_canonical",
        3: "receipt_ids_malformed",
        4: "proof_or_artifact_ref_malformed",
        5: "runtime_classification_not_honest",
        6: "source_validation_failed",
    }
    return OwnedOriginBindingEligibility(
        eligible=False,
        reason_code=reasons[failed[0]],
        failed_clauses=failed,
    )
