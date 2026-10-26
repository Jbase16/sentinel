"""Canonical, authority-free evidence for one real concurrent oversell.

This record is dormant and unwired. No production entry point imports it.
Neither eligibility nor corroboration grants authority or changes
``real_concurrency_effect_observed``. Producing a real-concurrency observation
artifact and the future C2 candidate-derivation wire-in are deferred.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import math
import re
from typing import Any, Mapping, Tuple

from core.base.scope import canonical_origin


REAL_CONCURRENCY_EFFECT_EVIDENCE_SCHEMA_VERSION = 1
REAL_CONCURRENCY_EFFECT_EVIDENCE_MAX_BYTES = 64 * 1024
_ROOT_DOMAIN = b"sentinelforge:real-concurrency-effect-evidence:v1\x00"

_BARE_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_TYPED_SHA256 = re.compile(r"^([a-z][a-z0-9_]{0,127}):([0-9a-f]{64})$")
_BEHAVIORAL_RECEIPT = re.compile(r"^behavioral-[0-9a-f]{64}$")
_SEMANTIC = re.compile(r"^[a-z][a-z0-9_]{0,63}$")

_PROOF_MODE = "behavioral_real_concurrency_effect_v1"
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
    }
)


class RealConcurrencyEffectEvidenceError(ValueError):
    """A real-concurrency-effect evidence record is invalid."""


def _exact(value: object, fields: frozenset[str], label: str) -> Mapping[str, Any]:
    if (
        not isinstance(value, Mapping)
        or set(value) != fields
        or any(type(key) is not str for key in value)
    ):
        raise RealConcurrencyEffectEvidenceError(f"{label} fields are invalid")
    return value


def _bounded(value: object, label: str, maximum: int) -> str:
    if (
        type(value) is not str
        or not value
        or len(value) > maximum
        or value != value.strip()
        or any(ord(character) < 0x20 for character in value)
    ):
        raise RealConcurrencyEffectEvidenceError(f"{label} is invalid")
    return value


def _semantic(value: object, label: str) -> str:
    if type(value) is not str or _SEMANTIC.fullmatch(value) is None:
        raise RealConcurrencyEffectEvidenceError(f"{label} is invalid")
    return value


def _typed_ref(value: object, prefix: str, label: str) -> str:
    if type(value) is not str:
        raise RealConcurrencyEffectEvidenceError(f"{label} is invalid")
    match = _TYPED_SHA256.fullmatch(value)
    if match is None or match.group(1) != prefix:
        raise RealConcurrencyEffectEvidenceError(f"{label} is invalid")
    return value


def _behavioral_receipt(value: object, label: str) -> str:
    if type(value) is not str or _BEHAVIORAL_RECEIPT.fullmatch(value) is None:
        raise RealConcurrencyEffectEvidenceError(f"{label} is invalid")
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
        raise RealConcurrencyEffectEvidenceError(
            "real concurrency effect evidence is not JSON-safe"
        ) from exc


def _evidence_root(payload: Mapping[str, Any]) -> str:
    return hashlib.sha256(
        _ROOT_DOMAIN + _canonical_json_bytes(dict(payload))
    ).hexdigest()


@dataclass(frozen=True)
class RealConcurrencyEffectEvidence:
    schema_version: int
    evidence_root: str
    observed_origin: str
    resource_ref: str
    declared_limit: int
    observed_consumed: int
    commit_receipt_ids: tuple[str, str]
    cleanup_receipt_id: str
    overlap_proof_ref: str
    proof_ref: str
    artifact_ref: str
    proof_mode: str
    observed_at_epoch: float
    runtime_evidence_classification: str

    @classmethod
    def build(
        cls,
        *,
        observed_origin: str,
        resource_ref: str,
        declared_limit: int,
        observed_consumed: int,
        commit_receipt_ids: tuple[str, str],
        cleanup_receipt_id: str,
        overlap_proof_ref: str,
        proof_ref: str,
        artifact_ref: str,
        proof_mode: str,
        observed_at_epoch: float,
        runtime_evidence_classification: str,
    ) -> RealConcurrencyEffectEvidence:
        payload = {
            "schema_version": REAL_CONCURRENCY_EFFECT_EVIDENCE_SCHEMA_VERSION,
            "observed_origin": observed_origin,
            "resource_ref": resource_ref,
            "declared_limit": declared_limit,
            "observed_consumed": observed_consumed,
            "commit_receipt_ids": commit_receipt_ids,
            "cleanup_receipt_id": cleanup_receipt_id,
            "overlap_proof_ref": overlap_proof_ref,
            "proof_ref": proof_ref,
            "artifact_ref": artifact_ref,
            "proof_mode": proof_mode,
            "observed_at_epoch": observed_at_epoch,
            "runtime_evidence_classification": runtime_evidence_classification,
        }
        return cls(evidence_root=_evidence_root(payload), **payload)

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> RealConcurrencyEffectEvidence:
        source = _exact(value, _FIELDS, "real concurrency effect evidence")
        commit_receipt_ids = source["commit_receipt_ids"]
        if type(commit_receipt_ids) is not list:
            raise RealConcurrencyEffectEvidenceError(
                "commit receipt ids are invalid"
            )
        payload = dict(source)
        payload["commit_receipt_ids"] = tuple(commit_receipt_ids)
        return cls(**payload)

    @classmethod
    def from_json_bytes(cls, value: bytes) -> RealConcurrencyEffectEvidence:
        if type(value) is not bytes:
            raise TypeError("real concurrency effect evidence JSON must be bytes")
        if len(value) > REAL_CONCURRENCY_EFFECT_EVIDENCE_MAX_BYTES:
            raise RealConcurrencyEffectEvidenceError(
                "real concurrency effect evidence is oversized"
            )

        def reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for key, child in pairs:
                if key in result:
                    raise RealConcurrencyEffectEvidenceError(
                        "real concurrency effect evidence has duplicate keys"
                    )
                result[key] = child
            return result

        def reject_constant(value: str) -> None:
            raise RealConcurrencyEffectEvidenceError(
                f"invalid JSON constant: {value}"
            )

        try:
            parsed = json.loads(
                value.decode("utf-8", errors="strict"),
                object_pairs_hook=reject_duplicate_pairs,
                parse_constant=reject_constant,
            )
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RealConcurrencyEffectEvidenceError(
                "real concurrency effect evidence JSON is invalid"
            ) from exc
        evidence = cls.from_mapping(parsed)
        if value != evidence.to_json_bytes():
            raise RealConcurrencyEffectEvidenceError(
                "real concurrency effect evidence JSON is not canonical"
            )
        return evidence

    def __post_init__(self) -> None:
        if type(self.schema_version) is not int or self.schema_version != 1:
            raise RealConcurrencyEffectEvidenceError(
                "real concurrency effect evidence version is invalid"
            )
        if type(self.evidence_root) is not str or not _BARE_SHA256.fullmatch(
            self.evidence_root
        ):
            raise RealConcurrencyEffectEvidenceError(
                "real concurrency effect evidence root is invalid"
            )
        origin = _bounded(self.observed_origin, "observed origin", 2048)
        parsed = canonical_origin(origin)
        if parsed is None or parsed.as_url() != origin:
            raise RealConcurrencyEffectEvidenceError(
                "observed origin is not canonical"
            )
        _typed_ref(self.resource_ref, "owned_resource", "resource ref")
        if (
            type(self.declared_limit) is not int
            or not 1 <= self.declared_limit <= 2**63 - 1
        ):
            raise RealConcurrencyEffectEvidenceError("declared limit is invalid")
        if (
            type(self.observed_consumed) is not int
            or self.observed_consumed <= self.declared_limit
        ):
            raise RealConcurrencyEffectEvidenceError(
                "observed consumed is invalid"
            )
        if type(self.commit_receipt_ids) is not tuple or len(
            self.commit_receipt_ids
        ) != 2:
            raise RealConcurrencyEffectEvidenceError(
                "commit receipt ids are invalid"
            )
        for receipt_id in self.commit_receipt_ids:
            _behavioral_receipt(receipt_id, "commit receipt id")
        if self.commit_receipt_ids[0] == self.commit_receipt_ids[1]:
            raise RealConcurrencyEffectEvidenceError(
                "commit receipt ids must be distinct"
            )
        _behavioral_receipt(self.cleanup_receipt_id, "cleanup receipt id")
        _typed_ref(
            self.overlap_proof_ref,
            "concurrency_overlap",
            "overlap proof ref",
        )
        _typed_ref(
            self.proof_ref,
            "real_concurrency_effect",
            "proof ref",
        )
        _typed_ref(self.artifact_ref, "sha256", "artifact ref")
        if type(self.proof_mode) is not str or self.proof_mode != _PROOF_MODE:
            raise RealConcurrencyEffectEvidenceError("proof mode is invalid")
        if (
            type(self.observed_at_epoch) is not float
            or not math.isfinite(self.observed_at_epoch)
            or self.observed_at_epoch <= 0
        ):
            raise RealConcurrencyEffectEvidenceError("observation time is invalid")
        if (
            type(self.runtime_evidence_classification) is not str
            or self.runtime_evidence_classification not in _RUNTIME_CLASSIFICATIONS
        ):
            raise RealConcurrencyEffectEvidenceError(
                "runtime evidence classification is invalid"
            )
        payload = self.to_dict()
        payload.pop("evidence_root")
        if self.evidence_root != _evidence_root(payload):
            raise RealConcurrencyEffectEvidenceError("evidence root mismatches")
        self.to_json_bytes()

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "evidence_root": self.evidence_root,
            "observed_origin": self.observed_origin,
            "resource_ref": self.resource_ref,
            "declared_limit": self.declared_limit,
            "observed_consumed": self.observed_consumed,
            "commit_receipt_ids": list(self.commit_receipt_ids),
            "cleanup_receipt_id": self.cleanup_receipt_id,
            "overlap_proof_ref": self.overlap_proof_ref,
            "proof_ref": self.proof_ref,
            "artifact_ref": self.artifact_ref,
            "proof_mode": self.proof_mode,
            "observed_at_epoch": self.observed_at_epoch,
            "runtime_evidence_classification": self.runtime_evidence_classification,
        }

    def to_json_bytes(self) -> bytes:
        encoded = _canonical_json_bytes(self.to_dict())
        if len(encoded) > REAL_CONCURRENCY_EFFECT_EVIDENCE_MAX_BYTES:
            raise RealConcurrencyEffectEvidenceError(
                "real concurrency effect evidence is oversized"
            )
        return encoded


def corroborates(
    evidence: RealConcurrencyEffectEvidence,
    *,
    confined_origin: str,
    resource_ref: str,
    declared_limit: int,
) -> bool:
    """Purely corroborate a matching real concurrent oversell observation.

    This grants NO authority. It is the seam a FUTURE C2 candidate-derivation
    would call with the run's confined origin, resource ref, and declared limit
    before it could consider a real-concurrency authority decision. C1 wires
    none of that.
    """

    if (
        type(evidence) is not RealConcurrencyEffectEvidence
        or type(confined_origin) is not str
        or type(resource_ref) is not str
        or type(declared_limit) is not int
    ):
        return False
    try:
        left = canonical_origin(evidence.observed_origin)
        right = canonical_origin(confined_origin)
        return (
            type(evidence.resource_ref) is str
            and type(evidence.declared_limit) is int
            and type(evidence.observed_consumed) is int
            and 1 <= declared_limit <= 2**63 - 1
            and left is not None
            and right is not None
            and right.as_url() == confined_origin
            and left.as_url() == right.as_url()
            and evidence.resource_ref == resource_ref
            and evidence.declared_limit == declared_limit
            and evidence.observed_consumed > declared_limit
        )
    except Exception:
        return False


@dataclass(frozen=True)
class RealConcurrencyEffectEligibility:
    eligible: bool
    reason_code: str
    failed_clauses: Tuple[int, ...]

    def __post_init__(self) -> None:
        if type(self.eligible) is not bool:
            raise TypeError("real concurrency effect eligibility must be boolean")
        _semantic(self.reason_code, "real concurrency effect reason code")
        if type(self.failed_clauses) is not tuple or any(
            type(item) is not int or not 1 <= item <= 6
            for item in self.failed_clauses
        ):
            raise ValueError("real concurrency effect failed clauses are invalid")


def evaluate_real_concurrency_effect_eligibility(
    evidence: RealConcurrencyEffectEvidence,
) -> RealConcurrencyEffectEligibility:
    """Evaluate well-formed, honest, self-consistent evidence without authority."""

    if type(evidence) is not RealConcurrencyEffectEvidence:
        raise TypeError(
            "real concurrency effect eligibility requires typed evidence"
        )
    resource_ref = (
        _TYPED_SHA256.fullmatch(evidence.resource_ref)
        if type(evidence.resource_ref) is str
        else None
    )
    overlap_proof_ref = (
        _TYPED_SHA256.fullmatch(evidence.overlap_proof_ref)
        if type(evidence.overlap_proof_ref) is str
        else None
    )
    proof_ref = (
        _TYPED_SHA256.fullmatch(evidence.proof_ref)
        if type(evidence.proof_ref) is str
        else None
    )
    artifact_ref = (
        _TYPED_SHA256.fullmatch(evidence.artifact_ref)
        if type(evidence.artifact_ref) is str
        else None
    )
    try:
        observed_origin = canonical_origin(evidence.observed_origin)
    except (TypeError, ValueError, AttributeError):
        observed_origin = None
    try:
        preimage = evidence.to_dict()
        preimage.pop("evidence_root")
        root_valid = evidence.evidence_root == _evidence_root(preimage)
    except (TypeError, ValueError, AttributeError, KeyError):
        root_valid = False
    commit_receipts = evidence.commit_receipt_ids
    clause_1 = evidence.proof_mode == _PROOF_MODE
    clause_2 = (
        type(evidence.observed_origin) is str
        and observed_origin is not None
        and observed_origin.as_url() == evidence.observed_origin
    )
    clause_3 = bool(
        resource_ref is not None
        and resource_ref.group(1) == "owned_resource"
        and overlap_proof_ref is not None
        and overlap_proof_ref.group(1) == "concurrency_overlap"
        and proof_ref is not None
        and proof_ref.group(1) == "real_concurrency_effect"
        and artifact_ref is not None
        and artifact_ref.group(1) == "sha256"
    )
    clause_4 = bool(
        type(commit_receipts) is tuple
        and len(commit_receipts) == 2
        and all(
            type(receipt_id) is str
            and _BEHAVIORAL_RECEIPT.fullmatch(receipt_id) is not None
            for receipt_id in commit_receipts
        )
        and commit_receipts[0] != commit_receipts[1]
        and type(evidence.cleanup_receipt_id) is str
        and _BEHAVIORAL_RECEIPT.fullmatch(evidence.cleanup_receipt_id) is not None
    )
    clause_5 = (
        type(evidence.runtime_evidence_classification) is str
        and evidence.runtime_evidence_classification in _HONEST_CLASSIFICATIONS
    )
    clause_6 = (
        type(evidence.declared_limit) is int
        and type(evidence.observed_consumed) is int
        and evidence.observed_consumed > evidence.declared_limit >= 1
        and type(evidence.observed_at_epoch) is float
        and math.isfinite(evidence.observed_at_epoch)
        and evidence.observed_at_epoch > 0
        and root_valid
    )
    clauses = (clause_1, clause_2, clause_3, clause_4, clause_5, clause_6)
    failed = tuple(index for index, passed in enumerate(clauses, 1) if not passed)
    if not failed:
        return RealConcurrencyEffectEligibility(
            eligible=True,
            reason_code="eligible_real_concurrency_effect",
            failed_clauses=(),
        )
    reasons = {
        1: "proof_mode_mismatch",
        2: "observed_origin_not_canonical",
        3: "refs_malformed",
        4: "receipts_malformed",
        5: "runtime_classification_not_honest",
        6: "source_validation_failed",
    }
    return RealConcurrencyEffectEligibility(
        eligible=False,
        reason_code=reasons[failed[0]],
        failed_clauses=failed,
    )
