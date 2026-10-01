"""R5F5: passive, unwired retained race evidence and inert eligibility.

No production entry point imports this module. It adds no authority of any kind.
The evaluator runs a deterministic offline logical schedule, with no real
concurrency, threads, async execution, or clock. Its result is not independent
evidence of an observed target-side effect. Running-workflow effect proof and
native OCB-S22 are deferred to the active tail.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import json
import os
from pathlib import Path
from typing import Any, Mapping

from .concurrency_invariant_binding import (
    ConcurrencyCaptureProvenance,
    ConcurrencyInvariantBinding,
    validate_current_capture,
)
from .concurrency_invariant_contract import (
    ConcurrencyOutcome,
    _fields,
    _hash_ref,
    _passive_flags,
    _revalidate,
)
from .concurrency_invariant_ledger import ConcurrencyScheduleResult
from .concurrency_invariant_store import _canonical_json
from .normalize import stable_hash
from .receipts import BehavioralReceiptStore, ReceiptStoreError, _MAX_RECEIPT_BYTES

CONCURRENCY_INVARIANT_EVIDENCE_ENV = "SENTINELFORGE_CONCURRENCY_INVARIANT_EVIDENCE"
CONCURRENCY_INVARIANT_EVIDENCE_MODE = "behavioral_concurrency_invariant_evidence_v1"
_RETAINED_BY_STORE = object()


class ConcurrencyInvariantEvidenceError(RuntimeError):
    """Offline race evidence cannot be safely retained or integrity-checked."""


def _evidence_payload(result: ConcurrencyScheduleResult) -> dict[str, Any]:
    return {
        "mode": CONCURRENCY_INVARIANT_EVIDENCE_MODE,
        "schedule_result": result.to_dict(),
        "evidence_kind": "deterministic_offline_schedule_result",
        "observed_target_effect": False,
        **_passive_flags(),
    }


def _evidence_id(result: ConcurrencyScheduleResult) -> str:
    return stable_hash("concurrency_invariant_evidence", _evidence_payload(result))


@dataclass(frozen=True)
class StoredConcurrencyInvariantEvidence:
    """Store-minted inert value; a public serialization cannot mint retention."""

    evidence_id: str
    _result: ConcurrencyScheduleResult = field(repr=False)
    _storage_marker: object = field(repr=False, compare=False)
    reloaded: bool = True

    def __post_init__(self) -> None:
        if (
            type(self._result) is not ConcurrencyScheduleResult
            or self._storage_marker is not _RETAINED_BY_STORE
            or self.reloaded is not True
            or not _hash_ref(self.evidence_id, "concurrency_invariant_evidence")
        ):
            raise ConcurrencyInvariantEvidenceError(
                "concurrency_evidence_not_retained_by_store"
            )
        _revalidate(self._result)
        if self.evidence_id != _evidence_id(self._result):
            raise ConcurrencyInvariantEvidenceError(
                "concurrency_evidence_address_mismatch"
            )

    @property
    def outcome(self) -> ConcurrencyOutcome:
        return self._result.decision.outcome

    @property
    def race_confirmed(self) -> bool:
        return self._result.decision.race_confirmed

    @property
    def result_ref(self) -> str:
        return self._result.result_id

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "evidence_id": self.evidence_id,
            **_evidence_payload(self._result),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> StoredConcurrencyInvariantEvidence:
        raise ConcurrencyInvariantEvidenceError(
            "retention requires validated store reload"
        )


@dataclass(frozen=True)
class ConcurrencyEvidencePersistence:
    evidence: StoredConcurrencyInvariantEvidence
    durable_written: bool

    def __post_init__(self) -> None:
        if (
            type(self.evidence) is not StoredConcurrencyInvariantEvidence
            or type(self.durable_written) is not bool
        ):
            raise ConcurrencyInvariantEvidenceError(
                "concurrency_evidence_persistence_invalid"
            )
        _revalidate(self.evidence)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "evidence": self.evidence.to_dict(),
            "durable_written": self.durable_written,
            **_passive_flags(),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> ConcurrencyEvidencePersistence:
        raise ConcurrencyInvariantEvidenceError(
            "retention requires validated store reload"
        )


class ConcurrencyInvariantEvidenceStore:
    """Exclusive-publication offline evidence store with no finding authority."""

    def __init__(self, root: Path | None = None) -> None:
        self.root = root

    def _root(self) -> Path:
        if self.root is not None:
            return self.root
        override = os.environ.get(CONCURRENCY_INVARIANT_EVIDENCE_ENV)
        if override:
            return Path(override)
        data = os.environ.get("SENTINEL_DATA_DIR")
        return (
            Path(data) / "concurrency_invariant_evidence"
            if data
            else Path.home() / ".sentinelforge" / "concurrency_invariant_evidence"
        )

    def _prepare_root(self) -> Path:
        try:
            return BehavioralReceiptStore(self._root())._prepare_root()
        except (OSError, ReceiptStoreError) as exc:
            raise ConcurrencyInvariantEvidenceError(
                "concurrency_evidence_root_unsafe"
            ) from exc

    @staticmethod
    def _file_name(evidence_id: str) -> str:
        if not _hash_ref(evidence_id, "concurrency_invariant_evidence"):
            raise ConcurrencyInvariantEvidenceError(
                "concurrency_evidence_reference_invalid"
            )
        return f"concurrency-evidence-{evidence_id.split(':', 1)[1]}.json"

    @staticmethod
    def _read(path: Path, evidence_id: str) -> StoredConcurrencyInvariantEvidence:
        descriptor = -1
        try:
            descriptor = os.open(
                path,
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
            )
            BehavioralReceiptStore._validate_file_info(os.fstat(descriptor))
            handle = os.fdopen(descriptor, "r", encoding="utf-8")
            descriptor = -1
            with handle:
                payload = handle.read(_MAX_RECEIPT_BYTES + 1)
            value = _fields(
                json.loads(payload),
                {
                    "evidence_id",
                    "mode",
                    "schedule_result",
                    "evidence_kind",
                    "observed_target_effect",
                    *_passive_flags(),
                },
            )
            result = ConcurrencyScheduleResult.from_dict(value["schedule_result"])
            expected = {
                "schema_version": 1,
                "evidence_id": _evidence_id(result),
                **_evidence_payload(result),
            }
            if value["evidence_id"] != evidence_id or payload != _canonical_json(
                expected
            ):
                raise ConcurrencyInvariantEvidenceError(
                    "concurrency_evidence_address_or_encoding_mismatch"
                )
            return StoredConcurrencyInvariantEvidence(
                evidence_id, result, _RETAINED_BY_STORE
            )
        except ConcurrencyInvariantEvidenceError:
            raise
        except (
            OSError,
            ReceiptStoreError,
            UnicodeError,
            ValueError,
            TypeError,
            KeyError,
            AttributeError,
        ) as exc:
            raise ConcurrencyInvariantEvidenceError(
                "concurrency_evidence_unreadable"
            ) from exc
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    def load(self, evidence_id: str) -> StoredConcurrencyInvariantEvidence | None:
        name = self._file_name(evidence_id)
        try:
            self._root().lstat()
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise ConcurrencyInvariantEvidenceError(
                "concurrency_evidence_root_unreadable"
            ) from exc
        root = self._prepare_root()
        path = root / name
        try:
            path.lstat()
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise ConcurrencyInvariantEvidenceError(
                "concurrency_evidence_path_unreadable"
            ) from exc
        return self._read(path, evidence_id)

    def persist(
        self, result: ConcurrencyScheduleResult
    ) -> ConcurrencyEvidencePersistence:
        if type(result) is not ConcurrencyScheduleResult:
            raise ConcurrencyInvariantEvidenceError(
                "concurrency_evidence_requires_completed_result"
            )
        _revalidate(result)
        evidence_id = _evidence_id(result)
        payload = _canonical_json(
            {
                "schema_version": 1,
                "evidence_id": evidence_id,
                **_evidence_payload(result),
            }
        )
        if len(payload.encode("utf-8")) > _MAX_RECEIPT_BYTES:
            raise ConcurrencyInvariantEvidenceError(
                "concurrency_evidence_size_cap_exceeded"
            )
        root = self._prepare_root()
        path = root / self._file_name(evidence_id)
        written = True
        try:
            BehavioralReceiptStore._link_exclusive(path, payload)
            BehavioralReceiptStore._fsync_directory(root)
        except FileExistsError:
            written = False
        except (OSError, ReceiptStoreError) as exc:
            raise ConcurrencyInvariantEvidenceError(
                "concurrency_evidence_publication_failed"
            ) from exc
        retained = self._read(path, evidence_id)
        if retained.to_dict() != json.loads(payload):
            raise ConcurrencyInvariantEvidenceError(
                "concurrency_evidence_collision_mismatch"
            )
        return ConcurrencyEvidencePersistence(retained, written)


@dataclass(frozen=True)
class ConcurrencyPromotionEligibility:
    """Family F's inert answer to offline race-counterexample eligibility."""

    eligible: bool
    evidence_ref: str | None
    reason_code: str

    def __post_init__(self) -> None:
        if (
            type(self.eligible) is not bool
            or (
                self.evidence_ref is not None
                and not _hash_ref(self.evidence_ref, "concurrency_invariant_evidence")
            )
            or self.reason_code
            not in {
                "retained_evidence_required",
                "invalid_or_stale_evidence",
                "race_counterexample_not_confirmed",
                "retained_fresh_offline_counterexample",
            }
            or self.eligible
            != (self.reason_code == "retained_fresh_offline_counterexample")
            or (self.eligible and self.evidence_ref is None)
        ):
            raise ConcurrencyInvariantEvidenceError("concurrency_eligibility_invalid")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "eligible": self.eligible,
            "evidence_ref": self.evidence_ref,
            "reason_code": self.reason_code,
            "offline_only": True,
            **_passive_flags(),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> ConcurrencyPromotionEligibility:
        value = _fields(
            value,
            {
                "eligible",
                "evidence_ref",
                "reason_code",
                "offline_only",
                *_passive_flags(),
            },
        )
        result = cls(value["eligible"], value["evidence_ref"], value["reason_code"])
        if value != result.to_dict():
            raise ConcurrencyInvariantEvidenceError(
                "concurrency_eligibility_flags_invalid"
            )
        return result


def offline_promotion_eligibility(
    evidence: StoredConcurrencyInvariantEvidence,
    binding: ConcurrencyInvariantBinding,
    current_capture: ConcurrencyCaptureProvenance,
    *,
    at_index: int,
) -> ConcurrencyPromotionEligibility:
    """Pure retained/fresh/exact-binding predicate; never promotes a finding."""
    if type(evidence) is not StoredConcurrencyInvariantEvidence:
        return ConcurrencyPromotionEligibility(
            False, None, "retained_evidence_required"
        )
    try:
        _revalidate(evidence)
        if type(binding) is not ConcurrencyInvariantBinding:
            raise ConcurrencyInvariantEvidenceError("concurrency_binding_type_invalid")
        _revalidate(binding)
        retained_binding = evidence._result.ledger.binding
        if binding.binding_id != retained_binding.binding_id:
            raise ConcurrencyInvariantEvidenceError("concurrency_binding_mismatch")
        validate_current_capture(retained_binding, current_capture, at_index)
    except (ConcurrencyInvariantEvidenceError, ValueError, TypeError, AttributeError):
        return ConcurrencyPromotionEligibility(False, None, "invalid_or_stale_evidence")
    if (
        evidence.outcome is not ConcurrencyOutcome.INVARIANT_VIOLATED
        or not evidence.race_confirmed
    ):
        return ConcurrencyPromotionEligibility(
            False, evidence.evidence_id, "race_counterexample_not_confirmed"
        )
    return ConcurrencyPromotionEligibility(
        True, evidence.evidence_id, "retained_fresh_offline_counterexample"
    )
