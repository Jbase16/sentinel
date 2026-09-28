"""R5E5: durable inert offline evidence and passive promotion eligibility.

Retains an already-completed E3 deterministic result, using receipt-store exclusive
publication. Reload recomputes hashes, pure transitions and the separate invariant
predicate, then mints a distinct inert value. Eligibility requires that retained
value, a violated invariant, the exact owned binding, and fresh current provenance.
The predicate performs no I/O and grants no promotion authority.

Passive/unwired; bounded local filesystem I/O only. No production router, Foundry,
Scan, scheduler or coordinator calls this layer. No origin, identity, action class,
budget, transport, receipt/certificate/finding or execution authority is added.
Disposable fixtures have no cleanup obligation or orphan risk. This is a
deterministic outcome evaluator, not independent evidence of an observed target-side
effect. Running-workflow effect proof and OCB-S21 are deferred to the active tail.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import json
import os
from pathlib import Path
from typing import Any, Mapping

from .normalize import stable_hash
from .receipts import BehavioralReceiptStore, ReceiptStoreError, _MAX_RECEIPT_BYTES
from .workflow_invariant_binding import (
    WorkflowCaptureProvenance,
    validate_current_capture,
)
from .workflow_invariant_contract import (
    WorkflowInvariantOutcome,
    _fields,
    _hash_ref,
    _revalidate,
    classify_sequence,
)
from .workflow_invariant_ledger import WorkflowSequenceResult, WorkflowTransitionLedger
from .workflow_invariant_store import _canonical_json

WORKFLOW_INVARIANT_EVIDENCE_ENV = "SENTINELFORGE_WORKFLOW_INVARIANT_EVIDENCE"
WORKFLOW_INVARIANT_EVIDENCE_MODE = "behavioral_workflow_invariant_evidence_v1"
# A serialization or an ephemeral evaluator result cannot assert successful local
# retention. Only the store's validated read boundary supplies this private marker.
_RETAINED_BY_STORE = object()


class WorkflowInvariantEvidenceError(RuntimeError):
    """Offline evidence cannot be safely retained or integrity-checked."""


def _evidence_payload(result: WorkflowSequenceResult) -> dict[str, Any]:
    return {
        "mode": WORKFLOW_INVARIANT_EVIDENCE_MODE,
        "sequence_result": result.to_dict(),
        "evidence_kind": "deterministic_offline_result",
        "observed_target_effect": False,
        "target_requests_sent": 0,
        "executable": False,
        "promotion_authority": False,
        "finding_authority": False,
        "orphan_risk": False,
    }


def _evidence_id(result: WorkflowSequenceResult) -> str:
    return stable_hash("workflow_invariant_evidence", _evidence_payload(result))


@dataclass(frozen=True)
class StoredWorkflowInvariantEvidence:
    """Distinct inert retained value; public deserialization cannot mint this type."""

    evidence_id: str
    _result: WorkflowSequenceResult = field(repr=False)
    _storage_marker: object = field(repr=False, compare=False)
    reloaded: bool = True

    def __post_init__(self) -> None:
        if (
            type(self._result) is not WorkflowSequenceResult
            or self._storage_marker is not _RETAINED_BY_STORE
            or self.reloaded is not True
            or not _hash_ref(self.evidence_id, "workflow_invariant_evidence")
        ):
            raise WorkflowInvariantEvidenceError(
                "workflow_evidence_not_retained_by_store"
            )
        _revalidate(self._result)
        if self.evidence_id != _evidence_id(self._result):
            raise WorkflowInvariantEvidenceError("workflow_evidence_address_mismatch")

    @property
    def outcome(self) -> WorkflowInvariantOutcome:
        return self._result.decision.outcome

    @property
    def result_ref(self) -> str:
        return self._result.result_id

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "evidence_id": self.evidence_id,
            **_evidence_payload(self._result),
        }


@dataclass(frozen=True)
class WorkflowEvidencePersistence:
    evidence: StoredWorkflowInvariantEvidence
    durable_written: bool

    def __post_init__(self) -> None:
        if (
            type(self.evidence) is not StoredWorkflowInvariantEvidence
            or type(self.durable_written) is not bool
        ):
            raise WorkflowInvariantEvidenceError(
                "workflow_evidence_persistence_invalid"
            )
        _revalidate(self.evidence)


def _decode_result(value: Mapping[str, Any]) -> WorkflowSequenceResult:
    value = _fields(value, {"result_id", "ledger", "at_index", "decision"})
    ledger = WorkflowTransitionLedger.from_dict(value["ledger"])
    contract = ledger.binding.fixture.contract
    decision = classify_sequence(contract, contract.initial_state, contract.operations)
    result = WorkflowSequenceResult(ledger, value["at_index"], decision)
    if _canonical_json(value) != _canonical_json(result.to_dict()):
        raise WorkflowInvariantEvidenceError("workflow_retained_result_mismatch")
    return result


class WorkflowInvariantEvidenceStore:
    """Append-only content-addressed offline evidence, no promotion or dispatch."""

    def __init__(self, root: Path | None = None) -> None:
        self.root = root

    def _root(self) -> Path:
        if self.root is not None:
            return self.root
        override = os.environ.get(WORKFLOW_INVARIANT_EVIDENCE_ENV)
        if override:
            return Path(override)
        data = os.environ.get("SENTINEL_DATA_DIR")
        return (
            Path(data) / "workflow_invariant_evidence"
            if data
            else Path.home() / ".sentinelforge" / "workflow_invariant_evidence"
        )

    def _prepare_root(self) -> Path:
        try:
            return BehavioralReceiptStore(self._root())._prepare_root()
        except (OSError, ReceiptStoreError) as exc:
            raise WorkflowInvariantEvidenceError(
                "workflow_evidence_root_unsafe"
            ) from exc

    @staticmethod
    def _file_name(evidence_id: str) -> str:
        if not _hash_ref(evidence_id, "workflow_invariant_evidence"):
            raise WorkflowInvariantEvidenceError("workflow_evidence_reference_invalid")
        return f"workflow-evidence-{evidence_id.split(':', 1)[1]}.json"

    @staticmethod
    def _read(path: Path, evidence_id: str) -> StoredWorkflowInvariantEvidence:
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
                    "sequence_result",
                    "evidence_kind",
                    "observed_target_effect",
                    "target_requests_sent",
                    "executable",
                    "promotion_authority",
                    "finding_authority",
                    "orphan_risk",
                },
            )
            result = _decode_result(value["sequence_result"])
            expected = {
                "schema_version": 1,
                "evidence_id": _evidence_id(result),
                **_evidence_payload(result),
            }
            if value["evidence_id"] != evidence_id or payload != _canonical_json(
                expected
            ):
                raise WorkflowInvariantEvidenceError(
                    "workflow_evidence_encoding_or_address_mismatch"
                )
            return StoredWorkflowInvariantEvidence(
                evidence_id, result, _RETAINED_BY_STORE
            )
        except WorkflowInvariantEvidenceError:
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
            raise WorkflowInvariantEvidenceError(
                "workflow_evidence_unreadable"
            ) from exc
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    def load(self, evidence_id: str) -> StoredWorkflowInvariantEvidence | None:
        name = self._file_name(evidence_id)
        try:
            self._root().lstat()
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise WorkflowInvariantEvidenceError(
                "workflow_evidence_root_unreadable"
            ) from exc
        root = self._prepare_root()
        path = root / name
        try:
            path.lstat()
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise WorkflowInvariantEvidenceError(
                "workflow_evidence_path_unreadable"
            ) from exc
        return self._read(path, evidence_id)

    def persist(self, result: WorkflowSequenceResult) -> WorkflowEvidencePersistence:
        if type(result) is not WorkflowSequenceResult:
            raise WorkflowInvariantEvidenceError(
                "workflow_evidence_requires_completed_offline_result"
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
            raise WorkflowInvariantEvidenceError("workflow_evidence_size_cap_exceeded")
        root = self._prepare_root()
        path = root / self._file_name(evidence_id)
        written = True
        try:
            BehavioralReceiptStore._link_exclusive(path, payload)
            BehavioralReceiptStore._fsync_directory(root)
        except FileExistsError:
            written = False
        except (OSError, ReceiptStoreError) as exc:
            raise WorkflowInvariantEvidenceError(
                "workflow_evidence_publication_failed"
            ) from exc
        retained = self._read(path, evidence_id)
        if retained.to_dict() != json.loads(payload):
            raise WorkflowInvariantEvidenceError("workflow_evidence_collision_mismatch")
        return WorkflowEvidencePersistence(retained, written)


@dataclass(frozen=True)
class WorkflowPromotionEligibility:
    """Family E's own inert answer to 'would this offline result be promotable?'"""

    eligible: bool
    evidence_ref: str | None
    reason_code: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "eligible": self.eligible,
            "evidence_ref": self.evidence_ref,
            "reason_code": self.reason_code,
            "offline_only": True,
            "promotion_authority": False,
            "finding_authority": False,
            "executable": False,
        }


def offline_promotion_eligibility(
    evidence: StoredWorkflowInvariantEvidence,
    current_capture: WorkflowCaptureProvenance,
    *,
    at_index: int,
) -> WorkflowPromotionEligibility:
    """Pure, fail-closed retained/fresh/positive predicate; never promote a finding."""
    if type(evidence) is not StoredWorkflowInvariantEvidence:
        return WorkflowPromotionEligibility(False, None, "retained_evidence_required")
    try:
        _revalidate(evidence)
        validate_current_capture(
            evidence._result.ledger.binding, current_capture, at_index
        )
    except (WorkflowInvariantEvidenceError, ValueError, TypeError, AttributeError):
        return WorkflowPromotionEligibility(False, None, "invalid_or_stale_evidence")
    if evidence.outcome is not WorkflowInvariantOutcome.INVARIANT_VIOLATED:
        return WorkflowPromotionEligibility(
            False, evidence.evidence_id, "invariant_not_violated"
        )
    return WorkflowPromotionEligibility(
        True, evidence.evidence_id, "retained_fresh_offline_counterexample"
    )
