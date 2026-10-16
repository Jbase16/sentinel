"""Durable R5E9f workflow-effect admission, status, and promotion.

This module deliberately has no transport, browser, capture, credential-vault,
or cleanup dependency.  Initial processing, explicit retry, and startup
reconciliation all call the same local service over an already completed inner
behavioral receipt.
"""

from __future__ import annotations

from dataclasses import dataclass
import logging
import os
from pathlib import Path
import sqlite3
import stat
import time
from typing import Any, Mapping, Optional
import uuid

from core.base.config import SentinelConfig, get_config
from core.base.scope import canonical_origin
from core.behavior.normalize import stable_hash
from core.behavior.receipts import (
    ABORTED,
    COMPLETED,
    RESERVED,
    BehavioralReceiptStore,
    ReceiptStoreError,
)
from core.epistemic.ledger import EvidenceLedger, LifecycleState
from core.epistemic.cas import ContentAddressableStorage
from core.epistemic.persistence import (
    CanonicalEvidenceRepository,
    _workflow_admission_id,
)
from core.epistemic.storage_boundary import (
    EvidenceStorageAnchor,
    production_evidence_roots,
)
from core.identity import AssessmentIdentityContext, CredentialFreshness


WORKFLOW_FINDING_PROMOTION_ENV = "SENTINELFORGE_BEHAVIOR_WORKFLOW_FINDING_PROMOTION"
WORKFLOW_INVARIANT_VIOLATION_CLASS = "workflow_invariant_violation_v1"
_TRUE = frozenset({"1", "true", "yes", "on"})
logger = logging.getLogger(__name__)


class _AnchoredRepository:
    """Revalidate the storage anchor around every SQLite adapter call."""

    def __init__(
        self,
        repository: CanonicalEvidenceRepository,
        anchor: EvidenceStorageAnchor,
    ) -> None:
        self._repository = repository
        self._anchor = anchor

    def __getattr__(self, name: str) -> Any:
        attribute = getattr(self._repository, name)
        if not callable(attribute):
            return attribute

        def guarded(*args: Any, **kwargs: Any) -> Any:
            self._anchor.assert_unchanged()
            try:
                return attribute(*args, **kwargs)
            finally:
                self._anchor.assert_unchanged()

        return guarded


class _AnchoredEvidenceLedger(EvidenceLedger):
    """Apply the same location anchor to ledger construction and audit writes."""

    def __init__(
        self,
        config: SentinelConfig,
        *,
        receipt_store: BehavioralReceiptStore,
        storage_anchor: EvidenceStorageAnchor,
        cas: ContentAddressableStorage,
        repository: _AnchoredRepository,
    ) -> None:
        self._workflow_storage_anchor = storage_anchor
        storage_anchor.assert_unchanged()
        super().__init__(config, receipt_store=receipt_store)
        storage_anchor.assert_unchanged()
        self.cas = cas
        self._repository = repository

    def _ensure_audit_log(self) -> None:
        self._workflow_storage_anchor.assert_unchanged()
        try:
            super()._ensure_audit_log()
        finally:
            self._workflow_storage_anchor.assert_unchanged()

    def _append_audit_event(self, event: Any) -> None:
        self._workflow_storage_anchor.assert_unchanged()
        try:
            super()._append_audit_event(event)
        finally:
            self._workflow_storage_anchor.assert_unchanged()


class WorkflowEffectPromotionError(RuntimeError):
    """A retained source could not be classified or admitted safely."""


class WorkflowEffectSourceUnavailable(WorkflowEffectPromotionError):
    """A retained source could not be read because local persistence failed."""


class WorkflowEffectSourceInvalid(WorkflowEffectPromotionError):
    """A retained source was read but failed its durable receipt contract."""


@dataclass(frozen=True)
class WorkflowFindingPromotionConfig:
    enabled: bool = False

    def __post_init__(self) -> None:
        if type(self.enabled) is not bool:
            raise TypeError("workflow finding promotion enabled must be boolean")

    @classmethod
    def from_environment(cls) -> "WorkflowFindingPromotionConfig":
        return cls(
            enabled=(
                str(os.environ.get(WORKFLOW_FINDING_PROMOTION_ENV, ""))
                .strip()
                .lower()
                in _TRUE
            )
        )


@dataclass(frozen=True)
class WorkflowEffectAdmission:
    admission_id: str
    session_id: str
    target_origin: str
    identity_binding: Mapping[str, Any]
    specification_id: str
    transport_specification_id: str
    candidate_id: str
    producer_identity: Mapping[str, Any]
    source_receipt_id: Optional[str]
    source_fingerprint: Optional[str]
    event_timestamp: float
    event_run_id: str

    @classmethod
    def from_record(cls, value: Mapping[str, Any]) -> "WorkflowEffectAdmission":
        return cls(
            admission_id=value["admission_id"],
            session_id=value["session_id"],
            target_origin=value["target_origin"],
            identity_binding=dict(value["identity_data"]),
            specification_id=value["specification_id"],
            transport_specification_id=value["transport_specification_id"],
            candidate_id=value["candidate_id"],
            producer_identity=dict(value["producer_data"]),
            source_receipt_id=value.get("source_receipt_id"),
            source_fingerprint=value.get("source_fingerprint"),
            event_timestamp=float(value["event_timestamp"]),
            event_run_id=value["event_run_id"],
        )


@dataclass(frozen=True)
class WorkflowEffectPromotionStatus:
    execution_id: str
    assessment_session_id: Optional[str]
    source_receipt_id: Optional[str]
    execution_state: str
    evidence_classification: str
    promotion_state: str
    reason_code: str
    canonical_observation_id: Optional[str] = None
    canonical_finding_id: Optional[str] = None
    permitted_next_local_action: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "slice": "R5E9f",
            "execution_id": self.execution_id,
            "assessment_session_id": self.assessment_session_id,
            "source_receipt_id": self.source_receipt_id,
            "execution_state": self.execution_state,
            "evidence_classification": self.evidence_classification,
            "promotion_state": self.promotion_state,
            "reason_code": self.reason_code,
            "canonical_observation_id": self.canonical_observation_id,
            "canonical_finding_id": self.canonical_finding_id,
            "permitted_next_local_action": self.permitted_next_local_action,
        }


class WorkflowEffectPromotionService:
    """The sole processor for initial, explicit, and restart promotion."""

    def __init__(
        self,
        config: Optional[SentinelConfig] = None,
        *,
        receipt_store: Optional[BehavioralReceiptStore] = None,
    ) -> None:
        self.config = config or get_config()
        self.receipt_store = receipt_store or BehavioralReceiptStore()
        self._storage_anchor = EvidenceStorageAnchor(
            production_evidence_roots(
                self.config,
                behavioral_receipt_root=self.receipt_store._root(),
            )
        )
        roots = self._storage_anchor.resolved_locations
        self._resolved_roots = tuple(str(item) for item in roots)
        self.receipt_store.bind_storage_anchor(self._storage_anchor)
        self._storage_anchor.assert_unchanged()
        repository = CanonicalEvidenceRepository(self.config.storage.db_path)
        self._storage_anchor.assert_unchanged()
        self._storage_anchor.seal()
        self.repository = _AnchoredRepository(repository, self._storage_anchor)
        self._cas = ContentAddressableStorage(
            self.config,
            storage_anchor=self._storage_anchor,
        )

    @staticmethod
    def _preflight_audit_path(path: Path) -> None:
        if path.is_symlink():
            raise ValueError("canonical audit path is unsafe")
        probe_path = path
        temporary = False
        flags = (
            os.O_WRONLY
            | os.O_APPEND
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        if not path.exists():
            probe_path = path.with_name(f".audit-preflight.{uuid.uuid4().hex}")
            flags |= os.O_CREAT | os.O_EXCL
            temporary = True
        descriptor = os.open(
            probe_path,
            flags,
            0o600,
        )
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or metadata.st_mode & 0o022
            ):
                raise ValueError("canonical audit path ownership or mode is unsafe")
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        if temporary:
            probe_path.unlink()
            ContentAddressableStorage._fsync_directory(path.parent)

    def preflight_local_persistence(self) -> None:
        """Revalidate and exercise every required local persistence surface."""

        current_roots = self._storage_anchor.assert_unchanged()
        if tuple(str(item) for item in current_roots) != self._resolved_roots:
            raise ValueError("workflow evidence storage changed after admission")
        self.receipt_store.preflight()
        self._storage_anchor.assert_unchanged()
        self._cas.preflight()
        self._storage_anchor.assert_unchanged()
        self._preflight_audit_path(Path(self.config.storage.base_dir) / "audit.jsonl")
        self._storage_anchor.assert_unchanged()
        self.repository.preflight(uuid.uuid4().hex)
        self._storage_anchor.seal()

    def _new_ledger(self) -> EvidenceLedger:
        return _AnchoredEvidenceLedger(
            self.config,
            receipt_store=self.receipt_store,
            storage_anchor=self._storage_anchor,
            cas=self._cas,
            repository=self.repository,
        )

    def reserve_execution(
        self,
        *,
        target_origin: str,
        authorization_envelope_id: str,
        authorization_envelope_ref: str,
        persona_id: str,
        persona_source_ref: str,
        world_persona_ref: str,
        tenant_ref: str,
        binding_ref: str,
        specification_id: str,
        transport_specification_id: str,
        candidate_id: str,
        source_fingerprint: str,
        event_run_id: str,
        requested_session_id: Optional[str] = None,
        producer_identity: Optional[Mapping[str, Any]] = None,
    ) -> WorkflowEffectAdmission:
        """Reserve candidate-owned journal context without granting authority."""

        from core.behavior.workflow_effect_evidence import (
            workflow_effect_producer_build_identity,
        )

        self.preflight_local_persistence()
        origin = canonical_origin(target_origin)
        if origin is None:
            raise ValueError("workflow admission target origin is invalid")
        if (
            not isinstance(source_fingerprint, str)
            or len(source_fingerprint) != 64
            or any(character not in "0123456789abcdef" for character in source_fingerprint)
        ):
            raise ValueError("workflow source fingerprint is invalid")
        source_receipt_id = f"behavioral-{source_fingerprint}"
        producer = dict(producer_identity or workflow_effect_producer_build_identity())
        owner_record = self.repository.load_workflow_effect_admission(source_receipt_id)
        owner = (
            WorkflowEffectAdmission.from_record(owner_record)
            if owner_record is not None
            else None
        )
        if owner is not None and requested_session_id not in (None, owner.session_id):
            raise ValueError("workflow source owner session collision")
        session_id = (
            owner.session_id if owner is not None else requested_session_id
        ) or str(
            uuid.uuid5(uuid.NAMESPACE_URL, f"sentinelforge:r5e9f:{source_fingerprint}")
        )
        timestamp = float(time.time())
        if timestamp <= 0:
            raise ValueError("workflow admission timestamp is invalid")
        identity = AssessmentIdentityContext(
            session_id=session_id,
            authorization_envelope_id=authorization_envelope_id,
            authorization_envelope_ref=authorization_envelope_ref,
            target_origin=origin.as_url(),
            target_reset_epoch=0,
            world_id=persona_id,
            persona_id=persona_id,
            target_actor_id=world_persona_ref,
            tenant_id=tenant_ref,
            credential_source_ref=persona_source_ref,
            credential_epoch=0,
            credential_freshness=CredentialFreshness.UNKNOWN,
            resource_id=stable_hash("resource", binding_ref),
            representation_id=stable_hash("representation", specification_id),
        )
        if owner is not None:
            if (
                owner.target_origin != origin.as_url()
                or owner.identity_binding != identity.to_dict()
                or owner.specification_id != specification_id
                or owner.transport_specification_id != transport_specification_id
                or owner.candidate_id != candidate_id
                or owner.producer_identity != producer
            ):
                raise ValueError("workflow source owner context collision")
            return owner
        admission_id = _workflow_admission_id(
            session_id=session_id,
            target_origin=origin.as_url(),
            identity_digest=identity.digest,
            specification_id=specification_id,
            transport_specification_id=transport_specification_id,
            candidate_id=candidate_id,
            producer=producer,
        )
        self.repository.reserve_workflow_effect_promotion(
            admission_id=admission_id,
            session_id=session_id,
            target_origin=origin.as_url(),
            identity=identity.to_dict(),
            specification_id=specification_id,
            transport_specification_id=transport_specification_id,
            candidate_id=candidate_id,
            producer=producer,
            event_timestamp=timestamp,
            event_run_id=event_run_id,
        )
        record = self.repository.bind_workflow_effect_source(
            admission_id=admission_id,
            source_receipt_id=source_receipt_id,
            source_fingerprint=source_fingerprint,
        )
        return WorkflowEffectAdmission.from_record(record)

    def _receipt_for(
        self,
        admission: WorkflowEffectAdmission,
    ) -> Any:
        if admission.source_fingerprint is None:
            return None
        try:
            receipt = self.receipt_store.load(admission.source_fingerprint)
        except OSError as exc:
            raise WorkflowEffectSourceUnavailable(
                "source_receipt_unavailable"
            ) from exc
        except ReceiptStoreError as exc:
            if isinstance(exc.__cause__, OSError):
                raise WorkflowEffectSourceUnavailable(
                    "source_receipt_unavailable"
                ) from exc
            raise WorkflowEffectSourceInvalid(
                "invalid_or_corrupted_evidence"
            ) from exc
        if receipt is None:
            raise WorkflowEffectSourceUnavailable("source_receipt_unavailable")
        return receipt

    @staticmethod
    def _evidence_from_receipt(receipt: Any) -> Any:
        from core.behavior.workflow_effect_evidence import WorkflowEffectEvidence

        if (
            receipt is None
            or receipt.state != COMPLETED
            or not isinstance(receipt.outcome, Mapping)
        ):
            return None
        value = receipt.outcome.get("workflow_effect_evidence")
        if value is None:
            return None
        if not isinstance(value, Mapping):
            raise WorkflowEffectSourceInvalid("invalid_or_corrupted_evidence")
        try:
            return WorkflowEffectEvidence.from_mapping(value)
        except (TypeError, ValueError) as exc:
            raise WorkflowEffectSourceInvalid(
                "invalid_or_corrupted_evidence"
            ) from exc

    @staticmethod
    def _corresponds(
        admission: WorkflowEffectAdmission,
        evidence: Any,
    ) -> bool:
        return bool(
            evidence.source_receipt_id == admission.source_receipt_id
            and evidence.execution_admission_ref == admission.admission_id
            and evidence.assessment_session_id == admission.session_id
            and evidence.identity_binding == admission.identity_binding
            and evidence.target_origin == admission.target_origin
            and evidence.specification_id == admission.specification_id
            and evidence.transport_specification_id == admission.transport_specification_id
            and evidence.candidate_id == admission.candidate_id
            and evidence.producer_identity == admission.producer_identity
        )

    def _result(
        self,
        admission: WorkflowEffectAdmission,
        *,
        execution_state: str,
        evidence_classification: str,
        promotion_state: str,
        reason_code: str,
        next_action: Optional[str] = None,
        record: Optional[Mapping[str, Any]] = None,
    ) -> WorkflowEffectPromotionStatus:
        source_id = admission.source_receipt_id
        return WorkflowEffectPromotionStatus(
            execution_id=source_id or admission.admission_id,
            assessment_session_id=admission.session_id,
            source_receipt_id=source_id,
            execution_state=execution_state,
            evidence_classification=evidence_classification,
            promotion_state=promotion_state,
            reason_code=reason_code,
            canonical_observation_id=(record or {}).get("observation_id"),
            canonical_finding_id=(record or {}).get("finding_id"),
            permitted_next_local_action=next_action,
        )

    def status(self, identifier: str) -> WorkflowEffectPromotionStatus:
        record = self.repository.load_workflow_effect_admission(identifier)
        if record is None:
            fingerprint = identifier.removeprefix("behavioral-")
            if len(fingerprint) == 64 and all(
                character in "0123456789abcdef" for character in fingerprint
            ):
                try:
                    legacy = self.receipt_store.load(fingerprint)
                except (OSError, ReceiptStoreError):
                    legacy = None
                if legacy is not None:
                    execution_state = (
                        "completed"
                        if legacy.state == COMPLETED
                        else "aborted"
                        if legacy.state == ABORTED
                        else "source_incomplete"
                    )
                    return WorkflowEffectPromotionStatus(
                        execution_id=legacy.receipt_id,
                        assessment_session_id=None,
                        source_receipt_id=legacy.receipt_id,
                        execution_state=execution_state,
                        evidence_classification="legacy_unavailable",
                        promotion_state="not_eligible",
                        reason_code="legacy_evidence_unavailable",
                    )
            return WorkflowEffectPromotionStatus(
                execution_id=identifier,
                assessment_session_id=None,
                source_receipt_id=None,
                execution_state="unknown",
                evidence_classification="unavailable",
                promotion_state="not_admitted",
                reason_code="execution_not_found",
            )
        admission = WorkflowEffectAdmission.from_record(record)
        if admission.source_receipt_id is None:
            return self._result(
                admission,
                execution_state="source_incomplete",
                evidence_classification="unavailable",
                promotion_state=record["state"],
                reason_code="source_incomplete_or_outcome_unknown",
            )
        try:
            receipt = self._receipt_for(admission)
        except WorkflowEffectSourceUnavailable:
            return self._result(
                admission,
                execution_state="unavailable",
                evidence_classification="unavailable",
                promotion_state="retryable_local_persistence_failure",
                reason_code="source_receipt_unavailable",
                next_action="retry_promotion",
                record=record,
            )
        except WorkflowEffectSourceInvalid:
            return self._result(
                admission,
                execution_state="completed",
                evidence_classification="invalid",
                promotion_state="invalid_evidence",
                reason_code="invalid_or_corrupted_evidence",
                record=record,
            )
        if receipt is None or receipt.state == RESERVED:
            return self._result(
                admission,
                execution_state="source_incomplete",
                evidence_classification="unavailable",
                promotion_state=record["state"],
                reason_code="source_incomplete_or_outcome_unknown",
                record=record,
            )
        if receipt.state == ABORTED:
            return self._result(
                admission,
                execution_state="aborted",
                evidence_classification="denial_evidence",
                promotion_state="not_eligible",
                reason_code="source_incomplete_or_outcome_unknown",
                record=record,
            )
        try:
            evidence = self._evidence_from_receipt(receipt)
        except WorkflowEffectSourceInvalid:
            return self._result(
                admission,
                execution_state="completed",
                evidence_classification="invalid",
                promotion_state="invalid_evidence",
                reason_code="invalid_or_corrupted_evidence",
                record=record,
            )
        if evidence is None:
            return self._result(
                admission,
                execution_state="completed",
                evidence_classification="legacy_unavailable",
                promotion_state="not_eligible",
                reason_code="legacy_evidence_unavailable",
                record=record,
            )
        if not self._corresponds(admission, evidence):
            return self._result(
                admission,
                execution_state="completed",
                evidence_classification="invalid",
                promotion_state="invalid_evidence",
                reason_code="invalid_or_corrupted_evidence",
                record=record,
            )
        from core.behavior.workflow_effect_evidence import evaluate_workflow_effect_eligibility

        predicate = evaluate_workflow_effect_eligibility(evidence)
        if not predicate.eligible:
            return self._result(
                admission,
                execution_state="completed",
                evidence_classification="not_workflow_invariant_violation",
                promotion_state="not_eligible",
                reason_code=predicate.reason_code,
                record=record,
            )
        if record["state"] == "promoted":
            try:
                ledger = self._new_ledger()
                finding_state = ledger.get_state(str(record.get("finding_id")))
                observation_state = ledger.get_state(str(record.get("observation_id")))
                inactive_states = {
                    LifecycleState.SUPPRESSED,
                    LifecycleState.INVALIDATED,
                    LifecycleState.REJECTED,
                }
                if (
                    finding_state is not None
                    and observation_state is not None
                    and (
                        finding_state.state in inactive_states
                        or observation_state.state in inactive_states
                    )
                ):
                    return self._result(
                        admission,
                        execution_state="completed",
                        evidence_classification="eligible_workflow_effect",
                        promotion_state="canonical_result_inactive",
                        reason_code="canonical_result_inactive",
                        record=record,
                    )
                read_model = ledger.session_read_model(admission.session_id)
                finding = next(
                    (
                        item
                        for item in read_model.findings
                        if item.id == record.get("finding_id")
                    ),
                    None,
                )
                observation = next(
                    (
                        item
                        for item in read_model.observations
                        if item.id == record.get("observation_id")
                    ),
                    None,
                )
                if finding is None or observation is None:
                    raise ValueError("canonical result is not active")
            except (OSError, ValueError) as exc:
                raise WorkflowEffectPromotionError(
                    "canonical_result_correspondence_failed"
                ) from exc
            return self._result(
                admission,
                execution_state="completed",
                evidence_classification="eligible_workflow_effect",
                promotion_state="promoted",
                reason_code="promoted",
                record=record,
            )
        promotion_enabled = WorkflowFindingPromotionConfig.from_environment().enabled
        return self._result(
            admission,
            execution_state="completed",
            evidence_classification="eligible_workflow_effect",
            promotion_state=(
                "eligible_awaiting_processing"
                if promotion_enabled
                else "blocked_by_policy"
            ),
            reason_code=(
                "eligible_awaiting_processing"
                if promotion_enabled
                else "blocked_by_policy"
            ),
            next_action="promote" if promotion_enabled else None,
            record=record,
        )

    def promote(self, identifier: str) -> WorkflowEffectPromotionStatus:
        """Classify and, when currently enabled, admit retained evidence locally."""

        record = self.repository.load_workflow_effect_admission(identifier)
        if record is None:
            return self.status(identifier)
        admission = WorkflowEffectAdmission.from_record(record)
        current = self.status(identifier)
        gate_enabled = WorkflowFindingPromotionConfig.from_environment().enabled
        attempt = {
            "schema_version": 1,
            "attempted_at_epoch": repr(time.time()),
            "promotion_enabled": gate_enabled,
            "reason_code": current.reason_code,
        }
        if current.promotion_state in {
            "promoted",
            "canonical_result_inactive",
        }:
            return current
        if current.evidence_classification != "eligible_workflow_effect":
            state = (
                "invalid_evidence"
                if current.evidence_classification == "invalid"
                else "not_workflow_invariant_violation"
                if current.evidence_classification == "not_workflow_invariant_violation"
                else "retryable_local_persistence_failure"
                if current.evidence_classification == "unavailable"
                else record["state"]
            )
            self.repository.record_workflow_effect_attempt(
                admission_id=admission.admission_id,
                attempt=attempt,
                state=state,
                last_error=(
                    current.reason_code if state == "invalid_evidence" else None
                ),
            )
            return self.status(identifier)
        if not gate_enabled:
            self.repository.record_workflow_effect_attempt(
                admission_id=admission.admission_id,
                attempt=attempt,
                state="blocked_by_policy",
            )
            return self.status(identifier)

        self.repository.record_workflow_effect_attempt(
            admission_id=admission.admission_id,
            attempt=attempt,
            state="eligible_awaiting_processing",
        )
        try:
            receipt = self._receipt_for(admission)
            evidence = self._evidence_from_receipt(receipt)
        except WorkflowEffectSourceUnavailable:
            self.repository.set_workflow_effect_state(
                admission_id=admission.admission_id,
                state="retryable_local_persistence_failure",
                last_error="source_receipt_unavailable",
            )
            return self.status(identifier)
        except WorkflowEffectSourceInvalid:
            self.repository.set_workflow_effect_state(
                admission_id=admission.admission_id,
                state="invalid_evidence",
                last_error="invalid_or_corrupted_evidence",
            )
            return self.status(identifier)
        if evidence is None or not self._corresponds(admission, evidence):
            self.repository.set_workflow_effect_state(
                admission_id=admission.admission_id,
                state="invalid_evidence",
                last_error="invalid_or_corrupted_evidence",
            )
            return self.status(identifier)
        try:
            ledger = self._new_ledger()
            observation, finding = ledger.admit_workflow_invariant_finding(
                evidence=evidence,
                admission_id=admission.admission_id,
                event_timestamp=admission.event_timestamp,
                event_run_id=admission.event_run_id,
            )
        except (OSError, ReceiptStoreError, sqlite3.Error, ValueError) as exc:
            self.repository.set_workflow_effect_state(
                admission_id=admission.admission_id,
                state="retryable_local_persistence_failure",
                last_error=type(exc).__name__,
            )
            return self._result(
                admission,
                execution_state="completed",
                evidence_classification="eligible_workflow_effect",
                promotion_state="retryable_local_persistence_failure",
                reason_code="retryable_local_persistence_failure",
                next_action="retry_promotion",
            )
        committed = self.repository.load_workflow_effect_admission(
            admission.admission_id
        )
        if (
            committed is None
            or committed.get("observation_id") != observation.id
            or committed.get("finding_id") != finding.id
        ):
            raise WorkflowEffectPromotionError(
                "canonical_result_correspondence_failed"
            )
        return self.status(identifier)

    def reconcile(
        self,
        *,
        limit: int = 256,
    ) -> tuple[WorkflowEffectPromotionStatus, ...]:
        """Retry only source-complete local work; never reconstruct execution."""

        if not WorkflowFindingPromotionConfig.from_environment().enabled:
            return ()
        results: list[WorkflowEffectPromotionStatus] = []
        admission_ids = self.repository.list_workflow_effect_admission_ids(
            states=(
                "awaiting_source",
                "blocked_by_policy",
                "eligible_awaiting_processing",
                "retryable_local_persistence_failure",
            ),
            limit=limit,
        )
        for admission_id in admission_ids:
            try:
                results.append(self.promote(admission_id))
            except Exception:
                logger.exception(
                    "workflow promotion reconciliation failed for %s",
                    admission_id,
                )
        return tuple(results)


__all__ = [
    "WORKFLOW_FINDING_PROMOTION_ENV",
    "WORKFLOW_INVARIANT_VIOLATION_CLASS",
    "WorkflowEffectAdmission",
    "WorkflowEffectPromotionError",
    "WorkflowEffectPromotionService",
    "WorkflowEffectPromotionStatus",
    "WorkflowEffectSourceInvalid",
    "WorkflowEffectSourceUnavailable",
    "WorkflowFindingPromotionConfig",
]
