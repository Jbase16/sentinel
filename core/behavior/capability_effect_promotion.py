"""Durable R5D10 admission, local promotion, status, and reconciliation.

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
from core.epistemic.persistence import CanonicalEvidenceRepository
from core.epistemic.storage_boundary import (
    EvidenceStorageAnchor,
    production_evidence_roots,
)
from core.identity import AssessmentIdentityContext, CredentialFreshness


CAPABILITY_FINDING_PROMOTION_ENV = "SENTINELFORGE_BEHAVIOR_CAPABILITY_FINDING_PROMOTION"
CAPABILITY_REPLAY_LEAK_CLASS = "capability_replay_leak_v1"
_TRUE = frozenset({"1", "true", "yes", "on"})
_RUNTIME_CLASSIFICATIONS = frozenset(
    {"controlled_in_memory_twin", "controlled_owned_lab", "unknown"}
)
logger = logging.getLogger(__name__)


class _AnchoredRepository:
    """Revalidate the R5D10 storage anchor around every SQLite adapter call."""

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
        self._r5d10_storage_anchor = storage_anchor
        storage_anchor.assert_unchanged()
        super().__init__(config, receipt_store=receipt_store)
        storage_anchor.assert_unchanged()
        self.cas = cas
        self._repository = repository

    def _ensure_audit_log(self) -> None:
        self._r5d10_storage_anchor.assert_unchanged()
        try:
            super()._ensure_audit_log()
        finally:
            self._r5d10_storage_anchor.assert_unchanged()

    def _append_audit_event(self, event: Any) -> None:
        self._r5d10_storage_anchor.assert_unchanged()
        try:
            super()._append_audit_event(event)
        finally:
            self._r5d10_storage_anchor.assert_unchanged()


class CapabilityEffectPromotionError(RuntimeError):
    """A retained source could not be classified or admitted safely."""


class CapabilityEffectSourceUnavailable(CapabilityEffectPromotionError):
    """A retained source could not be read because local persistence failed."""


class CapabilityEffectSourceInvalid(CapabilityEffectPromotionError):
    """A retained source was read but failed its durable receipt contract."""


@dataclass(frozen=True)
class CapabilityFindingPromotionConfig:
    enabled: bool = False

    def __post_init__(self) -> None:
        if type(self.enabled) is not bool:
            raise TypeError("capability finding promotion enabled must be boolean")

    @classmethod
    def from_environment(cls) -> "CapabilityFindingPromotionConfig":
        return cls(
            enabled=(
                str(os.environ.get(CAPABILITY_FINDING_PROMOTION_ENV, ""))
                .strip()
                .lower()
                in _TRUE
            )
        )


@dataclass(frozen=True)
class CapabilityEffectAdmission:
    admission_id: str
    intake_id: str
    session_id: str
    target_origin: str
    identity_binding: Mapping[str, Any]
    operation: Mapping[str, Any]
    producer_identity: Mapping[str, Any]
    storage: Mapping[str, Any]
    source_receipt_id: Optional[str]
    source_fingerprint: Optional[str]
    event_timestamp: float
    event_run_id: Optional[str]

    @classmethod
    def from_record(cls, value: Mapping[str, Any]) -> "CapabilityEffectAdmission":
        return cls(
            admission_id=value["admission_id"],
            intake_id=value["intake_id"],
            session_id=value["session_id"],
            target_origin=value["target_origin"],
            identity_binding=dict(value["identity_data"]),
            operation=dict(value["operation_data"]),
            producer_identity=dict(value["producer_data"]),
            storage=dict(value["storage_data"]),
            source_receipt_id=value.get("source_receipt_id"),
            source_fingerprint=value.get("source_fingerprint"),
            event_timestamp=float(value["event_timestamp"]),
            event_run_id=value.get("event_run_id"),
        )

    @property
    def execution_policy(self) -> Mapping[str, Any]:
        return dict(self.operation["execution_policy"])

    @property
    def specification_ref(self) -> str:
        return str(self.operation["specification_ref"])

    @property
    def operation_ref(self) -> str:
        return str(self.operation["operation_ref"])


@dataclass(frozen=True)
class CapabilityEffectPromotionStatus:
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
            "slice": "R5D10",
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


def producer_build_identity() -> dict[str, Any]:
    """Return an explicit redacted build qualification, never an inferred SHA."""

    from core.behavior.capability_effect_evidence import (
        CapabilityEffectProducerIdentity,
    )

    build_sha = str(os.environ.get("SENTINEL_BUILD_SHA", "")).strip().lower()
    valid_sha = len(build_sha) == 40 and all(
        character in "0123456789abcdef" for character in build_sha
    )
    dirty_value = str(os.environ.get("SENTINEL_BUILD_DIRTY", "")).strip().lower()
    dirty = (
        True
        if dirty_value in _TRUE
        else False
        if dirty_value in {"0", "false", "no", "off"}
        else None
    )
    source_state = (
        "dirty"
        if dirty is True and valid_sha
        else "clean"
        if dirty is False and valid_sha
        else "unknown"
    )
    build_id = str(os.environ.get("SENTINEL_BUILD_ID", "local")).strip()
    return CapabilityEffectProducerIdentity.build(
        producer_name="sentinelforge_behavioral_execution",
        build_id=(build_id or "local")[:256],
        build_sha=build_sha if source_state != "unknown" else "unknown",
        source_state=source_state,
    ).to_dict()


def runtime_evidence_classification() -> str:
    """Return an explicit runtime trust class without upgrading local proof."""

    value = str(
        os.environ.get("SENTINELFORGE_CAPABILITY_EVIDENCE_CLASSIFICATION", "unknown")
    ).strip()
    if value not in _RUNTIME_CLASSIFICATIONS:
        raise ValueError("capability runtime evidence classification is invalid")
    return value


class CapabilityEffectPromotionService:
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
            raise ValueError("capability evidence storage changed after admission")
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

    @property
    def storage_snapshot(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "resolved_roots": list(self._resolved_roots),
            "roots_digest": stable_hash(
                "capability_effect_storage_roots",
                list(self._resolved_roots),
            ),
            "outside_git_worktrees": True,
        }

    def reserve_execution(
        self,
        *,
        intake_id: str,
        target_origin: str,
        authorization_envelope_id: str,
        authorization_envelope_ref: str,
        persona_id: str,
        persona_source_ref: str,
        specification: Mapping[str, Any],
        execution_policy: Mapping[str, Any],
        requested_session_id: Optional[str] = None,
        source_fingerprint: Optional[str] = None,
        event_run_id: Optional[str] = None,
        observed_at: Optional[float] = None,
        producer_identity: Optional[Mapping[str, Any]] = None,
    ) -> CapabilityEffectAdmission:
        """Persist immutable owner context and optionally bind the inner source."""

        self.preflight_local_persistence()
        if (
            not isinstance(intake_id, str)
            or not intake_id.startswith("capability_effect_intake:")
            or len(intake_id) != len("capability_effect_intake:") + 64
            or any(
                character not in "0123456789abcdef"
                for character in intake_id.rsplit(":", 1)[-1]
            )
        ):
            raise ValueError("capability intake id is required")
        origin = canonical_origin(target_origin)
        if origin is None:
            raise ValueError("capability admission target origin is invalid")
        source_receipt_id = (
            f"behavioral-{source_fingerprint}" if source_fingerprint else None
        )
        source_owner_record = None
        for identifier in (source_receipt_id, source_fingerprint):
            if identifier:
                source_owner_record = self.repository.load_capability_effect_admission(
                    identifier
                )
                if source_owner_record is not None:
                    break
        intake_owner_record = self.repository.load_capability_effect_admission(
            intake_id
        )
        if source_owner_record is not None:
            # The first successful source admission owns the original session.
            # A later scan may only reference it, never transplant it.
            source_owner = CapabilityEffectAdmission.from_record(source_owner_record)
            expected_specification = dict(specification)
            expected_identity = source_owner.identity_binding
            expected_operation = source_owner.operation
            if (
                source_owner.target_origin != origin.as_url()
                or expected_identity.get("authorization_envelope_id")
                != authorization_envelope_id
                or expected_identity.get("persona_id") != persona_id
                or expected_operation.get("specification") != expected_specification
            ):
                raise ValueError("capability source owner context collision")
            return source_owner

        existing = (
            CapabilityEffectAdmission.from_record(intake_owner_record)
            if intake_owner_record is not None
            else None
        )
        session_id = (
            (existing.session_id if existing is not None else None)
            or requested_session_id
            or str(uuid.uuid5(uuid.NAMESPACE_URL, f"sentinelforge:r5d10:{intake_id}"))
        )
        timestamp = float(observed_at if observed_at is not None else time.time())
        if timestamp <= 0:
            raise ValueError("capability admission timestamp is invalid")
        specification_value = dict(specification)
        specification_ref = specification_value.get("specification_id")
        if not isinstance(specification_ref, str):
            raise ValueError("capability admission specification is invalid")
        operation_ref = stable_hash(
            "capability_operation",
            specification_value.get("target_endpoint_ref"),
        )
        identity = AssessmentIdentityContext(
            session_id=session_id,
            authorization_envelope_id=authorization_envelope_id,
            authorization_envelope_ref=authorization_envelope_ref,
            target_origin=origin.as_url(),
            target_reset_epoch=0,
            world_id=persona_id,
            persona_id=persona_id,
            target_actor_id="actor:unresolved",
            tenant_id="tenant:unresolved",
            credential_source_ref=persona_source_ref,
            credential_epoch=0,
            credential_freshness=CredentialFreshness.UNKNOWN,
            resource_id=stable_hash(
                "resource",
                specification_value.get("target_request_ref"),
            ),
            representation_id=stable_hash(
                "representation",
                {"kind": "capability_effect_intake", "intake_id": intake_id},
            ),
        )
        storage = self.storage_snapshot
        producer = dict(producer_identity or producer_build_identity())
        operation = {
            "schema_version": 1,
            "specification_ref": specification_ref,
            "specification": specification_value,
            "operation_ref": operation_ref,
            "authorization_envelope_ref": authorization_envelope_ref,
            "persona_ref": stable_hash("experiment_persona", persona_id),
            "execution_policy": dict(execution_policy),
        }
        if existing is not None:
            if (
                existing.target_origin != origin.as_url()
                or (
                    requested_session_id is not None
                    and requested_session_id != existing.session_id
                )
                or existing.identity_binding != identity.to_dict()
                or existing.operation != operation
                or existing.producer_identity != producer
                or existing.storage != storage
            ):
                raise ValueError("capability execution admission context collision")
            if source_fingerprint:
                bound = self.repository.bind_capability_effect_source(
                    admission_id=existing.admission_id,
                    source_receipt_id=source_receipt_id or "",
                    source_fingerprint=source_fingerprint,
                )
                return CapabilityEffectAdmission.from_record(bound)
            return existing
        admission_id = stable_hash(
            "capability_effect_execution_admission",
            {
                "intake_id": intake_id,
                "session_id": session_id,
                "target_origin": origin.as_url(),
                "identity_digest": identity.digest,
                "operation": operation,
                "producer": producer,
                "storage": storage,
            },
        )
        record = self.repository.reserve_capability_effect_admission(
            admission_id=admission_id,
            intake_id=intake_id,
            session_id=session_id,
            target_origin=origin.as_url(),
            identity=identity.to_dict(),
            operation=operation,
            producer=producer,
            storage=storage,
            event_timestamp=timestamp,
            event_run_id=event_run_id,
            session_projection=(
                {
                    "id": session_id,
                    "target": origin.as_url(),
                    "status": "BehavioralEvidence",
                    "start_time": repr(timestamp),
                    "end_time": None,
                    "logs": [],
                }
                if requested_session_id is None
                else None
            ),
        )
        if source_fingerprint:
            record = self.repository.bind_capability_effect_source(
                admission_id=admission_id,
                source_receipt_id=source_receipt_id or "",
                source_fingerprint=source_fingerprint,
            )
        return CapabilityEffectAdmission.from_record(record)

    def _receipt_for(
        self,
        admission: CapabilityEffectAdmission,
    ) -> Any:
        if admission.source_fingerprint is None:
            return None
        try:
            receipt = self.receipt_store.load(admission.source_fingerprint)
        except OSError as exc:
            raise CapabilityEffectSourceUnavailable(
                "source_receipt_unavailable"
            ) from exc
        except ReceiptStoreError as exc:
            if isinstance(exc.__cause__, OSError):
                raise CapabilityEffectSourceUnavailable(
                    "source_receipt_unavailable"
                ) from exc
            raise CapabilityEffectSourceInvalid(
                "invalid_or_corrupted_evidence"
            ) from exc
        if receipt is None:
            raise CapabilityEffectSourceUnavailable("source_receipt_unavailable")
        return receipt

    @staticmethod
    def _evidence_from_receipt(receipt: Any) -> Any:
        from core.behavior.capability_effect_evidence import CapabilityEffectEvidence

        if (
            receipt is None
            or receipt.state != COMPLETED
            or not isinstance(receipt.outcome, Mapping)
        ):
            return None
        value = receipt.outcome.get("capability_effect_evidence")
        if value is None:
            return None
        if not isinstance(value, Mapping):
            raise CapabilityEffectSourceInvalid("invalid_or_corrupted_evidence")
        try:
            return CapabilityEffectEvidence.from_mapping(value)
        except (TypeError, ValueError) as exc:
            raise CapabilityEffectSourceInvalid(
                "invalid_or_corrupted_evidence"
            ) from exc

    @staticmethod
    def _corresponds(
        admission: CapabilityEffectAdmission,
        evidence: Any,
    ) -> bool:
        return bool(
            evidence.source_receipt_id == admission.source_receipt_id
            and evidence.execution_admission_ref == admission.admission_id
            and evidence.assessment_session_id == admission.session_id
            and evidence.identity_binding == admission.identity_binding
            and evidence.target_origin == admission.target_origin
            and evidence.specification_ref == admission.specification_ref
            and evidence.operation_ref == admission.operation_ref
            and evidence.execution_policy == admission.execution_policy
            and evidence.producer_identity == admission.producer_identity
        )

    def _result(
        self,
        admission: CapabilityEffectAdmission,
        *,
        execution_state: str,
        evidence_classification: str,
        promotion_state: str,
        reason_code: str,
        next_action: Optional[str] = None,
        record: Optional[Mapping[str, Any]] = None,
    ) -> CapabilityEffectPromotionStatus:
        source_id = admission.source_receipt_id
        return CapabilityEffectPromotionStatus(
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

    def status(self, identifier: str) -> CapabilityEffectPromotionStatus:
        record = self.repository.load_capability_effect_admission(identifier)
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
                    return CapabilityEffectPromotionStatus(
                        execution_id=legacy.receipt_id,
                        assessment_session_id=None,
                        source_receipt_id=legacy.receipt_id,
                        execution_state=execution_state,
                        evidence_classification="legacy_unavailable",
                        promotion_state="not_eligible",
                        reason_code="legacy_evidence_unavailable",
                    )
            return CapabilityEffectPromotionStatus(
                execution_id=identifier,
                assessment_session_id=None,
                source_receipt_id=None,
                execution_state="unknown",
                evidence_classification="unavailable",
                promotion_state="not_admitted",
                reason_code="execution_not_found",
            )
        admission = CapabilityEffectAdmission.from_record(record)
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
        except CapabilityEffectSourceUnavailable:
            return self._result(
                admission,
                execution_state="unavailable",
                evidence_classification="unavailable",
                promotion_state="retryable_local_persistence_failure",
                reason_code="source_receipt_unavailable",
                next_action="retry_promotion",
                record=record,
            )
        except CapabilityEffectSourceInvalid:
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
        except CapabilityEffectSourceInvalid:
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
        from core.behavior.capability_effect_evidence import evaluate_replay_leak

        predicate = evaluate_replay_leak(evidence)
        if not predicate.eligible:
            return self._result(
                admission,
                execution_state="completed",
                evidence_classification="not_replay_leak",
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
                        evidence_classification="eligible_replay_leak",
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
                raise CapabilityEffectPromotionError(
                    "canonical_result_correspondence_failed"
                ) from exc
            return self._result(
                admission,
                execution_state="completed",
                evidence_classification="eligible_replay_leak",
                promotion_state="promoted",
                reason_code="promoted",
                record=record,
            )
        promotion_enabled = CapabilityFindingPromotionConfig.from_environment().enabled
        return self._result(
            admission,
            execution_state="completed",
            evidence_classification="eligible_replay_leak",
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

    def promote(self, identifier: str) -> CapabilityEffectPromotionStatus:
        """Classify and, when currently enabled, admit retained evidence locally."""

        record = self.repository.load_capability_effect_admission(identifier)
        if record is None:
            return self.status(identifier)
        admission = CapabilityEffectAdmission.from_record(record)
        current = self.status(identifier)
        gate_enabled = CapabilityFindingPromotionConfig.from_environment().enabled
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
        if current.evidence_classification != "eligible_replay_leak":
            state = (
                "invalid_evidence"
                if current.evidence_classification == "invalid"
                else "not_replay_leak"
                if current.evidence_classification == "not_replay_leak"
                else "retryable_local_persistence_failure"
                if current.evidence_classification == "unavailable"
                else record["state"]
            )
            self.repository.record_capability_effect_attempt(
                admission_id=admission.admission_id,
                attempt=attempt,
                state=state,
                last_error=(
                    current.reason_code if state == "invalid_evidence" else None
                ),
            )
            return self.status(identifier)
        if not gate_enabled:
            self.repository.record_capability_effect_attempt(
                admission_id=admission.admission_id,
                attempt=attempt,
                state="blocked_by_policy",
            )
            return self.status(identifier)

        self.repository.record_capability_effect_attempt(
            admission_id=admission.admission_id,
            attempt=attempt,
            state="eligible_awaiting_processing",
        )
        try:
            receipt = self._receipt_for(admission)
            evidence = self._evidence_from_receipt(receipt)
        except CapabilityEffectSourceUnavailable:
            self.repository.set_capability_effect_state(
                admission_id=admission.admission_id,
                state="retryable_local_persistence_failure",
                last_error="source_receipt_unavailable",
            )
            return self.status(identifier)
        except CapabilityEffectSourceInvalid:
            self.repository.set_capability_effect_state(
                admission_id=admission.admission_id,
                state="invalid_evidence",
                last_error="invalid_or_corrupted_evidence",
            )
            return self.status(identifier)
        if evidence is None or not self._corresponds(admission, evidence):
            self.repository.set_capability_effect_state(
                admission_id=admission.admission_id,
                state="invalid_evidence",
                last_error="invalid_or_corrupted_evidence",
            )
            return self.status(identifier)
        try:
            ledger = self._new_ledger()
            observation, finding = ledger.admit_capability_replay_finding(
                evidence=evidence,
                admission_id=admission.admission_id,
                event_timestamp=admission.event_timestamp,
                event_run_id=admission.event_run_id,
            )
        except (OSError, ReceiptStoreError, sqlite3.Error, ValueError) as exc:
            self.repository.set_capability_effect_state(
                admission_id=admission.admission_id,
                state="retryable_local_persistence_failure",
                last_error=type(exc).__name__,
            )
            return self._result(
                admission,
                execution_state="completed",
                evidence_classification="eligible_replay_leak",
                promotion_state="retryable_local_persistence_failure",
                reason_code="retryable_local_persistence_failure",
                next_action="retry_promotion",
            )
        committed = self.repository.load_capability_effect_admission(
            admission.admission_id
        )
        if (
            committed is None
            or committed.get("observation_id") != observation.id
            or committed.get("finding_id") != finding.id
        ):
            raise CapabilityEffectPromotionError(
                "canonical_result_correspondence_failed"
            )
        return self.status(identifier)

    def reconcile(
        self,
        *,
        limit: int = 256,
    ) -> tuple[CapabilityEffectPromotionStatus, ...]:
        """Retry only source-complete local work; never reconstruct execution."""

        if not CapabilityFindingPromotionConfig.from_environment().enabled:
            return ()
        results: list[CapabilityEffectPromotionStatus] = []
        admission_ids = self.repository.list_capability_effect_admission_ids(
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
                    "capability promotion reconciliation failed for %s",
                    admission_id,
                )
        return tuple(results)


__all__ = [
    "CAPABILITY_FINDING_PROMOTION_ENV",
    "CAPABILITY_REPLAY_LEAK_CLASS",
    "CapabilityEffectAdmission",
    "CapabilityEffectPromotionError",
    "CapabilityEffectPromotionService",
    "CapabilityEffectPromotionStatus",
    "CapabilityEffectSourceInvalid",
    "CapabilityEffectSourceUnavailable",
    "CapabilityFindingPromotionConfig",
    "producer_build_identity",
    "runtime_evidence_classification",
]
