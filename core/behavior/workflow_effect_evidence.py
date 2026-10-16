"""Canonical, authority-free evidence for a retained workflow-effect run.

This record is a faithful mirror of the capability promotion substrate's
``CapabilityEffectEvidence``: it is constructed from explicit inputs and does
not capture runtime context, resolve a receipt, admit evidence, journal a
commitment, triage a candidate, or grant finding authority. It differs from
the capability record only in the two load-bearing fields the downstream
promotion substrate consumes directly:

* ``source_receipt_id`` is a bare ``behavioral-<64 hex>`` receipt id (the form
  the epistemic ledger's ``ActiveProofCitation.receipt_id`` requires), not a
  typed ``behavioral_receipt:<hash>`` reference; and
* ``execution_admission_ref`` is a typed
  ``workflow_effect_promotion_admission:<64 hex>`` reference to the (future)
  committed workflow journal admission.

Neither field is bound by :func:`bind_to_run`; both are format-validated here
and cross-checked only by the (future) admission validator. Nothing in this
module wires into production, and the companion
:func:`evaluate_workflow_effect_eligibility` is a pure predicate that grants no
authority.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import math
import os
import re
from types import MappingProxyType
from typing import Any, Mapping, Tuple

from core.base.scope import canonical_origin
from core.identity.context import AssessmentIdentityContext

from .normalize import stable_hash
from .workflow_invariant_effect import (
    WorkflowEffectCorrespondence,
    WorkflowEffectOutcome,
)
from .workflow_invariant_effect_one_click import WorkflowEffectOneClickRun


WORKFLOW_EFFECT_EVIDENCE_SCHEMA_VERSION = 1
WORKFLOW_EFFECT_EVIDENCE_MAX_BYTES = 256 * 1024
_ROOT_DOMAIN = b"sentinelforge:workflow-effect-evidence:v1\x00"
_BARE_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_TYPED_SHA256 = re.compile(r"^([a-z][a-z0-9_]{0,127}):([0-9a-f]{64})$")
# The epistemic ledger's ActiveProofCitation.receipt_id form; the downstream
# admission validator cites this evidence by exactly this bare receipt id.
_BEHAVIORAL_RECEIPT = re.compile(r"^behavioral-[0-9a-f]{64}$")
_SEMANTIC = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_BUILD_SHA = re.compile(r"^[0-9a-f]{40}$")
_RUNTIME_CLASSIFICATIONS = frozenset(
    {"controlled_in_memory_twin", "controlled_owned_lab", "unknown"}
)
_HONEST_CLASSIFICATIONS = frozenset(
    {"controlled_in_memory_twin", "controlled_owned_lab"}
)
_TRUE = frozenset({"1", "true", "yes", "on"})
_FALSE = frozenset({"0", "false", "no", "off"})
_FIELDS = frozenset(
    {
        "schema_version",
        "evidence_root",
        "source_receipt_id",
        "execution_admission_ref",
        "specification_id",
        "transport_specification_id",
        "candidate_id",
        "result_id",
        "evidence_id",
        "target_origin",
        "assessment_session_id",
        "identity_binding",
        "experiment_world_ref",
        "authority_ref",
        "tenant_ref",
        "source_evidence_ref",
        "oracle",
        "compensating_cleanup_verified",
        "producer_identity",
        "observed_at_epoch",
        "runtime_evidence_classification",
    }
)
_ORACLE_FIELDS = frozenset(
    {
        "outcome",
        "correspondence",
        "effect_observed",
        "adversarial_triage_required",
        "promotion_authority",
        "finding_authority",
    }
)
_PRODUCER_FIELDS = frozenset(
    {
        "schema_version",
        "producer_id",
        "producer_name",
        "build_id",
        "build_sha",
        "source_state",
    }
)


class WorkflowEffectEvidenceError(ValueError):
    """A workflow effect evidence record or run binding is invalid."""


def _exact(value: object, fields: frozenset[str], label: str) -> Mapping[str, Any]:
    if (
        not isinstance(value, Mapping)
        or set(value) != fields
        or any(type(key) is not str for key in value)
    ):
        raise WorkflowEffectEvidenceError(f"{label} fields are invalid")
    return value


def _bounded(value: object, label: str, maximum: int) -> str:
    if (
        type(value) is not str
        or not value
        or len(value) > maximum
        or value != value.strip()
        or any(ord(character) < 0x20 for character in value)
    ):
        raise WorkflowEffectEvidenceError(f"{label} is invalid")
    return value


def _semantic(value: object, label: str) -> str:
    if type(value) is not str or _SEMANTIC.fullmatch(value) is None:
        raise WorkflowEffectEvidenceError(f"{label} is invalid")
    return value


def _typed_ref(value: object, prefix: str, label: str) -> str:
    if type(value) is not str:
        raise WorkflowEffectEvidenceError(f"{label} is invalid")
    match = _TYPED_SHA256.fullmatch(value)
    if match is None or match.group(1) != prefix:
        raise WorkflowEffectEvidenceError(f"{label} is invalid")
    return value


def _behavioral_receipt(value: object, label: str) -> str:
    if type(value) is not str or _BEHAVIORAL_RECEIPT.fullmatch(value) is None:
        raise WorkflowEffectEvidenceError(f"{label} is invalid")
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
        raise WorkflowEffectEvidenceError(
            "workflow effect evidence is not JSON-safe"
        ) from exc


def _evidence_root(payload: Mapping[str, Any]) -> str:
    return hashlib.sha256(
        _ROOT_DOMAIN + _canonical_json_bytes(dict(payload))
    ).hexdigest()


def _validate_identity(value: object) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise WorkflowEffectEvidenceError("workflow effect identity is invalid")
    if (
        type(value.get("target_reset_epoch")) is not int
        or type(value.get("credential_epoch")) is not int
    ):
        raise WorkflowEffectEvidenceError("workflow effect identity is invalid")
    try:
        identity = AssessmentIdentityContext.from_dict(value)
    except (KeyError, TypeError, ValueError) as exc:
        raise WorkflowEffectEvidenceError(
            "workflow effect identity is invalid"
        ) from exc
    normalized = identity.to_dict()
    if dict(value) != normalized or normalized["display_name"] != "":
        raise WorkflowEffectEvidenceError("workflow effect identity is not canonical")
    return MappingProxyType(normalized)


def _validate_oracle(value: object) -> Mapping[str, Any]:
    source = _exact(value, _ORACLE_FIELDS, "workflow effect oracle")
    try:
        outcome = WorkflowEffectOutcome(source["outcome"])
        correspondence = WorkflowEffectCorrespondence(source["correspondence"])
    except ValueError as exc:
        raise WorkflowEffectEvidenceError(
            "workflow effect oracle is invalid"
        ) from exc
    effect_observed = (
        outcome is WorkflowEffectOutcome.EFFECT_OBSERVED_VIOLATION
        and correspondence is WorkflowEffectCorrespondence.COHERENT
    )
    if (
        type(source["outcome"]) is not str
        or type(source["correspondence"]) is not str
        or source["effect_observed"] is not effect_observed
        or source["adversarial_triage_required"] is not True
        or source["promotion_authority"] is not False
        or source["finding_authority"] is not False
    ):
        raise WorkflowEffectEvidenceError("workflow effect oracle is invalid")
    return MappingProxyType(dict(source))


def _validate_producer(value: object) -> Mapping[str, Any]:
    source = _exact(value, _PRODUCER_FIELDS, "workflow effect producer")
    if type(source["schema_version"]) is not int or source["schema_version"] != 1:
        raise WorkflowEffectEvidenceError(
            "workflow effect producer version is invalid"
        )
    _typed_ref(
        source["producer_id"],
        "workflow_effect_producer_identity",
        "workflow effect producer id",
    )
    producer_name = _bounded(source["producer_name"], "producer name", 128)
    build_id = _bounded(source["build_id"], "producer build id", 256)
    state = source["source_state"]
    sha = source["build_sha"]
    if (
        type(state) is not str
        or state not in {"clean", "dirty", "unknown"}
        or (
            state in {"clean", "dirty"}
            and (type(sha) is not str or _BUILD_SHA.fullmatch(sha) is None)
        )
        or (state == "unknown" and sha != "unknown")
    ):
        raise WorkflowEffectEvidenceError("workflow effect producer build is invalid")
    payload = {
        "producer_name": producer_name,
        "build_id": build_id,
        "build_sha": sha,
        "source_state": state,
    }
    if source["producer_id"] != stable_hash(
        "workflow_effect_producer_identity", payload
    ):
        raise WorkflowEffectEvidenceError("workflow effect producer id mismatches")
    return MappingProxyType(dict(source))


def workflow_runtime_evidence_classification() -> str:
    """Read an explicit workflow runtime class without upgrading local proof."""

    value = os.environ.get(
        "SENTINELFORGE_BEHAVIOR_WORKFLOW_EVIDENCE_CLASSIFICATION", "unknown"
    ).strip()
    if value not in _RUNTIME_CLASSIFICATIONS:
        raise WorkflowEffectEvidenceError(
            "workflow runtime evidence classification is invalid"
        )
    return value


def workflow_effect_producer_build_identity() -> Mapping[str, Any]:
    """Return an explicit, authority-free workflow producer build identity."""

    build_sha = os.environ.get("SENTINEL_BUILD_SHA", "").strip().lower()
    valid_sha = _BUILD_SHA.fullmatch(build_sha) is not None
    dirty_value = os.environ.get("SENTINEL_BUILD_DIRTY", "").strip().lower()
    dirty = True if dirty_value in _TRUE else False if dirty_value in _FALSE else None
    source_state = (
        "dirty"
        if dirty is True and valid_sha
        else "clean"
        if dirty is False and valid_sha
        else "unknown"
    )
    build_id = (os.environ.get("SENTINEL_BUILD_ID", "local").strip() or "local")[:256]
    payload = {
        "producer_name": "sentinelforge_behavioral_execution",
        "build_id": build_id,
        "build_sha": build_sha if source_state != "unknown" else "unknown",
        "source_state": source_state,
    }
    record = {
        "schema_version": 1,
        "producer_id": stable_hash("workflow_effect_producer_identity", payload),
        **payload,
    }
    return dict(_validate_producer(record))


@dataclass(frozen=True)
class WorkflowEffectEvidence:
    schema_version: int
    evidence_root: str
    source_receipt_id: str
    execution_admission_ref: str
    specification_id: str
    transport_specification_id: str
    candidate_id: str
    result_id: str
    evidence_id: str
    target_origin: str
    assessment_session_id: str
    identity_binding: Mapping[str, Any]
    experiment_world_ref: str
    authority_ref: str
    tenant_ref: str
    source_evidence_ref: str
    oracle: Mapping[str, Any]
    compensating_cleanup_verified: bool
    producer_identity: Mapping[str, Any]
    observed_at_epoch: float
    runtime_evidence_classification: str

    @classmethod
    def build(
        cls,
        *,
        source_receipt_id: str,
        execution_admission_ref: str,
        specification_id: str,
        transport_specification_id: str,
        candidate_id: str,
        result_id: str,
        evidence_id: str,
        target_origin: str,
        assessment_session_id: str,
        identity_binding: Mapping[str, Any],
        experiment_world_ref: str,
        authority_ref: str,
        tenant_ref: str,
        source_evidence_ref: str,
        oracle: Mapping[str, Any],
        compensating_cleanup_verified: bool,
        producer_identity: Mapping[str, Any],
        observed_at_epoch: float,
        runtime_evidence_classification: str,
    ) -> WorkflowEffectEvidence:
        payload = {
            "schema_version": WORKFLOW_EFFECT_EVIDENCE_SCHEMA_VERSION,
            "source_receipt_id": source_receipt_id,
            "execution_admission_ref": execution_admission_ref,
            "specification_id": specification_id,
            "transport_specification_id": transport_specification_id,
            "candidate_id": candidate_id,
            "result_id": result_id,
            "evidence_id": evidence_id,
            "target_origin": target_origin,
            "assessment_session_id": assessment_session_id,
            "identity_binding": dict(identity_binding),
            "experiment_world_ref": experiment_world_ref,
            "authority_ref": authority_ref,
            "tenant_ref": tenant_ref,
            "source_evidence_ref": source_evidence_ref,
            "oracle": dict(oracle),
            "compensating_cleanup_verified": compensating_cleanup_verified,
            "producer_identity": dict(producer_identity),
            "observed_at_epoch": observed_at_epoch,
            "runtime_evidence_classification": runtime_evidence_classification,
        }
        return cls(evidence_root=_evidence_root(payload), **payload)

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> WorkflowEffectEvidence:
        source = _exact(value, _FIELDS, "workflow effect evidence")
        return cls(**dict(source))

    @classmethod
    def from_json_bytes(cls, value: bytes) -> WorkflowEffectEvidence:
        if type(value) is not bytes:
            raise TypeError("workflow effect evidence JSON must be bytes")
        if len(value) > WORKFLOW_EFFECT_EVIDENCE_MAX_BYTES:
            raise WorkflowEffectEvidenceError(
                "workflow effect evidence is oversized"
            )

        def reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for key, child in pairs:
                if key in result:
                    raise WorkflowEffectEvidenceError(
                        "workflow effect evidence has duplicate keys"
                    )
                result[key] = child
            return result

        def reject_constant(value: str) -> None:
            raise WorkflowEffectEvidenceError(f"invalid JSON constant: {value}")

        try:
            parsed = json.loads(
                value.decode("utf-8", errors="strict"),
                object_pairs_hook=reject_duplicate_pairs,
                parse_constant=reject_constant,
            )
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise WorkflowEffectEvidenceError(
                "workflow effect evidence JSON is invalid"
            ) from exc
        evidence = cls.from_mapping(parsed)
        if value != evidence.to_json_bytes():
            raise WorkflowEffectEvidenceError(
                "workflow effect evidence JSON is not canonical"
            )
        return evidence

    def __post_init__(self) -> None:
        if type(self.schema_version) is not int or self.schema_version != 1:
            raise WorkflowEffectEvidenceError(
                "workflow effect evidence version is invalid"
            )
        if type(self.evidence_root) is not str or not _BARE_SHA256.fullmatch(
            self.evidence_root
        ):
            raise WorkflowEffectEvidenceError(
                "workflow effect evidence root is invalid"
            )
        # DELTA-1: the ledger cites this evidence by a bare behavioral-<hash>
        # receipt id, not a typed behavioral_receipt:<hash> reference.
        _behavioral_receipt(self.source_receipt_id, "source receipt id")
        for name, prefix in (
            # DELTA-2: typed reference to the committed workflow journal admission.
            ("execution_admission_ref", "workflow_effect_promotion_admission"),
            ("specification_id", "workflow_effect_one_click_specification"),
            ("transport_specification_id", "workflow_effect_transport_specification"),
            ("candidate_id", "workflow_effect_finding_candidate"),
            ("result_id", "workflow_effect_transport_result"),
            ("evidence_id", "workflow_effect_evidence"),
            ("experiment_world_ref", "world"),
            ("authority_ref", "experiment_authority_context"),
            ("tenant_ref", "owned_tenant"),
            ("source_evidence_ref", "graph_bound_capture_artifact"),
        ):
            _typed_ref(getattr(self, name), prefix, name)
        origin = _bounded(self.target_origin, "workflow target origin", 2048)
        parsed_origin = canonical_origin(origin)
        if parsed_origin is None or parsed_origin.as_url() != origin:
            raise WorkflowEffectEvidenceError(
                "workflow target origin is not canonical"
            )
        session = _bounded(self.assessment_session_id, "assessment session id", 256)
        identity = _validate_identity(self.identity_binding)
        if (
            identity["session_id"] != session
            or identity["target_origin"] != origin
            or self.experiment_world_ref != stable_hash("world", identity["persona_id"])
        ):
            raise WorkflowEffectEvidenceError("workflow identity bindings mismatch")
        oracle = _validate_oracle(self.oracle)
        if type(self.compensating_cleanup_verified) is not bool:
            raise WorkflowEffectEvidenceError(
                "workflow cleanup verification is invalid"
            )
        producer = _validate_producer(self.producer_identity)
        if (
            type(self.observed_at_epoch) is not float
            or not math.isfinite(self.observed_at_epoch)
            or self.observed_at_epoch <= 0
        ):
            raise WorkflowEffectEvidenceError("workflow observation time is invalid")
        if (
            type(self.runtime_evidence_classification) is not str
            or self.runtime_evidence_classification not in _RUNTIME_CLASSIFICATIONS
        ):
            raise WorkflowEffectEvidenceError(
                "workflow runtime evidence classification is invalid"
            )
        object.__setattr__(self, "identity_binding", identity)
        object.__setattr__(self, "oracle", oracle)
        object.__setattr__(self, "producer_identity", producer)
        payload = self.to_dict()
        payload.pop("evidence_root")
        if self.evidence_root != _evidence_root(payload):
            raise WorkflowEffectEvidenceError("workflow evidence root mismatches")
        self.to_json_bytes()

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "evidence_root": self.evidence_root,
            "source_receipt_id": self.source_receipt_id,
            "execution_admission_ref": self.execution_admission_ref,
            "specification_id": self.specification_id,
            "transport_specification_id": self.transport_specification_id,
            "candidate_id": self.candidate_id,
            "result_id": self.result_id,
            "evidence_id": self.evidence_id,
            "target_origin": self.target_origin,
            "assessment_session_id": self.assessment_session_id,
            "identity_binding": dict(self.identity_binding),
            "experiment_world_ref": self.experiment_world_ref,
            "authority_ref": self.authority_ref,
            "tenant_ref": self.tenant_ref,
            "source_evidence_ref": self.source_evidence_ref,
            "oracle": dict(self.oracle),
            "compensating_cleanup_verified": self.compensating_cleanup_verified,
            "producer_identity": dict(self.producer_identity),
            "observed_at_epoch": self.observed_at_epoch,
            "runtime_evidence_classification": self.runtime_evidence_classification,
        }

    def to_json_bytes(self) -> bytes:
        encoded = _canonical_json_bytes(self.to_dict())
        if len(encoded) > WORKFLOW_EFFECT_EVIDENCE_MAX_BYTES:
            raise WorkflowEffectEvidenceError(
                "workflow effect evidence is oversized"
            )
        return encoded


def bind_to_run(
    evidence: WorkflowEffectEvidence, run: WorkflowEffectOneClickRun
) -> None:
    """Refuse an evidence claim that differs from its authority-free run."""

    if (
        type(evidence) is not WorkflowEffectEvidence
        or type(run) is not WorkflowEffectOneClickRun
    ):
        raise WorkflowEffectEvidenceError(
            "workflow evidence binding type is invalid"
        )
    if (
        run.finding_authority is not False
        or run.promotion_authority is not False
        or run.real_workflow_effect_observed is not False
        or run.wired_into_production is not False
        or not run.dispatched
        or run.result is None
        or run.candidate is None
    ):
        raise WorkflowEffectEvidenceError(
            "workflow run is not an authority-free candidate"
        )
    candidate = run.candidate
    if (
        candidate.finding_authority is not False
        or candidate.promotion_authority is not False
        or candidate.real_workflow_effect_observed is not False
        or candidate.wired_into_production is not False
        or candidate.adversarial_triage_required is not True
    ):
        raise WorkflowEffectEvidenceError("workflow candidate claims authority")
    try:
        checked = WorkflowEffectOneClickRun.from_dict(run.to_dict())
        source = WorkflowEffectEvidence.from_mapping(evidence.to_dict())
    except (TypeError, ValueError) as exc:
        raise WorkflowEffectEvidenceError(
            "workflow evidence binding is invalid"
        ) from exc
    result = checked.result
    attested = result.evidence if result is not None else None
    if (
        result is None
        or attested is None
        or checked.candidate is None
        or source.specification_id != checked.specification_id
        or source.transport_specification_id != checked.transport_specification_id
        or source.candidate_id != checked.candidate.candidate_id
        or source.result_id != checked.candidate.result_id
        or source.evidence_id != checked.candidate.evidence_id
        or source.oracle["outcome"] != attested.oracle_outcome.value
        or source.oracle["correspondence"] != result.correspondence.value
        or source.compensating_cleanup_verified
        is not result.compensating_cleanup_verified
    ):
        raise WorkflowEffectEvidenceError("workflow evidence does not bind to run")


@dataclass(frozen=True)
class WorkflowEffectEligibility:
    eligible: bool
    reason_code: str
    failed_clauses: Tuple[int, ...]

    def __post_init__(self) -> None:
        if type(self.eligible) is not bool:
            raise TypeError("workflow effect eligibility must be boolean")
        _semantic(self.reason_code, "workflow effect reason code")
        if any(
            type(item) is not int or not 1 <= item <= 6
            for item in self.failed_clauses
        ):
            raise ValueError("workflow effect failed clauses are invalid")


def evaluate_workflow_effect_eligibility(
    evidence: WorkflowEffectEvidence,
) -> WorkflowEffectEligibility:
    """Purely evaluate whether an evidence record may ENTER promotion triage.

    This is authority-free: an ``eligible`` record is one that is well-formed,
    authority-free, and carries an observed, cleaned-up workflow-effect
    violation from an honest runtime class with the downstream reference
    material. It does NOT confirm a finding, grant promotion, or wire anything;
    the (future) admission + adversarial triage remain mandatory.
    """

    if type(evidence) is not WorkflowEffectEvidence:
        raise TypeError("workflow effect eligibility requires typed evidence")
    oracle = evidence.oracle
    try:
        outcome = WorkflowEffectOutcome(oracle["outcome"])
        correspondence = WorkflowEffectCorrespondence(oracle["correspondence"])
    except ValueError:
        return WorkflowEffectEligibility(
            eligible=False,
            reason_code="oracle_not_interpretable",
            failed_clauses=(1,),
        )
    # Re-derive the effect signal; never trust the stored boolean.
    effect_observed = (
        outcome is WorkflowEffectOutcome.EFFECT_OBSERVED_VIOLATION
        and correspondence is WorkflowEffectCorrespondence.COHERENT
    )
    effect_absent_coherent = (
        outcome is WorkflowEffectOutcome.EFFECT_ABSENT
        and correspondence is WorkflowEffectCorrespondence.COHERENT
    )
    preimage = evidence.to_dict()
    preimage.pop("evidence_root")
    clause_1 = effect_observed
    clause_2 = oracle["adversarial_triage_required"] is True
    clause_3 = (
        oracle["promotion_authority"] is False
        and oracle["finding_authority"] is False
    )
    clause_4 = evidence.compensating_cleanup_verified is True
    clause_5 = evidence.runtime_evidence_classification in _HONEST_CLASSIFICATIONS
    clause_6 = bool(
        _BEHAVIORAL_RECEIPT.fullmatch(evidence.source_receipt_id)
        and _TYPED_SHA256.fullmatch(evidence.execution_admission_ref)
        and _TYPED_SHA256.fullmatch(evidence.execution_admission_ref).group(1)
        == "workflow_effect_promotion_admission"
        and evidence.evidence_root == _evidence_root(preimage)
    )
    clauses = (clause_1, clause_2, clause_3, clause_4, clause_5, clause_6)
    failed = tuple(index for index, passed in enumerate(clauses, 1) if not passed)
    if not failed:
        return WorkflowEffectEligibility(
            eligible=True,
            reason_code="eligible_workflow_effect",
            failed_clauses=(),
        )
    if failed[0] == 1 and effect_absent_coherent:
        reason = "effect_absent_secure_workflow"
    else:
        reasons = {
            1: "workflow_effect_not_observed",
            2: "adversarial_triage_not_required",
            3: "evidence_claims_authority",
            4: "compensating_cleanup_not_verified",
            5: "runtime_classification_not_honest",
            6: "source_validation_failed",
        }
        reason = reasons[failed[0]]
    return WorkflowEffectEligibility(
        eligible=False,
        reason_code=reason,
        failed_clauses=failed,
    )


def workflow_invariant_finding_material(
    evidence: WorkflowEffectEvidence,
) -> dict[str, Any]:
    """Derive the bounded workflow-invariant claim from eligible typed evidence."""

    if not evaluate_workflow_effect_eligibility(evidence).eligible:
        raise ValueError("workflow effect evidence is not an invariant violation")
    return {
        "title": "Observed workflow effects exceed the declared aggregate limit",
        "confirmation_level": "confirmed",
        "severity": "medium",
        "description": (
            "Retained controlled-execution evidence shows a coherent observed "
            "workflow effect that violated the declared aggregate limit, with "
            "compensating cleanup verified. The finding is limited to the "
            "observed workflow and does not establish impact beyond it."
        ),
        "remediation": (
            "Enforce the aggregate limit atomically across sequential workflow "
            "operations, and reject an operation before it can exceed the limit."
        ),
        "metadata": {
            "finding_class": "workflow_invariant_violation_v1",
            "evidence_schema_version": evidence.schema_version,
            "evidence_root": evidence.evidence_root,
            "source_receipt_id": evidence.source_receipt_id,
            "execution_admission_ref": evidence.execution_admission_ref,
            "producer_identity": dict(evidence.producer_identity),
            "assessment_session_id": evidence.assessment_session_id,
            "target_origin": evidence.target_origin,
            "specification_id": evidence.specification_id,
            "transport_specification_id": evidence.transport_specification_id,
            "candidate_id": evidence.candidate_id,
            "result_id": evidence.result_id,
            "evidence_id": evidence.evidence_id,
            "experiment_world_ref": evidence.experiment_world_ref,
            "oracle_outcome": evidence.oracle["outcome"],
            "oracle_correspondence": evidence.oracle["correspondence"],
            "compensating_cleanup_verified": evidence.compensating_cleanup_verified,
            "observed_at_epoch": evidence.observed_at_epoch,
            "runtime_evidence_classification": (
                evidence.runtime_evidence_classification
            ),
            "impact_assessment": "unassessed",
            "severity_basis": "provisional_class_default_pending_impact_assessment",
        },
    }
