"""Durable, redacted idempotency receipts for behavioral target traffic.

Reservation uses an exclusive create and terminal transitions require the
unpersisted reservation token. Concurrent processes therefore cannot refresh or
finish the proof budget for the same capture pair. The persisted schema accepts
only hashed context and bounded operational summaries; captures, credentials,
identifiers, response bodies, and semantic finding evidence cannot enter it.
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
import math
import os
import re
import secrets
import stat
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Sequence

from core.epistemic.storage_boundary import (
    EvidenceStorageAnchor,
    EvidenceStorageBoundaryError,
)

from .normalize import stable_hash

RECEIPT_ENV = "SENTINELFORGE_BEHAVIOR_RECEIPTS"
RESERVED = "reserved"
COMPLETED = "completed"
ABORTED = "aborted"
_VALID_STATES = frozenset({RESERVED, COMPLETED, ABORTED})
_VALID_RUN_STATUSES = frozenset(
    {"completed", "aborted", "cleanup_failed", "no_executable_candidate"}
)
_VALID_EXECUTION_STATUSES = frozenset({"completed", "aborted"})
_VALID_EXPLORATION_STATUSES = frozenset(
    {"completed", "disabled", "failed", "not_needed"}
)
_VALID_COMPILED_STATUSES = frozenset({"completed", "aborted", "cleanup_failed"})
_VALID_LEGACY_VERDICTS = frozenset(
    {"BOLA_CONFIRMED", "DENIED", "NO_CROSS_READ", "AMBIGUOUS", "ERROR"}
)
_PROPOSAL_REF = re.compile(r"^authorization_proposal:[0-9a-f]{64}$")
_OWNED_EXPERIMENT_REF = re.compile(r"^owned_experiment:[0-9a-f]{64}$")
_OMISSION_EXPERIMENT_REF = re.compile(r"^omission_experiment:[0-9a-f]{64}$")
_OWNED_LIFECYCLE_REF = re.compile(r"^owned_lifecycle:[0-9a-f]{64}$")
_ACTION_REF = re.compile(r"^action:[0-9a-f]{64}$")
_FRESH_BOUNDARY_REF = re.compile(r"^fresh_owned_boundary:[0-9a-f]{64}$")
_FRESH_OMISSION_BOUNDARY_REF = re.compile(r"^fresh_omission_boundary:[0-9a-f]{64}$")
_FRESH_OMISSION_CONFIRMATION_REF = re.compile(
    r"^fresh_omission_confirmation:[0-9a-f]{64}$"
)
_OMISSION_CAPABILITY_FINDING_REF = re.compile(
    r"^omission_capability_finding:[0-9a-f]{64}$"
)
_SECURITY_OBLIGATION_REF = re.compile(r"^security_obligation:[0-9a-f]{64}$")
_COMPILED_SEQUENCE_REF = re.compile(r"^controlled_runtime_sequence:[0-9a-f]{64}$")
_INTERACTION_ACQUISITION_REF = re.compile(
    r"^interaction_read_acquisition:[0-9a-f]{64}$"
)
_INTERACTION_ADMISSION_REF = re.compile(
    r"^interaction_intent_admission:[0-9a-f]{64}$"
)
_INTERACTION_REQUEST_REF = re.compile(
    r"^interaction_acquisition_request:[0-9a-f]{64}$"
)
_INTERACTION_RESPONSE_REF = re.compile(
    r"^interaction_acquisition_response:[0-9a-f]{64}$"
)
_OWNED_READ_PROOF_REF = re.compile(r"^owned_read_proof:[0-9a-f]{64}$")
_OWNED_STATE_TRANSITION_PROOF_REF = re.compile(
    r"^owned_state_transition_proof:[0-9a-f]{64}$"
)
_PROOF_EXPERIMENT_MANIFEST_REF = re.compile(
    r"^proof_experiment_manifest:[0-9a-f]{64}$"
)
_PROOF_EXPERIMENT_ADMISSION_REF = re.compile(
    r"^proof_experiment_admission:[0-9a-f]{64}$"
)
_PROOF_EXPERIMENT_EVALUATION_REF = re.compile(
    r"^proof_experiment_evaluation:[0-9a-f]{64}$"
)
_PROOF_EXPERIMENT_ORACLE_REF = re.compile(
    r"^proof_experiment_oracle:[0-9a-f]{64}$"
)
_PROOF_EXPERIMENT_ACTION_EVIDENCE_REF = re.compile(
    r"^proof_experiment_action_evidence:[0-9a-f]{64}$"
)
_PROOF_EXPERIMENT_FINDING_CANDIDATE_REF = re.compile(
    r"^proof_experiment_finding_candidate:[0-9a-f]{64}$"
)
_OWNERSHIP_EXPERIMENT_PROOF_REF = re.compile(
    r"^ownership_experiment_proof:[0-9a-f]{64}$"
)
_OWNERSHIP_EXPERIMENT_ADMISSION_REF = re.compile(
    r"^ownership_experiment_admission:[0-9a-f]{64}$"
)
_LOCATOR_OWNERSHIP_PROOF_REF = re.compile(
    r"^locator_ownership_proof:[0-9a-f]{64}$"
)
_LOCATOR_RUNTIME_AUTHORITY_REF = re.compile(
    r"^locator_runtime_authority:[0-9a-f]{64}$"
)
_GENERALIZED_AUTHORIZATION_PLAN_REF = re.compile(
    r"^generalized_authorization_plan:[0-9a-f]{64}$"
)
_LOCATOR_TRANSPORT_CONTEXT_REF = re.compile(
    r"^locator_transport_context:[0-9a-f]{64}$"
)
_BEHAVIORAL_RECEIPT_REF = re.compile(r"^behavioral_receipt:[0-9a-f]{64}$")
_PROVENANCE_REF = re.compile(r"^provenance:[0-9a-f]{64}$")
_STATE_TRANSITION_ACTION_REF = re.compile(
    r"^state_transition_action:[0-9a-f]{64}$"
)
_LIFECYCLE_FINDING_REF = re.compile(
    r"^forbidden_lifecycle_transition:[0-9a-f]{64}$"
)
_SHA256_ARTIFACT_REF = re.compile(r"^sha256:[0-9a-f]{64}$")
_CORRELATION_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9:._-]{0,127}$")
_STATE_TRANSITION_SEMANTIC = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
_NATIVE_OWNERSHIP_PROOF_REF = re.compile(
    r"^native_ownership_witness:[0-9a-f]{64}$"
)
_INTERACTION_PAGE_REF = re.compile(r"^interaction_page:[0-9a-f]{64}$")
_INTERACTION_RENDER_REF = re.compile(
    r"^interaction_render_observation:[0-9a-f]{64}$"
)
_INTERACTION_TARGET_REF = re.compile(r"^interaction_target:[0-9a-f]{64}$")
_INTERACTION_WORLD_REF = re.compile(r"^world:[0-9a-f]{64}$")
_INTERACTION_CATALOG_REF = re.compile(
    r"^interaction_intent_catalog:[0-9a-f]{64}$"
)
_INTERACTION_INTENT_SET_REF = re.compile(
    r"^interaction_intent_set:[0-9a-f]{64}$"
)
_BROWSER_TRANSITION_REF = re.compile(
    r"^browser_state_transition:[0-9a-f]{64}$"
)
_BROWSER_STATE_REF = re.compile(r"^browser_state:[0-9a-f]{64}$")
_BEHAVIORAL_RECEIPT_ID = re.compile(r"^behavioral-[0-9a-f]{64}$")
_INTERACTION_ADAPTIVE_CONTROLLER_REF = re.compile(
    r"^interaction_adaptive_controller:[0-9a-f]{64}$"
)
_INTERACTION_ADAPTIVE_CHAIN_REF = re.compile(
    r"^interaction_adaptive_chain:[0-9a-f]{64}$"
)
_FRESH_BOUNDARY_ERROR_CODES = frozenset(
    {
        "fresh_boundary_baseline_is_not_usable",
        "fresh_boundary_cleanup_failed",
        "fresh_boundary_create_identifier_is_unavailable",
        "fresh_boundary_create_policy_denied",
        "fresh_boundary_create_returned_non_2xx",
        "fresh_boundary_create_transport_error",
        "fresh_boundary_cross_probe_policy_denied",
        "fresh_boundary_identifiers_are_not_distinct",
        "fresh_boundary_oracle_request_changed",
        "fresh_boundary_ownership_registration_failed",
        "fresh_boundary_proof_aborted",
        "fresh_boundary_proof_leg_budget_exceeded",
        "fresh_boundary_proof_transport_error",
        "fresh_boundary_runtime_binding_changed",
        "fresh_boundary_unexpected_proof_error",
    }
)
_COMPILED_ERROR_CODES = frozenset(
    {
        "runtime_body_is_not_structured",
        "runtime_body_json_is_invalid",
        "runtime_body_json_is_not_container",
        "runtime_cleanup_changed_endpoint_budget_key",
        "runtime_cleanup_failed",
        "runtime_cleanup_target_is_not_registered",
        "runtime_cleanup_transport_error",
        "runtime_cleanup_value_is_unavailable",
        "runtime_consumer_locator_is_not_supported",
        "runtime_create_id_is_missing_or_ambiguous",
        "runtime_create_ownership_registration_failed",
        "runtime_dependency_value_is_unavailable",
        "runtime_form_body_is_not_text",
        "runtime_owned_target_is_not_registered",
        "runtime_parameter_locator_is_invalid",
        "runtime_parameter_locator_missing",
        "runtime_parameter_occurrence_is_invalid",
        "runtime_path_index_is_invalid",
        "runtime_path_locator_is_invalid",
        "runtime_path_locator_missing",
        "runtime_producer_locator_is_not_supported",
        "runtime_request_array_index_invalid",
        "runtime_request_array_index_missing",
        "runtime_request_locator_crosses_scalar",
        "runtime_request_locator_is_empty",
        "runtime_request_locator_missing",
        "runtime_request_locator_parent_is_scalar",
        "runtime_response_array_index_invalid",
        "runtime_response_array_index_missing",
        "runtime_response_json_is_invalid",
        "runtime_response_json_is_not_container",
        "runtime_response_locator_crosses_scalar",
        "runtime_response_locator_missing",
        "runtime_response_value_is_invalid",
        "runtime_response_value_is_not_scalar_identifier",
        "runtime_step_denied_by_policy",
        "runtime_step_returned_non_2xx",
        "runtime_substitution_changed_endpoint_budget_key",
        "runtime_transport_error",
    }
)
_FRESH_OMISSION_ERROR_CODES = frozenset(
    {
        "fresh_omission_baseline_reference_mismatch",
        "fresh_omission_binding_changed_endpoint",
        "fresh_omission_cleanup_binding_failed",
        "fresh_omission_cleanup_endpoint_changed",
        "fresh_omission_cleanup_failed",
        "fresh_omission_create_identifier_is_ambiguous",
        "fresh_omission_dependency_value_is_unavailable",
        "fresh_omission_execution_aborted",
        "fresh_omission_identifiers_are_not_distinct",
        "fresh_omission_leg_did_not_reach_terminal",
        "fresh_omission_owned_object_is_unavailable",
        "fresh_omission_ownership_registration_failed",
        "fresh_omission_policy_denied",
        "fresh_omission_runtime_binding_failed",
        "fresh_omission_runtime_value_is_unavailable",
        "fresh_omission_setup_step_returned_non_2xx",
        "fresh_omission_transport_error",
        "fresh_omission_unexpected_execution_error",
    }
)
_FRESH_OMISSION_COMPARISONS = frozenset(
    {
        "not_completed",
        "exact_match",
        "response_mismatch",
        "omission_rejected",
        "inconclusive_truncated",
    }
)
_FRESH_OMISSION_CONFIRMATION_STATUSES = frozenset(
    {
        "not_completed",
        "confirmed_fail_open",
        "omission_rejected",
        "response_mismatch",
        "inconclusive_truncated",
        "control_accepted",
        "control_inconclusive",
        "inconclusive_cleanup_failed",
    }
)
_FRESH_OMISSION_CONFIRMATION_ERROR_CODES = (
    _FRESH_OMISSION_ERROR_CODES
    | frozenset(
        {
            "fresh_omission_confirmation_aborted",
            "fresh_omission_confirmation_binding_is_missing",
            "fresh_omission_confirmation_capability_is_invalid",
            "fresh_omission_confirmation_cleanup_failed",
            "fresh_omission_confirmation_unexpected_execution_error",
        }
    )
)
_ABORT_REASON = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_CONTEXT_PREFIXES = {
    "target_ref": "behavioral_receipt_target:",
    "envelope_ref": "behavioral_receipt_envelope:",
    "source_persona_ref": "behavioral_receipt_persona:",
    "peer_persona_ref": "behavioral_receipt_persona:",
}
_MAX_RECEIPT_BYTES = 1024 * 1024


def _reject_duplicate_json_keys(pairs: Sequence[tuple[str, Any]]) -> Dict[str, Any]:
    """Build one JSON object while rejecting ambiguous signed evidence."""

    value: Dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


class ReceiptStoreError(RuntimeError):
    """A receipt is corrupt or cannot be advanced safely."""


def re_full_sha256(value: str) -> bool:
    return len(value) == 64 and all(character in "0123456789abcdef" for character in value)


def _validated_timestamp(value: Any, *, field_name: str) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError) as exc:
        raise ReceiptStoreError(f"behavioral receipt {field_name} is invalid") from exc
    if not math.isfinite(parsed) or parsed <= 0:
        raise ReceiptStoreError(f"behavioral receipt {field_name} is invalid")
    return parsed


def _nonnegative_int(value: Any, *, field_name: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < 0
        or value > 2**63 - 1
    ):
        raise ReceiptStoreError(f"behavioral receipt {field_name} is invalid")
    return value


@dataclass(frozen=True)
class BehavioralReceiptContext:
    target_ref: str
    envelope_ref: str
    source_persona_ref: str
    peer_persona_ref: str

    def __post_init__(self) -> None:
        for key, prefix in _CONTEXT_PREFIXES.items():
            item = getattr(self, key)
            if (
                not isinstance(item, str)
                or not item.startswith(prefix)
                or not re_full_sha256(item[len(prefix):])
            ):
                raise ReceiptStoreError("behavioral receipt context is not redacted")

    def to_dict(self) -> Dict[str, str]:
        return {
            "target_ref": self.target_ref,
            "envelope_ref": self.envelope_ref,
            "source_persona_ref": self.source_persona_ref,
            "peer_persona_ref": self.peer_persona_ref,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "BehavioralReceiptContext":
        if set(value) != set(_CONTEXT_PREFIXES):
            raise ReceiptStoreError("behavioral receipt context fields are invalid")
        validated: Dict[str, str] = {}
        for key in _CONTEXT_PREFIXES:
            item = value[key]
            if not isinstance(item, str):
                raise ReceiptStoreError("behavioral receipt context is not redacted")
            validated[key] = item
        return cls(**validated)


@dataclass(frozen=True)
class BehavioralExecutionReceipt:
    receipt_id: str
    fingerprint: str
    state: str
    context: BehavioralReceiptContext
    created_at: float
    updated_at: float
    reservation_hash: Optional[str] = field(default=None, repr=False)
    outcome: Optional[Dict[str, Any]] = None
    abort_reason: Optional[str] = None
    terminal_evidence: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": 1,
            "receipt_id": self.receipt_id,
            "fingerprint": self.fingerprint,
            "state": self.state,
            "context": self.context.to_dict(),
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "reservation_hash": self.reservation_hash,
            "outcome": copy.deepcopy(self.outcome),
            "abort_reason": self.abort_reason,
            "terminal_evidence": copy.deepcopy(self.terminal_evidence),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "BehavioralExecutionReceipt":
        if value.get("schema_version") != 1:
            raise ReceiptStoreError("behavioral receipt schema version is invalid")
        state = str(value.get("state") or "")
        fingerprint = str(value.get("fingerprint") or "")
        receipt_id = str(value.get("receipt_id") or "")
        if state not in _VALID_STATES:
            raise ReceiptStoreError("behavioral receipt has invalid state")
        if not re_full_sha256(fingerprint) or receipt_id != f"behavioral-{fingerprint}":
            raise ReceiptStoreError("behavioral receipt identity mismatch")
        context = value.get("context")
        if not isinstance(context, Mapping):
            raise ReceiptStoreError("behavioral receipt context is invalid")
        created_at = _validated_timestamp(value.get("created_at"), field_name="created_at")
        updated_at = _validated_timestamp(value.get("updated_at"), field_name="updated_at")
        if updated_at < created_at:
            raise ReceiptStoreError("behavioral receipt timestamps are inconsistent")

        reservation_hash = value.get("reservation_hash")
        outcome = value.get("outcome")
        abort_reason = value.get("abort_reason")
        terminal_evidence = value.get("terminal_evidence")
        if state == RESERVED:
            if (
                not isinstance(reservation_hash, str)
                or not re_full_sha256(reservation_hash)
                or outcome is not None
                or abort_reason is not None
                or terminal_evidence is not None
            ):
                raise ReceiptStoreError("behavioral reserved receipt is invalid")
        elif reservation_hash is not None:
            raise ReceiptStoreError("behavioral terminal receipt retained a reservation")

        normalized_outcome: Optional[Dict[str, Any]] = None
        normalized_reason: Optional[str] = None
        normalized_terminal_evidence: Optional[Dict[str, Any]] = None
        if state == COMPLETED:
            if (
                not isinstance(outcome, Mapping)
                or abort_reason is not None
                or terminal_evidence is not None
            ):
                raise ReceiptStoreError("behavioral completed receipt is invalid")
            normalized_outcome = _redacted_stored_outcome(outcome)
            if normalized_outcome != dict(outcome):
                raise ReceiptStoreError("behavioral receipt outcome is not strictly redacted")
        elif state == ABORTED:
            if outcome is not None or not isinstance(abort_reason, str):
                raise ReceiptStoreError("behavioral aborted receipt is invalid")
            if _ABORT_REASON.fullmatch(abort_reason) is None:
                raise ReceiptStoreError("behavioral receipt abort reason is invalid")
            normalized_reason = abort_reason
            if terminal_evidence is not None:
                if not isinstance(terminal_evidence, Mapping):
                    raise ReceiptStoreError(
                        "behavioral terminal evidence is invalid"
                    )
                normalized_terminal_evidence = redacted_terminal_evidence(
                    terminal_evidence
                )
                if normalized_terminal_evidence != dict(terminal_evidence):
                    raise ReceiptStoreError(
                        "behavioral terminal evidence is not strictly redacted"
                    )

        return cls(
            receipt_id=receipt_id,
            fingerprint=fingerprint,
            state=state,
            context=BehavioralReceiptContext.from_dict(context),
            created_at=created_at,
            updated_at=updated_at,
            reservation_hash=reservation_hash,
            outcome=normalized_outcome,
            abort_reason=normalized_reason,
            terminal_evidence=normalized_terminal_evidence,
        )


@dataclass(frozen=True)
class ReceiptReservation:
    created: bool
    receipt: BehavioralExecutionReceipt
    reservation_token: Optional[str] = field(default=None, repr=False)


def request_fingerprint(value: Mapping[str, Any]) -> str:
    """Hash a canonical request envelope; raw material is never returned or stored."""
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def redacted_receipt_context(
    *, target_origin: str, envelope_id: str, source_persona_id: str, peer_persona_id: str
) -> BehavioralReceiptContext:
    return BehavioralReceiptContext(
        target_ref=stable_hash("behavioral_receipt_target", target_origin),
        envelope_ref=stable_hash("behavioral_receipt_envelope", envelope_id),
        source_persona_ref=stable_hash("behavioral_receipt_persona", source_persona_id),
        peer_persona_ref=stable_hash("behavioral_receipt_persona", peer_persona_id),
    )


def _selected_proposal(plan: Any) -> Optional[str]:
    if not isinstance(plan, Mapping):
        raise ReceiptStoreError("behavioral receipt plan is invalid")
    proposal_id = plan.get("selected_proposal_id")
    if proposal_id is None:
        return None
    if not isinstance(proposal_id, str) or _PROPOSAL_REF.fullmatch(proposal_id) is None:
        raise ReceiptStoreError("behavioral receipt proposal reference is invalid")
    return proposal_id


def _selected_experiment(plan: Any) -> Optional[str]:
    if not isinstance(plan, Mapping):
        raise ReceiptStoreError("behavioral receipt plan is invalid")
    experiment_id = plan.get("selected_experiment_id")
    if experiment_id is None:
        return None
    if (
        not isinstance(experiment_id, str)
        or _OWNED_EXPERIMENT_REF.fullmatch(experiment_id) is None
    ):
        raise ReceiptStoreError("behavioral receipt experiment reference is invalid")
    return experiment_id


def _selected_obligation(plan: Any) -> Optional[str]:
    if not isinstance(plan, Mapping):
        raise ReceiptStoreError("behavioral receipt plan is invalid")
    obligation_id = plan.get("selected_obligation_id")
    if obligation_id is None:
        return None
    if (
        not isinstance(obligation_id, str)
        or _SECURITY_OBLIGATION_REF.fullmatch(obligation_id) is None
    ):
        raise ReceiptStoreError("behavioral receipt obligation reference is invalid")
    return obligation_id


def _redacted_execution(value: Any) -> Optional[Dict[str, Any]]:
    if value is None:
        return None
    if not isinstance(value, Mapping):
        raise ReceiptStoreError("behavioral receipt execution is invalid")
    status = value.get("status")
    verdict = value.get("legacy_verdict")
    if status not in _VALID_EXECUTION_STATUSES or verdict not in _VALID_LEGACY_VERDICTS:
        raise ReceiptStoreError("behavioral receipt execution summary is invalid")
    output = {
        "status": status,
        "legacy_verdict": verdict,
        "finding_confirmed": bool(value.get("finding_confirmed")),
        "requests_attempted": _nonnegative_int(
            value.get("requests_attempted"), field_name="requests_attempted"
        ),
        "requests_sent": _nonnegative_int(
            value.get("requests_sent"), field_name="requests_sent"
        ),
        "policy_denials": _nonnegative_int(
            value.get("policy_denials"), field_name="policy_denials"
        ),
    }
    provenance_root = value.get("provenance_root")
    if provenance_root is not None:
        if not isinstance(provenance_root, str) or not re_full_sha256(
            provenance_root
        ):
            raise ReceiptStoreError(
                "behavioral receipt execution provenance root is invalid"
            )
        output["provenance_root"] = provenance_root
    return output


def _count_section(value: Any, keys: tuple[str, ...], *, section: str) -> Dict[str, int]:
    if not isinstance(value, Mapping):
        raise ReceiptStoreError(f"behavioral receipt {section} diagnostics are invalid")
    return {
        key: _nonnegative_int(value.get(key), field_name=f"{section}.{key}")
        for key in keys
    }


def _redacted_graphql_diagnostics(value: Any) -> Dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ReceiptStoreError("behavioral receipt GraphQL diagnostics are invalid")
    catalog: Dict[str, Any] = _count_section(
        value.get("catalog"),
        ("artifacts", "artifact_bytes", "documents", "operation_names"),
        section="catalog",
    )
    raw_catalog = value.get("catalog")
    assert isinstance(raw_catalog, Mapping)
    catalog["dropped"] = _count_section(
        raw_catalog.get("dropped"),
        ("artifacts", "artifact_bytes", "documents"),
        section="catalog.dropped",
    )
    return {
        "catalog": catalog,
        "assets": _count_section(
            value.get("assets"),
            ("attempted", "fetched", "failed", "documents_added"),
            section="assets",
        ),
        "source": _count_section(
            value.get("source"),
            ("resolved_operations", "unresolved_operations", "ambiguous_operations"),
            section="source",
        ),
        "peer": _count_section(
            value.get("peer"),
            ("resolved_operations", "unresolved_operations", "ambiguous_operations"),
            section="peer",
        ),
    }


def _redacted_read_exploration(value: Any) -> Dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ReceiptStoreError("behavioral receipt read exploration is invalid")
    status = value.get("status")
    if status not in _VALID_EXPLORATION_STATUSES:
        raise ReceiptStoreError("behavioral receipt read exploration status is invalid")
    counters = {
        key: _nonnegative_int(value.get(key), field_name=f"read_exploration.{key}")
        for key in (
            "pairs_attempted",
            "pairs_completed",
            "requests_attempted",
            "requests_sent",
            "successful_responses",
            "policy_denials",
            "failed_requests",
            "candidates_discovered",
            "selected_after_pair",
        )
    }
    if (
        counters["pairs_completed"] > counters["pairs_attempted"]
        or counters["requests_sent"] > counters["requests_attempted"]
        or counters["successful_responses"] > counters["requests_sent"]
        or counters["selected_after_pair"] > counters["pairs_attempted"]
    ):
        raise ReceiptStoreError("behavioral receipt read exploration is inconsistent")
    if status in {"disabled", "not_needed"} and any(counters.values()):
        raise ReceiptStoreError("inactive behavioral read exploration has activity")
    return {
        "status": status,
        **counters,
        "frontier_exhausted": bool(value.get("frontier_exhausted")),
    }


def redacted_interaction_acquisition_outcome(
    value: Mapping[str, Any],
) -> Dict[str, Any]:
    """Return only redacted conduct facts for one acquired navigation response."""

    refs = {
        "acquisition_id": (
            value.get("acquisition_id"),
            _INTERACTION_ACQUISITION_REF,
        ),
        "admission_id": (
            value.get("admission_id"),
            _INTERACTION_ADMISSION_REF,
        ),
        "obligation_id": (
            value.get("obligation_id"),
            _SECURITY_OBLIGATION_REF,
        ),
        "request_ref": (
            value.get("request_ref"),
            _INTERACTION_REQUEST_REF,
        ),
        "response_ref": (
            value.get("response_ref"),
            _INTERACTION_RESPONSE_REF,
        ),
    }
    if any(
        not isinstance(item, str) or pattern.fullmatch(item) is None
        for item, pattern in refs.values()
    ):
        raise ReceiptStoreError("interaction acquisition identity is invalid")
    state_refs = {
        "destination_page_ref": (
            value.get("destination_page_ref"),
            _INTERACTION_PAGE_REF,
        ),
        "operation_ref": (
            value.get("operation_ref"),
            _ACTION_REF,
        ),
    }
    state_ref_presence = tuple(
        item is not None for item, _pattern in state_refs.values()
    )
    if any(state_ref_presence) and (
        not all(state_ref_presence)
        or any(
            not isinstance(item, str) or pattern.fullmatch(item) is None
            for item, pattern in state_refs.values()
        )
    ):
        raise ReceiptStoreError(
            "interaction acquisition state identity is invalid"
        )
    response_status = value.get("response_status")
    response_truncated = value.get("response_truncated")
    cross_persona_probe = value.get("cross_persona_probe", False)
    ownership_proof_ref = value.get("ownership_proof_ref")
    counters = {
        key: _nonnegative_int(
            value.get(key),
            field_name=f"interaction_acquisition.{key}",
        )
        for key in (
            "requests_attempted",
            "requests_sent",
            "policy_denials",
        )
    }
    provenance_root = value.get("provenance_root")
    if (
        value.get("kind") != "interaction_read_acquisition"
        or value.get("mode") != "behavioral_interaction_read_acquisition_v1"
        or value.get("status") != "completed"
        or isinstance(response_status, bool)
        or not isinstance(response_status, int)
        or not 100 <= response_status <= 599
        or not isinstance(response_truncated, bool)
        or not isinstance(cross_persona_probe, bool)
        or (
            ownership_proof_ref is not None
            and (
                not cross_persona_probe
                or not isinstance(ownership_proof_ref, str)
                or _NATIVE_OWNERSHIP_PROOF_REF.fullmatch(ownership_proof_ref)
                is None
            )
        )
        or counters
        != {
            "requests_attempted": 1,
            "requests_sent": 1,
            "policy_denials": 0,
        }
        or not isinstance(provenance_root, str)
        or not re_full_sha256(provenance_root)
    ):
        raise ReceiptStoreError("interaction acquisition outcome is invalid")
    budget = _count_section(
        value.get("budget_snapshot"),
        (
            "total_requests",
            "cross_object_reads",
            "privilege_mutations",
            "creates",
            "endpoints_touched",
        ),
        section="interaction_acquisition.budget_snapshot",
    )
    if (
        budget["total_requests"] < 1
        or budget["cross_object_reads"] != int(cross_persona_probe)
        or budget["privilege_mutations"] != 0
        or budget["creates"] != 0
        or not 1 <= budget["endpoints_touched"] <= budget["total_requests"]
    ):
        raise ReceiptStoreError("interaction acquisition budget is inconsistent")
    output = {
        "kind": "interaction_read_acquisition",
        "mode": "behavioral_interaction_read_acquisition_v1",
        "status": "completed",
        **{key: item for key, (item, _pattern) in refs.items()},
        "response_status": response_status,
        "response_truncated": response_truncated,
        "cross_persona_probe": cross_persona_probe,
        **counters,
        "provenance_root": provenance_root,
        "budget_snapshot": budget,
    }
    correlation_ids_value = value.get("correlation_ids", ())
    if (
        not isinstance(correlation_ids_value, Sequence)
        or isinstance(correlation_ids_value, (str, bytes))
        or len(correlation_ids_value) > 8
        or any(
            not isinstance(item, str)
            or _CORRELATION_ID.fullmatch(item) is None
            for item in correlation_ids_value
        )
    ):
        raise ReceiptStoreError(
            "interaction acquisition correlation identity is invalid"
        )
    correlation_ids = tuple(sorted(set(correlation_ids_value)))
    if len(correlation_ids) != len(correlation_ids_value):
        raise ReceiptStoreError(
            "interaction acquisition correlation identity is duplicated"
        )
    if correlation_ids:
        output["correlation_ids"] = list(correlation_ids)
    if ownership_proof_ref is not None:
        output["ownership_proof_ref"] = ownership_proof_ref
    if all(state_ref_presence):
        output.update(
            {
                key: item
                for key, (item, _pattern) in state_refs.items()
            }
        )
    return output


def redacted_owned_state_transition_outcome(
    value: Mapping[str, Any],
) -> Dict[str, Any]:
    """Seal one owned lifecycle proof without object identifiers or URLs."""

    if not isinstance(value, Mapping):
        raise ReceiptStoreError("owned state transition outcome is invalid")
    proof_id = value.get("proof_id")
    confirmation_status = value.get("confirmation_status")
    states = {
        key: value.get(key)
        for key in ("source_state", "prerequisite_state", "target_state")
    }
    action_refs = {
        key: value.get(key)
        for key in (
            "prerequisite_action_ref",
            "terminal_action_ref",
            "cleanup_action_ref",
        )
    }
    correlation_ids_value = value.get("correlation_ids", ())
    artifact_refs_value = value.get("artifact_refs", ())
    finding_ref = value.get("finding_ref")
    requests_sent = value.get("requests_sent")
    provenance_root = value.get("provenance_root")
    if (
        value.get("kind") != "owned_state_transition_proof"
        or value.get("mode") != "behavioral_owned_state_transition_proof_v1"
        or value.get("status") != "completed"
        or not isinstance(proof_id, str)
        or _OWNED_STATE_TRANSITION_PROOF_REF.fullmatch(proof_id) is None
        or confirmation_status
        not in {"confirmed_fail_open", "prerequisite_enforced"}
        or any(
            not isinstance(item, str)
            or _STATE_TRANSITION_SEMANTIC.fullmatch(item) is None
            for item in states.values()
        )
        or len(set(states.values())) != 3
        or any(
            not isinstance(item, str)
            or _STATE_TRANSITION_ACTION_REF.fullmatch(item) is None
            for item in action_refs.values()
        )
        or len(set(action_refs.values())) != 3
        or not isinstance(correlation_ids_value, Sequence)
        or isinstance(correlation_ids_value, (str, bytes))
        or not 1 <= len(correlation_ids_value) <= 24
        or any(
            not isinstance(item, str)
            or _CORRELATION_ID.fullmatch(item) is None
            for item in correlation_ids_value
        )
        or len(set(correlation_ids_value)) != len(correlation_ids_value)
        or not isinstance(artifact_refs_value, Sequence)
        or isinstance(artifact_refs_value, (str, bytes))
        or len(artifact_refs_value) != len(correlation_ids_value)
        or any(
            not isinstance(item, str)
            or _SHA256_ARTIFACT_REF.fullmatch(item) is None
            for item in artifact_refs_value
        )
        or value.get("cleanup_complete") is not True
        or isinstance(requests_sent, bool)
        or not isinstance(requests_sent, int)
        or not 1 <= requests_sent <= 21
        or not isinstance(provenance_root, str)
        or not re_full_sha256(provenance_root)
    ):
        raise ReceiptStoreError("owned state transition outcome is invalid")
    if confirmation_status == "confirmed_fail_open":
        if (
            not isinstance(finding_ref, str)
            or _LIFECYCLE_FINDING_REF.fullmatch(finding_ref) is None
        ):
            raise ReceiptStoreError("owned state transition finding is invalid")
    elif finding_ref is not None:
        raise ReceiptStoreError("enforced state transition cannot retain a finding")
    correlation_ids = list(correlation_ids_value)
    artifact_refs = list(artifact_refs_value)
    identity = {
        "confirmation_status": confirmation_status,
        **states,
        **action_refs,
        "correlation_ids": correlation_ids,
        "artifact_refs": artifact_refs,
    }
    if proof_id != stable_hash("owned_state_transition_proof", identity):
        raise ReceiptStoreError("owned state transition identity is inconsistent")
    expected_finding_ref = (
        stable_hash("forbidden_lifecycle_transition", identity)
        if confirmation_status == "confirmed_fail_open"
        else None
    )
    if finding_ref != expected_finding_ref:
        raise ReceiptStoreError("owned state transition finding is inconsistent")
    budget = _count_section(
        value.get("budget_snapshot"),
        (
            "total_requests",
            "cross_object_reads",
            "privilege_mutations",
            "creates",
            "endpoints_touched",
        ),
        section="owned_state_transition.budget_snapshot",
    )
    if (
        budget["total_requests"] != requests_sent
        or budget["cross_object_reads"] != 0
        or budget["privilege_mutations"] != 0
        or budget["creates"] != 2
        or not 1 <= budget["endpoints_touched"] <= requests_sent
    ):
        raise ReceiptStoreError("owned state transition budget is inconsistent")
    return {
        "kind": "owned_state_transition_proof",
        "mode": "behavioral_owned_state_transition_proof_v1",
        "status": "completed",
        "proof_id": proof_id,
        "confirmation_status": confirmation_status,
        **states,
        **action_refs,
        "correlation_ids": correlation_ids,
        "artifact_refs": artifact_refs,
        "finding_ref": finding_ref,
        "cleanup_complete": True,
        "requests_sent": requests_sent,
        "provenance_root": provenance_root,
        "budget_snapshot": budget,
    }


def redacted_owned_read_proof_outcome(
    value: Mapping[str, Any],
) -> Dict[str, Any]:
    """Seal one same-persona read proof without retaining its URL or body."""

    if not isinstance(value, Mapping):
        raise ReceiptStoreError("owned read proof outcome is invalid")
    proof_id = value.get("proof_id")
    acquisition_receipt_id = value.get("acquisition_receipt_id")
    artifact_ref = value.get("artifact_ref")
    acquisition_value = value.get("acquisition")
    correlation_ids_value = value.get("correlation_ids", ())
    if (
        value.get("kind") != "owned_read_proof"
        or value.get("mode") != "behavioral_owned_read_proof_v1"
        or value.get("status") != "completed"
        or not isinstance(proof_id, str)
        or _OWNED_READ_PROOF_REF.fullmatch(proof_id) is None
        or not isinstance(acquisition_receipt_id, str)
        or _BEHAVIORAL_RECEIPT_ID.fullmatch(acquisition_receipt_id) is None
        or not isinstance(artifact_ref, str)
        or _SHA256_ARTIFACT_REF.fullmatch(artifact_ref) is None
        or not isinstance(acquisition_value, Mapping)
        or not isinstance(correlation_ids_value, Sequence)
        or isinstance(correlation_ids_value, (str, bytes))
        or not 1 <= len(correlation_ids_value) <= 8
        or any(
            not isinstance(item, str)
            or _CORRELATION_ID.fullmatch(item) is None
            for item in correlation_ids_value
        )
    ):
        raise ReceiptStoreError("owned read proof outcome is invalid")
    correlation_ids = tuple(sorted(set(correlation_ids_value)))
    if len(correlation_ids) != len(correlation_ids_value):
        raise ReceiptStoreError("owned read proof correlation identity is duplicated")
    acquisition = redacted_interaction_acquisition_outcome(acquisition_value)
    if acquisition.get("cross_persona_probe") is not False:
        raise ReceiptStoreError("owned read proof became cross-persona")
    identity = {
        "acquisition_receipt_id": acquisition_receipt_id,
        "acquisition_id": acquisition["acquisition_id"],
        "artifact_ref": artifact_ref,
        "correlation_ids": list(correlation_ids),
    }
    if proof_id != stable_hash("owned_read_proof", identity):
        raise ReceiptStoreError("owned read proof identity is inconsistent")
    return {
        "kind": "owned_read_proof",
        "mode": "behavioral_owned_read_proof_v1",
        "status": "completed",
        "proof_id": proof_id,
        "acquisition_receipt_id": acquisition_receipt_id,
        "artifact_ref": artifact_ref,
        "correlation_ids": list(correlation_ids),
        "acquisition": acquisition,
    }


def _redacted_browser_transition_summary(value: Any) -> Dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ReceiptStoreError("browser state transition summary is invalid")
    status = value.get("status")
    if status == "unavailable":
        if (
            set(value)
            != {
                "schema_version",
                "mode",
                "status",
                "reason_code",
                "executable",
            }
            or value.get("schema_version") != 1
            or value.get("mode") != "behavioral_browser_state_explorer_v1"
            or value.get("reason_code") not in {
                "legacy_acquisition_receipt_missing_state_refs",
                "cross_persona_probe_has_no_browser_transition",
            }
            or value.get("executable") is not False
        ):
            raise ReceiptStoreError(
                "unavailable browser state transition is invalid"
            )
        return dict(value)
    if status == "error":
        if (
            set(value)
            != {
                "schema_version",
                "mode",
                "status",
                "error_code",
                "executable",
            }
            or value.get("schema_version") != 1
            or value.get("mode") != "behavioral_browser_state_explorer_v1"
            or value.get("error_code") != "state_transition_analysis_failed"
            or value.get("executable") is not False
        ):
            raise ReceiptStoreError("failed browser state transition is invalid")
        return dict(value)
    if status != "completed" or set(value) != {"status", "result"}:
        raise ReceiptStoreError("browser state transition summary is invalid")
    result = value.get("result")
    if not isinstance(result, Mapping):
        raise ReceiptStoreError("browser state transition result is invalid")
    try:
        from .interaction_state import BrowserTransitionResult

        normalized = BrowserTransitionResult.from_dict(result).to_dict()
    except (TypeError, ValueError) as exc:
        raise ReceiptStoreError(
            "browser state transition result is invalid"
        ) from exc
    return {"status": "completed", "result": normalized}


def _redacted_interaction_render_summary(value: Any) -> Dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ReceiptStoreError("interaction render observation is invalid")
    common = {
        "schema_version": 1,
        "mode": "behavioral_interaction_render_observation_v1",
        "target_requests_sent": 0,
        "executable": False,
    }
    if any(value.get(key) != expected for key, expected in common.items()):
        raise ReceiptStoreError(
            "interaction render observation contract is invalid"
        )
    status = value.get("status")
    if status == "not_needed":
        expected = {*common, "status"}
        if set(value) != expected:
            raise ReceiptStoreError(
                "inactive interaction render observation is invalid"
            )
        return {**common, "status": status}
    if status == "unavailable":
        if (
            set(value) != {*common, "status", "reason_code"}
            or value.get("reason_code")
            != "acquisition_response_not_available_for_observation"
        ):
            raise ReceiptStoreError(
                "unavailable interaction render observation is invalid"
            )
        return {**common, "status": status, "reason_code": value["reason_code"]}
    if status in {"denied", "error"}:
        error_code = value.get("error_code")
        if (
            set(value) != {*common, "status", "error_code"}
            or not isinstance(error_code, str)
            or _ABORT_REASON.fullmatch(error_code) is None
        ):
            raise ReceiptStoreError(
                "failed interaction render observation is invalid"
            )
        return {**common, "status": status, "error_code": error_code}
    expected = {
        *common,
        "status",
        "observation_id",
        "acquisition_id",
        "acquisition_receipt_id",
        "admission_id",
        "obligation_id",
        "target_ref",
        "world_ref",
        "page_ref",
        "response_ref",
        "catalog_id",
        "intent_digest",
        "controls_observed",
        "scanned_nodes",
        "controls_truncated",
        "bytes_inspected",
        "complete",
    }
    refs = {
        "observation_id": _INTERACTION_RENDER_REF,
        "acquisition_id": _INTERACTION_ACQUISITION_REF,
        "admission_id": _INTERACTION_ADMISSION_REF,
        "obligation_id": _SECURITY_OBLIGATION_REF,
        "target_ref": _INTERACTION_TARGET_REF,
        "world_ref": _INTERACTION_WORLD_REF,
        "page_ref": _INTERACTION_PAGE_REF,
        "response_ref": _INTERACTION_RESPONSE_REF,
        "catalog_id": _INTERACTION_CATALOG_REF,
        "intent_digest": _INTERACTION_INTENT_SET_REF,
    }
    controls_observed = _nonnegative_int(
        value.get("controls_observed"),
        field_name="interaction_render.controls_observed",
    )
    scanned_nodes = _nonnegative_int(
        value.get("scanned_nodes"),
        field_name="interaction_render.scanned_nodes",
    )
    bytes_inspected = _nonnegative_int(
        value.get("bytes_inspected"),
        field_name="interaction_render.bytes_inspected",
    )
    receipt_id = value.get("acquisition_receipt_id")
    if (
        status != "completed"
        or set(value) != expected
        or any(
            not isinstance(value.get(key), str)
            or pattern.fullmatch(value[key]) is None
            for key, pattern in refs.items()
        )
        or not isinstance(receipt_id, str)
        or not receipt_id.startswith("behavioral-")
        or not re_full_sha256(receipt_id[len("behavioral-") :])
        or controls_observed > 256
        or scanned_nodes > 4_096
        or bytes_inspected > 2 * 1024 * 1024
        or not isinstance(value.get("controls_truncated"), bool)
        or not isinstance(value.get("complete"), bool)
        or value.get("complete") != (not value.get("controls_truncated"))
    ):
        raise ReceiptStoreError("completed interaction render observation is invalid")
    return {
        **common,
        "status": status,
        **{key: value[key] for key in refs},
        "acquisition_receipt_id": receipt_id,
        "controls_observed": controls_observed,
        "scanned_nodes": scanned_nodes,
        "controls_truncated": value["controls_truncated"],
        "bytes_inspected": bytes_inspected,
        "complete": value["complete"],
    }


def _redacted_second_interaction_summary(value: Any) -> Dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ReceiptStoreError("second interaction transition is invalid")
    if (
        value.get("schema_version") != 1
        or value.get("mode")
        != "behavioral_interaction_second_read_transition_v1"
    ):
        raise ReceiptStoreError(
            "second interaction transition contract is invalid"
        )
    status = value.get("status")
    if status == "not_needed":
        if set(value) != {
            "schema_version",
            "mode",
            "status",
            "target_requests_sent",
            "executable",
        } or (
            value.get("target_requests_sent") != 0
            or value.get("executable") is not False
        ):
            raise ReceiptStoreError(
                "inactive second interaction transition is invalid"
            )
        return dict(value)
    if status in {"denied", "failed"}:
        error_code = value.get("error_code")
        uncertain = value.get("target_request_may_have_been_sent", False)
        target_requests_sent = value.get("target_requests_sent")
        if (
            set(value)
            != {
                "schema_version",
                "mode",
                "status",
                "error_code",
                "target_requests_sent",
                "target_request_may_have_been_sent",
                "executable",
            }
            or isinstance(target_requests_sent, bool)
            or not isinstance(target_requests_sent, int)
            or not 0 <= target_requests_sent <= 3
            or value.get("executable") is not False
            or not isinstance(error_code, str)
            or _ABORT_REASON.fullmatch(error_code) is None
            or not isinstance(uncertain, bool)
            or (status == "denied" and (target_requests_sent != 0 or uncertain))
            or (
                status == "failed"
                and target_requests_sent == 0
                and not uncertain
            )
        ):
            raise ReceiptStoreError(
                "failed second interaction transition is invalid"
            )
        return dict(value)
    parent_receipt_id = value.get("parent_receipt_id")
    parent_transition_id = value.get("parent_transition_id")
    parent_after_state_id = value.get("parent_after_state_id")
    observation_id = value.get("observation_id")
    acquisition_fields = {
        key: value.get(key)
        for key in (
            "status",
            "receipt",
            "execution",
            "target_requests_sent",
            "render_observation",
            "state_transition",
        )
        if key in value
    }
    acquisition = _redacted_interaction_acquisition_summary(
        {
            "schema_version": 1,
            "mode": "behavioral_interaction_read_acquisition_v1",
            **acquisition_fields,
        }
    )
    expected = {
        "schema_version",
        "mode",
        "status",
        "parent_receipt_id",
        "parent_transition_id",
        "parent_after_state_id",
        "observation_id",
        "receipt",
        "execution",
        "target_requests_sent",
        "render_observation",
        "state_transition",
        "executable",
    }
    if (
        status not in {"completed", "already_executed"}
        or set(value) != expected
        or not isinstance(parent_receipt_id, str)
        or not parent_receipt_id.startswith("behavioral-")
        or not re_full_sha256(parent_receipt_id[len("behavioral-") :])
        or not isinstance(parent_transition_id, str)
        or _BROWSER_TRANSITION_REF.fullmatch(parent_transition_id) is None
        or not isinstance(parent_after_state_id, str)
        or _BROWSER_STATE_REF.fullmatch(parent_after_state_id) is None
        or not isinstance(observation_id, str)
        or _INTERACTION_RENDER_REF.fullmatch(observation_id) is None
        or value.get("executable") is not False
        or acquisition.get("receipt", {}).get("receipt_id")
        == parent_receipt_id
    ):
        raise ReceiptStoreError(
            "completed second interaction transition is invalid"
        )
    return {
        "schema_version": 1,
        "mode": "behavioral_interaction_second_read_transition_v1",
        "status": status,
        "parent_receipt_id": parent_receipt_id,
        "parent_transition_id": parent_transition_id,
        "parent_after_state_id": parent_after_state_id,
        "observation_id": observation_id,
        "receipt": acquisition["receipt"],
        "execution": acquisition["execution"],
        "target_requests_sent": acquisition["target_requests_sent"],
        "render_observation": acquisition["render_observation"],
        "state_transition": acquisition["state_transition"],
        "executable": False,
    }


def _redacted_adaptive_interaction_step(value: Any) -> Dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ReceiptStoreError("adaptive interaction step is invalid")
    if (
        value.get("schema_version") != 1
        or value.get("mode") != "behavioral_interaction_adaptive_read_v1"
    ):
        raise ReceiptStoreError("adaptive interaction step contract is invalid")
    acquisition = _redacted_interaction_acquisition_summary(
        {
            "schema_version": 1,
            "mode": "behavioral_interaction_read_acquisition_v1",
            **{
                key: value.get(key)
                for key in (
                    "status",
                    "receipt",
                    "execution",
                    "target_requests_sent",
                    "render_observation",
                    "state_transition",
                )
            },
        }
    )
    expected = {
        "schema_version",
        "mode",
        "status",
        "step_index",
        "controller_id",
        "root_receipt_id",
        "root_transition_id",
        "parent_chain_ref",
        "chain_ref",
        "parent_receipt_id",
        "parent_transition_id",
        "parent_after_state_id",
        "observation_id",
        "receipt",
        "execution",
        "target_requests_sent",
        "render_observation",
        "state_transition",
        "analysis",
        "executable",
    }
    analysis = value.get("analysis")
    analysis_valid = analysis == {"status": "completed"} or (
        isinstance(analysis, Mapping)
        and set(analysis) == {"status", "error_code"}
        and analysis.get("status") == "error"
        and isinstance(analysis.get("error_code"), str)
        and _ABORT_REASON.fullmatch(analysis["error_code"]) is not None
    )
    refs = {
        "controller_id": _INTERACTION_ADAPTIVE_CONTROLLER_REF,
        "root_transition_id": _BROWSER_TRANSITION_REF,
        "parent_chain_ref": _INTERACTION_ADAPTIVE_CHAIN_REF,
        "chain_ref": _INTERACTION_ADAPTIVE_CHAIN_REF,
        "parent_transition_id": _BROWSER_TRANSITION_REF,
        "parent_after_state_id": _BROWSER_STATE_REF,
        "observation_id": _INTERACTION_RENDER_REF,
    }
    root_receipt_id = value.get("root_receipt_id")
    parent_receipt_id = value.get("parent_receipt_id")
    step_index = value.get("step_index")
    transition = acquisition.get("state_transition")
    if (
        value.get("status") not in {"completed", "already_executed"}
        or set(value) != expected
        or value.get("executable") is not False
        or not isinstance(step_index, int)
        or isinstance(step_index, bool)
        or not 2 <= step_index <= 4
        or any(
            not isinstance(value.get(key), str)
            or pattern.fullmatch(value[key]) is None
            for key, pattern in refs.items()
        )
        or not isinstance(root_receipt_id, str)
        or not isinstance(parent_receipt_id, str)
        or _BEHAVIORAL_RECEIPT_ID.fullmatch(root_receipt_id) is None
        or _BEHAVIORAL_RECEIPT_ID.fullmatch(parent_receipt_id) is None
        or not analysis_valid
        or not isinstance(transition, Mapping)
        or transition.get("status") != "completed"
    ):
        raise ReceiptStoreError("completed adaptive interaction step is invalid")
    result = transition["result"]
    child_transition = result["transition"]
    if (
        acquisition["receipt"]["receipt_id"] == parent_receipt_id
        or child_transition["receipt_id"]
        != acquisition["receipt"]["receipt_id"]
        or child_transition["before_state_id"]
        != value["parent_after_state_id"]
        or child_transition["admission_id"]
        != acquisition["execution"]["admission_id"]
        or child_transition["depth"] != step_index
        or result["transition_count"] != step_index
    ):
        raise ReceiptStoreError("adaptive interaction step binding is invalid")
    expected_chain_ref = stable_hash(
        "interaction_adaptive_chain",
        {
            "controller_id": value["controller_id"],
            "parent_chain_ref": value["parent_chain_ref"],
            "receipt_id": acquisition["receipt"]["receipt_id"],
            "transition_id": child_transition["transition_id"],
            "after_state_id": result["after_state"]["state_id"],
        },
    )
    if value["chain_ref"] != expected_chain_ref:
        raise ReceiptStoreError("adaptive interaction chain identity is invalid")
    return {
        "schema_version": 1,
        "mode": "behavioral_interaction_adaptive_read_v1",
        "status": value["status"],
        "step_index": step_index,
        **{key: value[key] for key in refs},
        "root_receipt_id": root_receipt_id,
        "parent_receipt_id": parent_receipt_id,
        "receipt": acquisition["receipt"],
        "execution": acquisition["execution"],
        "target_requests_sent": acquisition["target_requests_sent"],
        "render_observation": acquisition["render_observation"],
        "state_transition": transition,
        "analysis": dict(analysis),
        "executable": False,
    }


def _redacted_adaptive_interaction_summary(value: Any) -> Dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ReceiptStoreError("adaptive interaction chain is invalid")
    if (
        value.get("schema_version") != 1
        or value.get("mode")
        != "behavioral_interaction_adaptive_safe_read_v1"
    ):
        raise ReceiptStoreError("adaptive interaction chain contract is invalid")
    status = value.get("status")
    if status == "not_needed":
        if set(value) != {
            "schema_version",
            "mode",
            "status",
            "target_requests_sent",
            "executable",
        } or (
            value.get("target_requests_sent") != 0
            or value.get("executable") is not False
        ):
            raise ReceiptStoreError("inactive adaptive interaction is invalid")
        return dict(value)
    if status in {"denied", "failed"}:
        error_code = value.get("error_code")
        uncertain = value.get("target_request_may_have_been_sent", False)
        if (
            set(value)
            != {
                "schema_version",
                "mode",
                "status",
                "error_code",
                "target_requests_sent",
                "target_request_may_have_been_sent",
                "executable",
            }
            or value.get("target_requests_sent") != 0
            or value.get("executable") is not False
            or not isinstance(error_code, str)
            or _ABORT_REASON.fullmatch(error_code) is None
            or not isinstance(uncertain, bool)
            or uncertain != (status == "failed")
        ):
            raise ReceiptStoreError("failed adaptive interaction is invalid")
        return dict(value)
    expected = {
        "schema_version",
        "mode",
        "status",
        "controller_id",
        "root_receipt_id",
        "root_transition_id",
        "root_after_state_id",
        "root_chain_ref",
        "chain_ref",
        "limits",
        "steps",
        "target_requests_sent",
        "transition_count",
        "final_state_id",
        "stop_reasons",
        "executable",
    }
    limits = value.get("limits")
    raw_steps = value.get("steps")
    if (
        status != "completed"
        or set(value) != expected
        or value.get("executable") is not False
        or not isinstance(limits, Mapping)
        or set(limits)
        != {
            "max_states",
            "max_transitions",
            "max_depth",
            "max_operation_refs",
            "max_obligation_refs",
        }
        or any(
            isinstance(item, bool)
            or not isinstance(item, int)
            or item <= 0
            for item in limits.values()
        )
        or limits["max_states"] > 5
        or limits["max_transitions"] > 4
        or limits["max_depth"] > 4
        or limits["max_operation_refs"] > 512
        or limits["max_obligation_refs"] > 512
        or limits["max_transitions"] >= limits["max_states"]
        or not isinstance(raw_steps, Sequence)
        or isinstance(raw_steps, (str, bytes))
        or not 1 <= len(raw_steps) <= limits["max_transitions"] - 1
    ):
        raise ReceiptStoreError("completed adaptive interaction is invalid")
    steps = tuple(
        _redacted_adaptive_interaction_step(item) for item in raw_steps
    )
    step_receipts = tuple(item["receipt"]["receipt_id"] for item in steps)
    step_transitions = tuple(
        item["state_transition"]["result"]["transition"]["transition_id"]
        for item in steps
    )
    step_chain_refs = tuple(item["chain_ref"] for item in steps)
    controller_id = value.get("controller_id")
    root_receipt_id = value.get("root_receipt_id")
    root_transition_id = value.get("root_transition_id")
    root_after_state_id = value.get("root_after_state_id")
    root_chain_ref = value.get("root_chain_ref")
    chain_ref = value.get("chain_ref")
    final_state_id = value.get("final_state_id")
    stop_reasons = value.get("stop_reasons")
    final_transition = steps[-1]["state_transition"]["result"]
    if (
        not isinstance(controller_id, str)
        or _INTERACTION_ADAPTIVE_CONTROLLER_REF.fullmatch(controller_id)
        is None
        or not isinstance(root_receipt_id, str)
        or _BEHAVIORAL_RECEIPT_ID.fullmatch(root_receipt_id) is None
        or not isinstance(root_transition_id, str)
        or _BROWSER_TRANSITION_REF.fullmatch(root_transition_id) is None
        or not isinstance(root_after_state_id, str)
        or _BROWSER_STATE_REF.fullmatch(root_after_state_id) is None
        or not isinstance(root_chain_ref, str)
        or _INTERACTION_ADAPTIVE_CHAIN_REF.fullmatch(root_chain_ref) is None
        or not isinstance(chain_ref, str)
        or _INTERACTION_ADAPTIVE_CHAIN_REF.fullmatch(chain_ref) is None
        or not isinstance(final_state_id, str)
        or _BROWSER_STATE_REF.fullmatch(final_state_id) is None
        or not isinstance(stop_reasons, Sequence)
        or isinstance(stop_reasons, (str, bytes))
        or list(stop_reasons)
        != final_transition["transition"]["stop_reasons"]
        or value.get("target_requests_sent")
        != sum(item["target_requests_sent"] for item in steps)
        or value.get("transition_count") != 1 + len(steps)
        or value["transition_count"] != final_transition["transition_count"]
        or final_state_id != final_transition["after_state"]["state_id"]
        or chain_ref != steps[-1]["chain_ref"]
        or len(set(step_receipts)) != len(step_receipts)
        or len(set(step_transitions)) != len(step_transitions)
        or len(set(step_chain_refs)) != len(step_chain_refs)
        or root_receipt_id in step_receipts
        or root_transition_id in step_transitions
        or root_chain_ref in step_chain_refs
    ):
        raise ReceiptStoreError("adaptive interaction result is invalid")
    return {
        "schema_version": 1,
        "mode": "behavioral_interaction_adaptive_safe_read_v1",
        "status": "completed",
        "controller_id": controller_id,
        "root_receipt_id": root_receipt_id,
        "root_transition_id": root_transition_id,
        "root_after_state_id": root_after_state_id,
        "root_chain_ref": root_chain_ref,
        "chain_ref": chain_ref,
        "limits": dict(limits),
        "steps": list(steps),
        "target_requests_sent": value["target_requests_sent"],
        "transition_count": value["transition_count"],
        "final_state_id": final_state_id,
        "stop_reasons": list(stop_reasons),
        "executable": False,
    }


def redacted_adaptive_proof_handoff(value: Any) -> Dict[str, Any]:
    """Validate and copy the transport-free adaptive-to-proof binding."""

    from .adaptive_proof import AdaptiveProofHandoff

    if not isinstance(value, Mapping):
        raise ReceiptStoreError("adaptive proof handoff is invalid")
    try:
        return AdaptiveProofHandoff.from_dict(value).to_dict()
    except (TypeError, ValueError) as exc:
        raise ReceiptStoreError("adaptive proof handoff contract is invalid") from exc


def _attach_adaptive_proof_handoff(
    output: Dict[str, Any],
    source: Mapping[str, Any],
) -> Dict[str, Any]:
    if "adaptive_proof_handoff" in source:
        handoff = redacted_adaptive_proof_handoff(
            source.get("adaptive_proof_handoff")
        )
        plan = source.get("plan")
        if isinstance(plan, Mapping):
            plan_id = plan.get("plan_id")
            obligation_id = plan.get("selected_obligation_id")
            selected_refs = {
                "authorization_proposal": plan.get(
                    "selected_proposal_id"
                ),
                "owned_experiment": plan.get("selected_experiment_id"),
                "omission_experiment": plan.get(
                    "selected_omission_experiment_id"
                ),
            }
            selected_ref = selected_refs[handoff["resolution_kind"]]
            if (
                (plan_id is not None and plan_id != handoff["plan_id"])
                or (
                    obligation_id is not None
                    and obligation_id != handoff["obligation_id"]
                )
                or (
                    selected_ref is not None
                    and selected_ref != handoff["resolution_ref"]
                )
            ):
                raise ReceiptStoreError(
                    "adaptive proof handoff selection binding is invalid"
                )
        experiment_id = source.get("experiment_id")
        if (
            experiment_id is not None
            and handoff["resolution_kind"] == "omission_experiment"
            and experiment_id != handoff["resolution_ref"]
        ):
            raise ReceiptStoreError(
                "adaptive proof handoff experiment binding is invalid"
            )
        output["adaptive_proof_handoff"] = handoff
    return output


def _redacted_interaction_acquisition_summary(value: Any) -> Dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ReceiptStoreError("interaction acquisition summary is invalid")
    if (
        value.get("schema_version") != 1
        or value.get("mode") != "behavioral_interaction_read_acquisition_v1"
    ):
        raise ReceiptStoreError("interaction acquisition summary contract is invalid")
    status = value.get("status")
    requests_sent = _nonnegative_int(
        value.get("target_requests_sent"),
        field_name="interaction_acquisition.target_requests_sent",
    )
    if status in {"disabled", "not_needed"}:
        if requests_sent != 0:
            raise ReceiptStoreError("inactive interaction acquisition sent traffic")
        return {
            "schema_version": 1,
            "mode": "behavioral_interaction_read_acquisition_v1",
            "status": status,
            "target_requests_sent": 0,
        }
    if status in {"denied", "failed"}:
        error_code = value.get("error_code")
        request_uncertain = value.get(
            "target_request_may_have_been_sent",
            False,
        )
        if (
            requests_sent != 0
            or not isinstance(error_code, str)
            or _ABORT_REASON.fullmatch(error_code) is None
            or not isinstance(request_uncertain, bool)
            or request_uncertain != (status == "failed")
        ):
            raise ReceiptStoreError("failed interaction acquisition is invalid")
        return {
            "schema_version": 1,
            "mode": "behavioral_interaction_read_acquisition_v1",
            "status": status,
            "error_code": error_code,
            "target_requests_sent": 0,
            "target_request_may_have_been_sent": request_uncertain,
        }
    if status not in {"completed", "already_executed"}:
        raise ReceiptStoreError("interaction acquisition summary status is invalid")
    receipt = value.get("receipt")
    execution = value.get("execution")
    if (
        not isinstance(receipt, Mapping)
        or set(receipt) != {"receipt_id", "state", "reused"}
        or receipt.get("state") != COMPLETED
        or not isinstance(receipt.get("receipt_id"), str)
        or not receipt["receipt_id"].startswith("behavioral-")
        or not re_full_sha256(receipt["receipt_id"][len("behavioral-") :])
        or receipt.get("reused") != (status == "already_executed")
        or requests_sent != (0 if status == "already_executed" else 1)
        or not isinstance(execution, Mapping)
    ):
        raise ReceiptStoreError("interaction acquisition receipt summary is invalid")
    output = {
        "schema_version": 1,
        "mode": "behavioral_interaction_read_acquisition_v1",
        "status": status,
        "receipt": dict(receipt),
        "execution": redacted_interaction_acquisition_outcome(execution),
        "target_requests_sent": requests_sent,
    }
    if "state_transition" in value:
        transition_summary = _redacted_browser_transition_summary(
            value.get("state_transition")
        )
        if transition_summary["status"] == "completed":
            transition = transition_summary["result"]["transition"]
            redacted_execution = output["execution"]
            if (
                transition["receipt_id"] != receipt["receipt_id"]
                or transition["admission_id"]
                != redacted_execution["admission_id"]
                or transition["obligation_id"]
                != redacted_execution["obligation_id"]
                or transition["acquisition_id"]
                != redacted_execution["acquisition_id"]
                or transition["request_ref"]
                != redacted_execution["request_ref"]
                or transition["response_ref"]
                != redacted_execution["response_ref"]
            ):
                raise ReceiptStoreError(
                    "browser state transition acquisition binding is invalid"
                )
        output["state_transition"] = transition_summary
    if "render_observation" in value:
        render_summary = _redacted_interaction_render_summary(
            value.get("render_observation")
        )
        if render_summary["status"] == "completed":
            redacted_execution = output["execution"]
            if (
                render_summary["acquisition_receipt_id"]
                != receipt["receipt_id"]
                or render_summary["acquisition_id"]
                != redacted_execution["acquisition_id"]
                or render_summary["admission_id"]
                != redacted_execution["admission_id"]
                or render_summary["obligation_id"]
                != redacted_execution["obligation_id"]
                or render_summary["response_ref"]
                != redacted_execution["response_ref"]
                or render_summary["page_ref"]
                != redacted_execution["destination_page_ref"]
            ):
                raise ReceiptStoreError(
                    "interaction render acquisition binding is invalid"
                )
            transition = output.get("state_transition")
            if (
                render_summary["complete"]
                and (
                    not isinstance(transition, Mapping)
                    or transition.get("status") != "completed"
                    or render_summary["page_ref"]
                    != transition["result"]["after_state"]["page_ref"]
                    or render_summary["catalog_id"]
                    != transition["result"]["after_state"][
                        "interaction_catalog_id"
                    ]
                )
            ):
                raise ReceiptStoreError(
                    "interaction render state binding is invalid"
                )
        output["render_observation"] = render_summary
    if "second_transition" in value:
        second = _redacted_second_interaction_summary(
            value.get("second_transition")
        )
        if second["status"] in {"completed", "already_executed"}:
            parent = output.get("state_transition")
            if (
                not isinstance(parent, Mapping)
                or parent.get("status") != "completed"
            ):
                raise ReceiptStoreError(
                    "second interaction parent transition is unavailable"
                )
            parent_result = parent["result"]
            parent_transition = parent_result["transition"]
            if (
                second["parent_receipt_id"] != receipt["receipt_id"]
                or second["parent_transition_id"]
                != parent_transition["transition_id"]
                or second["parent_after_state_id"]
                != parent_result["after_state"]["state_id"]
                or second["observation_id"]
                != output.get("render_observation", {}).get(
                    "observation_id"
                )
                or second["execution"]["admission_id"]
                != parent_transition["next_admission_id"]
            ):
                raise ReceiptStoreError(
                    "second interaction parent binding is invalid"
                )
            child_transition = second["state_transition"]
            if (
                child_transition["status"] == "completed"
                and child_transition["result"]["before_state"]["state_id"]
                != parent_result["after_state"]["state_id"]
            ):
                raise ReceiptStoreError(
                    "second interaction state binding is invalid"
                )
        output["second_transition"] = second
    if "adaptive_chain" in value:
        if "second_transition" in value:
            raise ReceiptStoreError(
                "fixed and adaptive interaction continuations are mutually exclusive"
            )
        adaptive = _redacted_adaptive_interaction_summary(
            value.get("adaptive_chain")
        )
        if adaptive["status"] == "completed":
            parent = output.get("state_transition")
            root_observation = output.get("render_observation")
            if (
                not isinstance(parent, Mapping)
                or parent.get("status") != "completed"
                or not isinstance(root_observation, Mapping)
                or root_observation.get("status") != "completed"
                or not root_observation.get("complete")
            ):
                raise ReceiptStoreError(
                    "adaptive interaction root evidence is unavailable"
                )
            parent_result = parent["result"]
            parent_transition = parent_result["transition"]
            parent_after = parent_result["after_state"]
            expected_controller_id = stable_hash(
                "interaction_adaptive_controller",
                {
                    "root_receipt_id": receipt["receipt_id"],
                    "root_transition_id": parent_transition["transition_id"],
                    "root_after_state_id": parent_after["state_id"],
                    "target_ref": parent_after["target_ref"],
                    "world_ref": parent_after["world_ref"],
                    "limits": adaptive["limits"],
                },
            )
            expected_root_chain_ref = stable_hash(
                "interaction_adaptive_chain",
                {
                    "controller_id": expected_controller_id,
                    "receipt_id": receipt["receipt_id"],
                    "transition_id": parent_transition["transition_id"],
                    "after_state_id": parent_after["state_id"],
                },
            )
            if (
                adaptive["controller_id"] != expected_controller_id
                or adaptive["root_receipt_id"] != receipt["receipt_id"]
                or adaptive["root_transition_id"]
                != parent_transition["transition_id"]
                or adaptive["root_after_state_id"] != parent_after["state_id"]
                or adaptive["root_chain_ref"] != expected_root_chain_ref
            ):
                raise ReceiptStoreError(
                    "adaptive interaction root binding is invalid"
                )
            expected_parent_receipt = receipt["receipt_id"]
            expected_parent_transition = parent_transition
            expected_parent_after = parent_after
            expected_observation_id = root_observation["observation_id"]
            expected_parent_chain_ref = expected_root_chain_ref
            for index, step in enumerate(adaptive["steps"], start=2):
                if (
                    step["step_index"] != index
                    or step["controller_id"] != expected_controller_id
                    or step["root_receipt_id"] != receipt["receipt_id"]
                    or step["root_transition_id"]
                    != parent_transition["transition_id"]
                    or step["parent_chain_ref"]
                    != expected_parent_chain_ref
                    or step["parent_receipt_id"] != expected_parent_receipt
                    or step["parent_transition_id"]
                    != expected_parent_transition["transition_id"]
                    or step["parent_after_state_id"]
                    != expected_parent_after["state_id"]
                    or step["observation_id"] != expected_observation_id
                    or step["execution"]["admission_id"]
                    != expected_parent_transition["next_admission_id"]
                    or expected_parent_transition["decision"]
                    != "eligible_for_next_transition"
                ):
                    raise ReceiptStoreError(
                        "adaptive interaction parent chain is invalid"
                    )
                child_result = step["state_transition"]["result"]
                expected_parent_receipt = step["receipt"]["receipt_id"]
                expected_parent_transition = child_result["transition"]
                expected_parent_after = child_result["after_state"]
                expected_parent_chain_ref = step["chain_ref"]
                child_observation = step["render_observation"]
                expected_observation_id = child_observation.get(
                    "observation_id"
                )
                if (
                    index < 1 + len(adaptive["steps"])
                    and (
                        child_observation.get("status") != "completed"
                        or not child_observation.get("complete")
                        or not isinstance(expected_observation_id, str)
                    )
                ):
                    raise ReceiptStoreError(
                        "adaptive interaction continuation evidence is unavailable"
                    )
            if expected_parent_transition["decision"] != "stop":
                raise ReceiptStoreError(
                    "adaptive interaction chain did not terminate"
                )
        output["adaptive_chain"] = adaptive
    return output


def redacted_compiled_outcome(value: Mapping[str, Any]) -> Dict[str, Any]:
    """Return the only compiled-runtime fields permitted in a durable receipt."""

    sequence_id = value.get("sequence_id")
    status = value.get("status")
    if (
        not isinstance(sequence_id, str)
        or _COMPILED_SEQUENCE_REF.fullmatch(sequence_id) is None
    ):
        raise ReceiptStoreError("compiled receipt sequence identity is invalid")
    if status not in _VALID_COMPILED_STATUSES:
        raise ReceiptStoreError("compiled receipt status is invalid")
    counters = {
        key: _nonnegative_int(value.get(key), field_name=f"compiled.{key}")
        for key in (
            "main_steps_attempted",
            "main_steps_completed",
            "cleanup_steps_attempted",
            "cleanup_steps_completed",
            "policy_denials",
            "runtime_values_bound",
        )
    }
    if (
        counters["main_steps_completed"] > counters["main_steps_attempted"]
        or counters["cleanup_steps_completed"]
        > counters["cleanup_steps_attempted"]
    ):
        raise ReceiptStoreError("compiled receipt counters are inconsistent")
    orphaned = value.get("orphaned_owned_state_possible")
    if not isinstance(orphaned, bool):
        raise ReceiptStoreError("compiled receipt orphan state is invalid")
    provenance_root = value.get("provenance_root")
    if not isinstance(provenance_root, str) or not re_full_sha256(provenance_root):
        raise ReceiptStoreError("compiled receipt provenance root is invalid")
    budget = _count_section(
        value.get("budget_snapshot"),
        (
            "total_requests",
            "cross_object_reads",
            "privilege_mutations",
            "creates",
            "endpoints_touched",
        ),
        section="compiled.budget_snapshot",
    )
    attempted = (
        counters["main_steps_attempted"] + counters["cleanup_steps_attempted"]
    )
    if (
        budget["total_requests"] > attempted
        or budget["cross_object_reads"] > budget["total_requests"]
        or budget["privilege_mutations"] > budget["total_requests"]
        or budget["creates"] > budget["total_requests"]
        or budget["endpoints_touched"] > budget["total_requests"]
    ):
        raise ReceiptStoreError("compiled receipt budget is inconsistent")
    error_code = value.get("error_code")
    if error_code is not None and error_code not in _COMPILED_ERROR_CODES:
        raise ReceiptStoreError("compiled receipt error code is invalid")
    if status == "completed":
        if (
            error_code is not None
            or orphaned
            or counters["main_steps_attempted"]
            != counters["main_steps_completed"]
            or counters["cleanup_steps_attempted"]
            != counters["cleanup_steps_completed"]
        ):
            raise ReceiptStoreError("compiled completed receipt is inconsistent")
    elif error_code is None:
        raise ReceiptStoreError("compiled unsuccessful receipt requires an error code")
    if status == "cleanup_failed" and (
        not orphaned
        or counters["cleanup_steps_attempted"]
        == counters["cleanup_steps_completed"]
    ):
        raise ReceiptStoreError("compiled cleanup failure receipt is inconsistent")
    return {
        "kind": "compiled_sequence",
        "sequence_id": sequence_id,
        "status": status,
        **counters,
        "orphaned_owned_state_possible": orphaned,
        "provenance_root": provenance_root,
        "budget_snapshot": budget,
        "error_code": error_code,
    }


def redacted_fresh_owned_boundary_outcome(
    response: Mapping[str, Any],
) -> Dict[str, Any]:
    """Return the bounded fresh-state proof fields permitted in a receipt."""

    status = response.get("status")
    if status not in {"completed", "aborted", "cleanup_failed"}:
        raise ReceiptStoreError("fresh boundary receipt status is invalid")
    selected_experiment = _selected_experiment(response.get("plan"))
    selected_obligation = _selected_obligation(response.get("plan"))
    if (
        selected_experiment is None
        or selected_obligation is None
        or _selected_proposal(response.get("plan")) is not None
    ):
        raise ReceiptStoreError("fresh boundary receipt selection is invalid")
    execution = response.get("execution")
    if not isinstance(execution, Mapping) or execution.get("kind") != (
        "fresh_owned_boundary"
    ):
        raise ReceiptStoreError("fresh boundary receipt execution is invalid")
    refs = {
        "boundary_id": (execution.get("boundary_id"), _FRESH_BOUNDARY_REF),
        "experiment_id": (execution.get("experiment_id"), _OWNED_EXPERIMENT_REF),
        "lifecycle_id": (execution.get("lifecycle_id"), _OWNED_LIFECYCLE_REF),
        "terminal_operation_id": (
            execution.get("terminal_operation_id"),
            _ACTION_REF,
        ),
        "peer_experiment_id": (
            execution.get("peer_experiment_id"),
            _OWNED_EXPERIMENT_REF,
        ),
    }
    if any(
        not isinstance(value, str) or pattern.fullmatch(value) is None
        for value, pattern in refs.values()
    ) or execution.get("experiment_id") != selected_experiment:
        raise ReceiptStoreError("fresh boundary receipt identity is invalid")
    verdict = execution.get("legacy_verdict")
    if verdict not in _VALID_LEGACY_VERDICTS:
        raise ReceiptStoreError("fresh boundary receipt verdict is invalid")
    finding_confirmed = response.get("finding_confirmed")
    if not isinstance(finding_confirmed, bool):
        finding_confirmed = bool(response.get("finding"))
    execution_finding = execution.get("finding_confirmed")
    if not isinstance(execution_finding, bool) or (
        execution_finding != finding_confirmed
        or (verdict == "BOLA_CONFIRMED") != finding_confirmed
    ):
        raise ReceiptStoreError("fresh boundary finding state is inconsistent")
    counters = {
        key: _nonnegative_int(execution.get(key), field_name=f"fresh_boundary.{key}")
        for key in (
            "requests_attempted",
            "requests_sent",
            "creates_attempted",
            "creates_completed",
            "proof_legs_attempted",
            "proof_legs_sent",
            "cleanup_steps_attempted",
            "cleanup_steps_completed",
            "policy_denials",
        )
    }
    if (
        counters["requests_sent"] > counters["requests_attempted"]
        or counters["requests_attempted"]
        != counters["creates_attempted"]
        + counters["proof_legs_attempted"]
        + counters["cleanup_steps_attempted"]
        or counters["creates_completed"] > counters["creates_attempted"]
        or counters["creates_attempted"] > 2
        or counters["proof_legs_sent"] > counters["proof_legs_attempted"]
        or counters["proof_legs_attempted"] > 3
        or counters["cleanup_steps_completed"]
        > counters["cleanup_steps_attempted"]
        or counters["cleanup_steps_attempted"] > 2
    ):
        raise ReceiptStoreError("fresh boundary receipt counters are inconsistent")
    orphaned = execution.get("orphaned_owned_state_possible")
    if not isinstance(orphaned, bool):
        raise ReceiptStoreError("fresh boundary orphan state is invalid")
    error_code = execution.get("error_code")
    if error_code is not None and error_code not in _FRESH_BOUNDARY_ERROR_CODES:
        raise ReceiptStoreError("fresh boundary error code is invalid")
    if status == "completed" and (
        error_code is not None
        or orphaned
        or counters["creates_completed"] != 2
        or counters["cleanup_steps_completed"] != 2
    ):
        raise ReceiptStoreError("fresh boundary completed state is inconsistent")
    if status == "aborted" and error_code is None:
        raise ReceiptStoreError("fresh boundary aborted state requires an error")
    if status == "cleanup_failed" and (
        error_code != "fresh_boundary_cleanup_failed" or not orphaned
    ):
        raise ReceiptStoreError("fresh boundary cleanup failure is inconsistent")
    provenance_root = execution.get("provenance_root")
    if not isinstance(provenance_root, str) or not re_full_sha256(provenance_root):
        raise ReceiptStoreError("fresh boundary provenance root is invalid")
    budget = _count_section(
        execution.get("budget_snapshot"),
        (
            "total_requests",
            "cross_object_reads",
            "privilege_mutations",
            "creates",
            "endpoints_touched",
        ),
        section="fresh_boundary.budget_snapshot",
    )
    if (
        budget["total_requests"] > counters["requests_attempted"]
        or budget["cross_object_reads"] > 1
        or budget["privilege_mutations"] != 0
        or budget["creates"] > 2
        or budget["endpoints_touched"] > budget["total_requests"]
    ):
        raise ReceiptStoreError("fresh boundary budget is inconsistent")
    output = {
        "kind": "fresh_owned_boundary",
        "status": status,
        "plan": {
            "selected_proposal_id": None,
            "selected_experiment_id": selected_experiment,
            "selected_obligation_id": selected_obligation,
        },
        "execution": {
            "kind": "fresh_owned_boundary",
            **{key: value for key, (value, _pattern) in refs.items()},
            "status": status,
            "legacy_verdict": verdict,
            "finding_confirmed": finding_confirmed,
            **counters,
            "orphaned_owned_state_possible": orphaned,
            "provenance_root": provenance_root,
            "budget_snapshot": budget,
            "error_code": error_code,
        },
        "finding": None,
        "finding_confirmed": finding_confirmed,
        "graphql_resolution": _redacted_graphql_diagnostics(
            response.get("graphql_resolution")
        ),
    }
    if "read_exploration" in response:
        output["read_exploration"] = _redacted_read_exploration(
            response.get("read_exploration")
        )
    if "interaction_acquisition" in response:
        output["interaction_acquisition"] = (
            _redacted_interaction_acquisition_summary(
                response.get("interaction_acquisition")
            )
        )
    return _attach_adaptive_proof_handoff(output, response)


def redacted_fresh_omission_outcome(
    value: Mapping[str, Any],
) -> Dict[str, Any]:
    """Return the evidence-only fresh omission fields permitted in a receipt."""

    refs = {
        "boundary_id": (
            value.get("boundary_id"),
            _FRESH_OMISSION_BOUNDARY_REF,
        ),
        "experiment_id": (
            value.get("experiment_id"),
            _OMISSION_EXPERIMENT_REF,
        ),
        "lifecycle_id": (
            value.get("lifecycle_id"),
            _OWNED_LIFECYCLE_REF,
        ),
        "terminal_operation_id": (
            value.get("terminal_operation_id"),
            _ACTION_REF,
        ),
    }
    if any(
        not isinstance(item, str) or pattern.fullmatch(item) is None
        for item, pattern in refs.values()
    ):
        raise ReceiptStoreError("fresh omission receipt identity is invalid")
    status = value.get("status")
    comparison = value.get("comparison_status")
    if (
        status not in _VALID_COMPILED_STATUSES
        or comparison not in _FRESH_OMISSION_COMPARISONS
        or value.get("finding_authority") is not False
        or value.get("finding") is not None
    ):
        raise ReceiptStoreError("fresh omission receipt outcome is invalid")
    evidence_fields = (
        "baseline_reference_match",
        "baseline_terminal_success",
        "omission_terminal_success",
        "baseline_terminal_truncated",
        "omission_terminal_truncated",
        "terminal_body_match",
    )
    evidence = {}
    for field_name in evidence_fields:
        field_value = value.get(field_name)
        if not isinstance(field_value, bool):
            raise ReceiptStoreError(f"fresh omission receipt {field_name} is invalid")
        evidence[field_name] = field_value
    counters = {
        key: _nonnegative_int(
            value.get(key),
            field_name=f"fresh_omission.{key}",
        )
        for key in (
            "requests_attempted",
            "requests_sent",
            "baseline_steps_attempted",
            "baseline_steps_completed",
            "omission_steps_attempted",
            "omission_steps_completed",
            "creates_attempted",
            "creates_completed",
            "cleanup_steps_attempted",
            "cleanup_steps_completed",
            "policy_denials",
        )
    }
    if (
        counters["requests_sent"] > counters["requests_attempted"]
        or counters["requests_attempted"]
        != counters["baseline_steps_attempted"]
        + counters["omission_steps_attempted"]
        + counters["cleanup_steps_attempted"]
        or counters["baseline_steps_completed"] > counters["baseline_steps_attempted"]
        or counters["omission_steps_completed"] > counters["omission_steps_attempted"]
        or counters["creates_completed"] > counters["creates_attempted"]
        or counters["creates_attempted"] > 2
        or counters["cleanup_steps_completed"] > counters["cleanup_steps_attempted"]
        or counters["cleanup_steps_attempted"] > 2
    ):
        raise ReceiptStoreError("fresh omission receipt counters are inconsistent")
    orphaned = value.get("orphaned_owned_state_possible")
    if not isinstance(orphaned, bool):
        raise ReceiptStoreError("fresh omission orphan state is invalid")
    error_code = value.get("error_code")
    if error_code is not None and error_code not in _FRESH_OMISSION_ERROR_CODES:
        raise ReceiptStoreError("fresh omission receipt error code is invalid")
    if status == "completed" and (
        error_code is not None
        or orphaned
        or not evidence["baseline_reference_match"]
        or counters["creates_completed"] != 2
        or counters["cleanup_steps_completed"] != 2
        or comparison == "not_completed"
    ):
        raise ReceiptStoreError("fresh omission completed state is inconsistent")
    if status == "aborted" and error_code is None:
        raise ReceiptStoreError("fresh omission aborted state requires an error")
    if status == "cleanup_failed" and (
        error_code != "fresh_omission_cleanup_failed"
        or not orphaned
        or counters["cleanup_steps_completed"] == counters["cleanup_steps_attempted"]
    ):
        raise ReceiptStoreError("fresh omission cleanup failure is inconsistent")
    if comparison == "exact_match" and (
        not evidence["baseline_reference_match"]
        or not evidence["baseline_terminal_success"]
        or not evidence["omission_terminal_success"]
        or evidence["baseline_terminal_truncated"]
        or evidence["omission_terminal_truncated"]
        or not evidence["terminal_body_match"]
    ):
        raise ReceiptStoreError("fresh omission exact comparison is inconsistent")
    provenance_root = value.get("provenance_root")
    if not isinstance(provenance_root, str) or not re_full_sha256(provenance_root):
        raise ReceiptStoreError("fresh omission provenance root is invalid")
    budget = _count_section(
        value.get("budget_snapshot"),
        (
            "total_requests",
            "cross_object_reads",
            "privilege_mutations",
            "creates",
            "endpoints_touched",
        ),
        section="fresh_omission.budget_snapshot",
    )
    if (
        budget["total_requests"] != counters["requests_sent"]
        or budget["cross_object_reads"] != 0
        or budget["privilege_mutations"] != 0
        or budget["creates"] > 2
        or budget["endpoints_touched"] > budget["total_requests"]
    ):
        raise ReceiptStoreError("fresh omission receipt budget is inconsistent")
    return {
        "kind": "fresh_omission_boundary",
        **{key: item for key, (item, _pattern) in refs.items()},
        "status": status,
        "comparison_status": comparison,
        **evidence,
        **counters,
        "orphaned_owned_state_possible": orphaned,
        "provenance_root": provenance_root,
        "budget_snapshot": budget,
        "error_code": error_code,
        "finding_authority": False,
        "finding": None,
    }


def redacted_fresh_omission_confirmation_outcome(
    value: Mapping[str, Any],
) -> Dict[str, Any]:
    """Return only bounded proof facts from a capability-binding confirmation."""

    refs = {
        "confirmation_id": (
            value.get("confirmation_id"),
            _FRESH_OMISSION_CONFIRMATION_REF,
        ),
        "experiment_id": (
            value.get("experiment_id"),
            _OMISSION_EXPERIMENT_REF,
        ),
        "lifecycle_id": (
            value.get("lifecycle_id"),
            _OWNED_LIFECYCLE_REF,
        ),
        "terminal_operation_id": (
            value.get("terminal_operation_id"),
            _ACTION_REF,
        ),
    }
    if any(
        not isinstance(item, str) or pattern.fullmatch(item) is None
        for item, pattern in refs.values()
    ):
        raise ReceiptStoreError(
            "fresh omission confirmation identity is invalid"
        )
    status = value.get("status")
    confirmation = value.get("confirmation_status")
    finding_authority = value.get("finding_authority")
    if (
        status not in _VALID_COMPILED_STATUSES
        or confirmation not in _FRESH_OMISSION_CONFIRMATION_STATUSES
        or not isinstance(finding_authority, bool)
    ):
        raise ReceiptStoreError(
            "fresh omission confirmation outcome is invalid"
        )

    evidence_fields = (
        "baseline_reference_match",
        "baseline_terminal_success",
        "omission_terminal_success",
        "control_terminal_success",
        "baseline_terminal_truncated",
        "omission_terminal_truncated",
        "control_terminal_truncated",
        "terminal_body_match",
        "capability_object_binding_proven",
    )
    evidence: Dict[str, bool] = {}
    for field_name in evidence_fields:
        field_value = value.get(field_name)
        if not isinstance(field_value, bool):
            raise ReceiptStoreError(
                f"fresh omission confirmation {field_name} is invalid"
            )
        evidence[field_name] = field_value

    control_status = value.get("control_response_status")
    if control_status is not None and (
        isinstance(control_status, bool)
        or not isinstance(control_status, int)
        or not 100 <= control_status <= 599
    ):
        raise ReceiptStoreError(
            "fresh omission confirmation control status is invalid"
        )
    counters = {
        key: _nonnegative_int(
            value.get(key),
            field_name=f"fresh_omission_confirmation.{key}",
        )
        for key in (
            "requests_attempted",
            "requests_sent",
            "baseline_steps_attempted",
            "baseline_steps_completed",
            "omission_steps_attempted",
            "omission_steps_completed",
            "control_steps_attempted",
            "control_steps_completed",
            "creates_attempted",
            "creates_completed",
            "cleanup_steps_attempted",
            "cleanup_steps_completed",
            "policy_denials",
        )
    }
    if (
        counters["requests_sent"] > counters["requests_attempted"]
        or counters["requests_attempted"]
        != counters["baseline_steps_attempted"]
        + counters["omission_steps_attempted"]
        + counters["control_steps_attempted"]
        + counters["cleanup_steps_attempted"]
        or counters["baseline_steps_completed"]
        > counters["baseline_steps_attempted"]
        or counters["omission_steps_completed"]
        > counters["omission_steps_attempted"]
        or counters["control_steps_completed"]
        > counters["control_steps_attempted"]
        or counters["creates_completed"] > counters["creates_attempted"]
        or counters["creates_attempted"] > 3
        or counters["cleanup_steps_completed"]
        > counters["cleanup_steps_attempted"]
        or counters["cleanup_steps_attempted"] > 3
    ):
        raise ReceiptStoreError(
            "fresh omission confirmation counters are inconsistent"
        )
    orphaned = value.get("orphaned_owned_state_possible")
    if not isinstance(orphaned, bool):
        raise ReceiptStoreError(
            "fresh omission confirmation orphan state is invalid"
        )
    error_code = value.get("error_code")
    if (
        error_code is not None
        and error_code not in _FRESH_OMISSION_CONFIRMATION_ERROR_CODES
    ):
        raise ReceiptStoreError(
            "fresh omission confirmation error code is invalid"
        )

    finding_ref = value.get("finding_ref")
    finding = value.get("finding")
    if finding_authority:
        if isinstance(finding, Mapping):
            finding_ref = finding.get("finding_id")
            if (
                finding.get("confirmation_id") != refs["confirmation_id"][0]
                or finding.get("experiment_id") != refs["experiment_id"][0]
                or finding.get("lifecycle_id") != refs["lifecycle_id"][0]
                or finding.get("terminal_operation_id")
                != refs["terminal_operation_id"][0]
                or finding.get("finding_authority") is not True
                or finding.get("proof_kind")
                != "known_valid_wrong_object_capability_rejected"
            ):
                raise ReceiptStoreError(
                    "fresh omission confirmation finding binding is invalid"
                )
        if (
            not isinstance(finding_ref, str)
            or _OMISSION_CAPABILITY_FINDING_REF.fullmatch(finding_ref) is None
        ):
            raise ReceiptStoreError(
                "fresh omission confirmation finding reference is invalid"
            )
    elif finding is not None or finding_ref is not None:
        raise ReceiptStoreError(
            "unconfirmed omission receipt cannot contain a finding"
        )

    if status == "completed" and (
        error_code is not None
        or orphaned
        or not evidence["baseline_reference_match"]
        or counters["creates_completed"] < 2
        or counters["cleanup_steps_completed"] != counters["creates_completed"]
        or confirmation == "not_completed"
    ):
        raise ReceiptStoreError(
            "completed omission confirmation is inconsistent"
        )
    if status == "aborted" and error_code is None:
        raise ReceiptStoreError(
            "aborted omission confirmation requires an error"
        )
    if status == "cleanup_failed" and (
        error_code != "fresh_omission_confirmation_cleanup_failed"
        or not orphaned
        or finding_authority
    ):
        raise ReceiptStoreError(
            "omission confirmation cleanup failure is inconsistent"
        )
    if confirmation == "confirmed_fail_open" and (
        status != "completed"
        or not evidence["baseline_reference_match"]
        or not evidence["baseline_terminal_success"]
        or not evidence["omission_terminal_success"]
        or evidence["control_terminal_success"]
        or evidence["baseline_terminal_truncated"]
        or evidence["omission_terminal_truncated"]
        or evidence["control_terminal_truncated"]
        or not evidence["terminal_body_match"]
        or not evidence["capability_object_binding_proven"]
        or control_status not in {400, 401, 403, 422}
        or counters["creates_completed"] != 3
        or counters["cleanup_steps_completed"] != 3
        or not finding_authority
    ):
        raise ReceiptStoreError(
            "confirmed omission receipt is inconsistent"
        )
    if confirmation != "confirmed_fail_open" and (
        evidence["capability_object_binding_proven"] or finding_authority
    ):
        raise ReceiptStoreError(
            "unconfirmed omission receipt has finding authority"
        )

    provenance_root = value.get("provenance_root")
    if (
        not isinstance(provenance_root, str)
        or not re_full_sha256(provenance_root)
    ):
        raise ReceiptStoreError(
            "fresh omission confirmation provenance root is invalid"
        )
    budget = _count_section(
        value.get("budget_snapshot"),
        (
            "total_requests",
            "cross_object_reads",
            "privilege_mutations",
            "creates",
            "endpoints_touched",
        ),
        section="fresh_omission_confirmation.budget_snapshot",
    )
    if (
        budget["total_requests"] != counters["requests_sent"]
        or budget["cross_object_reads"] != 0
        or budget["privilege_mutations"] != 0
        or budget["creates"] > 3
        or budget["endpoints_touched"] > budget["total_requests"]
    ):
        raise ReceiptStoreError(
            "fresh omission confirmation budget is inconsistent"
        )
    output = {
        "kind": "fresh_omission_confirmation",
        **{key: item for key, (item, _pattern) in refs.items()},
        "status": status,
        "confirmation_status": confirmation,
        **evidence,
        "control_response_status": control_status,
        **counters,
        "orphaned_owned_state_possible": orphaned,
        "provenance_root": provenance_root,
        "budget_snapshot": budget,
        "error_code": error_code,
        "finding_authority": finding_authority,
        "finding_ref": finding_ref,
        "finding": None,
    }
    return _attach_adaptive_proof_handoff(output, value)


def redacted_continuation_outcome(response: Mapping[str, Any]) -> Dict[str, Any]:
    """Return a redacted final outcome plus its bounded round transcript."""

    from .continuation import (
        BOUNDED_CONTINUATION_MODE,
        BoundedContinuationResult,
        ContinuationRound,
    )

    raw = response.get("continuation")
    if not isinstance(raw, Mapping):
        raise ReceiptStoreError("behavioral continuation summary is invalid")
    required = {
        "schema_version",
        "session_id",
        "mode",
        "root_fingerprint",
        "initial_shadow_id",
        "final_shadow_id",
        "final_closure_id",
        "rounds",
        "stop_reason",
        "total_requests_attempted",
        "total_requests_sent",
        "max_rounds",
        "max_proof_requests",
        "executable",
    }
    if set(raw) != required or raw.get("schema_version") != 1:
        raise ReceiptStoreError("behavioral continuation fields are invalid")
    raw_rounds = raw.get("rounds")
    if not isinstance(raw_rounds, list):
        raise ReceiptStoreError("behavioral continuation rounds are invalid")
    round_fields = set(ContinuationRound.__dataclass_fields__)
    rounds = []
    try:
        for item in raw_rounds:
            if not isinstance(item, Mapping) or set(item) != round_fields:
                raise ReceiptStoreError("behavioral continuation round fields are invalid")
            rounds.append(ContinuationRound(**dict(item)))
        continuation = BoundedContinuationResult(
            session_id=raw.get("session_id"),
            root_fingerprint=raw.get("root_fingerprint"),
            initial_shadow_id=raw.get("initial_shadow_id"),
            final_shadow_id=raw.get("final_shadow_id"),
            final_closure_id=raw.get("final_closure_id"),
            rounds=tuple(rounds),
            stop_reason=raw.get("stop_reason"),
            total_requests_attempted=raw.get("total_requests_attempted"),
            total_requests_sent=raw.get("total_requests_sent"),
            max_rounds=raw.get("max_rounds"),
            max_proof_requests=raw.get("max_proof_requests"),
            mode=raw.get("mode"),
            executable=raw.get("executable"),
        )
    except (TypeError, ValueError) as exc:
        raise ReceiptStoreError("behavioral continuation contract is invalid") from exc
    if continuation.mode != BOUNDED_CONTINUATION_MODE:
        raise ReceiptStoreError("behavioral continuation mode is invalid")
    final_response = dict(response)
    final_response.pop("continuation", None)
    final_response.pop("kind", None)
    output = redacted_outcome(final_response)
    output["kind"] = "bounded_continuation"
    output["continuation"] = continuation.to_dict()
    return output


def redacted_proof_experiment_authorization_outcome(
    value: Mapping[str, Any],
) -> Dict[str, Any]:
    """Validate the content-addressed, non-promoting R4C authorization summary."""

    if value.get("kind") != "proof_experiment_authorization":
        raise ReceiptStoreError("proof experiment authorization kind is invalid")
    status = value.get("status")
    oracle_verdict = value.get("oracle_verdict")
    legacy_verdict = value.get("legacy_verdict")
    if (
        status not in {"completed", "aborted"}
        or oracle_verdict not in {"confirmed", "refuted", "inconclusive"}
        or legacy_verdict not in _VALID_LEGACY_VERDICTS
    ):
        raise ReceiptStoreError(
            "proof experiment authorization verdict is invalid"
        )

    exact_refs = (
        (value.get("manifest_id"), _PROOF_EXPERIMENT_MANIFEST_REF),
        (value.get("admission_id"), _PROOF_EXPERIMENT_ADMISSION_REF),
        (value.get("evaluation_id"), _PROOF_EXPERIMENT_EVALUATION_REF),
        (value.get("oracle_id"), _PROOF_EXPERIMENT_ORACLE_REF),
        (value.get("backend_receipt_ref"), _BEHAVIORAL_RECEIPT_REF),
        (value.get("provenance_root"), _PROVENANCE_REF),
    )
    if any(
        not isinstance(item, str) or pattern.fullmatch(item) is None
        for item, pattern in exact_refs
    ):
        raise ReceiptStoreError(
            "proof experiment authorization reference is invalid"
        )

    def evidence_refs(field_name: str) -> tuple[str, ...]:
        raw = value.get(field_name)
        if not isinstance(raw, (list, tuple)) or any(
            not isinstance(item, str)
            or _PROOF_EXPERIMENT_ACTION_EVIDENCE_REF.fullmatch(item) is None
            for item in raw
        ):
            raise ReceiptStoreError(
                "proof experiment authorization evidence reference is invalid"
            )
        refs = tuple(raw)
        if refs != tuple(sorted(set(refs))):
            raise ReceiptStoreError(
                "proof experiment authorization evidence is not canonical"
            )
        return refs

    controls = evidence_refs("control_evidence_refs")
    treatment = evidence_refs("treatment_evidence_refs")
    witnesses = evidence_refs("witness_evidence_refs")
    raw_uncertainty = value.get("uncertainty_reasons")
    if not isinstance(raw_uncertainty, (list, tuple)) or any(
        not isinstance(item, str)
        or _STATE_TRANSITION_SEMANTIC.fullmatch(item) is None
        for item in raw_uncertainty
    ):
        raise ReceiptStoreError(
            "proof experiment authorization uncertainty is invalid"
        )
    uncertainty = tuple(raw_uncertainty)
    if uncertainty != tuple(sorted(set(uncertainty))):
        raise ReceiptStoreError(
            "proof experiment authorization uncertainty is not canonical"
        )

    attempted = _nonnegative_int(
        value.get("requests_attempted"), field_name="requests_attempted"
    )
    sent = _nonnegative_int(
        value.get("requests_sent"), field_name="requests_sent"
    )
    denials = _nonnegative_int(
        value.get("policy_denials"), field_name="policy_denials"
    )
    released = _nonnegative_int(
        value.get("reserved_units_released"),
        field_name="reserved_units_released",
    )
    candidate_ref = value.get("finding_candidate_ref")
    if candidate_ref is not None and (
        not isinstance(candidate_ref, str)
        or _PROOF_EXPERIMENT_FINDING_CANDIDATE_REF.fullmatch(candidate_ref) is None
    ):
        raise ReceiptStoreError(
            "proof experiment authorization candidate reference is invalid"
        )
    conclusive = oracle_verdict in {"confirmed", "refuted"}
    all_evidence = controls + treatment + witnesses
    if (
        attempted > 4
        or sent > attempted
        or denials > attempted
        or sent + released != 4
        or len(controls) > 2
        or len(treatment) > 1
        or len(witnesses) > 1
        or len(all_evidence) > attempted
        or len(set(all_evidence)) != len(all_evidence)
        or (legacy_verdict == "BOLA_CONFIRMED") != (candidate_ref is not None)
        or (oracle_verdict == "confirmed" and legacy_verdict != "BOLA_CONFIRMED")
        or (
            oracle_verdict == "refuted"
            and legacy_verdict not in {"DENIED", "NO_CROSS_READ"}
        )
        or (conclusive and status != "completed")
        or (conclusive and (sent != 4 or len(controls) != 2))
        or (conclusive and (len(treatment) != 1 or len(witnesses) != 1))
        or (conclusive and uncertainty)
        or (oracle_verdict == "inconclusive" and status != "aborted")
        or (oracle_verdict == "inconclusive" and not uncertainty)
        or value.get("adversarial_triage_required") is not True
        or value.get("promotion_authority") is not False
        or value.get("finding_authority") is not False
    ):
        raise ReceiptStoreError(
            "proof experiment authorization outcome is inconsistent"
        )
    return {
        "kind": "proof_experiment_authorization",
        "status": status,
        "manifest_id": value["manifest_id"],
        "admission_id": value["admission_id"],
        "evaluation_id": value["evaluation_id"],
        "oracle_id": value["oracle_id"],
        "oracle_verdict": oracle_verdict,
        "backend_receipt_ref": value["backend_receipt_ref"],
        "legacy_verdict": legacy_verdict,
        "control_evidence_refs": list(controls),
        "treatment_evidence_refs": list(treatment),
        "witness_evidence_refs": list(witnesses),
        "provenance_root": value["provenance_root"],
        "uncertainty_reasons": list(uncertainty),
        "requests_attempted": attempted,
        "requests_sent": sent,
        "policy_denials": denials,
        "reserved_units_released": released,
        "finding_candidate_ref": candidate_ref,
        "adversarial_triage_required": True,
        "promotion_authority": False,
        "finding_authority": False,
    }


def redacted_proof_experiment_generalized_authorization_outcome(
    value: Mapping[str, Any],
) -> Dict[str, Any]:
    """Validate R5A3b's R4 outcome plus its locator authority chain."""

    if value.get("kind") != "proof_experiment_generalized_authorization":
        raise ReceiptStoreError(
            "proof experiment generalized authorization kind is invalid"
        )
    exact_refs = (
        (value.get("ownership_proof_id"), _OWNERSHIP_EXPERIMENT_PROOF_REF),
        (
            value.get("ownership_admission_id"),
            _OWNERSHIP_EXPERIMENT_ADMISSION_REF,
        ),
        (value.get("locator_proof_ref"), _LOCATOR_OWNERSHIP_PROOF_REF),
        (
            value.get("runtime_authority_ref"),
            _LOCATOR_RUNTIME_AUTHORITY_REF,
        ),
        (
            value.get("execution_plan_ref"),
            _GENERALIZED_AUTHORIZATION_PLAN_REF,
        ),
        (
            value.get("transport_context_ref"),
            _LOCATOR_TRANSPORT_CONTEXT_REF,
        ),
    )
    if any(
        not isinstance(item, str) or pattern.fullmatch(item) is None
        for item, pattern in exact_refs
    ):
        raise ReceiptStoreError(
            "proof experiment generalized authorization reference is invalid"
        )
    base = dict(value)
    base["kind"] = "proof_experiment_authorization"
    output = redacted_proof_experiment_authorization_outcome(base)
    output.update({
        "kind": "proof_experiment_generalized_authorization",
        "ownership_proof_id": value["ownership_proof_id"],
        "ownership_admission_id": value["ownership_admission_id"],
        "locator_proof_ref": value["locator_proof_ref"],
        "runtime_authority_ref": value["runtime_authority_ref"],
        "execution_plan_ref": value["execution_plan_ref"],
        "transport_context_ref": value["transport_context_ref"],
    })
    return output


def redacted_proof_experiment_omission_outcome(
    value: Mapping[str, Any],
) -> Dict[str, Any]:
    """Validate the cleanup-bound, non-promoting R4C2 omission summary."""

    if value.get("kind") != "proof_experiment_omission":
        raise ReceiptStoreError("proof experiment omission kind is invalid")
    status = value.get("status")
    oracle_verdict = value.get("oracle_verdict")
    legacy_verdict = value.get("legacy_verdict")
    cleanup_outcome = value.get("cleanup_outcome")
    if (
        status not in {"completed", "aborted"}
        or oracle_verdict not in {"confirmed", "refuted", "inconclusive"}
        or legacy_verdict not in _FRESH_OMISSION_CONFIRMATION_STATUSES
        or cleanup_outcome not in {"complete", "failed", "uncertain"}
    ):
        raise ReceiptStoreError("proof experiment omission verdict is invalid")

    exact_refs = (
        (value.get("manifest_id"), _PROOF_EXPERIMENT_MANIFEST_REF),
        (value.get("admission_id"), _PROOF_EXPERIMENT_ADMISSION_REF),
        (value.get("evaluation_id"), _PROOF_EXPERIMENT_EVALUATION_REF),
        (value.get("oracle_id"), _PROOF_EXPERIMENT_ORACLE_REF),
        (value.get("backend_receipt_ref"), _BEHAVIORAL_RECEIPT_REF),
        (value.get("provenance_root"), _PROVENANCE_REF),
    )
    if any(
        not isinstance(item, str) or pattern.fullmatch(item) is None
        for item, pattern in exact_refs
    ):
        raise ReceiptStoreError(
            "proof experiment omission reference is invalid"
        )

    def evidence_refs(field_name: str) -> tuple[str, ...]:
        raw = value.get(field_name)
        if not isinstance(raw, (list, tuple)) or any(
            not isinstance(item, str)
            or _PROOF_EXPERIMENT_ACTION_EVIDENCE_REF.fullmatch(item) is None
            for item in raw
        ):
            raise ReceiptStoreError(
                "proof experiment omission evidence reference is invalid"
            )
        refs = tuple(raw)
        if refs != tuple(sorted(set(refs))):
            raise ReceiptStoreError(
                "proof experiment omission evidence is not canonical"
            )
        return refs

    controls = evidence_refs("control_evidence_refs")
    treatment = evidence_refs("treatment_evidence_refs")
    witnesses = evidence_refs("witness_evidence_refs")
    cleanup = evidence_refs("cleanup_evidence_refs")
    raw_uncertainty = value.get("uncertainty_reasons")
    if not isinstance(raw_uncertainty, (list, tuple)) or any(
        not isinstance(item, str)
        or _STATE_TRANSITION_SEMANTIC.fullmatch(item) is None
        for item in raw_uncertainty
    ):
        raise ReceiptStoreError(
            "proof experiment omission uncertainty is invalid"
        )
    uncertainty = tuple(raw_uncertainty)
    if uncertainty != tuple(sorted(set(uncertainty))):
        raise ReceiptStoreError(
            "proof experiment omission uncertainty is not canonical"
        )

    counters = {
        key: _nonnegative_int(
            value.get(key),
            field_name=f"proof_experiment_omission.{key}",
        )
        for key in (
            "requests_attempted",
            "requests_sent",
            "policy_denials",
            "reserved_units_released",
            "total_request_units",
            "creates_attempted",
            "creates_completed",
            "cleanup_steps_attempted",
            "cleanup_steps_completed",
            "cleanup_verifications_attempted",
            "cleanup_verifications_completed",
        )
    }
    orphaned = value.get("orphaned_owned_state_possible")
    candidate_ref = value.get("finding_candidate_ref")
    if candidate_ref is not None and (
        not isinstance(candidate_ref, str)
        or _PROOF_EXPERIMENT_FINDING_CANDIDATE_REF.fullmatch(candidate_ref)
        is None
    ):
        raise ReceiptStoreError(
            "proof experiment omission candidate reference is invalid"
        )
    all_evidence = controls + treatment + witnesses + cleanup
    conclusive = oracle_verdict in {"confirmed", "refuted"}
    cleanup_complete = bool(
        counters["creates_completed"] > 0
        and counters["creates_attempted"] == counters["creates_completed"]
        and counters["cleanup_steps_completed"]
        == counters["creates_completed"]
        and counters["cleanup_verifications_completed"]
        == counters["creates_completed"]
        and orphaned is False
    )
    if (
        counters["total_request_units"] == 0
        or counters["total_request_units"] > 64
        or counters["requests_attempted"] > counters["total_request_units"]
        or counters["requests_sent"] > counters["requests_attempted"]
        or counters["requests_sent"] + counters["reserved_units_released"]
        != counters["total_request_units"]
        or counters["policy_denials"] > counters["requests_attempted"]
        or counters["creates_completed"] > counters["creates_attempted"]
        or counters["creates_attempted"] > 3
        or counters["cleanup_steps_completed"]
        > counters["cleanup_steps_attempted"]
        or counters["cleanup_steps_attempted"] > 3
        or counters["cleanup_verifications_completed"]
        > counters["cleanup_verifications_attempted"]
        or counters["cleanup_verifications_attempted"] > 3
        or not isinstance(orphaned, bool)
        or len(set(all_evidence)) != len(all_evidence)
        or len(all_evidence) > counters["requests_attempted"]
        or (cleanup_outcome == "complete") != cleanup_complete
        or (cleanup_outcome == "complete" and not cleanup)
        or (oracle_verdict == "confirmed")
        != (candidate_ref is not None)
        or (
            oracle_verdict == "confirmed"
            and legacy_verdict != "confirmed_fail_open"
        )
        or (
            oracle_verdict == "refuted"
            and legacy_verdict != "omission_rejected"
        )
        or (conclusive and status != "completed")
        or (conclusive and counters["requests_sent"] != counters["total_request_units"])
        or (conclusive and counters["creates_completed"] != 3)
        or (conclusive and not controls)
        or (conclusive and not treatment)
        or (conclusive and not witnesses)
        or (conclusive and not cleanup)
        or (conclusive and cleanup_outcome != "complete")
        or (conclusive and uncertainty)
        or (oracle_verdict == "inconclusive" and status != "aborted")
        or (oracle_verdict == "inconclusive" and not uncertainty)
        or value.get("adversarial_triage_required") is not True
        or value.get("promotion_authority") is not False
        or value.get("finding_authority") is not False
    ):
        raise ReceiptStoreError(
            "proof experiment omission outcome is inconsistent"
        )
    return {
        "kind": "proof_experiment_omission",
        "status": status,
        "manifest_id": value["manifest_id"],
        "admission_id": value["admission_id"],
        "evaluation_id": value["evaluation_id"],
        "oracle_id": value["oracle_id"],
        "oracle_verdict": oracle_verdict,
        "backend_receipt_ref": value["backend_receipt_ref"],
        "legacy_verdict": legacy_verdict,
        "control_evidence_refs": list(controls),
        "treatment_evidence_refs": list(treatment),
        "witness_evidence_refs": list(witnesses),
        "cleanup_evidence_refs": list(cleanup),
        "cleanup_outcome": cleanup_outcome,
        "provenance_root": value["provenance_root"],
        "uncertainty_reasons": list(uncertainty),
        **counters,
        "orphaned_owned_state_possible": orphaned,
        "finding_candidate_ref": candidate_ref,
        "adversarial_triage_required": True,
        "promotion_authority": False,
        "finding_authority": False,
    }


def redacted_graph_bound_prerequisite_execution_outcome(
    response: Mapping[str, Any],
) -> Dict[str, Any]:
    """Validate the only graph-bound execution fields allowed at rest."""

    def typed_ref(value: Any, prefix: str) -> bool:
        return bool(
            isinstance(value, str)
            and re.fullmatch(rf"{re.escape(prefix)}:[0-9a-f]{{64}}", value)
        )

    kind = response.get("kind")
    mode = response.get("mode")
    status = response.get("status")
    verdict = response.get("oracle_verdict")
    family = response.get("family")
    claim_contract_id = response.get("claim_contract_id")
    capture_freshness_ref = response.get("capture_freshness_ref")
    plan_id = response.get("plan_id")
    provisioning_id = response.get("provisioning_id")
    oracle_requirement_id = response.get("oracle_requirement_id")
    reference_state_id = response.get("reference_state_id")
    oracle_evaluation_id = response.get("oracle_evaluation_id")
    effect_witness_ref = response.get("effect_witness_ref")
    runtime_value_inequality_ref = response.get(
        "runtime_value_inequality_ref"
    )
    terminal_refs = response.get("terminal_evidence_refs")
    cleanup_refs = response.get("cleanup_evidence_refs")
    provenance_root = response.get("provenance_root")
    candidate_ref = response.get("finding_candidate_ref")
    finding_confirmed = response.get("finding_confirmed")
    selection = {
        key: response.get(key)
        for key in (
            "payout_goal_plan_id",
            "payout_candidate_id",
            "payout_goal_id",
            "payout_terminal_operation_id",
            "specification_id",
            "plan_id",
            "graph_target_ref",
            "graph_digest",
        )
    }
    selection_ref = response.get("selection_ref")
    selection_present = selection_ref is not None or any(
        value is not None
        for key, value in selection.items()
        if key != "plan_id"
    )
    counts = {
        key: response.get(key)
        for key in (
            "cleanup_steps_attempted",
            "cleanup_steps_completed",
            "cleanup_verifications_attempted",
            "cleanup_verifications_completed",
            "ownership_grants_removed",
            "target_requests_sent",
        )
    }
    confirmed = verdict == "confirmed"
    if (
        kind != "graph_bound_prerequisite_execution"
        or mode != "behavioral_graph_bound_prerequisite_execution_v1"
        or status not in {"confirmed", "refuted", "inconclusive"}
        or verdict != status
        or family not in {"omission", "reordering"}
        or response.get("receipt_state") != COMPLETED
        or not typed_ref(
            claim_contract_id,
            "graph_bound_execution_claim_contract",
        )
        or not typed_ref(
            capture_freshness_ref,
            "graph_bound_capture_freshness",
        )
        or not typed_ref(plan_id, "graph_bound_prepared_request_plan")
        or not typed_ref(
            provisioning_id,
            "graph_bound_fresh_world_provisioning",
        )
        or not typed_ref(
            oracle_requirement_id,
            "prerequisite_effect_oracle_requirement",
        )
        or not typed_ref(reference_state_id, "state")
        or not typed_ref(
            oracle_evaluation_id,
            "graph_bound_prerequisite_oracle_evaluation",
        )
        or (
            effect_witness_ref is not None
            and not typed_ref(
                effect_witness_ref,
                (
                    "graph_bound_independent_effect_witness"
                    if family == "omission"
                    else "graph_bound_reordering_effect_witness"
                ),
            )
        )
        or (
            family == "omission"
            and (effect_witness_ref is not None)
            != (runtime_value_inequality_ref is not None)
        )
        or (
            family == "reordering"
            and runtime_value_inequality_ref is not None
        )
        or (
            runtime_value_inequality_ref is not None
            and not typed_ref(
                runtime_value_inequality_ref,
                "graph_bound_runtime_value_inequality_attestation",
            )
        )
        or (
            family == "omission"
            and verdict in {"confirmed", "refuted"}
            and effect_witness_ref is None
        )
        or (
            family == "reordering"
            and (effect_witness_ref is not None) != confirmed
        )
        or not isinstance(terminal_refs, (list, tuple))
        or len(terminal_refs) != 3
        or any(not isinstance(item, str) for item in terminal_refs)
        or len(set(terminal_refs)) != 3
        or any(
            not typed_ref(item, "graph_bound_terminal_observation")
            for item in terminal_refs
        )
        or not isinstance(cleanup_refs, (list, tuple))
        or len(cleanup_refs) != 6
        or any(not isinstance(item, str) for item in cleanup_refs)
        or len(set(cleanup_refs)) != 6
        or any(
            not typed_ref(item, "graph_bound_cleanup_evidence")
            for item in cleanup_refs
        )
        or response.get("cleanup_status") != "verified"
        or response.get("orphaned_owned_state_possible") is not False
        or any(
            isinstance(value, bool)
            or not isinstance(value, int)
            or value < 0
            for value in counts.values()
        )
        or any(
            counts[key] != 3
            for key in (
                "cleanup_steps_attempted",
                "cleanup_steps_completed",
                "cleanup_verifications_attempted",
                "cleanup_verifications_completed",
                "ownership_grants_removed",
            )
        )
        or counts["target_requests_sent"] < 9
        or not isinstance(provenance_root, str)
        or re.fullmatch(r"[0-9a-f]{64}", provenance_root) is None
        or not isinstance(finding_confirmed, bool)
        or finding_confirmed != confirmed
        or (candidate_ref is not None)
        != confirmed
        or (
            candidate_ref is not None
            and not typed_ref(
                candidate_ref,
                "graph_bound_prerequisite_candidate",
            )
        )
        or response.get("adversarial_triage_required") is not True
        or response.get("promotion_authority") is not False
        or response.get("finding_authority") is not False
        or (
            selection_present
            and (
                not typed_ref(selection_ref, "graph_bound_one_click_selection")
                or not typed_ref(
                    selection["payout_goal_plan_id"],
                    "payout_goal_plan",
                )
                or not typed_ref(
                    selection["payout_candidate_id"],
                    "payout_goal_candidate",
                )
                or not typed_ref(
                    selection["payout_goal_id"],
                    "security_witness_goal",
                )
                or not typed_ref(
                    selection["payout_terminal_operation_id"],
                    "action",
                )
                or not typed_ref(
                    selection["specification_id"],
                    "graph_bound_prerequisite_experiment",
                )
                or selection["plan_id"] != plan_id
                or not typed_ref(
                    selection["graph_target_ref"],
                    "security_obligation_target",
                )
                or not typed_ref(
                    selection["graph_digest"],
                    "security_obligation_graph",
                )
                or selection_ref
                != stable_hash("graph_bound_one_click_selection", selection)
            )
        )
    ):
        raise ReceiptStoreError(
            "graph-bound prerequisite execution outcome is invalid"
        )
    outcome = {
        "kind": kind,
        "mode": mode,
        "status": status,
        "receipt_state": COMPLETED,
        "claim_contract_id": claim_contract_id,
        "capture_freshness_ref": capture_freshness_ref,
        "plan_id": plan_id,
        "family": family,
        "provisioning_id": provisioning_id,
        "oracle_requirement_id": oracle_requirement_id,
        "reference_state_id": reference_state_id,
        "oracle_evaluation_id": oracle_evaluation_id,
        "oracle_verdict": verdict,
        "effect_witness_ref": effect_witness_ref,
        "runtime_value_inequality_ref": runtime_value_inequality_ref,
        "terminal_evidence_refs": list(terminal_refs),
        "cleanup_evidence_refs": list(cleanup_refs),
        "cleanup_status": "verified",
        **counts,
        "orphaned_owned_state_possible": False,
        "provenance_root": provenance_root,
        "finding_candidate_ref": candidate_ref,
        "finding_confirmed": finding_confirmed,
        "adversarial_triage_required": True,
        "promotion_authority": False,
        "finding_authority": False,
    }
    if selection_present:
        outcome.update({**selection, "selection_ref": selection_ref})
    return outcome


def redacted_role_protected_effect_execution_outcome(
    response: Mapping[str, Any],
) -> Dict[str, Any]:
    """Validate the conclusive, redacted R5C6 outcome allowed at rest."""

    required_fields = {
        "kind",
        "mode",
        "status",
        "receipt_state",
        "claim_contract_id",
        "oracle_id",
        "oracle_evaluation_id",
        "oracle_verdict",
        "active_membership_observation_ref",
        "revoked_membership_observation_ref",
        "effect_observation_refs",
        "active_effect_witness_ref",
        "revoked_effect_witness_ref",
        "cleanup_status",
        "target_requests_sent",
        "target_request_may_have_been_sent",
        "orphaned_owned_state_possible",
        "provenance_root",
        "finding_candidate_ref",
        "finding_confirmed",
        "adversarial_triage_required",
        "promotion_authority",
        "finding_authority",
    }
    selection_fields = {
        "payout_goal_plan_id",
        "payout_candidate_id",
        "payout_goal_id",
        "payout_terminal_operation_id",
        "specification_id",
        "proof_id",
        "request_binding_id",
        "effect_observation_binding_id",
        "graph_target_ref",
        "graph_digest",
        "role_receipt_id",
        "selection_ref",
    }
    response_fields = set(response)
    selection_present = bool(response_fields & selection_fields)
    if (
        not required_fields <= response_fields
        or (selection_present and not selection_fields <= response_fields)
    ):
        raise ReceiptStoreError(
            "role protected effect execution outcome fields are invalid"
        )

    def typed_ref(item: Any, prefix: str) -> bool:
        return bool(
            isinstance(item, str)
            and re.fullmatch(rf"{re.escape(prefix)}:[0-9a-f]{{64}}", item)
        )

    status = response.get("status")
    refs = response.get("effect_observation_refs")
    candidate_ref = response.get("finding_candidate_ref")
    confirmed = status in {
        "confirmed_active_escalation",
        "confirmed_revocation_survival",
    }
    if (
        response.get("kind") != "role_protected_effect_execution"
        or response.get("mode")
        != "behavioral_role_protected_effect_execution_v1"
        or status
        not in {
            "confirmed_active_escalation",
            "confirmed_revocation_survival",
            "refuted",
        }
        or response.get("oracle_verdict") != status
        or response.get("receipt_state") != COMPLETED
        or not typed_ref(
            response.get("claim_contract_id"),
            "role_monotonicity_execution_claim_contract",
        )
        or not typed_ref(
            response.get("oracle_id"),
            "role_monotonicity_oracle",
        )
        or not typed_ref(
            response.get("oracle_evaluation_id"),
            "role_protected_effect_oracle_evaluation",
        )
        or not typed_ref(
            response.get("active_membership_observation_ref"),
            "role_membership_state_observation",
        )
        or not typed_ref(
            response.get("revoked_membership_observation_ref"),
            "role_membership_state_observation",
        )
        or not isinstance(refs, (list, tuple))
        or len(refs) != 5
        or len(set(refs)) != 5
        or any(
            not typed_ref(item, "role_protected_effect_observation")
            for item in refs
        )
        or not typed_ref(
            response.get("active_effect_witness_ref"),
            "role_active_effect_witness",
        )
        or not typed_ref(
            response.get("revoked_effect_witness_ref"),
            "role_revoked_effect_witness",
        )
        or response.get("cleanup_status") != "verified"
        or response.get("target_requests_sent") != 8
        or response.get("target_request_may_have_been_sent") is not False
        or response.get("orphaned_owned_state_possible") is not False
        or not isinstance(response.get("provenance_root"), str)
        or re.fullmatch(r"[0-9a-f]{64}", response["provenance_root"])
        is None
        or response.get("finding_confirmed") is not confirmed
        or (candidate_ref is not None) != confirmed
        or (
            candidate_ref is not None
            and not typed_ref(
                candidate_ref,
                "role_monotonicity_finding_candidate",
            )
        )
        or response.get("adversarial_triage_required") is not True
        or response.get("promotion_authority") is not False
        or response.get("finding_authority") is not False
        or (
            selection_present
            and (
                not typed_ref(
                    response.get("payout_goal_plan_id"),
                    "payout_goal_plan",
                )
                or not typed_ref(
                    response.get("payout_candidate_id"),
                    "payout_goal_candidate",
                )
                or not typed_ref(
                    response.get("payout_goal_id"),
                    "security_witness_goal",
                )
                or not typed_ref(
                    response.get("payout_terminal_operation_id"),
                    "action",
                )
                or not typed_ref(
                    response.get("specification_id"),
                    "role_monotonicity_one_click_specification",
                )
                or not typed_ref(
                    response.get("proof_id"),
                    "role_monotonicity_proof",
                )
                or not typed_ref(
                    response.get("request_binding_id"),
                    "role_monotonicity_request_binding",
                )
                or not typed_ref(
                    response.get("effect_observation_binding_id"),
                    "role_protected_effect_observation_binding",
                )
                or not typed_ref(
                    response.get("graph_target_ref"),
                    "security_obligation_target",
                )
                or not typed_ref(
                    response.get("graph_digest"),
                    "security_obligation_graph",
                )
                or not isinstance(response.get("role_receipt_id"), str)
                or re.fullmatch(
                    r"behavioral-[0-9a-f]{64}",
                    response["role_receipt_id"],
                )
                is None
                or not typed_ref(
                    response.get("selection_ref"),
                    "role_monotonicity_one_click_selection",
                )
                or response.get("selection_ref")
                != stable_hash(
                    "role_monotonicity_one_click_selection",
                    {
                        key: response.get(key)
                        for key in selection_fields
                        if key != "selection_ref"
                    },
                )
            )
        )
    ):
        raise ReceiptStoreError(
            "role protected effect execution outcome is invalid"
        )
    outcome = {
        "kind": "role_protected_effect_execution",
        "mode": "behavioral_role_protected_effect_execution_v1",
        "status": status,
        "receipt_state": COMPLETED,
        "claim_contract_id": response["claim_contract_id"],
        "oracle_id": response["oracle_id"],
        "oracle_evaluation_id": response["oracle_evaluation_id"],
        "oracle_verdict": status,
        "active_membership_observation_ref": response[
            "active_membership_observation_ref"
        ],
        "revoked_membership_observation_ref": response[
            "revoked_membership_observation_ref"
        ],
        "effect_observation_refs": list(refs),
        "active_effect_witness_ref": response["active_effect_witness_ref"],
        "revoked_effect_witness_ref": response["revoked_effect_witness_ref"],
        "cleanup_status": "verified",
        "target_requests_sent": 8,
        "target_request_may_have_been_sent": False,
        "orphaned_owned_state_possible": False,
        "provenance_root": response["provenance_root"],
        "finding_candidate_ref": candidate_ref,
        "finding_confirmed": confirmed,
        "adversarial_triage_required": True,
        "promotion_authority": False,
        "finding_authority": False,
    }
    if selection_present:
        outcome.update(
            {
                key: response[key]
                for key in selection_fields
            }
        )
    return outcome


def redacted_role_monotonicity_one_click_summary(
    value: Mapping[str, Any],
) -> Dict[str, Any]:
    """Retain truthful, non-authoritative status for a selected role run."""

    fields = {
        "schema_version",
        "mode",
        "status",
        "payout_candidate_id",
        "specification_id",
        "payout_goal_plan_id",
        "payout_goal_id",
        "payout_terminal_operation_id",
        "proof_id",
        "request_binding_id",
        "effect_observation_binding_id",
        "graph_target_ref",
        "graph_digest",
        "role_receipt_id",
        "selection_ref",
        "disabled_gates",
        "dispatched",
        "finding_candidate_ref",
        "promotion_authority",
        "finding_authority",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise ReceiptStoreError("role one-click status fields are invalid")

    def typed_ref(item: Any, prefix: str) -> bool:
        return bool(
            isinstance(item, str)
            and re.fullmatch(rf"{re.escape(prefix)}:[0-9a-f]{{64}}", item)
        )

    status = value.get("status")
    refs = {
        "payout_candidate_id": "payout_goal_candidate",
        "specification_id": "role_monotonicity_one_click_specification",
        "payout_goal_plan_id": "payout_goal_plan",
        "payout_goal_id": "security_witness_goal",
        "payout_terminal_operation_id": "action",
        "proof_id": "role_monotonicity_proof",
        "request_binding_id": "role_monotonicity_request_binding",
        "effect_observation_binding_id": (
            "role_protected_effect_observation_binding"
        ),
        "graph_target_ref": "security_obligation_target",
        "graph_digest": "security_obligation_graph",
        "selection_ref": "role_monotonicity_one_click_selection",
    }
    first_refs = ("payout_candidate_id", "specification_id")
    remaining_refs = tuple(key for key in refs if key not in first_refs)
    disabled = value.get("disabled_gates")
    allowed_gates = {
        "SENTINELFORGE_BEHAVIOR_ROLE_MONOTONICITY_ONE_CLICK",
        "SENTINELFORGE_BEHAVIOR_ROLE_MONOTONICITY_EXECUTION_CLAIM",
        "SENTINELFORGE_BEHAVIOR_ROLE_MEMBERSHIP_LIFECYCLE",
        "SENTINELFORGE_BEHAVIOR_ROLE_PROTECTED_EFFECT_EXECUTION",
    }
    if (
        value.get("schema_version") != 1
        or value.get("mode") != "behavioral_role_monotonicity_one_click_v1"
        or status
        not in {
            "no_eligible_candidate",
            "selected_execution_disabled",
            "completed",
        }
        or not isinstance(disabled, (list, tuple))
        or len(disabled) != len(set(disabled))
        or any(item not in allowed_gates for item in disabled)
        or value.get("promotion_authority") is not False
        or value.get("finding_authority") is not False
        or not isinstance(value.get("dispatched"), bool)
    ):
        raise ReceiptStoreError("role one-click status is invalid")
    candidate_ref = value.get("finding_candidate_ref")
    role_receipt_id = value.get("role_receipt_id")
    if status == "no_eligible_candidate":
        if (
            any(value.get(key) is not None for key in refs)
            or role_receipt_id is not None
            or candidate_ref is not None
            or disabled
            or value.get("dispatched") is not False
        ):
            raise ReceiptStoreError("inactive role one-click status is invalid")
    elif status == "selected_execution_disabled":
        if (
            any(not typed_ref(value.get(key), refs[key]) for key in first_refs)
            or any(value.get(key) is not None for key in remaining_refs)
            or role_receipt_id is not None
            or candidate_ref is not None
            or not disabled
            or value.get("dispatched") is not False
        ):
            raise ReceiptStoreError("disabled role one-click status is invalid")
    else:
        selection = {
            key: value.get(key)
            for key in (
                "payout_goal_plan_id",
                "payout_candidate_id",
                "payout_goal_id",
                "payout_terminal_operation_id",
                "specification_id",
                "proof_id",
                "request_binding_id",
                "effect_observation_binding_id",
                "graph_target_ref",
                "graph_digest",
                "role_receipt_id",
            )
        }
        if (
            any(not typed_ref(value.get(key), prefix) for key, prefix in refs.items())
            or not isinstance(role_receipt_id, str)
            or re.fullmatch(r"behavioral-[0-9a-f]{64}", role_receipt_id) is None
            or value.get("selection_ref")
            != stable_hash("role_monotonicity_one_click_selection", selection)
            or (
                candidate_ref is not None
                and not typed_ref(
                    candidate_ref,
                    "role_monotonicity_finding_candidate",
                )
            )
            or disabled
            or value.get("dispatched") is not True
        ):
            raise ReceiptStoreError("completed role one-click status is invalid")
    return {
        key: (list(value[key]) if key == "disabled_gates" else value[key])
        for key in fields
    }


def redacted_graph_bound_prerequisite_denial_evidence(
    value: Mapping[str, Any],
) -> Dict[str, Any]:
    """Validate graph-denial evidence that is safe to retain on an abort."""

    required_fields = {
        "schema_version",
        "kind",
        "status",
        "denial_evidence_ref",
        "graph_receipt_id",
        "reason_code",
        "category",
        "claim_contract_id",
        "capture_freshness_ref",
        "plan_id",
        "family",
        "cleanup",
        "finding_confirmed",
        "promotion_authority",
        "finding_authority",
        "retry_authority",
    }
    if set(value) != required_fields:
        raise ReceiptStoreError("graph-bound denial evidence fields are invalid")

    def typed_ref(item: Any, prefix: str) -> bool:
        return bool(
            isinstance(item, str)
            and re.fullmatch(rf"{re.escape(prefix)}:[0-9a-f]{{64}}", item)
        )

    cleanup = value.get("cleanup")
    cleanup_fields = {
        "status",
        "cleanup_steps_attempted",
        "cleanup_steps_completed",
        "cleanup_verifications_attempted",
        "cleanup_verifications_completed",
        "ownership_grants_removed",
        "cleanup_evidence_refs",
        "orphaned_owned_state_possible",
    }
    if not isinstance(cleanup, Mapping) or set(cleanup) != cleanup_fields:
        raise ReceiptStoreError("graph-bound denial cleanup evidence is invalid")
    counts = {
        key: cleanup.get(key)
        for key in (
            "cleanup_steps_attempted",
            "cleanup_steps_completed",
            "cleanup_verifications_attempted",
            "cleanup_verifications_completed",
            "ownership_grants_removed",
        )
    }
    cleanup_refs = cleanup.get("cleanup_evidence_refs")
    orphaned = cleanup.get("orphaned_owned_state_possible")
    verified = (
        all(value == 3 for value in counts.values())
        and orphaned is False
    )
    if (
        cleanup.get("status") not in {"verified", "failed", "uncertain"}
        or any(
            isinstance(item, bool) or not isinstance(item, int) or item < 0
            for item in counts.values()
        )
        or counts["cleanup_steps_completed"]
        > counts["cleanup_steps_attempted"]
        or counts["cleanup_verifications_completed"]
        > counts["cleanup_verifications_attempted"]
        or counts["ownership_grants_removed"]
        > counts["cleanup_verifications_completed"]
        or not isinstance(orphaned, bool)
        or (cleanup.get("status") == "verified") != verified
        or (cleanup.get("status") == "verified") == orphaned
        or not isinstance(cleanup_refs, (list, tuple))
        or len(cleanup_refs)
        != counts["cleanup_steps_attempted"]
        + counts["cleanup_verifications_attempted"]
        or list(cleanup_refs) != sorted(set(cleanup_refs))
        or any(
            not typed_ref(item, "graph_bound_cleanup_evidence")
            for item in cleanup_refs
        )
    ):
        raise ReceiptStoreError("graph-bound denial cleanup evidence is inconsistent")

    graph_receipt_id = value.get("graph_receipt_id")
    reason_code = value.get("reason_code")
    category = value.get("category")
    normalized_cleanup = {
        "status": cleanup.get("status"),
        **counts,
        "cleanup_evidence_refs": list(cleanup_refs),
        "orphaned_owned_state_possible": orphaned,
    }
    payload = {
        "kind": "graph_bound_prerequisite_execution_denial",
        "status": "denied",
        "graph_receipt_id": graph_receipt_id,
        "reason_code": reason_code,
        "category": category,
        "claim_contract_id": value.get("claim_contract_id"),
        "capture_freshness_ref": value.get("capture_freshness_ref"),
        "plan_id": value.get("plan_id"),
        "family": value.get("family"),
        "cleanup": normalized_cleanup,
        "finding_confirmed": False,
        "promotion_authority": False,
        "finding_authority": False,
        "retry_authority": False,
    }
    if (
        value.get("schema_version") != 1
        or value.get("kind") != payload["kind"]
        or value.get("status") != "denied"
        or not isinstance(graph_receipt_id, str)
        or not graph_receipt_id.startswith("behavioral-")
        or not re_full_sha256(graph_receipt_id[len("behavioral-") :])
        or not isinstance(reason_code, str)
        or _ABORT_REASON.fullmatch(reason_code) is None
        or not isinstance(category, str)
        or _ABORT_REASON.fullmatch(category) is None
        or not typed_ref(
            value.get("claim_contract_id"),
            "graph_bound_execution_claim_contract",
        )
        or not typed_ref(
            value.get("capture_freshness_ref"),
            "graph_bound_capture_freshness",
        )
        or not typed_ref(
            value.get("plan_id"),
            "graph_bound_prepared_request_plan",
        )
        or value.get("family") not in {"omission", "reordering"}
        or value.get("finding_confirmed") is not False
        or value.get("promotion_authority") is not False
        or value.get("finding_authority") is not False
        or value.get("retry_authority") is not False
        or value.get("denial_evidence_ref")
        != stable_hash("graph_bound_prerequisite_denial_evidence", payload)
    ):
        raise ReceiptStoreError("graph-bound denial evidence is invalid")
    return {
        "schema_version": 1,
        "denial_evidence_ref": value.get("denial_evidence_ref"),
        **payload,
    }


def redacted_role_membership_lifecycle_terminal_evidence(
    value: Mapping[str, Any],
) -> Dict[str, Any]:
    """Validate redacted R5C5 cleanup evidence retained on an abort."""

    required_fields = {
        "schema_version",
        "terminal_evidence_ref",
        "kind",
        "status",
        "reason_code",
        "category",
        "claim_contract_id",
        "active_observation_ref",
        "revoked_observation_ref",
        "cleanup",
        "target_requests_sent",
        "remaining_execution_blockers",
        "finding_confirmed",
        "promotion_authority",
        "finding_authority",
        "retry_authority",
    }
    if set(value) != required_fields:
        raise ReceiptStoreError(
            "role membership terminal evidence fields are invalid"
        )

    def typed_ref(item: Any, prefix: str) -> bool:
        return bool(
            isinstance(item, str)
            and re.fullmatch(rf"{re.escape(prefix)}:[0-9a-f]{{64}}", item)
        )

    cleanup = value.get("cleanup")
    cleanup_fields = {
        "status",
        "revocation_attempted",
        "revocation_completed",
        "verification_attempted",
        "verification_completed",
        "revoked_observation_ref",
        "target_requests_sent",
        "target_request_may_have_been_sent",
        "orphaned_owned_state_possible",
    }
    if not isinstance(cleanup, Mapping) or set(cleanup) != cleanup_fields:
        raise ReceiptStoreError(
            "role membership terminal cleanup evidence is invalid"
        )
    counts = {
        key: cleanup.get(key)
        for key in (
            "revocation_attempted",
            "revocation_completed",
            "verification_attempted",
            "verification_completed",
            "target_requests_sent",
        )
    }
    cleanup_status = cleanup.get("status")
    cleanup_revoked_ref = cleanup.get("revoked_observation_ref")
    uncertain = cleanup.get("target_request_may_have_been_sent")
    orphaned = cleanup.get("orphaned_owned_state_possible")
    verified = (
        counts["revocation_attempted"]
        == counts["revocation_completed"]
        == counts["verification_attempted"]
        == counts["verification_completed"]
        == 1
        and typed_ref(
            cleanup_revoked_ref,
            "role_membership_state_observation",
        )
        and orphaned is False
    )
    if (
        cleanup_status not in {"verified", "failed", "uncertain"}
        or any(
            isinstance(item, bool) or not isinstance(item, int) or item < 0
            for item in counts.values()
        )
        or counts["revocation_attempted"] > 1
        or counts["verification_attempted"] > 1
        or counts["revocation_completed"] > counts["revocation_attempted"]
        or counts["verification_completed"] > counts["verification_attempted"]
        or counts["target_requests_sent"] > 3
        or not isinstance(uncertain, bool)
        or not isinstance(orphaned, bool)
        or (cleanup_status == "verified") != verified
        or (cleanup_status == "verified") == orphaned
    ):
        raise ReceiptStoreError(
            "role membership terminal cleanup evidence is inconsistent"
        )

    payload = {
        "kind": "role_membership_lifecycle_terminal",
        "status": value.get("status"),
        "reason_code": value.get("reason_code"),
        "category": value.get("category"),
        "claim_contract_id": value.get("claim_contract_id"),
        "active_observation_ref": value.get("active_observation_ref"),
        "revoked_observation_ref": value.get("revoked_observation_ref"),
        "cleanup": dict(cleanup),
        "target_requests_sent": value.get("target_requests_sent"),
        "remaining_execution_blockers": value.get(
            "remaining_execution_blockers"
        ),
        "finding_confirmed": False,
        "promotion_authority": False,
        "finding_authority": False,
        "retry_authority": False,
    }
    active_ref = payload["active_observation_ref"]
    revoked_ref = payload["revoked_observation_ref"]
    if (
        value.get("schema_version") != 1
        or payload["status"] not in {"cleaned", "cleanup_failed"}
        or (payload["status"] == "cleaned") != verified
        or not isinstance(payload["reason_code"], str)
        or _ABORT_REASON.fullmatch(payload["reason_code"]) is None
        or not isinstance(payload["category"], str)
        or _ABORT_REASON.fullmatch(payload["category"]) is None
        or not typed_ref(
            payload["claim_contract_id"],
            "role_monotonicity_execution_claim_contract",
        )
        or (
            active_ref is not None
            and not typed_ref(
                active_ref,
                "role_membership_state_observation",
            )
        )
        or (
            revoked_ref is not None
            and not typed_ref(
                revoked_ref,
                "role_membership_state_observation",
            )
        )
        or revoked_ref != cleanup_revoked_ref
        or payload["target_requests_sent"]
        != counts["target_requests_sent"]
        or payload["remaining_execution_blockers"]
        != ["effect_evaluation_required"]
        or value.get("finding_confirmed") is not False
        or value.get("promotion_authority") is not False
        or value.get("finding_authority") is not False
        or value.get("retry_authority") is not False
        or value.get("terminal_evidence_ref")
        != stable_hash(
            "role_membership_lifecycle_terminal_evidence",
            payload,
        )
    ):
        raise ReceiptStoreError("role membership terminal evidence is invalid")
    return {
        "schema_version": 1,
        "terminal_evidence_ref": value.get("terminal_evidence_ref"),
        **payload,
    }


def redacted_role_protected_effect_terminal_evidence(
    value: Mapping[str, Any],
) -> Dict[str, Any]:
    """Validate redacted R5C6 evidence retained on every aborted path."""

    required_fields = {
        "schema_version",
        "terminal_evidence_ref",
        "kind",
        "status",
        "reason_code",
        "category",
        "claim_contract_id",
        "oracle_id",
        "oracle_evaluation_id",
        "active_membership_observation_ref",
        "revoked_membership_observation_ref",
        "effect_observation_refs",
        "cleanup",
        "target_requests_sent",
        "target_request_may_have_been_sent",
        "orphaned_owned_state_possible",
        "oracle_verdict",
        "finding_candidate_ref",
        "finding_confirmed",
        "promotion_authority",
        "finding_authority",
        "retry_authority",
    }
    if set(value) != required_fields:
        raise ReceiptStoreError(
            "role protected effect terminal evidence fields are invalid"
        )

    def typed_ref(item: Any, prefix: str) -> bool:
        return bool(
            isinstance(item, str)
            and re.fullmatch(rf"{re.escape(prefix)}:[0-9a-f]{{64}}", item)
        )

    cleanup = value.get("cleanup")
    cleanup_fields = {
        "status",
        "revocation_attempted",
        "revocation_completed",
        "verification_attempted",
        "verification_completed",
        "revoked_observation_ref",
        "target_requests_sent",
        "target_request_may_have_been_sent",
        "orphaned_owned_state_possible",
    }
    if not isinstance(cleanup, Mapping) or set(cleanup) != cleanup_fields:
        raise ReceiptStoreError(
            "role protected effect terminal cleanup evidence is invalid"
        )
    count_keys = (
        "revocation_attempted",
        "revocation_completed",
        "verification_attempted",
        "verification_completed",
        "target_requests_sent",
    )
    counts = {key: cleanup.get(key) for key in count_keys}
    cleanup_revoked_ref = cleanup.get("revoked_observation_ref")
    uncertain = cleanup.get("target_request_may_have_been_sent")
    orphaned = cleanup.get("orphaned_owned_state_possible")
    verified = (
        counts["revocation_attempted"]
        == counts["revocation_completed"]
        == counts["verification_attempted"]
        == counts["verification_completed"]
        == 1
        and typed_ref(
            cleanup_revoked_ref,
            "role_membership_state_observation",
        )
        and orphaned is False
    )
    effect_refs = value.get("effect_observation_refs")
    if (
        cleanup.get("status") not in {"verified", "failed", "uncertain"}
        or any(
            isinstance(item, bool) or not isinstance(item, int) or item < 0
            for item in counts.values()
        )
        or counts["revocation_attempted"] > 1
        or counts["verification_attempted"] > 1
        or counts["revocation_completed"] > counts["revocation_attempted"]
        or counts["verification_completed"] > counts["verification_attempted"]
        or counts["target_requests_sent"] > 8
        or not isinstance(uncertain, bool)
        or not isinstance(orphaned, bool)
        or (cleanup.get("status") == "verified") != verified
        or (cleanup.get("status") == "verified") == orphaned
        or not isinstance(effect_refs, (list, tuple))
        or len(effect_refs) > 5
        or len(set(effect_refs)) != len(effect_refs)
        or any(
            not typed_ref(item, "role_protected_effect_observation")
            for item in effect_refs
        )
    ):
        raise ReceiptStoreError(
            "role protected effect terminal cleanup evidence is inconsistent"
        )

    payload = {
        "kind": "role_protected_effect_execution_terminal",
        "status": value.get("status"),
        "reason_code": value.get("reason_code"),
        "category": value.get("category"),
        "claim_contract_id": value.get("claim_contract_id"),
        "oracle_id": value.get("oracle_id"),
        "oracle_evaluation_id": value.get("oracle_evaluation_id"),
        "active_membership_observation_ref": value.get(
            "active_membership_observation_ref"
        ),
        "revoked_membership_observation_ref": value.get(
            "revoked_membership_observation_ref"
        ),
        "effect_observation_refs": list(effect_refs),
        "cleanup": dict(cleanup),
        "target_requests_sent": value.get("target_requests_sent"),
        "target_request_may_have_been_sent": value.get(
            "target_request_may_have_been_sent"
        ),
        "orphaned_owned_state_possible": value.get(
            "orphaned_owned_state_possible"
        ),
        "oracle_verdict": value.get("oracle_verdict"),
        "finding_candidate_ref": None,
        "finding_confirmed": False,
        "promotion_authority": False,
        "finding_authority": False,
        "retry_authority": False,
    }
    active_ref = payload["active_membership_observation_ref"]
    revoked_ref = payload["revoked_membership_observation_ref"]
    evaluation_id = payload["oracle_evaluation_id"]
    if (
        value.get("schema_version") != 1
        or payload["status"] not in {"cleaned", "cleanup_failed"}
        or (payload["status"] == "cleaned") != verified
        or not isinstance(payload["reason_code"], str)
        or _ABORT_REASON.fullmatch(payload["reason_code"]) is None
        or not isinstance(payload["category"], str)
        or _ABORT_REASON.fullmatch(payload["category"]) is None
        or not typed_ref(
            payload["claim_contract_id"],
            "role_monotonicity_execution_claim_contract",
        )
        or not typed_ref(payload["oracle_id"], "role_monotonicity_oracle")
        or (
            evaluation_id is not None
            and not typed_ref(
                evaluation_id,
                "role_protected_effect_oracle_evaluation",
            )
        )
        or (
            active_ref is not None
            and not typed_ref(
                active_ref,
                "role_membership_state_observation",
            )
        )
        or (
            revoked_ref is not None
            and not typed_ref(
                revoked_ref,
                "role_membership_state_observation",
            )
        )
        or revoked_ref != cleanup_revoked_ref
        or payload["target_requests_sent"] != counts["target_requests_sent"]
        or payload["target_request_may_have_been_sent"] != uncertain
        or payload["orphaned_owned_state_possible"] != orphaned
        or payload["oracle_verdict"] != "inconclusive"
        or value.get("finding_candidate_ref") is not None
        or value.get("finding_confirmed") is not False
        or value.get("promotion_authority") is not False
        or value.get("finding_authority") is not False
        or value.get("retry_authority") is not False
        or value.get("terminal_evidence_ref")
        != stable_hash(
            "role_protected_effect_execution_terminal_evidence",
            payload,
        )
    ):
        raise ReceiptStoreError(
            "role protected effect terminal evidence is invalid"
        )
    return {
        "schema_version": 1,
        "terminal_evidence_ref": value.get("terminal_evidence_ref"),
        **payload,
    }


def redacted_terminal_evidence(
    value: Mapping[str, Any],
) -> Dict[str, Any]:
    """Route one terminal receipt payload to its strict family schema."""

    if value.get("kind") == "role_membership_lifecycle_terminal":
        return redacted_role_membership_lifecycle_terminal_evidence(value)
    if value.get("kind") == "role_protected_effect_execution_terminal":
        return redacted_role_protected_effect_terminal_evidence(value)
    return redacted_graph_bound_prerequisite_denial_evidence(value)


def redacted_graph_bound_prerequisite_denial_response(
    receipt: BehavioralExecutionReceipt,
    *,
    reused: bool,
) -> Dict[str, Any]:
    """Build one public denial solely from a durably aborted root receipt."""

    if not isinstance(receipt, BehavioralExecutionReceipt):
        raise TypeError("receipt must be a BehavioralExecutionReceipt")
    if not isinstance(reused, bool):
        raise TypeError("reused must be boolean")
    if receipt.state != ABORTED or receipt.terminal_evidence is None:
        raise ReceiptStoreError("graph-bound denial receipt is not terminal")
    evidence = redacted_graph_bound_prerequisite_denial_evidence(
        receipt.terminal_evidence
    )
    return {
        "schema_version": 1,
        "kind": "graph_bound_prerequisite_execution_denial",
        "status": "denied",
        "reused": reused,
        "graph_receipt": {
            "receipt_id": evidence["graph_receipt_id"],
            "state": ABORTED,
        },
        "orchestration_receipt": {
            "receipt_id": receipt.receipt_id,
            "state": ABORTED,
        },
        "denial": evidence,
    }


def redacted_role_protected_effect_denial_response(
    receipt: BehavioralExecutionReceipt,
    *,
    reused: bool,
) -> Dict[str, Any]:
    """Build one public role denial solely from a durably aborted receipt."""

    if not isinstance(receipt, BehavioralExecutionReceipt):
        raise TypeError("receipt must be a BehavioralExecutionReceipt")
    if not isinstance(reused, bool):
        raise TypeError("reused must be boolean")
    if receipt.state != ABORTED or receipt.terminal_evidence is None:
        raise ReceiptStoreError("role denial receipt is not terminal")
    evidence = redacted_role_protected_effect_terminal_evidence(
        receipt.terminal_evidence
    )
    return {
        "schema_version": 1,
        "kind": "role_protected_effect_execution_denial",
        "status": "denied",
        "reused": reused,
        "orchestration_receipt": {
            "receipt_id": receipt.receipt_id,
            "state": ABORTED,
        },
        "denial": evidence,
    }


def redacted_behavioral_execution_denial_response(
    receipt: BehavioralExecutionReceipt,
    *,
    reused: bool,
) -> Dict[str, Any]:
    """Render the exact family schema selected by terminal evidence."""

    evidence = receipt.terminal_evidence
    if isinstance(evidence, Mapping) and evidence.get("kind") == (
        "role_protected_effect_execution_terminal"
    ):
        return redacted_role_protected_effect_denial_response(
            receipt,
            reused=reused,
        )
    return redacted_graph_bound_prerequisite_denial_response(
        receipt,
        reused=reused,
    )


def redacted_capability_effect_evidence_outcome(
    response: Mapping[str, Any],
) -> Dict[str, Any]:
    """Persist the strict inner R5D10 source without candidate authority."""

    from core.behavior.capability_effect_evidence import CapabilityEffectEvidence

    if response.get("kind") != "capability_effect_one_click":
        raise ReceiptStoreError("capability effect receipt kind is invalid")
    evidence_value = response.get("capability_effect_evidence")
    if not isinstance(evidence_value, Mapping):
        raise ReceiptStoreError("capability effect receipt evidence is missing")
    try:
        evidence = CapabilityEffectEvidence.from_mapping(evidence_value)
    except (TypeError, ValueError) as exc:
        raise ReceiptStoreError(
            "capability effect receipt evidence is invalid"
        ) from exc
    status = evidence.oracle["verdict"]
    if response.get("status") != status:
        raise ReceiptStoreError("capability effect receipt status is inconsistent")
    return {
        "kind": "capability_effect_one_click",
        "status": status,
        "capability_effect_evidence": evidence.to_dict(),
        "finding": None,
        "finding_confirmed": False,
        "promotion_authority": False,
        "finding_authority": False,
    }


def redacted_capability_effect_orchestration_outcome(
    response: Mapping[str, Any],
) -> Dict[str, Any]:
    """Retain only the outer orchestration link to the authoritative source."""

    source_receipt_id = response.get("source_receipt_id")
    assessment_session_id = response.get("assessment_session_id")
    if (
        response.get("kind") != "capability_effect_orchestration"
        or response.get("status") != "completed"
        or not isinstance(source_receipt_id, str)
        or not source_receipt_id.startswith("behavioral-")
        or not re_full_sha256(source_receipt_id.removeprefix("behavioral-"))
        or not isinstance(assessment_session_id, str)
        or not assessment_session_id
        or assessment_session_id == "global_scan"
    ):
        raise ReceiptStoreError("capability effect orchestration outcome is invalid")
    return {
        "kind": "capability_effect_orchestration",
        "status": "completed",
        "source_receipt_id": source_receipt_id,
        "assessment_session_id": assessment_session_id,
    }


def redacted_outcome(response: Mapping[str, Any]) -> Dict[str, Any]:
    """Return the only response fields permitted in a durable receipt."""
    if response.get("kind") == "capability_effect_orchestration":
        return redacted_capability_effect_orchestration_outcome(response)
    if (
        response.get("kind") == "capability_effect_one_click"
        and "capability_effect_evidence" in response
    ):
        return redacted_capability_effect_evidence_outcome(response)
    if response.get("kind") == "graph_bound_prerequisite_execution":
        return redacted_graph_bound_prerequisite_execution_outcome(response)
    if response.get("kind") == "role_protected_effect_execution":
        return redacted_role_protected_effect_execution_outcome(response)
    if response.get("kind") == "proof_experiment_generalized_authorization":
        return redacted_proof_experiment_generalized_authorization_outcome(
            response
        )
    if response.get("kind") == "proof_experiment_authorization":
        return redacted_proof_experiment_authorization_outcome(response)
    if response.get("kind") == "proof_experiment_omission":
        return redacted_proof_experiment_omission_outcome(response)
    if "continuation" in response:
        return redacted_continuation_outcome(response)
    if response.get("kind") == "fresh_omission_confirmation":
        return redacted_fresh_omission_confirmation_outcome(response)
    execution_value = response.get("execution")
    if isinstance(execution_value, Mapping):
        admission_execution = execution_value.get("execution")
        if (
            isinstance(admission_execution, Mapping)
            and admission_execution.get("kind") == "fresh_omission_confirmation"
        ):
            output = redacted_fresh_omission_confirmation_outcome(
                admission_execution
            )
            return _attach_adaptive_proof_handoff(output, response)
    if isinstance(execution_value, Mapping) and execution_value.get("kind") == (
        "fresh_owned_boundary"
    ):
        return redacted_fresh_owned_boundary_outcome(response)
    status = response.get("status")
    if status not in _VALID_RUN_STATUSES:
        raise ReceiptStoreError("behavioral receipt run status is invalid")
    finding_confirmed = response.get("finding_confirmed")
    if not isinstance(finding_confirmed, bool):
        finding_confirmed = bool(response.get("finding"))
    selected_proposal = _selected_proposal(response.get("plan"))
    execution = _redacted_execution(response.get("execution"))
    if status == "no_executable_candidate":
        if selected_proposal is not None or execution is not None or finding_confirmed:
            raise ReceiptStoreError("behavioral no-candidate outcome is inconsistent")
    else:
        if selected_proposal is None or execution is None or execution["status"] != status:
            raise ReceiptStoreError("behavioral execution outcome is inconsistent")
        if execution["finding_confirmed"] != finding_confirmed:
            raise ReceiptStoreError("behavioral finding state is inconsistent")
        if (execution["legacy_verdict"] == "BOLA_CONFIRMED") != finding_confirmed:
            raise ReceiptStoreError("behavioral legacy verdict is inconsistent")
    output = {
        "status": status,
        "plan": {"selected_proposal_id": selected_proposal},
        "execution": execution,
        "finding": None,
        "finding_confirmed": finding_confirmed,
        "graphql_resolution": _redacted_graphql_diagnostics(
            response.get("graphql_resolution")
        ),
    }
    if "read_exploration" in response:
        output["read_exploration"] = _redacted_read_exploration(
            response.get("read_exploration")
        )
    if "interaction_acquisition" in response:
        output["interaction_acquisition"] = (
            _redacted_interaction_acquisition_summary(
                response.get("interaction_acquisition")
            )
        )
    if "role_monotonicity_one_click" in response:
        output["role_monotonicity_one_click"] = (
            redacted_role_monotonicity_one_click_summary(
                response.get("role_monotonicity_one_click")
            )
        )
    return _attach_adaptive_proof_handoff(output, response)


def _redacted_stored_outcome(value: Mapping[str, Any]) -> Dict[str, Any]:
    if value.get("kind") == "capability_effect_orchestration":
        return redacted_capability_effect_orchestration_outcome(value)
    if value.get("kind") == "capability_effect_one_click":
        return redacted_capability_effect_evidence_outcome(value)
    if value.get("kind") == "graph_bound_prerequisite_execution":
        return redacted_graph_bound_prerequisite_execution_outcome(value)
    if value.get("kind") == "role_protected_effect_execution":
        return redacted_role_protected_effect_execution_outcome(value)
    if value.get("kind") == "proof_experiment_generalized_authorization":
        return redacted_proof_experiment_generalized_authorization_outcome(
            value
        )
    if value.get("kind") == "proof_experiment_authorization":
        return redacted_proof_experiment_authorization_outcome(value)
    if value.get("kind") == "proof_experiment_omission":
        return redacted_proof_experiment_omission_outcome(value)
    if value.get("kind") == "owned_state_transition_proof":
        return redacted_owned_state_transition_outcome(value)
    if value.get("kind") == "owned_read_proof":
        return redacted_owned_read_proof_outcome(value)
    if value.get("kind") == "interaction_read_acquisition":
        return redacted_interaction_acquisition_outcome(value)
    if value.get("kind") == "compiled_sequence":
        return redacted_compiled_outcome(value)
    if value.get("kind") == "fresh_owned_boundary":
        return redacted_fresh_owned_boundary_outcome(value)
    if value.get("kind") == "fresh_omission_boundary":
        return redacted_fresh_omission_outcome(value)
    if value.get("kind") == "fresh_omission_confirmation":
        return redacted_fresh_omission_confirmation_outcome(value)
    if value.get("kind") == "bounded_continuation":
        return redacted_continuation_outcome(value)
    return redacted_outcome(value)


class BehavioralReceiptStore:
    def __init__(self, root: Optional[Path] = None) -> None:
        self.root = root
        self._storage_anchor: Optional[EvidenceStorageAnchor] = None
        self._root_identity: Optional[tuple[int, int]] = None
        self._root_location: Optional[Path] = None

    def _assert_storage_anchor(self, *, seal: bool = False) -> None:
        if self._storage_anchor is None:
            return
        try:
            if seal:
                self._storage_anchor.seal()
            else:
                self._storage_anchor.assert_unchanged()
        except EvidenceStorageBoundaryError as exc:
            raise ReceiptStoreError(
                "behavioral receipt storage changed after admission"
            ) from exc

    def bind_storage_anchor(self, anchor: EvidenceStorageAnchor) -> None:
        """Require every later receipt access to retain an admitted location."""

        if not isinstance(anchor, EvidenceStorageAnchor):
            raise TypeError("behavioral receipt storage anchor is invalid")
        anchor.assert_unchanged()
        if self._storage_anchor is not None:
            self._assert_storage_anchor()
            if self._storage_anchor.resolved_locations != anchor.resolved_locations:
                raise ReceiptStoreError(
                    "behavioral receipt storage anchor cannot be replaced"
                )
        self._storage_anchor = anchor

    def _root(self) -> Path:
        if self.root is not None:
            return self.root
        override = os.environ.get(RECEIPT_ENV)
        if override:
            return Path(override)
        data_dir = os.environ.get("SENTINEL_DATA_DIR")
        if data_dir:
            return Path(data_dir) / "behavioral_receipts"
        return Path.home() / ".sentinelforge" / "behavioral_receipts"

    def _prepare_root(self) -> Path:
        self._assert_storage_anchor()
        root = self._root().expanduser()
        if not root.is_absolute():
            root = Path.cwd() / root
        missing_directories: list[Path] = []
        cursor = root
        while not cursor.exists():
            missing_directories.append(cursor)
            parent = cursor.parent
            if parent == cursor:
                break
            cursor = parent
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        if root.is_symlink():
            raise ReceiptStoreError("behavioral receipt root cannot be a symlink")
        info = root.stat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid():
            raise ReceiptStoreError("behavioral receipt root ownership is invalid")
        os.chmod(root, 0o700)
        for created_directory in reversed(missing_directories):
            parent_descriptor = os.open(
                created_directory.parent,
                self._directory_flags(),
            )
            try:
                os.fsync(parent_descriptor)
            finally:
                os.close(parent_descriptor)
        self._assert_storage_anchor(seal=True)
        return root

    @staticmethod
    def _directory_flags() -> int:
        return (
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )

    def _open_root(self, *, create: bool = True) -> int:
        if create:
            root = self._prepare_root()
        else:
            self._assert_storage_anchor()
            root = self._root().expanduser()
            if not root.is_absolute():
                root = Path.cwd() / root
        self._assert_storage_anchor()
        descriptor = os.open(root, self._directory_flags())
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_mode & 0o077
        ):
            os.close(descriptor)
            raise ReceiptStoreError("behavioral receipt root attributes are unsafe")
        identity = (metadata.st_dev, metadata.st_ino)
        location = root.resolve(strict=True)
        if self._root_identity is None:
            self._root_identity = identity
            self._root_location = location
        elif identity != self._root_identity or location != self._root_location:
            os.close(descriptor)
            raise ReceiptStoreError("behavioral receipt root changed after admission")
        return descriptor

    def preflight(self) -> None:
        """Verify durable receipt publication is available without reserving work."""

        root_descriptor = self._open_root()
        temporary_name = f".receipt-preflight.{secrets.token_hex(16)}.tmp"
        descriptor = -1
        try:
            descriptor = os.open(
                temporary_name,
                self._exclusive_flags(),
                0o600,
                dir_fd=root_descriptor,
            )
            os.fchmod(descriptor, 0o600)
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = -1
            os.unlink(temporary_name, dir_fd=root_descriptor)
            os.fsync(root_descriptor)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            try:
                os.unlink(temporary_name, dir_fd=root_descriptor)
            except FileNotFoundError:
                pass
            os.close(root_descriptor)

    def _path(self, fingerprint: str) -> Path:
        if not re_full_sha256(fingerprint):
            raise ValueError("fingerprint must be a lowercase SHA-256 hex digest")
        return self._root() / f"behavioral-{fingerprint}.json"

    @staticmethod
    def _filename(fingerprint: str) -> str:
        if not re_full_sha256(fingerprint):
            raise ValueError("fingerprint must be a lowercase SHA-256 hex digest")
        return f"behavioral-{fingerprint}.json"

    @staticmethod
    def _fsync_directory(root: Path) -> None:
        descriptor = os.open(root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    @staticmethod
    def _exclusive_flags() -> int:
        return (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )

    @classmethod
    def _link_exclusive(cls, path: Path, payload: str) -> None:
        """Publish a fully written receipt without exposing a partial final file."""
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{path.name}.", suffix=".reserve", dir=path.parent
        )
        temporary = Path(temporary_name)
        try:
            os.fchmod(descriptor, 0o600)
            handle = os.fdopen(descriptor, "w", encoding="utf-8")
            descriptor = -1
            with handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.link(temporary, path, follow_symlinks=False)
        except BaseException:
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            raise
        finally:
            try:
                temporary.unlink()
            except OSError:
                pass

    @classmethod
    def _write_exclusive_at(
        cls,
        root_descriptor: int,
        name: str,
        payload: str,
    ) -> None:
        descriptor = os.open(
            name,
            cls._exclusive_flags(),
            0o600,
            dir_fd=root_descriptor,
        )
        try:
            handle = os.fdopen(descriptor, "w", encoding="utf-8")
            descriptor = -1
            with handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
        except BaseException:
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            try:
                os.unlink(name, dir_fd=root_descriptor)
            except OSError:
                pass
            raise

    @classmethod
    def _atomic_replace_at(
        cls,
        root_descriptor: int,
        name: str,
        payload: str,
    ) -> None:
        temporary_name = f".{name}.{secrets.token_hex(16)}.tmp"
        descriptor = -1
        try:
            descriptor = os.open(
                temporary_name,
                cls._exclusive_flags(),
                0o600,
                dir_fd=root_descriptor,
            )
            handle = os.fdopen(descriptor, "w", encoding="utf-8")
            descriptor = -1
            with handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(
                temporary_name,
                name,
                src_dir_fd=root_descriptor,
                dst_dir_fd=root_descriptor,
            )
        except BaseException:
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            try:
                os.unlink(temporary_name, dir_fd=root_descriptor)
            except OSError:
                pass
            raise

    @classmethod
    def _link_exclusive_at(
        cls,
        root_descriptor: int,
        name: str,
        payload: str,
    ) -> None:
        temporary_name = f".{name}.{secrets.token_hex(16)}.reserve"
        descriptor = -1
        try:
            descriptor = os.open(
                temporary_name,
                cls._exclusive_flags(),
                0o600,
                dir_fd=root_descriptor,
            )
            handle = os.fdopen(descriptor, "w", encoding="utf-8")
            descriptor = -1
            with handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.link(
                temporary_name,
                name,
                src_dir_fd=root_descriptor,
                dst_dir_fd=root_descriptor,
                follow_symlinks=False,
            )
        except BaseException:
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            raise
        finally:
            try:
                os.unlink(temporary_name, dir_fd=root_descriptor)
            except OSError:
                pass

    @staticmethod
    def _validate_file_info(info: os.stat_result) -> None:
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_size > _MAX_RECEIPT_BYTES
        ):
            raise ReceiptStoreError("behavioral receipt file attributes are unsafe")

    def load(self, fingerprint: str) -> Optional[BehavioralExecutionReceipt]:
        name = self._filename(fingerprint)
        root_descriptor = -1
        descriptor = -1
        try:
            root_descriptor = self._open_root(create=False)
            descriptor = os.open(
                name,
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=root_descriptor,
            )
        except FileNotFoundError:
            if root_descriptor >= 0:
                os.close(root_descriptor)
            return None
        except OSError as exc:
            if root_descriptor >= 0:
                os.close(root_descriptor)
            raise ReceiptStoreError("behavioral receipt cannot be opened safely") from exc
        try:
            self._validate_file_info(os.fstat(descriptor))
            handle = os.fdopen(descriptor, "r", encoding="utf-8")
            descriptor = -1
            with handle:
                value = json.load(
                    handle,
                    object_pairs_hook=_reject_duplicate_json_keys,
                )
        except ReceiptStoreError:
            raise
        except (OSError, ValueError, TypeError) as exc:
            raise ReceiptStoreError("behavioral receipt cannot be read safely") from exc
        finally:
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            if root_descriptor >= 0:
                os.close(root_descriptor)
        if not isinstance(value, Mapping):
            raise ReceiptStoreError("behavioral receipt root is invalid")
        return BehavioralExecutionReceipt.from_dict(value)

    def reserve(
        self, fingerprint: str, *, context: BehavioralReceiptContext
    ) -> ReceiptReservation:
        if not isinstance(context, BehavioralReceiptContext):
            raise TypeError("context must be a BehavioralReceiptContext")
        name = self._filename(fingerprint)
        root_descriptor = self._open_root()
        now = time.time()
        reservation_token = secrets.token_hex(32)
        receipt = BehavioralExecutionReceipt(
            receipt_id=f"behavioral-{fingerprint}",
            fingerprint=fingerprint,
            state=RESERVED,
            context=context,
            created_at=now,
            updated_at=now,
            reservation_hash=hashlib.sha256(reservation_token.encode()).hexdigest(),
        )
        payload = json.dumps(receipt.to_dict(), sort_keys=True, separators=(",", ":"))
        try:
            self._link_exclusive_at(root_descriptor, name, payload)
        except FileExistsError:
            existing = self.load(fingerprint)
            if existing is None:
                raise ReceiptStoreError("behavioral receipt reservation disappeared")
            return ReceiptReservation(False, existing)
        finally:
            os.fsync(root_descriptor)
            os.close(root_descriptor)
        return ReceiptReservation(True, receipt, reservation_token)

    def _advance(
        self,
        fingerprint: str,
        *,
        reservation_token: str,
        state: str,
        outcome: Optional[Mapping[str, Any]] = None,
        abort_reason: Optional[str] = None,
        terminal_evidence: Optional[Mapping[str, Any]] = None,
    ) -> BehavioralExecutionReceipt:
        if state not in {COMPLETED, ABORTED}:
            raise ValueError("receipt terminal state is invalid")
        if not isinstance(reservation_token, str) or not reservation_token:
            raise ReceiptStoreError("behavioral receipt reservation token is required")
        name = self._filename(fingerprint)
        root_descriptor = self._open_root()
        lock_name = f".{name}.transition"
        try:
            self._write_exclusive_at(root_descriptor, lock_name, "")
        except FileExistsError as exc:
            os.close(root_descriptor)
            raise ReceiptStoreError(
                "behavioral receipt transition is already in progress"
            ) from exc
        except BaseException:
            os.close(root_descriptor)
            raise
        try:
            current = self.load(fingerprint)
            if current is None:
                raise ReceiptStoreError("behavioral receipt was not reserved")
            if current.state != RESERVED or current.reservation_hash is None:
                raise ReceiptStoreError("behavioral receipt is already terminal")
            supplied_hash = hashlib.sha256(reservation_token.encode()).hexdigest()
            if not hmac.compare_digest(current.reservation_hash, supplied_hash):
                raise ReceiptStoreError("behavioral receipt reservation token mismatch")

            normalized_outcome = (
                _redacted_stored_outcome(outcome) if outcome is not None else None
            )
            normalized_reason = abort_reason
            normalized_terminal_evidence = (
                redacted_terminal_evidence(terminal_evidence)
                if terminal_evidence is not None
                else None
            )
            if state == COMPLETED:
                if normalized_outcome is None:
                    raise ReceiptStoreError(
                        "completed receipt requires a redacted outcome"
                    )
                if normalized_terminal_evidence is not None:
                    raise ReceiptStoreError(
                        "completed receipt cannot contain terminal denial evidence"
                    )
            if state == ABORTED:
                if (
                    not isinstance(normalized_reason, str)
                    or _ABORT_REASON.fullmatch(normalized_reason) is None
                ):
                    raise ReceiptStoreError("behavioral receipt abort reason is invalid")
                if normalized_outcome is not None:
                    raise ReceiptStoreError("aborted receipt cannot contain an outcome")

            updated = BehavioralExecutionReceipt(
                receipt_id=current.receipt_id,
                fingerprint=current.fingerprint,
                state=state,
                context=current.context,
                created_at=current.created_at,
                updated_at=time.time(),
                outcome=normalized_outcome,
                abort_reason=normalized_reason,
                terminal_evidence=normalized_terminal_evidence,
            )
            self._atomic_replace_at(
                root_descriptor,
                name,
                json.dumps(updated.to_dict(), sort_keys=True, separators=(",", ":")),
            )
            os.fsync(root_descriptor)
            return updated
        finally:
            try:
                os.unlink(lock_name, dir_fd=root_descriptor)
                os.fsync(root_descriptor)
            except FileNotFoundError:
                pass
            os.close(root_descriptor)

    def complete(
        self,
        fingerprint: str,
        *,
        reservation_token: str,
        outcome: Mapping[str, Any],
    ) -> BehavioralExecutionReceipt:
        return self._advance(
            fingerprint,
            reservation_token=reservation_token,
            state=COMPLETED,
            outcome=outcome,
        )

    def abort(
        self,
        fingerprint: str,
        *,
        reservation_token: str,
        reason: str,
        terminal_evidence: Optional[Mapping[str, Any]] = None,
    ) -> BehavioralExecutionReceipt:
        return self._advance(
            fingerprint,
            reservation_token=reservation_token,
            state=ABORTED,
            abort_reason=reason,
            terminal_evidence=terminal_evidence,
        )
