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
from typing import Any, Dict, Mapping, Optional

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
        if state == RESERVED:
            if (
                not isinstance(reservation_hash, str)
                or not re_full_sha256(reservation_hash)
                or outcome is not None
                or abort_reason is not None
            ):
                raise ReceiptStoreError("behavioral reserved receipt is invalid")
        elif reservation_hash is not None:
            raise ReceiptStoreError("behavioral terminal receipt retained a reservation")

        normalized_outcome: Optional[Dict[str, Any]] = None
        normalized_reason: Optional[str] = None
        if state == COMPLETED:
            if not isinstance(outcome, Mapping) or abort_reason is not None:
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
    return {
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
        or budget["cross_object_reads"] != 0
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
        **counters,
        "provenance_root": provenance_root,
        "budget_snapshot": budget,
    }
    if all(state_ref_presence):
        output.update(
            {
                key: item
                for key, (item, _pattern) in state_refs.items()
            }
        )
    return output


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
            or value.get("reason_code")
            != "legacy_acquisition_receipt_missing_state_refs"
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
    return output


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
    return {
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


def redacted_outcome(response: Mapping[str, Any]) -> Dict[str, Any]:
    """Return the only response fields permitted in a durable receipt."""
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
            return redacted_fresh_omission_confirmation_outcome(
                admission_execution
            )
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
    return output


def _redacted_stored_outcome(value: Mapping[str, Any]) -> Dict[str, Any]:
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

    def _root(self) -> Path:
        if self.root is not None:
            return self.root
        override = os.environ.get(RECEIPT_ENV)
        if override:
            return Path(override)
        return Path.home() / ".sentinelforge" / "behavioral_receipts"

    def _prepare_root(self) -> Path:
        root = self._root()
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        if root.is_symlink():
            raise ReceiptStoreError("behavioral receipt root cannot be a symlink")
        info = root.stat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid():
            raise ReceiptStoreError("behavioral receipt root ownership is invalid")
        os.chmod(root, 0o700)
        return root

    def _path(self, fingerprint: str) -> Path:
        if not re_full_sha256(fingerprint):
            raise ValueError("fingerprint must be a lowercase SHA-256 hex digest")
        return self._root() / f"behavioral-{fingerprint}.json"

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
    def _write_exclusive(cls, path: Path, payload: str) -> None:
        descriptor = os.open(path, cls._exclusive_flags(), 0o600)
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
                path.unlink()
            except OSError:
                pass
            raise

    @classmethod
    def _atomic_replace(cls, path: Path, payload: str) -> None:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
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
            os.replace(temporary, path)
        except BaseException:
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            try:
                temporary.unlink()
            except OSError:
                pass
            raise

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
        path = self._path(fingerprint)
        descriptor = -1
        try:
            descriptor = os.open(
                path,
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
            )
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise ReceiptStoreError("behavioral receipt cannot be opened safely") from exc
        try:
            self._validate_file_info(os.fstat(descriptor))
            handle = os.fdopen(descriptor, "r", encoding="utf-8")
            descriptor = -1
            with handle:
                value = json.load(handle)
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
        if not isinstance(value, Mapping):
            raise ReceiptStoreError("behavioral receipt root is invalid")
        return BehavioralExecutionReceipt.from_dict(value)

    def reserve(
        self, fingerprint: str, *, context: BehavioralReceiptContext
    ) -> ReceiptReservation:
        if not isinstance(context, BehavioralReceiptContext):
            raise TypeError("context must be a BehavioralReceiptContext")
        root = self._prepare_root()
        path = self._path(fingerprint)
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
            self._link_exclusive(path, payload)
        except FileExistsError:
            existing = self.load(fingerprint)
            if existing is None:
                raise ReceiptStoreError("behavioral receipt reservation disappeared")
            return ReceiptReservation(False, existing)
        self._fsync_directory(root)
        return ReceiptReservation(True, receipt, reservation_token)

    def _advance(
        self,
        fingerprint: str,
        *,
        reservation_token: str,
        state: str,
        outcome: Optional[Mapping[str, Any]] = None,
        abort_reason: Optional[str] = None,
    ) -> BehavioralExecutionReceipt:
        if state not in {COMPLETED, ABORTED}:
            raise ValueError("receipt terminal state is invalid")
        if not isinstance(reservation_token, str) or not reservation_token:
            raise ReceiptStoreError("behavioral receipt reservation token is required")
        path = self._path(fingerprint)
        root = self._prepare_root()
        lock_path = root / f".{path.name}.transition"
        try:
            self._write_exclusive(lock_path, "")
        except FileExistsError as exc:
            raise ReceiptStoreError("behavioral receipt transition is already in progress") from exc
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
            if state == COMPLETED and normalized_outcome is None:
                raise ReceiptStoreError("completed receipt requires a redacted outcome")
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
            )
            self._atomic_replace(
                path,
                json.dumps(updated.to_dict(), sort_keys=True, separators=(",", ":")),
            )
            self._fsync_directory(root)
            return updated
        finally:
            try:
                lock_path.unlink()
                self._fsync_directory(root)
            except FileNotFoundError:
                pass

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
        self, fingerprint: str, *, reservation_token: str, reason: str
    ) -> BehavioralExecutionReceipt:
        return self._advance(
            fingerprint,
            reservation_token=reservation_token,
            state=ABORTED,
            abort_reason=reason,
        )
