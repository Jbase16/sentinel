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
_VALID_RUN_STATUSES = frozenset({"completed", "aborted", "no_executable_candidate"})
_VALID_EXECUTION_STATUSES = frozenset({"completed", "aborted"})
_VALID_EXPLORATION_STATUSES = frozenset(
    {"completed", "disabled", "failed", "not_needed"}
)
_VALID_COMPILED_STATUSES = frozenset({"completed", "aborted", "cleanup_failed"})
_VALID_LEGACY_VERDICTS = frozenset(
    {"BOLA_CONFIRMED", "DENIED", "NO_CROSS_READ", "AMBIGUOUS", "ERROR"}
)
_PROPOSAL_REF = re.compile(r"^authorization_proposal:[0-9a-f]{64}$")
_COMPILED_SEQUENCE_REF = re.compile(r"^controlled_runtime_sequence:[0-9a-f]{64}$")
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


def redacted_outcome(response: Mapping[str, Any]) -> Dict[str, Any]:
    """Return the only response fields permitted in a durable receipt."""
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
    return output


def _redacted_stored_outcome(value: Mapping[str, Any]) -> Dict[str, Any]:
    if value.get("kind") == "compiled_sequence":
        return redacted_compiled_outcome(value)
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
