"""Default-off ordinary-click sequencing over existing Foundry family entries.

The coordinator grants no execution authority.  It constructs the same public
Foundry request used by the ordinary Scan path, once for Family A and once for
each profile-selected family among B, C, and D.  Native results remain the
authority for verdict and cleanup truth; only a bounded, sanitized summary is
serialized.
"""

from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass, replace
from enum import StrEnum
from typing import Any, Awaitable, Callable, Mapping, Optional

from fastapi import HTTPException

from core.server.routers.foundry import RunBehavioralAuthorizationFromURLRequest


ORDINARY_CLICK_ORCHESTRATION_ENV = "SENTINELFORGE_ORDINARY_CLICK_ORCHESTRATION"
ORDINARY_CLICK_ORCHESTRATION_MODE = "ordinary_click_orchestration_v1"
_TRUE = frozenset({"1", "true", "yes", "on"})


class BoundedOrchestrationState(StrEnum):
    OBSERVING = "observing"
    ACQUIRING = "acquiring"
    BLOCKED = "blocked"
    PROVING = "proving"
    CLEANING = "cleaning"
    CONFIRMED = "confirmed"
    EXHAUSTED = "exhausted"
    INCOMPLETE = "incomplete"


BOUNDED_ORCHESTRATION_STATES = frozenset(BoundedOrchestrationState)


class OrdinaryClickFamily(StrEnum):
    A = "A"
    B = "B"
    C = "C"
    D = "D"


@dataclass(frozen=True)
class OrdinaryClickOrchestrationConfig:
    enabled: bool = False

    def __post_init__(self) -> None:
        if type(self.enabled) is not bool:
            raise TypeError("ordinary-click orchestration enabled must be boolean")

    @classmethod
    def from_environment(cls) -> "OrdinaryClickOrchestrationConfig":
        return cls(
            enabled=(
                str(os.environ.get(ORDINARY_CLICK_ORCHESTRATION_ENV, ""))
                .strip()
                .lower()
                in _TRUE
            )
        )


@dataclass(frozen=True)
class CleanupReport:
    status: Optional[str]
    orphaned_owned_state_possible: bool
    attention_required: bool

    def __post_init__(self) -> None:
        if (
            (self.status is not None and not _safe_token(self.status))
            or type(self.orphaned_owned_state_possible) is not bool
            or type(self.attention_required) is not bool
            or self.attention_required
            != (
                self.orphaned_owned_state_possible
                or self.status in {"failed", "uncertain", "cleanup_failed"}
            )
        ):
            raise ValueError("ordinary-click cleanup report is invalid")

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "orphaned_owned_state_possible": (self.orphaned_owned_state_possible),
            "attention_required": self.attention_required,
        }


@dataclass(frozen=True)
class CandidateHandoff:
    finding_id: str
    candidate_digest: str
    reproduction_kind: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.finding_id, str)
            or not self.finding_id
            or len(self.finding_id) > 256
            or not isinstance(self.candidate_digest, str)
            or not self.candidate_digest.startswith("submission_candidate:")
            or self.reproduction_kind
            not in {"replayable_recipe", "evidence_attestation"}
        ):
            raise ValueError("ordinary-click candidate handoff is invalid")

    def to_dict(self) -> dict[str, str]:
        return {
            "finding_id": self.finding_id,
            "candidate_digest": self.candidate_digest,
            "reproduction_kind": self.reproduction_kind,
        }


@dataclass(frozen=True)
class FamilyPassResult:
    family: OrdinaryClickFamily
    applicable: bool
    attempted: bool
    native_status: Optional[str] = None
    receipt_kind: Optional[str] = None
    oracle_verdict: Optional[str] = None
    cleanup: Optional[CleanupReport] = None
    terminal: bool = False
    blocked: bool = False
    incomplete: bool = False
    failure_code: Optional[str] = None
    candidate: Optional[CandidateHandoff] = None

    def __post_init__(self) -> None:
        if not isinstance(self.family, OrdinaryClickFamily):
            raise TypeError("ordinary-click family is invalid")
        if any(
            type(value) is not bool
            for value in (
                self.applicable,
                self.attempted,
                self.terminal,
                self.blocked,
                self.incomplete,
            )
        ):
            raise TypeError("ordinary-click family state is invalid")
        tokens = (
            self.native_status,
            self.receipt_kind,
            self.oracle_verdict,
            self.failure_code,
        )
        if any(value is not None and not _safe_token(value) for value in tokens):
            raise ValueError("ordinary-click family status is invalid")
        if not self.applicable and (
            self.attempted
            or self.native_status is not None
            or self.receipt_kind is not None
            or self.oracle_verdict is not None
            or self.cleanup is not None
            or self.terminal
            or self.blocked
            or self.incomplete
            or self.failure_code is not None
            or self.candidate is not None
        ):
            raise ValueError("non-applicable family cannot claim execution")
        if self.candidate is not None and not self.attempted:
            raise ValueError("candidate handoff requires an attempted family")

    @property
    def finding_confirmed(self) -> bool:
        return self.candidate is not None

    def to_dict(self) -> dict[str, Any]:
        return {
            "family": self.family.value,
            "applicable": self.applicable,
            "attempted": self.attempted,
            "native_status": self.native_status,
            "receipt_kind": self.receipt_kind,
            "oracle_verdict": self.oracle_verdict,
            "cleanup": self.cleanup.to_dict() if self.cleanup is not None else None,
            "terminal": self.terminal,
            "finding_confirmed": self.finding_confirmed,
            "failure_code": self.failure_code,
            "candidate": (
                self.candidate.to_dict() if self.candidate is not None else None
            ),
        }


@dataclass(frozen=True)
class OrdinaryClickOrchestrationResult:
    status: BoundedOrchestrationState
    state_trace: tuple[BoundedOrchestrationState, ...]
    families: tuple[FamilyPassResult, ...]
    mode: str = ORDINARY_CLICK_ORCHESTRATION_MODE

    def __post_init__(self) -> None:
        if (
            not isinstance(self.status, BoundedOrchestrationState)
            or self.status
            not in {
                BoundedOrchestrationState.BLOCKED,
                BoundedOrchestrationState.CONFIRMED,
                BoundedOrchestrationState.EXHAUSTED,
                BoundedOrchestrationState.INCOMPLETE,
            }
            or not self.state_trace
            or self.state_trace[-1] is not self.status
            or any(
                item not in BOUNDED_ORCHESTRATION_STATES for item in self.state_trace
            )
            or tuple(item.family for item in self.families)
            != tuple(OrdinaryClickFamily)
            or self.mode != ORDINARY_CLICK_ORCHESTRATION_MODE
        ):
            raise ValueError("ordinary-click orchestration result is invalid")

    def to_dict(self) -> dict[str, Any]:
        result = {
            "schema_version": 1,
            "mode": self.mode,
            "status": self.status.value,
            "state_trace": [item.value for item in self.state_trace],
            "families": [item.to_dict() for item in self.families],
            "submission_candidates": [
                item.candidate.to_dict()
                for item in self.families
                if item.candidate is not None
            ],
        }
        if self.status is BoundedOrchestrationState.EXHAUSTED:
            result["exhaustion_kind"] = "sequence_exhausted"
        return result


FamilyExecutor = Callable[
    [RunBehavioralAuthorizationFromURLRequest],
    Awaitable[Mapping[str, Any]],
]
FamilyResultHandler = Callable[
    [OrdinaryClickFamily, Mapping[str, Any]],
    Awaitable[Optional[CandidateHandoff]],
]
StateObserver = Callable[[BoundedOrchestrationState], None]


def _safe_token(value: object) -> bool:
    return bool(
        isinstance(value, str)
        and value
        and len(value) <= 128
        and value == value.strip()
        and all(character.isalnum() or character in {"_", "-"} for character in value)
    )


def _token(value: object) -> Optional[str]:
    if isinstance(value, int) and not isinstance(value, bool):
        return str(value)
    if not isinstance(value, str):
        return None
    normalized = value.strip().lower().replace(" ", "_")
    return normalized if _safe_token(normalized) else None


def _nested_mappings(result: Mapping[str, Any]) -> tuple[Mapping[str, Any], ...]:
    values = [result]
    for key in (
        "execution",
        "one_click_selection",
        "generalized_authorization_one_click",
        "graph_bound_prerequisite_one_click",
        "role_monotonicity_one_click",
        "capability_effect_one_click",
        "capability_effect_evidence",
    ):
        value = result.get(key)
        if isinstance(value, Mapping):
            values.append(value)
    return tuple(values)


def _first_token(result: Mapping[str, Any], field_name: str) -> Optional[str]:
    for value in _nested_mappings(result):
        token = _token(value.get(field_name))
        if token is not None:
            return token
    return None


def _cleanup_report(result: Mapping[str, Any]) -> Optional[CleanupReport]:
    cleanup_values: list[Mapping[str, Any]] = []
    native_values = _nested_mappings(result)
    for value in native_values:
        cleanup = value.get("cleanup")
        if isinstance(cleanup, Mapping):
            cleanup_values.append(cleanup)
    status = None
    orphaned = False
    observed = False
    for value in cleanup_values:
        candidate_status = _token(value.get("status"))
        if status is None and candidate_status is not None:
            status = candidate_status
            observed = True
        candidate_orphaned = value.get("orphaned_owned_state_possible")
        if type(candidate_orphaned) is bool:
            orphaned = orphaned or candidate_orphaned
            observed = True
    for value in native_values:
        candidate_status = _token(value.get("cleanup_status"))
        if status is None and candidate_status is not None:
            status = candidate_status
            observed = True
        candidate_orphaned = value.get("orphaned_owned_state_possible")
        if type(candidate_orphaned) is bool:
            orphaned = orphaned or candidate_orphaned
            observed = True
    if not observed:
        return None
    attention = orphaned or status in {"failed", "uncertain", "cleanup_failed"}
    return CleanupReport(status, orphaned, attention)


def _native_confirmation(result: Mapping[str, Any]) -> bool:
    if isinstance(result.get("finding"), Mapping):
        return True
    if result.get("finding_confirmed") is True:
        return True
    promotion = result.get("capability_effect_promotion")
    return bool(
        isinstance(promotion, Mapping)
        and promotion.get("promotion_state") == "promoted"
        and isinstance(promotion.get("canonical_finding_id"), str)
        and promotion.get("canonical_finding_id")
    )


_INCOMPLETE_STATUSES = frozenset(
    {"aborted", "cleanup_failed", "error", "failed", "inconclusive", "uncertain"}
)
_BLOCKED_STATUS_PARTS = ("blocked", "denied", "disabled", "refused", "unavailable")
_TERMINAL_STATUSES = frozenset(
    {
        "already_executed",
        "canonical_result_inactive",
        "completed",
        "confirmed",
        "confirmed_one_time_authorized_effect",
        "confirmed_active_escalation",
        "confirmed_revocation_survival",
        "no_eligible_candidate",
        "no_executable_candidate",
        "not_eligible",
        "refuted",
    }
)


def _classify_native_result(
    family: OrdinaryClickFamily,
    result: Mapping[str, Any],
) -> FamilyPassResult:
    native_status = _first_token(result, "status")
    receipt_kind = _token(result.get("kind"))
    oracle_verdict = _first_token(result, "oracle_verdict")
    cleanup = _cleanup_report(result)
    status_values = {
        token
        for value in _nested_mappings(result)
        if (token := _token(value.get("status"))) is not None
    }
    promotion = result.get("capability_effect_promotion")
    promotion_state = (
        _token(promotion.get("promotion_state"))
        if isinstance(promotion, Mapping)
        else None
    )
    incomplete = (
        bool(cleanup is not None and cleanup.attention_required)
        or bool(status_values & _INCOMPLETE_STATUSES)
        or promotion_state
        in {
            "retryable_local_persistence_failure",
            "unavailable",
        }
    )
    blocked = any(
        part in status for status in status_values for part in _BLOCKED_STATUS_PARTS
    )
    terminal = bool(
        _native_confirmation(result)
        or blocked
        or incomplete
        or status_values & _TERMINAL_STATUSES
    )
    if not terminal:
        incomplete = True
    return FamilyPassResult(
        family=family,
        applicable=True,
        attempted=True,
        native_status=native_status,
        receipt_kind=receipt_kind,
        oracle_verdict=oracle_verdict,
        cleanup=cleanup,
        terminal=terminal,
        blocked=blocked,
        incomplete=incomplete,
        failure_code=("native_terminal_unknown" if not terminal else None),
    )


def _request_for_family(
    request: RunBehavioralAuthorizationFromURLRequest,
    family: OrdinaryClickFamily,
    *,
    assessment_session_id: str,
) -> RunBehavioralAuthorizationFromURLRequest:
    common = {
        "target_url": request.target_url,
        "envelope_id": request.envelope_id,
        "source_persona_id": request.source_persona_id,
        "peer_persona_id": request.peer_persona_id,
    }
    if family is OrdinaryClickFamily.B:
        common.update(
            prior_source_records=request.prior_source_records,
            prior_peer_records=request.prior_peer_records,
        )
    elif family is OrdinaryClickFamily.C:
        common["role_monotonicity"] = request.role_monotonicity
    elif family is OrdinaryClickFamily.D:
        common["capability_effect"] = request.capability_effect
    family_request = RunBehavioralAuthorizationFromURLRequest(**common)
    family_request._assessment_session_id = assessment_session_id
    return family_request


def _applicable(
    request: RunBehavioralAuthorizationFromURLRequest,
    family: OrdinaryClickFamily,
) -> bool:
    if family is OrdinaryClickFamily.A:
        return True
    if family is OrdinaryClickFamily.B:
        return (
            request.prior_source_records is not None
            and request.prior_peer_records is not None
        )
    if family is OrdinaryClickFamily.C:
        return request.role_monotonicity is not None
    return request.capability_effect is not None


def _terminal_state(
    families: tuple[FamilyPassResult, ...],
) -> BoundedOrchestrationState:
    applicable = tuple(item for item in families if item.applicable)
    if any(item.incomplete for item in applicable):
        return BoundedOrchestrationState.INCOMPLETE
    if any(item.finding_confirmed for item in applicable):
        return BoundedOrchestrationState.CONFIRMED
    if any(item.blocked for item in applicable):
        return BoundedOrchestrationState.BLOCKED
    if applicable and all(item.attempted and item.terminal for item in applicable):
        return BoundedOrchestrationState.EXHAUSTED
    return BoundedOrchestrationState.INCOMPLETE


async def _default_executor(
    request: RunBehavioralAuthorizationFromURLRequest,
) -> Mapping[str, Any]:
    from core.server.routers import foundry

    return await foundry.run_behavioral_authorization_from_url_endpoint(
        request,
        _=True,
    )


async def run_ordinary_click_orchestration(
    request: RunBehavioralAuthorizationFromURLRequest,
    *,
    assessment_session_id: str,
    execute_family: Optional[FamilyExecutor] = None,
    handle_result: Optional[FamilyResultHandler] = None,
    observe_state: Optional[StateObserver] = None,
    config: OrdinaryClickOrchestrationConfig = OrdinaryClickOrchestrationConfig(),
) -> OrdinaryClickOrchestrationResult:
    """Sequence A plus profile-selected native families under one explicit gate."""

    if not isinstance(request, RunBehavioralAuthorizationFromURLRequest):
        raise TypeError("ordinary-click Foundry request is required")
    if not isinstance(config, OrdinaryClickOrchestrationConfig) or not config.enabled:
        raise RuntimeError("ordinary-click orchestration is disabled")
    if not isinstance(assessment_session_id, str) or not assessment_session_id:
        raise ValueError("ordinary-click assessment session is required")
    if execute_family is not None and not callable(execute_family):
        raise TypeError("ordinary-click family executor is invalid")
    if handle_result is not None and not callable(handle_result):
        raise TypeError("ordinary-click result handler is invalid")
    if observe_state is not None and not callable(observe_state):
        raise TypeError("ordinary-click state observer is invalid")

    executor = execute_family or _default_executor
    trace: list[BoundedOrchestrationState] = []

    def emit(state: BoundedOrchestrationState) -> None:
        if not trace or trace[-1] is not state:
            trace.append(state)
            if observe_state is not None:
                observe_state(state)

    emit(BoundedOrchestrationState.OBSERVING)
    families: list[FamilyPassResult] = []
    stop_sequence = False
    for family in OrdinaryClickFamily:
        applies = _applicable(request, family)
        if not applies:
            families.append(FamilyPassResult(family, False, False))
            continue
        if stop_sequence:
            families.append(
                FamilyPassResult(
                    family,
                    True,
                    False,
                    incomplete=True,
                    failure_code="sequence_stopped",
                )
            )
            continue

        emit(BoundedOrchestrationState.ACQUIRING)
        family_request = _request_for_family(
            request,
            family,
            assessment_session_id=assessment_session_id,
        )
        emit(BoundedOrchestrationState.PROVING)
        try:
            native_result = await executor(family_request)
        except asyncio.CancelledError:
            raise
        except HTTPException as exc:
            blocked = 400 <= exc.status_code < 500
            families.append(
                FamilyPassResult(
                    family,
                    True,
                    True,
                    native_status=("refused" if blocked else "failed"),
                    terminal=True,
                    blocked=blocked,
                    incomplete=not blocked,
                    failure_code=f"http_{exc.status_code}",
                )
            )
            stop_sequence = not blocked
            continue
        except Exception:
            families.append(
                FamilyPassResult(
                    family,
                    True,
                    True,
                    native_status="failed",
                    terminal=True,
                    incomplete=True,
                    failure_code="family_call_failed",
                )
            )
            stop_sequence = True
            continue
        if not isinstance(native_result, Mapping):
            families.append(
                FamilyPassResult(
                    family,
                    True,
                    True,
                    native_status="failed",
                    terminal=True,
                    incomplete=True,
                    failure_code="invalid_native_result",
                )
            )
            stop_sequence = True
            continue

        family_result = _classify_native_result(family, native_result)
        if family_result.cleanup is not None:
            emit(BoundedOrchestrationState.CLEANING)
        if _native_confirmation(native_result):
            if (
                family_result.cleanup is not None
                and family_result.cleanup.attention_required
            ):
                family_result = replace(
                    family_result,
                    incomplete=True,
                    failure_code="cleanup_attention_required",
                )
            elif handle_result is None:
                family_result = replace(
                    family_result,
                    incomplete=True,
                    failure_code="candidate_handoff_unavailable",
                )
            else:
                try:
                    candidate = await handle_result(family, native_result)
                except asyncio.CancelledError:
                    raise
                except Exception:
                    candidate = None
                if candidate is None:
                    family_result = replace(
                        family_result,
                        incomplete=True,
                        failure_code="candidate_handoff_failed",
                    )
                else:
                    family_result = replace(family_result, candidate=candidate)
        families.append(family_result)
        if family_result.cleanup is not None and (
            family_result.cleanup.attention_required
        ):
            stop_sequence = True

    family_tuple = tuple(families)
    terminal = _terminal_state(family_tuple)
    emit(terminal)
    return OrdinaryClickOrchestrationResult(
        status=terminal,
        state_trace=tuple(trace),
        families=family_tuple,
    )


def resolve_submission_candidate_handoff(
    *,
    session_id: str,
    finding_id: str,
    workbench_store: Any = None,
    read_model_loader: Optional[Callable[[str], Any]] = None,
) -> CandidateHandoff:
    """Call the existing R7 resolver/builder without adding submission authority."""

    if read_model_loader is None:
        from core.epistemic.ledger import load_canonical_session_read_model

        read_model_loader = load_canonical_session_read_model
    from core.reporting.submission_candidate import resolve_submission_candidate

    read_model = read_model_loader(session_id)
    candidate = resolve_submission_candidate(
        read_model,
        finding_id=finding_id,
        workbench_store=workbench_store,
    )
    return CandidateHandoff(
        finding_id=candidate.finding_id,
        candidate_digest=candidate.candidate_digest,
        reproduction_kind=candidate.reproduction_kind,
    )


__all__ = [
    "BOUNDED_ORCHESTRATION_STATES",
    "ORDINARY_CLICK_ORCHESTRATION_ENV",
    "ORDINARY_CLICK_ORCHESTRATION_MODE",
    "BoundedOrchestrationState",
    "CandidateHandoff",
    "CleanupReport",
    "FamilyPassResult",
    "OrdinaryClickFamily",
    "OrdinaryClickOrchestrationConfig",
    "OrdinaryClickOrchestrationResult",
    "resolve_submission_candidate_handoff",
    "run_ordinary_click_orchestration",
]
