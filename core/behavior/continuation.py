"""Bounded continuation decisions over receipt-backed behavioral rounds.

This module has no transport and grants no authority by itself. It permits the
Foundry coordinator to ask for at most one second proof only after the first
terminal receipt strictly reduces the unresolved obligation frontier.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Any, Dict, Sequence, Tuple

from core.foundry.authorization import AuthorizationEnvelope

from .closure import BLOCKED, CONDITIONALLY_CLOSED, FINDING, OPEN
from .normalize import stable_hash
from .orchestrator import BehavioralShadowRun
from .resolver import ClosedLoopResolverPlan, ClosedLoopResolverRun
from .scheduler import PRIMARY_ENV

CONTINUATION_ENV = "SENTINELFORGE_BEHAVIOR_CONTINUATION"
CONTINUATION_WORKFLOW = "behavioral_bounded_continuation"
BOUNDED_CONTINUATION_MODE = "behavioral_bounded_continuation_v1"
MAX_CONTINUATION_ROUNDS = 2
MAX_CONTINUATION_PROOF_REQUESTS = 14
_TRUE = frozenset({"1", "true", "yes", "on"})
_HASH_REF = re.compile(r"^[a-z][a-z0-9_]*:[0-9a-f]{64}$")
_RECEIPT_REF = re.compile(r"^behavioral_receipt:[0-9a-f]{64}$")
_STOP_REASONS = frozenset(
    {
        "finding_confirmed",
        "cleanup_uncertain",
        "execution_aborted",
        "frontier_blocked",
        "frontier_closed",
        "round_limit_reached",
        "proof_request_limit_reached",
        "frontier_progress_missing",
        "repeated_obligation",
        "repeated_resolution",
        "no_executable_candidate",
    }
)


class BoundedContinuationDenied(RuntimeError):
    """Continuation authority or its deterministic contract was refused."""


def _hash_ref(value: Any, prefix: str) -> bool:
    return (
        isinstance(value, str)
        and value.startswith(f"{prefix}:")
        and _HASH_REF.fullmatch(value) is not None
    )


@dataclass(frozen=True)
class BoundedContinuationConfig:
    enabled: bool = False
    max_rounds: int = MAX_CONTINUATION_ROUNDS
    max_proof_requests: int = MAX_CONTINUATION_PROOF_REQUESTS

    def __post_init__(self) -> None:
        if (
            not isinstance(self.enabled, bool)
            or self.max_rounds != MAX_CONTINUATION_ROUNDS
            or self.max_proof_requests != MAX_CONTINUATION_PROOF_REQUESTS
        ):
            raise ValueError("bounded continuation config must use fixed safety limits")

    @classmethod
    def from_environment(cls) -> "BoundedContinuationConfig":
        primary = os.environ.get(PRIMARY_ENV, "").strip().lower() in _TRUE
        continuation = os.environ.get(CONTINUATION_ENV, "").strip().lower() in _TRUE
        return cls(enabled=primary and continuation)

    def authorize(
        self,
        envelope: AuthorizationEnvelope,
        *,
        target_origin: str,
    ) -> None:
        if not self.enabled:
            return
        try:
            envelope.authorize_action(
                target_origin=target_origin,
                workflow=CONTINUATION_WORKFLOW,
            )
        except Exception as exc:
            raise BoundedContinuationDenied(
                "bounded_continuation_authorization_denied"
            ) from exc


@dataclass(frozen=True)
class ContinuationRound:
    round_index: int
    receipt_ref: str
    obligation_id: str
    resolution_kind: str
    resolution_ref: str
    plan_id: str
    shadow_before_id: str
    shadow_after_id: str
    closure_before_id: str
    closure_after_id: str
    status: str
    legacy_verdict: str
    finding_confirmed: bool
    requests_attempted: int
    requests_sent: int
    cleanup_uncertain: bool

    def __post_init__(self) -> None:
        counters = (self.requests_attempted, self.requests_sent)
        if (
            isinstance(self.round_index, bool)
            or not isinstance(self.round_index, int)
            or not 1 <= self.round_index <= MAX_CONTINUATION_ROUNDS
            or _RECEIPT_REF.fullmatch(self.receipt_ref) is None
            or not _hash_ref(self.obligation_id, "security_obligation")
            or self.resolution_kind
            not in {"authorization_proposal", "owned_experiment"}
            or not _hash_ref(self.resolution_ref, self.resolution_kind)
            or not _hash_ref(self.plan_id, "closed_loop_resolver_plan")
            or not _hash_ref(self.shadow_before_id, "behavioral_shadow_run")
            or not _hash_ref(self.shadow_after_id, "behavioral_shadow_run")
            or not _hash_ref(self.closure_before_id, "security_closure_certificate")
            or not _hash_ref(self.closure_after_id, "security_closure_certificate")
            or self.status not in {"completed", "aborted", "cleanup_failed"}
            or self.legacy_verdict
            not in {"BOLA_CONFIRMED", "DENIED", "NO_CROSS_READ", "AMBIGUOUS", "ERROR"}
            or not isinstance(self.finding_confirmed, bool)
            or (self.legacy_verdict == "BOLA_CONFIRMED")
            != self.finding_confirmed
            or any(
                isinstance(value, bool) or not isinstance(value, int) or value < 0
                for value in counters
            )
            or self.requests_sent > self.requests_attempted
            or not isinstance(self.cleanup_uncertain, bool)
            or (self.status == "cleanup_failed" and not self.cleanup_uncertain)
            or (self.status == "completed" and self.cleanup_uncertain)
        ):
            raise ValueError("continuation round contract is invalid")

    @classmethod
    def create(
        cls,
        *,
        round_index: int,
        receipt_fingerprint: str,
        before: BehavioralShadowRun,
        after: BehavioralShadowRun,
        run: ClosedLoopResolverRun,
    ) -> "ContinuationRound":
        selected = run.plan.selected
        execution = run.execution
        if selected is None or execution is None:
            raise BoundedContinuationDenied(
                "continuation_round_requires_terminal_execution"
            )
        orphaned = bool(
            getattr(execution, "orphaned_owned_state_possible", False)
        )
        return cls(
            round_index=round_index,
            receipt_ref=f"behavioral_receipt:{receipt_fingerprint}",
            obligation_id=selected.obligation_id,
            resolution_kind=selected.resolution_kind,
            resolution_ref=selected.resolution_ref,
            plan_id=run.plan.plan_id,
            shadow_before_id=before.run_id,
            shadow_after_id=after.run_id,
            closure_before_id=before.closure.certificate_id,
            closure_after_id=after.closure.certificate_id,
            status=run.status,
            legacy_verdict=execution.legacy_verdict.verdict,
            finding_confirmed=run.finding is not None,
            requests_attempted=execution.requests_attempted,
            requests_sent=execution.requests_sent,
            cleanup_uncertain=run.status == "cleanup_failed" or orphaned,
        )

    def to_dict(self) -> Dict[str, Any]:
        return dict(vars(self))


@dataclass(frozen=True)
class ContinuationDecision:
    continue_execution: bool
    reason: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.continue_execution, bool)
            or self.reason not in _STOP_REASONS | {"continue"}
            or self.continue_execution != (self.reason == "continue")
        ):
            raise ValueError("continuation decision contract is invalid")


def _session_payload(
    *,
    root_fingerprint: str,
    initial_shadow_id: str,
    final_shadow_id: str,
    final_closure_id: str,
    rounds: Sequence[ContinuationRound],
    stop_reason: str,
    total_requests_attempted: int,
    total_requests_sent: int,
) -> Dict[str, Any]:
    return {
        "mode": BOUNDED_CONTINUATION_MODE,
        "root_fingerprint": root_fingerprint,
        "initial_shadow_id": initial_shadow_id,
        "final_shadow_id": final_shadow_id,
        "final_closure_id": final_closure_id,
        "rounds": [item.to_dict() for item in rounds],
        "stop_reason": stop_reason,
        "total_requests_attempted": total_requests_attempted,
        "total_requests_sent": total_requests_sent,
        "max_rounds": MAX_CONTINUATION_ROUNDS,
        "max_proof_requests": MAX_CONTINUATION_PROOF_REQUESTS,
    }


@dataclass(frozen=True)
class BoundedContinuationResult:
    session_id: str
    root_fingerprint: str
    initial_shadow_id: str
    final_shadow_id: str
    final_closure_id: str
    rounds: Tuple[ContinuationRound, ...]
    stop_reason: str
    total_requests_attempted: int
    total_requests_sent: int
    max_rounds: int = MAX_CONTINUATION_ROUNDS
    max_proof_requests: int = MAX_CONTINUATION_PROOF_REQUESTS
    mode: str = BOUNDED_CONTINUATION_MODE
    executable: bool = False

    def __post_init__(self) -> None:
        payload = _session_payload(
            root_fingerprint=self.root_fingerprint,
            initial_shadow_id=self.initial_shadow_id,
            final_shadow_id=self.final_shadow_id,
            final_closure_id=self.final_closure_id,
            rounds=self.rounds,
            stop_reason=self.stop_reason,
            total_requests_attempted=self.total_requests_attempted,
            total_requests_sent=self.total_requests_sent,
        )
        if (
            self.session_id != stable_hash("bounded_continuation_session", payload)
            or self.mode != BOUNDED_CONTINUATION_MODE
            or self.executable
            or len(self.root_fingerprint) != 64
            or any(character not in "0123456789abcdef" for character in self.root_fingerprint)
            or not _hash_ref(self.initial_shadow_id, "behavioral_shadow_run")
            or not _hash_ref(self.final_shadow_id, "behavioral_shadow_run")
            or not _hash_ref(
                self.final_closure_id,
                "security_closure_certificate",
            )
            or not 0 <= len(self.rounds) <= MAX_CONTINUATION_ROUNDS
            or tuple(item.round_index for item in self.rounds)
            != tuple(range(1, len(self.rounds) + 1))
            or len({item.receipt_ref for item in self.rounds}) != len(self.rounds)
            or len({item.obligation_id for item in self.rounds}) != len(self.rounds)
            or len({item.resolution_ref for item in self.rounds}) != len(self.rounds)
            or self.stop_reason not in _STOP_REASONS
            or self.total_requests_attempted
            != sum(item.requests_attempted for item in self.rounds)
            or self.total_requests_sent != sum(item.requests_sent for item in self.rounds)
            or self.total_requests_sent > self.total_requests_attempted
            or self.total_requests_attempted > MAX_CONTINUATION_PROOF_REQUESTS
            or self.max_rounds != MAX_CONTINUATION_ROUNDS
            or self.max_proof_requests != MAX_CONTINUATION_PROOF_REQUESTS
        ):
            raise ValueError("bounded continuation result contract is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": 1,
            "session_id": self.session_id,
            **_session_payload(
                root_fingerprint=self.root_fingerprint,
                initial_shadow_id=self.initial_shadow_id,
                final_shadow_id=self.final_shadow_id,
                final_closure_id=self.final_closure_id,
                rounds=self.rounds,
                stop_reason=self.stop_reason,
                total_requests_attempted=self.total_requests_attempted,
                total_requests_sent=self.total_requests_sent,
            ),
            "executable": self.executable,
        }


class BoundedContinuationController:
    """Admit one next round only after exact receipt-backed frontier progress."""

    def __init__(self, config: BoundedContinuationConfig) -> None:
        if not isinstance(config, BoundedContinuationConfig):
            raise TypeError("config must be a BoundedContinuationConfig")
        self.config = config

    @staticmethod
    def _cost(plan: ClosedLoopResolverPlan) -> int:
        selected = plan.selected
        if selected is None:
            return 0
        return 7 if selected.resolution_kind == "owned_experiment" else 3

    def admit_plan(
        self,
        rounds: Sequence[ContinuationRound],
        plan: ClosedLoopResolverPlan,
    ) -> ContinuationDecision:
        if not self.config.enabled:
            return ContinuationDecision(False, "round_limit_reached")
        if plan.selected is None:
            return ContinuationDecision(False, "no_executable_candidate")
        if len(rounds) >= self.config.max_rounds:
            return ContinuationDecision(False, "round_limit_reached")
        selected = plan.selected
        if selected.obligation_id in {item.obligation_id for item in rounds}:
            return ContinuationDecision(False, "repeated_obligation")
        if selected.resolution_ref in {item.resolution_ref for item in rounds}:
            return ContinuationDecision(False, "repeated_resolution")
        attempted = sum(item.requests_attempted for item in rounds)
        if attempted + self._cost(plan) > self.config.max_proof_requests:
            return ContinuationDecision(False, "proof_request_limit_reached")
        return ContinuationDecision(True, "continue")

    def after_round(
        self,
        rounds: Sequence[ContinuationRound],
        *,
        before: BehavioralShadowRun,
        after: BehavioralShadowRun,
    ) -> ContinuationDecision:
        if not rounds:
            raise BoundedContinuationDenied("continuation_round_history_is_empty")
        latest = rounds[-1]
        if (
            latest.shadow_before_id != before.run_id
            or latest.shadow_after_id != after.run_id
        ):
            raise BoundedContinuationDenied("continuation_round_shadow_binding_changed")
        if latest.cleanup_uncertain:
            return ContinuationDecision(False, "cleanup_uncertain")
        if latest.finding_confirmed:
            return ContinuationDecision(False, "finding_confirmed")
        if latest.status != "completed":
            return ContinuationDecision(False, "execution_aborted")
        if after.closure.status == FINDING:
            return ContinuationDecision(False, "finding_confirmed")
        if after.closure.status == BLOCKED:
            return ContinuationDecision(False, "frontier_blocked")
        if after.closure.status == CONDITIONALLY_CLOSED:
            return ContinuationDecision(False, "frontier_closed")
        if len(rounds) >= self.config.max_rounds:
            return ContinuationDecision(False, "round_limit_reached")
        if sum(item.requests_attempted for item in rounds) >= self.config.max_proof_requests:
            return ContinuationDecision(False, "proof_request_limit_reached")
        before_unresolved = set(before.closure.unresolved_ids)
        after_unresolved = set(after.closure.unresolved_ids)
        if (
            after.closure.status != OPEN
            or after.graph.graph_digest != before.graph.graph_digest
            or latest.obligation_id in after_unresolved
            or not after_unresolved < before_unresolved
        ):
            return ContinuationDecision(False, "frontier_progress_missing")
        return ContinuationDecision(True, "continue")

    def finish(
        self,
        *,
        root_fingerprint: str,
        initial: BehavioralShadowRun,
        final: BehavioralShadowRun,
        rounds: Sequence[ContinuationRound],
        stop_reason: str,
    ) -> BoundedContinuationResult:
        ordered = tuple(rounds)
        latest = ordered[-1] if ordered else None
        stop_valid = (
            (stop_reason == "no_executable_candidate")
            or (
                stop_reason == "finding_confirmed"
                and latest is not None
                and latest.finding_confirmed
            )
            or (
                stop_reason == "cleanup_uncertain"
                and latest is not None
                and latest.cleanup_uncertain
            )
            or (
                stop_reason == "execution_aborted"
                and latest is not None
                and latest.status == "aborted"
            )
            or (stop_reason == "frontier_blocked" and final.closure.status == BLOCKED)
            or (
                stop_reason == "frontier_closed"
                and final.closure.status == CONDITIONALLY_CLOSED
            )
            or (
                stop_reason == "round_limit_reached"
                and len(ordered) == self.config.max_rounds
            )
            or stop_reason
            in {
                "proof_request_limit_reached",
                "frontier_progress_missing",
                "repeated_obligation",
                "repeated_resolution",
            }
        )
        if not stop_valid or (not ordered and stop_reason != "no_executable_candidate"):
            raise BoundedContinuationDenied(
                "continuation_stop_reason_is_inconsistent"
            )
        attempted = sum(item.requests_attempted for item in ordered)
        sent = sum(item.requests_sent for item in ordered)
        payload = _session_payload(
            root_fingerprint=root_fingerprint,
            initial_shadow_id=initial.run_id,
            final_shadow_id=final.run_id,
            final_closure_id=final.closure.certificate_id,
            rounds=ordered,
            stop_reason=stop_reason,
            total_requests_attempted=attempted,
            total_requests_sent=sent,
        )
        return BoundedContinuationResult(
            session_id=stable_hash("bounded_continuation_session", payload),
            root_fingerprint=root_fingerprint,
            initial_shadow_id=initial.run_id,
            final_shadow_id=final.run_id,
            final_closure_id=final.closure.certificate_id,
            rounds=ordered,
            stop_reason=stop_reason,
            total_requests_attempted=attempted,
            total_requests_sent=sent,
        )


__all__ = [
    "BOUNDED_CONTINUATION_MODE",
    "CONTINUATION_ENV",
    "CONTINUATION_WORKFLOW",
    "BoundedContinuationConfig",
    "BoundedContinuationController",
    "BoundedContinuationDenied",
    "BoundedContinuationResult",
    "ContinuationDecision",
    "ContinuationRound",
]
