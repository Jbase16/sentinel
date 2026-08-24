"""Default-off R5C5 owned-membership lifecycle probe.

This slice consumes one R5C4 claim and exercises only its setup, revocation, and
revocation-verification actions. The five role-probe/effect slots are released
without transport. Every sent action crosses the ordinary policy, reservation,
provenance, scope, and native-driver seams and must attest the exact retained
browser session. Target responses are interpreted only through the R5C3-bound
membership observation projection. The durable receipt is aborted after cleanup
because the protected-effect oracle has deliberately not run.
"""

from __future__ import annotations

import asyncio
import copy
import hmac
import json
import os
import re
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple

from core.cortex.execution_policy import (
    CandidateAction,
    DENIED_STATUS,
    ExecutionPolicy,
    PolicyExecutor,
)
from core.safety.provenance import ProvenanceSink
from core.wraith.bola_replay import (
    ReplayRequest,
    SNDReplayTransport,
    SessionBoundReplayResponse,
    SessionBoundReplayTransport,
)

from .normalize import stable_hash
from .receipts import ABORTED, BehavioralExecutionReceipt
from .role_execution_claim import (
    RoleMonotonicityExecutionClaim,
    RoleMonotonicityExecutionClaimDenied,
)
from .role_request_binding import (
    RoleMonotonicityRequestBindingContract,
    RoleMonotonicityRuntimeContext,
    RoleRuntimeActionAuthorityBinding,
)


ROLE_MEMBERSHIP_LIFECYCLE_ENV = (
    "SENTINELFORGE_BEHAVIOR_ROLE_MEMBERSHIP_LIFECYCLE"
)
ROLE_MEMBERSHIP_LIFECYCLE_MODE = (
    "behavioral_role_membership_lifecycle_v1"
)

_TRUE = frozenset({"1", "true", "yes", "on"})
_HASH_REF = re.compile(r"^[a-z][a-z0-9_]*:[0-9a-f]{64}$")
_SEMANTIC = re.compile(r"^[a-z][a-z0-9_]{0,127}$")
_REMAINING_EXECUTION_BLOCKERS = ("effect_evaluation_required",)
_MAX_RESPONSE_CHARS = 256 * 1024


def _hash_ref(value: object, prefix: Optional[str] = None) -> bool:
    return (
        isinstance(value, str)
        and _HASH_REF.fullmatch(value) is not None
        and (prefix is None or value.startswith(f"{prefix}:"))
    )


class RoleMembershipLifecycleDenied(RuntimeError):
    """The membership lifecycle was refused, failed, or could not clean up."""

    def __init__(
        self,
        reason: str,
        *,
        category: str = "lifecycle",
        target_request_possible: bool = False,
        cleanup: Optional["RoleMembershipCleanupResult"] = None,
        terminal_receipt: Optional[BehavioralExecutionReceipt] = None,
    ) -> None:
        super().__init__(reason)
        self.category = category
        self.target_request_possible = bool(target_request_possible)
        self.cleanup = cleanup
        if terminal_receipt is not None and (
            not isinstance(terminal_receipt, BehavioralExecutionReceipt)
            or terminal_receipt.state != ABORTED
        ):
            raise ValueError("role membership terminal receipt is invalid")
        self.terminal_receipt = terminal_receipt


@dataclass(frozen=True)
class RoleMembershipLifecycleConfig:
    enabled: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.enabled, bool):
            raise ValueError("role membership lifecycle enabled must be boolean")

    @classmethod
    def from_environment(cls) -> "RoleMembershipLifecycleConfig":
        return cls(
            enabled=(
                str(os.environ.get(ROLE_MEMBERSHIP_LIFECYCLE_ENV, ""))
                .strip()
                .lower()
                in _TRUE
            )
        )


class RoleSessionResponseText(str):
    """Response text with private exact-session transport evidence."""

    def __new__(
        cls,
        body: str,
        *,
        persona_id: str,
        session_id: str,
        headers: Mapping[str, str],
        body_truncated: bool,
    ) -> "RoleSessionResponseText":
        if (
            not isinstance(body, str)
            or not isinstance(persona_id, str)
            or not persona_id
            or not isinstance(session_id, str)
            or not session_id
            or not isinstance(headers, Mapping)
            or not isinstance(body_truncated, bool)
        ):
            raise TypeError("role session response metadata is invalid")
        value = super().__new__(cls, body)
        value.persona_id = persona_id
        value.session_id = session_id
        value.headers = dict(headers)
        value.body_truncated = body_truncated
        return value


class RoleSessionPolicyExecutor(PolicyExecutor):
    """Policy executor whose raw seam requires native session-bound replay."""

    def __init__(
        self,
        transport: SessionBoundReplayTransport,
        policy: ExecutionPolicy,
        *,
        provenance: ProvenanceSink,
    ) -> None:
        send_bound = getattr(transport, "send_bound", None)
        if not callable(send_bound):
            raise TypeError("role session transport must implement send_bound")
        if not isinstance(policy, ExecutionPolicy):
            raise TypeError("policy must be an ExecutionPolicy")
        if not isinstance(provenance, ProvenanceSink):
            raise TypeError("provenance must be a ProvenanceSink")

        async def raw_send(method, url, body=None, **kwargs):
            persona_id = kwargs.pop("_role_persona_id", None)
            session_id = kwargs.pop("_role_session_id", None)
            headers = kwargs.pop("headers", {}) or {}
            response_cap = kwargs.pop(
                "_max_response_chars",
                _MAX_RESPONSE_CHARS,
            )
            redirect_mode = kwargs.pop("_redirect_mode", "manual")
            if kwargs:
                raise ValueError("unsupported role session transport arguments")
            if (
                not isinstance(persona_id, str)
                or not persona_id
                or not isinstance(session_id, str)
                or not session_id
            ):
                raise ValueError("exact role persona and session are required")
            if (
                isinstance(response_cap, bool)
                or not isinstance(response_cap, int)
                or not 1 <= response_cap <= _MAX_RESPONSE_CHARS
            ):
                raise ValueError("role response bound is invalid")
            if redirect_mode != "manual":
                raise ValueError("role session replay must keep redirects manual")
            if not isinstance(headers, Mapping):
                raise TypeError("role session replay headers must be a mapping")
            if isinstance(body, str) or body is None:
                encoded_body = body
            else:
                encoded_body = json.dumps(
                    body,
                    sort_keys=True,
                    separators=(",", ":"),
                )
            result = await send_bound(
                persona_id,
                session_id,
                ReplayRequest(
                    method=str(method),
                    url=str(url),
                    body=encoded_body,
                    headers={
                        str(key): str(value)
                        for key, value in headers.items()
                    },
                    max_response_chars=response_cap,
                    redirect_mode="manual",
                ),
            )
            if not isinstance(result, SessionBoundReplayResponse):
                raise TypeError("role session transport response is invalid")
            if (
                not hmac.compare_digest(result.persona, persona_id)
                or not hmac.compare_digest(result.session_id, session_id)
            ):
                raise RoleMembershipLifecycleDenied(
                    "role_membership_session_attestation_mismatch",
                    category="session",
                    target_request_possible=True,
                )
            response = result.response
            return response.status, RoleSessionResponseText(
                response.body,
                persona_id=result.persona,
                session_id=result.session_id,
                headers=response.headers,
                body_truncated=response.body_truncated,
            )

        super().__init__(raw_send, policy, provenance=provenance)
        self._role_session_transport = transport
        self._role_session_raw_send = raw_send


def make_native_role_session_executor(
    *,
    scope_filter,
    policy: ExecutionPolicy,
    provenance: ProvenanceSink,
    timeout: float = 30.0,
) -> RoleSessionPolicyExecutor:
    """Production factory binding policy execution to strict SND replay."""

    return RoleSessionPolicyExecutor(
        SNDReplayTransport(scope_filter=scope_filter, timeout=timeout),
        policy,
        provenance=provenance,
    )


def _resolve_pointer(value: Any, pointer: str) -> Any:
    current = value
    for raw_token in pointer.split("/")[1:]:
        token = raw_token.replace("~1", "/").replace("~0", "~")
        if isinstance(current, Mapping) and token in current:
            current = current[token]
            continue
        if isinstance(current, list) and token.isdigit():
            index = int(token)
            if index < len(current):
                current = current[index]
                continue
        raise RoleMembershipLifecycleDenied(
            "role_membership_observation_pointer_unresolved",
            category="observation",
            target_request_possible=True,
        )
    return current


def _observation_payload(
    *,
    action_binding_id: str,
    observation_binding_id: str,
    session_attestation_ref: str,
    response_ref: str,
    membership_ref: str,
    state: str,
    generation_ref: str,
) -> Dict[str, Any]:
    return {
        "action_binding_id": action_binding_id,
        "observation_binding_id": observation_binding_id,
        "session_attestation_ref": session_attestation_ref,
        "response_ref": response_ref,
        "membership_ref": membership_ref,
        "state": state,
        "generation_ref": generation_ref,
        "target_state_observed": True,
    }


@dataclass(frozen=True)
class RoleMembershipStateObservation:
    observation_id: str
    action_binding_id: str
    observation_binding_id: str
    session_attestation_ref: str
    response_ref: str
    membership_ref: str
    state: str
    generation_ref: str
    target_state_observed: bool = True

    def __post_init__(self) -> None:
        payload = _observation_payload(
            action_binding_id=self.action_binding_id,
            observation_binding_id=self.observation_binding_id,
            session_attestation_ref=self.session_attestation_ref,
            response_ref=self.response_ref,
            membership_ref=self.membership_ref,
            state=self.state,
            generation_ref=self.generation_ref,
        )
        if (
            self.observation_id
            != stable_hash("role_membership_state_observation", payload)
            or not _hash_ref(
                self.observation_id,
                "role_membership_state_observation",
            )
            or not _hash_ref(
                self.action_binding_id,
                "role_runtime_action_authority",
            )
            or not _hash_ref(
                self.observation_binding_id,
                "role_membership_observation_binding",
            )
            or not _hash_ref(
                self.session_attestation_ref,
                "role_session_transport_attestation",
            )
            or not _hash_ref(
                self.response_ref,
                "role_membership_target_response",
            )
            or not _hash_ref(self.membership_ref, "owned_membership")
            or self.state not in {"active", "revoked"}
            or not _hash_ref(
                self.generation_ref,
                "role_membership_generation",
            )
            or not self.target_state_observed
        ):
            raise ValueError("role membership state observation is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "observation_id": self.observation_id,
            **_observation_payload(
                action_binding_id=self.action_binding_id,
                observation_binding_id=self.observation_binding_id,
                session_attestation_ref=self.session_attestation_ref,
                response_ref=self.response_ref,
                membership_ref=self.membership_ref,
                state=self.state,
                generation_ref=self.generation_ref,
            ),
        }


def _observe_membership(
    *,
    entry: RoleRuntimeActionAuthorityBinding,
    runtime: RoleMonotonicityRuntimeContext,
    response_status: int,
    response: Any,
    expected_state: str,
    expected_generation: int,
    expected_generation_ref: str,
) -> RoleMembershipStateObservation:
    if (
        response_status == DENIED_STATUS
        or not 200 <= int(response_status) < 300
        or not isinstance(response, RoleSessionResponseText)
        or response.body_truncated
    ):
        raise RoleMembershipLifecycleDenied(
            "role_membership_target_observation_unavailable",
            category="observation",
            target_request_possible=True,
        )
    if (
        not hmac.compare_digest(response.persona_id, runtime.higher_persona_id)
        or not hmac.compare_digest(response.session_id, runtime.higher_session_id)
        or entry.session_ref != runtime.higher_session_ref
    ):
        raise RoleMembershipLifecycleDenied(
            "role_membership_session_attestation_mismatch",
            category="session",
            target_request_possible=True,
        )
    try:
        decoded = json.loads(str(response))
    except (TypeError, ValueError) as exc:
        raise RoleMembershipLifecycleDenied(
            "role_membership_target_observation_is_not_json",
            category="observation",
            target_request_possible=True,
        ) from exc
    if not isinstance(decoded, Mapping):
        raise RoleMembershipLifecycleDenied(
            "role_membership_target_observation_is_not_an_object",
            category="observation",
            target_request_possible=True,
        )
    binding = runtime.membership_observation_binding
    observed_tenant = _resolve_pointer(decoded, binding.tenant_pointer)
    observed_subject = _resolve_pointer(decoded, binding.subject_pointer)
    observed_role = _resolve_pointer(decoded, binding.role_pointer)
    observed_state = _resolve_pointer(decoded, binding.state_pointer)
    observed_generation = _resolve_pointer(decoded, binding.generation_pointer)
    strings_match = all(
        isinstance(observed, str)
        and hmac.compare_digest(observed, expected)
        for observed, expected in (
            (observed_tenant, runtime.tenant_id),
            (observed_subject, runtime.lower_persona_id),
            (observed_role, runtime.lower_role_ref),
            (observed_state, expected_state),
        )
    )
    if (
        not strings_match
        or isinstance(observed_generation, bool)
        or not isinstance(observed_generation, int)
        or observed_generation != expected_generation
        or entry.membership_state != expected_state
        or entry.membership_generation_ref != expected_generation_ref
    ):
        raise RoleMembershipLifecycleDenied(
            "role_membership_target_observation_mismatch",
            category="observation",
            target_request_possible=True,
        )
    response_ref = stable_hash(
        "role_membership_target_response",
        {
            "status": int(response_status),
            "body": str(response),
        },
    )
    session_attestation_ref = stable_hash(
        "role_session_transport_attestation",
        {
            "action_binding_id": entry.binding_id,
            "session_ref": entry.session_ref,
            "response_ref": response_ref,
        },
    )
    payload = _observation_payload(
        action_binding_id=entry.binding_id,
        observation_binding_id=binding.binding_id,
        session_attestation_ref=session_attestation_ref,
        response_ref=response_ref,
        membership_ref=entry.membership_ref,
        state=expected_state,
        generation_ref=expected_generation_ref,
    )
    return RoleMembershipStateObservation(
        observation_id=stable_hash(
            "role_membership_state_observation",
            payload,
        ),
        action_binding_id=entry.binding_id,
        observation_binding_id=binding.binding_id,
        session_attestation_ref=session_attestation_ref,
        response_ref=response_ref,
        membership_ref=entry.membership_ref,
        state=expected_state,
        generation_ref=expected_generation_ref,
    )


@dataclass(frozen=True)
class RoleMembershipCleanupResult:
    status: str
    revocation_attempted: int
    revocation_completed: int
    verification_attempted: int
    verification_completed: int
    revoked_observation_ref: Optional[str]
    target_requests_sent: int
    target_request_may_have_been_sent: bool
    orphaned_owned_state_possible: bool

    def __post_init__(self) -> None:
        counts = (
            self.revocation_attempted,
            self.revocation_completed,
            self.verification_attempted,
            self.verification_completed,
            self.target_requests_sent,
        )
        verified = (
            self.revocation_attempted
            == self.revocation_completed
            == self.verification_attempted
            == self.verification_completed
            == 1
            and _hash_ref(
                self.revoked_observation_ref,
                "role_membership_state_observation",
            )
            and not self.orphaned_owned_state_possible
        )
        if (
            self.status not in {"verified", "failed", "uncertain"}
            or any(
                isinstance(value, bool)
                or not isinstance(value, int)
                or value < 0
                for value in counts
            )
            or self.revocation_attempted > 1
            or self.verification_attempted > 1
            or self.revocation_completed > self.revocation_attempted
            or self.verification_completed > self.verification_attempted
            or self.target_requests_sent > 8
            or not isinstance(
                self.target_request_may_have_been_sent,
                bool,
            )
            or not isinstance(self.orphaned_owned_state_possible, bool)
            or (self.status == "verified") != bool(verified)
            or (self.status == "verified")
            == self.orphaned_owned_state_possible
        ):
            raise ValueError("role membership cleanup result is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "revocation_attempted": self.revocation_attempted,
            "revocation_completed": self.revocation_completed,
            "verification_attempted": self.verification_attempted,
            "verification_completed": self.verification_completed,
            "revoked_observation_ref": self.revoked_observation_ref,
            "target_requests_sent": self.target_requests_sent,
            "target_request_may_have_been_sent": (
                self.target_request_may_have_been_sent
            ),
            "orphaned_owned_state_possible": (
                self.orphaned_owned_state_possible
            ),
        }


def _result_payload(
    *,
    claim_contract_id: str,
    active_observation: RoleMembershipStateObservation,
    revoked_observation: RoleMembershipStateObservation,
    cleanup: RoleMembershipCleanupResult,
    provenance_ref: str,
    receipt_id: str,
) -> Dict[str, Any]:
    return {
        "kind": "role_membership_lifecycle",
        "mode": ROLE_MEMBERSHIP_LIFECYCLE_MODE,
        "status": "cleaned",
        "claim_contract_id": claim_contract_id,
        "active_observation": active_observation.to_dict(),
        "revoked_observation": revoked_observation.to_dict(),
        "cleanup": cleanup.to_dict(),
        "provenance_ref": provenance_ref,
        "receipt": {"receipt_id": receipt_id, "state": ABORTED},
        "remaining_execution_blockers": list(
            _REMAINING_EXECUTION_BLOCKERS
        ),
        "target_requests_sent": cleanup.target_requests_sent,
        "role_probes_sent": 0,
        "effect_evaluation_authority": False,
        "finding_authority": False,
        "promotion_authority": False,
        "executable": False,
    }


@dataclass(frozen=True)
class RoleMembershipLifecycleResult:
    result_id: str
    claim_contract_id: str
    active_observation: RoleMembershipStateObservation
    revoked_observation: RoleMembershipStateObservation
    cleanup: RoleMembershipCleanupResult
    provenance_ref: str
    receipt_id: str
    remaining_execution_blockers: Tuple[str, ...] = (
        _REMAINING_EXECUTION_BLOCKERS
    )

    def __post_init__(self) -> None:
        payload = _result_payload(
            claim_contract_id=self.claim_contract_id,
            active_observation=self.active_observation,
            revoked_observation=self.revoked_observation,
            cleanup=self.cleanup,
            provenance_ref=self.provenance_ref,
            receipt_id=self.receipt_id,
        )
        if (
            self.result_id
            != stable_hash("role_membership_lifecycle_result", payload)
            or not _hash_ref(
                self.result_id,
                "role_membership_lifecycle_result",
            )
            or not _hash_ref(
                self.claim_contract_id,
                "role_monotonicity_execution_claim_contract",
            )
            or self.active_observation.state != "active"
            or self.revoked_observation.state != "revoked"
            or self.active_observation.membership_ref
            != self.revoked_observation.membership_ref
            or self.cleanup.status != "verified"
            or self.cleanup.target_requests_sent != 3
            or self.cleanup.revoked_observation_ref
            != self.revoked_observation.observation_id
            or not _hash_ref(
                self.provenance_ref,
                "role_membership_lifecycle_provenance",
            )
            or not isinstance(self.receipt_id, str)
            or not self.receipt_id.startswith("behavioral-")
            or len(self.receipt_id) != len("behavioral-") + 64
            or self.remaining_execution_blockers
            != _REMAINING_EXECUTION_BLOCKERS
        ):
            raise ValueError("role membership lifecycle result is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": 1,
            "result_id": self.result_id,
            **_result_payload(
                claim_contract_id=self.claim_contract_id,
                active_observation=self.active_observation,
                revoked_observation=self.revoked_observation,
                cleanup=self.cleanup,
                provenance_ref=self.provenance_ref,
                receipt_id=self.receipt_id,
            ),
        }


@dataclass
class _LifecycleState:
    next_ordinal: int = 0
    target_requests_sent: int = 0
    target_request_may_have_been_sent: bool = False


def _entries(
    binding: RoleMonotonicityRequestBindingContract,
) -> Tuple[RoleRuntimeActionAuthorityBinding, ...]:
    entries = tuple(
        sorted(
            binding.action_bindings,
            key=lambda item: item.request_binding.ordinal,
        )
    )
    if (
        tuple(item.request_binding.ordinal for item in entries)
        != tuple(range(8))
        or tuple(item.membership_state for item in entries)
        != (
            "active",
            "active",
            "active",
            "active",
            "revoking",
            "revoked",
            "revoked",
            "revoked",
        )
    ):
        raise RoleMembershipLifecycleDenied(
            "role_membership_lifecycle_action_contract_invalid",
            category="plan",
        )
    return entries


def _expected_budget_tail(
    entries: Sequence[RoleRuntimeActionAuthorityBinding],
    ordinal: int,
) -> Tuple[Tuple[str, str], ...]:
    return tuple(
        (
            item.request_binding.action_class.value,
            item.request_binding.endpoint_key,
        )
        for item in entries[ordinal:]
    )


def _session_executor_is_sealed(
    executor: object,
    binding: RoleMonotonicityRequestBindingContract,
) -> bool:
    return bool(
        type(executor) is RoleSessionPolicyExecutor
        and "send_action" not in vars(executor)
        and executor.raw_send is executor._role_session_raw_send
        and isinstance(executor.policy, ExecutionPolicy)
        and executor.policy.digest() == binding.execution_policy_digest
    )


def _validate_runtime_plan(authority, entries) -> None:
    plan = authority.runtime_plan
    binding = plan.request_binding
    runtime = plan.runtime
    executor = plan.executor
    observation = runtime.membership_observation_binding
    effect_observation = runtime.effect_observation_binding
    expected_sessions = {
        **{index: runtime.higher_session_ref for index in (0, 1, 3, 4, 5, 7)},
        2: runtime.active_lower_session_ref,
        6: runtime.revoked_lower_session_ref,
    }
    expected_personas = {
        **{index: runtime.higher_persona_id for index in (0, 1, 3, 4, 5, 7)},
        2: runtime.lower_persona_id,
        6: runtime.lower_persona_id,
    }
    if (
        not _session_executor_is_sealed(executor, binding)
        or observation != binding.membership_observation_binding
        or effect_observation != binding.effect_observation_binding
        or observation.setup_action_id
        != entries[0].request_binding.action_id
        or observation.revocation_verification_action_id
        != entries[5].request_binding.action_id
        or any(
            entries[index].session_ref != expected_sessions[index]
            for index in range(8)
        )
        or any(
            runtime.runtime_actions[
                entries[index].request_binding.action_id
            ].actor_persona_id
            != expected_personas[index]
            for index in range(8)
        )
        or not executor.policy.budget.reservation_matches(
            authority.budget_reservation_id,
            _expected_budget_tail(entries, 0),
        )
    ):
        raise RoleMembershipLifecycleDenied(
            "role_membership_lifecycle_runtime_authority_invalid",
            category="authority",
        )


def _skip_to(authority, entries, state: _LifecycleState, ordinal: int) -> None:
    if ordinal < state.next_ordinal or ordinal > len(entries):
        raise RoleMembershipLifecycleDenied(
            "role_membership_lifecycle_budget_cursor_invalid",
            category="budget",
        )
    budget = authority.runtime_plan.executor.policy.budget
    reservation_id = authority.budget_reservation_id
    if not budget.reservation_matches(
        reservation_id,
        _expected_budget_tail(entries, state.next_ordinal),
    ):
        raise RoleMembershipLifecycleDenied(
            "role_membership_lifecycle_budget_sequence_changed",
            category="budget",
        )
    count = ordinal - state.next_ordinal
    if count:
        skipped = budget.skip_reservation_entries(reservation_id, count)
        if skipped != count:
            raise RoleMembershipLifecycleDenied(
                "role_membership_lifecycle_budget_skip_mismatch",
                category="budget",
            )
        authority.note_budget_units(skipped)
        state.next_ordinal = ordinal


def _advance_after_attempt(
    authority,
    entries,
    state: _LifecycleState,
    *,
    before: int,
) -> int:
    budget = authority.runtime_plan.executor.policy.budget
    reservation_id = authority.budget_reservation_id
    after = budget.reservation_remaining(reservation_id)
    consumed = before - after
    if consumed == 0:
        skipped = budget.skip_reservation_entries(reservation_id, 1)
        if skipped != 1:
            raise RoleMembershipLifecycleDenied(
                "role_membership_lifecycle_budget_advance_failed",
                category="budget",
            )
        authority.note_budget_units(1)
    elif consumed == 1:
        authority.note_budget_units(1)
    else:
        raise RoleMembershipLifecycleDenied(
            "role_membership_lifecycle_budget_consumption_mismatch",
            category="budget",
        )
    state.next_ordinal += 1
    if state.next_ordinal < len(entries) and not budget.reservation_matches(
        reservation_id,
        _expected_budget_tail(entries, state.next_ordinal),
    ):
        raise RoleMembershipLifecycleDenied(
            "role_membership_lifecycle_budget_sequence_changed",
            category="budget",
        )
    return consumed


async def _dispatch(authority, entries, state, ordinal):
    if state.next_ordinal != ordinal:
        raise RoleMembershipLifecycleDenied(
            "role_membership_lifecycle_dispatch_order_invalid",
            category="budget",
        )
    plan = authority.runtime_plan
    runtime = plan.runtime
    executor = plan.executor
    entry = entries[ordinal]
    if not _session_executor_is_sealed(
        executor,
        plan.request_binding,
    ):
        raise RoleMembershipLifecycleDenied(
            "role_membership_lifecycle_runtime_authority_invalid",
            category="authority",
        )
    candidate = copy.deepcopy(
        runtime.runtime_actions[entry.request_binding.action_id]
    )
    if not isinstance(candidate, CandidateAction):
        raise RoleMembershipLifecycleDenied(
            "role_membership_lifecycle_candidate_invalid",
            category="plan",
        )
    if entry.session_ref == runtime.higher_session_ref:
        persona_id = runtime.higher_persona_id
        session_id = runtime.higher_session_id
    elif entry.session_ref == runtime.active_lower_session_ref:
        persona_id = runtime.lower_persona_id
        session_id = runtime.active_lower_session_id
    elif entry.session_ref == runtime.revoked_lower_session_ref:
        persona_id = runtime.lower_persona_id
        session_id = runtime.revoked_lower_session_id
    else:
        raise RoleMembershipLifecycleDenied(
            "role_membership_runtime_session_is_not_bound",
            category="session",
        )
    if (
        not isinstance(candidate.actor_persona_id, str)
        or not hmac.compare_digest(candidate.actor_persona_id, persona_id)
    ):
        raise RoleMembershipLifecycleDenied(
            "role_membership_runtime_actor_is_not_bound",
            category="session",
        )
    candidate.budget_reservation_id = authority.budget_reservation_id
    budget = executor.policy.budget
    before = budget.reservation_remaining(authority.budget_reservation_id)
    try:
        status, response = await executor.send_action(
            candidate,
            _role_persona_id=persona_id,
            _role_session_id=session_id,
            _max_response_chars=_MAX_RESPONSE_CHARS,
            _redirect_mode="manual",
        )
    except BaseException:
        consumed = _advance_after_attempt(
            authority,
            entries,
            state,
            before=before,
        )
        if consumed:
            state.target_requests_sent += 1
        else:
            state.target_request_may_have_been_sent = True
        raise
    consumed = _advance_after_attempt(
        authority,
        entries,
        state,
        before=before,
    )
    if consumed != 1:
        raise RoleMembershipLifecycleDenied(
            "role_membership_lifecycle_policy_denied_before_transport",
            category="policy",
        )
    state.target_requests_sent += 1
    if (
        status == DENIED_STATUS
        or not isinstance(response, RoleSessionResponseText)
        or not hmac.compare_digest(
            response.persona_id,
            persona_id,
        )
        or not hmac.compare_digest(
            response.session_id,
            session_id,
        )
    ):
        raise RoleMembershipLifecycleDenied(
            "role_membership_session_attestation_mismatch",
            category="session",
            target_request_possible=True,
        )
    return status, response


async def _cleanup(
    authority,
    entries,
    state,
    *,
    release_post_revocation_units: bool = True,
):
    if not isinstance(release_post_revocation_units, bool):
        raise TypeError("release_post_revocation_units must be boolean")
    runtime = authority.runtime_plan.runtime
    revocation_attempted = 0
    revocation_completed = 0
    verification_attempted = 0
    verification_completed = 0
    revoked_observation = None
    errors = []
    try:
        _skip_to(authority, entries, state, 4)
    except BaseException as exc:
        errors.append(exc)
    if state.next_ordinal == 4:
        revocation_attempted = 1
        try:
            status, _response = await _dispatch(
                authority,
                entries,
                state,
                4,
            )
            if status == DENIED_STATUS or not 200 <= int(status) < 300:
                raise RoleMembershipLifecycleDenied(
                    "role_membership_revocation_failed",
                    category="cleanup",
                    target_request_possible=True,
                )
            revocation_completed = 1
        except BaseException as exc:
            errors.append(exc)
    if state.next_ordinal == 5:
        verification_attempted = 1
        try:
            status, response = await _dispatch(
                authority,
                entries,
                state,
                5,
            )
            revoked_observation = _observe_membership(
                entry=entries[5],
                runtime=runtime,
                response_status=status,
                response=response,
                expected_state="revoked",
                expected_generation=runtime.revoked_membership_generation,
                expected_generation_ref=runtime.revoked_generation_ref,
            )
            verification_completed = 1
        except BaseException as exc:
            errors.append(exc)
    if release_post_revocation_units:
        try:
            _skip_to(authority, entries, state, 8)
        except BaseException as exc:
            errors.append(exc)

    verified = (
        revocation_completed == 1
        and verification_completed == 1
        and revoked_observation is not None
    )
    orphaned = not verified
    status = (
        "verified"
        if verified
        else (
            "uncertain"
            if state.target_request_may_have_been_sent
            else "failed"
        )
    )
    cleanup = RoleMembershipCleanupResult(
        status=status,
        revocation_attempted=revocation_attempted,
        revocation_completed=revocation_completed,
        verification_attempted=verification_attempted,
        verification_completed=verification_completed,
        revoked_observation_ref=(
            revoked_observation.observation_id
            if revoked_observation is not None
            else None
        ),
        target_requests_sent=state.target_requests_sent,
        target_request_may_have_been_sent=(
            state.target_request_may_have_been_sent
        ),
        orphaned_owned_state_possible=orphaned,
    )
    return cleanup, revoked_observation, errors


def _reason(error: Optional[BaseException], cleanup) -> Tuple[str, str]:
    if cleanup.status != "verified":
        return "role_membership_lifecycle_cleanup_unverified", "cleanup"
    if error is None:
        return "role_membership_lifecycle_probe_completed", "lifecycle"
    reason = str(error)
    category = getattr(error, "category", "lifecycle")
    if _SEMANTIC.fullmatch(reason) is None:
        reason = "role_membership_lifecycle_failed"
    if _SEMANTIC.fullmatch(str(category or "")) is None:
        category = "lifecycle"
    return reason, str(category)


def _terminal_evidence(
    *,
    claim_contract_id: str,
    reason: str,
    category: str,
    active_observation: Optional[RoleMembershipStateObservation],
    revoked_observation: Optional[RoleMembershipStateObservation],
    cleanup: RoleMembershipCleanupResult,
) -> Dict[str, Any]:
    payload = {
        "kind": "role_membership_lifecycle_terminal",
        "status": (
            "cleaned" if cleanup.status == "verified" else "cleanup_failed"
        ),
        "reason_code": reason,
        "category": category,
        "claim_contract_id": claim_contract_id,
        "active_observation_ref": (
            active_observation.observation_id
            if active_observation is not None
            else None
        ),
        "revoked_observation_ref": (
            revoked_observation.observation_id
            if revoked_observation is not None
            else None
        ),
        "cleanup": cleanup.to_dict(),
        "target_requests_sent": cleanup.target_requests_sent,
        "remaining_execution_blockers": list(
            _REMAINING_EXECUTION_BLOCKERS
        ),
        "finding_confirmed": False,
        "promotion_authority": False,
        "finding_authority": False,
        "retry_authority": False,
    }
    return {
        "schema_version": 1,
        "terminal_evidence_ref": stable_hash(
            "role_membership_lifecycle_terminal_evidence",
            payload,
        ),
        **payload,
    }


class RoleMembershipLifecycleExecutor:
    """Consume one claim for setup/revoke verification, never role probes."""

    def __init__(
        self,
        claim: RoleMonotonicityExecutionClaim,
        *,
        config: Optional[RoleMembershipLifecycleConfig] = None,
    ) -> None:
        if not isinstance(claim, RoleMonotonicityExecutionClaim):
            raise TypeError("claim must be a RoleMonotonicityExecutionClaim")
        if config is not None and not isinstance(
            config,
            RoleMembershipLifecycleConfig,
        ):
            raise TypeError("config must be a RoleMembershipLifecycleConfig")
        self.claim = claim
        self.config = config or RoleMembershipLifecycleConfig.from_environment()
        self._lock = asyncio.Lock()
        self._consumed = False

    async def execute(self) -> RoleMembershipLifecycleResult:
        async with self._lock:
            if self._consumed:
                raise RoleMembershipLifecycleDenied(
                    "role_membership_lifecycle_executor_already_consumed",
                    category="claim",
                )
            if not self.config.enabled:
                raise RoleMembershipLifecycleDenied(
                    "role_membership_lifecycle_is_disabled",
                    category="configuration",
                )
            self._consumed = True
            try:
                authority = self.claim._begin_membership_lifecycle()
            except RoleMonotonicityExecutionClaimDenied as exc:
                raise RoleMembershipLifecycleDenied(
                    str(exc),
                    category=exc.category,
                ) from exc

            state = _LifecycleState()
            active_observation = None
            primary_error: Optional[BaseException] = None
            cancellation: Optional[asyncio.CancelledError] = None
            plan_valid = False
            try:
                entries = _entries(authority.runtime_plan.request_binding)
                _validate_runtime_plan(authority, entries)
                plan_valid = True
                status, response = await _dispatch(
                    authority,
                    entries,
                    state,
                    0,
                )
                runtime = authority.runtime_plan.runtime
                active_observation = _observe_membership(
                    entry=entries[0],
                    runtime=runtime,
                    response_status=status,
                    response=response,
                    expected_state="active",
                    expected_generation=runtime.active_membership_generation,
                    expected_generation_ref=runtime.active_generation_ref,
                )
            except asyncio.CancelledError as exc:
                primary_error = exc
                cancellation = exc
            except BaseException as exc:
                primary_error = exc

            if not plan_valid:
                try:
                    authority.abort(
                        reason="role_membership_lifecycle_plan_invalid"
                    )
                except Exception as abort_exc:
                    raise RoleMembershipLifecycleDenied(
                        "role_membership_lifecycle_plan_abort_failed",
                        category="receipt",
                    ) from abort_exc
                if cancellation is not None:
                    raise cancellation
                raise RoleMembershipLifecycleDenied(
                    "role_membership_lifecycle_runtime_authority_invalid",
                    category="authority",
                    terminal_receipt=authority.terminal_receipt,
                ) from primary_error

            cleanup_task = asyncio.create_task(
                _cleanup(authority, entries, state)
            )
            try:
                cleanup, revoked_observation, cleanup_errors = await asyncio.shield(
                    cleanup_task
                )
            except asyncio.CancelledError as exc:
                cancellation = cancellation or exc
                cleanup, revoked_observation, cleanup_errors = await cleanup_task

            if cleanup_errors and primary_error is None:
                primary_error = cleanup_errors[0]
            sink = authority.runtime_plan.executor.provenance
            provenance_root = (
                sink.root()
                if sink is not None and sink.verify() and sink.root()
                else None
            )
            if provenance_root is None and primary_error is None:
                primary_error = RoleMembershipLifecycleDenied(
                    "role_membership_lifecycle_provenance_invalid",
                    category="provenance",
                    target_request_possible=True,
                )
            reason, category = _reason(primary_error, cleanup)
            terminal_evidence = _terminal_evidence(
                claim_contract_id=self.claim.contract.contract_id,
                reason=reason,
                category=category,
                active_observation=active_observation,
                revoked_observation=revoked_observation,
                cleanup=cleanup,
            )
            try:
                authority.abort(
                    reason=reason,
                    terminal_evidence=terminal_evidence,
                )
            except Exception as exc:
                raise RoleMembershipLifecycleDenied(
                    "role_membership_lifecycle_receipt_abort_failed",
                    category="receipt",
                    target_request_possible=(
                        state.target_requests_sent > 0
                        or state.target_request_may_have_been_sent
                    ),
                    cleanup=cleanup,
                ) from exc
            terminal_receipt = authority.terminal_receipt
            if cancellation is not None:
                raise cancellation
            if (
                primary_error is not None
                or cleanup.status != "verified"
                or active_observation is None
                or revoked_observation is None
            ):
                raise RoleMembershipLifecycleDenied(
                    reason,
                    category=category,
                    target_request_possible=(
                        state.target_requests_sent > 0
                        or state.target_request_may_have_been_sent
                    ),
                    cleanup=cleanup,
                    terminal_receipt=terminal_receipt,
                ) from primary_error

            provenance_ref = stable_hash(
                "role_membership_lifecycle_provenance",
                provenance_root,
            )
            payload = _result_payload(
                claim_contract_id=self.claim.contract.contract_id,
                active_observation=active_observation,
                revoked_observation=revoked_observation,
                cleanup=cleanup,
                provenance_ref=provenance_ref,
                receipt_id=terminal_receipt.receipt_id,
            )
            return RoleMembershipLifecycleResult(
                result_id=stable_hash(
                    "role_membership_lifecycle_result",
                    payload,
                ),
                claim_contract_id=self.claim.contract.contract_id,
                active_observation=active_observation,
                revoked_observation=revoked_observation,
                cleanup=cleanup,
                provenance_ref=provenance_ref,
                receipt_id=terminal_receipt.receipt_id,
            )


__all__ = [
    "ROLE_MEMBERSHIP_LIFECYCLE_ENV",
    "ROLE_MEMBERSHIP_LIFECYCLE_MODE",
    "RoleMembershipCleanupResult",
    "RoleMembershipLifecycleConfig",
    "RoleMembershipLifecycleDenied",
    "RoleMembershipLifecycleExecutor",
    "RoleMembershipLifecycleResult",
    "RoleMembershipStateObservation",
    "RoleSessionPolicyExecutor",
    "RoleSessionResponseText",
    "make_native_role_session_executor",
]
