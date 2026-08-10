"""Durable proof for one declared owned-object lifecycle prerequisite.

The experiment rehearses the complete lifecycle and its reverse action on one
fresh object before attempting the prerequisite-omitting transition on a second
fresh object.  Every request crosses ``PolicyExecutor`` and both objects are
returned to their initial state before a result can complete.
"""

from __future__ import annotations

import copy
import html
import re
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlencode, urlsplit, urlunsplit

from core.behavior.active import BoundedResponseText
from core.behavior.normalize import stable_hash
from core.behavior.receipts import (
    COMPLETED,
    BehavioralReceiptStore,
    ReceiptStoreError,
    redacted_owned_state_transition_outcome,
    redacted_receipt_context,
    request_fingerprint,
)
from core.cortex.execution_policy import DENIED_STATUS, ExecutionPolicy, PolicyExecutor
from core.foundry.authorization import AuthorizationEnvelope
from core.safety.action_classifier import OWNED_CREATE, OWNED_UPDATE_LOW_RISK, SAFE_READ
from core.safety.proof_budget import ProofBudget
from core.safety.provenance import ProvenanceSink
from core.wraith.bola_replay import ReplayRequest, ReplayTransport

OWNED_STATE_TRANSITION_MODE = "behavioral_owned_state_transition_proof_v1"
OWNED_STATE_TRANSITION_WORKFLOW = "behavioral_owned_state_transition_proof"
_SEMANTIC = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
_OBJECT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_MAX_RESPONSE_CHARS = 2 * 1024 * 1024
_FORM_ACTION = re.compile(
    r"<form\b[^>]*\baction\s*=\s*([\"'])(?P<action>[^\"']+)\1[^>]*>",
    re.IGNORECASE,
)
_BADGE = re.compile(
    r"<span\b[^>]*\bclass\s*=\s*([\"'])[^\"']*\bbadge\b[^\"']*\1[^>]*>"
    r"(?P<state>.*?)</span>",
    re.IGNORECASE | re.DOTALL,
)


class OwnedStateTransitionDenied(RuntimeError):
    def __init__(self, message: str, *, target_request_possible: bool = False):
        super().__init__(message)
        self.target_request_possible = bool(target_request_possible)


@dataclass(frozen=True)
class StateTransitionContract:
    initial_state: str
    prerequisite_action: str
    prerequisite_state: str
    terminal_action: str
    terminal_state: str
    cleanup_action: str

    def __post_init__(self) -> None:
        values = (
            self.initial_state,
            self.prerequisite_action,
            self.prerequisite_state,
            self.terminal_action,
            self.terminal_state,
            self.cleanup_action,
        )
        if any(
            not isinstance(value, str) or _SEMANTIC.fullmatch(value) is None
            for value in values
        ):
            raise ValueError("state transition contract fields must be bounded semantics")
        if len(set(values[:3:2] + values[4:5])) != 3:
            raise ValueError("state transition states must be distinct")
        if len({self.prerequisite_action, self.terminal_action, self.cleanup_action}) != 3:
            raise ValueError("state transition actions must be distinct")

    def to_dict(self) -> Dict[str, str]:
        return {
            "initial_state": self.initial_state,
            "prerequisite_action": self.prerequisite_action,
            "prerequisite_state": self.prerequisite_state,
            "terminal_action": self.terminal_action,
            "terminal_state": self.terminal_state,
            "cleanup_action": self.cleanup_action,
        }


@dataclass(frozen=True)
class OwnedStateTransitionResult:
    status: str
    receipt_id: str
    reused: bool
    proof: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "kind": "owned_state_transition_proof",
            "mode": OWNED_STATE_TRANSITION_MODE,
            "receipt": {
                "receipt_id": self.receipt_id,
                "state": COMPLETED,
                "reused": self.reused,
            },
            "proof": copy.deepcopy(self.proof),
        }


def _normalized_url(value: str) -> str:
    parts = urlsplit(str(value or "").strip())
    try:
        host = (parts.hostname or "").lower()
        port = parts.port
    except ValueError as exc:
        raise ValueError("state transition URL is invalid") from exc
    scheme = parts.scheme.lower()
    if (
        scheme not in {"http", "https"}
        or not host
        or parts.username
        or parts.password
        or parts.query
    ):
        raise ValueError("state transition URL must be absolute HTTP(S)")
    default_port = (scheme == "http" and port in {None, 80}) or (
        scheme == "https" and port in {None, 443}
    )
    netloc = host if default_port else f"{host}:{port}"
    return urlunsplit((scheme, netloc, parts.path.rstrip("/") or "/", parts.query, ""))


def _origin(value: str) -> str:
    parts = urlsplit(_normalized_url(value))
    return urlunsplit((parts.scheme, parts.netloc, "", "", ""))


def _visible_state(body: str) -> Optional[str]:
    match = _BADGE.search(body)
    if match is None:
        return None
    value = re.sub(r"<[^>]+>", " ", match.group("state"))
    value = " ".join(html.unescape(value).lower().split())
    return value if _SEMANTIC.fullmatch(value) is not None else None


def _form_actions(body: str) -> Tuple[str, ...]:
    return tuple(match.group("action") for match in _FORM_ACTION.finditer(body))


def _object_id(body: str, *, collection_path: str, action: str) -> str:
    prefix = f"{collection_path.rstrip('/')}/"
    suffix = f"/{action}"
    candidates = []
    for value in _form_actions(body):
        path = urlsplit(value).path
        if path.startswith(prefix) and path.endswith(suffix):
            candidate = path[len(prefix) : -len(suffix)]
            if _OBJECT_ID.fullmatch(candidate) is not None:
                candidates.append(candidate)
    if len(set(candidates)) != 1:
        raise OwnedStateTransitionDenied("state_transition_object_identity_unavailable")
    return candidates[0]


def _require_action(body: str, expected_path: str) -> None:
    if expected_path not in {urlsplit(value).path for value in _form_actions(body)}:
        raise OwnedStateTransitionDenied("state_transition_visible_action_unavailable")


async def execute_owned_state_transition_proof(
    *,
    collection_url: str,
    contract: StateTransitionContract,
    envelope: AuthorizationEnvelope,
    persona_id: str,
    transport: ReplayTransport,
    store_artifact,
    receipt_store: Optional[BehavioralReceiptStore] = None,
) -> OwnedStateTransitionResult:
    """Rehearse, omit, independently observe, and clean one lifecycle transition."""

    if not isinstance(envelope, AuthorizationEnvelope):
        raise TypeError("state transition authorization envelope is required")
    if not isinstance(persona_id, str) or len(persona_id) != 32:
        raise ValueError("state transition persona identity is invalid")
    if not callable(store_artifact) or not hasattr(transport, "send"):
        raise TypeError("state transition proof dependencies are invalid")
    collection_url = _normalized_url(collection_url)
    target_origin = _origin(collection_url)
    envelope.authorize_action(
        target_origin=target_origin,
        workflow=OWNED_STATE_TRANSITION_WORKFLOW,
    )
    fingerprint = request_fingerprint({
        "schema_version": 1,
        "mode": OWNED_STATE_TRANSITION_MODE,
        "collection_url": collection_url,
        "contract": contract.to_dict(),
        "envelope_id": envelope.envelope_id,
        "authorization_signature": envelope.attestation_signature,
        "persona_id": persona_id,
    })
    context = redacted_receipt_context(
        target_origin=target_origin,
        envelope_id=envelope.envelope_id,
        source_persona_id=persona_id,
        peer_persona_id=persona_id,
    )
    receipts = receipt_store or BehavioralReceiptStore()
    try:
        reservation = receipts.reserve(fingerprint, context=context)
    except (OSError, ReceiptStoreError) as exc:
        raise OwnedStateTransitionDenied("state_transition_receipt_store_unavailable") from exc
    if not reservation.created:
        receipt = reservation.receipt
        if (
            receipt.context == context
            and receipt.state == COMPLETED
            and receipt.outcome is not None
            and receipt.outcome.get("kind") == "owned_state_transition_proof"
        ):
            return OwnedStateTransitionResult(
                status="already_executed",
                receipt_id=receipt.receipt_id,
                reused=True,
                proof=copy.deepcopy(receipt.outcome),
            )
        raise OwnedStateTransitionDenied("state_transition_is_already_reserved_or_terminal")
    token = reservation.reservation_token
    if token is None:
        raise OwnedStateTransitionDenied("state_transition_reservation_token_unavailable")

    policy = ExecutionPolicy(
        "bounty_safe",
        scope_filter=lambda url: _origin(str(url)) == target_origin,
        budget=ProofBudget(
            max_total_requests=21,
            max_requests_per_endpoint=12,
            max_cross_object_reads=0,
            max_privilege_mutations=0,
            max_creates=2,
            allow_delete=False,
            allow_real_user_data_access=False,
        ),
    )
    provenance = ProvenanceSink()
    provenance.record_context(
        target=target_origin,
        proof_mode="bounty_safe",
        policy_digest=policy.digest(),
    )
    target_request_possible = False

    async def raw_send(method, url, body=None, **kwargs):
        nonlocal target_request_possible
        target_request_possible = True
        response = await transport.send(
            persona_id,
            ReplayRequest(
                method=str(method),
                url=str(url),
                body=body if isinstance(body, str) or body is None else str(body),
                headers={str(key): str(value) for key, value in (kwargs.get("headers") or {}).items()},
                max_response_chars=_MAX_RESPONSE_CHARS,
                redirect_mode="follow",
            ),
        )
        bounded = BoundedResponseText(response.body, body_truncated=response.body_truncated)
        bounded.response_headers = dict(response.headers)
        return response.status, bounded

    executor = PolicyExecutor(raw_send, policy, provenance=provenance)
    correlations = []
    artifacts = []
    created_ids = []
    cleaned_ids = set()
    collection_path = urlsplit(collection_url).path.rstrip("/") or "/"

    def action_url(object_id: str, action: str) -> str:
        return f"{collection_url}/{object_id}/{action}"

    def object_url(object_id: str) -> str:
        return f"{collection_url}/{object_id}"

    async def send(
        step: str,
        method: str,
        url: str,
        *,
        body: Optional[str] = None,
        hint: str,
    ) -> Tuple[int, str]:
        correlation = "sentinel:" + stable_hash(
            "owned_state_transition_request",
            {"fingerprint": fingerprint, "step": step},
        ).split(":", 1)[-1][:24]
        headers = {"X-Correlation-Id": correlation}
        if body is not None:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        status, response = await executor.send(
            method,
            url,
            body,
            hint=hint,
            actor=persona_id,
            target_owner=persona_id,
            target_is_researcher_owned=True,
            expected_side_effect=step,
            proof_goal="confirm_owned_state_prerequisite_omission",
            headers=headers,
        )
        if status == DENIED_STATUS:
            raise OwnedStateTransitionDenied("state_transition_policy_denied")
        correlations.append(correlation)
        text = str(response)
        if len(text) > _MAX_RESPONSE_CHARS:
            raise OwnedStateTransitionDenied("state_transition_response_exceeded_limit")
        digest = store_artifact(text.encode("utf-8"))
        artifacts.append(f"sha256:{digest}")
        return int(status), text

    async def read_state(step: str, object_id: str, expected: str) -> str:
        status, body = await send(step, "GET", object_url(object_id), hint=SAFE_READ)
        if status != 200 or _visible_state(body) != expected:
            raise OwnedStateTransitionDenied("state_transition_state_observation_mismatch")
        return body

    async def create(step: str, name: str) -> Tuple[str, str]:
        status, body = await send(
            step,
            "POST",
            collection_url,
            body=urlencode({"name": name}),
            hint=OWNED_CREATE,
        )
        if not 200 <= status < 400 or _visible_state(body) != contract.initial_state:
            raise OwnedStateTransitionDenied("state_transition_owned_create_failed")
        object_id = _object_id(
            body,
            collection_path=collection_path,
            action=contract.terminal_action,
        )
        if object_id in created_ids:
            raise OwnedStateTransitionDenied("state_transition_object_identity_reused")
        created_ids.append(object_id)
        return object_id, body

    async def mutate(step: str, object_id: str, action: str) -> Tuple[int, str]:
        url = action_url(object_id, action)
        current_status, current_body = await send(
            f"{step}_preflight",
            "GET",
            object_url(object_id),
            hint=SAFE_READ,
        )
        if current_status != 200:
            raise OwnedStateTransitionDenied("state_transition_preflight_read_failed")
        _require_action(current_body, urlsplit(url).path)
        return await send(
            step,
            "POST",
            url,
            body="",
            hint=OWNED_UPDATE_LOW_RISK,
        )

    async def cleanup(step: str, object_id: str) -> None:
        status, body = await mutate(step, object_id, contract.cleanup_action)
        if not 200 <= status < 400 or _visible_state(body) != contract.initial_state:
            raise OwnedStateTransitionDenied(
                "state_transition_cleanup_failed",
                target_request_possible=True,
            )
        cleaned_ids.add(object_id)

    try:
        baseline_id, _ = await create(
            "baseline_create",
            f"Sentinel lifecycle rehearsal {fingerprint[:8]}",
        )
        await read_state("baseline_initial", baseline_id, contract.initial_state)
        status, body = await mutate(
            "baseline_prerequisite",
            baseline_id,
            contract.prerequisite_action,
        )
        if not 200 <= status < 400 or _visible_state(body) != contract.prerequisite_state:
            raise OwnedStateTransitionDenied("state_transition_prerequisite_rehearsal_failed")
        await read_state("baseline_prerequisite_state", baseline_id, contract.prerequisite_state)
        status, body = await mutate(
            "baseline_terminal",
            baseline_id,
            contract.terminal_action,
        )
        if not 200 <= status < 400 or _visible_state(body) != contract.terminal_state:
            raise OwnedStateTransitionDenied("state_transition_terminal_rehearsal_failed")
        await read_state("baseline_terminal_state", baseline_id, contract.terminal_state)
        await cleanup("baseline_cleanup", baseline_id)

        subject_id, _ = await create(
            "subject_create",
            f"Sentinel omission subject {fingerprint[:8]}",
        )
        await read_state("subject_initial", subject_id, contract.initial_state)
        status, body = await mutate(
            "subject_terminal_without_prerequisite",
            subject_id,
            contract.terminal_action,
        )
        if 200 <= status < 400:
            if _visible_state(body) != contract.terminal_state:
                raise OwnedStateTransitionDenied("state_transition_terminal_response_mismatch")
            await read_state("subject_terminal_state", subject_id, contract.terminal_state)
            confirmation_status = "confirmed_fail_open"
        elif status == 409:
            await read_state("subject_refused_state", subject_id, contract.initial_state)
            confirmation_status = "prerequisite_enforced"
        else:
            raise OwnedStateTransitionDenied("state_transition_terminal_result_inconclusive")
        await cleanup("subject_cleanup", subject_id)

        action_refs = {
            "prerequisite_action_ref": stable_hash(
                "state_transition_action",
                contract.prerequisite_action,
            ),
            "terminal_action_ref": stable_hash(
                "state_transition_action",
                contract.terminal_action,
            ),
            "cleanup_action_ref": stable_hash(
                "state_transition_action",
                contract.cleanup_action,
            ),
        }
        identity = {
            "confirmation_status": confirmation_status,
            "source_state": contract.initial_state,
            "prerequisite_state": contract.prerequisite_state,
            "target_state": contract.terminal_state,
            **action_refs,
            "correlation_ids": list(correlations),
            "artifact_refs": list(artifacts),
        }
        finding_ref = (
            stable_hash("forbidden_lifecycle_transition", identity)
            if confirmation_status == "confirmed_fail_open"
            else None
        )
        outcome = redacted_owned_state_transition_outcome({
            "kind": "owned_state_transition_proof",
            "mode": OWNED_STATE_TRANSITION_MODE,
            "status": "completed",
            "proof_id": stable_hash("owned_state_transition_proof", identity),
            "confirmation_status": confirmation_status,
            "source_state": contract.initial_state,
            "prerequisite_state": contract.prerequisite_state,
            "target_state": contract.terminal_state,
            **action_refs,
            "correlation_ids": correlations,
            "artifact_refs": artifacts,
            "finding_ref": finding_ref,
            "cleanup_complete": len(cleaned_ids) == 2,
            "requests_sent": executor.policy.budget.snapshot()["total_requests"],
            "provenance_root": provenance.root() or "",
            "budget_snapshot": executor.policy.budget.snapshot(),
        })
        completed = receipts.complete(
            fingerprint,
            reservation_token=token,
            outcome=outcome,
        )
        return OwnedStateTransitionResult(
            status="completed",
            receipt_id=completed.receipt_id,
            reused=False,
            proof=copy.deepcopy(completed.outcome or outcome),
        )
    except Exception as exc:
        cleanup_failed = False
        for object_id in reversed(created_ids):
            if object_id in cleaned_ids:
                continue
            try:
                await cleanup(f"emergency_cleanup_{len(cleaned_ids)}", object_id)
            except Exception:
                cleanup_failed = True
        try:
            receipts.abort(
                fingerprint,
                reservation_token=token,
                reason=(
                    "state_transition_cleanup_failed"
                    if cleanup_failed
                    else "state_transition_error"
                ),
            )
        except (OSError, ReceiptStoreError):
            cleanup_failed = True
        if isinstance(exc, OwnedStateTransitionDenied) and not cleanup_failed:
            raise
        raise OwnedStateTransitionDenied(
            "state_transition_cleanup_failed" if cleanup_failed else "state_transition_failed",
            target_request_possible=target_request_possible,
        ) from exc


__all__ = [
    "OWNED_STATE_TRANSITION_MODE",
    "OWNED_STATE_TRANSITION_WORKFLOW",
    "OwnedStateTransitionDenied",
    "OwnedStateTransitionResult",
    "StateTransitionContract",
    "execute_owned_state_transition_proof",
]
