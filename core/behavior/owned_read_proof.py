"""Durable, single-persona proof for one explicit same-origin read.

The outer receipt is resolved before any browser dependency is consulted.  A
completed proof can therefore be replayed after the native window, target, or
Sentinel process has restarted without renewing target traffic.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Dict, Mapping, Optional, Sequence, Tuple
from urllib.parse import urlsplit, urlunsplit

from core.behavior.active import BoundedResponseText
from core.behavior.interaction_admission import InteractionIntentAdmission, InteractionIntentSelector
from core.behavior.interaction_boundary import (
    INTERACTION_ACQUISITION_WORKFLOW,
    InteractionAcquisitionConfig,
    InteractionReadAcquisitionAdmission,
    InteractionReadAcquisitionBoundary,
)
from core.behavior.interactions import InteractionIntent, InteractionIntentMiner
from core.behavior.normalize import stable_hash
from core.behavior.receipts import (
    COMPLETED,
    BehavioralReceiptStore,
    ReceiptStoreError,
    redacted_owned_read_proof_outcome,
    redacted_receipt_context,
    request_fingerprint,
)
from core.cortex.execution_policy import ExecutionPolicy, PolicyExecutor
from core.foundry.authorization import AuthorizationEnvelope
from core.safety.proof_budget import ProofBudget
from core.safety.provenance import ProvenanceSink
from core.wraith.bola_replay import ReplayRequest, ReplayTransport

OWNED_READ_PROOF_MODE = "behavioral_owned_read_proof_v1"
OWNED_READ_PROOF_WORKFLOW = "behavioral_owned_read_proof"
_MAX_RESPONSE_CHARS = 2 * 1024 * 1024

InteractionSnapshot = Callable[
    [str],
    Awaitable[Tuple[str, Sequence[Mapping[str, Any]]]],
]
InteractionResolver = Callable[
    [str, Sequence[Dict[str, Any]], Optional[str]],
    Awaitable[Mapping[str, Any]],
]
ArtifactStore = Callable[[bytes], str]


class OwnedReadProofDenied(RuntimeError):
    """The proof could not complete under the sealed read-only contract."""

    def __init__(self, message: str, *, target_request_possible: bool = False):
        super().__init__(message)
        self.target_request_possible = bool(target_request_possible)


@dataclass(frozen=True)
class OwnedReadProofResult:
    status: str
    receipt_id: str
    reused: bool
    proof: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "kind": "owned_read_proof",
            "mode": OWNED_READ_PROOF_MODE,
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
        raise ValueError("owned read proof URL is invalid") from exc
    scheme = parts.scheme.lower()
    if scheme not in {"http", "https"} or not host or parts.username or parts.password:
        raise ValueError("owned read proof URL must be absolute HTTP(S)")
    default_port = (scheme == "http" and port in {None, 80}) or (
        scheme == "https" and port in {None, 443}
    )
    netloc = host if default_port else f"{host}:{port}"
    return urlunsplit((scheme, netloc, parts.path or "/", parts.query, ""))


def _origin(value: str) -> str:
    parts = urlsplit(_normalized_url(value))
    return urlunsplit((parts.scheme, parts.netloc, "", "", ""))


def _proof_frontier(intent: InteractionIntent) -> Tuple[Dict[str, Any], ...]:
    return ({
        "obligation_id": stable_hash(
            "security_obligation",
            {"kind": "owned_read_proof", "intent_id": intent.intent_id},
        ),
        "kind": "owned_read_proof",
        "risk_class": "read",
        "score": 1_000,
        "actionable": False,
        "resolution_kind": "unavailable",
        "resolution_ref": None,
        "signals": [intent.intent_id],
    },)


def _eligible_owned_intents(catalog, *, world_ref: str) -> Tuple[InteractionIntent, ...]:
    intents = tuple(
        intent
        for intent in catalog.intents
        if intent.world_ref == world_ref
        and intent.intent_kind == "navigate"
        and intent.risk_class == "read_interaction"
        and not intent.locator_truncated
        and not intent.disabled
        and not intent.scripted_handler
    )
    return tuple(sorted(intents, key=lambda item: item.intent_id))


async def execute_owned_read_proof(
    *,
    proof_url: str,
    envelope: AuthorizationEnvelope,
    persona_id: str,
    snapshot: InteractionSnapshot,
    resolve_navigation: InteractionResolver,
    transport: ReplayTransport,
    store_artifact: ArtifactStore,
    receipt_store: Optional[BehavioralReceiptStore] = None,
    acquisition_config: Optional[InteractionAcquisitionConfig] = None,
) -> OwnedReadProofResult:
    """Execute or replay one exact same-persona GET backed by durable evidence."""

    if not isinstance(envelope, AuthorizationEnvelope):
        raise TypeError("owned read proof authorization envelope is required")
    if not isinstance(persona_id, str) or len(persona_id) != 32:
        raise ValueError("owned read proof persona identity is invalid")
    if not callable(snapshot) or not callable(resolve_navigation) or not callable(store_artifact):
        raise TypeError("owned read proof dependencies are invalid")
    normalized_proof_url = _normalized_url(proof_url)
    target_origin = _origin(normalized_proof_url)
    envelope.authorize_action(
        target_origin=target_origin,
        workflow=OWNED_READ_PROOF_WORKFLOW,
    )
    envelope.authorize_action(
        target_origin=target_origin,
        workflow=INTERACTION_ACQUISITION_WORKFLOW,
    )
    config = acquisition_config or InteractionAcquisitionConfig.from_environment()
    if not config.enabled:
        raise OwnedReadProofDenied("owned_read_proof_interaction_acquisition_disabled")

    fingerprint = request_fingerprint({
        "schema_version": 1,
        "mode": OWNED_READ_PROOF_MODE,
        "proof_url": normalized_proof_url,
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
        raise OwnedReadProofDenied("owned_read_proof_receipt_store_unavailable") from exc
    if not reservation.created:
        receipt = reservation.receipt
        if (
            receipt.context == context
            and receipt.state == COMPLETED
            and receipt.outcome is not None
            and receipt.outcome.get("kind") == "owned_read_proof"
        ):
            return OwnedReadProofResult(
                status="already_executed",
                receipt_id=receipt.receipt_id,
                reused=True,
                proof=copy.deepcopy(receipt.outcome),
            )
        raise OwnedReadProofDenied("owned_read_proof_is_already_reserved_or_terminal")
    token = reservation.reservation_token
    if token is None:
        raise OwnedReadProofDenied("owned_read_proof_reservation_token_unavailable")

    target_request_possible = False
    try:
        current_url, controls = await snapshot(persona_id)
        current_url = _normalized_url(current_url)
        if _origin(current_url) != target_origin:
            raise OwnedReadProofDenied("owned_read_proof_persona_page_changed_origin")
        catalog = InteractionIntentMiner().mine(
            controls,
            target_origin=target_origin,
            world_id=persona_id,
            page_url=current_url,
        )
        world_ref = stable_hash("world", persona_id)
        selected_intent = None
        for intent in _eligible_owned_intents(catalog, world_ref=world_ref):
            resolved = await resolve_navigation(
                persona_id,
                [segment.to_dict() for segment in intent.locator],
                None,
            )
            try:
                destination_url = _normalized_url(str(resolved.get("destination_url") or ""))
            except (TypeError, ValueError):
                continue
            if destination_url == normalized_proof_url:
                selected_intent = intent
                break
        if selected_intent is None:
            raise OwnedReadProofDenied("owned_read_proof_visible_navigation_not_found")

        policy = ExecutionPolicy(
            "bounty_safe",
            scope_filter=lambda url: _origin(str(url)) == target_origin,
            budget=ProofBudget(
                max_total_requests=1,
                max_requests_per_endpoint=1,
                max_cross_object_reads=0,
                max_privilege_mutations=0,
                max_creates=0,
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

        async def raw_send(method, url, body=None, **kwargs):
            nonlocal target_request_possible
            target_request_possible = True
            response = await transport.send(
                persona_id,
                ReplayRequest(
                    method=str(method),
                    url=str(url),
                    body=body if isinstance(body, str) or body is None else str(body),
                    headers={
                        str(key): str(value)
                        for key, value in (kwargs.get("headers") or {}).items()
                    },
                    max_response_chars=_MAX_RESPONSE_CHARS,
                    redirect_mode="manual",
                ),
            )
            bounded = BoundedResponseText(
                response.body,
                body_truncated=response.body_truncated,
            )
            bounded.response_headers = dict(response.headers)
            return response.status, bounded

        executor = PolicyExecutor(raw_send, policy, provenance=provenance)
        frontier = _proof_frontier(selected_intent)
        selection = InteractionIntentSelector().select(
            catalog,
            frontier,
            world_id=persona_id,
            policy_digest=policy.digest(),
            budget_snapshot=policy.budget.snapshot(),
            max_total_requests=policy.budget.max_total_requests,
        )
        admission: Optional[InteractionIntentAdmission] = selection.admission
        if admission is None or admission.intent_id != selected_intent.intent_id:
            raise OwnedReadProofDenied("owned_read_proof_admission_unavailable")

        async def sealed_resolver(actor, locator, peer):
            resolved = await resolve_navigation(actor, locator, peer)
            if _normalized_url(str(resolved.get("destination_url") or "")) != normalized_proof_url:
                raise OwnedReadProofDenied("owned_read_proof_navigation_binding_changed")
            return resolved

        acquisition = await InteractionReadAcquisitionAdmission(
            InteractionReadAcquisitionBoundary(
                admission=admission,
                target_origin=target_origin,
                authorization=envelope,
                actor_persona_id=persona_id,
                peer_persona_id=None,
                request_persona_id=persona_id,
                executor=executor,
                resolver=sealed_resolver,
                config=config,
            ),
            receipt_store=receipts,
        ).execute()
        if acquisition.reused or acquisition.record is None:
            raise OwnedReadProofDenied("owned_read_proof_fresh_acquisition_unavailable")
        response_body = str(acquisition.record.get("response_body") or "")
        artifact_hash = store_artifact(response_body.encode("utf-8"))
        artifact_ref = f"sha256:{artifact_hash}"
        correlation_ids = tuple(acquisition.execution.get("correlation_ids") or ())
        identity = {
            "acquisition_receipt_id": acquisition.receipt_id,
            "acquisition_id": acquisition.execution["acquisition_id"],
            "artifact_ref": artifact_ref,
            "correlation_ids": list(correlation_ids),
        }
        outcome = redacted_owned_read_proof_outcome({
            "kind": "owned_read_proof",
            "mode": OWNED_READ_PROOF_MODE,
            "status": "completed",
            "proof_id": stable_hash("owned_read_proof", identity),
            "acquisition_receipt_id": acquisition.receipt_id,
            "artifact_ref": artifact_ref,
            "correlation_ids": list(correlation_ids),
            "acquisition": acquisition.execution,
        })
        completed = receipts.complete(
            fingerprint,
            reservation_token=token,
            outcome=outcome,
        )
        if completed.outcome is None:
            raise OwnedReadProofDenied(
                "owned_read_proof_receipt_outcome_missing",
                target_request_possible=True,
            )
        return OwnedReadProofResult(
            status="completed",
            receipt_id=completed.receipt_id,
            reused=False,
            proof=copy.deepcopy(completed.outcome),
        )
    except Exception as exc:
        try:
            receipts.abort(
                fingerprint,
                reservation_token=token,
                reason="owned_read_proof_error",
            )
        except (OSError, ReceiptStoreError):
            raise OwnedReadProofDenied(
                "owned_read_proof_failed_and_receipt_could_not_finalize",
                target_request_possible=target_request_possible,
            ) from exc
        if isinstance(exc, OwnedReadProofDenied):
            raise
        raise OwnedReadProofDenied(
            "owned_read_proof_failed",
            target_request_possible=target_request_possible,
        ) from exc


__all__ = [
    "OWNED_READ_PROOF_MODE",
    "OWNED_READ_PROOF_WORKFLOW",
    "OwnedReadProofDenied",
    "OwnedReadProofResult",
    "execute_owned_read_proof",
]
