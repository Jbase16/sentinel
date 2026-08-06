"""Controlled acquisition of one sealed same-origin navigation response.

The boundary never clicks the DOM.  A local resolver re-reads the structural
catalog and exact anchor destination; only a still-identical admission may compile
one authenticated GET through ``PolicyExecutor`` under a one-request reservation.
"""

from __future__ import annotations

import copy
import hmac
import os
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, Mapping, Optional, Sequence, Tuple
from urllib.parse import urlsplit

from core.cortex.execution_policy import DENIED_STATUS, CandidateAction, PolicyExecutor
from core.foundry.authorization import AuthorizationEnvelope
from core.safety.action_classifier import CROSS_OBJECT_READ, SAFE_READ
from core.safety.ownership_registry import NativeOwnedCreationWitness
from core.safety.proof_budget import endpoint_key
from core.safety.provenance import body_hash, response_shape

from .interaction_admission import (
    PASSIVE_CATALOG_BLOCKER,
    InteractionAdmissionPolicy,
    InteractionIntentAdmission,
)
from .interactions import InteractionIntentMiner
from .normalize import normalize_exchange, stable_hash
from .receipts import (
    COMPLETED,
    BehavioralReceiptContext,
    BehavioralReceiptStore,
    ReceiptStoreError,
    redacted_interaction_acquisition_outcome,
    redacted_receipt_context,
    request_fingerprint,
)

INTERACTION_ACQUISITION_ENV = "SENTINELFORGE_BEHAVIOR_INTERACTION_ACQUISITION"
INTERACTION_ACQUISITION_MODE = "behavioral_interaction_read_acquisition_v1"
INTERACTION_ACQUISITION_WORKFLOW = "behavioral_interaction_read_acquisition"
_TRUE = frozenset({"1", "true", "yes", "on"})
_MAX_RESPONSE_CHARS = 2 * 1024 * 1024

InteractionResolver = Callable[
    [str, Sequence[Dict[str, Any]], Optional[str]],
    Awaitable[Mapping[str, Any]],
]


class InteractionAcquisitionDenied(RuntimeError):
    """The local binding or active request failed closed."""

    def __init__(
        self,
        message: str,
        *,
        target_request_possible: bool = False,
    ) -> None:
        super().__init__(message)
        self.target_request_possible = bool(target_request_possible)


@dataclass(frozen=True)
class InteractionAcquisitionConfig:
    enabled: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.enabled, bool):
            raise ValueError("interaction acquisition enabled must be a boolean")

    @classmethod
    def from_environment(cls) -> "InteractionAcquisitionConfig":
        return cls(
            enabled=os.environ.get(INTERACTION_ACQUISITION_ENV, "").strip().lower()
            in _TRUE
        )


@dataclass(frozen=True)
class _ResolvedNavigation:
    resolution_id: str
    destination_url: str = field(repr=False, compare=False)
    current_url: str = field(repr=False, compare=False)
    ownership_witness: Optional[NativeOwnedCreationWitness] = field(
        default=None,
        repr=False,
        compare=False,
    )


@dataclass(frozen=True)
class InteractionAcquisitionResult:
    acquisition_id: str
    admission_id: str
    obligation_id: str
    destination_page_ref: str
    operation_ref: str
    request_ref: str
    response_ref: str
    response_status: int
    response_truncated: bool
    cross_persona_probe: bool
    ownership_proof_ref: Optional[str]
    requests_attempted: int
    requests_sent: int
    policy_denials: int
    provenance_root: str
    budget_snapshot: Dict[str, int]
    restraint: Dict[str, Any]
    record: Optional[Dict[str, Any]] = field(
        default=None,
        repr=False,
        compare=False,
    )
    status: str = "completed"
    kind: str = "interaction_read_acquisition"
    mode: str = INTERACTION_ACQUISITION_MODE

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": 1,
            "kind": self.kind,
            "mode": self.mode,
            "status": self.status,
            "acquisition_id": self.acquisition_id,
            "admission_id": self.admission_id,
            "obligation_id": self.obligation_id,
            "destination_page_ref": self.destination_page_ref,
            "operation_ref": self.operation_ref,
            "request_ref": self.request_ref,
            "response_ref": self.response_ref,
            "response_status": self.response_status,
            "response_truncated": self.response_truncated,
            "cross_persona_probe": self.cross_persona_probe,
            "ownership_proof_ref": self.ownership_proof_ref,
            "requests_attempted": self.requests_attempted,
            "requests_sent": self.requests_sent,
            "policy_denials": self.policy_denials,
            "provenance_root": self.provenance_root,
            "budget_snapshot": dict(self.budget_snapshot),
            "restraint": copy.deepcopy(self.restraint),
        }


def _origin(value: str) -> str:
    parsed = urlsplit(str(value or "").strip())
    try:
        host = (parsed.hostname or "").lower()
        port = parsed.port
    except ValueError as exc:
        raise InteractionAcquisitionDenied(
            "interaction_acquisition_origin_is_invalid"
        ) from exc
    scheme = parsed.scheme.lower()
    if (
        scheme not in {"http", "https"}
        or not host
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise InteractionAcquisitionDenied(
            "interaction_acquisition_origin_is_invalid"
        )
    default_port = (scheme == "http" and port in {None, 80}) or (
        scheme == "https" and port in {None, 443}
    )
    return f"{scheme}://{host}" if default_port else f"{scheme}://{host}:{port}"


def _verify_authorization(
    envelope: AuthorizationEnvelope,
    *,
    target_origin: str,
) -> None:
    signature = envelope.attestation_signature
    if not signature:
        raise InteractionAcquisitionDenied(
            "interaction_acquisition_authorization_is_unsigned"
        )
    verification = copy.deepcopy(envelope)
    if not hmac.compare_digest(signature, verification.sign()):
        raise InteractionAcquisitionDenied(
            "interaction_acquisition_authorization_signature_mismatch"
        )
    try:
        envelope.authorize_action(
            target_origin=target_origin,
            workflow=INTERACTION_ACQUISITION_WORKFLOW,
        )
    except Exception as exc:
        raise InteractionAcquisitionDenied(
            "interaction_acquisition_authorization_denied"
        ) from exc


class InteractionReadAcquisitionBoundary:
    """Revalidate and acquire one exact admitted navigation response."""

    def __init__(
        self,
        *,
        admission: InteractionIntentAdmission,
        target_origin: str,
        authorization: AuthorizationEnvelope,
        actor_persona_id: str,
        peer_persona_id: str,
        request_persona_id: Optional[str] = None,
        executor: PolicyExecutor,
        resolver: InteractionResolver,
        config: Optional[InteractionAcquisitionConfig] = None,
    ) -> None:
        if not isinstance(admission, InteractionIntentAdmission):
            raise TypeError("interaction admission is required")
        if not isinstance(authorization, AuthorizationEnvelope):
            raise TypeError("authorization envelope is required")
        if not isinstance(executor, PolicyExecutor):
            raise TypeError("policy executor is required")
        if not callable(resolver):
            raise TypeError("interaction resolver is required")
        if (
            not isinstance(actor_persona_id, str)
            or not actor_persona_id
            or not isinstance(peer_persona_id, str)
            or not peer_persona_id
            or actor_persona_id == peer_persona_id
        ):
            raise ValueError("two distinct interaction personas are required")
        self.admission = admission
        self.target_origin = _origin(target_origin)
        self.authorization = authorization
        self.actor_persona_id = actor_persona_id
        self.peer_persona_id = peer_persona_id
        self.request_persona_id = request_persona_id or actor_persona_id
        if self.request_persona_id not in {
            self.actor_persona_id,
            self.peer_persona_id,
        }:
            raise ValueError("interaction request persona is not in the admitted pair")
        self.executor = executor
        self.resolver = resolver
        self.config = config or InteractionAcquisitionConfig.from_environment()

    def _validate_static_preflight(self) -> None:
        if not self.config.enabled:
            raise InteractionAcquisitionDenied(
                "interaction_acquisition_is_disabled"
            )
        admission = self.admission
        if (
            admission.executable
            or admission.intent_kind != "navigate"
            or admission.risk_class != "read_interaction"
            or admission.expected_side_effect != "navigation"
            or admission.action_limit != 1
            or admission.locator_truncated
            or admission.disabled
            or admission.scripted_handler
            or admission.safety_blockers != (PASSIVE_CATALOG_BLOCKER,)
        ):
            raise InteractionAcquisitionDenied(
                "interaction_admission_is_not_a_safe_navigation"
            )
        _verify_authorization(
            self.authorization,
            target_origin=self.target_origin,
        )
        expected_target_ref = stable_hash(
            "interaction_target",
            self.target_origin,
        )
        if admission.target_ref != expected_target_ref:
            raise InteractionAcquisitionDenied(
                "interaction_acquisition_target_binding_changed"
            )
        budget = self.executor.policy.budget
        current_policy = InteractionAdmissionPolicy.create(
            policy_digest=self.executor.policy.digest(),
            budget_snapshot=budget.snapshot(),
            max_total_requests=budget.max_total_requests,
            world_id=self.actor_persona_id,
        )
        if (
            admission.world_ref != current_policy.world_ref
            or admission.policy_ref != current_policy.policy_ref
            or admission.budget_ref != current_policy.budget_ref
            or not current_policy.budget_available
            or self.executor.provenance is None
        ):
            raise InteractionAcquisitionDenied(
                "interaction_acquisition_policy_binding_changed"
            )

    async def _resolve(self) -> _ResolvedNavigation:
        self._validate_static_preflight()
        try:
            value = await self.resolver(
                self.actor_persona_id,
                [segment.to_dict() for segment in self.admission.locator],
                self.peer_persona_id,
            )
        except InteractionAcquisitionDenied:
            raise
        except Exception as exc:
            raise InteractionAcquisitionDenied(
                "interaction_navigation_resolution_failed"
            ) from exc
        required_keys = {
            "current_url",
            "destination_url",
            "control",
            "catalog_controls",
            "peer_catalog_controls",
        }
        if (
            not isinstance(value, Mapping)
            or set(value) not in (
                required_keys,
                required_keys | {"ownership_witness"},
            )
        ):
            raise InteractionAcquisitionDenied(
                "interaction_navigation_resolution_is_invalid"
            )
        current_url = str(value.get("current_url") or "")
        destination_url = str(value.get("destination_url") or "")
        if (
            _origin(current_url) != self.target_origin
            or _origin(destination_url) != self.target_origin
        ):
            raise InteractionAcquisitionDenied(
                "interaction_navigation_resolution_changed_origin"
            )
        catalog_controls = value.get("catalog_controls")
        peer_controls = value.get("peer_catalog_controls")
        control = value.get("control")
        if (
            not isinstance(catalog_controls, Sequence)
            or isinstance(catalog_controls, (str, bytes))
            or not isinstance(peer_controls, Sequence)
            or isinstance(peer_controls, (str, bytes))
            or not isinstance(control, Mapping)
        ):
            raise InteractionAcquisitionDenied(
                "interaction_navigation_catalog_is_invalid"
            )
        try:
            miner = InteractionIntentMiner()
            catalog = miner.mine(
                catalog_controls,
                target_origin=self.target_origin,
                world_id=self.actor_persona_id,
                peer_controls=peer_controls,
                peer_world_id=self.peer_persona_id,
                page_url=current_url,
            )
            resolved_catalog = miner.mine(
                [control],
                target_origin=self.target_origin,
                world_id=self.actor_persona_id,
                page_url=current_url,
            )
        except (TypeError, ValueError) as exc:
            raise InteractionAcquisitionDenied(
                "interaction_navigation_catalog_cannot_be_rebuilt"
            ) from exc
        if (
            catalog.catalog_id != self.admission.catalog_id
            or len(resolved_catalog.intents) != 1
        ):
            raise InteractionAcquisitionDenied(
                "interaction_navigation_catalog_binding_changed"
            )
        current_intent = resolved_catalog.intents[0]
        ownership_witness = value.get("ownership_witness")
        if (
            current_intent.intent_id != self.admission.intent_id
            or current_intent.locator_ref != self.admission.locator_ref
            or current_intent.page_ref != self.admission.page_ref
            or current_intent.world_ref != self.admission.world_ref
            or current_intent.intent_kind != "navigate"
            or current_intent.risk_class != "read_interaction"
            or current_intent.safety_blockers != (PASSIVE_CATALOG_BLOCKER,)
            or (
                ownership_witness is not None
                and (
                    not isinstance(
                        ownership_witness,
                        NativeOwnedCreationWitness,
                    )
                    or ownership_witness.persona_id != self.actor_persona_id
                    or ownership_witness.destination_ref
                    != current_intent.destination_ref
                )
            )
        ):
            raise InteractionAcquisitionDenied(
                "interaction_navigation_intent_binding_changed"
            )
        resolution_id = stable_hash(
            "interaction_navigation_resolution",
            {
                "admission_id": self.admission.admission_id,
                "catalog_id": catalog.catalog_id,
                "intent_id": current_intent.intent_id,
                "current_page_ref": current_intent.page_ref,
                "destination_url": destination_url,
                "ownership_proof_ref": (
                    ownership_witness.proof_ref
                    if isinstance(
                        ownership_witness,
                        NativeOwnedCreationWitness,
                    )
                    else None
                ),
            },
        )
        return _ResolvedNavigation(
            resolution_id=resolution_id,
            ownership_witness=ownership_witness,
            destination_url=destination_url,
            current_url=current_url,
        )

    async def validate_preflight(self) -> str:
        """Return a fresh, local-only resolution identity."""

        return (await self._resolve()).resolution_id

    async def execute(
        self,
        *,
        expected_resolution_id: str,
    ) -> InteractionAcquisitionResult:
        resolved = await self._resolve()
        if resolved.resolution_id != expected_resolution_id:
            raise InteractionAcquisitionDenied(
                "interaction_navigation_resolution_changed_before_send"
            )
        budget = self.executor.policy.budget
        action_class = (
            CROSS_OBJECT_READ
            if self.request_persona_id != self.actor_persona_id
            else SAFE_READ
        )
        ownership_proof_ref = None
        if action_class == CROSS_OBJECT_READ:
            registry = self.executor.policy.ownership_registry
            if registry is None:
                raise InteractionAcquisitionDenied(
                    "interaction_cross_persona_ownership_registry_unavailable"
                )
            if registry.owner_of(resolved.destination_url) != self.actor_persona_id:
                witness = resolved.ownership_witness
                if witness is None or registry.register_native_witnessed_read(
                    resolved.destination_url,
                    witness,
                    actor_persona=self.actor_persona_id,
                    destination_ref=self.admission.destination_ref,
                ) is None:
                    raise InteractionAcquisitionDenied(
                        "interaction_cross_persona_ownership_proof_unavailable"
                    )
                ownership_proof_ref = witness.proof_ref
            if registry.owner_of(resolved.destination_url) != self.actor_persona_id:
                raise InteractionAcquisitionDenied(
                    "interaction_cross_persona_ownership_binding_changed"
                )
        reservation_id, reason = budget.try_reserve(
            ((action_class, endpoint_key(resolved.destination_url)),)
        )
        if reservation_id is None:
            raise InteractionAcquisitionDenied(
                f"interaction_acquisition_budget_denied:{reason}"
            )
        skipped_before = len(self.executor.skipped)
        try:
            try:
                status, response = await self.executor.send_action(
                    CandidateAction(
                        method="GET",
                        url=resolved.destination_url,
                        body=None,
                        hint=action_class,
                        actor_persona_id=self.request_persona_id,
                        target_owner_persona_id=self.actor_persona_id,
                        target_is_researcher_owned=True,
                        expected_side_effect="read_only_navigation",
                        proof_goal=(
                            "source_only_navigation_authorization_probe"
                            if action_class == CROSS_OBJECT_READ
                            else "obligation_directed_interaction_acquisition"
                        ),
                        budget_reservation_id=reservation_id,
                    ),
                    _max_response_chars=_MAX_RESPONSE_CHARS,
                    _redirect_mode="manual",
                )
            except Exception as exc:
                raise InteractionAcquisitionDenied(
                    "interaction_acquisition_transport_failed",
                    target_request_possible=True,
                ) from exc
        finally:
            budget.release_reservation(reservation_id)
        if status == DENIED_STATUS:
            raise InteractionAcquisitionDenied(
                "interaction_acquisition_was_denied_by_policy"
            )
        if (
            isinstance(status, bool)
            or not isinstance(status, int)
            or not 100 <= status <= 599
            or not isinstance(response, str)
        ):
            raise InteractionAcquisitionDenied(
                "interaction_acquisition_transport_result_is_invalid",
                target_request_possible=True,
            )
        response_truncated = bool(
            getattr(response, "body_truncated", False)
        )
        request_ref = stable_hash(
            "interaction_acquisition_request",
            {
                "method": "GET",
                "url": resolved.destination_url,
                "redirect_mode": "manual",
            },
        )
        response_ref = stable_hash(
            "interaction_acquisition_response",
            {
                "request_ref": request_ref,
                "status": status,
                "body_hash": body_hash(response),
                "shape": response_shape(response),
                "truncated": response_truncated,
            },
        )
        sink = self.executor.provenance
        record = {
            "action": "interaction_acquisition",
            "persona_id": self.request_persona_id,
            "type": "fetch",
            "url": resolved.destination_url,
            "method": "GET",
            "request_headers": {},
            "request_body": "",
            "response_status": status,
            "response_body": str(response),
            "request_truncated": False,
            "response_truncated": response_truncated,
        }
        normalized = normalize_exchange(
            record,
            world_id=self.request_persona_id,
        )
        destination_page_ref = stable_hash(
            "interaction_page",
            {
                "origin": normalized.origin,
                "path_template": normalized.path_template,
            },
        )
        operation_ref = normalized.action_id
        acquisition_id = stable_hash(
            "interaction_read_acquisition",
            {
                "admission_id": self.admission.admission_id,
                "resolution_id": resolved.resolution_id,
                "destination_page_ref": destination_page_ref,
                "operation_ref": operation_ref,
                "request_ref": request_ref,
                "response_ref": response_ref,
            },
        )
        return InteractionAcquisitionResult(
            acquisition_id=acquisition_id,
            admission_id=self.admission.admission_id,
            obligation_id=self.admission.obligation_id,
            destination_page_ref=destination_page_ref,
            operation_ref=operation_ref,
            request_ref=request_ref,
            response_ref=response_ref,
            response_status=status,
            response_truncated=response_truncated,
            cross_persona_probe=(
                self.request_persona_id != self.actor_persona_id
            ),
            ownership_proof_ref=ownership_proof_ref,
            requests_attempted=1,
            requests_sent=1,
            policy_denials=len(self.executor.skipped) - skipped_before,
            provenance_root=(sink.root() if sink is not None else "") or "",
            budget_snapshot=budget.snapshot(),
            restraint=self.executor.restraint_summary(),
            record=record,
        )


@dataclass(frozen=True)
class InteractionAcquisitionAdmissionResult:
    status: str
    receipt_id: str
    reused: bool
    execution: Dict[str, Any]
    record: Optional[Dict[str, Any]] = field(
        default=None,
        repr=False,
        compare=False,
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "receipt": {
                "receipt_id": self.receipt_id,
                "state": COMPLETED,
                "reused": self.reused,
            },
            "execution": copy.deepcopy(self.execution),
        }


class InteractionReadAcquisitionAdmission:
    """Reserve durable identity before one acquisition may send target traffic."""

    def __init__(
        self,
        boundary: InteractionReadAcquisitionBoundary,
        *,
        receipt_store: Optional[BehavioralReceiptStore] = None,
    ) -> None:
        if not isinstance(boundary, InteractionReadAcquisitionBoundary):
            raise TypeError("interaction acquisition boundary is required")
        self.boundary = boundary
        self.receipt_store = receipt_store or BehavioralReceiptStore()

    def _context(self) -> BehavioralReceiptContext:
        boundary = self.boundary
        return redacted_receipt_context(
            target_origin=boundary.target_origin,
            envelope_id=boundary.authorization.envelope_id,
            source_persona_id=boundary.actor_persona_id,
            peer_persona_id=boundary.peer_persona_id,
        )

    def _descriptor(self, resolution_id: str) -> Dict[str, Any]:
        boundary = self.boundary
        return {
            "schema_version": 1,
            "mode": INTERACTION_ACQUISITION_MODE,
            "resolution_id": resolution_id,
            "admission_id": boundary.admission.admission_id,
            "obligation_id": boundary.admission.obligation_id,
            "target_origin": boundary.target_origin,
            "envelope_id": boundary.authorization.envelope_id,
            "authorization_signature": (
                boundary.authorization.attestation_signature
            ),
            "actor_persona_id": boundary.actor_persona_id,
            "peer_persona_id": boundary.peer_persona_id,
            "request_persona_id": boundary.request_persona_id,
            "policy_digest": boundary.executor.policy.digest(),
        }

    async def _identity(self) -> Tuple[str, str]:
        resolution_id = await self.boundary.validate_preflight()
        try:
            fingerprint = request_fingerprint(self._descriptor(resolution_id))
        except (TypeError, ValueError) as exc:
            raise InteractionAcquisitionDenied(
                "interaction_acquisition_admission_is_not_deterministic"
            ) from exc
        return resolution_id, fingerprint

    async def validate_preflight(self) -> str:
        _resolution_id, fingerprint = await self._identity()
        return fingerprint

    async def execute(self) -> InteractionAcquisitionAdmissionResult:
        resolution_id, fingerprint = await self._identity()
        context = self._context()
        try:
            reservation = self.receipt_store.reserve(
                fingerprint,
                context=context,
            )
        except (OSError, ReceiptStoreError) as exc:
            raise InteractionAcquisitionDenied(
                "interaction_acquisition_receipt_store_unavailable"
            ) from exc
        if not reservation.created:
            if reservation.receipt.context != context:
                raise InteractionAcquisitionDenied(
                    "interaction_acquisition_receipt_context_mismatch"
                )
            if (
                reservation.receipt.state == COMPLETED
                and reservation.receipt.outcome is not None
                and reservation.receipt.outcome.get("kind")
                == "interaction_read_acquisition"
            ):
                return InteractionAcquisitionAdmissionResult(
                    status="already_executed",
                    receipt_id=reservation.receipt.receipt_id,
                    reused=True,
                    execution=copy.deepcopy(reservation.receipt.outcome),
                )
            raise InteractionAcquisitionDenied(
                "interaction_acquisition_is_already_reserved_or_terminal"
            )
        token = reservation.reservation_token
        if token is None:
            raise InteractionAcquisitionDenied(
                "interaction_acquisition_reservation_token_is_unavailable"
            )
        try:
            result = await self.boundary.execute(
                expected_resolution_id=resolution_id,
            )
        except Exception:
            try:
                self.receipt_store.abort(
                    fingerprint,
                    reservation_token=token,
                    reason="interaction_acquisition_error",
                )
            except (OSError, ReceiptStoreError) as receipt_exc:
                raise InteractionAcquisitionDenied(
                    "interaction_acquisition_failed_and_receipt_could_not_finalize"
                ) from receipt_exc
            raise
        outcome = redacted_interaction_acquisition_outcome(result.to_dict())
        try:
            completed = self.receipt_store.complete(
                fingerprint,
                reservation_token=token,
                outcome=outcome,
            )
        except (OSError, ReceiptStoreError) as exc:
            raise InteractionAcquisitionDenied(
                "interaction_acquisition_completed_but_receipt_could_not_finalize",
                target_request_possible=True,
            ) from exc
        if completed.outcome is None:
            raise InteractionAcquisitionDenied(
                "interaction_acquisition_receipt_outcome_is_missing",
                target_request_possible=True,
            )
        return InteractionAcquisitionAdmissionResult(
            status=result.status,
            receipt_id=completed.receipt_id,
            reused=False,
            execution=copy.deepcopy(completed.outcome),
            record=copy.deepcopy(result.record),
        )


__all__ = [
    "INTERACTION_ACQUISITION_ENV",
    "INTERACTION_ACQUISITION_MODE",
    "INTERACTION_ACQUISITION_WORKFLOW",
    "InteractionAcquisitionAdmissionResult",
    "InteractionAcquisitionConfig",
    "InteractionAcquisitionDenied",
    "InteractionAcquisitionResult",
    "InteractionReadAcquisitionAdmission",
    "InteractionReadAcquisitionBoundary",
]
