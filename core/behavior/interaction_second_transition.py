"""Receipt-chained execution of one second inertly resolved safe read.

The boundary accepts only the exact next admission sealed by the first browser-state
transition. It resolves that admission against the same receipt-bound response bytes
twice and delegates the single authenticated GET to the existing interaction
acquisition boundary. It grants no live DOM, script, form, write, redirect, or
external-origin authority.
"""

from __future__ import annotations

import copy
import hmac
import os
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Dict, Mapping, Optional, Tuple

from core.cortex.execution_policy import PolicyExecutor
from core.foundry.authorization import AuthorizationEnvelope

from .interaction_admission import InteractionIntentAdmission
from .interaction_boundary import (
    InteractionAcquisitionAdmissionResult,
    InteractionAcquisitionConfig,
    InteractionAcquisitionDenied,
    InteractionReadAcquisitionBoundary,
)
from .interaction_render import (
    InteractionRenderObservation,
    InteractionRenderObservationBoundary,
)
from .interaction_state import BrowserTransitionResult
from .receipts import (
    COMPLETED,
    BehavioralReceiptContext,
    BehavioralReceiptStore,
    ReceiptStoreError,
    redacted_interaction_acquisition_outcome,
    redacted_receipt_context,
    request_fingerprint,
)

INTERACTION_SECOND_TRANSITION_ENV = (
    "SENTINELFORGE_BEHAVIOR_INTERACTION_SECOND_TRANSITION"
)
INTERACTION_SECOND_TRANSITION_MODE = (
    "behavioral_interaction_second_read_transition_v1"
)
INTERACTION_SECOND_TRANSITION_WORKFLOW = (
    "behavioral_interaction_second_read_transition"
)
_TRUE = frozenset({"1", "true", "yes", "on"})

InertNavigationResolver = Callable[..., Awaitable[Mapping[str, Any]]]


class InteractionSecondTransitionDenied(RuntimeError):
    """The parent binding, child receipt, or second read failed closed."""

    def __init__(
        self,
        message: str,
        *,
        target_request_possible: bool = False,
    ) -> None:
        super().__init__(message)
        self.target_request_possible = bool(target_request_possible)


@dataclass(frozen=True)
class InteractionSecondTransitionConfig:
    enabled: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.enabled, bool):
            raise ValueError(
                "interaction second transition enabled must be a boolean"
            )

    @classmethod
    def from_environment(cls) -> "InteractionSecondTransitionConfig":
        return cls(
            enabled=os.environ.get(
                INTERACTION_SECOND_TRANSITION_ENV,
                "",
            ).strip().lower()
            in _TRUE
        )


def _verify_authorization(
    envelope: AuthorizationEnvelope,
    *,
    target_origin: str,
) -> None:
    signature = envelope.attestation_signature
    if not signature:
        raise InteractionSecondTransitionDenied(
            "interaction_second_transition_authorization_is_unsigned"
        )
    verification = copy.deepcopy(envelope)
    if not hmac.compare_digest(signature, verification.sign()):
        raise InteractionSecondTransitionDenied(
            "interaction_second_transition_authorization_signature_mismatch"
        )
    try:
        envelope.authorize_action(
            target_origin=target_origin,
            workflow=INTERACTION_SECOND_TRANSITION_WORKFLOW,
        )
    except Exception as exc:
        raise InteractionSecondTransitionDenied(
            "interaction_second_transition_authorization_denied"
        ) from exc


class InteractionSecondReadBoundary:
    """Revalidate the parent state and execute its one sealed next read."""

    def __init__(
        self,
        *,
        admission: InteractionIntentAdmission,
        parent_transition: BrowserTransitionResult,
        source_boundary: InteractionRenderObservationBoundary,
        observation: InteractionRenderObservation,
        target_origin: str,
        authorization: AuthorizationEnvelope,
        actor_persona_id: str,
        peer_persona_id: str,
        executor: PolicyExecutor,
        resolver: InertNavigationResolver,
        config: Optional[InteractionSecondTransitionConfig] = None,
    ) -> None:
        if not isinstance(admission, InteractionIntentAdmission):
            raise TypeError("second interaction admission is required")
        if not isinstance(parent_transition, BrowserTransitionResult):
            raise TypeError("parent browser transition is required")
        if not isinstance(
            source_boundary,
            InteractionRenderObservationBoundary,
        ):
            raise TypeError("interaction response source boundary is required")
        if not isinstance(observation, InteractionRenderObservation):
            raise TypeError("interaction render observation is required")
        if not isinstance(authorization, AuthorizationEnvelope):
            raise TypeError("authorization envelope is required")
        if not isinstance(executor, PolicyExecutor):
            raise TypeError("policy executor is required")
        if not callable(resolver):
            raise TypeError("inert interaction resolver is required")
        if (
            not isinstance(actor_persona_id, str)
            or not actor_persona_id
            or not isinstance(peer_persona_id, str)
            or not peer_persona_id
            or actor_persona_id == peer_persona_id
        ):
            raise ValueError("two distinct interaction personas are required")
        self.admission = admission
        self.parent_transition = parent_transition
        self.source_boundary = source_boundary
        self.observation = observation
        self.target_origin = target_origin
        self.authorization = authorization
        self.actor_persona_id = actor_persona_id
        self.peer_persona_id = peer_persona_id
        self.executor = executor
        self.resolver = resolver
        self.config = (
            config or InteractionSecondTransitionConfig.from_environment()
        )

    @property
    def parent_receipt_id(self) -> str:
        return self.parent_transition.transition.receipt_id

    @property
    def parent_transition_id(self) -> str:
        return self.parent_transition.transition.transition_id

    def _validate_parent(self) -> tuple[str, str]:
        if not self.config.enabled:
            raise InteractionSecondTransitionDenied(
                "interaction_second_transition_is_disabled"
            )
        _verify_authorization(
            self.authorization,
            target_origin=self.target_origin,
        )
        parent = self.parent_transition
        transition = parent.transition
        after_state = parent.after_state
        observation = self.observation
        admission = self.admission
        if (
            not observation.complete
            or parent.transition_count != 1
            or transition.depth != 1
            or transition.decision != "eligible_for_next_transition"
            or transition.next_admission_id != admission.admission_id
            or transition.next_intent_id != admission.intent_id
            or transition.after_state_id != after_state.state_id
            or observation.acquisition_receipt_id != transition.receipt_id
            or observation.acquisition_id
            != self.source_boundary.acquisition.get("acquisition_id")
            or observation.response_ref
            != self.source_boundary.acquisition.get("response_ref")
            or observation.admission_id
            != self.source_boundary.admission.admission_id
            or observation.obligation_id
            != self.source_boundary.admission.obligation_id
            or observation.page_ref != after_state.page_ref
            or observation.catalog_id != after_state.interaction_catalog_id
            or observation.target_ref != after_state.target_ref
            or observation.world_ref != after_state.world_ref
            or admission.target_ref != after_state.target_ref
            or admission.world_ref != after_state.world_ref
            or admission.page_ref != after_state.page_ref
            or admission.catalog_id != after_state.interaction_catalog_id
            or admission.policy_ref != after_state.policy_ref
            or admission.budget_ref != after_state.budget_ref
        ):
            raise InteractionSecondTransitionDenied(
                "interaction_second_transition_parent_binding_changed"
            )
        if (
            self.source_boundary.authorization.envelope_id
            != self.authorization.envelope_id
            or self.source_boundary.authorization.attestation_signature
            != self.authorization.attestation_signature
            or self.source_boundary.target_origin != self.target_origin
            or self.source_boundary.actor_persona_id
            != self.actor_persona_id
            or self.source_boundary.peer_persona_id
            != self.peer_persona_id
            or self.source_boundary.acquisition_receipt_id
            != observation.acquisition_receipt_id
        ):
            raise InteractionSecondTransitionDenied(
                "interaction_second_transition_source_context_changed"
            )
        try:
            return self.source_boundary.validated_source()
        except Exception as exc:
            raise InteractionSecondTransitionDenied(
                "interaction_second_transition_source_binding_changed"
            ) from exc

    def _acquisition_boundary(self) -> InteractionReadAcquisitionBoundary:
        base_url, html = self._validate_parent()

        async def resolve(
            persona_id: str,
            locator: Any,
            peer_persona_id: Optional[str],
        ) -> Mapping[str, Any]:
            if (
                persona_id != self.actor_persona_id
                or peer_persona_id != self.peer_persona_id
            ):
                raise InteractionSecondTransitionDenied(
                    "interaction_second_transition_persona_binding_changed"
                )
            try:
                return await self.resolver(
                    persona_id,
                    locator,
                    base_url=base_url,
                    html=html,
                )
            except InteractionSecondTransitionDenied:
                raise
            except Exception as exc:
                raise InteractionSecondTransitionDenied(
                    "interaction_second_transition_resolution_failed"
                ) from exc

        return InteractionReadAcquisitionBoundary(
            admission=self.admission,
            target_origin=self.target_origin,
            authorization=self.authorization,
            actor_persona_id=self.actor_persona_id,
            peer_persona_id=self.peer_persona_id,
            executor=self.executor,
            resolver=resolve,
            config=InteractionAcquisitionConfig(enabled=True),
        )

    async def validate_preflight(self) -> str:
        try:
            return await self._acquisition_boundary().validate_preflight()
        except InteractionSecondTransitionDenied:
            raise
        except InteractionAcquisitionDenied as exc:
            raise InteractionSecondTransitionDenied(str(exc)) from exc

    async def execute(
        self,
        *,
        expected_resolution_id: str,
    ):
        try:
            return await self._acquisition_boundary().execute(
                expected_resolution_id=expected_resolution_id,
            )
        except InteractionSecondTransitionDenied:
            raise
        except InteractionAcquisitionDenied as exc:
            raise InteractionSecondTransitionDenied(
                str(exc),
                target_request_possible=exc.target_request_possible,
            ) from exc


class InteractionSecondReadAdmission:
    """Reserve a parent-bound child receipt before the second GET."""

    def __init__(
        self,
        boundary: InteractionSecondReadBoundary,
        *,
        receipt_store: Optional[BehavioralReceiptStore] = None,
    ) -> None:
        if not isinstance(boundary, InteractionSecondReadBoundary):
            raise TypeError("interaction second transition boundary is required")
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
        parent = boundary.parent_transition
        return {
            "schema_version": 1,
            "mode": INTERACTION_SECOND_TRANSITION_MODE,
            "resolution_id": resolution_id,
            "parent_receipt_id": boundary.parent_receipt_id,
            "parent_transition_id": boundary.parent_transition_id,
            "parent_after_state_id": parent.after_state.state_id,
            "observation_id": boundary.observation.observation_id,
            "admission_id": boundary.admission.admission_id,
            "obligation_id": boundary.admission.obligation_id,
            "target_origin": boundary.target_origin,
            "envelope_id": boundary.authorization.envelope_id,
            "authorization_signature": (
                boundary.authorization.attestation_signature
            ),
            "actor_persona_id": boundary.actor_persona_id,
            "peer_persona_id": boundary.peer_persona_id,
            "policy_digest": boundary.executor.policy.digest(),
            "depth": 2,
            "transition_ceiling": 2,
        }

    async def _identity(self) -> Tuple[str, str]:
        resolution_id = await self.boundary.validate_preflight()
        try:
            fingerprint = request_fingerprint(
                self._descriptor(resolution_id)
            )
        except (TypeError, ValueError) as exc:
            raise InteractionSecondTransitionDenied(
                "interaction_second_transition_admission_is_not_deterministic"
            ) from exc
        return resolution_id, fingerprint

    async def execute(self) -> InteractionAcquisitionAdmissionResult:
        resolution_id, fingerprint = await self._identity()
        context = self._context()
        try:
            reservation = self.receipt_store.reserve(
                fingerprint,
                context=context,
            )
        except (OSError, ReceiptStoreError) as exc:
            raise InteractionSecondTransitionDenied(
                "interaction_second_transition_receipt_store_unavailable"
            ) from exc
        if not reservation.created:
            if reservation.receipt.context != context:
                raise InteractionSecondTransitionDenied(
                    "interaction_second_transition_receipt_context_mismatch"
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
            raise InteractionSecondTransitionDenied(
                "interaction_second_transition_is_already_reserved_or_terminal"
            )
        token = reservation.reservation_token
        if token is None:
            raise InteractionSecondTransitionDenied(
                "interaction_second_transition_reservation_token_is_unavailable"
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
                    reason="interaction_second_transition_error",
                )
            except (OSError, ReceiptStoreError) as receipt_exc:
                raise InteractionSecondTransitionDenied(
                    "interaction_second_transition_failed_and_receipt_could_not_finalize"
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
            raise InteractionSecondTransitionDenied(
                "interaction_second_transition_completed_but_receipt_could_not_finalize",
                target_request_possible=True,
            ) from exc
        if completed.outcome is None:
            raise InteractionSecondTransitionDenied(
                "interaction_second_transition_receipt_outcome_is_missing",
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
    "INTERACTION_SECOND_TRANSITION_ENV",
    "INTERACTION_SECOND_TRANSITION_MODE",
    "INTERACTION_SECOND_TRANSITION_WORKFLOW",
    "InteractionSecondReadAdmission",
    "InteractionSecondReadBoundary",
    "InteractionSecondTransitionConfig",
    "InteractionSecondTransitionDenied",
]
