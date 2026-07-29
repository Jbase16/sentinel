"""Bounded adaptive execution of receipt-chained same-origin safe reads.

The controller may continue only from the exact next admission sealed by the
immediately preceding browser-state transition. Every child is resolved twice from
the same receipt-bound inert response, receives its own parent-bound durable receipt,
and is stopped by explicit state, transition, depth, endpoint, and proof budgets.
It grants no live-DOM, script, form, write, redirect, or external-origin authority.
"""

from __future__ import annotations

import copy
import hmac
import os
import re
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, Mapping, Optional, Sequence, Tuple

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
    InteractionRenderConfig,
    InteractionRenderDenied,
    InteractionRenderObservation,
    InteractionRenderObservationBoundary,
)
from .interaction_state import (
    BrowserStateLimits,
    BrowserTransitionResult,
    build_chained_acquisition_transition,
)
from .normalize import stable_hash
from .receipts import (
    COMPLETED,
    BehavioralReceiptContext,
    BehavioralReceiptStore,
    ReceiptStoreError,
    redacted_interaction_acquisition_outcome,
    redacted_receipt_context,
    request_fingerprint,
)

INTERACTION_ADAPTIVE_ENV = "SENTINELFORGE_BEHAVIOR_INTERACTION_ADAPTIVE"
INTERACTION_ADAPTIVE_MODE = "behavioral_interaction_adaptive_safe_read_v1"
INTERACTION_ADAPTIVE_STEP_MODE = "behavioral_interaction_adaptive_read_v1"
INTERACTION_ADAPTIVE_WORKFLOW = "behavioral_interaction_adaptive_safe_read"
INTERACTION_ADAPTIVE_LIMITS = BrowserStateLimits(
    max_states=5,
    max_transitions=4,
    max_depth=4,
)

_TRUE = frozenset({"1", "true", "yes", "on"})
_HASH_REF = re.compile(r"^[a-z][a-z0-9_]*:[0-9a-f]{64}$")
_RECEIPT_ID = re.compile(r"^behavioral-[0-9a-f]{64}$")

InertNavigationResolver = Callable[..., Awaitable[Mapping[str, Any]]]
InteractionResponseObserver = Callable[..., Awaitable[Mapping[str, Any]]]
AdaptiveDeriver = Callable[
    [
        Mapping[str, Any],
        InteractionRenderObservation,
        Any,
        int,
    ],
    Awaitable["InteractionAdaptiveDerivation"],
]
RecordSink = Callable[[Mapping[str, Any]], None]


def _limits_dict(limits: BrowserStateLimits) -> Dict[str, int]:
    return {
        "max_states": limits.max_states,
        "max_transitions": limits.max_transitions,
        "max_depth": limits.max_depth,
        "max_operation_refs": limits.max_operation_refs,
        "max_obligation_refs": limits.max_obligation_refs,
    }


def _hash_ref(value: Any, prefix: str) -> bool:
    return (
        isinstance(value, str)
        and value.startswith(f"{prefix}:")
        and _HASH_REF.fullmatch(value) is not None
    )


class InteractionAdaptiveDenied(RuntimeError):
    """The adaptive chain failed closed before or after a possible target read."""

    def __init__(
        self,
        message: str,
        *,
        target_request_possible: bool = False,
        target_requests_sent: int = 0,
    ) -> None:
        super().__init__(message)
        if (
            isinstance(target_requests_sent, bool)
            or not isinstance(target_requests_sent, int)
            or target_requests_sent < 0
        ):
            raise ValueError("adaptive target request count is invalid")
        self.target_request_possible = bool(target_request_possible)
        self.target_requests_sent = target_requests_sent


@dataclass(frozen=True)
class InteractionAdaptiveConfig:
    enabled: bool = False
    limits: BrowserStateLimits = INTERACTION_ADAPTIVE_LIMITS

    def __post_init__(self) -> None:
        if not isinstance(self.enabled, bool):
            raise ValueError("adaptive interaction enabled must be a boolean")
        if not isinstance(self.limits, BrowserStateLimits):
            raise ValueError("adaptive interaction limits are invalid")
        if (
            self.limits.max_states > INTERACTION_ADAPTIVE_LIMITS.max_states
            or self.limits.max_transitions
            > INTERACTION_ADAPTIVE_LIMITS.max_transitions
            or self.limits.max_depth > INTERACTION_ADAPTIVE_LIMITS.max_depth
            or self.limits.max_operation_refs
            > INTERACTION_ADAPTIVE_LIMITS.max_operation_refs
            or self.limits.max_obligation_refs
            > INTERACTION_ADAPTIVE_LIMITS.max_obligation_refs
        ):
            raise ValueError(
                "adaptive interaction limits exceed the implementation ceiling"
            )

    @classmethod
    def from_environment(cls) -> "InteractionAdaptiveConfig":
        return cls(
            enabled=os.environ.get(INTERACTION_ADAPTIVE_ENV, "").strip().lower()
            in _TRUE
        )


def _verify_authorization(
    envelope: AuthorizationEnvelope,
    *,
    target_origin: str,
) -> None:
    signature = envelope.attestation_signature
    if not signature:
        raise InteractionAdaptiveDenied(
            "interaction_adaptive_authorization_is_unsigned"
        )
    verification = copy.deepcopy(envelope)
    if not hmac.compare_digest(signature, verification.sign()):
        raise InteractionAdaptiveDenied(
            "interaction_adaptive_authorization_signature_mismatch"
        )
    try:
        envelope.authorize_action(
            target_origin=target_origin,
            workflow=INTERACTION_ADAPTIVE_WORKFLOW,
        )
    except Exception as exc:
        raise InteractionAdaptiveDenied(
            "interaction_adaptive_authorization_denied"
        ) from exc


@dataclass(frozen=True)
class InteractionAdaptiveDerivation:
    """One local shadow re-derivation after a newly observed response."""

    after_frontier: Tuple[Dict[str, Any], ...]
    next_admission: Optional[InteractionIntentAdmission]
    state: Any = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if any(not isinstance(item, dict) for item in self.after_frontier):
            raise ValueError("adaptive derivation frontier is invalid")
        if self.next_admission is not None and not isinstance(
            self.next_admission,
            InteractionIntentAdmission,
        ):
            raise ValueError("adaptive derivation admission is invalid")


class InteractionAdaptiveReadBoundary:
    """Execute one exact child read from an immediate receipt-backed parent."""

    def __init__(
        self,
        *,
        admission: InteractionIntentAdmission,
        parent_transition: BrowserTransitionResult,
        source_boundary: InteractionRenderObservationBoundary,
        observation: InteractionRenderObservation,
        root_receipt_id: str,
        root_transition_id: str,
        controller_id: str,
        parent_chain_ref: str,
        target_origin: str,
        authorization: AuthorizationEnvelope,
        actor_persona_id: str,
        peer_persona_id: str,
        executor: PolicyExecutor,
        resolver: InertNavigationResolver,
        config: InteractionAdaptiveConfig,
    ) -> None:
        if not isinstance(admission, InteractionIntentAdmission):
            raise TypeError("adaptive interaction admission is required")
        if not isinstance(parent_transition, BrowserTransitionResult):
            raise TypeError("adaptive parent transition is required")
        if not isinstance(
            source_boundary,
            InteractionRenderObservationBoundary,
        ):
            raise TypeError("adaptive response source boundary is required")
        if not isinstance(observation, InteractionRenderObservation):
            raise TypeError("adaptive render observation is required")
        if not isinstance(authorization, AuthorizationEnvelope):
            raise TypeError("adaptive authorization envelope is required")
        if not isinstance(executor, PolicyExecutor):
            raise TypeError("adaptive policy executor is required")
        if not callable(resolver):
            raise TypeError("adaptive inert resolver is required")
        if not isinstance(config, InteractionAdaptiveConfig):
            raise TypeError("adaptive interaction config is required")
        if (
            not isinstance(actor_persona_id, str)
            or not actor_persona_id
            or not isinstance(peer_persona_id, str)
            or not peer_persona_id
            or actor_persona_id == peer_persona_id
        ):
            raise ValueError("two distinct adaptive interaction personas are required")
        if (
            _RECEIPT_ID.fullmatch(root_receipt_id) is None
            or not _hash_ref(root_transition_id, "browser_state_transition")
            or not _hash_ref(controller_id, "interaction_adaptive_controller")
            or not _hash_ref(parent_chain_ref, "interaction_adaptive_chain")
        ):
            raise ValueError("adaptive chain identity is invalid")
        self.admission = admission
        self.parent_transition = parent_transition
        self.source_boundary = source_boundary
        self.observation = observation
        self.root_receipt_id = root_receipt_id
        self.root_transition_id = root_transition_id
        self.controller_id = controller_id
        self.parent_chain_ref = parent_chain_ref
        self.target_origin = target_origin
        self.authorization = authorization
        self.actor_persona_id = actor_persona_id
        self.peer_persona_id = peer_persona_id
        self.executor = executor
        self.resolver = resolver
        self.config = config

    def _validate_parent(self) -> tuple[str, str]:
        if not self.config.enabled:
            raise InteractionAdaptiveDenied("interaction_adaptive_is_disabled")
        _verify_authorization(
            self.authorization,
            target_origin=self.target_origin,
        )
        parent = self.parent_transition
        transition = parent.transition
        after_state = parent.after_state
        observation = self.observation
        admission = self.admission
        limits = self.config.limits
        if (
            not observation.complete
            or parent.transition_count != transition.depth
            or transition.depth != after_state.depth
            or parent.transition_count >= limits.max_transitions
            or after_state.depth >= limits.max_depth
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
            raise InteractionAdaptiveDenied(
                "interaction_adaptive_parent_binding_changed"
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
            raise InteractionAdaptiveDenied(
                "interaction_adaptive_source_context_changed"
            )
        try:
            return self.source_boundary.validated_source()
        except Exception as exc:
            raise InteractionAdaptiveDenied(
                "interaction_adaptive_source_binding_changed"
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
                raise InteractionAdaptiveDenied(
                    "interaction_adaptive_persona_binding_changed"
                )
            try:
                return await self.resolver(
                    persona_id,
                    locator,
                    base_url=base_url,
                    html=html,
                )
            except InteractionAdaptiveDenied:
                raise
            except Exception as exc:
                raise InteractionAdaptiveDenied(
                    "interaction_adaptive_resolution_failed"
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
        except InteractionAdaptiveDenied:
            raise
        except InteractionAcquisitionDenied as exc:
            raise InteractionAdaptiveDenied(str(exc)) from exc

    async def execute(
        self,
        *,
        expected_resolution_id: str,
    ):
        try:
            return await self._acquisition_boundary().execute(
                expected_resolution_id=expected_resolution_id,
            )
        except InteractionAdaptiveDenied:
            raise
        except InteractionAcquisitionDenied as exc:
            raise InteractionAdaptiveDenied(
                str(exc),
                target_request_possible=exc.target_request_possible,
            ) from exc


class InteractionAdaptiveReadAdmission:
    """Reserve an immediate-parent-bound receipt before one adaptive GET."""

    def __init__(
        self,
        boundary: InteractionAdaptiveReadBoundary,
        *,
        receipt_store: BehavioralReceiptStore,
    ) -> None:
        if not isinstance(boundary, InteractionAdaptiveReadBoundary):
            raise TypeError("adaptive interaction boundary is required")
        if not isinstance(receipt_store, BehavioralReceiptStore):
            raise TypeError("adaptive receipt store is required")
        self.boundary = boundary
        self.receipt_store = receipt_store

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
            "mode": INTERACTION_ADAPTIVE_STEP_MODE,
            "resolution_id": resolution_id,
            "controller_id": boundary.controller_id,
            "root_receipt_id": boundary.root_receipt_id,
            "root_transition_id": boundary.root_transition_id,
            "parent_chain_ref": boundary.parent_chain_ref,
            "parent_receipt_id": parent.transition.receipt_id,
            "parent_transition_id": parent.transition.transition_id,
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
            "depth": parent.transition.depth + 1,
            "limits": _limits_dict(boundary.config.limits),
        }

    async def _identity(self) -> Tuple[str, str]:
        resolution_id = await self.boundary.validate_preflight()
        try:
            fingerprint = request_fingerprint(
                self._descriptor(resolution_id)
            )
        except (TypeError, ValueError) as exc:
            raise InteractionAdaptiveDenied(
                "interaction_adaptive_admission_is_not_deterministic"
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
            raise InteractionAdaptiveDenied(
                "interaction_adaptive_receipt_store_unavailable"
            ) from exc
        if not reservation.created:
            if reservation.receipt.context != context:
                raise InteractionAdaptiveDenied(
                    "interaction_adaptive_receipt_context_mismatch"
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
            raise InteractionAdaptiveDenied(
                "interaction_adaptive_is_already_reserved_or_terminal"
            )
        token = reservation.reservation_token
        if token is None:
            raise InteractionAdaptiveDenied(
                "interaction_adaptive_reservation_token_is_unavailable"
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
                    reason="interaction_adaptive_step_error",
                )
            except (OSError, ReceiptStoreError) as receipt_exc:
                raise InteractionAdaptiveDenied(
                    "interaction_adaptive_failed_and_receipt_could_not_finalize"
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
            raise InteractionAdaptiveDenied(
                "interaction_adaptive_completed_but_receipt_could_not_finalize",
                target_requests_sent=1,
            ) from exc
        if completed.outcome is None:
            raise InteractionAdaptiveDenied(
                "interaction_adaptive_receipt_outcome_is_missing",
                target_requests_sent=1,
            )
        return InteractionAcquisitionAdmissionResult(
            status=result.status,
            receipt_id=completed.receipt_id,
            reused=False,
            execution=copy.deepcopy(completed.outcome),
            record=copy.deepcopy(result.record),
        )


@dataclass(frozen=True)
class InteractionAdaptiveStep:
    step_index: int
    controller_id: str
    root_receipt_id: str
    root_transition_id: str
    parent_chain_ref: str
    chain_ref: str
    parent_receipt_id: str
    parent_transition_id: str
    parent_after_state_id: str
    observation_id: str
    acquisition: InteractionAcquisitionAdmissionResult = field(
        repr=False,
        compare=False,
    )
    render_observation: Dict[str, Any]
    state_transition: BrowserTransitionResult = field(
        repr=False,
        compare=False,
    )
    analysis_error_code: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        analysis = (
            {"status": "completed"}
            if self.analysis_error_code is None
            else {
                "status": "error",
                "error_code": self.analysis_error_code,
            }
        )
        return {
            "schema_version": 1,
            "mode": INTERACTION_ADAPTIVE_STEP_MODE,
            "status": self.acquisition.status,
            "step_index": self.step_index,
            "controller_id": self.controller_id,
            "root_receipt_id": self.root_receipt_id,
            "root_transition_id": self.root_transition_id,
            "parent_chain_ref": self.parent_chain_ref,
            "chain_ref": self.chain_ref,
            "parent_receipt_id": self.parent_receipt_id,
            "parent_transition_id": self.parent_transition_id,
            "parent_after_state_id": self.parent_after_state_id,
            "observation_id": self.observation_id,
            "receipt": {
                "receipt_id": self.acquisition.receipt_id,
                "state": COMPLETED,
                "reused": self.acquisition.reused,
            },
            "execution": copy.deepcopy(self.acquisition.execution),
            "target_requests_sent": 0 if self.acquisition.reused else 1,
            "render_observation": copy.deepcopy(self.render_observation),
            "state_transition": {
                "status": "completed",
                "result": self.state_transition.to_dict(),
            },
            "analysis": analysis,
            "executable": False,
        }


@dataclass(frozen=True)
class InteractionAdaptiveRunResult:
    controller_id: str
    root_receipt_id: str
    root_transition_id: str
    root_after_state_id: str
    root_chain_ref: str
    chain_ref: str
    steps: Tuple[InteractionAdaptiveStep, ...]
    final_transition: BrowserTransitionResult = field(
        repr=False,
        compare=False,
    )
    final_state: Any = field(repr=False, compare=False)
    limits: BrowserStateLimits

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": 1,
            "mode": INTERACTION_ADAPTIVE_MODE,
            "status": "completed",
            "controller_id": self.controller_id,
            "root_receipt_id": self.root_receipt_id,
            "root_transition_id": self.root_transition_id,
            "root_after_state_id": self.root_after_state_id,
            "root_chain_ref": self.root_chain_ref,
            "chain_ref": self.chain_ref,
            "limits": _limits_dict(self.limits),
            "steps": [item.to_dict() for item in self.steps],
            "target_requests_sent": sum(
                0 if item.acquisition.reused else 1
                for item in self.steps
            ),
            "transition_count": self.final_transition.transition_count,
            "final_state_id": self.final_transition.after_state.state_id,
            "stop_reasons": list(
                self.final_transition.transition.stop_reasons
            ),
            "executable": False,
        }


class InteractionAdaptiveController:
    """Run the sealed safe-read chain until an evidence-backed stop condition."""

    def __init__(
        self,
        *,
        target_origin: str,
        authorization: AuthorizationEnvelope,
        actor_persona_id: str,
        peer_persona_id: str,
        executor: PolicyExecutor,
        resolver: InertNavigationResolver,
        observer: InteractionResponseObserver,
        render_config: InteractionRenderConfig,
        receipt_store: BehavioralReceiptStore,
        config: InteractionAdaptiveConfig,
    ) -> None:
        if not isinstance(authorization, AuthorizationEnvelope):
            raise TypeError("adaptive authorization envelope is required")
        if not isinstance(executor, PolicyExecutor):
            raise TypeError("adaptive policy executor is required")
        if not callable(resolver) or not callable(observer):
            raise TypeError("adaptive native dependencies are required")
        if not isinstance(render_config, InteractionRenderConfig):
            raise TypeError("adaptive render config is required")
        if not isinstance(receipt_store, BehavioralReceiptStore):
            raise TypeError("adaptive receipt store is required")
        if not isinstance(config, InteractionAdaptiveConfig):
            raise TypeError("adaptive interaction config is required")
        if (
            not isinstance(actor_persona_id, str)
            or not actor_persona_id
            or not isinstance(peer_persona_id, str)
            or not peer_persona_id
            or actor_persona_id == peer_persona_id
        ):
            raise ValueError("two distinct adaptive interaction personas are required")
        self.target_origin = target_origin
        self.authorization = authorization
        self.actor_persona_id = actor_persona_id
        self.peer_persona_id = peer_persona_id
        self.executor = executor
        self.resolver = resolver
        self.observer = observer
        self.render_config = render_config
        self.receipt_store = receipt_store
        self.config = config

    def _controller_identity(
        self,
        parent: BrowserTransitionResult,
    ) -> tuple[str, str]:
        controller_id = stable_hash(
            "interaction_adaptive_controller",
            {
                "root_receipt_id": parent.transition.receipt_id,
                "root_transition_id": parent.transition.transition_id,
                "root_after_state_id": parent.after_state.state_id,
                "target_ref": parent.after_state.target_ref,
                "world_ref": parent.after_state.world_ref,
                "limits": _limits_dict(self.config.limits),
            },
        )
        root_chain_ref = stable_hash(
            "interaction_adaptive_chain",
            {
                "controller_id": controller_id,
                "receipt_id": parent.transition.receipt_id,
                "transition_id": parent.transition.transition_id,
                "after_state_id": parent.after_state.state_id,
            },
        )
        return controller_id, root_chain_ref

    async def run(
        self,
        *,
        initial_parent: BrowserTransitionResult,
        initial_source_boundary: InteractionRenderObservationBoundary,
        initial_observation: InteractionRenderObservation,
        initial_admission: InteractionIntentAdmission,
        initial_frontier: Sequence[Mapping[str, Any]],
        initial_state: Any,
        derive: AdaptiveDeriver,
        record_sink: Optional[RecordSink] = None,
    ) -> InteractionAdaptiveRunResult:
        if not self.config.enabled:
            raise InteractionAdaptiveDenied("interaction_adaptive_is_disabled")
        if not callable(derive):
            raise TypeError("adaptive derivation callback is required")
        if record_sink is not None and not callable(record_sink):
            raise TypeError("adaptive record sink is invalid")
        if (
            not isinstance(initial_parent, BrowserTransitionResult)
            or not isinstance(
                initial_source_boundary,
                InteractionRenderObservationBoundary,
            )
            or not isinstance(
                initial_observation,
                InteractionRenderObservation,
            )
            or not isinstance(
                initial_admission,
                InteractionIntentAdmission,
            )
            or initial_parent.transition_count != 1
            or initial_parent.transition.depth != 1
            or initial_parent.transition.decision
            != "eligible_for_next_transition"
        ):
            raise InteractionAdaptiveDenied(
                "interaction_adaptive_root_is_invalid"
            )
        _verify_authorization(
            self.authorization,
            target_origin=self.target_origin,
        )
        current_frontier = tuple(dict(item) for item in initial_frontier)
        controller_id, root_chain_ref = self._controller_identity(
            initial_parent
        )
        root_receipt_id = initial_parent.transition.receipt_id
        root_transition_id = initial_parent.transition.transition_id
        parent = initial_parent
        source_boundary = initial_source_boundary
        observation = initial_observation
        admission = initial_admission
        parent_chain_ref = root_chain_ref
        state = initial_state
        seen_behavior_refs = (initial_parent.before_state.behavior_ref,)
        steps = []
        target_requests_sent = 0

        while parent.transition.decision == "eligible_for_next_transition":
            boundary = InteractionAdaptiveReadBoundary(
                admission=admission,
                parent_transition=parent,
                source_boundary=source_boundary,
                observation=observation,
                root_receipt_id=root_receipt_id,
                root_transition_id=root_transition_id,
                controller_id=controller_id,
                parent_chain_ref=parent_chain_ref,
                target_origin=self.target_origin,
                authorization=self.authorization,
                actor_persona_id=self.actor_persona_id,
                peer_persona_id=self.peer_persona_id,
                executor=self.executor,
                resolver=self.resolver,
                config=self.config,
            )
            try:
                acquisition = await InteractionAdaptiveReadAdmission(
                    boundary,
                    receipt_store=self.receipt_store,
                ).execute()
            except InteractionAdaptiveDenied as exc:
                raise InteractionAdaptiveDenied(
                    str(exc),
                    target_request_possible=exc.target_request_possible,
                    target_requests_sent=(
                        target_requests_sent + exc.target_requests_sent
                    ),
                ) from exc
            except Exception as exc:
                raise InteractionAdaptiveDenied(
                    "interaction_adaptive_step_internal_error",
                    target_request_possible=True,
                    target_requests_sent=target_requests_sent,
                ) from exc
            if not acquisition.reused:
                target_requests_sent += 1
            render_summary: Dict[str, Any]
            child_source_boundary = None
            child_observation = None
            next_admission = None
            after_frontier = current_frontier
            analysis_error_code = None
            child_state = state

            if acquisition.record is None:
                render_summary = {
                    "schema_version": 1,
                    "mode": "behavioral_interaction_render_observation_v1",
                    "status": "unavailable",
                    "reason_code": (
                        "acquisition_response_not_available_for_observation"
                    ),
                    "target_requests_sent": 0,
                    "executable": False,
                }
            else:
                if record_sink is not None:
                    try:
                        record_sink(copy.deepcopy(acquisition.record))
                    except Exception as exc:
                        raise InteractionAdaptiveDenied(
                            "interaction_adaptive_record_sink_failed",
                            target_requests_sent=target_requests_sent,
                        ) from exc
                try:
                    child_source_boundary = (
                        InteractionRenderObservationBoundary(
                            admission=admission,
                            acquisition=acquisition.execution,
                            acquisition_receipt_id=acquisition.receipt_id,
                            record=acquisition.record,
                            target_origin=self.target_origin,
                            authorization=self.authorization,
                            actor_persona_id=self.actor_persona_id,
                            peer_persona_id=self.peer_persona_id,
                            observer=self.observer,
                            config=self.render_config,
                        )
                    )
                    child_observation = await child_source_boundary.execute()
                    render_summary = child_observation.to_dict()
                except InteractionRenderDenied as exc:
                    render_summary = {
                        "schema_version": 1,
                        "mode": (
                            "behavioral_interaction_render_observation_v1"
                        ),
                        "status": "denied",
                        "error_code": str(exc).split(":", 1)[0],
                        "target_requests_sent": 0,
                        "executable": False,
                    }
                    child_source_boundary = None
                    child_observation = None
                except Exception:
                    render_summary = {
                        "schema_version": 1,
                        "mode": (
                            "behavioral_interaction_render_observation_v1"
                        ),
                        "status": "error",
                        "error_code": "interaction_render_internal_error",
                        "target_requests_sent": 0,
                        "executable": False,
                    }
                    child_source_boundary = None
                    child_observation = None

            if child_observation is not None and child_observation.complete:
                try:
                    derivation = await derive(
                        acquisition.record or {},
                        child_observation,
                        state,
                        parent.transition.depth + 1,
                    )
                    if not isinstance(
                        derivation,
                        InteractionAdaptiveDerivation,
                    ):
                        raise TypeError(
                            "adaptive derivation returned an invalid result"
                        )
                except Exception:
                    analysis_error_code = (
                        "interaction_adaptive_derivation_failed"
                    )
                else:
                    after_frontier = derivation.after_frontier
                    next_admission = derivation.next_admission
                    child_state = derivation.state

            try:
                child_transition = build_chained_acquisition_transition(
                    parent=parent,
                    world_id=self.actor_persona_id,
                    admission=admission,
                    acquisition=acquisition.execution,
                    receipt_id=acquisition.receipt_id,
                    policy_digest=self.executor.policy.digest(),
                    max_total_requests=(
                        self.executor.policy.budget.max_total_requests
                    ),
                    before_frontier=current_frontier,
                    after_frontier=after_frontier,
                    after_control_surface=(
                        "observed"
                        if child_observation is not None
                        and child_observation.complete
                        else "unobserved"
                    ),
                    after_catalog_id=(
                        child_observation.catalog_id
                        if child_observation is not None
                        and child_observation.complete
                        else None
                    ),
                    limits=self.config.limits,
                    seen_behavior_refs=seen_behavior_refs,
                    next_admission=next_admission,
                )
            except Exception as exc:
                raise InteractionAdaptiveDenied(
                    "interaction_adaptive_transition_failed",
                    target_requests_sent=target_requests_sent,
                ) from exc
            chain_ref = stable_hash(
                "interaction_adaptive_chain",
                {
                    "controller_id": controller_id,
                    "parent_chain_ref": parent_chain_ref,
                    "receipt_id": acquisition.receipt_id,
                    "transition_id": (
                        child_transition.transition.transition_id
                    ),
                    "after_state_id": child_transition.after_state.state_id,
                },
            )
            step = InteractionAdaptiveStep(
                step_index=child_transition.transition.depth,
                controller_id=controller_id,
                root_receipt_id=root_receipt_id,
                root_transition_id=root_transition_id,
                parent_chain_ref=parent_chain_ref,
                chain_ref=chain_ref,
                parent_receipt_id=parent.transition.receipt_id,
                parent_transition_id=parent.transition.transition_id,
                parent_after_state_id=parent.after_state.state_id,
                observation_id=observation.observation_id,
                acquisition=acquisition,
                render_observation=render_summary,
                state_transition=child_transition,
                analysis_error_code=analysis_error_code,
            )
            steps.append(step)
            state = child_state
            if child_transition.transition.decision == "stop":
                parent = child_transition
                parent_chain_ref = chain_ref
                break
            if (
                child_source_boundary is None
                or child_observation is None
                or next_admission is None
            ):
                raise InteractionAdaptiveDenied(
                    "interaction_adaptive_continuation_contract_is_invalid",
                    target_requests_sent=target_requests_sent,
                )
            seen_behavior_refs = (
                *seen_behavior_refs,
                parent.after_state.behavior_ref,
            )
            parent = child_transition
            source_boundary = child_source_boundary
            observation = child_observation
            admission = next_admission
            current_frontier = tuple(after_frontier)
            parent_chain_ref = chain_ref

        if not steps:
            raise InteractionAdaptiveDenied(
                "interaction_adaptive_produced_no_steps"
            )
        return InteractionAdaptiveRunResult(
            controller_id=controller_id,
            root_receipt_id=root_receipt_id,
            root_transition_id=root_transition_id,
            root_after_state_id=initial_parent.after_state.state_id,
            root_chain_ref=root_chain_ref,
            chain_ref=parent_chain_ref,
            steps=tuple(steps),
            final_transition=parent,
            final_state=state,
            limits=self.config.limits,
        )


__all__ = [
    "INTERACTION_ADAPTIVE_ENV",
    "INTERACTION_ADAPTIVE_LIMITS",
    "INTERACTION_ADAPTIVE_MODE",
    "INTERACTION_ADAPTIVE_STEP_MODE",
    "INTERACTION_ADAPTIVE_WORKFLOW",
    "InteractionAdaptiveConfig",
    "InteractionAdaptiveController",
    "InteractionAdaptiveDenied",
    "InteractionAdaptiveDerivation",
    "InteractionAdaptiveReadAdmission",
    "InteractionAdaptiveReadBoundary",
    "InteractionAdaptiveRunResult",
    "InteractionAdaptiveStep",
]
