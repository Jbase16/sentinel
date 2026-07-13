"""Durable admission for one explicitly enabled compiled runtime sequence.

This module is deliberately absent from package-level imports, routers, schedulers,
and UI handlers.  It adds a non-renewable receipt boundary around a fully constructed
``ControlledRuntimeSequenceExecutor``; it does not discover, compile, or select plans.
"""

from __future__ import annotations

import copy
import os
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional

from .receipts import (
    COMPLETED,
    BehavioralReceiptContext,
    BehavioralReceiptStore,
    ReceiptStoreError,
    redacted_compiled_outcome,
    redacted_receipt_context,
    request_fingerprint,
)
from .runtime import ControlledRuntimeSequenceExecutor

COMPILED_ADMISSION_ENV = "SENTINELFORGE_BEHAVIOR_COMPILED_EXECUTION"
COMPILED_ADMISSION_MODE = "behavioral_compiled_admission"
_TRUE = frozenset({"1", "true", "yes", "on"})


class ControlledAdmissionDenied(RuntimeError):
    """Admission was refused before a new compiled execution could begin."""


@dataclass(frozen=True)
class ControlledAdmissionConfig:
    enabled: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.enabled, bool):
            raise ValueError("compiled admission enabled must be a boolean")

    @classmethod
    def from_environment(cls) -> "ControlledAdmissionConfig":
        enabled = os.environ.get(COMPILED_ADMISSION_ENV, "").strip().lower() in _TRUE
        return cls(enabled=enabled)


@dataclass(frozen=True)
class ControlledAdmissionResult:
    status: str
    receipt_id: str
    reused: bool
    execution: Dict[str, Any]

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


class ControlledSequenceAdmission:
    """Admit one pre-built sequence through a durable single-execution boundary."""

    def __init__(
        self,
        runtime: ControlledRuntimeSequenceExecutor,
        *,
        config: Optional[ControlledAdmissionConfig] = None,
        receipt_store: Optional[BehavioralReceiptStore] = None,
    ) -> None:
        if not isinstance(runtime, ControlledRuntimeSequenceExecutor):
            raise TypeError("runtime must be a ControlledRuntimeSequenceExecutor")
        self.runtime = runtime
        self.config = config or ControlledAdmissionConfig.from_environment()
        self.receipt_store = receipt_store or BehavioralReceiptStore()

    def _context(self) -> BehavioralReceiptContext:
        return redacted_receipt_context(
            target_origin=self.runtime.target_origin,
            envelope_id=self.runtime.authorization.envelope_id,
            source_persona_id=self.runtime.actor_persona_id,
            peer_persona_id=self.runtime.actor_persona_id,
        )

    def _descriptor(self, sequence_id: str) -> Dict[str, Any]:
        recipe = self.runtime.recipe
        return {
            "schema_version": 1,
            "mode": COMPILED_ADMISSION_MODE,
            "sequence_id": sequence_id,
            "recipe_id": recipe.recipe_id,
            "plan_id": recipe.plan_id,
            "capture_digest": recipe.capture_digest,
            "catalog_digest": recipe.catalog_digest,
            "world_ref": recipe.world_ref,
            "target_origin": self.runtime.target_origin,
            "envelope_id": self.runtime.authorization.envelope_id,
            "authorization_signature": (
                self.runtime.authorization.attestation_signature
            ),
            "actor_persona_id": self.runtime.actor_persona_id,
            "policy_digest": self.runtime.executor.policy.digest(),
        }

    def _identity(self) -> tuple[str, str]:
        if not self.config.enabled:
            raise ControlledAdmissionDenied("compiled_sequence_admission_is_disabled")
        sequence_id = self.runtime.validate_preflight()
        try:
            fingerprint = request_fingerprint(self._descriptor(sequence_id))
        except (TypeError, ValueError) as exc:
            raise ControlledAdmissionDenied(
                "compiled_sequence_admission_is_not_deterministic"
            ) from exc
        return sequence_id, fingerprint

    def validate_preflight(self) -> str:
        """Return the durable request fingerprint without I/O or target traffic."""

        _sequence_id, fingerprint = self._identity()
        return fingerprint

    @staticmethod
    def _cached_result(receipt_id: str, outcome: Mapping[str, Any]) -> ControlledAdmissionResult:
        if outcome.get("kind") != "compiled_sequence":
            raise ControlledAdmissionDenied("compiled_sequence_receipt_kind_mismatch")
        return ControlledAdmissionResult(
            status="already_executed",
            receipt_id=receipt_id,
            reused=True,
            execution=copy.deepcopy(dict(outcome)),
        )

    async def execute(self) -> ControlledAdmissionResult:
        sequence_id, fingerprint = self._identity()
        context = self._context()
        try:
            reservation = self.receipt_store.reserve(fingerprint, context=context)
        except (OSError, ReceiptStoreError) as exc:
            raise ControlledAdmissionDenied(
                "compiled_sequence_receipt_store_unavailable"
            ) from exc
        if not reservation.created:
            if reservation.receipt.context != context:
                raise ControlledAdmissionDenied(
                    "compiled_sequence_receipt_context_mismatch"
                )
            if (
                reservation.receipt.state == COMPLETED
                and reservation.receipt.outcome is not None
            ):
                return self._cached_result(
                    reservation.receipt.receipt_id,
                    reservation.receipt.outcome,
                )
            raise ControlledAdmissionDenied(
                "compiled_sequence_is_already_reserved_or_terminal"
            )
        token = reservation.reservation_token
        if token is None:
            raise ControlledAdmissionDenied(
                "compiled_sequence_reservation_token_is_unavailable"
            )
        try:
            result = await self.runtime.execute(expected_sequence_id=sequence_id)
        except Exception:
            try:
                self.receipt_store.abort(
                    fingerprint,
                    reservation_token=token,
                    reason="compiled_execution_error",
                )
            except (OSError, ReceiptStoreError) as receipt_exc:
                raise ControlledAdmissionDenied(
                    "compiled_sequence_failed_and_receipt_could_not_finalize"
                ) from receipt_exc
            raise
        outcome = redacted_compiled_outcome(result.to_dict())
        try:
            completed = self.receipt_store.complete(
                fingerprint,
                reservation_token=token,
                outcome=outcome,
            )
        except (OSError, ReceiptStoreError) as exc:
            raise ControlledAdmissionDenied(
                "compiled_sequence_completed_but_receipt_could_not_finalize"
            ) from exc
        if completed.outcome is None:
            raise ControlledAdmissionDenied("compiled_sequence_receipt_outcome_is_missing")
        return ControlledAdmissionResult(
            status=result.status,
            receipt_id=completed.receipt_id,
            reused=False,
            execution=copy.deepcopy(completed.outcome),
        )


__all__ = [
    "COMPILED_ADMISSION_ENV",
    "COMPILED_ADMISSION_MODE",
    "ControlledAdmissionConfig",
    "ControlledAdmissionDenied",
    "ControlledAdmissionResult",
    "ControlledSequenceAdmission",
]
