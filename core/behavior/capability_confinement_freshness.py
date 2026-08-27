"""Transport-free R5D2 capability-confinement freshness evidence.

R5D1 classifies a capability's logical bounds.  This module adds the orthogonal
evidence axis: one R5D1 capability is bound to an exact owned-account world,
owned-tenant context, canonical target origin, and structurally revalidated capture.
A use is fully admissible only when the R5D1 outcome is ``VALID`` and the R5D2
outcome is ``CONFINED_FRESH``; this module never re-derives revocation, expiry, or
use-count state.

The evaluator uses the fixed precedence
``escaped_confinement -> stale_capture -> confined_fresh``.  Confinement is checked
first because evidence presented outside the owned world must not be described as
merely stale, even when both conditions are true.

The module is passive and unwired.  It performs no target I/O, sends no requests,
reserves no budget, dispatches no backend, persists no consumption or replay state,
writes no receipt, evaluates no target effect, and grants no retry, promotion,
finding, or execution authority.  Operator-supplied captures are normalized and
hashed during construction; no captured request or response value is retained.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Mapping, Sequence, Tuple

from .capability_contract import IssuedCapabilityContract, _hash_ref
from .experiment_sdk import ExperimentWorldBinding, ExperimentWorldKind
from .normalize import stable_hash
from .prerequisite_capture_freshness import (
    GraphBoundCaptureFreshnessDenied,
    _canonical_origin,
    _snapshot,
    graph_bound_capture_artifact_ref,
)


CAPABILITY_CONFINEMENT_FRESHNESS_MODE = (
    "behavioral_capability_confinement_freshness_v1"
)

_CONFINEMENT_ORDER = ("world", "tenant", "tenant_ownership", "origin")
_FRESHNESS_ORDER = ("snapshot", "record_count")


class ConfinementFreshnessDenied(RuntimeError):
    """A capability presentation cannot form confined-fresh evidence."""


class ConfinementOutcome(str, Enum):
    CONFINED_FRESH = "confined_fresh"
    ESCAPED_CONFINEMENT = "escaped_confinement"
    STALE_CAPTURE = "stale_capture"


def _owned_world_shape(world: object) -> bool:
    return (
        isinstance(world, ExperimentWorldBinding)
        and world.kind is ExperimentWorldKind.OWNED_ACCOUNT
        and world.slot == "actor"
        and world.persona_ref is not None
        and world.ownership_ref is not None
        and world.role_ref is None
        and world.lifecycle_ref is None
        and world.callback_ref is None
        and world.fresh is False
    )


def _canonical_origin_or_deny(value: str) -> str:
    try:
        return _canonical_origin(value)
    except GraphBoundCaptureFreshnessDenied as exc:
        raise ConfinementFreshnessDenied(
            "capability_confinement_target_origin_is_invalid"
        ) from exc


def _capture_snapshot(
    records: Sequence[Mapping[str, Any]],
    *,
    target_origin: str,
    world_id: str,
    label: str,
) -> Tuple[str, int]:
    try:
        return _snapshot(
            records,
            target_origin=target_origin,
            world_id=world_id,
            label=label,
        )
    except GraphBoundCaptureFreshnessDenied as exc:
        if "origin_mismatch" in str(exc):
            raise ConfinementFreshnessDenied(
                "capability_presentation_capture_escaped_confinement"
            ) from exc
        raise ConfinementFreshnessDenied(
            "capability_presentation_capture_is_invalid"
        ) from exc


def _capture_artifact_ref(
    records: Sequence[Mapping[str, Any]],
    *,
    target_origin: str,
    world_id: str,
) -> str:
    try:
        return graph_bound_capture_artifact_ref(
            records,
            target_origin=target_origin,
            world_id=world_id,
        )
    except GraphBoundCaptureFreshnessDenied as exc:
        raise ConfinementFreshnessDenied(
            "capability_presentation_capture_is_invalid"
        ) from exc


def _binding_payload(binding: "ConfinedPresentationBinding") -> Dict[str, Any]:
    return {
        "capability_ref": binding.capability_ref,
        "confined_world_ref": binding.confined_world_ref,
        "confined_tenant_ref": binding.confined_tenant_ref,
        "confined_tenant_ownership_ref": (
            binding.confined_tenant_ownership_ref
        ),
        "target_origin_ref": binding.target_origin_ref,
        "presentation_capture_ref": binding.presentation_capture_ref,
        "presentation_snapshot_ref": binding.presentation_snapshot_ref,
        "presentation_record_count": binding.presentation_record_count,
        "current_capture_revalidated": binding.current_capture_revalidated,
        "target_requests_sent": binding.target_requests_sent,
        "backend_dispatch_authority": binding.backend_dispatch_authority,
        "promotion_authority": binding.promotion_authority,
        "finding_authority": binding.finding_authority,
        "retry_authority": binding.retry_authority,
    }


def _binding_matches_contract(
    contract: IssuedCapabilityContract,
    binding: "ConfinedPresentationBinding",
) -> bool:
    world = binding._confined_world
    return (
        binding.capability_ref == contract.capability_id
        and binding._contract.capability_id == contract.capability_id
        and _owned_world_shape(world)
        and world.binding_id == contract._owned_world.binding_id
        and contract.subject_ref == contract.audience_ref == world.persona_ref
        and binding.confined_world_ref == world.binding_id
        and binding.confined_tenant_ref == contract.tenant_ref
        and binding.confined_tenant_ref == contract._world_tenant_ref
        and binding.confined_tenant_ownership_ref
        == contract.tenant_ownership_ref
        and binding.confined_tenant_ownership_ref
        == contract._world_tenant_ownership_ref
    )


@dataclass(frozen=True)
class ConfinedPresentationBinding:
    binding_id: str
    capability_ref: str
    confined_world_ref: str
    confined_tenant_ref: str
    confined_tenant_ownership_ref: str
    target_origin_ref: str
    presentation_capture_ref: str
    presentation_snapshot_ref: str
    presentation_record_count: int
    _contract: IssuedCapabilityContract = field(repr=False, compare=False)
    _confined_world: ExperimentWorldBinding = field(repr=False, compare=False)
    _target_origin: str = field(repr=False, compare=False)
    current_capture_revalidated: bool = True
    target_requests_sent: int = 0
    backend_dispatch_authority: bool = False
    promotion_authority: bool = False
    finding_authority: bool = False
    retry_authority: bool = False
    mode: str = CAPABILITY_CONFINEMENT_FRESHNESS_MODE

    @classmethod
    def build(
        cls,
        *,
        contract: IssuedCapabilityContract,
        capability_ref: str,
        confined_world: ExperimentWorldBinding,
        confined_tenant_ref: str,
        confined_tenant_ownership_ref: str,
        target_origin: str,
        prior_presentation_records: Sequence[Mapping[str, Any]],
        current_presentation_records: Sequence[Mapping[str, Any]],
        target_requests_sent: int = 0,
        backend_dispatch_authority: bool = False,
        promotion_authority: bool = False,
        finding_authority: bool = False,
        retry_authority: bool = False,
    ) -> "ConfinedPresentationBinding":
        if not isinstance(contract, IssuedCapabilityContract):
            raise TypeError("contract must be an IssuedCapabilityContract")
        if not isinstance(confined_world, ExperimentWorldBinding):
            raise TypeError("confined_world must be an ExperimentWorldBinding")
        if not _hash_ref(capability_ref, "issued_capability_contract"):
            raise ValueError("capability confinement reference is invalid")
        if capability_ref != contract.capability_id:
            raise ConfinementFreshnessDenied(
                "capability_confinement_contract_reference_mismatch"
            )
        if not _owned_world_shape(confined_world):
            raise ConfinementFreshnessDenied(
                "capability_confinement_requires_owned_account_world"
            )
        if (
            confined_world.binding_id != contract._owned_world.binding_id
            or contract.subject_ref != confined_world.persona_ref
            or contract.audience_ref != confined_world.persona_ref
        ):
            raise ConfinementFreshnessDenied(
                "capability_confinement_contract_world_mismatch"
            )
        if (
            not _hash_ref(confined_tenant_ref, "owned_tenant")
            or not _hash_ref(
                confined_tenant_ownership_ref,
                "ownership_proof",
            )
        ):
            raise ValueError("capability confinement tenant reference is invalid")
        if (
            confined_tenant_ref != contract.tenant_ref
            or confined_tenant_ref != contract._world_tenant_ref
            or confined_tenant_ownership_ref != contract.tenant_ownership_ref
            or confined_tenant_ownership_ref
            != contract._world_tenant_ownership_ref
        ):
            raise ConfinementFreshnessDenied(
                "capability_confinement_cross_tenant_world"
            )
        if (
            type(target_requests_sent) is not int
            or target_requests_sent != 0
            or backend_dispatch_authority is not False
            or promotion_authority is not False
            or finding_authority is not False
            or retry_authority is not False
        ):
            raise ConfinementFreshnessDenied(
                "capability_confinement_passive_boundary_violation"
            )

        origin = _canonical_origin_or_deny(target_origin)
        world_id = confined_world.binding_id
        prior_snapshot_ref, prior_count = _capture_snapshot(
            prior_presentation_records,
            target_origin=origin,
            world_id=world_id,
            label="prior_presentation",
        )
        current_snapshot_ref, current_count = _capture_snapshot(
            current_presentation_records,
            target_origin=origin,
            world_id=world_id,
            label="current_presentation",
        )
        if (
            prior_snapshot_ref != current_snapshot_ref
            or prior_count != current_count
        ):
            raise ConfinementFreshnessDenied(
                "capability_presentation_capture_is_stale"
            )

        values = {
            "binding_id": "",
            "capability_ref": capability_ref,
            "confined_world_ref": confined_world.binding_id,
            "confined_tenant_ref": confined_tenant_ref,
            "confined_tenant_ownership_ref": (
                confined_tenant_ownership_ref
            ),
            "target_origin_ref": stable_hash(
                "behavioral_capture_target",
                origin,
            ),
            "presentation_capture_ref": _capture_artifact_ref(
                current_presentation_records,
                target_origin=origin,
                world_id=world_id,
            ),
            "presentation_snapshot_ref": current_snapshot_ref,
            "presentation_record_count": current_count,
            "_contract": contract,
            "_confined_world": confined_world,
            "_target_origin": origin,
            "target_requests_sent": target_requests_sent,
            "backend_dispatch_authority": backend_dispatch_authority,
            "promotion_authority": promotion_authority,
            "finding_authority": finding_authority,
            "retry_authority": retry_authority,
        }
        payload = {
            key: value
            for key, value in values.items()
            if key != "binding_id" and not key.startswith("_")
        }
        payload["current_capture_revalidated"] = True
        return cls(
            **{
                **values,
                "binding_id": stable_hash(
                    "capability_confinement_freshness",
                    payload,
                ),
            }
        )

    def __post_init__(self) -> None:
        if not isinstance(self._contract, IssuedCapabilityContract):
            raise TypeError("contract must be an IssuedCapabilityContract")
        if not isinstance(self._confined_world, ExperimentWorldBinding):
            raise TypeError("confined_world must be an ExperimentWorldBinding")
        try:
            canonical_origin = _canonical_origin(self._target_origin)
        except GraphBoundCaptureFreshnessDenied as exc:
            raise ValueError(
                "capability confinement freshness binding is invalid"
            ) from exc
        refs = (
            (self.binding_id, "capability_confinement_freshness"),
            (self.capability_ref, "issued_capability_contract"),
            (self.confined_world_ref, "experiment_world_binding"),
            (self.confined_tenant_ref, "owned_tenant"),
            (self.confined_tenant_ownership_ref, "ownership_proof"),
            (self.target_origin_ref, "behavioral_capture_target"),
            (self.presentation_capture_ref, "graph_bound_capture_artifact"),
            (self.presentation_snapshot_ref, "graph_bound_capture_snapshot"),
        )
        if (
            self.mode != CAPABILITY_CONFINEMENT_FRESHNESS_MODE
            or self.binding_id
            != stable_hash(
                "capability_confinement_freshness",
                _binding_payload(self),
            )
            or any(not _hash_ref(value, prefix) for value, prefix in refs)
            or not _binding_matches_contract(self._contract, self)
            or canonical_origin != self._target_origin
            or self.target_origin_ref
            != stable_hash("behavioral_capture_target", canonical_origin)
            or type(self.presentation_record_count) is not int
            or self.presentation_record_count < 1
            or self.current_capture_revalidated is not True
            or type(self.target_requests_sent) is not int
            or self.target_requests_sent != 0
            or self.backend_dispatch_authority is not False
            or self.promotion_authority is not False
            or self.finding_authority is not False
            or self.retry_authority is not False
        ):
            raise ValueError(
                "capability confinement freshness binding is invalid"
            )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": 1,
            "mode": self.mode,
            "binding_id": self.binding_id,
            **_binding_payload(self),
        }


def _presentation_payload(
    presentation: "ConfinementPresentation",
) -> Dict[str, Any]:
    return {
        "presented_world_ref": presentation.presented_world_ref,
        "presented_tenant_ref": presentation.presented_tenant_ref,
        "presented_tenant_ownership_ref": (
            presentation.presented_tenant_ownership_ref
        ),
        "presented_target_origin_ref": presentation.presented_target_origin_ref,
        "current_capture_ref": presentation.current_capture_ref,
        "current_snapshot_ref": presentation.current_snapshot_ref,
        "current_record_count": presentation.current_record_count,
    }


@dataclass(frozen=True)
class ConfinementPresentation:
    presentation_id: str
    presented_world_ref: str
    presented_tenant_ref: str
    presented_tenant_ownership_ref: str
    presented_target_origin_ref: str
    current_capture_ref: str
    current_snapshot_ref: str
    current_record_count: int

    @classmethod
    def build(
        cls,
        *,
        presented_world_ref: str,
        presented_tenant_ref: str,
        presented_tenant_ownership_ref: str,
        presented_target_origin: str,
        current_capture_records: Sequence[Mapping[str, Any]],
    ) -> "ConfinementPresentation":
        refs = (
            (presented_world_ref, "experiment_world_binding"),
            (presented_tenant_ref, "owned_tenant"),
            (presented_tenant_ownership_ref, "ownership_proof"),
        )
        if any(not _hash_ref(value, prefix) for value, prefix in refs):
            raise ValueError("capability confinement presentation is invalid")
        origin = _canonical_origin_or_deny(presented_target_origin)
        snapshot_ref, record_count = _capture_snapshot(
            current_capture_records,
            target_origin=origin,
            world_id=presented_world_ref,
            label="current_presentation",
        )
        values = {
            "presentation_id": "",
            "presented_world_ref": presented_world_ref,
            "presented_tenant_ref": presented_tenant_ref,
            "presented_tenant_ownership_ref": (
                presented_tenant_ownership_ref
            ),
            "presented_target_origin_ref": stable_hash(
                "behavioral_capture_target",
                origin,
            ),
            "current_capture_ref": _capture_artifact_ref(
                current_capture_records,
                target_origin=origin,
                world_id=presented_world_ref,
            ),
            "current_snapshot_ref": snapshot_ref,
            "current_record_count": record_count,
        }
        payload = {
            key: value for key, value in values.items() if key != "presentation_id"
        }
        return cls(
            **{
                **values,
                "presentation_id": stable_hash(
                    "capability_confinement_presentation",
                    payload,
                ),
            }
        )

    def __post_init__(self) -> None:
        refs = (
            (self.presentation_id, "capability_confinement_presentation"),
            (self.presented_world_ref, "experiment_world_binding"),
            (self.presented_tenant_ref, "owned_tenant"),
            (self.presented_tenant_ownership_ref, "ownership_proof"),
            (self.presented_target_origin_ref, "behavioral_capture_target"),
            (self.current_capture_ref, "graph_bound_capture_artifact"),
            (self.current_snapshot_ref, "graph_bound_capture_snapshot"),
        )
        if (
            self.presentation_id
            != stable_hash(
                "capability_confinement_presentation",
                _presentation_payload(self),
            )
            or any(not _hash_ref(value, prefix) for value, prefix in refs)
            or type(self.current_record_count) is not int
            or self.current_record_count < 1
        ):
            raise ValueError("capability confinement presentation is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": 1,
            "presentation_id": self.presentation_id,
            **_presentation_payload(self),
        }


def _decision_payload(decision: "ConfinementDecision") -> Dict[str, Any]:
    return {
        "capability_ref": decision.capability_ref,
        "binding_id": decision.binding_id,
        "presentation_id": decision.presentation_id,
        "outcome": decision.outcome.value,
        "reason_ref": decision.reason_ref,
    }


def _is_ordered_subset(values: Tuple[str, ...], order: Tuple[str, ...]) -> bool:
    return values == tuple(item for item in order if item in values)


@dataclass(frozen=True)
class ConfinementDecision:
    decision_id: str
    capability_ref: str
    binding_id: str
    presentation_id: str
    outcome: ConfinementOutcome
    reason_ref: str

    @classmethod
    def build(
        cls,
        *,
        contract: IssuedCapabilityContract,
        binding: ConfinedPresentationBinding,
        presentation: ConfinementPresentation,
        outcome: ConfinementOutcome,
        confinement_mismatches: Tuple[str, ...] = (),
        freshness_mismatches: Tuple[str, ...] = (),
    ) -> "ConfinementDecision":
        if not isinstance(contract, IssuedCapabilityContract):
            raise TypeError("contract must be an IssuedCapabilityContract")
        if not isinstance(binding, ConfinedPresentationBinding):
            raise TypeError("binding must be a ConfinedPresentationBinding")
        if not isinstance(presentation, ConfinementPresentation):
            raise TypeError("presentation must be a ConfinementPresentation")
        if not isinstance(outcome, ConfinementOutcome):
            raise TypeError("outcome must be a ConfinementOutcome")
        if not _binding_matches_contract(contract, binding):
            raise ValueError("capability confinement binding does not match contract")
        if (
            not _is_ordered_subset(
                confinement_mismatches,
                _CONFINEMENT_ORDER,
            )
            or not _is_ordered_subset(
                freshness_mismatches,
                _FRESHNESS_ORDER,
            )
        ):
            raise ValueError("capability confinement decision reason is invalid")
        escaped = outcome is ConfinementOutcome.ESCAPED_CONFINEMENT
        stale = outcome is ConfinementOutcome.STALE_CAPTURE
        fresh = outcome is ConfinementOutcome.CONFINED_FRESH
        if (
            escaped
            != (bool(confinement_mismatches) and not freshness_mismatches)
            or stale
            != (bool(freshness_mismatches) and not confinement_mismatches)
            or fresh
            != (not confinement_mismatches and not freshness_mismatches)
        ):
            raise ValueError("capability confinement decision reason is invalid")
        reason_ref = stable_hash(
            "capability_confinement_reason",
            {
                "outcome": outcome.value,
                "confinement_mismatches": list(confinement_mismatches),
                "freshness_mismatches": list(freshness_mismatches),
            },
        )
        values = {
            "decision_id": "",
            "capability_ref": contract.capability_id,
            "binding_id": binding.binding_id,
            "presentation_id": presentation.presentation_id,
            "outcome": outcome,
            "reason_ref": reason_ref,
        }
        payload = {
            "capability_ref": values["capability_ref"],
            "binding_id": values["binding_id"],
            "presentation_id": values["presentation_id"],
            "outcome": outcome.value,
            "reason_ref": reason_ref,
        }
        return cls(
            **{
                **values,
                "decision_id": stable_hash(
                    "capability_confinement_decision",
                    payload,
                ),
            }
        )

    def __post_init__(self) -> None:
        if not isinstance(self.outcome, ConfinementOutcome):
            raise TypeError("outcome must be a ConfinementOutcome")
        refs = (
            (self.decision_id, "capability_confinement_decision"),
            (self.capability_ref, "issued_capability_contract"),
            (self.binding_id, "capability_confinement_freshness"),
            (self.presentation_id, "capability_confinement_presentation"),
            (self.reason_ref, "capability_confinement_reason"),
        )
        if (
            self.decision_id
            != stable_hash(
                "capability_confinement_decision",
                _decision_payload(self),
            )
            or any(not _hash_ref(value, prefix) for value, prefix in refs)
        ):
            raise ValueError("capability confinement decision is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": 1,
            "decision_id": self.decision_id,
            **_decision_payload(self),
        }


def evaluate_confinement(
    contract: IssuedCapabilityContract,
    binding: ConfinedPresentationBinding,
    presentation: ConfinementPresentation,
) -> ConfinementDecision:
    """Classify one typed evidence presentation without dispatch or mutation.

    World, tenant, and origin escape is checked before structural freshness.  Capture
    artifact hashes are deliberately not compared: raw dynamic values may rotate while
    the normalized snapshot and record count remain current.
    """

    if not isinstance(contract, IssuedCapabilityContract):
        raise TypeError("contract must be an IssuedCapabilityContract")
    if not isinstance(binding, ConfinedPresentationBinding):
        raise TypeError("binding must be a ConfinedPresentationBinding")
    if not isinstance(presentation, ConfinementPresentation):
        raise TypeError("presentation must be a ConfinementPresentation")
    if not _binding_matches_contract(contract, binding):
        raise ValueError("capability confinement binding does not match contract")

    confinement_checks = {
        "world": presentation.presented_world_ref == binding.confined_world_ref,
        "tenant": (
            presentation.presented_tenant_ref == binding.confined_tenant_ref
        ),
        "tenant_ownership": (
            presentation.presented_tenant_ownership_ref
            == binding.confined_tenant_ownership_ref
        ),
        "origin": (
            presentation.presented_target_origin_ref == binding.target_origin_ref
        ),
    }
    confinement_mismatches = tuple(
        name for name in _CONFINEMENT_ORDER if not confinement_checks[name]
    )
    if confinement_mismatches:
        return ConfinementDecision.build(
            contract=contract,
            binding=binding,
            presentation=presentation,
            outcome=ConfinementOutcome.ESCAPED_CONFINEMENT,
            confinement_mismatches=confinement_mismatches,
        )

    freshness_checks = {
        "snapshot": (
            presentation.current_snapshot_ref
            == binding.presentation_snapshot_ref
        ),
        "record_count": (
            presentation.current_record_count
            == binding.presentation_record_count
        ),
    }
    freshness_mismatches = tuple(
        name for name in _FRESHNESS_ORDER if not freshness_checks[name]
    )
    if freshness_mismatches:
        return ConfinementDecision.build(
            contract=contract,
            binding=binding,
            presentation=presentation,
            outcome=ConfinementOutcome.STALE_CAPTURE,
            freshness_mismatches=freshness_mismatches,
        )

    return ConfinementDecision.build(
        contract=contract,
        binding=binding,
        presentation=presentation,
        outcome=ConfinementOutcome.CONFINED_FRESH,
    )


__all__ = [
    "CAPABILITY_CONFINEMENT_FRESHNESS_MODE",
    "ConfinedPresentationBinding",
    "ConfinementDecision",
    "ConfinementFreshnessDenied",
    "ConfinementOutcome",
    "ConfinementPresentation",
    "evaluate_confinement",
]
