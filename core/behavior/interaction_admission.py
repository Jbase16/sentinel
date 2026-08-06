"""Passive admission manifest for one obligation-directed browser interaction.

This module selects and seals a redacted acquisition candidate. It has no driver,
transport, receipt, or budget-reservation dependency and cannot execute the intent.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple

from .interactions import (
    InteractionIntent,
    InteractionIntentCatalog,
    StructuralLocatorSegment,
)
from .normalize import stable_hash

INTERACTION_ADMISSION_MODE = "behavioral_interaction_admission_v1"
PASSIVE_CATALOG_BLOCKER = "passive_catalog_only"

_HASH_REF = re.compile(r"^[a-z][a-z0-9_]*:[0-9a-f]{64}$")
_POLICY_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_SEMANTIC = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_STATUSES = frozenset(
    {
        "ready_for_active_boundary",
        "policy_unavailable",
        "budget_unavailable",
        "no_open_acquisition_obligation",
        "no_eligible_intents",
    }
)
_ELIGIBLE_INTENT_KINDS = frozenset({"navigate", "reveal"})
_OBLIGATION_RISK_CLASSES = frozenset(
    {"control", "read", "state_mutation", "unknown"}
)
_RESOLUTION_KINDS = frozenset(
    {
        "authorization_proposal",
        "owned_experiment",
        "omission_experiment",
        "unavailable",
    }
)
_BUDGET_KEYS = frozenset(
    {
        "total_requests",
        "cross_object_reads",
        "privilege_mutations",
        "creates",
        "endpoints_touched",
    }
)
_ADMISSION_CONSTRAINTS = (
    "catalog_bound",
    "frontier_bound",
    "page_bound",
    "policy_bound",
    "scope_bound",
    "single_action_limit",
    "world_bound",
)


def _hash_ref(value: Any, prefix: str) -> bool:
    return (
        isinstance(value, str)
        and value.startswith(f"{prefix}:")
        and _HASH_REF.fullmatch(value) is not None
    )


def _frontier_signal(value: Any) -> bool:
    text = str(value or "")
    return _SEMANTIC.fullmatch(text) is not None or _hash_ref(
        text,
        "interaction_intent",
    )


@dataclass(frozen=True)
class InteractionAdmissionPolicy:
    policy_ref: str
    budget_ref: str
    world_ref: str
    action_limit: int
    budget_available: bool

    def __post_init__(self) -> None:
        if (
            not _hash_ref(self.policy_ref, "interaction_policy")
            or not _hash_ref(self.budget_ref, "interaction_action_budget")
            or not _hash_ref(self.world_ref, "world")
            or self.action_limit != 1
            or not isinstance(self.budget_available, bool)
        ):
            raise ValueError("interaction admission policy is invalid")

    @classmethod
    def create(
        cls,
        *,
        policy_digest: str,
        budget_snapshot: Mapping[str, int],
        max_total_requests: int,
        world_id: str,
    ) -> "InteractionAdmissionPolicy":
        if _POLICY_DIGEST.fullmatch(str(policy_digest or "")) is None:
            raise ValueError("interaction policy digest is invalid")
        if (
            not isinstance(budget_snapshot, Mapping)
            or set(budget_snapshot) != _BUDGET_KEYS
            or any(
                isinstance(value, bool)
                or not isinstance(value, int)
                or value < 0
                for value in budget_snapshot.values()
            )
        ):
            raise ValueError("interaction policy budget snapshot is invalid")
        if (
            isinstance(max_total_requests, bool)
            or not isinstance(max_total_requests, int)
            or max_total_requests <= 0
            or budget_snapshot["total_requests"] > max_total_requests
        ):
            raise ValueError("interaction policy request limit is invalid")
        if not isinstance(world_id, str) or not world_id:
            raise ValueError("interaction policy world is invalid")
        policy_ref = stable_hash(
            "interaction_policy",
            {"policy_digest": policy_digest},
        )
        budget_ref = stable_hash(
            "interaction_action_budget",
            {
                "policy_ref": policy_ref,
                "snapshot": dict(sorted(budget_snapshot.items())),
                "max_total_requests": max_total_requests,
                "action_limit": 1,
            },
        )
        return cls(
            policy_ref=policy_ref,
            budget_ref=budget_ref,
            world_ref=stable_hash("world", world_id),
            action_limit=1,
            budget_available=(
                budget_snapshot["total_requests"] < max_total_requests
            ),
        )


@dataclass(frozen=True)
class _AcquisitionObligation:
    obligation_id: str
    kind: str
    risk_class: str
    score: int
    actionable: bool
    resolution_kind: str
    resolution_ref: Optional[str]
    signals: Tuple[str, ...]

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "_AcquisitionObligation":
        if not isinstance(value, Mapping):
            raise ValueError("interaction acquisition obligation is invalid")
        signals_value = value.get("signals")
        resolution_ref = value.get("resolution_ref")
        resolution_kind = str(value.get("resolution_kind") or "")
        actionable = value.get("actionable")
        resolution_valid = (
            resolution_kind == "unavailable" and resolution_ref is None
        ) or (
            resolution_kind == "authorization_proposal"
            and _hash_ref(resolution_ref, "authorization_proposal")
        ) or (
            resolution_kind == "owned_experiment"
            and _hash_ref(resolution_ref, "owned_experiment")
        ) or (
            resolution_kind == "omission_experiment"
            and _hash_ref(resolution_ref, "omission_experiment")
        )
        if (
            not _hash_ref(value.get("obligation_id"), "security_obligation")
            or _SEMANTIC.fullmatch(str(value.get("kind") or "")) is None
            or str(value.get("risk_class") or "")
            not in _OBLIGATION_RISK_CLASSES
            or isinstance(value.get("score"), bool)
            or not isinstance(value.get("score"), int)
            or value["score"] < 0
            or not isinstance(actionable, bool)
            or resolution_kind not in _RESOLUTION_KINDS
            or not resolution_valid
            or actionable != (resolution_kind != "unavailable")
            or not isinstance(signals_value, Sequence)
            or isinstance(signals_value, (str, bytes))
            or any(not _frontier_signal(item) for item in signals_value)
        ):
            raise ValueError("interaction acquisition obligation is invalid")
        signals = tuple(sorted(set(str(item) for item in signals_value)))
        if tuple(signals_value) != signals:
            raise ValueError("interaction acquisition obligation signals are invalid")
        return cls(
            obligation_id=value["obligation_id"],
            kind=str(value["kind"]),
            risk_class=str(value["risk_class"]),
            score=value["score"],
            actionable=actionable,
            resolution_kind=resolution_kind,
            resolution_ref=resolution_ref,
            signals=signals,
        )

    @property
    def needs_acquisition(self) -> bool:
        return not self.actionable and self.resolution_kind == "unavailable"

    @property
    def bound_intent_ref(self) -> Optional[str]:
        refs = tuple(
            signal
            for signal in self.signals
            if _hash_ref(signal, "interaction_intent")
        )
        if len(refs) > 1:
            raise ValueError(
                "interaction acquisition obligation has multiple intent bindings"
            )
        return refs[0] if refs else None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "obligation_id": self.obligation_id,
            "kind": self.kind,
            "risk_class": self.risk_class,
            "score": self.score,
            "actionable": self.actionable,
            "resolution_kind": self.resolution_kind,
            "resolution_ref": self.resolution_ref,
            "signals": list(self.signals),
        }


def _ordered_obligations(
    frontier: Sequence[Mapping[str, Any]],
) -> Tuple[_AcquisitionObligation, ...]:
    if isinstance(frontier, (str, bytes)) or len(frontier) > 512:
        raise ValueError("interaction frontier is invalid or exceeds its limit")
    obligations = tuple(
        _AcquisitionObligation.from_mapping(item) for item in frontier
    )
    obligation_ids = [item.obligation_id for item in obligations]
    if len(obligation_ids) != len(set(obligation_ids)):
        raise ValueError("interaction frontier contains duplicate obligations")
    return tuple(
        sorted(
            obligations,
            key=lambda item: (
                not item.actionable,
                -item.score,
                item.kind,
                item.obligation_id,
            ),
        )
    )


def interaction_frontier_ref(
    frontier: Sequence[Mapping[str, Any]],
) -> str:
    ordered = _ordered_obligations(frontier)
    return stable_hash(
        "interaction_frontier",
        [item.to_dict() for item in ordered],
    )


def _admission_payload(
    *,
    catalog_id: str,
    intent: InteractionIntent,
    obligation_id: str,
    frontier_ref: str,
    scope_ref: str,
    policy: InteractionAdmissionPolicy,
) -> Dict[str, Any]:
    return {
        "catalog_id": catalog_id,
        "intent_id": intent.intent_id,
        "target_ref": intent.target_ref,
        "page_ref": intent.page_ref,
        "world_ref": intent.world_ref,
        "locator_ref": intent.locator_ref,
        "locator": [item.to_dict() for item in intent.locator],
        "destination_ref": intent.destination_ref,
        "obligation_id": obligation_id,
        "frontier_ref": frontier_ref,
        "scope_ref": scope_ref,
        "policy_ref": policy.policy_ref,
        "budget_ref": policy.budget_ref,
        "action_limit": policy.action_limit,
        "intent_kind": intent.intent_kind,
        "risk_class": intent.risk_class,
        "constraints": list(_ADMISSION_CONSTRAINTS),
    }


@dataclass(frozen=True)
class InteractionIntentAdmission:
    admission_id: str
    catalog_id: str
    intent_id: str
    target_ref: str
    page_ref: str
    world_ref: str
    locator_ref: str
    locator: Tuple[StructuralLocatorSegment, ...]
    locator_truncated: bool
    tag: str
    role: str
    input_type: str
    destination_ref: str
    obligation_id: str
    frontier_ref: str
    scope_ref: str
    policy_ref: str
    budget_ref: str
    action_limit: int
    intent_kind: str
    risk_class: str
    expected_side_effect: str
    safety_blockers: Tuple[str, ...]
    disabled: bool
    scripted_handler: bool
    constraints: Tuple[str, ...] = _ADMISSION_CONSTRAINTS
    executable: bool = False
    mode: str = INTERACTION_ADMISSION_MODE

    def __post_init__(self) -> None:
        intent = InteractionIntent(
            intent_id=self.intent_id,
            target_ref=self.target_ref,
            world_ref=self.world_ref,
            page_ref=self.page_ref,
            locator_ref=self.locator_ref,
            locator=self.locator,
            locator_truncated=self.locator_truncated,
            tag=self.tag,
            role=self.role,
            input_type=self.input_type,
            destination_ref=self.destination_ref,
            intent_kind=self.intent_kind,
            risk_class=self.risk_class,
            expected_side_effect=self.expected_side_effect,
            safety_blockers=self.safety_blockers,
            disabled=self.disabled,
            scripted_handler=self.scripted_handler,
        )
        payload = _admission_payload(
            catalog_id=self.catalog_id,
            intent=intent,
            obligation_id=self.obligation_id,
            frontier_ref=self.frontier_ref,
            scope_ref=self.scope_ref,
            policy=InteractionAdmissionPolicy(
                policy_ref=self.policy_ref,
                budget_ref=self.budget_ref,
                world_ref=self.world_ref,
                action_limit=self.action_limit,
                budget_available=True,
            ),
        )
        if (
            self.admission_id != stable_hash("interaction_intent_admission", payload)
            or self.mode != INTERACTION_ADMISSION_MODE
            or self.executable
            or not _hash_ref(self.catalog_id, "interaction_intent_catalog")
            or not _hash_ref(self.intent_id, "interaction_intent")
            or not _hash_ref(self.target_ref, "interaction_target")
            or not _hash_ref(self.page_ref, "interaction_page")
            or not _hash_ref(self.world_ref, "world")
            or not _hash_ref(self.locator_ref, "interaction_locator")
            or not _hash_ref(self.obligation_id, "security_obligation")
            or not _hash_ref(self.frontier_ref, "interaction_frontier")
            or not _hash_ref(self.scope_ref, "interaction_scope")
            or self.scope_ref
            != stable_hash(
                "interaction_scope",
                {
                    "target_ref": self.target_ref,
                    "page_ref": self.page_ref,
                },
            )
            or not _hash_ref(self.policy_ref, "interaction_policy")
            or not _hash_ref(self.budget_ref, "interaction_action_budget")
            or self.action_limit != 1
            or self.intent_kind not in _ELIGIBLE_INTENT_KINDS
            or self.risk_class != "read_interaction"
            or self.locator_truncated
            or self.safety_blockers != (PASSIVE_CATALOG_BLOCKER,)
            or self.disabled
            or self.scripted_handler
            or self.constraints != _ADMISSION_CONSTRAINTS
        ):
            raise ValueError("interaction intent admission contract is invalid")

    @classmethod
    def create(
        cls,
        *,
        catalog_id: str,
        intent: InteractionIntent,
        obligation_id: str,
        frontier_ref: str,
        policy: InteractionAdmissionPolicy,
    ) -> "InteractionIntentAdmission":
        if intent.world_ref != policy.world_ref:
            raise ValueError("interaction intent and policy worlds do not match")
        scope_ref = stable_hash(
            "interaction_scope",
            {
                "target_ref": intent.target_ref,
                "page_ref": intent.page_ref,
            },
        )
        payload = _admission_payload(
            catalog_id=catalog_id,
            intent=intent,
            obligation_id=obligation_id,
            frontier_ref=frontier_ref,
            scope_ref=scope_ref,
            policy=policy,
        )
        return cls(
            admission_id=stable_hash("interaction_intent_admission", payload),
            catalog_id=catalog_id,
            intent_id=intent.intent_id,
            target_ref=intent.target_ref,
            page_ref=intent.page_ref,
            world_ref=intent.world_ref,
            locator_ref=intent.locator_ref,
            locator=intent.locator,
            locator_truncated=intent.locator_truncated,
            tag=intent.tag,
            role=intent.role,
            input_type=intent.input_type,
            destination_ref=intent.destination_ref,
            obligation_id=obligation_id,
            frontier_ref=frontier_ref,
            scope_ref=scope_ref,
            policy_ref=policy.policy_ref,
            budget_ref=policy.budget_ref,
            action_limit=policy.action_limit,
            intent_kind=intent.intent_kind,
            risk_class=intent.risk_class,
            expected_side_effect=intent.expected_side_effect,
            safety_blockers=intent.safety_blockers,
            disabled=intent.disabled,
            scripted_handler=intent.scripted_handler,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "admission_id": self.admission_id,
            "catalog_id": self.catalog_id,
            "intent_id": self.intent_id,
            "target_ref": self.target_ref,
            "page_ref": self.page_ref,
            "world_ref": self.world_ref,
            "locator_ref": self.locator_ref,
            "locator": [item.to_dict() for item in self.locator],
            "locator_truncated": self.locator_truncated,
            "tag": self.tag,
            "role": self.role,
            "input_type": self.input_type,
            "destination_ref": self.destination_ref,
            "obligation_id": self.obligation_id,
            "frontier_ref": self.frontier_ref,
            "scope_ref": self.scope_ref,
            "policy_ref": self.policy_ref,
            "budget_ref": self.budget_ref,
            "action_limit": self.action_limit,
            "intent_kind": self.intent_kind,
            "risk_class": self.risk_class,
            "expected_side_effect": self.expected_side_effect,
            "safety_blockers": list(self.safety_blockers),
            "disabled": self.disabled,
            "scripted_handler": self.scripted_handler,
            "constraints": list(self.constraints),
            "requires_active_boundary": True,
            "executable": self.executable,
        }


@dataclass(frozen=True)
class InteractionAdmissionDiagnostics:
    intents_seen: int
    eligible_intents: int
    wrong_world: int
    non_read: int
    unsafe_kind: int
    blocked: int
    ambiguous: int
    obligations_seen: int
    acquisition_obligations: int

    def __post_init__(self) -> None:
        if any(
            isinstance(value, bool) or not isinstance(value, int) or value < 0
            for value in vars(self).values()
        ):
            raise ValueError("interaction admission diagnostics are invalid")

    def to_dict(self) -> Dict[str, int]:
        return dict(vars(self))


@dataclass(frozen=True)
class InteractionAdmissionResult:
    result_id: str
    status: str
    catalog_id: str
    frontier_ref: str
    world_ref: str
    policy_ref: Optional[str]
    budget_ref: Optional[str]
    admission: Optional[InteractionIntentAdmission]
    diagnostics: InteractionAdmissionDiagnostics
    executable: bool = False
    mode: str = INTERACTION_ADMISSION_MODE

    def __post_init__(self) -> None:
        payload = {
            "mode": self.mode,
            "status": self.status,
            "catalog_id": self.catalog_id,
            "frontier_ref": self.frontier_ref,
            "world_ref": self.world_ref,
            "policy_ref": self.policy_ref,
            "budget_ref": self.budget_ref,
            "admission": (
                self.admission.to_dict() if self.admission is not None else None
            ),
            "diagnostics": self.diagnostics.to_dict(),
        }
        ready = self.status == "ready_for_active_boundary"
        if (
            self.result_id != stable_hash("interaction_admission_result", payload)
            or self.status not in _STATUSES
            or self.mode != INTERACTION_ADMISSION_MODE
            or self.executable
            or not _hash_ref(self.catalog_id, "interaction_intent_catalog")
            or not _hash_ref(self.frontier_ref, "interaction_frontier")
            or not _hash_ref(self.world_ref, "world")
            or (self.policy_ref is not None)
            != (self.status != "policy_unavailable")
            or (self.budget_ref is not None)
            != (self.status != "policy_unavailable")
            or (
                self.policy_ref is not None
                and not _hash_ref(self.policy_ref, "interaction_policy")
            )
            or (
                self.budget_ref is not None
                and not _hash_ref(
                    self.budget_ref,
                    "interaction_action_budget",
                )
            )
            or ready != (self.admission is not None)
            or (
                self.admission is not None
                and (
                    self.admission.catalog_id != self.catalog_id
                    or self.admission.frontier_ref != self.frontier_ref
                    or self.admission.world_ref != self.world_ref
                    or self.admission.policy_ref != self.policy_ref
                    or self.admission.budget_ref != self.budget_ref
                )
            )
        ):
            raise ValueError("interaction admission result contract is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": 1,
            "mode": self.mode,
            "executable": self.executable,
            "result_id": self.result_id,
            "status": self.status,
            "catalog_id": self.catalog_id,
            "frontier_ref": self.frontier_ref,
            "world_ref": self.world_ref,
            "policy_ref": self.policy_ref,
            "budget_ref": self.budget_ref,
            "admission": (
                self.admission.to_dict() if self.admission is not None else None
            ),
            "diagnostics": self.diagnostics.to_dict(),
        }


class InteractionIntentSelector:
    """Choose one sealed read interaction without acquiring execution authority."""

    @staticmethod
    def _policy(
        *,
        policy_digest: Optional[str],
        budget_snapshot: Optional[Mapping[str, int]],
        max_total_requests: Optional[int],
        world_id: str,
    ) -> Optional[InteractionAdmissionPolicy]:
        supplied = (
            policy_digest is not None,
            budget_snapshot is not None,
            max_total_requests is not None,
        )
        if not any(supplied):
            return None
        if not all(supplied):
            raise ValueError("interaction policy context is incomplete")
        return InteractionAdmissionPolicy.create(
            policy_digest=policy_digest or "",
            budget_snapshot=budget_snapshot or {},
            max_total_requests=max_total_requests or 0,
            world_id=world_id,
        )

    @staticmethod
    def _eligible_intents(
        catalog: InteractionIntentCatalog,
        *,
        world_ref: str,
    ) -> Tuple[Tuple[InteractionIntent, ...], Dict[str, int]]:
        locator_counts = Counter(
            item.locator_ref
            for item in catalog.intents
            if item.world_ref == world_ref
        )
        counters = {
            "wrong_world": 0,
            "non_read": 0,
            "unsafe_kind": 0,
            "blocked": 0,
            "ambiguous": 0,
        }
        eligible = []
        for intent in catalog.intents:
            if intent.world_ref != world_ref:
                counters["wrong_world"] += 1
                continue
            if intent.risk_class != "read_interaction":
                counters["non_read"] += 1
                continue
            if intent.intent_kind not in _ELIGIBLE_INTENT_KINDS:
                counters["unsafe_kind"] += 1
                continue
            if (
                intent.safety_blockers != (PASSIVE_CATALOG_BLOCKER,)
                or intent.disabled
                or intent.locator_truncated
                or intent.scripted_handler
            ):
                counters["blocked"] += 1
                continue
            if locator_counts[intent.locator_ref] != 1:
                counters["ambiguous"] += 1
                continue
            eligible.append(intent)
        eligible.sort(
            key=lambda item: (
                0 if item.intent_kind == "navigate" else 1,
                item.intent_id,
            )
        )
        return tuple(eligible), counters

    def select(
        self,
        catalog: InteractionIntentCatalog,
        frontier: Sequence[Mapping[str, Any]],
        *,
        world_id: str,
        policy_digest: Optional[str] = None,
        budget_snapshot: Optional[Mapping[str, int]] = None,
        max_total_requests: Optional[int] = None,
    ) -> InteractionAdmissionResult:
        if not isinstance(catalog, InteractionIntentCatalog):
            raise TypeError("catalog must be an InteractionIntentCatalog")
        if not isinstance(world_id, str) or not world_id:
            raise ValueError("interaction selection world is invalid")
        ordered_obligations = _ordered_obligations(frontier)
        frontier_ref = interaction_frontier_ref(frontier)
        world_ref = stable_hash("world", world_id)
        policy = self._policy(
            policy_digest=policy_digest,
            budget_snapshot=budget_snapshot,
            max_total_requests=max_total_requests,
            world_id=world_id,
        )
        eligible, rejection_counts = self._eligible_intents(
            catalog,
            world_ref=world_ref,
        )
        acquisition_obligations = tuple(
            item for item in ordered_obligations if item.needs_acquisition
        )
        bound_obligations = tuple(
            item
            for item in acquisition_obligations
            if item.bound_intent_ref is not None
        )
        selected_obligation = (
            bound_obligations[0]
            if bound_obligations
            else (acquisition_obligations[0] if acquisition_obligations else None)
        )
        selected_intent = None
        if selected_obligation is not None:
            bound_intent_ref = selected_obligation.bound_intent_ref
            selected_intent = next(
                (
                    intent
                    for intent in eligible
                    if bound_intent_ref is None
                    or intent.intent_id == bound_intent_ref
                ),
                None,
            )
        diagnostics = InteractionAdmissionDiagnostics(
            intents_seen=len(catalog.intents),
            eligible_intents=len(eligible),
            obligations_seen=len(ordered_obligations),
            acquisition_obligations=len(acquisition_obligations),
            **rejection_counts,
        )
        admission = None
        if policy is None:
            status = "policy_unavailable"
        elif not policy.budget_available:
            status = "budget_unavailable"
        elif not acquisition_obligations:
            status = "no_open_acquisition_obligation"
        elif selected_intent is None:
            status = "no_eligible_intents"
        else:
            status = "ready_for_active_boundary"
            assert selected_obligation is not None
            admission = InteractionIntentAdmission.create(
                catalog_id=catalog.catalog_id,
                intent=selected_intent,
                obligation_id=selected_obligation.obligation_id,
                frontier_ref=frontier_ref,
                policy=policy,
            )
        payload = {
            "mode": INTERACTION_ADMISSION_MODE,
            "status": status,
            "catalog_id": catalog.catalog_id,
            "frontier_ref": frontier_ref,
            "world_ref": world_ref,
            "policy_ref": policy.policy_ref if policy is not None else None,
            "budget_ref": policy.budget_ref if policy is not None else None,
            "admission": admission.to_dict() if admission is not None else None,
            "diagnostics": diagnostics.to_dict(),
        }
        return InteractionAdmissionResult(
            result_id=stable_hash("interaction_admission_result", payload),
            status=status,
            catalog_id=catalog.catalog_id,
            frontier_ref=frontier_ref,
            world_ref=world_ref,
            policy_ref=policy.policy_ref if policy is not None else None,
            budget_ref=policy.budget_ref if policy is not None else None,
            admission=admission,
            diagnostics=diagnostics,
        )


__all__ = [
    "INTERACTION_ADMISSION_MODE",
    "InteractionAdmissionDiagnostics",
    "InteractionAdmissionPolicy",
    "InteractionAdmissionResult",
    "InteractionIntentAdmission",
    "InteractionIntentSelector",
    "PASSIVE_CATALOG_BLOCKER",
    "interaction_frontier_ref",
]
