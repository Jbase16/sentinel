"""Redacted state and transition contracts for bounded browser exploration.

This module is analysis-only.  It turns one already completed, receipt-backed
interaction acquisition into a content-addressed transition and decides whether
the resulting state is eligible to present another safe intent.  It has no
driver, transport, receipt mutation, or execution dependency.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, Iterable, Mapping, Optional, Sequence, Tuple

from .interaction_admission import (
    InteractionAdmissionPolicy,
    InteractionIntentAdmission,
)
from .normalize import normalize_exchange, stable_hash

BROWSER_STATE_EXPLORER_MODE = "behavioral_browser_state_explorer_v1"
MAX_BROWSER_STATES = 8
MAX_BROWSER_TRANSITIONS = 7
MAX_BROWSER_DEPTH = 4
MAX_BROWSER_OPERATION_REFS = 512
MAX_BROWSER_OBLIGATION_REFS = 512

_HASH_REF = re.compile(r"^[a-z][a-z0-9_]*:[0-9a-f]{64}$")
_RECEIPT_ID = re.compile(r"^behavioral-[0-9a-f]{64}$")
_CONTROL_SURFACES = frozenset({"observed", "unobserved"})
_DECISIONS = frozenset({"stop", "eligible_for_next_transition"})
_STOP_REASONS = frozenset(
    {
        "control_surface_unobserved",
        "depth_limit",
        "duplicate_state",
        "no_next_safe_intent",
        "no_progress",
        "state_limit",
        "transition_limit",
    }
)
_SIGNALS = frozenset(
    {
        "blocker_set_changed",
        "control_surface_unobserved",
        "duplicate_state",
        "named_blocker_resolved",
        "new_control_catalog",
        "new_operation",
        "no_new_control_catalog",
        "no_named_blocker_resolved",
        "no_new_operation",
    }
)


def _hash_ref(value: Any, prefix: Optional[str] = None) -> bool:
    return (
        isinstance(value, str)
        and _HASH_REF.fullmatch(value) is not None
        and (prefix is None or value.startswith(f"{prefix}:"))
    )


def _ordered_refs(
    values: Iterable[str],
    *,
    prefix: str,
    limit: int,
    field_name: str,
) -> Tuple[str, ...]:
    consumed = tuple(values)
    if len(consumed) > limit:
        raise ValueError(f"{field_name} exceeds its limit")
    ordered = tuple(sorted(set(consumed)))
    if len(ordered) != len(consumed) or any(
        not _hash_ref(item, prefix) for item in ordered
    ):
        raise ValueError(f"{field_name} is invalid")
    return ordered


@dataclass(frozen=True)
class BrowserStateLimits:
    """Hard bounds for the future multi-transition controller."""

    max_states: int = MAX_BROWSER_STATES
    max_transitions: int = MAX_BROWSER_TRANSITIONS
    max_depth: int = MAX_BROWSER_DEPTH
    max_operation_refs: int = MAX_BROWSER_OPERATION_REFS
    max_obligation_refs: int = MAX_BROWSER_OBLIGATION_REFS

    def __post_init__(self) -> None:
        if any(
            isinstance(value, bool) or not isinstance(value, int) or value <= 0
            for value in vars(self).values()
        ):
            raise ValueError("browser state limits must be positive integers")
        if self.max_transitions >= self.max_states:
            raise ValueError("browser transition limit must be lower than state limit")
        if (
            self.max_states > MAX_BROWSER_STATES
            or self.max_transitions > MAX_BROWSER_TRANSITIONS
            or self.max_depth > MAX_BROWSER_DEPTH
            or self.max_operation_refs > MAX_BROWSER_OPERATION_REFS
            or self.max_obligation_refs > MAX_BROWSER_OBLIGATION_REFS
        ):
            raise ValueError("browser state limits exceed the safety maximum")


def operation_refs_from_records(
    records: Sequence[Mapping[str, Any]],
    *,
    target_origin: str,
    world_id: str,
    limit: int = MAX_BROWSER_OPERATION_REFS,
) -> Tuple[str, ...]:
    """Return bounded, redacted operation identities for one owned world."""

    if (
        isinstance(records, (str, bytes))
        or not isinstance(world_id, str)
        or not world_id
    ):
        raise ValueError("browser state operation input is invalid")
    if (
        isinstance(limit, bool)
        or not isinstance(limit, int)
        or not 0 < limit <= MAX_BROWSER_OPERATION_REFS
    ):
        raise ValueError("browser state operation limit is invalid")
    target = normalize_exchange(
        {"url": target_origin, "method": "GET"},
        world_id=world_id,
    ).origin
    refs = set()
    for record in records:
        if not isinstance(record, Mapping):
            raise ValueError("browser state records must contain mappings")
        exchange = normalize_exchange(record, world_id=world_id)
        if exchange.origin == target:
            refs.add(exchange.action_id)
            if len(refs) > limit:
                raise ValueError("browser state operations exceed their limit")
    return _ordered_refs(
        sorted(refs),
        prefix="action",
        limit=limit,
        field_name="browser state operations",
    )


def _behavior_payload(
    *,
    target_ref: str,
    world_ref: str,
    page_ref: str,
    control_surface: str,
    interaction_catalog_id: Optional[str],
    operation_refs: Sequence[str],
) -> Dict[str, Any]:
    return {
        "target_ref": target_ref,
        "world_ref": world_ref,
        "page_ref": page_ref,
        "control_surface": control_surface,
        "interaction_catalog_id": interaction_catalog_id,
        "operation_refs": list(operation_refs),
    }


def _state_payload(
    *,
    behavior_ref: str,
    policy_ref: str,
    budget_ref: str,
) -> Dict[str, Any]:
    return {
        "behavior_ref": behavior_ref,
        "policy_ref": policy_ref,
        "budget_ref": budget_ref,
    }


@dataclass(frozen=True)
class BrowserState:
    state_id: str
    behavior_ref: str
    target_ref: str
    world_ref: str
    page_ref: str
    control_surface: str
    interaction_catalog_id: Optional[str]
    operation_refs: Tuple[str, ...]
    policy_ref: str
    budget_ref: str
    depth: int
    executable: bool = False
    mode: str = BROWSER_STATE_EXPLORER_MODE

    def __post_init__(self) -> None:
        behavior_payload = _behavior_payload(
            target_ref=self.target_ref,
            world_ref=self.world_ref,
            page_ref=self.page_ref,
            control_surface=self.control_surface,
            interaction_catalog_id=self.interaction_catalog_id,
            operation_refs=self.operation_refs,
        )
        payload = _state_payload(
            behavior_ref=self.behavior_ref,
            policy_ref=self.policy_ref,
            budget_ref=self.budget_ref,
        )
        catalog_valid = (
            self.control_surface == "observed"
            and _hash_ref(
                self.interaction_catalog_id,
                "interaction_intent_catalog",
            )
        ) or (
            self.control_surface == "unobserved" and self.interaction_catalog_id is None
        )
        if (
            self.state_id != stable_hash("browser_state", payload)
            or self.behavior_ref != stable_hash("browser_behavior", behavior_payload)
            or self.mode != BROWSER_STATE_EXPLORER_MODE
            or self.executable
            or not _hash_ref(self.target_ref, "interaction_target")
            or not _hash_ref(self.world_ref, "world")
            or not _hash_ref(self.page_ref, "interaction_page")
            or self.control_surface not in _CONTROL_SURFACES
            or not catalog_valid
            or tuple(sorted(set(self.operation_refs))) != self.operation_refs
            or len(self.operation_refs) > MAX_BROWSER_OPERATION_REFS
            or any(not _hash_ref(item, "action") for item in self.operation_refs)
            or not _hash_ref(self.policy_ref, "interaction_policy")
            or not _hash_ref(self.budget_ref, "interaction_action_budget")
            or isinstance(self.depth, bool)
            or not isinstance(self.depth, int)
            or not 0 <= self.depth <= MAX_BROWSER_DEPTH
        ):
            raise ValueError("browser state contract is invalid")

    @classmethod
    def create(
        cls,
        *,
        target_ref: str,
        world_ref: str,
        page_ref: str,
        control_surface: str,
        interaction_catalog_id: Optional[str],
        operation_refs: Iterable[str],
        policy_ref: str,
        budget_ref: str,
        depth: int,
        limits: BrowserStateLimits = BrowserStateLimits(),
    ) -> "BrowserState":
        if not isinstance(limits, BrowserStateLimits):
            raise TypeError("limits must be BrowserStateLimits")
        if depth > limits.max_depth:
            raise ValueError("browser state depth exceeds its limit")
        ordered_operations = _ordered_refs(
            operation_refs,
            prefix="action",
            limit=limits.max_operation_refs,
            field_name="browser state operations",
        )
        behavior_payload = _behavior_payload(
            target_ref=target_ref,
            world_ref=world_ref,
            page_ref=page_ref,
            control_surface=control_surface,
            interaction_catalog_id=interaction_catalog_id,
            operation_refs=ordered_operations,
        )
        behavior_ref = stable_hash("browser_behavior", behavior_payload)
        payload = _state_payload(
            behavior_ref=behavior_ref,
            policy_ref=policy_ref,
            budget_ref=budget_ref,
        )
        return cls(
            state_id=stable_hash("browser_state", payload),
            behavior_ref=behavior_ref,
            target_ref=target_ref,
            world_ref=world_ref,
            page_ref=page_ref,
            control_surface=control_surface,
            interaction_catalog_id=interaction_catalog_id,
            operation_refs=ordered_operations,
            policy_ref=policy_ref,
            budget_ref=budget_ref,
            depth=depth,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "state_id": self.state_id,
            "behavior_ref": self.behavior_ref,
            **_behavior_payload(
                target_ref=self.target_ref,
                world_ref=self.world_ref,
                page_ref=self.page_ref,
                control_surface=self.control_surface,
                interaction_catalog_id=self.interaction_catalog_id,
                operation_refs=self.operation_refs,
            ),
            **_state_payload(
                behavior_ref=self.behavior_ref,
                policy_ref=self.policy_ref,
                budget_ref=self.budget_ref,
            ),
            "depth": self.depth,
            "mode": self.mode,
            "executable": self.executable,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "BrowserState":
        if not isinstance(value, Mapping) or set(value) != {
            "state_id",
            "behavior_ref",
            "target_ref",
            "world_ref",
            "page_ref",
            "control_surface",
            "interaction_catalog_id",
            "operation_refs",
            "policy_ref",
            "budget_ref",
            "depth",
            "mode",
            "executable",
        }:
            raise ValueError("serialized browser state is invalid")
        operation_refs = value.get("operation_refs")
        if not isinstance(operation_refs, Sequence) or isinstance(
            operation_refs,
            (str, bytes),
        ):
            raise ValueError("serialized browser state operations are invalid")
        return cls(
            state_id=value["state_id"],
            behavior_ref=value["behavior_ref"],
            target_ref=value["target_ref"],
            world_ref=value["world_ref"],
            page_ref=value["page_ref"],
            control_surface=value["control_surface"],
            interaction_catalog_id=value["interaction_catalog_id"],
            operation_refs=tuple(operation_refs),
            policy_ref=value["policy_ref"],
            budget_ref=value["budget_ref"],
            depth=value["depth"],
            mode=value["mode"],
            executable=value["executable"],
        )


def _frontier_status(
    frontier: Sequence[Mapping[str, Any]],
    *,
    limit: int,
) -> Dict[str, bool]:
    if isinstance(frontier, (str, bytes)) or len(frontier) > limit:
        raise ValueError("browser transition obligation frontier is invalid")
    statuses: Dict[str, bool] = {}
    for item in frontier:
        if not isinstance(item, Mapping):
            raise ValueError("browser transition obligation frontier is invalid")
        obligation_id = item.get("obligation_id")
        actionable = item.get("actionable")
        if (
            not _hash_ref(obligation_id, "security_obligation")
            or not isinstance(actionable, bool)
            or obligation_id in statuses
        ):
            raise ValueError("browser transition obligation frontier is invalid")
        statuses[obligation_id] = actionable
    return statuses


def _transition_payload(
    *,
    receipt_id: str,
    before_state_id: str,
    after_state_id: str,
    admission_id: str,
    intent_id: str,
    obligation_id: str,
    acquisition_id: str,
    request_ref: str,
    response_ref: str,
    new_operation_refs: Sequence[str],
    resolved_blocker_ids: Sequence[str],
    remaining_blocker_ids: Sequence[str],
    next_admission_id: Optional[str],
    next_intent_id: Optional[str],
    depth: int,
    decision: str,
    stop_reasons: Sequence[str],
    signals: Sequence[str],
) -> Dict[str, Any]:
    return {
        "receipt_id": receipt_id,
        "before_state_id": before_state_id,
        "after_state_id": after_state_id,
        "admission_id": admission_id,
        "intent_id": intent_id,
        "obligation_id": obligation_id,
        "acquisition_id": acquisition_id,
        "request_ref": request_ref,
        "response_ref": response_ref,
        "new_operation_refs": list(new_operation_refs),
        "resolved_blocker_ids": list(resolved_blocker_ids),
        "remaining_blocker_ids": list(remaining_blocker_ids),
        "next_admission_id": next_admission_id,
        "next_intent_id": next_intent_id,
        "depth": depth,
        "decision": decision,
        "stop_reasons": list(stop_reasons),
        "signals": list(signals),
    }


@dataclass(frozen=True)
class BrowserStateTransition:
    transition_id: str
    receipt_id: str
    before_state_id: str
    after_state_id: str
    admission_id: str
    intent_id: str
    obligation_id: str
    acquisition_id: str
    request_ref: str
    response_ref: str
    new_operation_refs: Tuple[str, ...]
    resolved_blocker_ids: Tuple[str, ...]
    remaining_blocker_ids: Tuple[str, ...]
    next_admission_id: Optional[str]
    next_intent_id: Optional[str]
    depth: int
    decision: str
    stop_reasons: Tuple[str, ...]
    signals: Tuple[str, ...]
    executable: bool = False
    mode: str = BROWSER_STATE_EXPLORER_MODE

    def __post_init__(self) -> None:
        payload = _transition_payload(
            receipt_id=self.receipt_id,
            before_state_id=self.before_state_id,
            after_state_id=self.after_state_id,
            admission_id=self.admission_id,
            intent_id=self.intent_id,
            obligation_id=self.obligation_id,
            acquisition_id=self.acquisition_id,
            request_ref=self.request_ref,
            response_ref=self.response_ref,
            new_operation_refs=self.new_operation_refs,
            resolved_blocker_ids=self.resolved_blocker_ids,
            remaining_blocker_ids=self.remaining_blocker_ids,
            next_admission_id=self.next_admission_id,
            next_intent_id=self.next_intent_id,
            depth=self.depth,
            decision=self.decision,
            stop_reasons=self.stop_reasons,
            signals=self.signals,
        )
        next_valid = (
            self.next_admission_id is None and self.next_intent_id is None
        ) or (
            _hash_ref(self.next_admission_id, "interaction_intent_admission")
            and _hash_ref(self.next_intent_id, "interaction_intent")
        )
        if (
            self.transition_id != stable_hash("browser_state_transition", payload)
            or self.mode != BROWSER_STATE_EXPLORER_MODE
            or self.executable
            or _RECEIPT_ID.fullmatch(self.receipt_id) is None
            or not _hash_ref(self.before_state_id, "browser_state")
            or not _hash_ref(self.after_state_id, "browser_state")
            or not _hash_ref(self.admission_id, "interaction_intent_admission")
            or not _hash_ref(self.intent_id, "interaction_intent")
            or not _hash_ref(self.obligation_id, "security_obligation")
            or not _hash_ref(self.acquisition_id, "interaction_read_acquisition")
            or not _hash_ref(self.request_ref, "interaction_acquisition_request")
            or not _hash_ref(self.response_ref, "interaction_acquisition_response")
            or tuple(sorted(set(self.new_operation_refs))) != self.new_operation_refs
            or len(self.new_operation_refs) > MAX_BROWSER_OPERATION_REFS
            or any(not _hash_ref(item, "action") for item in self.new_operation_refs)
            or tuple(sorted(set(self.resolved_blocker_ids)))
            != self.resolved_blocker_ids
            or len(self.resolved_blocker_ids) > MAX_BROWSER_OBLIGATION_REFS
            or any(
                not _hash_ref(item, "security_obligation")
                for item in self.resolved_blocker_ids
            )
            or tuple(sorted(set(self.remaining_blocker_ids)))
            != self.remaining_blocker_ids
            or len(self.remaining_blocker_ids) > MAX_BROWSER_OBLIGATION_REFS
            or any(
                not _hash_ref(item, "security_obligation")
                for item in self.remaining_blocker_ids
            )
            or not next_valid
            or isinstance(self.depth, bool)
            or not isinstance(self.depth, int)
            or not 0 < self.depth <= MAX_BROWSER_DEPTH
            or self.decision not in _DECISIONS
            or tuple(sorted(set(self.stop_reasons))) != self.stop_reasons
            or any(item not in _STOP_REASONS for item in self.stop_reasons)
            or tuple(sorted(set(self.signals))) != self.signals
            or any(item not in _SIGNALS for item in self.signals)
            or (self.decision == "stop") != bool(self.stop_reasons)
            or (self.decision == "eligible_for_next_transition")
            != (self.next_admission_id is not None)
        ):
            raise ValueError("browser state transition contract is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": 1,
            "mode": self.mode,
            "executable": self.executable,
            "transition_id": self.transition_id,
            **_transition_payload(
                receipt_id=self.receipt_id,
                before_state_id=self.before_state_id,
                after_state_id=self.after_state_id,
                admission_id=self.admission_id,
                intent_id=self.intent_id,
                obligation_id=self.obligation_id,
                acquisition_id=self.acquisition_id,
                request_ref=self.request_ref,
                response_ref=self.response_ref,
                new_operation_refs=self.new_operation_refs,
                resolved_blocker_ids=self.resolved_blocker_ids,
                remaining_blocker_ids=self.remaining_blocker_ids,
                next_admission_id=self.next_admission_id,
                next_intent_id=self.next_intent_id,
                depth=self.depth,
                decision=self.decision,
                stop_reasons=self.stop_reasons,
                signals=self.signals,
            ),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "BrowserStateTransition":
        if (
            not isinstance(value, Mapping)
            or set(value)
            != {
                "schema_version",
                "mode",
                "executable",
                "transition_id",
                "receipt_id",
                "before_state_id",
                "after_state_id",
                "admission_id",
                "intent_id",
                "obligation_id",
                "acquisition_id",
                "request_ref",
                "response_ref",
                "new_operation_refs",
                "resolved_blocker_ids",
                "remaining_blocker_ids",
                "next_admission_id",
                "next_intent_id",
                "depth",
                "decision",
                "stop_reasons",
                "signals",
            }
            or value.get("schema_version") != 1
        ):
            raise ValueError("serialized browser state transition is invalid")
        sequence_fields = (
            "new_operation_refs",
            "resolved_blocker_ids",
            "remaining_blocker_ids",
            "stop_reasons",
            "signals",
        )
        if any(
            not isinstance(value.get(key), Sequence)
            or isinstance(value.get(key), (str, bytes))
            for key in sequence_fields
        ):
            raise ValueError("serialized browser transition sequences are invalid")
        return cls(
            transition_id=value["transition_id"],
            receipt_id=value["receipt_id"],
            before_state_id=value["before_state_id"],
            after_state_id=value["after_state_id"],
            admission_id=value["admission_id"],
            intent_id=value["intent_id"],
            obligation_id=value["obligation_id"],
            acquisition_id=value["acquisition_id"],
            request_ref=value["request_ref"],
            response_ref=value["response_ref"],
            new_operation_refs=tuple(value["new_operation_refs"]),
            resolved_blocker_ids=tuple(value["resolved_blocker_ids"]),
            remaining_blocker_ids=tuple(value["remaining_blocker_ids"]),
            next_admission_id=value["next_admission_id"],
            next_intent_id=value["next_intent_id"],
            depth=value["depth"],
            decision=value["decision"],
            stop_reasons=tuple(value["stop_reasons"]),
            signals=tuple(value["signals"]),
            mode=value["mode"],
            executable=value["executable"],
        )


@dataclass(frozen=True)
class BrowserTransitionResult:
    result_id: str
    before_state: BrowserState
    after_state: BrowserState
    transition: BrowserStateTransition
    state_count: int
    transition_count: int
    executable: bool = False
    mode: str = BROWSER_STATE_EXPLORER_MODE

    def __post_init__(self) -> None:
        payload = {
            "before_state_id": self.before_state.state_id,
            "after_state_id": self.after_state.state_id,
            "transition_id": self.transition.transition_id,
            "state_count": self.state_count,
            "transition_count": self.transition_count,
        }
        if (
            self.result_id != stable_hash("browser_transition_result", payload)
            or self.mode != BROWSER_STATE_EXPLORER_MODE
            or self.executable
            or self.transition.before_state_id != self.before_state.state_id
            or self.transition.after_state_id != self.after_state.state_id
            or isinstance(self.state_count, bool)
            or not isinstance(self.state_count, int)
            or self.state_count <= 0
            or self.state_count > MAX_BROWSER_STATES
            or isinstance(self.transition_count, bool)
            or not isinstance(self.transition_count, int)
            or self.transition_count <= 0
            or self.transition_count > MAX_BROWSER_TRANSITIONS
        ):
            raise ValueError("browser transition result contract is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": 1,
            "mode": self.mode,
            "executable": self.executable,
            "result_id": self.result_id,
            "state_count": self.state_count,
            "transition_count": self.transition_count,
            "before_state": self.before_state.to_dict(),
            "after_state": self.after_state.to_dict(),
            "transition": self.transition.to_dict(),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "BrowserTransitionResult":
        if (
            not isinstance(value, Mapping)
            or set(value)
            != {
                "schema_version",
                "mode",
                "executable",
                "result_id",
                "state_count",
                "transition_count",
                "before_state",
                "after_state",
                "transition",
            }
            or value.get("schema_version") != 1
        ):
            raise ValueError("serialized browser transition result is invalid")
        before_state = value.get("before_state")
        after_state = value.get("after_state")
        transition = value.get("transition")
        if not all(
            isinstance(item, Mapping)
            for item in (before_state, after_state, transition)
        ):
            raise ValueError("serialized browser transition result is invalid")
        return cls(
            result_id=value["result_id"],
            before_state=BrowserState.from_dict(before_state),
            after_state=BrowserState.from_dict(after_state),
            transition=BrowserStateTransition.from_dict(transition),
            state_count=value["state_count"],
            transition_count=value["transition_count"],
            mode=value["mode"],
            executable=value["executable"],
        )


class BoundedBrowserStateExplorer:
    """Evaluate one completed state transition without executing another."""

    def __init__(
        self,
        *,
        limits: BrowserStateLimits = BrowserStateLimits(),
    ) -> None:
        if not isinstance(limits, BrowserStateLimits):
            raise TypeError("limits must be BrowserStateLimits")
        self.limits = limits

    def observe_transition(
        self,
        *,
        before_state: BrowserState,
        after_state: BrowserState,
        admission: InteractionIntentAdmission,
        acquisition: Mapping[str, Any],
        receipt_id: str,
        before_frontier: Sequence[Mapping[str, Any]],
        after_frontier: Sequence[Mapping[str, Any]],
        seen_behavior_refs: Iterable[str] = (),
        transition_count: int = 0,
        next_admission: Optional[InteractionIntentAdmission] = None,
    ) -> BrowserTransitionResult:
        if (
            not isinstance(before_state, BrowserState)
            or not isinstance(after_state, BrowserState)
            or not isinstance(admission, InteractionIntentAdmission)
            or not isinstance(acquisition, Mapping)
        ):
            raise TypeError("browser transition inputs are invalid")
        if (
            isinstance(transition_count, bool)
            or not isinstance(transition_count, int)
            or transition_count < 0
        ):
            raise ValueError("browser transition count is invalid")
        seen = _ordered_refs(
            seen_behavior_refs,
            prefix="browser_behavior",
            limit=self.limits.max_states,
            field_name="seen browser behaviors",
        )
        before_status = _frontier_status(
            before_frontier,
            limit=self.limits.max_obligation_refs,
        )
        after_status = _frontier_status(
            after_frontier,
            limit=self.limits.max_obligation_refs,
        )
        if (
            before_state.target_ref != after_state.target_ref
            or before_state.world_ref != after_state.world_ref
            or after_state.depth != before_state.depth + 1
            or admission.target_ref != before_state.target_ref
            or admission.world_ref != before_state.world_ref
            or admission.page_ref != before_state.page_ref
            or admission.catalog_id != before_state.interaction_catalog_id
            or acquisition.get("admission_id") != admission.admission_id
            or acquisition.get("obligation_id") != admission.obligation_id
            or not _hash_ref(
                acquisition.get("acquisition_id"),
                "interaction_read_acquisition",
            )
            or not _hash_ref(
                acquisition.get("request_ref"),
                "interaction_acquisition_request",
            )
            or not _hash_ref(
                acquisition.get("response_ref"),
                "interaction_acquisition_response",
            )
            or acquisition.get("destination_page_ref") != after_state.page_ref
            or acquisition.get("operation_ref") not in after_state.operation_refs
        ):
            raise ValueError("browser transition binding is invalid")

        before_blockers = {
            obligation_id
            for obligation_id, actionable in before_status.items()
            if not actionable
        }
        after_blockers = {
            obligation_id
            for obligation_id, actionable in after_status.items()
            if not actionable
        }
        resolved = tuple(
            sorted(
                obligation_id
                for obligation_id in before_blockers
                if after_status.get(obligation_id) is True
            )
        )
        remaining = tuple(sorted(after_blockers))
        new_operations = tuple(
            sorted(set(after_state.operation_refs) - set(before_state.operation_refs))
        )
        new_control_catalog = (
            after_state.control_surface == "observed"
            and after_state.interaction_catalog_id
            != before_state.interaction_catalog_id
        )
        duplicate_state = (
            after_state.behavior_ref == before_state.behavior_ref
            or after_state.behavior_ref in seen
        )
        candidate_state_count = len(
            set(
                (
                    *seen,
                    before_state.behavior_ref,
                    after_state.behavior_ref,
                )
            )
        )
        candidate_transition_count = transition_count + 1
        state_count = min(candidate_state_count, self.limits.max_states)
        next_transition_count = min(
            candidate_transition_count,
            self.limits.max_transitions,
        )

        signals = {
            (
                "new_control_catalog"
                if new_control_catalog
                else "no_new_control_catalog"
            ),
            "new_operation" if new_operations else "no_new_operation",
            ("named_blocker_resolved" if resolved else "no_named_blocker_resolved"),
        }
        if before_blockers != after_blockers:
            signals.add("blocker_set_changed")
        if duplicate_state:
            signals.add("duplicate_state")
        if after_state.control_surface == "unobserved":
            signals.add("control_surface_unobserved")

        stop_reasons = set()
        if duplicate_state:
            stop_reasons.add("duplicate_state")
        if not new_operations and not resolved and not new_control_catalog:
            stop_reasons.add("no_progress")
        if candidate_state_count >= self.limits.max_states:
            stop_reasons.add("state_limit")
        if candidate_transition_count >= self.limits.max_transitions:
            stop_reasons.add("transition_limit")
        if after_state.depth >= self.limits.max_depth:
            stop_reasons.add("depth_limit")
        if after_state.control_surface != "observed":
            stop_reasons.add("control_surface_unobserved")

        next_admission_id = None
        next_intent_id = None
        if not stop_reasons:
            if next_admission is None:
                stop_reasons.add("no_next_safe_intent")
            elif (
                next_admission.target_ref != after_state.target_ref
                or next_admission.world_ref != after_state.world_ref
                or next_admission.page_ref != after_state.page_ref
                or next_admission.catalog_id != after_state.interaction_catalog_id
                or next_admission.policy_ref != after_state.policy_ref
                or next_admission.budget_ref != after_state.budget_ref
                or after_status.get(next_admission.obligation_id) is not False
            ):
                raise ValueError("next browser transition admission is not state-bound")
            else:
                next_admission_id = next_admission.admission_id
                next_intent_id = next_admission.intent_id

        decision = (
            "eligible_for_next_transition" if next_admission_id is not None else "stop"
        )
        transition_payload = _transition_payload(
            receipt_id=receipt_id,
            before_state_id=before_state.state_id,
            after_state_id=after_state.state_id,
            admission_id=admission.admission_id,
            intent_id=admission.intent_id,
            obligation_id=admission.obligation_id,
            acquisition_id=acquisition["acquisition_id"],
            request_ref=acquisition["request_ref"],
            response_ref=acquisition["response_ref"],
            new_operation_refs=new_operations,
            resolved_blocker_ids=resolved,
            remaining_blocker_ids=remaining,
            next_admission_id=next_admission_id,
            next_intent_id=next_intent_id,
            depth=after_state.depth,
            decision=decision,
            stop_reasons=tuple(sorted(stop_reasons)),
            signals=tuple(sorted(signals)),
        )
        transition = BrowserStateTransition(
            transition_id=stable_hash(
                "browser_state_transition",
                transition_payload,
            ),
            new_operation_refs=new_operations,
            resolved_blocker_ids=resolved,
            remaining_blocker_ids=remaining,
            stop_reasons=tuple(sorted(stop_reasons)),
            signals=tuple(sorted(signals)),
            **{
                key: value
                for key, value in transition_payload.items()
                if key
                not in {
                    "new_operation_refs",
                    "resolved_blocker_ids",
                    "remaining_blocker_ids",
                    "stop_reasons",
                    "signals",
                }
            },
        )
        result_payload = {
            "before_state_id": before_state.state_id,
            "after_state_id": after_state.state_id,
            "transition_id": transition.transition_id,
            "state_count": state_count,
            "transition_count": next_transition_count,
        }
        return BrowserTransitionResult(
            result_id=stable_hash("browser_transition_result", result_payload),
            before_state=before_state,
            after_state=after_state,
            transition=transition,
            state_count=state_count,
            transition_count=next_transition_count,
        )


def build_acquisition_transition(
    *,
    target_origin: str,
    world_id: str,
    before_records: Sequence[Mapping[str, Any]],
    admission: InteractionIntentAdmission,
    acquisition: Mapping[str, Any],
    receipt_id: str,
    policy_digest: str,
    max_total_requests: int,
    before_frontier: Sequence[Mapping[str, Any]],
    after_frontier: Sequence[Mapping[str, Any]],
    limits: BrowserStateLimits = BrowserStateLimits(),
    next_admission: Optional[InteractionIntentAdmission] = None,
    after_control_surface: str = "unobserved",
    after_catalog_id: Optional[str] = None,
) -> BrowserTransitionResult:
    """Build the exact one-click transition from one redacted acquisition."""

    if not isinstance(admission, InteractionIntentAdmission):
        raise TypeError("interaction admission is required")
    budget_snapshot = acquisition.get("budget_snapshot")
    if not isinstance(budget_snapshot, Mapping):
        raise ValueError("interaction acquisition budget snapshot is missing")
    before_state = BrowserState.create(
        target_ref=admission.target_ref,
        world_ref=admission.world_ref,
        page_ref=admission.page_ref,
        control_surface="observed",
        interaction_catalog_id=admission.catalog_id,
        operation_refs=operation_refs_from_records(
            before_records,
            target_origin=target_origin,
            world_id=world_id,
            limit=limits.max_operation_refs,
        ),
        policy_ref=admission.policy_ref,
        budget_ref=admission.budget_ref,
        depth=0,
        limits=limits,
    )
    after_policy = InteractionAdmissionPolicy.create(
        policy_digest=policy_digest,
        budget_snapshot=budget_snapshot,
        max_total_requests=max_total_requests,
        world_id=world_id,
    )
    operation_ref = acquisition.get("operation_ref")
    if not _hash_ref(operation_ref, "action"):
        raise ValueError("interaction acquisition operation reference is invalid")
    after_state = BrowserState.create(
        target_ref=admission.target_ref,
        world_ref=admission.world_ref,
        page_ref=acquisition.get("destination_page_ref"),
        control_surface=after_control_surface,
        interaction_catalog_id=after_catalog_id,
        operation_refs=tuple(sorted({*before_state.operation_refs, operation_ref})),
        policy_ref=after_policy.policy_ref,
        budget_ref=after_policy.budget_ref,
        depth=1,
        limits=limits,
    )
    return BoundedBrowserStateExplorer(limits=limits).observe_transition(
        before_state=before_state,
        after_state=after_state,
        admission=admission,
        acquisition=acquisition,
        receipt_id=receipt_id,
        before_frontier=before_frontier,
        after_frontier=after_frontier,
        next_admission=next_admission,
    )


def build_chained_acquisition_transition(
    *,
    parent: BrowserTransitionResult,
    world_id: str,
    admission: InteractionIntentAdmission,
    acquisition: Mapping[str, Any],
    receipt_id: str,
    policy_digest: str,
    max_total_requests: int,
    before_frontier: Sequence[Mapping[str, Any]],
    after_frontier: Sequence[Mapping[str, Any]],
    after_control_surface: str,
    after_catalog_id: Optional[str],
    limits: BrowserStateLimits,
) -> BrowserTransitionResult:
    """Build one parent-bound transition and refuse a third interaction."""

    if (
        not isinstance(parent, BrowserTransitionResult)
        or not isinstance(admission, InteractionIntentAdmission)
        or not isinstance(limits, BrowserStateLimits)
        or not isinstance(world_id, str)
        or not world_id
    ):
        raise TypeError("chained browser transition inputs are invalid")
    if (
        parent.transition.decision != "eligible_for_next_transition"
        or parent.transition.next_admission_id != admission.admission_id
        or parent.transition.next_intent_id != admission.intent_id
        or parent.transition.after_state_id != parent.after_state.state_id
        or parent.transition_count != 1
        or limits.max_transitions != 2
    ):
        raise ValueError("chained browser transition parent is invalid")
    budget_snapshot = acquisition.get("budget_snapshot")
    if not isinstance(budget_snapshot, Mapping):
        raise ValueError("chained interaction budget snapshot is missing")
    operation_ref = acquisition.get("operation_ref")
    if not _hash_ref(operation_ref, "action"):
        raise ValueError("chained interaction operation reference is invalid")
    after_policy = InteractionAdmissionPolicy.create(
        policy_digest=policy_digest,
        budget_snapshot=budget_snapshot,
        max_total_requests=max_total_requests,
        world_id=world_id,
    )
    if after_policy.world_ref != admission.world_ref:
        raise ValueError("chained interaction world binding is invalid")
    after_state = BrowserState.create(
        target_ref=admission.target_ref,
        world_ref=admission.world_ref,
        page_ref=acquisition.get("destination_page_ref"),
        control_surface=after_control_surface,
        interaction_catalog_id=after_catalog_id,
        operation_refs=tuple(
            sorted({*parent.after_state.operation_refs, operation_ref})
        ),
        policy_ref=after_policy.policy_ref,
        budget_ref=after_policy.budget_ref,
        depth=parent.after_state.depth + 1,
        limits=limits,
    )
    return BoundedBrowserStateExplorer(limits=limits).observe_transition(
        before_state=parent.after_state,
        after_state=after_state,
        admission=admission,
        acquisition=acquisition,
        receipt_id=receipt_id,
        before_frontier=before_frontier,
        after_frontier=after_frontier,
        seen_behavior_refs=(parent.before_state.behavior_ref,),
        transition_count=parent.transition_count,
        next_admission=None,
    )


__all__ = [
    "BROWSER_STATE_EXPLORER_MODE",
    "BoundedBrowserStateExplorer",
    "BrowserState",
    "BrowserStateLimits",
    "BrowserStateTransition",
    "BrowserTransitionResult",
    "build_acquisition_transition",
    "build_chained_acquisition_transition",
    "operation_refs_from_records",
]
