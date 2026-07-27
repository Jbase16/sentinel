"""Passive, redacted browser-control intent catalog.

The catalog consumes bounded structural DOM observations that were already read
from an owned browser window. It has no driver or transport dependency, never
retains labels or attribute values, and cannot authorize an interaction.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple
from urllib.parse import urlsplit

from .normalize import normalize_exchange, stable_hash

INTERACTION_INTENT_MODE = "behavioral_interaction_intent_v1"

_HASH_REF = re.compile(r"^[a-z][a-z0-9_]*:[0-9a-f]{64}$")
_SEMANTIC = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_LOCATOR_TAG = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
_TAGS = frozenset(
    {
        "a",
        "button",
        "input",
        "option",
        "other",
        "select",
        "summary",
        "textarea",
    }
)
_ROLES = frozenset(
    {
        "button",
        "checkbox",
        "combobox",
        "link",
        "menuitem",
        "option",
        "radio",
        "searchbox",
        "switch",
        "tab",
        "textbox",
    }
)
_INPUT_TYPES = frozenset(
    {
        "button",
        "checkbox",
        "color",
        "date",
        "datetime-local",
        "email",
        "file",
        "hidden",
        "image",
        "month",
        "number",
        "password",
        "radio",
        "range",
        "reset",
        "search",
        "submit",
        "tel",
        "text",
        "time",
        "url",
        "week",
    }
)
_FORM_METHODS = frozenset({"none", "get", "post", "destructive_override", "unknown"})
_DESTINATIONS = frozenset(
    {"none", "same_origin", "external_origin", "non_http", "invalid"}
)
_INTENT_KINDS = frozenset(
    {
        "filter",
        "navigate",
        "reveal",
        "select",
        "submit_form",
        "unknown",
    }
)
_RISK_CLASSES = frozenset(
    {
        "read_interaction",
        "state_mutation",
        "externally_consequential",
        "destructive",
        "unknown",
    }
)


def _hash_ref(value: Any, prefix: str) -> bool:
    return (
        isinstance(value, str)
        and value.startswith(f"{prefix}:")
        and _HASH_REF.fullmatch(value) is not None
    )


def _normalized_origin(value: str) -> str:
    parts = urlsplit(str(value or "").strip())
    try:
        host = (parts.hostname or "").lower()
        port = parts.port
    except ValueError as exc:
        raise ValueError("interaction target origin is invalid") from exc
    scheme = parts.scheme.lower()
    if scheme not in {"http", "https"} or not host:
        raise ValueError("interaction target origin must be absolute HTTP(S)")
    default_port = (scheme == "http" and port in {None, 80}) or (
        scheme == "https" and port in {None, 443}
    )
    return f"{scheme}://{host}" if default_port else f"{scheme}://{host}:{port}"


def _interaction_page_ref(origin: str, page_url: Optional[str]) -> str:
    normalized = normalize_exchange({
        "url": page_url or f"{origin}/",
        "method": "GET",
    })
    if normalized.origin != origin:
        raise ValueError("interaction page must match the target origin")
    return stable_hash(
        "interaction_page",
        {
            "origin": origin,
            "path_template": normalized.path_template,
        },
    )


@dataclass(frozen=True)
class InteractionIntentLimits:
    max_controls_per_world: int = 256
    max_total_controls: int = 512
    max_locator_depth: int = 12
    max_sibling_index: int = 4_096

    def __post_init__(self) -> None:
        if (
            any(
                isinstance(value, bool)
                or not isinstance(value, int)
                or value <= 0
                for value in vars(self).values()
            )
            or self.max_total_controls < self.max_controls_per_world
            or self.max_controls_per_world > 256
            or self.max_total_controls > 512
            or self.max_locator_depth > 12
            or self.max_sibling_index > 4_096
        ):
            raise ValueError("interaction intent limits are invalid")


@dataclass(frozen=True)
class StructuralLocatorSegment:
    tag: str
    sibling_index: int

    def __post_init__(self) -> None:
        if (
            _LOCATOR_TAG.fullmatch(self.tag) is None
            or isinstance(self.sibling_index, bool)
            or not isinstance(self.sibling_index, int)
            or not 1 <= self.sibling_index <= 4_096
        ):
            raise ValueError("structural locator segment is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {"tag": self.tag, "sibling_index": self.sibling_index}


@dataclass(frozen=True)
class InteractionIntent:
    intent_id: str
    target_ref: str
    world_ref: str
    page_ref: str
    locator_ref: str
    locator: Tuple[StructuralLocatorSegment, ...]
    locator_truncated: bool
    tag: str
    role: str
    input_type: str
    intent_kind: str
    risk_class: str
    expected_side_effect: str
    safety_blockers: Tuple[str, ...]
    disabled: bool
    scripted_handler: bool
    executable: bool = False
    mode: str = INTERACTION_INTENT_MODE

    def __post_init__(self) -> None:
        identity = {
            "target_ref": self.target_ref,
            "world_ref": self.world_ref,
            "page_ref": self.page_ref,
            "locator_ref": self.locator_ref,
            "locator_truncated": self.locator_truncated,
            "tag": self.tag,
            "role": self.role,
            "input_type": self.input_type,
            "intent_kind": self.intent_kind,
            "risk_class": self.risk_class,
            "expected_side_effect": self.expected_side_effect,
            "safety_blockers": list(self.safety_blockers),
            "disabled": self.disabled,
            "scripted_handler": self.scripted_handler,
        }
        locator_payload = [item.to_dict() for item in self.locator]
        if (
            self.intent_id != stable_hash("interaction_intent", identity)
            or self.locator_ref
            != stable_hash("interaction_locator", locator_payload)
            or self.mode != INTERACTION_INTENT_MODE
            or self.executable
            or not _hash_ref(self.target_ref, "interaction_target")
            or not _hash_ref(self.world_ref, "world")
            or not _hash_ref(self.page_ref, "interaction_page")
            or not _hash_ref(self.locator_ref, "interaction_locator")
            or not self.locator
            or not isinstance(self.locator_truncated, bool)
            or self.tag not in _TAGS
            or (self.role and self.role not in _ROLES)
            or (self.input_type and self.input_type not in _INPUT_TYPES)
            or self.intent_kind not in _INTENT_KINDS
            or self.risk_class not in _RISK_CLASSES
            or _SEMANTIC.fullmatch(self.expected_side_effect) is None
            or not self.safety_blockers
            or tuple(sorted(set(self.safety_blockers))) != self.safety_blockers
            or any(_SEMANTIC.fullmatch(item) is None for item in self.safety_blockers)
            or not isinstance(self.disabled, bool)
            or not isinstance(self.scripted_handler, bool)
        ):
            raise ValueError("interaction intent contract is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "intent_id": self.intent_id,
            "target_ref": self.target_ref,
            "world_ref": self.world_ref,
            "page_ref": self.page_ref,
            "locator_ref": self.locator_ref,
            "locator": [item.to_dict() for item in self.locator],
            "locator_truncated": self.locator_truncated,
            "tag": self.tag,
            "role": self.role,
            "input_type": self.input_type,
            "intent_kind": self.intent_kind,
            "risk_class": self.risk_class,
            "expected_side_effect": self.expected_side_effect,
            "safety_blockers": list(self.safety_blockers),
            "disabled": self.disabled,
            "scripted_handler": self.scripted_handler,
            "requires_active_confirmation": True,
            "executable": self.executable,
        }


@dataclass(frozen=True)
class InteractionIntentDiagnostics:
    controls_seen: int
    accepted_controls: int
    invalid_controls: int
    hidden_controls: int
    duplicate_controls: int
    dropped_controls: int
    read_interactions: int
    state_mutations: int
    externally_consequential: int
    destructive: int
    unknown: int
    truncated_locators: int

    def __post_init__(self) -> None:
        if any(
            isinstance(value, bool) or not isinstance(value, int) or value < 0
            for value in vars(self).values()
        ):
            raise ValueError("interaction diagnostics must be non-negative integers")

    def to_dict(self) -> Dict[str, int]:
        return dict(vars(self))


@dataclass(frozen=True)
class InteractionIntentCatalog:
    catalog_id: str
    target_ref: str
    intent_digest: str
    intents: Tuple[InteractionIntent, ...]
    diagnostics: InteractionIntentDiagnostics
    status: str
    executable: bool = False
    mode: str = INTERACTION_INTENT_MODE

    def __post_init__(self) -> None:
        intent_ids = [item.intent_id for item in self.intents]
        identity = {
            "mode": self.mode,
            "target_ref": self.target_ref,
            "intent_digest": self.intent_digest,
            "intent_ids": intent_ids,
            "diagnostics": self.diagnostics.to_dict(),
        }
        expected_status = "ready" if self.intents else "no_interaction_intents"
        if (
            self.catalog_id != stable_hash("interaction_intent_catalog", identity)
            or self.intent_digest
            != stable_hash(
                "interaction_intent_set",
                [item.to_dict() for item in self.intents],
            )
            or self.status != expected_status
            or self.mode != INTERACTION_INTENT_MODE
            or self.executable
            or not _hash_ref(self.target_ref, "interaction_target")
            or intent_ids != sorted(set(intent_ids))
            or any(item.target_ref != self.target_ref for item in self.intents)
        ):
            raise ValueError("interaction intent catalog contract is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": 1,
            "mode": self.mode,
            "executable": self.executable,
            "status": self.status,
            "catalog_id": self.catalog_id,
            "target_ref": self.target_ref,
            "intent_digest": self.intent_digest,
            "intents": [item.to_dict() for item in self.intents],
            "diagnostics": self.diagnostics.to_dict(),
        }


@dataclass(frozen=True)
class _NormalizedControl:
    locator: Tuple[StructuralLocatorSegment, ...]
    locator_truncated: bool
    tag: str
    role: str
    input_type: str
    form_method: str
    destination: str
    visible: bool
    disabled: bool
    content_editable: bool
    aria_expanded: bool
    aria_haspopup: bool
    sensitive_form: bool
    download: bool
    scripted_handler: bool
    submitter: bool


def _boolean(value: Any) -> Optional[bool]:
    return value if isinstance(value, bool) else None


def _normalize_control(
    value: Mapping[str, Any],
    *,
    limits: InteractionIntentLimits,
) -> Optional[_NormalizedControl]:
    tag = str(value.get("tag") or "").strip().lower()
    role = str(value.get("role") or "").strip().lower()
    input_type = str(value.get("input_type") or "").strip().lower()
    form_method = str(value.get("form_method") or "none").strip().lower()
    destination = str(value.get("destination") or "none").strip().lower()
    raw_locator = value.get("locator")
    booleans = {
        name: _boolean(value.get(name))
        for name in (
            "locator_truncated",
            "visible",
            "disabled",
            "content_editable",
            "aria_expanded",
            "aria_haspopup",
            "sensitive_form",
            "download",
            "scripted_handler",
            "submitter",
        )
    }
    if (
        tag not in _TAGS
        or (role and role not in _ROLES)
        or (input_type and input_type not in _INPUT_TYPES)
        or form_method not in _FORM_METHODS
        or destination not in _DESTINATIONS
        or not isinstance(raw_locator, Sequence)
        or isinstance(raw_locator, (str, bytes))
        or not 1 <= len(raw_locator) <= limits.max_locator_depth
        or any(item is None for item in booleans.values())
    ):
        return None
    locator = []
    for raw_segment in raw_locator:
        if not isinstance(raw_segment, Mapping):
            return None
        segment_tag = str(raw_segment.get("tag") or "").strip().lower()
        sibling_index = raw_segment.get("sibling_index")
        if (
            _LOCATOR_TAG.fullmatch(segment_tag) is None
            or isinstance(sibling_index, bool)
            or not isinstance(sibling_index, int)
            or not 1 <= sibling_index <= limits.max_sibling_index
        ):
            return None
        locator.append(StructuralLocatorSegment(segment_tag, sibling_index))
    return _NormalizedControl(
        locator=tuple(locator),
        locator_truncated=bool(booleans["locator_truncated"]),
        tag=tag,
        role=role,
        input_type=input_type,
        form_method=form_method,
        destination=destination,
        visible=bool(booleans["visible"]),
        disabled=bool(booleans["disabled"]),
        content_editable=bool(booleans["content_editable"]),
        aria_expanded=bool(booleans["aria_expanded"]),
        aria_haspopup=bool(booleans["aria_haspopup"]),
        sensitive_form=bool(booleans["sensitive_form"]),
        download=bool(booleans["download"]),
        scripted_handler=bool(booleans["scripted_handler"]),
        submitter=bool(booleans["submitter"]),
    )


def _classify(control: _NormalizedControl) -> Tuple[str, str, str, Tuple[str, ...]]:
    blockers = {"passive_catalog_only"}
    if control.disabled:
        blockers.add("control_disabled")
    if control.locator_truncated:
        blockers.add("locator_truncated")
    if control.scripted_handler:
        blockers.add("script_effect_unproven")
    if control.destination in {"external_origin", "non_http", "invalid"}:
        blockers.add("destination_not_admitted")
        return (
            "navigate",
            "externally_consequential",
            "external_navigation",
            tuple(sorted(blockers)),
        )
    if control.download:
        blockers.add("download_not_admitted")
        return (
            "navigate",
            "externally_consequential",
            "download",
            tuple(sorted(blockers)),
        )
    if control.form_method == "destructive_override":
        blockers.add("destructive_method")
        return (
            "submit_form",
            "destructive",
            "state_mutation",
            tuple(sorted(blockers)),
        )
    if control.sensitive_form or control.input_type in {"file", "password"}:
        blockers.add("sensitive_input")
        return (
            "submit_form" if control.submitter else "unknown",
            "externally_consequential",
            "sensitive_submission",
            tuple(sorted(blockers)),
        )
    if control.submitter or control.form_method in {"get", "post", "unknown"}:
        if (
            control.form_method == "get"
            and control.destination in {"none", "same_origin"}
        ):
            return (
                "filter",
                "read_interaction",
                "navigation",
                tuple(sorted(blockers)),
            )
        blockers.add("form_effect_unproven")
        return (
            "submit_form",
            "state_mutation" if control.form_method == "post" else "unknown",
            "form_submission",
            tuple(sorted(blockers)),
        )
    if control.tag == "a" or control.role == "link":
        if control.destination == "same_origin":
            return (
                "navigate",
                "read_interaction",
                "navigation",
                tuple(sorted(blockers)),
            )
        blockers.add("destination_missing")
        return (
            "navigate",
            "unknown",
            "navigation",
            tuple(sorted(blockers)),
        )
    if (
        control.tag == "summary"
        or control.aria_expanded
        or control.aria_haspopup
        or control.role == "tab"
    ):
        return (
            "reveal",
            "read_interaction",
            "ui_state",
            tuple(sorted(blockers)),
        )
    if control.tag in {"select", "option"} or control.role in {
        "combobox",
        "option",
    }:
        blockers.add("change_effect_unproven")
        return (
            "select",
            "unknown",
            "unknown",
            tuple(sorted(blockers)),
        )
    if control.content_editable or control.tag in {"input", "textarea"}:
        blockers.add("user_input_required")
    return (
        "unknown",
        "unknown",
        "unknown",
        tuple(sorted(blockers)),
    )


class InteractionIntentMiner:
    """Compile already-observed DOM control structures without browser access."""

    def __init__(
        self,
        limits: InteractionIntentLimits = InteractionIntentLimits(),
    ) -> None:
        if not isinstance(limits, InteractionIntentLimits):
            raise TypeError("limits must be InteractionIntentLimits")
        self.limits = limits

    def mine(
        self,
        controls: Sequence[Mapping[str, Any]],
        *,
        target_origin: str,
        world_id: str,
        peer_controls: Sequence[Mapping[str, Any]] = (),
        peer_world_id: str = "peer",
        page_url: Optional[str] = None,
    ) -> InteractionIntentCatalog:
        if isinstance(controls, (str, bytes)) or isinstance(
            peer_controls, (str, bytes)
        ):
            raise TypeError("interaction controls must be sequences")
        if not isinstance(world_id, str) or not world_id:
            raise ValueError("interaction world_id must be non-empty")
        if peer_controls and (
            not isinstance(peer_world_id, str)
            or not peer_world_id
            or peer_world_id == world_id
        ):
            raise ValueError("peer interaction world must be distinct")

        origin = _normalized_origin(target_origin)
        target_ref = stable_hash("interaction_target", origin)
        page_ref = _interaction_page_ref(origin, page_url)
        seen = set()
        intents = []
        counters = {
            "controls_seen": 0,
            "accepted_controls": 0,
            "invalid_controls": 0,
            "hidden_controls": 0,
            "duplicate_controls": 0,
            "dropped_controls": 0,
            "read_interactions": 0,
            "state_mutations": 0,
            "externally_consequential": 0,
            "destructive": 0,
            "unknown": 0,
            "truncated_locators": 0,
        }
        worlds = (
            (world_id, controls),
            (peer_world_id, peer_controls),
        )
        remaining = self.limits.max_total_controls
        for current_world, values in worlds:
            if not values:
                continue
            world_values = values[: self.limits.max_controls_per_world]
            dropped = max(0, len(values) - len(world_values))
            counters["dropped_controls"] += dropped
            for value in world_values:
                if remaining <= 0:
                    counters["dropped_controls"] += 1
                    continue
                remaining -= 1
                counters["controls_seen"] += 1
                if not isinstance(value, Mapping):
                    counters["invalid_controls"] += 1
                    continue
                control = _normalize_control(value, limits=self.limits)
                if control is None:
                    counters["invalid_controls"] += 1
                    continue
                if not control.visible:
                    counters["hidden_controls"] += 1
                    continue
                world_ref = stable_hash("world", current_world)
                locator_payload = [item.to_dict() for item in control.locator]
                locator_ref = stable_hash(
                    "interaction_locator",
                    locator_payload,
                )
                intent_kind, risk_class, side_effect, blockers = _classify(
                    control
                )
                identity = {
                    "target_ref": target_ref,
                    "world_ref": world_ref,
                    "page_ref": page_ref,
                    "locator_ref": locator_ref,
                    "locator_truncated": control.locator_truncated,
                    "tag": control.tag,
                    "role": control.role,
                    "input_type": control.input_type,
                    "intent_kind": intent_kind,
                    "risk_class": risk_class,
                    "expected_side_effect": side_effect,
                    "safety_blockers": list(blockers),
                    "disabled": control.disabled,
                    "scripted_handler": control.scripted_handler,
                }
                intent_id = stable_hash("interaction_intent", identity)
                if intent_id in seen:
                    counters["duplicate_controls"] += 1
                    continue
                seen.add(intent_id)
                intent = InteractionIntent(
                    intent_id=intent_id,
                    target_ref=target_ref,
                    world_ref=world_ref,
                    page_ref=page_ref,
                    locator_ref=locator_ref,
                    locator=control.locator,
                    locator_truncated=control.locator_truncated,
                    tag=control.tag,
                    role=control.role,
                    input_type=control.input_type,
                    intent_kind=intent_kind,
                    risk_class=risk_class,
                    expected_side_effect=side_effect,
                    safety_blockers=blockers,
                    disabled=control.disabled,
                    scripted_handler=control.scripted_handler,
                )
                intents.append(intent)
                counters["accepted_controls"] += 1
                if control.locator_truncated:
                    counters["truncated_locators"] += 1
                counter_name = {
                    "read_interaction": "read_interactions",
                    "state_mutation": "state_mutations",
                    "externally_consequential": "externally_consequential",
                    "destructive": "destructive",
                    "unknown": "unknown",
                }[risk_class]
                counters[counter_name] += 1

        intents.sort(key=lambda item: item.intent_id)
        diagnostics = InteractionIntentDiagnostics(**counters)
        intent_values = tuple(intents)
        intent_digest = stable_hash(
            "interaction_intent_set",
            [item.to_dict() for item in intent_values],
        )
        identity = {
            "mode": INTERACTION_INTENT_MODE,
            "target_ref": target_ref,
            "intent_digest": intent_digest,
            "intent_ids": [item.intent_id for item in intent_values],
            "diagnostics": diagnostics.to_dict(),
        }
        return InteractionIntentCatalog(
            catalog_id=stable_hash("interaction_intent_catalog", identity),
            target_ref=target_ref,
            intent_digest=intent_digest,
            intents=intent_values,
            diagnostics=diagnostics,
            status="ready" if intent_values else "no_interaction_intents",
        )


__all__ = [
    "INTERACTION_INTENT_MODE",
    "InteractionIntent",
    "InteractionIntentCatalog",
    "InteractionIntentDiagnostics",
    "InteractionIntentLimits",
    "InteractionIntentMiner",
    "StructuralLocatorSegment",
]
