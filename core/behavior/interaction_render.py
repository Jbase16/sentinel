"""Inert observation of one already-acquired interaction response.

The boundary passes the exact authenticated response bytes to the native driver for
DOMParser-based structural inspection. It never navigates, executes target scripts,
loads resources, or sends target traffic. The resulting catalog remains passive and
can only support a separately validated future interaction admission.
"""

from __future__ import annotations

import copy
import hmac
import os
import re
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, Mapping, Optional, Sequence, Tuple
from urllib.parse import urlsplit

from core.foundry.authorization import AuthorizationEnvelope
from core.safety.provenance import body_hash, response_shape

from .interaction_admission import InteractionIntentAdmission
from .interactions import InteractionIntentCatalog, InteractionIntentMiner
from .normalize import normalize_exchange, stable_hash

INTERACTION_RENDER_ENV = "SENTINELFORGE_BEHAVIOR_INTERACTION_RENDER"
INTERACTION_RENDER_MODE = "behavioral_interaction_render_observation_v1"
INTERACTION_RENDER_WORKFLOW = "behavioral_interaction_render_observation"
_TRUE = frozenset({"1", "true", "yes", "on"})
_MAX_RESPONSE_BYTES = 2 * 1024 * 1024
_MAX_SCANNED_NODES = 4096
_RECEIPT_ID = re.compile(r"^behavioral-[0-9a-f]{64}$")
_HASH_REF = re.compile(r"^[a-z][a-z0-9_]*:[0-9a-f]{64}$")

InteractionResponseObserver = Callable[
    ...,
    Awaitable[Mapping[str, Any]],
]


def _hash_ref(value: Any, prefix: str) -> bool:
    return (
        isinstance(value, str)
        and value.startswith(f"{prefix}:")
        and _HASH_REF.fullmatch(value) is not None
    )


def _origin(value: str) -> str:
    parsed = urlsplit(str(value or "").strip())
    try:
        host = (parsed.hostname or "").lower()
        port = parsed.port
    except ValueError as exc:
        raise InteractionRenderDenied("interaction_render_origin_is_invalid") from exc
    scheme = parsed.scheme.lower()
    if (
        scheme not in {"http", "https"}
        or not host
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise InteractionRenderDenied("interaction_render_origin_is_invalid")
    default_port = (scheme == "http" and port in {None, 80}) or (
        scheme == "https" and port in {None, 443}
    )
    return f"{scheme}://{host}" if default_port else f"{scheme}://{host}:{port}"


def _page_ref(url: str) -> str:
    normalized = normalize_exchange({"url": url, "method": "GET"})
    return stable_hash(
        "interaction_page",
        {
            "origin": normalized.origin,
            "path_template": normalized.path_template,
        },
    )


def _url_identity(value: str) -> tuple[str, str, str]:
    parsed = urlsplit(str(value or "").strip())
    return _origin(value), parsed.path or "/", parsed.query


def _verify_authorization(
    envelope: AuthorizationEnvelope,
    *,
    target_origin: str,
) -> None:
    signature = envelope.attestation_signature
    if not signature:
        raise InteractionRenderDenied("interaction_render_authorization_is_unsigned")
    verification = copy.deepcopy(envelope)
    if not hmac.compare_digest(signature, verification.sign()):
        raise InteractionRenderDenied(
            "interaction_render_authorization_signature_mismatch"
        )
    try:
        envelope.authorize_action(
            target_origin=target_origin,
            workflow=INTERACTION_RENDER_WORKFLOW,
        )
    except Exception as exc:
        raise InteractionRenderDenied(
            "interaction_render_authorization_denied"
        ) from exc


class InteractionRenderDenied(RuntimeError):
    """The response binding or inert observation failed closed."""


@dataclass(frozen=True)
class InteractionRenderConfig:
    enabled: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.enabled, bool):
            raise ValueError("interaction render enabled must be a boolean")

    @classmethod
    def from_environment(cls) -> "InteractionRenderConfig":
        return cls(
            enabled=os.environ.get(INTERACTION_RENDER_ENV, "").strip().lower()
            in _TRUE
        )


@dataclass(frozen=True)
class InteractionRenderObservation:
    observation_id: str
    acquisition_id: str
    acquisition_receipt_id: str
    admission_id: str
    obligation_id: str
    target_ref: str
    world_ref: str
    page_ref: str
    response_ref: str
    catalog_id: str
    intent_digest: str
    controls_observed: int
    scanned_nodes: int
    controls_truncated: bool
    bytes_inspected: int
    catalog: InteractionIntentCatalog = field(repr=False, compare=False)
    controls: Tuple[Dict[str, Any], ...] = field(repr=False, compare=False)
    status: str = "completed"
    target_requests_sent: int = 0
    executable: bool = False
    mode: str = INTERACTION_RENDER_MODE

    def __post_init__(self) -> None:
        payload = {
            "acquisition_id": self.acquisition_id,
            "acquisition_receipt_id": self.acquisition_receipt_id,
            "admission_id": self.admission_id,
            "obligation_id": self.obligation_id,
            "target_ref": self.target_ref,
            "world_ref": self.world_ref,
            "page_ref": self.page_ref,
            "response_ref": self.response_ref,
            "catalog_id": self.catalog_id,
            "intent_digest": self.intent_digest,
            "controls_observed": self.controls_observed,
            "scanned_nodes": self.scanned_nodes,
            "controls_truncated": self.controls_truncated,
            "bytes_inspected": self.bytes_inspected,
        }
        if (
            self.observation_id
            != stable_hash("interaction_render_observation", payload)
            or self.mode != INTERACTION_RENDER_MODE
            or self.status != "completed"
            or self.target_requests_sent != 0
            or self.executable
            or not _hash_ref(self.acquisition_id, "interaction_read_acquisition")
            or _RECEIPT_ID.fullmatch(self.acquisition_receipt_id) is None
            or not _hash_ref(self.admission_id, "interaction_intent_admission")
            or not _hash_ref(self.obligation_id, "security_obligation")
            or not _hash_ref(self.target_ref, "interaction_target")
            or not _hash_ref(self.world_ref, "world")
            or not _hash_ref(self.page_ref, "interaction_page")
            or not _hash_ref(
                self.response_ref,
                "interaction_acquisition_response",
            )
            or not _hash_ref(self.catalog_id, "interaction_intent_catalog")
            or not _hash_ref(self.intent_digest, "interaction_intent_set")
            or self.catalog.catalog_id != self.catalog_id
            or self.catalog.intent_digest != self.intent_digest
            or self.catalog.target_ref != self.target_ref
            or len(self.controls) > 256
            or any(not isinstance(item, dict) for item in self.controls)
            or isinstance(self.controls_observed, bool)
            or not isinstance(self.controls_observed, int)
            or not 0 <= self.controls_observed <= 256
            or self.controls_observed != len(self.catalog.intents)
            or isinstance(self.scanned_nodes, bool)
            or not isinstance(self.scanned_nodes, int)
            or not 0 <= self.scanned_nodes <= _MAX_SCANNED_NODES
            or not isinstance(self.controls_truncated, bool)
            or isinstance(self.bytes_inspected, bool)
            or not isinstance(self.bytes_inspected, int)
            or not 0 <= self.bytes_inspected <= _MAX_RESPONSE_BYTES
        ):
            raise ValueError("interaction render observation contract is invalid")

    @property
    def complete(self) -> bool:
        return not self.controls_truncated

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": 1,
            "mode": self.mode,
            "status": self.status,
            "executable": self.executable,
            "target_requests_sent": self.target_requests_sent,
            "observation_id": self.observation_id,
            "acquisition_id": self.acquisition_id,
            "acquisition_receipt_id": self.acquisition_receipt_id,
            "admission_id": self.admission_id,
            "obligation_id": self.obligation_id,
            "target_ref": self.target_ref,
            "world_ref": self.world_ref,
            "page_ref": self.page_ref,
            "response_ref": self.response_ref,
            "catalog_id": self.catalog_id,
            "intent_digest": self.intent_digest,
            "controls_observed": self.controls_observed,
            "scanned_nodes": self.scanned_nodes,
            "controls_truncated": self.controls_truncated,
            "bytes_inspected": self.bytes_inspected,
            "complete": self.complete,
        }


class InteractionRenderObservationBoundary:
    """Validate and inertly inspect one exact acquired response."""

    def __init__(
        self,
        *,
        admission: InteractionIntentAdmission,
        acquisition: Mapping[str, Any],
        acquisition_receipt_id: str,
        record: Mapping[str, Any],
        target_origin: str,
        authorization: AuthorizationEnvelope,
        actor_persona_id: str,
        peer_persona_id: str,
        observer: InteractionResponseObserver,
        config: Optional[InteractionRenderConfig] = None,
    ) -> None:
        if not isinstance(admission, InteractionIntentAdmission):
            raise TypeError("interaction admission is required")
        if not isinstance(acquisition, Mapping):
            raise TypeError("interaction acquisition is required")
        if not isinstance(record, Mapping):
            raise TypeError("interaction acquisition record is required")
        if not isinstance(authorization, AuthorizationEnvelope):
            raise TypeError("authorization envelope is required")
        if (
            not isinstance(actor_persona_id, str)
            or not actor_persona_id
            or not isinstance(peer_persona_id, str)
            or not peer_persona_id
            or actor_persona_id == peer_persona_id
        ):
            raise ValueError("two distinct interaction personas are required")
        if not callable(observer):
            raise TypeError("interaction response observer is required")
        self.admission = admission
        self.acquisition = dict(acquisition)
        self.acquisition_receipt_id = acquisition_receipt_id
        self.record = record
        self.target_origin = _origin(target_origin)
        self.authorization = authorization
        self.actor_persona_id = actor_persona_id
        self.peer_persona_id = peer_persona_id
        self.observer = observer
        self.config = config or InteractionRenderConfig.from_environment()

    def _validated_source(self) -> tuple[str, str]:
        if not self.config.enabled:
            raise InteractionRenderDenied("interaction_render_is_disabled")
        _verify_authorization(
            self.authorization,
            target_origin=self.target_origin,
        )
        if _RECEIPT_ID.fullmatch(self.acquisition_receipt_id) is None:
            raise InteractionRenderDenied(
                "interaction_render_receipt_identity_is_invalid"
            )
        acquisition = self.acquisition
        admission = self.admission
        if (
            acquisition.get("status") != "completed"
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
            or acquisition.get("response_truncated") is not False
        ):
            raise InteractionRenderDenied(
                "interaction_render_acquisition_binding_is_invalid"
            )
        record = self.record
        url = str(record.get("url") or "")
        body = record.get("response_body")
        if isinstance(record.get("response_status"), bool):
            raise InteractionRenderDenied("interaction_render_record_is_invalid")
        try:
            response_status = int(record.get("response_status"))
        except (TypeError, ValueError) as exc:
            raise InteractionRenderDenied(
                "interaction_render_record_is_invalid"
            ) from exc
        if (
            record.get("persona_id") != self.actor_persona_id
            or str(record.get("method") or "").upper() != "GET"
            or _origin(url) != self.target_origin
            or not isinstance(body, str)
            or len(body.encode("utf-8", errors="replace")) > _MAX_RESPONSE_BYTES
            or response_status != acquisition.get("response_status")
            or record.get("response_truncated") is not False
        ):
            raise InteractionRenderDenied("interaction_render_record_is_invalid")
        normalized = normalize_exchange(record, world_id=self.actor_persona_id)
        request_ref = stable_hash(
            "interaction_acquisition_request",
            {
                "method": "GET",
                "url": url,
                "redirect_mode": "manual",
            },
        )
        response_ref = stable_hash(
            "interaction_acquisition_response",
            {
                "request_ref": request_ref,
                "status": response_status,
                "body_hash": body_hash(body),
                "shape": response_shape(body),
                "truncated": False,
            },
        )
        if (
            admission.target_ref
            != stable_hash("interaction_target", self.target_origin)
            or admission.world_ref
            != stable_hash("world", self.actor_persona_id)
            or acquisition.get("request_ref") != request_ref
            or acquisition.get("response_ref") != response_ref
            or acquisition.get("destination_page_ref") != _page_ref(url)
            or acquisition.get("operation_ref") != normalized.action_id
        ):
            raise InteractionRenderDenied(
                "interaction_render_response_binding_changed"
            )
        return url, body

    async def execute(self) -> InteractionRenderObservation:
        url, body = self._validated_source()
        try:
            observed = await self.observer(
                self.actor_persona_id,
                base_url=url,
                html=body,
            )
        except InteractionRenderDenied:
            raise
        except Exception as exc:
            raise InteractionRenderDenied(
                "interaction_render_observer_failed"
            ) from exc
        if not isinstance(observed, Mapping) or set(observed) != {
            "base_url",
            "controls",
            "scanned_nodes",
            "controls_truncated",
            "bytes_inspected",
            "target_requests_sent",
        }:
            raise InteractionRenderDenied(
                "interaction_render_observation_is_invalid"
            )
        controls = observed.get("controls")
        scanned_nodes = observed.get("scanned_nodes")
        controls_truncated = observed.get("controls_truncated")
        bytes_inspected = observed.get("bytes_inspected")
        target_requests_sent = observed.get("target_requests_sent")
        if (
            not isinstance(controls, Sequence)
            or isinstance(controls, (str, bytes))
            or len(controls) > 256
            or any(not isinstance(item, Mapping) for item in controls)
            or isinstance(scanned_nodes, bool)
            or not isinstance(scanned_nodes, int)
            or not 0 <= scanned_nodes <= _MAX_SCANNED_NODES
            or scanned_nodes < len(controls)
            or not isinstance(controls_truncated, bool)
            or isinstance(bytes_inspected, bool)
            or not isinstance(bytes_inspected, int)
            or isinstance(target_requests_sent, bool)
            or not isinstance(target_requests_sent, int)
            or _url_identity(str(observed.get("base_url") or ""))
            != _url_identity(url)
            or target_requests_sent != 0
            or bytes_inspected != len(body.encode("utf-8", errors="replace"))
        ):
            raise InteractionRenderDenied(
                "interaction_render_observation_is_invalid"
            )
        try:
            captured_controls = tuple(
                copy.deepcopy(dict(item)) for item in controls
            )
            catalog = InteractionIntentMiner().mine(
                captured_controls,
                target_origin=self.target_origin,
                world_id=self.actor_persona_id,
                page_url=url,
            )
            if catalog.diagnostics.invalid_controls:
                raise ValueError(
                    "interaction render contained invalid controls"
                )
        except (TypeError, ValueError) as exc:
            raise InteractionRenderDenied(
                "interaction_render_catalog_is_invalid"
            ) from exc
        payload = {
            "acquisition_id": self.acquisition["acquisition_id"],
            "acquisition_receipt_id": self.acquisition_receipt_id,
            "admission_id": self.admission.admission_id,
            "obligation_id": self.admission.obligation_id,
            "target_ref": self.admission.target_ref,
            "world_ref": self.admission.world_ref,
            "page_ref": self.acquisition["destination_page_ref"],
            "response_ref": self.acquisition["response_ref"],
            "catalog_id": catalog.catalog_id,
            "intent_digest": catalog.intent_digest,
            "controls_observed": len(catalog.intents),
            "scanned_nodes": observed["scanned_nodes"],
            "controls_truncated": observed["controls_truncated"],
            "bytes_inspected": observed["bytes_inspected"],
        }
        return InteractionRenderObservation(
            observation_id=stable_hash(
                "interaction_render_observation",
                payload,
            ),
            catalog=catalog,
            controls=captured_controls,
            **payload,
        )


__all__ = [
    "INTERACTION_RENDER_ENV",
    "INTERACTION_RENDER_MODE",
    "INTERACTION_RENDER_WORKFLOW",
    "InteractionRenderConfig",
    "InteractionRenderDenied",
    "InteractionRenderObservation",
    "InteractionRenderObservationBoundary",
]
