"""Registry-authenticated ownership proofs for exact request locations.

This module is a safety primitive, not an execution surface.  It extracts one
object identifier from an exact path, query, JSON, form, or GraphQL-variable
locator and seals the resulting request identity with a session-local registry
key.  The public proof contains only opaque references and cannot authorize or
dispatch a request by itself.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import copy
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping, Optional, Sequence, Tuple
from urllib.parse import (
    parse_qsl,
    quote,
    unquote,
    urlencode,
    urlsplit,
    urlunsplit,
)


LOCATOR_OWNERSHIP_MODE = "locator_ownership_guard_v1"

_HASH_REF = re.compile(r"^[a-z][a-z0-9_]*:[0-9a-f]{64}$")
_METHOD = re.compile(r"^[A-Z]{3,16}$")
_SOURCE_PROOF_REF = re.compile(r"^ownership_experiment_proof:[0-9a-f]{64}$")
_SOURCE_ROLE_REF = re.compile(r"^ownership_experiment_role:[0-9a-f]{64}$")


class LocatorOwnershipDenied(RuntimeError):
    """A locator proof could not be issued from deterministic owned state."""


class OwnedRequestLocatorKind(str, Enum):
    PATH = "path"
    QUERY = "query"
    JSON = "json"
    FORM = "form"
    GRAPHQL_VARIABLE = "graphql_variable"


def _is_hash_ref(value: Any, prefix: Optional[str] = None) -> bool:
    return bool(
        isinstance(value, str)
        and _HASH_REF.fullmatch(value)
        and (prefix is None or value.startswith(f"{prefix}:"))
    )


def _canonical_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise LocatorOwnershipDenied(
            "locator_ownership_material_is_not_deterministic"
        ) from exc


def _content_ref(prefix: str, value: Any) -> str:
    return f"{prefix}:{hashlib.sha256(_canonical_bytes(value)).hexdigest()}"


def _opaque_ref(prefix: str, seal_key: bytes, value: Any) -> str:
    digest = hmac.new(seal_key, _canonical_bytes(value), hashlib.sha256).hexdigest()
    return f"{prefix}:{digest}"


def _normalized_method(value: Any) -> str:
    method = str(value or "").strip().upper()
    if _METHOD.fullmatch(method) is None:
        raise LocatorOwnershipDenied("locator_ownership_method_is_invalid")
    return method


def _normalized_url(value: Any) -> str:
    parsed = urlsplit(str(value or "").strip())
    if (
        parsed.scheme.lower() not in {"http", "https"}
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise LocatorOwnershipDenied("locator_ownership_url_is_invalid")
    return urlunsplit(
        (
            parsed.scheme.lower(),
            parsed.netloc.lower(),
            parsed.path or "/",
            parsed.query,
            "",
        )
    )


def request_origin(url: Any) -> str:
    parsed = urlsplit(_normalized_url(url))
    return f"{parsed.scheme}://{parsed.netloc}"


def _normalized_body(value: Any) -> Any:
    if value is None:
        return {"kind": "none", "value": None}
    if isinstance(value, str):
        return {"kind": "text", "value": value}
    if isinstance(value, (Mapping, list)):
        _canonical_bytes(value)
        return {"kind": "json", "value": value}
    raise LocatorOwnershipDenied("locator_ownership_body_is_not_deterministic")


def request_material_ref(
    seal_key: bytes,
    *,
    method: Any,
    url: Any,
    body: Any,
) -> str:
    return _opaque_ref(
        "owned_request",
        seal_key,
        {
            "method": _normalized_method(method),
            "url": _normalized_url(url),
            "body": _normalized_body(body),
        },
    )


def _decode_pointer(pointer: Any) -> Tuple[str, ...]:
    if (
        not isinstance(pointer, str)
        or not pointer.startswith("/")
        or len(pointer) > 1_024
        or any(ord(character) < 0x20 for character in pointer)
    ):
        raise LocatorOwnershipDenied("locator_ownership_pointer_is_invalid")
    tokens = []
    for raw in pointer[1:].split("/"):
        index = 0
        while index < len(raw):
            if raw[index] == "~" and (
                index + 1 >= len(raw) or raw[index + 1] not in {"0", "1"}
            ):
                raise LocatorOwnershipDenied(
                    "locator_ownership_pointer_escape_is_invalid"
                )
            index += 2 if raw[index] == "~" else 1
        tokens.append(raw.replace("~1", "/").replace("~0", "~"))
    return tuple(tokens)


def _occurrence_index(value: str) -> int:
    try:
        index = int(value)
    except (TypeError, ValueError) as exc:
        raise LocatorOwnershipDenied("locator_ownership_occurrence_is_invalid") from exc
    if index < 0 or str(index) != value:
        raise LocatorOwnershipDenied("locator_ownership_occurrence_is_invalid")
    return index


def _key_occurrence(
    pairs: Sequence[Tuple[str, str]],
    pointer: str,
) -> str:
    tokens = _decode_pointer(pointer)
    if len(tokens) != 2 or not tokens[0]:
        raise LocatorOwnershipDenied("locator_ownership_parameter_pointer_is_invalid")
    key, raw_occurrence = tokens
    desired = _occurrence_index(raw_occurrence)
    matches = [value for current_key, value in pairs if current_key == key]
    if desired >= len(matches):
        raise LocatorOwnershipDenied("locator_ownership_parameter_is_missing")
    return matches[desired]


def _json_body(value: Any) -> Any:
    if isinstance(value, (Mapping, list)):
        return value
    if not isinstance(value, str):
        raise LocatorOwnershipDenied("locator_ownership_json_body_is_invalid")
    stripped = value.lstrip()
    if not stripped.startswith(("{", "[")):
        raise LocatorOwnershipDenied("locator_ownership_json_body_is_invalid")
    try:
        parsed = json.loads(value)
    except (TypeError, ValueError) as exc:
        raise LocatorOwnershipDenied("locator_ownership_json_body_is_invalid") from exc
    if not isinstance(parsed, (Mapping, list)):
        raise LocatorOwnershipDenied("locator_ownership_json_body_is_invalid")
    return parsed


def _json_pointer_value(value: Any, pointer: str) -> Any:
    current = value
    for token in _decode_pointer(pointer):
        if isinstance(current, Mapping):
            if token not in current:
                raise LocatorOwnershipDenied("locator_ownership_json_value_is_missing")
            current = current[token]
            continue
        if isinstance(current, list):
            index = _occurrence_index(token)
            if index >= len(current):
                raise LocatorOwnershipDenied("locator_ownership_json_value_is_missing")
            current = current[index]
            continue
        raise LocatorOwnershipDenied("locator_ownership_json_value_is_missing")
    return current


def _graphql_item(body: Any, pointer: str) -> Optional[Mapping[str, Any]]:
    tokens = _decode_pointer(pointer)
    if not tokens:
        return None
    parsed = _json_body(body)
    item: Any = parsed
    if isinstance(item, list):
        try:
            index = _occurrence_index(tokens[0])
        except LocatorOwnershipDenied:
            return None
        if index >= len(item):
            return None
        item = item[index]
        tokens = tokens[1:]
    if (
        not isinstance(item, Mapping)
        or len(tokens) < 2
        or tokens[0] != "variables"
        or not isinstance(item.get("variables"), Mapping)
    ):
        return None
    return item


def _graphql_protocol_is_proven(url: Any, body: Any, pointer: str) -> bool:
    item = _graphql_item(body, pointer)
    if item is None:
        return False
    path_tail = urlsplit(_normalized_url(url)).path.rstrip("/").rsplit("/", 1)[-1]
    return bool(
        {"query", "operationName", "extensions"} & set(item)
        or path_tail.lower() in {"graphql", "gql"}
    )


def _object_id(value: Any) -> str:
    if value is None or isinstance(value, (bool, Mapping, list, float)):
        raise LocatorOwnershipDenied("locator_ownership_value_is_not_an_object_id")
    if not isinstance(value, (str, int)):
        raise LocatorOwnershipDenied("locator_ownership_value_is_not_an_object_id")
    result = str(value)
    if (
        not result
        or len(result) > 4_096
        or any(ord(character) < 0x20 for character in result)
    ):
        raise LocatorOwnershipDenied("locator_ownership_value_is_not_an_object_id")
    return result


def extract_locator_native_value(
    *,
    kind: OwnedRequestLocatorKind,
    pointer: str,
    url: Any,
    body: Any,
) -> Any:
    """Extract one validated locator value while retaining its JSON scalar type."""

    if not isinstance(kind, OwnedRequestLocatorKind):
        raise LocatorOwnershipDenied("locator_ownership_kind_is_invalid")
    if kind is OwnedRequestLocatorKind.PATH:
        tokens = _decode_pointer(pointer)
        if len(tokens) != 2 or tokens[0] != "segments":
            raise LocatorOwnershipDenied("locator_ownership_path_pointer_is_invalid")
        desired = _occurrence_index(tokens[1])
        segments = [
            unquote(item)
            for item in urlsplit(_normalized_url(url)).path.split("/")
            if item
        ]
        if desired >= len(segments):
            raise LocatorOwnershipDenied("locator_ownership_path_value_is_missing")
        value: Any = segments[desired]
        _object_id(value)
        return value
    if kind is OwnedRequestLocatorKind.QUERY:
        pairs = parse_qsl(
            urlsplit(_normalized_url(url)).query,
            keep_blank_values=True,
        )
        value = _key_occurrence(pairs, pointer)
        _object_id(value)
        return value
    if kind is OwnedRequestLocatorKind.FORM:
        if not isinstance(body, str):
            raise LocatorOwnershipDenied("locator_ownership_form_body_is_invalid")
        value = _key_occurrence(
            parse_qsl(body, keep_blank_values=True),
            pointer,
        )
        _object_id(value)
        return value
    if kind is OwnedRequestLocatorKind.GRAPHQL_VARIABLE:
        if not _graphql_protocol_is_proven(url, body, pointer):
            raise LocatorOwnershipDenied(
                "locator_ownership_graphql_protocol_is_unproven"
            )
        value = _json_pointer_value(_json_body(body), pointer)
        _object_id(value)
        return value
    if kind is OwnedRequestLocatorKind.JSON:
        value = _json_pointer_value(_json_body(body), pointer)
        _object_id(value)
        return value
    raise LocatorOwnershipDenied("locator_ownership_kind_is_invalid")


def extract_locator_value(
    *,
    kind: OwnedRequestLocatorKind,
    pointer: str,
    url: Any,
    body: Any,
) -> str:
    return _object_id(extract_locator_native_value(
        kind=kind,
        pointer=pointer,
        url=url,
        body=body,
    ))


def _replace_parameter_occurrence(
    pairs: Sequence[Tuple[str, str]],
    pointer: str,
    replacement: str,
) -> Tuple[Tuple[str, str], ...]:
    tokens = _decode_pointer(pointer)
    if len(tokens) != 2 or not tokens[0]:
        raise LocatorOwnershipDenied(
            "locator_ownership_parameter_pointer_is_invalid"
        )
    key, raw_occurrence = tokens
    desired = _occurrence_index(raw_occurrence)
    seen = 0
    replaced = False
    output = []
    for current_key, current_value in pairs:
        if current_key == key:
            if seen == desired:
                current_value = replacement
                replaced = True
            seen += 1
        output.append((current_key, current_value))
    if not replaced:
        raise LocatorOwnershipDenied("locator_ownership_parameter_is_missing")
    return tuple(output)


def _replace_json_pointer(value: Any, pointer: str, replacement: Any) -> Any:
    tokens = _decode_pointer(pointer)
    if not tokens:
        raise LocatorOwnershipDenied("locator_ownership_json_pointer_is_invalid")
    current = value
    for token in tokens[:-1]:
        if isinstance(current, Mapping):
            if token not in current:
                raise LocatorOwnershipDenied(
                    "locator_ownership_json_value_is_missing"
                )
            current = current[token]
        elif isinstance(current, list):
            index = _occurrence_index(token)
            if index >= len(current):
                raise LocatorOwnershipDenied(
                    "locator_ownership_json_value_is_missing"
                )
            current = current[index]
        else:
            raise LocatorOwnershipDenied(
                "locator_ownership_json_value_is_missing"
            )
    final = tokens[-1]
    if isinstance(current, dict):
        if final not in current:
            raise LocatorOwnershipDenied(
                "locator_ownership_json_value_is_missing"
            )
        current[final] = copy.deepcopy(replacement)
    elif isinstance(current, list):
        index = _occurrence_index(final)
        if index >= len(current):
            raise LocatorOwnershipDenied(
                "locator_ownership_json_value_is_missing"
            )
        current[index] = copy.deepcopy(replacement)
    else:
        raise LocatorOwnershipDenied("locator_ownership_json_value_is_missing")
    return value


def replace_locator_value(
    *,
    kind: OwnedRequestLocatorKind,
    pointer: str,
    url: Any,
    body: Any,
    expected_value: str,
    replacement_value: Any,
) -> Tuple[str, Any]:
    """Replace one exact locator without granting budget or transport authority."""

    normalized_url = _normalized_url(url)
    if extract_locator_value(
        kind=kind,
        pointer=pointer,
        url=normalized_url,
        body=body,
    ) != expected_value:
        raise LocatorOwnershipDenied("locator_ownership_source_value_changed")
    replacement_text = _object_id(replacement_value)
    if replacement_text == expected_value:
        raise LocatorOwnershipDenied("locator_ownership_replacement_did_not_change")
    parsed = urlsplit(normalized_url)
    output_url = normalized_url
    output_body = copy.deepcopy(body)
    if kind is OwnedRequestLocatorKind.PATH:
        tokens = _decode_pointer(pointer)
        if len(tokens) != 2 or tokens[0] != "segments":
            raise LocatorOwnershipDenied(
                "locator_ownership_path_pointer_is_invalid"
            )
        desired = _occurrence_index(tokens[1])
        segments = parsed.path.split("/")
        populated = [index for index, value in enumerate(segments) if value]
        if desired >= len(populated):
            raise LocatorOwnershipDenied(
                "locator_ownership_path_value_is_missing"
            )
        segments[populated[desired]] = quote(replacement_text, safe="")
        output_url = urlunsplit(parsed._replace(path="/".join(segments)))
    elif kind is OwnedRequestLocatorKind.QUERY:
        pairs = _replace_parameter_occurrence(
            parse_qsl(parsed.query, keep_blank_values=True),
            pointer,
            replacement_text,
        )
        output_url = urlunsplit(parsed._replace(query=urlencode(pairs)))
    elif kind is OwnedRequestLocatorKind.FORM:
        if not isinstance(body, str):
            raise LocatorOwnershipDenied("locator_ownership_form_body_is_invalid")
        pairs = _replace_parameter_occurrence(
            parse_qsl(body, keep_blank_values=True),
            pointer,
            replacement_text,
        )
        output_body = urlencode(pairs)
    elif kind in {
        OwnedRequestLocatorKind.JSON,
        OwnedRequestLocatorKind.GRAPHQL_VARIABLE,
    }:
        was_text = isinstance(body, str)
        value = copy.deepcopy(_json_body(body))
        output = _replace_json_pointer(value, pointer, replacement_value)
        output_body = (
            json.dumps(output, sort_keys=True, separators=(",", ":"))
            if was_text
            else output
        )
    else:
        raise LocatorOwnershipDenied("locator_ownership_kind_is_invalid")
    if extract_locator_value(
        kind=kind,
        pointer=pointer,
        url=output_url,
        body=output_body,
    ) != replacement_text:
        raise LocatorOwnershipDenied("locator_ownership_replacement_failed")
    return output_url, output_body


def _proof_payload(
    *,
    registry_ref: str,
    source_proof_ref: str,
    source_role_binding_ref: str,
    actor_ref: str,
    target_owner_ref: str,
    request_ref: str,
    object_ref: str,
    collection_ref: str,
    locator_kind: OwnedRequestLocatorKind,
    locator_pointer: str,
) -> Mapping[str, Any]:
    return {
        "mode": LOCATOR_OWNERSHIP_MODE,
        "registry_ref": registry_ref,
        "source_proof_ref": source_proof_ref,
        "source_role_binding_ref": source_role_binding_ref,
        "actor_ref": actor_ref,
        "target_owner_ref": target_owner_ref,
        "request_ref": request_ref,
        "object_ref": object_ref,
        "collection_ref": collection_ref,
        "locator_kind": locator_kind.value,
        "locator_pointer": locator_pointer,
        "target_requests_sent": 0,
        "budget_consumed": False,
        "backend_dispatch_authority": False,
        "executable": False,
    }


@dataclass(frozen=True)
class LocatorOwnershipProof:
    proof_ref: str
    registry_ref: str
    source_proof_ref: str
    source_role_binding_ref: str
    actor_ref: str
    target_owner_ref: str
    request_ref: str
    object_ref: str
    collection_ref: str
    locator_kind: OwnedRequestLocatorKind
    locator_pointer: str
    mode: str = LOCATOR_OWNERSHIP_MODE
    target_requests_sent: int = 0
    budget_consumed: bool = False
    backend_dispatch_authority: bool = False
    executable: bool = False
    _seal: str = field(default="", repr=False, compare=False)

    def __post_init__(self) -> None:
        payload = _proof_payload(
            registry_ref=self.registry_ref,
            source_proof_ref=self.source_proof_ref,
            source_role_binding_ref=self.source_role_binding_ref,
            actor_ref=self.actor_ref,
            target_owner_ref=self.target_owner_ref,
            request_ref=self.request_ref,
            object_ref=self.object_ref,
            collection_ref=self.collection_ref,
            locator_kind=self.locator_kind,
            locator_pointer=self.locator_pointer,
        )
        if (
            self.mode != LOCATOR_OWNERSHIP_MODE
            or not _is_hash_ref(self.proof_ref, "locator_ownership_proof")
            or self.proof_ref != _content_ref("locator_ownership_proof", payload)
            or not _is_hash_ref(self.registry_ref, "ownership_registry")
            or _SOURCE_PROOF_REF.fullmatch(self.source_proof_ref) is None
            or _SOURCE_ROLE_REF.fullmatch(self.source_role_binding_ref) is None
            or not _is_hash_ref(self.actor_ref, "owned_actor")
            or not _is_hash_ref(self.target_owner_ref, "owned_target_owner")
            or self.actor_ref == self.target_owner_ref
            or not _is_hash_ref(self.request_ref, "owned_request")
            or not _is_hash_ref(self.object_ref, "owned_object")
            or not _is_hash_ref(self.collection_ref, "owned_collection")
            or not isinstance(self.locator_kind, OwnedRequestLocatorKind)
            or not isinstance(self.locator_pointer, str)
            or not self.locator_pointer.startswith("/")
            or len(self.locator_pointer) > 1_024
            or any(ord(character) < 0x20 for character in self.locator_pointer)
            or not isinstance(self._seal, str)
            or re.fullmatch(r"[0-9a-f]{64}", self._seal) is None
            or self.target_requests_sent != 0
            or self.budget_consumed
            or self.backend_dispatch_authority
            or self.executable
        ):
            raise ValueError("locator ownership proof contract is invalid")

    def to_dict(self) -> Mapping[str, Any]:
        return {
            "schema_version": 1,
            "proof_ref": self.proof_ref,
            **_proof_payload(
                registry_ref=self.registry_ref,
                source_proof_ref=self.source_proof_ref,
                source_role_binding_ref=self.source_role_binding_ref,
                actor_ref=self.actor_ref,
                target_owner_ref=self.target_owner_ref,
                request_ref=self.request_ref,
                object_ref=self.object_ref,
                collection_ref=self.collection_ref,
                locator_kind=self.locator_kind,
                locator_pointer=self.locator_pointer,
            ),
        }


@dataclass(frozen=True)
class LocatorOwnershipVerification:
    verified: bool
    reason: str
    proof_ref: Optional[str] = None
    mode: str = LOCATOR_OWNERSHIP_MODE
    target_requests_sent: int = 0
    budget_consumed: bool = False
    execution_authority: bool = False

    def __post_init__(self) -> None:
        if (
            self.mode != LOCATOR_OWNERSHIP_MODE
            or not isinstance(self.verified, bool)
            or not isinstance(self.reason, str)
            or not self.reason
            or len(self.reason) > 192
            or any(ord(character) < 0x20 for character in self.reason)
            or (
                self.proof_ref is not None
                and not _is_hash_ref(self.proof_ref, "locator_ownership_proof")
            )
            or (self.verified and self.reason != "locator_ownership_verified")
            or self.target_requests_sent != 0
            or self.budget_consumed
            or self.execution_authority
        ):
            raise ValueError("locator ownership verification contract is invalid")

    def to_dict(self) -> Mapping[str, Any]:
        return {
            "schema_version": 1,
            "mode": self.mode,
            "verified": self.verified,
            "reason": self.reason,
            "proof_ref": self.proof_ref,
            "target_requests_sent": self.target_requests_sent,
            "budget_consumed": self.budget_consumed,
            "execution_authority": self.execution_authority,
        }


def proof_material(
    seal_key: bytes,
    *,
    registry_ref: str,
    source_proof_ref: str,
    source_role_binding_ref: str,
    actor_persona_id: str,
    target_owner_persona_id: str,
    method: Any,
    url: Any,
    body: Any,
    object_id: str,
    collection: str,
    locator_kind: OwnedRequestLocatorKind,
    locator_pointer: str,
) -> Tuple[Mapping[str, Any], str]:
    payload = _proof_payload(
        registry_ref=registry_ref,
        source_proof_ref=source_proof_ref,
        source_role_binding_ref=source_role_binding_ref,
        actor_ref=_opaque_ref("owned_actor", seal_key, actor_persona_id),
        target_owner_ref=_opaque_ref(
            "owned_target_owner", seal_key, target_owner_persona_id
        ),
        request_ref=request_material_ref(
            seal_key,
            method=method,
            url=url,
            body=body,
        ),
        object_ref=_opaque_ref("owned_object", seal_key, object_id),
        collection_ref=_opaque_ref("owned_collection", seal_key, collection),
        locator_kind=locator_kind,
        locator_pointer=locator_pointer,
    )
    seal = hmac.new(
        seal_key,
        _canonical_bytes(payload),
        hashlib.sha256,
    ).hexdigest()
    return payload, seal


def build_locator_proof(payload: Mapping[str, Any], seal: str) -> LocatorOwnershipProof:
    kind = OwnedRequestLocatorKind(str(payload["locator_kind"]))
    return LocatorOwnershipProof(
        proof_ref=_content_ref("locator_ownership_proof", payload),
        registry_ref=str(payload["registry_ref"]),
        source_proof_ref=str(payload["source_proof_ref"]),
        source_role_binding_ref=str(payload["source_role_binding_ref"]),
        actor_ref=str(payload["actor_ref"]),
        target_owner_ref=str(payload["target_owner_ref"]),
        request_ref=str(payload["request_ref"]),
        object_ref=str(payload["object_ref"]),
        collection_ref=str(payload["collection_ref"]),
        locator_kind=kind,
        locator_pointer=str(payload["locator_pointer"]),
        _seal=seal,
    )


def seal_matches(seal_key: bytes, proof: LocatorOwnershipProof) -> bool:
    payload = _proof_payload(
        registry_ref=proof.registry_ref,
        source_proof_ref=proof.source_proof_ref,
        source_role_binding_ref=proof.source_role_binding_ref,
        actor_ref=proof.actor_ref,
        target_owner_ref=proof.target_owner_ref,
        request_ref=proof.request_ref,
        object_ref=proof.object_ref,
        collection_ref=proof.collection_ref,
        locator_kind=proof.locator_kind,
        locator_pointer=proof.locator_pointer,
    )
    expected = hmac.new(
        seal_key,
        _canonical_bytes(payload),
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(expected, proof._seal)


__all__ = [
    "LOCATOR_OWNERSHIP_MODE",
    "LocatorOwnershipDenied",
    "LocatorOwnershipProof",
    "LocatorOwnershipVerification",
    "OwnedRequestLocatorKind",
    "extract_locator_native_value",
    "extract_locator_value",
    "replace_locator_value",
]
