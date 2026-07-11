"""Deterministic redaction and structural fingerprinting for HTTP exchanges."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Dict, Iterable, Mapping, Optional, Tuple
from urllib.parse import parse_qsl, unquote, urlsplit

from .models import NormalizedExchange

MAX_SHAPE_DEPTH = 7
MAX_OBJECT_FIELDS = 64
MAX_ARRAY_VARIANTS = 8

_UUID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
_LONG_NUMBER = re.compile(r"^\d{4,}$")
_OPAQUE_ID = re.compile(r"^[A-Za-z0-9_-]{16,128}$")
_HEX_ID = re.compile(r"^[0-9a-f]{16,128}$", re.IGNORECASE)
_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def stable_hash(kind: str, value: Any) -> str:
    digest = hashlib.sha256(_canonical(value).encode("utf-8", errors="replace")).hexdigest()
    return f"{kind}:{digest}"


def _body_hash(body: Any) -> Optional[str]:
    if body is None or body == "":
        return None
    if isinstance(body, (dict, list, tuple, bool, int, float)):
        payload = _canonical(body)
    elif isinstance(body, bytes):
        payload = body.decode("utf-8", errors="replace")
    else:
        payload = str(body)
    return "sha256:" + hashlib.sha256(payload.encode("utf-8", errors="replace")).hexdigest()


def _media_type(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    return str(value).split(";", 1)[0].strip().lower() or None


def _header_names(headers: Any) -> Tuple[str, ...]:
    if isinstance(headers, Mapping):
        names: Iterable[Any] = headers.keys()
    elif isinstance(headers, list):
        names = [item.get("name") or item.get("key") for item in headers if isinstance(item, Mapping)]
    else:
        names = ()
    return tuple(sorted({str(name).strip().lower() for name in names if name}))


def _looks_dynamic(value: str) -> bool:
    return bool(
        _UUID.fullmatch(value)
        or _LONG_NUMBER.fullmatch(value)
        or _HEX_ID.fullmatch(value)
        or _OPAQUE_ID.fullmatch(value)
        or _EMAIL.fullmatch(value)
    )


def _safe_field_name(value: Any) -> str:
    text = str(value)
    if len(text) > 80 or _looks_dynamic(text):
        return "{dynamic_key}"
    return text


def _string_format(value: str) -> str:
    if _UUID.fullmatch(value):
        return "uuid"
    if _EMAIL.fullmatch(value):
        return "email"
    if value.startswith(("http://", "https://")):
        return "url"
    if _HEX_ID.fullmatch(value) or _OPAQUE_ID.fullmatch(value):
        return "opaque"
    if _LONG_NUMBER.fullmatch(value):
        return "numeric_id"
    return "text"


def _shape(value: Any, *, depth: int = 0) -> Dict[str, Any]:
    if depth >= MAX_SHAPE_DEPTH:
        return {"kind": "depth_limit"}
    if value is None:
        return {"kind": "null"}
    if isinstance(value, bool):
        return {"kind": "boolean"}
    if isinstance(value, int) and not isinstance(value, bool):
        return {"kind": "integer"}
    if isinstance(value, float):
        return {"kind": "number"}
    if isinstance(value, str):
        return {"kind": "string", "format": _string_format(value)}
    if isinstance(value, Mapping):
        items = sorted(((_safe_field_name(k), v) for k, v in value.items()), key=lambda item: item[0])
        fields = {
            key: _shape(child, depth=depth + 1)
            for key, child in items[:MAX_OBJECT_FIELDS]
        }
        result: Dict[str, Any] = {"kind": "object", "fields": fields}
        if len(items) > MAX_OBJECT_FIELDS:
            result["truncated_fields"] = True
        return result
    if isinstance(value, (list, tuple)):
        variants: Dict[str, Dict[str, Any]] = {}
        for child in value:
            child_shape = _shape(child, depth=depth + 1)
            variants.setdefault(_canonical(child_shape), child_shape)
            if len(variants) >= MAX_ARRAY_VARIANTS:
                break
        return {
            "kind": "array",
            "item_variants": [variants[key] for key in sorted(variants)],
            "empty": len(value) == 0,
        }
    if isinstance(value, bytes):
        return {"kind": "binary"}
    return {"kind": type(value).__name__.lower()}


def _parse_body(body: Any, content_type: Optional[str]) -> Any:
    if body is None or body == "":
        return None
    if not isinstance(body, str):
        return body
    stripped = body.lstrip()
    media = _media_type(content_type)
    if media == "application/json" or media == "application/graphql+json" or stripped.startswith(("{", "[")):
        try:
            return json.loads(body)
        except (TypeError, ValueError):
            return body
    if media == "application/x-www-form-urlencoded":
        return {key: value for key, value in parse_qsl(body, keep_blank_values=True)}
    return body


def body_shape(body: Any, content_type: Optional[str]) -> Dict[str, Any]:
    if body in (None, ""):
        return {"kind": "none"}
    return _shape(_parse_body(body, content_type))


def _origin(parts) -> str:
    scheme = (parts.scheme or "http").lower()
    host = (parts.hostname or "").lower()
    if not host:
        return "relative"
    port = parts.port
    default = (scheme == "http" and port in (None, 80)) or (scheme == "https" and port in (None, 443))
    return f"{scheme}://{host}" if default else f"{scheme}://{host}:{port}"


def _path_template(path: str) -> str:
    decoded = unquote(path or "/")
    segments = decoded.split("/")
    normalized = ["{id}" if _looks_dynamic(segment) else segment for segment in segments]
    result = "/".join(normalized)
    return result if result.startswith("/") else "/" + result


def _cookie_names(cookies: Any) -> Tuple[str, ...]:
    if not isinstance(cookies, Mapping):
        return ()
    return tuple(sorted({str(name) for name in cookies if name}))


def normalize_exchange(
    record: Mapping[str, Any],
    *,
    source_id: Optional[str] = None,
    world_id: str = "anonymous",
) -> NormalizedExchange:
    """Normalize a FlowStep-like mapping without retaining any raw values."""
    raw_url = str(record.get("url") or "/")
    parts = urlsplit(raw_url)
    request_headers = record.get("headers") or record.get("request_headers") or {}
    response_headers = record.get("response_headers") or {}
    request_content_type = _media_type(
        record.get("request_content_type")
        or (request_headers.get("content-type") if isinstance(request_headers, Mapping) else None)
    )
    response_content_type = _media_type(
        record.get("response_content_type")
        or (response_headers.get("content-type") if isinstance(response_headers, Mapping) else None)
    )
    request_body = record.get("request_body")
    response_body = record.get("response_body")
    query_keys = tuple(sorted({_safe_field_name(key) for key, _ in parse_qsl(
        parts.query, keep_blank_values=True
    )}))

    method = str(record.get("method") or "GET").upper()
    origin = _origin(parts)
    path_template = _path_template(parts.path)
    request_header_names = _header_names(request_headers)
    response_header_names = _header_names(response_headers)
    request_shape = body_shape(request_body, request_content_type)
    response_status = int(record.get("response_status") or record.get("status") or 0)
    response_shape = body_shape(response_body, response_content_type)
    cookie_names = _cookie_names(record.get("cookies_after_step"))
    response_truncated = bool(record.get("response_body_truncated", False))

    action_descriptor: Dict[str, Any] = {
        "method": method,
        "origin": origin,
        "path_template": path_template,
        "query_keys": list(query_keys),
        "request_header_names": list(request_header_names),
        "request_content_type": request_content_type,
        "request_shape": request_shape,
    }
    state_descriptor: Dict[str, Any] = {
        "status": response_status,
        "response_header_names": list(response_header_names),
        "response_content_type": response_content_type,
        "response_shape": response_shape,
        "cookie_names": list(cookie_names),
        "response_truncated": response_truncated,
    }

    raw_source_id = source_id or record.get("id") or {
        "action": action_descriptor, "state": state_descriptor,
    }
    safe_source_id = stable_hash("source_ref", raw_source_id)
    safe_world_id = stable_hash("world", str(world_id or "anonymous"))

    return NormalizedExchange(
        source_id=safe_source_id,
        world_id=safe_world_id,
        action_id=stable_hash("action", action_descriptor),
        state_id=stable_hash("state", state_descriptor),
        method=method,
        origin=origin,
        path_template=path_template,
        query_keys=query_keys,
        request_header_names=request_header_names,
        response_header_names=response_header_names,
        request_content_type=request_content_type,
        response_content_type=response_content_type,
        request_shape=request_shape,
        response_status=response_status,
        response_shape=response_shape,
        cookie_names=cookie_names,
        request_body_hash=_body_hash(_parse_body(request_body, request_content_type)),
        response_body_hash=_body_hash(_parse_body(response_body, response_content_type)),
        request_truncated=bool(record.get("request_body_truncated", False)),
        response_truncated=response_truncated,
    )
