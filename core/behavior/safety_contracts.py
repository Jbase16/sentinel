"""Shared structural safety predicates for captured behavioral operations."""

from __future__ import annotations

import copy
import json
import re
from typing import Any, Mapping

_CLEANUP_FIELDS = frozenset({"active", "archived", "is_archived", "state", "status"})
_CLEANUP_VALUES = frozenset(
    {"archive", "archived", "inactive", "removed", "test_complete"}
)
_CONSEQUENTIAL_CREATE_FIELDS = frozenset(
    {
        "admin",
        "amount",
        "callback",
        "destination",
        "email",
        "is_admin",
        "is_staff",
        "is_superuser",
        "message",
        "payment",
        "permissions",
        "phone",
        "privilege",
        "recipient",
        "role",
        "roles",
        "scope",
        "scopes",
        "tenant",
        "tenant_id",
        "to",
        "transfer",
        "url",
        "webhook",
    }
)
_ABSOLUTE_URL = re.compile(r"https?://", re.IGNORECASE)


def classification_body(body: Any) -> Any:
    """Return a detached structured body when JSON parsing is unambiguous."""

    if isinstance(body, (Mapping, list)):
        return copy.deepcopy(body)
    if not isinstance(body, str):
        return body
    stripped = body.lstrip()
    if not stripped.startswith(("{", "[")):
        return body
    try:
        return json.loads(body)
    except (TypeError, ValueError):
        return body


def is_proven_safe_cleanup_body(body: Any) -> bool:
    """Accept only narrow archival/deactivation state transitions."""

    parsed = classification_body(body)
    if not isinstance(parsed, Mapping) or not parsed:
        return False
    keys = {str(key).lower() for key in parsed}
    if not keys <= _CLEANUP_FIELDS:
        return False
    for key, value in parsed.items():
        normalized_key = str(key).lower()
        if normalized_key in {"active", "archived", "is_archived"}:
            if not isinstance(value, bool):
                return False
            if normalized_key == "active" and value is not False:
                return False
            if normalized_key in {"archived", "is_archived"} and value is not True:
                return False
        elif str(value).strip().lower() not in _CLEANUP_VALUES:
            return False
    return True


def is_proven_safe_owned_create_body(body: Any) -> bool:
    """Reject unstructured or consequential create payloads for manifest v1."""

    if body is None:
        return True
    parsed = classification_body(body)
    if not isinstance(parsed, (Mapping, list)):
        return False

    def safe(value: Any) -> bool:
        if isinstance(value, Mapping):
            for key, child in value.items():
                if str(key).strip().lower() in _CONSEQUENTIAL_CREATE_FIELDS:
                    return False
                if not safe(child):
                    return False
            return True
        if isinstance(value, list):
            return all(safe(item) for item in value)
        return not (isinstance(value, str) and _ABSOLUTE_URL.search(value))

    return safe(parsed)


__all__ = [
    "classification_body",
    "is_proven_safe_cleanup_body",
    "is_proven_safe_owned_create_body",
]
