"""Secret-safe commitments for credential-bearing HTTP material."""

from __future__ import annotations

import hashlib
import json
from typing import Mapping


CREDENTIAL_HEADER_NAMES = frozenset(
    {
        "authorization",
        "cookie",
        "proxy-authorization",
        "x-api-key",
        "x-auth-token",
        "x-csrf-token",
        "x-session-token",
        "x-xsrf-token",
    }
)


def credential_headers(headers: Mapping[str, str] | None) -> dict[str, str]:
    return {
        str(name).lower(): str(value)
        for name, value in (headers or {}).items()
        if str(name).lower() in CREDENTIAL_HEADER_NAMES
    }


def credential_material_commitment(
    *,
    headers: Mapping[str, str] | None,
    cookies: Mapping[str, str] | None,
) -> str:
    """Commit exact auth material without allowing its values to serialize."""

    material = {
        "headers": sorted(credential_headers(headers).items()),
        "cookies": sorted(
            (str(name), str(value)) for name, value in (cookies or {}).items()
        ),
    }
    encoded = json.dumps(material, separators=(",", ":"), ensure_ascii=False).encode()
    return f"credential_material:{hashlib.sha256(encoded).hexdigest()}"
