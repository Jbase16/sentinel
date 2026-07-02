"""
core/safety/ownership_registry.py

Proof-backed object ownership for the bounty-safe envelope.

The last "trust me bro" hole: the CROSS_OBJECT_READ gate trusted the caller's
`target_is_researcher_owned=True`. A proof module could set that flag on ANY ref.
This registry replaces the assertion with EVIDENCE — an object ref counts as
researcher-owned only if a researcher persona provably CREATED it earlier in this
session, observed at the executor seam from a real 2xx OWNED_CREATE response (not
claimed by a module).

The key is (origin, collection_noun, object_id): the server-assigned id, scoped to
the collection it was created in, so a created invoice's id can't vouch for a same-id
document. Because both owned_proof and minimal_amplification read via an OpenAPI by-id
SIBLING of the create collection (collection + "/{id}"), the read's noun-before-id
equals the create collection's last segment — so the key matches without the executor
needing to know the by-id template in advance. Unknown/mismatched refs fail closed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlparse

Key = Tuple[str, str, str]   # (origin, collection_noun, object_id)


def _origin(url: str) -> str:
    try:
        p = urlparse(url if "://" in url else "http://" + url)
        return f"{p.scheme}://{p.netloc}"
    except Exception:
        return ""


def _segments(url: str) -> list:
    try:
        return [s for s in (urlparse(url).path or "").split("/") if s]
    except Exception:
        return []


def _extract_id(resp: Any) -> Optional[Any]:
    """The server-assigned object id from a create response (dict, list-of-one, or a
    {'data': ...} envelope). Deliberately compact — no wraith dependency."""
    if isinstance(resp, dict):
        for k, v in resp.items():
            if str(k).lower() == "id" and v is not None:
                return v
        inner = resp.get("data")
        if isinstance(inner, (dict, list)):
            return _extract_id(inner)
    elif isinstance(resp, list) and resp:
        return _extract_id(resp[0])
    return None


def _created_key(create_url: str, object_id: Any) -> Optional[Key]:
    segs = _segments(create_url)
    if not segs or object_id is None:
        return None
    return (_origin(create_url), segs[-1].lower(), str(object_id))


def _read_key(read_url: str) -> Optional[Key]:
    segs = _segments(read_url)
    if len(segs) < 2:                       # need at least .../<collection>/<id>
        return None
    return (_origin(read_url), segs[-2].lower(), str(segs[-1]))


@dataclass
class OwnershipRegistry:
    """Session-scoped, in-memory record of objects researcher personas created here.
    Not exported/redacted like the provenance sink — this is an internal authorization
    structure the policy consults; it may hold raw ids."""

    _owned: Dict[Key, Dict[str, Any]] = field(default_factory=dict)

    def register_created(self, create_url: str, response: Any, *,
                         actor_persona: Optional[str] = None) -> Optional[Key]:
        """Record that a researcher persona created an object here, from a 2xx create
        response. Returns the key, or None if no id could be extracted."""
        key = _created_key(create_url, _extract_id(response))
        if key is None:
            return None
        self._owned[key] = {"actor_persona": actor_persona,
                            "collection": key[1], "object_id": key[2]}
        return key

    def is_owned(self, read_url: str) -> bool:
        """True iff the object this read targets was researcher-created in this session."""
        key = _read_key(read_url)
        return key is not None and key in self._owned

    def owner_of(self, read_url: str) -> Optional[str]:
        key = _read_key(read_url)
        entry = self._owned.get(key) if key else None
        return entry.get("actor_persona") if entry else None

    def __len__(self) -> int:
        return len(self._owned)
