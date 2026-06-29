"""
core/wraith/logic_probe.py

Autonomous business-logic probing: drive logic_flaws against a live target.

The invariant engine (logic_flaws) needs a write endpoint + one legitimate
request to mutate. Producing that autonomously is the work this module does:

  1. For each discovered write collection (/api/X), learn the object schema —
     from an existing instance (GET) or, failing that, the JS.
  2. Resolve the schema's foreign-key references (ProductId → an id from
     /api/Products, BasketId → the session's basket, …) so we can build a VALID
     creation request.
  3. Create an object we OWN (POST), then run invariant violations on its
     PUT/PATCH and confirm via the honesty gate.

Everything is authenticated with a capability the caller already acquired and is
scope-gated + bounded. Best-effort, never raises.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from core.wraith.logic_flaws import test_invariants

logger = logging.getLogger(__name__)

# request(method, path_or_url, json_body|None) -> (status, parsed_json)
Request = Callable[[str, str, Optional[Dict[str, Any]]], Awaitable[Tuple[int, Any]]]

_SKIP_FIELDS = {"id", "createdat", "updatedat", "deletedat", "created_at", "updated_at"}
_ID_REF_RE = re.compile(r"^(.*?)(id)$", re.IGNORECASE)  # ProductId -> Product


def _items(resp: Any) -> List[Dict[str, Any]]:
    if isinstance(resp, dict):
        d = resp.get("data")
        if isinstance(d, list):
            return [x for x in d if isinstance(x, dict)]
        if isinstance(d, dict):
            return [d]
    if isinstance(resp, list):
        return [x for x in resp if isinstance(x, dict)]
    return []


def _obj_id(resp: Any) -> Optional[Any]:
    items = _items(resp)
    if items and "id" in items[0]:
        return items[0]["id"]
    if isinstance(resp, dict) and "id" in resp:
        return resp["id"]
    return None


async def _resolve_reference(
    origin: str, request: Request, field: str, context: Dict[str, Any]
) -> Optional[Any]:
    """Resolve a foreign-key field (e.g. ProductId) to a real id."""
    if field in context:
        return context[field]
    m = _ID_REF_RE.match(field)
    if not m or not m.group(1):
        return None
    noun = m.group(1).rstrip("_")
    # Try the referenced collection, a few plural/case variants.
    for coll in (f"/api/{noun}s", f"/api/{noun}", f"/api/{noun.capitalize()}s",
                 f"/rest/{noun.lower()}s"):
        try:
            st, resp = await request("GET", origin + coll, None)
        except Exception:
            continue
        if 200 <= st < 300:
            rid = _obj_id(resp)
            if rid is not None:
                return rid
    return None


async def _build_create_body(
    origin: str, request: Request, schema: Dict[str, Any], context: Dict[str, Any]
) -> Optional[Dict[str, Any]]:
    """Build a VALID creation body from a learned object schema."""
    body: Dict[str, Any] = {}
    for k, v in schema.items():
        if str(k).lower() in _SKIP_FIELDS:
            continue
        if _ID_REF_RE.match(k) and str(k).lower() != "id":
            ref = await _resolve_reference(origin, request, k, context)
            if ref is None:
                return None  # can't satisfy a required reference → give up on this collection
            body[k] = ref
        elif isinstance(v, bool):
            body[k] = v
        elif isinstance(v, (int, float)):
            body[k] = 1
        elif isinstance(v, str):
            body[k] = "sf-probe"
        # nested/None fields left out
    return body or None


async def probe_business_logic(
    target: str,
    request: Request,
    collections: List[str],
    *,
    context: Optional[Dict[str, Any]] = None,
    max_collections: int = 8,
) -> List[Dict[str, Any]]:
    """Autonomously test discovered write collections for invariant violations.

    `collections` are paths like '/api/BasketItems'. Returns finding dicts. The
    caller supplies an authenticated `request` and may seed `context` with known
    ids (e.g. the session's basket id). Best-effort; never raises.
    """
    parsed = urlparse(target if "://" in target else "http://" + target)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    context = dict(context or {})
    findings: List[Dict[str, Any]] = []
    seen: set = set()

    for coll in collections[:max_collections]:
        path = coll if coll.startswith("/") else "/" + coll
        if path in seen:
            continue
        seen.add(path)

        # 1. Learn the object schema from an existing instance.
        try:
            st, listing = await request("GET", origin + path, None)
        except Exception:
            continue
        items = _items(listing) if 200 <= st < 300 else []
        if not items:
            continue
        schema = items[0]

        # 2. Build a valid creation body (resolving references) and create one.
        body = await _build_create_body(origin, request, schema, context)
        if not body:
            continue
        try:
            st, created = await request("POST", origin + path, body)
        except Exception:
            continue
        if not (200 <= st < 300):
            continue
        oid = _obj_id(created) or _obj_id({"data": created})
        if oid is None:
            continue

        # 3. Run invariant violations on the object's update endpoint.
        sample = {k: v for k, v in body.items()}
        try:
            flaws = await test_invariants("PUT", f"{origin}{path}/{oid}", sample, request)
        except Exception as e:
            logger.debug("[logic_probe] invariant test failed on %s: %s", path, e)
            continue
        for f in flaws:
            findings.append(f.to_finding())
            logger.info("[logic_probe] business-logic flaw on %s: %s", path, f.field)

    return findings
