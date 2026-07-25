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
from core.wraith.mass_assignment import MassAssignmentFlaw, test_mass_assignment

logger = logging.getLogger(__name__)

# Business-logic / BFLA testing needs a LOW-privilege principal — using an admin
# session would make "a user can edit products" a false positive (admin can).
# `_u(e)` derives a stable, unique username from the (already-unique) probe email
# so register and login agree on identity across differently-shaped APIs.
def _u(email: str) -> str:
    return email.split("@")[0]


_REGISTER_ENDPOINTS = [
    ("/api/Users", lambda e, p: {"email": e, "password": p, "passwordRepeat": p,
                                 "securityQuestion": {"id": 1}, "securityAnswer": "sf"}),
    ("/users/v1/register", lambda e, p: {"username": _u(e), "password": p, "email": e}),
    ("/api/register", lambda e, p: {"email": e, "password": p}),
    ("/api/auth/register", lambda e, p: {"email": e, "username": _u(e), "password": p}),
    ("/api/users", lambda e, p: {"email": e, "username": _u(e), "password": p}),
    ("/register", lambda e, p: {"username": _u(e), "email": e, "password": p}),
    ("/signup", lambda e, p: {"email": e, "username": _u(e), "password": p}),
    ("/auth/register", lambda e, p: {"email": e, "username": _u(e), "password": p}),
]
_LOGIN_ENDPOINTS = [
    ("/rest/user/login", lambda e, p: {"email": e, "password": p}),
    ("/users/v1/login", lambda e, p: {"username": _u(e), "password": p}),
    ("/api/login", lambda e, p: {"email": e, "password": p}),
    ("/api/auth/login", lambda e, p: {"email": e, "username": _u(e), "password": p}),
    ("/login", lambda e, p: {"username": _u(e), "email": e, "password": p}),
    ("/auth/login", lambda e, p: {"username": _u(e), "email": e, "password": p}),
]
# Directory/listing endpoints used to READ BACK a just-created account so a
# mass-assignment claim can be confirmed against what the server actually stored.
_DIRECTORY_ENDPOINTS = [
    "/users/v1/_debug", "/users/v1", "/api/Users", "/api/users", "/users", "/rest/user",
]


def _find_token(obj: Any) -> Optional[str]:
    if isinstance(obj, dict):
        for k, v in obj.items():
            if str(k).lower() in ("token", "accesstoken", "access_token", "auth_token",
                                  "authtoken", "jwt") and isinstance(v, str) and len(v) >= 20:
                return v
            t = _find_token(v)
            if t:
                return t
    elif isinstance(obj, list):
        for x in obj:
            t = _find_token(x)
            if t:
                return t
    return None


async def acquire_low_priv_session(
    origin: str, post: Request,
) -> Optional[Tuple[str, Dict[str, Any]]]:
    """Register a fresh account and log in → (bearer token, context).

    `post(method, url, body)` must be UNAUTHENTICATED. Returns (token, context)
    where context seeds known ids (e.g. basket id) for reference resolution.
    Best-effort; None if no register/login pair works.
    """
    import os as _os
    email = f"sf_probe_{_os.urandom(4).hex()}@example.test"
    password = "Sf!Probe_9183"
    register = None  # (path, maker) of the endpoint that worked — reused for mass-assignment
    for path, mk in _REGISTER_ENDPOINTS:
        try:
            st, _ = await post("POST", origin + path, mk(email, password))
        except Exception:
            continue
        if 200 <= st < 300:
            register = (path, mk)
            break
    if register is None:
        return None
    for path, mk in _LOGIN_ENDPOINTS:
        try:
            st, resp = await post("POST", origin + path, mk(email, password))
        except Exception:
            continue
        if 200 <= st < 300:
            token = _find_token(resp)
            if token:
                # Capture session-scoped ids (basket id) for ref resolution, plus the
                # working register AND login shapes so mass-assignment and the kill-
                # chain composer can mint further principals (e.g. an escalated one).
                ctx: Dict[str, Any] = {"_register": register, "_login": (path, mk)}
                auth = resp.get("authentication") if isinstance(resp, dict) else None
                if isinstance(auth, dict) and auth.get("bid") is not None:
                    ctx["BasketId"] = auth["bid"]
                return token, ctx
    return None


async def register_and_login(
    origin: str,
    post: Request,
    register: Tuple[str, Any],
    login: Tuple[str, Any],
    *,
    extra_fields: Optional[Dict[str, Any]] = None,
) -> Optional[Tuple[str, Dict[str, Any]]]:
    """Mint one principal with a KNOWN register/login shape, optionally injecting
    extra registration fields (e.g. {"role": "admin"} to forge an escalated account
    via a confirmed mass-assignment vector). Returns (token, identity) where identity
    carries the email/username used (so a caller can reference the new account, e.g.
    as a deletion victim). Best-effort; None on any failure."""
    import os as _os
    rpath, rmk = register
    lpath, lmk = login
    email = f"sf_kc_{_os.urandom(5).hex()}@example.test"
    password = "Sf!Probe_9183"
    body = dict(rmk(email, password))
    if extra_fields:
        body.update(extra_fields)
    try:
        st, _ = await post("POST", origin + rpath, body)
    except Exception:
        return None
    if not (200 <= int(st) < 300):
        return None
    try:
        st, resp = await post("POST", origin + lpath, lmk(email, password))
    except Exception:
        return None
    if not (200 <= int(st) < 300):
        return None
    token = _find_token(resp)
    if not token:
        return None
    return token, {"email": email, "username": _u(email), "password": password}


def _records(resp: Any) -> List[Dict[str, Any]]:
    """Extract a list of object records from a listing response of any common shape
    ({data|users|items|results: [...]}, a bare list, or a single object)."""
    if isinstance(resp, dict):
        for key in ("data", "users", "items", "results", "records"):
            v = resp.get(key)
            if isinstance(v, list):
                return [x for x in v if isinstance(x, dict)]
        # a dict of dicts, or a single record
        if any(isinstance(v, dict) for v in resp.values()):
            return [v for v in resp.values() if isinstance(v, dict)] or [resp]
        return [resp]
    if isinstance(resp, list):
        return [x for x in resp if isinstance(x, dict)]
    return []


async def probe_registration_mass_assignment(
    origin: str,
    request: Request,
    register: Tuple[str, Any],
    *,
    max_fields: int = 14,
) -> List[Dict[str, Any]]:
    """Test the registration endpoint for mass-assignment of privilege fields.

    `register` is the (path, maker) pair `acquire_low_priv_session` proved works.
    Each probe registers a fresh account; confirmation reads the account back from
    a directory/listing endpoint and checks the injected field against a baseline.
    Best-effort; never raises.
    """
    import os as _os
    path, maker = register
    url = origin + path
    password = "Sf!Probe_9183"

    def make_body() -> Dict[str, Any]:
        email = f"sf_ma_{_os.urandom(5).hex()}@example.test"
        return dict(maker(email, password))

    # Match a stored record to a probe ONLY by identity (username/email), never by
    # shared values like the constant probe password — every probe account uses
    # the same password, so matching on it would return the wrong (baseline) row
    # and silently defeat the differential.
    _ID_KEYS = ("username", "email", "user", "login", "handle", "name")

    def _hints(body: Dict[str, Any]) -> set:
        out = set()
        for k, v in body.items():
            kl = str(k).lower()
            if "pass" in kl or not isinstance(v, str) or len(v) < 3:
                continue
            if any(idk in kl for idk in _ID_KEYS):
                out.add(v)
                out.add(v.split("@")[0])
        return out

    async def read_back(body: Dict[str, Any], _resp: Any) -> Optional[Dict[str, Any]]:
        hints = _hints(body)
        if not hints:
            return None
        for dpath in _DIRECTORY_ENDPOINTS:
            try:
                st, listing = await request("GET", origin + dpath, None)
            except Exception:
                continue
            if not (200 <= int(st) < 300):
                continue
            for rec in _records(listing):
                for k, v in rec.items():
                    if "pass" in str(k).lower() or not isinstance(v, str):
                        continue
                    if v in hints:
                        return rec
        return None

    try:
        flaws: List[MassAssignmentFlaw] = await test_mass_assignment(
            "POST", url, make_body, request, read_back, max_fields=max_fields,
        )
    except Exception as e:
        logger.debug("[logic_probe] registration mass-assignment failed on %s: %s", path, e)
        return []
    for f in flaws:
        logger.info("[logic_probe] mass-assignment on %s: %s=%r", path, f.field, f.injected)
    return [f.to_finding() for f in flaws]

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

        # Clean up the throwaway probe object — leave no footprint on the target
        # (we only ever create + mutate objects WE made, never existing ones).
        try:
            await request("DELETE", f"{origin}{path}/{oid}", None)
        except Exception:
            pass

    return findings
