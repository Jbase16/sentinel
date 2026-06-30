"""
core/wraith/mass_assignment.py

Mass assignment — the universal undefended class.

A create/register endpoint should DERIVE certain fields server-side: privilege
(admin, role, isVerified) and ownership (userId, ownerId). A mass-assignment flaw
is when the client can SET one of those fields in the request body and the server
TRUSTS it. Like the rest of the business-logic family there is no payload to
match — the request is a well-formed, authenticated message that merely sets a
field it must not be allowed to set — so WAFs and signature scanners are blind to
it. Nearly every API has a registration or object-create path, which is why this
class travels across targets where injection signatures do not.

CONFIRMATION (differential honesty gate): a flaw is reported only when, reading
the created object back, the injected field holds the privileged value AND a
baseline object created WITHOUT the injection does NOT. The differential is the
whole point: a field that DEFAULTS to the privileged value (e.g. `active=true`)
would otherwise look injectable when it isn't. Acceptance (2xx) is never enough —
the server must be shown to have STORED a value it should have controlled itself.

`send` and `read_back` are injectable. Real exploitation — callers MUST gate it
(active mode, scope, authorized target).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# (method, url, json_body) -> (status, response_json). Async; injectable for tests.
Send = Callable[[str, str, Dict[str, Any]], Awaitable[Tuple[int, Any]]]
# (body_used, create_response) -> the stored object (or None if it can't be read).
ReadBack = Callable[[Dict[str, Any], Any], Awaitable[Optional[Dict[str, Any]]]]

# Server-controlled privilege fields a client must never set, with the value that
# would constitute escalation. Ordered most-decisive first. Booleans default false
# on a well-built server, so the differential gate confirms cleanly; ambiguous
# defaults-true fields (active/enabled) are included but the differential drops
# them when they aren't actually injectable.
_PRIVILEGE_FIELDS: List[Tuple[str, Any]] = [
    ("isadmin", True), ("is_admin", True), ("admin", True),
    ("role", "admin"), ("userrole", "admin"), ("user_role", "admin"),
    ("roles", ["admin"]),
    ("isverified", True), ("verified", True),
    ("emailverified", True), ("email_verified", True),
    ("ispaid", True), ("is_paid", True), ("paid", True),
    ("premium", True), ("ispremium", True),
    ("isvip", True), ("vip", True),
    ("approved", True), ("isapproved", True),
    ("active", True), ("isactive", True), ("enabled", True),
]


@dataclass
class MassAssignmentFlaw:
    field: str
    injected: Any
    baseline: Any
    method: str
    url: str
    evidence: str
    klass: str = "privilege"        # privilege | ownership
    severity: str = "HIGH"

    def to_finding(self) -> Dict[str, Any]:
        return {
            "type": "Mass Assignment (active verification)",
            "severity": self.severity,
            "tool": "mass_assignment",
            "target": self.url,
            "message": (f"Client-supplied '{self.field}' is trusted at {self.klass} boundary. "
                        f"{self.method} {self.url} accepted+persisted {self.field}={self.injected!r} "
                        f"(baseline {self.field}={self.baseline!r})."),
            "tags": ["verified", "business_logic", "mass_assignment", self.klass, self.field],
            "families": ["confirmed_vuln"],
            "metadata": {"vuln_class": "mass_assignment", "field": self.field,
                         "klass": self.klass, "injected": self.injected,
                         "baseline": self.baseline, "evidence": self.evidence},
        }


def _eq(a: Any, b: Any) -> bool:
    if isinstance(a, bool) or isinstance(b, bool):
        return a is b or a == b
    if isinstance(a, (list, dict)) or isinstance(b, (list, dict)):
        return a == b
    try:
        if isinstance(a, (int, float)) and isinstance(b, (int, float)):
            return float(a) == float(b)
    except Exception:
        pass
    return str(a) == str(b)


_MISSING = object()


def _read_field(obj: Any, name: str) -> Any:
    """Return the value stored for `name` (case-insensitive), searching nested
    dicts/lists. Returns _MISSING if the field is absent — distinct from a stored
    None, so 'field never existed' and 'field is null' don't get conflated."""
    target = name.lower()
    if isinstance(obj, dict):
        for k, v in obj.items():
            if str(k).lower() == target:
                return v
        for v in obj.values():
            r = _read_field(v, name)
            if r is not _MISSING:
                return r
    elif isinstance(obj, list):
        for x in obj:
            r = _read_field(x, name)
            if r is not _MISSING:
                return r
    return _MISSING


async def _confirm(read_back: ReadBack, body: Dict[str, Any], resp: Any) -> Optional[Dict[str, Any]]:
    try:
        obj = await read_back(body, resp)
    except Exception as e:
        logger.debug("[mass_assignment] read_back errored: %s", e)
        return None
    return obj if isinstance(obj, dict) else None


async def test_mass_assignment(
    create_method: str,
    create_url: str,
    make_body: Callable[[], Dict[str, Any]],
    send: Send,
    read_back: ReadBack,
    *,
    extra_fields: Optional[List[Tuple[str, Any]]] = None,
    max_fields: int = 14,
) -> List[MassAssignmentFlaw]:
    """Test a create/register endpoint for trusted-client privilege/ownership fields.

    `make_body()` must return a FRESH, valid creation body each call (unique
    identity where the endpoint demands one — every probe creates a real object).
    `read_back(body, create_response)` returns the STORED object so the injected
    field can be checked against what the server actually persisted.

    Reports a flaw only when the injected field is read back with the injected
    value AND a baseline object (no injection) does not carry it. Best-effort;
    never raises.
    """
    flaws: List[MassAssignmentFlaw] = []

    # 1. Baseline object — establishes each field's server-default value.
    base_body = make_body()
    try:
        st, base_resp = await send(create_method, create_url, base_body)
    except Exception as e:
        logger.debug("[mass_assignment] baseline create failed: %s", e)
        return flaws
    if not (200 <= int(st) < 300):
        return flaws  # can't even create normally → nothing to test
    base_obj = await _confirm(read_back, base_body, base_resp)
    # Best available view of the baseline object: the authoritative read-back if we
    # have one, else whatever the create response echoed. Used so the differential
    # is enforced even on APIs that only reflect (never separately readable).
    base_repr = base_obj if base_obj is not None else base_resp

    candidates: List[Tuple[str, Any]] = list(extra_fields or []) + _PRIVILEGE_FIELDS
    klass_of = {f for f, _ in (extra_fields or [])}
    seen: set = set()
    for field, priv_value in candidates[:max_fields]:
        if field in seen:
            continue
        seen.add(field)

        base_val = _read_field(base_repr, field)
        # Field already holds the privileged value by default → not injectable.
        if base_val is not _MISSING and _eq(base_val, priv_value):
            continue

        body = make_body()
        body[field] = priv_value
        try:
            st, resp = await send(create_method, create_url, body)
        except Exception:
            continue
        if not (200 <= int(st) < 300):
            continue  # rejected → the field is validated/stripped on this path

        obj = await _confirm(read_back, body, resp)
        # Prefer the authoritative read-back; fall back to reflection in the
        # create response (some APIs echo the created object).
        inj_repr = obj if obj is not None else resp
        val = _read_field(inj_repr, field)
        if val is _MISSING or not _eq(val, priv_value):
            continue
        if base_val is not _MISSING and _eq(val, base_val):
            continue  # no differential → field isn't actually client-controlled

        klass = "ownership" if field in klass_of else "privilege"
        flaw = MassAssignmentFlaw(
            field=field, injected=priv_value,
            baseline=(None if base_val is _MISSING else base_val),
            method=create_method, url=create_url, klass=klass,
            evidence=f"HTTP {st}; baseline {field}={'<absent>' if base_val is _MISSING else base_val!r}, "
                     f"injected {field}={priv_value!r} read back as {val!r}",
        )
        flaws.append(flaw)
        logger.info("[mass_assignment] CONFIRMED %s on %s %s: %s=%r (baseline %r)",
                    klass, create_method, create_url, field, priv_value,
                    None if base_val is _MISSING else base_val)
    return flaws
