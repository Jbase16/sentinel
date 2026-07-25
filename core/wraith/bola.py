"""
core/wraith/bola.py

Broken Object-Level Authorization (BOLA / IDOR) — OWASP API #1, the undefended
frontier and the single largest real-world API bounty category.

A BOLA flaw is a well-formed, authenticated request for someone else's object:
`GET /basket/8` when basket 8 isn't yours. There is no payload — which is why WAFs
and signature scanners are blind to it, and why single-session IDOR scanners drown
in false positives: a 200 doesn't prove you read private data, it might be your own
object, an empty list, or a filtered view.

This engine confirms BOLA the only honest way — with TWO distinct principals:

  - Principal A owns an object that carries an A-PRIVATE marker: a value B could
    NOT have supplied itself (a planted secret nonce, or A's own user id) and that
    is therefore proof of a genuine cross-boundary read.
  - Principal B — a different low-priv account — requests A's object.

It is a confirmed BOLA only when B's response is 2xx AND carries A's private
marker. The reference id is excluded by construction (the caller must never pass a
marker B already knows, e.g. the object id in B's own URL). A bare 200, or a 200
whose body lacks A's marker, is NOT reported.

`as_attacker` is injectable. Real exploitation — callers MUST gate it (active
mode, scope, authorized target).
"""

from __future__ import annotations

import json as _json
import logging
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# (method, url, json_body) -> (status, response_json). Async; injectable for tests.
Send = Callable[[str, str, Optional[Dict[str, Any]]], Awaitable[Tuple[int, Any]]]


@dataclass
class OwnedObject:
    """An object owned by the victim principal A, plus the A-private markers whose
    appearance in a *different* principal's response proves a cross-boundary read."""
    ref: str                       # absolute URL of A's object
    markers: List[str]             # A-private strings B could not have supplied
    label: str = ""                # human description, e.g. "victim's basket"
    methods: Tuple[str, ...] = ("GET",)


@dataclass
class BolaFinding:
    object_ref: str
    method: str
    leaked: List[str]
    evidence: str
    victim: str = ""
    severity: str = "HIGH"

    def to_finding(self) -> Dict[str, Any]:
        return {
            "type": "Broken Object-Level Authorization (BOLA/IDOR, active verification)",
            "severity": self.severity,
            "tool": "bola",
            "target": self.object_ref,
            "message": (f"Cross-principal access confirmed: a second low-priv account "
                        f"retrieved another user's object via {self.method} {self.object_ref}; "
                        f"the response carried the victim's private data ({', '.join(self.leaked)})."),
            "tags": ["verified", "bola", "idor", "authorization", "broken_access_control"],
            "families": ["confirmed_vuln"],
            "metadata": {"vuln_class": "bola", "object_ref": self.object_ref,
                         "method": self.method, "leaked_markers": self.leaked,
                         "victim": self.victim, "evidence": self.evidence,
                         "intended_invariant": "A user may access only objects they own.",
                         "observed_violation": (f"a second account retrieved another user's object "
                                                f"and the response carried the owner's private data "
                                                f"({', '.join(self.leaked)})")},
        }


def _stringify(resp: Any) -> str:
    if isinstance(resp, str):
        return resp
    try:
        return _json.dumps(resp, default=str)
    except Exception:
        return str(resp)


def _contains(body: str, marker: str) -> bool:
    """Whitespace-insensitive substring test so JSON spacing (`"UserId": 42` vs
    `"UserId":42`) doesn't cause a confirmed leak to be missed."""
    return marker.replace(" ", "") in body.replace(" ", "")


async def test_bola(
    owned: List[OwnedObject],
    as_attacker: Send,
    *,
    max_objects: int = 32,
) -> List[BolaFinding]:
    """Attacker B attempts each of victim A's objects.

    Confirmed only when B gets 2xx AND an A-private marker appears in B's response.
    Best-effort; never raises.
    """
    findings: List[BolaFinding] = []
    for obj in owned[:max_objects]:
        markers = [m for m in obj.markers if m]
        if not markers:
            continue
        for method in obj.methods:
            try:
                status, resp = await as_attacker(method, obj.ref, None)
            except Exception:
                continue
            if not (200 <= int(status) < 300):
                continue
            body = _stringify(resp)
            leaked = [m for m in markers if _contains(body, m)]
            if leaked:
                findings.append(BolaFinding(
                    object_ref=obj.ref, method=method, leaked=leaked, victim=obj.label,
                    evidence=f"HTTP {status}; attacker response carried victim marker(s): {leaked}",
                ))
                logger.info("[bola] CONFIRMED cross-principal access: %s %s leaked %s",
                            method, obj.ref, leaked)
                break  # one confirmation per object is enough
    return findings
