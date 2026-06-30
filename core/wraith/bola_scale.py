"""
core/wraith/bola_scale.py

Object-graph BOLA at scale — horizontal id enumeration.

One-object BOLA (core.wraith.bola) proves a single cross-boundary read with a
planted marker. This proves the SYSTEMIC version: a low-priv principal walks an
object id space and reads a whole population's private objects.

Confirmation is an OWNERSHIP DIFFERENTIAL at scale. For each id the attacker can
read, the object's owner field (UserId / ownerId / email / …) is collected. A
finding requires the attacker to have read objects belonging to at least
`min_owners` DISTINCT owners. The attacker is a single identity, so ≥3 distinct
owners means ≥2 are provably not the attacker — systemic exposure, not a fluke,
and not the attacker's own data. Objects with no owner field (public catalog data)
contribute nothing, so public endpoints can't false-positive.

`send` is injectable. Real exploitation — callers MUST gate it (active mode,
scope, authorized target).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Optional, Tuple

logger = logging.getLogger(__name__)

Send = Callable[[str, str, Optional[Dict[str, Any]]], Awaitable[Tuple[int, Any]]]

# Owner-semantic field names (case-insensitive). A varying owner value across ids
# is what separates user-scoped private data from shared/public data.
_OWNER_KEYS = ("userid", "user_id", "ownerid", "owner_id", "owner", "useremail",
               "user_email", "email", "createdby", "created_by", "author",
               "accountid", "account_id")
# Endpoints whose objects are typically sensitive enough to rate CRITICAL.
_SENSITIVE = ("card", "wallet", "payment", "address", "order", "ssn", "passport")


@dataclass
class ScaleBolaFinding:
    endpoint: str            # by-id template, e.g. /rest/basket/{id}
    method: str
    accessed: int            # # of cross-principal objects read
    distinct_owners: int
    sample_owners: List[str]
    owner_field: str
    id_range: str
    severity: str = "HIGH"

    def to_finding(self) -> Dict[str, Any]:
        return {
            "type": "Horizontal BOLA at scale (object-graph enumeration)",
            "severity": self.severity,
            "tool": "bola_scale",
            "target": self.endpoint,
            "message": (f"A single low-priv principal enumerated {self.accessed} private object(s) "
                        f"across {self.distinct_owners} distinct owners via {self.method} {self.endpoint} "
                        f"(owner field '{self.owner_field}', ids {self.id_range}). Systemic broken "
                        f"object-level authorization — the whole population's data is reachable."),
            "tags": ["verified", "bola", "idor", "bola_at_scale", "broken_access_control", "mass_data_exposure"],
            "families": ["confirmed_vuln"],
            "metadata": {"vuln_class": "bola", "subtype": "horizontal_enumeration",
                         "endpoint": self.endpoint, "accessed": self.accessed,
                         "distinct_owners": self.distinct_owners,
                         "sample_owners": self.sample_owners, "owner_field": self.owner_field,
                         "id_range": self.id_range},
        }


def _first_object(resp: Any) -> Any:
    """A by-id GET usually returns the object under `data`, or bare."""
    if isinstance(resp, dict):
        d = resp.get("data")
        if isinstance(d, dict):
            return d
        if isinstance(d, list) and d and isinstance(d[0], dict):
            return d[0]
        return resp
    if isinstance(resp, list) and resp and isinstance(resp[0], dict):
        return resp[0]
    return resp


def _extract_owner(obj: Any) -> Optional[Tuple[str, str]]:
    """Return (owner_field, owner_value) for the first owner-semantic field found,
    descending one level into a nested owner object (e.g. {"User": {"id": 5}})."""
    if not isinstance(obj, dict):
        return None
    lowered = {str(k).lower(): k for k in obj}
    for key in _OWNER_KEYS:
        if key in lowered:
            v = obj[lowered[key]]
            if isinstance(v, (str, int)) and not isinstance(v, bool):
                return lowered[key], str(v)
            if isinstance(v, dict):
                for idk in ("id", "userId", "email", "username"):
                    if idk in v and isinstance(v[idk], (str, int)):
                        return f"{lowered[key]}.{idk}", str(v[idk])
    return None


async def sweep_object_ids(
    method: str,
    template: str,
    send: Send,
    *,
    own_identity: set,
    ids: Iterable[int],
    min_owners: int = 3,
    max_requests: int = 20,
) -> Optional[ScaleBolaFinding]:
    """Walk `template` (containing '{id}') across `ids` as the attacker; confirm
    systemic BOLA when objects from >= min_owners distinct (non-attacker) owners are
    read. Best-effort; never raises."""
    owners: Dict[str, int] = {}
    accessed = 0
    field_used: Optional[str] = None
    id_list = list(ids)[:max_requests]
    for i in id_list:
        url = template.replace("{id}", str(i))
        try:
            st, resp = await send(method, url, None)
        except Exception:
            continue
        if not (200 <= int(st) < 300):
            continue
        owner = _extract_owner(_first_object(resp))
        if not owner:
            continue
        key, val = owner
        if val in own_identity:
            continue                       # the attacker's own object — never counts
        owners[val] = owners.get(val, 0) + 1
        accessed += 1
        field_used = field_used or key
    if len(owners) >= min_owners:
        sev = "CRITICAL" if (len(owners) >= 10 or any(s in template.lower() for s in _SENSITIVE)) else "HIGH"
        rng = f"{id_list[0]}..{id_list[-1]}" if id_list else "?"
        logger.info("[bola_scale] CONFIRMED systemic BOLA: %s — %d objects across %d owners",
                    template, accessed, len(owners))
        return ScaleBolaFinding(
            endpoint=template, method=method, accessed=accessed,
            distinct_owners=len(owners), sample_owners=list(owners)[:8],
            owner_field=field_used or "?", id_range=rng, severity=sev,
        )
    return None
