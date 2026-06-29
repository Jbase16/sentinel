"""
core/wraith/logic_flaws.py

Business-logic / server-trust invariant testing — the UNDEFENDED class.

WAFs, signatures, and token allowlists all key off a payload or a known pattern.
Business-logic flaws have neither: the request is a well-formed, authenticated,
WAF-clean message whose ONLY fault is that it violates an invariant the server
should have enforced but instead TRUSTED from the client. Nothing for a defense
to match — which is exactly why these survive modern targets and why signature
scanners (and most autonomous tools) can't find them.

This is not a fixed checklist. Given a write endpoint and one legitimate request,
it INFERS each field's invariant from the field's shape/name and tests the trust
boundary:

  - quantity-like numbers  → must be a positive integer  (test: negative, 0, fractional)
  - money-like numbers     → server-derived, not client-set (test: tiny/negative value)
  - privilege flags        → client must not set them      (test: role=admin, isAdmin=true)

CONFIRMATION (honesty gate): a flaw is only reported when the server both ACCEPTS
the tampered request (2xx) AND PERSISTS the violating value (it's reflected back).
A bare 200 isn't enough — the invariant must actually be broken server-side. That
keeps false positives near zero.

`send` is injectable for tests. Real exploitation — callers MUST gate it (active
mode, scope, authorized target).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Field-name semantics. Substrings, matched case-insensitively.
_QUANTITY_NAMES = ("quantity", "qty", "count", "units", "stock", "numberof", "num_")
_MONEY_NAMES = ("price", "cost", "total", "subtotal", "discount", "balance",
                "amount", "fee", "credit", "wallet", "refund")
_FLAG_NAMES = ("isadmin", "is_admin", "admin", "role", "status", "verified",
               "approved", "ispaid", "is_paid", "active", "premium", "deluxe",
               "isvip", "privilege")

# (method, url, json_body) -> (status, response_json). Async; injectable for tests.
Send = Callable[[str, str, Dict[str, Any]], Awaitable[Tuple[int, Any]]]


@dataclass
class InvariantProbe:
    field: str
    value: Any
    invariant: str        # human-readable invariant being violated
    klass: str            # quantity | money | privilege


@dataclass
class LogicFlaw:
    field: str
    invariant: str
    violation: Any
    method: str
    url: str
    evidence: str
    severity: str = "HIGH"

    def to_finding(self) -> Dict[str, Any]:
        return {
            "type": "Business Logic Flaw (active verification)",
            "severity": self.severity,
            "tool": "logic_flaws",
            "target": self.url,
            "message": (f"Server trusts client-controlled '{self.field}': {self.invariant}. "
                        f"Accepted+persisted {self.field}={self.violation!r} via {self.method} {self.url}."),
            "tags": ["verified", "business_logic", "broken_invariant", self.field],
            "families": ["confirmed_vuln"],
            "metadata": {"vuln_class": "business_logic", "field": self.field,
                         "invariant": self.invariant, "violation": self.violation,
                         "evidence": self.evidence},
        }


def infer_probes(body: Dict[str, Any]) -> List[InvariantProbe]:
    """Infer per-field invariant violations to try, from one sample request."""
    probes: List[InvariantProbe] = []
    if not isinstance(body, dict):
        return probes
    for k, v in body.items():
        kl = str(k).lower()
        is_num = isinstance(v, (int, float)) and not isinstance(v, bool)
        # Each field gets ONE class, most-specific first: a numeric "deluxePrice"
        # is money, not a privilege flag, even though it contains "deluxe".
        if is_num and any(n in kl for n in _QUANTITY_NAMES):
            probes.append(InvariantProbe(k, -999, f"'{k}' must be a positive quantity", "quantity"))
            probes.append(InvariantProbe(k, 0, f"'{k}' must be >= 1", "quantity"))
        elif is_num and any(n in kl for n in _MONEY_NAMES):
            probes.append(InvariantProbe(k, -1, f"'{k}' (money) must not be negative / client-set", "money"))
            probes.append(InvariantProbe(k, 0.01, f"'{k}' (money) should be server-derived, not client-set", "money"))
        elif any(n in kl for n in _FLAG_NAMES):
            val = "admin" if ("role" in kl or "privilege" in kl) else True
            probes.append(InvariantProbe(k, val, f"'{k}' is a privileged flag the client must not set", "privilege"))
    return probes


def _value_persisted(resp: Any, field_name: str, value: Any) -> bool:
    """Did the server store the violating value? (reflected anywhere in the response.)"""
    def walk(o: Any) -> bool:
        if isinstance(o, dict):
            for k, v in o.items():
                if str(k).lower() == field_name.lower() and _eq(v, value):
                    return True
                if walk(v):
                    return True
        elif isinstance(o, list):
            return any(walk(x) for x in o)
        return False
    return walk(resp)


def _eq(a: Any, b: Any) -> bool:
    if isinstance(a, bool) or isinstance(b, bool):
        return a is b or a == b
    try:
        if isinstance(b, (int, float)) and isinstance(a, (int, float)):
            return float(a) == float(b)
    except Exception:
        pass
    return str(a) == str(b)


async def test_invariants(
    method: str,
    url: str,
    sample_body: Dict[str, Any],
    send: Send,
    *,
    max_probes: int = 12,
) -> List[LogicFlaw]:
    """Probe a write endpoint for trusted-client-invariant violations.

    Reports a flaw only when the server ACCEPTS the tampered request AND PERSISTS
    the violating value. Best-effort; never raises.
    """
    flaws: List[LogicFlaw] = []
    seen_fields: set = set()
    for probe in infer_probes(sample_body)[:max_probes]:
        tampered = dict(sample_body)
        tampered[probe.field] = probe.value
        try:
            status, resp = await send(method, url, tampered)
        except Exception as e:
            logger.debug("[logic_flaws] probe %s errored: %s", probe.field, e)
            continue
        if not (200 <= int(status) < 300):
            continue  # rejected → invariant enforced for this value
        if _value_persisted(resp, probe.field, probe.value):
            key = (probe.field, probe.klass)
            if key in seen_fields:
                continue
            seen_fields.add(key)
            flaws.append(LogicFlaw(
                field=probe.field, invariant=probe.invariant, violation=probe.value,
                method=method, url=url,
                evidence=f"HTTP {status}; server persisted {probe.field}={probe.value!r}",
            ))
            logger.info("[logic_flaws] CONFIRMED %s on %s %s: %s=%r",
                        probe.klass, method, url, probe.field, probe.value)
    return flaws
