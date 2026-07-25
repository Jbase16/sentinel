"""
core/wraith/owned_proof.py

Bounty-safe BOLA: prove a cross-object read with TWO researcher-owned personas and
exactly one object — never by enumerating a population.

    owner B authenticates, accessor A authenticates
    B creates one throwaway object B1 (a safe, non-sensitive type) with a planted
        marker only B could know
    A requests B1 exactly once, declaring it a researcher-owned cross-object read
    if A gets 200 and B's marker is in the response → confirmed BOLA. STOP.

Only *safe* object types are created (documents/notes/projects/tasks/books/…);
anything that smells like money, messaging, credentials, or third-party side
effects (invoices, invites, api-keys, webhooks, exports) is skipped — that is where
bug-bounty dreams become incident reports. Every request is issued through the
policy executor: the create is OWNED_CREATE, the read is a CROSS_OBJECT_READ with
`target_is_researcher_owned=True`, so the policy can actually authorize it (an
undeclared cross-read is refused in bounty mode).
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, List, Optional
from urllib.parse import urlparse

from core.safety.action_classifier import CROSS_OBJECT_READ, OWNED_CREATE
from core.wraith.bola import _stringify
from core.wraith.bola_probe import _build_owned_body, _fill_byid, _mine_openapi

logger = logging.getLogger(__name__)

Send = Callable[..., Awaitable[Any]]   # policy-executor send: (method, url, body, **intent)

# Object nouns we refuse to create/touch even in a "safe" two-persona proof.
_UNSAFE_NOUNS = ("invoice", "billing", "payment", "refund", "charge", "order",
                 "subscription", "checkout", "key", "token", "secret", "credential",
                 "webhook", "callback", "invite", "export", "import", "email",
                 "sms", "message", "notification", "admin", "transfer", "wallet",
                 "payout", "integration")


@dataclass
class OwnedObjectProof:
    owner_persona: str
    accessor_persona: str
    object_type: str
    object_ref: str
    create_endpoint: str
    read_endpoint: str
    ownership_markers: Dict[str, Any] = field(default_factory=dict)
    severity: str = "HIGH"

    def to_finding(self) -> Dict[str, Any]:
        return {
            "type": "Broken Object-Level Authorization (BOLA, two-persona proof)",
            "severity": self.severity,
            "tool": "owned_proof",
            "target": self.object_ref,
            "message": (f"Cross-account read confirmed with researcher-owned test accounts: "
                        f"persona {self.accessor_persona!r} read a {self.object_type} object owned by "
                        f"persona {self.owner_persona!r} ({self.read_endpoint}); the response carried the "
                        f"owner's private marker. One object, one read, then stopped."),
            "tags": ["verified", "bola", "idor", "broken_access_control", "minimal_impact"],
            "families": ["confirmed_vuln"],
            "metadata": {"vuln_class": "bola", "subtype": "two_persona_owned",
                         "owner_persona": self.owner_persona, "accessor_persona": self.accessor_persona,
                         "object_type": self.object_type, "object_ref": self.object_ref,
                         "create_endpoint": self.create_endpoint,
                         "ownership_markers": self.ownership_markers,
                         "intended_invariant": "A user may access only objects they own.",
                         "observed_violation": (f"persona {self.accessor_persona!r} read persona "
                                                f"{self.owner_persona!r}'s {self.object_type} object")},
        }


def with_restraint(finding: Dict[str, Any], *, executors: List[Any],
                   proof_mode: str = "bounty_safe") -> Dict[str, Any]:
    """Attach the restraint block a triager needs to trust a live finding: the
    proof mode, that only owned test accounts were used, the counts, and that we
    stopped after the first proof. `policy_denials` is summed across every executor
    that shared the budget, so a two-persona proof reports both personas' refusals.
    """
    execs = [e for e in executors if e is not None]
    base = execs[0].restraint_summary() if execs else {}
    base["policy_denials"] = sum(len(getattr(e, "skipped", [])) for e in execs)
    base["stopped_after_first_proof"] = True
    meta = finding.setdefault("metadata", {})
    meta["proof_mode"] = proof_mode
    meta["restraint"] = base
    return finding


def _noun(collection: str) -> str:
    """The meaningful object noun, skipping version/prefix segments (v1, api, rest)."""
    segs = [s for s in collection.strip("/").lower().split("/")
            if s and not re.match(r"^v\d+$", s) and s not in ("api", "rest")]
    return segs[-1] if segs else collection.strip("/").lower()


def _is_safe(collection: str) -> bool:
    n = _noun(collection)
    return not any(u in n for u in _UNSAFE_NOUNS)


async def prove_owned_cross_read(
    target: str,
    *,
    owner_send: Send,       # persona B — creates the object
    accessor_send: Send,    # persona A — attempts the cross-read
    owner_persona: str = "B",
    accessor_persona: str = "A",
    max_types: int = 6,
) -> Optional[OwnedObjectProof]:
    """Confirm BOLA with two owned personas and a single object. Best-effort; None
    unless one cross-owned read leaks the owner's planted marker."""
    parsed = urlparse(target if "://" in target else "http://" + target)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    try:
        specs = await _mine_openapi(origin, owner_send)
    except Exception:
        specs = []

    tried = 0
    for spec in specs:
        if tried >= max_types:
            break
        coll, byid = spec["collection"], spec["byid"]
        if not _is_safe(coll):
            continue
        body, markers = _build_owned_body(spec["props"], byid)
        if not markers:
            continue
        tried += 1

        # B creates one throwaway object it owns.
        try:
            st, created = await owner_send("POST", origin + coll, body, hint=OWNED_CREATE)
        except Exception:
            continue
        if not (200 <= int(st) < 300):
            continue
        ref = _fill_byid(origin, byid, body, created)
        if not ref:
            continue

        # A reads it ONCE — declared as a researcher-owned cross-object read so the
        # policy can authorize it; an undeclared cross-read would be refused.
        try:
            st_a, resp_a = await accessor_send(
                "GET", ref, None, hint=CROSS_OBJECT_READ,
                target_is_researcher_owned=True, target_owner=owner_persona,
                actor=accessor_persona, proof_goal="single_cross_owned_object_read")
        except Exception:
            continue
        if 200 <= int(st_a) < 300:
            body_s = _stringify(resp_a)
            leaked = [m for m in markers if m and m in body_s]
            if leaked:
                logger.info("[owned_proof] BOLA confirmed: %s read %s's %s object %s",
                            accessor_persona, owner_persona, _noun(coll), ref)
                return OwnedObjectProof(
                    owner_persona=owner_persona, accessor_persona=accessor_persona,
                    object_type=_noun(coll), object_ref=ref, create_endpoint=coll,
                    read_endpoint=ref, ownership_markers={"planted": leaked})
        # One create, one read per type; move on. No enumeration, no retries.
    return None
