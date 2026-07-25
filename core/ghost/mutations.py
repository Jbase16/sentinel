"""
core/ghost/mutations.py — Phase 4-G4: semantic mutation library.

Each Mutation in this module encodes a NAMED VULNERABILITY HYPOTHESIS —
not a byte-level fuzz, but a specific theory about how this class of
request could be broken. The replay engine (G3) takes any subset of
these, applies them to captured flow steps, and shows the operator the
divergence between baseline and mutated replays.

The hypotheses are intentionally interpretable. Operators (and AI
proposers) should be able to read a mutation's name and immediately
know what it tests:

    JWTAlgNone        — CVE-2015-9235 class: unsigned JWT acceptance.
    OAuthStateStrip   — OAuth/OIDC CSRF via missing `state`.
    PrivilegeDowngrade — Mass assignment of role/is_admin in body.
    NegativeQuantity  — Integer invariant violations (qty/price/amount).
    HeaderInject      — Trust-boundary spoofing via X-Forwarded-For et al.
    VerbTampering     — Method-confusion (GET-as-POST, PUT-as-DELETE).
    RaceReplay        — Concurrent N× replay for state-update races.

Each mutation:
  * `label`: short identifier for the diff report.
  * `rationale`: one-sentence "why is this interesting" for the AI.
  * `applies_to(step)`: cheap predicate — does this hypothesis make
    sense for this captured step?
  * `apply(step)`: returns a new FlowStep with the mutation applied.

The PROPOSER (`propose_mutations(flow)`) inspects the whole flow and
emits a list of (step_index, mutation) suggestions — what to try
where. Operators can review + filter before kicking off the replay.
"""
from __future__ import annotations

import base64
import copy
import json
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from core.ghost.flow import FlowStep
from core.ghost.replay import Mutation, _clone_step

logger = logging.getLogger(__name__)


# ─────────────────────── helpers for body manipulation ───────────────────────


def _try_parse_json_body(step: FlowStep) -> Optional[Any]:
    """Try to parse the step's request body as JSON. Returns None if
    not JSON-shaped or unparseable."""
    if not step.request_body:
        return None
    ct = (step.request_content_type or "").lower()
    if "json" not in ct and not step.request_body.lstrip().startswith(("{", "[")):
        return None
    try:
        return json.loads(step.request_body)
    except Exception:
        return None


def _set_json_body(step: FlowStep, parsed: Any) -> None:
    """Serialize parsed JSON back onto step.request_body."""
    step.request_body = json.dumps(parsed, separators=(",", ":"))
    if not step.request_content_type:
        step.request_content_type = "application/json"


def _replace_query_param(url: str, key: str, new_value: Optional[str]) -> str:
    """Return url with `?key=` set to new_value, or removed if None."""
    parsed = urlparse(url)
    q = parse_qs(parsed.query, keep_blank_values=True)
    if new_value is None:
        q.pop(key, None)
    else:
        q[key] = [new_value]
    flat = []
    for k, vs in q.items():
        for v in vs:
            flat.append((k, v))
    return urlunparse(parsed._replace(query=urlencode(flat)))


def _has_query_param(url: str, key: str) -> bool:
    parsed = urlparse(url)
    q = parse_qs(parsed.query, keep_blank_values=True)
    return key in q


# ──────────────────────────── JWT inspection ────────────────────────────


def _split_jwt(token: str) -> Optional[Tuple[str, str, str]]:
    """Split a JWT into (header_b64, payload_b64, signature_b64). Returns
    None if the token doesn't look like a JWT (3 dot-separated b64-ish
    chunks)."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    return (parts[0], parts[1], parts[2])


def _decode_jwt_header(header_b64: str) -> Optional[Dict[str, Any]]:
    """Best-effort decode of a JWT header. Returns None on any failure."""
    try:
        # JWT uses URL-safe base64 without padding.
        padded = header_b64 + "=" * (-len(header_b64) % 4)
        raw = base64.urlsafe_b64decode(padded)
        return json.loads(raw)
    except Exception:
        return None


def _b64url_no_pad(data: bytes) -> str:
    """URL-safe base64 with padding stripped — standard JWT form."""
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


# ──────────────────────────── Mutation classes ────────────────────────────


@dataclass
class JWTAlgNone(Mutation):
    """Replace the JWT in `Authorization: Bearer <jwt>` with one using
    `alg: none` and an empty signature.

    Tests for the CVE-2015-9235 class of vulnerabilities: JWT libraries
    that accept `alg: none` tokens without rejecting them. If the
    application validates the token via a library configured to allow
    `none`, this mutation will be accepted as a valid identity claim —
    a complete auth bypass.

    Strategy: split the existing JWT, replace the header with
    `{"alg": "none", "typ": "JWT"}`, keep the payload, set sig empty.
    """
    label: str = "jwt-alg-none"
    rationale: str = (
        "If the JWT library accepts alg=none, this token passes "
        "verification with no key — complete auth bypass."
    )

    def applies_to(self, step: FlowStep) -> bool:
        auth = step.headers.get("authorization", "")
        if not auth.startswith("Bearer "):
            return False
        token = auth[7:]
        parts = _split_jwt(token)
        if parts is None:
            return False
        # Cheap algo check — only fire if the captured token uses HS/RS.
        header = _decode_jwt_header(parts[0])
        if not isinstance(header, dict):
            return False
        alg = str(header.get("alg", "")).lower()
        return alg in ("hs256", "hs384", "hs512", "rs256", "rs384", "rs512", "es256")

    def apply(self, step: FlowStep) -> FlowStep:
        cloned = _clone_step(step)
        auth = cloned.headers.get("authorization", "")
        token = auth[7:]  # strip "Bearer "
        parts = _split_jwt(token)
        if parts is None:
            return cloned
        _, payload_b64, _ = parts
        new_header = _b64url_no_pad(json.dumps(
            {"alg": "none", "typ": "JWT"}, separators=(",", ":")
        ).encode("ascii"))
        # Empty signature.
        new_token = f"{new_header}.{payload_b64}."
        cloned.headers["authorization"] = f"Bearer {new_token}"
        return cloned


@dataclass
class OAuthStateStrip(Mutation):
    """Remove the `state` query parameter from an OAuth/OIDC step.

    Tests OAuth CSRF: a flow that accepts a callback without verifying
    the `state` parameter allows an attacker to splice their own
    authorization code into the victim's session.
    """
    label: str = "oauth-state-strip"
    rationale: str = (
        "Drop the `state` query param — tests OAuth/OIDC CSRF (CWE-352). "
        "Callbacks that accept missing/empty state are vulnerable to "
        "session-fixation via splicing the attacker's auth code."
    )

    def applies_to(self, step: FlowStep) -> bool:
        return _has_query_param(step.url, "state")

    def apply(self, step: FlowStep) -> FlowStep:
        cloned = _clone_step(step)
        cloned.url = _replace_query_param(cloned.url, "state", None)
        return cloned


@dataclass
class PrivilegeDowngrade(Mutation):
    """Flip role / is_admin / permission fields in the request body.

    Mass-assignment class: APIs that blindly accept role/permission
    fields from the client are vulnerable to privilege escalation. The
    captured flow probably WRITES these from the server; the mutation
    asks "what if I send them from the client?"
    """
    label: str = "privilege-downgrade"
    rationale: str = (
        "Inject is_admin=true / role=admin into the request body. Tests "
        "mass-assignment (CWE-915): APIs that accept role fields from "
        "client-supplied data."
    )
    # Fields we try to set or flip.
    privilege_fields: Tuple[str, ...] = (
        "role", "roles", "is_admin", "isAdmin", "admin",
        "permissions", "scope", "scopes",
    )

    def applies_to(self, step: FlowStep) -> bool:
        # Only applies to bodies we can parse. JSON for now.
        return _try_parse_json_body(step) is not None

    def apply(self, step: FlowStep) -> FlowStep:
        cloned = _clone_step(step)
        parsed = _try_parse_json_body(cloned)
        if not isinstance(parsed, dict):
            return cloned
        # Inject obvious privilege-escalation values.
        parsed = dict(parsed)  # shallow copy
        parsed["is_admin"] = True
        parsed["isAdmin"] = True
        parsed["role"] = "admin"
        _set_json_body(cloned, parsed)
        return cloned


@dataclass
class NegativeQuantity(Mutation):
    """Flip numeric quantity/price/amount fields to a negative value.

    Tests integer-invariant bugs in business logic — "we charge $10 ×
    quantity; if quantity = -1 we owe the user $10." Class of issues:
    CWE-840 (business logic errors).
    """
    label: str = "negative-quantity"
    rationale: str = (
        "Replace numeric quantity/price/amount fields with -1. Tests "
        "CWE-840 business logic invariants — apps that don't bound "
        "numeric inputs may credit the user or skip charging."
    )
    target_fields: Tuple[str, ...] = (
        "quantity", "qty", "amount", "count", "price", "total",
        "balance", "credit", "discount", "fee",
    )

    def applies_to(self, step: FlowStep) -> bool:
        parsed = _try_parse_json_body(step)
        if not isinstance(parsed, dict):
            return False
        # At least one target field present, with a numeric value.
        return any(
            isinstance(parsed.get(f), (int, float)) for f in self.target_fields
        )

    def apply(self, step: FlowStep) -> FlowStep:
        cloned = _clone_step(step)
        parsed = _try_parse_json_body(cloned)
        if not isinstance(parsed, dict):
            return cloned
        parsed = dict(parsed)
        for f in self.target_fields:
            if isinstance(parsed.get(f), (int, float)):
                parsed[f] = -1
        _set_json_body(cloned, parsed)
        return cloned


@dataclass
class HeaderInject(Mutation):
    """Inject trust-boundary spoofing headers (X-Forwarded-For,
    X-Real-IP, X-Original-URL) with localhost values.

    Tests apps that grant elevated trust to requests appearing to
    originate from localhost (admin panels, debug endpoints, internal
    APIs gated by IP rather than auth).
    """
    label: str = "header-inject-localhost"
    rationale: str = (
        "Inject X-Forwarded-For: 127.0.0.1 + X-Real-IP: 127.0.0.1. Tests "
        "CWE-348/693: apps trusting client-supplied origin headers for "
        "internal-network gating."
    )
    headers_to_inject: Dict[str, str] = field(default_factory=lambda: {
        "x-forwarded-for": "127.0.0.1",
        "x-real-ip": "127.0.0.1",
        "x-original-url": "/admin",
        "x-rewrite-url": "/admin",
    })

    def applies_to(self, step: FlowStep) -> bool:
        # Always applies — every HTTP request can carry headers.
        return True

    def apply(self, step: FlowStep) -> FlowStep:
        cloned = _clone_step(step)
        for k, v in self.headers_to_inject.items():
            cloned.headers[k.lower()] = v
        return cloned


@dataclass
class VerbTampering(Mutation):
    """Change the HTTP method (GET → POST, POST → PUT, etc.).

    Tests endpoint-routing bugs where access control is configured for
    one verb but the same handler accepts another. CWE-650.
    """
    label: str = "verb-tamper"
    rationale: str = (
        "Swap HTTP method (GET↔POST, PUT↔PATCH, etc.). Tests CWE-650: "
        "endpoints with method-specific access control that's bypassable "
        "by sending an unexpected verb."
    )
    # Verb-swap matrix: original → mutated.
    swap_table: Dict[str, str] = field(default_factory=lambda: {
        "GET": "POST",
        "POST": "PUT",
        "PUT": "PATCH",
        "PATCH": "POST",
        "DELETE": "POST",
    })

    def applies_to(self, step: FlowStep) -> bool:
        return step.method.upper() in self.swap_table

    def apply(self, step: FlowStep) -> FlowStep:
        cloned = _clone_step(step)
        new_method = self.swap_table.get(cloned.method.upper(), cloned.method)
        cloned.method = new_method
        return cloned


@dataclass
class CSRFTokenStrip(Mutation):
    """Remove CSRF tokens from headers and body.

    Tests endpoints that have CSRF middleware but mis-configure it
    (e.g. only checks header, body still has it). CWE-352.
    """
    label: str = "csrf-token-strip"
    rationale: str = (
        "Strip X-CSRF-Token / X-XSRF-Token headers and csrf_token / "
        "authenticity_token body fields. Tests CWE-352 CSRF gating."
    )

    def applies_to(self, step: FlowStep) -> bool:
        # Applies if any common CSRF token is present.
        has_csrf_header = any(
            k.lower() in ("x-csrf-token", "x-xsrf-token", "csrf-token")
            for k in step.headers
        )
        if has_csrf_header:
            return True
        parsed = _try_parse_json_body(step)
        if isinstance(parsed, dict):
            if any(k in parsed for k in (
                "csrf_token", "csrfToken", "authenticity_token", "_csrf"
            )):
                return True
        return False

    def apply(self, step: FlowStep) -> FlowStep:
        cloned = _clone_step(step)
        for header_name in list(cloned.headers.keys()):
            if header_name.lower() in (
                "x-csrf-token", "x-xsrf-token", "csrf-token"
            ):
                cloned.headers.pop(header_name)
        parsed = _try_parse_json_body(cloned)
        if isinstance(parsed, dict):
            parsed = dict(parsed)
            for field_name in (
                "csrf_token", "csrfToken", "authenticity_token", "_csrf"
            ):
                parsed.pop(field_name, None)
            _set_json_body(cloned, parsed)
        return cloned


# ─────────────────────────── Mutation catalog ───────────────────────────


# The full library — used by the proposer + the API resolver.
ALL_MUTATIONS: List[type] = [
    JWTAlgNone,
    OAuthStateStrip,
    PrivilegeDowngrade,
    NegativeQuantity,
    HeaderInject,
    VerbTampering,
    CSRFTokenStrip,
]


def _mutation_by_label(label: str) -> Optional[Mutation]:
    """Resolve a label to a fresh Mutation instance, or None if unknown."""
    for cls in ALL_MUTATIONS:
        if cls.label == label or (
            hasattr(cls, "__dataclass_fields__")
            and cls().label == label
        ):
            return cls()
    return None


# ─────────────────────────── Proposer ───────────────────────────


@dataclass
class MutationProposal:
    """Suggested mutation: step index + mutation instance + rationale.

    The proposer emits these for the operator to review. Each carries
    enough context for the AI / operator to decide whether to run it."""
    step_index: int
    step_method: str
    step_url: str
    mutation_label: str
    rationale: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "step_index": self.step_index,
            "step_method": self.step_method,
            "step_url": self.step_url,
            "mutation_label": self.mutation_label,
            "rationale": self.rationale,
        }


def propose_mutations(
    flow,  # UserFlow — left untyped to avoid circular imports at type-check time
    catalog: Optional[List[type]] = None,
) -> List[MutationProposal]:
    """Inspect every step of `flow` and return mutation proposals.

    For each step, every mutation class in `catalog` (or ALL_MUTATIONS)
    is instantiated and asked `applies_to(step)`. If yes, a
    MutationProposal is emitted.

    The proposer is deterministic — same flow + same catalog → same
    proposals — so operators can regenerate the list without surprise.
    """
    if catalog is None:
        catalog = ALL_MUTATIONS

    proposals: List[MutationProposal] = []
    for i, step in enumerate(flow.steps):
        for mut_cls in catalog:
            try:
                mut = mut_cls()
            except Exception as e:
                logger.warning(
                    f"[proposer] could not instantiate {mut_cls.__name__}: "
                    f"{type(e).__name__}: {e}"
                )
                continue
            try:
                applicable = mut.applies_to(step)
            except Exception as e:
                logger.warning(
                    f"[proposer] {mut.label} applies_to raised on step {i}: "
                    f"{type(e).__name__}: {e}"
                )
                continue
            if applicable:
                proposals.append(MutationProposal(
                    step_index=i,
                    step_method=step.method,
                    step_url=step.url,
                    mutation_label=mut.label,
                    rationale=mut.rationale,
                ))
    return proposals
