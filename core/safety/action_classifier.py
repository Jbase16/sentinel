"""
core/safety/action_classifier.py

Classify a candidate HTTP action by its real-world RISK before it is executed.

The rule the whole safety layer turns on: classification FAILS CLOSED and beats
the caller's opinion of itself. If a module hints `SAFE_READ` but the method is
`DELETE`, the action is `DESTRUCTIVE` — danger overrides intent. Anything the
classifier cannot place lands in `UNKNOWN`, which bounty-safe mode denies.

Structural danger (destructive method, financial/messaging write, external side
effect) is decided from the request itself and cannot be overridden by a hint.
Only once an action is proven non-dangerous does a caller-supplied hint (e.g.
`CROSS_OBJECT_READ`, which a bare GET can't reveal on its own) take effect.
"""

from __future__ import annotations

import re
from typing import Any, Optional
from urllib.parse import urlparse

# --- Action classes (string constants; travel cleanly into finding metadata) ---
SAFE_READ = "SAFE_READ"
OWNED_CREATE = "OWNED_CREATE"
OWNED_UPDATE_LOW_RISK = "OWNED_UPDATE_LOW_RISK"
AUTHZ_PROBE = "AUTHZ_PROBE"
PRIVILEGE_MUTATION = "PRIVILEGE_MUTATION"
CROSS_OBJECT_READ = "CROSS_OBJECT_READ"
DESTRUCTIVE = "DESTRUCTIVE"
FINANCIAL = "FINANCIAL"
MESSAGING = "MESSAGING"
EXTERNAL_SIDE_EFFECT = "EXTERNAL_SIDE_EFFECT"
UNKNOWN = "UNKNOWN"

ALL = {SAFE_READ, OWNED_CREATE, OWNED_UPDATE_LOW_RISK, AUTHZ_PROBE, PRIVILEGE_MUTATION,
       CROSS_OBJECT_READ, DESTRUCTIVE, FINANCIAL, MESSAGING, EXTERNAL_SIDE_EFFECT, UNKNOWN}

_WRITE = {"POST", "PUT", "PATCH"}
# Keyed on the URL path for WRITE methods only — GET /invoices/123 is a read, not
# a financial action; only POST/PUT/PATCH to these is a money-moving side effect.
_FINANCIAL_KW = ("payment", "/pay", "refund", "charge", "checkout", "purchase",
                 "transfer", "withdraw", "deposit", "payout", "billing", "subscribe",
                 "subscription", "order/", "orders", "wallet/", "topup", "invoice/pay")
_MESSAGING_KW = ("email", "/mail", "sms", "invite", "notify", "notification",
                 "message", "/send", "contact", "push")
_EXTERNAL_KW = ("webhook", "callback", "integration", "connect/")
_PROFILE_KW = ("/me", "/users/me", "/profile", "/account", "/user/me", "/whoami", "/self")
_PRIV_FIELDS = {"role", "roles", "admin", "isadmin", "is_admin", "privilege",
                "privileges", "permissions", "scope", "scopes", "tenant", "tenant_id",
                "is_staff", "isstaff", "superuser", "is_superuser", "verified",
                "isverified", "approved", "plan", "tier", "assigned_tenants"}
_URL_RE = re.compile(r"https?://", re.IGNORECASE)


def _path(url: str) -> str:
    if not url:
        return ""
    try:
        return (urlparse(url).path if "://" in url else url).lower()
    except Exception:
        return str(url).lower()


def _has_kw(path: str, kws) -> bool:
    return any(k in path for k in kws)


def _body_keys(body: Any) -> set:
    return {str(k).lower() for k in body} if isinstance(body, dict) else set()


def _external_side_effect(path: str, body: Any) -> bool:
    if _has_kw(path, _EXTERNAL_KW):
        return True
    # A request body that carries an absolute URL usually means "call out to here".
    for v in (body.values() if isinstance(body, dict) else []):
        if isinstance(v, str) and _URL_RE.search(v):
            return True
    return False


def classify(method: str, url: str, body: Any = None, *, hint: Optional[str] = None) -> str:
    """Return the risk class of a candidate action. Fails closed; danger wins."""
    m = (method or "GET").upper()
    path = _path(url)
    is_write = m in _WRITE

    # 1. Structural danger — cannot be overridden by a hint.
    if m == "DELETE":
        return DESTRUCTIVE
    if is_write and _has_kw(path, _FINANCIAL_KW):
        return FINANCIAL
    if is_write and _has_kw(path, _MESSAGING_KW):
        return MESSAGING
    if is_write and _external_side_effect(path, body):
        return EXTERNAL_SIDE_EFFECT

    # 2. Trust an explicit, valid hint now that danger is ruled out (lets a caller
    #    declare a GET is actually a cross-object read, which the request can't show).
    if hint in ALL and hint not in (DESTRUCTIVE, FINANCIAL, MESSAGING, EXTERNAL_SIDE_EFFECT):
        return hint

    # 3. Structural heuristics.
    if m == "GET":
        return SAFE_READ
    if is_write and _has_kw(path, _PROFILE_KW) and (_body_keys(body) & _PRIV_FIELDS):
        return PRIVILEGE_MUTATION
    if m == "POST":
        return OWNED_CREATE
    if m in ("PUT", "PATCH"):
        # A write that sets a privilege field anywhere is a privilege mutation.
        if _body_keys(body) & _PRIV_FIELDS:
            return PRIVILEGE_MUTATION
        return OWNED_UPDATE_LOW_RISK
    return UNKNOWN
