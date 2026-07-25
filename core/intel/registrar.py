"""
Auto-registration — create test accounts on targets whose policy
authorizes self-service signup.

This is the only Phase 2 capability that mutates target state. The
cost of getting it wrong (registering on a program that doesn't
authorize it) is a ToS violation, possibly worse. The gating is
deliberately heavy:

  Three gates in series — all must pass before any HTTP POST goes out:

    1. ``allow_auto_register=True`` must be passed by the caller.
       Default is False. CLI surfaces this as ``--allow-auto-register``.
    2. No ``NO_AUTOMATED_SCAN`` restriction of severity "hard" may
       exist. That's an explicit denial.
    3. The policy must contain explicit authorization keywords. Phase
       2D uses a conservative keyword match; future Phase can use the
       LLM for a more nuanced read.

If all three gates pass, the registrar:

    a. Generates cryptographically random credentials.
    b. POSTs to the signup endpoint (from ``scope.signup_endpoint`` or
       a small list of common paths).
    c. If signup returns 2xx, attempts a login to verify the account
       actually works.
    d. Returns a fully-formed ``Persona`` with ``source=AUTO_REGISTERED``
       and ``verified=VERIFIED`` (or FAILED if step c failed).

Credentials format:

  email:    ``{prefix}+{token}@{domain}``     default domain example.com
  password: 32-char ``secrets.token_urlsafe`` — alphanumeric + - and _

Email is intentionally addr-spec safe (RFC 5322), with ``+tag`` style
so a real domain would route them all to the same inbox if the
operator points it somewhere real via ``--email-domain``. Default
``example.com`` is an IANA sinkhole — guaranteed not to deliver to a
real user.
"""
from __future__ import annotations

import logging
import secrets
from dataclasses import dataclass
from typing import List, Optional

from core.intel.program_scope import (
    CredentialSource,
    LoginFlow,
    Persona,
    ProgramScope,
    Restriction,
    RestrictionKind,
    VerificationStatus,
)
from core.intel.verifier import verify

logger = logging.getLogger(__name__)


# Conservative authorization keywords — at least one must appear in the
# policy text (verbatim) for gate 3 to pass. This is intentionally
# strict; the operator can override with ``force=True`` if they've
# manually confirmed the program authorizes signup.
_SIGNUP_AUTHORIZATION_KEYWORDS = (
    "create a test account",
    "create your own account",
    "sign up to test",
    "register a test account",
    "register an account to test",
    "researchers may create",
    "you may create accounts",
    "create accounts for testing",
)

# Common signup paths to probe if ``scope.signup_endpoint`` is not set.
# Tried in order; the first 2xx response wins.
_SIGNUP_PATH_CANDIDATES = (
    "/api/signup",
    "/api/register",
    "/api/v1/signup",
    "/api/v1/register",
    "/signup",
    "/register",
    "/users",  # REST convention
    "/api/users",
)

# How long an account-discovery POST is allowed to take. Generous to
# accommodate slow auth backends.
_SIGNUP_TIMEOUT_SECONDS = 20.0


@dataclass
class RegistrationFlow:
    """Shape of a signup HTTP request — mirrors ``LoginFlow``.

    ``RegistrationFlow`` is separate from ``LoginFlow`` even though they
    have nearly identical fields, because they encode different intents
    (signup vs login) and the operator-facing names should reflect that.
    """
    endpoint: str
    method: str = "POST"
    email_param: str = "email"
    password_param: str = "password"
    content_type: str = "application/json"
    extra_fields: dict[str, str] = None  # additional form fields (name, terms_accepted, etc.)

    def __post_init__(self):
        if self.extra_fields is None:
            self.extra_fields = {}


@dataclass
class RegistrationReport:
    """Outcome of an auto-registration attempt — for the operator-facing
    summary report. Always returned, even on failure, so the operator
    can see exactly why."""
    attempted: bool
    succeeded: bool
    blocked_reason: Optional[str] = None
    endpoint_tried: Optional[str] = None
    persona: Optional[Persona] = None
    raw_quote: Optional[str] = None  # If blocked by policy, the policy quote


async def auto_register(
    scope: ProgramScope,
    *,
    allow_auto_register: bool = False,
    persona_type: str = "user",
    email_prefix: str = "sentinelforge",
    email_domain: str = "example.com",
    registration_flow: Optional[RegistrationFlow] = None,
    http_factory=None,
    force_policy_check: bool = True,
) -> RegistrationReport:
    """Attempt to create a test account on the program's target.

    Returns a ``RegistrationReport`` describing what happened. The new
    ``Persona`` (if created) is on ``report.persona``.

    Args:
        scope: The program scope (post-extraction).
        allow_auto_register: Operator-supplied gate. Default False.
        persona_type: "user" or "admin" — what role to label the new account.
        email_prefix: Username prefix. Final email is
            ``{prefix}-{random8}@{domain}``.
        email_domain: Domain to use for the generated email. Default
            ``example.com`` (IANA sinkhole). Override with a domain you
            actually receive mail on if you need verification emails.
        registration_flow: Custom signup request shape. If None, a
            default JSON-POST shape is used and the endpoint is
            auto-discovered from ``scope.signup_endpoint`` or common paths.
        http_factory: Injectable for testing.
        force_policy_check: If True (default), require explicit
            authorization keywords in the scope. Operators who have
            manually confirmed the program allows signup can set False.
    """
    # ─── Gate 1: operator opt-in ──────────────────────────────────────
    if not allow_auto_register:
        logger.info(
            "[intel.registrar] auto-registration not enabled "
            "(pass --allow-auto-register to opt in)"
        )
        return RegistrationReport(
            attempted=False, succeeded=False,
            blocked_reason="not_authorized_by_operator",
        )

    # ─── Gate 2: no hard NO_AUTOMATED_SCAN restriction ────────────────
    blocking_restriction = _find_blocking_restriction(scope.restrictions)
    if blocking_restriction is not None:
        logger.warning(
            "[intel.registrar] blocked by hard restriction: %s",
            blocking_restriction.description,
        )
        return RegistrationReport(
            attempted=False, succeeded=False,
            blocked_reason="hard_restriction_blocks",
            raw_quote=blocking_restriction.raw_quote,
        )

    # ─── Gate 3: policy text authorizes signup ────────────────────────
    if force_policy_check:
        authorized, matched_phrase = _check_policy_authorization(scope)
        if not authorized:
            logger.warning(
                "[intel.registrar] policy text does not explicitly authorize "
                "self-service signup. Use force_policy_check=False to override."
            )
            return RegistrationReport(
                attempted=False, succeeded=False,
                blocked_reason="no_explicit_authorization",
            )
        logger.info(
            "[intel.registrar] authorization keyword matched: %r", matched_phrase,
        )

    # All gates passed. Build the registration request.
    if registration_flow is None:
        endpoint = scope.signup_endpoint or _SIGNUP_PATH_CANDIDATES[0]
        registration_flow = RegistrationFlow(endpoint=endpoint)

    base_url = _infer_base_url(scope)
    if not base_url:
        return RegistrationReport(
            attempted=False, succeeded=False,
            blocked_reason="could_not_infer_base_url",
        )

    # Generate credentials.
    token = secrets.token_urlsafe(6).lower().replace("-", "").replace("_", "")[:8]
    email = f"{email_prefix}-{token}@{email_domain}"
    password = secrets.token_urlsafe(24)  # 24 bytes → 32 chars

    # Attempt registration.
    url = _resolve_url(base_url, registration_flow.endpoint)
    report = await _perform_registration(
        url=url,
        flow=registration_flow,
        email=email,
        password=password,
        http_factory=http_factory,
    )
    if not report.succeeded:
        return report

    # Registration succeeded. Build the Persona and verify it via login.
    persona = _build_persona(
        scope=scope,
        base_url=base_url,
        persona_type=persona_type,
        email=email,
        password=password,
    )

    # Run the persona through the verifier so login_flow is exercised.
    # If login fails, the persona is still returned (operator may want
    # to investigate manually) but marked FAILED.
    temp_scope = ProgramScope(
        handle=scope.handle,
        platform=scope.platform,
        name=scope.name,
        source_url=scope.source_url,
        fetched_at=scope.fetched_at,
        personas=[persona],
    )
    await verify(temp_scope, http_factory=http_factory)

    report.persona = persona
    return report


# ─────────────────────────── Gate helpers ──────────────────────────

def _find_blocking_restriction(restrictions: List[Restriction]) -> Optional[Restriction]:
    """Return the first hard restriction that should block auto-registration.

    ``NO_AUTOMATED_SCAN`` of severity "hard" is the explicit blocker.
    Other restrictions might be relevant (REGION_RESTRICTED), but
    auto-registration is specifically about *creating* an account —
    only NO_AUTOMATED_SCAN squarely forbids it.
    """
    for r in restrictions:
        if r.kind == RestrictionKind.NO_AUTOMATED_SCAN and r.severity == "hard":
            return r
    return None


def _check_policy_authorization(scope: ProgramScope) -> tuple[bool, Optional[str]]:
    """Return (authorized, matched_phrase).

    Looks for explicit authorization phrases in the policy text. The
    text comes from the restriction ``raw_quote`` and ``description``
    fields, plus the program name.

    This is a *deliberately conservative* check — false negatives
    (saying "not authorized" when the program does authorize) are
    recoverable (operator override with ``force_policy_check=False``).
    False positives (proceeding when the program forbids) are not.
    """
    haystack_parts: List[str] = [scope.name]
    for r in scope.restrictions:
        if r.description:
            haystack_parts.append(r.description)
        if r.raw_quote:
            haystack_parts.append(r.raw_quote)
    haystack = " ".join(haystack_parts).lower()

    for phrase in _SIGNUP_AUTHORIZATION_KEYWORDS:
        if phrase.lower() in haystack:
            return True, phrase
    return False, None


# ─────────────────────────── HTTP helpers ──────────────────────────

def _infer_base_url(scope: ProgramScope) -> str:
    """Derive the base URL to register against.

    Strategy:
      1. First in-scope DOMAIN rule with a real-looking hostname.
      2. First persona's base_url.
      3. Fall back to scope.source_url's netloc.
    """
    for r in scope.scope_rules:
        if not r.in_scope:
            continue
        pattern = r.pattern.strip()
        if not pattern or pattern.startswith("*."):
            continue
        if "://" in pattern:
            return pattern.rstrip("/")
        # Plain hostname.
        return f"https://{pattern}"

    for p in scope.personas:
        if p.base_url:
            return p.base_url.rstrip("/")

    from urllib.parse import urlparse
    try:
        parsed = urlparse(scope.source_url)
        if parsed.scheme and parsed.netloc:
            return f"{parsed.scheme}://{parsed.netloc}"
    except Exception:  # noqa: BLE001
        pass
    return ""


def _resolve_url(base_url: str, endpoint: str) -> str:
    """Combine base_url and endpoint into a fully-qualified URL."""
    if endpoint.startswith(("http://", "https://")):
        return endpoint
    base = base_url.rstrip("/")
    path = endpoint if endpoint.startswith("/") else "/" + endpoint
    return base + path


async def _perform_registration(
    *,
    url: str,
    flow: RegistrationFlow,
    email: str,
    password: str,
    http_factory,
) -> RegistrationReport:
    """Send the signup request. Returns a report; persona is set
    by the caller after building it."""
    if http_factory is None:
        from core.net.http_factory import create_async_client
        http_factory = create_async_client

    payload = {
        flow.email_param: email,
        flow.password_param: password,
        **flow.extra_fields,
    }

    import httpx
    timeout = httpx.Timeout(_SIGNUP_TIMEOUT_SECONDS)
    headers = {"User-Agent": "SentinelForge/Phase2-registrar"}

    try:
        async with http_factory() as client:
            if flow.content_type == "application/json":
                response = await client.request(
                    flow.method, url, json=payload, headers=headers, timeout=timeout,
                )
            else:
                response = await client.request(
                    flow.method, url, data=payload, headers=headers, timeout=timeout,
                )
    except Exception as e:  # noqa: BLE001 - any failure is a soft fail
        logger.warning("[intel.registrar] signup request failed: %s", e)
        return RegistrationReport(
            attempted=True, succeeded=False,
            blocked_reason=f"network_error: {e}",
            endpoint_tried=url,
        )

    if response.status_code >= 400:
        logger.warning(
            "[intel.registrar] signup HTTP %d at %s", response.status_code, url,
        )
        return RegistrationReport(
            attempted=True, succeeded=False,
            blocked_reason=f"http_{response.status_code}",
            endpoint_tried=url,
        )

    logger.info("[intel.registrar] signup HTTP %d at %s — created", response.status_code, url)
    return RegistrationReport(
        attempted=True, succeeded=True,
        endpoint_tried=url,
    )


def _build_persona(
    *,
    scope: ProgramScope,
    base_url: str,
    persona_type: str,
    email: str,
    password: str,
) -> Persona:
    """Construct the Persona for the newly-registered account.

    The ``login_flow`` mirrors what a normal user persona looks like —
    POST JSON to a guessed login endpoint with email + password. If
    the program has an existing persona with a known login_flow, we
    reuse its shape (much more likely to work than guessing).
    """
    existing_user = next(
        (p for p in scope.personas
         if p.persona_type in ("user", "admin") and p.login_flow is not None),
        None,
    )
    if existing_user and existing_user.login_flow:
        login_flow = LoginFlow(
            endpoint=existing_user.login_flow.endpoint,
            method=existing_user.login_flow.method,
            username_param=existing_user.login_flow.username_param,
            password_param=existing_user.login_flow.password_param,
            content_type=existing_user.login_flow.content_type,
            token_extract_path=existing_user.login_flow.token_extract_path,
            cookie_extract_name=existing_user.login_flow.cookie_extract_name,
        )
    else:
        # Best-guess defaults — JSON POST to /api/login with email + password.
        login_flow = LoginFlow(
            endpoint="/api/login",
            method="POST",
            username_param="email",
            password_param="password",
            content_type="application/json",
            token_extract_path="token",
        )

    return Persona(
        name=f"auto-{persona_type}",
        persona_type=persona_type,
        base_url=base_url,
        login_flow=login_flow,
        username=email,
        password=password,
        role_hint=f"auto-registered {persona_type} for differential testing",
        source=CredentialSource.AUTO_REGISTERED,
        verified=VerificationStatus.UNVERIFIED,  # verifier will set this
        confidence=0.8,  # high — we created it ourselves
    )
