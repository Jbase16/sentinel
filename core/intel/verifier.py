"""
CredentialVerifier — attempts each extracted persona's login and
records whether it actually works.

Why this matters:

  Extraction (LLM or platform-specific) produces candidate credentials.
  Many will be:

    - Stale (rotated since the policy was last updated)
    - Hallucinated (LLM invented something plausible-looking)
    - Behind MFA / CAPTCHA we can't navigate automatically
    - Test-environment-only credentials we can't reach from outside

  Without verification, the downstream scanner would happily fire IDOR
  tests with bad creds and produce zero signal — same shape as the
  Phase 1 bug class where the engine looked broken because the *inputs*
  were bad. Verification surfaces these failures as findings on the
  ``ProgramScope`` itself so the operator sees them before any scan
  burns a target's rate budget.

Behavior:

  ``verify(scope)`` iterates ``scope.personas``. For each persona with
  ``login_flow`` + ``username`` + ``password``, it attempts the login
  and mutates ``persona.verified`` to ``VERIFIED`` or ``FAILED``.
  Anonymous personas (no login_flow) keep their existing status.

  The function returns the same ``ProgramScope`` it was given — the
  contract is "annotate, don't reconstruct."

Success detection — layered:

  1. If ``login_flow.token_extract_path`` is set, check that JSON path
     resolves to a non-empty value in the response body. This is the
     strongest signal — the API returned the auth token we expected.
  2. If ``login_flow.cookie_extract_name`` is set, check that cookie
     was set on the response. Classic session-cookie auth.
  3. Otherwise, a 2xx response code counts as success. The weakest
     signal, but the only one available when the policy didn't tell us
     what success looks like.

  Each path errs on the side of marking ``FAILED`` if anything looks
  off (non-2xx, exception, JSON parse error, missing field). That
  matches the design: false negatives are recoverable (operator can
  override); false positives let bad creds through to the scanner.
"""
from __future__ import annotations

import logging
from typing import Any, Optional

from core.intel.program_scope import (
    LoginFlow,
    Persona,
    ProgramScope,
    VerificationStatus,
)

logger = logging.getLogger(__name__)

# Per-login attempt timeout. Generous enough for slow login flows
# (some auth backends do 1-2s of bcrypt+lookups) but short enough
# that a flaky target doesn't stall the whole verification step.
LOGIN_TIMEOUT_SECONDS = 15.0


async def verify(
    scope: ProgramScope,
    *,
    http_factory=None,
) -> ProgramScope:
    """Attempt each persona's login. Mutates ``scope.personas`` in place.

    ``http_factory`` is injectable for testing — defaults to
    ``core.net.http_factory.create_async_client``.

    Returns the same ``ProgramScope`` for fluent chaining.
    """
    if http_factory is None:
        from core.net.http_factory import create_async_client
        http_factory = create_async_client

    verified_count = 0
    failed_count = 0
    skipped_count = 0

    for persona in scope.personas:
        outcome = await _verify_persona(persona, http_factory=http_factory)
        if outcome == VerificationStatus.VERIFIED:
            verified_count += 1
        elif outcome == VerificationStatus.FAILED:
            failed_count += 1
        else:
            skipped_count += 1
        persona.verified = outcome

    logger.info(
        "[intel.verifier] verified=%d failed=%d skipped=%d (total personas=%d)",
        verified_count, failed_count, skipped_count, len(scope.personas),
    )
    return scope


async def _verify_persona(
    persona: Persona,
    *,
    http_factory,
) -> VerificationStatus:
    """Attempt a single persona's login. Returns the new status.

    Skip rules (returns UNVERIFIED):
      - anonymous personas (by design — nothing to verify)
      - no login_flow defined
      - missing username or password
    """
    if persona.persona_type == "anonymous":
        return VerificationStatus.UNVERIFIED
    if persona.login_flow is None:
        logger.debug("[intel.verifier] %s: no login_flow → UNVERIFIED", persona.name)
        return VerificationStatus.UNVERIFIED
    if not persona.username or not persona.password:
        logger.debug("[intel.verifier] %s: missing username/password → UNVERIFIED", persona.name)
        return VerificationStatus.UNVERIFIED

    try:
        success = await _attempt_login(
            persona=persona,
            login_flow=persona.login_flow,
            http_factory=http_factory,
        )
    except Exception as e:  # noqa: BLE001 - any exception = login failed, not a crash
        logger.warning(
            "[intel.verifier] %s: login attempt raised %s — marking FAILED",
            persona.name, e,
        )
        return VerificationStatus.FAILED

    return VerificationStatus.VERIFIED if success else VerificationStatus.FAILED


async def _attempt_login(
    *,
    persona: Persona,
    login_flow: LoginFlow,
    http_factory,
) -> bool:
    """Build the login request from the login_flow spec and send it.

    Returns True if the login succeeded (per the layered success rules
    documented at the top of this module), False otherwise.
    """
    # Resolve the URL. login_flow.endpoint may be absolute or relative.
    if login_flow.endpoint.startswith(("http://", "https://")):
        url = login_flow.endpoint
    else:
        base = persona.base_url.rstrip("/")
        path = login_flow.endpoint if login_flow.endpoint.startswith("/") \
               else "/" + login_flow.endpoint
        url = base + path

    # Build the payload according to content_type.
    payload_body = {
        login_flow.username_param: persona.username,
        login_flow.password_param: persona.password,
    }
    payload_body.update(login_flow.additional_fields)

    method = login_flow.method.upper()
    headers = {"User-Agent": "SentinelForge/Phase2-verifier"}

    import httpx
    timeout = httpx.Timeout(LOGIN_TIMEOUT_SECONDS)

    async with http_factory() as client:
        if login_flow.content_type == "application/json":
            response = await client.request(
                method, url, json=payload_body, headers=headers, timeout=timeout,
            )
        else:
            # application/x-www-form-urlencoded or anything else: form data.
            response = await client.request(
                method, url, data=payload_body, headers=headers, timeout=timeout,
            )

    return _is_login_successful(response, login_flow)


def _is_login_successful(response, login_flow: LoginFlow) -> bool:
    """Apply the layered success detection rules."""
    # Layer 1: explicit token path in JSON body.
    if login_flow.token_extract_path:
        try:
            body = response.json()
        except Exception:  # noqa: BLE001 - non-JSON body when token expected = failure
            logger.debug(
                "[intel.verifier] expected JSON body for token extraction, "
                "got non-JSON; treating as login failure"
            )
            return False
        value = _extract_json_path(body, login_flow.token_extract_path)
        success = bool(value)
        if not success:
            logger.debug(
                "[intel.verifier] token path %r not found in response — login failed",
                login_flow.token_extract_path,
            )
        return success

    # Layer 2: explicit cookie name.
    if login_flow.cookie_extract_name:
        cookie_value = response.cookies.get(login_flow.cookie_extract_name)
        success = bool(cookie_value)
        if not success:
            logger.debug(
                "[intel.verifier] cookie %r not set on response — login failed",
                login_flow.cookie_extract_name,
            )
        return success

    # Layer 3: 2xx status fallback.
    return 200 <= response.status_code < 300


def _extract_json_path(body: Any, path: str) -> Any:
    """Resolve a dotted JSON path like ``"data.token"`` against ``body``.

    Returns the value at that path, or None if any segment is missing
    or the body isn't dict-shaped where it needs to be.

    Deliberately small — full JSONPath is overkill for the auth-response
    shapes we see in practice (1-3 levels deep, always object access,
    never array indexing).
    """
    if not isinstance(body, dict):
        return None
    cur: Any = body
    for segment in path.split("."):
        if not isinstance(cur, dict):
            return None
        if segment not in cur:
            return None
        cur = cur[segment]
    return cur
