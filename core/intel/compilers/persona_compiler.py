"""
persona_compiler — emit Sentinel's existing personas.json format.

Output format (verified against ``pysentinel.py:343`` and
``core/wraith/personas.py`` — the dataclass that consumes the loaded JSON):

  [
    {
      "name": "anonymous",
      "persona_type": "anonymous",
      "base_url": "https://example.com"
    },
    {
      "name": "researcher",
      "persona_type": "user",
      "base_url": "https://example.com",
      "login_flow": {
        "endpoint": "/api/login",
        "method": "POST",
        "username_param": "email",
        "password_param": "password",
        "username_value": "test@example.com",      # <— wraith field name
        "password_value": "<known-good-pass>",     # <— wraith field name
        "token_extract_path": "data.token",
        "cookie_extract": "session_id",            # <— singular, NOT cookie_extract_name
        "content_type": "application/json"
      }
    }
  ]

Three field-name translations between our internal model and wraith's
serialized format:

  ProgramScope's Persona             →  wraith's persona JSON
  ──────────────────────────────────────────────────────────────
  persona.username                   →  login_flow.username_value
  persona.password                   →  login_flow.password_value
  login_flow.cookie_extract_name     →  login_flow.cookie_extract

The mismatches exist because the wraith ``Persona`` dataclass and our
``ProgramScope.Persona`` evolved independently. Renames are explicit
here so the contract is visible in the diff if either side changes.

Filtering rules:

  - **Anonymous personas are always included** even if their
    verification status is UNVERIFIED. They represent the
    no-credentials baseline that diff testing needs.
  - **Authenticated personas are included only if they have
    credentials** (username AND password). UNVERIFIED-but-credentialed
    personas are included (the operator may verify them manually later);
    FAILED personas are dropped by default (they're known-bad).
  - The caller can override the filter via ``include_failed=True`` to
    emit FAILED personas with a comment — useful for debugging
    extraction quality.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List

from core.intel.program_scope import (
    LoginFlow,
    Persona,
    Platform,
    ProgramScope,
    VerificationStatus,
)


def compile_personas_json(
    scope: ProgramScope,
    *,
    include_failed: bool = False,
    indent: int = 2,
) -> str:
    """Render ``ProgramScope.personas`` as a wraith-compatible JSON string.

    Args:
        scope: The program scope to compile.
        include_failed: If True, emit personas marked ``VerificationStatus
            .FAILED``. Default False (operators usually don't want known-bad
            creds in their scan config).
        indent: JSON indent level. Default 2 for readability.

    Returns:
        A JSON document — list of persona objects, ready to be written to
        ``<program>-personas.json`` and consumed by ``pysentinel --personas
        <path>``.

    Note: the returned string always ends with a trailing newline so the
    file is POSIX-compliant when written to disk.
    """
    output: List[Dict[str, Any]] = []
    for persona in scope.personas:
        if not _should_include(persona, include_failed=include_failed):
            continue
        output.append(_render_persona(persona))

    # Always include an explicit anonymous baseline if one isn't already
    # present. Diff testing requires an anonymous baseline, and the
    # personas file must be a non-empty list (pysentinel's loader rejects
    # an empty []). So we synthesize an anonymous persona whenever the
    # rendered output lacks one AND we can derive a base URL — even if the
    # scope had zero personas extracted (common when the LLM extraction
    # times out or the program lists no test creds). This guarantees the
    # emitted personas.json is always loadable.
    if not _has_anonymous(output):
        synthesized = _synthesize_anonymous_from(scope)
        if synthesized.get("base_url"):
            output.insert(0, synthesized)

    return json.dumps(output, indent=indent, ensure_ascii=False) + "\n"


# ─────────────────────────── Internals ─────────────────────────────

def _should_include(persona: Persona, *, include_failed: bool) -> bool:
    """Apply the filtering rules documented at the top of the module."""
    if persona.persona_type == "anonymous":
        return True

    if not persona.username or not persona.password:
        # Authenticated personas without credentials are useless — the
        # scanner can't authenticate. Drop with no comment; the
        # ProgramScope JSON cache retains the full record for audit.
        return False

    if persona.verified == VerificationStatus.FAILED and not include_failed:
        return False

    return True


def _has_anonymous(rendered: List[Dict[str, Any]]) -> bool:
    return any(p.get("persona_type") == "anonymous" for p in rendered)


def _synthesize_anonymous_from(scope: ProgramScope) -> Dict[str, Any]:
    """Build an anonymous persona using a base_url inferred from the scope.

    Strategy, in priority order:
      1. The base_url of the first authenticated persona (most accurate —
         it's a host the program actually authenticates against).
      2. The first in-scope DOMAIN/URL rule (a real scannable target).
      3. Derive from source_url — last resort. NOTE: for API-sourced
         scopes (Platform.HACKERONE), source_url is the *API endpoint*
         (api.hackerone.com), NOT the target — so this fallback is only
         meaningful for DIRECT_URL scopes. We prefer (2) precisely to
         avoid emitting api.hackerone.com as a scan base.

    Returns a dict with base_url possibly empty — the caller checks that
    and skips synthesis if no usable base could be found.
    """
    # (1) authenticated persona base_url
    for persona in scope.personas:
        if persona.persona_type != "anonymous" and persona.base_url:
            return _anon_dict(persona.base_url)

    # (2) first in-scope domain/url rule
    domain_base = _base_url_from_scope_rules(scope)
    if domain_base:
        return _anon_dict(domain_base)

    # (3) source_url fallback — only useful for non-API scopes
    if scope.platform != Platform.HACKERONE and scope.platform != Platform.BUGCROWD:
        derived = _derive_base_url(scope.source_url)
        if derived:
            return _anon_dict(derived)

    # No usable base — caller will skip synthesis.
    return _anon_dict("")


def _anon_dict(base_url: str) -> Dict[str, Any]:
    return {
        "name": "anonymous",
        "persona_type": "anonymous",
        "base_url": base_url,
    }


def _base_url_from_scope_rules(scope: ProgramScope) -> str:
    """Pick the first concrete in-scope host as a base URL.

    Skips wildcards (``*.example.com`` is not a single host) and
    non-network rule types (mobile apps, source repos)."""
    from core.intel.program_scope import ScopeRuleType
    for rule in scope.scope_rules:
        if not rule.in_scope:
            continue
        if rule.rule_type not in (ScopeRuleType.DOMAIN, ScopeRuleType.URL):
            continue
        pattern = rule.pattern.strip()
        if not pattern or pattern.startswith("*."):
            continue
        if pattern.startswith(("http://", "https://")):
            return pattern.rstrip("/")
        return f"https://{pattern}"
    return ""


def _derive_base_url(source_url: str) -> str:
    """Strip path off a source URL to get a likely base. Defensive — works
    on hackerone.com/gitlab/policy or example.com/security/policy."""
    from urllib.parse import urlparse
    try:
        parsed = urlparse(source_url)
        if parsed.scheme and parsed.netloc:
            return f"{parsed.scheme}://{parsed.netloc}"
    except Exception:  # noqa: BLE001
        pass
    return source_url


def _render_persona(persona: Persona) -> Dict[str, Any]:
    """Render one ``Persona`` to a wraith-compatible dict.

    Handles the field-name translations between internal model and
    wraith's JSON format. Documented at the top of the module.
    """
    out: Dict[str, Any] = {
        "name": persona.name,
        "persona_type": persona.persona_type,
        "base_url": persona.base_url,
    }
    if persona.login_flow is not None:
        out["login_flow"] = _render_login_flow(persona.login_flow, persona)
    return out


def _render_login_flow(flow: LoginFlow, persona: Persona) -> Dict[str, Any]:
    """Render a ``LoginFlow`` to the wraith JSON shape.

    This is where the field-name translation happens:

      persona.username                   → username_value
      persona.password                   → password_value
      flow.cookie_extract_name           → cookie_extract
    """
    result: Dict[str, Any] = {
        "endpoint": flow.endpoint,
        "method": flow.method,
        "username_param": flow.username_param,
        "password_param": flow.password_param,
        "content_type": flow.content_type,
        # Credentials hoist from persona-level into login_flow-level
        # because that's how the wraith dataclass expects them.
        "username_value": persona.username or "",
        "password_value": persona.password or "",
    }
    if flow.token_extract_path:
        result["token_extract_path"] = flow.token_extract_path
    if flow.cookie_extract_name:
        # Wraith calls it `cookie_extract` (singular noun), not
        # `cookie_extract_name`. Rename here.
        result["cookie_extract"] = flow.cookie_extract_name
    if flow.additional_fields:
        # Wraith calls this `headers` if used for header injection. The
        # additional_fields slot is more general (CSRF tokens, etc.) so
        # we pass it through under a neutral key the runtime ignores
        # unless it knows the convention. For Phase 2C we emit it; Phase
        # 2D wiring in wraith can consume.
        result["additional_fields"] = dict(flow.additional_fields)
    return result
