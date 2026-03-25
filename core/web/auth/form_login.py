from __future__ import annotations

import hashlib
import logging
import re
from typing import Dict, List, Optional, Tuple

from .base import AuthProvider, AuthResult, AuthenticationError
from ..context import WebContext
from ..contracts.models import PrincipalProfile, WebMission

logger = logging.getLogger(__name__)

# Common form field names for username/password
_USERNAME_FIELDS = {"username", "user", "email", "login", "user_login", "userid", "user_id"}
_PASSWORD_FIELDS = {"password", "pass", "passwd", "pwd", "user_password", "user_pass"}

# Patterns indicating a successful login redirect or response
_SUCCESS_PATTERNS = [
    re.compile(r"dashboard|account|profile|welcome|home|logout", re.I),
    re.compile(r"<meta\s+http-equiv=[\"']refresh", re.I),
]

# Patterns indicating login failure
_FAILURE_PATTERNS = [
    re.compile(r"invalid.*(credentials|password|username|login)", re.I),
    re.compile(r"(login|authentication)\s+(failed|error|incorrect)", re.I),
    re.compile(r"wrong\s+(password|username|credentials)", re.I),
    re.compile(r"access\s+denied", re.I),
]


class FormLoginProvider(AuthProvider):
    """Authenticates via HTML form POST.

    Strategy:
    1. GET the login page to discover CSRF tokens and form structure
    2. POST credentials with any discovered hidden fields
    3. Validate success via cookies, redirects, or response content
    """

    def authenticate(
        self,
        mission: WebMission,
        ctx: WebContext,
        profile: PrincipalProfile,
    ) -> AuthResult:
        if not profile.login_url:
            raise AuthenticationError(
                f"FormLoginProvider requires login_url for {profile.principal_id}"
            )

        login_url = str(profile.login_url)
        logger.info(
            "FormLoginProvider: starting login for %s at %s",
            profile.principal_id, login_url,
        )

        # Scope guard: reject login URLs that are out-of-scope
        if ctx.scope_enforcer is not None:
            ctx.scope_enforcer.assert_in_scope(login_url)

        # Step 1: GET the login page to discover hidden fields / CSRF tokens
        try:
            get_resp = ctx.client.get(login_url, follow_redirects=True)
        except Exception as exc:
            raise AuthenticationError(
                f"Failed to fetch login page at {login_url}: {exc}"
            ) from exc

        hidden_fields = self._extract_hidden_fields(get_resp.text)
        csrf_token = self._extract_csrf_token(get_resp.text, get_resp.headers)

        # Step 2: Build form payload
        form_data: Dict[str, str] = {}
        form_data.update(hidden_fields)

        if csrf_token:
            # Try common CSRF field names
            for name in ("_token", "csrf_token", "csrfmiddlewaretoken", "authenticity_token", "_csrf"):
                if name in hidden_fields:
                    form_data[name] = csrf_token
                    break
            else:
                form_data["csrf_token"] = csrf_token
            ctx.csrf_tokens[login_url] = csrf_token

        if profile.username:
            field_name = self._find_field_name(get_resp.text, _USERNAME_FIELDS, "username")
            form_data[field_name] = profile.username
        if profile.password:
            field_name = self._find_field_name(get_resp.text, _PASSWORD_FIELDS, "password")
            form_data[field_name] = profile.password

        # Step 3: POST the login form
        try:
            post_resp = ctx.client.post(
                login_url,
                data=form_data,
                follow_redirects=True,
            )
        except Exception as exc:
            raise AuthenticationError(
                f"Login POST failed for {profile.principal_id}: {exc}"
            ) from exc

        # Scope guard: verify redirect chain didn't leave scope
        if ctx.scope_enforcer is not None:
            final_url = str(post_resp.url)
            if final_url != login_url:
                ctx.scope_enforcer.assert_in_scope(final_url)

        # Step 4: Validate the response
        cookies = dict(ctx.client.cookies)
        has_cookies = bool(cookies)

        # Check for explicit failure patterns
        body = post_resp.text
        for pat in _FAILURE_PATTERNS:
            if pat.search(body):
                raise AuthenticationError(
                    f"Login failed for {profile.principal_id}: response contains failure indicator"
                )

        # HTTP 4xx/5xx on the final response is a failure
        if post_resp.status_code >= 400:
            raise AuthenticationError(
                f"Login failed for {profile.principal_id}: HTTP {post_resp.status_code}"
            )

        if not has_cookies:
            # Some apps set tokens in response body/headers instead of cookies
            auth_header = post_resp.headers.get("authorization")
            if auth_header:
                ctx.auth_tokens[login_url] = auth_header
                ctx.default_headers["Authorization"] = auth_header

        # Compute session fingerprint
        cookie_str = ";".join(f"{k}={v}" for k, v in sorted(cookies.items()))
        fingerprint = hashlib.sha256(cookie_str.encode()).hexdigest()[:16]

        signal = "cookie_set" if has_cookies else "header_auth"
        logger.info(
            "FormLoginProvider: login succeeded for %s (signal=%s, cookies=%d)",
            profile.principal_id, signal, len(cookies),
        )

        return AuthResult(
            success=True,
            signal=signal,
            fingerprint=fingerprint,
        )

    @staticmethod
    def _extract_hidden_fields(html: str) -> Dict[str, str]:
        """Extract all hidden input fields from HTML form."""
        fields: Dict[str, str] = {}
        for match in re.finditer(
            r'<input[^>]+type=["\']hidden["\'][^>]*>', html, re.I
        ):
            tag = match.group(0)
            name_m = re.search(r'name=["\']([^"\']+)["\']', tag)
            value_m = re.search(r'value=["\']([^"\']*)["\']', tag)
            if name_m:
                fields[name_m.group(1)] = value_m.group(1) if value_m else ""
        return fields

    @staticmethod
    def _extract_csrf_token(html: str, headers: dict) -> Optional[str]:
        """Try to find CSRF token from meta tags or headers."""
        # Meta tag (Rails, Laravel, Django, etc.)
        meta_match = re.search(
            r'<meta[^>]+name=["\']csrf-token["\'][^>]+content=["\']([^"\']+)["\']',
            html, re.I,
        )
        if meta_match:
            return meta_match.group(1)

        # X-CSRF-Token header
        for header_name in ("x-csrf-token", "x-xsrf-token"):
            token = headers.get(header_name)
            if token:
                return token

        return None

    @staticmethod
    def _find_field_name(html: str, candidates: set, fallback: str) -> str:
        """Find the actual form field name from HTML, falling back to a default."""
        for match in re.finditer(
            r'<input[^>]+name=["\']([^"\']+)["\']', html, re.I
        ):
            name = match.group(1).lower()
            if name in candidates:
                return match.group(1)  # Return original case
        return fallback
