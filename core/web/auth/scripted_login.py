from __future__ import annotations

import hashlib
import logging
from typing import Any, Dict, List

from .base import AuthProvider, AuthResult, AuthenticationError
from ..context import WebContext
from ..contracts.models import PrincipalProfile, WebMission

logger = logging.getLogger(__name__)


class ScriptedLoginProvider(AuthProvider):
    """Authenticates via a scripted sequence of HTTP requests.

    Used when login flows require multi-step interactions that can't be
    expressed as a single form POST — e.g., API token exchanges, multi-factor
    setup steps, or custom REST login endpoints.

    The script is provided as a list of step dicts in profile.extra_headers
    under the key "_login_script". Each step is:
        {"method": "POST", "url": "...", "json": {...}, "extract": {"token": "$.data.token"}}

    The "extract" field uses simple dot-notation paths to pull values from
    JSON responses into the context for subsequent steps.
    """

    def authenticate(
        self,
        mission: WebMission,
        ctx: WebContext,
        profile: PrincipalProfile,
    ) -> AuthResult:
        if not profile.login_url:
            raise AuthenticationError(
                f"ScriptedLoginProvider requires login_url for {profile.principal_id}"
            )

        login_url = str(profile.login_url)
        script = profile.extra_headers.get("_login_script")

        if not script or not isinstance(script, list):
            # Fall back to simple JSON POST with credentials
            return self._simple_api_login(mission, ctx, profile, login_url)

        return self._run_script(ctx, profile, script)

    def _simple_api_login(
        self,
        mission: WebMission,
        ctx: WebContext,
        profile: PrincipalProfile,
        login_url: str,
    ) -> AuthResult:
        """Simple single-request API login (e.g., POST /api/auth/login)."""
        payload: Dict[str, Any] = {}
        if profile.username:
            payload["email"] = profile.username
            payload["username"] = profile.username
        if profile.password:
            payload["password"] = profile.password

        try:
            resp = ctx.client.post(login_url, json=payload)
        except Exception as exc:
            raise AuthenticationError(
                f"API login request failed for {profile.principal_id}: {exc}"
            ) from exc

        if resp.status_code >= 400:
            raise AuthenticationError(
                f"API login failed for {profile.principal_id}: HTTP {resp.status_code}"
            )

        # Try to extract token from JSON response
        try:
            data = resp.json()
        except Exception:
            data = {}

        token = self._deep_get(data, "token") or self._deep_get(data, "authentication.token") or self._deep_get(data, "access_token")
        if token and isinstance(token, str):
            ctx.auth_tokens[login_url] = token
            ctx.default_headers["Authorization"] = f"Bearer {token}"
            ctx.client.headers["Authorization"] = f"Bearer {token}"

        fingerprint = hashlib.sha256(
            (token or str(resp.status_code)).encode()
        ).hexdigest()[:16]

        logger.info(
            "ScriptedLoginProvider: API login succeeded for %s (token=%s)",
            profile.principal_id, "yes" if token else "no",
        )
        return AuthResult(success=True, signal="api_token", fingerprint=fingerprint)

    def _run_script(
        self,
        ctx: WebContext,
        profile: PrincipalProfile,
        script: List[Dict[str, Any]],
    ) -> AuthResult:
        """Execute a multi-step login script."""
        context_vars: Dict[str, str] = {}
        if profile.username:
            context_vars["username"] = profile.username
        if profile.password:
            context_vars["password"] = profile.password

        for i, step in enumerate(script):
            method = step.get("method", "POST").upper()
            url = self._interpolate(step.get("url", ""), context_vars)

            json_body = step.get("json")
            if json_body and isinstance(json_body, dict):
                json_body = {
                    k: self._interpolate(v, context_vars) if isinstance(v, str) else v
                    for k, v in json_body.items()
                }

            try:
                resp = ctx.client.request(method, url, json=json_body)
            except Exception as exc:
                raise AuthenticationError(
                    f"Script step {i} failed for {profile.principal_id}: {exc}"
                ) from exc

            if resp.status_code >= 400:
                raise AuthenticationError(
                    f"Script step {i} returned HTTP {resp.status_code} for {profile.principal_id}"
                )

            # Extract values for next steps
            extracts = step.get("extract", {})
            if extracts and isinstance(extracts, dict):
                try:
                    data = resp.json()
                except Exception:
                    data = {}
                for var_name, json_path in extracts.items():
                    value = self._deep_get(data, json_path.lstrip("$."))
                    if value is not None:
                        context_vars[var_name] = str(value)

        # Apply final token if extracted
        token = context_vars.get("token") or context_vars.get("access_token")
        if token:
            ctx.auth_tokens["scripted"] = token
            ctx.default_headers["Authorization"] = f"Bearer {token}"
            ctx.client.headers["Authorization"] = f"Bearer {token}"

        fingerprint = hashlib.sha256(
            str(sorted(context_vars.items())).encode()
        ).hexdigest()[:16]

        logger.info(
            "ScriptedLoginProvider: script completed for %s (%d steps)",
            profile.principal_id, len(script),
        )
        return AuthResult(success=True, signal="scripted_login", fingerprint=fingerprint)

    @staticmethod
    def _interpolate(template: str, context: Dict[str, str]) -> str:
        """Replace {{var}} placeholders with context values."""
        for key, value in context.items():
            template = template.replace(f"{{{{{key}}}}}", value)
        return template

    @staticmethod
    def _deep_get(obj: Any, path: str) -> Any:
        """Traverse a dict by dot-separated path. Returns None if not found."""
        parts = path.split(".")
        current = obj
        for part in parts:
            if isinstance(current, dict):
                current = current.get(part)
            else:
                return None
        return current
