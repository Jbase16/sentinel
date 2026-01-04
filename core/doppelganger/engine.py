from __future__ import annotations

import base64
import json
import logging
import time
from typing import Optional, Dict, Any, Tuple

import httpx

from .models import Persona, Credential

log = logging.getLogger("doppelganger.engine")


def _b64url_decode(data: str) -> bytes:
    # JWT uses base64url without padding
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def _parse_jwt_times(token: str) -> Tuple[Optional[int], Optional[int]]:
    """
    Parse JWT payload for iat/exp without verifying signature.
    This is for refresh timing only, not trust.
    """
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None, None
        payload_raw = _b64url_decode(parts[1]).decode("utf-8", errors="replace")
        payload = json.loads(payload_raw)
        iat = payload.get("iat")
        exp = payload.get("exp")
        if iat is not None:
            iat = int(iat)
        if exp is not None:
            exp = int(exp)
        return iat, exp
    except Exception:
        return None, None


def _extract_token(body: Any) -> Optional[str]:
    """
    Juice Shop typically returns:
      { "authentication": { "token": "<jwt>" } }
    but we’ll be defensive.
    """
    try:
        if isinstance(body, dict):
            auth = body.get("authentication")
            if isinstance(auth, dict):
                tok = auth.get("token")
                if isinstance(tok, str) and tok.strip():
                    return tok.strip()

            # fallback: search any nested dict for key "token"
            stack = [body]
            while stack:
                cur = stack.pop()
                if isinstance(cur, dict):
                    for k, v in cur.items():
                        if k == "token" and isinstance(v, str) and v.strip():
                            return v.strip()
                        if isinstance(v, (dict, list)):
                            stack.append(v)
                elif isinstance(cur, list):
                    for it in cur:
                        if isinstance(it, (dict, list)):
                            stack.append(it)
        return None
    except Exception:
        return None


class DoppelgangerEngine:
    """
    Manages Personas and their active sessions.
    """

    def __init__(self) -> None:
        self.active_personas: Dict[str, Persona] = {}

    async def authenticate(self, credential: Credential, target_url: str) -> Optional[Persona]:
        """
        Attempt to log in and create/overwrite a Persona.
        """
        persona_id = credential.username
        safe_user = credential.username
        log.info(f"🎭 Doppelganger: login attempt user={safe_user} target={target_url}")

        login_endpoint = f"{target_url.rstrip('/')}/rest/user/login"

        try:
            async with httpx.AsyncClient(verify=False, follow_redirects=True) as client:
                resp = await client.post(
                    login_endpoint,
                    json={"email": credential.username, "password": credential.password},
                    timeout=10.0,
                )

                if resp.status_code != 200:
                    log.warning(f"🎭 Login failed status={resp.status_code} body={resp.text[:200]}")
                    return None

                try:
                    data = resp.json()
                except Exception:
                    log.warning("🎭 Login returned 200 but body was not JSON.")
                    return None

                token = _extract_token(data)
                if not token:
                    log.warning("🎭 Login returned 200 but no token found in JSON.")
                    return None

                iat, exp = _parse_jwt_times(token)

                persona = Persona(
                    id=persona_id,
                    credential=credential,
                    session_token=token,
                    cookies={k: v for k, v in resp.cookies.items()},
                    headers={},  # put persona-specific static headers here if needed
                    token_issued_at=iat,
                    token_expires_at=exp,
                )

                self.active_personas[persona.id] = persona

                exp_str = str(exp) if exp else "unknown"
                log.info(f"✅ Doppelganger: login ok user={safe_user} exp={exp_str}")
                return persona

        except httpx.RequestError as e:
            log.error(f"🎭 Login request error: {type(e).__name__}: {e}")
            return None
        except Exception as e:
            log.error(f"🎭 Login exception: {e}", exc_info=True)
            return None

    async def refresh(self, persona: Persona, target_url: str) -> Optional[Persona]:
        """
        Refresh strategy V1: re-authenticate (Juice Shop doesn’t give a refresh token flow by default).
        """
        if not persona or not persona.credential:
            return None

        if not persona.should_refresh(skew_seconds=30):
            return persona

        log.info(f"🎭 Doppelganger: refreshing persona={persona.id}")
        new_persona = await self.authenticate(persona.credential, target_url)
        return new_persona

    def get_persona(self, persona_id: str) -> Optional[Persona]:
        return self.active_personas.get(persona_id)

    def inject_auth(self, headers: Optional[Dict[str, str]], cookies: Optional[Dict[str, str]], persona: Optional[Persona]) -> Tuple[Dict[str, str], Dict[str, str]]:
        """
        Merge persona auth into outbound request materials.
        Returns (headers, cookies).
        """
        out_h = dict(headers) if headers else {}
        out_c = dict(cookies) if cookies else {}

        if not persona:
            return out_h, out_c

        # Merge in persona static headers + bearer token
        for k, v in persona.get_auth_headers().items():
            out_h[k] = v

        # Merge cookies (per-request injection avoids cross-persona contamination)
        for k, v in persona.get_cookies().items():
            out_c[k] = v

        return out_h, out_c
