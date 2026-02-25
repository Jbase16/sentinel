import logging

from .contracts.enums import WebAuthMode
from .contracts.events import EventEnvelope, EventType, WebAuthEstablishedPayload
from .contracts.models import PrincipalProfile, WebMission
from .context import WebContext
from .transport import SentinelEventBus

logger = logging.getLogger(__name__)

class AuthManager:
    """
    Handles deterministic initialization of isolated WebContexts per Principal.
    """
    def __init__(self, bus: SentinelEventBus):
        self.bus = bus

    def bootstrap(self, mission: WebMission, ctx: WebContext, profile: PrincipalProfile) -> None:
        """
        Executes deterministic login for the given context and profile.
        """
        logger.info(f"Bootstrapping auth for principal {profile.principal_id}")

        # 1. Apply static extra headers (e.g., test headers or hardcoded tokens)
        if profile.extra_headers:
            ctx.client.headers.update(profile.extra_headers)  # Update httpx client exactly
            ctx.default_headers.update(profile.extra_headers)

        if not profile.login_url or mission.auth_mode in (WebAuthMode.STATIC_HEADER, WebAuthMode.NONE):
            # STATIC_HEADER mode (or NONE)
            self._emit_auth_established(mission, ctx, WebAuthMode.STATIC_HEADER, profile, "static_headers", "static_hash")
            return

        if mission.auth_mode == WebAuthMode.FORM_LOGIN:
            login_url = str(profile.login_url)
            
            # Simple V1 deterministic form POST (no javascript required)
            data = {}
            if profile.username:
                data["username"] = profile.username
            if profile.password:
                data["password"] = profile.password

            resp = ctx.client.post(login_url, data=data)
            if resp.status_code >= 400:
                raise ValueError(f"Deterministic login failed for {profile.principal_id} at {login_url} (HTTP {resp.status_code})")
                
            if not ctx.client.cookies:
                raise ValueError(f"Login succeeded but no cookies set for {profile.principal_id}")
                
            # Compute a non-secret session fingerprint from cookie keys/values
            cookie_str = ";".join(f"{k}={v}" for k, v in sorted(ctx.client.cookies.items()))
            session_fingerprint = str(hash(cookie_str))
            
            self._emit_auth_established(mission, ctx, WebAuthMode.FORM_LOGIN, profile, "cookie_set", session_fingerprint)
            return
            
        raise NotImplementedError(f"Auth mode {mission.auth_mode} not implemented for AuthManager")

    def _emit_auth_established(self, mission: WebMission, ctx: WebContext, mode: WebAuthMode, profile: PrincipalProfile, signal: str, fingerprint: str) -> None:
        payload = WebAuthEstablishedPayload(
            auth_mode=mode,
            principal_id=profile.principal_id,
            login_url=profile.login_url,
            success_signal=signal,
            session_fingerprint=fingerprint
        )
        
        self.bus.emit(EventEnvelope(
            event_type=EventType.WEB_AUTH_ESTABLISHED,
            mission_id=mission.mission_id,
            scan_id=mission.scan_id,
            session_id=mission.session_id,
            principal_id=ctx.principal_id,
            payload=payload.model_dump(mode="json")
        ))
        logger.info(f"Auth established for {profile.principal_id} via {mode.value}")
