"""
core/wraith/session_manager.py

Auth Session Manager for SentinelForge.

Problem:
  - Internal tools (verification, OOB probes, differential analysis) need a safe,
    deterministic way to obtain authenticated headers/cookies for a target.
  - Personas can define login flows, bearer tokens, or cookie jars, but without a
    dedicated driver we re-auth repeatedly and cannot persist session material.

Design:
  - AuthSessionManager is a per-target-origin cache that:
      1) parses personas config from ScanSession.knowledge["personas"]
      2) loads persisted auth material (optional, TTL-bounded)
      3) performs login flows only when required
      4) exposes headers/cookies for internal tools (MutationEngine/Wraith)
  - Persistence stores ONLY session material (cookies/bearer tokens), never passwords.

Security posture:
  - Persistence is opt-in per persona (`{"persist": true}`) or via knowledge override.
  - Stored files are chmod 0600 best-effort.
  - Scope is enforced by pinning personas' base_url to the scan target origin.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import urlparse

from core.base.config import get_config
from core.wraith.personas import LoginFlow, Persona, PersonaManager, PersonaType

logger = logging.getLogger(__name__)


_SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9_.-]+")


def _origin(url: str) -> str:
    parsed = urlparse(url)
    scheme = parsed.scheme or "http"
    netloc = parsed.netloc
    return f"{scheme}://{netloc}"


def _safe_filename(value: str, *, fallback: str = "persona") -> str:
    value = (value or "").strip()
    if not value:
        value = fallback
    value = _SAFE_NAME_RE.sub("_", value)
    value = value.strip("._")
    return value or fallback


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _parse_dt(value: str) -> Optional[datetime]:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception:
        return None


@dataclass(frozen=True)
class AuthMaterial:
    persona_name: str
    origin: str
    headers: Dict[str, str]
    cookies: Dict[str, str]
    bearer_token: Optional[str] = None
    loaded_from: str = "runtime"  # runtime|disk|login_flow

    def redacted_summary(self) -> Dict[str, Any]:
        """For logs/telemetry without leaking secrets."""
        return {
            "persona": self.persona_name,
            "origin": self.origin,
            "headers": sorted(self.headers.keys()),
            "cookie_names": sorted(self.cookies.keys()),
            "has_bearer_token": bool(self.bearer_token),
            "loaded_from": self.loaded_from,
        }


def parse_personas_config(base_url: str, cfg: Sequence[Any]) -> Tuple[List[Persona], Dict[str, bool]]:
    """
    Parse ScanSession.knowledge["personas"] into Persona objects.

    Returns:
      (personas, persist_by_name)
    """
    personas: List[Persona] = []
    persist_by_name: Dict[str, bool] = {}

    pinned_base = _origin(base_url)

    for item in cfg:
        if not isinstance(item, dict):
            continue

        name = str(item.get("name") or "").strip()
        if not name:
            continue

        # Persistence is opt-in per persona.
        persist_by_name[name] = bool(item.get("persist", False))

        ptype_raw = str(item.get("persona_type") or item.get("type") or "custom").strip().lower()
        try:
            ptype = PersonaType(ptype_raw)
        except Exception:
            ptype = PersonaType.CUSTOM

        login_flow_cfg = item.get("login_flow")
        login_flow: Optional[LoginFlow] = None
        if isinstance(login_flow_cfg, dict):
            try:
                login_flow = LoginFlow(
                    endpoint=str(login_flow_cfg.get("endpoint") or ""),
                    method=str(login_flow_cfg.get("method") or "POST"),
                    username_param=str(login_flow_cfg.get("username_param") or "username"),
                    password_param=str(login_flow_cfg.get("password_param") or "password"),
                    username_value=str(login_flow_cfg.get("username_value") or ""),
                    password_value=str(login_flow_cfg.get("password_value") or ""),
                    token_extract_path=login_flow_cfg.get("token_extract_path"),
                    cookie_extract=login_flow_cfg.get("cookie_extract"),
                    headers=login_flow_cfg.get("headers") if isinstance(login_flow_cfg.get("headers"), dict) else {},
                    content_type=str(login_flow_cfg.get("content_type") or "application/json"),
                )
            except Exception:
                login_flow = None
        if login_flow and isinstance(login_flow.endpoint, str) and login_flow.endpoint.startswith(("http://", "https://")):
            # Scope guard: absolute endpoints must be same-origin, otherwise a persona config
            # could pivot authentication to a different host than the scan target.
            try:
                if _origin(login_flow.endpoint) != pinned_base:
                    logger.warning(
                        "[SessionBridge] Dropping persona '%s' login_flow: endpoint origin %s != target origin %s",
                        name,
                        _origin(login_flow.endpoint),
                        pinned_base,
                    )
                    login_flow = None
            except Exception:
                login_flow = None

        cookie_jar = item.get("cookie_jar") if isinstance(item.get("cookie_jar"), dict) else None
        bearer_token = item.get("bearer_token") if isinstance(item.get("bearer_token"), str) else None
        extra_headers = item.get("extra_headers") if isinstance(item.get("extra_headers"), dict) else {}

        normalized_cookies = {str(k): str(v) for k, v in (cookie_jar or {}).items()} if cookie_jar else {}
        if not normalized_cookies:
            normalized_cookies = None

        personas.append(
            Persona(
                name=name,
                persona_type=ptype,
                cookie_jar=normalized_cookies,
                bearer_token=bearer_token,
                login_flow=login_flow,
                extra_headers={str(k): str(v) for k, v in extra_headers.items()},
                # Scope guard: pin base_url to the scan target origin to prevent pivoting.
                base_url=pinned_base,
            )
        )

    # Ensure Anonymous exists to test auth bypass.
    if not any(p.persona_type == PersonaType.ANONYMOUS for p in personas):
        personas.append(Persona(name="Anonymous", persona_type=PersonaType.ANONYMOUS, base_url=pinned_base))

    return personas, persist_by_name


class AuthSessionManager:
    """
    Session material cache for internal tools.

    Stored in ScanSession.knowledge under key "session_bridge".
    """

    DEFAULT_TTL_S = 12 * 60 * 60  # 12 hours

    def __init__(
        self,
        *,
        base_url: str,
        personas_cfg: Sequence[Any],
        baseline_persona: str = "Admin",
        ttl_s: float = DEFAULT_TTL_S,
        persist_default: bool = False,
    ):
        self.origin = _origin(base_url)
        self.baseline_persona = str(baseline_persona or "Admin")
        self.ttl_s = float(ttl_s) if ttl_s and ttl_s > 0 else float(self.DEFAULT_TTL_S)
        self.persist_default = bool(persist_default)
        self._personas_cfg = list(personas_cfg or [])

        self._lock = asyncio.Lock()
        self._initialized = False

        self.personas: List[Persona] = []
        self._persist_by_name: Dict[str, bool] = {}
        self._auth_by_name: Dict[str, AuthMaterial] = {}

        # Storage directory keyed by origin to avoid collisions across targets.
        cfg = get_config()
        digest = hashlib.sha256(self.origin.encode("utf-8")).hexdigest()[:16]
        self._store_dir = (cfg.storage.base_dir / "auth_sessions" / digest)

    @classmethod
    async def from_knowledge(
        cls,
        knowledge: Dict[str, Any],
        *,
        base_url: str,
    ) -> Optional["AuthSessionManager"]:
        """
        Get or create the session bridge for this scan.

        Returns None when no personas config is present.
        """
        personas_cfg = knowledge.get("personas")
        if not isinstance(personas_cfg, list) or not personas_cfg:
            return None

        lock = knowledge.get("_session_bridge_lock")
        if not isinstance(lock, asyncio.Lock):
            lock = asyncio.Lock()
            knowledge["_session_bridge_lock"] = lock

        async with lock:
            existing = knowledge.get("session_bridge")
            if isinstance(existing, AuthSessionManager):
                await existing.initialize()
                return existing

            baseline_persona = str(knowledge.get("persona_baseline") or "Admin")
            ttl_s = float(knowledge.get("persona_ttl_s") or cls.DEFAULT_TTL_S)
            persist_default = bool(knowledge.get("persona_persist_default") or False)

            mgr = cls(
                base_url=base_url,
                personas_cfg=personas_cfg,
                baseline_persona=baseline_persona,
                ttl_s=ttl_s,
                persist_default=persist_default,
            )
            knowledge["session_bridge"] = mgr
            await mgr.initialize()
            return mgr

    def _persona_store_path(self, persona_name: str) -> Path:
        return self._store_dir / f"{_safe_filename(persona_name)}.json"

    def _load_persisted(self, persona_name: str) -> Optional[AuthMaterial]:
        path = self._persona_store_path(persona_name)
        if not path.exists():
            return None

        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return None

        if not isinstance(raw, dict):
            return None

        stored_origin = raw.get("origin")
        if stored_origin is not None and str(stored_origin) != self.origin:
            return None

        saved_at = raw.get("saved_at")
        saved_dt = _parse_dt(saved_at) if isinstance(saved_at, str) else None
        if saved_dt is None:
            return None

        age_s = (_utcnow() - saved_dt).total_seconds()
        ttl_s = float(raw.get("ttl_s") or self.ttl_s)
        if age_s < 0:
            return None
        if ttl_s > 0 and age_s > ttl_s:
            return None

        cookies = raw.get("cookies")
        token = raw.get("bearer_token")
        if cookies is not None and not isinstance(cookies, dict):
            return None
        if token is not None and not isinstance(token, str):
            token = None

        headers: Dict[str, str] = {}
        if token:
            headers["Authorization"] = f"Bearer {token}"

        return AuthMaterial(
            persona_name=persona_name,
            origin=self.origin,
            headers=headers,
            cookies={str(k): str(v) for k, v in (cookies or {}).items()},
            bearer_token=token,
            loaded_from="disk",
        )

    def _persist(self, auth: AuthMaterial) -> None:
        try:
            self._store_dir.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            logger.debug("[SessionBridge] Failed to create auth store dir %s: %s", self._store_dir, e)
            return

        payload = {
            "version": 1,
            "origin": auth.origin,
            "persona_name": auth.persona_name,
            "saved_at": _utcnow().isoformat(),
            "ttl_s": self.ttl_s,
            "cookies": auth.cookies,
            "bearer_token": auth.bearer_token,
        }
        path = self._persona_store_path(auth.persona_name)
        try:
            path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
            try:
                path.chmod(0o600)
            except Exception:
                pass
        except Exception as e:
            logger.debug("[SessionBridge] Failed to persist auth material to %s: %s", path, e)

    def _build_auth_material(self, persona: Persona, *, loaded_from: str) -> AuthMaterial:
        headers = dict(persona.extra_headers or {})
        token = persona.bearer_token
        if token:
            headers["Authorization"] = f"Bearer {token}"

        cookies = {str(k): str(v) for k, v in (persona.cookie_jar or {}).items()}
        return AuthMaterial(
            persona_name=persona.name,
            origin=self.origin,
            headers=headers,
            cookies=cookies,
            bearer_token=token,
            loaded_from=loaded_from,
        )

    async def initialize(self) -> bool:
        """
        Initialize auth material.

        Returns:
          True if initialization ran (even if some personas failed auth), False if fatally misconfigured.
        """
        async with self._lock:
            if self._initialized:
                return True

            personas, persist_by_name = parse_personas_config(self.origin, self._personas_cfg)
            self.personas = personas
            self._persist_by_name = persist_by_name

            # 1) Load persisted session material (TTL bounded) when persona lacks explicit auth.
            for p in self.personas:
                if p.persona_type == PersonaType.ANONYMOUS:
                    continue
                if p.bearer_token or p.cookie_jar:
                    continue
                persisted = self._load_persisted(p.name)
                if persisted:
                    # Apply persisted material back onto persona for downstream PersonaManager usage.
                    if persisted.bearer_token:
                        p.bearer_token = persisted.bearer_token
                    if persisted.cookies:
                        p.cookie_jar = dict(persisted.cookies)
                    self._auth_by_name[p.name] = persisted

            # Determine if we still need to execute login flows.
            needs_login = [
                p for p in self.personas
                if p.persona_type != PersonaType.ANONYMOUS
                and p.login_flow is not None
                and not p.bearer_token
                and not p.cookie_jar
            ]

            # 2) If required, execute login flows via PersonaManager, then extract session material.
            if needs_login:
                mgr = PersonaManager(personas=self.personas)
                ok = await mgr.initialize()
                try:
                    for p in self.personas:
                        auth = self._build_auth_material(p, loaded_from="login_flow")
                        # If PersonaManager acquired cookies on the client, capture them too.
                        session = mgr.get_session(p.name)
                        if session is not None:
                            try:
                                client_cookies = dict(getattr(session.client, "cookies", {}) or {})
                                if client_cookies:
                                    merged = {**auth.cookies, **{str(k): str(v) for k, v in client_cookies.items()}}
                                    auth = AuthMaterial(
                                        persona_name=auth.persona_name,
                                        origin=auth.origin,
                                        headers=auth.headers,
                                        cookies=merged,
                                        bearer_token=auth.bearer_token,
                                        loaded_from=auth.loaded_from,
                                    )
                                    # Feed session cookies back into the Persona object so downstream
                                    # PersonaManager invocations can skip re-running login flows.
                                    if merged:
                                        p.cookie_jar = dict(merged)
                            except Exception:
                                pass
                        self._auth_by_name[p.name] = auth
                finally:
                    await mgr.close()

                # Persist opted-in personas.
                for name, auth in list(self._auth_by_name.items()):
                    should_persist = self._persist_by_name.get(name, False) or self.persist_default
                    if should_persist:
                        self._persist(auth)

                self._initialized = True
                return bool(ok)

            # 3) No login needed; material is derived from config/persisted state only.
            for p in self.personas:
                if p.name in self._auth_by_name:
                    continue
                self._auth_by_name[p.name] = self._build_auth_material(p, loaded_from="runtime")
                should_persist = self._persist_by_name.get(p.name, False) or self.persist_default
                if should_persist:
                    self._persist(self._auth_by_name[p.name])

            self._initialized = True
            return True

    async def get_auth(self, persona_name: str) -> Optional[AuthMaterial]:
        await self.initialize()
        return self._auth_by_name.get(persona_name)

    async def get_baseline_auth(self) -> Optional[AuthMaterial]:
        await self.initialize()
        # Baseline persona may not exist; fall back to first non-anon with auth.
        baseline = self._auth_by_name.get(self.baseline_persona)
        if baseline and (baseline.cookies or baseline.bearer_token or baseline.headers):
            return baseline
        for p in self.personas:
            if p.persona_type == PersonaType.ANONYMOUS:
                continue
            auth = self._auth_by_name.get(p.name)
            if auth and (auth.cookies or auth.bearer_token or auth.headers):
                return auth
        return None


__all__ = [
    "AuthMaterial",
    "AuthSessionManager",
    "parse_personas_config",
]
