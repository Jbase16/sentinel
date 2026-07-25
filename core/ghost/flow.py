"""
core/ghost/flow.py — Phase 4-G2: full-fidelity flow capture.

The FlowMapper records sequences of HTTP exchanges (request + response)
that an operator drives through the Ghost proxy. Phase 4-G1 wired the
proxy lifecycle; this commit (G2) makes the captured artifact
*replay-capable*:

  * FlowStep now carries the FULL request body and the FULL response
    (status, headers, body, timing, content-type) — not just the
    request shape and status code.
  * Each step records the cookie-jar state AFTER the request so a
    replayer can faithfully reconstruct mid-flow session state.
  * UserFlow + FlowStep are JSON-serializable round-trip — `to_dict()`
    + `from_dict()` are the canonical interchange format.
  * FlowMapper.persist(flow_id) writes to
    ~/.sentinelforge/ghost_flows/{flow_id}.json (atomic write, dir
    auto-created). FlowMapper.load_persisted(flow_id) reads it back.
  * FlowMapper now exposes finalize_step(step_id, response_data) so
    the addon can record the response AFTER it lands (request is
    seen first, response later — two distinct hook invocations in
    mitmproxy).

Why JSON-per-flow (vs sqlite or jsonl):
  * Each flow is the natural atomic unit. One file per flow → easy
    to inspect, diff, copy, version-control.
  * Persisting the FULL flow at stop-time (not per-step append) is
    more I/O-efficient when flows are typically 10-200 steps.
  * JSON is human-readable, which matters when an operator wants to
    eyeball a captured flow before replaying it.
  * If we later need queryability, the operator can grep + jq.
"""
from __future__ import annotations

import json
import logging
import os
import time
import uuid
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Optional
from urllib.parse import urlparse

if TYPE_CHECKING:
    from core.wraith.personas import Persona

logger = logging.getLogger(__name__)


# Where persisted flows live. Operators can override via env for tests
# (and the persistence tests do exactly that).
_FLOW_STORE_ENV = "SENTINELFORGE_FLOW_STORE"
_DEFAULT_FLOW_STORE = Path.home() / ".sentinelforge" / "ghost_flows"


def _flow_store_dir() -> Path:
    """Resolve the on-disk flow store directory, honoring env override.

    Resolved per-call rather than at import time so tests can monkeypatch
    the env var. Auto-creates the dir on first persist."""
    override = os.environ.get(_FLOW_STORE_ENV)
    if override:
        return Path(override)
    return _DEFAULT_FLOW_STORE


# Maximum body size we record per step. Large binary uploads / downloads
# would balloon flow files; capping at 1 MiB is sufficient for replay
# of typical web-app interactions (login, CRUD, OAuth handshakes). The
# original full size is still recorded as `request_body_truncated` /
# `response_body_truncated` flags for honest accounting.
MAX_BODY_BYTES = 1 * 1024 * 1024


class FlowStep:
    """One HTTP exchange in a recorded flow — request + response.

    Before G2 this only carried the request shape; G2 adds the full
    response and a few replay-needed extras.

    Attributes:
        id: Unique identifier for this step.
        method: HTTP method.
        url: Full request URL (post-redirect-resolved).
        params: Query/form parameters.
        headers: Request headers (lowercased keys for case-insensitive
            replay lookup).
        request_body: Raw request body bytes encoded as UTF-8 string
            (with errors="replace"). Empty for GET/HEAD.
        request_body_truncated: True if the body was larger than
            MAX_BODY_BYTES and got cut.
        request_content_type: Content-Type header value at request time.

        timestamp: Unix timestamp when the request was made.

        response_status: HTTP response status code (0 = not yet
            captured — step was started but response hasn't landed).
        response_headers: Response headers (case-preserved on the wire,
            but stored lowercased here for replay-time lookup).
        response_body: Raw response body bytes encoded as UTF-8 string.
        response_body_truncated: True if response was cut.
        response_content_type: Response Content-Type header.
        response_elapsed_ms: Time from request start to response end.

        cookies_after_step: The cookie jar state AFTER this step
            (post-Set-Cookie). A replayer uses this to carry session
            state forward to step N+1.
    """

    def __init__(
        self,
        method: str,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        request_body: Optional[str] = None,
        request_body_truncated: bool = False,
        request_content_type: Optional[str] = None,
    ):
        self.id = str(uuid.uuid4())
        self.method = method
        self.url = url
        self.params: Dict[str, Any] = dict(params) if params else {}
        # Normalize header keys to canonical (lowercase) — replay-time
        # lookups become case-safe. Original case is preserved in the
        # source captures if needed; we don't need it for replay.
        self.headers: Dict[str, str] = (
            {str(k).lower(): str(v) for k, v in headers.items()}
            if headers else {}
        )
        self.request_body: str = request_body or ""
        self.request_body_truncated: bool = bool(request_body_truncated)
        self.request_content_type: Optional[str] = request_content_type

        self.timestamp: float = time.time()

        # Optional persona attribution captured at request time. Used
        # by Verify Console (VC3) to render per-step prose that says
        # "as `admin`" / "as `jim`" — distinguishing successive requests
        # to the same URL from different identities. Calibration Run
        # #50 surfaced the need; without this, the bounty-report repro
        # steps for cross-principal IDOR were indistinguishable text.
        self.persona_at_capture: Optional[str] = None

        self.response_status: int = 0
        self.response_headers: Dict[str, str] = {}
        self.response_body: str = ""
        self.response_body_truncated: bool = False
        self.response_content_type: Optional[str] = None
        self.response_elapsed_ms: float = 0.0

        self.cookies_after_step: Dict[str, str] = {}

    # ─────────── response-side population (filled in by addon) ───────────

    def set_response(
        self,
        *,
        status: int,
        headers: Optional[Dict[str, str]] = None,
        body: Optional[str] = None,
        body_truncated: bool = False,
        content_type: Optional[str] = None,
        elapsed_ms: Optional[float] = None,
        cookies_after_step: Optional[Dict[str, str]] = None,
    ) -> None:
        """Populate the response side of the exchange.

        Called by the addon's response() handler. The request side was
        already populated when the addon's request() handler fired
        earlier; this fills in everything from the response.
        """
        self.response_status = int(status)
        if headers is not None:
            self.response_headers = {
                str(k).lower(): str(v) for k, v in headers.items()
            }
        if body is not None:
            self.response_body = body
        self.response_body_truncated = bool(body_truncated)
        if content_type is not None:
            self.response_content_type = content_type
        if elapsed_ms is not None:
            self.response_elapsed_ms = float(elapsed_ms)
        if cookies_after_step is not None:
            self.cookies_after_step = dict(cookies_after_step)

    # ─────────────────────── serialization ───────────────────────

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "method": self.method,
            "url": self.url,
            "params": dict(self.params),
            "headers": dict(self.headers),
            "request_body": self.request_body,
            "request_body_truncated": self.request_body_truncated,
            "request_content_type": self.request_content_type,
            "timestamp": self.timestamp,
            "persona_at_capture": self.persona_at_capture,
            "response_status": self.response_status,
            "response_headers": dict(self.response_headers),
            "response_body": self.response_body,
            "response_body_truncated": self.response_body_truncated,
            "response_content_type": self.response_content_type,
            "response_elapsed_ms": self.response_elapsed_ms,
            "cookies_after_step": dict(self.cookies_after_step),
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "FlowStep":
        step = cls(
            method=d.get("method", "GET"),
            url=d.get("url", ""),
            params=d.get("params", {}) or {},
            headers=d.get("headers", {}) or {},
            request_body=d.get("request_body", "") or "",
            request_body_truncated=bool(d.get("request_body_truncated", False)),
            request_content_type=d.get("request_content_type"),
        )
        # Restore identity + timestamps from the source (otherwise
        # serialization round-trip would generate a new id/ts).
        if "id" in d:
            step.id = d["id"]
        if "timestamp" in d:
            step.timestamp = float(d["timestamp"])
        if "persona_at_capture" in d:
            step.persona_at_capture = d["persona_at_capture"]
        # Restore the response side.
        step.response_status = int(d.get("response_status", 0) or 0)
        step.response_headers = dict(d.get("response_headers", {}) or {})
        step.response_body = d.get("response_body", "") or ""
        step.response_body_truncated = bool(d.get("response_body_truncated", False))
        step.response_content_type = d.get("response_content_type")
        step.response_elapsed_ms = float(d.get("response_elapsed_ms", 0) or 0)
        step.cookies_after_step = dict(d.get("cookies_after_step", {}) or {})
        return step


class UserFlow:
    """A named sequence of FlowSteps captured during one user journey."""

    def __init__(self, name: str, flow_id: Optional[str] = None):
        self.id: str = flow_id or str(uuid.uuid4())
        self.name = name
        self.steps: List[FlowStep] = []
        self.auth_tokens: Dict[str, str] = {}
        # Cookie jar accumulated across the flow. Updated step-by-step
        # by extract_cookies_from_response() so the latest snapshot
        # ends up on the FINAL step's cookies_after_step.
        self._cookie_jar: Dict[str, str] = {}
        self.created_at: float = time.time()

    def add_step(self, step: FlowStep) -> None:
        self.steps.append(step)

    def extract_tokens(self, headers: Dict[str, str]) -> None:
        """Pull common auth tokens from request headers."""
        for k, v in headers.items():
            if k.lower() in ("authorization", "cookie", "x-csrf-token"):
                self.auth_tokens[k] = v

    def update_cookie_jar_from_response(
        self,
        response_headers: Dict[str, str],
    ) -> Dict[str, str]:
        """Parse Set-Cookie headers and update the flow's running cookie
        jar. Returns the post-update snapshot for storage on the step.

        Note: Set-Cookie can appear multiple times in HTTP responses, but
        in our (headers: Dict) representation we already get the joined
        value if the proxy concatenates them. For most apps a single
        Set-Cookie per response is the common case; we handle multi via
        split-on-comma-then-semicolon (mitmproxy joins with ', ').
        """
        # Headers stored lowercased; look for 'set-cookie'.
        sc = response_headers.get("set-cookie")
        if sc:
            # Multiple Set-Cookie can be comma-joined; each cookie has
            # a `name=value` followed by attributes after ';'.
            for cookie_chunk in sc.split(","):
                first_attr = cookie_chunk.split(";", 1)[0].strip()
                if "=" in first_attr:
                    name, value = first_attr.split("=", 1)
                    name = name.strip()
                    value = value.strip()
                    if name:
                        self._cookie_jar[name] = value
        return dict(self._cookie_jar)

    # ─────────────────────── serialization ───────────────────────

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "created_at": self.created_at,
            "auth_tokens": dict(self.auth_tokens),
            "final_cookie_jar": dict(self._cookie_jar),
            "steps": [s.to_dict() for s in self.steps],
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "UserFlow":
        flow = cls(name=d.get("name", "unnamed"), flow_id=d.get("id"))
        flow.created_at = float(d.get("created_at", time.time()))
        flow.auth_tokens = dict(d.get("auth_tokens", {}) or {})
        flow._cookie_jar = dict(d.get("final_cookie_jar", {}) or {})
        for sd in d.get("steps", []):
            flow.add_step(FlowStep.from_dict(sd))
        return flow


class FlowMapper:
    """Singleton registry of active and persisted flows.

    Active flows live in `active_flows: Dict[flow_id, UserFlow]`. They're
    populated by the GhostAddon as traffic flows through the proxy.
    Persisted flows live on disk under `_flow_store_dir()` and can be
    loaded back into memory via `load_persisted(flow_id)`.

    Lifecycle:
      start_recording(name) → flow_id  (new in-memory UserFlow)
      record_request(flow_id, …)       (called per request by addon)
      finalize_step(step_id, …)        (called per response by addon)
      persist(flow_id)                  (write to disk; preserve in mem)
      load_persisted(flow_id)           (read from disk into memory)
      list_persisted()                  (enumerate on-disk flow ids+names)
    """

    _instance: Optional["FlowMapper"] = None

    @staticmethod
    def instance() -> "FlowMapper":
        if FlowMapper._instance is None:
            FlowMapper._instance = FlowMapper()
        return FlowMapper._instance

    def __init__(self):
        self.active_flows: Dict[str, UserFlow] = {}
        # Reverse map: step_id → flow_id, so the addon's response hook
        # can find which flow a step belongs to without a global scan.
        self._step_to_flow: Dict[str, str] = {}

    # ───────────────── recording (in-memory) ─────────────────

    def start_recording(self, flow_name: str) -> str:
        flow = UserFlow(flow_name)
        self.active_flows[flow.id] = flow
        return flow.id

    def record_request(
        self,
        flow_id: str,
        method: str,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        request_body: Optional[str] = None,
        request_body_truncated: bool = False,
        request_content_type: Optional[str] = None,
    ) -> Optional[str]:
        """Record a request side. Returns the new step_id, or None if
        the flow_id isn't recording."""
        flow = self.active_flows.get(flow_id)
        if flow is None:
            return None
        step = FlowStep(
            method=method,
            url=url,
            params=params,
            headers=headers,
            request_body=request_body,
            request_body_truncated=request_body_truncated,
            request_content_type=request_content_type,
        )
        flow.add_step(step)
        flow.extract_tokens(step.headers)
        self._step_to_flow[step.id] = flow_id
        return step.id

    def record_request_to_all(
        self,
        method: str,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        request_body: Optional[str] = None,
        request_body_truncated: bool = False,
        request_content_type: Optional[str] = None,
    ) -> List[str]:
        """Fan-out helper used by the addon: when traffic arrives, record
        it into EVERY currently-active flow. Returns the list of step_ids
        created (one per active flow). If no flows are recording, returns
        an empty list — addon just observes without capturing.
        """
        step_ids: List[str] = []
        for flow_id in list(self.active_flows.keys()):
            sid = self.record_request(
                flow_id=flow_id,
                method=method,
                url=url,
                params=params,
                headers=headers,
                request_body=request_body,
                request_body_truncated=request_body_truncated,
                request_content_type=request_content_type,
            )
            if sid is not None:
                step_ids.append(sid)
        return step_ids

    def finalize_step(
        self,
        step_id: str,
        *,
        status: int,
        headers: Optional[Dict[str, str]] = None,
        body: Optional[str] = None,
        body_truncated: bool = False,
        content_type: Optional[str] = None,
        elapsed_ms: Optional[float] = None,
    ) -> bool:
        """Populate the response side of a step. Called by the addon's
        response hook. Updates the owning flow's cookie jar and stores
        the post-step snapshot on the step.

        Returns True if the step was found and finalized; False if
        step_id was never registered (stale event, no-op)."""
        flow_id = self._step_to_flow.get(step_id)
        if flow_id is None:
            return False
        flow = self.active_flows.get(flow_id)
        if flow is None:
            return False
        # Find the step by id (steps are append-only, list is short).
        target_step: Optional[FlowStep] = None
        for s in flow.steps:
            if s.id == step_id:
                target_step = s
                break
        if target_step is None:
            return False
        post_step_jar = flow.update_cookie_jar_from_response(headers or {})
        target_step.set_response(
            status=status,
            headers=headers,
            body=body,
            body_truncated=body_truncated,
            content_type=content_type,
            elapsed_ms=elapsed_ms,
            cookies_after_step=post_step_jar,
        )
        return True

    # ───────────────── persistence (on-disk) ─────────────────

    def persist(self, flow_id: str) -> Optional[Path]:
        """Write the named in-memory flow to disk. Returns the path
        written, or None if flow_id isn't in active_flows.

        Atomic write semantics: write to a `.tmp` neighbor first, then
        os.replace to the final name. Operators inspecting the dir
        never see half-written files."""
        flow = self.active_flows.get(flow_id)
        if flow is None:
            return None
        store = _flow_store_dir()
        store.mkdir(parents=True, exist_ok=True)
        final = store / f"{flow_id}.json"
        tmp = store / f"{flow_id}.json.tmp"
        try:
            with tmp.open("w") as f:
                json.dump(flow.to_dict(), f, indent=2)
            os.replace(tmp, final)
        except Exception as e:
            logger.error(
                f"[FlowMapper] persist failed for {flow_id!r}: "
                f"{type(e).__name__}: {e}"
            )
            try:
                tmp.unlink()
            except OSError:
                pass
            return None
        logger.info(f"[FlowMapper] persisted flow {flow_id!r} → {final}")
        return final

    def load_persisted(self, flow_id: str) -> Optional[UserFlow]:
        """Load a persisted flow from disk into memory. If the flow is
        already in active_flows, return it; otherwise read from disk
        and register it. Returns None if no such persisted flow."""
        if flow_id in self.active_flows:
            return self.active_flows[flow_id]
        path = _flow_store_dir() / f"{flow_id}.json"
        if not path.exists():
            return None
        try:
            with path.open() as f:
                d = json.load(f)
            flow = UserFlow.from_dict(d)
        except Exception as e:
            logger.error(
                f"[FlowMapper] load_persisted failed for {flow_id!r}: "
                f"{type(e).__name__}: {e}"
            )
            return None
        self.active_flows[flow.id] = flow
        # Rebuild step→flow index for any steps in the loaded flow.
        for s in flow.steps:
            self._step_to_flow[s.id] = flow.id
        return flow

    def list_persisted(self) -> List[Dict[str, Any]]:
        """Enumerate on-disk flow summaries: id, name, step_count,
        created_at. Skips files that can't be parsed."""
        store = _flow_store_dir()
        if not store.exists():
            return []
        out: List[Dict[str, Any]] = []
        for p in sorted(store.glob("*.json")):
            try:
                with p.open() as f:
                    d = json.load(f)
                out.append({
                    "id": d.get("id"),
                    "name": d.get("name"),
                    "step_count": len(d.get("steps", [])),
                    "created_at": d.get("created_at"),
                    "has_auth_tokens": bool(d.get("auth_tokens")),
                })
            except Exception as e:
                logger.warning(
                    f"[FlowMapper] could not read persisted flow {p}: "
                    f"{type(e).__name__}: {e}"
                )
                continue
        return out

    # ───────────────── persona conversion (unchanged) ─────────────────

    def to_personas(self, base_url: str = "http://localhost:8000") -> List["Persona"]:
        """Convert recorded flows into Persona objects.

        Bearer tokens → PersonaType.USER + bearer_token.
        Cookies      → PersonaType.USER + cookie_jar.
        Always includes a single ANONYMOUS persona at the end.
        Skips flows with no steps or no extracted tokens.
        """
        from core.wraith.personas import Persona, PersonaType

        personas: List[Persona] = []
        for user_flow in self.active_flows.values():
            if not user_flow.steps or not user_flow.auth_tokens:
                continue

            flow_base_url = base_url
            try:
                first_url = user_flow.steps[0].url
                parsed = urlparse(first_url)
                if parsed.scheme and parsed.netloc:
                    flow_base_url = f"{parsed.scheme}://{parsed.netloc}"
            except (ValueError, AttributeError):
                pass

            # Bearer token persona.
            if "Authorization" in user_flow.auth_tokens or "authorization" in user_flow.auth_tokens:
                auth_header = (
                    user_flow.auth_tokens.get("Authorization")
                    or user_flow.auth_tokens.get("authorization")
                    or ""
                )
                if auth_header.startswith("Bearer "):
                    personas.append(Persona(
                        name=user_flow.name,
                        persona_type=PersonaType.USER,
                        bearer_token=auth_header[7:],
                        base_url=flow_base_url,
                    ))
                    continue

            # Cookie persona.
            cookie_header = (
                user_flow.auth_tokens.get("Cookie")
                or user_flow.auth_tokens.get("cookie")
            )
            if cookie_header:
                personas.append(Persona(
                    name=user_flow.name,
                    persona_type=PersonaType.USER,
                    cookie_jar=self._parse_cookie_string(cookie_header),
                    base_url=flow_base_url,
                ))
                continue

        personas.append(Persona(
            name="Anonymous",
            persona_type=PersonaType.ANONYMOUS,
            base_url=base_url,
        ))
        return personas

    @staticmethod
    def _parse_cookie_string(cookie_str: str) -> Dict[str, str]:
        out: Dict[str, str] = {}
        if not cookie_str:
            return out
        for part in cookie_str.split(";"):
            part = part.strip()
            if "=" in part:
                name, value = part.split("=", 1)
                out[name.strip()] = value.strip()
        return out
