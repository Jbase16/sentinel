"""Module api: inline documentation for /Users/jason/Developer/sentinelforge/core/server/api.py."""
#
# PURPOSE:
# This module is part of the server package in SentinelForge.
# [Specific purpose based on module name: api]
#
# KEY RESPONSIBILITIES:
# - [Automatically generated - review and enhance based on actual functionality]
#
# INTEGRATION:
# - Used by: [To be documented]
# - Depends on: [To be documented]
#

# core/api.py
# Production-grade FastAPI server (Hybrid Version)

from __future__ import annotations

import asyncio
import json
import logging
import os
import threading
import time
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, Iterable, List, Optional

import uvicorn
from fastapi import APIRouter, Depends, FastAPI, Query, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field, validator



from core.base.config import get_config, setup_logging, SecurityInterlock
from core.ai.ai_engine import AIEngine
from core.base.task_router import TaskRouter
from core.cortex.reasoning import reasoning_engine
from core.cortex.events import GraphEventType, get_event_bus, GraphEvent
from core.cortex.event_store import get_event_store
from core.wraith.evasion import WraithEngine
from core.ghost.flow import FlowMapper
from core.forge.compiler import ExploitCompiler
from core.forge.sandbox import SandboxRunner
from core.chat.chat_engine import GraphAwareChat
from core.base.action_dispatcher import ActionDispatcher
from core.ai.reporting import ReportComposer
from core.engine.pty_manager import PTYManager
from core.data.db import Database
from core.errors import SentinelError, ErrorCode

logger = logging.getLogger(__name__)

# Pre-bind security interlock: fail closed before uvicorn binds.
SecurityInterlock.verify_safe_boot(get_config())

# --- Models ---

class ScanRequest(BaseModel):
    """Class ScanRequest."""
    target: str = Field(..., min_length=1, max_length=2048)
    modules: Optional[List[str]] = None
    force: bool = False
    mode: str = "standard"  # Strategos mode: standard, bug_bounty, stealth

    @validator("target")
    def validate_target(cls, v: str) -> str:
        """Function validate_target."""
        v = v.strip()
        # Conditional branch.
        if not v:
            raise ValueError("Target cannot be empty")
        dangerous_patterns = [";", "&&", "||", "`", "$(", "\n", "\r"]
        # Loop over items.
        for pattern in dangerous_patterns:
            if pattern in v:
                raise ValueError(f"Invalid character in target: {pattern}")
        return v

    @validator("modules")
    def validate_modules(cls, v: Optional[List[str]]) -> Optional[List[str]]:
        """Function validate_modules."""
        if v is None:
            return v
        from core.toolkit.tools import TOOLS
        valid_tools = set(TOOLS.keys())
        invalid = [tool for tool in v if tool not in valid_tools]
        if invalid:
            raise ValueError(f"Invalid tool names: {', '.join(invalid)}. Valid tools: {', '.join(sorted(valid_tools))}")
        return v


class ChatRequest(BaseModel):
    """Class ChatRequest."""
    prompt: str = Field(..., min_length=1, max_length=32000)


# --- App Setup ---

app = FastAPI(
    title="SentinelForge API",
    description="AI-augmented offensive security platform",
    version="1.0.0",
)

# API Versioning: Create v1 router for all endpoints
# This allows future API versions to coexist without breaking existing clients
# All endpoints should be registered on the v1_router, not directly on app
v1_router = APIRouter(
    prefix="/v1",
    tags=["v1"],
    responses={404: {"description": "Not found"}},
)

security = HTTPBearer(auto_error=False)

# Exception handler for SentinelError
@app.exception_handler(SentinelError)
async def sentinel_error_handler(request: Request, exc: SentinelError):
    """Convert SentinelError to HTTPException for FastAPI."""
    logger.error(f"[API] {exc.code.value}: {exc.message}", extra=exc.details)
    return JSONResponse(
        status_code=exc.http_status,
        content=exc.to_dict()
    )

# --- Rate Limiting ---

class RateLimiter:
    """Class RateLimiter."""
    def __init__(self, requests_per_minute: int = 60):
        """Function __init__."""
        self.requests_per_minute = requests_per_minute
        self.requests: Dict[str, List[float]] = defaultdict(list)
        self._lock = threading.Lock()
    
    def is_allowed(self, key: str) -> bool:
        """Function is_allowed."""
        now = time.time()
        window = 60.0
        # Context-managed operation.
        with self._lock:
            self.requests[key] = [t for t in self.requests[key] if now - t < window]
            if len(self.requests[key]) >= self.requests_per_minute:
                return False
            self.requests[key].append(now)
            return True

_rate_limiter = RateLimiter()
_ai_rate_limiter = RateLimiter(requests_per_minute=10)

# --- State ---

_log_queue: asyncio.Queue = asyncio.Queue(maxsize=10000)
_api_loop: Optional[asyncio.AbstractEventLoop] = None
_scan_state: Dict[str, Any] = {}
_cancel_requested = threading.Event()


def _boot_manifest_path() -> Optional[str]:
    path = os.getenv("SENTINEL_BOOT_MANIFEST")
    return path if path else None


def _write_boot_manifest(state: str, detail: Optional[Dict[str, Any]] = None) -> None:
    manifest_path = _boot_manifest_path()
    if not manifest_path:
        return
    payload = {
        "state": state,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    if detail:
        payload.update(detail)
    try:
        os.makedirs(os.path.dirname(manifest_path), exist_ok=True)
        with open(manifest_path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)
    except Exception as exc:
        logger.warning(f"[BootManifest] Failed to write manifest: {exc}")
_active_scan_task: Optional[asyncio.Task] = None
_scan_lock = asyncio.Lock()

# from core.cortex.events import get_event_bus, GraphEventType  <-- Moved to top
# from core.cortex.events import get_event_bus, GraphEventType  <-- Moved to top (already done)
# from core.cortex.event_store import get_event_store <-- moved to top manually

# Initialize Store (which auto-subscribes to Bus)
_ = get_event_store()

# --- Session Manager ---

_session_manager: Dict[str, Any] = {}
_session_manager_lock = asyncio.Lock()
_session_cleanup_task: Optional[asyncio.Task] = None

async def register_session(session_id: str, session) -> None:
    """Register a session for tracking."""
    async with _session_manager_lock:
        _session_manager[session_id] = session

async def get_session(session_id: str):
    """Get a session by ID."""
    async with _session_manager_lock:
        return _session_manager.get(session_id)

async def unregister_session(session_id: str) -> None:
    """Unregister a session."""
    async with _session_manager_lock:
        if session_id in _session_manager:
            del _session_manager[session_id]

async def cleanup_old_sessions(max_age: timedelta = timedelta(days=1)) -> int:
    """
    Remove sessions older than max_age from the session manager.

    Args:
        max_age: Maximum age of a session before it's cleaned up (default 1 day)

    Returns:
        Number of sessions removed
    """
    now = datetime.now(timezone.utc)
    to_remove = []

    async with _session_manager_lock:
        for session_id, session in _session_manager.items():
            # Check if session has start_time attribute
            session_start = getattr(session, "start_time", None)
            if session_start:
                # Calculate age based on session start time
                if isinstance(session_start, (int, float)):
                    # Unix timestamp - convert to datetime
                    session_time = datetime.fromtimestamp(session_start, tz=timezone.utc)
                elif isinstance(session_start, datetime):
                    session_time = session_start
                else:
                    # Unknown format, skip this session
                    continue

                age = now - session_time
                if age > max_age:
                    to_remove.append(session_id)

        # Remove old sessions
        for session_id in to_remove:
            del _session_manager[session_id]

    return len(to_remove)

async def _session_cleanup_loop():
    """Background task that periodically cleans up old sessions."""
    while True:
        try:
            # Run cleanup every 24 hours
            await asyncio.sleep(86400)  # 24 hours in seconds
            removed = await cleanup_old_sessions()
            if removed > 0:
                logger.info(f"Session cleanup: removed {removed} old sessions")
        except asyncio.CancelledError:
            logger.info("Session cleanup task cancelled")
            break
        except Exception as e:
            logger.error(f"Session cleanup error: {e}")


async def _begin_scan(req: ScanRequest) -> str:
    """Start a scan using the single canonical, event-emitting path.

    Returns the created session id.
    """
    global _active_scan_task, _scan_state

    from core.base.session import ScanSession
    from core.cortex.events import get_event_bus
    from core.engine.scanner_engine import ScannerEngine
    from core.toolkit.tools import get_installed_tools

    async with _scan_lock:
        if _active_scan_task and not _active_scan_task.done():
            if req.force:
                logger.info("Force-killing active scan...")
                _cancel_requested.set()
                _active_scan_task.cancel()
                try:
                    await _active_scan_task
                except asyncio.CancelledError:
                    pass
                _active_scan_task = None
            else:
                raise SentinelError(
                    ErrorCode.SCAN_ALREADY_RUNNING,
                    "Cannot start scan while another is active",
                    details={"active_target": _scan_state.get("target")}
                )

        # Ensure any previous session is no longer addressable via /results.
        previous_session_id = _scan_state.get("session_id")
        if previous_session_id:
            try:
                await unregister_session(previous_session_id)
            except Exception:
                pass

        _cancel_requested.clear()

        session = ScanSession(req.target)
        session.set_external_log_sink(_log_sink_sync)
        await register_session(session.id, session)

        # Persist session to DB to satisfy foreign key constraints in findings/evidence tables
        # Note: save_session() is fire-and-forget (synchronous), no await needed
        Database.instance().save_session(session.to_dict())

        # Compute tool allowlist up-front so the UI can trust SCAN_STARTED payload immediately.
        installed_tools = list(get_installed_tools().keys())
        requested_tools = list(dict.fromkeys(req.modules or []))
        allowed_tools = (
            [t for t in requested_tools if t in installed_tools]
            if requested_tools
            else installed_tools
        )
        missing_tools = [t for t in requested_tools if t not in installed_tools]

        _scan_state = {
            "target": req.target,
            "modules": req.modules,
            "mode": req.mode,  # Strategos mode
            "status": "running",
            "started_at": datetime.now(timezone.utc).isoformat(),
            "session_id": session.id,
        }

        event_bus = get_event_bus()

        session.log(f"[Strategos] Installed tools: {len(installed_tools)}")
        if requested_tools:
            session.log(f"[Strategos] Custom tool whitelist: {', '.join(allowed_tools) or '(none)'}")
        if missing_tools:
            session.log(f"[Strategos] ⚠️ Requested tools not installed: {', '.join(missing_tools)}")

        event_bus.emit_scan_started(req.target, allowed_tools, session.id)

        async def _runner() -> None:
            """AsyncFunction _runner."""
            start_time = time.time()
            # Error handling block.
            try:

                async def dispatch_tool(tool: str) -> List[Dict]:
                    """AsyncFunction dispatch_tool."""
                    findings: List[Dict] = []
                    exit_code = 0
                    session.log(f"[Strategos] Dispatching tool: {tool}")
                    engine = ScannerEngine(session=session)

                    # Error handling block.
                    try:
                        event_bus.emit_tool_invoked(tool=tool, target=req.target, args=[])

                        if _cancel_requested.is_set():
                            exit_code = 130
                            return []

                        async for log_line in engine.scan(
                            req.target, selected_tools=[tool], cancel_flag=_cancel_requested
                        ):
                            session.log(log_line)

                        findings = engine.get_last_results() or []
                        exit_code = 130 if _cancel_requested.is_set() else 0
                        return findings
                    except asyncio.CancelledError:
                        _cancel_requested.set()
                        exit_code = 130
                        try:
                            await engine.shutdown(reason="cancelled")
                        except Exception:
                            pass
                        raise
                    except Exception as exc:
                        exit_code = 1
                        session.log(f"[Strategos] Tool failed ({tool}): {exc}")
                        try:
                            await engine.shutdown(reason="error")
                        except Exception:
                            pass
                        return []
                    finally:
                        try:
                            event_bus.emit_tool_completed(
                                tool=tool, exit_code=exit_code, findings_count=len(findings)
                            )
                        except Exception as emit_exc:
                            logger.error(
                                f"[EventBus] Failed to emit tool_completed for {tool}: {emit_exc}",
                                exc_info=True,
                            )

                mission = await reasoning_engine.start_scan(
                    target=req.target,
                    available_tools=allowed_tools,
                    mode=req.mode,
                    dispatch_tool=dispatch_tool,
                    log_fn=session.log
                )
                session.log(f"[Strategos] {mission.reason}")

                _scan_state["status"] = "completed"
                _scan_state["finished_at"] = datetime.now(timezone.utc).isoformat()
                _scan_state["summary"] = session.to_dict()

                duration = time.time() - start_time
                event_bus.emit_scan_completed("completed", len(session.findings.get_all()), duration)

            except asyncio.CancelledError:
                _scan_state["status"] = "cancelled"
                _scan_state["summary"] = session.to_dict()

                duration = time.time() - start_time
                event_bus.emit_scan_completed("cancelled", len(session.findings.get_all()), duration)

            except Exception as e:
                _scan_state["status"] = "error"
                _scan_state["error"] = str(e)
                _scan_state["summary"] = session.to_dict()
                logger.error(f"Scan error: {e}", exc_info=True)

                # Emit SCAN_FAILED event to notify UI and DecisionLedger
                try:
                    event_bus.emit(GraphEvent(
                        type=GraphEventType.SCAN_FAILED,
                        payload={"error": str(e), "target": req.target}
                    ))
                except Exception:
                    pass

        _active_scan_task = asyncio.create_task(_runner())
        return session.id

# --- Middleware & Auth ---

def get_client_ip(request: Request) -> str:
    """Function get_client_ip."""
    forwarded = request.headers.get("X-Forwarded-For")
    # Conditional branch.
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"

async def verify_token(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
) -> bool:
    """
    Standard token verification for regular API endpoints.

    Behavior:
    - If require_auth=False: Allow all requests (no token needed)
    - If require_auth=True: Require valid Bearer token
    """
    config = get_config()
    if not config.security.require_auth:
        return True
    if credentials is None:
        raise SentinelError(
            ErrorCode.AUTH_TOKEN_MISSING,
            "Authentication token required",
            details={"endpoint": str(request.url.path)}
        )
    if credentials.credentials != config.security.api_token:
        raise SentinelError(
            ErrorCode.AUTH_TOKEN_INVALID,
            "Invalid authentication token",
            details={"endpoint": str(request.url.path)}
        )
    return True


async def verify_sensitive_token(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
) -> bool:
    """
    STRICT token verification for sensitive/dangerous endpoints.

    These endpoints can execute arbitrary commands, compile exploits, or install
    software. They MUST require authentication when the API is network-exposed,
    regardless of the global require_auth setting.

    Endpoints protected by this dependency:
    - /ws/pty: Full terminal access
    - /forge/compile, /forge/execute: Exploit compilation
    - /tools/install, /tools/uninstall: Package management
    - /mission/start: Launch security scans

    Behavior:
    - If localhost (127.0.0.1): Respect require_auth setting (backward compatible)
    - If network-exposed: ALWAYS require valid Bearer token

    This is defense-in-depth - the boot interlock should prevent exposed+unauthenticated
    configurations, but this provides an additional safety layer.
    """
    from core.base.config import is_network_exposed

    config = get_config()
    is_exposed = is_network_exposed(config.api_host)

    # If exposed to network, ALWAYS require token (defense-in-depth)
    # If localhost, respect the require_auth setting for backward compatibility
    require_token = is_exposed or config.security.require_auth

    if not require_token:
        return True

    if credentials is None:
        raise SentinelError(
            ErrorCode.AUTH_TOKEN_MISSING,
            "Authentication token required for sensitive endpoint",
            details={
                "endpoint": str(request.url.path),
                "reason": "network_exposed" if is_exposed else "require_auth_enabled"
            }
        )
    if credentials.credentials != config.security.api_token:
        raise SentinelError(
            ErrorCode.AUTH_TOKEN_INVALID,
            "Invalid authentication token",
            details={"endpoint": str(request.url.path)}
        )
    return True

async def check_rate_limit(request: Request) -> None:
    """AsyncFunction check_rate_limit."""
    # Conditional branch.
    if not _rate_limiter.is_allowed(get_client_ip(request)):
        raise SentinelError(
            ErrorCode.AUTH_RATE_LIMIT_EXCEEDED,
            "Rate limit exceeded",
            details={"endpoint": str(request.url.path), "client_ip": get_client_ip(request)}
        )

async def check_ai_rate_limit(request: Request) -> None:
    """AsyncFunction check_ai_rate_limit."""
    # Conditional branch.
    if not _ai_rate_limiter.is_allowed(get_client_ip(request)):
        raise SentinelError(
            ErrorCode.AI_RATE_LIMIT_EXCEEDED,
            "AI rate limit exceeded",
            details={"endpoint": str(request.url.path), "client_ip": get_client_ip(request)}
        )

@app.on_event("startup")
async def startup_event():
    """
    FastAPI startup event handler.

    This is the first code that runs when the server starts. We use it to:
    1. Initialize logging
    2. Initialize database
    3. Start background tasks

    The security interlock runs at import time to prevent pre-bind exposure.
    """
    global _api_loop, _session_cleanup_task
    config = get_config()

    setup_logging(config)
    logger.info(f"SentinelForge API Starting on {config.api_host}:{config.api_port}")
    _write_boot_manifest(
        "starting",
        {
            "pid": os.getpid(),
            "api_host": config.api_host,
            "api_port": config.api_port,
            "require_auth": config.security.require_auth,
            "ai_provider": config.ai.provider,
            "ollama_url": config.ai.ollama_url,
        },
    )

    # Error handling block.
    try:
        _api_loop = asyncio.get_running_loop()
    except RuntimeError:
        _api_loop = None

    # Async DB Init
    db = Database.instance()
    await db.init()  # Ensure DB is ready before requests

    # Initialize global event sequence counter from database
    # This ensures event IDs remain unique across restarts (one continuous logical brain)
    from core.cortex.events import initialize_event_sequence_from_db
    await initialize_event_sequence_from_db()

    # Start session cleanup task
    _session_cleanup_task = asyncio.create_task(_session_cleanup_loop())
    logger.info("Session cleanup task started")
    _write_boot_manifest("ready")

@app.on_event("shutdown")
async def shutdown_event():
    """AsyncFunction shutdown_event."""
    global _session_cleanup_task
    logger.info("SentinelForge API Shutting Down...")
    _write_boot_manifest("stopping")

    # Cancel session cleanup task
    if _session_cleanup_task and not _session_cleanup_task.done():
        _session_cleanup_task.cancel()
        try:
            await _session_cleanup_task
        except asyncio.CancelledError:
            pass

    from core.data.blackbox import BlackBox
    await BlackBox.instance().shutdown()

    # Persist final sequence counter to GlobalSequenceAuthority
    # This ensures continuity across restarts for both Events and Decisions
    from core.base.sequence import GlobalSequenceAuthority
    await GlobalSequenceAuthority.persist_to_db()

    # Close database connection
    db = Database.instance()
    await db.close()
    _write_boot_manifest("stopped")

def is_origin_allowed(origin: str, allowed_patterns: Iterable[str]) -> bool:
    """
    Check if an origin matches any of the allowed patterns.

    Patterns support:
    - Exact matches: "https://example.com"
    - Wildcard ports: "http://localhost:*" matches any port on localhost

    Args:
        origin: The Origin header value to validate
        allowed_patterns: Iterable of allowed origin patterns (tuple, list, etc.)

    Returns:
        True if origin matches any pattern, False otherwise
    """
    from urllib.parse import urlparse

    if not origin:
        return False

    parsed = urlparse(origin)
    origin_netloc = parsed.netloc

    for pattern in allowed_patterns:
        parsed_pattern = urlparse(pattern)

        # Scheme must match exactly
        if parsed.scheme != parsed_pattern.scheme:
            continue

        # Check if pattern has wildcard port
        pattern_netloc = parsed_pattern.netloc
        if pattern_netloc.endswith(":*"):
            # Match hostname, ignore port
            pattern_host = pattern_netloc[:-2]
            if origin_netloc == pattern_host or origin_netloc.startswith(f"{pattern_host}:"):
                return True
        elif pattern_netloc == "localhost" and parsed.hostname == "localhost":
            # Special case for tauri://localhost pattern
            return True
        elif origin_netloc == pattern_netloc:
            # Exact match
            return True

    return False


def setup_cors():
    """
    Setup CORS with dynamic origin validation.

    When credentials are enabled, CORS spec requires exact origin matches
    (no wildcards). We use a custom middleware to validate patterns like
    "http://localhost:*" and return the exact origin in responses.
    """
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.responses import Response

    config = get_config()
    allowed_patterns = config.security.allowed_origins

    class DynamicCORSMiddleware(BaseHTTPMiddleware):
        """CORS middleware that supports wildcard patterns with credentials."""

        async def dispatch(self, request, call_next):
            origin = request.headers.get("origin")

            # Early return for preflight requests (more efficient)
            if request.method == "OPTIONS":
                if origin and is_origin_allowed(origin, allowed_patterns):
                    # Return preflight response immediately without calling downstream
                    return Response(
                        status=200,
                        headers={
                            "Access-Control-Allow-Origin": origin,
                            "Access-Control-Allow-Credentials": "true",
                            "Access-Control-Allow-Methods": "*",
                            "Access-Control-Allow-Headers": "*",
                            "Access-Control-Expose-Headers": "*",
                            "Access-Control-Max-Age": "600",
                        }
                    )
                else:
                    # Origin not allowed for preflight - return 403 explicitly
                    return Response(status=403)

            # For non-OPTIONS requests with valid origin
            if origin and is_origin_allowed(origin, allowed_patterns):
                # Call downstream handler, then add CORS headers
                response = await call_next(request)
                response.headers["Access-Control-Allow-Origin"] = origin
                response.headers["Access-Control-Allow-Credentials"] = "true"
                response.headers["Access-Control-Allow-Methods"] = "*"
                response.headers["Access-Control-Allow-Headers"] = "*"
                response.headers["Access-Control-Expose-Headers"] = "*"
                response.headers["Access-Control-Max-Age"] = "600"
                return response
            else:
                # Origin not allowed or no origin header - pass through
                return await call_next(request)

    app.add_middleware(DynamicCORSMiddleware)
setup_cors()


# ============================================================================
# WebSocket Security Layer
# ============================================================================
#
# THREAT MODEL FOR WEBSOCKET ENDPOINTS
# -------------------------------------
#
# What We Protect Against:
#   - CSRF-style attacks from malicious websites embedding our WS URLs
#   - Unauthorized remote access to sensitive operations (terminal, graph state)
#   - Information disclosure via WebSocket protocol confusion
#
# What We DON'T Protect Against (by design):
#   - Compromised local machine (attacker has code execution locally)
#   - Malicious local process with access to localhost
#   - Browser extension attacks (same-origin JS is our trust boundary)
#
# SentinelForge's Deployment Context:
#   - Local-first: Typically runs on localhost or trusted desktop (Tauri)
#   - Operator-driven: Authenticated user is also the system operator
#   - Not a multi-tenant SaaS: No untrusted third-party users
#   - Developer tools: Target audience understands security tradeoffs
#
# Security Strategy:
#   1. Origin validation: Prevent CSRF from external websites
#      - Uses wildcard-aware matcher (http://localhost:*, tauri://localhost)
#      - Origin is a CSRF control, NOT authentication
#
#   2. Optional token-based auth: For production/remote deployments
#      - Token passed via query param: ws://host/ws/endpoint?token=xxx
#      - Controlled by require_auth and terminal_require_auth config flags
#      - Note: Query params may leak in logs; acceptable for local tools
#
#   3. Per-endpoint authorization:
#      - /ws/graph: Read-only graph state (token if require_auth)
#      - /ws/terminal: Read-only terminal output (token if terminal_require_auth)
#      - /ws/pty: Full bidirectional PTY access (token if terminal_require_auth)
#
# Why This Level of Security is Sufficient:
#   - Origin checks prevent drive-by attacks from malicious websites
#   - Optional tokens enable hardening for remote/prod deployments
#   - Local dev workflows remain frictionless
#   - No "security theater" - controls match actual threat landscape
#
# Future Hardening Options (if deployment model changes):
#   - WebSocket subprotocol-based auth (more complex, no logging leakage)
#   - Signed JWT tokens instead of shared secret
#   - Per-connection rate limiting (typically done at reverse proxy)
#   - Connection IP allowlisting
#
# ============================================================================


async def validate_websocket_connection(
    websocket: WebSocket,
    endpoint_name: str,
    *,
    require_token: bool = False,
) -> bool:
    """
    Validate WebSocket connection security before accepting.

    This is the SINGLE authoritative security check for all WebSocket endpoints.
    All endpoints MUST use this helper to ensure consistent security posture.

    Args:
        websocket: The WebSocket connection to validate
        endpoint_name: Friendly name for logging (e.g., "/ws/pty")
        require_token: Whether to require auth token (defaults to False)

    Returns:
        True if connection should be accepted, False if rejected

    Side effects:
        - Logs security denials with context
        - Closes WebSocket with appropriate close code on rejection:
            * 4003: Origin not allowed (CSRF protection)
            * 4001: Unauthorized (invalid/missing token)

    Usage example:
        ```python
        @app.websocket("/ws/example")
        async def ws_example(websocket: WebSocket):
            if not await validate_websocket_connection(websocket, "/ws/example"):
                return  # Connection was closed by validator
            await websocket.accept()
            # ... handle connection
        ```
    """
    config = get_config()

    # Step 1: Validate Origin (CSRF protection)
    # WebSockets bypass CORS, so we must check manually
    # Skip origin validation in dev mode (require_auth=False) for convenience
    origin = websocket.headers.get("origin")
    if config.security.require_auth and origin and not is_origin_allowed(origin, config.security.allowed_origins):
        logger.warning(
            f"[WebSocket] {endpoint_name} denied origin: {origin} "
            f"(allowed: {config.security.allowed_origins})"
        )
        await websocket.close(code=4003, reason="Origin not allowed")
        return False

    # Step 2: Optional token validation
    if require_token:
        token = websocket.query_params.get("token")
        if not token or token != config.security.api_token:
            logger.warning(
                f"[WebSocket] {endpoint_name} denied: invalid or missing token "
                f"(require_auth={config.security.require_auth}, "
                f"terminal_require_auth={config.security.terminal_require_auth})"
            )
            await websocket.close(code=4001, reason="Unauthorized")
            return False

    return True


# NOTE: /ws/pty endpoint is defined below (line ~1357) with full PTY implementation
# including resize support and bidirectional communication.

# --- Helpers ---

def _log_sink_sync(msg: str) -> None:
    """Function _log_sink_sync."""
    loop: Optional[asyncio.AbstractEventLoop] = None
    # Error handling block.
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = _api_loop

    # Conditional branch.
    if loop is not None:
        try:
            def _enqueue_or_warn():
                if _log_queue.full():
                    logger.warning(f"Log queue overflow, dropping entry. Queue size: {_log_queue.maxsize}")
                else:
                    _log_queue.put_nowait(msg)

            loop.call_soon_threadsafe(_enqueue_or_warn)
        except Exception:
            pass

    # Bridge log to EventBus (Unified Path)
    try:
        get_event_bus().emit(GraphEvent(
            type=GraphEventType.LOG,  # Need to ensure LOG type exists or use generic
            payload={"line": msg}
        ))
    except Exception:
        pass
        
    # Error handling block.
    try:
        # Legacy bridge for TaskRouter (cleanup later?)
        event_payload = {"line": msg}
        TaskRouter.instance().ui_event.emit("log", event_payload)
    except Exception:
        pass

def _ai_status() -> Dict[str, Any]:
    """Function _ai_status."""
    # Error handling block.
    try:
        return AIEngine.instance().status()
    except Exception as e:
        return {"connected": False, "error": str(e)}

def _get_latest_results_sync() -> Dict[str, Any]:
    """Synchronous version for non-async contexts."""
    from core.data.findings_store import findings_store
    from core.data.issues_store import issues_store
    from core.data.killchain_store import killchain_store
    return {
        "findings": findings_store.get_all(),
        "issues": issues_store.get_all(),
        "killchain_edges": killchain_store.get_all(),
        "scan": _scan_state,
    }

async def _get_latest_results() -> Dict[str, Any]:
    """AsyncFunction _get_latest_results."""
    from core.data.findings_store import findings_store
    from core.data.issues_store import issues_store
    from core.data.killchain_store import killchain_store
    
    # Use session-scoped stores if available, otherwise fallback to global singletons
    session_id = _scan_state.get("session_id")
    
    # Conditional branch.
    if session_id:
        # Session-based query using session manager
        session = await get_session(session_id)
        if session:
            return {
                "findings": session.findings.get_all(),
                "issues": session.issues.get_all(),
                "killchain": {"edges": session.killchain.get_all()},  # Nested to match Swift
                "scan": _scan_state,
                "session_id": session_id,
            }
    
    # Fallback to global stores (legacy behavior or no session)
    return {
        "findings": findings_store.get_all(),
        "issues": issues_store.get_all(),
        "killchain": {"edges": killchain_store.get_all()},  # Nested to match Swift Killchain struct
        "scan": _scan_state,
    }

# ============================================================================
# API Versioning: v1 Routes
# ============================================================================
# All new endpoints should be registered on v1_router with /v1 prefix
# This allows future API versions to be introduced without breaking existing clients
#
# Example:
#   @v1_router.get("/status")  # -> /v1/status
#   async def get_status_v1(): ...
#
# Legacy routes (without /v1 prefix) are kept for backward compatibility
# ============================================================================

@v1_router.get("/ping")
async def ping_v1():
    """API v1: Health check endpoint."""
    return {"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()}

@v1_router.get("/status")
async def get_status_v1(_: bool = Depends(verify_token)):
    """API v1: Get system status including scan state, AI health, and tool installation."""
    from core.toolkit.tools import get_installed_tools, TOOLS
    installed = get_installed_tools()
    all_tools = list(TOOLS.keys())
    missing = [t for t in all_tools if t not in installed]

    return {
        "status": "ok",
        "scan_running": _active_scan_task is not None and not _active_scan_task.done(),
        "latest_target": _scan_state.get("target"),
        "ai": _ai_status(),
        "tools": {
            "installed": list(installed.keys()),
            "missing": missing,
            "count_installed": len(installed),
            "count_total": len(all_tools),
        },
    }

@v1_router.get("/tools/status")
async def tools_status_v1(_: bool = Depends(verify_token)):
    """API v1: Get installed tools status."""
    from core.toolkit.tools import get_installed_tools, TOOLS
    installed = get_installed_tools()
    all_tools = list(TOOLS.keys())
    missing = [t for t in all_tools if t not in installed]
    payload = {
        "installed": list(installed.keys()),
        "missing": missing,
        "count_installed": len(installed),
        "count_total": len(all_tools),
    }
    # Also emit a UI event so the Tools tab can update via SSE if connected
    try:
        TaskRouter.instance().emit_ui_event("tools_status", payload)
    except Exception:
        pass
    return {"tools": payload}

@v1_router.get("/logs")
async def get_logs_v1(limit: int = 100, _: bool = Depends(verify_token)):
    """API v1: Get scan logs."""
    lines = []
    session_id = _scan_state.get("session_id")

    # First try to get session-specific logs
    if session_id:
        session = await get_session(session_id)
        if session and hasattr(session, "logs"):
            # Return session logs (most recent first, respecting limit)
            lines = session.logs[-limit:] if len(session.logs) > limit else session.logs
            if lines:
                return {"lines": lines, "session_id": session_id}

    # Fallback to global queue for legacy behavior
    while not _log_queue.empty() and len(lines) < limit:
        lines.append(_log_queue.get_nowait())
    return {"lines": lines}

@v1_router.get("/results")
async def get_results_v1(_: bool = Depends(verify_token)):
    """API v1: Get scan results including findings, issues, and killchain data."""
    from core.data.findings_store import findings_store
    from core.data.issues_store import issues_store
    from core.data.killchain_store import killchain_store
    
    # If there's an active scan with a session, return session-specific results
    session_id = _scan_state.get("session_id")
    if session_id:
        session = await get_session(session_id)
        if session:
            return {
                "findings": session.findings.get_all(),
                "issues": session.issues.get_all(),
                "killchain": {"edges": session.killchain.get_all()},
                "session_id": session_id,
            }

    # Fallback to global stores (legacy behavior or no session)
    return {
        "findings": findings_store.get_all(),
        "issues": issues_store.get_all(),
        "killchain": {"edges": killchain_store.get_all()},
        "scan": _scan_state,
    }


# ============================================================================
# Legacy Routes (without /v1 prefix) - Kept for backward compatibility
# ============================================================================
# These routes are DEPRECATED and will be removed in a future version.
# Please migrate to use the /v1 prefixed endpoints.
# ============================================================================

@app.get("/ping")
async def ping():
    """
    DEPRECATED: Use /v1/ping instead.
    Health check endpoint.
    """
    return await ping_v1()

@app.get("/status")
async def get_status(_: bool = Depends(verify_token)):
    """
    DEPRECATED: Use /v1/status instead.
    Get system status.
    """
    return await get_status_v1(_)

@app.get("/tools/status")
async def tools_status(_: bool = Depends(verify_token)):
    """
    DEPRECATED: Use /v1/tools/status instead.
    Get tools status.
    """
    return await tools_status_v1(_)

@app.get("/logs")
async def get_logs(limit: int = 100, _: bool = Depends(verify_token)):
    """
    DEPRECATED: Use /v1/logs instead.
    Get scan logs.
    """
    return await get_logs_v1(limit, _)

@app.get("/results")
async def get_results(_: bool = Depends(verify_token)):
    """
    DEPRECATED: Use /v1/results instead.
    Get scan results.
    """
    return await get_results_v1(_)

@v1_router.get("/cortex/graph")
@app.get("/cortex/graph")
async def get_cortex_graph(_: bool = Depends(verify_token)):
    """AsyncFunction get_cortex_graph."""
    from core.cortex.memory import KnowledgeGraph
    return KnowledgeGraph.instance().export_json()

@v1_router.get("/cortex/reasoning")
@app.get("/cortex/reasoning")
async def get_cortex_reasoning(_: bool = Depends(verify_token)):
    """AsyncFunction get_cortex_reasoning."""
    return reasoning_engine.analyze()

# --- God-Tier Endpoints ---

@v1_router.post("/wraith/evade")
@app.post("/wraith/evade")
async def wraith_evade(
    target: str, 
    payload: str, 
    _: bool = Depends(verify_token)
):
    """
    Trigger the Autonomous Evasion Loop.
    """
    import httpx
    async with httpx.AsyncClient() as client:
        return await WraithEngine.instance().stealth_send(client, target, "GET", payload)

@v1_router.post("/ghost/record/{flow_name}")
@app.post("/ghost/record/{flow_name}")
async def ghost_record(flow_name: str, _: bool = Depends(verify_token)):
    """
    Start recording a user flow for Logic Fuzzing.
    """
    fid = FlowMapper.instance().start_recording(flow_name)
    return {"status": "recording", "flow_id": fid}

# --- Ghost Protocol Control ---

@v1_router.post("/ghost/start")
@app.post("/ghost/start")
async def ghost_start(port: int = 8080, _: bool = Depends(verify_token)):
    """Start the passive interception proxy (Lazarus Engine enabled)."""
    from core.ghost.proxy import GhostInterceptor
    from core.base.session import ScanSession
    
    # We need a session for the proxy to log to. Use a global 'ghost' session.
    # Check if we have one?
    global _scan_state
    session_id = _scan_state.get("session_id")
    session = await get_session(session_id) if session_id else None
    
    # Conditional branch.
    if not session:
        # Create a dedicated Ghost session if no scan is active
        session = ScanSession("ghost-mode")
        await register_session(session.id, session)
        _scan_state["session_id"] = session.id # Track it
        
    # Ideally store the interceptor instance somewhere global or in session
    if not hasattr(app.state, "ghost"):
        app.state.ghost = GhostInterceptor(session, port=port)
        await app.state.ghost.start()
        return {"status": "started", "port": app.state.ghost.port}
    else:
        return {"status": "already_running", "port": app.state.ghost.port}

@v1_router.post("/ghost/stop")
@app.post("/ghost/stop")
async def ghost_stop(_: bool = Depends(verify_token)):
    """Stop the passive interception proxy."""
    # Conditional branch.
    if hasattr(app.state, "ghost") and app.state.ghost:
        app.state.ghost.stop()
        del app.state.ghost
        return {"status": "stopped"}
    return {"status": "not_running"}

@v1_router.post("/forge/compile")
@app.post("/forge/compile")
async def forge_compile(
    target: str,
    anomaly: str,
    _: bool = Depends(verify_sensitive_token)  # SENSITIVE: Always requires auth when exposed
):
    """
    Trigger the JIT Exploit Compiler.

    SECURITY: This endpoint compiles exploit code and is protected by
    verify_sensitive_token which ALWAYS requires auth when network-exposed.
    """
    # Error handling block.
    try:
        script_path = ExploitCompiler.instance().compile_exploit(target, anomaly)
        return {"status": "compiled", "script_path": script_path}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@v1_router.post("/forge/execute")
@app.post("/forge/execute")
async def forge_execute(
    script_path: str,
    _: bool = Depends(verify_sensitive_token)  # SENSITIVE: Always requires auth when exposed
):
    """
    Execute a compiled exploit in the sandbox.

    SECURITY: This endpoint executes exploit code and is protected by
    verify_sensitive_token which ALWAYS requires auth when network-exposed.
    """
    result = await SandboxRunner.run(script_path)
    return result

# --- Command Deck Endpoints ---

class InstallRequest(BaseModel):
    """Class InstallRequest."""
    tools: List[str]

    @validator("tools")
    def validate_tools(cls, v: List[str]) -> List[str]:
        """Function validate_tools."""
        from core.toolkit.tools import TOOLS
        valid_tools = set(TOOLS.keys())
        invalid = [tool for tool in v if tool not in valid_tools]
        if invalid:
            raise ValueError(f"Invalid tool names: {', '.join(invalid)}. Valid tools: {', '.join(sorted(valid_tools))}")
        return v

@v1_router.post("/tools/install")
@app.post("/tools/install")
async def tools_install(req: InstallRequest, _: bool = Depends(verify_sensitive_token)):
    """
    Install selected tools using Homebrew or pip (best-effort).
    Returns per-tool status. The process output tail is included for diagnostics.

    SECURITY: This endpoint installs system packages and is protected by
    verify_sensitive_token which ALWAYS requires auth when network-exposed.
    """
    from core.toolkit.tools import install_tools, get_installed_tools, TOOLS
    # Notify UI: installation started
    try:
        TaskRouter.instance().emit_ui_event("tools_install_started", {"tools": req.tools})
    except Exception:
        pass

    results = await install_tools(req.tools)

    # Compute updated tool status
    installed = get_installed_tools()
    all_tools = list(TOOLS.keys())
    missing = [t for t in all_tools if t not in installed]
    status_payload = {
        "installed": list(installed.keys()),
        "missing": missing,
        "count_installed": len(installed),
        "count_total": len(all_tools),
    }

    # Emit UI events so the Tools tab updates live
    try:
        TaskRouter.instance().emit_ui_event("tools_install_result", {"results": results})
        TaskRouter.instance().emit_ui_event("tools_status", status_payload)
    except Exception:
        pass

    return {"results": results, "tools": status_payload}

@v1_router.post("/tools/uninstall")
@app.post("/tools/uninstall")
async def tools_uninstall(req: InstallRequest, _: bool = Depends(verify_sensitive_token)):
    """
    Uninstall selected tools using Homebrew or pip (best-effort).

    SECURITY: This endpoint removes system packages and is protected by
    verify_sensitive_token which ALWAYS requires auth when network-exposed.
    """
    from core.toolkit.tools import uninstall_tools, get_installed_tools, TOOLS
    
    results = await uninstall_tools(req.tools)

    # Compute updated tool status
    installed = get_installed_tools()
    all_tools = list(TOOLS.keys())
    missing = [t for t in all_tools if t not in installed]
    status_payload = {
        "installed": list(installed.keys()),
        "missing": missing,
        "count_installed": len(installed),
        "count_total": len(all_tools),
    }

    # Emit UI events
    try:
        TaskRouter.instance().emit_ui_event("tools_status", status_payload)
    except Exception:
        pass

    return {"results": results, "tools": status_payload}

@v1_router.post("/chat/query")
@app.post("/chat/query")
async def chat_query(
    question: str,
    _: bool = Depends(verify_token)
):
    """
    Context-Aware RAG Chat.
    """
    answer = GraphAwareChat.instance().query(question)
    return {"response": answer}

@v1_router.post("/mission/start")
@app.post("/mission/start")
async def mission_start(
    target: str,
    mode: str = "standard",
    force: bool = True,
    _: bool = Depends(verify_sensitive_token),  # SENSITIVE: Always requires auth when exposed
    __: None = Depends(check_rate_limit),
):
    """
    The ONE-CLICK Button. Starts the full autonomous loop.

    SECURITY: This endpoint launches security scans against targets and is
    protected by verify_sensitive_token which ALWAYS requires auth when
    network-exposed. Prevents unauthorized reconnaissance operations.
    """
    req = ScanRequest(target=target, modules=None, force=force, mode=mode)
    session_id = await _begin_scan(req)
    return JSONResponse(
        {"status": "started", "mission_id": session_id, "session_id": session_id, "target": req.target},
        status_code=202,
    )

# --- WebSockets ---

@v1_router.websocket("/ws/graph")
@app.websocket("/ws/graph")
async def ws_graph_endpoint(websocket: WebSocket):
    """
    WebSocket endpoint for real-time graph state streaming.

    Uses validate_websocket_connection() for consistent security.
    Requires token if require_auth is enabled in config.

    Available at:
    - /v1/ws/graph (versioned, recommended)
    - /ws/graph (legacy, will be deprecated)
    """
    # Validate connection using the centralized security helper
    if not await validate_websocket_connection(
        websocket,
        "/ws/graph",
        require_token=get_config().security.require_auth,
    ):
        return  # Connection was closed by validator

    await websocket.accept()
    from core.cortex.memory import KnowledgeGraph
    # Error handling block.
    try:
        while True:
            # Stream the graph state every 500ms
            graph_data = KnowledgeGraph.instance().export_json()
            await websocket.send_json(graph_data)
            await asyncio.sleep(0.5)
    except WebSocketDisconnect:
        logger.info("Graph WS disconnected")

@v1_router.websocket("/ws/terminal")
@app.websocket("/ws/terminal")
async def ws_terminal_endpoint(
    websocket: WebSocket, session_id: Optional[str] = Query(None)
):
    """
    WebSocket endpoint for terminal output streaming.

    Uses validate_websocket_connection() for consistent security.
    Requires token if terminal_require_auth is enabled in config.

    Available at:
    - /v1/ws/terminal (versioned, recommended)
    - /ws/terminal (legacy, will be deprecated)
    """
    config = get_config()

    # Validate connection using the centralized security helper
    if not await validate_websocket_connection(
        websocket,
        "/ws/terminal",
        require_token=config.security.terminal_require_auth,
    ):
        return  # Connection was closed by validator

    # Additional endpoint-specific check: terminal_enabled
    if not config.security.terminal_enabled:
        await websocket.close(code=4003, reason="Terminal access disabled")
        return

    await websocket.accept()
    manager = PTYManager.instance()
    # Use provided session_id or create a new session
    if session_id:
        session = manager.get_or_create_session(session_id)
    else:
        session = manager.create_session()

    # Simple loop to pipe PTY output to WS
    try:
        while True:
            output = session.read()
            if output:
                await websocket.send_text(output.decode(errors="ignore"))
            await asyncio.sleep(0.05)
    except WebSocketDisconnect:
        pass

@v1_router.post("/scan")
@app.post("/scan")
async def start_scan(
    req: ScanRequest,
    _: bool = Depends(verify_token),
    __: None = Depends(check_rate_limit),
):
    """AsyncFunction start_scan."""
    session_id = await _begin_scan(req)
    return JSONResponse(
        {"status": "started", "target": req.target, "session_id": session_id},
        status_code=202,
    )

@v1_router.post("/cancel")
@app.post("/cancel")
async def cancel_scan(_: bool = Depends(verify_token)):
    """AsyncFunction cancel_scan."""
    # Conditional branch.
    if _active_scan_task and not _active_scan_task.done():
        _cancel_requested.set()
        _active_scan_task.cancel()
        return JSONResponse({"status": "cancelling"}, status_code=202)
    raise SentinelError(
        ErrorCode.SCAN_SESSION_NOT_FOUND,
        "No active scan to cancel",
        details={}
    )

@v1_router.post("/chat")
@app.post("/chat")
async def chat(
    req: ChatRequest,
    request: Request,
    _: bool = Depends(verify_token),
    __: None = Depends(check_ai_rate_limit),
):
    """AsyncFunction chat."""
    async def _stream():
        """AsyncFunction _stream."""
        full_response = ""
        # Error handling block.
        try:
            for token in AIEngine.instance().stream_chat(req.prompt):
                if await request.is_disconnected():
                    break
                
                full_response += token
                payload = json.dumps({"token": token})
                yield f"data: {payload}\n\n"
            
            # Parse EXEC commands only after streaming completes
            # This avoids issues with JSON split across tokens
            for line in full_response.splitlines():
                if ">>> EXEC:" in line:
                    try:
                        clean_line = line.strip()
                        if clean_line.startswith(">>> EXEC:"):
                            json_str = clean_line.replace(">>> EXEC:", "").strip()
                            action = json.loads(json_str)
                            dispatcher = ActionDispatcher.instance()
                            target = _scan_state.get("target") or "manual-interaction"
                            status = dispatcher.request_action(action, target)
                            if status != "DROPPED":
                                logger.info(f"Action Requested: {action} -> {status}")
                    except json.JSONDecodeError:
                        pass
            
            yield "data: [DONE]\n\n"
        except Exception as e:
            logger.error(f"Chat error: {e}")
            yield f"data: {json.dumps({'error': str(e)})}\n\n"
            yield "data: [DONE]\n\n"

    return StreamingResponse(_stream(), media_type="text/event-stream")

@v1_router.get("/events")
@app.get("/events")
async def events(request: Request, _: bool = Depends(verify_token)):
    """
    Unified SSE stream (Legacy Alias).
    Delegates to the same logic as /events/stream but without history replay (since=0).
    """
    # Reuse the same generator logic
    return await events_stream(request=request, since=0)


# ============================================================================
# Event-Sourced Reactive Graph Stream (ESRG)
# ============================================================================

@v1_router.get("/events/stream")
@app.get("/events/stream")
async def events_stream(
    request: Request,
    since: int = Query(default=0, description="Sequence number to replay from"),
    _: bool = Depends(verify_token),
):
    """
    Unified SSE stream for all graph events.
    
    This is the primary real-time API for the UI. It:
    1. Replays missed events from `since` sequence
    2. Streams new events as they occur
    3. Sends keepalives every 15s to maintain connection
    
    Event format:
        event: <event_type>
        data: {"sequence": N, "type": "...", "payload": {...}, "timestamp": ...}
    
    The client should track the highest `sequence` received and use it
    as the `since` parameter on reconnection.
    """
    event_store = get_event_store()
    
    async def _generate():
        """AsyncFunction _generate."""
        # Error handling block.
        try:
            # Phase 1: Replay missed events
            missed_events, truncated = event_store.get_since(since)
            
            # Warn client if history was truncated
            if truncated:
                yield f"event: warning\ndata: {{\"type\": \"replay_truncated\", \"since\": {since}}}\n\n"
            
            for stored in missed_events:
                if await request.is_disconnected():
                    return
                yield f"event: {stored.event.type.value}\ndata: {stored.to_json()}\n\n"
            
            # Phase 2: Stream live events
            async for stored in event_store.subscribe():
                if await request.is_disconnected():
                    break
                yield f"event: {stored.event.type.value}\ndata: {stored.to_json()}\n\n"
                
        except asyncio.CancelledError:
            logger.debug("[EventStream] Client disconnected")
        except Exception as e:
            logger.error(f"[EventStream] Error: {e}")
            yield f"event: error\ndata: {json.dumps({'error': str(e)})}\n\n"
    
    return StreamingResponse(
        _generate(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",  # Disable nginx buffering
        }
    )


@v1_router.get("/events/stats")
@app.get("/events/stats")
async def events_stats(_: bool = Depends(verify_token)):
    """Return diagnostic stats about the event store."""
    return get_event_store().stats()

@v1_router.get("/report/generate")
@app.get("/report/generate")
async def generate_report(
    request: Request,
    section: str = Query(default="executive_summary", pattern="^[a-z_]+$"),
    _: bool = Depends(verify_token),
):
    """AsyncFunction generate_report."""
    async def _stream():
        """AsyncFunction _stream."""
        # Error handling block.
        try:
            composer = ReportComposer()
            content = await asyncio.to_thread(composer.generate_section, section)
            chunk_size = 512
            for i in range(0, len(content), chunk_size):
                if await request.is_disconnected():
                    break
                chunk = content[i : i + chunk_size]
                payload = json.dumps({"token": chunk})
                yield f"data: {payload}\n\n"
            yield "data: [DONE]\n\n"
        except Exception as e:
            yield f"data: {json.dumps({'error': str(e)})}\n\n"
            yield "data: [DONE]\n\n"

    return StreamingResponse(_stream(), media_type="text/event-stream")

@v1_router.get("/clipboard")
@app.get("/clipboard")
async def get_clipboard(_: bool = Depends(verify_token)):
    """AsyncFunction get_clipboard."""
    return {"content": "Clipboard unavailable in container environment"}

@v1_router.post("/actions/{action_id}/{verb}")
@app.post("/actions/{action_id}/{verb}")
async def handle_action(action_id: str, verb: str, _: bool = Depends(verify_token)):
    """AsyncFunction handle_action."""
    dispatcher = ActionDispatcher.instance()
    success = False
    # Conditional branch.
    if verb == "approve":
        success = dispatcher.approve_action(action_id)
    elif verb == "deny":
        success = dispatcher.deny_action(action_id)
    
    # Conditional branch.
    if not success:
        raise SentinelError(
            ErrorCode.SYSTEM_INTERNAL_ERROR,
            f"Action not found: {action_id}",
            details={"action_id": action_id, "verb": verb}
        )
    return {"status": "ok", "action_id": action_id, "result": verb}

# Terminal WebSocket endpoint with config check
@app.websocket("/ws/pty")
async def terminal_websocket_pty(websocket: WebSocket, session_id: Optional[str] = Query(None)):
    """
    WebSocket endpoint for Bidirectional PTY access (Terminal Virtual Session).
    
    This endpoint powers the "Terminal VS" feature.
    
    FEATURES:
    - Virtual Sessions: Connect to a specific persistent shell instance via ?session_id=UUID.
    - Multiplexing: Multiple clients can view/control the same session simultaneously without data loss.
    - Threaded I/O: Uses PTYManager's non-blocking architecture.
    
    ARGS:
    - websocket: The active connection.
    - session_id: (Optional) UUID of an existing session to join. If None, creates a new one.
    """
    config = get_config()

    # -------------------------------------------------------------------------
    # 1. Security & Configuration Validation
    # -------------------------------------------------------------------------
    #
    # /ws/pty provides FULL TERMINAL ACCESS - this is the most dangerous
    # endpoint in the entire API. We apply strict security:
    #
    # - If network-exposed: ALWAYS require token (defense-in-depth)
    # - If localhost: Respect terminal_require_auth setting
    # -------------------------------------------------------------------------
    from core.base.config import is_network_exposed

    is_exposed = is_network_exposed(config.api_host)
    # SENSITIVE: Always require auth when exposed, regardless of terminal_require_auth
    require_token_for_pty = is_exposed or config.security.terminal_require_auth

    if not await validate_websocket_connection(
        websocket,
        "/ws/pty",
        require_token=require_token_for_pty,
    ):
        return  # Connection closed by validator if failed

    # Global kill-switch check
    if not config.security.terminal_enabled:
        await websocket.close(code=4003, reason="Terminal access disabled by configuration")
        return

    await websocket.accept()

    # -------------------------------------------------------------------------
    # 2. Session Binding (The "Virtual" Layer)
    # -------------------------------------------------------------------------
    
    manager = PTYManager.instance()
    
    # If the client requested a specific session, try to find it.
    # Otherwise, spin up a fresh shell environment.
    if session_id:
        pty_session = manager.get_or_create_session(session_id)
    else:
        pty_session = manager.create_session()
    
    # Tell the client which session they are connected to.
    # The frontend should use this ID to reconnect if the socket drops.
    try:
        await websocket.send_json({
            "type": "session_info", 
            "session_id": pty_session.session_id,
            "pid": pty_session.pid
        })
    except Exception as e:
        logger.error(f"Failed to send session info: {e}")
        return

    # -------------------------------------------------------------------------
    # 3. Multiplexing Reader Loop (Server -> Client)
    # -------------------------------------------------------------------------
    
    async def read_pty_loop():
        """
        Continuously skims the PTY's history buffer for new data.
        Maintains a local 'cursor' to ensure this specific client gets
        exactly the data it hasn't seen yet (Multiplexing).
        """
        cursor = 0
        try:
            while True:
                # Fetch new data since our last read position.
                # This is non-blocking and thread-safe.
                text, new_cursor = pty_session.read_from_offset(cursor)
                
                if new_cursor > cursor:
                    # We found new data! Push it to the client.
                    await websocket.send_text(text)
                    cursor = new_cursor
                else:
                    # No new data yet. Sleep briefly to yield the event loop.
                    # 50ms is low enough latency for typing but high enough to save CPU.
                    await asyncio.sleep(0.05)
                    
        except Exception as e:
            # Only log if it's not a normal disconnect
            if not isinstance(e, (RuntimeError, asyncio.CancelledError)):
                logger.error(f"PTY Reader Error (Session {pty_session.session_id}): {e}")

    # Launch the reader as a background task
    reader_task = asyncio.create_task(read_pty_loop())

    # -------------------------------------------------------------------------
    # 4. Writer Loop (Client -> Server)
    # -------------------------------------------------------------------------

    def _sanitize_terminal_input(data: str) -> str:
        """
        Sanitizes usage of terminal escape sequences to prevent injection attacks.
        
        Blocks dangerous control sequences (OSC, DCS, APC, PM) that could be used checks 
        to manipulate the terminal state or exfiltrate data (e.g. clipboard reading).
        Allows standard Control Sequence Introducer (CSI) sequences (e.g. arrow keys).
        """
        # Block:
        # \x1b] = OSC (Operating System Command)
        # \x1bP = DCS (Device Control String)
        # \x1b_ = APC (Application Program Command)
        # \x1b^ = PM  (Privacy Message)
        dangerous_sequences = ["\x1b]", "\x1bP", "\x1b_", "\x1b^"]
        
        for seq in dangerous_sequences:
            if seq in data:
                logger.warning(f"Blocked potential terminal injection in session {session_id}")
                return ""
        return data

    try:
        while True:
            # Wait for input from the browser
            # We use receive_text() to handle both JSON packets and raw keystrokes
            message_text = await websocket.receive_text()
            
            # 1. Attempt to parse as JSON Command (New Protocol)
            try:
                # Optimized for "startsWith" check to avoid costly exception on every keystroke
                if message_text.startswith("{"):
                    cmd = json.loads(message_text)
                    msg_type = cmd.get("type")
                    
                    if msg_type == "input":
                        # Standard input payload
                        raw_data = cmd.get("data", "")
                        safe_data = _sanitize_terminal_input(raw_data)
                        if safe_data:
                            pty_session.write(safe_data)
                        continue

                    elif msg_type == "resize":
                        # Handle window resize events
                        rows = cmd.get("rows", 24)
                        cols = cmd.get("cols", 80)
                        pty_session.resize(rows, cols)
                        continue
                        
                    elif msg_type == "ping":
                        # Keep-alive
                        await websocket.send_json({"type": "pong"})
                        continue
            
            except json.JSONDecodeError:
                # If it looked like JSON but failed, treat as raw input
                pass

            # 2. Fallback: Treat as Raw Input (Keystrokes/Legacy)
            # This handles direct xterm.js "data" events if not wrapped
            if not message_text.startswith("{") or "type" not in message_text:
                safe_data = _sanitize_terminal_input(message_text)
                if safe_data:
                    pty_session.write(safe_data)
            
    except WebSocketDisconnect:
        # Normal closure (user closed tab)
        logger.debug(f"Client disconnected from PTY session {pty_session.session_id}")
        
    except Exception as e:
        logger.error(f"WebSocket Error in PTY handler: {e}")
        
    finally:
        # ---------------------------------------------------------------------
        # 5. Cleanup
        # ---------------------------------------------------------------------
        # Kill the reader task so it doesn't run forever
        reader_task.cancel()
        
        # NOTE: We do NOT close the pty_session here.
        # This is intentional. We want the shell to persist so the user can
        # reload the page and resume their work (persistence).
        # The session will effectively "time out" or be cleaned up by a 
        # separate housekeeper if we implement one, or when the server restarts.

# ============================================================================
# Register API Versioning Routers
# ============================================================================
# This must be done AFTER all route decorators have been applied
# (i.e., after all @v1_router.get/post/put/delete decorators have run)
app.include_router(v1_router)

def serve(port: Optional[int] = None, host: Optional[str] = None):
    """Function serve."""
    config = get_config()
    uvicorn.run(app, host=host or config.api_host, port=port or config.api_port, log_level="info")

if __name__ == "__main__":
    serve()
