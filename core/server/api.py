"""Module api: inline documentation for /Users/jason/Developer/sentinelforge/core/server/api.py."""
#
# PURPOSE:
# The main entry point for the SentinelForge API Server.
# It initializes the application, mounts routers, and handles the global lifecycle.
#
# ARCHITECTURE:
# - ApplicationState: Singleton holding global state (core/server/state.py)
# - Routers: Modular route handlers (core/server/routers/)
# - Lifespan: Handles startup/shutdown sequences
#

from __future__ import annotations

import logging
import os
import asyncio
import json
from datetime import datetime, timezone
from typing import Optional, Dict, Any
from contextlib import asynccontextmanager

from fastapi import FastAPI, APIRouter, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

from core.base.config import get_config, setup_logging, SecurityInterlock
from core.server.state import get_state
from core.data.db import Database
from core.errors import SentinelError

logger = logging.getLogger(__name__)

# Pre-bind security interlock: fail closed before uvicorn binds.
SecurityInterlock.verify_safe_boot(get_config())


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


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    FastAPI lifespan context manager for startup and shutdown.
    """
    # === STARTUP ===
    state = get_state()
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

    try:
        state.api_loop = asyncio.get_running_loop()
    except RuntimeError:
        state.api_loop = None

    # Async DB Init
    db = Database.instance()
    await db.init()

    # Initialize global event sequence counter
    from core.cortex.events import initialize_event_sequence_from_db
    await initialize_event_sequence_from_db()

    # Load CAL policies from database
    try:
        from core.cortex.reasoning import reasoning_engine
        policy_count = await reasoning_engine.strategos.load_policies_from_db()
        if policy_count > 0:
            logger.info(f"[Startup] Loaded {policy_count} CAL policies from database")
    except Exception as e:
        logger.error(f"[Startup] Failed to load policies from database: {e}")

    # Start policy file watcher
    try:
        from core.cortex.policy_watcher import get_policy_watcher
        from core.cortex.reasoning import reasoning_engine

        watcher = get_policy_watcher()

        async def reload_policies_on_change():
            try:
                arbitrator = reasoning_engine.strategos.arbitrator
                active_policies = arbitrator.list_policies()
                for policy_name in active_policies:
                    if policy_name.startswith("CAL:"):
                        arbitrator.unregister_policy(policy_name)

                policies = arbitrator.load_cal_file("assets/laws/constitution.cal")
                logger.info(
                    f"[PolicyWatcher] Reloaded {len(policies)} policies from constitution.cal"
                )

                db_count = await reasoning_engine.strategos.load_policies_from_db()
                logger.info(
                    f"[PolicyWatcher] Reloaded {db_count} policies from database"
                )

            except Exception as e:
                logger.error(f"[PolicyWatcher] Reload callback failed: {e}")

        watcher.set_reload_callback(reload_policies_on_change)
        await watcher.start()
        logger.info("[Startup] Policy file watcher started")

    except Exception as e:
        logger.error(f"[Startup] Failed to start policy watcher: {e}")

    # Session cleanup loop
    async def session_cleanup_loop():
        while True:
            try:
                await asyncio.sleep(86400)
                removed = await state.cleanup_old_sessions()
                if removed > 0:
                    logger.info(f"Session cleanup: removed {removed} old sessions")
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Session cleanup error: {e}")

    state.session_cleanup_task = asyncio.create_task(session_cleanup_loop())
    logger.info("Session cleanup task started")

    _write_boot_manifest("ready")

    yield

    # === SHUTDOWN ===
    logger.info("SentinelForge API Shutting Down...")
    _write_boot_manifest("stopping")

    if state.session_cleanup_task and not state.session_cleanup_task.done():
        state.session_cleanup_task.cancel()
        try:
            await state.session_cleanup_task
        except asyncio.CancelledError:
            pass

    try:
        from core.cortex.policy_watcher import get_policy_watcher
        watcher = get_policy_watcher()
        await watcher.stop()
        logger.info("[Shutdown] Policy file watcher stopped")
    except Exception as e:
        logger.error(f"[Shutdown] Failed to stop policy watcher: {e}")

    from core.data.blackbox import BlackBox
    await BlackBox.instance().shutdown()

    from core.base.sequence import GlobalSequenceAuthority
    await GlobalSequenceAuthority.persist_to_db()

    await db.close()
    _write_boot_manifest("stopped")


# --- FastAPI App ---

app = FastAPI(
    title="SentinelForge API",
    description="AI-augmented offensive security platform",
    version="1.0.0",
    lifespan=lifespan,
)


# Exception handler
@app.exception_handler(SentinelError)
async def sentinel_error_handler(request: Request, exc: SentinelError):
    logger.error(f"[API] {exc.code.value}: {exc.message}", extra=exc.details)
    return JSONResponse(
        status_code=exc.http_status,
        content=exc.to_dict(),
    )


# CORS
config = get_config()
if config.security.allowed_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=config.security.allowed_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )


# --- Router Mounting ---

v1_router = APIRouter(prefix="/v1")

@v1_router.get("/ping")
async def ping():
    return {"status": "ok"}

@v1_router.get("/status")
async def status():
    """
    Comprehensive status endpoint matching Swift EngineStatus structure.
    Returns scan state, AI status, and tool information.
    """
    from core.ai.ai_engine import AIEngine
    from core.toolkit.tools import get_installed_tools, TOOLS
    from core.base.config import get_config
    
    state = get_state()
    
    # Get scan state - ensure it's always present
    scan_state = state.scan_state if state.scan_state else {}
    scan_running = scan_state.get("status") == "running" if scan_state else False
    
    # Get AI status
    try:
        ai_engine = AIEngine.instance()
        ai_status = ai_engine.status()
    except Exception as e:
        logger.warning(f"[Status] Failed to get AI status: {e}")
        ai_status = None
    
    # Get tool status
    try:
        installed_tools = list(get_installed_tools().keys())
        all_tools = list(TOOLS.keys())
        missing_tools = [t for t in all_tools if t not in installed_tools]
        tools_status = {
            "installed": installed_tools,
            "missing": missing_tools,
            "count_installed": len(installed_tools),
            "count_total": len(all_tools)
        }
    except Exception as e:
        logger.warning(f"[Status] Failed to get tool status: {e}")
        tools_status = {
            "installed": [],
            "missing": [],
            "count_installed": 0,
            "count_total": 0
        }
    
    # Build response matching Swift EngineStatus structure
    # Ensure all expected fields are present, even if empty
    response = {
        "status": "ok",
        "scan_running": scan_running,
        "latest_target": scan_state.get("target") if scan_state else None,
        "ai": ai_status if ai_status else {},
        "tools": tools_status,
        "scan_state": scan_state,
        "cancel_requested": state.cancel_requested.is_set() if state.cancel_requested else False
    }
    
    return response


# Import routers AFTER v1_router exists
# Import routers AFTER v1_router exists
from core.server.routers import auth, scans, ai, system, realtime, cortex, ghost, forge

v1_router.include_router(scans.router)
v1_router.include_router(ai.router)
v1_router.include_router(system.router)
v1_router.include_router(ghost.router, prefix="/ghost")
v1_router.include_router(forge.router)
# v1_router.include_router(realtime.router) # Removed from v1_router
v1_router.include_router(cortex.router)
v1_router.include_router(realtime.sse_router, prefix="/events")
# v1_router.include_router(auth.router)  # Auth is dependencies-only

# AI Chat alias route for backwards compatibility
@v1_router.post("/chat", include_in_schema=False)
async def chat_alias(req: ai.ChatRequest):
    """Alias route for /v1/chat -> /v1/ai/chat for Swift client compatibility."""
    return await ai.chat_with_ai(req)

# Scan results alias route for Swift client compatibility
@v1_router.get("/scan/results", include_in_schema=False)
async def scan_results_alias():
    """Alias route for /v1/scan/results -> /v1/scans/results for Swift client compatibility."""
    return await scans.get_scan_results()

# Scan alias routes for backwards compatibility
@v1_router.post("/scan", include_in_schema=False)
async def scan_alias(req: scans.ScanRequest):
    """Alias route for /v1/scan -> /v1/scans/start for Swift client compatibility."""
    return await scans.start_scan(req)

@v1_router.get("/scan/status", include_in_schema=False)
async def scan_status_alias():
    """Alias route for /v1/scan/status -> /v1/scans/status for Swift client compatibility."""
    return await scans.get_scan_status()

# Graph alias route for backwards compatibility
@v1_router.get("/graph", include_in_schema=False)
async def graph_alias():
    """
    Alias route for /v1/graph -> Returns current graph state for Swift client compatibility.
    Returns current Pressure Graph state for Swift client compatibility.
    """
    from fastapi.responses import Response

    state = get_state()
    scan_state = state.scan_state or {}
    db = Database.instance()

    session_id = scan_state.get("session_id")
    if not session_id:
        recent_sessions = await db.fetch_all(
            "SELECT id FROM sessions ORDER BY start_time DESC LIMIT 1",
            (),
        )
        if not recent_sessions:
            return Response(status_code=204)
        session_id = recent_sessions[0][0]

    try:
        session = await state.get_session(session_id)
        if session and getattr(session, "pressure_graph", None):
            return session.pressure_graph.to_dict()

        nodes, edges = await db.load_graph_snapshot(session_id)
        return {
            "session_id": session_id,
            "nodes": nodes,
            "edges": edges,
            "count": {"nodes": len(nodes), "edges": len(edges)},
        }
    except Exception as e:
        logger.warning(f"[Graph] Failed to get graph state: {e}")
        return Response(status_code=204)

app.include_router(v1_router)
# Mount realtime directly to support /ws path
app.include_router(realtime.router)


# Root redirect
@app.get("/")
async def root():
    return {
        "message": "SentinelForge API is running",
        "docs": "/docs",
    }
