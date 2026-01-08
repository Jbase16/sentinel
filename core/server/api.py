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

# Import Modular Routers
from core.server.routers import auth, scans, ai, system, realtime

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

    # Initialize global event sequence counter from database
    from core.cortex.events import initialize_event_sequence_from_db
    await initialize_event_sequence_from_db()

    # Load CAL policies from database into ArbitrationEngine
    try:
        from core.cortex.reasoning import reasoning_engine
        policy_count = await reasoning_engine.strategos.load_policies_from_db()
        if policy_count > 0:
            logger.info(f"[Startup] Loaded {policy_count} CAL policies from database")
    except Exception as e:
        logger.error(f"[Startup] Failed to load policies from database: {e}")

    # Start policy file watcher for hot-reload
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
                logger.info(f"[PolicyWatcher] Reloaded {len(policies)} policies from constitution.cal")

                db_count = await reasoning_engine.strategos.load_policies_from_db()
                logger.info(f"[PolicyWatcher] Reloaded {db_count} policies from database")

            except Exception as e:
                logger.error(f"[PolicyWatcher] Reload callback failed: {e}")

        watcher.set_reload_callback(reload_policies_on_change)
        await watcher.start()
        logger.info("[Startup] Policy file watcher started")
    except Exception as e:
        logger.error(f"[Startup] Failed to start policy watcher: {e}")

    # Start session cleanup task
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

    yield  # Application runs here

    # === SHUTDOWN ===
    logger.info("SentinelForge API Shutting Down...")
    _write_boot_manifest("stopping")

    # Cancel session cleanup task
    if state.session_cleanup_task and not state.session_cleanup_task.done():
        state.session_cleanup_task.cancel()
        try:
            await state.session_cleanup_task
        except asyncio.CancelledError:
            pass

    # Stop policy file watcher
    try:
        from core.cortex.policy_watcher import get_policy_watcher
        watcher = get_policy_watcher()
        await watcher.stop()
        logger.info("[Shutdown] Policy file watcher stopped")
    except Exception as e:
        logger.error(f"[Shutdown] Failed to stop policy watcher: {e}")

    from core.data.blackbox import BlackBox
    await BlackBox.instance().shutdown()

    # Persist final sequence counter
    from core.base.sequence import GlobalSequenceAuthority
    await GlobalSequenceAuthority.persist_to_db()

    # Close database connection
    db = Database.instance()
    await db.close()
    _write_boot_manifest("stopped")


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
        content=exc.to_dict()
    )

# CORS Setup
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

# Mount sub-routers
v1_router.include_router(scans.router)
v1_router.include_router(ai.router)
v1_router.include_router(system.router)
v1_router.include_router(realtime.router)
# v1_router.include_router(auth.router) # Auth is mostly dependencies, not endpoints

app.include_router(v1_router)

# Root redirect
@app.get("/")
async def root():
    return {"message": "SentinelForge API is running", "docs": "/docs"}