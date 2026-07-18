from __future__ import annotations

import asyncio
import threading
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional
import logging

logger = logging.getLogger(__name__)

class ApplicationState:
    _instance = None

    @classmethod
    def instance(cls) -> ApplicationState:
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def __init__(self):
        self.api_loop: Optional[asyncio.AbstractEventLoop] = None
        self.log_queue: asyncio.Queue = asyncio.Queue(maxsize=10000)
        
        # Scan State
        self.active_scan_task: Optional[asyncio.Task] = None
        self.scan_lock = asyncio.Lock()
        self.scan_state: Dict[str, Any] = {}
        self.cancel_requested = threading.Event()
        
        # Session Management
        self.session_manager: Dict[str, Any] = {}
        self.session_manager_lock = asyncio.Lock()
        self.session_cleanup_task: Optional[asyncio.Task] = None

    async def register_session(self, session_id: str, session) -> None:
        async with self.session_manager_lock:
            self.session_manager[session_id] = session

    async def get_session(self, session_id: str):
        async with self.session_manager_lock:
            return self.session_manager.get(session_id)

    async def unregister_session(self, session_id: str) -> None:
        session = None
        async with self.session_manager_lock:
            session = self.session_manager.pop(session_id, None)
        if session is not None:
            try:
                session.close()
            except Exception:
                logger.warning("Failed to close session %s", session_id, exc_info=True)

    async def cleanup_old_sessions(self, max_age: timedelta = timedelta(days=1)) -> int:
        now = datetime.now(timezone.utc)
        to_remove = []
        removed_sessions = []

        async with self.session_manager_lock:
            for session_id, session in self.session_manager.items():
                session_start = getattr(session, "start_time", None)
                if session_start:
                    if isinstance(session_start, (int, float)):
                        session_time = datetime.fromtimestamp(session_start, tz=timezone.utc)
                    elif isinstance(session_start, datetime):
                        session_time = session_start
                    else:
                        continue

                    if now - session_time > max_age:
                        to_remove.append(session_id)

            for session_id in to_remove:
                session = self.session_manager.pop(session_id, None)
                if session is not None:
                    removed_sessions.append(session)

        for session in removed_sessions:
            try:
                session.close()
            except Exception:
                logger.warning(
                    "Failed to close expired session %s",
                    getattr(session, "id", "unknown"),
                    exc_info=True,
                )

        return len(to_remove)

def get_state() -> ApplicationState:
    return ApplicationState.instance()
