"""
core/session.py

Defines the ScanSession Context.
This object encapsulates ALL state related to a specific scan/mission.
It replaces global singletons to allow concurrent scanning and robust isolation.
"""

import uuid
import time
from threading import Lock
from typing import Optional, Dict, List

# Import store classes (we will refactor them to be instantiable)
from core.data.findings_store import FindingsStore
from core.data.issues_store import IssuesStore
from core.data.killchain_store import KillchainStore
from core.data.evidence_store import EvidenceStore

class ScanSession:
    """
    A single "Mission" or "Scan" context.
    Owns its own data stores, preventing cross-contamination between concurrent scans.
    """
    def __init__(self, target: str):
        self.id = str(uuid.uuid4())
        self.target = target
        self.start_time = time.time()
        self.status = "Created"
        
        # Each session gets its own isolated stores, linked to DB ID
        self.findings = FindingsStore(session_id=self.id)
        self.issues = IssuesStore(session_id=self.id)
        self.killchain = KillchainStore(session_id=self.id) # Killchain is transient/derived mostly, but could be persisted
        self.evidence = EvidenceStore(session_id=self.id)   # Now supports session-scoping
        
        # Session-local logs (thread-safe)
        self.logs: List[str] = []
        self._logs_lock = Lock()
        self._external_log_sink = None  # Will be set by ScanOrchestrator
        
        # Ghost Protocol (Traffic Interceptor)
        self.ghost = None
        
        # Wraith Automator (The Hand)
        from core.wraith.automator import WraithAutomator
        self.wraith = WraithAutomator(self)

    def start_ghost(self, port: int = 8080):
        """Activates the Ghost Protocol traffic interceptor."""
        from core.ghost.proxy import GhostInterceptor
        self.ghost = GhostInterceptor(self, port)
        # We need to run the async start method. 
        # Since we are likely in an async context, we can await it or create a task.
        import asyncio
        asyncio.create_task(self.ghost.start())

    def stop_ghost(self):
        if self.ghost:
            self.ghost.stop()
            self.ghost = None

    def log(self, message: str):
        timestamp = time.strftime("%H:%M:%S", time.localtime())
        entry = f"[{timestamp}] {message}"
        
        # Thread-safe logging
        with self._logs_lock:
            self.logs.append(entry)
            
        # Also send to external log sink for UI streaming if available
        if self._external_log_sink:
            self._external_log_sink(entry)
        
        # We could also emit a signal here for real-time UI updates specific to this session
    
    def set_external_log_sink(self, log_fn):
        """Set the external log sink function."""
        self._external_log_sink = log_fn

    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "target": self.target,
            "status": self.status,
            "findings_count": len(self.findings.get_all()),
            "issues_count": len(self.issues.get_all()),
            "start_time": self.start_time,
            "ghost_active": self.ghost is not None
        }
