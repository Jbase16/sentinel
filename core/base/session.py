# ============================================================================
# core/base/session.py
# Scan Session Management - Isolated Context for Each Security Test
# ============================================================================
#
# PURPOSE:
# Each security scan gets its own "session" - a container that holds all the
# data, tools, and state for that specific scan. Think of it like creating a
# fresh workspace for each project.
#
# WHY SESSIONS MATTER:
# - Prevents mixing data from different scans (scan A's findings don't leak into scan B)
# - Allows running multiple scans at the same time (parallel testing)
# - Makes it easy to pause/resume/delete scans independently
# - Provides clean audit trail (all actions for scan X are in session X)
#
# KEY CONCEPTS:
# - Isolation: Each session has its own stores (findings, evidence, etc.)
# - Threading: Sessions use locks to handle concurrent access safely
# - Lifecycle: Create → Run Tools → Analyze → Generate Report → Archive
#
# ============================================================================

import uuid
import time
from threading import Lock
from typing import Optional, Dict, List

# Import data storage classes (each session gets its own instances)
from core.data.findings_store import FindingsStore  # Stores security vulnerabilities/discoveries
from core.data.issues_store import IssuesStore  # Stores confirmed issues/exploits
from core.data.killchain_store import KillchainStore  # Tracks attack progression
from core.data.evidence_store import EvidenceStore  # Stores raw tool outputs

class ScanSession:
    """
    A single security scan session - an isolated workspace for one target.
    
    Think of this like a lab notebook: all observations, findings, and actions
    for this specific scan are recorded here and nowhere else.
    
    Prevents data from multiple scans getting mixed together.
    """
    def __init__(self, target: str):
        """
        Create a new scan session for the given target.
        
        Args:
            target: What we're scanning (URL, IP address, domain name, etc.)
                   Examples: "example.com", "192.168.1.1", "https://app.example.com"
        """
        # Generate a unique ID for this session (random UUID)
        # UUIDs are 128-bit random numbers, virtually impossible to collide
        # Example: "f47ac10b-58cc-4372-a567-0e02b2c3d479"
        self.id = str(uuid.uuid4())
        
        # Store the target we're scanning
        self.target = target
        
        # Record when this scan started (Unix timestamp: seconds since 1970)
        self.start_time = time.time()
        
        # Current status of the scan ("Created", "Running", "Complete", "Failed", etc.)
        self.status = "Created"
        
        # Create isolated data stores for this session
        # Each store is linked to this session's ID so data doesn't leak between scans
        
        # Findings: Security discoveries (open ports, exposed services, vulnerabilities)
        self.findings = FindingsStore(session_id=self.id)
        
        # Issues: Confirmed exploitable vulnerabilities (subset of findings)
        self.issues = IssuesStore(session_id=self.id)
        
        # Killchain: Maps findings to attack phases (recon → weaponization → delivery → etc.)
        # Helps understand "how far could an attacker get?" with these findings
        self.killchain = KillchainStore(session_id=self.id)
        
        # Evidence: Raw outputs from security tools (nmap scans, HTTP responses, etc.)
        self.evidence = EvidenceStore(session_id=self.id)
        
        # Session-specific logs (messages describing what's happening in this scan)
        # Separate from global app logs - only logs related to THIS scan
        self.logs: List[str] = []
        
        # Thread lock to prevent concurrent access corruption
        # Multiple threads might try to write logs at the same time, lock prevents conflicts
        self._logs_lock = Lock()
        
        # Optional external log sink (function to call when new log is added)
        # Used to stream logs to UI in real-time (WebSocket, SSE, etc.)
        self._external_log_sink = None  # Will be set by ScanOrchestrator if needed
        
        # Ghost Protocol: Network traffic interceptor (proxy)
        # Captures HTTP/HTTPS traffic for analysis (like Burp Suite's proxy)
        # Starts as None, activated on demand
        self.ghost = None
        
        # Wraith Automator: Browser automation engine ("The Hand")
        # Controls headless browsers for authenticated scanning, JS-heavy apps, etc.
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
