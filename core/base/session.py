"""Module session: inline documentation for /Users/jason/Developer/sentinelforge/core/base/session.py."""
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
        """
        Activate the Ghost Protocol network proxy for this session.
        
        Ghost intercepts HTTP/HTTPS traffic between target and browser,
        allowing us to inspect/modify requests and discover API endpoints.
        
        Args:
            port: Port to run the proxy on (default 8080, like Burp Suite)
        """
        from core.ghost.proxy import GhostInterceptor
        # Create and configure the proxy for this session
        self.ghost = GhostInterceptor(self, port)
        
        # Start the proxy in the background (async operation)
        # asyncio.create_task runs it concurrently without blocking
        import asyncio
        asyncio.create_task(self.ghost.start())

    def stop_ghost(self):
        """
        Deactivate the Ghost Protocol proxy.
        
        Shuts down the proxy server and cleans up resources.
        Safe to call even if Ghost isn't running.
        """
        # Conditional branch.
        if self.ghost:
            self.ghost.stop()  # Shut down the proxy
            self.ghost = None  # Clear the reference

    def log(self, message: str):
        """
        Add a log message to this session's log stream.
        
        Unlike global logging, these logs are tied to this specific scan.
        They're shown in the UI for this session and saved with the scan results.
        
        Thread-safe: multiple tools can log simultaneously without corruption.
        
        Args:
            message: What to log (e.g., "nmap scan started", "Found SQL injection")
        """
        # Format timestamp as HH:MM:SS for readability
        timestamp = time.strftime("%H:%M:%S", time.localtime())
        entry = f"[{timestamp}] {message}"
        
        # Use a lock to prevent race conditions when multiple threads log at once
        with self._logs_lock:
            self.logs.append(entry)
            
        # If UI is subscribed, send the log there too (real-time streaming)
        if self._external_log_sink:
            self._external_log_sink(entry)
    
    def set_external_log_sink(self, log_fn):
        """
        Connect a function to receive log messages as they're added.
        
        Used by the scan orchestrator to stream logs to UI via WebSocket/SSE.
        
        Args:
            log_fn: Function to call with each log entry (e.g., lambda msg: send_to_ui(msg))
        """
        self._external_log_sink = log_fn

    def to_dict(self) -> Dict:
        """
        Serialize this session to a dictionary (for API responses).
        
        Returns a JSON-friendly summary of the session state.
        
        Returns:
            Dictionary with session metadata and statistics
        """
        return {
            "id": self.id,  # Unique session identifier
            "target": self.target,  # What we're scanning
            "status": self.status,  # Current state (Created/Running/Complete)
            "findings_count": len(self.findings.get_all()),  # How many vulnerabilities found
            "issues_count": len(self.issues.get_all()),  # How many confirmed exploits
            "start_time": self.start_time,  # When scan began (Unix timestamp)
            "ghost_active": self.ghost is not None  # Is proxy running?
        }
