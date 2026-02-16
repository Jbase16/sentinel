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
import re
from pathlib import Path
from threading import Lock
from typing import Any, Dict, Deque, Optional
from collections import deque
import logging

from core.data.findings_store import FindingsStore  # Stores security vulnerabilities/discoveries
from core.data.issues_store import IssuesStore  # Stores confirmed issues/exploits
from core.data.killchain_store import KillchainStore  # Tracks attack progression
from core.data.evidence_store import EvidenceStore  # Stores raw tool outputs

logger = logging.getLogger(__name__)


def _sanitize_target_for_filename(target: str) -> str:
    """
    Convert a target URL/domain into a valid filename component.

    Minimal sanitization - keeps target readable while making it filesystem-safe.
    Examples:
        "https://example.com/api" -> "example.com_api"
        "localhost:3002" -> "localhost:3002"
        "192.168.1.1" -> "192.168.1.1"
    """
    # Strip protocol prefix
    result = re.sub(r'^https?://', '', target)
    # Replace filesystem-invalid characters with underscore
    result = re.sub(r'[/\\]', '_', result)
    # Strip trailing underscores/dots
    result = result.strip('_.')
    return result


def _generate_scan_log_path(target: str, log_dir: Path) -> Path:
    """
    Generate a unique log file path for a scan session.

    Format: {target}-{M-DD-YY}.log
    If file exists, adds counter: {target}-{M-DD-YY} (2).log

    Args:
        target: The scan target (URL, domain, IP)
        log_dir: Directory where log files are stored

    Returns:
        Path to the log file (unique, doesn't overwrite existing)
    """
    sanitized = _sanitize_target_for_filename(target)
    date_str = time.strftime("%-m-%d-%y")  # e.g., "1-26-26"

    base_name = f"{sanitized}-{date_str}"
    log_path = log_dir / f"{base_name}.log"

    # If file exists, add counter suffix like macOS does
    if log_path.exists():
        counter = 2
        while True:
            log_path = log_dir / f"{base_name} ({counter}).log"
            if not log_path.exists():
                break
            counter += 1

    return log_path

# Max logs to keep in memory per session
MAX_SESSION_LOGS = 5000

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

        # Shared per-scan knowledge for cross-layer coordination.
        #
        # This is intentionally NOT persisted to the database (see to_dict()),
        # because it may contain runtime-only objects (e.g., bypass engines,
        # auth sessions) that are not JSON serializable.
        self.knowledge: Dict[str, Any] = {}
        
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
        # Capped to avoid memory exhaustion on long-running scans
        self.logs: Deque[str] = deque(maxlen=MAX_SESSION_LOGS)
        self._log_overflow_warned = False

        # Thread lock to prevent concurrent access corruption
        # Multiple threads might try to write logs at the same time, lock prevents conflicts
        self._logs_lock = Lock()

        # Optional external log sink (function to call when new log is added)
        # Used to stream logs to UI in real-time (WebSocket, SSE, etc.)
        self._external_log_sink = None  # Will be set by ScanOrchestrator if needed

        # Per-scan log file - each scan gets its own file in logs/
        # Format: {target}-{date}.log (e.g., localhost:3002-1-26-26.log)
        self._log_file: Optional[Path] = None
        self._log_file_handle = None
        self._logging_handler: Optional[logging.FileHandler] = None
        self._init_log_file()
        
        # Ghost Protocol: Network traffic interceptor (proxy)
        # Captures HTTP/HTTPS traffic for analysis (like Burp Suite's proxy)
        # Starts as None, activated on demand
        self.ghost = None
        
        # Wraith Automator: Browser automation engine ("The Hand")
        # Controls headless browsers for authenticated scanning, JS-heavy apps, etc.
        from core.wraith.automator import WraithAutomator
        self.wraith = WraithAutomator(self)

        from core.data.pressure_graph.manager import PressureGraphManager
        self.pressure_graph = PressureGraphManager(
            session_id=self.id,
            issues_store=self.issues,
            killchain_store=self.killchain,
            findings_store=self.findings
        )

    @property
    def session_id(self) -> str:
        """Alias for self.id for compatibility with scanner_engine."""
        return self.id

    @property
    def scan_id(self) -> str:
        """Alias for scan identifiers used by components that expect scan_id."""
        return self.id

    def _init_log_file(self) -> None:
        """
        Initialize the per-scan log file.

        Creates a log file in ~/.sentinelforge/logs/ with the format:
        {target}-{M-DD-YY}.log (e.g., localhost:3002-1-26-26.log)
        """
        try:
            from core.base.config import get_config
            cfg = get_config()

            if not cfg.log.file_enabled:
                return

            # Get log directory path
            log_dir = cfg.storage.base_dir / cfg.log.log_dir
            log_dir.mkdir(parents=True, exist_ok=True)

            # Generate unique log file path
            self._log_file = _generate_scan_log_path(self.target, log_dir)

            # Open file for writing (append mode in case session is resumed)
            self._log_file_handle = open(self._log_file, 'a', encoding='utf-8')

            # Write session header
            header = f"=== Scan Session: {self.id} ===\n"
            header += f"Target: {self.target}\n"
            header += f"Started: {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
            header += "=" * 50 + "\n"
            self._log_file_handle.write(header)
            self._log_file_handle.flush()

            # Attach a handler to Python's root logger so all logger.info() etc.
            # calls throughout the codebase also write to this scan's log file
            self._logging_handler = logging.FileHandler(self._log_file, mode='a', encoding='utf-8')
            self._logging_handler.setFormatter(logging.Formatter(cfg.log.format))
            logging.getLogger().addHandler(self._logging_handler)

            logger.info(f"Session log file: {self._log_file}")
        except Exception as e:
            logger.warning(f"Failed to create session log file: {e}")
            self._log_file = None
            self._log_file_handle = None

    def close_log_file(self) -> None:
        """
        Close the per-scan log file.

        Call this when the scan session ends to flush and close the file handle.
        """
        # Remove the logging handler from root logger first
        if self._logging_handler:
            try:
                logging.getLogger().removeHandler(self._logging_handler)
                self._logging_handler.close()
            except Exception:
                pass
            finally:
                self._logging_handler = None

        if self._log_file_handle:
            try:
                # Write session footer
                footer = "\n" + "=" * 50 + "\n"
                footer += f"Session ended: {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
                footer += f"Status: {self.status}\n"
                self._log_file_handle.write(footer)
                self._log_file_handle.close()
            except Exception as e:
                logger.warning(f"Error closing session log file: {e}")
            finally:
                self._log_file_handle = None

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
        # Use a lock to prevent race conditions when multiple threads log at once
        with self._logs_lock:
            if len(self.logs) >= MAX_SESSION_LOGS and not self._log_overflow_warned:
                self.logs.append(f"[{timestamp}] WARNING: Log limit ({MAX_SESSION_LOGS}) reached. Older logs will be dropped.")
                self._log_overflow_warned = True
            self.logs.append(entry)

            # Write to per-scan log file
            if self._log_file_handle:
                try:
                    self._log_file_handle.write(entry + "\n")
                    self._log_file_handle.flush()
                except Exception:
                    pass  # Don't let file errors break logging

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
        with self._logs_lock:
            # Convert deque to list for serialization
            logs_list = list(self.logs)

        return {
            "id": self.id,  # Unique session identifier
            "target": self.target,  # What we're scanning
            "status": self.status,  # Current state (Created/Running/Complete)
            "findings_count": len(self.findings.get_all()),  # How many vulnerabilities found
            "issues_count": len(self.issues.get_all()),  # How many confirmed exploits
            "start_time": self.start_time,  # When scan began (Unix timestamp)
            "ghost_active": self.ghost is not None,  # Is proxy running?
            "logs": logs_list  # Include logs for persistence
        }
