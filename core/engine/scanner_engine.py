"""Module scanner_engine: inline documentation for /Users/jason/Developer/sentinelforge/core/engine/scanner_engine.py."""
#
# PURPOSE:
# This module is part of the engine package in SentinelForge.
# [Specific purpose based on module name: scanner_engine]
#
# KEY RESPONSIBILITIES:
# - [Automatically generated - review and enhance based on actual functionality]
#
# INTEGRATION:
# - Used by: [To be documented]
# - Depends on: [To be documented]
#

# core/scanner_engine.py — macOS-compatible active scanner engine
from __future__ import annotations

import asyncio
import logging
import os
import threading
from collections import deque
from urllib.parse import urlparse
from typing import Any, AsyncGenerator, Dict, List, Optional

from core.data.findings_store import findings_store
from core.data.evidence_store import EvidenceStore
from core.cortex.scanner_bridge import ScannerBridge
from core.toolkit.vuln_rules import apply_rules
from core.data.issues_store import issues_store
from core.data.killchain_store import killchain_store
from core.toolkit.tools import TOOLS, get_tool_command, get_installed_tools
from core.base.task_router import TaskRouter
from core.cortex.correlator import GraphCorrelator

logger = logging.getLogger(__name__)


class ResourceExhaustedError(Exception):
    """Raised when resource limits are exceeded."""
    pass


class ResourceGuard:
    """
    Prevents resource exhaustion during scans.

    Tracks and enforces limits on:
    - Total findings count
    - Disk usage for evidence/output
    """

    def __init__(self, max_findings: int = 10000, max_disk_mb: int = 1000):
        """
        Initialize resource guard.

        Args:
            max_findings: Maximum number of findings before raising error
            max_disk_mb: Maximum disk usage in MB before raising error
        """
        self.max_findings = max_findings
        self.max_disk_mb = max_disk_mb
        self.findings_count = 0
        self.disk_usage = 0
        self._lock = threading.Lock()

    def reset(self):
        """Reset counters for a new scan."""
        with self._lock:
            self.findings_count = 0
            self.disk_usage = 0

    def check_findings(self, count: int) -> bool:
        """
        Check if adding findings would exceed limit.

        Args:
            count: Number of findings to add

        Returns:
            True if within limits

        Raises:
            ResourceExhaustedError: If limit would be exceeded
        """
        with self._lock:
            if self.findings_count + count > self.max_findings:
                raise ResourceExhaustedError(
                    f"Too many findings: {self.findings_count + count} exceeds limit {self.max_findings}"
                )
            self.findings_count += count
            return True

    def check_disk(self, size_bytes: int) -> bool:
        """
        Check if adding disk usage would exceed limit.

        Args:
            size_bytes: Size in bytes to add

        Returns:
            True if within limits

        Raises:
            ResourceExhaustedError: If limit would be exceeded
        """
        with self._lock:
            max_bytes = self.max_disk_mb * 1024 * 1024
            if self.disk_usage + size_bytes > max_bytes:
                raise ResourceExhaustedError(
                    f"Too much disk usage: {(self.disk_usage + size_bytes) / 1024 / 1024:.1f}MB exceeds limit {self.max_disk_mb}MB"
                )
            self.disk_usage += size_bytes
            return True

    def get_usage(self) -> Dict[str, object]:
        """Get current resource usage for monitoring."""
        with self._lock:
            return {
                "findings_count": self.findings_count,
                "max_findings": self.max_findings,
                "disk_usage_mb": self.disk_usage / 1024 / 1024,
                "max_disk_mb": self.max_disk_mb,
                "findings_percent": (self.findings_count / self.max_findings) * 100 if self.max_findings > 0 else 0,
                "disk_percent": (self.disk_usage / (self.max_disk_mb * 1024 * 1024)) * 100 if self.max_disk_mb > 0 else 0,
            }

# Try to import psutil for resource awareness
try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

# Configurable concurrency limit based on system resources
MIN_CONCURRENT_TOOLS = 1
MAX_CONCURRENT_TOOLS_BASE = 20  # Base value for small systems

def calculate_concurrent_limit() -> int:
    """Calculate optimal concurrency based on available system resources."""
    # Error handling block.
    try:
        cpu_count = os.cpu_count() or 2
        
        # Get available memory in GB if psutil is available
        if HAS_PSUTIL:
            memory_info = psutil.virtual_memory()
            available_memory_gb = memory_info.available / (1024**3)
            
            # Calculate limit based on resources
            # Use 1 tool per 2GB of available RAM, up to CPU count
            memory_based = max(1, int(available_memory_gb / 2))
            cpu_based = max(1, cpu_count // 2)
            
            # Use the smaller of the two to avoid overload
            calculated = min(memory_based, cpu_based)
            
            # Ensure at least the minimum and not too high
            return max(MIN_CONCURRENT_TOOLS, min(calculated, MAX_CONCURRENT_TOOLS_BASE * 2))
        else:
            # Fallback when psutil is not available: use CPU count with cap
            return max(MIN_CONCURRENT_TOOLS, min(cpu_count // 2, MAX_CONCURRENT_TOOLS_BASE * 2))
    except Exception:
        # Ultimate fallback if detection fails
        return MAX_CONCURRENT_TOOLS_BASE

# Calculate actual limit at module load
MAX_CONCURRENT_TOOLS = calculate_concurrent_limit()

# Timeout configuration (can be overridden via environment variables)
DEFAULT_TOOL_TIMEOUT_SECONDS = 300          # 5 minutes per tool hard cap
DEFAULT_TOOL_IDLE_TIMEOUT_SECONDS = 60      # 1 minute without output => consider stuck
DEFAULT_GLOBAL_SCAN_TIMEOUT_SECONDS = 900   # 15 minutes overall cap


class ScanTransaction:
    """
    Context manager for atomic scan operations.

    Ensures scan results are committed atomically - either all results
    are saved to the database, or none are (on failure/crash).

    This prevents inconsistent state where some results are persisted
    but others are lost due to crashes or exceptions.

    Usage:
        async with ScanTransaction(engine, session_id, target) as txn:
            # Run scan, collect results
            txn.add_finding(finding)
            txn.add_result(result)
            # On exit, all results are atomically committed
            # On exception, all results are rolled back

    Design Pattern: Two-Phase Commit
    - Phase 1 (active): Accumulate results in memory
    - Phase 2 (commit): Atomically write to database
    - On error: Rollback (discard all accumulated results)

    Audit Trail:
    - Creates a scan record on entry for auditability
    - Updates status to 'committed' or 'rolled_back' on exit
    - Enables post-mortem analysis and resume capability
    """

    def __init__(self, engine: "ScannerEngine", session_id: str, target: str = "unknown"):
        """
        Initialize scan transaction.

        Args:
            engine: ScannerEngine instance
            session_id: Session ID for this scan
            target: Target being scanned (for audit trail)
        """
        self._engine = engine
        self._session_id = session_id
        self._target = target
        self._committed = False
        self._rolled_back = False

        # Generate unique scan ID for this transaction
        import uuid
        self._scan_id = str(uuid.uuid4())

        # Staging area for transactional data
        self._staged_findings: List[Dict[str, Any]] = []
        self._staged_issues: List[Dict[str, Any]] = []
        self._staged_evidence: List[Dict[str, Any]] = []

    async def __aenter__(self) -> "ScanTransaction":
        """Enter transaction context and create scan record."""
        if self._engine._active_transaction:
            raise RuntimeError("Nested transactions not supported")
        self._engine._active_transaction = self

        # Create scan record for audit trail
        from core.data.db import Database
        db = Database.instance()
        try:
            await db.create_scan_record(self._scan_id, self._session_id, self._target)
        except Exception as e:
            logger.warning(f"[ScanTransaction] Failed to create scan record: {e}")

        logger.debug(f"[ScanTransaction] Started transaction {self._scan_id} for session {self._session_id}")
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """
        Exit transaction context.

        - If no exception: commit all staged data
        - If exception: rollback (discard all staged data)
        """
        if exc_type is None and not self._rolled_back:
            await self.commit()
        else:
            error_msg = str(exc_val) if exc_val else "canceled"
            await self.rollback(error_message=error_msg)

        self._engine._active_transaction = None
        return False  # Don't suppress exceptions

    def add_finding(self, finding: Dict[str, Any]) -> None:
        """Stage a finding for commit."""
        if self._committed or self._rolled_back:
            raise RuntimeError("Transaction already closed")
        self._staged_findings.append(finding)

    def add_issue(self, issue: Dict[str, Any]) -> None:
        """Stage an issue for commit."""
        if self._committed or self._rolled_back:
            raise RuntimeError("Transaction already closed")
        self._staged_issues.append(issue)

    def add_evidence(self, evidence: Dict[str, Any]) -> None:
        """Stage evidence for commit."""
        if self._committed or self._rolled_back:
            raise RuntimeError("Transaction already closed")
        self._staged_evidence.append(evidence)

    async def commit(self) -> None:
        """
        Commit all staged data to the database atomically.

        Commit order: findings → evidence → issues
        (Evidence may reference findings, issues may reference findings)

        After DB commit, updates in-memory stores to ensure UI sees
        committed data only.

        CRITICAL: Uses transaction-aware DB methods that do NOT acquire
        locks or commit internally, avoiding deadlock and preserving atomicity.
        """
        if self._committed or self._rolled_back:
            return  # Already handled

        from core.data.db import Database
        db = None  # Initialize for exception handler scope

        # Phase 0: Log transaction start
        logger.info(
            f"[ScanTransaction] START COMMIT {self._scan_id}: "
            f"staged={len(self._staged_findings)} findings, "
            f"{len(self._staged_issues)} issues, "
            f"{len(self._staged_evidence)} evidence"
        )

        try:
            db = Database.instance()

            # Ensure database is initialized
            if not db._initialized:
                await db.init()

            # Fail fast if DB unavailable
            if db._db_connection is None:
                raise RuntimeError("Database not available - cannot commit")

            # Use database lock for the entire transaction
            async with db._db_lock:
                conn = db._db_connection
                if conn is None:
                    raise RuntimeError("Database connection is not available")

                # BEGIN IMMEDIATE: Acquires reserved lock on DB file
                # Prevents other writers until we commit/rollback
                await conn.execute("BEGIN IMMEDIATE")

                try:
                    # Phase 1: Commit findings first (other entities may reference them)
                    for finding in self._staged_findings:
                        await db.save_finding_txn(finding, self._session_id, conn)

                    # Phase 2: Commit evidence (may reference findings)
                    for evidence in self._staged_evidence:
                        await db.save_evidence_txn(evidence, self._session_id, conn)

                    # Phase 3: Commit issues last (may reference findings)
                    for issue in self._staged_issues:
                        await db.save_issue_txn(issue, self._session_id, conn)

                    # Mark transaction complete - SINGLE commit point
                    await conn.commit()

                    self._committed = True
                    logger.info(
                        f"[ScanTransaction] DB COMMIT COMPLETE {self._scan_id}: "
                        f"{len(self._staged_findings)} findings, "
                        f"{len(self._staged_issues)} issues, "
                        f"{len(self._staged_evidence)} evidence"
                    )

                except Exception as e:
                    # Rollback on any error
                    try:
                        await conn.rollback()
                    except Exception:
                        pass  # Connection might be closed already
                    raise RuntimeError(f"Transaction commit failed: {e}") from e

            # Phase 4: After DB commit, update in-memory stores for UI
            # This ensures UI only sees committed data
            self._update_stores_after_commit()

            # Phase 5: Update scan record to 'committed' (outside transaction lock)
            if db is not None:
                try:
                    await db.update_scan_status(
                        self._scan_id,
                        'committed',
                        findings_count=len(self._staged_findings),
                        issues_count=len(self._staged_issues),
                        evidence_count=len(self._staged_evidence)
                    )
                except Exception as e:
                    logger.warning(f"[ScanTransaction] Failed to update scan record: {e}")

        except Exception as e:
            logger.error(f"[ScanTransaction] Commit error: {e}")
            # Mark as rolled back
            self._rolled_back = True

            # CRITICAL: Clear recon state to prevent stale data from affecting next scan
            self._engine._recon_edges.clear()
            self._engine._recon_edge_keys.clear()

            # Clear staged data
            self._staged_findings.clear()
            self._staged_issues.clear()
            self._staged_evidence.clear()

            # Update scan record to 'failed' - rollback() will NOT be called since we set _rolled_back
            if db is not None:
                try:
                    await db.update_scan_status(self._scan_id, 'failed', error_message=str(e))
                except Exception:
                    pass
            raise

    def _update_stores_after_commit(self) -> None:
        """
        Update in-memory stores after successful commit.

        This is called AFTER database commit to ensure UI only sees
        data that was successfully persisted.

        Phase 4: UI Publish - Update in-memory stores after DB commit
        """
        logger.info(
            f"[ScanTransaction] UI PUBLISH {self._scan_id}: "
            f"updating stores with {len(self._staged_findings)} findings, "
            f"{len(self._staged_issues)} issues, "
            f"{len(self._staged_evidence)} evidence"
        )

        # Update findings store
        if self._staged_findings:
            if self._engine.session:
                self._engine.session.findings.bulk_add(self._staged_findings, persist=True)
            else:
                findings_store.bulk_add(self._staged_findings, persist=True)

        # Update evidence store
        if self._staged_evidence:
            from core.data.evidence_store import EvidenceStore
            evidence_store = self._engine.session.evidence if self._engine.session else EvidenceStore.instance()
            for ev in self._staged_evidence:
                tool = ev.get("tool", "unknown")
                raw_output = ev.get("raw_output", "")
                metadata = ev.get("metadata", {})
                evidence_store.add_evidence(tool, raw_output, metadata, persist=True)

        # Update issues store (now that findings are committed)
        if self._staged_issues:
            if self._engine.session:
                self._engine.session.issues.replace_all(self._staged_issues, persist=True)
            else:
                issues_store.replace_all(self._staged_issues, persist=True)

        # Update killchain (after commit, run enrichment)
        if self._engine.session and hasattr(self._engine.session, 'killchain'):
            # Trigger enrichment now that we're committed
            enriched_count, edge_count = self._engine._refresh_enrichment()
            logger.info(
                f"[ScanTransaction] UI PUBLISH COMPLETE {self._scan_id}: "
                f"enrichment generated {enriched_count} issues, {edge_count} edges"
            )

    async def rollback(self, error_message: Optional[str] = None) -> None:
        """
        Rollback the transaction - discard all staged data.

        Clears staged data and does NOT update in-memory stores,
        ensuring UI doesn't see rolled-back data.

        Args:
            error_message: Optional error message for audit trail
        """
        if self._committed or self._rolled_back:
            return  # Already handled

        # Phase 0: Log rollback start
        logger.info(
            f"[ScanTransaction] START ROLLBACK {self._scan_id}: "
            f"discarding {len(self._staged_findings)} findings, "
            f"{len(self._staged_issues)} issues, "
            f"{len(self._staged_evidence)} evidence"
        )

        self._rolled_back = True

        # Clear staged data
        self._staged_findings.clear()
        self._staged_issues.clear()
        self._staged_evidence.clear()

        # CRITICAL: Clear recon state to prevent stale data from affecting next scan
        self._engine._recon_edges.clear()
        self._engine._recon_edge_keys.clear()

        # Update scan record to 'rolled_back'
        from core.data.db import Database
        db = Database.instance()
        try:
            await db.update_scan_status(self._scan_id, 'rolled_back', error_message=error_message)
        except Exception as e:
            logger.warning(f"[ScanTransaction] Failed to update scan record on rollback: {e}")

        logger.info(
            f"[ScanTransaction] ROLLBACK COMPLETE {self._scan_id}: "
            f"discarded for session {self._session_id}"
            + (f" - reason: {error_message}" if error_message else "")
        )

    @property
    def is_active(self) -> bool:
        """Check if transaction is currently active."""
        return not self._committed and not self._rolled_back

    def stats(self) -> Dict[str, int]:
        """Get statistics about staged data."""
        return {
            "findings": len(self._staged_findings),
            "issues": len(self._staged_issues),
            "evidence": len(self._staged_evidence),
        }


class ScannerEngine:
    """Runs supported scanning tools on macOS (no unsupported tool errors)."""

    def __init__(self, session=None):
        """
        Args:
            session: Optional ScanSession. If None, uses legacy global behavior or temp state.
        """
        self.session = session
        self._last_results: List[dict] = []
        self._fingerprint_cache: set[str] = set()
        self._fingerprint_cache_max = 10000  # Bound memory growth
        self._installed_meta: Dict[str, Dict[str, object]] = {}
        self._recon_edges: List[dict] = []
        self._recon_edge_keys: set[tuple] = set()

        # Task management state
        self._pending_tasks = []
        self._running_tasks = {}
        self._queue = asyncio.Queue()
        self._results_map = {}
        self._procs = {}

        # Resource guard to prevent exhaustion
        self.resource_guard = ResourceGuard(max_findings=10000, max_disk_mb=1000)

        # Scan transaction state
        self._active_transaction: Optional["ScanTransaction"] = None

    @staticmethod
    def _get_env_seconds(name: str, default: int) -> int:
        """Parse an integer number of seconds from environment, falling back to default.
        Returns 0 or negative to mean 'disabled' if provided as such.
        """
        val = os.environ.get(name)
        # Conditional branch.
        if not val:
            return default
        # Error handling block.
        try:
            return int(val)
        except ValueError:
            return default

    def _tool_timeout_seconds(self) -> int:
        """Per-tool wall-clock timeout in seconds (0 disables)."""
        return self._get_env_seconds("SCANNER_TOOL_TIMEOUT", DEFAULT_TOOL_TIMEOUT_SECONDS)

    def _tool_idle_timeout_seconds(self) -> int:
        """Per-tool idle-output timeout in seconds (0 disables)."""
        return self._get_env_seconds("SCANNER_TOOL_IDLE_TIMEOUT", DEFAULT_TOOL_IDLE_TIMEOUT_SECONDS)

    def _global_scan_timeout_seconds(self) -> int:
        """Global scan timeout in seconds (0 disables)."""
        return self._get_env_seconds("SCANNER_GLOBAL_TIMEOUT", DEFAULT_GLOBAL_SCAN_TIMEOUT_SECONDS)

    async def _global_timeout_runner(self, timeout_secs: int, cancel_flag, queue: asyncio.Queue[str]):
        """Watchdog that enforces a global scan timeout by triggering cancellation and
        attempting to terminate/kill any running subprocesses.
        """
        # Error handling block.
        try:
            await asyncio.sleep(max(0, timeout_secs))
        except asyncio.CancelledError:
            return
        # If already canceled, do nothing
        try:
            is_canceled = cancel_flag.is_set()
        except Exception:
            is_canceled = False
        # Conditional branch.
        if is_canceled:
            return
        # Signal cancellation
        try:
            cancel_flag.set()
        except Exception:
            # If cancel_flag doesn't support set(), we still proceed with termination best-effort
            pass
        await queue.put(f"[scanner] ⏱️ Global timeout {timeout_secs}s reached; canceling scan and terminating tools...")
        # Best-effort termination of running subprocesses
        for name, proc in list(self._procs.items()):
            if proc.returncode is None:
                try:
                    proc.terminate()
                    await queue.put(f"[{name}] terminated due to global timeout")
                except ProcessLookupError:
                    pass
                except Exception as exc:
                    await queue.put(f"[{name}] termination error on timeout: {exc}")
        # Give them a moment, then force-kill stubborn ones
        await asyncio.sleep(0.2)
        # Loop over items.
        for name, proc in list(self._procs.items()):
            if proc.returncode is None:
                try:
                    proc.kill()
                    await queue.put(f"[{name}] force-killed after global timeout")
                except ProcessLookupError:
                    pass
                except Exception as exc:
                    await queue.put(f"[{name}] force-kill error on timeout: {exc}")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    async def scan(self, target: str, selected_tools: List[str] | None = None, cancel_flag=None) -> AsyncGenerator[str, None]:
        """
        Async generator that yields log-style strings while the supported tools run.
        """
        # CRITICAL: Use Vanguard to preflight check tools availability & compatibility
        from core.engine.vanguard import Vanguard
        
        # 1. Get raw installed
        installed = self._detect_installed()
        # 2. Filter via Vanguard
        # We need a list of names to check.
        # Vanguard check takes a list and returns a valid list.
        # But here we have a dict.
        candidates = list(installed.keys())
        valid_names = Vanguard.preflight_check(candidates)
        
        # Re-build installed map with only valid tools
        self._installed_meta = {k: v for k, v in installed.items() if k in valid_names}
        
        # Allow logic to proceed using filtered meta
        installed = self._installed_meta
        
        # Reset state for this run
        self._last_results = []
        self._recon_edges = []
        self._procs = {}
        self._pending_tasks = []
        
        selected_clean = [t for t in (selected_tools or []) if t in TOOLS]
        # ... logic continues ...
        tools_to_run = list(installed.keys())
        missing: List[str] = []
        # Conditional branch.
        if selected_clean:
            tools_to_run = [t for t in selected_clean if t in installed]
            missing = [t for t in selected_clean if t not in installed]
        # Conditional branch.
        if selected_clean:
            yield f"[scanner] Selected tools: {', '.join(selected_clean)}"
        # Conditional branch.
        if missing:
            msg = f"[scanner] ⚠️ WARNING: The following tools were requested but NOT found in PATH: {', '.join(missing)}"
            yield msg
            # Also log to console for debugging
            print(msg)
            print(f"[scanner] Current PATH: {os.environ.get('PATH')}")

        # Conditional branch.
        if not tools_to_run:
            yield "[scanner] No supported tools available in PATH. Skipping tool phase."
            return
        else:
            yield f"Installed tools: {', '.join(tools_to_run)}"

            # Use session ID or temp ID
            sess_id = self.session.session_id if self.session else "global_scan"

            # RESET STATE for this new scan
            self._fingerprint_cache.clear()
            self.resource_guard.reset()

            # WRAPPER: All tool execution and findings should be atomic
            # FIX: The entire queue processing loop MUST be inside the transaction context
            async with ScanTransaction(self, sess_id, target) as txn:
                try:
                    queue: asyncio.Queue[str] = asyncio.Queue()
                    running: Dict[str, asyncio.Task[List[dict]]] = {}
                    pending = list(tools_to_run)

                    # Expose state for dynamic additions and watchdog
                    self._pending_tasks = pending
                    self._running_tasks = running
                    self._queue = queue
                    self._results_map = {}  # Initialize results map

                    # Cancellation and global timeout setup
                    local_cancel = cancel_flag or asyncio.Event()
                    watchdog_task = None
                    global_timeout = self._global_scan_timeout_seconds()
                    if global_timeout and global_timeout > 0:
                        watchdog_task = asyncio.create_task(self._global_timeout_runner(global_timeout, local_cancel, self._queue))

                    # FIXED: Wait for ALL tasks to complete, not just until slots fill
                    while self._pending_tasks or self._running_tasks:
                        # Fill available slots
                        # Check for cancellation before launching new tasks
                        if local_cancel.is_set():
                            await self._queue.put("[scanner] cancellation requested; stopping new tasks")
                            self._pending_tasks.clear()
                            break

                        while self._pending_tasks and len(self._running_tasks) < MAX_CONCURRENT_TOOLS:
                            task_def = self._pending_tasks.pop(0)
                            # Handle both simple strings (legacy) and dicts (dynamic args)
                            if isinstance(task_def, str):
                                tool = task_def
                                args = None
                            else:
                                tool = task_def["tool"]
                                args = task_def.get("args")

                            self._running_tasks[tool] = asyncio.create_task(
                                self._run_tool_task(tool, target, self._queue, args, local_cancel)
                            )
                            await self._queue.put(f"[scanner] Started {tool} (dynamic launch)")

                        if not self._running_tasks:
                            break

                        done, _ = await asyncio.wait(list(self._running_tasks.values()), timeout=0.2)
                        while not self._queue.empty():
                            yield self._queue.get_nowait()

                        for finished in done:
                            tool_name = next((name for name, t in self._running_tasks.items() if t is finished), None)
                            if tool_name:
                                try:
                                    self._results_map[tool_name] = finished.result()
                                except Exception as exc: # pragma: no cover
                                    self._results_map[tool_name] = exc
                                    await self._queue.put(f"[{tool_name}] task error: {exc}")
                                del self._running_tasks[tool_name]
                        
                        if not done:
                            # If cancellation was requested mid-run, try to wait for running tasks to finish.
                            if local_cancel.is_set():
                                # Best-effort: terminate running subprocesses and wait for tasks to notice.
                                await self._queue.put("[scanner]Cancellation detected - terminating running tools...")
                                for name, proc in list(self._procs.items()):
                                    if proc.returncode is None:
                                        try:
                                            proc.terminate()
                                            await self._queue.put(f"[{name}] terminated due to cancellation")
                                        except ProcessLookupError:
                                            pass
                                
                                # Give subprocesses a moment to terminate
                                await asyncio.sleep(0.2)
                                
                                # Force kill any stubborn processes
                                for name, proc in list(self._procs.items()):
                                    if proc.returncode is None:
                                        try:
                                            proc.kill()
                                            await self._queue.put(f"[{name}] force-killed after termination timeout")
                                        except ProcessLookupError:
                                            pass
                                
                                await self._queue.put("[scanner] All tools terminated due to cancellation")
                    
                    # Stop global watchdog if running
                    if 'watchdog_task' in locals() and watchdog_task is not None:
                        try:
                            watchdog_task.cancel()
                        except Exception:
                            pass
                    
                    while not self._queue.empty():
                        yield self._queue.get_nowait()

                    # If canceled, explicitly rollback, cleanup, and abort (do not commit partials)
                    if local_cancel.is_set():
                        await txn.rollback()
                        # CRITICAL: Call shutdown to cleanup any running tasks/processes
                        await self.shutdown(reason="canceled")
                        yield "[scanner] Scan canceled - Transaction Rolled Back."
                        return

                    # CRITICAL FIX: Aggregate all findings from tool results
                    all_findings: List[dict] = []
                    for tool_name, result in self._results_map.items():
                        if isinstance(result, list):
                            all_findings.extend(result)
                    
                    # Normalize and deduplicate findings
                    normalized = self._normalize_findings(all_findings)
                    self._last_results = normalized

                    # CRITICAL: When transactional, stage findings ONLY
                    # Do NOT update UI stores until after commit (prevents UI pollution on rollback)
                    if txn.is_active:
                        for f in normalized:
                            txn.add_finding(f)

                        # Build recon edges for later enrichment
                        recon_edges = self._build_recon_edges(normalized)
                        self._record_recon_edges(recon_edges)

                        # Note: We deliberately do NOT update the in-memory stores here
                        # They will be updated after commit (see ScanTransaction.commit())
                        # Enrichment and issue generation will also happen after commit
                    else:
                        # Non-transactional path: update stores directly and run enrichment
                        if self.session:
                            self.session.findings.bulk_add(normalized)
                        else:
                            findings_store.bulk_add(normalized)

                        # Build recon edges
                        recon_edges = self._build_recon_edges(normalized)
                        self._record_recon_edges(recon_edges)

                        # Run enrichment (non-transactional path)
                        enriched_count, edge_count = self._refresh_enrichment()

                        yield f"[scanner] Processed {len(normalized)} findings, {enriched_count} issues, {edge_count} killchain edges"

                except Exception as e:
                    # On unhandled exception, ensuring rollback
                    await txn.rollback()
                    logger.error(f"[ScannerEngine] Critical error, rolling back: {e}")
                    raise e

            # Transactional path: yield summary after commit
            # The transaction has committed here, and _update_stores_after_commit() has run
            # Note: txn.is_active is False here because the context manager has exited
            # We check _committed instead
            if hasattr(txn, '_committed') and txn._committed:
                # Enrichment was run in _update_stores_after_commit()
                # Get counts from the transaction stats
                stats = txn.stats()
                yield f"[scanner] Processed {stats['findings']} findings, committed transaction"

    async def shutdown(self, reason: str = "shutdown") -> None:
        """
        Best-effort cleanup for cancellation/error paths.

        Terminates any running subprocesses and cancels any in-flight tool tasks
        spawned by this engine instance. Safe to call multiple times.
        """
        # Stop launching new tasks.
        try:
            self._pending_tasks.clear()
        except Exception:
            pass

        # Cancel running tasks first (they may be awaiting process IO).
        tasks = []
        # Error handling block.
        try:
            tasks = list(self._running_tasks.values())
            for task in tasks:
                task.cancel()
        except Exception:
            tasks = []

        # Terminate processes.
        procs = []
        # Error handling block.
        try:
            procs = list(self._procs.items())
        except Exception:
            procs = []

        # Loop over items.
        for name, proc in procs:
            if proc is None:
                continue
            if proc.returncode is not None:
                continue
            try:
                proc.terminate()
            except ProcessLookupError:
                pass
            except Exception as exc:
                logger.debug(f"[scanner] terminate failed for {name} ({reason}): {exc}")

        # Give processes a brief moment to exit, then force-kill stubborn ones.
        try:
            await asyncio.sleep(0.2)
        except asyncio.CancelledError:
            # Continue with best-effort cleanup even if cancelled.
            pass

        # Loop over items.
        for name, proc in procs:
            if proc is None:
                continue
            if proc.returncode is not None:
                continue
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            except Exception as exc:
                logger.debug(f"[scanner] kill failed for {name} ({reason}): {exc}")

        # Await task completion without propagating cancellation outward.
        if tasks:
            try:
                await asyncio.gather(*tasks, return_exceptions=True)
            except Exception:
                pass

        # Best-effort waits for processes to fully exit (avoid zombies).
        for name, proc in procs:
            if proc is None:
                continue
            try:
                if proc.returncode is None:
                    await asyncio.wait_for(proc.wait(), timeout=1.0)
            except asyncio.TimeoutError:
                pass
            except Exception:
                pass

        # Error handling block.
        try:
            self._running_tasks.clear()
        except Exception:
            pass
        # Error handling block.
        try:
            self._procs.clear()
        except Exception:
            pass


    def queue_task(self, tool: str, args: List[str] = None):
        """
        Dynamically add a task to the running scan.

        Args:
            tool: Tool name (must be in TOOLS allowlist)
            args: Optional arguments for the tool

        Raises:
            ValueError: If tool is not in the TOOLS allowlist
        """
        # SECURITY: Validate tool against allowlist to prevent RCE
        if tool not in TOOLS:
            raise ValueError(f"Unknown tool '{tool}'. Must be one of: {', '.join(TOOLS)}")

        # Optional: Validate tool is installed
        if hasattr(self, "_installed_meta") and tool not in self._installed_meta:
            logger.warning(f"[queue_task] Tool '{tool}' is not installed, adding anyway (will fail during execution)")

        if hasattr(self, "_pending_tasks"):
            self._pending_tasks.append({"tool": tool, "args": args})

    async def run_all(self, target: str):
        """
        Compatibility helper: run the scan generator and return aggregated findings.
        """
        # Async loop over items.
        async for _ in self.scan(target):
            # Discard streamed lines – this helper mirrors the old API surface.
            pass
        return list(self._last_results)

    # ----------------------------------------------------------------------
    # Helpers
    # ----------------------------------------------------------------------
    def _detect_installed(self) -> Dict[str, Dict[str, object]]:
        """Function _detect_installed."""
        return get_installed_tools()

    def _normalize_findings(self, items: List[dict] | None) -> List[dict]:
        """Function _normalize_findings."""
        normalized: List[dict] = []
        # Conditional branch.
        if not items:
            return normalized

        # Bound fingerprint cache to prevent unbounded memory growth
        if len(self._fingerprint_cache) > self._fingerprint_cache_max:
            self._fingerprint_cache.clear()
            logger.debug(f"[ScannerEngine] Cleared fingerprint cache (exceeded {self._fingerprint_cache_max})")

        # Loop over items.
        for item in items:
            entry = dict(item)
            entry.setdefault("message", entry.get("proof", ""))
            entry.setdefault("tags", [])
            entry.setdefault("families", [])
            entry.setdefault("metadata", {})
            severity = str(entry.get("severity", "INFO")).upper()
            entry["severity"] = severity
            original_target = entry.get("target") or entry.get("asset") or "unknown"
            asset = self._normalize_asset(original_target)
            entry.setdefault("metadata", {})
            entry["metadata"].setdefault("original_target", original_target)
            entry["asset"] = asset
            entry["target"] = asset
            fingerprint = entry.setdefault(
                "fingerprint",
                f"{entry.get('tool', 'scanner')}:{asset}:{entry.get('type', 'generic')}:{severity}"
            )
            if fingerprint in self._fingerprint_cache:
                continue
            self._fingerprint_cache.add(fingerprint)
            normalized.append(entry)
        return normalized

    def get_last_results(self) -> List[dict]:
        """Return the findings produced by the most recent scan."""
        return list(self._last_results)

    def _build_recon_edges(self, findings: List[dict]) -> List[dict]:
        """Function _build_recon_edges."""
        edges: List[dict] = []
        # Loop over items.
        for item in findings:
            families = item.get("families", [])
            recon_families = [fam for fam in families if fam.startswith("recon-phase")]
            if not recon_families:
                continue
            metadata = item.get("metadata") or {}
            variant = metadata.get("variant") or "behavior"
            for fam in recon_families:
                edges.append({
                    "source": item.get("asset", "unknown"),
                    "target": f"{fam}:{variant}",
                    "label": item.get("type"),
                    "severity": item.get("severity"),
                    "tags": item.get("tags", []),
                    "signal": item.get("message"),
                    "families": families,
                    "edge_type": "behavioral-signal",
                })
        return edges

    def _record_recon_edges(self, edges: List[dict]):
        """Function _record_recon_edges."""
        # Loop over items.
        for edge in edges:
            key = self._edge_signature(edge)
            if key in self._recon_edge_keys:
                continue
            self._recon_edge_keys.add(key)
            self._recon_edges.append(edge)

    def _edge_signature(self, edge: dict) -> tuple:
        """Function _edge_signature."""
        return (
            edge.get("source"),
            edge.get("target"),
            edge.get("label"),
            edge.get("edge_type"),
            edge.get("severity"),
        )

    def _refresh_enrichment(self) -> tuple[int, int]:
        """
        Enrich findings with issues and killchain analysis.

        Transactional Behavior:
        - When in transactional mode: Stage data only, do NOT update stores/UI
        - When NOT in transactional mode: Update stores and run correlator

        This prevents:
        - Double commit (staging + replace_all)
        - UI pollution from rolled-back scans
        - Correlator side effects during transactions
        """
        is_transactional = self._active_transaction and self._active_transaction.is_active

        # Step 1: Generate issues from findings
        if self._last_results:
            enriched, _, killchain_edges = apply_rules(self._last_results)
        else:
            enriched, _, killchain_edges = [], [], []

        # Step 2: Build combined killchain edges
        combined_edges = list(killchain_edges) + list(self._recon_edges)

        # Step 3: Handle issues
        if is_transactional:
            # Transactional: Stage only, do NOT update stores
            for issue in enriched:
                self._active_transaction.add_issue(issue)
        else:
            # Non-transactional: Update stores directly
            if self.session:
                self.session.issues.replace_all(enriched, persist=True)
            else:
                issues_store.replace_all(enriched, persist=True)

        # Step 4: Handle killchain edges
        if is_transactional:
            # Transactional: Do NOT update stores (no DB persistence for killchain currently)
            # Just skip entirely - correlator will run after commit if needed
            pass
        else:
            # Non-transactional: Update stores and run correlator
            if self.session:
                self.session.killchain.replace_all(combined_edges, persist=True)
            else:
                killchain_store.replace_all(combined_edges, persist=True)

            # -----------------------------------------------------------------
            # Cartographer: Graph Intelligence (Layer 5) - NON-TRANSACTIONAL ONLY
            # -----------------------------------------------------------------
            # Skip correlator during transaction to prevent side effects
            source_findings = self.session.findings.get_all() if self.session else findings_store.get_all()

            # Transform to Nodes for Correlator
            nodes = []
            for f in source_findings:
                asset = f.get("asset") or f.get("target") or "unknown"
                if asset == "unknown":
                    continue

                attributes = {}
                meta = f.get("metadata", {})
                for key in ["simhash", "favicon_hash", "ssl_serial", "ga_id"]:
                    if val := meta.get(key):
                        attributes[key] = val

                if attributes:
                    nodes.append({"id": asset, "attributes": attributes})

            # Run correlator and update killchain
            if nodes:
                correlator = GraphCorrelator()
                implied_edges = correlator.process(nodes)

                if implied_edges:
                    combined_edges.extend(implied_edges)

                    # Re-save with correlator results
                    if self.session:
                        self.session.killchain.replace_all(combined_edges, persist=True)
                    else:
                        killchain_store.replace_all(combined_edges, persist=True)

        return len(enriched), len(combined_edges)

    async def _run_tool_task(
        self,
        tool: str,
        target: str,
        queue: asyncio.Queue[str],
        custom_args: List[str] = None,
        cancel_flag=None,
    ) -> List[dict]:
        """AsyncFunction _run_tool_task."""
        meta_override = self._installed_meta.get(tool)

        tool_timeout = self._tool_timeout_seconds()
        idle_timeout = self._tool_idle_timeout_seconds()
        
        # Conditional branch.
        if custom_args:
            # Use custom args directly if provided (for autonomous actions)
            cmd = [tool] + custom_args
            # Replace {target} placeholder if present in custom args
            cmd = [arg.replace("{target}", target) for arg in cmd]
            stdin_input = None
        else:
            cmd, stdin_input = get_tool_command(tool, target, meta_override)
            
        await queue.put(f"--- Running {tool} ---")
        # Error handling block.
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.PIPE if stdin_input else None,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            # Track proc so cancellation can terminate it.
            self._procs[tool] = proc

            # Write to stdin if the tool requires it
            if stdin_input and proc.stdin:
                proc.stdin.write((stdin_input + "\n").encode("utf-8"))
                proc.stdin.close()
        except FileNotFoundError:
            msg = f"[{tool}] NOT INSTALLED or not in PATH."

            # Transactional: stage evidence only, do NOT update stores
            if self._active_transaction and self._active_transaction.is_active:
                self._active_transaction.add_evidence({
                    "tool": tool, "raw_output": msg, "metadata": {"target": target, "error": "not_found"}
                })
            else:
                # Non-transactional: update stores directly
                evidence_store = self.session.evidence if self.session else EvidenceStore.instance()
                evidence_store.add_evidence(tool, msg, {"target": target, "error": "not_found"})

            await queue.put(msg)
            return []
        except Exception as exc:
            msg = f"[{tool}] failed to start: {exc}"

            # Transactional: stage evidence only, do NOT update stores
            if self._active_transaction and self._active_transaction.is_active:
                self._active_transaction.add_evidence({
                    "tool": tool, "raw_output": msg, "metadata": {"target": target, "error": str(exc)}
                })
            else:
                # Non-transactional: update stores directly
                evidence_store = self.session.evidence if self.session else EvidenceStore.instance()
                evidence_store.add_evidence(tool, msg, {"target": target, "error": str(exc)})

            await queue.put(msg)
            return []

        start_time = asyncio.get_running_loop().time()
        timed_out_reason = None
        truncated = False
        output_bytes = 0

        output_lines: List[str] = []
        assert proc.stdout is not None

        # Get disk limit to enforce during read (not after)
        max_bytes = self.resource_guard.max_disk_mb * 1024 * 1024
        # While loop.
        while True:
            # Cooperative cancellation: terminate and break
            if cancel_flag is not None and cancel_flag.is_set():
                try:
                    if proc.returncode is None:
                        proc.terminate()
                except ProcessLookupError:
                    pass
                break
            # Read a line with optional idle timeout
            try:
                if idle_timeout and idle_timeout > 0:
                    line = await asyncio.wait_for(proc.stdout.readline(), timeout=idle_timeout)
                else:
                    line = await proc.stdout.readline()
            except asyncio.TimeoutError:
                timed_out_reason = "idle"
                await queue.put(f"[{tool}] idle timeout after {idle_timeout}s without output; terminating")
                try:
                    if proc.returncode is None:
                        proc.terminate()
                except ProcessLookupError:
                    pass
                break
            if not line:
                break
            text = line.decode("utf-8", errors="ignore").rstrip()
            if not text:
                # Even empty lines count as activity for idle timeout because we received a line
                continue
            output_lines.append(text)
            await queue.put(f"[{tool}] {text}")
            # Check wall-clock timeout
            if tool_timeout and tool_timeout > 0:
                now = asyncio.get_running_loop().time()
                if (now - start_time) > tool_timeout:
                    timed_out_reason = "wall-clock"
                    await queue.put(f"[{tool}] time limit {tool_timeout}s exceeded; terminating")
                    try:
                        if proc.returncode is None:
                            proc.terminate()
                    except ProcessLookupError:
                        pass
                    break

        # Ensure the process exits; force-kill if needed
        try:
            exit_code = await asyncio.wait_for(proc.wait(), timeout=2)
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            exit_code = await proc.wait()
        await queue.put(f"[{tool}] Exit code: {exit_code}")
        # Cleanup tracked proc
        self._procs.pop(tool, None)

        output_text = "\n".join(output_lines)

        # Check disk usage before storing evidence
        output_size = len(output_text.encode('utf-8'))
        try:
            self.resource_guard.check_disk(output_size)
        except ResourceExhaustedError as e:
            await queue.put(f"[{tool}] Resource limit exceeded: {e}")
            logger.warning(f"[{tool}] {e}")
            return []

        # Use session-scoped evidence store if available, otherwise global singleton
        evidence_store = self.session.evidence if self.session else EvidenceStore.instance()
        
        ev_meta = {
            "target": target,
            "exit_code": exit_code,
            "lines": len(output_lines),
            "timed_out": bool(timed_out_reason),
            "timeout_reason": timed_out_reason,
            "canceled": bool(cancel_flag and getattr(cancel_flag, 'is_set', lambda: False)())
        }

        # Transactional: stage evidence only, do NOT update stores
        if self._active_transaction and self._active_transaction.is_active:
            self._active_transaction.add_evidence({
                "tool": tool, "raw_output": output_text, "metadata": ev_meta
            })
        else:
            # Non-transactional: update stores directly
            evidence_store = self.session.evidence if self.session else EvidenceStore.instance()
            evidence_store.add_evidence(tool, output_text, ev_meta)

        # Error handling block.
        try:
            findings = ScannerBridge.classify(tool, target, output_text)

            # Check findings count limit
            try:
                self.resource_guard.check_findings(len(findings))
            except ResourceExhaustedError as e:
                await queue.put(f"[{tool}] {e} - truncating results")
                logger.warning(f"[{tool}] {e}")
                # Return empty findings to prevent overflow
                return []

            # Session-scoped scans own their lifecycle via the canonical EventBus path.
            # Avoid global TaskRouter side effects (global stores / non-session DB writes).
            if self.session is None:
                try:
                    router = TaskRouter.instance()
                    router.handle_tool_output(
                        tool_name=tool,
                        stdout=output_text,
                        stderr="",
                        rc=exit_code,
                        metadata={"target": target, "findings_count": len(findings)},
                    )
                except Exception as router_err:
                    logger.warning(f"[{tool}] TaskRouter processing error: {router_err}")

            return findings
        except Exception as exc:
            err = f"[{tool}] classifier error: {exc}"

            # Transactional: stage evidence only, do NOT update stores
            if self._active_transaction and self._active_transaction.is_active:
                self._active_transaction.add_evidence({
                    "tool": f"{tool}_classifier_error", "raw_output": err, "metadata": {"target": target}
                })
            else:
                # Non-transactional: update stores directly
                evidence_store = self.session.evidence if self.session else EvidenceStore.instance()
                evidence_store.add_evidence(f"{tool}_classifier_error", err, {"target": target})
            await queue.put(err)
            return []

    def _normalize_asset(self, target: str) -> str:
        """Function _normalize_asset."""
        parsed = urlparse(target)
        host = parsed.hostname or target
        # Conditional branch.
        if host.startswith("www."):
            host = host[4:]
        return host
