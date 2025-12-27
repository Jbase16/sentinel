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
        async with ScanTransaction(engine, session_id) as txn:
            # Run scan, collect results
            txn.add_finding(finding)
            txn.add_result(result)
            # On exit, all results are atomically committed
            # On exception, all results are rolled back

    Design Pattern: Two-Phase Commit
    - Phase 1 (active): Accumulate results in memory
    - Phase 2 (commit): Atomically write to database
    - On error: Rollback (discard all accumulated results)
    """

    def __init__(self, engine: "ScannerEngine", session_id: str):
        """
        Initialize scan transaction.

        Args:
            engine: ScannerEngine instance
            session_id: Session ID for this scan
        """
        self._engine = engine
        self._session_id = session_id
        self._committed = False
        self._rolled_back = False

        # Staging area for transactional data
        self._staged_findings: List[Dict[str, Any]] = []
        self._staged_issues: List[Dict[str, Any]] = []
        self._staged_evidence: List[Dict[str, Any]] = []

    async def __aenter__(self) -> "ScanTransaction":
        """Enter transaction context."""
        if self._engine._active_transaction:
            raise RuntimeError("Nested transactions not supported")
        self._engine._active_transaction = self
        logger.debug(f"[ScanTransaction] Started transaction for session {self._session_id}")
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
            await self.rollback()

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

        Uses a single database transaction to ensure all data
        is written together or not at all.
        """
        if self._committed or self._rolled_back:
            return  # Already handled

        try:
            # Import here to avoid circular dependency
            from core.data.db import Database

            db = Database.instance()

            # Use database transaction for atomicity
            async with db._db_lock:
                conn = db._db_connection
                if conn is None:
                    await db.init()
                    conn = db._db_connection

                # Begin explicit transaction
                await conn.execute("BEGIN IMMEDIATE")

                try:
                    # Commit all findings
                    for finding in self._staged_findings:
                        await db._save_finding_impl(finding, self._session_id)

                    # Commit all issues
                    for issue in self._staged_issues:
                        await db._save_issue_impl(issue, self._session_id)

                    # Commit all evidence
                    for evidence in self._staged_evidence:
                        await db._save_evidence_impl(evidence, self._session_id)

                    # Mark transaction complete
                    await conn.commit()

                    self._committed = True
                    logger.info(
                        f"[ScanTransaction] Committed: "
                        f"{len(self._staged_findings)} findings, "
                        f"{len(self._staged_issues)} issues, "
                        f"{len(self._staged_evidence)} evidence"
                    )

                except Exception as e:
                    # Rollback on any error
                    await conn.rollback()
                    raise RuntimeError(f"Transaction commit failed: {e}") from e

        except Exception as e:
            logger.error(f"[ScanTransaction] Commit error: {e}")
            # Mark as rolled back to prevent retry
            self._rolled_back = True
            raise

    async def rollback(self) -> None:
        """
        Rollback the transaction - discard all staged data.

        This is called automatically on exception or can be called
        explicitly to cancel the scan.
        """
        if self._committed or self._rolled_back:
            return  # Already handled

        self._rolled_back = True
        self._staged_findings.clear()
        self._staged_issues.clear()
        self._staged_evidence.clear()

        logger.info(
            f"[ScanTransaction] Rolled back transaction for session {self._session_id}"
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
            queue: asyncio.Queue[str] = asyncio.Queue()
            running: Dict[str, asyncio.Task[List[dict]]] = {}
            pending = list(tools_to_run)
            results_map: Dict[str, List[dict] | Exception] = {}

            # Expose queue for dynamic additions
            self._pending_tasks = pending
            self._running_tasks = running
            self._queue = queue
            self._results_map = results_map

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
            
            # CRITICAL FIX: Aggregate all findings from tool results
            all_findings: List[dict] = []
            for tool_name, result in self._results_map.items():
                if isinstance(result, list):
                    all_findings.extend(result)
            
            # Normalize and deduplicate findings
            normalized = self._normalize_findings(all_findings)
            self._last_results = normalized
            
            # CRITICAL: Populate findings store (Session-Scoped or Global)
            if self.session:
                self.session.findings.bulk_add(normalized)
            else:
                # Fallback for legacy calls
                findings_store.bulk_add(normalized)
            
            # Build recon edges and update stores
            recon_edges = self._build_recon_edges(normalized)
            self._record_recon_edges(recon_edges)
            enriched_count, edge_count = self._refresh_enrichment()
            
            yield f"[scanner] Processed {len(normalized)} findings, {enriched_count} issues, {edge_count} killchain edges"

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
        """
        # Conditional branch.
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
        """Function _refresh_enrichment."""
        # Conditional branch.
        if self._last_results:
            enriched, _, killchain_edges = apply_rules(self._last_results)
        else:
            enriched, killchain_edges = [], []

        # Conditional branch.
        if self.session:
            self.session.issues.replace_all(enriched)
            combined_edges = list(killchain_edges) + list(self._recon_edges)
            self.session.killchain.replace_all(combined_edges)
        else:
            issues_store.replace_all(enriched)
            combined_edges = list(killchain_edges) + list(self._recon_edges)
            killchain_store.replace_all(combined_edges)
        
        # ---------------------------------------------------------------------
        # Cartographer: Graph Intelligence (Layer 5)
        # ---------------------------------------------------------------------
        # 1. Gather all data points
        source_findings = self.session.findings.get_all() if self.session else findings_store.get_all()
        
        # 2. Transform to Nodes for Correlator
        # Correlator expects: {"id": "asset_name", "attributes": {...}}
        nodes = []
        # Loop over items.
        for f in source_findings:
            # Only fingerprint "Asset" type findings or those with clear metadata signals
            # Ideally each Asset has one canonical node. This simplification treats every finding as a potential source of traits.
            # A better approach (future): Aggregate findings per asset first.
            asset = f.get("asset") or f.get("target") or "unknown"
            if asset == "unknown":
                continue
                
            attributes = {}
            # Extract potential fingerprints from metadata
            meta = f.get("metadata", {})
            for key in ["simhash", "favicon_hash", "ssl_serial", "ga_id"]:
                if val := meta.get(key):
                    attributes[key] = val
            
            if attributes:
                nodes.append({"id": asset, "attributes": attributes})
                
        # 3. Analyze
        if nodes:
            correlator = GraphCorrelator()
            implied_edges = correlator.process(nodes)
            
            # 4. Integrate
            if implied_edges:
                # Merge with existing edges
                # Note: This simplistic merge might duplicate if run repeatedly without deduplication logic
                # But _refresh_enrichment replaces ALL edges usually.
                # Here we are appending to the set we just built.
                combined_edges.extend(implied_edges)
                
                # Re-save
                if self.session:
                    self.session.killchain.replace_all(combined_edges)
                else:
                    killchain_store.replace_all(combined_edges)

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
            # Use session-scoped evidence store if available, otherwise global singleton
            evidence_store = self.session.evidence if self.session else EvidenceStore.instance()
            evidence_store.add_evidence(tool, msg, {"target": target, "error": "not_found"})
            await queue.put(msg)
            return []
        except Exception as exc:
            msg = f"[{tool}] failed to start: {exc}"
            evidence_store = self.session.evidence if self.session else EvidenceStore.instance()
            evidence_store.add_evidence(tool, msg, {"target": target, "error": str(exc)})
            await queue.put(msg)
            return []

        start_time = asyncio.get_running_loop().time()
        timed_out_reason = None

        output_lines: List[str] = []
        assert proc.stdout is not None
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
        evidence_store.add_evidence(tool, output_text, {
            "target": target,
            "exit_code": exit_code,
            "lines": len(output_lines),
            "timed_out": bool(timed_out_reason),
            "timeout_reason": timed_out_reason,
            "canceled": bool(cancel_flag and getattr(cancel_flag, 'is_set', lambda: False)())
        })

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
