"""Module scanner_engine: inline documentation for /Users/jason/Developer/sentinelforge/core/engine/scanner_engine.py.

PURPOSE
- macOS-compatible active scanner engine for SentinelForge.
- Orchestrates tool execution, streams live output, classifies results into findings,
  and persists findings/evidence/issues atomically via ScanTransaction.

KEY RESPONSIBILITIES
- Detect installed tools and filter via Vanguard.
- Execute multiple tools concurrently with resource limits and cancellation.
- Normalize and deduplicate findings deterministically.
- Stage all scan artifacts (findings, evidence, issues) and commit them atomically.

INTEGRATION
- Depends on:
  - core.toolkit.tools (tool registry + command builder)
  - core.cortex.scanner_bridge (classification)
  - core.toolkit.vuln_rules (issue/rule engine)
  - core.data.db (SQLite persistence)
  - core.engine.vanguard (preflight tool compatibility)
- Used by:
  - ScanSession / UI event pipeline (via session-scoped stores)
  - Legacy global behavior (when session is None)
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import threading
from collections import deque
from urllib.parse import urlparse
from typing import Any, AsyncGenerator, Deque, Dict, List, Optional, Set, Tuple

from core.data.findings_store import findings_store
from core.data.evidence_store import EvidenceStore
from core.cortex.scanner_bridge import ScannerBridge
from core.toolkit.vuln_rules import apply_rules
from core.data.issues_store import issues_store
from core.data.killchain_store import killchain_store
from core.toolkit.tools import TOOLS, get_tool_command, get_installed_tools
from core.base.task_router import TaskRouter
from core.cortex.correlator import GraphCorrelator
from core.base.config import get_config
from core.errors import ToolError

logger = logging.getLogger(__name__)


# ----------------------------
# Self-Healing (Resilience)
# ----------------------------
from core.sentient.diagnosis import ErrorClassifier, ErrorType, Diagnosis

class ResilienceContext:
    """
    Manages the 'Life Loop' of a scan task.
    Decides whether to retry, abort, or ignore failures.
    """
    def __init__(self, engine: "ScannerEngine", max_retries: int = 3):
        self.engine = engine
        self.max_retries = max_retries
        self.errors: List[Exception] = []
        self._classifier = ErrorClassifier()

    def diagnose(self, exc: Exception) -> str:
        diagnosis = self._classifier.diagnose(exc)
        logger.warning(f"[Resilience] Failure Diagnosed: {diagnosis.type} ({diagnosis.reason}) -> {diagnosis.recommendation}")
        
        if diagnosis.type == ErrorType.TRANSIENT:
            return "RETRY"
        elif diagnosis.type == ErrorType.WAF_BLOCK:
            # Trigger Stealth Mode
            if hasattr(self.engine, "enable_stealth_mode"):
                self.engine.enable_stealth_mode()
            return "RETRY" # Simple retry for now, eventually COOLDOWN
        elif diagnosis.type == ErrorType.RESOURCE:
            return "ABORT"
        else:
            return "FAIL"

    async def execute_with_retry(self, func, *args, **kwargs):
        """
        Execute a function with adaptive retry logic.
        """
        attempts = 0
        while attempts <= self.max_retries:
            try:
                return await func(*args, **kwargs)
            except Exception as e:
                attempts += 1
                decision = self.diagnose(e)
                
                if decision == "RETRY" and attempts <= self.max_retries:
                    backoff = 2 ** attempts # Exponential backoff: 2s, 4s, 8s
                    logger.info(f"[Resilience] Retrying task in {backoff}s (Attempt {attempts}/{self.max_retries})...")
                    await asyncio.sleep(backoff)
                    continue
                elif decision == "FAIL" or attempts > self.max_retries:
                    logger.error(f"[Resilience] Task failed permanently after {attempts} attempts.")
                    raise e
                elif decision == "ABORT":
                    raise ResourceExhaustedError(f"Aborting scan due to resource exhaustion: {e}")
                else:
                    raise e


class ResourceExhaustedError(Exception):
    """Raised when resource limits are exceeded."""


class ResourceGuard:
    """
    Prevents resource exhaustion during scans.

    Tracks and enforces limits on:
    - Total findings count (prevents runaway classifiers)
    - Disk usage for evidence/output (bounds in-memory + persisted evidence size)
    """

    def __init__(self, max_findings: int = 10000, max_disk_mb: int = 1000):
        self.base_max_findings = max_findings
        self.base_max_disk_mb = max_disk_mb
        self.max_findings = max_findings
        self.max_disk_mb = max_disk_mb
        self.findings_count = 0
        self.disk_usage_bytes = 0
        self._lock = threading.Lock()
        self._stealth_mode = False

    def set_stealth_mode(self, enabled: bool):
        with self._lock:
            self._stealth_mode = enabled
            factor = 0.5 if enabled else 1.0
            self.max_findings = int(self.base_max_findings * factor)
            # Disk limit usually stays hard cap, but we could lower it too
            logger.info(f"[ResourceGuard] Stealth Mode={'ON' if enabled else 'OFF'}. New Limits: Findings={self.max_findings}")

    def reset(self) -> None:
        """Reset counters for a new scan."""
        with self._lock:
            self.findings_count = 0
            self.disk_usage_bytes = 0

    def check_findings(self, count: int) -> bool:
        """Account findings and enforce max_findings."""
        with self._lock:
            if self.findings_count + count > self.max_findings:
                raise ResourceExhaustedError(
                    f"Too many findings: {self.findings_count + count} exceeds limit {self.max_findings}"
                )
            self.findings_count += count
            return True

    def enforce_disk_limit(self, additional_bytes: int) -> bool:
        """
        Enforce disk limit (hard cap). Use this while reading tool output.
        """
        with self._lock:
            max_bytes = self.max_disk_mb * 1024 * 1024
            if self.disk_usage_bytes + additional_bytes > max_bytes:
                raise ResourceExhaustedError(
                    f"Too much disk usage: {(self.disk_usage_bytes + additional_bytes) / 1024 / 1024:.1f}MB "
                    f"exceeds limit {self.max_disk_mb}MB"
                )
            return True

    def account_disk(self, additional_bytes: int) -> None:
        """
        Accounting-only disk tracking. Use this after output has already been truncated
        by enforce_disk_limit during read.
        """
        with self._lock:
            self.disk_usage_bytes += max(0, int(additional_bytes))

    def get_usage(self) -> Dict[str, object]:
        """Get current resource usage for monitoring."""
        with self._lock:
            max_bytes = self.max_disk_mb * 1024 * 1024
            return {
                "findings_count": self.findings_count,
                "max_findings": self.max_findings,
                "disk_usage_mb": self.disk_usage_bytes / 1024 / 1024,
                "max_disk_mb": self.max_disk_mb,
                "findings_percent": (self.findings_count / self.max_findings) * 100 if self.max_findings > 0 else 0,
                "disk_percent": (self.disk_usage_bytes / max_bytes) * 100 if max_bytes > 0 else 0,
            }


# Try to import psutil for resource awareness
try:
    import psutil

    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

MIN_CONCURRENT_TOOLS = 1
MAX_CONCURRENT_TOOLS_BASE = 20  # Base value for small systems


def calculate_concurrent_limit() -> int:
    """Calculate optimal concurrency based on available system resources."""
    try:
        cpu_count = os.cpu_count() or 2

        if HAS_PSUTIL:
            memory_info = psutil.virtual_memory()
            available_memory_gb = memory_info.available / (1024**3)

            # 1 tool per 2GB available RAM (floor), capped by half CPU cores
            memory_based = max(1, int(available_memory_gb / 2))
            cpu_based = max(1, cpu_count // 2)
            calculated = min(memory_based, cpu_based)

            # Cap at config limit
            config_limit = get_config().scan.max_concurrent_tools
            return min(max(MIN_CONCURRENT_TOOLS, calculated), config_limit)

        config_limit = get_config().scan.max_concurrent_tools
        return min(max(MIN_CONCURRENT_TOOLS, cpu_count // 2), config_limit)
    except Exception:
        return MAX_CONCURRENT_TOOLS_BASE


MAX_CONCURRENT_TOOLS = calculate_concurrent_limit()

DEFAULT_TOOL_TIMEOUT_SECONDS = get_config().scan.tool_timeout_seconds
DEFAULT_TOOL_IDLE_TIMEOUT_SECONDS = 60  # 1 minute without output => consider stuck

# Per-tool idle timeout overrides (seconds).
# Long-running tools like nmap emit output in bursts, not continuously.
# Without per-tool overrides, the global 60s idle watchdog kills them prematurely.
TOOL_IDLE_TIMEOUT_OVERRIDES: dict = {
    "nmap": 300,       # nmap can go 5min between output bursts during host discovery
    "masscan": 180,    # masscan is fast but bursty
    "testssl": 180,    # testssl does cipher enumeration which takes time
    "nuclei": 180,     # legacy alias (safe profile)
    "nuclei_safe": 180,      # nuclei low-severity profile
    "nuclei_mutating": 180,  # nuclei medium/high/critical profile
    "feroxbuster": 120,# recursive dir brute can stall between depth levels
    "nikto": 120,      # nikto has slow sequential tests
    "amass": 300,      # amass passive can be very slow
}
DEFAULT_GLOBAL_SCAN_TIMEOUT_SECONDS = 900  # 15 minutes overall cap


class ScanTransaction:
    """
    Transactional wrapper for a scan.

    Key invariants:
    - UI stores are ONLY updated AFTER DB commit succeeds.
    - All findings/issues/evidence are staged and written in a single SQLite transaction.
    - scan_sequence is allocated INSIDE commit(), so it represents committed order.
    - Scan record is created INSIDE commit(), eliminating zombie "running" records on crash.
    """

    def __init__(self, engine: "ScannerEngine", session_id: str, target: str = "unknown"):
        self._engine = engine
        self._session_id = session_id
        self._target = target

        self._committed = False
        self._rolled_back = False

        import uuid

        self._scan_id = str(uuid.uuid4())

        # Assigned during commit (not in __aenter__) to preserve "committed order"
        self._scan_sequence: int = 0

        # ResourceGuard snapshot for rollback
        self._resource_snapshot: Optional[Dict[str, object]] = None

        # Staging areas
        self._staged_findings: List[Dict[str, Any]] = []
        self._staged_issues: List[Dict[str, Any]] = []
        self._staged_evidence: List[Dict[str, Any]] = []

        # Recon edges staged during transaction
        self._staged_recon_edges: List[dict] = []
        self._staged_recon_edge_keys: set[tuple] = set()

        # Rule outputs staged once (no recompute after commit)
        self._staged_rule_killchain_edges: List[dict] = []

        # Best-effort progress marker
        self._last_completed_tool: Optional[str] = None

    async def __aenter__(self) -> "ScanTransaction":
        if self._engine._active_transaction:
            raise RuntimeError("Nested transactions not supported")
        self._engine._active_transaction = self

        self._resource_snapshot = self._engine.resource_guard.get_usage()

        logger.info(f"[SCAN_BEGIN] scan_id={self._scan_id} session_id={self._session_id} target={self._target}")
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if exc_type is None and not self._rolled_back:
            await self.commit()
        else:
            await self.rollback(error_message=str(exc_val) if exc_val else "canceled")

        self._engine._active_transaction = None
        return False

    @property
    def scan_id(self) -> str:
        return self._scan_id

    @property
    def scan_sequence(self) -> int:
        return self._scan_sequence

    def mark_tool_completed(self, tool: str) -> None:
        self._last_completed_tool = tool

    def add_finding(self, finding: Dict[str, Any]) -> None:
        if self._committed or self._rolled_back:
            raise RuntimeError("Transaction already closed")
        self._staged_findings.append(finding)

    def add_issue(self, issue: Dict[str, Any]) -> None:
        if self._committed or self._rolled_back:
            raise RuntimeError("Transaction already closed")
        self._staged_issues.append(issue)

    def add_evidence(self, evidence: Dict[str, Any]) -> None:
        if self._committed or self._rolled_back:
            raise RuntimeError("Transaction already closed")
        self._staged_evidence.append(evidence)

    def add_recon_edges(self, edges: List[dict]) -> None:
        if self._committed or self._rolled_back:
            raise RuntimeError("Transaction already closed")
        for edge in edges:
            key = self._engine._edge_signature(edge)
            if key in self._staged_recon_edge_keys:
                continue
            self._staged_recon_edge_keys.add(key)
            self._staged_recon_edges.append(edge)

    def stage_rule_killchain_edges(self, edges: List[dict]) -> None:
        if self._committed or self._rolled_back:
            raise RuntimeError("Transaction already closed")
        self._staged_rule_killchain_edges = list(edges)

    async def commit(self) -> None:
        if self._committed or self._rolled_back:
            return

        from core.data.db import Database

        db = None

        logger.info(
            f"[ScanTransaction] START COMMIT {self._scan_id}: "
            f"staged={len(self._staged_findings)} findings, "
            f"{len(self._staged_issues)} issues, {len(self._staged_evidence)} evidence"
        )

        try:
            db = Database.instance()
            if not db._initialized:
                await db.init()
            if db._db_connection is None:
                raise RuntimeError("Database not available - cannot commit")

            async with db._db_lock:
                conn = db._db_connection
                if conn is None:
                    raise RuntimeError("Database connection not available")

                await conn.execute("BEGIN IMMEDIATE")

                try:
                    # Allocate scan_sequence INSIDE the commit transaction
                    self._scan_sequence = await db.next_scan_sequence_txn(conn)

                    # Create scan record INSIDE the same transaction
                    await db.create_scan_record_txn(
                        scan_id=self._scan_id,
                        scan_sequence=self._scan_sequence,
                        session_id=self._session_id,
                        target=self._target,
                        status="running",
                        conn=conn,
                    )

                    # Persist findings/evidence/issues
                    # Cross-tool dedupe against already committed findings for this session.
                    existing_fingerprints: set[str] = set()
                    existing_transaction_keys: set[str] = set()
                    async with conn.execute(
                        "SELECT data FROM findings WHERE session_id = ?",
                        (self._session_id,),
                    ) as cursor:
                        async for row in cursor:
                            try:
                                parsed = json.loads(row[0]) if row and row[0] else {}
                            except Exception:
                                parsed = {}
                            fp = str(parsed.get("fingerprint", "")).strip()
                            if fp:
                                existing_fingerprints.add(fp)
                            metadata = parsed.get("metadata", {})
                            if not isinstance(metadata, dict):
                                metadata = {}
                            asset_value = self._engine._normalize_asset(
                                parsed.get("asset") or parsed.get("target") or "unknown"
                            )
                            tx_key = str(metadata.get("transaction_dedupe_key", "")).strip()
                            if not tx_key:
                                tx_key = self._engine._transaction_dedupe_key(parsed, asset_value)
                            if tx_key:
                                existing_transaction_keys.add(tx_key)

                    committed_findings: List[Dict[str, Any]] = []
                    deduped_count = 0
                    for finding in self._staged_findings:
                        asset_value = self._engine._normalize_asset(
                            finding.get("asset") or finding.get("target") or "unknown"
                        )
                        fingerprint = str(finding.get("fingerprint", "")).strip()
                        if not fingerprint:
                            fingerprint = self._engine._semantic_fingerprint(finding, asset_value)
                            finding["fingerprint"] = fingerprint

                        metadata = finding.setdefault("metadata", {})
                        if not isinstance(metadata, dict):
                            metadata = {}
                            finding["metadata"] = metadata
                        tx_key = str(metadata.get("transaction_dedupe_key", "")).strip()
                        if not tx_key:
                            tx_key = self._engine._transaction_dedupe_key(finding, asset_value)
                            if tx_key:
                                metadata["transaction_dedupe_key"] = tx_key

                        if (fingerprint and fingerprint in existing_fingerprints) or (
                            tx_key and tx_key in existing_transaction_keys
                        ):
                            deduped_count += 1
                            continue
                        await db.save_finding_txn(finding, self._session_id, self._scan_sequence, conn)
                        committed_findings.append(finding)
                        if fingerprint:
                            existing_fingerprints.add(fingerprint)
                        if tx_key:
                            existing_transaction_keys.add(tx_key)
                    self._staged_findings = committed_findings
                    if deduped_count:
                        logger.info(
                            "[ScanTransaction] Deduped %d findings against session fingerprint/transaction-key history",
                            deduped_count,
                        )

                    for evidence in self._staged_evidence:
                        await db.save_evidence_txn(evidence, self._session_id, self._scan_sequence, conn)

                    for issue in self._staged_issues:
                        await db.save_issue_txn(issue, self._session_id, self._scan_sequence, conn)

                    # Mark scan row with last_completed_tool if we have it
                    if self._last_completed_tool:
                        await db.update_scan_last_completed_tool_txn(self._scan_id, self._last_completed_tool, conn)

                    await conn.commit()
                    self._committed = True

                    logger.info(
                        f"[SCAN_COMMIT] scan_id={self._scan_id} scan_sequence={self._scan_sequence} "
                        f"findings={len(self._staged_findings)} issues={len(self._staged_issues)} "
                        f"evidence={len(self._staged_evidence)}"
                    )
                except Exception as e:
                    try:
                        await conn.rollback()
                    except Exception:
                        pass
                    raise RuntimeError(f"Transaction commit failed: {e}") from e

            # After DB commit, publish to in-memory stores (UI-safe)
            self._update_stores_after_commit()

            # Update scan record outside the transaction lock (best effort)
            try:
                await db.update_scan_status(
                    self._scan_id,
                    "committed",
                    findings_count=len(self._staged_findings),
                    issues_count=len(self._staged_issues),
                    evidence_count=len(self._staged_evidence),
                    last_completed_tool=self._last_completed_tool,
                )
            except Exception as e:
                logger.warning(f"[ScanTransaction] Failed to update scan record: {e}")

            # Cleanup engine maps to avoid stale cross-scan state
            try:
                self._engine._results_map.clear()
            except Exception:
                pass

        except Exception as e:
            logger.error(f"[ScanTransaction] Commit error: {e}")
            self._rolled_back = True

            # Clear engine scan-scoped state to prevent stale pollution
            self._engine._recon_edges.clear()
            self._engine._recon_edge_keys.clear()
            self._engine._last_results.clear()
            self._engine._results_map.clear()
            self._engine._fingerprint_cache_set.clear()
            self._engine._fingerprint_cache_order.clear()

            self._staged_findings.clear()
            self._staged_issues.clear()
            self._staged_evidence.clear()
            self._staged_recon_edges.clear()
            self._staged_recon_edge_keys.clear()
            self._staged_rule_killchain_edges.clear()

            if db is not None:
                try:
                    await db.update_scan_status(
                        self._scan_id,
                        "failed",
                        error_message=str(e),
                        failure_phase="commit",
                        exception_type=type(e).__name__,
                        last_completed_tool=self._last_completed_tool,
                    )
                except Exception:
                    pass
            raise

    def _update_stores_after_commit(self) -> None:
        """
        Publish committed data to in-memory stores AFTER DB commit.

        IMPORTANT:
        - We DO NOT recompute apply_rules() here.
        - We publish exactly what we staged to preserve determinism.
        """
        logger.info(
            f"[ScanTransaction] UI PUBLISH {self._scan_id}: "
            f"{len(self._staged_findings)} findings, {len(self._staged_issues)} issues, {len(self._staged_evidence)} evidence"
        )

        # Findings
        if self._staged_findings:
            if self._engine.session:
                self._engine.session.findings.bulk_add(self._staged_findings, persist=False)
            else:
                findings_store.bulk_add(self._staged_findings, persist=False)

        # Evidence
        if self._staged_evidence:
            evidence_store = self._engine.session.evidence if self._engine.session else EvidenceStore.instance()
            for ev in self._staged_evidence:
                tool = ev.get("tool", "unknown")
                raw_output = ev.get("raw_output", "")
                metadata = ev.get("metadata", {})
                evidence_store.add_evidence(tool, raw_output, metadata, persist=False)

        # Issues
        if self._staged_issues:
            if self._engine.session:
                self._engine.session.issues.replace_all(self._staged_issues, persist=False)
            else:
                issues_store.replace_all(self._staged_issues, persist=False)

        # Killchain edges (rules + recon + correlator implied edges)
        if self._engine.session and hasattr(self._engine.session, "killchain"):
            combined_edges = list(self._staged_rule_killchain_edges) + list(self._staged_recon_edges)

            # Correlator (graph intelligence)
            source_findings = self._engine.session.findings.get_all()
            nodes = []
            for f in source_findings:
                asset = f.get("asset") or f.get("target") or "unknown"
                if asset == "unknown":
                    continue
                attributes = {}
                meta = f.get("metadata", {})
                for key in ["simhash", "favicon_hash", "ssl_serial", "ga_id"]:
                    val = meta.get(key)
                    if val:
                        attributes[key] = val
                if attributes:
                    nodes.append({"id": asset, "attributes": attributes})

            if nodes:
                correlator = GraphCorrelator()
                implied_edges = correlator.process(nodes)
                if implied_edges:
                    combined_edges.extend(implied_edges)

            # CRITICAL: Use persist=True to trigger pressure graph persistence
            # This emits edges_changed signal → PressureGraphManager → save_graph_snapshot
            self._engine.session.killchain.replace_all(combined_edges, persist=True)
            logger.info(
                f"[ScanTransaction] UI PUBLISH COMPLETE {self._scan_id}: issues={len(self._staged_issues)} "
                f"killchain_edges={len(combined_edges)}"
            )

    async def rollback(self, error_message: Optional[str] = None) -> None:
        if self._committed or self._rolled_back:
            return
        self._rolled_back = True

        logger.info(
            f"[ScanTransaction] START ROLLBACK {self._scan_id}: "
            f"discarding {len(self._staged_findings)} findings, {len(self._staged_issues)} issues, {len(self._staged_evidence)} evidence"
        )

        self._staged_findings.clear()
        self._staged_issues.clear()
        self._staged_evidence.clear()
        self._staged_recon_edges.clear()
        self._staged_recon_edge_keys.clear()
        self._staged_rule_killchain_edges.clear()

        # Restore ResourceGuard snapshot
        if self._resource_snapshot:
            try:
                self._engine.resource_guard.findings_count = int(self._resource_snapshot.get("findings_count", 0))
                disk_mb = float(self._resource_snapshot.get("disk_usage_mb", 0.0))
                self._engine.resource_guard.disk_usage_bytes = int(disk_mb * 1024 * 1024)
            except Exception as e:
                logger.warning(f"[ScanTransaction] Failed to restore ResourceGuard: {e}")

        # Clear engine scan-scoped state
        self._engine._recon_edges.clear()
        self._engine._recon_edge_keys.clear()
        self._engine._results_map.clear()
        self._engine._fingerprint_cache_set.clear()
        self._engine._fingerprint_cache_order.clear()

        logger.info(
            f"[SCAN_ROLLBACK] scan_id={self._scan_id} session_id={self._session_id} reason={error_message or 'unknown'}"
        )

        from core.data.db import Database

        db = Database.instance()
        try:
            await db.update_scan_status(
                self._scan_id,
                "rolled_back",
                error_message=error_message,
                failure_phase="commit",
                exception_type="Rollback",
                last_completed_tool=self._last_completed_tool,
            )
        except Exception as e:
            logger.warning(f"[ScanTransaction] Failed to update scan record on rollback: {e}")

    @property
    def is_active(self) -> bool:
        return not self._committed and not self._rolled_back

    def stats(self) -> Dict[str, int]:
        return {"findings": len(self._staged_findings), "issues": len(self._staged_issues), "evidence": len(self._staged_evidence)}


class ScannerEngine:
    """Runs supported scanning tools on macOS (no unsupported tool errors)."""

    # Some tools use non-zero exits for non-fatal outcomes. Keep this list narrow.
    _NONFATAL_CLASSIFIABLE_EXIT_CODES: Dict[str, Tuple[int, ...]] = {
        "nikto": (1,),
    }

    def __init__(self, session=None):
        self.session = session

        self._last_results: List[dict] = []
        self._last_tool_error: Optional[Dict[str, Any]] = None

        # Deterministic, bounded fingerprint cache (deque + set)
        self._fingerprint_cache_max = 10000
        self._fingerprint_cache_order: Deque[str] = deque()
        self._fingerprint_cache_set: set[str] = set()

        self._installed_meta: Dict[str, Dict[str, object]] = {}

        # Recon edges (engine-scoped for legacy, but transaction uses txn staging)
        self._recon_edges: List[dict] = []
        self._recon_edge_keys: set[tuple] = set()

        # Task management state
        self._pending_tasks: List[object] = []
        self._running_tasks: Dict[str, asyncio.Task[List[dict]]] = {}
        self._queue: asyncio.Queue[str] = asyncio.Queue()
        self._results_map: Dict[str, object] = {}
        self._procs: Dict[str, asyncio.subprocess.Process] = {}

        # Resource guard
        config = get_config()
        scan_config = config.scan
        # We allow 10x the per-tool limit for the global scan aggregation
        global_max_findings = scan_config.max_findings_per_tool * 10
        self.resource_guard = ResourceGuard(
            max_findings=global_max_findings,
            max_disk_mb=config.storage.max_scan_output_mb,
        )

        # Transaction state
        self._active_transaction: Optional[ScanTransaction] = None

        # Scan lock
        self._scan_lock = asyncio.Lock()

        # Cancel state
        self._cancel_event: Optional[asyncio.Event] = None

    # ----------------------------
    # Env timeouts
    # ----------------------------
    @staticmethod
    def _get_env_seconds(name: str, default: int) -> int:
        val = os.environ.get(name)
        if not val:
            return default
        try:
            return int(val)
        except ValueError:
            return default

    def _tool_timeout_seconds(self) -> int:
        return get_config().scan.tool_timeout_seconds

    def _tool_idle_timeout_seconds(self, tool_name: str = "") -> int:
        """Get idle timeout for a tool. Per-tool overrides take priority, then env var, then default."""
        if tool_name and tool_name in TOOL_IDLE_TIMEOUT_OVERRIDES:
            return TOOL_IDLE_TIMEOUT_OVERRIDES[tool_name]
        return self._get_env_seconds("SCANNER_TOOL_IDLE_TIMEOUT", DEFAULT_TOOL_IDLE_TIMEOUT_SECONDS)

    def _global_scan_timeout_seconds(self) -> int:
        return self._get_env_seconds("SCANNER_GLOBAL_TIMEOUT", DEFAULT_GLOBAL_SCAN_TIMEOUT_SECONDS)

    @classmethod
    def _should_classify_tool_output(cls, tool: str, exit_code: Optional[int], output_text: str) -> bool:
        """
        Decide whether raw output should be sent through deterministic classification.

        Default policy is strict: classify only on successful exits. We selectively
        allow non-zero exit codes for tools with known non-fatal semantics.
        """
        if exit_code in (0, None):
            return True

        tool_name = (tool or "").lower()
        allowed_codes = cls._NONFATAL_CLASSIFIABLE_EXIT_CODES.get(tool_name, ())
        if exit_code not in allowed_codes:
            return False

        # Nikto classification expects shim-formatted lines.
        if tool_name == "nikto":
            text = output_text or ""
            if "[nikto-shim]" in text:
                return True
            # Native Nikto findings are emitted as "+ ..." lines.
            if re.search(r"^\+\s+", text, flags=re.MULTILINE):
                return True
            return False

        return bool(output_text and output_text.strip())

    async def _global_timeout_runner(self, timeout_secs: int, cancel_flag: asyncio.Event, queue: asyncio.Queue[str]):
        try:
            await asyncio.sleep(max(0, timeout_secs))
        except asyncio.CancelledError:
            return

        if cancel_flag.is_set():
            return

        cancel_flag.set()
        await queue.put(f"[scanner] ⏱️ Global timeout {timeout_secs}s reached; canceling scan and terminating tools...")

        for exec_id, proc in list(self._procs.items()):
            if proc and proc.returncode is None:
                try:
                    proc.terminate()
                    await queue.put(f"[{exec_id}] terminated due to global timeout")
                except ProcessLookupError:
                    pass
                except Exception as exc:
                    await queue.put(f"[{exec_id}] termination error on timeout: {exc}")

        await asyncio.sleep(0.2)

        for exec_id, proc in list(self._procs.items()):
            if proc and proc.returncode is None:
                try:
                    proc.kill()
                    await queue.put(f"[{exec_id}] force-killed after global timeout")
                except ProcessLookupError:
                    pass
                except Exception as exc:
                    await queue.put(f"[{exec_id}] force-kill error on timeout: {exc}")


    async def scan(self, target: str, selected_tools: List[str] | None = None, cancel_flag=None) -> AsyncGenerator[str, None]:
        """
        Async generator that yields log-style strings while tools run.

        Entire scan is under _scan_lock to protect engine state.
        """
        async with self._scan_lock:
            from core.engine.vanguard import Vanguard

            installed = self._detect_installed()
            candidates = list(installed.keys())
            valid_names = Vanguard.preflight_check(candidates)
            self._installed_meta = {k: v for k, v in installed.items() if k in valid_names}
            installed = self._installed_meta

            # Reset state for run
            self._last_results = []
            self._recon_edges = []
            self._recon_edge_keys = set()
            self._procs = {}
            self._pending_tasks = []
            self._running_tasks = {}
            self._results_map = {}
            self._fingerprint_cache_set.clear()
            self._fingerprint_cache_order.clear()

            selected_clean = [t for t in (selected_tools or []) if t in TOOLS]
            tools_to_run = list(installed.keys())
            missing: List[str] = []

            if selected_clean:
                tools_to_run = [t for t in selected_clean if t in installed]
                missing = [t for t in selected_clean if t not in installed]
                yield f"[scanner] Selected tools: {', '.join(selected_clean)}"

            if missing:
                msg = f"[scanner] ⚠️ WARNING: requested but NOT found in PATH: {', '.join(missing)}"
                yield msg
                logger.warning(msg)
                logger.warning(f"[scanner] PATH: {os.environ.get('PATH')}")

            if not tools_to_run:
                yield "[scanner] No supported tools available in PATH. Skipping tool phase."
                return

            yield f"Installed tools: {', '.join(tools_to_run)}"

            sess_id = self.session.session_id if self.session else "global_scan"

            self.resource_guard.reset()

            queue: asyncio.Queue[str] = asyncio.Queue()

            local_cancel: asyncio.Event = cancel_flag or asyncio.Event()
            self._cancel_event = local_cancel

            watchdog_task = None
            global_timeout = self._global_scan_timeout_seconds()
            if global_timeout and global_timeout > 0:
                watchdog_task = asyncio.create_task(self._global_timeout_runner(global_timeout, local_cancel, queue))

            async with ScanTransaction(self, sess_id, target) as txn:
                try:
                    pending: List[object] = list(tools_to_run)

                    self._pending_tasks = pending
                    self._running_tasks = {}
                    self._queue = queue
                    self._results_map = {}

                    import uuid

                    while self._pending_tasks or self._running_tasks:
                        if local_cancel.is_set():
                            await self._queue.put("[scanner] cancellation requested; stopping new tasks")
                            self._pending_tasks.clear()
                            break

                        while self._pending_tasks and len(self._running_tasks) < MAX_CONCURRENT_TOOLS:
                            task_def = self._pending_tasks.pop(0)

                            if isinstance(task_def, str):
                                tool = task_def
                                args = None
                            else:
                                tool = str(task_def.get("tool"))
                                args = task_def.get("args")

                            exec_id = f"{tool}:{uuid.uuid4().hex[:8]}"
                            self._running_tasks[exec_id] = asyncio.create_task(
                                self._run_tool_task(exec_id, tool, target, self._queue, args, local_cancel)
                            )
                            await self._queue.put(f"[scanner] Started {tool} ({exec_id})")

                        if not self._running_tasks:
                            break

                        done, _ = await asyncio.wait(list(self._running_tasks.values()), timeout=0.2)

                        while not self._queue.empty():
                            yield self._queue.get_nowait()

                        for finished in done:
                            exec_id = next((eid for eid, t in self._running_tasks.items() if t is finished), None)
                            if not exec_id:
                                continue
                            try:
                                self._results_map[exec_id] = finished.result()
                            except Exception as exc:  # pragma: no cover
                                self._results_map[exec_id] = exc
                                await self._queue.put(f"[{exec_id}] task error: {exc}")
                            del self._running_tasks[exec_id]

                        # Check for cancellation after every iteration, not just when no tasks completed
                        # This ensures the stop button works reliably even during long-running tools
                        if local_cancel.is_set():
                            await self._queue.put("[scanner] Cancellation detected - terminating running tools...")
                            for exec_id, proc in list(self._procs.items()):
                                if proc and proc.returncode is None:
                                    try:
                                        proc.terminate()
                                        await self._queue.put(f"[{exec_id}] terminated due to cancellation")
                                    except ProcessLookupError:
                                        pass
                            await asyncio.sleep(0.2)
                            for exec_id, proc in list(self._procs.items()):
                                if proc and proc.returncode is None:
                                    try:
                                        proc.kill()
                                        await self._queue.put(f"[{exec_id}] force-killed after termination timeout")
                                    except ProcessLookupError:
                                        pass
                            await self._queue.put("[scanner] All tools terminated due to cancellation")

                    # Queue drain before aggregation
                    while not self._queue.empty():
                        yield self._queue.get_nowait()

                    if local_cancel.is_set():
                        await txn.rollback("canceled")
                        await self.shutdown(reason="canceled")
                        yield "[scanner] Scan canceled - Transaction Rolled Back."
                        return

                    await asyncio.sleep(0)
                    while not self._queue.empty():
                        yield self._queue.get_nowait()

                    # Aggregate findings from all tool exec results
                    all_findings: List[dict] = []
                    for exec_id, result in self._results_map.items():
                        if isinstance(result, list):
                            all_findings.extend(result)

                    normalized = self._normalize_findings(all_findings)
                    self._last_results = normalized

                    # ================================================================
                    # TRANSACTIONAL INVARIANT:
                    # All findings MUST go through txn.add_finding().
                    # The transaction ensures atomicity: either ALL findings are
                    # committed to DB and published to UI stores, or NONE are.
                    # ================================================================
                    # Stage findings (no UI store updates until commit succeeds)
                    for f in normalized:
                        txn.add_finding(f)

                    # Stage recon edges (graph relationships between findings)
                    recon_edges = self._build_recon_edges(normalized)
                    txn.add_recon_edges(recon_edges)

                    # Enrichment: stage issues + killchain edges
                    self._refresh_enrichment(txn)

                except Exception as e:
                    await txn.rollback(str(e))
                    logger.error(f"[ScannerEngine] Critical error, rolling back: {e}")
                    raise
                finally:
                    # CRITICAL: Always cancel watchdog, even on exception paths
                    # This prevents the watchdog from continuing to run after
                    # the scan loop exits (exception, cancellation, or completion)
                    if watchdog_task is not None:
                        try:
                            watchdog_task.cancel()
                        except Exception:
                            pass

            # After context exit, commit has run and stores updated
            if hasattr(txn, "_committed") and txn._committed:
                stats = txn.stats()
                yield f"[scanner] Processed {stats['findings']} findings, committed transaction"

    def queue_task(self, tool: str, args: List[str] | None = None) -> None:
        """
        Dynamically add a tool to the current scan queue.

        Args:
            tool: Name of tool to run
            args: Optional arguments
        """
        if tool not in TOOLS:
            raise ValueError(f"Unknown tool: {tool}")
        if tool not in self._installed_meta:
            raise ValueError(f"Tool not installed: {tool}")

        if args:
             # Basic sanity check on args
             for arg in args:
                 if ";" in arg or "|" in arg or "&" in arg or "&&" in arg or "||" in arg or "$(" in arg:
                     raise ValueError(f"Potentially unsafe argument: {arg}")

        self._pending_tasks.append({"tool": tool, "args": args})
        logger.info(f"[ScannerEngine] Dynamically queued task: {tool} {args}")

    async def shutdown(self, reason: str = "shutdown") -> None:
        """Cleanup running tasks and processes."""
        try:
            self._pending_tasks.clear()
        except Exception:
            pass

        tasks: List[asyncio.Task] = []
        try:
            tasks = list(self._running_tasks.values())
            for t in tasks:
                t.cancel()
        except Exception:
            tasks = []

        procs: List[Tuple[str, asyncio.subprocess.Process]] = []
        try:
            procs = list(self._procs.items())
        except Exception:
            procs = []

        for exec_id, proc in procs:
            if not proc or proc.returncode is not None:
                continue
            try:
                proc.terminate()
            except ProcessLookupError:
                pass
            except Exception as exc:
                logger.debug(f"[scanner] terminate failed for {exec_id} ({reason}): {exc}")

        try:
            await asyncio.sleep(0.2)
        except asyncio.CancelledError:
            pass

        for exec_id, proc in procs:
            if not proc or proc.returncode is not None:
                continue
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            except Exception as exc:
                logger.debug(f"[scanner] kill failed for {exec_id} ({reason}): {exc}")

        if tasks:
            try:
                await asyncio.gather(*tasks, return_exceptions=True)
            except Exception:
                pass

        for exec_id, proc in procs:
            if not proc:
                continue
            try:
                if proc.returncode is None:
                    await asyncio.wait_for(proc.wait(), timeout=1.0)
            except asyncio.TimeoutError:
                pass
            except Exception:
                pass

        try:
            self._running_tasks.clear()
        except Exception:
            pass
        try:
            self._procs.clear()
        except Exception:
            pass

    def queue_task(self, tool: str, args: List[str] = None) -> None:
        """
        Dynamically add a task to the running scan.

        SECURITY
        - Tool must be in TOOLS allowlist.
        - Args validated to block shell injection patterns.
        - Reject if scan cancellation is set.
        """
        if tool not in TOOLS:
            raise ValueError(f"Unknown tool '{tool}'. Must be one of: {', '.join(TOOLS)}")

        if self._cancel_event is not None and self._cancel_event.is_set():
            raise RuntimeError("Scan is canceled - cannot queue dynamic tasks")

        if not hasattr(self, "_pending_tasks"):
            raise RuntimeError("No active scan - cannot queue dynamic tasks")

        if args:
            if len(args) > 50:
                raise ValueError(f"Too many arguments ({len(args)}), max 50 allowed")

            dangerous_patterns = [";", "|", "&&", "||", "$(", "`", "\n", "\r"]
            for arg in args:
                arg_str = str(arg)
                for pattern in dangerous_patterns:
                    if pattern in arg_str:
                        raise ValueError(
                            f"Dangerous character '{pattern}' in argument '{arg_str}'. Shell injection patterns not allowed."
                        )

        if hasattr(self, "_installed_meta") and tool not in self._installed_meta:
            logger.warning(f"[queue_task] Tool '{tool}' not installed, adding anyway (will fail during execution)")

        self._pending_tasks.append({"tool": tool, "args": args})

    async def run_all(self, target: str):
        async for _ in self.scan(target):
            pass
        return list(self._last_results)

    # ----------------------------
    # Helpers
    # ----------------------------
    def _detect_installed(self) -> Dict[str, Dict[str, object]]:
        return get_installed_tools()

    @staticmethod
    def _semantic_bucket_for_entry(entry: Dict[str, Any]) -> str:
        finding_type = str(entry.get("type", "generic")).strip().lower()
        tags = entry.get("tags", [])
        if isinstance(tags, str):
            tags = [tags]
        tag_set = {str(tag).strip().lower() for tag in tags if str(tag).strip()}
        families = entry.get("families", [])
        if isinstance(families, str):
            families = [families]
        family_set = {str(fam).strip().lower() for fam in families if str(fam).strip()}

        if any(token in finding_type for token in ("port", "service", "connectivity")):
            return "network_surface"
        if "auth" in tag_set or "auth" in family_set or any(token in finding_type for token in ("auth", "login", "session", "admin")):
            return "auth_surface"
        if any(token in finding_type for token in ("git", "backup", "exposure", "disclosure", "directory")):
            return "web_exposure"
        if "vulnerability" in finding_type or "vuln" in finding_type:
            return finding_type
        return finding_type or "generic"

    @staticmethod
    def _extract_locator_from_entry(entry: Dict[str, Any]) -> str:
        metadata = entry.get("metadata", {})
        if not isinstance(metadata, dict):
            metadata = {}

        # Prefer explicit metadata path-like values.
        for key in ("path", "endpoint", "url", "uri", "location", "redirect", "match"):
            value = metadata.get(key)
            if value is None:
                continue
            text = str(value).strip()
            if not text:
                continue
            if text.startswith(("http://", "https://")):
                parsed = urlparse(text)
                path = (parsed.path or "/").strip()
                if parsed.query:
                    path = f"{path}?{parsed.query}"
                return path.lower()
            if text.startswith("/"):
                return text.lower()
            # If metadata stores path-like fragments, normalize to slash-prefixed form.
            if "/" in text and not text.startswith("http"):
                return f"/{text.lstrip('/')}".lower()

        # Port findings dedupe on host:port when available.
        port = metadata.get("port")
        if port is not None:
            host = str(metadata.get("host") or entry.get("asset") or entry.get("target") or "").strip().lower()
            try:
                return f"{host}:{int(port)}"
            except (TypeError, ValueError):
                return f"{host}:{port}"

        # Fallback: extract URL/path-like fragment from message/proof.
        message = str(entry.get("message") or entry.get("proof") or "").strip()
        if message:
            url_match = re.search(r"https?://[^\s)]+", message, flags=re.IGNORECASE)
            if url_match:
                parsed = urlparse(url_match.group(0))
                path = (parsed.path or "/").strip()
                if parsed.query:
                    path = f"{path}?{parsed.query}"
                return path.lower()
            path_match = re.search(r"(/[\w\-./%]+)", message)
            if path_match:
                return path_match.group(1).lower()

        return ""

    def _semantic_fingerprint(self, entry: Dict[str, Any], asset: str) -> str:
        bucket = self._semantic_bucket_for_entry(entry)
        locator = self._extract_locator_from_entry(entry)
        if locator:
            return f"{asset}|{bucket}|{locator}"

        # Last-resort fallback: normalized message text without volatile IDs.
        message = str(entry.get("message") or entry.get("proof") or "").strip().lower()
        message = re.sub(r"\s+", " ", message)
        message = re.sub(r"\b(status|code|size):\s*\d+\b", "", message)
        message = message[:220]
        return f"{asset}|{bucket}|{message}"

    def _transaction_dedupe_key(self, entry: Dict[str, Any], asset: str) -> str:
        """
        Secondary dedupe key for cross-tool overlap within one session.
        Limited to discovery/surface buckets to avoid collapsing distinct exploit findings.
        """
        bucket = self._semantic_bucket_for_entry(entry)
        if bucket not in {"network_surface", "auth_surface", "web_exposure"}:
            return ""

        locator = self._extract_locator_from_entry(entry)
        if not locator:
            return ""

        return f"{asset}|surface|{locator}"

    @staticmethod
    def _merge_duplicate_finding(existing: Dict[str, Any], incoming: Dict[str, Any]) -> None:
        """
        Merge duplicate findings from overlapping tools into a single canonical finding.
        """
        existing_meta = existing.setdefault("metadata", {})
        if not isinstance(existing_meta, dict):
            existing_meta = {}
            existing["metadata"] = existing_meta
        incoming_meta = incoming.get("metadata", {})
        if not isinstance(incoming_meta, dict):
            incoming_meta = {}

        severity_rank = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
        existing_sev = str(existing.get("severity", "INFO")).upper()
        incoming_sev = str(incoming.get("severity", "INFO")).upper()
        if severity_rank.get(incoming_sev, 0) > severity_rank.get(existing_sev, 0):
            existing["severity"] = incoming_sev
            if incoming.get("message"):
                existing["message"] = incoming.get("message")
            if incoming.get("proof"):
                existing["proof"] = incoming.get("proof")

        seen_tools = set()
        for tool in (existing.get("tool"), incoming.get("tool")):
            tool_name = str(tool or "").strip().lower()
            if tool_name:
                seen_tools.add(tool_name)
        for tool in existing_meta.get("seen_by_tools", []) if isinstance(existing_meta.get("seen_by_tools"), list) else []:
            tool_name = str(tool or "").strip().lower()
            if tool_name:
                seen_tools.add(tool_name)
        if seen_tools:
            existing_meta["seen_by_tools"] = sorted(seen_tools)

        existing_meta["dedup_count"] = int(existing_meta.get("dedup_count", 1)) + 1

        alt_messages = existing_meta.get("alternate_messages", [])
        if not isinstance(alt_messages, list):
            alt_messages = []
        incoming_message = str(incoming.get("message", "")).strip()
        if incoming_message and incoming_message != str(existing.get("message", "")).strip():
            if incoming_message not in alt_messages:
                alt_messages.append(incoming_message)
        if len(alt_messages) > 5:
            alt_messages = alt_messages[-5:]
        if alt_messages:
            existing_meta["alternate_messages"] = alt_messages

        # Merge tags/families to preserve breadth from all tools.
        def _merge_string_list(lhs: Any, rhs: Any) -> List[str]:
            values: Set[str] = set()
            for source in (lhs, rhs):
                if isinstance(source, str):
                    source = [source]
                if isinstance(source, list):
                    for item in source:
                        value = str(item).strip()
                        if value:
                            values.add(value)
            return sorted(values)

        existing["tags"] = _merge_string_list(existing.get("tags", []), incoming.get("tags", []))
        existing["families"] = _merge_string_list(existing.get("families", []), incoming.get("families", []))

    def _normalize_findings(self, items: List[dict] | None) -> List[dict]:
        normalized: List[dict] = []
        semantic_index: Dict[str, int] = {}
        transaction_index: Dict[str, int] = {}
        if not items:
            return normalized

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

            fingerprint = self._semantic_fingerprint(entry, asset)
            entry["fingerprint"] = fingerprint

            transaction_key = self._transaction_dedupe_key(entry, asset)
            if transaction_key:
                metadata = entry.get("metadata")
                if not isinstance(metadata, dict):
                    metadata = {}
                    entry["metadata"] = metadata
                metadata["transaction_dedupe_key"] = transaction_key

            existing_idx = semantic_index.get(fingerprint)
            if existing_idx is not None and 0 <= existing_idx < len(normalized):
                self._merge_duplicate_finding(normalized[existing_idx], entry)
                continue
            if transaction_key:
                transaction_idx = transaction_index.get(transaction_key)
                if transaction_idx is not None and 0 <= transaction_idx < len(normalized):
                    self._merge_duplicate_finding(normalized[transaction_idx], entry)
                    continue

            # Deterministic bounded dedupe: FIFO eviction
            if fingerprint in self._fingerprint_cache_set:
                continue

            self._fingerprint_cache_set.add(fingerprint)
            self._fingerprint_cache_order.append(fingerprint)

            # Evict oldest if over capacity
            while len(self._fingerprint_cache_order) > self._fingerprint_cache_max:
                old = self._fingerprint_cache_order.popleft()
                self._fingerprint_cache_set.discard(old)

            semantic_index[fingerprint] = len(normalized)
            if transaction_key:
                transaction_index[transaction_key] = len(normalized)
            normalized.append(entry)

        return normalized

    def get_last_results(self) -> List[dict]:
        return list(self._last_results)

    def _build_recon_edges(self, findings: List[dict]) -> List[dict]:
        edges: List[dict] = []
        for item in findings:
            families = item.get("families", [])
            recon_families = [fam for fam in families if fam.startswith("recon-phase")]
            if not recon_families:
                continue
            metadata = item.get("metadata") or {}
            variant = metadata.get("variant") or "behavior"
            for fam in recon_families:
                edges.append(
                    {
                        "source": item.get("asset", "unknown"),
                        "target": f"{fam}:{variant}",
                        "label": item.get("type"),
                        "severity": item.get("severity"),
                        "tags": item.get("tags", []),
                        "signal": item.get("message"),
                        "families": families,
                        "edge_type": "behavioral-signal",
                    }
                )
        return edges

    def _record_recon_edges(self, edges: List[dict]) -> None:
        for edge in edges:
            key = self._edge_signature(edge)
            if key in self._recon_edge_keys:
                continue
            self._recon_edge_keys.add(key)
            self._recon_edges.append(edge)

    def _edge_signature(self, edge: dict) -> tuple:
        return (edge.get("source"), edge.get("target"), edge.get("label"), edge.get("edge_type"), edge.get("severity"))

    def _refresh_enrichment(self, txn: ScanTransaction) -> tuple[int, int]:
        """
        Enrich findings with issues and killchain analysis.

        TRANSACTIONAL INVARIANT:
        - All issues are staged via txn.add_issue()
        - All killchain edges are staged via txn.stage_rule_killchain_edges()
        - NO direct writes to stores (deferred until commit succeeds)
        - Correlator is run AFTER commit in ScanTransaction._update_stores_after_commit()

        Args:
            txn: Active ScanTransaction (must be non-None and is_active)

        Returns:
            (enriched_count, edge_count): Number of issues and edges staged
        """
        if not txn or not txn.is_active:
            raise RuntimeError("_refresh_enrichment requires an active transaction")

        if self._last_results:
            enriched, _, rule_killchain_edges = apply_rules(self._last_results)
        else:
            enriched, _, rule_killchain_edges = [], [], []

        # Stage issues for commit
        for issue in enriched:
            txn.add_issue(issue)

        # Stage rule-generated killchain edges for commit
        txn.stage_rule_killchain_edges(rule_killchain_edges)

        # Killchain store publish happens after commit, combining:
        # - txn staged recon edges (from findings)
        # - rule killchain edges (from this method)
        # - correlator implied edges (computed after commit)
        return len(enriched), len(rule_killchain_edges)

    async def _run_tool_task(
        self,
        exec_id: str,
        tool: str,
        target: str,
        queue: asyncio.Queue[str],
        args: List[str] | None,
        cancel_flag: asyncio.Event,
    ) -> List[dict]:
        """
        Run a single tool with resilience wrapper.
        """
        async def _core_executor():
             return await self._execute_tool(exec_id, tool, target, queue, args, cancel_flag)

        # Initialize resilience context with engine reference
        ctx = ResilienceContext(self, max_retries=3)
        try:
             return await ctx.execute_with_retry(_core_executor)
        except Exception:
             # Errors logged by resilience context, propagate up
             raise

    def enable_stealth_mode(self):
        """
        Activate Stealth Mode: Reduce resource limits and (TODO) increase delays.
        """
        logger.warning("[ScannerEngine] 🛡️ ACTIVATING STEALTH MODE due to detected WAF/Block.")
        self.resource_guard.set_stealth_mode(True)

    async def _execute_internal_tool(
        self,
        exec_id: str,
        tool: str,
        target: str,
        queue: asyncio.Queue[str],
        tool_def: Any,
    ) -> List[dict]:
        """
        Execute a Python-based internal tool (InternalTool subclass).

        Internal tools run in-process and return findings in the standard
        dict schema.  They receive an InternalToolContext with existing
        findings and shared scan knowledge so they can make data-driven
        decisions about what to verify/fuzz/test.
        """
        from core.toolkit.internal_tool import InternalToolContext

        await queue.put(f"--- Running {tool} [internal] ({exec_id}) ---")

        # Build context from current scan state
        existing_findings = []
        if self._active_transaction and hasattr(self._active_transaction, "_staged_findings"):
            existing_findings = list(self._active_transaction._staged_findings)
        elif self.session and hasattr(self.session, "findings"):
            existing_findings = list(getattr(self.session.findings, "items", lambda: [])())

        knowledge = {}
        if self.session and hasattr(self.session, "knowledge"):
            knowledge = getattr(self.session, "knowledge", {})

        scan_id = getattr(self.session, "scan_id", exec_id) if self.session else exec_id
        session_id = getattr(self.session, "session_id", exec_id) if self.session else exec_id

        ctx = InternalToolContext(
            target=target,
            scan_id=str(scan_id),
            session_id=str(session_id),
            existing_findings=existing_findings,
            knowledge=knowledge,
            mode=knowledge.get("execution_mode", "research"),
        )

        tool_timeout = self._tool_timeout_seconds()
        start_time = asyncio.get_running_loop().time()

        try:
            findings = await asyncio.wait_for(
                tool_def.handler.execute(target, ctx, queue),
                timeout=tool_timeout,
            )
        except asyncio.TimeoutError:
            elapsed = asyncio.get_running_loop().time() - start_time
            msg = f"[{tool}] internal tool timed out after {elapsed:.1f}s"
            logger.warning(msg)
            await queue.put(f"[{exec_id}] {msg}")
            return []
        except Exception as exc:
            msg = f"[{tool}] internal tool error: {exc}"
            logger.error(msg, exc_info=True)
            self._last_tool_error = ToolError(tool=tool, exit_code=-1, stderr=str(exc)).details
            await queue.put(f"[{exec_id}] {msg}")
            return []

        elapsed = asyncio.get_running_loop().time() - start_time
        await queue.put(
            f"[{exec_id}] {tool} completed: {len(findings)} findings in {elapsed:.1f}s"
        )
        return findings

    async def _execute_tool(
        self,
        exec_id: str,
        tool: str,
        target: str,
        queue: asyncio.Queue[str],
        args: List[str] | None,
        cancel_flag: asyncio.Event,
    ) -> List[dict]:
        # ── Internal tool dispatch ──────────────────────────────────────
        # If the tool is registered as "internal", run its Python handler
        # instead of shelling out to a subprocess.
        tool_def = TOOLS.get(tool)
        if tool_def and tool_def.tool_type == "internal" and tool_def.handler is not None:
            return await self._execute_internal_tool(exec_id, tool, target, queue, tool_def)

        # ── Subprocess tool dispatch (existing path) ────────────────────
        meta_override = self._installed_meta.get(tool)

        tool_timeout = self._tool_timeout_seconds()
        idle_timeout = self._tool_idle_timeout_seconds(tool_name=tool)

        if args:
            cmd = [tool] + args
            cmd = [arg.replace("{target}", target) for arg in cmd]
            stdin_input = None
        else:
            cmd, stdin_input = get_tool_command(tool, target, meta_override)

        self._last_tool_error = None

        await queue.put(f"--- Running {tool} ({exec_id}) ---")

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.PIPE if stdin_input else None,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            self._procs[exec_id] = proc

            if stdin_input and proc.stdin:
                proc.stdin.write((stdin_input + "\n").encode("utf-8"))
                proc.stdin.close()
        except FileNotFoundError:
            msg = f"[{tool}] NOT INSTALLED or not in PATH."
            self._last_tool_error = ToolError(tool=tool, exit_code=127, stderr=msg).details

            if self._active_transaction and self._active_transaction.is_active:
                self._active_transaction.add_evidence(
                    {"tool": tool, "raw_output": msg, "metadata": {"target": target, "error": "not_found", "exec_id": exec_id}}
                )
            else:
                ev_store = self.session.evidence if self.session else EvidenceStore.instance()
                ev_store.add_evidence(tool, msg, {"target": target, "error": "not_found", "exec_id": exec_id})

            await queue.put(f"[{exec_id}] {msg}")
            return []
        except Exception as exc:
            msg = f"[{tool}] failed to start: {exc}"
            self._last_tool_error = ToolError(tool=tool, exit_code=-1, stderr=str(exc)).details

            if self._active_transaction and self._active_transaction.is_active:
                self._active_transaction.add_evidence(
                    {"tool": tool, "raw_output": msg, "metadata": {"target": target, "error": str(exc), "exec_id": exec_id}}
                )
            else:
                ev_store = self.session.evidence if self.session else EvidenceStore.instance()
                ev_store.add_evidence(tool, msg, {"target": target, "error": str(exc), "exec_id": exec_id})

            await queue.put(f"[{exec_id}] {msg}")
            return []

        start_time = asyncio.get_running_loop().time()
        timed_out_reason: Optional[str] = None
        truncated = False
        output_bytes = 0
        output_lines: List[str] = []

        assert proc.stdout is not None

        max_bytes_total = self.resource_guard.max_disk_mb * 1024 * 1024

        while True:
            if cancel_flag is not None and cancel_flag.is_set():
                try:
                    if proc.returncode is None:
                        proc.terminate()
                except ProcessLookupError:
                    pass
                break

            try:
                if idle_timeout and idle_timeout > 0:
                    line = await asyncio.wait_for(proc.stdout.readline(), timeout=idle_timeout)
                else:
                    line = await proc.stdout.readline()
            except asyncio.TimeoutError:
                timed_out_reason = "idle"
                await queue.put(f"[{exec_id}] idle timeout after {idle_timeout}s without output; terminating")
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
                continue

            line_bytes = len(text.encode("utf-8"))

            # Enforce disk cap during read
            if output_bytes + line_bytes > max_bytes_total:
                truncated = True
                await queue.put(f"[{exec_id}] Output truncated: exceeded disk limit ({self.resource_guard.max_disk_mb}MB)")
                try:
                    if proc.returncode is None:
                        proc.terminate()
                except ProcessLookupError:
                    pass
                break

            output_bytes += line_bytes
            output_lines.append(text)
            await queue.put(f"[{exec_id}] {text}")

            if tool_timeout and tool_timeout > 0:
                now = asyncio.get_running_loop().time()
                if (now - start_time) > tool_timeout:
                    timed_out_reason = "wall-clock"
                    await queue.put(f"[{exec_id}] time limit {tool_timeout}s exceeded; terminating")
                    try:
                        if proc.returncode is None:
                            proc.terminate()
                    except ProcessLookupError:
                        pass
                    break

        # Ensure process exits
        try:
            exit_code = await asyncio.wait_for(proc.wait(), timeout=2)
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            exit_code = await proc.wait()

        await queue.put(f"[{exec_id}] Exit code: {exit_code}")

        # Cleanup proc tracking
        self._procs.pop(exec_id, None)

        output_text = "\n".join(output_lines)

        # Accounting only (limit already enforced during read)
        self.resource_guard.account_disk(output_bytes)
        should_classify_output = self._should_classify_tool_output(tool, exit_code, output_text)

        if timed_out_reason:
            self._last_tool_error = ToolError(
                tool=tool,
                exit_code=124,
                stderr=f"timeout:{timed_out_reason}",
            ).details
        elif exit_code not in (0, None) and not (cancel_flag and cancel_flag.is_set()) and not should_classify_output:
            tail = "\n".join(output_lines[-10:])
            self._last_tool_error = ToolError(tool=tool, exit_code=exit_code, stderr=tail).details
        elif exit_code not in (0, None) and should_classify_output:
            logger.info(
                f"[{exec_id}] Tool exited {exit_code}; non-fatal exit accepted for classification ({tool})"
            )

        ev_meta = {
            "target": target,
            "exec_id": exec_id,
            "tool": tool,
            "exit_code": exit_code,
            "lines": len(output_lines),
            "bytes": output_bytes,
            "timed_out": bool(timed_out_reason),
            "timeout_reason": timed_out_reason,
            "truncated": truncated,
            "canceled": bool(cancel_flag and cancel_flag.is_set()),
        }

        # Stage evidence
        if self._active_transaction and self._active_transaction.is_active:
            self._active_transaction.add_evidence({"tool": tool, "raw_output": output_text, "metadata": ev_meta})
            self._active_transaction.mark_tool_completed(tool)
        else:
            ev_store = self.session.evidence if self.session else EvidenceStore.instance()
            ev_store.add_evidence(tool, output_text, ev_meta)

        try:
            # Guard: don't classify output from failed tools — error messages
            # get misclassified as findings by the LLM (e.g. "connection refused" → "Open Redirect")
            if not should_classify_output:
                logger.info(f"[{exec_id}] Tool exited {exit_code}, skipping classification")
                # Still record observation for audit trail, but no findings
                try:
                    router = TaskRouter.instance()
                    await router.handle_tool_output(
                        tool_name=tool, stdout=output_text, stderr="",
                        rc=exit_code,
                        metadata={
                            "target": target,
                            "exec_id": exec_id,
                            "skipped_classification": True,
                            "classification_policy": "strict_exit_code",
                        },
                    )
                except Exception:
                    pass
                return []

            findings = ScannerBridge.classify(tool, target, output_text)

            try:
                self.resource_guard.check_findings(len(findings))
            except ResourceExhaustedError as e:
                await queue.put(f"[{exec_id}] {e} - truncating results")
                logger.warning(f"[{exec_id}] {e}")
                return []

            # Always record observation in Epistemic Ledger for audit trail
            # This ensures the Audit Feed shows all tool executions
            try:
                router = TaskRouter.instance()
                await router.handle_tool_output(
                    tool_name=tool,
                    stdout=output_text,
                    stderr="",
                    rc=exit_code,
                    metadata={
                        "target": target,
                        "findings_count": len(findings),
                        "exec_id": exec_id,
                        "classified_on_nonzero_exit": bool(exit_code not in (0, None)),
                    },
                )
            except Exception as router_err:
                logger.warning(f"[{exec_id}] TaskRouter processing error: {router_err}")

            return findings
        except Exception as exc:
            err = f"[{tool}] classifier error: {exc}"
            if self._active_transaction and self._active_transaction.is_active:
                self._active_transaction.add_evidence(
                    {"tool": f"{tool}_classifier_error", "raw_output": err, "metadata": {"target": target, "exec_id": exec_id}}
                )
            else:
                ev_store = self.session.evidence if self.session else EvidenceStore.instance()
                ev_store.add_evidence(f"{tool}_classifier_error", err, {"target": target, "exec_id": exec_id})
            await queue.put(f"[{exec_id}] {err}")
            return []
        finally:
            self._procs.pop(exec_id, None)

    def _normalize_asset(self, target: str) -> str:
        parsed = urlparse(target)
        host = parsed.hostname or target
        if host.startswith("www."):
            host = host[4:]
        return host

    def consume_last_tool_error(self) -> Optional[Dict[str, Any]]:
        error = self._last_tool_error
        self._last_tool_error = None
        return error

    def queue_task(self, tool: str, args: List[str] | None = None) -> None:
        """
        Dynamically add a tool to the current scan queue.

        Args:
            tool: Name of tool to run
            args: Optional arguments
        """
        if tool not in TOOLS:
            raise ValueError(f"Unknown tool: {tool}")
        if tool not in self._installed_meta:
            raise ValueError(f"Tool not installed: {tool}")

        if args:
             # Basic sanity check on args
             for arg in args:
                 if ";" in arg or "|" in arg:
                     raise ValueError(f"Potentially unsafe argument: {arg}")

        self._pending_tasks.append({"tool": tool, "args": args})
        logger.info(f"[ScannerEngine] Dynamically queued task: {tool} {args}")
