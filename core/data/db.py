"""Module db: inline documentation for /Users/jason/Developer/sentinelforge/core/data/db.py."""
#
# PURPOSE:
# Provides the database layer for storing all scan data persistently.
# Uses SQLite (file-based database) with async operations for performance.
#
# WHAT GETS STORED:
# - Sessions: Each scan's metadata (target, start time, status, logs)
# - Findings: Security discoveries (open ports, vulns, exposed services)
# - Issues: Confirmed exploitable vulnerabilities
# - Evidence: References to stored tool outputs
# - Kill Chain: Attack progression tracking
#
# WHY SQLITE:
# - No separate database server needed (just a file)
# - ACID transactions (data safety)
# - Good enough for local security tool (not meant for thousands of concurrent users)
# - Easy backup (just copy the .db file)
#
# KEY CONCEPTS:
# - Async/Await: Non-blocking database operations (app doesn't freeze during queries)
# - WAL Mode (Write-Ahead Logging): Allows concurrent reads while writing
# - Singleton Pattern: One database connection shared across the app
# - Foreign Keys: Enforce data relationships (findings belong to sessions)
#
# PERFORMANCE:
# - Single persistent connection (avoids reconnection overhead)
# - WAL mode enables concurrent readers
# - Async prevents blocking the event loop
#

import aiosqlite
import json
import logging
import os
import asyncio
import sqlite3
import threading
from typing import List, Dict, Optional, Any

from core.base.config import get_config

logger = logging.getLogger(__name__)

class Database:
    """Class Database."""
    _instance = None

    @staticmethod
    def instance():
        """Function instance."""
        # Conditional branch.
        if Database._instance is None:
            Database._instance = Database()
        return Database._instance

    def __init__(self):
        """Function __init__."""
        config = get_config()
        self.db_path = str(config.storage.db_path)
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)

        self._initialized = False
        # asyncio.Lock for async initialization - created lazily in init()
        self._init_lock: Optional[asyncio.Lock] = None
        self._db_connection: Optional[aiosqlite.Connection] = None
        # asyncio.Lock for database operations
        self._db_lock: Optional[asyncio.Lock] = None

        # Persistence Actor
        from core.data.blackbox import BlackBox
        self.blackbox = BlackBox.instance()

    async def init(self):
        """AsyncFunction init."""
        # Fast path: already initialized
        if self._initialized:
            return

        # Lazy-create locks on first call (asyncio.Lock must be created in async context)
        if self._init_lock is None:
            self._init_lock = asyncio.Lock()
        if self._db_lock is None:
            self._db_lock = asyncio.Lock()

        # Store the event loop for later validation (event loop safety)
        self._loop = asyncio.get_running_loop()

        # Double-checked locking pattern with asyncio.Lock
        async with self._init_lock:
            if self._initialized:
                return

            try:
                self._db_connection = await aiosqlite.connect(self.db_path, timeout=5.0)
                await self._db_connection.execute("PRAGMA journal_mode=WAL;")
                await self._db_connection.execute("PRAGMA synchronous=NORMAL;")
                await self._db_connection.execute("PRAGMA busy_timeout=5000;")
                await self._db_connection.execute("PRAGMA foreign_keys=ON;")

                await self._create_tables()

                await self._db_connection.commit()
                self._initialized = True

                # CRITICAL: Initialize event sequence from DB before any events are emitted
                # This ensures continuity across restarts - no duplicate event IDs
                try:
                    from core.cortex.events import initialize_event_sequence_from_db
                    seq = await initialize_event_sequence_from_db()
                    logger.info(f"[Database] Event sequence initialized from DB: {seq}")
                except Exception as e:
                    logger.warning(f"[Database] Failed to initialize event sequence: {e}")

                # Start the BlackBox worker now that we are ready
                self.blackbox.start()

                logger.info(f"Database initialized at {self.db_path} (WAL mode)")
            except Exception as e:
                logger.error(f"Database init failed: {e}")
                raise

    async def close(self):
        """Close the database connection safely."""
        # Conditional branch.
        if self._db_connection:
            try:
                await self._db_connection.close()
                self._initialized = False
                logger.info("[Database] Connection closed.")
            except Exception as e:
                logger.error(f"[Database] Error closing connection: {e}")

    async def _create_tables(self):
        """
        Create all database tables with production-grade constraints.

        Schema decisions:
        - Timestamps: TEXT (ISO8601 format via datetime('now'))
        - Foreign keys: ON DELETE CASCADE for clean cleanup
        - JSON: CHECK(json_valid) to enforce valid JSON
        - Indexes: session_id for query performance
        """
        # Sessions table - scan session metadata
        await self._db_connection.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                target TEXT NOT NULL,
                status TEXT,
                start_time TEXT NOT NULL DEFAULT (datetime('now')),
                end_time TEXT,
                logs TEXT
            )
        """)

        # Findings table - security findings with proper constraints
        await self._db_connection.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                tool TEXT NOT NULL,
                tool_version TEXT,
                type TEXT,
                severity TEXT,
                target TEXT,
                data JSON NOT NULL CHECK(json_valid(data)),
                timestamp TEXT NOT NULL DEFAULT (datetime('now')),
                FOREIGN KEY(session_id) REFERENCES sessions(id) ON DELETE CASCADE
            )
        """)

        # Issues table - confirmed vulnerabilities with deterministic IDs
        await self._db_connection.execute("""
            CREATE TABLE IF NOT EXISTS issues (
                id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                title TEXT NOT NULL,
                severity TEXT,
                target TEXT,
                data JSON NOT NULL CHECK(json_valid(data)),
                timestamp TEXT NOT NULL DEFAULT (datetime('now')),
                FOREIGN KEY(session_id) REFERENCES sessions(id) ON DELETE CASCADE
            )
        """)

        # Evidence table - raw tool outputs
        await self._db_connection.execute("""
            CREATE TABLE IF NOT EXISTS evidence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                tool TEXT NOT NULL,
                tool_version TEXT,
                raw_output TEXT,
                metadata JSON CHECK(json_valid(metadata)),
                timestamp TEXT NOT NULL DEFAULT (datetime('now')),
                FOREIGN KEY(session_id) REFERENCES sessions(id) ON DELETE CASCADE
            )
        """)

        # Scans table - audit trail for scan transactions
        await self._db_connection.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                target TEXT NOT NULL,
                status TEXT NOT NULL,
                findings_count INTEGER DEFAULT 0,
                issues_count INTEGER DEFAULT 0,
                evidence_count INTEGER DEFAULT 0,
                start_time TEXT NOT NULL DEFAULT (datetime('now')),
                end_time TEXT,
                last_completed_tool TEXT,
                error_message TEXT,
                FOREIGN KEY(session_id) REFERENCES sessions(id) ON DELETE CASCADE
            )
        """)

        # System state table - for sequence counters and other global state
        await self._db_connection.execute("""
            CREATE TABLE IF NOT EXISTS system_state (
                key TEXT PRIMARY KEY,
                value INTEGER NOT NULL,
                updated_at TEXT DEFAULT (datetime('now'))
            )
        """)

        # Create indexes for query performance
        # These are critical for UI performance when filtering by session
        await self._db_connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_findings_session ON findings(session_id)
        """)
        await self._db_connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_issues_session ON issues(session_id)
        """)
        await self._db_connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_evidence_session ON evidence(session_id)
        """)
        await self._db_connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_scans_session ON scans(session_id)
        """)

        # Optional: Timestamp indexes for time-based queries
        await self._db_connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_findings_timestamp ON findings(timestamp DESC)
        """)
        await self._db_connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_issues_timestamp ON issues(timestamp DESC)
        """)

    async def _execute_internal(self, query: str, params: tuple = ()):
        """
        Internal low-level execute used by BlackBox worker.

        EVENT LOOP SAFETY: Validates that we're running on the same event loop
        that was used during Database.init(). This prevents deadlocks and corruption
        when mixing aiosqlite (loop-bound) with threading.
        """
        # Validate event loop ownership
        current_loop = asyncio.get_running_loop()
        if hasattr(self, '_loop') and current_loop is not self._loop:
            raise RuntimeError(
                f"Database access from wrong event loop. "
                f"Database initialized on loop {self._loop}, "
                f"but called from loop {current_loop}. "
                f"This indicates a threading/asyncio mixing bug."
            )

        # Conditional branch.
        if not self._initialized:
             try:
                 await self.init()
             except Exception:
                 return # Init failed/cancelled during shutdown

        # Simple retry loop for robustness against external lockers
        max_retries = 5
        # Loop over items.
        for attempt in range(max_retries):
            try:
                async with self._db_lock:
                    if self._db_connection is None:
                        return
                    await self._db_connection.execute(query, params)
                    await self._db_connection.commit()
                return
            except (sqlite3.ProgrammingError, aiosqlite.Error, ValueError) as e:
                if "closed" in str(e).lower():
                    return # Shutdown in progress
                
                is_locked = "database is locked" in str(e).lower()
                if is_locked and attempt < max_retries - 1:
                    await asyncio.sleep(0.1 * (attempt + 1))
                    continue
                # If filtered or final attempt, raise
                raise e
            except Exception as e:
                # Catch-all for any other errors during execution that shouldn't crash the worker
                logger.debug(f"[Database] Execution error: {e}")
                raise e

    async def execute(self, query: str, params: tuple = ()):
        """
        Public execute. Prefer specific save_* methods which route to BlackBox.
        """
        if not self._initialized:
            try:
                await self.init()
            except Exception:
                return None

        try:
            async with self._db_lock:
                if self._db_connection is None:
                    return None
                cursor = await self._db_connection.execute(query, params)
                await self._db_connection.commit()
                return cursor
        except (sqlite3.ProgrammingError, aiosqlite.Error, ValueError) as e:
            if "closed" in str(e).lower():
                return None
            raise e

    async def fetch_all(self, query: str, params: tuple = ()) -> List[Any]:
        """AsyncFunction fetch_all."""
        # Conditional branch.
        if not self._initialized:
            try:
                await self.init()
            except Exception:
                return []
        
        try:
            async with self._db_lock:
                if self._db_connection is None:
                    return []
                async with self._db_connection.execute(query, params) as cursor:
                    return await cursor.fetchall()
        except (sqlite3.ProgrammingError, aiosqlite.Error, ValueError) as e:
            if "closed" in str(e).lower():
                return []
            raise e

    # -------- Session Methods --------

    def save_session(self, session_data: Dict[str, Any]) -> None:
        """
        Save session data (fire-and-forget).

        This is a synchronous method that delegates to the BlackBox worker.
        Returns immediately; actual persistence happens asynchronously.
        """
        self.blackbox.fire_and_forget(self._save_session_impl, session_data)

    async def _save_session_impl(self, session_data: Dict[str, Any]):
        """AsyncFunction _save_session_impl."""
        await self._execute_internal("""
            INSERT OR REPLACE INTO sessions (id, target, status, start_time, logs)
            VALUES (?, ?, ?, ?, ?)
        """, (
            session_data["id"],
            session_data["target"],
            session_data["status"],
            session_data["start_time"],
            json.dumps(session_data.get("logs", []))
        ))

    # -------- Findings Methods --------

    def save_finding(self, finding: Dict[str, Any], session_id: Optional[str] = None) -> None:
        """
        Save finding data (fire-and-forget).

        This is a synchronous method that delegates to the BlackBox worker.
        Returns immediately; actual persistence happens asynchronously.
        """
        self.blackbox.fire_and_forget(self._save_finding_impl, finding, session_id)

    async def _save_finding_impl(self, finding: Dict[str, Any], session_id: Optional[str] = None):
        """AsyncFunction _save_finding_impl."""
        import hashlib
        blob = json.dumps(finding, sort_keys=True)
        fid = hashlib.sha256(blob.encode()).hexdigest()
        
        await self._execute_internal("""
            INSERT OR REPLACE INTO findings (id, session_id, tool, type, severity, target, data, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))
        """, (
            fid,
            session_id,
            finding.get("tool", "unknown"),
            finding.get("type", "unknown"),
            finding.get("severity", "INFO"),
            finding.get("target", "unknown"),
            blob
        ))

    # -------- Issues Methods --------

    def save_issue(self, issue: Dict[str, Any], session_id: Optional[str] = None) -> None:
        """
        Save issue data (fire-and-forget).

        This is a synchronous method that delegates to the BlackBox worker.
        Returns immediately; actual persistence happens asynchronously.
        """
        self.blackbox.fire_and_forget(self._save_issue_impl, issue, session_id)

    async def _save_issue_impl(self, issue: Dict[str, Any], session_id: Optional[str] = None):
        """AsyncFunction _save_issue_impl."""
        import hashlib
        # Use deterministic hash for stable ID (same strategy as findings and transactional save)
        blob = json.dumps(issue, sort_keys=True)
        iid = hashlib.sha256(blob.encode()).hexdigest()

        await self._execute_internal("""
            INSERT OR REPLACE INTO issues (id, session_id, title, severity, target, data, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
        """, (
            iid,
            session_id,
            issue.get("title", "unknown"),
            issue.get("severity", "INFO"),
            issue.get("target", "unknown"),
            blob
        ))

    # -------- Evidence Methods --------

    def save_evidence(self, evidence_data: Dict[str, Any], session_id: Optional[str] = None) -> None:
        """
        Save evidence data (fire-and-forget).

        This is a synchronous method that delegates to the BlackBox worker.
        Returns immediately; actual persistence happens asynchronously.
        """
        self.blackbox.fire_and_forget(self._save_evidence_impl, evidence_data, session_id)

    async def _save_evidence_impl(self, evidence_data: Dict[str, Any], session_id: Optional[str] = None):
        """AsyncFunction _save_evidence_impl."""
        await self._execute_internal("""
            INSERT INTO evidence (session_id, tool, raw_output, metadata, timestamp)
            VALUES (?, ?, ?, ?, datetime('now'))
        """, (
            session_id,
            evidence_data.get("tool", "unknown"),
            evidence_data.get("raw_output", ""),
            json.dumps(evidence_data.get("metadata", {}))
        ))

    def update_evidence(self, evidence_id: int, summary: Optional[str] = None,
                        findings: Optional[List] = None, session_id: Optional[str] = None) -> None:
        """
        Update evidence metadata (fire-and-forget).

        This is a synchronous method that delegates to the BlackBox worker.
        Returns immediately; actual persistence happens asynchronously.
        """
        self.blackbox.fire_and_forget(self._update_evidence_impl, evidence_id, summary, findings, session_id)

    async def _update_evidence_impl(self, evidence_id: int, summary: Optional[str] = None,
                                    findings: Optional[List] = None, session_id: Optional[str] = None):
        """
        Async implementation for updating evidence metadata.

        Uses COALESCE to handle NULL metadata gracefully.
        """
        updates = []
        params = []

        # Use COALESCE to handle NULL metadata - prevents JSON mutation on NULL
        if summary is not None:
            updates.append("metadata = json_set(COALESCE(metadata, '{}'), '$.summary', ?)")
            params.append(summary)
        if findings is not None:
            updates.append("metadata = json_set(COALESCE(metadata, '{}'), '$.findings', ?)")
            params.append(json.dumps(findings))

        if not updates:
            return

        params.append(evidence_id)
        query = f"UPDATE evidence SET {', '.join(updates)} WHERE id = ?"

        try:
            await self._execute_internal(query, tuple(params))
        except Exception:
            pass  # Evidence might have been deleted

    # -------- Transactional Save Methods --------

    async def save_finding_txn(self, finding: Dict[str, Any], session_id: Optional[str] = None, conn=None) -> None:
        """
        Save a finding within an existing transaction.

        This is for use inside ScanTransaction where we already hold the lock
        and have an explicit transaction. Does NOT acquire locks or commit.

        Args:
            finding: Finding data to save
            session_id: Optional session ID
            conn: Database connection (must be provided, in transaction)
        """
        import hashlib
        blob = json.dumps(finding, sort_keys=True)
        fid = hashlib.sha256(blob.encode()).hexdigest()

        await conn.execute("""
            INSERT OR REPLACE INTO findings (id, session_id, tool, tool_version, type, severity, target, data, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
        """, (
            fid,
            session_id,
            finding.get("tool", "unknown"),
            finding.get("tool_version"),  # Optional tool version
            finding.get("type", "unknown"),
            finding.get("severity", "INFO"),
            finding.get("target", "unknown"),
            blob
        ))

    async def save_issue_txn(self, issue: Dict[str, Any], session_id: Optional[str] = None, conn=None) -> None:
        """
        Save an issue within an existing transaction.

        This is for use inside ScanTransaction where we already hold the lock
        and have an explicit transaction. Does NOT acquire locks or commit.

        Uses deterministic hashing for ID (same strategy as findings).

        Args:
            issue: Issue data to save
            session_id: Optional session ID
            conn: Database connection (must be provided, in transaction)
        """
        import hashlib
        # Use deterministic hash for stable ID (like findings)
        blob = json.dumps(issue, sort_keys=True)
        iid = hashlib.sha256(blob.encode()).hexdigest()

        await conn.execute("""
            INSERT OR REPLACE INTO issues (id, session_id, title, severity, target, data, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
        """, (
            iid,
            session_id,
            issue.get("title", "unknown"),
            issue.get("severity", "INFO"),
            issue.get("target", "unknown"),
            blob
        ))

    async def save_evidence_txn(self, evidence_data: Dict[str, Any], session_id: Optional[str] = None, conn=None) -> None:
        """
        Save evidence within an existing transaction.

        This is for use inside ScanTransaction where we already hold the lock
        and have an explicit transaction. Does NOT acquire locks or commit.

        Args:
            evidence_data: Evidence data to save
            session_id: Optional session ID
            conn: Database connection (must be provided, in transaction)
        """
        await conn.execute("""
            INSERT INTO evidence (session_id, tool, tool_version, raw_output, metadata, timestamp)
            VALUES (?, ?, ?, ?, ?, datetime('now'))
        """, (
            session_id,
            evidence_data.get("tool", "unknown"),
            evidence_data.get("tool_version"),  # Optional tool version
            evidence_data.get("raw_output", ""),
            json.dumps(evidence_data.get("metadata", {}))
        ))

    # -------- Read Methods (Safe to run directly) --------

    async def get_findings(self, session_id: Optional[str] = None) -> List[Dict]:
        """AsyncFunction get_findings."""
        query = "SELECT data FROM findings WHERE session_id = ? ORDER BY timestamp DESC"
        params = (session_id,)
        # Conditional branch.
        if session_id is None:
            query = "SELECT data FROM findings ORDER BY timestamp DESC"
            params = ()
        rows = await self.fetch_all(query, params)
        return [json.loads(row[0]) for row in rows]

    async def get_all_findings(self) -> List[Dict]:
        """AsyncFunction get_all_findings."""
        return await self.get_findings(None)

    async def get_issues(self, session_id: Optional[str] = None) -> List[Dict]:
        """AsyncFunction get_issues."""
        query = "SELECT data FROM issues WHERE session_id = ? ORDER BY timestamp DESC"
        params = (session_id,)
        # Conditional branch.
        if session_id is None:
            query = "SELECT data FROM issues ORDER BY timestamp DESC"
            params = ()
        rows = await self.fetch_all(query, params)
        return [json.loads(row[0]) for row in rows]

    async def get_all_issues(self) -> List[Dict]:
        """AsyncFunction get_all_issues."""
        return await self.get_issues(None)

    async def get_evidence(self, session_id: Optional[str] = None) -> List[Dict]:
        """AsyncFunction get_evidence."""
        query = "SELECT id, tool, raw_output, metadata, timestamp FROM evidence"
        params = ()
        # Conditional branch.
        if session_id is not None:
            query += " WHERE session_id = ?"
            params = (session_id,)
        query += " ORDER BY timestamp DESC"
        rows = await self.fetch_all(query, params)
        results = []
        # Loop over items.
        for row in rows:
            metadata = json.loads(row[3]) if row[3] else {}
            results.append({
                "id": row[0],
                "tool": row[1],
                "raw_output": row[2],
                "metadata": metadata,
                "summary": metadata.get("summary"),
                "findings": metadata.get("findings", []),
                "timestamp": row[4]
            })
        return results

    async def get_all_evidence(self) -> List[Dict]:
        """AsyncFunction get_all_evidence."""
        return await self.get_evidence(None)

    # -------- Event Sequence Counter Methods --------

    async def get_event_sequence(self) -> int:
        """
        Get the current global event sequence counter from the database.

        Returns:
            The last persisted sequence number, or 0 if not yet set.
        """
        if not self._initialized:
            await self.init()

        try:
            async with self._db_lock:
                if self._db_connection is None:
                    return 0
                cursor = await self._db_connection.execute(
                    "SELECT value FROM system_state WHERE key = ?",
                    ("event_sequence",)
                )
                row = await cursor.fetchone()
                return row[0] if row else 0
        except Exception as e:
            logger.error(f"[Database] Failed to get event_sequence: {e}")
            return 0

    def save_event_sequence(self, sequence: int) -> None:
        """
        Persist the event sequence counter to the database (fire-and-forget).

        This is called synchronously but delegates to the async BlackBox worker,
        ensuring the counter is persisted without blocking the caller.

        Args:
            sequence: The current sequence number to persist
        """
        self.blackbox.fire_and_forget(self._save_event_sequence_impl, sequence)

    async def _save_event_sequence_impl(self, sequence: int) -> None:
        """
        Async implementation of event sequence persistence.

        Uses INSERT OR REPLACE to upsert the counter value.
        """
        await self._execute_internal("""
            INSERT OR REPLACE INTO system_state (key, value, updated_at)
            VALUES (?, ?, datetime('now'))
        """, ("event_sequence", sequence))

    # -------- Scan Record Methods --------

    async def create_scan_record(self, scan_id: str, session_id: str, target: str) -> None:
        """
        Create a new scan record with status 'running'.

        Args:
            scan_id: Unique identifier for this scan
            session_id: Session ID this scan belongs to
            target: Target being scanned
        """
        await self.execute("""
            INSERT INTO scans (id, session_id, target, status, findings_count, issues_count, evidence_count, start_time)
            VALUES (?, ?, ?, 'running', 0, 0, 0, datetime('now'))
        """, (scan_id, session_id, target))

    async def update_scan_status(
        self,
        scan_id: str,
        status: str,
        findings_count: int = 0,
        issues_count: int = 0,
        evidence_count: int = 0,
        error_message: Optional[str] = None
    ) -> None:
        """
        Update scan record status and counts.

        Args:
            scan_id: Scan ID to update
            status: New status ('running', 'committed', 'rolled_back', 'failed')
            findings_count: Number of findings
            issues_count: Number of issues
            evidence_count: Number of evidence records
            error_message: Error message if status is 'failed'
        """
        if status in ('committed', 'rolled_back', 'failed'):
            await self.execute("""
                UPDATE scans
                SET status = ?, findings_count = ?, issues_count = ?, evidence_count = ?, end_time = datetime('now'), error_message = ?
                WHERE id = ?
            """, (status, findings_count, issues_count, evidence_count, error_message, scan_id))
        else:
            await self.execute("""
                UPDATE scans
                SET status = ?, findings_count = ?, issues_count = ?, evidence_count = ?
                WHERE id = ?
            """, (status, findings_count, issues_count, evidence_count, scan_id))

    async def get_scan_record(self, scan_id: str) -> Optional[Dict]:
        """
        Get a scan record by ID.

        Returns:
            Scan record dict or None if not found
        """
        rows = await self.fetch_all(
            "SELECT id, session_id, target, status, findings_count, issues_count, evidence_count, start_time, end_time, error_message FROM scans WHERE id = ?",
            (scan_id,)
        )
        if rows:
            row = rows[0]
            return {
                "id": row[0],
                "session_id": row[1],
                "target": row[2],
                "status": row[3],
                "findings_count": row[4],
                "issues_count": row[5],
                "evidence_count": row[6],
                "start_time": row[7],
                "end_time": row[8],
                "error_message": row[9],
            }
        return None

    async def get_scans_by_session(self, session_id: str) -> List[Dict]:
        """
        Get all scan records for a session.

        Returns:
            List of scan record dicts
        """
        rows = await self.fetch_all(
            "SELECT id, session_id, target, status, findings_count, issues_count, evidence_count, start_time, end_time, error_message FROM scans WHERE session_id = ? ORDER BY start_time DESC",
            (session_id,)
        )
        return [{
            "id": row[0],
            "session_id": row[1],
            "target": row[2],
            "status": row[3],
            "findings_count": row[4],
            "issues_count": row[5],
            "evidence_count": row[6],
            "start_time": row[7],
            "end_time": row[8],
            "error_message": row[9],
        } for row in rows]
