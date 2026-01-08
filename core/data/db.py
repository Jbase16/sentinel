"""Module db: inline documentation for /Users/jason/Developer/sentinelforge/core/data/db.py.

PURPOSE
- Database layer for storing scan data persistently in SQLite using async operations.

WHAT GETS STORED
- Sessions: Scan session metadata (target, status, logs)
- Findings: Discoveries (ports, services, exposures)
- Issues: Rule-derived vulnerabilities
- Evidence: Raw tool outputs + metadata
- Scans: Audit trail for transactional scans (status, counts, timing, errors)
- System state: Global counters (event_sequence, scan_sequence)

KEY CONCEPTS
- WAL mode for concurrent reads during writes
- Async connection via aiosqlite
- Singleton Database instance
- BlackBox worker for fire-and-forget writes (legacy non-transactional path)

CRITICAL INVARIANTS FIXED
- All tables requiring scan_sequence now receive it in both txn and non-txn paths.
- scan_sequence allocation for transactional scans happens inside the commit transaction
  via next_scan_sequence_txn(conn), preserving committed-order semantics.
- Scan record creation for transactional scans happens inside the commit transaction
  via create_scan_record_txn(..., conn).
"""

import aiosqlite
import json
import logging
import os
import asyncio
import sqlite3
from typing import List, Dict, Optional, Any, Tuple

from core.base.config import get_config

logger = logging.getLogger(__name__)


class Database:
    _instance = None

    @staticmethod
    def instance():
        if Database._instance is None:
            Database._instance = Database()
        return Database._instance

    def __init__(self):
        config = get_config()
        self.db_path = str(config.storage.db_path)
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)

        self._initialized = False
        self._init_lock: Optional[asyncio.Lock] = None
        self._db_connection: Optional[aiosqlite.Connection] = None
        self._db_lock: Optional[asyncio.Lock] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None

        # Persistence Actor (legacy non-transactional)
        from core.data.blackbox import BlackBox

        self.blackbox = BlackBox.instance()

    async def init(self):
        if self._initialized:
            return

        if self._init_lock is None:
            self._init_lock = asyncio.Lock()
        if self._db_lock is None:
            self._db_lock = asyncio.Lock()

        self._loop = asyncio.get_running_loop()

        async with self._init_lock:
            if self._initialized:
                return

            try:
                self._db_connection = await aiosqlite.connect(self.db_path, timeout=30.0, isolation_level=None)
                await self._db_connection.execute("PRAGMA journal_mode=WAL;")
                await self._db_connection.execute("PRAGMA synchronous=NORMAL;")
                await self._db_connection.execute("PRAGMA busy_timeout=30000;")  # 30 seconds
                await self._db_connection.execute("PRAGMA foreign_keys=ON;")

                await self._create_tables()
                await self._db_connection.commit()

                # Run schema migrations (automatic upgrades)
                await self._run_migrations()

                self._initialized = True

                # Start BlackBox worker
                self.blackbox.start()

                logger.info(f"Database initialized at {self.db_path} (WAL mode)")
            except Exception as e:
                logger.error(f"Database init failed: {e}")
                raise

    async def _run_migrations(self):
        """Run schema migrations automatically on startup."""
        try:
            from core.data.migrations import MigrationRunner

            runner = MigrationRunner(self.db_path)
            await runner.run_migrations()

        except Exception as e:
            logger.warning(f"[Database] Migration runner failed (non-fatal): {e}")
            # Non-fatal - database can still function with base schema

    async def close(self):
        if self._db_connection:
            try:
                await self._db_connection.close()
                self._initialized = False
                logger.info("[Database] Connection closed.")
            except Exception as e:
                logger.error(f"[Database] Error closing connection: {e}")

    async def _create_tables(self):
        await self._db_connection.execute(
            """
            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                target TEXT NOT NULL,
                status TEXT,
                start_time TEXT NOT NULL DEFAULT (datetime('now')),
                end_time TEXT,
                logs TEXT
            )
        """
        )

        await self._db_connection.execute(
            """
            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                scan_sequence INTEGER NOT NULL,
                tool TEXT NOT NULL,
                tool_version TEXT,
                type TEXT,
                severity TEXT,
                target TEXT,
                data JSON NOT NULL CHECK(json_valid(data)),
                timestamp TEXT NOT NULL DEFAULT (datetime('now')),
                FOREIGN KEY(session_id) REFERENCES sessions(id) ON DELETE CASCADE
            )
        """
        )

        await self._db_connection.execute(
            """
            CREATE TABLE IF NOT EXISTS issues (
                id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                scan_sequence INTEGER NOT NULL,
                title TEXT NOT NULL,
                severity TEXT,
                target TEXT,
                data JSON NOT NULL CHECK(json_valid(data)),
                timestamp TEXT NOT NULL DEFAULT (datetime('now')),
                FOREIGN KEY(session_id) REFERENCES sessions(id) ON DELETE CASCADE
            )
        """
        )

        await self._db_connection.execute(
            """
            CREATE TABLE IF NOT EXISTS evidence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                scan_sequence INTEGER NOT NULL,
                tool TEXT NOT NULL,
                tool_version TEXT,
                raw_output TEXT,
                metadata JSON CHECK(json_valid(metadata)),
                timestamp TEXT NOT NULL DEFAULT (datetime('now')),
                FOREIGN KEY(session_id) REFERENCES sessions(id) ON DELETE CASCADE
            )
        """
        )

        await self._db_connection.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                scan_sequence INTEGER NOT NULL,
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
                failure_phase TEXT,
                exception_type TEXT,
                FOREIGN KEY(session_id) REFERENCES sessions(id) ON DELETE CASCADE
            )
        """
        )

        await self._db_connection.execute(
            """
            CREATE TABLE IF NOT EXISTS system_state (
                key TEXT PRIMARY KEY,
                value INTEGER NOT NULL,
                updated_at TEXT DEFAULT (datetime('now'))
            )
        """
        )

        await self._db_connection.execute("CREATE INDEX IF NOT EXISTS idx_findings_session ON findings(session_id)")
        await self._db_connection.execute("CREATE INDEX IF NOT EXISTS idx_issues_session ON issues(session_id)")
        await self._db_connection.execute("CREATE INDEX IF NOT EXISTS idx_evidence_session ON evidence(session_id)")
        await self._db_connection.execute("CREATE INDEX IF NOT EXISTS idx_scans_session ON scans(session_id)")

        await self._db_connection.execute("CREATE INDEX IF NOT EXISTS idx_findings_timestamp ON findings(timestamp DESC)")
        await self._db_connection.execute("CREATE INDEX IF NOT EXISTS idx_issues_timestamp ON issues(timestamp DESC)")

        await self._db_connection.execute(
            """
            CREATE TABLE IF NOT EXISTS decisions (
                id TEXT PRIMARY KEY,
                event_sequence INTEGER NOT NULL,
                type TEXT NOT NULL,
                chosen TEXT,
                reason TEXT,
                alternatives JSON,
                context JSON,
                evidence JSON,
                parent_id TEXT,
                trigger_event_sequence INTEGER,
                timestamp TEXT NOT NULL DEFAULT (datetime('now'))
            )
        """
        )
        await self._db_connection.execute("CREATE INDEX IF NOT EXISTS idx_decisions_sequence ON decisions(event_sequence)")
        await self._db_connection.execute("CREATE INDEX IF NOT EXISTS idx_decisions_parent ON decisions(parent_id)")

        # Policies table for CAL policy persistence
        await self._db_connection.execute(
            """
            CREATE TABLE IF NOT EXISTS policies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                cal_source TEXT NOT NULL,
                enabled BOOLEAN NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            )
            """
        )
        await self._db_connection.execute("CREATE INDEX IF NOT EXISTS idx_policies_name ON policies(name)")
        await self._db_connection.execute("CREATE INDEX IF NOT EXISTS idx_policies_enabled ON policies(enabled)")

        # Graph Persistence (Session Persistence)
        await self._db_connection.execute(
            """
            CREATE TABLE IF NOT EXISTS graph_nodes (
                id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                type TEXT NOT NULL,
                label TEXT,
                data JSON,
                timestamp TEXT DEFAULT (datetime('now')),
                FOREIGN KEY(session_id) REFERENCES sessions(id) ON DELETE CASCADE
            )
            """
        )
        await self._db_connection.execute("CREATE INDEX IF NOT EXISTS idx_graph_nodes_session ON graph_nodes(session_id)")

        await self._db_connection.execute(
            """
            CREATE TABLE IF NOT EXISTS graph_edges (
                id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                source_id TEXT NOT NULL,
                target_id TEXT NOT NULL,
                type TEXT NOT NULL,
                weight REAL DEFAULT 1.0,
                data JSON,
                timestamp TEXT DEFAULT (datetime('now')),
                FOREIGN KEY(session_id) REFERENCES sessions(id) ON DELETE CASCADE
            )
            """
        )
        await self._db_connection.execute("CREATE INDEX IF NOT EXISTS idx_graph_edges_session ON graph_edges(session_id)")


        # Migration: Add scan_sequence column to evidence if it doesn't exist
        # This handles databases created before scan_sequence was added
        await self._migrate_evidence_table()

    async def _migrate_evidence_table(self) -> None:
        """Add missing columns to evidence table if needed."""
        try:
            # Check if columns exist by querying table info
            cursor = await self._db_connection.execute("PRAGMA table_info(evidence)")
            columns = await cursor.fetchall()
            column_names = {col[1] for col in columns}

            migrations_needed = []
            if "scan_sequence" not in column_names:
                migrations_needed.append(
                    ("scan_sequence", "ALTER TABLE evidence ADD COLUMN scan_sequence INTEGER NOT NULL DEFAULT 0")
                )
            if "tool_version" not in column_names:
                migrations_needed.append(
                    ("tool_version", "ALTER TABLE evidence ADD COLUMN tool_version TEXT")
                )

            if migrations_needed:
                for col_name, sql in migrations_needed:
                    logger.info(f"[Database] Migrating evidence table: adding {col_name} column")
                    await self._db_connection.execute(sql)
                await self._db_connection.commit()
                logger.info(f"[Database] Migration complete: added {len(migrations_needed)} column(s)")
        except Exception as e:
            logger.warning(f"[Database] Evidence migration check failed: {e}")

        # Ensure "global_scan" session exists for sessionless scanner operations
        await self._ensure_global_scan_session()

    async def _ensure_global_scan_session(self) -> None:
        """Create the global_scan session if it doesn't exist."""
        try:
            cursor = await self._db_connection.execute(
                "SELECT id FROM sessions WHERE id = ?", ("global_scan",)
            )
            row = await cursor.fetchone()
            if row is None:
                await self._db_connection.execute(
                    """
                    INSERT INTO sessions (id, target, status, start_time)
                    VALUES ('global_scan', 'system', 'active', datetime('now'))
                    """
                )
                await self._db_connection.commit()
                logger.info("[Database] Created global_scan session for sessionless operations")
        except Exception as e:
            logger.warning(f"[Database] Failed to ensure global_scan session: {e}")

    # ----------------------------
    # Low-level internal execution
    # ----------------------------
    async def _execute_internal(self, query: str, params: tuple = ()):
        # Event loop ownership safety (important with aiosqlite)
        current_loop = asyncio.get_running_loop()
        if self._loop is not None and current_loop is not self._loop:
            raise RuntimeError(
                f"Database access from wrong event loop. Initialized on {self._loop}, called from {current_loop}."
            )

        if not self._initialized:
            try:
                await self.init()
            except Exception:
                return

        max_retries = 5
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
                    return
                if "database is locked" in str(e).lower() and attempt < max_retries - 1:
                    await asyncio.sleep(0.1 * (attempt + 1))
                    continue
                raise
            except Exception as e:
                logger.debug(f"[Database] Execution error: {e}")
                raise

    async def execute(self, query: str, params: tuple = ()):
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
            raise

    async def fetch_all(self, query: str, params: tuple = ()) -> List[Any]:
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
            raise

    # ----------------------------
    # Sessions
    # ----------------------------
    def save_session(self, session_data: Dict[str, Any]) -> None:
        self.blackbox.fire_and_forget(self._save_session_impl, session_data)

    async def _save_session_impl(self, session_data: Dict[str, Any]):
        await self._execute_internal(
            """
            INSERT OR REPLACE INTO sessions (id, target, status, start_time, logs)
            VALUES (?, ?, ?, ?, ?)
        """,
            (
                session_data["id"],
                session_data["target"],
                session_data.get("status"),
                session_data.get("start_time"),
                json.dumps(session_data.get("logs", [])),
            ),
        )

    # ----------------------------
    # Findings (legacy non-txn)
    # ----------------------------
    def save_finding(self, finding: Dict[str, Any], session_id: Optional[str] = None, scan_sequence: int = 0) -> None:
        self.blackbox.fire_and_forget(self._save_finding_impl, finding, session_id, scan_sequence)

    async def _save_finding_impl(self, finding: Dict[str, Any], session_id: Optional[str] = None, scan_sequence: int = 0):
        import hashlib

        blob = json.dumps(finding, sort_keys=True)
        fid = hashlib.sha256(blob.encode()).hexdigest()

        await self._execute_internal(
            """
            INSERT OR REPLACE INTO findings
              (id, session_id, scan_sequence, tool, tool_version, type, severity, target, data, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
        """,
            (
                fid,
                session_id,
                int(scan_sequence),
                finding.get("tool", "unknown"),
                finding.get("tool_version"),
                finding.get("type", "unknown"),
                finding.get("severity", "INFO"),
                finding.get("target", "unknown"),
                blob,
            ),
        )

    # ----------------------------
    # Issues (legacy non-txn)
    # ----------------------------
    def save_issue(self, issue: Dict[str, Any], session_id: Optional[str] = None, scan_sequence: int = 0) -> None:
        self.blackbox.fire_and_forget(self._save_issue_impl, issue, session_id, scan_sequence)

    async def _save_issue_impl(self, issue: Dict[str, Any], session_id: Optional[str] = None, scan_sequence: int = 0):
        import hashlib

        blob = json.dumps(issue, sort_keys=True)
        iid = hashlib.sha256(blob.encode()).hexdigest()

        await self._execute_internal(
            """
            INSERT OR REPLACE INTO issues
              (id, session_id, scan_sequence, title, severity, target, data, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))
        """,
            (
                iid,
                session_id,
                int(scan_sequence),
                issue.get("title", "unknown"),
                issue.get("severity", "INFO"),
                issue.get("target", "unknown"),
                blob,
            ),
        )

    # ----------------------------
    # Evidence (legacy non-txn)
    # ----------------------------
    def save_evidence(self, evidence_data: Dict[str, Any], session_id: Optional[str] = None, scan_sequence: int = 0) -> None:
        self.blackbox.fire_and_forget(self._save_evidence_impl, evidence_data, session_id, scan_sequence)

    async def _save_evidence_impl(
        self, evidence_data: Dict[str, Any], session_id: Optional[str] = None, scan_sequence: int = 0
    ):
        await self._execute_internal(
            """
            INSERT INTO evidence
              (session_id, scan_sequence, tool, tool_version, raw_output, metadata, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
        """,
            (
                session_id,
                int(scan_sequence),
                evidence_data.get("tool", "unknown"),
                evidence_data.get("tool_version"),
                evidence_data.get("raw_output", ""),
                json.dumps(evidence_data.get("metadata", {})),
            ),
        )

    def update_evidence(
        self,
        evidence_id: int,
        summary: Optional[str] = None,
        findings: Optional[List] = None,
        session_id: Optional[str] = None,
    ) -> None:
        self.blackbox.fire_and_forget(self._update_evidence_impl, evidence_id, summary, findings, session_id)

    async def _update_evidence_impl(
        self,
        evidence_id: int,
        summary: Optional[str] = None,
        findings: Optional[List] = None,
        session_id: Optional[str] = None,
    ):
        updates = []
        params: List[Any] = []

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
            pass

    # ----------------------------
    # Transactional save methods
    # ----------------------------
    async def save_finding_txn(
        self, finding: Dict[str, Any], session_id: Optional[str] = None, scan_sequence: int = 0, conn=None
    ) -> None:
        import hashlib

        blob = json.dumps(finding, sort_keys=True)
        fid = hashlib.sha256(blob.encode()).hexdigest()

        await conn.execute(
            """
            INSERT OR REPLACE INTO findings
              (id, session_id, scan_sequence, tool, tool_version, type, severity, target, data, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
        """,
            (
                fid,
                session_id,
                int(scan_sequence),
                finding.get("tool", "unknown"),
                finding.get("tool_version"),
                finding.get("type", "unknown"),
                finding.get("severity", "INFO"),
                finding.get("target", "unknown"),
                blob,
            ),
        )

    async def save_issue_txn(
        self, issue: Dict[str, Any], session_id: Optional[str] = None, scan_sequence: int = 0, conn=None
    ) -> None:
        import hashlib

        blob = json.dumps(issue, sort_keys=True)
        iid = hashlib.sha256(blob.encode()).hexdigest()

        await conn.execute(
            """
            INSERT OR REPLACE INTO issues
              (id, session_id, scan_sequence, title, severity, target, data, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))
        """,
            (
                iid,
                session_id,
                int(scan_sequence),
                issue.get("title", "unknown"),
                issue.get("severity", "INFO"),
                issue.get("target", "unknown"),
                blob,
            ),
        )

    async def save_evidence_txn(
        self, evidence_data: Dict[str, Any], session_id: Optional[str] = None, scan_sequence: int = 0, conn=None
    ) -> None:
        await conn.execute(
            """
            INSERT INTO evidence
              (session_id, scan_sequence, tool, tool_version, raw_output, metadata, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
        """,
            (
                session_id,
                int(scan_sequence),
                evidence_data.get("tool", "unknown"),
                evidence_data.get("tool_version"),
                evidence_data.get("raw_output", ""),
                json.dumps(evidence_data.get("metadata", {})),
            ),
        )

    # ----------------------------
    # Read methods
    # ----------------------------
    async def get_findings(self, session_id: Optional[str] = None) -> List[Dict]:
        query = "SELECT data FROM findings WHERE session_id = ? ORDER BY timestamp DESC"
        params: Tuple[Any, ...] = (session_id,)
        if session_id is None:
            query = "SELECT data FROM findings ORDER BY timestamp DESC"
            params = ()
        rows = await self.fetch_all(query, params)
        return [json.loads(row[0]) for row in rows]

    async def get_all_findings(self) -> List[Dict]:
        return await self.get_findings(None)

    async def get_issues(self, session_id: Optional[str] = None) -> List[Dict]:
        query = "SELECT data FROM issues WHERE session_id = ? ORDER BY timestamp DESC"
        params: Tuple[Any, ...] = (session_id,)
        if session_id is None:
            query = "SELECT data FROM issues ORDER BY timestamp DESC"
            params = ()
        rows = await self.fetch_all(query, params)
        return [json.loads(row[0]) for row in rows]

    async def get_all_issues(self) -> List[Dict]:
        return await self.get_issues(None)

    async def get_evidence(self, session_id: Optional[str] = None) -> List[Dict]:
        query = "SELECT id, tool, raw_output, metadata, timestamp FROM evidence"
        params: Tuple[Any, ...] = ()
        if session_id is not None:
            query += " WHERE session_id = ?"
            params = (session_id,)
        query += " ORDER BY timestamp DESC"
        rows = await self.fetch_all(query, params)

        results = []
        for row in rows:
            metadata = json.loads(row[3]) if row[3] else {}
            results.append(
                {
                    "id": row[0],
                    "tool": row[1],
                    "raw_output": row[2],
                    "metadata": metadata,
                    "summary": metadata.get("summary"),
                    "findings": metadata.get("findings", []),
                    "timestamp": row[4],
                }
            )
        return results

    async def get_all_evidence(self) -> List[Dict]:
        return await self.get_evidence(None)

    async def get_session(self, session_id: str) -> Optional[Dict]:
        """
        Retrieve session metadata from database.

        Args:
            session_id: Session UUID

        Returns:
            Dict with session data or None if not found
        """
        query = "SELECT id, target, status, start_time, end_time, logs FROM sessions WHERE id = ?"
        rows = await self.fetch_all(query, (session_id,))

        if not rows:
            return None

        row = rows[0]
        return {
            'id': row[0],
            'target': row[1],
            'status': row[2],
            'start_time': row[3],
            'end_time': row[4],
            'logs': row[5]
        }

    # ----------------------------
    # System state counters
    # ----------------------------
    async def get_event_sequence(self) -> int:
        if not self._initialized:
            await self.init()

        try:
            async with self._db_lock:
                if self._db_connection is None:
                    return 0
                cursor = await self._db_connection.execute(
                    "SELECT value FROM system_state WHERE key = ?", ("event_sequence",)
                )
                row = await cursor.fetchone()
                return row[0] if row else 0
        except Exception as e:
            logger.error(f"[Database] Failed to get event_sequence: {e}")
            return 0

    def save_event_sequence(self, sequence: int) -> None:
        self.blackbox.fire_and_forget(self._save_event_sequence_impl, sequence)

    async def _save_event_sequence_impl(self, sequence: int) -> None:
        await self._execute_internal(
            """
            INSERT OR REPLACE INTO system_state (key, value, updated_at)
            VALUES (?, ?, datetime('now'))
        """,
            ("event_sequence", int(sequence)),
        )

    # ----------------------------
    # Scan sequence (txn + non-txn)
    # ----------------------------
    async def next_scan_sequence(self) -> int:
        """
        Non-transactional scan sequence allocator (legacy).
        Prefer next_scan_sequence_txn(conn) for ScanTransaction commits.
        """
        if not self._initialized:
            await self.init()

        async with self._db_lock:
            if self._db_connection is None:
                raise RuntimeError("Database not available")

            cursor = await self._db_connection.execute("SELECT value FROM system_state WHERE key = ?", ("scan_sequence",))
            row = await cursor.fetchone()
            current = row[0] if row else 0
            next_val = current + 1

            await self._db_connection.execute(
                """
                INSERT OR REPLACE INTO system_state (key, value, updated_at)
                VALUES (?, ?, datetime('now'))
            """,
                ("scan_sequence", int(next_val)),
            )
            await self._db_connection.commit()
            return int(next_val)

    async def next_scan_sequence_txn(self, conn) -> int:
        """
        Transactional scan sequence allocator. MUST be called inside an open transaction.
        This preserves scan_sequence as "committed order" semantics.
        """
        cursor = await conn.execute("SELECT value FROM system_state WHERE key = ?", ("scan_sequence",))
        row = await cursor.fetchone()
        current = row[0] if row else 0
        next_val = int(current) + 1

        await conn.execute(
            """
            INSERT OR REPLACE INTO system_state (key, value, updated_at)
            VALUES (?, ?, datetime('now'))
        """,
            ("scan_sequence", next_val),
        )
        return next_val

    # ----------------------------
    # Scan record methods (txn + non-txn)
    # ----------------------------
    async def create_scan_record(self, scan_id: str, scan_sequence: int, session_id: str, target: str) -> None:
        await self.execute(
            """
            INSERT INTO scans
              (id, scan_sequence, session_id, target, status, findings_count, issues_count, evidence_count, start_time)
            VALUES (?, ?, ?, ?, 'running', 0, 0, 0, datetime('now'))
        """,
            (scan_id, int(scan_sequence), session_id, target),
        )

    async def create_scan_record_txn(
        self,
        scan_id: str,
        scan_sequence: int,
        session_id: str,
        target: str,
        status: str,
        conn,
    ) -> None:
        await conn.execute(
            """
            INSERT INTO scans
              (id, scan_sequence, session_id, target, status, findings_count, issues_count, evidence_count, start_time)
            VALUES (?, ?, ?, ?, ?, 0, 0, 0, datetime('now'))
        """,
            (scan_id, int(scan_sequence), session_id, target, status),
        )

    async def update_scan_last_completed_tool_txn(self, scan_id: str, tool: str, conn) -> None:
        await conn.execute("UPDATE scans SET last_completed_tool = ? WHERE id = ?", (tool, scan_id))

    async def update_scan_status(
        self,
        scan_id: str,
        status: str,
        findings_count: int = 0,
        issues_count: int = 0,
        evidence_count: int = 0,
        error_message: Optional[str] = None,
        failure_phase: Optional[str] = None,
        exception_type: Optional[str] = None,
        last_completed_tool: Optional[str] = None,
    ) -> None:
        if status in ("committed", "rolled_back", "failed"):
            await self.execute(
                """
                UPDATE scans
                SET status = ?, findings_count = ?, issues_count = ?, evidence_count = ?,
                    end_time = datetime('now'),
                    error_message = ?, failure_phase = ?, exception_type = ?,
                    last_completed_tool = COALESCE(?, last_completed_tool)
                WHERE id = ?
            """,
                (
                    status,
                    int(findings_count),
                    int(issues_count),
                    int(evidence_count),
                    error_message,
                    failure_phase,
                    exception_type,
                    last_completed_tool,
                    scan_id,
                ),
            )
        else:
            await self.execute(
                """
                UPDATE scans
                SET status = ?, findings_count = ?, issues_count = ?, evidence_count = ?,
                    last_completed_tool = COALESCE(?, last_completed_tool)
                WHERE id = ?
            """,
                (status, int(findings_count), int(issues_count), int(evidence_count), last_completed_tool, scan_id),
            )

    async def get_scan_record(self, scan_id: str) -> Optional[Dict]:
        rows = await self.fetch_all(
            """
            SELECT id, session_id, target, status, findings_count, issues_count, evidence_count,
                   start_time, end_time, last_completed_tool, error_message
            FROM scans WHERE id = ?
        """,
            (scan_id,),
        )
        if not rows:
            return None
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
            "last_completed_tool": row[9],
            "error_message": row[10],
        }

    async def get_scans_by_session(self, session_id: str) -> List[Dict]:
        rows = await self.fetch_all(
            """
            SELECT id, session_id, target, status, findings_count, issues_count, evidence_count,
                   start_time, end_time, last_completed_tool, error_message
            FROM scans
            WHERE session_id = ?
            ORDER BY start_time DESC
        """,
            (session_id,),
        )
        return [
            {
                "id": row[0],
                "session_id": row[1],
                "target": row[2],
                "status": row[3],
                "findings_count": row[4],
                "issues_count": row[5],
                "evidence_count": row[6],
                "start_time": row[7],
                "end_time": row[8],
                "last_completed_tool": row[9],
                "error_message": row[10],
            }
            for row in rows
        ]

    # ----------------------------
    # Decisions (Strategic Brain)
    # ----------------------------
    def save_decision(self, decision: Dict[str, Any]) -> None:
        self.blackbox.fire_and_forget(self._save_decision_impl, decision)

    async def _save_decision_impl(self, decision: Dict[str, Any]):
        await self._execute_internal(
            """
            INSERT OR REPLACE INTO decisions
              (id, event_sequence, type, chosen, reason, alternatives, context, evidence, parent_id, trigger_event_sequence)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                decision["id"],
                int(decision.get("sequence", 0)),
                decision["type"],
                str(decision["chosen"]),
                decision["reason"],
                json.dumps(decision.get("alternatives", [])),
                json.dumps(decision.get("context", {})),
                json.dumps(decision.get("evidence", {})),
                decision.get("parent_id"),
                decision.get("trigger_event_sequence"),
            ),
        )

    async def save_decision_txn(self, decision: Dict[str, Any], conn) -> None:
        """
        Save a decision record within a transaction.
        """
        await conn.execute(
            """
            INSERT OR REPLACE INTO decisions
              (id, event_sequence, type, chosen, reason, alternatives, context, evidence, parent_id, trigger_event_sequence)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                decision["id"],
                int(decision.get("sequence", 0)),
                decision["type"],
                str(decision["chosen"]),
                decision["reason"],
                json.dumps(decision.get("alternatives", [])),
                json.dumps(decision.get("context", {})),
                json.dumps(decision.get("evidence", {})),
                decision.get("parent_id"),
                decision.get("trigger_event_sequence"),
            ),
        )

    async def get_decisions(self, limit: int = 100) -> List[Dict]:
        """
        Retrieve recent strategic decisions.
        """
        rows = await self.fetch_all(
            """
            SELECT id, event_sequence, type, chosen, reason, alternatives, context, evidence, parent_id, trigger_event_sequence, timestamp
            FROM decisions
            ORDER BY event_sequence DESC
            LIMIT ?
        """,
            (limit,),
        )
        return [
            {
                "id": row[0],
                "sequence": row[1],
                "type": row[2],
                "chosen": row[3],
                "reason": row[4],
                "alternatives": json.loads(row[5]) if row[5] else [],
                "context": json.loads(row[6]) if row[6] else {},
                "evidence": json.loads(row[7]) if row[7] else {},
                "parent_id": row[8],
                "trigger_event_sequence": row[9],
                "timestamp": row[10],
            }
            for row in rows
        ]

    async def get_decision_children(self, parent_id: str) -> List[Dict]:
        """
        Retrieve all decisions caused by a specific parent decision.
        """
        rows = await self.fetch_all(
            """
            SELECT id, event_sequence, type, chosen, reason, alternatives, context, evidence, parent_id, trigger_event_sequence, timestamp
            FROM decisions
            WHERE parent_id = ?
            ORDER BY event_sequence ASC
        """,
            (parent_id,),
        )
        return [
            {
                "id": row[0],
                "sequence": row[1],
                "type": row[2],
                "chosen": row[3],
                "reason": row[4],
                "alternatives": json.loads(row[5]) if row[5] else [],
                "context": json.loads(row[6]) if row[6] else {},
                "evidence": json.loads(row[7]) if row[7] else {},
                "parent_id": row[8],
                "trigger_event_sequence": row[9],
                "timestamp": row[10],
            }
            for row in rows
        ]

    # ============================================================================
    # Policy Management Methods
    # ============================================================================

    async def save_policy(self, name: str, cal_source: str, enabled: bool = True) -> int:
        """
        Save a new CAL policy to the database.

        Args:
            name: Unique policy name
            cal_source: CAL DSL source code
            enabled: Whether policy should be active

        Returns:
            The database ID of the inserted policy

        Raises:
            sqlite3.IntegrityError: If policy name already exists
        """
        cursor = await self._db_connection.execute(
            """
            INSERT INTO policies (name, cal_source, enabled, created_at, updated_at)
            VALUES (?, ?, ?, datetime('now'), datetime('now'))
            """,
            (name, cal_source, 1 if enabled else 0)
        )
        await self._db_connection.commit()
        return cursor.lastrowid

    async def get_policy_by_name(self, name: str) -> Optional[Dict]:
        """
        Get a policy by its name.

        Args:
            name: Policy name to retrieve

        Returns:
            Policy dict with id, name, cal_source, enabled, created_at, updated_at
            or None if not found
        """
        cursor = await self._db_connection.execute(
            """
            SELECT id, name, cal_source, enabled, created_at, updated_at
            FROM policies
            WHERE name = ?
            """,
            (name,)
        )
        row = await cursor.fetchone()
        if not row:
            return None

        return {
            "id": row[0],
            "name": row[1],
            "cal_source": row[2],
            "enabled": bool(row[3]),
            "created_at": row[4],
            "updated_at": row[5]
        }

    async def list_policies(self) -> List[Dict]:
        """
        List all policies in the database.

        Returns:
            List of policy dicts sorted by creation date
        """
        cursor = await self._db_connection.execute(
            """
            SELECT id, name, cal_source, enabled, created_at, updated_at
            FROM policies
            ORDER BY created_at DESC
            """
        )
        rows = await cursor.fetchall()

        return [
            {
                "id": row[0],
                "name": row[1],
                "cal_source": row[2],
                "enabled": bool(row[3]),
                "created_at": row[4],
                "updated_at": row[5]
            }
            for row in rows
        ]

    async def update_policy(self, name: str, cal_source: str = None, enabled: bool = None) -> bool:
        """
        Update an existing policy.

        Args:
            name: Policy name to update
            cal_source: New CAL source (optional)
            enabled: New enabled status (optional)

        Returns:
            True if policy was updated, False if not found
        """
        # Build dynamic UPDATE query
        updates = []
        params = []

        if cal_source is not None:
            updates.append("cal_source = ?")
            params.append(cal_source)

        if enabled is not None:
            updates.append("enabled = ?")
            params.append(1 if enabled else 0)

        if not updates:
            return False  # Nothing to update

        # Always update updated_at
        updates.append("updated_at = datetime('now')")

        params.append(name)  # WHERE clause parameter

        query = f"UPDATE policies SET {', '.join(updates)} WHERE name = ?"

        cursor = await self._db_connection.execute(query, params)
        await self._db_connection.commit()

        return cursor.rowcount > 0

    async def delete_policy(self, name: str) -> bool:
        """
        Delete a policy by name.

        Args:
            name: Policy name to delete

        Returns:
            True if policy was deleted, False if not found
        """
        cursor = await self._db_connection.execute(
            "DELETE FROM policies WHERE name = ?",
            (name,)
        )
        await self._db_connection.commit()
        return cursor.rowcount > 0



    async def save_graph_snapshot(
        self, session_id: str, nodes: List[Dict], edges: List[Dict]
    ) -> None:
        """
        Transactional wipe-and-replace of the graph for a session.
        Ensures the DB always reflects the latest in-memory state.
        """
        if not session_id:
            return

        async with self._db_lock:
            try:
                await self._db_connection.execute("BEGIN TRANSACTION")

                # Wipe existing graph for this session
                await self._db_connection.execute(
                    "DELETE FROM graph_nodes WHERE session_id = ?", (session_id,)
                )
                await self._db_connection.execute(
                    "DELETE FROM graph_edges WHERE session_id = ?", (session_id,)
                )

                # Bulk insert nodes
                if nodes:
                    await self._db_connection.executemany(
                        """
                        INSERT OR REPLACE INTO graph_nodes (id, session_id, type, label, data)
                        VALUES (?, ?, ?, ?, ?)
                        """,
                        [
                            (
                                n["id"],
                                session_id,
                                n["type"],
                                n.get("label"),
                                json.dumps(n.get("data", {})),
                            )
                            for n in nodes
                        ],
                    )

                # Bulk insert edges
                if edges:
                    await self._db_connection.executemany(
                        """
                        INSERT OR REPLACE INTO graph_edges (id, session_id, source_id, target_id, type, weight, data)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        [
                            (
                                e["id"],
                                session_id,
                                e["source"],
                                e["target"],
                                e["type"],
                                e.get("weight", 1.0),
                                json.dumps(e.get("data", {})),
                            )
                            for e in edges
                        ],
                    )

                await self._db_connection.execute("COMMIT")
                logger.debug(
                    f"[Database] Saved graph snapshot for {session_id} "
                    f"({len(nodes)} nodes, {len(edges)} edges)"
                )

            except Exception as e:
                await self._db_connection.execute("ROLLBACK")
                logger.error(f"[Database] Failed to save graph snapshot: {e}")
                raise

    async def load_graph_snapshot(
        self, session_id: str
    ) -> Tuple[List[Dict], List[Dict]]:
        """
        Load the full graph for a session.
        Returns (nodes, edges) lists of dicts.
        """
        if not session_id:
            return [], []

        async with self._db_lock:
            try:
                # Load Nodes
                nodes = []
                async with self._db_connection.execute(
                    "SELECT id, type, label, data FROM graph_nodes WHERE session_id = ?",
                    (session_id,),
                ) as cursor:
                    async for row in cursor:
                        nodes.append(
                            {
                                "id": row[0],
                                "type": row[1],
                                "label": row[2],
                                "data": json.loads(row[3]) if row[3] else {},
                            }
                        )

                # Load Edges
                edges = []
                async with self._db_connection.execute(
                    "SELECT id, source_id, target_id, type, weight, data FROM graph_edges WHERE session_id = ?",
                    (session_id,),
                ) as cursor:
                    async for row in cursor:
                        edges.append(
                            {
                                "id": row[0],
                                "source": row[1],
                                "target": row[2],
                                "type": row[3],
                                "weight": row[4],
                                "data": json.loads(row[5]) if row[5] else {},
                            }
                        )

                return nodes, edges

            except Exception as e:
                logger.error(f"[Database] Failed to load graph snapshot: {e}")
                return [], []
