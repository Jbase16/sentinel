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
from typing import List, Dict, Optional, Any

from core.base.config import get_config

logger = logging.getLogger(__name__)

class Database:
    """Class Database."""
    _instance = None

    @staticmethod
    def instance():
        """Function instance."""
        if Database._instance is None:
            Database._instance = Database()
        return Database._instance

    def __init__(self):
        config = get_config()
        self.db_path = str(config.storage.db_path)
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        
        self._initialized = False
        self._init_lock = asyncio.Lock()
        self._db_connection: Optional[aiosqlite.Connection] = None
        self._db_lock = asyncio.Lock()
        
        # Persistence Actor
        from core.data.blackbox import BlackBox
        self.blackbox = BlackBox.instance()

    async def init(self):
        """AsyncFunction init."""
        if self._initialized:
            return
            
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
                
                # Start the BlackBox worker now that we are ready
                self.blackbox.start()
                
                logger.info(f"Database initialized at {self.db_path} (WAL mode)")
            except Exception as e:
                logger.error(f"Database init failed: {e}")
                raise

    async def close(self):
        """Close the database connection safely."""
        if self._db_connection:
            try:
                await self._db_connection.close()
                self._initialized = False
                logger.info("[Database] Connection closed.")
            except Exception as e:
                logger.error(f"[Database] Error closing connection: {e}")

    async def _create_tables(self):
        """AsyncFunction _create_tables."""
        await self._db_connection.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                target TEXT,
                status TEXT,
                start_time REAL,
                end_time REAL,
                logs TEXT
            )
        """)
        await self._db_connection.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY,
                session_id TEXT,
                tool TEXT,
                type TEXT,
                severity TEXT,
                target TEXT,
                data JSON,
                timestamp TEXT,
                FOREIGN KEY(session_id) REFERENCES sessions(id)
            )
        """)
        await self._db_connection.execute("""
            CREATE TABLE IF NOT EXISTS issues (
                id TEXT PRIMARY KEY,
                session_id TEXT,
                title TEXT,
                severity TEXT,
                target TEXT,
                data JSON,
                timestamp TEXT,
                FOREIGN KEY(session_id) REFERENCES sessions(id)
            )
        """)
        await self._db_connection.execute("""
            CREATE TABLE IF NOT EXISTS evidence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT,
                tool TEXT,
                raw_output TEXT,
                metadata JSON,
                timestamp TEXT,
                FOREIGN KEY(session_id) REFERENCES sessions(id)
            )
        """)

    async def _execute_internal(self, query: str, params: tuple = ()):
        """Internal low-level execute used by BlackBox worker."""
        if not self._initialized:
             await self.init()
        
        # Simple retry loop for robustness against external lockers
        max_retries = 5
        for attempt in range(max_retries):
            try:
                async with self._db_lock:
                    await self._db_connection.execute(query, params)
                    await self._db_connection.commit()
                return
            except Exception as e:
                is_locked = "database is locked" in str(e).lower()
                if is_locked and attempt < max_retries - 1:
                    await asyncio.sleep(0.1 * (attempt + 1))
                    continue
                # If filtered or final attempt, raise
                raise e

    async def execute(self, query: str, params: tuple = ()):
        """
        Public execute. Prefer specific save_* methods which route to BlackBox.
        If used for writes, this bypasses the BlackBox, which is unsafe.
        Assuming this is mostly used for reads or ad-hoc queries?
        Actually, let's funnel it too if it's a write? 
        Regexing query is brittle. 
        For now, we leave this for READ operations or direct usage, 
        and update save_* to use the queue.
        """
        # ... logic as before or simplified ...
        # Simplified:
        if not self._initialized:
            await self.init()
        async with self._db_lock:
            cursor = await self._db_connection.execute(query, params)
            await self._db_connection.commit()
            return cursor

    async def fetch_all(self, query: str, params: tuple = ()) -> List[Any]:
        """AsyncFunction fetch_all."""
        if not self._initialized:
            await self.init()
        async with self._db_lock:
            async with self._db_connection.execute(query, params) as cursor:
                return await cursor.fetchall()

    # -------- Session Methods --------

    async def save_session(self, session_data: Dict[str, Any]):
        """Fire-and-forget save."""
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

    async def save_finding(self, finding: Dict[str, Any], session_id: Optional[str] = None):
        """AsyncFunction save_finding."""
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

    async def save_issue(self, issue: Dict[str, Any], session_id: Optional[str] = None):
        """AsyncFunction save_issue."""
        self.blackbox.fire_and_forget(self._save_issue_impl, issue, session_id)

    async def _save_issue_impl(self, issue: Dict[str, Any], session_id: Optional[str] = None):
        """AsyncFunction _save_issue_impl."""
        iid = issue.get("id") or issue.get("title", "unknown")
        blob = json.dumps(issue)
        
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

    async def save_evidence(self, evidence_data: Dict[str, Any], session_id: Optional[str] = None):
        """AsyncFunction save_evidence."""
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

    async def update_evidence(self, evidence_id: int, summary: Optional[str] = None, 
                              findings: Optional[List] = None, session_id: Optional[str] = None):
         """AsyncFunction update_evidence."""
         self.blackbox.fire_and_forget(self._update_evidence_impl, evidence_id, summary, findings, session_id)

    async def _update_evidence_impl(self, evidence_id: int, summary: Optional[str] = None, 
                                    findings: Optional[List] = None, session_id: Optional[str] = None):
        """AsyncFunction _update_evidence_impl."""
        updates = []
        params = []
        
        # Note: json_set is preferred but simple update works too
        if summary is not None:
            updates.append("metadata = json_set(metadata, '$.summary', ?)")
            params.append(summary)
        if findings is not None:
            updates.append("metadata = json_set(metadata, '$.findings', ?)")
            params.append(json.dumps(findings))
        
        if not updates:
            return
        
        params.append(evidence_id)
        query = f"UPDATE evidence SET {', '.join(updates)} WHERE id = ?"
        
        try:
            await self._execute_internal(query, tuple(params))
        except Exception:
            pass

    # -------- Read Methods (Safe to run directly) --------

    async def get_findings(self, session_id: Optional[str] = None) -> List[Dict]:
        """AsyncFunction get_findings."""
        query = "SELECT data FROM findings WHERE session_id = ? ORDER BY timestamp DESC"
        params = (session_id,)
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
        if session_id is not None:
            query += " WHERE session_id = ?"
            params = (session_id,)
        query += " ORDER BY timestamp DESC"
        rows = await self.fetch_all(query, params)
        results = []
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
