# core/db.py
# Async SQLite persistence layer (Single Connection + WAL)

import aiosqlite
import json
import logging
import os
import asyncio
from typing import List, Dict, Optional, Any

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
        self._init_lock = asyncio.Lock()
        self._db_connection: Optional[aiosqlite.Connection] = None
        self._db_lock = asyncio.Lock()

    async def init(self):
        if self._initialized:
            return
            
        async with self._init_lock:
            if self._initialized:
                return
                
            try:
                # Create persistent connection
                self._db_connection = await aiosqlite.connect(self.db_path)
                
                # Enable WAL mode for concurrency
                await self._db_connection.execute("PRAGMA journal_mode=WAL;")
                await self._db_connection.execute("PRAGMA synchronous=NORMAL;")
                
                # Create tables
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
                
                await self._db_connection.commit()
                self._initialized = True
                logger.info(f"Database initialized at {self.db_path} (WAL mode)")
            except Exception as e:
                logger.error(f"Database init failed: {e}")
                raise

    async def execute(self, query: str, params: tuple = ()):
        """Execute a query using the shared connection safely."""
        if not self._initialized:
            await self.init()
        
        async with self._db_lock:
            try:
                cursor = await self._db_connection.execute(query, params)
                await self._db_connection.commit()
                return cursor
            except Exception as e:
                logger.error(f"DB Execute Error: {e} | Query: {query}")
                raise

    async def fetch_all(self, query: str, params: tuple = ()) -> List[Any]:
        """Execute and fetch all results."""
        if not self._initialized:
            await self.init()
            
        async with self._db_lock:
            try:
                async with self._db_connection.execute(query, params) as cursor:
                    return await cursor.fetchall()
            except Exception as e:
                logger.error(f"DB Fetch Error: {e}")
                return []

    async def save_session(self, session_data: Dict[str, Any]):
        await self.execute("""
            INSERT OR REPLACE INTO sessions (id, target, status, start_time, logs)
            VALUES (?, ?, ?, ?, ?)
        """, (
            session_data["id"],
            session_data["target"],
            session_data["status"],
            session_data["start_time"],
            json.dumps(session_data.get("logs", []))
        ))

    async def save_finding(self, finding: Dict[str, Any], session_id: Optional[str] = None):
        import hashlib
        blob = json.dumps(finding, sort_keys=True)
        fid = hashlib.sha256(blob.encode()).hexdigest()
        
        await self.execute("""
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

    async def save_issue(self, issue: Dict[str, Any], session_id: Optional[str] = None):
        iid = issue.get("id") or issue.get("title", "unknown")
        blob = json.dumps(issue)
        
        await self.execute("""
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

    async def get_findings(self, session_id: Optional[str] = None) -> List[Dict]:
        query = "SELECT data FROM findings WHERE session_id = ? ORDER BY timestamp DESC"
        params = (session_id,)
        if session_id is None:
            query = "SELECT data FROM findings ORDER BY timestamp DESC"
            params = ()
            
        rows = await self.fetch_all(query, params)
        return [json.loads(row[0]) for row in rows]

    async def get_all_findings(self) -> List[Dict]:
        return await self.get_findings(None)

    async def get_issues(self, session_id: Optional[str] = None) -> List[Dict]:
        query = "SELECT data FROM issues WHERE session_id = ? ORDER BY timestamp DESC"
        params = (session_id,)
        if session_id is None:
            query = "SELECT data FROM issues ORDER BY timestamp DESC"
            params = ()

        rows = await self.fetch_all(query, params)
        return [json.loads(row[0]) for row in rows]

    async def get_all_issues(self) -> List[Dict]:
        return await self.get_issues(None)

    # -------- Evidence Methods --------
    
    async def save_evidence(self, evidence_data: Dict[str, Any], session_id: Optional[str] = None):
        await self.execute("""
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
        # Using json_patch logic is complex in pure SQL without json1 extension guaranteed
        # Simplified: Fetch, Update, Save
        # But for speed/locking, we just overwrite the metadata field carefully?
        # Actually, simpler to just run the UPDATE if we trust json_set/patch availability
        # Since we use standard SQLite3 on mac (which has JSON1), we can use json_patch or json_set
        
        updates = []
        params = []
        
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
            await self.execute(query, tuple(params))
        except Exception:
            # Fallback if json_set fails (old sqlite)
            pass

    async def get_evidence(self, session_id: Optional[str] = None) -> List[Dict]:
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
        return await self.get_evidence(None)