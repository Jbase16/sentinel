# core/db.py
# Async SQLite persistence layer (Hybrid: Config + Robust Init)

import aiosqlite
import json
import logging
import os
import asyncio
from typing import List, Dict, Optional, Any

from core.config import get_config

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
        # Use config path
        self.db_path = str(config.storage.db_path)
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        
        self._initialized = False
        self._init_lock = asyncio.Lock()

    async def init(self):
        if self._initialized:
            return
            
        async with self._init_lock:
            if self._initialized:
                return
                
            async with aiosqlite.connect(self.db_path) as db:
                # Sessions Table (New)
                await db.execute("""
                    CREATE TABLE IF NOT EXISTS sessions (
                        id TEXT PRIMARY KEY,
                        target TEXT,
                        status TEXT,
                        start_time REAL,
                        end_time REAL,
                        logs TEXT
                    )
                """)
                
                # Findings (Updated with session_id)
                await db.execute("""
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
                
                # Issues (Updated with session_id)
                await db.execute("""
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
                
                # Evidence (New)
                await db.execute("""
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
                
                await db.commit()
            self._initialized = True

    async def save_session(self, session_data: Dict[str, Any]):
        if not self._initialized: await self.init()
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                INSERT OR REPLACE INTO sessions (id, target, status, start_time, logs)
                VALUES (?, ?, ?, ?, ?)
            """, (
                session_data["id"],
                session_data["target"],
                session_data["status"],
                session_data["start_time"],
                json.dumps(session_data.get("logs", []))
            ))
            await db.commit()

    async def save_finding(self, finding: Dict[str, Any], session_id: Optional[str] = None):
        if not self._initialized: await self.init()
        import hashlib
        blob = json.dumps(finding, sort_keys=True)
        fid = hashlib.sha256(blob.encode()).hexdigest()
        
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
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
            await db.commit()

    async def save_issue(self, issue: Dict[str, Any], session_id: Optional[str] = None):
        if not self._initialized: await self.init()
        iid = issue.get("id") or issue.get("title", "unknown")
        blob = json.dumps(issue)
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
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
            await db.commit()

    async def get_findings(self, session_id: Optional[str] = None) -> List[Dict]:
        if not self._initialized: await self.init()
        query = "SELECT data FROM findings WHERE session_id = ? ORDER BY timestamp DESC"
        params = (session_id,)
        if session_id is None:
            query = "SELECT data FROM findings ORDER BY timestamp DESC"
            params = ()
            
        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute(query, params) as cursor:
                rows = await cursor.fetchall()
                return [json.loads(row[0]) for row in rows]

    async def get_all_findings(self) -> List[Dict]:
        return await self.get_findings(None)

    async def get_issues(self, session_id: Optional[str] = None) -> List[Dict]:
        if not self._initialized: await self.init()
        query = "SELECT data FROM issues WHERE session_id = ? ORDER BY timestamp DESC"
        params = (session_id,)
        if session_id is None:
            query = "SELECT data FROM issues ORDER BY timestamp DESC"
            params = ()

        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute(query, params) as cursor:
                rows = await cursor.fetchall()
                return [json.loads(row[0]) for row in rows]

    async def get_all_issues(self) -> List[Dict]:
        return await self.get_issues(None)