# core/db.py — Async SQLite persistence layer

import aiosqlite
import json
import logging
import os
from typing import List, Dict, Optional, Any

logger = logging.getLogger(__name__)

DB_PATH = os.path.expanduser("~/.sentinelforge/data.db")

class Database:
    _instance = None

    @staticmethod
    def instance():
        if Database._instance is None:
            Database._instance = Database()
        return Database._instance

    def __init__(self):
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        self.db_path = DB_PATH

    async def init(self):
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                CREATE TABLE IF NOT EXISTS findings (
                    id TEXT PRIMARY KEY,
                    tool TEXT,
                    type TEXT,
                    severity TEXT,
                    target TEXT,
                    data JSON,
                    timestamp TEXT
                )
            """)
            await db.execute("""
                CREATE TABLE IF NOT EXISTS issues (
                    id TEXT PRIMARY KEY,
                    title TEXT,
                    severity TEXT,
                    target TEXT,
                    data JSON,
                    timestamp TEXT
                )
            """)
            await db.execute("""
                CREATE TABLE IF NOT EXISTS scan_history (
                    id TEXT PRIMARY KEY,
                    target TEXT,
                    status TEXT,
                    started_at TEXT,
                    finished_at TEXT,
                    summary JSON
                )
            """)
            await db.commit()

    async def save_finding(self, finding: Dict[str, Any]):
        # Deterministic ID based on content to prevent dupes
        import hashlib
        blob = json.dumps(finding, sort_keys=True)
        fid = hashlib.sha256(blob.encode()).hexdigest()
        
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                INSERT OR REPLACE INTO findings (id, tool, type, severity, target, data, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
            """, (
                fid,
                finding.get("tool", "unknown"),
                finding.get("type", "unknown"),
                finding.get("severity", "INFO"),
                finding.get("target", "unknown"),
                blob
            ))
            await db.commit()

    async def save_issue(self, issue: Dict[str, Any]):
        iid = issue.get("id") or issue.get("title", "unknown")
        blob = json.dumps(issue)
        
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                INSERT OR REPLACE INTO issues (id, title, severity, target, data, timestamp)
                VALUES (?, ?, ?, ?, ?, datetime('now'))
            """, (
                iid,
                issue.get("title", "unknown"),
                issue.get("severity", "INFO"),
                issue.get("target", "unknown"),
                blob
            ))
            await db.commit()

    async def get_all_findings(self) -> List[Dict]:
        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute("SELECT data FROM findings ORDER BY timestamp DESC") as cursor:
                rows = await cursor.fetchall()
                return [json.loads(row[0]) for row in rows]

    async def get_all_issues(self) -> List[Dict]:
        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute("SELECT data FROM issues ORDER BY timestamp DESC") as cursor:
                rows = await cursor.fetchall()
                return [json.loads(row[0]) for row in rows]
