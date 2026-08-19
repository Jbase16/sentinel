
import unittest
import asyncio
import tempfile
import os
import shutil
from unittest.mock import patch, MagicMock
from core.data.db import Database

class TestDBConcurrency(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        # Create unique temp db for this test
        self.test_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.test_dir, "test.db")
        
        # Patch config to point to temp db
        self.config_patcher = patch("core.data.db.get_config")
        self.mock_config_fn = self.config_patcher.start()
        
        # Configure the MOCKED CONFIG OBJECT (returned by get_config())
        self.mock_config_obj = MagicMock()
        self.mock_config_obj.storage.db_path = self.db_path
        self.mock_config_fn.return_value = self.mock_config_obj
        
        # Patch BlackBox to avoid loop binding issues
        self.blackbox_patcher = patch("core.data.blackbox.BlackBox")
        self.mock_blackbox_cls = self.blackbox_patcher.start()
        self.mock_blackbox = self.mock_blackbox_cls.instance.return_value
        
        # Reset Database singleton - CRITICAL for test isolation
        Database._instance = None

    async def asyncTearDown(self):
        if Database._instance:
            await Database._instance.close()
        self.config_patcher.stop()
        self.blackbox_patcher.stop()
        shutil.rmtree(self.test_dir)

    async def test_concurrent_init(self):
        """Verify 50 concurrent init calls don't crash or corrupt DB."""
        db = Database.instance()
        
        async def try_init():
            await db.init()
            return True

        # Spawn 50 tasks
        tasks = [asyncio.create_task(try_init()) for _ in range(50)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Verify no exceptions
        for res in results:
            if isinstance(res, Exception):
                raise res
        
        self.assertTrue(db._initialized)
        self.assertTrue(os.path.exists(self.db_path))
        
        # Verify basic query works after storm
        rows = await db.fetch_all("SELECT 1")
        self.assertEqual(rows[0][0], 1)

    async def test_atomic_transaction_rollback(self):
        """Verify transaction rollback prevents partial writes."""
        db = Database.instance()
        await db.init()
        
        # 1. Start a transaction manually (or simulate one)
        # Since Database doesn't expose explicit transaction context manager easily,
        # we can verify atomicity by creating a function that fails mid-way.
        # But Database methods like save_finding are fire-and-forget in BlackBox by default.
        # We need to test the underlying connection's transaction behavior.
        
        async with db._db_lock:
             try:
                 async with db._db_connection.execute("BEGIN TRANSACTION") as cursor:
                     # A. Valid Write
                     await db._db_connection.execute(
                         "INSERT INTO system_state (key, value) VALUES (?, ?)", 
                         ("audit_test", 100)
                     )
                     
                     # B. Error
                     raise RuntimeError("Simulated Crash")
                     
                     # C. Commit (Unreachable)
                     await db._db_connection.commit()
             except RuntimeError:
                 await db._db_connection.rollback()
                 
        # Verify "audit_test" was NOT written
        val = await db.fetch_all("SELECT value FROM system_state WHERE key = ?", ("audit_test",))
        self.assertEqual(len(val), 0, "Partial write detected! Rollback failed.")

    async def test_writes_require_an_explicit_non_global_session(self):
        db = Database.instance()
        await db.init()

        global_rows = await db.fetch_all(
            "SELECT id FROM sessions WHERE id = ?",
            ("global_scan",),
        )
        self.assertEqual(global_rows, [])

        with self.assertRaisesRegex(ValueError, "explicit session_id"):
            db.save_finding({}, None)
        with self.assertRaisesRegex(ValueError, "explicit session_id"):
            db.save_issue({}, "")
        with self.assertRaisesRegex(ValueError, "forbid.*global_scan"):
            db.save_evidence({}, "global_scan")

        with self.assertRaisesRegex(ValueError, "explicit session_id"):
            await db.save_finding_txn({}, None, conn=db._db_connection)
        with self.assertRaisesRegex(ValueError, "explicit session_id"):
            await db.save_issue_txn({}, "", conn=db._db_connection)
        with self.assertRaisesRegex(ValueError, "forbid.*global_scan"):
            await db.save_evidence_txn(
                {},
                "global_scan",
                conn=db._db_connection,
            )

        session_id = "explicit-session"
        await db._save_session_impl({
            "id": session_id,
            "target": "https://owned.example.test",
            "status": "active",
            "start_time": "2026-08-18T00:00:00Z",
            "logs": [],
        })
        await db.save_finding_txn(
            {"tool": "test", "target": "owned.example.test"},
            session_id,
            conn=db._db_connection,
        )
        await db.save_issue_txn(
            {"title": "test", "target": "owned.example.test"},
            session_id,
            conn=db._db_connection,
        )
        await db.save_evidence_txn(
            {"tool": "test", "raw_output": "local fixture"},
            session_id,
            conn=db._db_connection,
        )

        for table in ("findings", "issues", "evidence"):
            rows = await db.fetch_all(
                f"SELECT DISTINCT session_id FROM {table}",
            )
            self.assertEqual(rows, [(session_id,)])

if __name__ == '__main__':
    unittest.main()
