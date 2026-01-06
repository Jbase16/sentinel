
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

if __name__ == '__main__':
    unittest.main()
