
import unittest
import time
import asyncio
from core.engine.pty_manager import PTYManager, PTYSession

class TestSessionSafety(unittest.IsolatedAsyncioTestCase):
    async def test_log_capping(self):
        """Verify that PTY session history is capped."""
        print("\n--- Testing Log Capping ---")
        session = PTYSession("test_cap", cmd=["/bin/echo", "hello"])
        
        # Inject synthetic history
        # We assume the implementation uses self.history as a deque or list that is capped
        # Implementation plan said deque(maxlen=1000)
        
        # Manually accessing history to check type/behavior
        # This depends on internal implementation details, which is fine for this verify script
        
        # Simulate massive output
        for i in range(2000):
            session.history.append(f"line {i}\n".encode())
            
        # Check size
        size = len(session.history)
        print(f"History size after 2000 appends: {size}")
        
        # Cleanup
        session.close()
        
        if size <= 1500: # Allow some buffer, but it should be close to maxlen (e.g. 1000)
            print("✅ History capped successfully.")
        else:
            self.fail(f"❌ History grew unbounded: {size}")

    async def test_session_cleanup(self):
        """Verify that inactive sessions are cleaned up."""
        print("\n--- Testing Session Cleanup ---")
        manager = PTYManager()
        
        # Create a session
        session_obj = manager.create_session()
        sid = session_obj.session_id
        print(f"Created session {sid}")
        
        # Mock the last_accessed time to be very old
        session = manager.get_session(sid)
        if session:
            # Set to 2 hours ago
            session.last_accessed = time.time() - 7200 
            print("Mocked session age to 2 hours old")
            
        # Trigger cleanup
        # We need to expose a way to trigger it or wait for the loop. 
        # For testing, calling the internal cleanup method is best if accessible, 
        # or we wait slightly if the interval is short (it isn't).
        # We will assume we add a public or internal method we can call.
        
        await manager.cleanup_stale_sessions()
        
        # Check if it's gone
        s = manager.get_session(sid)
        if s is None:
             print("✅ Session cleaned up successfully.")
        else:
             self.fail("❌ Session still exists after cleanup.")
             session.close()

if __name__ == '__main__':
    unittest.main()
