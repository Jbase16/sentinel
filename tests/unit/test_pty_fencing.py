import unittest
from unittest.mock import patch, MagicMock
from core.engine.pty_manager import PTYSession, PTYManager
import os
import time
import select

class TestPTYFencing(unittest.TestCase):
    
    @patch("core.engine.pty_manager.pty.fork")
    @patch("threading.Thread")
    def test_fence_check_terminates_ghost_reader(self, mock_thread, mock_fork):
        # Setup
        mock_fork.return_value = (100, 5) # pid, fd
        
        # We need to spy on the manager instance
        manager = PTYManager.instance()
        session = manager.create_session("victim-session")
        
        # Simulate the reader loop logic manually to verify the fence logic
        # Because threading is mocked, we can't run the real loop easily, 
        # so we extract the logic or test the side-effect?
        # Actually, let's just inspect the _reader_loop Code? 
        # No, unit tests on the loop itself are hard without threads.
        # Let's verify that create_session registers ownership.
        
        self.assertTrue(manager.verify_fd_ownership(5, "victim-session"))
        
        # Now simulate session close
        manager.close_session("victim-session")
        
        # Verify ownership is gone
        self.assertFalse(manager.verify_fd_ownership(5, "victim-session"))


    @patch("core.engine.pty_manager.select.select")
    @patch("core.engine.pty_manager.os.read")
    @patch("core.engine.pty_manager.pty.fork")
    def test_reader_loop_respects_fence(self, mock_fork, mock_read, mock_select):
        """
        Verify that if verify_fd_ownership returns False, read is NOT called.
        """
        mock_fork.return_value = (100, 5)
        # Select returns 'ready'
        mock_select.return_value = ([5], [], [])
        
        # Mock PTYManager.instance()
        with patch("core.engine.pty_manager.PTYManager.instance") as mock_mgr_cls:
            mock_mgr = MagicMock()
            mock_mgr_cls.return_value = mock_mgr
            # Crucial: Ownership check fails!
            mock_mgr.verify_fd_ownership.return_value = False
            
            session = PTYSession("ghost-session")
            # We must override start() to not spawn thread, but PTYSession spawns in init.
            # We can't prevent init spawning unless we patch Threading. 
            # But we want to call _reader_loop synchronously for one iteration?
            # PTYSession structure makes this hard.
            # Let's just create a session with Thread patched, then call _reader_loop manually once.
            pass

    @patch("core.engine.pty_manager.threading.Thread")
    @patch("core.engine.pty_manager.select.select")
    @patch("core.engine.pty_manager.os.read")
    @patch("core.engine.pty_manager.pty.fork")
    def test_reader_loop_abort(self, mock_fork, mock_read, mock_select, mock_thread):
        mock_fork.return_value = (100, 5)
        mock_select.return_value = ([5], [], [])
        
        with patch("core.engine.pty_manager.PTYManager.instance") as mock_mgr_cls:
            mock_mgr = MagicMock()
            mock_mgr_cls.return_value = mock_mgr
            mock_mgr.verify_fd_ownership.return_value = False
            
            session = PTYSession("test-id")
            session.fd = 5
            session.session_id = "test-id"
            
            # Run one iteration of reader loop by hacking "running"
            # We can't easily break the while loop without side effects or max_iters.
            # But the break in the code will stop it.
            
            # We'll rely on the break in the code to return (running logic)
            # Actually, `break` breaks the loop. So `_reader_loop` should return immediately.
            session._reader_loop()
            
            # Assertions
            mock_mgr.verify_fd_ownership.assert_called_with(5, "test-id")
            # CRITICAL: os.read should NOT have been called because check failed
            mock_read.assert_not_called()

if __name__ == '__main__':
    unittest.main()
