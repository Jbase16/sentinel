import unittest
from unittest.mock import patch, MagicMock
import os
import time
from core.engine.pty_manager import PTYSession

class TestPTYCleanup(unittest.TestCase):
    
    @patch("core.engine.pty_manager.pty.fork")
    @patch("core.engine.pty_manager.os.close")
    @patch("core.engine.pty_manager.os.kill")
    @patch("core.engine.pty_manager.os.waitpid")
    @patch("threading.Thread") # Prevent reader thread from starting
    def test_close_calls_waitpid(self, mock_thread, mock_waitpid, mock_kill, mock_close, mock_fork):
        # Setup
        mock_fork.return_value = (1234, 5678) # pid, fd
        # Mock waitpid to simulate child still alive initially, then reaped
        # First call: (0, 0) -> WNOHANG, child alive
        # Second call: (1234, 0) -> Blocking wait, child reaped
        mock_waitpid.side_effect = [(0, 0), (1234, 0)]
        
        session = PTYSession("test-session")
        
        # Action
        session.close()
        
        # Verification
        # 1. FD closed
        mock_close.assert_called_with(5678)
        
        # 2. SIGTERM sent
        mock_kill.assert_any_call(1234, 15)
        
        # 3. First waitpid (WNOHANG)
        mock_waitpid.assert_any_call(1234, os.WNOHANG)
        
        # 4. SIGKILL sent (because we returned 0,0 implying alive)
        mock_kill.assert_any_call(1234, 9)
        
        # 5. Final blocking waitpid (Critical Fix Verification)
        mock_waitpid.assert_any_call(1234, 0)

    @patch("core.engine.pty_manager.pty.fork")
    @patch("core.engine.pty_manager.os.close")
    @patch("core.engine.pty_manager.os.kill")
    @patch("core.engine.pty_manager.os.waitpid")
    @patch("threading.Thread")
    def test_close_handles_already_dead(self, mock_thread, mock_waitpid, mock_kill, mock_close, mock_fork):
        # Setup
        mock_fork.return_value = (1234, 5678)
        # Mock waitpid to simulate child already dead on first check
        mock_waitpid.return_value = (1234, 0)
        
        session = PTYSession("test-session")
        
        # Action
        session.close()
        
        # Verification
        mock_close.assert_called_with(5678)
        mock_kill.assert_called_with(1234, 15)
        # Should call WNOHANG check
        mock_waitpid.assert_called_with(1234, os.WNOHANG)
        # Should NOT call SIGKILL or blocking waitpid
        with self.assertRaises(AssertionError):
             mock_kill.assert_any_call(1234, 9)

if __name__ == '__main__':
    unittest.main()
