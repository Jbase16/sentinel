"""
Tests for PTY session cleanup — verifies zombie process reaping.

All OS calls (fork, close, kill, waitpid) are mocked to prevent
real process creation or signals.
"""

import os
import unittest
from unittest.mock import patch, call

_PTY = "core.engine.pty_manager"


class TestPTYCleanup(unittest.TestCase):

    def setUp(self):
        from core.engine.pty_manager import PTYManager
        PTYManager._instance = None

    def tearDown(self):
        from core.engine.pty_manager import PTYManager
        PTYManager._instance = None

    @patch(f"{_PTY}.threading.Thread")
    @patch(f"{_PTY}.time.sleep")
    @patch(f"{_PTY}.os.waitpid")
    @patch(f"{_PTY}.os.kill")
    @patch(f"{_PTY}.os.close")
    @patch(f"{_PTY}.pty.fork", return_value=(1234, 5678))
    def test_close_calls_waitpid(
        self, mock_fork, mock_close, mock_kill, mock_waitpid, mock_sleep, mock_thread
    ):
        # First waitpid (WNOHANG): child still alive → (0, 0)
        # Second waitpid (blocking): child reaped → (1234, 0)
        mock_waitpid.side_effect = [(0, 0), (1234, 0)]

        from core.engine.pty_manager import PTYSession
        session = PTYSession("test-session")

        session.close()

        # 1. FD closed
        mock_close.assert_called_with(5678)

        # 2. SIGTERM sent
        mock_kill.assert_any_call(1234, 15)

        # 3. First waitpid (WNOHANG) — check if child exited
        mock_waitpid.assert_any_call(1234, os.WNOHANG)

        # 4. SIGKILL sent (child was still alive after SIGTERM)
        mock_kill.assert_any_call(1234, 9)

        # 5. Final blocking waitpid to reap zombie
        mock_waitpid.assert_any_call(1234, 0)

    @patch(f"{_PTY}.threading.Thread")
    @patch(f"{_PTY}.time.sleep")
    @patch(f"{_PTY}.os.waitpid", return_value=(1234, 0))
    @patch(f"{_PTY}.os.kill")
    @patch(f"{_PTY}.os.close")
    @patch(f"{_PTY}.pty.fork", return_value=(1234, 5678))
    def test_close_handles_already_dead(
        self, mock_fork, mock_close, mock_kill, mock_waitpid, mock_sleep, mock_thread
    ):
        from core.engine.pty_manager import PTYSession
        session = PTYSession("test-session")

        session.close()

        # FD closed
        mock_close.assert_called_with(5678)

        # SIGTERM sent
        mock_kill.assert_called_with(1234, 15)

        # WNOHANG check — child already dead → (1234, 0)
        mock_waitpid.assert_called_with(1234, os.WNOHANG)

        # SIGKILL should NOT be called (child was already dead)
        kill_calls = mock_kill.call_args_list
        sigkill_calls = [c for c in kill_calls if c == call(1234, 9)]
        self.assertEqual(
            len(sigkill_calls), 0,
            "SIGKILL should not be sent when child is already dead"
        )


if __name__ == "__main__":
    unittest.main()
