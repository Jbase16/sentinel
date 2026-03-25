"""
Tests for PTY FD-fencing logic.

Verifies that the reader loop respects FD ownership and that
stale threads cannot read from recycled file descriptors.
"""

import unittest
from unittest.mock import patch, MagicMock

# All OS-level calls must be mocked to prevent real forks / signals.
_PTY = "core.engine.pty_manager"


class TestPTYFencing(unittest.TestCase):

    def setUp(self):
        # Reset the singleton so each test gets a clean PTYManager.
        from core.engine.pty_manager import PTYManager
        PTYManager._instance = None

    def tearDown(self):
        from core.engine.pty_manager import PTYManager
        PTYManager._instance = None

    @patch(f"{_PTY}.threading.Thread")
    @patch(f"{_PTY}.os.waitpid", return_value=(0, 0))
    @patch(f"{_PTY}.os.kill")
    @patch(f"{_PTY}.os.close")
    @patch(f"{_PTY}.pty.fork", return_value=(100, 5))
    def test_fence_check_terminates_ghost_reader(
        self, mock_fork, mock_close, mock_kill, mock_waitpid, mock_thread
    ):
        from core.engine.pty_manager import PTYManager

        manager = PTYManager.instance()
        session = manager.create_session("victim-session")

        # Ownership should be registered on creation
        self.assertTrue(manager.verify_fd_ownership(5, "victim-session"))

        # Simulate session close
        mock_waitpid.return_value = (100, 0)  # child reaped on first try
        manager.close_session("victim-session")

        # Ownership must be gone after close
        self.assertFalse(manager.verify_fd_ownership(5, "victim-session"))

    @patch(f"{_PTY}.threading.Thread")
    @patch(f"{_PTY}.os.waitpid", return_value=(0, 0))
    @patch(f"{_PTY}.os.kill")
    @patch(f"{_PTY}.os.close")
    @patch(f"{_PTY}.select.select", return_value=([5], [], []))
    @patch(f"{_PTY}.os.read", return_value=b"hello")
    @patch(f"{_PTY}.pty.fork", return_value=(100, 5))
    def test_reader_loop_respects_fence(
        self, mock_fork, mock_read, mock_select, mock_close, mock_kill, mock_waitpid, mock_thread
    ):
        """
        When verify_fd_ownership returns False, os.read must NOT be called.
        """
        from core.engine.pty_manager import PTYSession, PTYManager

        # Set up a manager where ownership check will fail
        manager = PTYManager.instance()

        with patch.object(manager, "verify_fd_ownership", return_value=False):
            session = PTYSession("ghost-session")
            session.fd = 5
            session.session_id = "ghost-session"

            # Run reader loop — it should break immediately due to fence failure
            session._reader_loop()

            # CRITICAL: os.read should NOT have been called
            mock_read.assert_not_called()

    @patch(f"{_PTY}.threading.Thread")
    @patch(f"{_PTY}.os.waitpid", return_value=(0, 0))
    @patch(f"{_PTY}.os.kill")
    @patch(f"{_PTY}.os.close")
    @patch(f"{_PTY}.select.select", return_value=([5], [], []))
    @patch(f"{_PTY}.os.read", return_value=b"data")
    @patch(f"{_PTY}.pty.fork", return_value=(100, 5))
    def test_reader_loop_abort(
        self, mock_fork, mock_read, mock_select, mock_close, mock_kill, mock_waitpid, mock_thread
    ):
        from core.engine.pty_manager import PTYSession, PTYManager

        manager = PTYManager.instance()

        with patch.object(manager, "verify_fd_ownership", return_value=False):
            session = PTYSession("test-id")
            session.fd = 5
            session.session_id = "test-id"

            session._reader_loop()

            manager.verify_fd_ownership.assert_called_with(5, "test-id")
            # os.read should NOT be called because ownership check failed
            mock_read.assert_not_called()


if __name__ == "__main__":
    unittest.main()
