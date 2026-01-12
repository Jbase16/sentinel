"""
core/engine/pty_manager.py

Purpose:
    Manages pseudo-terminal (PTY) sessions for the web terminal interface.

    CRITICAL FEATURES:
    - Multi-Session: Supports multiple independent terminal instances.
    - Multiplexing: Allows multiple WebSockets to "watch" the same session (broadcast).
    - Threaded I/O: Decouples PTY blocking reads from the AsyncIO event loop to prevent server hangs.
    - Persistence: Sessions stay alive even if the websocket reconnects.

Safety:
    - Uses strict session IDs.
    - Cleans up zombie processes on session closure.
    - FD fencing prevents stale reader threads from reading recycled FDs.
    - Listener dispatch is async-safe (no "coroutine was never awaited" warnings).
"""

from __future__ import annotations

import asyncio
import fcntl
import logging
import os
import pty
import select
import struct
import termios
import threading
import time
import uuid
from collections import deque
from typing import Any, Callable, Deque, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


Listener = Callable[[bytes], Any]
ListenerEntry = Tuple[Listener, Optional[asyncio.AbstractEventLoop]]


class PTYSession:
    """
    Represents a single running terminal process (shell).

    State is maintained here:
    - The child process PID
    - The Master File Descriptor (fd) for I/O
    - The output buffer (history) for multiplexing
    - The listener registry for real-time output fanout
    """

    def __init__(self, session_id: str, cmd: Optional[List[str]] = None):
        self.session_id = session_id
        self.cmd = cmd or ["/bin/zsh"]
        self.created_at = time.time()
        self.last_accessed = time.time()

        # Buffer for output history (capped)
        # We store chunks of bytes. Readers join what they need.
        self.history: Deque[bytes] = deque(maxlen=1000)
        self.write_counter: int = 0
        self.history_lock = threading.Lock()

        # Listeners for real-time events (callback, loop)
        # loop is needed because output is produced from a background thread.
        self._listeners: List[ListenerEntry] = []
        self._listeners_lock = threading.Lock()

        self.running = True
        self.exit_code: Optional[int] = None

        # Fork the PTY
        # pid=0 children, pid>0 parent
        self.pid, self.fd = pty.fork()

        if self.pid == 0:
            # --- CHILD PROCESS ---
            os.environ["TERM"] = "xterm-256color"
            try:
                os.execlp(self.cmd[0], *self.cmd)
            except Exception as e:
                # Child context: keep it simple.
                print(f"Failed to exec: {e}")
                os._exit(1)
        else:
            # --- PARENT PROCESS ---
            logger.info(f"Started PTY Session {session_id} (PID: {self.pid})")

            # Optional: non-blocking mode (select already prevents blocking reads).
            # flags = fcntl.fcntl(self.fd, fcntl.F_GETFL)
            # fcntl.fcntl(self.fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)

            # Start the Reader Thread
            self.thread = threading.Thread(
                target=self._reader_loop,
                name=f"pty-reader-{session_id}",
                daemon=True,
            )
            self.thread.start()

    def _reader_loop(self) -> None:
        """
        Background thread that continuously reads from the PTY master fd.
        Appends data to history so multiple async clients can read it.
        """
        buf_size = 4096

        while self.running:
            try:
                # Use select to wait for data (blocking with timeout).
                try:
                    if self.fd is None:
                        break
                    r, _, _ = select.select([self.fd], [], [], 1.0)
                except (ValueError, OSError):
                    # FD closed or invalid
                    break

                if not r:
                    # Check if process is still alive
                    if self._check_process_dead():
                        break
                    continue

                # FENCE: Verify we still own this FD
                try:
                    manager = PTYManager.instance()
                    if not manager.verify_fd_ownership(self.fd, self.session_id):
                        current_owner = manager._fd_registry.get(self.fd, "None")
                        logger.warning(
                            "FD FAIL: Ghost Read prevented. "
                            f"Me={self.session_id} FD={self.fd} Owner={current_owner}"
                        )
                        break
                except NameError:
                    # PTYManager not defined yet (shouldn't happen in practice)
                    pass
                except Exception as e:
                    logger.error(f"Fence check error: {e}")
                    break

                # Read data
                try:
                    data = os.read(self.fd, buf_size)
                except OSError:
                    # Input/output error usually means the child closed
                    break

                if not data:
                    break

                # Store in history
                with self.history_lock:
                    self.history.append(data)
                    self.write_counter += 1

                # Notify listeners
                self._notify_listeners(data)

            except Exception as e:
                logger.error(f"Error in PTY reader loop {self.session_id}: {e}")
                break

        # Cleanup
        self.running = False
        logger.info(f"PTY Session {self.session_id} reader loop ended.")

    def _check_process_dead(self) -> bool:
        """Check if child process has exited."""
        try:
            pid, status = os.waitpid(self.pid, os.WNOHANG)
            if pid == self.pid:
                self.exit_code = os.WEXITSTATUS(status)
                return True
        except OSError:
            return True
        return False

    def read_from_offset(self, offset: int) -> Tuple[str, int]:
        """
        Return all new data since the given offset.
        Offset logic handles rolling buffer (deque) scenarios.
        """
        self.last_accessed = time.time()

        with self.history_lock:
            total_written = self.write_counter
            current_buffer_len = len(self.history)

            # If client is ahead of us (or exactly caught up), return nothing
            if offset >= total_written:
                return "", total_written

            # deque_index = client_offset - (total_written - current_buffer_len)
            base_index = total_written - current_buffer_len
            deque_index = offset - base_index

            if deque_index < 0:
                # Client asked for history we already dropped.
                deque_index = 0

            relevant_chunks = list(self.history)[deque_index:]
            raw_data = b"".join(relevant_chunks)
            new_offset = total_written

            try:
                text = raw_data.decode("utf-8", errors="replace")
                return text, new_offset
            except Exception:
                return "", offset

    def write(self, data: str) -> None:
        """Write input to the PTY (stdin of child)."""
        if not self.running or self.fd is None:
            return
        try:
            os.write(self.fd, data.encode("utf-8"))
        except OSError:
            pass

    def resize(self, rows: int, cols: int) -> None:
        """Resize the terminal window."""
        if not self.running or self.fd is None:
            return
        try:
            winsize = struct.pack("HHHH", rows, cols, 0, 0)
            fcntl.ioctl(self.fd, termios.TIOCSWINSZ, winsize)
        except Exception as e:
            logger.warning(f"Failed to resize PTY {self.session_id}: {e}")

    def _notify_listeners(self, data: bytes) -> None:
        """
        Notify all registered listeners about new data.

        NOTE: This method runs in the reader THREAD, not in the asyncio loop.
        Therefore, if a listener is async (returns a coroutine), we must schedule it
        onto an event loop using run_coroutine_threadsafe.
        """
        # Copy listeners under lock to avoid holding locks during callback execution.
        with self._listeners_lock:
            listeners = list(self._listeners)

        for callback, loop in listeners:
            try:
                result = callback(data)
                if asyncio.iscoroutine(result):
                    if loop is None:
                        # No loop associated -> cannot safely run the coroutine.
                        logger.error(
                            "[PTYSession] Async listener has no event loop; dropping output",
                            extra={"session_id": self.session_id},
                        )
                        continue
                    asyncio.run_coroutine_threadsafe(result, loop)
            except Exception as e:
                logger.error(f"[PTYSession] Listener error: {e}")

    def attach_listener(self, callback: Listener, loop: Optional[asyncio.AbstractEventLoop] = None) -> "PTYSession":
        """
        Register a listener to be called when new data arrives.

        Args:
            callback: Callable accepting bytes. May be sync or async.
            loop: Required for async callbacks since output arrives on a thread.

        Returns:
            self (for chaining)
        """
        with self._listeners_lock:
            self._listeners.append((callback, loop))
        return self

    def detach_listener(self, callback: Listener) -> None:
        """Remove a previously registered listener (all occurrences)."""
        with self._listeners_lock:
            self._listeners = [(cb, lp) for (cb, lp) in self._listeners if cb is not callback]

    def close(self) -> None:
        """Terminate the session and cleanup."""
        self.running = False

        # Clear listeners
        with self._listeners_lock:
            self._listeners.clear()

        # 1. Close the Master FD (interrupts reader)
        if self.fd is not None:
            try:
                os.close(self.fd)
            except OSError:
                pass
            self.fd = None  # Prevent double close

        # 2. Terminate Child Process
        try:
            os.kill(self.pid, 15)  # SIGTERM
            time.sleep(0.1)

            pid, _ = os.waitpid(self.pid, os.WNOHANG)
            if pid == 0:
                # Still alive, force kill
                os.kill(self.pid, 9)  # SIGKILL
                os.waitpid(self.pid, 0)  # Reap zombie
        except OSError:
            pass  # Process already dead/gone


class PTYManager:
    """
    Singleton manager for all active PTY sessions.
    """
    _instance: Optional["PTYManager"] = None
    _lock = threading.Lock()

    @classmethod
    def instance(cls) -> "PTYManager":
        if not cls._instance:
            with cls._lock:
                if not cls._instance:
                    cls._instance = cls()
        return cls._instance

    def __init__(self):
        self.sessions: Dict[str, PTYSession] = {}
        self.sessions_lock = threading.Lock()

        # FD Fencing Registry: map fd -> session_id
        # Prevents race conditions where an FD is recycled by OS and read by stale thread.
        self._fd_registry: Dict[int, str] = {}
        self._registry_lock = threading.Lock()

    def verify_fd_ownership(self, fd: int, session_id: str) -> bool:
        """Thread-safe check if FD belongs to a specific session."""
        with self._registry_lock:
            return self._fd_registry.get(fd) == session_id

    def create_session(self, session_id: Optional[str] = None) -> PTYSession:
        """Create a new session, optionally with a specific ID."""
        sid = session_id or str(uuid.uuid4())

        with self.sessions_lock:
            if sid in self.sessions:
                # Idempotent: return existing if running; otherwise recreate.
                if self.sessions[sid].running:
                    return self.sessions[sid]
                del self.sessions[sid]

            session = PTYSession(sid)
            self.sessions[sid] = session

            # Register FD ownership immediately
            if session.fd is not None:
                with self._registry_lock:
                    self._fd_registry[session.fd] = sid

            return session

    def get_session(self, session_id: str) -> Optional[PTYSession]:
        """Get an active session by ID."""
        with self.sessions_lock:
            return self.sessions.get(session_id)

    def get_or_create_session(self, session_id: str) -> PTYSession:
        """Convenience method."""
        session = self.get_session(session_id)
        if session:
            return session
        return self.create_session(session_id)

    def close_session(self, session_id: str) -> None:
        with self.sessions_lock:
            session = self.sessions.get(session_id)
            if not session:
                return

            fd_to_clear = session.fd

            # Close the session (closes FD)
            session.close()

            # Remove from session map
            del self.sessions[session_id]

            # Cleanup registry
            if fd_to_clear is not None:
                with self._registry_lock:
                    # Only delete if it still points to this session
                    if self._fd_registry.get(fd_to_clear) == session_id:
                        del self._fd_registry[fd_to_clear]

    async def cleanup_stale_sessions(self, max_age: float = 3600) -> None:
        """Close sessions inactive for longer than max_age."""
        now = time.time()
        to_remove: List[str] = []

        with self.sessions_lock:
            for sid, session in self.sessions.items():
                if now - session.last_accessed > max_age:
                    to_remove.append(sid)

        if to_remove:
            logger.info(f"[PTYManager] Cleaning up {len(to_remove)} stale sessions: {to_remove}")
            for sid in to_remove:
                self.close_session(sid)

    async def start_cleanup_loop(self) -> None:
        """Background task to run cleanup periodically."""
        logger.info("[PTYManager] Cleanup loop started")
        while True:
            try:
                await asyncio.sleep(600)  # Run every 10 minutes
                await self.cleanup_stale_sessions()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"[PTYManager] Cleanup loop error: {e}")
                await asyncio.sleep(60)

    def attach_listener(self, session_id: str, callback: Listener) -> PTYSession:
        """
        Attach a listener to a session.

        If called from an async context (e.g. a WebSocket handler), this captures
        the running loop so async callbacks can be scheduled safely from the reader thread.
        """
        session = self.get_session(session_id)
        if not session:
            raise KeyError(f"PTY session not found: {session_id}")

        loop: Optional[asyncio.AbstractEventLoop] = None
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        return session.attach_listener(callback, loop=loop)

    def detach_listener(self, session_id: str, callback: Listener) -> None:
        session = self.get_session(session_id)
        if not session:
            return
        session.detach_listener(callback)