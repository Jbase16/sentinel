"""
core/engine/pty_manager.py

Purpose:
    Manages pseudo-terminal (PTY) sessions for the web terminal interface.
    
    CRITICAL FEATURES:
    - Multi-Session: Supports multiple independent terminal instances.
    - Multiplexing: Allows multiple Websockets to "watch" the same session (broadcast).
    - Threaded I/O: Decouples PTY blocking reads from the AsyncIO event loop to prevent server hangs.
    - Persistence: Sessions stay alive even if the websocket reconnects.

Safety:
    - Uses strict session IDs.
    - Cleans up zombie processes on session closure.
"""

import os
import pty
import fcntl
import termios
import struct
import threading
import time
import uuid
import logging
import select
from typing import Dict, Optional, Tuple, List

logger = logging.getLogger(__name__)

class PTYSession:
    """
    Represents a single running terminal process (shell).
    
    State is maintained here:
    - The child process PID
    - The Master File Descriptor (fd) for I/O
    - The output buffer (history) for multiplexing
    """
    
    def __init__(self, session_id: str, cmd: List[str] = ["/bin/zsh"]):
        self.session_id = session_id
        self.cmd = cmd
        self.created_at = time.time()
        self.last_accessed = time.time()
        
        # Buffer for output history
        # We store chunks of bytes. Readers join what they need.
        self.history: List[bytes] = [] 
        self.history_lock = threading.Lock()
        
        self.running = True
        self.exit_code: Optional[int] = None
        
        # Fork the PTY
        # pid=0 children, pid>0 parent
        self.pid, self.fd = pty.fork()
        
        if self.pid == 0:
            # --- CHILD PROCESS ---
            # Set environment variables if needed
            os.environ["TERM"] = "xterm-256color"
            try:
                os.execlp(cmd[0], *cmd)
            except Exception as e:
                print(f"Failed to exec: {e}")
                os._exit(1)
        else:
            # --- PARENT PROCESS ---
            logger.info(f"Started PTY Session {session_id} (PID: {self.pid})")
            
            # Set non-blocking mode on the master fd just in case,
            # though we use select/threads to manage it.
            # flags = fcntl.fcntl(self.fd, fcntl.F_GETFL)
            # fcntl.fcntl(self.fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)
            
            # Start the Reader Thread
            self.thread = threading.Thread(
                target=self._reader_loop, 
                name=f"pty-reader-{session_id}",
                daemon=True
            )
            self.thread.start()

    def _reader_loop(self):
        """
        Background thread that continuously reads from the PTY master fd.
        It appends data to self.history so multiple async clients can read it.
        """
        buf_size = 4096
        while self.running:
            try:
                # Use select to wait for data (blocking with timeout)
                # This prevents busy-waiting
                r, w, x = select.select([self.fd], [], [], 1.0)
                if not r:
                    # Check if process is still alive
                    if self._check_process_dead():
                        break
                    continue
                
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
        
        Returns:
            (data_str, new_offset)
        """
        self.last_accessed = time.time()
        with self.history_lock:
            current_len = len(self.history)
            
            if offset >= current_len:
                return "", current_len
            
            # Join all chunks from offset to end
            # This reconstructs the stream cleanly
            raw_data = b"".join(self.history[offset:])
            new_offset = current_len
            
            # Decode safely
            try:
                text = raw_data.decode("utf-8", errors="replace")
                return text, new_offset
            except Exception:
                return "", offset

    def write(self, data: str):
        """Write input to the PTY (stdin of child)."""
        if not self.running:
            return
            
        try:
            # Convert to bytes
            b_data = data.encode("utf-8")
            os.write(self.fd, b_data)
        except OSError:
            pass

    def resize(self, rows: int, cols: int):
        """Resize the terminal window."""
        if not self.running:
            return
        
        try:
            # TIOCSWINSZ struct: rows, cols, xpixels, ypixels
            winsize = struct.pack("HHHH", rows, cols, 0, 0)
            fcntl.ioctl(self.fd, termios.TIOCSWINSZ, winsize)
        except Exception as e:
            logger.warning(f"Failed to resize PTY {self.session_id}: {e}")

    def close(self):
        """Terminate the session and cleanup."""
        self.running = False
        try:
            os.close(self.fd)
        except OSError:
            pass
            
        try:
            os.kill(self.pid, 15)  # SIGTERM
            time.sleep(0.1)
            os.kill(self.pid, 9)   # SIGKILL
        except OSError:
            pass

class PTYManager:
    """
    Singleton manager for all active PTY sessions.
    """
    _instance = None
    _lock = threading.Lock()
    
    @classmethod
    def instance(cls):
        if not cls._instance:
            with cls._lock:
                if not cls._instance:
                    cls._instance = cls()
        return cls._instance

    def __init__(self):
        self.sessions: Dict[str, PTYSession] = {}
        self.sessions_lock = threading.Lock()

    def create_session(self, session_id: Optional[str] = None) -> PTYSession:
        """Create a new session, optionally with a specific ID."""
        sid = session_id or str(uuid.uuid4())
        
        with self.sessions_lock:
            if sid in self.sessions:
                # If it already exists and is running, return it?
                # Or error? Let's return existing to be safe/idempotent.
                if self.sessions[sid].running:
                    return self.sessions[sid]
                else:
                    # Clean up dead session before recreating
                    del self.sessions[sid]
            
            session = PTYSession(sid)
            self.sessions[sid] = session
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
        
    def close_session(self, session_id: str):
        with self.sessions_lock:
            if session_id in self.sessions:
                self.sessions[session_id].close()
                del self.sessions[session_id]

