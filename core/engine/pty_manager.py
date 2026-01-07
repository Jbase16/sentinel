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
from collections import deque
import asyncio

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
        
        # Buffer for output history (capped)
        # We store chunks of bytes. Readers join what they need.
        self.history: deque = deque(maxlen=1000) 
        self.write_counter: int = 0
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
                try:
                    if self.fd is None: break
                    r, w, x = select.select([self.fd], [], [], 1.0)
                except (ValueError, OSError):
                     # FD closed or invalid
                     break

                if not r:
                    # Check if process is still alive
                    if self._check_process_dead():
                        break
                    continue
                
                # FENCE: Verify we still own this FD
                # This prevents "Ghost Reader" attacks where we read from a recycled FD
                # belonging to a new session.
                # Lazy import to avoid circular dependency if any (usually safe with singleton)
                # But PTYSession is defined in same file as PTYManager... wait.
                # PTYManager is below PTYSession.
                # We need to access the singleton instance.
                # We can't import PTYManager here easily if it's not defined yet?
                # Actually they are in same file. PTYManager is defined AFTER PTYSession.
                # So we can use PTYManager.instance() inside the method, as PTYManager will be defined at runtime.
                try:
                    manager = PTYManager.instance()
                    if not manager.verify_fd_ownership(self.fd, self.session_id):
                        current_owner = manager._fd_registry.get(self.fd, "None")
                        logger.warning(
                            f"FD FAIL: Ghost Read prevented. "
                            f"Me={self.session_id} FD={self.fd} "
                            f"Owner={current_owner}"
                        )
                        break
                except NameError:
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
            
            # If client is ahead of us (impossible?), return nothing
            if offset >= total_written:
                return "", total_written
                
            # Calculate where the client's offset maps to in our current deque
            # Formula: deque_index = client_offset - (total_written - current_buffer_len)
            base_index = total_written - current_buffer_len
            deque_index = offset - base_index
            
            if deque_index < 0:
                # Client is asking for history we already dropped.
                # Give them everything we have effectively "resetting" them to the start of the window.
                deque_index = 0
            
            # Slice the deque from deque_index to end
            # Deque doesn't support slicing, so we iterate
            # Optimization: list(islice) would be better but simple list conversion is fine for 1000 items
            relevant_chunks = list(self.history)[deque_index:]
            
            raw_data = b"".join(relevant_chunks)
            new_offset = total_written # The client is now caught up to the end
            
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
        
        # 1. Close the Master FD (interrupts reader)
        if self.fd is not None:
            try:
                os.close(self.fd)
            except OSError:
                pass
            self.fd = None # Prevent double close
            
        # 2. Terminate Child Process
        try:
            os.kill(self.pid, 15)  # SIGTERM
            time.sleep(0.1)
            # Check if dead yet
            pid, status = os.waitpid(self.pid, os.WNOHANG)
            if pid == 0:
                # Still alive, force kill
                os.kill(self.pid, 9)   # SIGKILL
                # Blocking wait to ensure reaping (prevent zombie)
                os.waitpid(self.pid, 0)
        except OSError:
            pass # Process already dead/gone

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
        
        # FD Fencing Registry: map fd -> session_id
        # Prevents race conditions where an FD is recycled by OS and read by stale thread
        self._fd_registry: Dict[int, str] = {}
        self._registry_lock = threading.Lock()

    def verify_fd_ownership(self, fd: int, session_id: str) -> bool:
        """Threade-safe check if FD belongs to specific session."""
        with self._registry_lock:
            return self._fd_registry.get(fd) == session_id

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
            
            # Register FD ownership immediately
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
        
    def close_session(self, session_id: str):
        with self.sessions_lock:
            if session_id in self.sessions:
                session = self.sessions[session_id]
                fd_to_clear = session.fd
                
                # Close the session (closes FD)
                session.close()
                
                # Remove from session map
                del self.sessions[session_id]
                
                # Cleanup Registry
                if fd_to_clear is not None:
                     with self._registry_lock:
                         # Only delete if it still points to this session 
                         # (Extreme paranoia check, though lock prevents reuse)
                         if self._fd_registry.get(fd_to_clear) == session_id:
                             del self._fd_registry[fd_to_clear]

    async def cleanup_stale_sessions(self, max_age: float = 3600):
        """Close sessions inactive for longer than max_age."""
        now = time.time()
        to_remove = []
        
        with self.sessions_lock:
            for sid, session in self.sessions.items():
                if now - session.last_accessed > max_age:
                    to_remove.append(sid)
        
        if to_remove:
            logger.info(f"[PTYManager] Cleaning up {len(to_remove)} stale sessions: {to_remove}")
            for sid in to_remove:
                self.close_session(sid)
                
    async def start_cleanup_loop(self):
        """Background task to run cleanup periodically."""
        logger.info("[PTYManager] Cleanup loop started")
        while True:
            try:
                await asyncio.sleep(600) # Run every 10 minutes
                await self.cleanup_stale_sessions()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"[PTYManager] Cleanup loop error: {e}")
                await asyncio.sleep(60)

