# core/pty_manager.py
# Manages pseudo-terminal (PTY) sessions for the web terminal.

import os
import pty
import select
import subprocess
import struct
import fcntl
import termios
import asyncio
import logging
from typing import Dict, Optional

logger = logging.getLogger(__name__)

class PTYSession:
    def __init__(self, command: list[str] = ["/bin/zsh"]):
        self.command = command
        self.fd = None
        self.pid = None
        self.process = None
        self.history = b""

    def start(self):
        # Create PTY
        self.pid, self.fd = pty.fork()
        
        if self.pid == 0:
            # Child process
            os.execv(self.command[0], self.command)
        else:
            # Parent process
            # Set non-blocking
            fl = fcntl.fcntl(self.fd, fcntl.F_GETFL)
            fcntl.fcntl(self.fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)
            logger.info(f"PTY started. PID: {self.pid}, FD: {self.fd}")

    def read(self) -> bytes:
        if not self.fd: return b""
        try:
            data = os.read(self.fd, 1024)
            self.history += data
            return data
        except OSError:
            return b""

    def write(self, data: str):
        if not self.fd: return
        os.write(self.fd, data.encode())

    def resize(self, rows: int, cols: int):
        if not self.fd: return
        winsize = struct.pack("HHHH", rows, cols, 0, 0)
        fcntl.ioctl(self.fd, termios.TIOCSWINSZ, winsize)

    def close(self):
        if self.fd:
            os.close(self.fd)
            self.fd = None
        if self.pid:
            # Kill process group
            try:
                os.kill(self.pid, 9)
            except:
                pass
            self.pid = None

class PTYManager:
    _instance = None
    
    @staticmethod
    def instance():
        if PTYManager._instance is None:
            PTYManager._instance = PTYManager()
        return PTYManager._instance

    def __init__(self):
        self.session: Optional[PTYSession] = None

    def get_session(self) -> PTYSession:
        if not self.session or not self.session.fd:
            self.session = PTYSession()
            self.session.start()
        return self.session
