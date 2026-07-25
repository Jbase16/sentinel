"""Module observer: inline documentation for /Users/jason/Developer/sentinelforge/core/utils/observer.py."""
#
# PURPOSE:
# This module is part of the utils package in SentinelForge.
# [Specific purpose based on module name: observer]
#
# KEY RESPONSIBILITIES:
# - [Automatically generated - review and enhance based on actual functionality]
#
# INTEGRATION:
# - Used by: [To be documented]
# - Depends on: [To be documented]
#

import logging
import threading
from typing import Any, Callable, List

_sig_logger = logging.getLogger(__name__)

class Signal:
    """
    A thread-safe pure-Python signal implementation to replace PyQt6.pyqtSignal.

    connect/disconnect/emit are guarded by a reentrant lock so signals can
    be safely wired and fired from different threads (e.g. AI thread vs
    async event loop).
    """
    def __init__(self):
        """Function __init__."""
        self._observers: List[Callable[..., Any]] = []
        self._lock = threading.RLock()

    def connect(self, callback: Callable[..., Any]):
        """Subscribe a callback function."""
        with self._lock:
            if callback not in self._observers:
                self._observers.append(callback)

    def disconnect(self, callback: Callable[..., Any]):
        """Unsubscribe a callback function."""
        with self._lock:
            if callback in self._observers:
                self._observers.remove(callback)

    def emit(self, *args, **kwargs):
        """Notify all subscribers (snapshot to avoid mutation during iteration)."""
        with self._lock:
            snapshot = list(self._observers)
        for callback in snapshot:
            try:
                callback(*args, **kwargs)
            except Exception as e:
                _sig_logger.warning("[Signal] Error in observer callback: %s", e, exc_info=True)

class Observable:
    """
    Base class for objects that emit signals.
    Replaces QObject for our purposes.
    """
    pass
