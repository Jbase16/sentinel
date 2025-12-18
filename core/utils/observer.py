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

from typing import Any, Callable, List

class Signal:
    """
    A simple pure-Python signal implementation to replace PyQt6.pyqtSignal.
    """
    def __init__(self):
        """Function __init__."""
        self._observers: List[Callable[..., Any]] = []

    def connect(self, callback: Callable[..., Any]):
        """Subscribe a callback function."""
        # Conditional branch.
        if callback not in self._observers:
            self._observers.append(callback)

    def disconnect(self, callback: Callable[..., Any]):
        """Unsubscribe a callback function."""
        # Conditional branch.
        if callback in self._observers:
            self._observers.remove(callback)

    def emit(self, *args, **kwargs):
        """Notify all subscribers."""
        # Loop over items.
        for callback in self._observers:
            try:
                callback(*args, **kwargs)
            except Exception as e:
                # Prevent one subscriber from breaking the loop
                print(f"[Signal] Error in observer callback: {e}")

class Observable:
    """
    Base class for objects that emit signals.
    Replaces QObject for our purposes.
    """
    pass
