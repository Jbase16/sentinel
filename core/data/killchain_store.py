"""Module killchain_store: inline documentation for /Users/jason/Developer/sentinelforge/core/data/killchain_store.py."""
#
# PURPOSE:
# Maps discovered findings to phases of the Cyber Kill Chain to understand
# attack progression potential. Shows "how far could an attacker get?"
#
# CYBER KILL CHAIN (LOCKHEED MARTIN):
# 1. **Reconnaissance**: Information gathering
# 2. **Weaponization**: Creating exploits
# 3. **Delivery**: Getting exploit to target
# 4. **Exploitation**: Triggering vulnerability
# 5. **Installation**: Installing backdoor/malware
# 6. **Command & Control**: Establishing remote control
# 7. **Actions on Objectives**: Data theft, destruction, etc.
#
# WHY KILL CHAIN MAPPING:
# - Prioritization: Later-stage vulns are more dangerous
# - Attack Paths: Shows how vulns chain together
# - Remediation Strategy: Block earliest stages first
# - Executive Reporting: Non-technical stakeholders understand progression
#
# EXAMPLE MAPPING:
# - Open port 22 → Reconnaissance
# - SSH with weak password → Exploitation
# - Root access gained → Installation
# - Reverse shell established → Command & Control
#

from core.utils.observer import Observable, Signal


class KillchainStore(Observable):
    """
    Tracks the MITRE Kill Chain phases triggered by discovered findings.
    Simple and extensible store used by TaskRouter and the UI.
    Can be instantiated for session-specific use or accessed as global singleton.

    Transactional Behavior:
    - When persist=False (transactional mode): only updates in-memory state
    - When persist=True (non-transactional): updates state and emits signals to UI
    - This prevents UI pollution during rolled-back scans
    """

    edges_changed = Signal()

    def __init__(self, session_id: str = None):
        """Function __init__."""
        super().__init__()
        self._edges = []
        self.session_id = session_id

    def replace_all(self, edges: list, persist: bool = True):
        """
        Replace all edges with new set.

        Args:
            edges: New list of killchain edges
            persist: If False, only update memory (transactional mode)
                     If True, update memory and notify UI subscribers
        """
        self._edges = edges
        if persist:
            self.edges_changed.emit()

    def get_all(self):
        """Function get_all."""
        return list(self._edges)

    def add_phase(self, phase: dict, persist: bool = True):
        """
        Add a phase edge to the killchain.

        Args:
            phase: Killchain phase edge dict
            persist: If False, only update memory (transactional mode)
                     If True, update memory and notify UI subscribers
        """
        self._edges.append(phase)
        if persist:
            self.edges_changed.emit()

    def clear(self, persist: bool = True):
        """
        Clear all edges (useful for rollback).

        Args:
            persist: If False, only update memory (transactional mode)
                     If True, update memory and notify UI subscribers
        """
        self._edges.clear()
        if persist:
            self.edges_changed.emit()

# Singleton
killchain_store = KillchainStore()
