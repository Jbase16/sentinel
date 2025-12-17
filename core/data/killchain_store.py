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
    """
    
    edges_changed = Signal()

    def __init__(self, session_id: str = None):
        super().__init__()
        self._edges = []
        self.session_id = session_id

    def replace_all(self, edges: list):
        """Function replace_all."""
        self._edges = edges
        self.edges_changed.emit()

    def get_all(self):
        """Function get_all."""
        return list(self._edges)
    
    def add_phase(self, phase: dict):
        """Add a phase edge to the killchain."""
        self._edges.append(phase)
        self.edges_changed.emit()

# Singleton
killchain_store = KillchainStore()
