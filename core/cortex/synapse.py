"""Module synapse: inline documentation for /Users/jason/Developer/sentinelforge/core/cortex/synapse.py."""
#
# PURPOSE:
# Placeholder for future Cortex ↔ Strategos coordination.
# Currently unused, but required by WraithEngine imports.
#

class Synapse:
    """
    Temporary stub.
    Real coordination is currently handled by:
    - DecisionContext
    - EventBus
    - ArbitrationEngine
    - NarratorEngine
    """
    _instance = None

    @classmethod
    def instance(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

