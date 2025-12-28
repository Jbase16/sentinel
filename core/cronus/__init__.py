"""
Project CRONUS - The Archaeologist

Temporal mining for security assessment. This module discovers "zombie" endpoints -
deprecated routes that have been removed from public facing documentation but may still
be active on backend servers.

THREAT MODEL (Defensive Framing):
This module helps organizations identify:
1. Forgotten attack surfaces from old API versions
2. Deprecated endpoints that weren't properly disabled
3. Configuration drift between documentation and implementation

SAFETY CONSTRAINTS:
- All queries are read-only (no modification of historical archives)
- Rate limiting enforced to avoid archive service disruption
- Results are for authorized security assessments only

INTEGRATION POINTS:
- EventBus: Emits CRONUS_QUERY events for observability
- DecisionLedger: Logs temporal mining decisions
- KnowledgeGraph: Stores zombie endpoint relationships
"""

from core.cronus.time_machine import (
    TimeMachine,
    SnapshotQuery,
    SnapshotResult,
    ArchiveSource,
    SAFE_MODE,
    create_time_machine,
)
from core.cronus.differ import (
    SitemapDiffer,
    DiffReport,
    Endpoint,
    EndpointStatus,
    create_sitemap_differ,
)
from core.cronus.hunter import (
    ZombieHunter,
    ZombieProbe,
    ZombieReport,
    ActiveStatus,
    create_zombie_hunter,
)

# Export SAFE_MODE from time_machine as the module-level constant
SAFE_MODE = SAFE_MODE

# Aliases for shorter factory function names (convenience)
create_differ = create_sitemap_differ
create_hunter = create_zombie_hunter

__all__ = [
    # Time Machine
    "TimeMachine",
    "SnapshotQuery",
    "SnapshotResult",
    "ArchiveSource",
    # Differ
    "SitemapDiffer",
    "DiffReport",
    "Endpoint",
    "EndpointStatus",
    # Hunter
    "ZombieHunter",
    "ZombieProbe",
    "ZombieReport",
    "ActiveStatus",
    # Factory Functions
    "create_time_machine",
    "create_sitemap_differ",
    "create_zombie_hunter",
    "create_differ",  # alias
    "create_hunter",  # alias
    # Safety
    "SAFE_MODE",
]
