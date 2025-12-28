"""
Project OMEGA - Integration Manager (Module)

This file is kept as a placeholder. The main implementation is in __init__.py
to maintain consistency with the other modules.

For integration:
- Import with: from core.omega import OmegaManager, OmegaConfig, OmegaResult
- Create with: manager = create_omega_manager()
- Run with: result = await manager.run(config)
"""

# Re-export from __init__ for convenience
from core.omega import (
    OmegaManager,
    OmegaConfig,
    OmegaResult,
    OmegaPhase,
    create_omega_manager,
    SAFE_MODE,
)

__all__ = [
    "OmegaManager",
    "OmegaConfig",
    "OmegaResult",
    "OmegaPhase",
    "create_omega_manager",
    "SAFE_MODE",
]
