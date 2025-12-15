# ============================================================================
# core/toolkit/tools.py
# TOOL REGISTRY & INSTALLATION SYSTEM - FACADE MODULE
# ============================================================================
#
# This module has been refactored. The actual logic is now in:
# - normalizer.py: Target normalization functions
# - registry.py: Tool definitions (TOOLS dict)
# - installer.py: Async installation/uninstallation
#
# This file re-exports everything for backward compatibility.
# ============================================================================

import shutil
import os
import sys
import glob
from pathlib import Path
from typing import Dict, List

# ============================================================================
# PATH SETUP - Ensure tools can be found
# ============================================================================

_EXTRA_PATHS = [
    os.path.expanduser("~/go/bin"),
    os.path.expanduser("~/.local/bin"),
    "/opt/homebrew/bin",
    "/usr/local/bin",
]

# Add venv bin if running inside one
if hasattr(sys, 'prefix') and hasattr(sys, 'base_prefix') and sys.prefix != sys.base_prefix:
    venv_bin = os.path.join(sys.prefix, 'bin')
    if os.path.exists(venv_bin):
        _EXTRA_PATHS.insert(0, venv_bin)

# Check for .venv in project root
_project_root = Path(__file__).resolve().parents[2]
for venv_name in ['.venv', 'venv']:
    venv_bin = _project_root / venv_name / 'bin'
    if venv_bin.exists() and str(venv_bin) not in _EXTRA_PATHS:
        _EXTRA_PATHS.insert(0, str(venv_bin))

# Add Python user bin paths
for p in glob.glob(os.path.expanduser("~/Library/Python/*/bin")):
    _EXTRA_PATHS.append(p)

# Append paths to system PATH
for p in _EXTRA_PATHS:
    if p not in os.environ["PATH"]:
        os.environ["PATH"] += os.pathsep + p


# ============================================================================
# RE-EXPORTS from submodules (for backward compatibility)
# ============================================================================

# From normalizer.py
from core.toolkit.normalizer import (
    ensure_url as _ensure_url,
    extract_host as _extract_host,
    extract_domain as _extract_domain,
    extract_ip as _extract_ip,
    normalize_target as _normalize_target,
)

# From registry.py
from core.toolkit.registry import (
    TOOLS,
    COMMON_WORDLIST,
    get_wordlist_path as _wordlist_path,
    get_tool_command,
)

# From installer.py
from core.toolkit.installer import (
    INSTALLERS,
    install_tool,
    install_tools,
    uninstall_tool,
    uninstall_tools,
)


# ============================================================================
# PUBLIC API - Used by the scanner and API server
# ============================================================================

def get_installed_tools() -> Dict[str, Dict]:
    """
    Return only tools that are genuinely installed in PATH.
    """
    installed = {}
    for name, tdef in TOOLS.items():
        cmd = tdef["cmd"]
        exe = tdef.get("binary") or cmd[0]
        if shutil.which(exe):
            installed[name] = tdef
    return installed


# ============================================================================
# CALLBACK PLUMBING - Integration with TaskRouter
# ============================================================================

from core.base.task_router import TaskRouter


def tool_callback_factory(tool_name: str):
    """
    Create a callback function for a specific tool.
    """
    def callback(stdout, stderr, rc, metadata):
        TaskRouter.instance().handle_tool_output(
            tool_name=tool_name,
            stdout=stdout,
            stderr=stderr,
            rc=rc,
            metadata=metadata
        )
    return callback
