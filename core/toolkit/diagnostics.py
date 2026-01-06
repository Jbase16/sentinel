import shutil
import logging
from typing import Dict, List, Optional
from pydantic import BaseModel
from core.toolkit.registry import TOOLS, find_binary
from core.toolkit.installer import INSTALLERS

logger = logging.getLogger(__name__)

class DiagnosticIssue(BaseModel):
    tool_name: str
    issue_type: str = "missing_binary" # missing_binary, version_mismatch
    message: str
    install_hint: Optional[str] = None

def get_install_hint(tool_name: str) -> str:
    """Generate a helpful install hint for a missing tool."""
    spec = INSTALLERS.get(tool_name)
    if not spec:
        return f"Please install '{tool_name}' manually (no installer defined)."
    
    strategies = spec.get("strategies", [])
    if not strategies:
         return f"Please install '{tool_name}' manually."
         
    # Return the first strategy's command as a hint string
    cmd_parts = strategies[0]["cmd"]
    return " ".join(cmd_parts)

def check_missing_tools(required_tools: List[str] = None) -> List[DiagnosticIssue]:
    """
    Check for missing binaries and return actionable diagnostics.
    If required_tools is None, checks ALL registered tools.
    """
    issues = []
    
    # If no specific tools requested, check all in registry
    tools_to_check = required_tools if required_tools else list(TOOLS.keys())
    
    for name in tools_to_check:
        tool_def = TOOLS.get(name)
        if not tool_def:
            continue
            
        binary = tool_def.binary_name or tool_def.cmd_template[0]
        
        if not find_binary(binary):
            hint = get_install_hint(name)
            issues.append(DiagnosticIssue(
                tool_name=name,
                message=f"Binary '{binary}' not found in PATH or .venv",
                install_hint=hint
            ))
            
    return issues
