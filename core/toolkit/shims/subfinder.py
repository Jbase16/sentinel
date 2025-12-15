# ============================================================================
# core/toolkit/shims/subfinder.py
# Subfinder Module
# ============================================================================
#
# PURPOSE:
# This module is part of the shims package in SentinelForge.
# [Specific purpose based on module name: subfinder]
#
# KEY RESPONSIBILITIES:
# - [Automatically generated - review and enhance based on actual functionality]
#
# INTEGRATION:
# - Used by: [To be documented]
# - Depends on: [To be documented]
#
# ============================================================================

from ..tool_base import ToolBase

class Subfinder(ToolBase):
    def __init__(self):
        super().__init__("subfinder")

    def enumerate(self, domain: str):
        command = f"subfinder -silent -d {domain}"
        return self.run(command, metadata={"domain": domain, "type": "subdomain_enum"})