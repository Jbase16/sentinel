"""Module nmap: inline documentation for /Users/jason/Developer/sentinelforge/core/toolkit/shims/nmap.py."""
#
# PURPOSE:
# This module is part of the shims package in SentinelForge.
# [Specific purpose based on module name: nmap]
#
# KEY RESPONSIBILITIES:
# - [Automatically generated - review and enhance based on actual functionality]
#
# INTEGRATION:
# - Used by: [To be documented]
# - Depends on: [To be documented]
#

from ..tool_base import ToolBase

class NmapScan(ToolBase):
    """Class NmapScan."""
    def __init__(self):
        super().__init__("nmap")

    def scan_basic(self, target: str):
        """Function scan_basic."""
        command = f"nmap -sV -T4 {target}"
        return self.run(command, metadata={"target": target, "type": "basic_scan"})