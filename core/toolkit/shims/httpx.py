"""Module httpx: inline documentation for /Users/jason/Developer/sentinelforge/core/toolkit/shims/httpx.py."""
#
# PURPOSE:
# This module is part of the shims package in SentinelForge.
# [Specific purpose based on module name: httpx]
#
# KEY RESPONSIBILITIES:
# - [Automatically generated - review and enhance based on actual functionality]
#
# INTEGRATION:
# - Used by: [To be documented]
# - Depends on: [To be documented]
#

from ..tool_base import ToolBase

class Httpx(ToolBase):
    """Class Httpx."""
    def __init__(self):
        super().__init__("httpx")

    def probe(self, input_file: str):
        """Function probe."""
        command = f"httpx -silent -l {input_file}"
        return self.run(command, metadata={"input_file": input_file, "type": "http_probe"})