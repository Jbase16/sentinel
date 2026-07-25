"""Module check_tools: inline documentation for /Users/jason/Developer/sentinelforge/tests/verification/check_tools.py."""
#
# PURPOSE:
# This module is part of the verification package in SentinelForge.
# [Specific purpose based on module name: check_tools]
#
# KEY RESPONSIBILITIES:
# - [Automatically generated - review and enhance based on actual functionality]
#
# INTEGRATION:
# - Used by: [To be documented]
# - Depends on: [To be documented]
#

import shutil
import os

TOOLS = ["nmap", "httpx", "subfinder", "ollama"]

print("--- Checking Tool Availability ---")
for tool in TOOLS:
    path = shutil.which(tool)
    if path:
        print(f"[OK] {tool}: {path}")
    else:
        print(f"[MISSING] {tool}")

print("\n--- Checking PATH ---")
print(os.environ.get("PATH"))

