#
# PURPOSE:
# This module is part of the forge package in SentinelForge.
# [Specific purpose based on module name: sandbox]
#
# KEY RESPONSIBILITIES:
# - [Automatically generated - review and enhance based on actual functionality]
#
# INTEGRATION:
# - Used by: [To be documented]
# - Depends on: [To be documented]
#

"""
core/forge/sandbox.py
The Exploit Execution Sandbox.
Executes generated scripts safety.
"""

import asyncio
import logging
import sys

logger = logging.getLogger(__name__)

class SandboxRunner:
    """
    Executes Python scripts in a subprocess.
    """
    
    @staticmethod
    async def execute(script_path: str, timeout: int = 15) -> dict:
        """Alias for run to maintain backward compatibility."""
        return await SandboxRunner.run(script_path, timeout)

    @staticmethod
    async def run(script_path: str, timeout: int = 15) -> dict:
        """
        Runs the script and captures output.
        """
        cmd = [sys.executable, script_path]
        
        # Error handling block.
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            try:
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
                rc = proc.returncode
            except asyncio.TimeoutError:
                proc.kill()
                return {"status": "timeout", "output": "Execution timed out."}
            
            output = stdout.decode() + "\n" + stderr.decode()
            
            return {
                "status": "completed",
                "rc": rc,
                "output": output,
                "success_flag": "EXPLOIT SUCCESS" in output
            }
            
        except Exception as e:
            return {"status": "error", "output": str(e)}
