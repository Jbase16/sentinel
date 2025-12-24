#
# PURPOSE:
# This module is part of the forge package in SentinelForge.
# [Specific purpose based on module name: compiler]
#
# KEY RESPONSIBILITIES:
# - [Automatically generated - review and enhance based on actual functionality]
#
# INTEGRATION:
# - Used by: [To be documented]
# - Depends on: [To be documented]
#

"""
core/forge/compiler.py
The JIT Exploit Compiler.
"Why use a tool when you can be a weapon smith?"
"""

import os
import uuid
import logging
from core.ai.ai_engine import AIEngine

logger = logging.getLogger(__name__)

class ExploitCompiler:
    """
    Generates bespoke Python scripts to exploit specific anomalies.
    """
    
    _instance = None
    
    @staticmethod
    def instance():
        """Function instance."""
        # Conditional branch.
        if ExploitCompiler._instance is None:
            ExploitCompiler._instance = ExploitCompiler()
        return ExploitCompiler._instance

    def __init__(self):
        """Function __init__."""
        self.ai = AIEngine.instance()
        self.output_dir = os.path.join(os.getcwd(), "artifacts", "exploits")
        os.makedirs(self.output_dir, exist_ok=True)

    def compile_exploit(self, target: str, anomaly_context: str) -> str:
        """
        Asks the Forge (LLM) to write a script.
        Returns the path to the generated script.
        """
        # Conditional branch.
        if not self.ai.client:
            raise RuntimeError("Forge requires AI connection.")

        system_prompt = (
            "You are a Zero-Day Exploit Developer. "
            "Write a standalone Python 3 script to poc-exploit the described anomaly. "
            "The script must: "
            "1. Be self-contained (use 'requests' or standard lib). "
            "2. Accept the target as a command line argument (or hardcode it in a variable at the top). "
            "3. Print 'EXPLOIT SUCCESS' if it works. "
            "Return ONLY the code block."
        )

        user_prompt = (
            f"Target: {target}\n"
            f"Anomaly Context:\n{anomaly_context}\n\n"
            "Write the PoC script."
        )

        response = self.ai.client.generate(user_prompt, system_prompt)
        
        # Extract code block if wrapped in markdown
        code = self._extract_code(response)
        
        # Save to disk
        filename = f"exploit_{uuid.uuid4().hex[:8]}.py"
        filepath = os.path.join(self.output_dir, filename)
        
        # Context-managed operation.
        with open(filepath, "w") as f:
            f.write(code)
            
        logger.info(f"[Forge] Generated exploit: {filepath}")
        return filepath

    def _extract_code(self, text: str) -> str:
        """Function _extract_code."""
        # Conditional branch.
        if "```" in text:
            # Simple markdown extraction
            parts = text.split("```python")
            if len(parts) > 1:
                return parts[1].split("```")[0].strip()
            parts = text.split("```")
            if len(parts) > 1:
                return parts[1].strip()
        return text
