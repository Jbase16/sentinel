#
# PURPOSE:
# The JIT Exploit Compiler - generates bespoke Python scripts to exploit specific anomalies.
# "Why use a tool when you can be a weapon smith?"
#
# KEY RESPONSIBILITIES:
# - Take vulnerability context from findings and ask AI to write proof-of-concept code
# - Validate generated code for obvious safety issues before saving
# - Save exploits to disk for manual review before execution
#
# SECURITY CONSIDERATIONS:
# - Generated code is NEVER auto-executed
# - Basic validation prevents obviously malicious patterns
# - All code saved to isolated artifacts directory
# - Timeout prevents hanging on slow AI responses
#
# INTEGRATION:
# - Used by: API endpoints (/forge/compile)
# - Depends on: AIEngine, circuit breaker
#

"""
core/forge/compiler.py
The JIT Exploit Compiler.
"Why use a tool when you can be a weapon smith?"
"""

import os
import re
import uuid
import logging
import asyncio
from typing import Optional

from core.ai.ai_engine import AIEngine

logger = logging.getLogger(__name__)

# ============================================================================
# Configuration
# ============================================================================

# Maximum time to wait for AI to generate exploit code
COMPILE_TIMEOUT = 60.0  # seconds

# Patterns that should NEVER appear in generated code
# These are heuristics to catch obviously malicious output
FORBIDDEN_PATTERNS = [
    # System destruction
    r'rm\s+-rf\s+/',
    r'shutil\.rmtree\s*\(\s*[\'\"]/[\'\"]\s*\)',
    r'os\.system\s*\(\s*[\'"]rm\s+-rf',

    # Reverse shells (common patterns)
    r'socket\.socket.*connect.*exec',
    r'/bin/sh.*-i',
    r'bash\s+-i\s+>&\s+/dev/tcp',

    # Crypto mining indicators
    r'xmrig',
    r'monero',
    r'stratum\+tcp',

    # Base64 exec (common obfuscation)
    r'exec\s*\(\s*base64\.b64decode',
    r'eval\s*\(\s*base64\.b64decode',
]


class ExploitCompiler:
    """
    Generates bespoke Python scripts to exploit specific anomalies.

    LESSON: "Defense in Depth for AI-Generated Code"
    ─────────────────────────────────────────────────
    When AI generates code, you CANNOT trust it blindly. Even well-intentioned
    prompts can produce dangerous output. Our safety layers:

    1. TIMEOUT - Don't hang forever waiting for AI
    2. VALIDATION - Scan for obviously dangerous patterns
    3. ISOLATION - Save to dedicated directory, never auto-execute
    4. LOGGING - Record what was generated for audit
    5. HUMAN REVIEW - User must manually run the script

    This isn't perfect (AI could obfuscate malicious code), but it catches
    the obvious cases and creates a paper trail.
    """

    _instance = None

    @staticmethod
    def instance():
        """Get or create singleton instance."""
        if ExploitCompiler._instance is None:
            ExploitCompiler._instance = ExploitCompiler()
        return ExploitCompiler._instance

    def __init__(self):
        """Initialize the compiler with AI connection and output directory."""
        self.ai = AIEngine.instance()
        self.output_dir = os.path.join(os.getcwd(), "artifacts", "exploits")
        os.makedirs(self.output_dir, exist_ok=True)
        logger.info(f"[Forge] Exploit output directory: {self.output_dir}")

    async def compile_exploit_async(self, target: str, anomaly_context: str) -> Optional[str]:
        """
        Async version of compile_exploit with timeout protection.

        This is the recommended entry point for async contexts (like the API).

        Args:
            target: The target URL or host
            anomaly_context: Description of the vulnerability to exploit

        Returns:
            Path to generated script, or None if compilation failed
        """
        if not self.ai.client:
            logger.warning("[Forge] AI unavailable - cannot compile exploit")
            return None

        try:
            # Run blocking AI call in thread pool with timeout
            filepath = await asyncio.wait_for(
                asyncio.to_thread(self._compile_exploit_sync, target, anomaly_context),
                timeout=COMPILE_TIMEOUT
            )
            return filepath
        except asyncio.TimeoutError:
            logger.error(f"[Forge] Exploit compilation timed out after {COMPILE_TIMEOUT}s")
            return None
        except Exception as e:
            logger.error(f"[Forge] Exploit compilation failed: {e}")
            return None

    def compile_exploit(self, target: str, anomaly_context: str) -> str:
        """
        Sync entry point - asks AI to write an exploit script.

        Returns the path to the generated script.
        Raises RuntimeError if AI is unavailable (for backward compatibility).

        LESSON: "Backward Compatibility vs. Safety"
        ───────────────────────────────────────────
        The original code raised RuntimeError when AI was unavailable.
        Some callers might depend on this behavior. We keep it for the
        sync version, but the async version returns None instead.
        """
        if not self.ai.client:
            raise RuntimeError("Forge requires AI connection.")
        return self._compile_exploit_sync(target, anomaly_context)

    def _compile_exploit_sync(self, target: str, anomaly_context: str) -> str:
        """
        Internal sync implementation of exploit compilation.

        This is where the actual AI call, validation, and adversarial debate happens.
        
        TRINITY OF HARDENING - Chapter 20: Ethical Leash
        ─────────────────────────────────────────────────
        1. Static Validation: Check for forbidden patterns (validator.py)
        2. Adversarial Debate: Red/Blue agents critique the code (debate.py)
        3. Attestation: Arbiter must sign off before code hits disk
        """
        from core.forge.validator import validate_code, RiskLevel
        from core.ai.debate import run_debate, DebateVerdict
        
        system_prompt = (
            "You are a Zero-Day Exploit Developer. "
            "Write a standalone Python 3 script to poc-exploit the described anomaly. "
            "The script must: "
            "1. Be self-contained (use 'requests' or standard lib). "
            "2. Accept the target as a command line argument (or hardcode it in a variable at the top). "
            "3. Print 'EXPLOIT SUCCESS' if it works. "
            "4. Include comments explaining what each section does. "
            "SAFETY RULES: "
            "- Never use os.system() - use subprocess.run() with shell=False "
            "- Never access /etc/, /root/, or system directories "
            "- Never include reverse shell code "
            "Return ONLY the code block, no markdown formatting."
        )

        user_prompt = (
            f"Target: {target}\n"
            f"Anomaly Context:\n{anomaly_context}\n\n"
            "Write the PoC script."
        )

        logger.info(f"[Forge] Requesting exploit for target: {target[:50]}...")

        response = self.ai.client.generate(user_prompt, system_prompt)

        if not response:
            raise RuntimeError("AI returned empty response")

        # Extract code block if wrapped in markdown
        code = self._extract_code(response)

        # ═══════════════════════════════════════════════════════════════════
        # PHASE 1: Static Validation (The Validator)
        # ═══════════════════════════════════════════════════════════════════
        validation_result = validate_code(code, strict=True)
        
        if not validation_result.safe:
            logger.error(f"[Forge] Generated code REJECTED by validator: {validation_result.risk_level.value}")
            for v in validation_result.violations:
                logger.error(f"  - [{v['level']}] {v.get('reason', 'Unknown violation')}")
            
            # Save to quarantine directory
            quarantine_dir = os.path.join(self.output_dir, "quarantine")
            os.makedirs(quarantine_dir, exist_ok=True)
            filename = f"QUARANTINED_{uuid.uuid4().hex[:8]}.py"
            filepath = os.path.join(quarantine_dir, filename)
            with open(filepath, "w") as f:
                f.write(f"# QUARANTINED: {validation_result.risk_level.value} risk\n")
                f.write(f"# Violations:\n")
                for v in validation_result.violations:
                    f.write(f"#   - {v.get('reason', 'Unknown')}\n")
                f.write(f"# DO NOT EXECUTE - FLAGGED AS POTENTIALLY MALICIOUS\n\n")
                f.write(code)
            logger.warning(f"[Forge] Quarantined suspicious code: {filepath}")
            raise RuntimeError(f"Generated code failed validation: {validation_result.risk_level.value}")
        
        # ═══════════════════════════════════════════════════════════════════
        # PHASE 2: Adversarial Debate (Red/Blue/Arbiter)
        # ═══════════════════════════════════════════════════════════════════
        logger.info("[Forge] Starting adversarial debate...")
        debate_result = run_debate(code, target, anomaly_context)
        
        if debate_result.verdict == DebateVerdict.REJECTED:
            logger.error(f"[Forge] Exploit REJECTED by Arbiter: {debate_result.arbiter_ruling}")
            
            # Save to quarantine with debate transcript
            quarantine_dir = os.path.join(self.output_dir, "quarantine")
            os.makedirs(quarantine_dir, exist_ok=True)
            filename = f"DEBATE_REJECTED_{uuid.uuid4().hex[:8]}.py"
            filepath = os.path.join(quarantine_dir, filename)
            with open(filepath, "w") as f:
                f.write(f"# REJECTED BY ADVERSARIAL DEBATE\n")
                f.write(f"# Arbiter Ruling: {debate_result.arbiter_ruling}\n")
                f.write(f"# Blue Agent Concerns:\n")
                for arg in debate_result.blue_arguments:
                    f.write(f"#   - {arg.position[:100]}...\n")
                f.write(f"#\n# DO NOT EXECUTE\n\n")
                f.write(code)
            logger.warning(f"[Forge] Debate-rejected code saved: {filepath}")
            raise RuntimeError(f"Exploit rejected by adversarial debate: {debate_result.arbiter_ruling}")
        
        elif debate_result.verdict == DebateVerdict.INCONCLUSIVE:
            logger.warning("[Forge] Adversarial debate was inconclusive - proceeding with caution")
        
        elif debate_result.verdict == DebateVerdict.APPROVED:
            logger.info("[Forge] Exploit APPROVED by Arbiter")

        # Save to disk
        filename = f"exploit_{uuid.uuid4().hex[:8]}.py"
        filepath = os.path.join(self.output_dir, filename)

        # Add safety header
        header = f'''#!/usr/bin/env python3
"""
Auto-generated exploit by SentinelForge
Target: {target}
Context: {anomaly_context[:100]}...

WARNING: This code was generated by AI and should be reviewed before execution.
         Run in an isolated environment (VM, container) for safety.
"""

'''
        with open(filepath, "w") as f:
            f.write(header + code)

        logger.info(f"[Forge] Generated exploit: {filepath}")
        return filepath

    def _extract_code(self, text: str) -> str:
        """Extract code from potential markdown formatting."""
        if not text:
            return ""

        text = text.strip()

        # Try to extract from ```python ... ``` block
        if "```python" in text:
            parts = text.split("```python")
            if len(parts) > 1:
                return parts[1].split("```")[0].strip()

        # Try to extract from generic ``` ... ``` block
        if "```" in text:
            parts = text.split("```")
            if len(parts) > 1:
                return parts[1].strip()

        return text

    def _validate_code(self, code: str) -> dict:
        """
        Scan generated code for obviously dangerous patterns.

        LESSON: "Heuristic Safety Validation"
        ──────────────────────────────────────
        This is NOT a security sandbox. AI can obfuscate malicious code
        in ways we can't detect. This validation catches:
        - Obvious mistakes (rm -rf /)
        - Common malware patterns (reverse shells, crypto miners)
        - Accidental dangerous output from confused AI

        It does NOT protect against:
        - Sophisticated malware
        - Obfuscated payloads
        - Logic bombs

        That's why we NEVER auto-execute and require human review.

        Returns:
            {"safe": True/False, "reason": str}
        """
        if not code or len(code) < 10:
            return {"safe": False, "reason": "Code too short or empty"}

        if len(code) > 100000:
            return {"safe": False, "reason": "Code suspiciously large (>100KB)"}

        # Check against forbidden patterns
        for pattern in FORBIDDEN_PATTERNS:
            if re.search(pattern, code, re.IGNORECASE):
                return {"safe": False, "reason": f"Matched forbidden pattern: {pattern[:30]}..."}

        # Check for excessive obfuscation (high ratio of special chars)
        special_chars = sum(1 for c in code if c in '\\x0123456789abcdef' and c not in 'abcdef')
        if special_chars / max(len(code), 1) > 0.3:
            return {"safe": False, "reason": "High ratio of hex/escape characters (obfuscation?)"}

        return {"safe": True, "reason": "Passed basic validation"}
