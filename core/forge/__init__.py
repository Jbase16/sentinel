"""Module __init__: inline documentation for /Users/jason/Developer/sentinelforge/core/forge/__init__.py."""
#
# PURPOSE:
# Generates and tests proof-of-concept exploits for discovered vulnerabilities.
# Think of this as an automated exploit developer.
#
# JIT (JUST-IN-TIME) COMPILATION:
# Instead of using pre-written exploits, Forge generates custom exploits tailored
# to the specific vulnerability instance. Like a compiler: input = vuln details,
# output = working exploit code.
#
# WHAT IT DOES:
# 1. Takes vulnerability details (type, target, parameters)
# 2. Generates exploit code (Python, JavaScript, shell script)
# 3. Compiles/prepares the exploit
# 4. Runs it in a sandbox (isolated environment)
# 5. Validates if exploitation succeeded
#
# SAFETY:
# - **Sandbox**: Exploits run in isolated containers (can't harm your system)
# - **Validation**: Verifies exploitation without causing damage
# - **Logging**: Records all exploit attempts for audit
#
# KEY MODULES:
# - **compiler.py**: Generates exploit code from templates
# - **sandbox.py**: Isolated execution environment for testing exploits
#
# KEY CONCEPTS:
# - **JIT Compilation**: Generate code at runtime, not ahead-of-time
# - **Sandbox**: Isolated environment (Docker container, VM, etc.)
# - **Proof-of-Concept**: Demonstrates vulnerability without causing harm
#

from .compiler import ExploitCompiler
from .sandbox import SandboxRunner

__all__ = ["ExploitCompiler", "SandboxRunner"]
