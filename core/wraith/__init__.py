"""Module __init__: inline documentation for /Users/jason/Developer/sentinelforge/core/wraith/__init__.py."""
#
# PURPOSE:
# Provides intelligent browser automation for testing modern web applications.
# Goes beyond simple HTTP requests to handle JavaScript, authentication flows,
# and anti-bot defenses. "The Hand" that executes discovered attack vectors.
#
# WHY "WRAITH":
# Like a ghost/wraith, this module moves through applications stealthily,
# evading detection while carrying out automated testing. It's the execution
# layer for attacks discovered by the Strategy Engine.
#
# WHAT WRAITH DOES:
# - **Browser Automation**: Controls headless browsers (Chrome, Firefox)
# - **JavaScript Execution**: Tests SPAs and dynamic applications
# - **Authentication**: Handles login flows, 2FA, OAuth
# - **Evasion**: Bypasses bot detection (captcha solving, timing randomization)
# - **Payload Execution**: Automatically tests discovered attack vectors
# - **Session Management**: Maintains authenticated sessions
#
# EVASION TECHNIQUES:
# - **Human-like behavior**: Random mouse movements, realistic typing speed
# - **Timing randomization**: Vary request intervals to avoid patterns
# - **Fingerprint randomization**: Change browser fingerprints
# - **Proxy rotation**: Use different IPs to avoid rate limiting
#
# KEY MODULES:
# - **automator.py**: Core browser automation engine
# - **evasion.py**: Anti-detection and stealth techniques
# - **mutator.py**: Payload mutation and generation
#
# WORKFLOW:
# Strategy discovers attack vector → Wraith opens browser → Executes payload → Validates result
#
# KEY CONCEPTS:
# - **Headless Browser**: Browser without UI (runs in background)
# - **Bot Detection**: Systems that identify automated traffic
# - **Fingerprinting**: Techniques to identify browsers uniquely
# - **SPA (Single Page Application)**: JavaScript-heavy web apps
#

from .evasion import WraithEngine
from .mutator import PayloadMutator

__all__ = ["WraithEngine", "PayloadMutator"]
