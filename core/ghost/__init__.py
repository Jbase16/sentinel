"""Module __init__: inline documentation for /Users/jason/Developer/sentinelforge/core/ghost/__init__.py."""
#
# PURPOSE:
# Intercepts and analyzes HTTP/HTTPS traffic to understand application behavior
# and discover business logic vulnerabilities. Acts like an intelligent proxy.
#
# THE GHOST PROTOCOL:
# Think of Ghost as sitting between you and the target application, watching
# everything that happens:
# Browser ← → Ghost Proxy ← → Target Application
#
# WHAT IT DOES:
# - **Intercepts** all HTTP requests/responses
# - **Maps** user flows (login → view profile → edit settings → ...)
# - **Discovers** API endpoints and parameters
# - **Identifies** business logic flaws (IDOR, mass assignment, privilege escalation)
# - **Captures** authentication tokens and session data
#
# BUSINESS LOGIC VULNERABILITIES:
# These are flaws in how the application SHOULD work vs. how it DOES work:
# - **IDOR**: Access user 5's data by changing id=4 to id=5
# - **Mass Assignment**: Add "is_admin":true to profile update request
# - **Race Conditions**: Submit payment twice, get charged once
# - **Privilege Escalation**: Regular user performs admin actions
#
# KEY MODULES:
# - **proxy.py**: HTTP/HTTPS proxy server (intercepts traffic)
# - **flow.py**: User flow mapping (tracks multi-step interactions)
# - **logic.py**: Business logic vulnerability detection
# - **lazarus.py**: Session resurrection (replay captured sessions)
#
# KEY CONCEPTS:
# - **Proxy**: Intermediary that relays traffic while observing it
# - **User Flow**: Sequence of actions a user takes
# - **IDOR**: Insecure Direct Object Reference
# - **Mass Assignment**: Modifying object properties through API
#

from .flow import FlowMapper, UserFlow
from .logic import LogicFuzzer

__all__ = ["FlowMapper", "UserFlow", "LogicFuzzer"]
