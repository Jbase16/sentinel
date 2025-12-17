#
# PURPOSE:
# Translates high-level user intent ("find SQLi vulns") into concrete scan tasks.
# Maps goals to actionable tool executions.
#
# INTENT TYPES:
# - **Reconnaissance**: "Map the attack surface"
# - **Vulnerability Discovery**: "Find security flaws"
# - **Exploitation**: "Validate vulnerabilities"
# - **Post-Exploitation**: "Assess impact of compromise"
#
# INTENT → ACTION MAPPING:
# - "Find SQLi" → Run sqlmap on discovered forms
# - "Check for XSS" → Fuzz input fields with XSS payloads
# - "Discover subdomains" → Run subfinder, amass, crt.sh
# - "Map API endpoints" → Use proxy mode + crawler
#
# KEY CONCEPTS:
# - **Intent Recognition**: Understanding what user wants
# - **Task Decomposition**: Breaking goals into tool executions
# - **Context Awareness**: Different intents for web vs. infrastructure
#

"""
core/scheduler/intents.py
The Intent Vocabulary for Strategos.
Decouples "What we want to do" from "How we do it".
"""

# High-Level Intents
INTENT_PASSIVE_RECON = "intent_passive_recon"       # Zero-touch, public data
INTENT_ACTIVE_LIVE_CHECK = "intent_active_live"     # Gentle touching (ping/http)
INTENT_SURFACE_ENUMERATION = "intent_surface_enum"  # Crawling, port scanning
INTENT_PARAMETER_FUZZING = "intent_param_fuzzing"   # Fuzzing
INTENT_VULN_SCANNING = "intent_vuln_scan"           # Explicit vuln checks
INTENT_HEAVY_ARTILLERY = "intent_heavy_artillery"   # Opt-in heavy tools

# Helper to get human readable name
def get_intent_name(intent: str) -> str:
    """Function get_intent_name."""
    return intent.replace("intent_", "").replace("_", " ").title()
