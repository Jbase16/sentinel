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
    return intent.replace("intent_", "").replace("_", " ").title()
