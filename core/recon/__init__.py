# ============================================================================
# core/recon/__init__.py
# Reconnaissance Package - Information Gathering
# ============================================================================
#
# PURPOSE:
# Gathers information about targets before active testing. Like a detective
# collecting clues before confronting a suspect.
#
# RECONNAISSANCE PHASES:
# 1. **Passive**: Gather info without touching the target (DNS, WHOIS, Google)
# 2. **Active**: Directly interact with target (port scans, banner grabbing)
# 3. **Behavioral**: Observe how the application behaves under different conditions
#
# WHAT WE DISCOVER:
# - **Subdomains**: Find hidden parts of the infrastructure
# - **IP Addresses**: Map network topology
# - **Technologies**: Identify web servers, frameworks, libraries
# - **Endpoints**: Discover API routes and hidden pages
# - **Credentials**: Find exposed keys, tokens, passwords
#
# WHY RECON MATTERS:
# - More recon = larger attack surface discovered
# - Identifies low-hanging fruit (exposed admin panels, default creds)
# - Maps target architecture (helps plan attack strategy)
# - Often finds vulnerabilities without active exploitation
#
# KEY MODULES:
# - **behavioral.py**: Active behavioral probing and analysis
# - **module.py**: Core reconnaissance orchestration
#
# EXPORTED CLASSES:
# - **BehavioralRecon**: Active behavioral probes (how does app respond?)
# - **PassiveReconEngine**: Passive info gathering (no direct contact)
#
# KEY CONCEPTS:
# - **Passive Recon**: No direct interaction (can't be detected)
# - **Active Recon**: Direct interaction (might trigger alerts)
# - **OSINT**: Open Source Intelligence (public data sources)
# - **Attack Surface**: All possible entry points for attacks
#
# ============================================================================

from core.recon.behavioral import BehavioralRecon, PassiveReconEngine  # noqa: F401
