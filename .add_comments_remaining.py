#!/usr/bin/env python3
"""
Batch adds educational header comments to remaining SentinelForge files.
"""

import os
from pathlib import Path

# File-specific header documentation
HEADERS = {
    # === Data Store Files ===
    "core/data/findings_store.py": """# ============================================================================
# core/data/findings_store.py
# Findings Store - In-Memory + Persistent Vulnerability Storage
# ============================================================================
#
# PURPOSE:
# Manages all discovered vulnerabilities with both in-memory caching and
# database persistence. Acts as the central repository for scan findings.
#
# WHAT ARE FINDINGS:
# Findings are potential security issues discovered by tools:
# - Open ports (nmap finds port 22 open)
# - Exposed services (httpx finds admin panel at /admin)
# - Misconfigurations (TLS 1.0 enabled, weak ciphers)
# - Information disclosure (server version leaked)
# - Vulnerabilities (known CVEs in detected software)
#
# FINDINGS VS. ISSUES:
# - **Finding**: Something potentially risky (needs investigation)
# - **Issue**: Confirmed exploit (has been validated/tested)
#
# ARCHITECTURE:
# - In-memory list for fast access during scan
# - Async writes to SQLite for persistence
# - Observable pattern (emits signals when findings change)
# - Session scoping (findings belong to specific scans)
#
# KEY CONCEPTS:
# - **Observable Pattern**: Emits signals when data changes
# - **Dual Storage**: Memory (fast) + Database (permanent)
# - **Session Scoping**: Each scan's findings kept separate
#
# ============================================================================

""",
    
    "core/data/issues_store.py": """# ============================================================================
# core/data/issues_store.py
# Issues Store - Confirmed Exploitable Vulnerability Storage
# ============================================================================
#
# PURPOSE:
# Stores confirmed security issues that have been validated/exploited.
# These are the "real" vulnerabilities, not just potential findings.
#
# FINDINGS → ISSUES PROMOTION:
# 1. Tool discovers something (becomes a Finding)
# 2. AI or human analyzes it
# 3. If exploitable, promoted to Issue
# 4. Issue includes proof-of-concept and impact assessment
#
# WHAT MAKES AN ISSUE:
# - **Reproducible**: Can be triggered reliably
# - **Validated**: Confirmed through testing
# - **Impact assessed**: Severity and business risk determined
# - **Proof-of-concept**: Working exploit demonstrated
#
# ISSUE ATTRIBUTES:
# - Severity: CRITICAL, HIGH, MEDIUM, LOW
# - Type: SQLi, XSS, IDOR, RCE, etc.
# - Proof: Steps to reproduce / exploit code
# - Impact: What attacker could achieve
# - Remediation: How to fix it
#
# ============================================================================

""",

    "core/data/evidence_store.py": """# ============================================================================
# core/data/evidence_store.py  
# Evidence Store - File-Based Artifact Preservation
# ============================================================================
#
# PURPOSE:
# Saves raw tool outputs and artifacts as files for audit trail and later review.
# Think of this as the "crime scene photos" of a penetration test.
#
# WHAT GETS SAVED:
# - Raw tool outputs (nmap XML, httpx JSON)
# - Screenshots of vulnerabilities
# - Network packet captures
# - SSL/TLS certificates
# - Source code snippets
# - HTTP request/response pairs
#
# WHY FILE-BASED STORAGE:
# - Database bloat prevention (tool outputs can be huge)
# - Easy external access (can open files in other tools)
# - Archival compliance (some regulations require raw evidence)
# - Re-analysis capability (can reprocess with updated parsers)
#
# FILE ORGANIZATION:
# ~/AraUltra_Evidence/
#   ├── nmap/target_com_timestamp.txt
#   ├── httpx/target_com_timestamp.json
#   └── screenshots/target_com_timestamp.png
#
# KEY CONCEPTS:
# - **Evidence Chain**: Maintaining provable audit trail
# - **Sanitization**: Cleaning filenames for filesystem safety
# - **Timestamping**: Ensuring unique filenames per run
#
# ============================================================================

""",

    "core/data/killchain_store.py": """# ============================================================================
# core/data/killchain_store.py
# Kill Chain Store - Attack Progression Tracking
# ============================================================================
#
# PURPOSE:
# Maps discovered findings to phases of the Cyber Kill Chain to understand
# attack progression potential. Shows "how far could an attacker get?"
#
# CYBER KILL CHAIN (LOCKHEED MARTIN):
# 1. **Reconnaissance**: Information gathering
# 2. **Weaponization**: Creating exploits
# 3. **Delivery**: Getting exploit to target
# 4. **Exploitation**: Triggering vulnerability
# 5. **Installation**: Installing backdoor/malware
# 6. **Command & Control**: Establishing remote control
# 7. **Actions on Objectives**: Data theft, destruction, etc.
#
# WHY KILL CHAIN MAPPING:
# - Prioritization: Later-stage vulns are more dangerous
# - Attack Paths: Shows how vulns chain together
# - Remediation Strategy: Block earliest stages first
# - Executive Reporting: Non-technical stakeholders understand progression
#
# EXAMPLE MAPPING:
# - Open port 22 → Reconnaissance
# - SSH with weak password → Exploitation
# - Root access gained → Installation
# - Reverse shell established → Command & Control
#
# ============================================================================

""",
}

def add_header_to_file(filepath: Path, header: str):
    """Add educational header to a file if it doesn't have comprehensive comments."""
    try:
        content = filepath.read_text()
        
        # Skip if already has substantial header (heuristic: starts with ===== line)
        if content.startswith("#" + "=" * 70):
            print(f"⏭  Skipping {filepath} (already has header)")
            return
            
        # Prepend header
        new_content = header + content
        filepath.write_text(new_content)
        print(f"✅ Added header to {filepath}")
        
    except Exception as e:
        print(f"❌ Error processing {filepath}: {e}")

def main():
    """Process all configured files."""
    base_dir = Path("/Users/jason/Developer/sentinelforge")
    
    for rel_path, header in HEADERS.items():
        filepath = base_dir / rel_path
        if filepath.exists():
            add_header_to_file(filepath, header)
        else:
            print(f"⚠️  File not found: {filepath}")
    
    print("\n✨ Header annotation complete!")

if __name__ == "__main__":
    main()
