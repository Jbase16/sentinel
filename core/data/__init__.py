# ============================================================================
# core/data/__init__.py
# Data Layer Package - Storage and Persistence
# ============================================================================
#
# PURPOSE:
# Houses all data storage and persistence logic. Think of this as the "memory"
# layer where scan results, findings, and evidence are stored.
#
# MODULES IN THIS PACKAGE:
# - **db.py**: SQLite database layer (sessions, findings, issues)
# - **findings_store.py**: In-memory + persistent storage for discovered vulnerabilities
# - **issues_store.py**: Storage for confirmed exploitable issues
# - **evidence_store.py**: File-based storage for raw tool outputs
# - **killchain_store.py**: Tracks attack progression through kill chain phases
# - **risk.py**: Automated risk scoring based on findings severity
#
# DATA FLOW:
# Tool runs → Evidence saved to files → Findings extracted → Stored in DB → Risk calculated
#
# KEY CONCEPTS:
# - **Stores**: In-memory caches backed by database persistence
# - **Evidence**: Raw artifacts (tool outputs, screenshots) saved as files
# - **Findings vs. Issues**: Findings are discoveries, Issues are confirmed exploits
#
# ============================================================================
