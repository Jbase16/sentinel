# ============================================================================
# tests/verification/inspect_db.py
# Inspect Db Module
# ============================================================================
#
# PURPOSE:
# This module is part of the verification package in SentinelForge.
# [Specific purpose based on module name: inspect_db]
#
# KEY RESPONSIBILITIES:
# - [Automatically generated - review and enhance based on actual functionality]
#
# INTEGRATION:
# - Used by: [To be documented]
# - Depends on: [To be documented]
#
# ============================================================================

import sqlite3
import os
import json

DB_PATH = os.path.expanduser("~/.sentinelforge/data.db")

if not os.path.exists(DB_PATH):
    print(f"Database not found at {DB_PATH}")
    exit(0)

print(f"--- Inspecting {DB_PATH} ---")

try:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Check Findings
    cursor.execute("SELECT count(*) FROM findings")
    count = cursor.fetchone()[0]
    print(f"Findings Count: {count}")
    
    if count > 0:
        print("\n--- First 5 Findings ---")
        cursor.execute("SELECT tool, type, severity, target FROM findings LIMIT 5")
        for row in cursor.fetchall():
            print(f"  {row}")

    # Check Issues
    cursor.execute("SELECT count(*) FROM issues")
    count = cursor.fetchone()[0]
    print(f"\nIssues Count: {count}")

    # Check History
    cursor.execute("SELECT count(*) FROM scan_history")
    count = cursor.fetchone()[0]
    print(f"\nScan History Count: {count}")

    conn.close()

except Exception as e:
    print(f"Error inspecting DB: {e}")
