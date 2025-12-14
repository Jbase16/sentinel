"""
tests/verify_architecture.py

Verifies the Principal Engineering Upgrades:
1. ScanSession creation and isolation.
2. Database persistence.
3. ScannerEngine execution with Session scope.
"""

import asyncio
import os
import sys

# Add root to implementation
sys.path.append(os.getcwd())

from core.base.session import ScanSession
from core.engine.scanner_engine import ScannerEngine
from core.data.db import Database
from core.toolkit.tools import TOOLS

async def test_session_isolation():
    print("[*] Testing Session Isolation...")
    
    # Session A
    session_a = ScanSession("target-a.com")
    print(f"    Session A Created: {session_a.id}")
    
    # Session B
    session_b = ScanSession("target-b.com")
    print(f"    Session B Created: {session_b.id}")
    
    assert session_a.id != session_b.id
    assert session_a.findings is not session_b.findings
    print("    [OK] Sessions are isolated objects.")

    # DB Persistence Check
    print("[*] Testing DB Persistence...")
    session_a.findings.add_finding({
        "tool": "test_tool",
        "type": "vuln_a",
        "severity": "HIGH",
        "target": "target-a.com"
    })
    
    # Allow async write
    await asyncio.sleep(0.5)
    
    # Verify in DB
    db = Database.instance()
    loaded_findings = await db.get_findings(session_a.id)
    assert len(loaded_findings) == 1
    assert loaded_findings[0]["target"] == "target-a.com"
    print(f"    [OK] Finding persisted for Session A.")
    
    # Verify Session B sees nothing
    loaded_b = await db.get_findings(session_b.id)
    assert len(loaded_b) == 0
    print("    [OK] Session B has zero findings (Isolation Verified).")

async def test_scanner_integration():
    print("[*] Testing Scanner Engine Integration...")
    session = ScanSession("scanme.nmap.org")
    engine = ScannerEngine(session=session)
    
    # Verify Engine uses core.tools
    assert "nmap" in TOOLS
    assert engine._detect_installed() # Should find something if tools are installed
    
    print("    [OK] Scanner Engine initialized with Session.")

if __name__ == "__main__":
    loop = asyncio.new_event_loop()
    loop.run_until_complete(test_session_isolation())
    loop.run_until_complete(test_scanner_integration())
    print("\n[SUCCESS] Architecture Verified.")
