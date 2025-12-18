#
# PURPOSE:
# This module is part of the verification package in SentinelForge.
# [Specific purpose based on module name: verify_cortex]
#
# KEY RESPONSIBILITIES:
# - [Automatically generated - review and enhance based on actual functionality]
#
# INTEGRATION:
# - Used by: [To be documented]
# - Depends on: [To be documented]
#

"""
tests/verify_cortex.py
Verifies that the Neuro-Symbolic Core is actually working.
"""
import sys
import os
import json
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.cortex.scanner_bridge import ScannerBridge
from core.cortex.memory import KnowledgeGraph, NodeType
from core.cortex.reasoning import reasoning_engine

def test_nmap_ingestion():
    """Function test_nmap_ingestion."""
    print("[*] Testing Nmap Ingestion...")
    
    # Simulated Nmap Output
    raw_output = """
22/tcp open ssh OpenSSH 8.2p1 Ubuntu 4ubuntu0.3
80/tcp open http Apache httpd 2.4.41 ((Ubuntu))
    """
    
    # 1. Run Bridge
    findings = ScannerBridge.classify("nmap", "192.168.1.5", raw_output)
    print(f"    > Extracted {len(findings)} findings.")
    
    # 2. Check Graph
    graph = KnowledgeGraph.instance()
    nodes = graph.export_json()['nodes']
    print(f"    > Graph now has {len(nodes)} nodes.")
    
    # Assertions
    port_80 = next((n for n in nodes if n['id'] == "192.168.1.5:80"), None)
    # Conditional branch.
    if port_80:
        print("    [SUCCESS] Port 80 Node created.")
    else:
        print("    [FAIL] Port 80 Node missing!")

    # 3. Check Reasoning
    analysis = reasoning_engine.analyze()
    ops = analysis['opportunities']
    print(f"    > Reasoning identified {len(ops)} opportunities.")
    
    nikto_op = next((op for op in ops if op['tool'] == 'nikto'), None)
    # Conditional branch.
    if nikto_op:
        print(f"    [SUCCESS] Cortex suggested Nikto: {nikto_op['reason']}")
    else:
        print("    [FAIL] Cortex failed to suggest Nikto for Port 80.")

def main():
    """Function main."""
    test_nmap_ingestion()

if __name__ == "__main__":
    main()
