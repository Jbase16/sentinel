"""Module repro_import: inline documentation for /Users/jason/Developer/sentinelforge/repro_import.py."""
import sys
import os
sys.path.append(os.getcwd())

print("Attempting to import NarratorEngine...")
try:
    from core.cortex.narrator import NarratorEngine
    print("SUCCESS: Imported NarratorEngine")
except Exception as e:
    print(f"FAILURE: {e}")

print("Attempting to import DecisionPoint...")
try:
    from core.scheduler.decisions import DecisionPoint
    print("SUCCESS: Imported DecisionPoint")
except Exception as e:
    print(f"FAILURE: {e}")
