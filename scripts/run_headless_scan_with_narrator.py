# scripts/run_headless_scan_with_narrator.py
import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(message)s"
)

from core.cortex.narrator import NarratorEngine
from core.scheduler.decisions import DecisionLedger, DecisionPoint, DecisionType

def main():
    print("\n--- Headless Narrator Test ---\n")

    ledger = DecisionLedger()
    narrator = NarratorEngine(event_bus=None)  # headless mode

    decisions = [
        DecisionPoint.create(
            decision_type=DecisionType.PHASE_TRANSITION,
            chosen="ACTIVE_RECON",
            reason="Initial scan phase"
        ),
        DecisionPoint.create(
            decision_type=DecisionType.INTENT_TRANSITION,
            chosen="intent_surface_enum",
            reason="Standard progression"
        ),
        DecisionPoint.create(
            decision_type=DecisionType.TOOL_SELECTION,
            chosen=["nmap", "httpx", "nuclei"],
            reason="High-confidence surface",
            context={"target": "example.com"}
        ),
        DecisionPoint.create(
            decision_type=DecisionType.TOOL_REJECTION,
            chosen="BLOCKED",
            reason="Risk Policy",
            context={"tools": ["masscan"]}
        ),
        DecisionPoint.create(
            decision_type=DecisionType.EARLY_TERMINATION,
            chosen="WALK_AWAY",
            reason="No live services detected"
        ),
    ]

    for d in decisions:
        committed = ledger.commit(d)
        narrator.narrate(committed)

    print("\n✅ Narrator test complete.\n")

if __name__ == "__main__":
    main()
