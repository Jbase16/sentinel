"""Module test_event_sequence_persistence: inline documentation for /Users/jason/Developer/sentinelforge/tests/unit/test_event_sequence_persistence.py."""

"""
Event Sequence Persistence Invariant Test

INVARIANT: The global event sequence counter MUST never decrease across process restarts.
This ensures:
1. Event IDs (UUIDv5 derived from sequence) remain globally unique
2. Swift client deduplication via lastSequence tracking works correctly
3. Causal ordering is preserved as "one continuous logical brain"

This test simulates a restart scenario by:
1. Creating a temporary database
2. Initializing and generating events
3. Closing the database (simulating shutdown)
4. Reopening and reinitializing (simulating restart)
5. Verifying sequence continues monotonically
"""

import tempfile
import os
import asyncio

from core.cortex.events import (
    initialize_event_sequence_from_db,
    get_next_sequence,
    reset_event_sequence,
    reset_run_id,
    GraphEvent,
    GraphEventType,
)
from core.data.db import Database


def test_event_sequence_never_decreases_across_restarts():
    """
    Invariant: Event sequence counter is monotonically increasing across restarts.

    This is the CRITICAL invariant that guarantees:
    - No duplicate event IDs after restart
    - Swift client replay deduplication correctness
    - Continuous causal history
    """
    # Create a temporary database for isolated testing
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test_sequences.db")

        async def run_test():
            # --- Phase 1: First "boot" ---
            # Reset global state for clean test
            reset_event_sequence()
            reset_run_id()

            # Configure database to use temp file
            from core.base.config import get_config, SentinelConfig, StorageConfig, SecurityConfig
            test_config = SentinelConfig(
                storage=StorageConfig(db_path=db_path),
                security=SecurityConfig()
            )

            # Patch the config singleton for this test
            import core.base.config
            original_get_config = core.base.config._config
            core.base.config._config = test_config

            try:
                db = Database.instance()
                await db.init()

                # Initialize event sequence from empty database
                initial_seq = await initialize_event_sequence_from_db()
                assert initial_seq == 0, "New database should start at 0"

                # Generate some events in "first boot"
                seq1 = get_next_sequence()
                seq2 = get_next_sequence()
                seq3 = get_next_sequence()

                assert seq1 == 1
                assert seq2 == 2
                assert seq3 == 3

                # Persist final sequence (simulating shutdown)
                from core.cortex.events import get_event_bus
                last_seq = get_event_bus().last_event_sequence
                await db._save_event_sequence_impl(last_seq)

                # Close database (simulating shutdown)
                await db.close()

                # --- Phase 2: Simulate restart ---
                # Reset the in-memory singleton state
                Database._instance = None
                reset_event_sequence()
                reset_run_id()  # New process = new run_id

                # Reopen database (simulating process restart)
                db2 = Database.instance()
                await db2.init()

                # Reinitialize event sequence from persisted value
                restarted_seq = await initialize_event_sequence_from_db()

                # CRITICAL ASSERTION: Sequence must resume from last persisted value
                # This is the invariant that prevents duplicate IDs
                assert restarted_seq == 3, f"Expected sequence 3, got {restarted_seq}"

                # Generate new events after restart
                seq4 = get_next_sequence()
                seq5 = get_next_sequence()

                # Verify monotonic increase across restart
                assert seq4 == 4, f"Expected seq4=4, got {seq4}"
                assert seq5 == 5, f"Expected seq5=5, got {seq5}"

                # Verify no duplicates or regressions
                assert seq4 > seq3, "Sequence must increase after restart"
                assert seq5 > seq4, "Sequence must be monotonically increasing"

                # Cleanup
                await db2.close()

            finally:
                # Restore original config
                core.base.config._config = original_get_config

        # Run the async test
        asyncio.run(run_test())


def test_event_sequence_raises_if_not_initialized():
    """
    Verify that get_next_sequence() raises RuntimeError if called before initialization.

    This is a safety guard to prevent silent corruption where events are emitted
    before startup completes, which would cause the counter to start from 0
    instead of the persisted value.
    """
    # Reset global state
    reset_event_sequence()
    reset_run_id()

    # Attempt to get sequence without initialization should raise
    try:
        seq = get_next_sequence()
        assert False, f"Expected RuntimeError, but got sequence {seq}"
    except RuntimeError as e:
        assert "not initialized" in str(e)
        # Expected: guard worked


def test_event_sequence_id_uniqueness_across_restarts():
    """
    Verify that event IDs derived from sequence numbers remain unique across restarts.

    Uses UUIDv5 derivation: uuid.uuid5(uuid.NAMESPACE_DNS, f"sentinel-event-{sequence}")

    This is the practical invariant that matters to the Swift client.
    """
    import uuid

    # Simulate sequences from two "lifecycles"
    lifecycle1_sequences = [1, 2, 3]
    lifecycle2_sequences = [4, 5, 6]  # Continues from lifecycle1

    # Generate IDs for each lifecycle
    lifecycle1_ids = set()
    for seq in lifecycle1_sequences:
        event_id = uuid.uuid5(uuid.NAMESPACE_DNS, f"sentinel-event-{seq}")
        lifecycle1_ids.add(str(event_id))

    lifecycle2_ids = set()
    for seq in lifecycle2_sequences:
        event_id = uuid.uuid5(uuid.NAMESPACE_DNS, f"sentinel-event-{seq}")
        lifecycle2_ids.add(str(event_id))

    # Verify no overlap between lifecycles
    overlap = lifecycle1_ids & lifecycle2_ids
    assert len(overlap) == 0, f"Found duplicate IDs across restarts: {overlap}"

    # Verify all IDs are unique
    all_ids = lifecycle1_ids | lifecycle2_ids
    assert len(all_ids) == 6, "All 6 IDs should be unique"
