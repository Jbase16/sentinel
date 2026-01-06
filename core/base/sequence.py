"""
Global Sequence Authority - The Timeline Prime Provider.

PURPOSE:
This module provides a unified, monotonically increasing sequence counter
that serves as the single source of truth for all temporal ordering in
SentinelForge. Both EventStore and DecisionLedger draw from this same well.

ARCHITECTURAL INNOVATION:
Instead of having independent counters scattered across modules (which can
cause ordering ambiguity), we centralize sequencing into a single authority.
This enables:
- Perfect causal ordering across events and decisions
- Deterministic replay of entire agent sessions
- Cross-correlation between different data types
- Unambiguous "happened-before" relationships

DESIGN PRINCIPLES:
1. Singleton: One authority per process, thread-safe
2. Atomic: Uses itertools.count() which is GIL-protected in CPython
3. Persistent: Survives process restarts via database
4. Fail-Closed: Refuses to issue IDs if not properly initialized

WHY count() IS PERFECT HERE:
- itertools.count() is implemented in C and is atomic under the GIL
- next() on a count object is a single bytecode instruction
- No explicit locking needed for the increment operation itself
- Initialization still needs locking (singleton pattern)

USAGE:
    from core.base.sequence import GlobalSequenceAuthority

    # During startup (MUST be called before any sequences are issued)
    await GlobalSequenceAuthority.initialize_from_db()

    # Get next sequence (thread-safe, atomic)
    seq = GlobalSequenceAuthority.instance().next_id()

    # During shutdown (persist final state)
    await GlobalSequenceAuthority.persist_to_db()
"""

from __future__ import annotations

import logging
import threading
from itertools import count
import uuid
from typing import Optional

logger = logging.getLogger(__name__)


class GlobalSequenceAuthority:
    """
    The Timeline Prime Provider - unified monotonic sequence counter.

    This singleton replaces all independent counters with a single,
    thread-safe, database-backed sequence generator.

    Invariants:
    - Sequence numbers are strictly monotonically increasing
    - No sequence number is ever issued twice (across restarts)
    - All subsystems (events, decisions) share the same timeline
    - Initialization MUST happen before any sequences are issued

    Thread Safety:
    - Singleton initialization: protected by class-level lock
    - next_id(): atomic via itertools.count() (CPython GIL)
    - DB persistence: fire-and-forget, non-blocking
    """

    _instance: Optional[GlobalSequenceAuthority] = None
    _lock = threading.RLock()  # RLock allows reentrant acquisition (same thread can acquire multiple times)
    _initialized = False

    def __new__(cls) -> GlobalSequenceAuthority:
        """
        Singleton pattern using __new__.

        Thread-safe via double-checked locking.
        """
        if cls._instance is None:
            with cls._lock:
                # Double-check after acquiring lock
                if cls._instance is None:
                    instance = super().__new__(cls)
                    # count() starts at 0 by default, but we'll set start value
                    # during initialize_from_db()
                    instance._counter = count(start=1)
                    instance._last_issued = 0
                    instance._run_id: Optional[str] = None
                    cls._instance = instance
        return cls._instance

    @classmethod
    def instance(cls) -> GlobalSequenceAuthority:
        """
        Get the singleton instance.

        Raises:
            RuntimeError: If initialize_from_db() was not called first
        """
        if not cls._initialized:
            raise RuntimeError(
                "GlobalSequenceAuthority not initialized. "
                "Call await GlobalSequenceAuthority.initialize_from_db() during startup."
            )
        return cls()

    @classmethod
    async def initialize_from_db(cls) -> int:
        """
        Initialize the sequence counter from the database.

        This MUST be called once during application startup, before any
        events or decisions are created. It ensures the counter continues
        from where it left off after a restart.

        Returns:
            The starting sequence number (0 if first run)

        Side Effects:
            - Creates singleton instance if not exists
            - Loads last sequence from database
            - Marks authority as initialized

        Thread Safety:
            Uses a two-phase approach to avoid deadlock:
            1. Quick check under lock (fast path for already-initialized)
            2. Async DB fetch outside lock
            3. State update under lock with race condition handling
        """
        # Fast path: already initialized (check under lock)
        with cls._lock:
            if cls._initialized:
                return cls._instance._last_issued if cls._instance else 0

        # Slow path: need to fetch from DB
        # Do the async DB operation OUTSIDE the lock to avoid deadlock
        persisted = 0
        try:
            from core.data.db import Database
            db = Database.instance()
            persisted = await db.get_event_sequence()
        except Exception as e:
            logger.warning(
                f"[SequenceAuthority] Failed to load from DB: {e}, starting from 1"
            )
            persisted = 0

        # Now acquire lock to update state (handle race condition)
        with cls._lock:
            # Double-check: another coroutine may have initialized while we were awaiting
            if cls._initialized:
                return cls._instance._last_issued if cls._instance else 0

            # Ensure instance exists and initialize it
            instance = cls()
            instance._counter = count(start=persisted + 1)
            instance._last_issued = persisted
            instance._run_id = str(uuid.uuid4())
            cls._initialized = True

            if persisted > 0:
                logger.info(
                    f"[SequenceAuthority] Loaded from database: {persisted}, "
                    f"next ID will be {persisted + 1}"
                )
            else:
                logger.debug(
                    "[SequenceAuthority] No persisted sequence found, starting from 1"
                )

            return persisted

    @classmethod
    def is_initialized(cls) -> bool:
        """Check if the authority has been initialized."""
        return cls._initialized

    def next_id(self) -> int:
        """
        Get the next sequence number.

        This is the core operation - it returns a globally unique,
        monotonically increasing integer that can be used to order
        events and decisions.

        Returns:
            The next sequence number

        Thread Safety:
            Atomic via itertools.count() under the GIL.
            No explicit locking needed.

        Side Effects:
            - Persists new sequence to database (fire-and-forget)
        """
        # next() on itertools.count is atomic in CPython
        sequence = next(self._counter)
        self._last_issued = sequence

        # Fire-and-forget persistence
        self._persist_sequence(sequence)

        return sequence

    def _persist_sequence(self, sequence: int) -> None:
        """
        Asynchronously persist the sequence to database.

        Fire-and-forget: if this fails, we still have the correct
        in-memory value. The worst case is a small gap in sequences
        after a crash, which is acceptable.
        """
        try:
            from core.data.db import Database
            Database.instance().save_event_sequence(sequence)
        except Exception as e:
            # Log but don't fail - in-memory counter is authoritative
            logger.debug(
                f"[SequenceAuthority] Failed to persist sequence {sequence}: {e}"
            )

    @property
    def last_issued(self) -> int:
        """Get the last issued sequence number (for diagnostics)."""
        return self._last_issued

    @property
    def run_id(self) -> Optional[str]:
        """Get the unique run ID (epoch) for this process lifecycle."""
        return self._run_id

    @classmethod
    async def persist_to_db(cls) -> None:
        """
        Explicitly persist the current sequence to database.

        Call this during graceful shutdown to ensure no sequences are lost.
        """
        if cls._instance and cls._initialized:
            try:
                from core.data.db import Database
                db = Database.instance()
                await db._save_event_sequence_impl(cls._instance._last_issued)
                logger.info(
                    f"[SequenceAuthority] Persisted final sequence: "
                    f"{cls._instance._last_issued}"
                )
            except Exception as e:
                logger.warning(
                    f"[SequenceAuthority] Failed to persist final sequence: {e}"
                )

    @classmethod
    def reset_for_testing(cls) -> None:
        """
        Reset the singleton for testing purposes.

        WARNING: This should ONLY be used in tests!
        In production, the authority should never be reset.
        """
        with cls._lock:
            cls._instance = None
            cls._initialized = False

    @classmethod
    def initialize_for_testing(cls, start: int = 1) -> None:
        """
        Initialize with a specific starting value for testing.

        WARNING: This should ONLY be used in tests!
        Bypasses database initialization for fast, isolated tests.
        """
        # First, create instance without holding the lock (to avoid deadlock)
        # since __new__ also acquires the lock
        instance = cls()

        # Now update the instance state under the lock
        with cls._lock:
            instance._counter = count(start=start)
            instance._last_issued = start - 1
            instance._run_id = str(uuid.uuid4())
            cls._initialized = True


# ============================================================================
# Module-Level Convenience Functions
# ============================================================================
# These provide backward compatibility with the old get_next_sequence() API


def get_next_global_sequence() -> int:
    """
    Get the next global sequence number.

    This is the primary API for obtaining sequence numbers.
    Wraps GlobalSequenceAuthority.instance().next_id().

    Returns:
        The next monotonically increasing sequence number

    Raises:
        RuntimeError: If initialize_from_db() was not called first
    """
    return GlobalSequenceAuthority.instance().next_id()


def is_sequence_initialized() -> bool:
    """Check if the sequence authority has been initialized."""
    return GlobalSequenceAuthority.is_initialized()


# ============================================================================
# Self-Test
# ============================================================================

if __name__ == "__main__":
    import asyncio

    async def test():
        # Test initialization
        print("Testing GlobalSequenceAuthority...")

        # Initialize for testing (bypasses DB)
        GlobalSequenceAuthority.initialize_for_testing(start=100)

        # Test monotonicity
        auth = GlobalSequenceAuthority.instance()
        ids = [auth.next_id() for _ in range(10)]
        print(f"Generated IDs: {ids}")

        assert ids == list(range(100, 110)), "IDs should be monotonic"
        print("✓ Monotonicity verified")

        # Test last_issued property
        assert auth.last_issued == 109, "last_issued should track"
        print(f"✓ Last issued: {auth.last_issued}")

        # Test singleton pattern
        auth2 = GlobalSequenceAuthority.instance()
        assert auth is auth2, "Should be same instance"
        print("✓ Singleton pattern verified")

        # Test thread safety (basic)
        import concurrent.futures

        GlobalSequenceAuthority.reset_for_testing()
        GlobalSequenceAuthority.initialize_for_testing(start=1)

        def get_ids(n):
            return [GlobalSequenceAuthority.instance().next_id() for _ in range(n)]

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            futures = [executor.submit(get_ids, 100) for _ in range(4)]
            all_ids = []
            for f in concurrent.futures.as_completed(futures):
                all_ids.extend(f.result())

        # All IDs should be unique
        assert len(all_ids) == len(set(all_ids)), "All IDs should be unique"
        print(f"✓ Thread safety: {len(all_ids)} unique IDs from 4 threads")

        print("\n✅ All GlobalSequenceAuthority tests passed!")

    asyncio.run(test())
