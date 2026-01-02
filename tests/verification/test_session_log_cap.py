"""
Session Log Cap - Memory Safety Verification

CRITICAL INVARIANT:
Session logs MUST be bounded to prevent memory exhaustion during long-running scans.

This test verifies TODO #7: "Session Log Unbounded Growth" has been resolved.

THREAT MODEL:
A long-running scan (hours/days) with verbose tool output could accumulate millions
of log entries, causing OOM crashes. This happened with unbounded list.append().

DEFENSE:
- Use collections.deque with maxlen (circular buffer)
- Automatically evicts oldest entries when full
- Provides overflow warning to user
- No manual cleanup needed
"""

import pytest
from collections import deque

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from core.base.session import ScanSession, MAX_SESSION_LOGS


def test_session_logs_use_bounded_deque():
    """
    INVARIANT: Session.logs must be a deque with maxlen set.

    This ensures automatic eviction of old entries, preventing unbounded growth.
    """
    session = ScanSession(target="example.com")

    # Verify logs is a deque (not a list)
    assert isinstance(session.logs, deque), (
        f"session.logs is {type(session.logs)}, expected collections.deque"
    )

    # Verify maxlen is set (this makes it a circular buffer)
    assert session.logs.maxlen is not None, (
        "session.logs.maxlen is None! This means unbounded growth is possible."
    )

    # Verify maxlen is reasonable (not infinity)
    assert session.logs.maxlen == MAX_SESSION_LOGS, (
        f"Expected maxlen={MAX_SESSION_LOGS}, got {session.logs.maxlen}"
    )

    # Verify MAX_SESSION_LOGS is reasonable (5000 is good)
    assert 1000 <= MAX_SESSION_LOGS <= 10000, (
        f"MAX_SESSION_LOGS={MAX_SESSION_LOGS} seems wrong. "
        f"Should be 1000-10000 for memory safety."
    )


def test_session_logs_evict_oldest_when_full():
    """
    INVARIANT: When log cap is reached, oldest entries must be evicted.

    This is the core memory safety property. deque with maxlen does this automatically.
    """
    session = ScanSession(target="example.com")

    # Fill beyond capacity
    num_logs = MAX_SESSION_LOGS + 1000

    for i in range(num_logs):
        session.log(f"Log entry {i}")

    # Verify size is capped
    assert len(session.logs) <= MAX_SESSION_LOGS, (
        f"Log size {len(session.logs)} exceeds cap {MAX_SESSION_LOGS}!"
    )

    # Verify oldest entries were evicted
    # The first entry should be "Log entry 1000", not "Log entry 0"
    oldest_entry = session.logs[0]

    # Extract the entry number (format: "[HH:MM:SS] Log entry N")
    if "Log entry" in oldest_entry:
        entry_num = int(oldest_entry.split("Log entry ")[-1])
        expected_oldest = num_logs - MAX_SESSION_LOGS

        # Allow some tolerance for warning message insertion
        assert entry_num >= expected_oldest - 10, (
            f"Oldest entry is #{entry_num}, expected around #{expected_oldest}. "
            f"This means old entries weren't evicted!"
        )


def test_session_logs_warn_on_overflow():
    """
    INVARIANT: User must be warned when log cap is reached.

    This provides observability - user knows logs are being dropped.
    """
    session = ScanSession(target="example.com")

    # Fill to capacity + 100
    for i in range(MAX_SESSION_LOGS + 100):
        session.log(f"Entry {i}")

    # Find warning message in logs
    warning_found = False
    for entry in session.logs:
        if "WARNING" in entry and "Log limit" in entry:
            warning_found = True
            break

    assert warning_found, (
        "No overflow warning found in logs. "
        "User should be notified when logs start getting dropped."
    )


def test_session_logs_thread_safe():
    """
    INVARIANT: Session.log() must be thread-safe.

    Multiple tools run concurrently and all call session.log().
    Without locking, this would cause data corruption.
    """
    import threading
    import time

    session = ScanSession(target="example.com")

    # Simulate concurrent logging from multiple threads (like multiple tools)
    def log_worker(thread_id):
        for i in range(100):
            session.log(f"Thread {thread_id} - Entry {i}")
            time.sleep(0.001)  # Simulate some work

    # Launch 10 threads
    threads = []
    for t in range(10):
        thread = threading.Thread(target=log_worker, args=(t,))
        threads.append(thread)
        thread.start()

    # Wait for all threads to complete
    for thread in threads:
        thread.join()

    # Verify we got logs from all threads (no data corruption)
    # We should have at most MAX_SESSION_LOGS entries
    assert len(session.logs) <= MAX_SESSION_LOGS

    # Verify entries are well-formed (not corrupted)
    for entry in session.logs:
        # Should have timestamp prefix
        assert entry.startswith("["), f"Malformed entry: {entry}"
        assert "]" in entry, f"Malformed entry: {entry}"


def test_session_logs_no_memory_leak():
    """
    INVARIANT: Repeatedly filling logs must not leak memory.

    This verifies the circular buffer works correctly across multiple fill cycles.
    """
    session = ScanSession(target="example.com")

    # Fill and drain logs multiple times
    for cycle in range(5):
        # Fill to capacity
        for i in range(MAX_SESSION_LOGS + 100):
            session.log(f"Cycle {cycle} - Entry {i}")

        # Size should still be capped
        assert len(session.logs) <= MAX_SESSION_LOGS, (
            f"Memory leak detected in cycle {cycle}: "
            f"{len(session.logs)} > {MAX_SESSION_LOGS}"
        )


def test_session_logs_preserves_recent_entries():
    """
    INVARIANT: Most recent logs must be preserved when cap is reached.

    Circular buffer evicts oldest, keeps newest - critical for debugging.
    """
    session = ScanSession(target="example.com")

    # Add many logs
    for i in range(MAX_SESSION_LOGS + 1000):
        session.log(f"Entry {i}")

    # The LAST entry should still be present
    last_entry = session.logs[-1]
    expected_last = MAX_SESSION_LOGS + 1000 - 1

    assert f"Entry {expected_last}" in last_entry, (
        f"Most recent entry missing! Expected 'Entry {expected_last}', got: {last_entry}"
    )


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
