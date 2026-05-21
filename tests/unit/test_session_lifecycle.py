"""
Tests for ScanSession lifecycle state — Bug #4.

The Bug #4 regression: every scan left an orphan session row in the DB
with status='Created' and end_time=NULL, because no part of the pipeline
ever updated those fields. These tests pin down the invariants:

1. ScanSession has end_time (initially None).
2. to_dict() includes end_time.
3. Once status + end_time are set, to_dict() serializes them correctly.

The integration of these into the actual scan-completion handlers in
core/server/routers/scans.py is covered by the end-to-end scan tests.
"""
from __future__ import annotations

import time

from core.base.session import ScanSession


class TestScanSessionLifecycle:
    def test_initial_state(self):
        s = ScanSession("http://example.com")
        assert s.status == "Created"
        assert s.end_time is None
        assert s.start_time is not None

    def test_to_dict_includes_end_time_when_none(self):
        s = ScanSession("http://example.com")
        d = s.to_dict()
        assert "end_time" in d
        assert d["end_time"] is None

    def test_to_dict_includes_end_time_after_completion(self):
        """Simulates the scan-completion handler updating session state."""
        s = ScanSession("http://example.com")
        # Pretend the scan completed:
        s.status = "completed"
        s.end_time = time.time()

        d = s.to_dict()
        assert d["status"] == "completed"
        assert d["end_time"] is not None
        assert d["end_time"] >= d["start_time"]

    def test_to_dict_shape_for_cancellation(self):
        s = ScanSession("http://example.com")
        s.status = "cancelled"
        s.end_time = time.time()

        d = s.to_dict()
        assert d["status"] == "cancelled"
        assert d["end_time"] is not None

    def test_to_dict_shape_for_error(self):
        s = ScanSession("http://example.com")
        s.status = "error"
        s.end_time = time.time()

        d = s.to_dict()
        assert d["status"] == "error"
        assert d["end_time"] is not None


class TestTimestampSerialization:
    """Bug #3: to_dict() must emit ISO 8601 UTC strings, not raw floats.

    The DB schema declares ``sessions.start_time TEXT`` with a default of
    ``datetime('now')`` — i.e. it expects ISO strings. Writing floats
    breaks lexicographic ORDER BY across mixed-vintage rows.
    """

    def test_start_time_is_iso_string(self):
        s = ScanSession("http://example.com")
        d = s.to_dict()
        assert isinstance(d["start_time"], str)
        # Must parse back as a datetime
        from datetime import datetime
        parsed = datetime.fromisoformat(d["start_time"])
        # Must include timezone info (UTC)
        assert parsed.tzinfo is not None

    def test_end_time_is_iso_string_after_completion(self):
        s = ScanSession("http://example.com")
        s.end_time = time.time()
        d = s.to_dict()
        assert isinstance(d["end_time"], str)
        from datetime import datetime
        parsed = datetime.fromisoformat(d["end_time"])
        assert parsed.tzinfo is not None

    def test_end_time_is_none_while_running(self):
        s = ScanSession("http://example.com")
        d = s.to_dict()
        assert d["end_time"] is None

    def test_iso_strings_sort_correctly(self):
        """Two sessions created in order should sort the same way as ISO strings."""
        import time as _t
        s1 = ScanSession("http://example.com")
        _t.sleep(0.01)  # ensure timestamps differ
        s2 = ScanSession("http://example.com")
        d1, d2 = s1.to_dict(), s2.to_dict()
        # Lexicographic comparison on ISO strings == chronological
        assert d1["start_time"] < d2["start_time"]

    def test_internal_float_unchanged(self):
        """Internal attribute stays a float — only to_dict converts."""
        s = ScanSession("http://example.com")
        assert isinstance(s.start_time, float)
        s.end_time = time.time()
        assert isinstance(s.end_time, float)
        # to_dict produces strings without mutating the source
        s.to_dict()
        assert isinstance(s.start_time, float)
        assert isinstance(s.end_time, float)
