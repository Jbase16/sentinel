"""
Test Hot Reload Functionality (Phase 4)

Tests the policy file watcher and auto-reload capabilities.
"""

import pytest
import asyncio
import tempfile
from pathlib import Path
from core.cortex.policy_watcher import PolicyFileWatcher


@pytest.mark.asyncio
async def test_watcher_starts_and_stops():
    """Test that watcher can start and stop cleanly."""
    with tempfile.TemporaryDirectory() as tmpdir:
        watcher = PolicyFileWatcher(watch_directory=tmpdir, poll_interval=0.5)

        assert watcher._running is False

        await watcher.start()
        assert watcher._running is True

        await watcher.stop()
        assert watcher._running is False

    print("✓ Watcher starts and stops correctly")


@pytest.mark.asyncio
async def test_watcher_detects_new_file():
    """Test that watcher detects newly created .cal files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir_path = Path(tmpdir)

        reload_called = asyncio.Event()
        reload_count = [0]

        async def reload_callback():
            reload_count[0] += 1
            reload_called.set()

        watcher = PolicyFileWatcher(watch_directory=tmpdir, poll_interval=0.2)
        watcher.set_reload_callback(reload_callback)

        await watcher.start()

        # Wait for initial scan to complete
        await asyncio.sleep(0.1)

        # Create a new .cal file
        test_file = tmpdir_path / "test.cal"
        test_file.write_text("Law Test { When: true Then: ALLOW \"ok\" }")

        # Wait for reload to be triggered
        try:
            await asyncio.wait_for(reload_called.wait(), timeout=2.0)
            assert reload_count[0] >= 1
            print(f"✓ New file detected and reload triggered ({reload_count[0]} times)")
        finally:
            await watcher.stop()


@pytest.mark.asyncio
async def test_watcher_detects_file_modification():
    """Test that watcher detects file modifications."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir_path = Path(tmpdir)

        # Create initial file
        test_file = tmpdir_path / "test.cal"
        test_file.write_text("Law Test { When: true Then: ALLOW \"v1\" }")

        reload_called = asyncio.Event()
        reload_count = [0]

        async def reload_callback():
            reload_count[0] += 1
            reload_called.set()

        watcher = PolicyFileWatcher(watch_directory=tmpdir, poll_interval=0.2)
        watcher.set_reload_callback(reload_callback)

        await watcher.start()

        # Wait a moment for initial scan
        await asyncio.sleep(0.3)

        # Modify the file
        test_file.write_text("Law Test { When: true Then: DENY \"v2\" }")

        # Wait for reload to be triggered
        try:
            await asyncio.wait_for(reload_called.wait(), timeout=2.0)
            assert reload_count[0] >= 1
            print(f"✓ File modification detected and reload triggered ({reload_count[0]} times)")
        finally:
            await watcher.stop()


@pytest.mark.asyncio
async def test_watcher_ignores_non_cal_files():
    """Test that watcher only watches .cal files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir_path = Path(tmpdir)

        reload_count = [0]

        async def reload_callback():
            reload_count[0] += 1

        watcher = PolicyFileWatcher(watch_directory=tmpdir, poll_interval=0.2)
        watcher.set_reload_callback(reload_callback)

        await watcher.start()

        # Create non-.cal files
        (tmpdir_path / "test.txt").write_text("not a cal file")
        (tmpdir_path / "test.py").write_text("print('hello')")

        # Wait and verify no reload triggered
        await asyncio.sleep(0.5)

        assert reload_count[0] == 0
        print("✓ Non-.cal files ignored")

        await watcher.stop()


@pytest.mark.asyncio
async def test_watcher_debouncing():
    """Test that rapid file changes are debounced."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir_path = Path(tmpdir)

        test_file = tmpdir_path / "test.cal"
        test_file.write_text("Law Test { When: true Then: ALLOW \"v1\" }")

        reload_count = [0]

        async def reload_callback():
            reload_count[0] += 1

        watcher = PolicyFileWatcher(watch_directory=tmpdir, poll_interval=0.1)
        watcher._debounce_delay = 0.3  # 300ms debounce
        watcher.set_reload_callback(reload_callback)

        await watcher.start()

        # Wait for initial scan
        await asyncio.sleep(0.15)

        # Make rapid changes
        for i in range(5):
            test_file.write_text(f"Law Test {{ When: true Then: ALLOW \"v{i}\" }}")
            await asyncio.sleep(0.05)  # 50ms between changes

        # Wait for debounce period plus poll interval
        await asyncio.sleep(0.6)

        # Should only reload once due to debouncing
        assert reload_count[0] <= 2  # Allow for 1-2 reloads max
        print(f"✓ Debouncing works (reload count: {reload_count[0]})")

        await watcher.stop()


@pytest.mark.asyncio
async def test_watcher_get_watched_files():
    """Test that get_watched_files returns correct list."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir_path = Path(tmpdir)

        # Create multiple .cal files
        (tmpdir_path / "policy1.cal").write_text("Law One {}")
        (tmpdir_path / "policy2.cal").write_text("Law Two {}")
        (tmpdir_path / "readme.txt").write_text("Not a policy")

        watcher = PolicyFileWatcher(watch_directory=tmpdir, poll_interval=0.5)
        await watcher.start()

        # Wait for initial scan
        await asyncio.sleep(0.6)

        watched_files = watcher.get_watched_files()
        watched_names = [f.name for f in watched_files]

        assert len(watched_files) == 2
        assert "policy1.cal" in watched_names
        assert "policy2.cal" in watched_names
        assert "readme.txt" not in watched_names

        print(f"✓ Watched files list correct: {watched_names}")

        await watcher.stop()


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
