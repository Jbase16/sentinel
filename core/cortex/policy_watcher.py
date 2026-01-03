"""
Policy File Watcher (core/cortex/policy_watcher.py)

PURPOSE:
Monitors CAL policy files for changes and automatically reloads them
into the ArbitrationEngine without requiring server restart.

FEATURES:
- Watches assets/laws/*.cal files
- Debounces rapid changes (e.g., editor save patterns)
- Logs reload events for audit trail
- Non-blocking async implementation
"""

import asyncio
import logging
from pathlib import Path
from typing import Optional, Set
import time

logger = logging.getLogger(__name__)


class PolicyFileWatcher:
    """
    Watches CAL policy files and triggers reload on changes.

    Uses polling-based approach (compatible with all filesystems).
    For production, consider using watchdog library for inotify support.
    """

    def __init__(self, watch_directory: str = "assets/laws", poll_interval: float = 2.0):
        """
        Args:
            watch_directory: Directory to watch for .cal files
            poll_interval: How often to check for changes (seconds)
        """
        self.watch_directory = Path(watch_directory)
        self.poll_interval = poll_interval
        self._running = False
        self._task: Optional[asyncio.Task] = None
        self._file_mtimes: dict[Path, float] = {}
        self._debounce_delay = 0.5  # Wait 500ms after last change before reloading
        self._pending_reloads: Set[Path] = set()
        self._reload_callback: Optional[callable] = None

    def set_reload_callback(self, callback: callable):
        """
        Set callback function to invoke when policies need reloading.

        Args:
            callback: Async function called with no arguments
        """
        self._reload_callback = callback

    async def start(self):
        """Start watching for file changes."""
        if self._running:
            logger.warning("[PolicyWatcher] Already running")
            return

        self._running = True
        self._task = asyncio.create_task(self._watch_loop())
        logger.info(f"[PolicyWatcher] Started watching {self.watch_directory}")

    async def stop(self):
        """Stop watching for file changes."""
        if not self._running:
            return

        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("[PolicyWatcher] Stopped")

    async def _watch_loop(self):
        """Main polling loop."""
        try:
            # Initialize file modification times
            self._scan_files()

            while self._running:
                await asyncio.sleep(self.poll_interval)

                changed_files = self._detect_changes()
                if changed_files:
                    logger.info(f"[PolicyWatcher] Detected changes in {len(changed_files)} files")
                    self._pending_reloads.update(changed_files)

                    # Debounce: wait a bit to see if more changes arrive
                    await asyncio.sleep(self._debounce_delay)

                    # Trigger reload if callback is set
                    if self._reload_callback and self._pending_reloads:
                        files_str = ", ".join([f.name for f in self._pending_reloads])
                        logger.info(f"[PolicyWatcher] Reloading policies due to changes in: {files_str}")

                        try:
                            await self._reload_callback()
                            logger.info("[PolicyWatcher] Policies reloaded successfully")
                        except Exception as e:
                            logger.error(f"[PolicyWatcher] Reload failed: {e}")

                        self._pending_reloads.clear()

        except asyncio.CancelledError:
            logger.debug("[PolicyWatcher] Watch loop cancelled")
        except Exception as e:
            logger.error(f"[PolicyWatcher] Watch loop error: {e}")

    def _scan_files(self):
        """Scan directory and record current modification times."""
        if not self.watch_directory.exists():
            logger.warning(f"[PolicyWatcher] Directory not found: {self.watch_directory}")
            return

        for cal_file in self.watch_directory.glob("*.cal"):
            try:
                mtime = cal_file.stat().st_mtime
                self._file_mtimes[cal_file] = mtime
            except OSError as e:
                logger.warning(f"[PolicyWatcher] Cannot stat {cal_file}: {e}")

    def _detect_changes(self) -> Set[Path]:
        """
        Check for file changes.

        Returns:
            Set of files that have been modified, added, or deleted
        """
        if not self.watch_directory.exists():
            return set()

        changed_files = set()
        current_files = set(self.watch_directory.glob("*.cal"))

        # Check for new or modified files
        for cal_file in current_files:
            try:
                current_mtime = cal_file.stat().st_mtime
                previous_mtime = self._file_mtimes.get(cal_file)

                if previous_mtime is None:
                    # New file
                    logger.debug(f"[PolicyWatcher] New file detected: {cal_file.name}")
                    changed_files.add(cal_file)
                    self._file_mtimes[cal_file] = current_mtime
                elif current_mtime > previous_mtime:
                    # Modified file
                    logger.debug(f"[PolicyWatcher] Modified file detected: {cal_file.name}")
                    changed_files.add(cal_file)
                    self._file_mtimes[cal_file] = current_mtime

            except OSError as e:
                logger.warning(f"[PolicyWatcher] Cannot stat {cal_file}: {e}")

        # Check for deleted files
        deleted_files = set(self._file_mtimes.keys()) - current_files
        if deleted_files:
            for deleted_file in deleted_files:
                logger.debug(f"[PolicyWatcher] Deleted file detected: {deleted_file.name}")
                changed_files.add(deleted_file)
                del self._file_mtimes[deleted_file]

        return changed_files

    def get_watched_files(self) -> list[Path]:
        """Get list of currently watched files."""
        return list(self._file_mtimes.keys())


# Singleton instance
_policy_watcher: Optional[PolicyFileWatcher] = None


def get_policy_watcher() -> PolicyFileWatcher:
    """Get the global PolicyFileWatcher singleton."""
    global _policy_watcher
    if _policy_watcher is None:
        _policy_watcher = PolicyFileWatcher()
    return _policy_watcher
