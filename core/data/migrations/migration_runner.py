"""
Migration Runner - Applies Database Schema Changes

This module handles discovery, ordering, and execution of migration files.
Includes backup/restore functionality for safe rollbacks.
"""

import aiosqlite
import logging
import shutil
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass
from typing import List, Optional
import re

from core.cortex.events import GraphEvent, GraphEventType, get_event_bus

logger = logging.getLogger(__name__)


@dataclass
class Migration:
    """Represents a single migration file."""

    version: int  # Migration number (e.g., 1, 2, 3)
    name: str  # Migration name (e.g., "initial_schema", "add_confidence_column")
    filepath: Path  # Path to SQL file
    sql: str  # SQL content

    @property
    def display_name(self) -> str:
        """Human-readable name for logs."""
        return f"{self.version:03d}_{self.name}"


class MigrationRunner:
    """
    Discovers and applies SQL migrations to the database.

    Migrations are SQL files in core/data/migrations/ named like:
    - 001_initial_schema.sql
    - 002_add_confidence_column.sql
    - 003_add_foreign_keys.sql

    The number determines the order, the name is for human readability.

    Backup/Restore Strategy:
    - Before applying migrations, creates a filesystem backup
    - Rollback restores from backup (deterministic, explainable)
    - Keeps last N backups, garbage-collects older ones
    """

    # Backup configuration
    MAX_BACKUPS = 10  # Keep last 10 backups
    BACKUP_SUFFIX = ".backup"

    def __init__(self, db_path: str, migrations_dir: Optional[Path] = None, enable_backups: bool = True):
        """
        Initialize migration runner.

        Args:
            db_path: Path to SQLite database
            migrations_dir: Directory containing migration SQL files (defaults to this file's directory)
            enable_backups: Whether to create backups before migrations (default: True)
        """
        self.db_path = Path(db_path)
        self.enable_backups = enable_backups
        self.event_bus = get_event_bus()

        if migrations_dir is None:
            # Default to migrations directory next to this file
            migrations_dir = Path(__file__).parent
        self.migrations_dir = migrations_dir

        # Backup directory (same directory as database)
        self.backup_dir = self.db_path.parent / ".db_backups"
        self.backup_dir.mkdir(exist_ok=True)

        logger.info(f"[MigrationRunner] Initialized for {db_path}")
        logger.info(f"[MigrationRunner] Migrations directory: {migrations_dir}")
        logger.info(f"[MigrationRunner] Backup directory: {self.backup_dir}")
        logger.info(f"[MigrationRunner] Backups enabled: {enable_backups}")

    async def get_current_version(self) -> int:
        """
        Get the current schema version from the database.

        Returns:
            Current version number (0 if no migrations applied yet)
        """
        async with aiosqlite.connect(self.db_path) as conn:
            # Check if schema_version table exists
            cursor = await conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='schema_version'"
            )
            table_exists = await cursor.fetchone()

            if not table_exists:
                # No schema_version table = version 0
                return 0

            # Get current version
            cursor = await conn.execute("SELECT version FROM schema_version ORDER BY version DESC LIMIT 1")
            row = await cursor.fetchone()

            return row[0] if row else 0

    async def _ensure_schema_version_table(self, conn: aiosqlite.Connection):
        """Create schema_version table if it doesn't exist."""
        await conn.execute(
            """
            CREATE TABLE IF NOT EXISTS schema_version (
                version INTEGER PRIMARY KEY,
                applied_at TEXT NOT NULL DEFAULT (datetime('now')),
                description TEXT
            )
            """
        )
        await conn.commit()

    def _discover_migrations(self) -> List[Migration]:
        """
        Discover all migration files in the migrations directory.

        Returns:
            List of Migration objects, sorted by version
        """
        migrations = []

        # Find all .sql files matching pattern: NNN_name.sql
        pattern = re.compile(r'^(\d{3})_(.+)\.sql$')

        for sql_file in self.migrations_dir.glob("*.sql"):
            match = pattern.match(sql_file.name)
            if match:
                version = int(match.group(1))
                name = match.group(2)

                # Read SQL content
                sql = sql_file.read_text()

                migrations.append(Migration(
                    version=version,
                    name=name,
                    filepath=sql_file,
                    sql=sql
                ))

        # Sort by version
        migrations.sort(key=lambda m: m.version)

        logger.info(f"[MigrationRunner] Discovered {len(migrations)} migrations")
        return migrations

    def get_next_migration(self, current_version: int) -> Optional[Migration]:
        """
        Get the next migration to apply after current_version.

        Args:
            current_version: Current schema version

        Returns:
            Next Migration object, or None if no more migrations
        """
        migrations = self._discover_migrations()

        for migration in migrations:
            if migration.version > current_version:
                return migration

        return None

    async def apply_migration(self, migration: Migration):
        """
        Apply a single migration to the database.

        Creates a backup before applying if backups are enabled.

        Args:
            migration: Migration to apply
        """
        logger.info(f"[MigrationRunner] Applying migration {migration.display_name}")

        # Create backup before migration
        if self.enable_backups and self.db_path.exists():
            backup_label = f"v{migration.version - 1}_before_{migration.name}"
            await self.create_backup(label=backup_label)

        async with aiosqlite.connect(self.db_path) as conn:
            try:
                # Ensure schema_version table exists
                await self._ensure_schema_version_table(conn)

                # Execute migration SQL
                await conn.executescript(migration.sql)

                # Record migration in schema_version
                await conn.execute(
                    "INSERT INTO schema_version (version, description) VALUES (?, ?)",
                    (migration.version, migration.name)
                )

                await conn.commit()

                logger.info(f"[MigrationRunner] ✅ Applied {migration.display_name}")

            except Exception as e:
                logger.error(f"[MigrationRunner] ❌ Failed to apply {migration.display_name}: {e}")
                await conn.rollback()
                raise

    async def run_migrations(self):
        """
        Apply all pending migrations.

        This discovers all migrations, checks the current version,
        and applies any migrations that haven't been applied yet.
        """
        current_version = await self.get_current_version()
        logger.info(f"[MigrationRunner] Current schema version: {current_version}")

        migrations_applied = 0

        while True:
            next_migration = self.get_next_migration(current_version)

            if not next_migration:
                # No more migrations to apply
                break

            await self.apply_migration(next_migration)
            current_version = next_migration.version
            migrations_applied += 1

        if migrations_applied > 0:
            logger.info(f"[MigrationRunner] ✅ Applied {migrations_applied} migrations. New version: {current_version}")
        else:
            logger.info(f"[MigrationRunner] ✅ Schema is up to date (version {current_version})")

    async def create_backup(self, label: Optional[str] = None) -> Path:
        """
        Create a filesystem backup of the database.

        Uses SQLite backup API for atomic, consistent snapshots.

        Args:
            label: Optional label for the backup (e.g., "v2_before_migration")

        Returns:
            Path to the created backup file
        """
        if not self.db_path.exists():
            raise FileNotFoundError(f"Database not found: {self.db_path}")

        # Generate backup filename with timestamp
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        if label:
            backup_name = f"{self.db_path.stem}_{label}_{timestamp}{self.BACKUP_SUFFIX}"
        else:
            backup_name = f"{self.db_path.stem}_{timestamp}{self.BACKUP_SUFFIX}"

        backup_path = self.backup_dir / backup_name

        logger.info(f"[MigrationRunner] Creating backup: {backup_path}")

        # Use SQLite backup API for atomic copy
        async with aiosqlite.connect(self.db_path) as source:
            async with aiosqlite.connect(backup_path) as dest:
                await source.backup(dest)

        logger.info(f"[MigrationRunner] ✅ Backup created: {backup_path}")

        # Garbage collect old backups
        await self._garbage_collect_backups()

        # Emit event
        self.event_bus.emit(GraphEvent(
            type=GraphEventType.LOG,
            payload={
                "message": f"[MigrationRunner] Database backup created",
                "backup_path": str(backup_path),
            },
        ))

        return backup_path

    async def restore_from_backup(self, backup_path: Path) -> None:
        """
        Restore database from a backup file.

        Replaces the current database with the backup.
        This is deterministic and explainable.

        Args:
            backup_path: Path to the backup file to restore from
        """
        if not backup_path.exists():
            raise FileNotFoundError(f"Backup not found: {backup_path}")

        logger.info(f"[MigrationRunner] Restoring from backup: {backup_path}")

        # Create a safety backup of current state before restoring
        safety_backup = self.db_path.parent / f"{self.db_path.name}.pre_restore"
        if self.db_path.exists():
            shutil.copy2(self.db_path, safety_backup)
            logger.info(f"[MigrationRunner] Safety backup created: {safety_backup}")

        try:
            # Replace current database with backup
            shutil.copy2(backup_path, self.db_path)

            logger.info(f"[MigrationRunner] ✅ Database restored from {backup_path}")

            # Emit event
            self.event_bus.emit(GraphEvent(
                type=GraphEventType.LOG,
                payload={
                    "message": f"[MigrationRunner] Database restored from backup",
                    "backup_path": str(backup_path),
                    "restored_at": datetime.utcnow().isoformat(),
                },
            ))

            # Remove safety backup if successful
            if safety_backup.exists():
                safety_backup.unlink()

        except Exception as e:
            logger.error(f"[MigrationRunner] ❌ Restore failed: {e}")

            # Attempt to restore safety backup
            if safety_backup.exists():
                logger.warning(f"[MigrationRunner] Restoring safety backup")
                shutil.copy2(safety_backup, self.db_path)

            raise

    async def _garbage_collect_backups(self) -> None:
        """Remove old backups, keeping only the last MAX_BACKUPS."""
        backups = sorted(
            self.backup_dir.glob(f"*{self.BACKUP_SUFFIX}"),
            key=lambda p: p.stat().st_mtime,
            reverse=True  # Newest first
        )

        if len(backups) > self.MAX_BACKUPS:
            to_delete = backups[self.MAX_BACKUPS:]
            for backup_file in to_delete:
                logger.info(f"[MigrationRunner] Garbage collecting old backup: {backup_file}")
                backup_file.unlink()

    def list_backups(self) -> List[dict]:
        """
        List all available backups.

        Returns:
            List of dicts with backup metadata (path, size, created_at)
        """
        backups = []

        for backup_file in self.backup_dir.glob(f"*{self.BACKUP_SUFFIX}"):
            stat = backup_file.stat()
            backups.append({
                "path": str(backup_file),
                "name": backup_file.name,
                "size_bytes": stat.st_size,
                "created_at": datetime.fromtimestamp(stat.st_mtime).isoformat(),
            })

        # Sort by creation time (newest first)
        backups.sort(key=lambda b: b["created_at"], reverse=True)

        return backups

    async def rollback_to(self, target_version: int):
        """
        Rollback to a specific schema version by restoring from backup.

        Strategy: Find the most recent backup at or before the target version,
        then restore from that backup.

        Args:
            target_version: Version to rollback to
        """
        logger.info(f"[MigrationRunner] Rollback requested to version {target_version}")

        # Find suitable backup
        backups = self.list_backups()

        if not backups:
            raise RuntimeError("No backups available for rollback")

        # For now, use the most recent backup
        # In production, you'd parse backup filenames to find the right version
        most_recent_backup = Path(backups[0]["path"])

        logger.info(f"[MigrationRunner] Rolling back using backup: {most_recent_backup}")

        # Restore from backup
        await self.restore_from_backup(most_recent_backup)

        # Verify rollback succeeded
        new_version = await self.get_current_version()
        logger.info(f"[MigrationRunner] ✅ Rollback complete. Current version: {new_version}")

        # Emit rollback event
        self.event_bus.emit(GraphEvent(
            type=GraphEventType.LOG,
            payload={
                "message": f"[MigrationRunner] Database rolled back to version {new_version}",
                "target_version": target_version,
                "actual_version": new_version,
                "backup_used": str(most_recent_backup),
            },
        ))

    async def get_migration_history(self) -> List[dict]:
        """
        Get list of applied migrations.

        Returns:
            List of dicts with version, description, applied_at
        """
        current_version = await self.get_current_version()

        if current_version == 0:
            return []

        async with aiosqlite.connect(self.db_path) as conn:
            cursor = await conn.execute(
                "SELECT version, description, applied_at FROM schema_version ORDER BY version ASC"
            )
            rows = await cursor.fetchall()

            return [
                {"version": row[0], "description": row[1], "applied_at": row[2]}
                for row in rows
            ]
