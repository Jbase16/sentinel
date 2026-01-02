"""
Migration Runner - Applies Database Schema Changes

This module handles discovery, ordering, and execution of migration files.
"""

import aiosqlite
import logging
from pathlib import Path
from dataclasses import dataclass
from typing import List, Optional
import re

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
    """

    def __init__(self, db_path: str, migrations_dir: Optional[Path] = None):
        """
        Initialize migration runner.

        Args:
            db_path: Path to SQLite database
            migrations_dir: Directory containing migration SQL files (defaults to this file's directory)
        """
        self.db_path = db_path

        if migrations_dir is None:
            # Default to migrations directory next to this file
            migrations_dir = Path(__file__).parent
        self.migrations_dir = migrations_dir

        logger.info(f"[MigrationRunner] Initialized for {db_path}")
        logger.info(f"[MigrationRunner] Migrations directory: {migrations_dir}")

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

        Args:
            migration: Migration to apply
        """
        logger.info(f"[MigrationRunner] Applying migration {migration.display_name}")

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

    async def rollback_to(self, target_version: int):
        """
        Rollback to a specific schema version.

        NOT YET IMPLEMENTED - This requires:
        1. DOWN migration SQL files (rollback scripts)
        2. Transaction safety guarantees
        3. Data migration logic

        For now, this raises NotImplementedError.

        Args:
            target_version: Version to rollback to
        """
        raise NotImplementedError(
            "Rollback not yet implemented. "
            "For now, rollbacks must be done manually with custom SQL."
        )

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
