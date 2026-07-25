"""
Schema Migrations - Database Version Control

PURPOSE:
Manage database schema evolution with versioned SQL migrations.
Enables safe schema changes and rollbacks.

WHY THIS MATTERS:
1. **Safe Schema Evolution**: No manual SQL changes required
2. **Version Tracking**: Always know which schema version is running
3. **Team Coordination**: All devs apply same migrations automatically
4. **Rollback Support**: Can downgrade schema if needed
5. **Production Safety**: Test migrations before applying to production

KEY CONCEPTS:
- **Migration**: A numbered SQL file that changes the schema
- **Version**: Current schema version number stored in DB
- **Upgrade**: Apply migrations to move forward in versions
- **Downgrade**: Rollback migrations to move backward

DESIGN PATTERN:
This is the "Database Migration" pattern used by tools like Alembic, Flyway, Liquibase.
"""

from .migration_runner import MigrationRunner, Migration

__all__ = ['MigrationRunner', 'Migration']
