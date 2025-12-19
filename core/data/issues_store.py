"""Module issues_store: inline documentation for /Users/jason/Developer/sentinelforge/core/data/issues_store.py."""
#
# PURPOSE:
# Stores confirmed security issues that have been validated/exploited.
# These are the "real" vulnerabilities, not just potential findings.
#
# FINDINGS → ISSUES PROMOTION:
# 1. Tool discovers something (becomes a Finding)
# 2. AI or human analyzes it
# 3. If exploitable, promoted to Issue
# 4. Issue includes proof-of-concept and impact assessment
#
# WHAT MAKES AN ISSUE:
# - **Reproducible**: Can be triggered reliably
# - **Validated**: Confirmed through testing
# - **Impact assessed**: Severity and business risk determined
# - **Proof-of-concept**: Working exploit demonstrated
#
# ISSUE ATTRIBUTES:
# - Severity: CRITICAL, HIGH, MEDIUM, LOW
# - Type: SQLi, XSS, IDOR, RCE, etc.
# - Proof: Steps to reproduce / exploit code
# - Impact: What attacker could achieve
# - Remediation: How to fix it
#

from core.utils.observer import Observable, Signal
from core.data.db import Database
import asyncio
import logging
from core.utils.async_helpers import create_safe_task

logger = logging.getLogger(__name__)

class IssuesStore(Observable):
    """
    Tracks issues detected by AraUltra. Issues are higher-level
    concerns derived from findings or killchain data.
    """

    issues_changed = Signal()

    def __init__(self, session_id: str = None):
        """Function __init__."""
        super().__init__()
        self._issues = []
        self.session_id = session_id
        self.db = Database.instance()
        # Error handling block.
        try:
            asyncio.get_running_loop()
            create_safe_task(self._init_load(), name="issues_init_load")
        except RuntimeError:
            pass

    async def _init_load(self):
        # DB init is idempotent/shared
        """AsyncFunction _init_load."""
        try:
            await self.db.init()
            # Conditional branch.
            if self.session_id:
                loaded = await self.db.get_issues(self.session_id)
            else:
                loaded = await self.db.get_all_issues()
            self._issues = loaded
            self.issues_changed.emit()
        except (sqlite3.ProgrammingError, aiosqlite.Error, ValueError) as e:
            if "closed" in str(e).lower():
                return
            logger.error(f"[IssuesStore] DB error during init_load: {e}")
        except Exception as e:
            logger.error(f"[IssuesStore] Failed to load issues: {e}")

    def add_issue(self, issue: dict):
        """Function add_issue."""
        self._issues.append(issue)
        # Error handling block.
        try:
            asyncio.get_running_loop()
            create_safe_task(
                self.db.save_issue(issue, self.session_id),
                name="save_issue"
            )
        except RuntimeError:
            logger.warning("[IssuesStore] No event loop for async save")
        self.issues_changed.emit()

    def get_all(self):
        """Function get_all."""
        return list(self._issues)


    def clear(self):
        """Function clear."""
        self._issues = []
        self.issues_changed.emit()
    
    def replace_all(self, issues: list):
        """Replace all issues with a new list"""
        self._issues = list(issues)
        # Error handling block.
        try:
            asyncio.get_running_loop()
            for issue in issues:
                create_safe_task(
                    self.db.save_issue(issue, self.session_id),
                    name="replace_save_issue"
                )
        except RuntimeError:
            logger.warning("[IssuesStore] No event loop for async replace_all")
        self.issues_changed.emit()



issues_store = IssuesStore()