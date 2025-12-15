# ============================================================================
# core/data/issues_store.py
# Issues Store - Confirmed Exploitable Vulnerability Storage
# ============================================================================
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
# ============================================================================

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
        super().__init__()
        self._issues = []
        self.session_id = session_id
        self.db = Database.instance()
        try:
            asyncio.get_running_loop()
            create_safe_task(self._init_load(), name="issues_init_load")
        except RuntimeError:
            pass

    async def _init_load(self):
        # DB init is idempotent/shared
        await self.db.init()
        if self.session_id:
            loaded = await self.db.get_issues(self.session_id)
        else:
            loaded = await self.db.get_all_issues()
        self._issues = loaded
        self.issues_changed.emit()

    def add_issue(self, issue: dict):
        self._issues.append(issue)
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
        return list(self._issues)


    def clear(self):
        self._issues = []
        self.issues_changed.emit()
    
    def replace_all(self, issues: list):
        """Replace all issues with a new list"""
        self._issues = list(issues)
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