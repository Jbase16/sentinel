from core.utils.observer import Observable, Signal
from core.db import Database
import asyncio

class IssuesStore(Observable):
    """
    Tracks issues detected by AraUltra. Issues are higher-level
    concerns derived from findings or killchain data.
    """

    issues_changed = Signal()

    def __init__(self):
        super().__init__()
        self._issues = []
        self.db = Database.instance()
        try:
            asyncio.get_running_loop()
            asyncio.create_task(self._init_load())
        except RuntimeError:
            pass

    async def _init_load(self):
        # DB init is idempotent/shared
        await self.db.init()
        loaded = await self.db.get_all_issues()
        self._issues = loaded
        self.issues_changed.emit()

    def add_issue(self, issue: dict):
        self._issues.append(issue)
        asyncio.create_task(self.db.save_issue(issue))
        self.issues_changed.emit()

    def get_all(self):
        return list(self._issues)


    def clear(self):
        self._issues = []
        self.issues_changed.emit()
    
    def replace_all(self, issues: list):
        """Replace all issues with a new list"""
        self._issues = list(issues)
        for issue in issues:
            asyncio.create_task(self.db.save_issue(issue))
        self.issues_changed.emit()



issues_store = IssuesStore()