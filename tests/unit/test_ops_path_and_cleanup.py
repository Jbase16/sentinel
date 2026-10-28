"""Hermetic checks for operations scripts that are unsafe to run against targets."""

from pathlib import Path
import pytest

from tools import lint_structure
from tools.ops import annotate_inline_comments, manual_scan, run_real_scan_headless
from tools.ops import strip_banners, verify_strategic_logging


ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.asyncio
async def test_manual_scan_drains_persistence_after_scan_failure(monkeypatch):
    calls = []

    class FakeDatabase:
        @staticmethod
        def instance():
            return FakeDatabase()

        async def init(self):
            calls.append("db.init")

        async def close(self):
            calls.append("db.close")

    class FakeBlackBox:
        @staticmethod
        def instance():
            return FakeBlackBox()

        async def shutdown(self):
            calls.append("blackbox.shutdown")

    class FakeScanner:
        def __init__(self, session):
            assert session == "session"

        async def run_all(self, target):
            calls.append("scan.run")
            raise RuntimeError("simulated scan failure")

    monkeypatch.setattr(manual_scan, "Database", FakeDatabase)
    monkeypatch.setattr(manual_scan, "BlackBox", FakeBlackBox)
    monkeypatch.setattr(manual_scan, "ScanSession", lambda target: "session")
    monkeypatch.setattr(manual_scan, "ScannerEngine", FakeScanner)

    await manual_scan.main()

    assert calls == ["db.init", "scan.run", "blackbox.shutdown", "db.close"]


def test_source_rewriters_default_to_repository_root(monkeypatch):
    roots = []

    def empty_sources(root):
        roots.append(root)
        return ()

    monkeypatch.setattr(strip_banners, "iter_source_files", empty_sources)
    monkeypatch.setattr(annotate_inline_comments, "iter_source_files", empty_sources)

    assert strip_banners.main() == 0
    assert annotate_inline_comments.main(["annotate_inline_comments.py"]) == 0
    assert roots == [ROOT, ROOT]


def test_structure_linter_allows_repository_entry_points():
    assert {"core", "scripts", "pyproject.toml", "Makefile"} <= lint_structure.ALLOWED_ROOT


@pytest.mark.asyncio
async def test_headless_probe_uses_current_event_subscription(monkeypatch):
    calls = []

    class FakeBus:
        def subscribe_sync(self, callback):
            calls.append("subscribe_sync")

    class FakeStrategos:
        def __init__(self, **kwargs):
            assert kwargs["event_bus"] is bus

        async def run_mission(self, **kwargs):
            calls.append("run_mission")

    bus = FakeBus()
    monkeypatch.setattr(run_real_scan_headless, "EventBus", lambda: bus)
    monkeypatch.setattr(run_real_scan_headless, "DecisionLedger", lambda: object())
    monkeypatch.setattr(run_real_scan_headless, "NarratorEngine", lambda **kwargs: object())
    monkeypatch.setattr(run_real_scan_headless, "Strategos", FakeStrategos)

    await run_real_scan_headless.main()

    assert calls == ["subscribe_sync", "run_mission"]


@pytest.mark.asyncio
async def test_strategic_logging_probe_uses_shared_event_bus(monkeypatch):
    calls = []
    bus = object()

    class FakeStore:
        _events = ()

        async def subscribe(self):
            if False:
                yield None

        def get_latest(self, count):
            return []

    class FakeStrategos:
        def __init__(self, **kwargs):
            assert kwargs["event_bus"] is bus

        async def run_mission(self, **kwargs):
            calls.append("run_mission")

    real_sleep = verify_strategic_logging.asyncio.sleep

    async def no_wait(seconds):
        await real_sleep(0)

    monkeypatch.setattr(verify_strategic_logging, "get_event_store", FakeStore)
    monkeypatch.setattr(verify_strategic_logging, "get_event_bus", lambda: bus)
    monkeypatch.setattr(verify_strategic_logging, "Strategos", FakeStrategos)
    monkeypatch.setattr(verify_strategic_logging.asyncio, "sleep", no_wait)

    await verify_strategic_logging.main()

    assert calls == ["run_mission"]
