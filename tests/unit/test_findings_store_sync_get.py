"""
Regression test for the FindingsStore sync-then-async race surfaced by
Calibration Run #50.

Before the fix, calling `store.add_finding(f)` from inside an asyncio
event loop scheduled the in-memory append as a background task —
meaning an immediate `store.get(id)` on the same line would return None.
The no-loop branch had always done a synchronous append; the in-loop
branch now does too. Heavier work (dedup, persistence) still runs
async but operates on the already-in-memory finding.

Real-world manifestation:
  In calibration_50_end_to_end.py, step 2 did:
      store.add_finding(picked)
      vsess = create_session_from_finding(finding_id)
  which raised ValueError("finding not found") because the in-loop
  add_finding hadn't actually appended yet. Pipeline ran 1117 unit
  tests green but failed on the first integration attempt.
"""
from __future__ import annotations

import asyncio


def test_sync_add_get_outside_event_loop():
    """Baseline: with no running event loop, add → get works
    immediately. This branch was always correct; pinning it so it
    doesn't regress."""
    from core.data.findings_store import FindingsStore

    store = FindingsStore()
    store.add_finding({"id": "regression-1", "type": "X"})
    f = store.get("regression-1")
    assert f is not None
    assert f["id"] == "regression-1"


def test_sync_add_get_inside_event_loop():
    """THE REGRESSION TEST. Inside asyncio.run, the moment add_finding
    returns, get() must find the finding. Before the fix this returned
    None because add_finding scheduled the append as a background task
    that hadn't run yet."""
    from core.data.findings_store import FindingsStore

    async def main():
        store = FindingsStore()
        # Inside an asyncio context — this is the path that used to fail.
        store.add_finding({"id": "regression-2", "type": "Y"})
        f = store.get("regression-2")
        return f

    result = asyncio.run(main())
    assert result is not None, (
        "BUG: store.get() inside asyncio.run() returned None immediately "
        "after add_finding(). The sync-append in add_finding's in-loop "
        "branch is broken. Calibration #50 regression."
    )
    assert result["id"] == "regression-2"


def test_add_finding_inside_loop_sets_defaults_synchronously():
    """The basic annotation (is_duplicate=False, duplicate_info='NEW')
    is set synchronously so callers see a usable finding shape even
    before the async reannotation completes."""
    from core.data.findings_store import FindingsStore

    async def main():
        store = FindingsStore()
        store.add_finding({"id": "regression-3", "type": "Z"})
        f = store.get("regression-3")
        return f

    result = asyncio.run(main())
    # These keys should exist on the in-list dict even before async
    # reannotation runs (the test exits asyncio.run before any
    # background task gets to complete; the basic defaults must be
    # there from the sync path).
    assert "is_duplicate" in result
    assert "duplicate_info" in result


def test_no_duplicate_appended_when_async_reannotation_runs():
    """Defensive: when add_finding's sync path appends + the async
    reannotation runs, the finding must appear ONCE in the store,
    not twice. Pins the in-place-mutation contract."""
    from core.data.findings_store import FindingsStore

    async def main():
        store = FindingsStore()
        store.add_finding({"id": "regression-4", "type": "Z"})
        # Give the scheduled task a chance to run.
        await asyncio.sleep(0.1)
        return store.get_all()

    findings = asyncio.run(main())
    # Filter to just our test finding (other tests may have left state
    # on the singleton if this somehow runs with the shared instance).
    matching = [f for f in findings if f.get("id") == "regression-4"]
    assert len(matching) == 1, (
        f"Expected exactly 1 finding with id=regression-4 in store, "
        f"got {len(matching)}. Sync-then-async path is double-appending."
    )
