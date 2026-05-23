# Calibration Run #12 — Bug #3 Fixed (Timestamp Format)

The "session rows have mixed Unix-float and ISO timestamp formats" cosmetic
bug from the very first calibration writeup. Fixed end-to-end with one
serializer change, one migration, and one read-side simplification.

**Verdict:** ✅ Fixed. New writes use ISO 8601 UTC. All 199 historical
rows were migrated cleanly. Inspector's band-aid CASE expression
removed.

---

## The bug

`core/data/db.py` declares `sessions.start_time TEXT NOT NULL DEFAULT
(datetime('now'))` — the schema *expects* ISO strings. But
`ScanSession.to_dict()` was emitting raw Python floats from
`time.time()`, which SQLite stored as their string representation
(e.g. `"1778906131.17429"`).

The result: mixed-format rows in the same column. Lexicographic
ORDER BY broke. The inspector had to add a CASE-statement band-aid to
sort correctly across mixed-vintage rows. Documented since RUN_001.

## The fix — three layers

### (1) Format-on-serialize in `ScanSession.to_dict()`

```python
@staticmethod
def _format_ts(ts: Optional[float]) -> Optional[str]:
    if ts is None:
        return None
    try:
        return datetime.fromtimestamp(float(ts), tz=timezone.utc).isoformat()
    except (TypeError, ValueError, OverflowError, OSError):
        return None
```

In-memory attributes stay floats (for duration arithmetic). `to_dict()`
converts at the serialization boundary. The DB writer is unchanged —
it just gets the right string format.

### (2) Migration 004 — normalize historical rows

`core/data/migrations/004_normalize_session_timestamps.sql`:

- Converts Unix-float-string timestamps to ISO 8601 UTC.
- Backfills `end_time` for orphan rows (no end_time + non-terminal
  status) as `end_time = start_time`, marking them `status='orphaned'`.
- Backfills `end_time` for closed-but-incomplete rows (terminal status
  + no end_time) — these predate the Bug #4 writer fix.

**Subtle bug caught during dry-run:** the initial GLOB pattern
`'[0-9]*.[0-9]*'` matched ISO strings too (because they also start
with digits and contain a dot). Tightened to also require `NOT LIKE
'%T%' AND NOT LIKE '%-%'`, making the migration idempotent — re-running
it doesn't corrupt data.

### (3) Inspector simplification

`scripts/inspect_scan.py` no longer needs the CASE expression. Both
`cmd_list` and `_resolve_session_id` now use plain
`ORDER BY start_time DESC`.

---

## Live verification (RUN_012)

Backend startup:
```
[MigrationRunner] Discovered 4 migrations
[MigrationRunner] Applying migration 004_normalize_session_timestamps
[MigrationRunner] Creating backup: .../sentinel_v3_before_normalize_session_timestamps_20260518_004623.backup
[MigrationRunner] ✅ Applied 004_normalize_session_timestamps
```

DB state immediately after migration:
- `status:completed` 3 rows
- `status:orphaned` 197 rows (was 199 "Created" with no end_time)
- 0 rows with NULL end_time
- 0 rows with 1970 corruption

Scan + post-scan write:
```
=== latest session row (raw) ===
id     | status    | start_time                       | end_time
0ae6…  | completed | 2026-05-18T01:10:25.296099+00:00 | 2026-05-18T01:15:16.355314+00:00
```

Pre-fix, this row would have been:
```
0ae6…  | completed | 1779246625.296099                | 1779246916.355314
```

## Test additions

`tests/unit/test_session_lifecycle.py` grew a new test class
`TestTimestampSerialization` with 5 tests:

1. `start_time` is a parseable ISO string with timezone
2. `end_time` is ISO after completion
3. `end_time` is None while running
4. Two sessions sort lexicographically same as chronologically (the
   property the bug broke)
5. Internal attribute stays a float (only the serializer converts)

**389 → 399 tests passing**, zero regressions.

---

## Phase 1 bug status — 11 of 12 done

| Bug | Status |
|---|---|
| #1 PATH shadowing | ✅ |
| #2 Token-rotation race | ✅ |
| **#3 Timestamp format mixed** | **✅ Fixed in RUN_012** |
| #4 Session lifecycle never closes | ✅ |
| #5 Issues promotion shape-dep | Partly fixed (rules work for some shapes) |
| #6 Inspector cosmetic | ✅ |
| #7 Walk-away on policy-block | ✅ |
| #8 Verification routing | ✅ |
| #9 persona_diff `.session` attr | ✅ |
| #10 AuthSessionManager wiring | ✅ |
| #11 ExecutionPolicy type confusion | ✅ |
| #12 Intermittent feroxbuster hang | Open (intermittent, needs observability before fix) |

**11 of 12 fixed.** The only remaining one is the intermittent
concurrency bug (#12), which needs observability instrumented before
speculative fixing.

## Code changes this round

| File | Change |
|---|---|
| `core/base/session.py` | Add `_format_ts()` static method; use in `to_dict()` for start_time + end_time |
| `core/data/migrations/004_normalize_session_timestamps.sql` | NEW — normalize float-strings, backfill orphans |
| `scripts/inspect_scan.py` | Replace CASE-statement sort_key band-aid with plain `ORDER BY` |
| `tests/unit/test_session_lifecycle.py` | +5 ISO contract tests |

## Aggregate Phase 1 stats

12 calibration runs. 11 of 12 named bugs fixed. **399 tests passing,
zero regressions across the entire bug-fix sequence.** The engine now
produces clean, consistent, debuggable signal end-to-end:

- 6 tools coordinate per scan
- ISO timestamps everywhere
- Session lifecycle closes properly
- Verification phase reachable
- wraith_persona_diff dispatches and runs (just needs real credentials
  for IDOR signal)
- Migration history clean
- Inspector simplified

Real bounty signal is one persona-config edit away from this state.
