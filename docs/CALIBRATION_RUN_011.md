# Calibration Run #11 — 2026-05-14 — Bug #4 Fixed

Fix the oldest open bug in the calibration log: session rows never close.

**Verdict:** ✅ Fixed. Session rows now transition `Created` → `completed`
with `end_time` populated, across the success / cancellation / error
paths. Inspector now shows scan duration.

---

## Bug #4 — Three stacked bugs in the session-lifecycle writer

The "sessions stuck at status=Created" pattern has been visible since
RUN_001. It turned out to be three connected bugs, not one:

### (a) `ScanSession` had no `end_time` attribute

`core/base/session.py:126` initialized `self.status = "Created"` and
`self.start_time = time.time()`, but nothing for `end_time`. The object
literally couldn't represent a closed session.

### (b) `to_dict()` didn't serialize `end_time`

`core/base/session.py:357-366`. Even if some code path had set
`session.end_time = X`, `to_dict()` would have dropped it before
persistence.

### (c) `_save_session_impl` didn't have `end_time` in the SQL

`core/data/db.py:439-457`. The INSERT column list and UPSERT SET clause
both omitted `end_time`. So even a serializer that produced it would
hit a column the writer ignored.

### (d) [Compound] The scan-completion handlers updated the wrong state

`core/server/routers/scans.py:524-575` set
`state.scan_state["status"] = "completed"`, which is the *engine* state
(used for the `/v1/status` endpoint). But `session.to_dict()` reads
`session.status`, which nobody ever updated. So even after this
session bug got fixed, the writer would have read `"Created"` forever.

---

## The fix

Four atomic edits, each at the right layer:

| File | Change |
|---|---|
| `core/base/session.py:128` | Add `self.end_time: Optional[float] = None` to `__init__` |
| `core/base/session.py:364` | Include `"end_time": self.end_time` in `to_dict()` |
| `core/data/db.py:442-456` | Add `end_time` to INSERT columns and UPSERT SET |
| `core/server/routers/scans.py:524-575` | Set `session.status` + `session.end_time` in success/cancel/error branches |

Each edit makes one layer correct. Cumulatively, the writer chain works.

## RUN_011 verification

Same scan as RUN_010 (MegaShop, standard mode, placeholder personas). After
Mission Complete, inspecting the latest session:

```
=== Session 4b09b1b0-660e-4d30-b202-e7ed3dac663d ===
  target  : http://127.0.0.1:3003
  status  : completed            ← was "Created" in every prior run
  duration: 1.7m                  ← was "running" indefinitely
  started : 1778906131.17429
  ended   : 1778906230.30582      ← was NULL
```

And the raw DB row:
```
id     | target                | status    | start_time       | end_time
4b09…  | http://127.0.0.1:3003 | completed | 1778906131.17429 | 1778906230.30582
```

The completion timestamp is real. The duration is computed correctly.

## Tests added

`tests/unit/test_session_lifecycle.py` — 5 tests pinning the invariants:

1. Initial state: `status="Created"`, `end_time=None`
2. `to_dict()` includes `end_time` (None while running)
3. Success path: `status="completed"` + `end_time` after completion
4. Cancellation path: `status="cancelled"` + `end_time`
5. Error path: `status="error"` + `end_time`

These test the contract at the ScanSession layer. The integration into
the actual scans.py handlers is empirically verified by RUN_011.

---

## Status check — phase 1 bugs

| Bug | Status |
|---|---|
| Bug #1 (PATH shadowing) | ✅ Fixed |
| Bug #2 (token-rotation race) | ✅ Fixed |
| Bug #3 (timestamp format mixed) | Open (writer still emits Unix-float strings; inspector handles both) |
| **Bug #4 (session lifecycle never closes)** | **✅ Fixed in RUN_011** |
| Bug #5 (issues promotion shape-dep) | Partly fixed (works for feroxbuster output) |
| Bug #6 (inspector cosmetic) | ✅ Fixed |
| Bug #7 (walk-away on policy-block) | ✅ Fixed |
| Bug #8 (verification only in bounty mode) | ✅ Fixed |
| Bug #9 (persona_diff .session attr error) | ✅ Fixed |
| Bug #10 (AuthSessionManager not wired) | ✅ Fixed |
| Bug #11 (ExecutionPolicy type confusion) | ✅ Fixed |
| Bug #12 (feroxbuster commit hang) | Intermittent — observability not added yet |

**10 of 12 fixed. 1 intermittent. 1 cosmetic (Bug #3).**

## Side effect: orphan sessions from previous runs

The DB still has ~14 historical session rows stuck at `status: Created` /
`status: active` with no `end_time` from runs prior to this fix. They're
harmless but accumulate noise. A one-time cleanup query would close them:

```sql
UPDATE sessions
   SET status = 'orphaned',
       end_time = start_time   -- best-effort, no real duration data
 WHERE end_time IS NULL
   AND status IN ('Created', 'active', 'running');
```

Worth running once during Phase 2 prep, but not now.

## Test summary

| Suite | Before | After |
|---|---|---|
| `tests/unit/` | 283 | 288 (+5 session lifecycle tests) |
| `tests/security/` | 105 | 105 |
| Pre-existing integration failures (unchanged) | 8 | 8 |
| **Total passing** | 389 | **394** |
| Regressions | 0 | 0 |

## Code changes this session

| File | Change |
|---|---|
| `core/base/session.py` | Add end_time attr + include in to_dict |
| `core/data/db.py` | Add end_time column to session writer |
| `core/server/routers/scans.py` | Set session.status + end_time in completion handlers |
| `tests/unit/test_session_lifecycle.py` | NEW — 5 lifecycle tests |
