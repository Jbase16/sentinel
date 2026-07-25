-- Migration 004: Normalize session timestamps to ISO 8601 UTC
--
-- Historical drift: the sessions.start_time column is TEXT with a default of
-- datetime('now') (ISO format). But ScanSession.to_dict() previously emitted
-- Unix epoch floats (e.g. "1778906131.17429"), which SQLite stored as strings.
-- The result was a mix of ISO and float-string formats in the same column,
-- which broke lexicographic ORDER BY.
--
-- See docs/CALIBRATION_RUN_004.md and RUN_011 for the full bug history.
--
-- This migration:
--   (1) Converts every float-string start_time/end_time to ISO 8601 UTC.
--   (2) For orphan sessions (no end_time + non-terminal status) — left behind
--       by pre-Bug-#4-fix code — marks them as 'orphaned' and sets
--       end_time = start_time as a best-effort backfill (zero duration).
--
-- After this migration runs, all rows are queryable with simple
-- "ORDER BY start_time DESC" and the inspector can drop its band-aid CASE.

-- Convert float-string start_time to ISO format.
--
-- Filter design: GLOB '[0-9]*.[0-9]*' alone is over-inclusive — ISO strings
-- like "2026-05-16T04:35:31.174Z" also start with digits and contain a dot.
-- We additionally require NOT LIKE '%T%' AND NOT LIKE '%-%' so the pattern
-- matches only Unix-epoch-float strings (e.g. "1778906131.17429") and
-- never re-encodes an ISO row. Without the extra filter, a re-run of this
-- migration would CAST '2025-12-31...' to REAL → 2025.0 → strftime epoch
-- → 1970-01-01T00:33:45 garbage.
UPDATE sessions
   SET start_time = strftime('%Y-%m-%dT%H:%M:%fZ', CAST(start_time AS REAL), 'unixepoch')
 WHERE start_time GLOB '[0-9]*.[0-9]*'
   AND start_time NOT LIKE '%T%'
   AND start_time NOT LIKE '%-%';

-- Same for end_time.
UPDATE sessions
   SET end_time = strftime('%Y-%m-%dT%H:%M:%fZ', CAST(end_time AS REAL), 'unixepoch')
 WHERE end_time GLOB '[0-9]*.[0-9]*'
   AND end_time NOT LIKE '%T%'
   AND end_time NOT LIKE '%-%';

-- Orphan sessions — left active/Created with no end_time. Mark them and
-- backfill end_time so the row reflects a closed (if unknown-duration) state.
UPDATE sessions
   SET status = 'orphaned',
       end_time = start_time
 WHERE end_time IS NULL
   AND status IN ('Created', 'active', 'running');

-- Closed-but-incomplete: sessions with a terminal status (completed/
-- cancelled/error) that nonetheless never had end_time written. These
-- predate the Bug #4 writer fix. Best-effort: set end_time = start_time
-- so they have a non-null timestamp; don't change the status.
UPDATE sessions
   SET end_time = start_time
 WHERE end_time IS NULL
   AND status IN ('completed', 'cancelled', 'error');
