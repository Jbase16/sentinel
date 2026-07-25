-- Migration 005: Issue Suppression Flag
-- Adds a non-destructive suppression flag to the issues table so the
-- finding-verification gate (core/toolkit/finding_verifier.py) can HIDE refuted
-- false-positives from operator-facing results WITHOUT deleting them.
--
-- Why a side column instead of mutating the row:
--   An issue's primary key is sha256(canonical_json(issue)) — a content hash.
--   Re-saving an annotated issue would change its hash and INSERT a new row
--   rather than update the original. A separate `suppressed` column is updated
--   by id (UPDATE ... WHERE id = ?) without touching the hashed payload, so the
--   row — and its evidence — is preserved and recoverable (just set back to 0).

-- 0 = visible (default; all existing rows stay visible), 1 = suppressed/hidden.
ALTER TABLE issues ADD COLUMN suppressed INTEGER NOT NULL DEFAULT 0;

-- Index the common "visible issues for a session" query.
CREATE INDEX idx_issues_suppressed ON issues(session_id, suppressed);
