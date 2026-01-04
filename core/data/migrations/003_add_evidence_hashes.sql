-- Migration 003: Add Evidence Hashes
-- Adds SHA-256 hashes to evidence for deduplication and integrity verification

-- Add hash column to evidence table
-- ALTER TABLE evidence ADD COLUMN content_hash TEXT;

-- Create index for fast hash lookups (deduplication)
-- CREATE INDEX idx_evidence_hash ON evidence(content_hash);

-- Add created_at column (previously only had timestamp)
ALTER TABLE evidence ADD COLUMN created_at TEXT DEFAULT (datetime('now'));
