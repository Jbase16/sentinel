-- Migration 002: Add Confidence Scores
-- Adds confidence scoring to findings for ML-based vulnerability assessment

-- Add confidence column to findings table
ALTER TABLE findings ADD COLUMN confidence REAL DEFAULT 0.5;

-- Create index for querying high-confidence findings
CREATE INDEX idx_findings_confidence ON findings(confidence);

-- Add comment explaining confidence ranges
-- 0.0-0.3: Low confidence (likely false positive)
-- 0.3-0.7: Medium confidence (needs verification)
-- 0.7-1.0: High confidence (likely true positive)
