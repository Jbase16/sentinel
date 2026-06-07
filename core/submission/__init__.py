"""
core/submission — Phase 6-PT3: bounty-submission API integration.

Target-agnostic submission pipeline. Operator-driven: NEVER
auto-submits. Builds drafts, posts them to the right platform's
report-creation endpoint, tracks submission state, persists local
records for audit + status-polling.
"""
from core.submission.h1_client import (
    H1SubmissionClient,
    SubmissionState,
    StoredSubmission,
    load_submission_log,
    save_submission_log,
)

__all__ = [
    "H1SubmissionClient",
    "SubmissionState",
    "StoredSubmission",
    "load_submission_log",
    "save_submission_log",
]
