"""
core/submission/h1_client.py — Phase 6-PT3.

HackerOne report-submission API client. Operator-driven; NEVER
auto-submits. Every operation that mutates a report's state on H1
goes through an explicit `submit(...)` call that must be invoked
by the operator after they've reviewed the draft.

What this module does:
  1. PREPARE a report locally without touching the wire (draft mode).
     The operator can review the JSON payload Sentinel would send.
  2. SUBMIT (operator-explicit only) — POST /v1/reports to HackerOne.
     Returns the submission ID + the H1 report URL.
  3. POLL — GET /v1/reports/{id} to check state (new, triaged,
     resolved, closed-as-duplicate, etc).
  4. PERSIST — every submission lands in
     ~/.sentinelforge/submissions/{report_id}.json with the full
     payload + state history for audit + reload.

What this module deliberately does NOT do:
  * Modify report content after submission (you can't un-submit on H1;
    edits happen via comments).
  * Auto-resubmit on errors. Submission errors must be reviewed.
  * Post comments / replies on existing reports. That's PT4.

The submission flow expects the operator to:
  1. Build a SubmissionRender via core.reporting.submission_render.
  2. Call client.prepare(...) → returns the JSON payload Sentinel
     would send. Operator reads it.
  3. Call client.submit(...) ONLY when the operator is satisfied.
  4. Optionally call client.refresh_status(report_id) to poll.

H1's POST /v1/reports schema (from their docs):
  {
    "data": {
      "type": "report",
      "attributes": {
        "team_handle": "airtable",
        "title": "Any authenticated user can read another user's...",
        "vulnerability_information": "...markdown body...",
        "impact": "...optional impact restatement...",
        "severity_rating": "high",  // optional
        "weakness_id": 639,  // optional CWE ID
      },
      "relationships": {
        "structured_scope": {  // OPTIONAL but recommended for filing
                              // against a specific scope item
          "data": {"id": "scope_id_here", "type": "structured-scope"}
        }
      }
    }
  }
"""
from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# ───────────────────────── persistence ─────────────────────────


SUBMISSION_DIR = Path.home() / ".sentinelforge" / "submissions"


class SubmissionState(str, Enum):
    """Local-side view of where a submission is in its lifecycle.

    H1's own state vocabulary is richer ('new', 'triaged', 'pending-
    program-review', 'needs-more-info', 'resolved', 'duplicate',
    'informative', 'not-applicable', 'spam'). We mirror those values
    directly when we can; DRAFT and FAILED are local-only.
    """
    DRAFT = "draft"               # built locally, never sent
    SUBMITTING = "submitting"     # POST in flight
    NEW = "new"                   # H1 received, no triage yet
    TRIAGED = "triaged"
    PENDING_PROGRAM_REVIEW = "pending-program-review"
    NEEDS_MORE_INFO = "needs-more-info"
    RESOLVED = "resolved"
    DUPLICATE = "duplicate"
    INFORMATIVE = "informative"
    NOT_APPLICABLE = "not-applicable"
    SPAM = "spam"
    FAILED = "failed"             # local-side: submission errored


@dataclass
class StoredSubmission:
    """One submission's local record. Persisted as JSON.

    Includes the OUTGOING payload (so we can replay/inspect) AND the
    INCOMING state history (so we can reconstruct when H1 changed
    things on us)."""
    program_handle: str
    title: str
    payload: Dict[str, Any]
    state: SubmissionState = SubmissionState.DRAFT
    h1_report_id: Optional[str] = None
    h1_report_url: Optional[str] = None
    created_at: float = field(default_factory=time.time)
    last_polled_at: Optional[float] = None
    state_history: List[Dict[str, Any]] = field(default_factory=list)
    last_error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "program_handle": self.program_handle,
            "title": self.title,
            "payload": self.payload,
            "state": self.state.value,
            "h1_report_id": self.h1_report_id,
            "h1_report_url": self.h1_report_url,
            "created_at": self.created_at,
            "last_polled_at": self.last_polled_at,
            "state_history": list(self.state_history),
            "last_error": self.last_error,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "StoredSubmission":
        return cls(
            program_handle=d["program_handle"],
            title=d["title"],
            payload=d["payload"],
            state=SubmissionState(d.get("state", "draft")),
            h1_report_id=d.get("h1_report_id"),
            h1_report_url=d.get("h1_report_url"),
            created_at=d.get("created_at", time.time()),
            last_polled_at=d.get("last_polled_at"),
            state_history=list(d.get("state_history", [])),
            last_error=d.get("last_error"),
        )

    def record_state_change(self, new_state: SubmissionState, note: str = ""):
        """Append a transition to state_history without overwriting."""
        self.state_history.append({
            "at": time.time(),
            "from": self.state.value,
            "to": new_state.value,
            "note": note,
        })
        self.state = new_state

    def _filename_for(self) -> Path:
        # Use H1 report id when we have it, otherwise a local id
        # derived from creation time + title hash.
        if self.h1_report_id:
            return SUBMISSION_DIR / f"h1-{self.h1_report_id}.json"
        import hashlib
        key = hashlib.sha256(
            f"{self.program_handle}-{self.title}-{self.created_at}".encode()
        ).hexdigest()[:12]
        return SUBMISSION_DIR / f"draft-{key}.json"


def save_submission_log(submission: StoredSubmission) -> Path:
    """Persist a StoredSubmission to disk. Atomic write — never leaves
    half-written files in the dir."""
    SUBMISSION_DIR.mkdir(parents=True, exist_ok=True)
    out = submission._filename_for()
    tmp = out.with_suffix(out.suffix + ".tmp")
    tmp.write_text(json.dumps(submission.to_dict(), indent=2))
    tmp.replace(out)
    return out


def load_submission_log(path: Path) -> StoredSubmission:
    return StoredSubmission.from_dict(json.loads(path.read_text()))


# ───────────────────────── client ─────────────────────────


H1_API_BASE = "https://api.hackerone.com/v1"


class H1SubmissionClient:
    """HackerOne report-submission client.

    Construct with `H1SubmissionClient.from_token_store()` to use the
    credentials already in ~/.sentinelforge. For tests, construct
    directly with the (handle, token) pair + an injected httpx.Client.

    The client is intentionally synchronous — submission is a high-
    consequence one-shot action, not a streaming workflow. Async makes
    the code harder to reason about for no benefit here.
    """

    def __init__(self, handle: str, token: str, *, transport=None, base_url: str = H1_API_BASE):
        import httpx
        self._handle = handle
        self._token = token
        self._base_url = base_url
        client_kwargs = {
            "auth": httpx.BasicAuth(handle, token),
            "timeout": 30.0,
            "headers": {
                "Accept": "application/json",
                "Content-Type": "application/json",
                "User-Agent": "SentinelForge/Phase6-submission",
            },
        }
        if transport is not None:
            client_kwargs["transport"] = transport
        self._client = httpx.Client(**client_kwargs)

    @classmethod
    def from_token_store(cls) -> "H1SubmissionClient":
        from core.intel import token_store
        cred = token_store.get("hackerone")
        if cred is None:
            raise RuntimeError(
                "No HackerOne credential found. "
                "Run `python3 scripts/sentinel_token.py add hackerone`."
            )
        return cls(cred.handle, cred.token)

    # ── draft preparation (no network) ──

    def prepare(
        self,
        *,
        program_handle: str,
        title: str,
        markdown_body: str,
        severity: Optional[str] = None,
        cwe_id: Optional[int] = None,
        structured_scope_id: Optional[str] = None,
        impact: Optional[str] = None,
    ) -> StoredSubmission:
        """Build the H1 POST /reports payload locally. NO NETWORK CALL.

        Returns a StoredSubmission in DRAFT state. The operator should
        inspect `.payload` before calling `submit(submission)`.
        """
        attrs: Dict[str, Any] = {
            "team_handle": program_handle,
            "title": title,
            "vulnerability_information": markdown_body,
        }
        if severity:
            attrs["severity_rating"] = severity
        if cwe_id is not None:
            attrs["weakness_id"] = cwe_id
        if impact:
            attrs["impact"] = impact

        payload: Dict[str, Any] = {
            "data": {
                "type": "report",
                "attributes": attrs,
            },
        }
        if structured_scope_id:
            payload["data"]["relationships"] = {
                "structured_scope": {
                    "data": {
                        "id": structured_scope_id,
                        "type": "structured-scope",
                    }
                }
            }

        submission = StoredSubmission(
            program_handle=program_handle,
            title=title,
            payload=payload,
            state=SubmissionState.DRAFT,
        )
        save_submission_log(submission)
        return submission

    # ── submit (NETWORK; operator-explicit) ──

    def submit(self, submission: StoredSubmission, *, confirm: bool = False) -> StoredSubmission:
        """Post the prepared submission to HackerOne.

        Requires `confirm=True` as an explicit second-arg gate. We
        intentionally make this awkward to call accidentally — the
        operator's CLI / UI passes confirm=True only when the operator
        has reviewed and approved the draft.

        Raises RuntimeError on submission failure (operator must
        review the StoredSubmission.last_error and decide what to do).
        """
        if not confirm:
            raise RuntimeError(
                "submit() requires explicit confirm=True. This is a "
                "guardrail — submission is irreversible. Verify the "
                "draft (submission.payload) is what you want, then "
                "call submit(submission, confirm=True)."
            )
        if submission.state != SubmissionState.DRAFT:
            raise RuntimeError(
                f"Cannot submit: submission is in state "
                f"{submission.state.value}, not DRAFT. Submission is "
                f"already past the draft stage."
            )

        submission.record_state_change(
            SubmissionState.SUBMITTING, note="POST /v1/reports"
        )
        save_submission_log(submission)

        url = f"{self._base_url}/reports"
        try:
            r = self._client.post(url, content=json.dumps(submission.payload))
        except Exception as e:
            submission.last_error = f"transport: {type(e).__name__}: {e}"
            submission.record_state_change(SubmissionState.FAILED, note=submission.last_error)
            save_submission_log(submission)
            raise RuntimeError(submission.last_error) from e

        if r.status_code not in (200, 201):
            submission.last_error = f"HTTP {r.status_code}: {r.text[:600]}"
            submission.record_state_change(SubmissionState.FAILED, note=submission.last_error)
            save_submission_log(submission)
            raise RuntimeError(submission.last_error)

        try:
            data = r.json().get("data", {})
            submission.h1_report_id = str(data.get("id", "")) or None
            # H1 stops the URL out of the response; build it deterministically.
            if submission.h1_report_id:
                submission.h1_report_url = (
                    f"https://hackerone.com/reports/{submission.h1_report_id}"
                )
            attrs = data.get("attributes", {})
            h1_state = attrs.get("state") or "new"
            try:
                new_state = SubmissionState(h1_state)
            except ValueError:
                new_state = SubmissionState.NEW
            submission.record_state_change(
                new_state, note=f"submitted as report #{submission.h1_report_id}"
            )
        except Exception as e:
            submission.last_error = f"response parse: {type(e).__name__}: {e}"
            submission.record_state_change(SubmissionState.FAILED, note=submission.last_error)
            save_submission_log(submission)
            raise RuntimeError(submission.last_error) from e

        submission.last_polled_at = time.time()
        save_submission_log(submission)
        return submission

    # ── status polling ──

    def refresh_status(self, submission: StoredSubmission) -> StoredSubmission:
        """Poll GET /v1/reports/{id} and update local state.

        No-op if the submission is still in DRAFT or SUBMITTING.
        """
        if submission.h1_report_id is None:
            return submission
        url = f"{self._base_url}/reports/{submission.h1_report_id}"
        try:
            r = self._client.get(url)
        except Exception as e:
            submission.last_error = f"poll transport: {type(e).__name__}: {e}"
            save_submission_log(submission)
            return submission

        if r.status_code != 200:
            submission.last_error = f"poll HTTP {r.status_code}: {r.text[:200]}"
            save_submission_log(submission)
            return submission

        try:
            data = r.json().get("data", {})
            attrs = data.get("attributes", {})
            new_state_raw = attrs.get("state") or "new"
            try:
                new_state = SubmissionState(new_state_raw)
            except ValueError:
                new_state = SubmissionState.NEW
            if new_state != submission.state:
                submission.record_state_change(
                    new_state, note=f"polled at {time.time():.0f}"
                )
        except Exception:
            pass

        submission.last_polled_at = time.time()
        save_submission_log(submission)
        return submission
