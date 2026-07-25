"""
Phase 6-PT3 tests for core/submission/h1_client.py.

Critical correctness properties pinned:

  1. `submit()` REQUIRES explicit `confirm=True`. Forgetting it raises
     loudly; never silently no-ops or auto-confirms. Submission is
     irreversible — we don't trust calling code to know "is the
     operator ready?" — only the operator does.

  2. `prepare()` never touches the network. A draft can be inspected
     locally before any submission risk.

  3. State transitions are recorded in the history list — we never
     lose the timeline of "draft → submitting → new → triaged → ...".

  4. Persistence is atomic — partial writes never leave the directory.

  5. Status polling updates state only when the H1 side reports a new
     value; doesn't clobber on transient errors.
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

import httpx
import pytest

from core.submission.h1_client import (
    H1SubmissionClient,
    StoredSubmission,
    SubmissionState,
    load_submission_log,
    save_submission_log,
)


@pytest.fixture(autouse=True)
def _isolated_submission_dir(monkeypatch, tmp_path):
    """Redirect ~/.sentinelforge/submissions to a tmp path so tests
    don't leak into the operator's real data."""
    monkeypatch.setattr(
        "core.submission.h1_client.SUBMISSION_DIR",
        tmp_path / "submissions",
    )
    yield


def _mock_client(handler):
    """Construct an H1SubmissionClient with a MockTransport so no
    real network calls happen."""
    transport = httpx.MockTransport(handler)
    return H1SubmissionClient(
        handle="testuser", token="testtoken", transport=transport,
    )


# ───────────────────────── prepare (no network) ─────────────────────────


class TestPrepare:
    def test_prepare_builds_draft_without_network(self):
        # If prepare reached the network, no handler is set; this would 500.
        # The test is the absence of failure.
        def boom(req):
            raise AssertionError(
                f"prepare() touched the network: {req.method} {req.url}"
            )
        client = _mock_client(boom)
        sub = client.prepare(
            program_handle="airtable",
            title="Test draft",
            markdown_body="# Body",
        )
        assert sub.state == SubmissionState.DRAFT
        assert sub.program_handle == "airtable"
        # h1_report_id is None until submit
        assert sub.h1_report_id is None

    def test_prepare_payload_shape(self):
        client = _mock_client(lambda req: httpx.Response(200))
        sub = client.prepare(
            program_handle="airtable",
            title="A test bug",
            markdown_body="# Markdown",
            severity="high",
            cwe_id=639,
            structured_scope_id="scope-abc",
            impact="real impact text",
        )
        data = sub.payload["data"]
        assert data["type"] == "report"
        attrs = data["attributes"]
        assert attrs["team_handle"] == "airtable"
        assert attrs["title"] == "A test bug"
        assert attrs["vulnerability_information"] == "# Markdown"
        assert attrs["severity_rating"] == "high"
        assert attrs["weakness_id"] == 639
        assert attrs["impact"] == "real impact text"
        rels = data["relationships"]["structured_scope"]["data"]
        assert rels["id"] == "scope-abc"
        assert rels["type"] == "structured-scope"


# ───────────────────────── submit (with guardrails) ─────────────────────────


class TestSubmitGuardrails:
    def test_submit_without_confirm_raises(self):
        client = _mock_client(lambda req: httpx.Response(201, json={"data": {"id": "1"}}))
        sub = client.prepare(
            program_handle="airtable",
            title="x", markdown_body="y",
        )
        with pytest.raises(RuntimeError, match="confirm=True"):
            client.submit(sub)  # no confirm — must raise

    def test_submit_when_not_draft_raises(self):
        client = _mock_client(lambda req: httpx.Response(201, json={"data": {"id": "1"}}))
        sub = client.prepare(
            program_handle="airtable",
            title="x", markdown_body="y",
        )
        # Force out of DRAFT
        sub.record_state_change(SubmissionState.NEW)
        with pytest.raises(RuntimeError, match="not DRAFT"):
            client.submit(sub, confirm=True)


# ───────────────────────── submit (happy path) ─────────────────────────


class TestSubmitHappyPath:
    def test_submit_201_advances_to_NEW(self):
        captured = {"requests": []}
        def handler(req):
            captured["requests"].append({
                "method": req.method,
                "url": str(req.url),
                "body": req.content.decode(),
            })
            return httpx.Response(201, json={
                "data": {
                    "id": "9876543",
                    "type": "report",
                    "attributes": {"state": "new"},
                }
            })
        client = _mock_client(handler)
        sub = client.prepare(
            program_handle="airtable",
            title="A real test",
            markdown_body="# Yes",
        )
        result = client.submit(sub, confirm=True)
        assert result.state == SubmissionState.NEW
        assert result.h1_report_id == "9876543"
        assert result.h1_report_url == "https://hackerone.com/reports/9876543"
        # And the request went to the right place.
        assert len(captured["requests"]) == 1
        assert captured["requests"][0]["method"] == "POST"
        assert captured["requests"][0]["url"].endswith("/reports")

    def test_submit_records_state_history(self):
        def handler(req):
            return httpx.Response(201, json={
                "data": {"id": "1", "attributes": {"state": "new"}}
            })
        client = _mock_client(handler)
        sub = client.prepare(
            program_handle="airtable", title="x", markdown_body="y",
        )
        sub = client.submit(sub, confirm=True)
        # Must have at least: draft → submitting → new
        states_visited = [h["to"] for h in sub.state_history]
        assert "submitting" in states_visited
        assert "new" in states_visited


# ───────────────────────── submit (failure paths) ─────────────────────────


class TestSubmitFailure:
    def test_submit_400_records_failed_state(self):
        def handler(req):
            return httpx.Response(400, json={"errors": [{"detail": "bad body"}]})
        client = _mock_client(handler)
        sub = client.prepare(
            program_handle="airtable", title="x", markdown_body="y",
        )
        with pytest.raises(RuntimeError, match="HTTP 400"):
            client.submit(sub, confirm=True)
        # Local state reflects the failure.
        assert sub.state == SubmissionState.FAILED
        assert "HTTP 400" in sub.last_error

    def test_submit_transport_error_records_failed_state(self):
        def handler(req):
            raise httpx.ConnectError("simulated")
        client = _mock_client(handler)
        sub = client.prepare(
            program_handle="airtable", title="x", markdown_body="y",
        )
        with pytest.raises(RuntimeError):
            client.submit(sub, confirm=True)
        assert sub.state == SubmissionState.FAILED


# ───────────────────────── poll ─────────────────────────


class TestPoll:
    def test_refresh_status_updates_on_state_change(self):
        responses = iter([
            httpx.Response(201, json={"data": {"id": "11", "attributes": {"state": "new"}}}),
            httpx.Response(200, json={"data": {"id": "11", "attributes": {"state": "triaged"}}}),
        ])
        def handler(req): return next(responses)
        client = _mock_client(handler)
        sub = client.prepare(
            program_handle="airtable", title="x", markdown_body="y",
        )
        sub = client.submit(sub, confirm=True)
        assert sub.state == SubmissionState.NEW
        sub = client.refresh_status(sub)
        assert sub.state == SubmissionState.TRIAGED

    def test_poll_transient_error_does_not_clobber_state(self):
        post_resp = httpx.Response(201, json={"data": {"id": "12", "attributes": {"state": "new"}}})
        responses = iter([post_resp, httpx.Response(503, text="upstream")])
        def handler(req): return next(responses)
        client = _mock_client(handler)
        sub = client.prepare(
            program_handle="airtable", title="x", markdown_body="y",
        )
        sub = client.submit(sub, confirm=True)
        # Now hit a 503 — must not change state
        sub = client.refresh_status(sub)
        assert sub.state == SubmissionState.NEW  # unchanged
        assert sub.last_error and "503" in sub.last_error


# ───────────────────────── persistence ─────────────────────────


class TestPersistence:
    def test_round_trip_via_disk(self, tmp_path, monkeypatch):
        sub = StoredSubmission(
            program_handle="airtable",
            title="test",
            payload={"data": {"type": "report", "attributes": {"title": "t"}}},
            state=SubmissionState.NEW,
            h1_report_id="1234",
        )
        path = save_submission_log(sub)
        assert path.exists()
        reloaded = load_submission_log(path)
        assert reloaded.program_handle == "airtable"
        assert reloaded.state == SubmissionState.NEW
        assert reloaded.h1_report_id == "1234"

    def test_atomic_write_no_tmp_leftover(self):
        sub = StoredSubmission(
            program_handle="airtable", title="t",
            payload={}, state=SubmissionState.DRAFT,
        )
        path = save_submission_log(sub)
        tmp = path.with_suffix(path.suffix + ".tmp")
        assert not tmp.exists(), "atomic write left .tmp neighbor"
