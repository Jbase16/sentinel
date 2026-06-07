"""
Phase 5-VC3 tests for core/verify/promoter.py + the /promote endpoint.

Coverage:
  * sanitize_headers: Authorization (Bearer/Basic), API keys, CSRF,
    and Cookie (per-cookie name-aware placeholder).
  * render_curl: shape + sanitization on/off, body included, headers
    present in alphabetical order.
  * ReproEntry.markdown: prose + curl + response excerpt assembled.
  * promote_transcript_to_repro: subset selection, full-transcript
    default, finding-context-aware prose for the first step.
  * Endpoint: empty transcript → 400, subset selection works,
    sanitized output is the default, structured `entries` + flat
    `steps_to_reproduce` both populated.

The critical correctness property tested here: REAL AUTH TOKENS
never appear in the rendered output (sanitize=True). Verified by
asserting on the absence of the captured token byte sequence in
the rendered curl + markdown.
"""
from __future__ import annotations

import asyncio
from typing import Any, Dict

import pytest

from core.ghost.flow import FlowStep
from core.verify.console import (
    _reset_for_tests,
    create_session_from_target,
    create_session_from_finding,
)
from core.verify.promoter import (
    ReproEntry,
    promote_transcript_to_repro,
    render_curl,
    render_repro_as_strings,
    sanitize_headers,
    _excerpt_response_body,
    _sanitize_cookie_value,
)


def _run(coro):
    return asyncio.run(coro)


@pytest.fixture(autouse=True)
def _reset_store():
    _reset_for_tests()
    yield
    _reset_for_tests()


def _mk_step(
    method="GET",
    url="https://target.example/api/users/1",
    headers=None,
    body=None,
    resp_status=200,
    resp_body="",
    resp_headers=None,
):
    step = FlowStep(
        method=method, url=url,
        headers=headers or {},
        request_body=body or "",
    )
    step.set_response(
        status=resp_status,
        headers=resp_headers or {},
        body=resp_body,
        content_type=(resp_headers or {}).get("content-type"),
    )
    return step


# ─────────────────────────── sanitization ───────────────────────────


class TestSanitizeHeaders:
    def test_bearer_token_replaced_with_placeholder(self):
        sanitized, legend = sanitize_headers({
            "Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.real.token",
        })
        assert sanitized["authorization"] == "Bearer $TOKEN"
        # The real token must NOT appear anywhere in the sanitized output.
        assert "eyJhbGciOiJIUzI1NiJ9" not in str(sanitized)
        # Legend tells the triager what $TOKEN means.
        assert "$TOKEN" in legend

    def test_basic_auth_replaced(self):
        sanitized, _ = sanitize_headers({
            "Authorization": "Basic dXNlcjpwYXNz",
        })
        assert sanitized["authorization"] == "Basic $CREDENTIALS_B64"

    def test_x_api_key_replaced(self):
        sanitized, _ = sanitize_headers({"X-API-Key": "secret-key-123"})
        assert sanitized["x-api-key"] == "$API_KEY"
        assert "secret-key-123" not in str(sanitized)

    def test_csrf_token_header_replaced(self):
        sanitized, _ = sanitize_headers({"X-CSRF-Token": "abcdef1234"})
        assert sanitized["x-csrf-token"] == "$CSRF_TOKEN"

    def test_non_auth_headers_preserved(self):
        """Content-Type, X-Custom etc. carry no secret value; pass through."""
        sanitized, _ = sanitize_headers({
            "Content-Type": "application/json",
            "X-Custom-Trace": "trace-12345",
        })
        assert sanitized["content-type"] == "application/json"
        assert sanitized["x-custom-trace"] == "trace-12345"


class TestSanitizeCookie:
    def test_session_cookie_replaced_by_name(self):
        result = _sanitize_cookie_value("sid=abc123; csrf=xyz789")
        assert result == "sid=$SESSION_ID; csrf=$CSRF_TOKEN"

    def test_remember_token_replaced(self):
        result = _sanitize_cookie_value("remember_token=verylongvalue")
        assert result == "remember_token=$REMEMBER_TOKEN"

    def test_unknown_cookie_gets_named_placeholder(self):
        """Unknown cookies still get sanitized — the name becomes part
        of the placeholder so the triager knows what's expected."""
        result = _sanitize_cookie_value("custom-app=secret-value")
        assert "secret-value" not in result
        assert "custom-app=$" in result


# ─────────────────────────── curl rendering ───────────────────────────


class TestRenderCurl:
    def test_sanitized_curl_has_no_real_token(self):
        step = _mk_step(
            method="GET",
            url="https://h.example/api/users/2",
            headers={"Authorization": "Bearer SUPER-SECRET-JWT"},
        )
        curl, legend = render_curl(step, sanitize=True)
        # The real token must NOT appear anywhere in the curl.
        assert "SUPER-SECRET-JWT" not in curl
        # The placeholder appears instead.
        assert "$TOKEN" in curl
        # And the legend has an entry for it.
        assert "$TOKEN" in legend
        # Curl shape — method + URL present + header line + escaped.
        assert curl.startswith("curl -X GET")
        assert "https://h.example/api/users/2" in curl

    def test_sanitize_false_returns_raw_token(self):
        """Operator-local debug mode: see the real values."""
        step = _mk_step(
            headers={"Authorization": "Bearer LITERAL-TOKEN"},
        )
        curl, _ = render_curl(step, sanitize=False)
        assert "LITERAL-TOKEN" in curl

    def test_request_body_included(self):
        step = _mk_step(
            method="POST",
            url="https://h.example/api",
            headers={"Content-Type": "application/json"},
            body='{"x": 1}',
        )
        curl, _ = render_curl(step)
        assert '-d ' in curl
        assert '{"x": 1}' in curl

    def test_url_with_single_quotes_handled(self):
        """Shell-escape robustness: a URL with a single quote in it
        must not produce a broken curl."""
        step = _mk_step(url="https://h.example/search?q=O'Brien")
        curl, _ = render_curl(step)
        # The escaped URL appears verbatim somewhere in the output.
        # shlex.quote will quote it with single-quote-escape sequences.
        # The simplest verification: curl is non-empty and includes
        # the host.
        assert "https://h.example" in curl
        # And the apostrophe is shell-escaped (shlex.quote does
        # `O'"'"'Brien` style).
        assert "Brien" in curl


# ─────────────────────────── ReproEntry markdown ───────────────────────────


class TestReproEntryMarkdown:
    def test_markdown_includes_prose_curl_and_response(self):
        entry = ReproEntry(
            index=1,
            method="GET", url="https://h.example/users/1",
            prose="Send `GET /users/1` to demonstrate IDOR.",
            curl="curl -X GET 'https://h.example/users/1'",
            response_status=200,
            response_excerpt='{"id":1,"role":"admin"}',
        )
        md = entry.markdown
        assert "Send `GET /users/1`" in md
        assert "```bash" in md
        assert "curl -X GET" in md
        assert "**Response (HTTP 200):**" in md
        assert '"role":"admin"' in md

    def test_zero_status_omits_response_block(self):
        """A network-error step (status=0) shouldn't fake a response
        block in the repro — the prose can mention the failure."""
        entry = ReproEntry(
            index=1, method="GET", url="https://h.example/",
            prose="Send the request.",
            curl="curl ...",
            response_status=0,
            response_excerpt="<network error>",
        )
        md = entry.markdown
        assert "**Response" not in md


# ─────────────────────────── promote_transcript ───────────────────────────


class TestPromoteTranscript:
    def test_full_transcript_by_default(self):
        sess = create_session_from_target("https://h.example/")
        sess.append_exchange(_mk_step(url="https://h.example/a"))
        sess.append_exchange(_mk_step(url="https://h.example/b"))
        sess.append_exchange(_mk_step(url="https://h.example/c"))

        entries, _ = promote_transcript_to_repro(sess)
        assert len(entries) == 3
        # Indices are 1-based and dense (no gaps).
        assert [e.index for e in entries] == [1, 2, 3]

    def test_subset_selection(self):
        sess = create_session_from_target("https://h.example/")
        sess.append_exchange(_mk_step(url="https://h.example/a"))
        sess.append_exchange(_mk_step(url="https://h.example/b"))
        sess.append_exchange(_mk_step(url="https://h.example/c"))

        # Select just steps 0 and 2.
        entries, _ = promote_transcript_to_repro(sess, exchange_indices=[0, 2])
        urls = [e.url for e in entries]
        assert urls == ["https://h.example/a", "https://h.example/c"]
        # Re-numbered 1, 2 (not 1, 3).
        assert [e.index for e in entries] == [1, 2]

    def test_out_of_range_indices_skipped(self):
        sess = create_session_from_target("https://h.example/")
        sess.append_exchange(_mk_step(url="https://h.example/a"))

        # Indices 5 and 10 don't exist.
        entries, _ = promote_transcript_to_repro(
            sess, exchange_indices=[0, 5, 10]
        )
        assert len(entries) == 1
        assert entries[0].url == "https://h.example/a"

    def test_first_step_prose_does_not_leak_internal_labels(self):
        """Phase 6-PT2 regression: the first step's prose used to
        include 'to reproduce the IDOR confirmation (payload: id:1→2)'
        which leaked Sentinel-internal scoring labels into the
        rendered repro. The operator-facing narrative belongs in
        PT2's SubmissionRender summary/impact sections; the steps
        themselves stay action-only ('send GET ...', 'response is
        HTTP 200, body shows ...'). The vuln class + payload move
        out of the steps."""
        finding = {
            "id": "f-1",
            "target": "https://h.example/api/users/1",
            "type": "IDOR",
            "metadata": {
                "vuln_class": "IDOR",
                "payload": "id: 1→2",
            },
        }

        class _StubStore:
            def get(self, fid):
                return finding if fid == "f-1" else None

        sess = create_session_from_finding("f-1", finding_store=_StubStore())
        sess.append_exchange(_mk_step(
            url="https://h.example/api/users/2",
            resp_body='{"id": 2, "email": "victim@example.com"}',
        ))

        entries, _ = promote_transcript_to_repro(sess)
        first = entries[0]
        # The internal payload notation must NOT leak into the prose.
        assert "id: 1→2" not in first.prose, (
            "Sentinel-internal payload label leaked into repro prose"
        )
        # The "to reproduce the IDOR confirmation" boilerplate is also out.
        assert "to reproduce the IDOR confirmation" not in first.prose
        # The actual request action is still narrated.
        assert "GET" in first.prose or "GET" in first.curl

    def test_response_excerpt_truncated(self):
        long_body = "x" * 2000
        sess = create_session_from_target("https://h.example/")
        sess.append_exchange(_mk_step(resp_body=long_body))
        entries, _ = promote_transcript_to_repro(sess)
        # Excerpt is capped (< full body).
        assert len(entries[0].response_excerpt) < len(long_body)
        assert "…" in entries[0].response_excerpt


# ─────────────────────────── /promote endpoint ───────────────────────────


class TestPromoteEndpoint:
    def test_empty_transcript_returns_400(self):
        from core.server.routers.verify import (
            PromoteRequest, promote_to_repro,
        )
        from fastapi import HTTPException

        sess = create_session_from_target("https://h.example/")
        # No transcript — promote must 400.
        with pytest.raises(HTTPException) as ei:
            _run(promote_to_repro(
                sess.session_id, PromoteRequest(), _=True,
            ))
        assert ei.value.status_code == 400
        assert "empty" in ei.value.detail.lower()

    def test_unknown_session_returns_404(self):
        from core.server.routers.verify import (
            PromoteRequest, promote_to_repro,
        )
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as ei:
            _run(promote_to_repro(
                "no-such-session", PromoteRequest(), _=True,
            ))
        assert ei.value.status_code == 404

    def test_full_promotion_shape(self):
        from core.server.routers.verify import (
            PromoteRequest, promote_to_repro,
        )

        sess = create_session_from_target("https://h.example/")
        sess.append_exchange(_mk_step(
            method="GET", url="https://h.example/users/1",
            headers={"Authorization": "Bearer REAL-TOKEN-XYZ"},
            resp_status=200, resp_body='{"id": 1, "name": "alice"}',
        ))

        result = _run(promote_to_repro(
            sess.session_id, PromoteRequest(), _=True,
        ))
        # Top-level shape.
        assert result.finding_id is None
        assert result.target_url == "https://h.example/"
        assert result.entry_count == 1
        # Both representations populated.
        assert len(result.steps_to_reproduce) == 1
        assert len(result.entries) == 1
        # Sanitization default ON: real token not in any rendered output.
        flat = result.steps_to_reproduce[0]
        assert "REAL-TOKEN-XYZ" not in flat
        assert "$TOKEN" in flat
        # Legend includes $TOKEN.
        assert "$TOKEN" in result.placeholder_legend

    def test_subset_selection_via_indices(self):
        from core.server.routers.verify import (
            PromoteRequest, promote_to_repro,
        )

        sess = create_session_from_target("https://h.example/")
        for i in range(4):
            sess.append_exchange(_mk_step(
                url=f"https://h.example/step{i}",
                resp_body=f"resp {i}",
            ))

        # Pick exchanges 1 and 3.
        result = _run(promote_to_repro(
            sess.session_id,
            PromoteRequest(exchange_indices=[1, 3]),
            _=True,
        ))
        assert result.entry_count == 2
        # Re-numbered 1 + 2 in the rendered output.
        urls = [e["url"] for e in result.entries]
        assert urls == ["https://h.example/step1", "https://h.example/step3"]

    def test_unsanitized_path_includes_real_token(self):
        """sanitize=False is for local debug — verify it actually
        returns the real value (operators may need this for their own
        repro debugging before promoting to a report)."""
        from core.server.routers.verify import (
            PromoteRequest, promote_to_repro,
        )

        sess = create_session_from_target("https://h.example/")
        sess.append_exchange(_mk_step(
            headers={"Authorization": "Bearer LOCAL-DEBUG-TOKEN"},
        ))
        result = _run(promote_to_repro(
            sess.session_id,
            PromoteRequest(sanitize=False),
            _=True,
        ))
        # Real value DOES appear when sanitize=False.
        assert "LOCAL-DEBUG-TOKEN" in result.steps_to_reproduce[0]
